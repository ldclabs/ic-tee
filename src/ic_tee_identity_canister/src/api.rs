use candid::Principal;
use cbor2::from_slice;
use ic_auth_types::{Delegation, SignInResponse, SignedDelegation};
use ic_auth_verifier::{user_public_key_from_der, verify_basic_sig};
use ic_canister_sig_creation::delegation_signature_msg;
use ic_tee_cdk::{canister_user_key, AttestationUserRequest, SignInParams};
use ic_tee_nitro_attestation::{parse, verify};
use serde_bytes::ByteBuf;

use crate::store;

const ATTESTATION_EXPIRES_IN_MS: u64 = 1000 * 60 * 5; // 5 minute
const NANOS_PER_MS: u64 = 1_000_000;

/// Maximum clock difference allowed when checking an attestation timestamp.
const PERMITTED_DRIFT_MS: u64 = 60 * 1000;

#[ic_cdk::query]
fn get_state() -> Result<store::State, String> {
    Ok(store::state::with(|s| s.clone()))
}

#[ic_cdk::query]
fn whoami() -> Principal {
    ic_cdk::api::msg_caller()
}

#[ic_cdk::update]
fn sign_in(kind: String, attestation: ByteBuf) -> Result<SignInResponse, String> {
    if kind != "NITRO" {
        return Err(format!("unsupported attestation kind: {}", kind));
    }

    // Run the cheap checks first, verifying the COSE signature and the certificate chain
    // is by far the most expensive part.
    let (cs1, attestation) = parse(attestation.as_slice())?;

    let now_ms = ic_cdk::api::time() / NANOS_PER_MS;
    if attestation.timestamp.saturating_sub(now_ms) > PERMITTED_DRIFT_MS {
        return Err("attestation timestamp is in the future".to_string());
    }
    if now_ms.saturating_sub(attestation.timestamp) > ATTESTATION_EXPIRES_IN_MS + PERMITTED_DRIFT_MS
    {
        return Err("attestation expired".to_string());
    }
    let pcr0 = attestation.pcrs.get(&0).ok_or("missing PCR0")?;
    // PCRs of an enclave running in debug mode are all zeros.
    if pcr0.iter().all(|&b| b == 0) {
        return Err("attestation from a debug mode enclave is not allowed".to_string());
    }
    let pubkey = attestation
        .public_key
        .as_ref()
        .ok_or("missing public key")?;
    let user_data = attestation.user_data.as_ref().ok_or("missing user data")?;
    let sig = attestation.nonce.as_ref().ok_or("missing nonce")?;

    let req: AttestationUserRequest<SignInParams> =
        from_slice(user_data.as_slice()).map_err(|err| format!("invalid user data: {:?}", err))?;
    if req.method != "sign_in" {
        return Err("invalid attestation user request method".to_string());
    }
    let sub_seed = match req.params {
        Some(SignInParams { id_scope }) => match id_scope.as_str() {
            "image" => None,
            "instance" => Some(attestation.module_id.as_bytes()),
            _ => return Err(format!("unsupported id_scope: {}", id_scope)),
        },
        None => return Err("invalid attestation user request params".to_string()),
    };

    let (alg, pk) = user_public_key_from_der(pubkey.as_slice())?;
    verify_basic_sig(alg, &pk, user_data.as_slice(), sig.as_slice())
        .map_err(|err| format!("challenge verification failed: {:?}", err))?;

    verify(&cs1, &attestation)?;

    let user_key = canister_user_key(
        ic_cdk::api::canister_self(),
        &kind,
        pcr0.as_slice(),
        sub_seed,
    );

    let session_expires_in_ms = store::state::with(|state| state.session_expires_in_ms);
    if session_expires_in_ms == 0 {
        return Err("session lifetime must be positive".to_string());
    }
    let expiration = now_ms
        .checked_add(session_expires_in_ms)
        .and_then(|expiration_ms| expiration_ms.checked_mul(NANOS_PER_MS))
        .ok_or("invalid session expiration")?;

    let delegation_hash = delegation_signature_msg(pubkey.as_slice(), expiration, None);
    store::state::add_signature(user_key.seed.as_slice(), delegation_hash.as_slice());
    store::state::with_mut(|state| {
        state.sign_in_count = state.sign_in_count.saturating_add(1);
    });

    Ok(SignInResponse {
        expiration,
        user_key: user_key.to_der().into(),
        seed: user_key.seed.into(),
    })
}

#[ic_cdk::query]
fn get_delegation(
    seed: ByteBuf,
    session_key: ByteBuf,
    expiration: u64,
) -> Result<SignedDelegation, String> {
    if seed.len() > 128 {
        return Err("invalid seed length".to_string());
    }
    let delegation_hash = delegation_signature_msg(session_key.as_slice(), expiration, None);
    let signature = store::state::get_signature(seed.as_slice(), delegation_hash.as_slice())?;
    Ok(SignedDelegation {
        delegation: Delegation {
            pubkey: session_key.into_vec().into(),
            expiration,
            targets: None,
            permissions: None,
        },
        signature: signature.into(),
    })
}
