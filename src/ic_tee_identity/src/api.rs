use candid::Principal;
use ciborium::from_reader;
use ic_canister_sig_creation::delegation_signature_msg;
use ic_crypto_standalone_sig_verifier::{
    user_public_key_from_bytes, verify_basic_sig_by_public_key,
};
use ic_tee_cdk::{
    canister_user_key, AttestationUserRequest, Delegation, SignInParams, SignInResponse,
    SignedDelegation,
};
use ic_tee_nitro_attestation::parse_and_verify;
use serde_bytes::ByteBuf;

use crate::store;

const ATTESTATION_EXPIRES_IN_MS: u64 = 1000 * 60 * 5; // 5 minute
const MILLISECONDS: u64 = 1000000;

#[ic_cdk::query]
fn get_state() -> Result<store::State, String> {
    Ok(store::state::with(|s| s.clone()))
}

#[ic_cdk::query]
fn whoami() -> Principal {
    ic_cdk::caller()
}

#[ic_cdk::update]
fn sign_in(kind: String, attestation: ByteBuf) -> Result<SignInResponse, String> {
    let attestation = match kind.as_str() {
        "Nitro" => parse_and_verify(attestation.as_slice())?,
        _ => Err("unsupported attestation kind".to_string())?,
    };

    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    if now_ms > attestation.timestamp + ATTESTATION_EXPIRES_IN_MS {
        return Err("attestation expired".to_string());
    }
    let pcr0 = attestation.pcrs.get(&0).ok_or("missing PCR0")?;
    let pubkey: ByteBuf = attestation
        .public_key
        .ok_or_else(|| "missing public key".to_string())?;
    let user_data: ByteBuf = attestation
        .user_data
        .ok_or_else(|| "missing user data".to_string())?;
    let sig: ByteBuf = attestation
        .nonce
        .ok_or_else(|| "missing nonce".to_string())?;

    let (pk, _) = user_public_key_from_bytes(pubkey.as_slice())
        .map_err(|err| format!("invalid public key: {:?}", err))?;
    verify_basic_sig_by_public_key(
        pk.algorithm_id,
        user_data.as_slice(),
        sig.as_slice(),
        &pk.key,
    )
    .map_err(|err| format!("challenge verification failed: {:?}", err))?;

    let req: AttestationUserRequest<SignInParams> =
        from_reader(user_data.as_slice()).map_err(|err| format!("invalid user data: {:?}", err))?;
    if req.method != "sign_in" {
        return Err("invalid attestation user request method".to_string());
    }

    let user_key = match req.params.as_ref() {
        Some(SignInParams { id_scope }) => {
            if id_scope == "image" {
                canister_user_key(ic_cdk::id(), &kind, pcr0.as_slice(), None)
            } else if id_scope == "instance" {
                canister_user_key(
                    ic_cdk::id(),
                    &kind,
                    pcr0.as_slice(),
                    Some(attestation.module_id.as_bytes()),
                )
            } else {
                return Err(format!("unsupport id_scope: {}", id_scope));
            }
        }
        _ => return Err("invalid attestation user request params".to_string()),
    };

    let session_expires_in_ms = store::state::with_mut(|state| {
        state.sign_in_count = state.sign_in_count.saturating_add(1);
        state.session_expires_in_ms
    });
    let expiration = (now_ms + session_expires_in_ms) * MILLISECONDS;

    let delegation_hash = delegation_signature_msg(pubkey.as_slice(), expiration, None);
    store::state::add_signature(user_key.seed.as_slice(), delegation_hash.as_slice());

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
    if seed.len() > 48 {
        return Err("invalid seed length".to_string());
    }
    let delegation_hash = delegation_signature_msg(session_key.as_slice(), expiration, None);
    let signature = store::state::get_signature(seed.as_slice(), delegation_hash.as_slice())?;
    Ok(SignedDelegation {
        delegation: Delegation {
            pubkey: session_key,
            expiration,
            targets: None,
        },
        signature: ByteBuf::from(signature),
    })
}
