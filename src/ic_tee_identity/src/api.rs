use candid::Principal;
use ciborium::from_reader;
use ic_canister_sig_creation::{delegation_signature_msg, CanisterSigPublicKey};
use ic_tee_nitro_attestation::parse_and_verify;
use serde_bytes::ByteBuf;

use crate::{store, types};

const ATTESTATION_EXPIRES_IN_MS: u64 = 1000 * 60 * 5; // 5 minute
const MILLISECONDS: u64 = 1000000;

#[ic_cdk::query]
fn get_state() -> Result<store::State, String> {
    Ok(store::state::with(|s| s.clone()))
}

#[ic_cdk::update]
fn sign_in(kind: String, attestation: ByteBuf) -> Result<types::SignInResponse, String> {
    let attestation = match kind.as_str() {
        "Nitro" => parse_and_verify(attestation.as_slice())?,
        _ => Err("unsupported attestation kind".to_string())?,
    };

    ic_cdk::println!("attestation: {:?}", attestation);

    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    if now_ms > attestation.timestamp + ATTESTATION_EXPIRES_IN_MS {
        return Err("attestation expired".to_string());
    }
    let pcr0 = attestation.pcrs.get(&0).ok_or_else(|| "missing PCR0")?;
    let pubkey: ByteBuf = attestation
        .public_key
        .ok_or_else(|| "missing public key".to_string())?;

    // TODO: check request method and params
    let _req: types::AttestationRequest<types::SignInParams> = attestation.user_data.map_or_else(
        || Err("missing user data".to_string()),
        |data| from_reader(data.as_slice()).map_err(|err| format!("invalid user data: {:?}", err)),
    )?;

    let session_expires_in_ms = store::state::with_mut(|state| {
        state.sign_in_count = state.sign_in_count.saturating_add(1);
        state.session_expires_in_ms
    });
    let expiration = (now_ms + session_expires_in_ms) * MILLISECONDS;

    let user_key = CanisterSigPublicKey::new(ic_cdk::id(), pcr0.to_vec()).to_der();
    let principal = Principal::self_authenticating(&user_key);
    let delegation_hash = delegation_signature_msg(pubkey.as_slice(), expiration, None);
    store::state::add_signature(principal.as_slice(), delegation_hash.as_slice());

    Ok(types::SignInResponse {
        expiration,
        user_key: user_key.into(),
    })
}

#[ic_cdk::query]
fn get_delegation(
    principal: Principal,
    session_key: ByteBuf,
    expiration: u64,
) -> Result<types::SignedDelegation, String> {
    let delegation_hash = delegation_signature_msg(session_key.as_slice(), expiration, None);
    let signature = store::state::get_signature(principal.as_slice(), delegation_hash.as_slice())?;
    Ok(types::SignedDelegation {
        delegation: types::Delegation {
            pubkey: session_key,
            expiration,
            targets: None,
        },
        signature: ByteBuf::from(signature),
    })
}
