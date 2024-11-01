use candid::{CandidType, Principal};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct Delegation {
    pub pubkey: ByteBuf,
    pub expiration: u64,
    pub targets: Option<Vec<Principal>>,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct SignedDelegation {
    pub delegation: Delegation,
    pub signature: ByteBuf,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct SignInResponse {
    /// The session expiration time in nanoseconds since the UNIX epoch. This is the time at which
    /// the delegation will no longer be valid.
    pub expiration: u64,
    /// The user canister public key. This key is used to derive the user principal.
    pub user_key: ByteBuf,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct AttestationRequest<T> {
    pub method: String, // should be "sign_in"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<T>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SignInParams {
    pub id_scope: String, // should be "image" or "enclave"
}
