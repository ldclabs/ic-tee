use candid::{CandidType, Principal};
use ciborium::into_writer;
use ic_auth_types::ByteBufB64;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

pub mod identity;

pub use identity::*;

pub fn format_error<T>(err: T) -> String
where
    T: std::fmt::Debug,
{
    format!("{:?}", err)
}

pub fn to_cbor_bytes(obj: &impl Serialize) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    into_writer(obj, &mut buf).expect("failed to encode in CBOR format");
    buf
}

pub fn sha3_256_n<const N: usize>(array: [&[u8]; N]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    for data in array {
        hasher.update(data);
    }
    hasher.finalize().into()
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct AttestationUserRequest<T> {
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<T>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TEEAppInformation {
    pub id: Principal,
    pub instance: String,
    pub name: String,
    pub version: String,
    pub kind: String,
    pub pcr0: ByteBufB64,
    pub pcr1: ByteBufB64,
    pub pcr2: ByteBufB64,
    pub start_time_ms: u64,
    pub identity_canister: Principal,
    pub cose_canister: Principal,
    pub registration_canister: Option<Principal>,
    pub caller: Principal,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TEEAttestation {
    pub kind: String,
    pub document: ByteBufB64,
}

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub struct TEEInfo {
    pub id: Principal,
    pub kind: String,
    // (e.g. https://DOMAIN/.well-known/tee.json)
    pub url: String,
    pub attestation: ByteBufB64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CanisterRequest {
    pub canister: Principal,
    pub method: String,
    pub params: ByteBufB64, // params should be encoded in CANDID format
}

// result should be encoded in CANDID format
pub type CanisterResponse = Result<ByteBufB64, String>;
