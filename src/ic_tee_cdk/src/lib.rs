use candid::Principal;
use ciborium::into_writer;
use serde::{Deserialize, Serialize};

pub mod identity;

pub use identity::*;
use serde_bytes::ByteBuf;

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

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct AttestationUserRequest<T> {
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<T>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TEEAppInformation {
    pub name: String,
    pub version: String,
    pub kind: String,
    pub pcr0: ByteBuf,
    pub pcr1: ByteBuf,
    pub pcr2: ByteBuf,
    pub start_time_ms: u64,
    pub principal: Principal,
    pub authentication_canister: Principal,
    pub configuration_canister: Principal,
    pub registration_canister: Option<Principal>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TEEAppInformationJSON {
    pub name: String,
    pub version: String,
    pub kind: String,
    pub pcr0: String,
    pub pcr1: String,
    pub pcr2: String,
    pub start_time_ms: u64,
    pub principal: String,
    pub authentication_canister: String,
    pub configuration_canister: String,
    pub registration_canister: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TEEAttestation {
    pub kind: String,
    pub document: ByteBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TEEAttestationJSON {
    pub kind: String,
    pub document: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CanisterRequest {
    pub canister: Principal,
    pub method: String,
    pub params: ByteBuf,
}
