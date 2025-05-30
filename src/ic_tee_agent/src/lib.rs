use ic_auth_types::ByteBufB64;
use serde::{Deserialize, Serialize};

pub mod agent;
pub mod http;
pub mod identity;
pub mod setting;

pub use identity::*;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RPCRequest {
    pub method: String,
    pub params: ByteBufB64, // params should be encoded in CBOR format
}

#[derive(Clone, Debug, Serialize)]
pub struct RPCRequestRef<'a> {
    pub method: &'a str,
    pub params: &'a ByteBufB64,
}

// result should be encoded in CBOR format
pub type RPCResponse = Result<ByteBufB64, String>;
