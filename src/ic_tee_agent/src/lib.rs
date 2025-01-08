use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

pub mod agent;
pub mod crypto;
pub mod http;
pub mod identity;
pub mod setting;

pub use identity::*;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RPCRequest {
    pub method: String,
    pub params: ByteBuf, // params should be encoded in CBOR format
}

// result should be encoded in CBOR format
pub type RPCResponse = Result<ByteBuf, String>;
