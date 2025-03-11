use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

pub mod agent;
pub mod http;
pub mod identity;
pub mod setting;

pub use identity::*;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RPCRequest {
    pub method: String,
    pub params: ByteBuf, // params should be encoded in CBOR format
}

#[derive(Clone, Debug, Serialize)]
pub struct RPCRequestRef<'a> {
    pub method: &'a str,
    pub params: &'a ByteBuf,
}

// result should be encoded in CBOR format
pub type RPCResponse = Result<ByteBuf, String>;
