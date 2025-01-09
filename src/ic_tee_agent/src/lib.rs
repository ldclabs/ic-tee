use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

pub mod agent;
pub mod http;
pub mod identity;
pub mod setting;

/// The ic_sig_verifier module uses ic_types and ic_crypto_standalone_sig_verifier crates
/// which are not published. Therefore, ic_tee_agent cannot directly depend on these crates.
/// Users can copy the code from ic_sig_verifier into their own projects.
#[cfg(test)]
mod ic_sig_verifier;

pub use identity::*;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RPCRequest {
    pub method: String,
    pub params: ByteBuf, // params should be encoded in CBOR format
}

// result should be encoded in CBOR format
pub type RPCResponse = Result<ByteBuf, String>;
