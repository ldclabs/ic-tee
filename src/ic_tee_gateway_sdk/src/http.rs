//! HTTP utilities for making RPC calls to canisters and other services
//!
//! This module provides functionality for:
//! - Making CBOR-encoded RPC calls
//! - Making Candid-encoded canister calls
//! - Handling HTTP requests and responses
//! - Error handling for RPC operations
//!
//! The main types are:
//! - [`RPCRequest`]: Represents a generic RPC request with CBOR-encoded parameters
//! - [`CanisterRequest`]: Represents a canister-specific request with Candid-encoded parameters
//! - [`RPCResponse`]: Represents a response from an RPC call
//! - [`HttpRPCError`]: Represents possible errors during RPC operations
//!
//! The main functions are:
//! - [`http_rpc`]: Makes a generic CBOR-encoded RPC call
//! - [`canister_rpc`]: Makes a canister-specific RPC call with Candid encoding
//! - [`cbor_rpc`]: Internal function for making CBOR-encoded HTTP requests

use candid::{decode_args, encode_args, utils::ArgumentEncoder, CandidType, Principal};
use ciborium::from_reader;
use http::header;
use ic_cose_types::to_cbor_bytes;
use reqwest::Client;
use serde::{de::DeserializeOwned, Serialize};
use serde_bytes::ByteBuf;
use std::fmt::Display;

pub static CONTENT_TYPE_CBOR: &str = "application/cbor";
pub static CONTENT_TYPE_JSON: &str = "application/json";
pub static CONTENT_TYPE_TEXT: &str = "text/plain";

/// Represents an RPC request with method name and CBOR-encoded parameters
#[derive(Clone, Debug, Serialize)]
pub struct RPCRequest<'a> {
    /// The method name to call
    pub method: &'a str,
    /// CBOR-encoded parameters for the RPC call.
    /// Parameters should be provided as a tuple, where each element represents a single parameter.
    /// Examples:
    /// - `()`: No parameters
    /// - `(1,)`: Single parameter
    /// - `(1, "hello", 3.14)`: Three parameters
    pub params: &'a ByteBuf,
}

/// Represents a request to an ICP canister with canister ID, method name, and Candid-encoded parameters
#[derive(Clone, Debug, Serialize)]
pub struct CanisterRequest<'a> {
    /// The target canister's principal ID
    pub canister: &'a Principal,
    /// The method name to call on the canister
    pub method: &'a str,
    /// Candid-encoded parameters for the canister call.
    /// Parameters should be provided as a tuple, where each element represents a single parameter.
    /// Examples:
    /// - `()`: No parameters
    /// - `(1,)`: Single parameter
    /// - `(1, "hello", 3.14)`: Three parameters
    pub params: &'a ByteBuf,
}

/// Represents an RPC response that can be either:
/// - Ok(ByteBuf): CBOR or Candid encoded successful response
/// - Err(String): Error message as a string
pub type RPCResponse = Result<ByteBuf, String>;

/// Possible errors when working with http_rpc
#[derive(Debug, thiserror::Error)]
pub enum HttpRPCError {
    #[error("http_rpc({endpoint:?}, {path:?}): send error: {error}")]
    RequestError {
        endpoint: String,
        path: String,
        error: String,
    },

    #[error("http_rpc({endpoint:?}, {path:?}): response status {status}, error: {error}")]
    ResponseError {
        endpoint: String,
        path: String,
        status: u16,
        error: String,
    },

    #[error("http_rpc({endpoint:?}, {path:?}): parse result error: {error}")]
    ResultError {
        endpoint: String,
        path: String,
        error: String,
    },
}

/// Makes an HTTP RPC call with CBOR-encoded parameters and returns the decoded response
///
/// # Arguments
/// * `client` - HTTP client to use for the request
/// * `endpoint` - URL endpoint to send the request to
/// * `method` - RPC method name to call
/// * `args` - Arguments to serialize as CBOR and send with the request
///
/// # Returns
/// Result with either the deserialized response or an HttpRPCError
pub async fn http_rpc<T>(
    client: &Client,
    endpoint: &str,
    method: &str,
    args: &impl Serialize,
) -> Result<T, HttpRPCError>
where
    T: DeserializeOwned,
{
    let args = to_cbor_bytes(args);
    let req = RPCRequest {
        method,
        params: &args.into(),
    };

    let res = cbor_rpc(client, endpoint, method, None, to_cbor_bytes(&req)).await?;
    from_reader(&res[..]).map_err(|e| HttpRPCError::ResultError {
        endpoint: endpoint.to_string(),
        path: method.to_string(),
        error: format!("{e:?}"),
    })
}

/// Makes a canister-specific RPC call with Candid-encoded parameters
///
/// # Arguments
/// * `client` - HTTP client to use for the request
/// * `endpoint` - URL endpoint to send the request to
/// * `canister` - Target canister's principal ID
/// * `method` - Method name to call on the canister
/// * `args` - Arguments to encode using Candid
///
/// # Returns
/// Result with either the deserialized response or an HttpRPCError
pub async fn canister_rpc<In, Out>(
    client: &Client,
    endpoint: &str,
    canister: &Principal,
    method: &str,
    args: In,
) -> Result<Out, HttpRPCError>
where
    In: ArgumentEncoder,
    Out: CandidType + for<'a> candid::Deserialize<'a>,
{
    let args = encode_args(args).map_err(|e| HttpRPCError::RequestError {
        endpoint: format!("{endpoint}/{canister}"),
        path: method.to_string(),
        error: format!("{e:?}"),
    })?;
    let res = cbor_rpc(
        client,
        endpoint,
        canister,
        None,
        to_cbor_bytes(&CanisterRequest {
            canister,
            method,
            params: &ByteBuf::from(args),
        }),
    )
    .await?;
    let res: (Out,) = decode_args(&res).map_err(|e| HttpRPCError::ResultError {
        endpoint: format!("{endpoint}/{canister}"),
        path: method.to_string(),
        error: format!("{e:?}"),
    })?;
    Ok(res.0)
}

/// Internal function to make a CBOR-encoded RPC call
///
/// # Arguments
/// * `client` - HTTP client to use for the request
/// * `endpoint` - URL endpoint to send the request to
/// * `path` - Path or identifier for the request
/// * `headers` - Optional headers to include in the request
/// * `body` - CBOR-encoded request body
///
/// # Returns
/// Result with either the raw ByteBuf response or an HttpRPCError
pub async fn cbor_rpc(
    client: &Client,
    endpoint: &str,
    path: impl Display,
    headers: Option<http::HeaderMap>,
    body: Vec<u8>,
) -> Result<ByteBuf, HttpRPCError> {
    let mut headers = headers.unwrap_or_default();
    let ct: http::HeaderValue = CONTENT_TYPE_CBOR.parse().unwrap();
    headers.insert(header::CONTENT_TYPE, ct.clone());
    headers.insert(header::ACCEPT, ct);
    let res = client
        .post(endpoint)
        .headers(headers)
        .body(body)
        .send()
        .await
        .map_err(|e| HttpRPCError::RequestError {
            endpoint: endpoint.to_string(),
            path: path.to_string(),
            error: format!("{e:?}"),
        })?;
    let status = res.status().as_u16();
    if status != 200 {
        return Err(HttpRPCError::ResponseError {
            endpoint: endpoint.to_string(),
            path: path.to_string(),
            status,
            error: res.text().await.unwrap_or_default(),
        });
    }

    let data = res.bytes().await.map_err(|e| HttpRPCError::ResultError {
        endpoint: endpoint.to_string(),
        path: path.to_string(),
        error: format!("{e:?}"),
    })?;
    let res: RPCResponse = from_reader(&data[..]).map_err(|e| HttpRPCError::ResultError {
        endpoint: endpoint.to_string(),
        path: path.to_string(),
        error: format!("{e:?}"),
    })?;
    res.map_err(|e| HttpRPCError::ResultError {
        endpoint: endpoint.to_string(),
        path: path.to_string(),
        error: format!("{e:?}"),
    })
}
