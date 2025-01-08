use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, uri::Uri, StatusCode},
    response::IntoResponse,
};
use ciborium::from_reader;
use hyper_util::{client::legacy::connect::HttpConnector, rt::TokioExecutor};
use ic_cose_types::{format_error, to_cbor_bytes, types::ECDHInput};
use ic_tee_agent::{
    agent::TEEAgent,
    http::{
        Content, UserSignature, ANONYMOUS_PRINCIPAL, HEADER_IC_TEE_CALLER,
        HEADER_IC_TEE_CONTENT_DIGEST, HEADER_IC_TEE_DELEGATION, HEADER_IC_TEE_ID,
        HEADER_IC_TEE_INSTANCE, HEADER_IC_TEE_PUBKEY, HEADER_IC_TEE_SIGNATURE,
        HEADER_X_FORWARDED_FOR, HEADER_X_FORWARDED_HOST, HEADER_X_FORWARDED_PROTO,
    },
    RPCRequest, RPCResponse,
};
use ic_tee_cdk::{
    CanisterRequest, TEEAppInformation, TEEAppInformationJSON, TEEAttestation, TEEAttestationJSON,
};
use ic_tee_nitro_attestation::AttestationRequest;
use serde_bytes::ByteBuf;
use std::sync::Arc;
use structured_logger::unix_ms;

use crate::{attestation::sign_attestation, TEE_KIND};

type Client = hyper_util::client::legacy::Client<HttpConnector, Body>;

pub fn new_client() -> Client {
    hyper_util::client::legacy::Client::<(), ()>::builder(TokioExecutor::new())
        .build(HttpConnector::new())
}

#[derive(Clone)]
pub struct AppState {
    pub info: Arc<TEEAppInformation>,
    pub http_client: Arc<Client>,
    pub tee_agent: Arc<TEEAgent>,
    pub upstream_port: Option<u16>,
}

/// local_server: GET /information
/// public_server: GET /.well-known/information
pub async fn get_information(State(app): State<AppState>, req: Request) -> impl IntoResponse {
    let mut info = app.info.as_ref().clone();
    info.caller = if let Some(sig) = UserSignature::try_from(req.headers()) {
        match sig.validate_request(unix_ms(), app.info.id) {
            Ok(_) => sig.user,
            Err(_) => ANONYMOUS_PRINCIPAL,
        }
    } else {
        ANONYMOUS_PRINCIPAL
    };

    match Content::from(req.headers()) {
        Content::CBOR(_, _) => Content::CBOR(info, None).into_response(),
        _ => Content::JSON(
            TEEAppInformationJSON {
                id: app.info.id.to_string(),
                instance: app.info.instance.clone(),
                name: app.info.name.clone(),
                version: app.info.version.clone(),
                kind: app.info.kind.clone(),
                pcr0: const_hex::encode(&app.info.pcr0),
                pcr1: const_hex::encode(&app.info.pcr1),
                pcr2: const_hex::encode(&app.info.pcr2),
                start_time_ms: app.info.start_time_ms,
                identity_canister: app.info.identity_canister.to_string(),
                cose_canister: app.info.cose_canister.to_string(),
                registration_canister: app
                    .info
                    .registration_canister
                    .as_ref()
                    .map(|p| p.to_string()),
                caller: info.caller.to_string(),
            },
            None,
        )
        .into_response(),
    }
}

/// local_server: GET /attestation
/// public_server: GET /.well-known/attestation
pub async fn get_attestation(State(app): State<AppState>, req: Request) -> impl IntoResponse {
    let caller = if let Some(sig) = UserSignature::try_from(req.headers()) {
        match sig.validate_request(unix_ms(), app.info.id) {
            Ok(_) => sig.user,
            Err(_) => ANONYMOUS_PRINCIPAL,
        }
    } else {
        ANONYMOUS_PRINCIPAL
    };

    let res = sign_attestation(AttestationRequest {
        public_key: None,
        user_data: Some(ByteBuf::from(caller.as_slice())),
        nonce: None,
    });

    match res {
        Err(err) => Content::Text::<()>(err.to_string(), Some(StatusCode::INTERNAL_SERVER_ERROR))
            .into_response(),
        Ok(doc) => match Content::from(req.headers()) {
            Content::CBOR(_, _) => Content::CBOR(
                TEEAttestation {
                    kind: TEE_KIND.to_string(),
                    document: doc.into(),
                },
                None,
            )
            .into_response(),
            Content::JSON(_, _) => Content::JSON(
                TEEAttestationJSON {
                    kind: TEE_KIND.to_string(),
                    document: const_hex::encode(&doc),
                },
                None,
            )
            .into_response(),
            _ => Content::Text::<()>(const_hex::encode(&doc), None).into_response(),
        },
    }
}

/// local_server: POST /attestation
pub async fn post_attestation(
    State(_app): State<AppState>,
    ct: Content<AttestationRequest>,
) -> impl IntoResponse {
    match ct {
        Content::CBOR(req, _) => match sign_attestation(req) {
            Ok(doc) => Content::CBOR(
                TEEAttestation {
                    kind: TEE_KIND.to_string(),
                    document: doc.into(),
                },
                None,
            )
            .into_response(),
            Err(err) => {
                Content::Text::<()>(err, Some(StatusCode::INTERNAL_SERVER_ERROR)).into_response()
            }
        },
        Content::JSON(req, _) => match sign_attestation(req) {
            Ok(doc) => Content::JSON(
                TEEAttestationJSON {
                    kind: TEE_KIND.to_string(),
                    document: const_hex::encode(&doc),
                },
                None,
            )
            .into_response(),
            Err(err) => {
                Content::Text::<()>(err, Some(StatusCode::INTERNAL_SERVER_ERROR)).into_response()
            }
        },
        _ => StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response(),
    }
}

/// local_server: POST /canister/query
pub async fn query_canister(
    State(app): State<AppState>,
    ct: Content<CanisterRequest>,
) -> impl IntoResponse {
    match ct {
        Content::CBOR(req, _) => {
            if forbid_canister_request(&req, app.info.as_ref()) {
                return StatusCode::FORBIDDEN.into_response();
            }
            let res = app
                .tee_agent
                .query_call_raw(&req.canister, &req.method, req.params.to_vec())
                .await;
            Content::CBOR(res, None).into_response()
        }
        _ => StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response(),
    }
}

/// local_server: POST /canister/update
pub async fn update_canister(
    State(app): State<AppState>,
    ct: Content<CanisterRequest>,
) -> impl IntoResponse {
    match ct {
        Content::CBOR(req, _) => {
            if forbid_canister_request(&req, app.info.as_ref()) {
                return StatusCode::FORBIDDEN.into_response();
            }
            let res = app
                .tee_agent
                .update_call_raw(&req.canister, &req.method, req.params.to_vec())
                .await;
            Content::CBOR(res, None).into_response()
        }
        _ => StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response(),
    }
}

/// local_server: POST /keys
pub async fn call_keys(State(app): State<AppState>, ct: Content<RPCRequest>) -> impl IntoResponse {
    match ct {
        Content::CBOR(req, _) => {
            let res = handle_keys_request(&req, app.tee_agent.as_ref());
            Content::CBOR(res, None).into_response()
        }
        _ => StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response(),
    }
}

/// Handles all other public server requests and proxies them to the upstream service.
///
/// If the request contains valid headers for `ic-tee-pubkey`, `ic-tee-content-digest`,
/// `ic-tee-signature`, and `ic-tee-delegation`, they will be verified. Failed verification
/// results in a 401 response. Successful verification adds `ic-tee-id` and `ic-tee-caller`
/// headers to identify the caller. Otherwise, the request is treated as anonymous that without `ic-tee-caller` header.
pub async fn proxy(
    State(app): State<AppState>,
    mut req: Request,
) -> Result<impl IntoResponse, Content<String>> {
    let port = if let Some(port) = app.upstream_port {
        port
    } else {
        return Err(Content::Text(
            "The resource could not be found.\n-- ic_tee_nitro_gateway".to_string(),
            Some(StatusCode::NOT_FOUND),
        ));
    };

    let caller = if let Some(sig) = UserSignature::try_from(req.headers()) {
        match sig.validate_request(unix_ms(), app.info.id) {
            Ok(_) => sig.user,
            Err(err) => {
                return Err(Content::Text(
                    err.to_string(),
                    Some(StatusCode::UNAUTHORIZED),
                ));
            }
        }
    } else {
        ANONYMOUS_PRINCIPAL
    };

    let headers = req.headers_mut();
    headers.remove(&header::FORWARDED);
    headers.remove(&HEADER_X_FORWARDED_FOR);
    headers.remove(&HEADER_X_FORWARDED_HOST);
    headers.remove(&HEADER_X_FORWARDED_PROTO);
    headers.remove(&HEADER_IC_TEE_PUBKEY);
    headers.remove(&HEADER_IC_TEE_CONTENT_DIGEST);
    headers.remove(&HEADER_IC_TEE_SIGNATURE);
    headers.remove(&HEADER_IC_TEE_DELEGATION);

    headers.insert(
        &HEADER_IC_TEE_CALLER,
        caller.to_string().parse().map_err(|_| {
            Content::Text(
                "unexpected caller ID".to_string(),
                Some(StatusCode::BAD_REQUEST),
            )
        })?,
    );
    headers.insert(
        &HEADER_IC_TEE_ID,
        app.info.id.to_string().parse().map_err(|_| {
            Content::Text(
                "unexpected TEE ID".to_string(),
                Some(StatusCode::BAD_REQUEST),
            )
        })?,
    );
    headers.insert(
        &HEADER_IC_TEE_INSTANCE,
        app.info.instance.parse().map_err(|_| {
            Content::Text(
                "unexpected TEE instance".to_string(),
                Some(StatusCode::BAD_REQUEST),
            )
        })?,
    );

    let path = req.uri().path();
    let path_query = req
        .uri()
        .path_and_query()
        .map(|v| v.as_str())
        .unwrap_or(path);

    let uri = format!("http://127.0.0.1:{}{}", port, path_query);

    *req.uri_mut() = Uri::try_from(uri)
        .map_err(|err| Content::Text(err.to_string(), Some(StatusCode::BAD_REQUEST)))?;

    match app.http_client.request(req).await {
        Ok(res) => Ok(res.into_response()),
        Err(err) => Err(Content::Text(
            err.to_string(),
            Some(StatusCode::INTERNAL_SERVER_ERROR),
        )),
    }
}

fn handle_keys_request(req: &RPCRequest, agent: &TEEAgent) -> RPCResponse {
    match req.method.as_str() {
        "a256gcm_key" => {
            let params: (Vec<ByteBuf>,) =
                from_reader(req.params.as_slice()).map_err(format_error)?;
            let res = agent.a256gcm_key(params.0);
            Ok(to_cbor_bytes(&res).into())
        }
        "a256gcm_ecdh_key" => {
            let params: (Vec<ByteBuf>, ECDHInput) =
                from_reader(req.params.as_slice()).map_err(format_error)?;
            let res = agent.a256gcm_ecdh_key(params.0, &params.1);
            Ok(to_cbor_bytes(&res).into())
        }
        "ed25519_sign_message" => {
            let params: (Vec<ByteBuf>, ByteBuf) =
                from_reader(req.params.as_slice()).map_err(format_error)?;
            let res = agent.ed25519_sign_message(params.0, &params.1);
            Ok(to_cbor_bytes(&res).into())
        }
        "ed25519_public_key" => {
            let params: (Vec<ByteBuf>,) =
                from_reader(req.params.as_slice()).map_err(format_error)?;
            let res = agent.ed25519_public_key(params.0);
            Ok(to_cbor_bytes(&res).into())
        }
        "secp256k1_sign_message_bip340" => {
            let params: (Vec<ByteBuf>, ByteBuf) =
                from_reader(req.params.as_slice()).map_err(format_error)?;
            let res = agent.secp256k1_sign_message_bip340(params.0, &params.1);
            Ok(to_cbor_bytes(&res).into())
        }
        "secp256k1_sign_message_ecdsa" => {
            let params: (Vec<ByteBuf>, ByteBuf) =
                from_reader(req.params.as_slice()).map_err(format_error)?;
            let res = agent.secp256k1_sign_message_ecdsa(params.0, &params.1);
            Ok(to_cbor_bytes(&res).into())
        }
        "secp256k1_public_key" => {
            let params: (Vec<ByteBuf>,) =
                from_reader(req.params.as_slice()).map_err(format_error)?;
            let res = agent.secp256k1_public_key(params.0);
            Ok(to_cbor_bytes(&res).into())
        }
        _ => Err(format!("unsupported method {}", req.method)),
    }
}

fn forbid_canister_request(req: &CanisterRequest, info: &TEEAppInformation) -> bool {
    if req.canister == info.identity_canister {
        return true;
    }

    if req.canister == info.cose_canister {
        return matches!(
            req.method.as_str(),
            "namespace_sign_delegation" | "get_delegation"
        );
    }

    false
}
