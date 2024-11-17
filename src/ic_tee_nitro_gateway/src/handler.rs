use axum::{
    body::Body,
    extract::{Request, State},
    http::{uri::Uri, StatusCode},
    response::IntoResponse,
};
use candid::Principal;
use hyper_util::{client::legacy::connect::HttpConnector, rt::TokioExecutor};
use ic_tee_agent::{
    agent::TEEAgent,
    http::{Content, UserSignature, HEADER_IC_TEE_CALLER, HEADER_IC_TEE_ID},
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

pub async fn get_information(State(app): State<AppState>, req: Request) -> impl IntoResponse {
    let mut info = app.info.as_ref().clone();
    info.caller = if let Some(sig) = UserSignature::try_from(req.headers()) {
        match sig.validate_request(unix_ms(), app.info.id) {
            Ok(_) => sig.user,
            Err(_) => Principal::anonymous(),
        }
    } else {
        Principal::anonymous()
    };

    match Content::from(req.headers()) {
        Content::CBOR(_, _) => Content::CBOR(info, None).into_response(),
        _ => Content::JSON(
            TEEAppInformationJSON {
                id: app.info.id.to_string(),
                name: app.info.name.clone(),
                version: app.info.version.clone(),
                kind: app.info.kind.clone(),
                pcr0: const_hex::encode(&app.info.pcr0),
                pcr1: const_hex::encode(&app.info.pcr1),
                pcr2: const_hex::encode(&app.info.pcr2),
                start_time_ms: app.info.start_time_ms,
                authentication_canister: app.info.authentication_canister.to_string(),
                configuration_canister: app.info.configuration_canister.to_string(),
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

pub async fn get_attestation(State(app): State<AppState>, req: Request) -> impl IntoResponse {
    let caller = if let Some(sig) = UserSignature::try_from(req.headers()) {
        match sig.validate_request(unix_ms(), app.info.id) {
            Ok(_) => sig.user,
            Err(_) => Principal::anonymous(),
        }
    } else {
        Principal::anonymous()
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

pub async fn query_canister(
    State(app): State<AppState>,
    ct: Content<CanisterRequest>,
) -> impl IntoResponse {
    match ct {
        Content::CBOR(req, _) => {
            let res = app
                .tee_agent
                .query_call_raw(&req.canister, &req.method, req.params.to_vec())
                .await;
            Content::CBOR(res, None).into_response()
        }
        _ => StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response(),
    }
}

pub async fn update_canister(
    State(app): State<AppState>,
    ct: Content<CanisterRequest>,
) -> impl IntoResponse {
    match ct {
        Content::CBOR(req, _) => {
            let res = app
                .tee_agent
                .update_call_raw(&req.canister, &req.method, req.params.to_vec())
                .await;
            Content::CBOR(res, None).into_response()
        }
        _ => StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response(),
    }
}

pub async fn proxy(
    State(app): State<AppState>,
    mut req: Request,
) -> Result<impl IntoResponse, Content<String>> {
    let port = if let Some(port) = app.upstream_port {
        port
    } else {
        return Err(Content::Text(
            "The resource could not be found.\nic_tee_nitro_gateway".to_string(),
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
        Principal::anonymous()
    };

    let path = req.uri().path();
    let path_query = req
        .uri()
        .path_and_query()
        .map(|v| v.as_str())
        .unwrap_or(path);

    let uri = format!("http://127.0.0.1:{}{}", port, path_query);

    *req.uri_mut() = Uri::try_from(uri)
        .map_err(|err| Content::Text(err.to_string(), Some(StatusCode::BAD_REQUEST)))?;
    req.headers_mut().insert(
        &HEADER_IC_TEE_ID,
        app.info.id.to_string().parse().map_err(|_| {
            Content::Text(
                "unexpected TEE ID".to_string(),
                Some(StatusCode::BAD_REQUEST),
            )
        })?,
    );
    req.headers_mut().insert(
        &HEADER_IC_TEE_CALLER,
        caller.to_string().parse().map_err(|_| {
            Content::Text(
                "unexpected caller ID".to_string(),
                Some(StatusCode::BAD_REQUEST),
            )
        })?,
    );

    match app.http_client.request(req).await {
        Ok(res) => Ok(res.into_response()),
        Err(err) => Err(Content::Text(
            err.to_string(),
            Some(StatusCode::INTERNAL_SERVER_ERROR),
        )),
    }
}
