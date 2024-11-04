use axum::{
    body::Body,
    extract::{Request, State},
    http::{uri::Uri, StatusCode},
    response::IntoResponse,
};
use hyper_util::{client::legacy::connect::HttpConnector, rt::TokioExecutor};
use ic_tee_agent::{agent::TEEAgent, http::ContentType};
use ic_tee_cdk::{
    CanisterRequest, TEEAppInformation, TEEAppInformationJSON, TEEAttestation, TEEAttestationJSON,
};
use ic_tee_nitro_attestation::AttestationRequest;
use std::sync::Arc;

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
    match ContentType::from(req.headers()) {
        ContentType::CBOR(_, _) => {
            ContentType::CBOR(app.info.as_ref().clone(), None).into_response()
        }
        _ => ContentType::JSON(
            TEEAppInformationJSON {
                name: app.info.name.clone(),
                version: app.info.version.clone(),
                kind: app.info.kind.clone(),
                pcr0: const_hex::encode(&app.info.pcr0),
                pcr1: const_hex::encode(&app.info.pcr1),
                pcr2: const_hex::encode(&app.info.pcr2),
                start_time_ms: app.info.start_time_ms,
                principal: app.info.principal.to_string(),
                authentication_canister: app.info.authentication_canister.to_string(),
                configuration_canister: app.info.configuration_canister.to_string(),
                registration_canister: app
                    .info
                    .registration_canister
                    .as_ref()
                    .map(|p| p.to_string()),
            },
            None,
        )
        .into_response(),
    }
}

pub async fn get_attestation(State(_app): State<AppState>, req: Request) -> impl IntoResponse {
    let res = sign_attestation(AttestationRequest {
        public_key: None,
        user_data: None,
        nonce: None,
    });

    match res {
        Err(err) => {
            ContentType::Text::<()>(err.to_string(), Some(StatusCode::INTERNAL_SERVER_ERROR))
                .into_response()
        }
        Ok(doc) => match ContentType::from(req.headers()) {
            ContentType::CBOR(_, _) => ContentType::CBOR(
                TEEAttestation {
                    kind: TEE_KIND.to_string(),
                    document: doc.into(),
                },
                None,
            )
            .into_response(),
            ContentType::JSON(_, _) => ContentType::JSON(
                TEEAttestationJSON {
                    kind: TEE_KIND.to_string(),
                    document: const_hex::encode(&doc),
                },
                None,
            )
            .into_response(),
            _ => ContentType::Text::<()>(const_hex::encode(&doc), None).into_response(),
        },
    }
}

pub async fn post_attestation(
    State(_app): State<AppState>,
    ct: ContentType<AttestationRequest>,
) -> impl IntoResponse {
    match ct {
        ContentType::CBOR(req, _) => match sign_attestation(req) {
            Ok(doc) => ContentType::CBOR(
                TEEAttestation {
                    kind: TEE_KIND.to_string(),
                    document: doc.into(),
                },
                None,
            )
            .into_response(),
            Err(err) => ContentType::Text::<()>(err, Some(StatusCode::INTERNAL_SERVER_ERROR))
                .into_response(),
        },
        ContentType::JSON(req, _) => match sign_attestation(req) {
            Ok(doc) => ContentType::JSON(
                TEEAttestationJSON {
                    kind: TEE_KIND.to_string(),
                    document: const_hex::encode(&doc),
                },
                None,
            )
            .into_response(),
            Err(err) => ContentType::Text::<()>(err, Some(StatusCode::INTERNAL_SERVER_ERROR))
                .into_response(),
        },
        _ => StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response(),
    }
}

pub async fn query_canister(
    State(app): State<AppState>,
    ct: ContentType<CanisterRequest>,
) -> impl IntoResponse {
    match ct {
        ContentType::CBOR(req, _) => {
            let res = app
                .tee_agent
                .query_call_raw(&req.canister, &req.method, req.params.to_vec())
                .await;
            ContentType::CBOR(res, None).into_response()
        }
        _ => StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response(),
    }
}

pub async fn update_canister(
    State(app): State<AppState>,
    ct: ContentType<CanisterRequest>,
) -> impl IntoResponse {
    match ct {
        ContentType::CBOR(req, _) => {
            let res = app
                .tee_agent
                .update_call_raw(&req.canister, &req.method, req.params.to_vec())
                .await;
            ContentType::CBOR(res, None).into_response()
        }
        _ => StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response(),
    }
}

pub async fn proxy(State(app): State<AppState>, mut req: Request) -> impl IntoResponse {
    let port = if let Some(port) = app.upstream_port {
        port
    } else {
        return ContentType::Text::<()>(
            "The resource could not be found.\nic_tee_nitro_gateway".to_string(),
            Some(StatusCode::NOT_FOUND),
        )
        .into_response();
    };

    let path = req.uri().path();
    let path_query = req
        .uri()
        .path_and_query()
        .map(|v| v.as_str())
        .unwrap_or(path);

    let uri = format!("http://127.0.0.1:{}{}", port, path_query);

    *req.uri_mut() = Uri::try_from(uri).unwrap();

    match app.http_client.request(req).await {
        Ok(res) => res.into_response(),
        Err(err) => {
            ContentType::Text::<()>(err.to_string(), Some(StatusCode::INTERNAL_SERVER_ERROR))
                .into_response()
        }
    }
}
