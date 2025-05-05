use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, uri::Uri, HeaderMap, StatusCode, Version},
    response::IntoResponse,
};
use candid::decode_args;
use ciborium::from_reader;
use hyper_util::{client::legacy::connect::HttpConnector, rt::TokioExecutor};
use ic_auth_verifier::envelope::{
    SignedEnvelope, ANONYMOUS_PRINCIPAL, HEADER_IC_AUTH_DELEGATION, HEADER_IC_AUTH_PUBKEY,
    HEADER_IC_AUTH_SIGNATURE, HEADER_IC_AUTH_USER,
};
use ic_cose_types::{
    format_error, to_cbor_bytes,
    types::{ECDHInput, ECDHOutput, SettingPath},
};
use ic_tee_agent::{
    agent::TEEAgent,
    http::{
        Content, HEADER_IC_TEE_ID, HEADER_IC_TEE_INSTANCE, HEADER_X_FORWARDED_FOR,
        HEADER_X_FORWARDED_HOST, HEADER_X_FORWARDED_PROTO,
    },
    RPCRequest, RPCResponse,
};
use ic_tee_cdk::{
    AttestationUserRequest, CanisterRequest, TEEAppInformation, TEEAppInformationJSON,
    TEEAttestation, TEEAttestationJSON,
};
use ic_tee_gateway_sdk::crypto;
use ic_tee_nitro_attestation::AttestationRequest;
use serde_bytes::{ByteArray, ByteBuf};
use std::{collections::HashMap, sync::Arc};
use structured_logger::unix_ms;

use crate::{attestation::sign_attestation, TEE_KIND};

type Client = hyper_util::client::legacy::Client<HttpConnector, Body>;

#[derive(Clone)]
pub struct AppState {
    info: Arc<TEEAppInformation>,
    http_client: Arc<Client>,
    tee_agent: Arc<TEEAgent>,
    root_secret: [u8; 48],
    upstream_port: Option<u16>,
    cose_namespace: String,
    app_basic_token: Option<String>,
}

impl AppState {
    pub fn new(
        info: Arc<TEEAppInformation>,
        tee_agent: Arc<TEEAgent>,
        root_secret: [u8; 48],
        upstream_port: Option<u16>,
        cose_namespace: String,
        app_basic_token: Option<String>,
    ) -> Self {
        let http_client = Arc::new(
            hyper_util::client::legacy::Client::<(), ()>::builder(TokioExecutor::new())
                .build(HttpConnector::new()),
        );

        Self {
            info,
            http_client,
            tee_agent,
            root_secret,
            upstream_port,
            cose_namespace,
            app_basic_token,
        }
    }

    pub fn valid_session(&self, headers: &HeaderMap) -> bool {
        if let Some(app_basic_token) = &self.app_basic_token {
            if let Some(token) = headers.get(header::AUTHORIZATION) {
                if let Ok(token) = token.to_str() {
                    return token.trim_start_matches("Basic ") == app_basic_token;
                }
            }
            return false;
        }
        true
    }

    pub fn a256gcm_key(&self, derivation_path: Vec<ByteBuf>) -> ByteArray<32> {
        crypto::a256gcm_key(
            &self.root_secret,
            derivation_path.into_iter().map(|v| v.into_vec()).collect(),
        )
    }

    pub fn a256gcm_ecdh_key(
        &self,
        derivation_path: Vec<ByteBuf>,
        ecdh: &ECDHInput,
    ) -> ECDHOutput<ByteBuf> {
        crypto::a256gcm_ecdh_key(
            &self.root_secret,
            derivation_path.into_iter().map(|v| v.into_vec()).collect(),
            ecdh,
        )
    }

    pub fn ed25519_sign_message(&self, derivation_path: Vec<ByteBuf>, msg: &[u8]) -> ByteArray<64> {
        crypto::ed25519_sign_message(
            &self.root_secret,
            derivation_path.into_iter().map(|v| v.into_vec()).collect(),
            msg,
        )
    }

    pub fn ed25519_public_key(
        &self,
        derivation_path: Vec<ByteBuf>,
    ) -> (ByteArray<32>, ByteArray<32>) {
        crypto::ed25519_public_key(
            &self.root_secret,
            derivation_path.into_iter().map(|v| v.into_vec()).collect(),
        )
    }

    pub fn secp256k1_sign_message_bip340(
        &self,
        derivation_path: Vec<ByteBuf>,
        msg: &[u8],
    ) -> ByteArray<64> {
        crypto::secp256k1_sign_message_bip340(
            &self.root_secret,
            derivation_path.into_iter().map(|v| v.into_vec()).collect(),
            msg,
        )
    }

    pub fn secp256k1_sign_message_ecdsa(
        &self,
        derivation_path: Vec<ByteBuf>,
        msg: &[u8],
    ) -> ByteArray<64> {
        crypto::secp256k1_sign_message_ecdsa(
            &self.root_secret,
            derivation_path.into_iter().map(|v| v.into_vec()).collect(),
            msg,
        )
    }

    pub fn secp256k1_sign_digest_ecdsa(
        &self,
        derivation_path: Vec<ByteBuf>,
        msg_hash: &[u8],
    ) -> ByteArray<64> {
        crypto::secp256k1_sign_digest_ecdsa(
            &self.root_secret,
            derivation_path.into_iter().map(|v| v.into_vec()).collect(),
            msg_hash,
        )
    }

    pub fn secp256k1_public_key(
        &self,
        derivation_path: Vec<ByteBuf>,
    ) -> (ByteArray<33>, ByteArray<32>) {
        crypto::secp256k1_public_key(
            &self.root_secret,
            derivation_path.into_iter().map(|v| v.into_vec()).collect(),
        )
    }
}

/// local_server: GET /information
/// public_server: GET /.well-known/information
pub async fn get_information(State(app): State<AppState>, req: Request) -> impl IntoResponse {
    let mut info = app.info.as_ref().clone();
    info.caller = if let Some(se) = SignedEnvelope::from_authorization(req.headers())
        .or_else(|| SignedEnvelope::from_headers(req.headers()))
    {
        match se.verify(unix_ms(), Some(app.info.id), None) {
            Ok(_) => se.sender(),
            Err(_) => ANONYMOUS_PRINCIPAL,
        }
    } else {
        ANONYMOUS_PRINCIPAL
    };

    match Content::from(req.headers()) {
        Content::CBOR(_, _) => Content::CBOR(info, None).into_response(),
        _ => Content::JSON(
            TEEAppInformationJSON {
                id: info.id.to_string(),
                instance: info.instance,
                name: info.name,
                version: info.version,
                kind: info.kind,
                pcr0: const_hex::encode(&info.pcr0),
                pcr1: const_hex::encode(&info.pcr1),
                pcr2: const_hex::encode(&info.pcr2),
                start_time_ms: info.start_time_ms,
                identity_canister: info.identity_canister.to_string(),
                cose_canister: info.cose_canister.to_string(),
                registration_canister: info.registration_canister.as_ref().map(|p| p.to_string()),
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
    let caller = if let Some(se) = SignedEnvelope::from_authorization(req.headers())
        .or_else(|| SignedEnvelope::from_headers(req.headers()))
    {
        match se.verify(unix_ms(), Some(app.info.id), None) {
            Ok(_) => se.sender(),
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
pub async fn local_sign_attestation(
    State(app): State<AppState>,
    headers: HeaderMap,
    cr: Content<AttestationUserRequest<ByteBuf>>,
) -> impl IntoResponse {
    if !app.valid_session(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    match cr {
        Content::CBOR(req, _) => match sign_attestation(AttestationRequest {
            user_data: Some(ByteBuf::from(to_cbor_bytes(&req))),
            ..Default::default()
        }) {
            Ok(doc) => Content::CBOR(
                TEEAttestation {
                    kind: TEE_KIND.to_string(),
                    document: doc.into(),
                },
                None,
            )
            .into_response(),
            Err(err) => {
                Content::Text::<()>(err.to_string(), Some(StatusCode::INTERNAL_SERVER_ERROR))
                    .into_response()
            }
        },
        Content::JSON(req, _) => match sign_attestation(AttestationRequest {
            user_data: Some(ByteBuf::from(to_cbor_bytes(&req))),
            ..Default::default()
        }) {
            Ok(doc) => Content::JSON(
                TEEAttestationJSON {
                    kind: TEE_KIND.to_string(),
                    document: const_hex::encode(&doc),
                },
                None,
            )
            .into_response(),
            Err(err) => {
                Content::Text::<()>(err.to_string(), Some(StatusCode::INTERNAL_SERVER_ERROR))
                    .into_response()
            }
        },
        _ => StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response(),
    }
}

/// local_server: POST /canister/query
pub async fn local_query_canister(
    State(app): State<AppState>,
    headers: HeaderMap,
    ct: Content<CanisterRequest>,
) -> impl IntoResponse {
    if !app.valid_session(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    match ct {
        Content::CBOR(req, _) => {
            if forbid_canister_request(&app.cose_namespace, &req, app.info.as_ref()) {
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
pub async fn local_update_canister(
    State(app): State<AppState>,
    headers: HeaderMap,
    ct: Content<CanisterRequest>,
) -> impl IntoResponse {
    if !app.valid_session(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    match ct {
        Content::CBOR(req, _) => {
            if forbid_canister_request(&app.cose_namespace, &req, app.info.as_ref()) {
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
pub async fn local_call_keys(
    State(app): State<AppState>,
    headers: HeaderMap,
    ct: Content<RPCRequest>,
) -> impl IntoResponse {
    if !app.valid_session(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    match ct {
        Content::CBOR(req, _) => {
            let res = handle_keys_request(&req, &app);
            Content::CBOR(res, None).into_response()
        }
        _ => StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response(),
    }
}

/// local_server: POST /identity
pub async fn local_call_identity(
    State(app): State<AppState>,
    headers: HeaderMap,
    ct: Content<RPCRequest>,
) -> impl IntoResponse {
    if !app.valid_session(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    match ct {
        Content::CBOR(req, _) => {
            let res = handle_identity_request(&req, &app).await;
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

    let caller = if let Some(se) = SignedEnvelope::from_authorization(req.headers())
        .or_else(|| SignedEnvelope::from_headers(req.headers()))
    {
        match se.verify(unix_ms(), Some(app.info.id), None) {
            Ok(_) => se.sender(),
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
    headers.remove(&HEADER_IC_AUTH_PUBKEY);
    // headers.remove(&HEADER_IC_AUTH_CONTENT_DIGEST); keep it to verify the digest in upstream
    headers.remove(&HEADER_IC_AUTH_SIGNATURE);
    headers.remove(&HEADER_IC_AUTH_DELEGATION);

    headers.insert(
        &HEADER_IC_AUTH_USER,
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
    *req.version_mut() = Version::HTTP_11;

    match app.http_client.request(req).await {
        Ok(res) => Ok(res.into_response()),
        Err(err) => Err(Content::Text(
            err.to_string(),
            Some(StatusCode::BAD_REQUEST),
        )),
    }
}

async fn handle_identity_request(req: &RPCRequest, app: &AppState) -> RPCResponse {
    match req.method.as_str() {
        "sign_http" => {
            let (digest,): (ByteArray<32>,) =
                from_reader(req.params.as_slice()).map_err(format_error)?;
            let se =
                SignedEnvelope::sign_digest(&app.tee_agent.identity, digest.into_array().into())?;
            let mut headers = HeaderMap::new();
            se.to_headers(&mut headers)?;
            let headers: HashMap<&str, &str> = headers
                .iter()
                .map(|(k, v)| (k.as_str(), v.to_str().unwrap()))
                .collect();
            Ok(to_cbor_bytes(&headers).into())
        }
        // "sign_delegation" => {}
        _ => Err(format!("unsupported method {}", req.method)),
    }
}

fn handle_keys_request(req: &RPCRequest, app: &AppState) -> RPCResponse {
    match req.method.as_str() {
        "a256gcm_key" => {
            let params: (Vec<ByteBuf>,) =
                from_reader(req.params.as_slice()).map_err(format_error)?;
            let res = app.a256gcm_key(params.0);
            Ok(to_cbor_bytes(&res).into())
        }
        "a256gcm_ecdh_key" => {
            let params: (Vec<ByteBuf>, ECDHInput) =
                from_reader(req.params.as_slice()).map_err(format_error)?;
            let res = app.a256gcm_ecdh_key(params.0, &params.1);
            Ok(to_cbor_bytes(&res).into())
        }
        "ed25519_sign_message" => {
            let params: (Vec<ByteBuf>, ByteBuf) =
                from_reader(req.params.as_slice()).map_err(format_error)?;
            let res = app.ed25519_sign_message(params.0, &params.1);
            Ok(to_cbor_bytes(&res).into())
        }
        "ed25519_public_key" => {
            let params: (Vec<ByteBuf>,) =
                from_reader(req.params.as_slice()).map_err(format_error)?;
            let res = app.ed25519_public_key(params.0);
            Ok(to_cbor_bytes(&res).into())
        }
        "secp256k1_sign_message_bip340" => {
            let params: (Vec<ByteBuf>, ByteBuf) =
                from_reader(req.params.as_slice()).map_err(format_error)?;
            let res = app.secp256k1_sign_message_bip340(params.0, &params.1);
            Ok(to_cbor_bytes(&res).into())
        }
        "secp256k1_sign_message_ecdsa" => {
            let params: (Vec<ByteBuf>, ByteBuf) =
                from_reader(req.params.as_slice()).map_err(format_error)?;
            let res = app.secp256k1_sign_message_ecdsa(params.0, &params.1);
            Ok(to_cbor_bytes(&res).into())
        }
        "secp256k1_sign_digest_ecdsa" => {
            let params: (Vec<ByteBuf>, ByteBuf) =
                from_reader(req.params.as_slice()).map_err(format_error)?;
            let res = app.secp256k1_sign_digest_ecdsa(params.0, &params.1);
            Ok(to_cbor_bytes(&res).into())
        }
        "secp256k1_public_key" => {
            let params: (Vec<ByteBuf>,) =
                from_reader(req.params.as_slice()).map_err(format_error)?;
            let res = app.secp256k1_public_key(params.0);
            Ok(to_cbor_bytes(&res).into())
        }
        _ => Err(format!("unsupported method {}", req.method)),
    }
}

fn forbid_canister_request(ns: &str, req: &CanisterRequest, info: &TEEAppInformation) -> bool {
    if req.canister == info.identity_canister {
        return true;
    }

    if req.canister == info.cose_canister {
        if matches!(
            req.method.as_str(),
            "namespace_sign_delegation" | "get_delegation"
        ) {
            return true;
        }

        let path = match req.method.as_str() {
            "ecdh_cose_encrypted_key" => {
                let res: Result<(SettingPath, ECDHInput), _> = decode_args(req.params.as_slice());
                match res {
                    Ok((path, _)) => path,
                    _ => return true,
                }
            }
            "vetkd_public_key" => {
                let res: Result<(SettingPath,), _> = decode_args(req.params.as_slice());
                match res {
                    Ok((path,)) => path,
                    _ => return true,
                }
            }
            "vetkd_encrypted_key" => {
                let res: Result<(SettingPath, ByteArray<48>), _> =
                    decode_args(req.params.as_slice());
                match res {
                    Ok((path, _)) => path,
                    _ => return true,
                }
            }
            _ => return false,
        };

        return path.ns == ns && path.subject == Some(info.id) && path.user_owned;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use candid::{decode_args, encode_args, Principal};
    use ic_cose::rand_bytes;
    use ic_cose_types::{
        cose::ecdh,
        types::{state::StateInfo, ECDHOutput, SettingPath},
    };
    use ic_tee_agent::http::CONTENT_TYPE_CBOR;
    use ic_tee_cdk::CanisterResponse;

    static TEE_HOST: &str = "http://127.0.0.1:8080";
    // static TEE_ID: &str = "m6a24-ioo3h-wtn6z-rntjm-rkzgw-24nrf-2x6jb-znzpt-7uctp-akavf-yqe";
    static COSE_CANISTER: &str = "53cyg-yyaaa-aaaap-ahpua-cai";

    #[tokio::test(flavor = "current_thread")]
    #[ignore]
    async fn test_local_call_canister() {
        let client = reqwest::Client::new();

        // local_query_canister
        {
            let params = encode_args(()).unwrap();
            let req = CanisterRequest {
                canister: Principal::from_text(COSE_CANISTER).unwrap(),
                method: "state_get_info".to_string(),
                params: params.into(),
            };
            let res = client
                .post(format!("{}/canister/query", TEE_HOST))
                .header(&header::CONTENT_TYPE, CONTENT_TYPE_CBOR)
                .body(to_cbor_bytes(&req))
                .send()
                .await
                .unwrap();
            assert!(res.status().is_success());
            assert_eq!(
                res.headers().get(header::CONTENT_TYPE).unwrap(),
                CONTENT_TYPE_CBOR
            );

            let data = res.bytes().await.unwrap();
            let res: CanisterResponse = from_reader(&data[..]).unwrap();
            assert!(res.is_ok());
            let res: (Result<StateInfo, String>,) = decode_args(&res.unwrap()).unwrap();
            let res = res.0.unwrap();
            assert_eq!(res.name, "LDC Labs");
            assert_eq!(res.schnorr_key_name, "dfx_test_key");
        }

        // local_update_canister
        {
            let nonce: [u8; 12] = rand_bytes();
            let secret: [u8; 32] = rand_bytes();
            let secret = ecdh::StaticSecret::from(secret);
            let public = ecdh::PublicKey::from(&secret);
            let params = encode_args((
                SettingPath {
                    ns: "_".to_string(),
                    key: "v1".as_bytes().to_vec().into(),
                    ..Default::default()
                },
                ECDHInput {
                    nonce: nonce.into(),
                    public_key: public.to_bytes().into(),
                },
            ))
            .unwrap();
            let req = CanisterRequest {
                canister: Principal::from_text(COSE_CANISTER).unwrap(),
                method: "ecdh_cose_encrypted_key".to_string(),
                params: params.into(),
            };
            let res = client
                .post(format!("{}/canister/update", TEE_HOST))
                .header(&header::CONTENT_TYPE, CONTENT_TYPE_CBOR)
                .body(to_cbor_bytes(&req))
                .send()
                .await
                .unwrap();
            assert!(res.status().is_success());
            assert_eq!(
                res.headers().get(header::CONTENT_TYPE).unwrap(),
                CONTENT_TYPE_CBOR
            );

            let data = res.bytes().await.unwrap();
            let res: CanisterResponse = from_reader(&data[..]).unwrap();
            assert!(res.is_ok());
            let res: (Result<ECDHOutput<ByteBuf>, String>,) = decode_args(&res.unwrap()).unwrap();
            assert!(res.0.is_ok());
        }
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore]
    async fn test_local_call_keys() {
        let client = reqwest::Client::new();

        let nonce: [u8; 12] = rand_bytes();
        let secret: [u8; 32] = rand_bytes();
        let secret = ecdh::StaticSecret::from(secret);
        let public = ecdh::PublicKey::from(&secret);
        let params = to_cbor_bytes(&(
            &[0u8; 0],
            &ECDHInput {
                nonce: nonce.into(),
                public_key: public.to_bytes().into(),
            },
        ));
        let req = RPCRequest {
            method: "a256gcm_ecdh_key".to_string(),
            params: params.into(),
        };
        let res = client
            .post(format!("{}/keys", TEE_HOST))
            .header(&header::CONTENT_TYPE, CONTENT_TYPE_CBOR)
            .body(to_cbor_bytes(&req))
            .send()
            .await
            .unwrap();
        assert!(res.status().is_success());
        assert_eq!(
            res.headers().get(header::CONTENT_TYPE).unwrap(),
            CONTENT_TYPE_CBOR
        );

        let data = res.bytes().await.unwrap();
        let res: RPCResponse = from_reader(&data[..]).unwrap();
        assert!(res.is_ok());
        let res: ECDHOutput<ByteBuf> = from_reader(res.unwrap().as_slice()).unwrap();
        let key = crypto::decrypt_ecdh(secret.to_bytes(), &res).unwrap();
        assert_eq!(key.len(), 32);
    }
}
