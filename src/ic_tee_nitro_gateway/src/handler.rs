use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, uri::Uri, HeaderMap, HeaderValue, StatusCode, Version},
    response::IntoResponse,
};
use candid::{decode_args, Principal};
use cbor2::from_slice;
use hyper_util::{client::legacy::connect::HttpConnector, rt::TokioExecutor};
use ic_auth_types::ByteBufB64;
use ic_auth_verifier::envelope::{
    SignedEnvelope, ANONYMOUS_PRINCIPAL, HEADER_IC_AUTH_DELEGATION, HEADER_IC_AUTH_PUBKEY,
    HEADER_IC_AUTH_SIGNATURE, HEADER_IC_AUTH_USER,
};
use ic_cose_types::{
    format_error,
    types::{ECDHInput, SettingPath},
    BoxError,
};
use ic_tee_agent::{
    agent::TEEAgent,
    http::{
        Content, CONTENT_TYPE_CBOR, CONTENT_TYPE_JSON, HEADER_IC_TEE_ID, HEADER_IC_TEE_INSTANCE,
        HEADER_X_FORWARDED_FOR, HEADER_X_FORWARDED_HOST, HEADER_X_FORWARDED_PROTO,
    },
    RPCRequest, RPCResponse,
};
use ic_tee_cdk::{
    to_cbor_bytes, AttestationUserRequest, CanisterRequest, SignInParams, TEEAppInformation,
    TEEAttestation,
};
use ic_tee_gateway_sdk::crypto;
use ic_tee_nitro_attestation::AttestationRequest;
use serde::de::DeserializeOwned;
use serde_bytes::{ByteArray, ByteBuf};
use std::sync::Arc;
use structured_logger::unix_ms;

use crate::{attestation::sign_attestation, SETTING_KEY_TLS, TEE_KIND};

type Client = hyper_util::client::legacy::Client<HttpConnector, Body>;

#[derive(Clone)]
pub struct AppState {
    info: Arc<TEEAppInformation>,
    http_client: Arc<Client>,
    tee_agent: Arc<TEEAgent>,
    root_secret: [u8; 48],
    upstream_port: Option<u16>,
    cose_namespace: String,
    identity_signing: bool,
    app_basic_token: Option<String>,
    tee_id_header: HeaderValue,
    tee_instance_header: HeaderValue,
}

impl AppState {
    pub fn new(
        info: Arc<TEEAppInformation>,
        tee_agent: Arc<TEEAgent>,
        root_secret: [u8; 48],
        upstream_port: Option<u16>,
        cose_namespace: String,
        identity_signing: bool,
        app_basic_token: Option<String>,
    ) -> Result<Self, BoxError> {
        let http_client = Arc::new(
            hyper_util::client::legacy::Client::<(), ()>::builder(TokioExecutor::new())
                .build(HttpConnector::new()),
        );
        let tee_id_header = HeaderValue::from_str(&info.id.to_text())?;
        let tee_instance_header = HeaderValue::from_str(&info.instance)?;

        Ok(Self {
            info,
            http_client,
            tee_agent,
            root_secret,
            upstream_port,
            cose_namespace,
            identity_signing,
            app_basic_token,
            tee_id_header,
            tee_instance_header,
        })
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
}

/// Returns the caller verified from the signed envelope in the headers,
/// or the anonymous principal if there is no envelope.
fn verify_caller(headers: &HeaderMap, tee_id: Principal) -> Result<Principal, String> {
    let uses_icp_authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split_ascii_whitespace().next())
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("ICP"));
    let envelope = if uses_icp_authorization {
        SignedEnvelope::from_authorization(headers)
    } else {
        SignedEnvelope::from_headers(headers)
    };
    match envelope {
        Some(se) => se
            .verify(unix_ms(), Some(tee_id), None)
            .map(|_| se.sender()),
        None if uses_icp_authorization
            || headers.contains_key(&HEADER_IC_AUTH_PUBKEY)
            || headers.contains_key(&HEADER_IC_AUTH_SIGNATURE)
            || headers.contains_key(&HEADER_IC_AUTH_DELEGATION) =>
        {
            Err("invalid ICP authentication headers".to_string())
        }
        None => Ok(ANONYMOUS_PRINCIPAL),
    }
}

/// local_server: GET /tee
/// public_server: GET /.well-known/tee
pub async fn get_information(State(app): State<AppState>, req: Request) -> impl IntoResponse {
    let mut info = app.info.as_ref().clone();
    info.caller = verify_caller(req.headers(), info.id).unwrap_or(ANONYMOUS_PRINCIPAL);

    let response =
        match Content::from_accept(req.headers(), &[CONTENT_TYPE_CBOR, CONTENT_TYPE_JSON]) {
            Content::CBOR(_, _) => Content::CBOR(info, None).into_response(),
            _ => Content::JSON(info, None).into_response(),
        };
    ([(header::CACHE_CONTROL, "no-store")], response)
}

/// local_server: GET /attestation
/// public_server: GET /.well-known/attestation
pub async fn get_attestation(State(app): State<AppState>, req: Request) -> impl IntoResponse {
    let caller = verify_caller(req.headers(), app.info.id).unwrap_or(ANONYMOUS_PRINCIPAL);
    let res = sign_attestation(AttestationRequest {
        user_data: Some(ByteBufB64::from(caller.as_slice())),
        ..Default::default()
    })
    .await;

    let response = match res {
        Err(err) => Content::Text::<()>(err.to_string(), Some(StatusCode::INTERNAL_SERVER_ERROR))
            .into_response(),
        Ok(doc) => {
            let attestation = TEEAttestation {
                kind: TEE_KIND.to_string(),
                attestation: doc.into(),
            };
            match Content::from(req.headers()) {
                Content::CBOR(_, _) => Content::CBOR(attestation, None).into_response(),
                Content::JSON(_, _) => Content::JSON(attestation, None).into_response(),
                _ => Content::Text::<()>(attestation.attestation.to_string(), None).into_response(),
            }
        }
    };
    ([(header::CACHE_CONTROL, "no-store")], response)
}

/// local_server: POST /attestation
pub async fn local_sign_attestation(
    State(app): State<AppState>,
    headers: HeaderMap,
    cr: Content<RPCRequest>,
) -> impl IntoResponse {
    if !app.valid_session(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    match cr {
        Content::CBOR(req, _) => {
            match req.method.as_str() {
                "sign_attestation" => {}
                _ => {
                    return StatusCode::BAD_REQUEST.into_response();
                }
            }

            let req: AttestationRequest = match from_slice(req.params.as_slice()) {
                Ok(req) => req,
                Err(err) => {
                    return Content::Text::<()>(
                        format!("invalid request: {err:?}"),
                        Some(StatusCode::BAD_REQUEST),
                    )
                    .into_response();
                }
            };

            if let Some(user_data) = &req.user_data {
                if from_slice::<AttestationUserRequest<SignInParams>>(user_data.as_slice()).is_ok()
                {
                    return StatusCode::BAD_REQUEST.into_response();
                }
            }

            match sign_attestation(req).await {
                Ok(doc) => Content::CBOR(
                    TEEAttestation {
                        kind: TEE_KIND.to_string(),
                        attestation: doc.into(),
                    },
                    None,
                )
                .into_response(),
                Err(err) => {
                    Content::Text::<()>(err.to_string(), Some(StatusCode::INTERNAL_SERVER_ERROR))
                        .into_response()
                }
            }
        }
        _ => StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response(),
    }
}

/// local_server: POST /canister/query
pub async fn local_query_canister(
    State(app): State<AppState>,
    headers: HeaderMap,
    ct: Content<CanisterRequest>,
) -> impl IntoResponse {
    if !app.identity_signing {
        return StatusCode::FORBIDDEN.into_response();
    }

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
    if !app.identity_signing {
        return StatusCode::FORBIDDEN.into_response();
    }

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
            let res = handle_keys_request(&req, &app.root_secret);
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
    if !app.identity_signing {
        return StatusCode::FORBIDDEN.into_response();
    }

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
/// The gateway verifies ICP credentials and returns 401 if verification fails.
/// It sets `ic-auth-user` to the verified or anonymous principal and adds
/// `ic-tee-id` and `ic-tee-instance` before forwarding the request.
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

    let caller = verify_caller(req.headers(), app.info.id)
        .map_err(|err| Content::Text(err, Some(StatusCode::UNAUTHORIZED)))?;

    let headers = req.headers_mut();
    prepare_upstream_connection_headers(headers);
    headers.remove(&header::FORWARDED);
    headers.remove(&HEADER_X_FORWARDED_FOR);
    headers.remove(&HEADER_X_FORWARDED_HOST);
    headers.remove(&HEADER_X_FORWARDED_PROTO);
    headers.remove(&HEADER_IC_AUTH_PUBKEY);
    // The upstream can compare the content digest with the received body.
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
    headers.insert(&HEADER_IC_TEE_ID, app.tee_id_header.clone());
    headers.insert(&HEADER_IC_TEE_INSTANCE, app.tee_instance_header.clone());

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
        Ok(mut res) => {
            remove_connection_headers(res.headers_mut());
            Ok(res.into_response())
        }
        Err(err) => Err(Content::Text(
            err.to_string(),
            Some(StatusCode::BAD_GATEWAY),
        )),
    }
}

fn prepare_upstream_connection_headers(headers: &mut HeaderMap) {
    let accepts_trailers = headers
        .get_all(header::TE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("trailers"));
    remove_connection_headers(headers);

    if accepts_trailers {
        headers.insert(header::TE, HeaderValue::from_static("trailers"));
        headers.insert(header::CONNECTION, HeaderValue::from_static("te"));
    }
}

fn remove_connection_headers(headers: &mut HeaderMap) {
    let named_headers: Vec<_> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| header::HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in named_headers {
        headers.remove(name);
    }
    for name in [
        "connection",
        "keep-alive",
        "proxy-connection",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
}

async fn handle_identity_request(req: &RPCRequest, app: &AppState) -> RPCResponse {
    match req.method.as_str() {
        "sign_http" => {
            let (digest,): (ByteArray<32>,) = decode_params(req)?;
            let se = SignedEnvelope::sign_digest(
                &app.tee_agent.get_identity(),
                digest.into_array().into(),
            )?;
            Ok(to_cbor_bytes(&se).into())
        }
        // "sign_delegation" => {}
        _ => Err(format!("unsupported method {}", req.method)),
    }
}

fn handle_keys_request(req: &RPCRequest, root_secret: &[u8; 48]) -> RPCResponse {
    let res = match req.method.as_str() {
        "a256gcm_key" => {
            let (path,): (Vec<ByteBuf>,) = decode_params(req)?;
            let key = crypto::a256gcm_key(root_secret, into_path(path));
            to_cbor_bytes(&ByteArray::new(key))
        }
        "a256gcm_ecdh_key" => {
            let (path, ecdh): (Vec<ByteBuf>, ECDHInput) = decode_params(req)?;
            to_cbor_bytes(&crypto::try_a256gcm_ecdh_key(
                root_secret,
                into_path(path),
                &ecdh,
            )?)
        }
        "ed25519_sign_message" => {
            let (path, msg): (Vec<ByteBuf>, ByteBuf) = decode_params(req)?;
            let sig = crypto::ed25519_sign_message(root_secret, into_path(path), &msg);
            to_cbor_bytes(&ByteArray::new(sig))
        }
        "ed25519_public_key" => {
            let (path,): (Vec<ByteBuf>,) = decode_params(req)?;
            let (pk, code) = crypto::ed25519_public_key(root_secret, into_path(path));
            to_cbor_bytes(&(ByteArray::new(pk), ByteArray::new(code)))
        }
        "secp256k1_sign_message_bip340" => {
            let (path, msg): (Vec<ByteBuf>, ByteBuf) = decode_params(req)?;
            let sig = crypto::secp256k1_sign_message_bip340(root_secret, into_path(path), &msg);
            to_cbor_bytes(&ByteArray::new(sig))
        }
        "secp256k1_sign_message_ecdsa" => {
            let (path, msg): (Vec<ByteBuf>, ByteBuf) = decode_params(req)?;
            let sig = crypto::secp256k1_sign_message_ecdsa(root_secret, into_path(path), &msg);
            to_cbor_bytes(&ByteArray::new(sig))
        }
        "secp256k1_sign_digest_ecdsa" => {
            let (path, hash): (Vec<ByteBuf>, ByteBuf) = decode_params(req)?;
            let sig = crypto::secp256k1_sign_digest_ecdsa(root_secret, into_path(path), &hash);
            to_cbor_bytes(&ByteArray::new(sig))
        }
        "secp256k1_public_key" => {
            let (path,): (Vec<ByteBuf>,) = decode_params(req)?;
            let (pk, code) = crypto::secp256k1_public_key(root_secret, into_path(path));
            to_cbor_bytes(&(ByteArray::new(pk), ByteArray::new(code)))
        }
        _ => return Err(format!("unsupported method {}", req.method)),
    };
    Ok(res.into())
}

fn decode_params<T: DeserializeOwned>(req: &RPCRequest) -> Result<T, String> {
    from_slice(req.params.as_slice()).map_err(format_error)
}

fn into_path(path: Vec<ByteBuf>) -> Vec<Vec<u8>> {
    path.into_iter().map(ByteBuf::into_vec).collect()
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

        // The subject defaults to the gateway's identity. Its user-owned keys
        // and its namespace-owned TLS key are reserved for the gateway.
        return path.ns == ns
            && path.subject.unwrap_or(info.id) == info.id
            && (path.user_owned || path.key.as_slice() == SETTING_KEY_TLS.as_bytes());
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use candid::encode_args;
    use ic_cose::rand_bytes;
    use ic_cose_types::{
        cose::ecdh,
        types::{state::StateInfo, ECDHOutput},
    };
    use ic_tee_cdk::CanisterResponse;
    use ic_tee_gateway_sdk::client::ClientBuilder;

    static TEE_HOST: &str = "http://127.0.0.1:8080";
    static COSE_CANISTER: &str = "53cyg-yyaaa-aaaap-ahpua-cai";

    #[test]
    fn proxy_renegotiates_trailers_on_the_upstream_connection() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONNECTION,
            HeaderValue::from_static("TE, keep-alive"),
        );
        headers.insert(header::TE, HeaderValue::from_static("gzip, Trailers"));
        headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));

        prepare_upstream_connection_headers(&mut headers);

        assert_eq!(headers[header::TE], "trailers");
        assert_eq!(headers[header::CONNECTION], "te");
        assert!(!headers.contains_key("keep-alive"));
    }

    #[tokio::test]
    async fn sdk_attestation_uses_the_gateway_wire_format() {
        let router = axum::Router::new().route(
            "/attestation",
            axum::routing::post(|content: Content<RPCRequest>| async {
                let Content::CBOR(request, _) = content else {
                    panic!("expected CBOR request");
                };
                assert_eq!(request.method, "sign_attestation");
                let request: AttestationRequest = from_slice(request.params.as_slice()).unwrap();
                assert_eq!(request.nonce.unwrap().as_slice(), b"challenge");
                Content::CBOR(
                    TEEAttestation {
                        kind: TEE_KIND.to_string(),
                        attestation: ByteBufB64::from(b"document"),
                    },
                    None,
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let host = format!("http://{}/", listener.local_addr().unwrap());
        let server = tokio::spawn(async { axum::serve(listener, router).await.unwrap() });
        let client = ClientBuilder::default().with_tee_host(&host).build();
        let result = client
            .sign_attestation(ic_tee_cdk::AttestationRequest {
                nonce: Some(ByteBufB64::from(b"challenge")),
                ..Default::default()
            })
            .await;
        server.abort();
        let result = result.unwrap();
        assert_eq!(result.kind, TEE_KIND);
        assert_eq!(result.attestation.as_slice(), b"document");
    }

    #[test]
    fn test_forbid_canister_request() {
        let tee_id =
            Principal::from_text("m6a24-ioo3h-wtn6z-rntjm-rkzgw-24nrf-2x6jb-znzpt-7uctp-akavf-yqe")
                .unwrap();
        let cose_canister = Principal::from_text(COSE_CANISTER).unwrap();
        let info = TEEAppInformation {
            id: tee_id,
            instance: "i-test".to_string(),
            name: "test".to_string(),
            version: "0.0.0".to_string(),
            kind: TEE_KIND.to_string(),
            origin: "https://example.com".to_string(),
            url: "https://example.com/.well-known/tee".to_string(),
            pcr0: [0u8; 48].into(),
            pcr1: [0u8; 48].into(),
            pcr2: [0u8; 48].into(),
            start_time_ms: 0,
            identity_canister: Principal::from_text("e7tgb-6aaaa-aaaap-akqfa-cai").unwrap(),
            cose_canister,
            registration_canister: None,
            caller: Principal::anonymous(),
        };
        let root_path = |subject: Option<Principal>| SettingPath {
            ns: "_".to_string(),
            user_owned: true,
            subject,
            key: b"root".to_vec().into(),
            version: 0,
        };
        let vetkd_request = |path: SettingPath| CanisterRequest {
            canister: cose_canister,
            method: "vetkd_encrypted_key".to_string(),
            params: encode_args((path, ByteArray::new([0u8; 48])))
                .unwrap()
                .into(),
        };
        let forbid = |req: &CanisterRequest| forbid_canister_request("_", req, &info);

        assert!(forbid(&CanisterRequest {
            canister: info.identity_canister,
            method: "whoami".to_string(),
            params: encode_args(()).unwrap().into(),
        }));
        assert!(forbid(&CanisterRequest {
            canister: cose_canister,
            method: "namespace_sign_delegation".to_string(),
            params: encode_args(()).unwrap().into(),
        }));
        // the subject defaults to the caller, which is the TEE identity
        assert!(forbid(&vetkd_request(root_path(None))));
        assert!(forbid(&vetkd_request(root_path(Some(tee_id)))));
        assert!(forbid(&vetkd_request(SettingPath {
            user_owned: false,
            key: SETTING_KEY_TLS.as_bytes().to_vec().into(),
            ..root_path(None)
        })));
        assert!(forbid(&CanisterRequest {
            canister: cose_canister,
            method: "vetkd_encrypted_key".to_string(),
            params: encode_args(("invalid",)).unwrap().into(),
        }));

        assert!(!forbid(&vetkd_request(root_path(Some(
            Principal::anonymous()
        )))));
        assert!(!forbid(&vetkd_request(SettingPath {
            user_owned: false,
            ..root_path(None)
        })));
        assert!(!forbid(&vetkd_request(SettingPath {
            ns: "other".to_string(),
            ..root_path(None)
        })));
        assert!(!forbid(&CanisterRequest {
            canister: cose_canister,
            method: "setting_get".to_string(),
            params: encode_args((root_path(None),)).unwrap().into(),
        }));
    }

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
            let res: CanisterResponse = from_slice(&data[..]).unwrap();
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
            let res: CanisterResponse = from_slice(&data[..]).unwrap();
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
        let res: RPCResponse = from_slice(&data[..]).unwrap();
        assert!(res.is_ok());
        let res: ECDHOutput<ByteBuf> = from_slice(res.unwrap().as_slice()).unwrap();
        let key = crypto::decrypt_ecdh(secret.to_bytes(), &res).unwrap();
        assert_eq!(key.len(), 32);
    }
}
