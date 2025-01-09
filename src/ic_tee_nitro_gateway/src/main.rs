use anyhow::Result;
use axum::{routing, Router};
use axum_server::tls_rustls::RustlsConfig;
use candid::Principal;
use clap::Parser;
use ed25519_consensus::SigningKey;
use ic_agent::identity::BasicIdentity;
use ic_cose::rand_bytes;
use ic_cose_types::types::{setting::CreateSettingInput, SettingPath};
use ic_tee_agent::{
    agent::TEEAgent,
    identity::TEEIdentity,
    setting::{decrypt_payload, decrypt_tls, encrypt_payload, TLSPayload},
};
use ic_tee_cdk::{
    to_cbor_bytes, AttestationUserRequest, SignInParams, TEEAppInformation, SESSION_EXPIRES_IN_MS,
};
use ic_tee_nitro_attestation::{parse_and_verify, Attestation, AttestationRequest};
use serde_bytes::ByteBuf;
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use structured_logger::{async_json::new_writer, get_env_level, unix_ms, Builder};
use tokio::{net::TcpStream, signal};
use tokio_util::sync::CancellationToken;

mod attestation;
mod crypto;
mod handler;
mod ic_sig_verifier;

use attestation::sign_attestation;

const APP_NAME: &str = env!("CARGO_PKG_NAME");
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

static TEE_KIND: &str = "NITRO"; // AWS Nitro Enclaves
static SETTING_KEY_TLS: &str = "tls";
static COSE_SECRET_PERMANENT_KEY: &str = "v1";
static MY_COSE_AAD: &str = "ldclabs/ic-tee";

static LOCAL_HTTP_ADDR: &str = "127.0.0.1:8080";
static PUBLIC_HTTP_ADDR: &str = "127.0.0.1:8443";
static LOG_TARGET: &str = "bootstrap";

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// identity canister (e.g. e7tgb-6aaaa-aaaap-akqfa-cai)
    #[clap(long)]
    identity_canister: String,

    /// COSE canister
    #[clap(long)]
    cose_canister: String,

    /// COSE namespace
    #[clap(long)]
    cose_namespace: String,

    /// default is 24 hours
    #[clap(long)]
    session_expires_in_ms: Option<u64>,

    // id_scope should be "image" or "instance", default is "image"
    #[clap(long, default_value = "image")]
    id_scope: Option<String>,

    /// upgrade to a fixed identity derived from name in namespace on COSE canister
    #[clap(long)]
    cose_identity_name: Option<String>,

    /// upstream port
    #[clap(long)]
    upstream_port: Option<u16>,

    /// where the logtail server is running on host (e.g. 127.0.0.1:9999)
    #[clap(long)]
    bootstrap_logtail: Option<String>,

    /// where the logtail server is running on host (e.g. 127.0.0.1:9999)
    #[clap(long, default_value = "https://icp-api.io")]
    ic_host: String,
}

// cargo run -p ic_tee_nitro_gateway -- --identity-canister e7tgb-6aaaa-aaaap-akqfa-cai --cose-canister 53cyg-yyaaa-aaaap-ahpua-cai --cose-namespace _ --cose-identity-name jarvis --ic-host http://localhost:4943
//
// fixed identity for local development @53cyg-yyaaa-aaaap-ahpua-cai:_:jarvis
// "m6a24-ioo3h-wtn6z-rntjm-rkzgw-24nrf-2x6jb-znzpt-7uctp-akavf-yqe"
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let writer = if let Some(bootstrap_logtail) = &cli.bootstrap_logtail {
        let stream = TcpStream::connect(bootstrap_logtail).await?;
        stream.writable().await?;
        new_writer(stream)
    } else {
        new_writer(tokio::io::stdout())
    };

    Builder::with_level(&get_env_level().to_string())
        .with_target_writer(LOG_TARGET, writer)
        .with_target_writer("*", new_writer(tokio::io::stdout()))
        .init();

    log::info!(target: LOG_TARGET, "bootstrap {}@{} in TEE", APP_NAME, APP_VERSION);

    match bootstrap(cli).await {
        Ok(_) => Ok(()),
        Err(err) => {
            log::error!(target: LOG_TARGET, "server error: {:?}", err);
            Err(err)
        }
    }
}

async fn bootstrap(cli: Cli) -> Result<()> {
    let start = Instant::now();
    let is_local = cli.ic_host.starts_with("http://");

    // https://github.com/rustls/rustls/issues/1938
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    let identity_canister = Principal::from_text(cli.identity_canister)
        .map_err(|err| anyhow::anyhow!("invalid identity_canister id: {}", err))?;
    let cose_canister = Principal::from_text(cli.cose_canister)
        .map_err(|err| anyhow::anyhow!("invalid cose_canister id: {}", err))?;
    let tee_agent = TEEAgent::new(&cli.ic_host, identity_canister, cose_canister)
        .await
        .map_err(anyhow::Error::msg)?;

    let namespace = cli.cose_namespace;
    let session_expires_in_ms = cli.session_expires_in_ms.unwrap_or(SESSION_EXPIRES_IN_MS);

    let session_key = TEEIdentity::new_session();
    let user_sign_in_req = to_cbor_bytes(&AttestationUserRequest {
        method: "sign_in".to_string(),
        params: Some(SignInParams {
            id_scope: cli.id_scope.unwrap_or("image".to_string()),
        }),
    });

    let attestation = if is_local {
        // use a fixed identity for local development
        let sk = SigningKey::from([8u8; 32]);
        let id = BasicIdentity::from_signing_key(sk);
        // jjn6g-sh75l-r3cxb-wxrkl-frqld-6p6qq-d4ato-wske5-op7s5-n566f-bqe

        tee_agent.set_identity(&id, SESSION_EXPIRES_IN_MS).await;

        Attestation {
            timestamp: unix_ms(),
            module_id: "local_development".to_string(),
            pcrs: BTreeMap::from([
                (0usize, ByteBuf::from([0u8; 48])),
                (1, ByteBuf::from([1u8; 48])),
                (2, ByteBuf::from([2u8; 48])),
            ]),
            ..Default::default()
        }
    } else {
        let public_key = session_key.1.clone(); // der encoded public key
        let sig = session_key.0.sign(&user_sign_in_req);

        log::info!(target: LOG_TARGET, "start to sign_in_with_attestation");
        let doc = sign_attestation(AttestationRequest {
            public_key: Some(public_key.into()),
            user_data: Some(user_sign_in_req.clone().into()),
            nonce: Some(sig.to_bytes().to_vec().into()), // use signature as nonce for challenge
        })
        .map_err(anyhow::Error::msg)?;

        let attestation = parse_and_verify(doc.as_slice()).map_err(anyhow::Error::msg)?;
        log::info!(target: LOG_TARGET,
            elapsed = start.elapsed().as_millis() as u64;
            "parse_and_verify attestation for sign in, module_id: {:?}", attestation.module_id);

        tee_agent
            .sign_in_with_attestation(session_key.clone(), || {
                Ok((TEE_KIND.to_string(), doc.into()))
            })
            .await
            .map_err(anyhow::Error::msg)?;
        attestation
    };

    log::info!(target: LOG_TARGET,
        elapsed = start.elapsed().as_millis() as u64;
       "sign_in, principal: {:?}", tee_agent.get_principal().await.to_text());

    // upgrade to a permanent identity
    let upgrade_identity = if let Some(ref name) = cli.cose_identity_name {
        log::info!(target: LOG_TARGET, "start to cose_upgrade_identity");
        tee_agent
            .cose_upgrade_identity(namespace.clone(), name.clone(), session_key)
            .await
            .map_err(anyhow::Error::msg)?;

        log::info!(target: LOG_TARGET,
            elapsed = start.elapsed().as_millis() as u64;
            "upgrade to fixed identity, namespace: {}, name: {}, principal: {:?}", namespace, name, tee_agent.get_principal().await.to_text());
        Some(name.clone())
    } else {
        None
    };

    let principal = tee_agent.get_principal().await;
    log::info!(target: LOG_TARGET, "start to get master_secret");
    // should replace with vetkey in the future
    let master_secret = tee_agent
        .cose_get_secret(&SettingPath {
            ns: namespace.clone(),
            key: COSE_SECRET_PERMANENT_KEY.as_bytes().to_vec().into(),
            ..Default::default()
        })
        .await
        .map_err(anyhow::Error::msg)?;
    log::info!(target: LOG_TARGET,
            elapsed = start.elapsed().as_millis() as u64;
            "get master_secret");

    log::info!(target: LOG_TARGET, "start to get_or_set_root_secret");
    let root_secret =
        get_or_set_root_secret(&tee_agent, &start, namespace.clone(), &master_secret).await?;

    let info = TEEAppInformation {
        id: principal,
        instance: attestation.module_id.clone(),
        name: APP_NAME.to_string(),
        version: APP_VERSION.to_string(),
        kind: TEE_KIND.to_string(),
        pcr0: attestation.pcrs.get(&0).cloned().unwrap(),
        pcr1: attestation.pcrs.get(&1).cloned().unwrap(),
        pcr2: attestation.pcrs.get(&2).cloned().unwrap(),
        start_time_ms: unix_ms(),
        identity_canister,
        cose_canister,
        registration_canister: None,
        caller: Principal::anonymous(),
    };

    log::info!(target: LOG_TARGET,
        info:serde = info,
        elapsed = start.elapsed().as_millis() as u64;
        "TEE app information, principal: {:?}", principal.to_text());

    let http_client = Arc::new(handler::new_client());
    let tee_agent = Arc::new(tee_agent);
    let info = Arc::new(info);

    let handle = axum_server::Handle::new();
    let cancel_token = CancellationToken::new();
    let shutdown_future = shutdown_signal(handle.clone(), cancel_token.clone());

    // 24 hours - 10 minutes
    let refresh_identity_ms = session_expires_in_ms - 1000 * 60 * 10;
    let refresh_identity = async {
        loop {
            tokio::select! {
                _ = cancel_token.cancelled() => {
                    break;
                }
                _ = tokio::time::sleep(Duration::from_millis(refresh_identity_ms)) => {}
            };

            let session_key = TEEIdentity::new_session();
            let public_key = session_key.1.clone();
            // ignore error
            match upgrade_identity {
                Some(ref name) => {
                    let _ = tee_agent
                        .cose_upgrade_identity(namespace.clone(), name.clone(), session_key)
                        .await;
                }
                None => {
                    let _ = tee_agent
                        .sign_in_with_attestation(session_key, || {
                            let doc = sign_attestation(AttestationRequest {
                                public_key: Some(public_key.into()),
                                user_data: Some(user_sign_in_req.clone().into()),
                                nonce: None,
                            })?;
                            Ok((TEE_KIND.to_string(), doc.into()))
                        })
                        .await;
                }
            }
        }
        Result::<()>::Ok(())
    };

    let local_server = async {
        let app = Router::new()
            .route("/information", routing::get(handler::get_information))
            .route(
                "/attestation",
                routing::get(handler::get_attestation).post(handler::local_sign_attestation),
            )
            .route(
                "/canister/query",
                routing::post(handler::local_query_canister),
            )
            .route(
                "/canister/update",
                routing::post(handler::local_update_canister),
            )
            .route("/keys", routing::post(handler::local_call_keys))
            .with_state(handler::AppState::new(
                info.clone(),
                http_client.clone(),
                tee_agent.clone(),
                root_secret,
                None,
            ));
        let addr: SocketAddr = LOCAL_HTTP_ADDR.parse().map_err(anyhow::Error::new)?;
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .map_err(anyhow::Error::new)?;
        log::warn!(target: LOG_TARGET,
            elapsed = start.elapsed().as_millis() as u64;
            "local {}@{} listening on {:?}", APP_NAME, APP_VERSION, addr);
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_future)
            .await
            .map_err(anyhow::Error::new)
    };

    let public_server = async {
        let app = Router::new()
            .route(
                "/.well-known/information",
                routing::get(handler::get_information),
            )
            .route(
                "/.well-known/attestation",
                routing::get(handler::get_attestation),
            )
            .route("/*any", routing::any(handler::proxy))
            .with_state(handler::AppState::new(
                info.clone(),
                http_client.clone(),
                tee_agent.clone(),
                [0u8; 48],
                None,
            ));
        let addr: SocketAddr = PUBLIC_HTTP_ADDR.parse().map_err(anyhow::Error::new)?;

        if is_local {
            let listener = tokio::net::TcpListener::bind(&addr)
                .await
                .map_err(anyhow::Error::new)?;
            log::warn!(target: LOG_TARGET,
            elapsed = start.elapsed().as_millis() as u64;
            "public {}@{} listening on {:?}", APP_NAME, APP_VERSION, addr);
            axum::serve(listener, app)
                .with_graceful_shutdown(shutdown_signal(handle.clone(), cancel_token.clone()))
                .await
                .map_err(anyhow::Error::new)
        } else {
            log::info!(target: LOG_TARGET, "start to get_tls");
            let tls = get_tls(&tee_agent, &start, namespace.clone(), &master_secret).await?;
            let config = RustlsConfig::from_pem(tls.crt.to_vec(), tls.key.to_vec())
                .await
                .map_err(|err| anyhow::anyhow!("read tls file failed: {:?}", err))?;

            log::warn!(target: LOG_TARGET,
            elapsed = start.elapsed().as_millis() as u64;
            "public {}@{} listening on {:?} with TLS", APP_NAME, APP_VERSION, addr);
            axum_server::bind_rustls(addr, config)
                .handle(handle)
                .serve(app.into_make_service())
                .await
                .map_err(anyhow::Error::new)
        }
    };

    match tokio::try_join!(refresh_identity, local_server, public_server) {
        Ok(_) => Ok(()),
        Err(err) => {
            log::error!(target: LOG_TARGET, "server error: {:?}", err);
            Err(err)
        }
    }
}

async fn shutdown_signal(handle: axum_server::Handle, cancel_token: CancellationToken) {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    log::warn!(target: LOG_TARGET, "received termination signal, starting graceful shutdown");
    // 10 secs is how long server will wait to force shutdown
    handle.graceful_shutdown(Some(Duration::from_secs(10)));
    cancel_token.cancel();
}

async fn get_or_set_root_secret(
    tee_agent: &TEEAgent,
    start: &Instant,
    ns: String,
    master_secret: &[u8; 32],
) -> Result<[u8; 48]> {
    let path = SettingPath {
        ns,
        user_owned: true,
        key: COSE_SECRET_PERMANENT_KEY.as_bytes().to_vec().into(),
        ..Default::default()
    };

    let setting = tee_agent.cose_get_setting(&path).await;
    let setting = match setting {
        Ok(setting) => setting,
        Err(err) => {
            log::error!(target: LOG_TARGET, "get root_secret failed: {:?}", err);
            // generate a new root_secret in TEE
            let root_secret: [u8; 48] = rand_bytes();
            let payload = encrypt_payload(&root_secret, master_secret, MY_COSE_AAD.as_bytes())
                .map_err(anyhow::Error::msg)?;
            // ignore error because it may already exist
            let res = tee_agent
                .cose_create_setting(
                    &path,
                    &CreateSettingInput {
                        payload: Some(payload.into()),
                        desc: Some("IC-TEE root secret".to_string()),
                        status: Some(1),
                        ..Default::default()
                    },
                )
                .await;
            if let Some(err) = res.err() {
                log::error!(target: LOG_TARGET, "create root_secret failed: {:?}", err);
            }

            // fetch again
            tee_agent
                .cose_get_setting(&path)
                .await
                .map_err(anyhow::Error::msg)?
        }
    };

    log::info!(target: LOG_TARGET,
        elapsed = start.elapsed().as_millis() as u64;
        "get root_secret");

    let root_secret = decrypt_payload(&setting, master_secret, MY_COSE_AAD.as_bytes())
        .map_err(anyhow::Error::msg)?;
    root_secret.try_into().map_err(|val: Vec<u8>| {
        anyhow::anyhow!("invalid root secret, expected 48 bytes, got {}", val.len())
    })
}

async fn get_tls(
    tee_agent: &TEEAgent,
    start: &Instant,
    ns: String,
    master_secret: &[u8; 32],
) -> Result<TLSPayload> {
    let path = SettingPath {
        ns,
        key: SETTING_KEY_TLS.as_bytes().to_vec().into(),
        ..Default::default()
    };
    let setting = tee_agent.cose_get_setting(&path).await;
    match setting {
        Ok(setting) => {
            log::info!(target: LOG_TARGET,
            elapsed = start.elapsed().as_millis() as u64;
            "get TLS");

            decrypt_tls(&setting, master_secret).map_err(anyhow::Error::msg)
        }
        Err(err) => {
            log::error!(target: LOG_TARGET, "get TLS failed: {:?}", err);
            Err(anyhow::anyhow!("get TLS failed: {:?}", err))
        }
    }
}
