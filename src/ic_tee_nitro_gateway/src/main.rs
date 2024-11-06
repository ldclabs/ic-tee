use anyhow::Result;
use axum::{routing, Router};
use axum_server::tls_rustls::RustlsConfig;
use candid::Principal;
use clap::Parser;
use ic_cose_types::types::SettingPath;
use ic_tee_agent::{
    agent::TEEAgent,
    identity::identity_from,
    setting::{decrypt_payload, decrypt_tls},
};
use ic_tee_cdk::{to_cbor_bytes, AttestationUserRequest, SignInParams, TEEAppInformation};
use ic_tee_nitro_attestation::{parse_and_verify, AttestationRequest};
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use structured_logger::{async_json::new_writer, get_env_level, unix_ms, Builder};
use tokio::{net::TcpStream, signal};
use tokio_util::sync::CancellationToken;

mod attestation;
mod handler;

use attestation::sign_attestation;

const APP_NAME: &str = env!("CARGO_PKG_NAME");
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

static IC_HOST: &str = "https://icp-api.io";
static TEE_KIND: &str = "Nitro"; // AWS Nitro Enclaves
static SETTING_KEY_ID: &str = "id_ed25519";
static SETTING_KEY_TLS: &str = "tls";
static COSE_SECRET_PERMANENT_KEY: &str = "v1";

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// authentication canister (e.g. e7tgb-6aaaa-aaaap-akqfa-cai)
    #[clap(long, value_parser)]
    authentication_canister: String,

    /// default is 24 hours
    #[clap(long, value_parser)]
    session_expires_in_ms: Option<u64>,

    // id_scope should be "image" or "enclave", default is "image"
    #[clap(long, value_parser)]
    id_scope: Option<String>,

    /// configuration canister
    #[clap(long, value_parser)]
    configuration_canister: String,

    /// configuration namespace
    #[clap(long, value_parser)]
    configuration_namespace: String,

    /// identity to upgrade
    #[clap(long, value_parser)]
    configuration_upgrade_identity: Option<String>,

    /// upstream port
    #[clap(long, value_parser)]
    upstream_port: Option<u16>,

    /// where the logtail server is running on host (e.g. 127.0.0.1:9999)
    /// it should not be used in production
    #[clap(long, value_parser, default_value = "127.0.0.1:9999")]
    bootstrap_logtail: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let stream = TcpStream::connect(&cli.bootstrap_logtail).await?;
    stream.writable().await?;
    Builder::with_level(&get_env_level().to_string())
        .with_target_writer("bootstrap", new_writer(stream))
        .with_target_writer("*", new_writer(tokio::io::stdout()))
        .init();

    log::info!(target: "bootstrap", "starting {}@{} in TEE", APP_NAME, APP_VERSION);

    match serve(cli).await {
        Ok(_) => Ok(()),
        Err(err) => {
            log::error!(target: "bootstrap", "server error: {:?}", err);
            Err(err)
        }
    }
}

async fn serve(cli: Cli) -> Result<()> {
    let start = Instant::now();

    // https://github.com/rustls/rustls/issues/1938
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let authentication_canister = Principal::from_text(cli.authentication_canister)
        .map_err(|err| anyhow::anyhow!("invalid authentication_canister id: {}", err))?;
    let configuration_canister = Principal::from_text(cli.configuration_canister)
        .map_err(|err| anyhow::anyhow!("invalid configuration_canister id: {}", err))?;
    let tee_agent = TEEAgent::new(IC_HOST, authentication_canister, configuration_canister)
        .map_err(anyhow::Error::msg)?;

    let namespace = cli.configuration_namespace;
    let session_expires_in_ms = cli.session_expires_in_ms.unwrap_or(24 * 60 * 60 * 1000);
    let public_key = tee_agent.session_key().await;
    let id_scope = cli.id_scope.unwrap_or("image".to_string());
    let user_req = AttestationUserRequest {
        method: "sign_in".to_string(),
        params: Some(SignInParams { id_scope }),
    };
    let user_req = to_cbor_bytes(&user_req);
    let doc = sign_attestation(AttestationRequest {
        public_key: Some(public_key.into()),
        user_data: Some(user_req.clone().into()),
        nonce: None,
    })
    .map_err(anyhow::Error::msg)?;

    let attestation = parse_and_verify(doc.as_slice()).map_err(anyhow::Error::msg)?;
    log::info!(target: "bootstrap",
        elapsed = start.elapsed().as_millis() as u64;
       "parse_and_verify attestation for sign in, module_id: {:?}", attestation.module_id);

    tee_agent
        .sign_in(TEE_KIND.to_string(), doc.into())
        .await
        .map_err(anyhow::Error::msg)?;

    log::info!(target: "bootstrap",
        elapsed = start.elapsed().as_millis() as u64;
       "sign_in, principal: {:?}", tee_agent.principal().await.to_text());

    let upgrade_identity =
        if let Some(v) = cli.configuration_upgrade_identity {
            Some(Principal::from_text(v).map_err(|err| {
                anyhow::anyhow!("invalid configuration_upgrade_identity: {}", err)
            })?)
        } else {
            None
        };

    // upgrade to a permanent identity
    let upgrade_identity = if let Some(subject) = upgrade_identity {
        let id_path = SettingPath {
            ns: namespace.clone(),
            user_owned: false,
            subject: Some(subject),
            key: SETTING_KEY_ID.as_bytes().to_vec().into(),
            version: 0,
        };
        let secret = tee_agent
            .get_cose_secret(id_path.clone())
            .await
            .map_err(anyhow::Error::msg)?;
        log::info!(target: "bootstrap",
            elapsed = start.elapsed().as_millis() as u64;
            "get_cose_secret for upgrade_identity, principal: {:?}", subject.to_text());

        let setting = tee_agent
            .get_cose_setting(id_path)
            .await
            .map_err(anyhow::Error::msg)?;
        log::info!(target: "bootstrap",
            elapsed = start.elapsed().as_millis() as u64;
            "get_cose_setting for upgrade_identity, principal: {:?}", subject.to_text());

        let ed25519_secret = decrypt_payload(setting, secret).map_err(anyhow::Error::msg)?;
        let ed25519_secret: [u8; 32] = ed25519_secret.try_into().map_err(|val: Vec<u8>| {
            anyhow::anyhow!("invalid secret, expected 32 bytes, got {}", val.len())
        })?;
        let id = identity_from(ed25519_secret);
        tee_agent
            .upgrade_identity_with(&id, session_expires_in_ms)
            .await;

        log::info!(target: "bootstrap",
            elapsed = start.elapsed().as_millis() as u64;
            "upgrade_identity, principal: {:?}", tee_agent.principal().await.to_text());
        Some(id)
    } else {
        None
    };

    let principal = tee_agent.principal().await;
    let info = TEEAppInformation {
        name: APP_NAME.to_string(),
        version: APP_VERSION.to_string(),
        kind: TEE_KIND.to_string(),
        pcr0: attestation.pcrs.get(&0).cloned().unwrap(),
        pcr1: attestation.pcrs.get(&1).cloned().unwrap(),
        pcr2: attestation.pcrs.get(&2).cloned().unwrap(),
        start_time_ms: unix_ms(),
        principal,
        authentication_canister,
        configuration_canister,
        registration_canister: None,
    };

    log::info!(target: "bootstrap",
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

            match upgrade_identity {
                Some(ref id) => {
                    tee_agent
                        .upgrade_identity_with(id, session_expires_in_ms)
                        .await;
                }
                None => {
                    // ignore error
                    let _ = tee_agent
                        .sign_in_with(|public_key| {
                            let doc = sign_attestation(AttestationRequest {
                                public_key: Some(public_key.into()),
                                user_data: Some(user_req.clone().into()),
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
                routing::get(handler::get_attestation).post(handler::post_attestation),
            )
            .route("/canister/query", routing::post(handler::query_canister))
            .route("/canister/update", routing::post(handler::update_canister))
            .with_state(handler::AppState {
                info: info.clone(),
                http_client: http_client.clone(),
                tee_agent: tee_agent.clone(),
                upstream_port: None,
            });
        let addr: SocketAddr = "127.0.0.1:8080".parse().map_err(anyhow::Error::new)?;
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .map_err(anyhow::Error::new)?;
        log::warn!(target: "bootstrap",
            elapsed = start.elapsed().as_millis() as u64;
            "local {}@{} listening on {:?}", APP_NAME, APP_VERSION, addr);
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_future)
            .await
            .map_err(anyhow::Error::new)
    };

    let public_server = async {
        let secret = tee_agent
            .get_cose_secret(SettingPath {
                ns: namespace.clone(),
                user_owned: false,
                subject: Some(principal),
                key: COSE_SECRET_PERMANENT_KEY.as_bytes().to_vec().into(),
                version: 0,
            })
            .await
            .map_err(anyhow::Error::msg)?;
        log::info!(target: "bootstrap",
            elapsed = start.elapsed().as_millis() as u64;
            "get_cose_secret for TLS");

        let setting = tee_agent
            .get_cose_setting(SettingPath {
                ns: namespace.clone(),
                user_owned: false,
                subject: Some(principal),
                key: SETTING_KEY_TLS.as_bytes().to_vec().into(),
                version: 0,
            })
            .await
            .map_err(anyhow::Error::msg)?;
        log::info!(target: "bootstrap",
            elapsed = start.elapsed().as_millis() as u64;
            "get_cose_setting for TLS");

        let tls = decrypt_tls(setting, secret).map_err(anyhow::Error::msg)?;
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
            .with_state(handler::AppState {
                info: info.clone(),
                http_client: http_client.clone(),
                tee_agent: tee_agent.clone(),
                upstream_port: cli.upstream_port,
            });
        let addr: SocketAddr = "127.0.0.1:8443".parse().map_err(anyhow::Error::new)?;
        let config = RustlsConfig::from_pem(tls.crt.to_vec(), tls.key.to_vec())
            .await
            .map_err(|err| anyhow::anyhow!("read tls file failed: {:?}", err))?;

        log::warn!(target: "bootstrap",
            elapsed = start.elapsed().as_millis() as u64;
            "{}@{} listening on {:?} with tls", APP_NAME, APP_VERSION,addr);
        axum_server::bind_rustls(addr, config)
            .handle(handle)
            .serve(app.into_make_service())
            .await
            .map_err(anyhow::Error::new)
    };

    match tokio::try_join!(refresh_identity, local_server, public_server) {
        Ok(_) => Ok(()),
        Err(err) => {
            log::error!(target: "bootstrap", "server error: {:?}", err);
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

    log::warn!(target: "bootstrap", "received termination signal, starting graceful shutdown");
    // 10 secs is how long server will wait to force shutdown
    handle.graceful_shutdown(Some(Duration::from_secs(10)));
    cancel_token.cancel();
}
