use anyhow::Result;
use axum::{routing, Router};
use axum_server::tls_rustls::RustlsConfig;
use candid::Principal;
use clap::Parser;
use ic_tee_agent::agent::TEEAgent;
use ic_tee_cdk::{to_cbor_bytes, AttestationUserRequest, SignInParams, TEEAppInformation};
use ic_tee_nitro_attestation::{parse_and_verify, AttestationRequest};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use structured_logger::{async_json::new_writer, get_env_level, unix_ms, Builder};
use tokio::signal;
use tokio_util::sync::CancellationToken;

mod attestation;
mod handler;

use attestation::sign_attestation;

const APP_NAME: &str = env!("CARGO_PKG_NAME");
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

static IC_HOST: &str = "https://icp-api.io";
static TEE_KIND: &str = "Nitro"; // AWS Nitro Enclaves

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// authentication canister (e.g. e7tgb-6aaaa-aaaap-akqfa-cai)
    #[clap(long, value_parser)]
    authentication_canister: String,

    /// refresh identity every N seconds, default is 24 hours - 10 minutes
    #[clap(long, value_parser)]
    refresh_identity_secs: Option<u64>,

    // id_scope should be "image" or "enclave", default is "image"
    #[clap(long, value_parser)]
    id_scope: Option<String>,

    /// configuration canister
    #[clap(long, value_parser)]
    configuration_canister: String,

    /// configuration namespace
    #[clap(long, value_parser)]
    configuration_namespace: String,

    /// Bring Your Own Key (BYOK) to derive the KEK
    #[clap(long, value_parser)]
    configuration_byok: Option<String>,

    #[clap(long, value_parser)]
    upstream_port: Option<u16>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    Builder::with_level(&get_env_level().to_string())
        .with_target_writer("*", new_writer(tokio::io::stdout()))
        .init();

    let authentication_canister = Principal::from_text(cli.authentication_canister)
        .map_err(|err| anyhow::anyhow!("invalid authentication_canister id: {}", err))?;
    let configuration_canister = Principal::from_text(cli.configuration_canister)
        .map_err(|err| anyhow::anyhow!("invalid configuration_canister id: {}", err))?;
    let tee_agent = TEEAgent::new(IC_HOST, authentication_canister, configuration_canister)
        .map_err(anyhow::Error::msg)?;

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

    tee_agent
        .sign_in(TEE_KIND.to_string(), doc.into())
        .await
        .map_err(anyhow::Error::msg)?;
    let info = TEEAppInformation {
        name: APP_NAME.to_string(),
        version: APP_VERSION.to_string(),
        kind: TEE_KIND.to_string(),
        pcr0: attestation.pcrs.get(&0).cloned().unwrap(),
        pcr1: attestation.pcrs.get(&1).cloned().unwrap(),
        pcr2: attestation.pcrs.get(&2).cloned().unwrap(),
        start_time_ms: unix_ms(),
        principal: tee_agent.principal().await,
        authentication_canister,
        configuration_canister,
        registration_canister: None,
    };

    let http_client = Arc::new(handler::new_client());
    let tee_agent = Arc::new(tee_agent);
    let info = Arc::new(info);

    let handle = axum_server::Handle::new();
    let cancel_token = CancellationToken::new();
    let shutdown_future = shutdown_signal(handle.clone(), cancel_token.clone());

    // 24 hours - 10 minutes
    let refresh_identity_secs = cli.refresh_identity_secs.unwrap_or(3600 * 24 - 60 * 10);
    let refresh_identity = async {
        loop {
            tokio::select! {
                _ = cancel_token.cancelled() => {
                    break;
                }
                _ = tokio::time::sleep(Duration::from_secs(refresh_identity_secs)) => {}
            };
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
        Result::<()>::Ok(())
    };

    let local_server = async {
        let app = Router::new()
            .route("/information", routing::get(handler::get_information))
            .route("/attestation", routing::post(handler::post_attestation))
            .with_state(handler::AppState {
                info: info.clone(),
                http_client: http_client.clone(),
                tee_agent: tee_agent.clone(),
                upstream_port: None,
            });
        let addr: SocketAddr = "127.0.0.1:80".parse().map_err(anyhow::Error::new)?;
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .map_err(anyhow::Error::new)?;
        log::warn!(target: "local server", "{}@{} listening on {:?}", APP_NAME, APP_VERSION, addr);
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
            .with_state(handler::AppState {
                info: info.clone(),
                http_client: http_client.clone(),
                tee_agent: tee_agent.clone(),
                upstream_port: cli.upstream_port,
            });
        let addr: SocketAddr = "127.0.0.1:443".parse().map_err(anyhow::Error::new)?;
        // TODO: load tls cert and key from configuration canister
        let cert_file = std::env::var("TLS_CERT_FILE").unwrap_or_default();
        let key_file = std::env::var("TLS_KEY_FILE").unwrap_or_default();
        let config = RustlsConfig::from_pem_file(&cert_file, &key_file)
            .await
            .unwrap_or_else(|_| panic!("read tls file failed: {}, {}", cert_file, key_file));
        log::warn!(target: "server", "{}@{} listening on {:?} with tls", APP_NAME, APP_VERSION,addr);
        axum_server::bind_rustls(addr, config)
            .handle(handle)
            .serve(app.into_make_service())
            .await
            .map_err(anyhow::Error::new)
    };

    match tokio::try_join!(refresh_identity, local_server, public_server) {
        Ok(_) => Ok(()),
        Err(err) => {
            log::error!(target: "server", "server error: {:?}", err);
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

    log::warn!(target: "server", "received termination signal, starting graceful shutdown");
    // 10 secs is how long server will wait to force shutdown
    handle.graceful_shutdown(Some(Duration::from_secs(10)));
    cancel_token.cancel();
}
