use axum::{routing, Router};
use axum_server::tls_rustls::RustlsConfig;
use candid::Principal;
use clap::Parser;
use ic_agent::Identity;
use ic_auth_types::ByteBufB64;
use ic_auth_verifier::{new_basic_identity, BasicIdentity};
use ic_cose::{client::CoseSDK, rand_bytes};
use ic_cose_types::{
    types::{setting::CreateSettingInput, SettingPath},
    BoxError,
};
use ic_tee_agent::{
    agent::TEEAgent,
    setting::{decrypt_payload, encrypt_payload, vetkey_decrypt, TLSPayload},
};
use ic_tee_cdk::{
    to_cbor_bytes, AttestationUserRequest, SignInParams, TEEAppInformation, SESSION_EXPIRES_IN_MS,
};
use ic_tee_nitro_attestation::{parse_and_verify, Attestation, AttestationRequest};
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
mod handler;

use attestation::sign_attestation;

const APP_NAME: &str = env!("CARGO_PKG_NAME");
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

static TEE_KIND: &str = "NITRO"; // AWS Nitro Enclaves
static SETTING_KEY_TLS: &str = "tls";
static COSE_ROOT_SECRET_KEY: &str = "root";
static MY_COSE_AAD: &str = "ldclabs/ic-tee";

static LOCAL_HTTP_ADDR: &str = "127.0.0.1:8080";
static PUBLIC_HTTP_ADDR: &str = "127.0.0.1:8443";
static LOG_TARGET: &str = "bootstrap";

const PUBLIC_SERVER_GRACEFUL_DURATION: Duration = Duration::from_secs(10);

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

    /// if set, the app should provide basic auth to request local server APIs
    #[clap(long)]
    app_basic_token: Option<String>,

    /// where the logtail server is running on host (e.g. 127.0.0.1:9999)
    #[clap(long)]
    bootstrap_logtail: Option<String>,

    /// if set, the identity in TEE can be used to sign http requests and canister calls for the app.
    /// Default is false.
    #[clap(long)]
    identity_signing: Option<bool>,

    /// IC host, default is https://icp-api.io, set it to http://localhost:4943 for local development
    #[clap(long, default_value = "https://icp-api.io")]
    ic_host: String,

    /// The server origin URL, default is http://127.0.0.1:8443
    #[clap(long, default_value = "http://127.0.0.1:8443")]
    origin: String,
}

// cargo run -p ic_tee_nitro_gateway -- --identity-canister e7tgb-6aaaa-aaaap-akqfa-cai --cose-canister 53cyg-yyaaa-aaaap-ahpua-cai --cose-namespace _ --cose-identity-name jarvis --ic-host http://localhost:4943
//
// fixed identity for local development @53cyg-yyaaa-aaaap-ahpua-cai:_:jarvis
// "m6a24-ioo3h-wtn6z-rntjm-rkzgw-24nrf-2x6jb-znzpt-7uctp-akavf-yqe"
#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let cli = Cli::parse();

    let writer = if let Some(bootstrap_logtail) = &cli.bootstrap_logtail {
        let stream = TcpStream::connect(bootstrap_logtail).await?;
        stream.writable().await?;
        new_writer(stream)
    } else {
        new_writer(tokio::io::stdout())
    };

    Builder::with_level(&get_env_level().to_string())
        .with_target_writer("*", writer)
        .init();

    log::info!(target: LOG_TARGET, "bootstrap {}@{} in TEE", APP_NAME, APP_VERSION);

    match bootstrap(cli).await {
        Ok(_) => Ok(()),
        Err(err) => {
            log::error!(target: LOG_TARGET, "bootstrap error: {:?}", err);
            tokio::time::sleep(Duration::from_secs(3)).await;
            Err(err)
        }
    }
}

async fn bootstrap(cli: Cli) -> Result<(), BoxError> {
    let start = Instant::now();
    let is_dev = cli.ic_host.starts_with("http://");

    // https://github.com/rustls/rustls/issues/1938
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    let identity_canister = Principal::from_text(cli.identity_canister)?;
    let cose_canister = Principal::from_text(cli.cose_canister)?;
    let tee_agent = TEEAgent::new(&cli.ic_host, identity_canister, cose_canister).await?;

    log::info!(target: LOG_TARGET,
        elapsed = start.elapsed().as_millis() as u64;
       "start with principal: {:?}", tee_agent.get_principal().to_text());

    let namespace = cli.cose_namespace;
    let session_expires_in_ms = cli.session_expires_in_ms.unwrap_or(SESSION_EXPIRES_IN_MS);

    let user_sign_in_req = to_cbor_bytes(&AttestationUserRequest {
        method: "sign_in".to_string(),
        params: Some(SignInParams {
            id_scope: cli.id_scope.unwrap_or("image".to_string()),
        }),
    });

    let attestation = if is_dev {
        // use a fixed identity for local development
        let id = BasicIdentity::from_raw_key(&[8u8; 32]);
        // jjn6g-sh75l-r3cxb-wxrkl-frqld-6p6qq-d4ato-wske5-op7s5-n566f-bqe
        tee_agent.set_basic_identity(id, SESSION_EXPIRES_IN_MS);

        Attestation {
            timestamp: unix_ms(),
            module_id: "local_development".to_string(),
            pcrs: BTreeMap::from([
                (0usize, ByteBufB64::from([0u8; 48])),
                (1, ByteBufB64::from([1u8; 48])),
                (2, ByteBufB64::from([2u8; 48])),
            ]),
            ..Default::default()
        }
    } else {
        let session = new_basic_identity();
        let public_key = session.public_key().unwrap();
        let sig = session.sign_arbitrary(&user_sign_in_req).unwrap();
        log::info!(target: LOG_TARGET, "start to sign_in_with_attestation");
        let doc = sign_attestation(AttestationRequest {
            public_key: Some(public_key.into()),
            user_data: Some(user_sign_in_req.clone().into()),
            nonce: Some(sig.signature.unwrap().into()), // use signature as nonce for challenge
        })?;

        let attestation = parse_and_verify(doc.as_slice())?;
        log::info!(target: LOG_TARGET,
            elapsed = start.elapsed().as_millis() as u64;
            "parse_and_verify attestation for sign in, module_id: {:?}", attestation.module_id);

        tee_agent
            .sign_in_with_attestation(session, || Ok((TEE_KIND.to_string(), doc.into())))
            .await?;
        attestation
    };

    log::info!(target: LOG_TARGET,
        elapsed = start.elapsed().as_millis() as u64;
       "sign_in, principal: {:?}", tee_agent.get_principal().to_text());

    // upgrade to a permanent identity
    let upgrade_identity = if let Some(ref name) = cli.cose_identity_name {
        log::info!(target: LOG_TARGET, "start to cose_upgrade_identity");
        let session = new_basic_identity();
        tee_agent
            .cose_upgrade_identity(namespace.clone(), name.clone(), session)
            .await?;

        log::info!(target: LOG_TARGET,
            elapsed = start.elapsed().as_millis() as u64;
            "upgrade to fixed identity, namespace: {}, name: {}, principal: {:?}", namespace, name, tee_agent.get_principal().to_text());
        Some(name.clone())
    } else {
        None
    };

    let tee_agent = Arc::new(tee_agent);
    let principal = tee_agent.get_principal();

    log::info!(target: LOG_TARGET, "start to get_or_set_root_secret");
    let root_secret = get_or_set_root_secret(&tee_agent, namespace.clone(), &start).await?;

    let info = TEEAppInformation {
        id: principal,
        instance: attestation.module_id.clone(),
        name: APP_NAME.to_string(),
        version: APP_VERSION.to_string(),
        kind: TEE_KIND.to_string(),
        origin: cli.origin.clone(),
        url: format!("{}/.well-known/tee", cli.origin),
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

    let info = Arc::new(info);
    let global_cancel_token = CancellationToken::new();
    let server_cancel_token = global_cancel_token.child_token();

    // local server
    let local_app_state = handler::AppState::new(
        info.clone(),
        tee_agent.clone(),
        root_secret,
        None,
        namespace.clone(),
        cli.identity_signing.unwrap_or_default(),
        cli.app_basic_token.clone(),
    );
    let local_server = tokio::spawn(start_local_server(
        local_app_state.clone(),
        start,
        server_cancel_token.clone(),
    ));

    // public server
    let public_app_state = handler::AppState::new(
        info.clone(),
        tee_agent.clone(),
        [0u8; 48],
        cli.upstream_port,
        String::new(),
        false,
        None,
    );

    let tls_config = if is_dev {
        None
    } else {
        log::info!(target: LOG_TARGET, "start to get_tls");
        let tls = get_tls(&tee_agent, &start, namespace.clone()).await?;
        let config = RustlsConfig::from_pem(tls.crt.to_vec(), tls.key.to_vec()).await?;
        Some(config)
    };

    let public_server = tokio::spawn(start_public_server(
        public_app_state.clone(),
        start,
        server_cancel_token.clone(),
        tls_config,
    ));

    let refresh_identity_future = refresh_identity(
        global_cancel_token.clone(),
        local_app_state,
        session_expires_in_ms,
        upgrade_identity,
        namespace.clone(),
        user_sign_in_req,
    );

    let _ = tokio::join!(
        async {
            if let Err(err) = local_server.await {
                global_cancel_token.cancel();
                log::error!(target: LOG_TARGET, "local server shutdown with error: {err:?}");
            }
        },
        async {
            if let Err(err) = public_server.await {
                global_cancel_token.cancel();
                log::error!(target: LOG_TARGET, "public server shutdown with error: {err:?}");
            }
        },
        refresh_identity_future,
        shutdown_signal(global_cancel_token.clone()),
    );

    Ok(())
}

async fn start_local_server(
    app_state: handler::AppState,
    start: Instant,
    cancel_token: CancellationToken,
) -> Result<(), BoxError> {
    let app = Router::new()
        .route("/tee", routing::get(handler::get_information))
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
        .route("/identity", routing::post(handler::local_call_identity))
        .with_state(app_state);

    let addr: SocketAddr = LOCAL_HTTP_ADDR.parse()?;

    let listener = create_reuse_port_listener(addr).await?;

    log::warn!(target: LOG_TARGET,
                elapsed = start.elapsed().as_millis() as u64;
                "local {}@{} listening on {:?}", APP_NAME, APP_VERSION, addr);

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = cancel_token.cancelled().await;
        })
        .await?;
    Ok(())
}

async fn start_public_server(
    app_state: handler::AppState,
    start: Instant,
    cancel_token: CancellationToken,
    tls_config: Option<RustlsConfig>,
) -> Result<(), BoxError> {
    let app = Router::new()
        .route("/.well-known/tee", routing::get(handler::get_information))
        .route(
            "/.well-known/information",
            routing::get(handler::get_information),
        )
        .route(
            "/.well-known/attestation",
            routing::get(handler::get_attestation),
        )
        .route("/{*any}", routing::any(handler::proxy))
        .with_state(app_state);
    let addr: SocketAddr = PUBLIC_HTTP_ADDR.parse()?;
    if let Some(tls_config) = tls_config {
        log::warn!(target: LOG_TARGET,
            elapsed = start.elapsed().as_millis() as u64;
            "public {}@{} listening on {:?} with TLS", APP_NAME, APP_VERSION, addr);

        let handle = axum_server::Handle::new();
        let res = tokio::join!(
            async {
                let listener = create_reuse_port_listener(addr).await?;
                axum_server::from_tcp_rustls(listener.into_std()?, tls_config)
                    .handle(handle.clone())
                    .serve(app.into_make_service())
                    .await?;
                Result::<(), BoxError>::Ok(())
            },
            async {
                let _ = cancel_token.cancelled().await;
                handle.graceful_shutdown(Some(PUBLIC_SERVER_GRACEFUL_DURATION));

                Result::<(), BoxError>::Ok(())
            }
        );
        res.0?;
        res.1?;

        Ok(())
    } else {
        log::warn!(target: LOG_TARGET,
            elapsed = start.elapsed().as_millis() as u64;
            "public {}@{} listening on {:?}", APP_NAME, APP_VERSION, addr);

        let listener = create_reuse_port_listener(addr).await?;
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = cancel_token.cancelled().await;
            })
            .await?;
        Ok(())
    }
}

async fn refresh_identity(
    cancel_token: CancellationToken,
    local_app_state: handler::AppState,
    session_expires_in_ms: u64,
    upgrade_identity: Option<String>,
    namespace: String,
    user_sign_in_req: Vec<u8>,
) {
    // 24 hours - 30 minutes
    let refresh_identity_ms = session_expires_in_ms - 1000 * 60 * 30;
    // let refresh_identity_ms = 1000 * 60; // for test
    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                return;
            }
            _ = tokio::time::sleep(Duration::from_millis(refresh_identity_ms)) => {}
        };

        loop {
            let session = new_basic_identity();
            let public_key = session.public_key().unwrap();
            let rt = match upgrade_identity {
                Some(ref name) => {
                    // remember to `dfx canister call ic_cose_canister namespace_add_delegator`
                    local_app_state
                        .tee_agent()
                        .cose_upgrade_identity(namespace.clone(), name.clone(), session)
                        .await
                }
                None => {
                    local_app_state
                        .tee_agent()
                        .sign_in_with_attestation(session, || {
                            match sign_attestation(AttestationRequest {
                                public_key: Some(public_key.into()),
                                user_data: Some(user_sign_in_req.clone().into()),
                                nonce: None,
                            }) {
                                Ok(doc) => Ok((TEE_KIND.to_string(), doc.into())),
                                Err(err) => Err(err.to_string()),
                            }
                        })
                        .await
                }
            };

            match rt {
                Ok(()) => {
                    log::info!(target: LOG_TARGET, "refresh identity, principal: {:?}", local_app_state
                        .tee_agent().get_principal().to_text());
                    break;
                }
                Err(err) => {
                    log::error!(target: LOG_TARGET, "refresh identity failed: {:?}", err);
                    // retry after 10 seconds
                    tokio::time::sleep(Duration::from_secs(10)).await;
                }
            }
        }
    }
}

async fn shutdown_signal(cancel_token: CancellationToken) {
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
    cancel_token.cancel();
}

async fn get_or_set_root_secret(
    tee_agent: &TEEAgent,
    ns: String,
    start: &Instant,
) -> Result<[u8; 48], BoxError> {
    let path = SettingPath {
        ns,
        user_owned: true,
        key: COSE_ROOT_SECRET_KEY.as_bytes().to_vec().into(),
        ..Default::default()
    };

    log::info!(target: LOG_TARGET, "start to get master_secret");
    let (vk, _dpk) = tee_agent.vetkey(&path).await?;
    let master_secret = vk.derive_symmetric_key("", 32);
    let master_secret: [u8; 32] = master_secret
        .try_into()
        .map_err(|_| "invalid master key length")?;
    log::info!(target: LOG_TARGET,
            elapsed = start.elapsed().as_millis() as u64;
            "get master_secret");
    let setting = tee_agent.setting_get(&path).await;
    let setting = match setting {
        Ok(setting) => setting,
        Err(err) => {
            log::error!(target: LOG_TARGET, "get root_secret failed: {:?}", err);
            // generate a new root_secret in TEE
            let root_secret: [u8; 48] = rand_bytes();
            let payload = encrypt_payload(&root_secret, &master_secret, MY_COSE_AAD.as_bytes())?;
            // ignore error because it may already exist
            let res = tee_agent
                .setting_create(
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
            tee_agent.setting_get(&path).await?
        }
    };

    log::info!(target: LOG_TARGET,
        elapsed = start.elapsed().as_millis() as u64;
        "get root_secret");

    let root_secret = decrypt_payload(&setting, &master_secret, MY_COSE_AAD.as_bytes())?;
    root_secret.try_into().map_err(|val: Vec<u8>| {
        format!("invalid root secret, expected 48 bytes, got {}", val.len()).into()
    })
}

async fn get_tls(
    tee_agent: &TEEAgent,
    start: &Instant,
    ns: String,
) -> Result<TLSPayload, BoxError> {
    let path = SettingPath {
        ns,
        key: SETTING_KEY_TLS.as_bytes().to_vec().into(),
        ..Default::default()
    };
    log::info!(target: LOG_TARGET, "start to get master_secret");
    let (vk, _dpk) = tee_agent.vetkey(&path).await?;
    let setting = tee_agent.setting_get(&path).await;
    match setting {
        Ok(setting) => {
            log::info!(target: LOG_TARGET,
            elapsed = start.elapsed().as_millis() as u64;
            "get TLS");

            let tls = vetkey_decrypt(&vk, &setting.payload.ok_or("TLS payload not found")?)?;
            Ok(tls)
        }
        Err(err) => {
            log::error!(target: LOG_TARGET, "get TLS failed: {:?}", err);
            Err(format!("get TLS failed: {:?}", err).into())
        }
    }
}

async fn create_reuse_port_listener(addr: SocketAddr) -> Result<tokio::net::TcpListener, BoxError> {
    let socket = match &addr {
        SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
        SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
    };

    socket.set_reuseport(true)?;
    socket.bind(addr)?;
    let listener = socket.listen(1024)?;
    Ok(listener)
}
