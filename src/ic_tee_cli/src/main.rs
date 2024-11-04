use axum_server::tls_rustls::RustlsConfig;
use candid::{pretty::candid::value::pp_value, CandidType, IDLValue, Principal};
use clap::{Parser, Subcommand};
use ed25519_consensus::SigningKey;
use ic_agent::{
    identity::{AnonymousIdentity, BasicIdentity},
    Identity,
};
use ic_cose_types::{
    cose::{cose_aes256_key, encrypt0::cose_encrypt0, format_error, CborSerializable},
    to_cbor_bytes,
    types::{
        setting::{CreateSettingInput, CreateSettingOutput, SettingInfo},
        SettingPath,
    },
};
use ic_tee_agent::{
    agent::{query_call, update_call},
    rand_bytes,
    setting::{get_cose_secret, TLSPayload},
};
use ic_tee_cdk::canister_user_key;
use ic_tee_nitro_attestation::{parse, parse_and_verify};
use pkcs8::{
    der::{
        asn1::{ObjectIdentifier, OctetString},
        pem::LineEnding,
        Decode, Encode, EncodePem,
    },
    AlgorithmIdentifierRef, PrivateKeyInfo,
};
use rand::thread_rng;
use serde_bytes::ByteBuf;
use std::path::Path;

static IC_HOST: &str = "https://icp-api.io";
static SETTING_KEY_ID: &str = "id_ed25519";
static SETTING_KEY_TLS: &str = "tls";
static COSE_SECRET_PERMANENT_KEY: &str = "v1";

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// The user identity to run this command as.
    #[arg(short, long, value_name = "PEM_FILE", default_value = "Anonymous")]
    identity: String,

    #[arg(short, long, default_value = "")]
    canister: String,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// create a identity and save to a file
    IdentityNew {
        /// path to save the new identity
        #[arg(long, default_value = "")]
        path: String,
    },
    /// derive the principal with canister and seeds
    IdentityDerive {
        /// TEE kind to derive the principal
        #[arg(long, default_value = "Nitro")]
        kind: String,

        #[arg(long)]
        seed: String,

        /// sub seed to derive the principal
        #[arg(long)]
        sub_seed: Option<String>,
    },
    /// verify a TEE attestation document
    TeeVerify {
        /// TEE kind to verify
        #[arg(long, default_value = "Nitro")]
        kind: String,

        /// TEE attestation document
        #[arg(long, default_value = "")]
        doc: String,
    },
    /// get a setting from the COSE canister
    SettingGet {
        /// The namespace to get setting
        #[arg(long)]
        ns: String,
        /// The setting key
        #[arg(long)]
        key: String,
        /// The setting subject
        #[arg(long)]
        subject: Option<String>,
        /// The setting subject
        #[arg(long)]
        user_owned: bool,
        #[arg(long)]
        version: u32,
    },
    /// save a identity to the COSE canister
    SettingSaveIdentity {
        /// The setting's namespace
        #[arg(long)]
        ns: String,
        /// the identity path
        #[arg(long)]
        path: String,
    },

    /// save a tls certificate to the COSE canister
    SettingSaveTLS {
        /// The setting's namespace
        #[arg(long)]
        ns: String,
        /// setting's subject
        #[arg(long)]
        subject: String,
        /// The private key pem file
        #[arg(long)]
        key_file: String,
        /// The certificate pem file
        #[arg(long)]
        cert_file: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let cli = Cli::parse();
    let identity = load_identity(&cli.identity).map_err(format_error)?;

    match &cli.command {
        Some(Commands::IdentityNew { path }) => {
            let signing_key = SigningKey::new(thread_rng());
            let private_key = OctetString::new(signing_key.as_bytes()).map_err(format_error)?;
            let private_key = private_key.to_der().map_err(format_error)?;
            let id = BasicIdentity::from_signing_key(signing_key);
            let principal = id.sender()?;
            let oid = ObjectIdentifier::new("1.3.101.112").map_err(format_error)?;

            let pk = PrivateKeyInfo {
                algorithm: AlgorithmIdentifierRef {
                    oid,
                    parameters: None,
                },
                private_key: &private_key,
                public_key: None,
            };
            let pem = pk.to_pem(LineEnding::LF).map_err(format_error)?;

            let file = if path.is_empty() {
                format!("{}.pem", principal)
            } else {
                path.clone()
            };
            let file = Path::new(&file).to_path_buf();
            if file.try_exists().unwrap_or_default() {
                Err(format!("file already exists: {:?}", file))?;
            }

            std::fs::write(&file, pem.as_bytes()).map_err(format_error)?;
            println!("principal: {}", principal);
            println!("file: {}", file.to_str().unwrap());
        }

        Some(Commands::IdentityDerive {
            kind,
            seed,
            sub_seed,
        }) => {
            let seed = decode_hex(seed)?;
            let sub_seed = sub_seed.as_ref().map(|s| decode_hex(s)).transpose()?;
            let canister = Principal::from_text(&cli.canister)
                .map_err(|err| format!("invalid canister: {:?}", err))?;
            let user_key = canister_user_key(canister, kind, &seed, sub_seed.as_deref());
            let principal = Principal::self_authenticating(&user_key);

            println!("principal: {}", principal);
        }

        Some(Commands::TeeVerify { doc, kind: _ }) => {
            let doc = decode_hex(doc)?;
            let mut error: Option<String> = None;
            let doc = match parse_and_verify(&doc) {
                Ok(doc) => doc,
                Err(err) => {
                    error = Some(err);
                    let (_, doc) = parse(&doc)?;
                    doc
                }
            };
            pretty_println(&doc)?;
            if let Some(err) = error {
                println!("Verify failed: {}", err);
            }
        }

        Some(Commands::SettingGet {
            ns,
            key,
            subject,
            user_owned,
            version,
        }) => {
            let canister = Principal::from_text(&cli.canister)
                .map_err(|err| format!("invalid COSE canister: {:?}", err))?;
            let agent = build_agent(identity);
            let path = SettingPath {
                ns: ns.clone(),
                user_owned: *user_owned,
                subject: subject
                    .as_ref()
                    .map(|s| Principal::from_text(s).map_err(format_error))
                    .transpose()?,
                key: ByteBuf::from(key.as_bytes()),
                version: *version,
            };

            let res: Result<SettingInfo, String> =
                query_call(&agent, &canister, "setting_get", (path,)).await?;
            let res = res?;
            pretty_println(&res)?;
        }

        Some(Commands::SettingSaveIdentity { ns, path }) => {
            let canister = Principal::from_text(&cli.canister)
                .map_err(|err| format!("invalid COSE canister: {:?}", err))?;
            let content = std::fs::read_to_string(path).map_err(format_error)?;
            let id = BasicIdentity::from_pem(content.as_bytes()).map_err(format_error)?;
            let principal = id.sender()?;
            let pki = PrivateKeyInfo::try_from(content.as_bytes()).map_err(format_error)?;
            let decoded_key = OctetString::from_der(pki.private_key).map_err(format_error)?;
            let private_key = SigningKey::try_from(decoded_key.as_bytes()).map_err(format_error)?;
            let agent = build_agent(identity);
            let path = SettingPath {
                ns: ns.clone(),
                user_owned: false,
                subject: Some(principal),
                key: ByteBuf::from(SETTING_KEY_ID.as_bytes()),
                version: 0,
            };
            let secret = get_cose_secret(&agent, &canister, path.clone()).await?;
            let key = cose_aes256_key(private_key.to_bytes(), principal.as_slice().to_vec());
            let key = key.to_vec().map_err(format_error)?;
            let nonce: [u8; 12] = rand_bytes();
            let payload = cose_encrypt0(&key, &secret, &[], nonce, None)?;

            let res: Result<CreateSettingOutput, String> = update_call(
                &agent,
                &canister,
                "setting_create",
                (
                    path,
                    CreateSettingInput {
                        dek: Some(payload.into()),
                        payload: None,
                        desc: None,
                        status: None,
                        tags: None,
                    },
                ),
            )
            .await?;
            let res = res?;
            pretty_println(&res)?;
        }

        Some(Commands::SettingSaveTLS {
            ns,
            subject,
            key_file,
            cert_file,
        }) => {
            let canister = Principal::from_text(&cli.canister)
                .map_err(|err| format!("invalid COSE canister: {:?}", err))?;
            let subject = Principal::from_text(subject)
                .map_err(|err| format!("invalid subject: {:?}", err))?;
            let key_data = std::fs::read_to_string(key_file).map_err(format_error)?;
            let cert_data = std::fs::read_to_string(cert_file).map_err(format_error)?;
            let tls = TLSPayload {
                crt: cert_data.as_bytes().to_vec().into(),
                key: key_data.as_bytes().to_vec().into(),
            };
            let _ = RustlsConfig::from_pem(tls.crt.to_vec(), tls.key.to_vec())
                .await
                .map_err(|err| format!("read tls file failed: {:?}", err))?;
            let agent = build_agent(identity);
            let dek: [u8; 32] = rand_bytes();
            let nonce: [u8; 12] = rand_bytes();
            let payload = to_cbor_bytes(&tls);
            let payload = cose_encrypt0(&payload, &dek, &[], nonce, None)?;

            let secret = get_cose_secret(
                &agent,
                &canister,
                SettingPath {
                    ns: ns.clone(),
                    user_owned: false,
                    subject: Some(subject),
                    key: ByteBuf::from(COSE_SECRET_PERMANENT_KEY.as_bytes()),
                    version: 0,
                },
            )
            .await?;
            let dek = cose_aes256_key(dek, COSE_SECRET_PERMANENT_KEY.as_bytes().to_vec());
            let dek = dek.to_vec().map_err(format_error)?;
            let nonce: [u8; 12] = rand_bytes();
            let dek = cose_encrypt0(&dek, &secret, &[], nonce, None)?;
            let res: Result<CreateSettingOutput, String> = update_call(
                &agent,
                &canister,
                "setting_create",
                (
                    SettingPath {
                        ns: ns.clone(),
                        user_owned: false,
                        subject: Some(subject),
                        key: ByteBuf::from(SETTING_KEY_TLS.as_bytes()),
                        version: 0,
                    },
                    CreateSettingInput {
                        dek: Some(dek.into()),
                        payload: Some(payload.into()),
                        desc: None,
                        status: None,
                        tags: None,
                    },
                ),
            )
            .await?;
            let res = res?;
            pretty_println(&res)?;
        }

        None => {
            let principal = identity.sender()?;
            println!("principal: {}", principal);
        }
    }

    Ok(())
}

fn load_identity(path: &str) -> anyhow::Result<Box<dyn Identity>> {
    if path == "Anonymous" {
        return Ok(Box::new(AnonymousIdentity));
    }

    let content = std::fs::read_to_string(path)?;
    match BasicIdentity::from_pem(content.as_bytes()) {
        Ok(identity) => Ok(Box::new(identity)),
        Err(err) => Err(err.into()),
    }
}

fn build_agent(identity: Box<dyn Identity>) -> ic_agent::Agent {
    ic_agent::Agent::builder()
        .with_url(IC_HOST)
        .with_identity(identity)
        .with_verify_query_signatures(true)
        .build()
        .expect("failed to build agent")
}

fn pretty_println<T>(data: &T) -> Result<(), String>
where
    T: CandidType,
{
    let val = IDLValue::try_from_candid_type(data).map_err(format_error)?;
    let doc = pp_value(7, &val);
    println!("{}", doc.pretty(120));
    Ok(())
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.replace("\\", "");
    const_hex::decode(s.strip_prefix("0x").unwrap_or(&s)).map_err(format_error)
}
