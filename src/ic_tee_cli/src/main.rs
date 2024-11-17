use anyhow::Result;
use candid::{pretty::candid::value::pp_value, CandidType, IDLValue, Principal};
use clap::{Parser, Subcommand};
use ed25519::pkcs8::{DecodePrivateKey, KeypairBytes};
use ed25519_consensus::SigningKey;
use ic_agent::{
    identity::{AnonymousIdentity, BasicIdentity},
    Identity,
};
use ic_cose_types::{
    cose::{cose_aes256_key, encrypt0::cose_encrypt0, CborSerializable},
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
        Encode, EncodePem,
    },
    AlgorithmIdentifierRef, PrivateKeyInfo,
};
use rand::thread_rng;
use serde_bytes::ByteBuf;
use std::path::Path;

static LOCAL_HOST: &str = "http://127.0.0.1:4943";
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

    #[arg(long)]
    ic: bool,

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
        #[arg(long)]
        doc: Option<String>,

        /// TEE attestation document url
        #[arg(long)]
        url: Option<String>,
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
        #[arg(long, default_value = "0")]
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
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let identity = load_identity(&cli.identity)?;
    let host = if cli.ic { IC_HOST } else { LOCAL_HOST };

    match &cli.command {
        Some(Commands::IdentityNew { path }) => {
            let signing_key = SigningKey::new(thread_rng());
            let private_key = OctetString::new(signing_key.as_bytes())?;
            let private_key = private_key.to_der()?;
            let id = BasicIdentity::from_signing_key(signing_key);
            let principal = id.sender().map_err(anyhow::Error::msg)?;
            let oid = ObjectIdentifier::new("1.3.101.112").map_err(anyhow::Error::msg)?;

            let pk = PrivateKeyInfo {
                algorithm: AlgorithmIdentifierRef {
                    oid,
                    parameters: None,
                },
                private_key: &private_key,
                public_key: None,
            };
            let pem = pk.to_pem(LineEnding::LF)?;

            let file = if path.is_empty() {
                format!("{}.pem", principal)
            } else {
                path.clone()
            };
            let file = Path::new(&file).to_path_buf();
            if file.try_exists().unwrap_or_default() {
                Err(anyhow::anyhow!("file already exists: {:?}", file))?;
            }

            std::fs::write(&file, pem.as_bytes())?;
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
                .map_err(|err| anyhow::anyhow!("invalid canister: {:?}", err))?;
            let user_key = canister_user_key(canister, kind, &seed, sub_seed.as_deref());
            let principal = Principal::self_authenticating(user_key.to_der());

            println!("principal: {}", principal);
        }

        Some(Commands::TeeVerify { kind, doc, url }) => {
            let doc = match (doc, url) {
                (Some(doc), None) => doc.to_owned(),
                (None, Some(url)) => {
                    
                    reqwest::get(url).await?.text().await?
                }
                _ => Err(anyhow::anyhow!("doc or url is required"))?,
            };
            let doc = decode_hex(&doc)?;
            let mut error: Option<String> = None;
            let doc = match parse_and_verify(&doc) {
                Ok(doc) => doc,
                Err(err) => {
                    error = Some(err);
                    let (_, doc) = parse(&doc).map_err(anyhow::Error::msg)?;
                    doc
                }
            };
            pretty_println(&doc)?;
            match error {
                Some(err) => println!("{} attestation verification failed: {}", kind, err),
                None => println!("{} attestation verification success", kind),
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
                .map_err(|err| anyhow::anyhow!("invalid COSE canister: {:?}", err))?;
            let agent = build_agent(host, identity).await;
            let path = SettingPath {
                ns: ns.clone(),
                user_owned: *user_owned,
                subject: subject.as_ref().map(Principal::from_text).transpose()?,
                key: ByteBuf::from(key.as_bytes()),
                version: *version,
            };

            let res: Result<SettingInfo, String> =
                query_call(&agent, &canister, "setting_get", (path,))
                    .await
                    .map_err(anyhow::Error::msg)?;
            let res = res.map_err(anyhow::Error::msg)?;
            pretty_println(&res)?;
        }

        Some(Commands::SettingSaveIdentity { ns, path }) => {
            let canister = Principal::from_text(&cli.canister)
                .map_err(|err| anyhow::anyhow!("invalid COSE canister: {:?}", err))?;
            let content = std::fs::read_to_string(path)?;
            let id = BasicIdentity::from_pem(content.as_bytes())?;
            let principal = id.sender().map_err(anyhow::Error::msg)?;
            let keypair = KeypairBytes::from_pkcs8_pem(&content)?;
            let agent = build_agent(host, identity).await;
            let path = SettingPath {
                ns: ns.clone(),
                user_owned: false,
                subject: Some(principal),
                key: ByteBuf::from(SETTING_KEY_ID.as_bytes()),
                version: 0,
            };
            let secret = get_cose_secret(&agent, &canister, path.clone())
                .await
                .map_err(anyhow::Error::msg)?;
            let key = cose_aes256_key(keypair.secret_key, principal.as_slice().to_vec());
            let key = key.to_vec().unwrap();
            let nonce: [u8; 12] = rand_bytes();
            let payload =
                cose_encrypt0(&key, &secret, &[], nonce, None).map_err(anyhow::Error::msg)?;
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
            .await
            .map_err(anyhow::Error::msg)?;
            let res = res.map_err(anyhow::Error::msg)?;
            pretty_println(&res)?;
        }

        Some(Commands::SettingSaveTLS {
            ns,
            subject,
            key_file,
            cert_file,
        }) => {
            let canister = Principal::from_text(&cli.canister)
                .map_err(|err| anyhow::anyhow!("invalid COSE canister: {:?}", err))?;
            let subject = Principal::from_text(subject)
                .map_err(|err| anyhow::anyhow!("invalid subject: {:?}", err))?;
            let key_data = std::fs::read_to_string(key_file)?;
            let cert_data = std::fs::read_to_string(cert_file)?;
            let tls = TLSPayload {
                crt: cert_data.as_bytes().to_vec().into(),
                key: key_data.as_bytes().to_vec().into(),
            };
            // call CryptoProvider::install_default() before this point
            // let _ = RustlsConfig::from_pem(tls.crt.to_vec(), tls.key.to_vec())
            //     .await
            //     .map_err(|err| anyhow::anyhow!("read tls file failed: {:?}", err))?;
            let agent = build_agent(host, identity).await;
            let dek: [u8; 32] = rand_bytes();
            let nonce: [u8; 12] = rand_bytes();
            let payload = to_cbor_bytes(&tls);
            let payload =
                cose_encrypt0(&payload, &dek, &[], nonce, None).map_err(anyhow::Error::msg)?;

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
            .await
            .map_err(anyhow::Error::msg)?;
            let dek = cose_aes256_key(dek, COSE_SECRET_PERMANENT_KEY.as_bytes().to_vec());
            let dek = dek.to_vec().unwrap();
            let nonce: [u8; 12] = rand_bytes();
            let dek = cose_encrypt0(&dek, &secret, &[], nonce, None).map_err(anyhow::Error::msg)?;
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
            .await
            .map_err(anyhow::Error::msg)?;
            let res = res.map_err(anyhow::Error::msg)?;
            pretty_println(&res)?;
        }

        None => {
            let principal = identity.sender().unwrap();
            println!("principal: {}", principal);
        }
    }

    Ok(())
}

fn load_identity(path: &str) -> Result<Box<dyn Identity>> {
    if path == "Anonymous" {
        return Ok(Box::new(AnonymousIdentity));
    }

    let content = std::fs::read_to_string(path)?;
    match BasicIdentity::from_pem(content.as_bytes()) {
        Ok(identity) => Ok(Box::new(identity)),
        Err(err) => Err(err.into()),
    }
}

async fn build_agent(host: &str, identity: Box<dyn Identity>) -> ic_agent::Agent {
    let agent = ic_agent::Agent::builder()
        .with_url(host)
        .with_identity(identity)
        .with_verify_query_signatures(true)
        .build()
        .expect("failed to build agent");
    if host.starts_with("http://") {
        agent.fetch_root_key().await.expect("fetch root key failed");
    }
    agent
}

fn pretty_println<T>(data: &T) -> Result<()>
where
    T: CandidType,
{
    let val = IDLValue::try_from_candid_type(data)?;
    let doc = pp_value(7, &val);
    println!("{}", doc.pretty(120));
    Ok(())
}

fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.replace("\\", "");
    const_hex::decode(s.strip_prefix("0x").unwrap_or(&s)).map_err(anyhow::Error::msg)
}
