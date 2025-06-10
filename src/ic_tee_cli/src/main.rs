use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use candid::{pretty::candid::value::pp_value, CandidType, IDLValue, Principal};
use clap::{Parser, Subcommand};
use ed25519_consensus::SigningKey;
use ic_agent::{
    identity::{AnonymousIdentity, BasicIdentity, Secp256k1Identity},
    Identity,
};
use ic_cose::{
    agent::build_agent,
    client::{Client, CoseSDK},
    rand_bytes,
    vetkeys::DerivedPublicKey,
};
use ic_cose_types::{
    cose::{cose_aes256_key, encrypt0::cose_encrypt0, CborSerializable},
    to_cbor_bytes,
    types::{
        setting::{CreateSettingInput, UpdateSettingPayloadInput},
        SettingPath,
    },
    BoxError,
};
use ic_tee_agent::setting::{
    decrypt_dek, decrypt_payload, vetkey_decrypt_payload, vetkey_encrypt, vetkey_encrypt_payload,
    TLSPayload,
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
use rand::RngCore;
use serde_bytes::ByteBuf;
use std::{path::Path, sync::Arc, vec};

static LOCAL_HOST: &str = "http://127.0.0.1:4943";
static IC_HOST: &str = "https://icp-api.io";
static SETTING_KEY_TLS: &str = "tls";

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
        #[arg(long, default_value = "NITRO")]
        kind: String,

        #[arg(long)]
        seed: String,

        /// sub seed to derive the principal
        #[arg(long)]
        sub_seed: Option<String>,
    },
    RandBytes {
        #[arg(long, default_value = "32")]
        len: usize,

        #[arg(long, default_value = "hex")]
        format: String,
    },
    /// verify a TEE attestation document
    TeeVerify {
        /// TEE kind to verify
        #[arg(long, default_value = "NITRO")]
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

        #[arg(long, default_value = "false")]
        vetkey: bool,
    },
    /// save a identity to the COSE canister
    SettingUpsertFile {
        /// The setting's namespace
        #[arg(long)]
        ns: String,
        /// setting's subject
        #[arg(long)]
        subject: String,
        /// setting's key
        #[arg(long)]
        key: String,
        /// file to save
        #[arg(long)]
        file: String,

        #[arg(long)]
        desc: Option<String>,

        #[arg(long, default_value = "0")]
        version: u32,

        #[arg(long, default_value = "false")]
        vetkey: bool,
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

        #[arg(long, default_value = "false")]
        vetkey: bool,
    },
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let cli = Cli::parse();
    let identity = load_identity(&cli.identity)?;
    let identity = Arc::new(identity);
    let host = if cli.ic { IC_HOST } else { LOCAL_HOST };

    match &cli.command {
        Some(Commands::IdentityNew { path }) => {
            let secret: [u8; 32] = rand_bytes();
            let signing_key = SigningKey::from(secret);
            let private_key = OctetString::new(signing_key.as_bytes())?;
            let private_key = private_key.to_der()?;
            let id = BasicIdentity::from_signing_key(signing_key);
            let principal = id.sender()?;
            let oid = ObjectIdentifier::new("1.3.101.112").unwrap();

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
                Err(format!("file already exists: {:?}", file))?;
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
            let canister = Principal::from_text(&cli.canister)?;
            let user_key = canister_user_key(canister, kind, &seed, sub_seed.as_deref());
            let principal = Principal::self_authenticating(user_key.to_der());

            println!("principal: {}", principal);
        }

        Some(Commands::RandBytes { len, format }) => {
            let mut rng = rand::rng();
            let mut bytes = vec![0u8; (*len).min(1024)];
            rng.fill_bytes(&mut bytes);
            match format.as_str() {
                "hex" => {
                    println!("{}", const_hex::encode(&bytes));
                }
                "base64" => {
                    println!("{}", BASE64_URL_SAFE_NO_PAD.encode(&bytes));
                }
                _ => {
                    println!("{:?}", bytes);
                }
            }
        }

        Some(Commands::TeeVerify { kind, doc, url }) => {
            let doc = match (doc, url) {
                (Some(doc), None) => doc.to_owned(),
                (None, Some(url)) => reqwest::get(url).await?.text().await?,
                _ => Err("doc or url is required".to_string())?,
            };
            let doc = decode_hex(&doc)?;
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
            vetkey,
        }) => {
            let canister = Principal::from_text(&cli.canister)?;
            let agent = Arc::new(build_agent(host, identity).await?);
            let cose = Client::new(agent.clone(), canister);
            let path = SettingPath {
                ns: ns.clone(),
                user_owned: *user_owned,
                subject: subject.as_ref().map(Principal::from_text).transpose()?,
                key: ByteBuf::from(key.as_bytes()),
                version: *version,
            };

            let res = cose.setting_get(&path).await?;
            if res.dek.is_some() {
                let secret = cose.get_cose_encrypted_key(&path).await?;
                let payload = decrypt_payload(&res, &secret, &[])?;
                pretty_println(&res)?;
                if let Ok(doc) = String::from_utf8(payload.clone()) {
                    println!("-----------:payload:-----------\n{}", doc);
                } else {
                    println!(
                        "-----------:payload:-----------\n{}",
                        const_hex::encode(&payload)
                    );
                }
            } else if *vetkey && res.payload.is_some() {
                let (vk, _dpk) = cose.vetkey(&path).await?;
                let payload = vetkey_decrypt_payload(&vk, &res.payload.unwrap())?;
                if let Ok(doc) = String::from_utf8(payload.clone()) {
                    println!("-----------:payload:-----------\n{}", doc);
                } else {
                    println!(
                        "-----------:payload:-----------\n{}",
                        const_hex::encode(&payload)
                    );
                }
            } else {
                pretty_println(&res)?;
            }
        }

        Some(Commands::SettingUpsertFile {
            ns,
            subject,
            key,
            file,
            desc,
            version,
            vetkey,
        }) => {
            let canister = Principal::from_text(&cli.canister)?;
            let subject = Principal::from_text(subject)?;
            let content = std::fs::read(file)?;
            let agent = Arc::new(build_agent(host, identity).await?);
            let cose = Client::new(agent.clone(), canister);
            let path = SettingPath {
                ns: ns.clone(),
                user_owned: false,
                subject: Some(subject),
                key: ByteBuf::from(key.as_bytes()),
                version: *version,
            };

            // create setting with version 0
            if path.version == 0 {
                let (payload, dek) = if *vetkey {
                    let dpk = cose.vetkd_public_key(&path).await?;
                    let dpk = DerivedPublicKey::deserialize(&dpk).map_err(|err| {
                        format!("failed to deserialize DerivedPublicKey: {:?}", err)
                    })?;
                    let payload = vetkey_encrypt_payload(&dpk, &content, &path.key)?;
                    (Some(payload.into()), None)
                } else {
                    let secret = cose.get_cose_encrypted_key(&path).await?;
                    let dek: [u8; 32] = rand_bytes();
                    let nonce: [u8; 12] = rand_bytes();
                    let payload = cose_encrypt0(&content, &dek, &[], &nonce, None)?;
                    let dek = cose_aes256_key(dek, path.key.to_vec());
                    let dek = dek.to_vec().unwrap();
                    let nonce: [u8; 12] = rand_bytes();
                    let dek = cose_encrypt0(&dek, &secret, &[], &nonce, None)?;
                    (Some(payload.into()), Some(dek.into()))
                };

                let res = cose
                    .setting_create(
                        &path,
                        &CreateSettingInput {
                            dek,
                            payload,
                            desc: desc.clone(),
                            status: None,
                            tags: None,
                        },
                    )
                    .await?;
                pretty_println(&res)?;
            } else if *vetkey {
                let dpk = cose.vetkd_public_key(&path).await?;
                let dpk = DerivedPublicKey::deserialize(&dpk)
                    .map_err(|err| format!("failed to deserialize DerivedPublicKey: {:?}", err))?;
                let payload = vetkey_encrypt_payload(&dpk, &content, &path.key)?;
                let res = cose
                    .setting_update_payload(
                        &path,
                        &UpdateSettingPayloadInput {
                            payload: Some(payload.into()),
                            ..Default::default()
                        },
                    )
                    .await?;
                pretty_println(&res)?;
            } else {
                let res = cose.setting_get(&path).await?;
                let secret = cose.get_cose_encrypted_key(&path).await?;
                let secret = decrypt_dek(&res, &secret, &[])?;
                let nonce: [u8; 12] = rand_bytes();
                let payload = cose_encrypt0(&content, &secret, &[], &nonce, None)?;
                let res = cose
                    .setting_update_payload(
                        &path,
                        &UpdateSettingPayloadInput {
                            payload: Some(payload.into()),
                            ..Default::default()
                        },
                    )
                    .await?;
                pretty_println(&res)?;
            }
        }

        Some(Commands::SettingSaveTLS {
            ns,
            subject,
            key_file,
            cert_file,
            vetkey,
        }) => {
            let canister = Principal::from_text(&cli.canister)?;
            let subject = Principal::from_text(subject)?;
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
            let agent = Arc::new(build_agent(host, identity).await?);
            let cose = Client::new(agent.clone(), canister);
            let path = SettingPath {
                ns: ns.clone(),
                user_owned: false,
                subject: Some(subject),
                key: ByteBuf::from(SETTING_KEY_TLS.as_bytes()),
                version: 0,
            };
            let (payload, dek) = if *vetkey {
                let dpk = cose.vetkd_public_key(&path).await?;
                let dpk = DerivedPublicKey::deserialize(&dpk)
                    .map_err(|err| format!("failed to deserialize DerivedPublicKey: {:?}", err))?;
                let payload = vetkey_encrypt(&dpk, &tls, &path.key)?;
                (Some(payload.into()), None)
            } else {
                let dek: [u8; 32] = rand_bytes();
                let nonce: [u8; 12] = rand_bytes();
                let payload = to_cbor_bytes(&tls);
                let payload = cose_encrypt0(&payload, &dek, &[], &nonce, None)?;

                let secret = cose.get_cose_encrypted_key(&path).await?;
                let dek = cose_aes256_key(dek, path.key.to_vec());
                let dek = dek.to_vec().unwrap();
                let nonce: [u8; 12] = rand_bytes();
                let dek = cose_encrypt0(&dek, &secret, &[], &nonce, None)?;
                (Some(payload.into()), Some(dek.into()))
            };

            let res = cose
                .setting_create(
                    &SettingPath {
                        ns: ns.clone(),
                        user_owned: false,
                        subject: Some(subject),
                        key: ByteBuf::from(SETTING_KEY_TLS.as_bytes()),
                        version: 0,
                    },
                    &CreateSettingInput {
                        dek,
                        payload,
                        desc: None,
                        status: None,
                        tags: None,
                    },
                )
                .await?;
            pretty_println(&res)?;
        }

        None => {
            let principal = identity.sender().unwrap();
            println!("principal: {}", principal);
        }
    }

    Ok(())
}

fn load_identity(path: &str) -> Result<Box<dyn Identity>, BoxError> {
    if path == "Anonymous" {
        return Ok(Box::new(AnonymousIdentity));
    }

    let content = std::fs::read_to_string(path)?;
    match Secp256k1Identity::from_pem(content.as_bytes()) {
        Ok(identity) => Ok(Box::new(identity)),
        Err(_) => match BasicIdentity::from_pem(content.as_bytes()) {
            Ok(identity) => Ok(Box::new(identity)),
            Err(err) => Err(err.into()),
        },
    }
}

fn pretty_println<T>(data: &T) -> Result<(), BoxError>
where
    T: CandidType,
{
    let val = IDLValue::try_from_candid_type(data)?;
    let doc = pp_value(7, &val);
    println!("{}", doc.pretty(120));
    Ok(())
}

fn decode_hex(s: &str) -> Result<Vec<u8>, BoxError> {
    let s = s.replace("\\", "");
    let rt = const_hex::decode(s.strip_prefix("0x").unwrap_or(&s))?;
    Ok(rt)
}
