use candid::Principal;
use ciborium::from_reader;
use ic_agent::Agent;
use ic_cose_types::{
    cose::{
        ecdh::ecdh_x25519, encrypt0::cose_decrypt0, get_cose_key_secret, CborSerializable, CoseKey,
    },
    types::{setting::SettingInfo, ECDHInput, ECDHOutput, SettingPath},
};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{agent::update_call, rand_bytes};

pub async fn get_cose_secret(
    agent: &Agent,
    canister: &Principal,
    path: SettingPath,
) -> Result<[u8; 32], String> {
    let nonce: [u8; 12] = rand_bytes();
    let secret: [u8; 32] = rand_bytes();
    let secret = StaticSecret::from(secret);
    let public = PublicKey::from(&secret);
    let subject = if let Some(subject) = path.subject {
        subject
    } else {
        agent.get_principal()?
    };

    let res: Result<ECDHOutput<ByteBuf>, String> = update_call(
        agent,
        canister,
        "ecdh_cose_encrypted_key",
        (
            path,
            ECDHInput {
                nonce: nonce.into(),
                public_key: public.to_bytes().into(),
            },
        ),
    )
    .await;
    let res = res?;
    let (shared_secret, _) = ecdh_x25519(secret.to_bytes(), *res.public_key);
    let add = subject.as_slice();
    let kek = cose_decrypt0(&res.payload, &shared_secret.to_bytes(), add)?;
    let key = CoseKey::from_slice(&kek).map_err(|err| format!("invalid COSE key: {:?}", err))?;
    let secret = get_cose_key_secret(key)?;
    secret.try_into().map_err(|val: Vec<u8>| {
        format!("invalid COSE secret, expected 32 bytes, got {}", val.len())
    })
}

pub fn decrypt_payload(info: SettingInfo, mut secret: [u8; 32]) -> Result<Vec<u8>, String> {
    let aad: &[u8] = &[];
    if let Some(dek) = info.dek {
        let key = cose_decrypt0(dek.as_slice(), &secret, aad)?;
        let key =
            CoseKey::from_slice(&key).map_err(|err| format!("invalid COSE key: {:?}", err))?;
        let secret2 = get_cose_key_secret(key)?;
        if info.payload.is_none() {
            // payload in dek
            return Ok(secret2);
        }
        // get dek
        secret = secret2.try_into().map_err(|val: Vec<u8>| {
            format!("invalid COSE secret, expected 32 bytes, got {}", val.len())
        })?;
    }

    match info.payload {
        None => Err("no payload".to_string()),
        Some(payload) => cose_decrypt0(payload.as_slice(), &secret, aad),
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TLSPayload {
    pub crt: ByteBuf, // PEM-encoded certificate
    pub key: ByteBuf, // PEM-encoded private key
}

pub fn decrypt_tls(info: SettingInfo, secret: [u8; 32]) -> Result<TLSPayload, String> {
    let data = decrypt_payload(info, secret)?;
    from_reader(&data[..]).map_err(|err| format!("failed to decode TLS payload: {:?}", err))
}
