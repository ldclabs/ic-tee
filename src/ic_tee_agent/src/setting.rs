use ciborium::from_reader;
use ic_cose_types::{
    cose::{encrypt0::cose_decrypt0, get_cose_key_secret, CborSerializable, CoseKey},
    types::setting::SettingInfo,
};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

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
