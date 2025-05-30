use ciborium::from_reader;
use ic_auth_types::ByteBufB64;
use ic_cose::rand_bytes;
use ic_cose_types::{
    cose::{
        encrypt0::{cose_decrypt0, cose_encrypt0},
        get_cose_key_secret, CborSerializable, CoseKey,
    },
    types::setting::SettingInfo,
    OwnedRef,
};
use serde::{Deserialize, Serialize};

pub fn decrypt_payload(
    info: &SettingInfo,
    secret: &[u8; 32],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let secret = if let Some(dek) = &info.dek {
        let key = cose_decrypt0(dek.as_slice(), secret, aad)?;
        let key =
            CoseKey::from_slice(&key).map_err(|err| format!("invalid COSE key: {:?}", err))?;
        let secret2 = get_cose_key_secret(key)?;
        if info.payload.is_none() {
            // payload in dek
            return Ok(secret2);
        }
        // get dek
        let secret: [u8; 32] = secret2.try_into().map_err(|val: Vec<u8>| {
            format!(
                "invalid COSE secret from DEK, expected 32 bytes, got {}",
                val.len()
            )
        })?;
        OwnedRef::Owned(secret)
    } else {
        OwnedRef::Ref(secret)
    };

    match &info.payload {
        None => Err("no payload".to_string()),
        Some(payload) => cose_decrypt0(payload.as_slice(), &secret, aad),
    }
}

pub fn decrypt_dek(info: &SettingInfo, secret: &[u8; 32], aad: &[u8]) -> Result<[u8; 32], String> {
    if let Some(dek) = &info.dek {
        let key = cose_decrypt0(dek.as_slice(), secret, aad)?;
        let key =
            CoseKey::from_slice(&key).map_err(|err| format!("invalid COSE key: {:?}", err))?;
        let secret2 = get_cose_key_secret(key)?;
        // get dek
        let secret: [u8; 32] = secret2.try_into().map_err(|val: Vec<u8>| {
            format!(
                "invalid COSE secret from DEK, expected 32 bytes, got {}",
                val.len()
            )
        })?;
        Ok(secret)
    } else {
        Err("no DEK".to_string())
    }
}

pub fn encrypt_payload(payload: &[u8], secret: &[u8; 32], aad: &[u8]) -> Result<Vec<u8>, String> {
    let nonce: [u8; 12] = rand_bytes();
    cose_encrypt0(payload, secret, aad, &nonce, None)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TLSPayload {
    pub crt: ByteBufB64, // PEM-encoded certificate
    pub key: ByteBufB64, // PEM-encoded private key
}

pub fn decrypt_tls(info: &SettingInfo, secret: &[u8; 32]) -> Result<TLSPayload, String> {
    let data = decrypt_payload(info, secret, &[])?;
    from_reader(&data[..]).map_err(|err| format!("failed to decode TLS payload: {:?}", err))
}
