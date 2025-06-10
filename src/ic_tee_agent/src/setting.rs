use ciborium::from_reader;
use ic_auth_types::cbor_into_vec;
use ic_auth_types::ByteBufB64;
use ic_cose::{
    rand_bytes,
    vetkeys::{DerivedPublicKey, IbeCiphertext, IbeIdentity, IbeSeed, VetKey},
};
use ic_cose_types::{
    cose::{
        encrypt0::{cose_decrypt0, cose_encrypt0},
        get_cose_key_secret, CborSerializable, CoseKey,
    },
    types::setting::SettingInfo,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::borrow::Cow;

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
        Cow::Owned(secret)
    } else {
        Cow::Borrowed(secret)
    };

    match &info.payload {
        None => Err("no payload".to_string()),
        Some(payload) => cose_decrypt0(payload.as_slice(), secret.as_ref(), aad),
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

pub fn vetkey_decrypt_payload(vk: &VetKey, data: &[u8]) -> Result<Vec<u8>, String> {
    let ciphertext = IbeCiphertext::deserialize(data)
        .map_err(|err| format!("failed to deserialize IbeCiphertext: {:?}", err))?;

    ciphertext
        .decrypt(vk)
        .map_err(|err| format!("failed to decrypt payload with VetKey: {:?}", err))
}

pub fn vetkey_encrypt_payload(
    dpk: &DerivedPublicKey,
    payload: &[u8],
    path_key: &[u8],
) -> Result<Vec<u8>, String> {
    let ibe_seed: [u8; 32] = rand_bytes();
    let ibe_seed = IbeSeed::from_bytes(&ibe_seed).unwrap();
    let ibe_id = IbeIdentity::from_bytes(path_key);
    let ciphertext = IbeCiphertext::encrypt(dpk, &ibe_id, payload, &ibe_seed);
    Ok(ciphertext.serialize())
}

pub fn vetkey_decrypt<T>(vk: &VetKey, data: &[u8]) -> Result<T, String>
where
    T: DeserializeOwned,
{
    let data = vetkey_decrypt_payload(vk, data)?;
    from_reader(&data[..]).map_err(|err| {
        format!(
            "failed to decode VetKey decrypted payload to type {}: {:?}",
            std::any::type_name::<T>(),
            err
        )
    })
}

pub fn vetkey_encrypt<T>(
    dpk: &DerivedPublicKey,
    value: &T,
    path_key: &[u8],
) -> Result<Vec<u8>, String>
where
    T: Serialize,
{
    let payload = cbor_into_vec(value)?;
    vetkey_encrypt_payload(dpk, &payload, path_key)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TLSPayload {
    pub crt: ByteBufB64, // PEM-encoded certificate
    pub key: ByteBufB64, // PEM-encoded private key
}
