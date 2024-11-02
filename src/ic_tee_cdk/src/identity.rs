use candid::{CandidType, Principal};
use ic_canister_sig_creation::CanisterSigPublicKey;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha3::{Digest, Sha3_256};

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct Delegation {
    pub pubkey: ByteBuf,
    pub expiration: u64,
    pub targets: Option<Vec<Principal>>,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct SignedDelegation {
    pub delegation: Delegation,
    pub signature: ByteBuf,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct SignInResponse {
    /// The session expiration time in nanoseconds since the UNIX epoch. This is the time at which
    /// the delegation will no longer be valid.
    pub expiration: u64,
    /// The user canister public key. This key is used to derive the user principal.
    pub user_key: ByteBuf,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct AttestationUserRequest<T> {
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<T>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SignInParams {
    pub id_scope: String, // should be "image" or "enclave"
}

pub fn canister_user_key(
    canister: Principal,
    kind: &str, // should be "Nitro"
    seed: &[u8],
    sub_seed: Option<&[u8]>,
) -> Vec<u8> {
    let len = 1 + kind.len() + 32;
    let mut data = Vec::with_capacity(len);
    data.push(kind.len() as u8);
    data.extend_from_slice(kind.to_uppercase().as_bytes());
    data.resize(len, 0u8);

    let mut hasher = Sha3_256::new();
    hasher.update(seed);
    if let Some(seed) = sub_seed {
        hasher.update(seed);
    }
    let (_, buf) = data.split_last_chunk_mut::<32>().unwrap();
    hasher.finalize_into(buf.into());
    CanisterSigPublicKey::new(canister, data).to_der()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_sub(s: &[u8], sub: &[u8]) -> bool {
        s.windows(sub.len()).any(|w| w == sub)
    }

    #[test]
    fn test_canister_user_key() {
        let canister = Principal::from_text("e7tgb-6aaaa-aaaap-akqfa-cai").unwrap();
        let kind = "Nitro";
        let seed = [8u8; 48];
        let user_key = canister_user_key(canister, kind, &seed, None);
        assert!(is_sub(&user_key, canister.as_slice()));
        assert!(is_sub(&user_key, kind.to_uppercase().as_bytes()));
        assert!(!is_sub(&user_key, seed.as_slice()));

        let user_key2 = canister_user_key(canister, kind, &seed, Some(&[1u8, 2u8, 3u8, 4u8]));
        assert_ne!(user_key, user_key2);

        let user_key3 = canister_user_key(canister, kind, &seed, Some(&[1u8, 2u8, 3u8, 5u8]));
        assert_ne!(user_key2, user_key3);
    }
}
