use candid::{CandidType, Principal};
use ic_canister_sig_creation::CanisterSigPublicKey;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::{sha3_256_n, to_cbor_bytes};

pub const SESSION_EXPIRES_IN_MS: u64 = 1000 * 3600 * 24; // 1 day

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct Delegation {
    pub pubkey: ByteBuf,
    pub expiration: u64,
    pub targets: Option<Vec<Principal>>,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct SignedDelegation {
    pub delegation: Delegation,
    pub signature: ByteBuf,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
pub struct SignInParams {
    pub id_scope: String, // should be "image" or "enclave"
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct SignInResponse {
    /// The session expiration time in nanoseconds since the UNIX epoch. This is the time at which
    /// the delegation will no longer be valid.
    pub expiration: u64,
    /// The user canister public key. This key is used to derive the user principal.
    pub user_key: ByteBuf,
    /// seed is a part of the user_key
    pub seed: ByteBuf,
}

pub fn canister_user_key(
    canister: Principal,
    kind: &str, // should be "NITRO"
    seed: &[u8],
    sub_seed: Option<&[u8]>,
) -> CanisterSigPublicKey {
    let seed = if let Some(sub_seed) = sub_seed {
        to_cbor_bytes(&(kind, sha3_256_n([seed, sub_seed])))
    } else {
        to_cbor_bytes(&(kind, sha3_256_n([seed])))
    };
    CanisterSigPublicKey::new(canister, seed)
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
        let kind = "NITRO";
        let seed = [8u8; 32];
        let user_key = canister_user_key(canister, kind, &seed, None).to_der();
        println!("{:?}", const_hex::encode(user_key.as_slice()));
        assert!(is_sub(&user_key, canister.as_slice()));
        assert!(is_sub(&user_key, kind.as_bytes()));
        assert!(!is_sub(&user_key, seed.as_slice()));

        let sub_seed = [1u8, 2u8, 3u8, 4u8];
        let user_key2 = canister_user_key(canister, kind, &seed, Some(&sub_seed)).to_der();
        assert_ne!(user_key, user_key2);
        assert!(!is_sub(&user_key2, seed.as_slice()));
        assert!(!is_sub(&user_key2, sub_seed.as_slice()));
    }
}
