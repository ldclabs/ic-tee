use ic_crypto_standalone_sig_verifier::{
    user_public_key_from_bytes, verify_basic_sig_by_public_key, verify_canister_sig,
    KeyBytesContentType,
};
use ic_types::crypto::threshold_sig::IcRootOfTrust;
use lazy_static::lazy_static;

lazy_static! {
    /// The IC root public key used when verifying canister signatures.
    /// https://internetcomputer.org/docs/current/developer-docs/web-apps/obtain-verify-ic-pubkey
    /// remove der_prefix
    pub static ref IC_ROOT_PUBLIC_KEY: IcRootOfTrust =
    IcRootOfTrust::from([
        129, 76, 14, 110, 199, 31, 171, 88, 59, 8, 189, 129, 55, 60, 37, 92, 60, 55, 27, 46, 132, 134,
        60, 152, 164, 241, 224, 139, 116, 35, 93, 20, 251, 93, 156, 12, 213, 70, 217, 104, 95, 145, 58,
        12, 11, 44, 197, 52, 21, 131, 191, 75, 67, 146, 228, 103, 219, 150, 214, 91, 155, 180, 203,
        113, 113, 18, 248, 71, 46, 13, 90, 77, 20, 80, 95, 253, 116, 132, 176, 18, 145, 9, 28, 95, 135,
        185, 136, 131, 70, 63, 152, 9, 26, 11, 170, 174,
    ]);
}

pub fn verify_sig(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), String> {
    verify_sig_with_rootkey(&IC_ROOT_PUBLIC_KEY, pubkey, msg, sig)
}

pub fn verify_sig_with_rootkey(
    root: &IcRootOfTrust,
    pubkey: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> Result<(), String> {
    let (pk, kt) =
        user_public_key_from_bytes(pubkey).map_err(|err| format!("invalid public key: {err}"))?;
    match kt {
        KeyBytesContentType::IcCanisterSignatureAlgPublicKeyDer => {
            verify_canister_sig(msg, sig, &pk.key, root)
                .map_err(|err| format!("invalid signature: {err}"))
        }
        _ => verify_basic_sig_by_public_key(pk.algorithm_id, msg, sig, &pk.key)
            .map_err(|err| format!("invalid delegation: {err}")),
    }
}
