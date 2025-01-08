/// The `UserSignature` struct represents an end user's signature and provides methods to
/// parse and validate the signature from HTTP headers.
///
/// # Fields
/// - `pubkey`: User's public key
/// - `delegation`: Chain of signed delegations
/// - `signature`: Signature of the content digest
/// - `digest`: Hash of the request content
/// - `user`: Principal derived from public key
///
/// # Methods
/// - `try_from(headers: &HeaderMap) -> Option<Self>`:
///   Attempts to create a `UserSignature` from HTTP headers. Returns `Some(UserSignature)`
///   if successful, otherwise `None`.
///
/// - `validate_request(&self, now_ms: u64, tee_id: Principal) -> Result<(), AuthenticationError>`:
///   Validates the user signature and its delegations. Checks for expiration, delegation
///   targets, and verifies the signature. Returns `Ok(())` if valid, otherwise returns an
///   `AuthenticationError`.
///
/// # Errors
/// The `validate_request` method can return the following errors:
/// - `AuthenticationError::AnonymousSignatureNotAllowed`: If the signature belongs to an anonymous user.
/// - `AuthenticationError::DelegationTooLongError`: If the chain of delegations is too long.
/// - `AuthenticationError::InvalidDelegationExpiry`: If a delegation has expired.
/// - `AuthenticationError::InvalidPublicKey`: If the public key is invalid.
/// - `AuthenticationError::InvalidSignature`: If the signature is invalid.
/// - `AuthenticationError::InvalidDelegation`: If a delegation is invalid.
/// - `AuthenticationError::CanisterNotInDelegationTargets`: If the canister is not in the delegation targets.
///
/// # Constants
/// - `PERMITTED_DRIFT_MS`: Allowed time drift for expiration (30s)
/// - `ANONYMOUS_PRINCIPAL`: Anonymous user identifier
///
/// # Header Constants
/// - `HEADER_IC_TEE_PUBKEY`: Public key header
/// - `HEADER_IC_TEE_DELEGATION`: Delegation chain header
/// - `HEADER_IC_TEE_CONTENT_DIGEST`: Content hash header
/// - `HEADER_IC_TEE_SIGNATURE`: Signature header
/// - `HEADER_IC_TEE_ID`: TEE identifier header
/// - `HEADER_IC_TEE_CALLER`: Caller principal header
///
/// # Static Variables
/// - `IC_ROOT_PUBLIC_KEY`: The IC root public key used when verifying canister signatures.
///
use axum::http::header::{HeaderMap, HeaderName};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use candid::Principal;
use ciborium::from_reader;
use ic_canister_sig_creation::delegation_signature_msg;
use ic_crypto_standalone_sig_verifier::{
    user_public_key_from_bytes, verify_basic_sig_by_public_key, verify_canister_sig,
    KeyBytesContentType,
};
use ic_tee_cdk::SignedDelegation;
use ic_types::crypto::threshold_sig::IcRootOfTrust;
use lazy_static::lazy_static;
use thiserror::Error;

pub const PERMITTED_DRIFT_MS: u64 = 30 * 1000;
pub const ANONYMOUS_PRINCIPAL: Principal = Principal::anonymous();

pub static HEADER_X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
pub static HEADER_X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");
pub static HEADER_X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");

/// Caller's public key for authentication
pub static HEADER_IC_TEE_PUBKEY: HeaderName = HeaderName::from_static("ic-tee-pubkey");
/// Delegation chain for authentication
pub static HEADER_IC_TEE_DELEGATION: HeaderName = HeaderName::from_static("ic-tee-delegation");
/// Request content hash (customizable by business logic)
pub static HEADER_IC_TEE_CONTENT_DIGEST: HeaderName =
    HeaderName::from_static("ic-tee-content-digest");
/// Signature of the content digest
pub static HEADER_IC_TEE_SIGNATURE: HeaderName = HeaderName::from_static("ic-tee-signature");

/// TEE ID added to upstream requests
pub static HEADER_IC_TEE_ID: HeaderName = HeaderName::from_static("ic-tee-id");
/// TEE instance ID added to upstream requests
pub static HEADER_IC_TEE_INSTANCE: HeaderName = HeaderName::from_static("ic-tee-instance");
/// Authenticated caller principal (or anonymous principal)
pub static HEADER_IC_TEE_CALLER: HeaderName = HeaderName::from_static("ic-tee-caller");

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

/// Represents an end user's signature for HTTP request authentication.
#[derive(Clone, Debug)]
pub struct UserSignature {
    pub pubkey: Vec<u8>,
    pub delegation: Vec<SignedDelegation>,
    pub signature: Vec<u8>,
    pub digest: Vec<u8>,
    pub user: Principal,
}

impl UserSignature {
    pub fn try_from(headers: &HeaderMap) -> Option<Self> {
        if let Some(pubkey) = get_data(headers, &HEADER_IC_TEE_PUBKEY) {
            let user = Principal::self_authenticating(&pubkey);
            let mut sig = UserSignature {
                pubkey,
                delegation: Vec::new(),
                signature: Vec::new(),
                digest: Vec::new(),
                user,
            };
            if let Some(digest) = get_data(headers, &HEADER_IC_TEE_CONTENT_DIGEST) {
                sig.digest = digest;
            }
            if let Some(signature) = get_data(headers, &HEADER_IC_TEE_SIGNATURE) {
                sig.signature = signature;
                if let Some(data) = get_data(headers, &HEADER_IC_TEE_DELEGATION) {
                    if let Ok(delegation) = from_reader(&data[..]) {
                        sig.delegation = delegation;
                        return Some(sig);
                    }
                }
            }
        }

        None
    }

    /// Validation Rules
    /// - Rejects anonymous users
    /// - Delegation chain length ≤ 10
    /// - Delegations must not be expired
    /// - Signature must verify against the public key
    /// - Canister must be in delegation targets (if specified)
    pub fn validate_request(
        &self,
        now_ms: u64,
        tee_id: Principal,
    ) -> Result<(), AuthenticationError> {
        if self.user == ANONYMOUS_PRINCIPAL {
            return Err(AuthenticationError::AnonymousSignatureNotAllowed);
        }

        if self.delegation.len() > 10 {
            return Err(AuthenticationError::DelegationTooLongError {
                length: self.delegation.len(),
                maximum: 5,
            });
        }

        let mut has_targets = false;
        let mut in_targets = false;
        let mut last_verified = &self.pubkey;
        for d in &self.delegation {
            if d.delegation.expiration / 1_000_000 < now_ms - PERMITTED_DRIFT_MS {
                return Err(AuthenticationError::InvalidDelegationExpiry(format!(
                    "Delegation has expired:\n\
                     Provided expiry:    {}\n\
                     Local replica timestamp: {}",
                    d.delegation.expiration,
                    now_ms * 1_000_000,
                )));
            }

            let targets = match &d.delegation.targets {
                Some(targets) => {
                    has_targets = true;
                    in_targets = in_targets || targets.contains(&tee_id);
                    Some(
                        targets
                            .iter()
                            .map(|p| p.as_slice().to_vec())
                            .collect::<Vec<Vec<u8>>>(),
                    )
                }
                None => None,
            };

            let (pk, kt) = user_public_key_from_bytes(last_verified)
                .map_err(|e| AuthenticationError::InvalidPublicKey(e.to_string()))?;
            let msg = delegation_signature_msg(
                d.delegation.pubkey.as_slice(),
                d.delegation.expiration,
                targets.as_ref(),
            );
            match kt {
                KeyBytesContentType::IcCanisterSignatureAlgPublicKeyDer => {
                    verify_canister_sig(&msg, &d.signature, &pk.key, *IC_ROOT_PUBLIC_KEY)
                        .map_err(|e| AuthenticationError::InvalidDelegation(e.to_string()))?;
                }
                _ => {
                    verify_basic_sig_by_public_key(pk.algorithm_id, &msg, &d.signature, &pk.key)
                        .map_err(|e| AuthenticationError::InvalidDelegation(e.to_string()))?;
                }
            }

            last_verified = &d.delegation.pubkey;
        }

        if has_targets && !in_targets {
            return Err(AuthenticationError::CanisterNotInDelegationTargets(tee_id));
        }

        let (pk, _) = user_public_key_from_bytes(last_verified)
            .map_err(|e| AuthenticationError::InvalidPublicKey(e.to_string()))?;
        verify_basic_sig_by_public_key(pk.algorithm_id, &self.digest, &self.signature, &pk.key)
            .map_err(|e| AuthenticationError::InvalidSignature(e.to_string()))?;
        Ok(())
    }
}

/// Errors that can occur during signature validation
#[derive(Debug, Error)]
pub enum AuthenticationError {
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),
    #[error{"Chain of delegations is too long: got {length} delegations, but at most {maximum} are allowed."}]
    DelegationTooLongError { length: usize, maximum: usize },
    #[error("Invalid delegation expiry: {0}")]
    InvalidDelegationExpiry(String),
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    #[error("Invalid delegation: {0}")]
    InvalidDelegation(String),
    #[error("Signature is not allowed for the anonymous user.")]
    AnonymousSignatureNotAllowed,
    #[error("Canister '{0}' is not one of the delegation targets.")]
    CanisterNotInDelegationTargets(Principal),
}

fn get_data(headers: &HeaderMap, key: &HeaderName) -> Option<Vec<u8>> {
    if let Some(val) = headers.get(key) {
        if let Ok(val) = val.to_str() {
            if let Ok(data) = URL_SAFE_NO_PAD.decode(val.trim().trim_end_matches('=')) {
                return Some(data);
            }
        }
    }
    None
}
