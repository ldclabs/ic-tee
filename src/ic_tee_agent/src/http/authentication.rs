use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use candid::Principal;
use ciborium::from_reader;
use http::header::{HeaderMap, HeaderName};
use ic_agent::Identity;
use ic_canister_sig_creation::delegation_signature_msg;
use ic_cose_types::{cose::sha3_256, to_cbor_bytes};
use ic_tee_cdk::SignedDelegation;
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
/// - `AuthenticationError::VerifyFailed`: If verify failed.
/// - `AuthenticationError::AnonymousSignatureNotAllowed`: If the signature belongs to an anonymous user.
/// - `AuthenticationError::DelegationTooLongError`: If the chain of delegations is too long.
/// - `AuthenticationError::InvalidDelegationExpiry`: If a delegation has expired.
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
                match get_data(headers, &HEADER_IC_TEE_DELEGATION) {
                    Some(data) => {
                        if let Ok(delegation) = from_reader(&data[..]) {
                            sig.delegation = delegation;
                            return Some(sig);
                        }
                    }
                    None => return Some(sig),
                }
            }
        }

        None
    }

    /// Verify Rules
    /// - Rejects anonymous users
    /// - Delegation chain length ≤ 3
    /// - Delegations must not be expired
    /// - Signature must verify against the public key
    /// - Canister must be in delegation targets (if specified)
    pub fn verify_with(
        &self,
        canister: Principal,
        now_ms: u64,
        // fn verify_sig(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), String>
        verify: impl Fn(&[u8], &[u8], &[u8]) -> Result<(), String>,
    ) -> Result<(), AuthenticationError> {
        if self.user == ANONYMOUS_PRINCIPAL {
            return Err(AuthenticationError::AnonymousSignatureNotAllowed);
        }

        if self.delegation.len() > 3 {
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
                    in_targets = in_targets || targets.contains(&canister);
                    Some(
                        targets
                            .iter()
                            .map(|p| p.as_slice().to_vec())
                            .collect::<Vec<Vec<u8>>>(),
                    )
                }
                None => None,
            };

            let msg = delegation_signature_msg(
                d.delegation.pubkey.as_slice(),
                d.delegation.expiration,
                targets.as_ref(),
            );
            verify(last_verified, &msg, &d.signature).map_err(AuthenticationError::VerifyFailed)?;

            last_verified = &d.delegation.pubkey;
        }

        if has_targets && !in_targets {
            return Err(AuthenticationError::CanisterNotInDelegationTargets(
                canister,
            ));
        }

        verify(last_verified, &self.digest, &self.signature)
            .map_err(AuthenticationError::VerifyFailed)
    }
}

/// Errors that can occur during signature validation
#[derive(Debug, Error)]
pub enum AuthenticationError {
    #[error("Verify failed: {0}")]
    VerifyFailed(String),
    #[error{"Chain of delegations is too long: got {length} delegations, but at most {maximum} are allowed."}]
    DelegationTooLongError { length: usize, maximum: usize },
    #[error("Invalid delegation expiry: {0}")]
    InvalidDelegationExpiry(String),
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

pub fn sign_msg_to_headers(
    identity: impl Identity,
    headers: &mut HeaderMap,
    msg: &[u8],
) -> Result<(), String> {
    sign_digest_to_headers(identity, headers, &sha3_256(msg))
}

pub fn sign_digest_to_headers(
    identity: impl Identity,
    headers: &mut HeaderMap,
    digest: &[u8],
) -> Result<(), String> {
    let sig = identity
        .sign_arbitrary(digest)
        .map_err(|err| format!("{:?}", err))?;
    headers.insert(
        &HEADER_IC_TEE_PUBKEY,
        URL_SAFE_NO_PAD
            .encode(
                sig.public_key
                    .ok_or_else(|| "missing public_key".to_string())?,
            )
            .parse()
            .map_err(|err| format!("insert {HEADER_IC_TEE_PUBKEY} header failed: {err}"))?,
    );
    headers.insert(
        &HEADER_IC_TEE_CONTENT_DIGEST,
        URL_SAFE_NO_PAD
            .encode(digest)
            .parse()
            .map_err(|err| format!("insert {HEADER_IC_TEE_CONTENT_DIGEST} header failed: {err}"))?,
    );
    headers.insert(
        &HEADER_IC_TEE_SIGNATURE,
        URL_SAFE_NO_PAD
            .encode(
                sig.signature
                    .ok_or_else(|| "missing signature".to_string())?,
            )
            .parse()
            .map_err(|err| format!("insert {HEADER_IC_TEE_SIGNATURE} header failed: {err}"))?,
    );
    if let Some(delegations) = sig.delegations {
        headers.insert(
            &HEADER_IC_TEE_DELEGATION,
            URL_SAFE_NO_PAD
                .encode(to_cbor_bytes(&delegations))
                .parse()
                .map_err(|err| format!("insert {HEADER_IC_TEE_DELEGATION} header failed: {err}"))?,
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ic_sig_verifier::verify_sig;
    use ed25519_consensus::SigningKey;
    use ic_agent::{identity::BasicIdentity, Identity};
    use structured_logger::unix_ms;

    #[test]
    fn test_user_signature() {
        let secret = [8u8; 32];
        let sk = SigningKey::from(secret);
        let id = BasicIdentity::from_signing_key(sk);
        println!("id: {:?}", id.sender().unwrap().to_text());
        // jjn6g-sh75l-r3cxb-wxrkl-frqld-6p6qq-d4ato-wske5-op7s5-n566f-bqe

        let msg = b"hello world";
        let mut headers = HeaderMap::new();
        sign_msg_to_headers(id, &mut headers, msg).unwrap();

        let mut us = UserSignature::try_from(&headers).unwrap();
        assert!(us
            .verify_with(Principal::anonymous(), unix_ms(), verify_sig)
            .is_ok());

        us.digest = sha3_256(b"hello world 2").to_vec();
        assert!(us
            .verify_with(Principal::anonymous(), unix_ms(), verify_sig)
            .is_err());
    }
}
