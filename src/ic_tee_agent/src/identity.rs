use arc_swap::ArcSwap;
use candid::Principal;
use ed25519_consensus::SigningKey;
use ic_agent::{
    identity::{Delegation, SignedDelegation},
    {agent::EnvelopeContent, Signature},
};
use ic_cose::rand_bytes;
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub use ic_agent::identity::{AnonymousIdentity, BasicIdentity, DelegatedIdentity, Identity};

/// A thread-safe wrapper around an Identity implementation that can be atomically updated.
///
/// `AtomicIdentity` provides a way to safely share and update an identity across multiple threads.
/// It wraps any type that implements the `Identity` trait and allows for atomic updates of the
/// underlying identity.
pub struct AtomicIdentity {
    inner: ArcSwap<Box<dyn Identity>>,
}

impl Default for AtomicIdentity {
    /// Creates a new `AtomicIdentity` with an `AnonymousIdentity` as the default.
    ///
    /// # Returns
    /// A new `AtomicIdentity` instance with an anonymous identity.
    fn default() -> Self {
        Self::new(Box::new(AnonymousIdentity))
    }
}

impl AtomicIdentity {
    /// Creates a new `AtomicIdentity` with the provided identity.
    ///
    /// # Parameters
    /// * `identity` - A boxed implementation of the `Identity` trait.
    ///
    /// # Returns
    /// A new `AtomicIdentity` instance wrapping the provided identity.
    pub fn new(identity: Box<dyn Identity>) -> Self {
        Self {
            inner: ArcSwap::from(Arc::new(identity)),
        }
    }

    /// Gets a reference to the current identity.
    ///
    /// # Returns
    /// An `Arc` containing the current identity.
    pub fn get(&self) -> Arc<dyn Identity> {
        self.inner.load().clone()
    }

    /// Sets a new identity, replacing the current one.
    ///
    /// # Parameters
    /// * `identity` - A boxed implementation of the `Identity` trait to replace the current identity.
    pub fn set(&self, identity: Box<dyn Identity>) {
        self.inner.store(Arc::new(identity));
    }

    /// Checks if the identity is authenticated and not expired.
    ///
    /// An identity is considered authenticated if:
    /// 1. It has a valid sender principal that is not anonymous
    /// 2. Either it has no expiration time, or the expiration time is in the future
    ///
    /// # Returns
    /// `true` if the identity is authenticated and not expired, `false` otherwise.
    pub fn is_authenticated(&self) -> bool {
        match self.sender() {
            Err(_) => false,
            Ok(principal) => {
                if principal == Principal::anonymous() {
                    return false;
                }

                match get_expiration(self) {
                    None => true,
                    Some(expiration) => {
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .saturating_sub(Duration::from_secs(60))
                            .as_nanos() as u64;
                        expiration > now
                    }
                }
            }
        }
    }
}

impl From<Box<dyn Identity>> for AtomicIdentity {
    /// Creates an `AtomicIdentity` from a boxed `Identity` implementation.
    ///
    /// # Parameters
    /// * `identity` - A boxed implementation of the `Identity` trait.
    ///
    /// # Returns
    /// A new `AtomicIdentity` instance wrapping the provided identity.
    fn from(identity: Box<dyn Identity>) -> Self {
        Self::new(identity)
    }
}

impl Identity for AtomicIdentity {
    /// Gets the principal identifier associated with this identity.
    ///
    /// # Returns
    /// The principal identifier as a `Result<Principal, String>`.
    fn sender(&self) -> Result<Principal, String> {
        self.inner.load().sender()
    }

    /// Gets the public key associated with this identity, if available.
    ///
    /// # Returns
    /// An `Option<Vec<u8>>` containing the public key bytes, or `None` if not available.
    fn public_key(&self) -> Option<Vec<u8>> {
        self.inner.load().public_key()
    }

    /// Signs the provided envelope content using this identity.
    ///
    /// # Parameters
    /// * `content` - The envelope content to sign.
    ///
    /// # Returns
    /// A `Result<Signature, String>` containing the signature or an error message.
    fn sign(&self, content: &EnvelopeContent) -> Result<Signature, String> {
        self.inner.load().sign(content)
    }

    /// Signs a delegation using this identity.
    ///
    /// # Parameters
    /// * `content` - The delegation to sign.
    ///
    /// # Returns
    /// A `Result<Signature, String>` containing the signature or an error message.
    fn sign_delegation(&self, content: &Delegation) -> Result<Signature, String> {
        self.inner.load().sign_delegation(content)
    }

    /// Signs arbitrary content using this identity.
    ///
    /// # Parameters
    /// * `content` - The byte array to sign.
    ///
    /// # Returns
    /// A `Result<Signature, String>` containing the signature or an error message.
    fn sign_arbitrary(&self, content: &[u8]) -> Result<Signature, String> {
        self.inner.load().sign_arbitrary(content)
    }

    /// Gets the delegation chain associated with this identity.
    ///
    /// # Returns
    /// A vector of `SignedDelegation` objects representing the delegation chain.
    fn delegation_chain(&self) -> Vec<SignedDelegation> {
        self.inner.load().delegation_chain()
    }
}

/// Returns the smallest expiration time from the delegation chain, nanoseconds since UNIX epoch.
///
/// This function examines all delegations in the chain and returns the earliest expiration time.
///
/// # Parameters
/// * `identity` - Any type that implements the `Identity` trait.
///
/// # Returns
/// An `Option<u64>` containing the earliest expiration time in nanoseconds since the UNIX epoch,
/// or `None` if there are no delegations in the chain.
pub fn get_expiration(identity: &impl Identity) -> Option<u64> {
    let chain = identity.delegation_chain();
    if chain.is_empty() {
        return None;
    }

    let mut expiration = u64::MAX;
    for delegation in identity.delegation_chain() {
        if delegation.delegation.expiration < expiration {
            expiration = delegation.delegation.expiration;
        }
    }

    Some(expiration)
}

/// Converts an `ic_auth_types::SignedDelegation` to an `ic_agent::identity::SignedDelegation`.
///
/// This function is useful for interoperability between different Internet Computer SDK libraries.
///
/// # Parameters
/// * `src` - The source `SignedDelegation` from the `ic_auth_types` crate.
///
/// # Returns
/// A `SignedDelegation` from the `ic_agent::identity` module.
pub fn signed_delegation_from(src: ic_auth_types::SignedDelegation) -> SignedDelegation {
    SignedDelegation {
        delegation: Delegation {
            pubkey: src.delegation.pubkey.0,
            expiration: src.delegation.expiration,
            targets: src.delegation.targets,
        },
        signature: src.signature.0,
    }
}

/// Creates a `BasicIdentity` from a 32-byte secret key.
///
/// # Parameters
/// * `secret` - A 32-byte array containing the secret key.
///
/// # Returns
/// A `BasicIdentity` initialized with the provided secret key.
pub fn basic_identity(secret: [u8; 32]) -> BasicIdentity {
    let key = SigningKey::from(secret);
    BasicIdentity::from_signing_key(key)
}

/// Creates a new `BasicIdentity` with a randomly generated secret key.
///
/// # Returns
/// A `BasicIdentity` initialized with a randomly generated secret key.
pub fn new_basic_identity() -> BasicIdentity {
    let secret: [u8; 32] = rand_bytes();
    basic_identity(secret)
}

/// Creates a delegated identity from a basic identity with a specified expiration time.
///
/// This function creates a new session identity and delegates authority from the provided
/// identity to this session identity for the specified duration.
///
/// # Parameters
/// * `identity` - The `BasicIdentity` that will delegate authority.
/// * `expires_in_ms` - The duration in milliseconds after which the delegation expires.
///
/// # Returns
/// A `DelegatedIdentity` that can be used for the specified duration.
pub fn delegated_basic_identity(identity: &BasicIdentity, expires_in_ms: u64) -> DelegatedIdentity {
    let expiration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .saturating_add(Duration::from_millis(expires_in_ms));
    let session = new_basic_identity();
    let delegation = Delegation {
        pubkey: session.public_key().unwrap(),
        expiration: expiration.as_nanos() as u64,
        targets: None,
    };
    let signature = identity.sign_delegation(&delegation).unwrap();
    DelegatedIdentity::new_unchecked(
        identity.public_key().unwrap(),
        Box::new(session),
        vec![SignedDelegation {
            delegation,
            signature: signature.signature.unwrap(),
        }],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[test]
    fn test_atomic_identity_default() {
        let identity = AtomicIdentity::default();
        assert_eq!(identity.sender().unwrap(), Principal::anonymous());
        assert!(!identity.is_authenticated());
    }

    #[test]
    fn test_atomic_identity_new_and_get() {
        let basic = new_basic_identity();
        let principal = basic.sender().unwrap();
        let public_key = basic.public_key().unwrap();

        let atomic = AtomicIdentity::new(Box::new(basic));
        assert_eq!(atomic.sender().unwrap(), principal);
        assert_eq!(atomic.public_key().unwrap(), public_key);
        assert!(atomic.is_authenticated());
    }

    #[test]
    fn test_atomic_identity_set() {
        let atomic = AtomicIdentity::default();
        assert_eq!(atomic.sender().unwrap(), Principal::anonymous());

        let basic = new_basic_identity();
        let principal = basic.sender().unwrap();

        atomic.set(Box::new(basic));
        assert_eq!(atomic.sender().unwrap(), principal);
    }

    #[test]
    fn test_atomic_identity_from() {
        let basic = new_basic_identity();
        let principal = basic.sender().unwrap();
        let basic: Box<dyn Identity> = Box::new(basic);
        let atomic: AtomicIdentity = basic.into();
        assert_eq!(atomic.sender().unwrap(), principal);
    }

    #[test]
    fn test_atomic_identity_is_authenticated() {
        // 匿名身份不应该被认为是已认证的
        let anonymous = AtomicIdentity::default();
        assert!(!anonymous.is_authenticated());

        // 基本身份应该被认为是已认证的（没有过期时间）
        let basic = new_basic_identity();
        let atomic = AtomicIdentity::new(Box::new(basic));
        assert!(atomic.is_authenticated());

        // 测试过期的委托身份
        let basic = new_basic_identity();
        let expired = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .saturating_sub(Duration::from_secs(120)); // 2分钟前过期

        let session = new_basic_identity();
        let delegation = Delegation {
            pubkey: session.public_key().unwrap(),
            expiration: expired.as_nanos() as u64,
            targets: None,
        };
        let signature = basic.sign_delegation(&delegation).unwrap();
        let delegated = DelegatedIdentity::new_unchecked(
            basic.public_key().unwrap(),
            Box::new(session),
            vec![SignedDelegation {
                delegation,
                signature: signature.signature.unwrap(),
            }],
        );

        let atomic = AtomicIdentity::new(Box::new(delegated));
        assert!(!atomic.is_authenticated());

        // 测试未过期的委托身份
        let basic = new_basic_identity();
        let not_expired = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .saturating_add(Duration::from_secs(3600)); // 1小时后过期

        let session = new_basic_identity();
        let delegation = Delegation {
            pubkey: session.public_key().unwrap(),
            expiration: not_expired.as_nanos() as u64,
            targets: None,
        };
        let signature = basic.sign_delegation(&delegation).unwrap();
        let delegated = DelegatedIdentity::new_unchecked(
            basic.public_key().unwrap(),
            Box::new(session),
            vec![SignedDelegation {
                delegation,
                signature: signature.signature.unwrap(),
            }],
        );

        let atomic = AtomicIdentity::new(Box::new(delegated));
        assert!(atomic.is_authenticated());
    }

    #[test]
    fn test_get_expiration() {
        // 测试没有委托链的情况
        let basic = new_basic_identity();
        assert_eq!(get_expiration(&basic), None);

        // 测试有委托链的情况
        let basic = new_basic_identity();
        let expiration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .saturating_add(Duration::from_secs(3600))
            .as_millis() as u64;

        let delegated = delegated_basic_identity(&basic, 3600 * 1000);
        assert_eq!(get_expiration(&delegated).unwrap() / 1000000, expiration);

        // 测试多个委托的情况，应返回最早的过期时间
        let basic = new_basic_identity();
        let expiration1 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .saturating_add(Duration::from_secs(3600))
            .as_nanos() as u64;
        let expiration2 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .saturating_add(Duration::from_secs(1800))
            .as_nanos() as u64;

        let session1 = new_basic_identity();
        let delegation1 = Delegation {
            pubkey: session1.public_key().unwrap(),
            expiration: expiration1,
            targets: None,
        };
        let signature1 = basic.sign_delegation(&delegation1).unwrap();

        let session2 = new_basic_identity();
        let delegation2 = Delegation {
            pubkey: session2.public_key().unwrap(),
            expiration: expiration2,
            targets: None,
        };
        let signature2 = basic.sign_delegation(&delegation2).unwrap();

        let delegated = DelegatedIdentity::new_unchecked(
            basic.public_key().unwrap(),
            Box::new(session1),
            vec![
                SignedDelegation {
                    delegation: delegation1,
                    signature: signature1.signature.unwrap(),
                },
                SignedDelegation {
                    delegation: delegation2,
                    signature: signature2.signature.unwrap(),
                },
            ],
        );

        assert_eq!(get_expiration(&delegated), Some(expiration2)); // 应返回较早的过期时间
    }

    #[test]
    fn test_delegated_basic_identity() {
        let basic = new_basic_identity();
        let expires_in_ms = 3600 * 1000; // 1小时

        let delegated = delegated_basic_identity(&basic, expires_in_ms);

        // 验证委托链
        assert_eq!(delegated.delegation_chain().len(), 1);

        // 验证过期时间
        let expiration = get_expiration(&delegated).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        // 过期时间应该在未来
        assert!(expiration > now);
    }
}
