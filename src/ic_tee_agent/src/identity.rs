use candid::Principal;
use ed25519_consensus::SigningKey;
use ic_agent::{
    identity::{DelegatedIdentity, Delegation, SignedDelegation},
    {agent::EnvelopeContent, Signature},
};
use ic_tee_cdk::identity;
use rand::thread_rng;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub use ic_agent::identity::{AnonymousIdentity, BasicIdentity, Identity};

enum InnerIdentity {
    Anonymous(AnonymousIdentity),
    Delegated(DelegatedIdentity),
}

pub struct TEEIdentity {
    identity: InnerIdentity,
    signing_key: SigningKey,
    delegation: Vec<SignedDelegation>,
    user_key: Vec<u8>,
    session_key: Vec<u8>,
    principal: Principal,
    expiration: u64, // ns since UNIX epoch
}

impl Default for TEEIdentity {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for TEEIdentity {
    fn clone(&self) -> Self {
        Self {
            identity: match &self.identity {
                InnerIdentity::Anonymous(id) => InnerIdentity::Anonymous(*id),
                InnerIdentity::Delegated(_) => {
                    InnerIdentity::Delegated(DelegatedIdentity::new_unchecked(
                        self.user_key.clone(),
                        Box::new(BasicIdentity::from_signing_key(self.signing_key.clone())),
                        self.delegation.clone(),
                    ))
                }
            },
            signing_key: self.signing_key.clone(),
            delegation: self.delegation.clone(),
            user_key: self.user_key.clone(),
            session_key: self.session_key.clone(),
            principal: self.principal,
            expiration: self.expiration,
        }
    }
}

impl TEEIdentity {
    pub fn new() -> Self {
        let signing_key = SigningKey::new(thread_rng());
        let basic = BasicIdentity::from_signing_key(SigningKey::new(thread_rng()));
        Self {
            identity: InnerIdentity::Anonymous(AnonymousIdentity),
            signing_key,
            delegation: vec![],
            user_key: vec![],
            session_key: basic.public_key().unwrap(),
            principal: AnonymousIdentity.sender().unwrap(),
            expiration: 0,
        }
    }

    pub fn is_authenticated(&self) -> bool {
        match &self.identity {
            InnerIdentity::Anonymous(_) => false,
            InnerIdentity::Delegated(_) => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .saturating_sub(Duration::from_secs(300));
                !now.is_zero() && now.as_nanos() < self.expiration as u128
            }
        }
    }

    pub fn session_key(&self) -> Vec<u8> {
        self.session_key.clone()
    }

    pub fn principal(&self) -> Principal {
        self.principal
    }

    pub fn upgrade_with(&mut self, identity: &BasicIdentity, expires_in_ms: u64) {
        let expiration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .saturating_add(Duration::from_millis(expires_in_ms));
        let delegation = Delegation {
            pubkey: self.session_key.clone(),
            expiration: expiration.as_nanos() as u64,
            targets: None,
        };
        let signature = identity.sign_delegation(&delegation).unwrap();
        self.principal = identity.sender().unwrap();
        self.user_key = identity.public_key().unwrap();
        self.expiration = delegation.expiration;
        self.delegation = vec![SignedDelegation {
            delegation,
            signature: signature.signature.unwrap(),
        }];
        let id = DelegatedIdentity::new_unchecked(
            self.user_key.clone(),
            Box::new(BasicIdentity::from_signing_key(self.signing_key.clone())),
            self.delegation.clone(),
        );
        self.identity = InnerIdentity::Delegated(id);
    }

    pub fn with_user_key(&mut self, user_key: Vec<u8>) {
        self.principal = Principal::self_authenticating(&user_key);
        self.user_key = user_key;
    }

    pub fn with_delegation(
        &mut self,
        delegation: identity::SignedDelegation,
    ) -> Result<(), String> {
        if delegation.delegation.pubkey != self.session_key {
            return Err("delegation pubkey does not match".to_string());
        }

        self.expiration = delegation.delegation.expiration;
        self.delegation = vec![SignedDelegation {
            delegation: Delegation {
                pubkey: delegation.delegation.pubkey.to_vec(),
                expiration: delegation.delegation.expiration,
                targets: delegation.delegation.targets.clone(),
            },
            signature: delegation.signature.to_vec(),
        }];
        let id = DelegatedIdentity::new_unchecked(
            self.user_key.clone(),
            Box::new(BasicIdentity::from_signing_key(self.signing_key.clone())),
            self.delegation.clone(),
        );
        self.identity = InnerIdentity::Delegated(id);
        Ok(())
    }
}

impl Identity for TEEIdentity {
    fn sender(&self) -> Result<Principal, String> {
        match &self.identity {
            InnerIdentity::Anonymous(id) => id.sender(),
            InnerIdentity::Delegated(id) => id.sender(),
        }
    }
    fn public_key(&self) -> Option<Vec<u8>> {
        match &self.identity {
            InnerIdentity::Anonymous(id) => id.public_key(),
            InnerIdentity::Delegated(id) => id.public_key(),
        }
    }
    fn sign(&self, content: &EnvelopeContent) -> Result<Signature, String> {
        match &self.identity {
            InnerIdentity::Anonymous(id) => id.sign(content),
            InnerIdentity::Delegated(id) => id.sign(content),
        }
    }
    fn sign_delegation(&self, content: &Delegation) -> Result<Signature, String> {
        match &self.identity {
            InnerIdentity::Anonymous(id) => id.sign_delegation(content),
            InnerIdentity::Delegated(id) => id.sign_delegation(content),
        }
    }
    fn sign_arbitrary(&self, content: &[u8]) -> Result<Signature, String> {
        match &self.identity {
            InnerIdentity::Anonymous(id) => id.sign_arbitrary(content),
            InnerIdentity::Delegated(id) => id.sign_arbitrary(content),
        }
    }
    fn delegation_chain(&self) -> Vec<SignedDelegation> {
        match &self.identity {
            InnerIdentity::Anonymous(id) => id.delegation_chain(),
            InnerIdentity::Delegated(id) => id.delegation_chain(),
        }
    }
}

pub fn identity_from(secret: [u8; 32]) -> BasicIdentity {
    let key = SigningKey::from(secret);
    BasicIdentity::from_signing_key(key)
}
