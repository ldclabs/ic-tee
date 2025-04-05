use candid::Principal;
use ed25519_consensus::SigningKey;
use ic_agent::{
    identity::{DelegatedIdentity, Delegation, SignedDelegation},
    {agent::EnvelopeContent, Signature},
};
use ic_cose::rand_bytes;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub use ic_agent::identity::{AnonymousIdentity, BasicIdentity, Identity};

enum InnerIdentity {
    Anonymous(AnonymousIdentity),
    Delegated(DelegatedIdentity),
}

pub struct TEEIdentity {
    identity: InnerIdentity,
    session_key: (SigningKey, Vec<u8>),
    delegation: Vec<SignedDelegation>,
    user_key: Vec<u8>,
    principal: Principal,
    expiration: u128, // ns since UNIX epoch
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
                        Box::new(BasicIdentity::from_signing_key(self.session_key.0.clone())),
                        self.delegation.clone(),
                    ))
                }
            },
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
        let session_key = Self::new_session();
        Self {
            identity: InnerIdentity::Anonymous(AnonymousIdentity),
            delegation: vec![],
            user_key: vec![],
            session_key,
            principal: AnonymousIdentity.sender().unwrap(),
            expiration: 0,
        }
    }

    pub fn new_session() -> (SigningKey, Vec<u8>) {
        let secret: [u8; 32] = rand_bytes();
        let signing_key = SigningKey::from(secret);
        let basic = BasicIdentity::from_signing_key(signing_key.clone());
        (signing_key, basic.public_key().unwrap())
    }

    pub fn is_authenticated(&self) -> bool {
        match &self.identity {
            InnerIdentity::Anonymous(_) => false,
            InnerIdentity::Delegated(_) => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .saturating_sub(Duration::from_secs(300));
                !now.is_zero() && now.as_nanos() < self.expiration
            }
        }
    }

    pub fn get_principal(&self) -> Principal {
        self.principal
    }

    pub fn upgrade_with_identity(&mut self, identity: &BasicIdentity, expires_in_ms: u64) {
        let expiration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .saturating_add(Duration::from_millis(expires_in_ms));
        let session_key = Self::new_session();
        let delegation = Delegation {
            pubkey: session_key.1.clone(),
            expiration: expiration.as_nanos() as u64,
            targets: None,
        };
        let signature = identity.sign_delegation(&delegation).unwrap();
        self.principal = identity.sender().unwrap();
        self.user_key = identity.public_key().unwrap();
        self.expiration = delegation.expiration as u128;
        self.delegation = vec![SignedDelegation {
            delegation,
            signature: signature.signature.unwrap(),
        }];
        let id = DelegatedIdentity::new_unchecked(
            self.user_key.clone(),
            Box::new(BasicIdentity::from_signing_key(session_key.0.clone())),
            self.delegation.clone(),
        );
        self.session_key = session_key;
        self.identity = InnerIdentity::Delegated(id);
    }

    pub fn update_with_delegation(
        &mut self,
        user_key: Vec<u8>,
        session_key: (SigningKey, Vec<u8>),
        delegation: SignedDelegation,
    ) {
        self.principal = Principal::self_authenticating(&user_key);
        self.user_key = user_key;
        self.expiration = delegation.delegation.expiration as u128;
        self.delegation = vec![delegation];
        let id = DelegatedIdentity::new_unchecked(
            self.user_key.clone(),
            Box::new(BasicIdentity::from_signing_key(self.session_key.0.clone())),
            self.delegation.clone(),
        );
        self.session_key = session_key;
        self.identity = InnerIdentity::Delegated(id);
    }
}

impl Identity for &TEEIdentity {
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
