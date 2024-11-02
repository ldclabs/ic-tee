use candid::Principal;
use ed25519_consensus::SigningKey;
use ic_agent::{
    identity::{
        AnonymousIdentity, BasicIdentity, DelegatedIdentity, Delegation, Identity, SignedDelegation,
    },
    {agent::EnvelopeContent, Signature},
};
use rand::thread_rng;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

enum InnerIdentity {
    Anonymous(AnonymousIdentity),
    Delegated(DelegatedIdentity),
}

pub struct TEEIdentity {
    identity: InnerIdentity,
    signing_key: SigningKey,
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

impl TEEIdentity {
    pub fn new() -> Self {
        let signing_key = SigningKey::new(thread_rng());
        let basic = BasicIdentity::from_signing_key(SigningKey::new(thread_rng()));
        Self {
            identity: InnerIdentity::Anonymous(AnonymousIdentity),
            signing_key,
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

    pub fn with_user_key(&mut self, user_key: Vec<u8>) {
        self.principal = Principal::self_authenticating(&user_key);
        self.user_key = user_key;
    }

    pub fn with_delegation(&mut self, delegation: SignedDelegation) -> Result<(), String> {
        if delegation.delegation.pubkey != self.session_key {
            return Err("delegation pubkey does not match".to_string());
        }

        self.expiration = delegation.delegation.expiration;
        let id = DelegatedIdentity::new_unchecked(
            self.user_key.clone(),
            Box::new(BasicIdentity::from_signing_key(self.signing_key.clone())),
            vec![delegation],
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
