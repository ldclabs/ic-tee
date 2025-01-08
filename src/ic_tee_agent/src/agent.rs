use candid::Principal;
use ciborium::into_writer;
use ed25519_consensus::SigningKey;
use ic_agent::Agent;
use ic_cose::{
    agent::{query_call, update_call},
    client::Client,
};
use ic_cose_types::{
    cose::format_error,
    types::{
        setting::{CreateSettingInput, CreateSettingOutput, SettingInfo},
        ECDHInput, ECDHOutput, SettingPath, SignDelegationInput,
    },
};
use ic_tee_cdk::{Delegation, SignInResponse, SignedDelegation};
use serde_bytes::{ByteArray, ByteBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{crypto, BasicIdentity, TEEIdentity};

#[derive(Clone)]
pub struct TEEAgent {
    agents: Arc<RwLock<Agents>>,
    auth_canister: Principal,
    root_secret: [u8; 48],
}

struct Agents {
    identity: TEEIdentity,
    agent: Agent,
    cose: Client,
    cose_canister: Principal,
}

impl Agents {
    fn set_identity(&mut self, identity: TEEIdentity) {
        self.identity = identity;
        self.agent.set_identity(self.identity.clone());
        self.cose = Client::new(Arc::new(self.agent.clone()), self.cose_canister);
    }
}

impl TEEAgent {
    pub async fn new(
        host: &str,
        authentication_canister: Principal,
        configuration_canister: Principal,
        root_secret: [u8; 48],
    ) -> Result<Self, String> {
        let identity = TEEIdentity::new();
        let agent = Agent::builder()
            .with_url(host)
            .with_verify_query_signatures(true)
            .with_identity(identity.clone())
            .build()
            .map_err(format_error)?;
        if host.starts_with("http://") {
            agent.fetch_root_key().await.map_err(format_error)?;
        }
        let agents = Agents {
            identity,
            agent: agent.clone(),
            cose: Client::new(Arc::new(agent), configuration_canister),
            cose_canister: configuration_canister,
        };
        Ok(Self {
            auth_canister: authentication_canister,
            agents: Arc::new(RwLock::new(agents)),
            root_secret,
        })
    }

    pub fn set_root_secret(&mut self, root_secret: [u8; 48]) {
        self.root_secret = root_secret;
    }

    pub fn a256gcm_key(&self, derivation_path: Vec<ByteBuf>) -> ByteArray<32> {
        crypto::a256gcm_key(
            &self.root_secret,
            derivation_path.into_iter().map(|v| v.into_vec()).collect(),
        )
    }

    pub fn a256gcm_ecdh_key(
        &self,
        derivation_path: Vec<ByteBuf>,
        ecdh: &ECDHInput,
    ) -> ECDHOutput<ByteBuf> {
        crypto::a256gcm_ecdh_key(
            &self.root_secret,
            derivation_path.into_iter().map(|v| v.into_vec()).collect(),
            ecdh,
        )
    }

    pub fn ed25519_sign_message(&self, derivation_path: Vec<ByteBuf>, msg: &[u8]) -> ByteArray<64> {
        crypto::ed25519_sign_message(
            &self.root_secret,
            derivation_path.into_iter().map(|v| v.into_vec()).collect(),
            msg,
        )
    }

    pub fn ed25519_public_key(
        &self,
        derivation_path: Vec<ByteBuf>,
    ) -> (ByteArray<32>, ByteArray<32>) {
        crypto::ed25519_public_key(
            &self.root_secret,
            derivation_path.into_iter().map(|v| v.into_vec()).collect(),
        )
    }

    pub fn secp256k1_sign_message_bip340(
        &self,
        derivation_path: Vec<ByteBuf>,
        msg: &[u8],
    ) -> ByteArray<64> {
        crypto::secp256k1_sign_message_bip340(
            &self.root_secret,
            derivation_path.into_iter().map(|v| v.into_vec()).collect(),
            msg,
        )
    }

    pub fn secp256k1_sign_message_ecdsa(
        &self,
        derivation_path: Vec<ByteBuf>,
        msg: &[u8],
    ) -> ByteArray<64> {
        crypto::secp256k1_sign_message_ecdsa(
            &self.root_secret,
            derivation_path.into_iter().map(|v| v.into_vec()).collect(),
            msg,
        )
    }

    pub fn secp256k1_public_key(
        &self,
        derivation_path: Vec<ByteBuf>,
    ) -> (ByteArray<33>, ByteArray<32>) {
        crypto::secp256k1_public_key(
            &self.root_secret,
            derivation_path.into_iter().map(|v| v.into_vec()).collect(),
        )
    }

    pub async fn get_principal(&self) -> Principal {
        self.agents.read().await.identity.get_principal()
    }

    pub async fn is_authenticated(&self) -> bool {
        self.agents.read().await.identity.is_authenticated()
    }

    pub async fn set_identity(&self, identity: &BasicIdentity, expires_in_ms: u64) {
        let mut id = {
            self.agents.read().await.identity.clone()
            // drop read lock
        };
        id.upgrade_with_identity(identity, expires_in_ms);
        self.agents.write().await.set_identity(id.clone());
    }

    pub async fn sign_in_with_attestation(
        &self,
        session_key: (SigningKey, Vec<u8>),
        f: impl FnOnce() -> Result<(String, ByteBuf), String>,
    ) -> Result<(), String> {
        let (kind, attestation) = f()?;

        let mut id = {
            self.agents.read().await.identity.clone()
            // drop read lock
        };

        let (user_key, delegation) = {
            let agent = &self.agents.read().await.agent;
            let res: Result<SignInResponse, String> =
                update_call(agent, &self.auth_canister, "sign_in", (kind, attestation)).await?;
            let res = res?;
            let user_key = res.user_key.to_vec();

            let res: Result<SignedDelegation, String> = query_call(
                agent,
                &self.auth_canister,
                "get_delegation",
                (
                    res.seed,
                    ByteBuf::from(session_key.1.clone()),
                    res.expiration,
                ),
            )
            .await?;
            (user_key, res?)
        };

        id.update_with_delegation(user_key, session_key, delegation);
        self.agents.write().await.set_identity(id.clone());

        Ok(())
    }

    // upgrade to a fixed identity derived from a name in a namespace on COSE canister
    pub async fn cose_upgrade_identity(
        &self,
        ns: String,
        name: String,
        session_key: (SigningKey, Vec<u8>),
    ) -> Result<(), String> {
        let mut id = {
            self.agents.read().await.identity.clone()
            // drop read lock
        };

        let mut msg = vec![];
        into_writer(&(&ns, &name, &id.get_principal()), &mut msg)
            .expect("failed to encode Delegations data");
        let sig = session_key.0.sign(&msg);
        let pubkey = ByteBuf::from(session_key.1.clone());

        {
            let cose = &self.agents.read().await.cose;
            let res = cose
                .namespace_sign_delegation(&SignDelegationInput {
                    ns,
                    name,
                    pubkey: pubkey.clone(),
                    sig: sig.to_bytes().to_vec().into(),
                })
                .await?;

            let user_key = res.user_key.to_vec();
            let res = cose
                .get_delegation(&res.seed, &pubkey, res.expiration)
                .await?;

            id.update_with_delegation(
                user_key,
                session_key,
                SignedDelegation {
                    delegation: Delegation {
                        pubkey: res.delegation.pubkey,
                        expiration: res.delegation.expiration,
                        targets: res.delegation.targets,
                    },
                    signature: res.signature,
                },
            );
            // drop read lock
        }

        self.agents.write().await.set_identity(id);
        Ok(())
    }

    pub async fn cose_get_secret(&self, path: &SettingPath) -> Result<[u8; 32], String> {
        let cose = &self.agents.read().await.cose;
        let key = cose.get_cose_encrypted_key(path).await?;
        Ok(*key)
    }

    pub async fn cose_get_setting(&self, path: &SettingPath) -> Result<SettingInfo, String> {
        let cose = &self.agents.read().await.cose;
        cose.setting_get(path).await
    }

    pub async fn cose_create_setting(
        &self,
        path: &SettingPath,
        input: &CreateSettingInput,
    ) -> Result<CreateSettingOutput, String> {
        let cose = &self.agents.read().await.cose;
        cose.setting_create(path, input).await
    }

    pub async fn update_call_raw(
        &self,
        canister_id: &Principal,
        method_name: &str,
        input: Vec<u8>,
    ) -> Result<ByteBuf, String> {
        let res = self
            .agents
            .read()
            .await
            .agent
            .update(canister_id, method_name)
            .with_arg(input)
            .call_and_wait()
            .await
            .map_err(format_error)?;
        Ok(res.into())
    }

    pub async fn query_call_raw(
        &self,
        canister_id: &Principal,
        method_name: &str,
        input: Vec<u8>,
    ) -> Result<ByteBuf, String> {
        let res = self
            .agents
            .read()
            .await
            .agent
            .query(canister_id, method_name)
            .with_arg(input)
            .call()
            .await
            .map_err(format_error)?;
        Ok(res.into())
    }
}
