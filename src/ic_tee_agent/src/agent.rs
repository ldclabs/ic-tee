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
        SettingPath, SignDelegationInput,
    },
};
use ic_tee_cdk::{Delegation, SignInResponse, SignedDelegation};
use serde_bytes::ByteBuf;
use std::sync::Arc;

use crate::{BasicIdentity, TEEIdentity};

#[derive(Clone)]
pub struct TEEAgent {
    pub auth_canister: Principal,
    pub cose_canister: Principal,
    pub identity: TEEIdentity,
    pub agent: Agent,
    pub cose: Client,
}

impl TEEAgent {
    pub async fn new(
        host: &str,
        authentication_canister: Principal,
        configuration_canister: Principal,
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
        let cose = Client::new(Arc::new(agent.clone()), configuration_canister);
        Ok(Self {
            auth_canister: authentication_canister,
            cose_canister: configuration_canister,
            identity,
            agent,
            cose,
        })
    }

    fn with_new_identity(&self, identity: TEEIdentity) -> Self {
        let mut agent = self.agent.clone();
        agent.set_identity(identity.clone());
        let cose = Client::new(Arc::new(agent.clone()), self.cose_canister);
        Self {
            auth_canister: self.auth_canister,
            cose_canister: self.cose_canister,
            identity,
            agent,
            cose,
        }
    }

    pub fn get_principal(&self) -> Principal {
        self.identity.get_principal()
    }

    pub fn is_authenticated(&self) -> bool {
        self.identity.is_authenticated()
    }

    pub fn with_identity(&self, identity: BasicIdentity, expires_in_ms: u64) -> Self {
        let mut id = self.identity.clone();
        id.upgrade_with_identity(&identity, expires_in_ms);
        self.with_new_identity(id)
    }

    pub async fn sign_in_with_attestation(
        &self,
        session_key: (SigningKey, Vec<u8>),
        f: impl FnOnce() -> Result<(String, ByteBuf), String>,
    ) -> Result<Self, String> {
        let (kind, attestation) = f()?;

        let mut id = self.identity.clone();
        let (user_key, delegation) = {
            let res: Result<SignInResponse, String> = update_call(
                &self.agent,
                &self.auth_canister,
                "sign_in",
                (kind, attestation),
            )
            .await?;
            let res = res?;
            let user_key = res.user_key.to_vec();

            let res: Result<SignedDelegation, String> = query_call(
                &self.agent,
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
        Ok(self.with_new_identity(id))
    }

    // upgrade to a fixed identity derived from a name in a namespace on COSE canister
    pub async fn cose_upgrade_identity(
        &self,
        ns: String,
        name: String,
        session_key: (SigningKey, Vec<u8>),
    ) -> Result<Self, String> {
        let mut id = self.identity.clone();
        let mut msg = vec![];
        into_writer(&(&ns, &name, &id.get_principal()), &mut msg)
            .expect("failed to encode Delegations data");
        let sig = session_key.0.sign(&msg);
        let pubkey = ByteBuf::from(session_key.1.clone());

        let res = self
            .cose
            .namespace_sign_delegation(&SignDelegationInput {
                ns,
                name,
                pubkey: pubkey.clone(),
                sig: sig.to_bytes().to_vec().into(),
            })
            .await?;

        let user_key = res.user_key.to_vec();
        let res = self
            .cose
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

        Ok(self.with_new_identity(id))
    }

    pub async fn cose_get_secret(&self, path: &SettingPath) -> Result<[u8; 32], String> {
        let key = self.cose.get_cose_encrypted_key(path).await?;
        Ok(*key)
    }

    pub async fn cose_get_setting(&self, path: &SettingPath) -> Result<SettingInfo, String> {
        self.cose.setting_get(path).await
    }

    pub async fn cose_create_setting(
        &self,
        path: &SettingPath,
        input: &CreateSettingInput,
    ) -> Result<CreateSettingOutput, String> {
        self.cose.setting_create(path, input).await
    }

    pub async fn update_call_raw(
        &self,
        canister_id: &Principal,
        method_name: &str,
        input: Vec<u8>,
    ) -> Result<ByteBuf, String> {
        let res = self
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
            .agent
            .query(canister_id, method_name)
            .with_arg(input)
            .call()
            .await
            .map_err(format_error)?;
        Ok(res.into())
    }
}
