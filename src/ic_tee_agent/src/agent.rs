use candid::{
    utils::{encode_args, ArgumentEncoder},
    CandidType, Decode, Principal,
};
use ic_agent::Agent;
use ic_cose_types::{
    cose::format_error,
    types::{setting::SettingInfo, SettingPath},
};
use ic_tee_cdk::{SignInResponse, SignedDelegation};
use serde_bytes::ByteBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{setting::get_cose_secret, BasicIdentity, TEEIdentity};

#[derive(Clone)]
pub struct TEEAgent {
    identity: Arc<RwLock<TEEIdentity>>,
    agent: Arc<RwLock<Agent>>,
    authentication_canister: Principal,
    configuration_canister: Principal,
}

impl TEEAgent {
    pub fn new(
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
        Ok(Self {
            identity: Arc::new(RwLock::new(identity)),
            agent: Arc::new(RwLock::new(agent)),
            authentication_canister,
            configuration_canister,
        })
    }

    pub async fn principal(&self) -> Principal {
        self.identity.read().await.principal()
    }

    pub async fn session_key(&self) -> Vec<u8> {
        self.identity.read().await.session_key()
    }

    pub async fn is_authenticated(&self) -> bool {
        self.identity.read().await.is_authenticated()
    }

    pub async fn sign_in(&self, kind: String, attestation: ByteBuf) -> Result<(), String> {
        let res: Result<SignInResponse, String> = self
            .update_call(
                &self.authentication_canister,
                "sign_in",
                (kind, attestation),
            )
            .await?;
        let res = res?;
        let mut id = {
            let id = self.identity.read().await;
            id.clone()
            // drop read lock
        };

        id.with_user_key(res.user_key.to_vec());
        let res: Result<SignedDelegation, String> = self
            .query_call(
                &self.authentication_canister,
                "get_delegation",
                (
                    id.principal(),
                    ByteBuf::from(id.session_key()),
                    res.expiration,
                ),
            )
            .await?;
        let res = res?;

        id.with_delegation(res)?;
        self.agent.write().await.set_identity(id.clone());
        let mut w = self.identity.write().await;
        *w = id;

        Ok(())
    }

    pub async fn sign_in_with(
        &self,
        f: impl FnOnce(Vec<u8>) -> Result<(String, ByteBuf), String>,
    ) -> Result<(), String> {
        let session_key = self.session_key().await;
        let (kind, attestation) = f(session_key)?;
        self.sign_in(kind, attestation).await
    }

    pub async fn upgrade_identity_with(&self, id: &BasicIdentity, expires_in_ms: u64) {
        self.identity.write().await.upgrade_with(id, expires_in_ms);
    }

    pub async fn get_cose_secret(&self, path: SettingPath) -> Result<[u8; 32], String> {
        let agent = self.agent.read().await;
        get_cose_secret(&agent, &self.configuration_canister, path).await
    }

    pub async fn get_cose_setting(&self, path: SettingPath) -> Result<SettingInfo, String> {
        let res: Result<SettingInfo, String> = self
            .update_call(&self.configuration_canister, "setting_get", (path,))
            .await;
        res
    }

    pub async fn update_call<In, Out>(
        &self,
        canister_id: &Principal,
        method_name: &str,
        args: In,
    ) -> Result<Out, String>
    where
        In: ArgumentEncoder + Send,
        Out: CandidType + for<'a> candid::Deserialize<'a>,
    {
        let agent = self.agent.read().await;
        update_call(&agent, canister_id, method_name, args).await
    }

    pub async fn query_call<In, Out>(
        &self,
        canister_id: &Principal,
        method_name: &str,
        args: In,
    ) -> Result<Out, String>
    where
        In: ArgumentEncoder + Send,
        Out: CandidType + for<'a> candid::Deserialize<'a>,
    {
        let agent = self.agent.read().await;
        query_call(&agent, canister_id, method_name, args).await
    }

    pub async fn update_call_raw(
        &self,
        canister_id: &Principal,
        method_name: &str,
        input: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        self.agent
            .read()
            .await
            .update(canister_id, method_name)
            .with_arg(input)
            .call_and_wait()
            .await
            .map_err(format_error)
    }

    pub async fn query_call_raw(
        &self,
        canister_id: &Principal,
        method_name: &str,
        input: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        self.agent
            .read()
            .await
            .query(canister_id, method_name)
            .with_arg(input)
            .call()
            .await
            .map_err(format_error)
    }
}

pub async fn update_call<In, Out>(
    agent: &Agent,
    canister_id: &Principal,
    method_name: &str,
    args: In,
) -> Result<Out, String>
where
    In: ArgumentEncoder + Send,
    Out: CandidType + for<'a> candid::Deserialize<'a>,
{
    let input = encode_args(args).map_err(format_error)?;
    let res = agent
        .update(canister_id, method_name)
        .with_arg(input)
        .call_and_wait()
        .await
        .map_err(format_error)?;
    let output = Decode!(res.as_slice(), Out).map_err(format_error)?;
    Ok(output)
}

pub async fn query_call<In, Out>(
    agent: &Agent,
    canister_id: &Principal,
    method_name: &str,
    args: In,
) -> Result<Out, String>
where
    In: ArgumentEncoder + Send,
    Out: CandidType + for<'a> candid::Deserialize<'a>,
{
    let input = encode_args(args).map_err(format_error)?;
    let res = agent
        .query(canister_id, method_name)
        .with_arg(input)
        .call()
        .await
        .map_err(format_error)?;
    let output = Decode!(res.as_slice(), Out).map_err(format_error)?;
    Ok(output)
}
