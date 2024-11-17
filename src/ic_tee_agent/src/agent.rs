use candid::{
    utils::{encode_args, ArgumentEncoder},
    CandidType, Decode, Principal,
};
use ed25519_consensus::SigningKey;
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
    is_local: bool,
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
            is_local: host.starts_with("http://"),
            identity: Arc::new(RwLock::new(identity)),
            agent: Arc::new(RwLock::new(agent)),
            authentication_canister,
            configuration_canister,
        })
    }

    pub async fn init(&self) -> Result<(), String> {
        if self.is_local {
            let agent = self.agent.read().await;
            agent
                .fetch_root_key()
                .await
                .map_err(|err| format!("fetch root key failed: {:?}", err))?;
        }
        Ok(())
    }

    pub async fn get_principal(&self) -> Principal {
        self.identity.read().await.get_principal()
    }

    pub async fn is_authenticated(&self) -> bool {
        self.identity.read().await.is_authenticated()
    }

    pub async fn sign_in_with(
        &self,
        session_key: (SigningKey, Vec<u8>),
        f: impl FnOnce() -> Result<(String, ByteBuf), String>,
    ) -> Result<(), String> {
        let (kind, attestation) = f()?;
        let res: Result<SignInResponse, String> = self
            .update_call(
                &self.authentication_canister,
                "sign_in",
                (kind, attestation),
            )
            .await?;
        let res = res?;
        let user_key = res.user_key.to_vec();

        let res: Result<SignedDelegation, String> = self
            .query_call(
                &self.authentication_canister,
                "get_delegation",
                (
                    res.seed,
                    ByteBuf::from(session_key.1.clone()),
                    res.expiration,
                ),
            )
            .await?;
        let res = res?;

        let mut id = {
            let id = self.identity.read().await;
            id.clone()
            // drop read lock
        };

        id.update_with_delegation(user_key, session_key, res);
        self.agent.write().await.set_identity(id.clone());
        let mut w = self.identity.write().await;
        *w = id;

        Ok(())
    }

    pub async fn upgrade_identity(&self, identity: &BasicIdentity, expires_in_ms: u64) {
        let mut id = {
            let id = self.identity.read().await;
            id.clone()
            // drop read lock
        };
        id.upgrade_with_identity(identity, expires_in_ms);
        self.agent.write().await.set_identity(id.clone());
        let mut w = self.identity.write().await;
        *w = id;
    }

    pub async fn get_cose_secret(&self, path: SettingPath) -> Result<[u8; 32], String> {
        let agent = self.agent.read().await;
        get_cose_secret(&agent, &self.configuration_canister, path).await
    }

    pub async fn get_cose_setting(&self, path: SettingPath) -> Result<SettingInfo, String> {
        let res: Result<SettingInfo, String> = self
            .query_call(&self.configuration_canister, "setting_get", (path,))
            .await?;
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

// #[cfg(test)]
// mod tests {
//     use super::*;
// }
