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
                (res.seed, ByteBuf::from(id.session_key()), res.expiration),
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

#[cfg(test)]
mod tests {
    use super::*;
    use ic_cose_types::types::state::StateInfo;

    #[tokio::test(flavor = "current_thread")]
    #[ignore]
    async fn test_ic_tee_identity() {
        let host = "https://icp-api.io";
        // let host = "http://127.0.0.1:4943";
        let authentication_canister = Principal::from_text("e7tgb-6aaaa-aaaap-akqfa-cai").unwrap();
        let configuration_canister = Principal::from_text("53cyg-yyaaa-aaaap-ahpua-cai").unwrap();
        let tee_agent = TEEAgent::new(host, authentication_canister, configuration_canister)
            .expect("Failed to create TEEAgent");
        tee_agent.init().await.unwrap();

        println!(
            "tee_agent init principal: {:?}",
            tee_agent.principal().await.to_text()
        );
        let pubkey = tee_agent.session_key().await;
        let res: Result<SignInResponse, String> = tee_agent
            .update_call(
                &tee_agent.authentication_canister,
                "sign_in_debug",
                (ByteBuf::from(pubkey),),
            )
            .await
            .unwrap();
        let res = res.unwrap();
        let mut id = {
            let id = tee_agent.identity.read().await;
            id.clone()
            // drop read lock
        };

        println!("user_key: {:?}", const_hex::encode(&res.user_key));
        id.with_user_key(res.user_key.to_vec());
        let principal = id.principal();
        let res: Result<SignedDelegation, String> = tee_agent
            .query_call(
                &tee_agent.authentication_canister,
                "get_delegation",
                (res.seed, ByteBuf::from(id.session_key()), res.expiration),
            )
            .await
            .unwrap();
        let res = res.unwrap();

        id.with_delegation(res).unwrap();
        {
            tee_agent.agent.write().await.set_identity(id.clone());
            let mut w = tee_agent.identity.write().await;
            *w = id;
            // drop write lock
        }
        let principal2 = { tee_agent.agent.read().await.get_principal().unwrap() };
        assert_eq!(principal, principal2);
        assert_eq!(principal, tee_agent.principal().await);

        println!("tee_agent sign in principal: {:?}", principal.to_text());
        println!(
            "tee_agent sign in seed: {:?}",
            const_hex::encode(principal.as_slice())
        );
        let res: Principal = tee_agent
            .query_call(&tee_agent.authentication_canister, "whoami", ())
            .await
            .unwrap();
        println!("configuration canister whoami: {:?}", res.to_text());
        let res: Result<StateInfo, String> = tee_agent
            .query_call(&tee_agent.configuration_canister, "state_get_info", ())
            .await
            .unwrap();
        println!("configuration canister state: {:?}", res.unwrap());
    }
}
