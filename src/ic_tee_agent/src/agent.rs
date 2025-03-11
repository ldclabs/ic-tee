use candid::{
    utils::{encode_args, ArgumentEncoder},
    CandidType, Decode, Principal,
};
use ciborium::into_writer;
use ed25519_consensus::SigningKey;
use ic_agent::Agent;
use ic_auth_types::{SignInResponse, SignedDelegation};
use ic_cose::client::CoseSDK;
use ic_cose_types::{format_error, types::SignDelegationInput, BoxError, CanisterCaller};
use serde_bytes::ByteBuf;

use crate::{signed_delegation_from, BasicIdentity, TEEIdentity};

#[derive(Clone)]
pub struct TEEAgent {
    pub identity_canister: Principal,
    pub cose_canister: Principal,
    pub identity: TEEIdentity,
    pub agent: Agent,
}

impl TEEAgent {
    pub async fn new(
        host: &str,
        identity_canister: Principal,
        cose_canister: Principal,
    ) -> Result<Self, String> {
        let identity = TEEIdentity::new();
        let agent = Agent::builder()
            .with_url(host)
            .with_verify_query_signatures(false)
            .with_identity(identity.clone())
            .build()
            .map_err(format_error)?;
        if host.starts_with("http://") {
            agent.fetch_root_key().await.map_err(format_error)?;
        }
        Ok(Self {
            identity_canister,
            cose_canister,
            identity,
            agent,
        })
    }

    fn with_new_identity(&self, identity: TEEIdentity) -> Self {
        let mut agent = self.agent.clone();
        agent.set_identity(identity.clone());
        Self {
            identity_canister: self.identity_canister,
            cose_canister: self.cose_canister,
            identity,
            agent,
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
            let res: Result<SignInResponse, String> = self
                .canister_update(&self.identity_canister, "sign_in", (kind, attestation))
                .await
                .map_err(format_error)?;
            let res = res?;
            let user_key = res.user_key.to_vec();

            let res: Result<SignedDelegation, String> = self
                .canister_query(
                    &self.identity_canister,
                    "get_delegation",
                    (
                        res.seed,
                        ByteBuf::from(session_key.1.clone()),
                        res.expiration,
                    ),
                )
                .await
                .map_err(format_error)?;
            (user_key, res?)
        };

        id.update_with_delegation(user_key, session_key, signed_delegation_from(delegation));
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
            .namespace_sign_delegation(&SignDelegationInput {
                ns,
                name,
                pubkey: pubkey.clone(),
                sig: sig.to_bytes().to_vec().into(),
            })
            .await?;

        let user_key = res.user_key.to_vec();
        let res = self
            .get_delegation(&res.seed, &pubkey, res.expiration)
            .await?;
        id.update_with_delegation(user_key, session_key, signed_delegation_from(res));

        Ok(self.with_new_identity(id))
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

impl CoseSDK for TEEAgent {
    fn canister(&self) -> &Principal {
        &self.cose_canister
    }
}

impl CanisterCaller for TEEAgent {
    async fn canister_query<
        In: ArgumentEncoder + Send,
        Out: CandidType + for<'a> candid::Deserialize<'a>,
    >(
        &self,
        canister: &Principal,
        method: &str,
        args: In,
    ) -> Result<Out, BoxError> {
        let input = encode_args(args)?;
        let res = self
            .agent
            .query(canister, method)
            .with_arg(input)
            .call()
            .await?;
        let output = Decode!(res.as_slice(), Out)?;
        Ok(output)
    }

    async fn canister_update<
        In: ArgumentEncoder + Send,
        Out: CandidType + for<'a> candid::Deserialize<'a>,
    >(
        &self,
        canister: &Principal,
        method: &str,
        args: In,
    ) -> Result<Out, BoxError> {
        let input = encode_args(args)?;
        let res = self
            .agent
            .update(canister, method)
            .with_arg(input)
            .call_and_wait()
            .await?;
        let output = Decode!(res.as_slice(), Out)?;
        Ok(output)
    }
}
