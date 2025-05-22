use candid::{
    utils::{encode_args, ArgumentEncoder},
    CandidType, Decode, Principal,
};
use ciborium::into_writer;
use ic_agent::{Agent, Identity};
use ic_auth_types::{SignInResponse, SignedDelegation};
use ic_cose::client::CoseSDK;
use ic_cose_types::{format_error, types::SignDelegationInput, BoxError, CanisterCaller};
use serde_bytes::ByteBuf;
use std::sync::Arc;

use crate::{
    delegated_basic_identity, signed_delegation_from, AtomicIdentity, BasicIdentity,
    DelegatedIdentity,
};

#[derive(Clone)]
pub struct TEEAgent {
    pub identity_canister: Principal,
    pub cose_canister: Principal,
    pub identity: Arc<AtomicIdentity>,
    pub agent: Agent,
}

impl TEEAgent {
    pub async fn new(
        host: &str,
        identity_canister: Principal,
        cose_canister: Principal,
    ) -> Result<Self, String> {
        let identity = Arc::new(AtomicIdentity::default());
        let agent = Agent::builder()
            .with_url(host)
            .with_arc_identity(identity.clone())
            .with_verify_query_signatures(false);

        let agent = if host.starts_with("https://") {
            agent
                .with_background_dynamic_routing()
                .build()
                .map_err(format_error)?
        } else {
            agent.build().map_err(format_error)?
        };

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

    pub fn get_principal(&self) -> Principal {
        self.identity.sender().expect("failed to get principal")
    }

    pub fn is_authenticated(&self) -> bool {
        self.identity.is_authenticated()
    }

    pub fn get_identity(&self) -> Arc<dyn Identity> {
        self.identity.get()
    }

    pub fn set_basic_identity(&self, identity: BasicIdentity, expires_in_ms: u64) {
        let id = delegated_basic_identity(&identity, expires_in_ms);
        self.identity.set(Box::new(id));
    }

    pub async fn sign_in_with_attestation(
        &self,
        session: BasicIdentity,
        f: impl FnOnce() -> Result<(String, ByteBuf), String>,
    ) -> Result<(), String> {
        let (kind, attestation) = f()?;

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
                        ByteBuf::from(session.public_key().unwrap()),
                        res.expiration,
                    ),
                )
                .await
                .map_err(format_error)?;
            (user_key, res?)
        };
        let id = DelegatedIdentity::new(
            user_key,
            Box::new(session),
            vec![signed_delegation_from(delegation)],
        )
        .map_err(format_error)?;

        self.identity.set(Box::new(id));
        Ok(())
    }

    // upgrade to a fixed identity derived from a name in a namespace on COSE canister
    pub async fn cose_upgrade_identity(
        &self,
        ns: String,
        name: String,
        session: BasicIdentity,
    ) -> Result<(), String> {
        let mut msg = vec![];
        into_writer(&(&ns, &name, &self.identity.sender().unwrap()), &mut msg)
            .expect("failed to encode Delegations data");
        let sig = session.sign_arbitrary(&msg).unwrap();
        let pubkey = ByteBuf::from(session.public_key().unwrap());

        let res = self
            .namespace_sign_delegation(&SignDelegationInput {
                ns,
                name,
                pubkey: pubkey.clone(),
                sig: sig.signature.unwrap().into(),
            })
            .await?;

        let user_key = res.user_key.to_vec();
        let delegation = self
            .get_delegation(&res.seed.0.into(), &pubkey, res.expiration)
            .await?;
        let id = DelegatedIdentity::new(
            user_key,
            Box::new(session),
            vec![signed_delegation_from(delegation)],
        )
        .map_err(format_error)?;

        self.identity.set(Box::new(id));
        Ok(())
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
