use candid::CandidType;
use ic_tee_cdk::SESSION_EXPIRES_IN_MS;
use serde::Deserialize;

use crate::store;

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum CanArgs {
    Init(InitArgs),
    Upgrade(UpgradeArgs),
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct InitArgs {
    name: String,
    session_expires_in_ms: u64,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct UpgradeArgs {
    name: Option<String>,
    session_expires_in_ms: Option<u64>,
}

#[ic_cdk::init]
fn init(args: Option<CanArgs>) {
    match args.unwrap_or(CanArgs::Init(InitArgs {
        name: "IC TEE Identity Service".to_string(),
        session_expires_in_ms: SESSION_EXPIRES_IN_MS, // 1 day
    })) {
        CanArgs::Init(args) => {
            store::state::with_mut(|s| {
                s.name = args.name;
                s.session_expires_in_ms = args.session_expires_in_ms;
            });
        }
        CanArgs::Upgrade(_) => {
            ic_cdk::trap(
                "cannot initialize the canister with an Upgrade args. Please provide an Init args.",
            );
        }
    }
}

#[ic_cdk::pre_upgrade]
fn pre_upgrade() {
    store::state::save();
}

#[ic_cdk::post_upgrade]
fn post_upgrade(args: Option<CanArgs>) {
    store::state::load();

    match args {
        Some(CanArgs::Upgrade(args)) => {
            store::state::with_mut(|s| {
                if let Some(name) = args.name {
                    s.name = name;
                }
                if let Some(session_expires_in_ms) = args.session_expires_in_ms {
                    s.session_expires_in_ms = session_expires_in_ms;
                }
            });
        }
        Some(CanArgs::Init(_)) => {
            ic_cdk::trap(
                "cannot upgrade the canister with an Init args. Please provide an Upgrade args.",
            );
        }
        _ => {}
    }
}
