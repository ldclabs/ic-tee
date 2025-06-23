use candid::Principal;
use ic_auth_types::{SignInResponse, SignedDelegation};
use serde_bytes::ByteBuf;

mod api;
mod api_init;
mod store;

use api_init::CanArgs;

ic_cdk::export_candid!();
