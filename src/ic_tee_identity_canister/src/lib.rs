use candid::Principal;
use ic_auth_types::{SignInResponse, SignedDelegation};
use serde_bytes::ByteBuf;

mod api;
mod api_init;
mod store;

use api_init::CanArgs;

ic_cdk::export_candid!();

#[cfg(test)]
mod tests {
    #[test]
    fn test_candid_interface() {
        let did = super::__export_service();
        let expected = include_str!("../ic_tee_identity_canister.did");
        assert_eq!(
            did.trim(),
            expected.trim(),
            "the .did file is outdated, please run `make build-did`"
        );
    }
}
