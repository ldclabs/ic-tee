# `ic_tee_identity_canister`
🔐 An on-chain authentication service for Trusted Execution Environments (TEEs) on the Internet Computer.

## Candid API

```shell
get_delegation : (principal, blob, nat64) -> (Result) query;
get_state : () -> (Result_1) query;
sign_in : (text, blob) -> (Result_2);
```

The complete Candid API definition can be found in the [ic_tee_identity_canister.did](https://github.com/ldclabs/ic-tee/tree/main/src/ic_tee_identity_canister/ic_tee_identity_canister.did) file.

## Running locally

Deploy to local network:
```bash
# dfx canister create --specified-id e7tgb-6aaaa-aaaap-akqfa-cai ic_tee_identity_canister
dfx deploy ic_tee_identity_canister

# or with arguments
dfx deploy ic_tee_identity_canister --argument "(opt variant {Init =
  record {
    name = \"IC TEE Identity Service\";
    session_expires_in_ms = 3_600_000;
  }
})"

dfx canister call ic_tee_identity_canister get_state '()'
```

**Online Demo**: https://a4gq6-oaaaa-aaaab-qaa4q-cai.raw.icp0.io/?id=e7tgb-6aaaa-aaaap-akqfa-cai

## License
Copyright © 2024-2025 [LDC Labs](https://github.com/ldclabs).

`ldclabs/ic-tee` is licensed under the MIT License. See [LICENSE](../../LICENSE-MIT) for the full license text.