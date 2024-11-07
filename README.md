# IC-TEE
🔐 Make Trusted Execution Environments (TEEs) work with the Internet Computer.

Relation project:
- [IC-COSE](https://github.com/ldclabs/ic-cose), a decentralized COnfiguration service with Signing and Encryption on the Internet Computer.
- [ic-tee-host-daemon](https://github.com/ldclabs/ic-tee-host-daemon), a daemon running on the host machine of TEEs.

## Libraries

| Library                                                                                              | Description                                                                                               |
| :--------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------- |
| [ic_tee_agent](https://github.com/ldclabs/ic-tee/tree/main/src/ic_tee_agent)                         | An agent to interact with the Internet Computer for Trusted Execution Environments (TEEs).                |
| [ic_tee_cdk](https://github.com/ldclabs/ic-tee/tree/main/src/ic_tee_cdk)                             | A Canister Development Kit to make Trusted Execution Environments (TEEs) work with the Internet Computer. |
| [ic_tee_cli](https://github.com/ldclabs/ic-tee/tree/main/src/ic_tee_cli)                             | A command-line tool implemented in Rust for the IC-TEE.                                                   |
| [ic_tee_identity](https://github.com/ldclabs/ic-tee/tree/main/src/ic_tee_identity)                   | An on-chain authentication service for Trusted Execution Environments (TEEs) on the Internet Computer.    |
| [ic_tee_logtail](https://github.com/ldclabs/ic-tee/tree/main/src/ic_tee_logtail)                     | A simple log tailing service for the TEE environment.                                                     |
| [ic_tee_nitro_attestation](https://github.com/ldclabs/ic-tee/tree/main/src/ic_tee_nitro_attestation) | A Rust library to process AWS Nitro enclave attestation.                                                  |
| [ic_tee_nitro_gateway](https://github.com/ldclabs/ic-tee/tree/main/src/ic_tee_nitro_gateway)         | A gateway service within an AWS Nitro enclave.                                                            |


## License
Copyright © 2024 [LDC Labs](https://github.com/ldclabs).

`ldclabs/ic-tee` is licensed under the MIT License. See [LICENSE](./LICENSE-MIT) for the full license text.