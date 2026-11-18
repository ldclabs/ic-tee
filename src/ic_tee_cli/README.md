# `ic_tee_cli`

`ic_tee_cli` is a command-line tool implemented in Rust for the `ic-tee`.

## Usage

Install:
```sh
cargo install ic_tee_cli
# get help info
ic_tee_cli --help

# verify a TEE attestation from url
ic_tee_cli tee-verify --url https://tee-demo.panda.fans/.well-known/attestation
```

`tee-verify` checks the AWS signature and certificate chain at the document's timestamp. For live attestation, check the timestamp and PCRs against your deployment's freshness policy and expected image.

## License
Copyright © 2024-2025 [LDC Labs](https://github.com/ldclabs).

This project is dual-licensed under the [MIT License](../../LICENSE-MIT) and [Apache License, Version 2.0](../../LICENSE-APACHE). You may use either license.
