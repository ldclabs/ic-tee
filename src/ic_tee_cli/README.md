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

## License
Copyright © 2024-2025 [LDC Labs](https://github.com/ldclabs).

`ldclabs/ic-tee` is licensed under the MIT License. See [LICENSE](../../LICENSE-MIT) for the full license text.