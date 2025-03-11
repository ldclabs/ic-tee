BUILD_ENV := rust

.PHONY: build-wasm build-did

lint:
	@cargo fmt
	@cargo clippy --all-targets --all-features

fix:
	@cargo clippy --fix --workspace --tests

test:
	@AWS_LC_SYS_NO_ASM=1 cargo test --workspace --all-features -- --nocapture

# cargo install ic-wasm
build-wasm:
	@cargo build --release --target wasm32-unknown-unknown --package ic_tee_identity

# cargo install candid-extractor
build-did:
	candid-extractor target/wasm32-unknown-unknown/release/ic_tee_identity.wasm > src/ic_tee_identity/ic_tee_identity.did
	dfx generate
