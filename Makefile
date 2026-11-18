CARGO_TARGET_DIR ?= target

.PHONY: lint fix test build-wasm build-did

lint:
	@cargo fmt --all -- --check
	@cargo clippy --workspace --all-targets --all-features --locked

fix:
	@cargo clippy --fix --workspace --tests --locked

test:
	@cargo test --workspace --all-features --locked

build-wasm:
	@cargo build --release --locked --target-dir "$(CARGO_TARGET_DIR)" --target wasm32-unknown-unknown --package ic_tee_identity_canister

# cargo install candid-extractor
build-did: build-wasm
	@did=$$(candid-extractor "$(CARGO_TARGET_DIR)/wasm32-unknown-unknown/release/ic_tee_identity_canister.wasm") && \
		printf '%s\n' "$$did" > src/ic_tee_identity_canister/ic_tee_identity_canister.did
	dfx generate
