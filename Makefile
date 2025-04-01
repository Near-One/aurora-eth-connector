MAKEFILE_DIR :=  $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

MANIFEST := $(MAKEFILE_DIR)/eth-connector/Cargo.toml

build-migration:
	cargo near build non-reproducible-wasm --manifest-path $(MANIFEST) --out-dir $(MAKEFILE_DIR)/bin --features migration
	mv $(MAKEFILE_DIR)/bin/aurora_eth_connector.wasm $(MAKEFILE_DIR)/bin/aurora_eth_connector_migration.wasm

build:
	cargo near build reproducible-wasm --manifest-path $(MANIFEST) --out-dir $(MAKEFILE_DIR)/bin

test:
	cargo test

check-fmt:
	cargo fmt --check

clippy-near:
	cargo clippy

check: clippy-near check-fmt
