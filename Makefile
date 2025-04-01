MAKEFILE_DIR :=  $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

MANIFEST := $(MAKEFILE_DIR)/eth-connector/Cargo.toml

build-migration:
	cargo near build non-reproducible-wasm --manifest-path $(MANIFEST) --features migration

build:
	cargo near build reproducible-wasm --manifest-path $(MANIFEST)

test:
	cargo test

check-fmt:
	cargo fmt --check

clippy-near:
	cargo clippy

check: clippy-near check-fmt
