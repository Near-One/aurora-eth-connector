# Aurora Eth Connector

[![Project license](https://img.shields.io/badge/License-Public%20Domain-blue.svg)](https://creativecommons.org/publicdomain/zero/1.0/)
[![Lints](https://github.com/aurora-is-near/aurora-fungible-token/actions/workflows/lints.yml/badge.svg)](https://github.com/aurora-is-near/aurora-fungible-token/actions/workflows/lints.yml)
[![Tests](https://github.com/aurora-is-near/aurora-fungible-token/actions/workflows/tests.yml/badge.svg)](https://github.com/aurora-is-near/aurora-fungible-token/actions/workflows/tests.yml)

Aurora Eth Connector - Fungible Token implementation is a smart contract on the NEAR Protocol for the
[Aurora Engine](https://github.com/aurora-is-near/aurora-engine).
It is an implementation for [NEP-141](https://nomicon.io/Standards/Tokens/FungibleToken/Core).

It is based on [AIP:  Split NEP-141 logic outside of Engine](https://github.com/aurora-is-near/AIPs/pull/5).

## Development

### Prerequisites

- Rust nightly (2022-08-08) with the WebAssembly toolchain
- cargo-make

```sh
rustup target add wasm32-unknown-unknown
cargo install --force cargo-make
```

#### Running unit & integration tests

`cago make test`: tests the whole cargo workspace and the ETH contracts. This requires a `--profile` argument.

For example, the following will test the whole workspace and the ETH contracts:

```sh
cargo make --profile mainnet test 
```

### Building & Make Commands

Every task with `cargo make` must have a `--profile` argument.

The currently available `profile`s are:

- `mainnet`, suitable for mainnet.
- `testnet`, suitable for testnet.
- `local`, suitable for local development.
- `custom`, suitable for custom environments, see the note below.

A custom environment may be required depending on the circumstances. This can
be created in the `.env` folder as `custom.env` following the structure of the
other `.env` files. See `bin/local-custom.env` for more details.

Every make must follow the following pattern, though `--profile` is not required
for all such as cleanup:

```sh
cargo make [--profile <profile>] <task>
```

#### Building the aurora-eth-connector contract

There are a few different commands available to build binaries.

The currently available build `task`s are:

- `default`: does not need to be specified, runs `build`. Requires a `--profile` argument.
- `build`: builds smart contract and produces `aurora-<profile>.wasm` in the `bin` folder.
  Requires a `--profile` argument.
- `build-test`: builds all tasks using the test features. Requires a `--profile` argument.
- `build-migration`, builds smart contract with the migration functionality and produces
  `aurora-<profile>.wasm` in the `bin` folder.

For example, the following will build the mainnet debug binary:

```sh
cargo make --profile mainnet build
```

#### Running checks & lints

To run lints and checks, the following tasks are available:

- `check`, checks the format, clippy, and ETH contracts.
- `check-fmt`, checks the workspace Rust format only.
- `check-clippy`, checks the Rust workspace with clippy only.

For example the following command will run the checks. `profile` is not required
here:

```sh
cargo make check
```

## License

**aurora-eth-connector** has [**CCO-1.0** license](LICENSE)
