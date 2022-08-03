# Aurora Fungible Token

[![Project license](https://img.shields.io/badge/License-Public%20Domain-blue.svg)](https://creativecommons.org/publicdomain/zero/1.0/)
[![Lints](https://github.com/aurora-is-near/aurora-fungible-token/actions/workflows/lints.yml/badge.svg)](https://github.com/aurora-is-near/aurora-fungible-token/actions/workflows/lints.yml)
[![Tests](https://github.com/aurora-is-near/aurora-fungible-token/actions/workflows/tests.yml/badge.svg)](https://github.com/aurora-is-near/aurora-fungible-token/actions/workflows/tests.yml)
[![Builds](https://github.com/aurora-is-near/aurora-fungible-token/actions/workflows/builds.yml/badge.svg)](https://github.com/aurora-is-near/aurora-fungible-token/actions/workflows/builds.yml)

Aurora Fungible Token implementation is the smart contract on the NEAR Protocol for 
[Aurora Engine](https://github.com/aurora-is-near/aurora-engine).
It is implementation for [NEP-141](https://nomicon.io/Standards/Tokens/FungibleToken/Core).

It is base on [AIP:  Split NEP-141 logic outside of Engine](https://github.com/aurora-is-near/AIPs/pull/5).

## Development

### Prerequisites

- Rust nightly (2022-08-08) with the WebAssembly toolchain
- cargo-make

```sh
rustup target add wasm32-unknown-unknown
cargo install --force cargo-make
```

### Building & Make Commands

Every task with `cargo make` must have a `--profile` argument.

The current available `profile`s are:
- `mainnet`, suitable for mainnet.
- `testnet`, suitable for testnet.
- `local`, suitable for local development.
- `custom`, suitable for custom environments, see note below.

A custom environment may be required depending on the circumstances. This can
be created in the `.env` folder as `custom.env` following the structure of the
other `.env` files. See `bin/local-custom.env` for more details.

Every make most follow the following pattern, though `--profile` is not required
for all such as cleanup:
```sh
cargo make [--profile <profile>] <task>
```

#### Building the aurora-fungible-token contract

To build the binaries there are a few commands to do such following the format.

The current available build `task`s are:
- `default`, does not need to be specified, runs `build`. Requires a `--profile`
  argument.
- `build`, builds all fungible-token smart contract and produces the
  `aurora-<profile>-test.wasm` in the `bin` folder.
  Requires a `--profile` argument.
- `build-test`, builds all the below using test features. Requires a `--profile`
  argument.

For example, the following will build the mainnet debug binary:
```sh
cargo make --profile mainnet build
```

## License
**aurora-fungible-token** has multiple licenses:
* all crates except `fungible-token-tests` has **CCO-1.0** license
* `fungible-token-tests` has **GPL-v3** license