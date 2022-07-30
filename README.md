# Aurora Fungible Token

[![Project license](https://img.shields.io/badge/License-Public%20Domain-blue.svg)](https://creativecommons.org/publicdomain/zero/1.0/)

Aurora Fungible Token implementation is the smart contract on the NEAR Protocol for 
[Aurora Engine](https://github.com/aurora-is-near/aurora-engine).
It is implementation for [NEP-141](https://nomicon.io/Standards/Tokens/FungibleToken/Core).

It is base on [AIP:  Split NEP-141 logic outside of Engine](https://github.com/aurora-is-near/AIPs/pull/5).

## Development

### Prerequisites

- Rust stable (1.62+)
- cargo-make

```sh
rustup target add wasm32-unknown-unknown --toolchain nightly-2021-03-25
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
- `build`, builds all engine smart contract and produces the
  `aurora-<profile>-test.wasm` in the `bin` folder. Requires `build-contracts`.
  Requires a `--profile` argument.
- `build-test`, builds all the below using test features. Requires a `--profile`
  argument.
- `build-contracts`, builds all the ETH contracts.

For example, the following will build the mainnet debug binary:
```sh
cargo make --profile mainnet build
```

## License
**aurora-engine** has multiple licenses:
* all crates except `engine-test` has **CCO-1.0** license
* `engine-test` has **GPL-v3** license