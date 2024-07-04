#!/usr/bin/env bash

# Exit script as soon as a command fails.
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

docker run \
     --rm \
     --mount type=bind,source=$DIR,target=/host \
     --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
     -w /host \
     -e RUSTFLAGS='-C link-arg=-s' \
     rust:latest \
     /bin/bash -c "rustup target add wasm32-unknown-unknown; cargo install --force cargo-make; \
     cargo make --profile mainnet build; cargo make --profile mainnet build-migration"

mkdir -p res
cp $DIR/bin/aurora-eth-connector-mainnet.wasm $DIR/res/
cp $DIR/bin/aurora-eth-connector-mainnet-migration.wasm $DIR/res/