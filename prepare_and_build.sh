#!/bin/bash
set -e;

# Set directory to script directory
cd "$(dirname "$0")";

# Install and set "our" Rust version
rustup default nightly-2023-08-01-x86_64-unknown-linux-gnu;

# Download external repos and patch them
rm -rf external/nym;
rm -rf external/forked-nym-sphinx;

cd external;
git clone https://github.com/nymtech/nym.git;
cd nym;
git checkout "34a47a9449d5c3c4a8f4270dcb9f0a004972c752";
git apply ../../nym.patch;
git apply ../../nym-lock.patch;
cd ..;
git clone https://github.com/lambdapioneer/forked-nym-sphinx/;
cd forked-nym-sphinx;
git checkout pudding;
cd ../..;

# Build pudding in debug and test
cd pudding;
cargo build;
cargo test;
cd ..;

# Build pudding in release mode
cd pudding;
cargo build --release;
cd ..;

# All good :)
echo "";
echo "[+] All prepared and built for the evaluation";
echo "";
