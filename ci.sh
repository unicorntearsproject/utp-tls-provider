#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# Everything the crate checks about itself. Run from this folder: ./ci.sh
set -eu

cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test

# It must build for a bare-metal target (no operating system, no vector code), with a randomness
# source supplied by the program.
rustup target add x86_64-unknown-none >/dev/null 2>&1 || true
RUSTFLAGS='--cfg aes_force_soft --cfg polyval_force_soft --cfg chacha20_force_soft --cfg poly1305_force_soft --cfg curve25519_dalek_backend="serial"' \
  cargo build --release --target x86_64-unknown-none --features getrandom-custom

# The point of the crate: no RSA code that handles a private key. The only big-number code is
# num-bigint's, for a public power.
for banned in rsa num-bigint-dig pkcs1 pkcs8; do
  if cargo tree -e normal,build --prefix none | cut -d' ' -f1 | grep -qx "$banned"; then
    echo "error: $banned is in the dependency tree" >&2
    exit 1
  fi
done

if command -v cargo-deny >/dev/null 2>&1; then
  cargo deny check
else
  echo "note: cargo-deny not installed; skipping the license and advisory check" >&2
fi
echo "all checks passed"
