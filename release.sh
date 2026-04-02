#!/bin/sh
cargo audit && \
  cargo build --release && \
  env RUST_BACKTRACE=1 cargo test --no-fail-fast && \
  cargo release patch --no-publish --execute
