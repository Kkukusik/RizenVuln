#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
python3 -m unittest discover -s tests -p 'test_*.py'
(cd frontend && npm ci && npm run build && npm run test -- --run)
docker compose config -q
