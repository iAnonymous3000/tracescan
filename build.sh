#!/usr/bin/env bash
# Full build: Rust tests → WASM module → demo fixtures.
# Output is the static site in web/ - deploy that directory anywhere
# (any static host; no server-side code exists by design).
#
# When deploying a new version, bump CACHE in web/sw.js so returning
# offline users pick up the update.
set -euo pipefail
cd "$(dirname "$0")"

cargo test
wasm-pack build crates/trace-core --target web --release --out-dir ../../web/pkg
./fixtures/make_fixtures.sh

echo
echo "Build complete. Serve web/ locally with:"
echo "  python3 -m http.server 8973 --directory web"
