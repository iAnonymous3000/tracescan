#!/usr/bin/env bash
# Full build: Rust tests → WASM module.
# Output is the static site in web/ - deploy that directory anywhere
# (any static host; no server-side code exists by design).
# Tracked demo fixtures are intentionally regenerated only by the explicit
# fixtures/make_fixtures.sh command so a normal build does not rewrite them.
#
# When deploying a new version, bump CACHE in web/sw.js so returning
# offline users pick up the update.
set -euo pipefail
cd "$(dirname "$0")"

# Reports embed the exact build commit (tool.build_commit). A dirty tree
# is not that commit, so it must not claim to be.
if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
  export TRACE_BUILD_COMMIT=""
else
  export TRACE_BUILD_COMMIT="$(git rev-parse HEAD 2>/dev/null || echo "")"
fi

cargo test --locked --all-targets
wasm-pack build crates/trace-core --target web --release --out-dir ../../web/pkg -- --locked

echo
echo "Build complete for local use. Serve web/ with:"
echo "  python3 -m http.server 8973 --directory web"
echo "Regenerate tracked demo fixtures explicitly with:"
echo "  ./fixtures/make_fixtures.sh"
echo "Before any manual production deploy, replace the trace-v1 cache marker"
echo "in web/sw.js with a release-unique value; CI-gated production does this"
echo "automatically with the validated commit SHA."
