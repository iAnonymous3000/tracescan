# Changelog

Forensic reports cite the tool version that produced them (`tool.version` in
every exported report), so each release below is an annotated git tag whose
tree is exactly what that version shipped.

## v0.4.0 - 2026-07-08

- Indicator coverage: eight iOS-relevant campaigns bundled (was three).
  Added KingSpawn/QuaDream (Citizen Lab, Microsoft), Operation Triangulation
  (Kaspersky), RCS Lab (Google, Lookout), Coruna and DarkSword (Google TIG,
  iVerify), all via the MVT project's aggregated indicator collection. The
  2021 Cytrox snapshot is replaced by MVT's maintained Predator aggregate
  (verified superset: zero indicators lost). Totals: 2,887 indicators
  loaded, 149 checkable against v1 artifacts (up from 2,067 / 88).
- Production hosting moved to Cloudflare Pages (https://tracescan.pages.dev):
  the security headers in `web/_headers` (CSP, COOP, frame-ancestors,
  nosniff) are now real response headers. The old GitHub Pages URL serves a
  permanent redirect plus a service-worker kill switch.
- Build chain pinned end to end: `rust-toolchain.toml` fixes the compiler for
  CI, the Cloudflare build, and local checkouts; wasm-pack is pinned by
  version (checksum-verified in the Cloudflare build); GitHub Actions are
  pinned to commit SHAs with dependabot proposing bumps.
- E2E suite runs on Chromium, Firefox, and WebKit (one WebKit skip: Playwright
  cannot emulate offline across a service-worker navigation there).
- VALIDATION.md documents what each detection surface is validated against
  and what cannot be validated with public data.
- Demo fixtures are byte-for-byte reproducible across machines: bsdtar was
  embedding a macOS `com.apple.provenance` xattr whose value varies per
  creating process; xattrs, ACLs, and file flags are now stripped.
- Boot-time indicator fetches revalidate the HTTP cache (`cache: 'no-cache'`),
  so dev servers without Cache-Control headers cannot serve stale sets.

## v0.3.1 - 2026-07-08

Verdict-accuracy fixes from a full methodology, bug, UI/UX, and code-quality
review.

- A raw tar that ends before its end-of-archive marker is reported as an
  incomplete scan (inconclusive verdict) instead of scanning as a false
  clear. Non-archive bytes still read as "not a sysdiagnose".
- Crash-log filename matching recovers hyphenated process names (Pegasus
  publishes `Diagnostics-2543`) by stripping the trailing date stamp instead
  of cutting at the first hyphen; matters when a crash log's JSON is
  unparseable.
- Live-fetched indicator files are validated as STIX bundles before use;
  a valid-JSON non-bundle now falls back to the bundled snapshot instead of
  breaking scanner startup.
- Indicator sets load in parallel; a crashed worker retries the scan inline;
  demo fixture fetch failures surface as errors.
- Path-flag heuristic text centralized so the three artifact surfaces cannot
  drift; ps and crash surfaces regained the research citation.

## v0.3.0 - 2026-07-07

- iOS 26 support, verified against a real iOS 26.5.2 capture: rotated
  `shutdown.N.log` filenames, header-plus-indented-clients format, and
  stripping of the trailing binary-UUID path component (which otherwise
  silently defeated every process-name indicator).
- Property tests over the hostile-input surface (tar state machine, engine,
  STIX loader, chunking invariance).
- Playwright browser E2E suite, including the offline privacy claim.
- Hardened pipeline: deploys gated on CI success and pinned to the validated
  commit; weekly indicator refresh PRs; `cargo audit` in CI.

## v0.2.0 - 2026-07-07

- Production hardening: streaming memory caps surfaced as scan limits with
  an inconclusive verdict, AppleDouble companion filtering, kernel panic
  `panicString` extraction, `file:path` indicator matching, AND-pattern
  skipping in STIX extraction, scan worker with inline fallback.

## v0.1.0 - 2026-07-07

- Initial release: local-first iOS sysdiagnose scanner as Rust/WASM in the
  browser. Streams gzip/tar, analyzes shutdown.log, crash logs, and process
  listings against Amnesty Security Lab STIX2 indicators (Pegasus, Predator,
  Wintego Helios), with honest-epistemics verdicts and JSON report export.
