# Changelog

Forensic reports cite the tool version that produced them (`tool.version` in
every exported report), so each release below is an annotated git tag whose
tree is exactly what that version shipped.

## v0.6.3 - 2026-07-09

Deploy-pipeline liveness and credential hygiene, before the Cloudflare
cutover makes the workflow the only production writer.

- **The newest green commit can no longer be evicted from the deploy
  queue.** GitHub's default concurrency keeps a single pending slot and
  *replaces* its occupant: with deploys serialized, an older commit's
  late-finishing CI could evict the newest commit's queued deploy, then
  skip itself as stale (v0.6.2's guard), leaving production stuck on an
  old commit with every run green. Concurrency now sits on the deploy
  job itself with `queue: max`, so runs queue instead of replacing each
  other, stale ones drain as no-op skips, and failed-CI events (whose
  job is skipped) never enter the group.
- **Production credentials are scoped to the two steps that use them.**
  The Cloudflare token was previously job-level environment, visible to
  checkout, toolchain installers, and the build. It now reaches only
  preflight (which checks its presence) and the wrangler upload.
- **wrangler installs from a committed lockfile** (`deploy/package.json`
  + `package-lock.json`, exact-pinned) in a credential-free step, instead
  of `npx` resolving transitive npm dependencies at deploy time.
- **Missing credentials fail loudly after cutover.** Once the
  `PRODUCTION_DEPLOY_REQUIRED` repository variable is set (cutover step 4
  in the workflow header), a missing or deleted secret fails the run
  instead of green-skipping while production silently stops updating.
- README: the memory-safety claim now discloses the one known gap (the
  upstream unified-log parser sizes some allocations from archive
  metadata; worst case is a crafted file aborting its own scan, an
  availability nuisance rather than a result-integrity risk).

## v0.6.2 - 2026-07-09

One fix: the CI-gated deploy workflow could roll production backward.

- **Stale deploys are refused.** Deploy runs trigger on CI completion, and
  CI runs can finish out of order - a newer push's CI completing before an
  older one's. The later-finishing older run would then deploy its older
  commit over the newer one, and "verify" its own stale commit as success.
  (Observed dormant on 2026-07-09: `fecdac3`'s CI finished two minutes
  before `4119475`'s.) Deploys now confirm the validated commit is still
  the tip of `main` at preflight and again immediately before the upload,
  and a concurrency group serializes deploy runs so the check cannot be
  raced mid-build. The workflow remains inert until the Cloudflare
  secrets exist; the fix ships before cutover so the race never goes live.

## v0.6.1 - 2026-07-09

Focused integrity follow-up to the v0.6.0 audit release, closing the
remaining paths where a scan could overstate what it checked.

- **Live indicator data no longer reaches scans at all.** A count-based
  floor cannot tell a legitimate update from a feed that swapped reviewed
  indicators for unreviewed ones while preserving counts, so scans now use
  only the bundled, reviewed snapshots. The upstream fetch powers a
  "newer data published upstream" notice (shown only for plausible
  updates that meet the reviewed floor); updates ship through the weekly
  reviewed-snapshot PR process.
- **Structural parse success is now defined per surface.** An empty or
  unrecognizable shutdown.log is `unparsed` (a real log with no delayed
  clients still counts as parsed); a crash log whose body JSON fails is
  `parsed_partial` even when the header line parses; a unified-log
  inventory in which zero processes resolved to binary paths is
  `parsed_partial`. Each downgrades the verdict to inconclusive via scan
  limits.
- **A scan with no applicable indicators loaded can never be clear** -
  "no traces found" with nothing to match would be vacuously true. Guards
  the native harness and embedders; the browser always loads the bundled
  sets. Garbage input still reads as "not a sysdiagnose".
- **The decompression budget now counts every byte**, including data
  arriving after the tar end-of-archive marker, closing the gzip-bomb
  bypass; a stream continuing past the budget halts with an error.
- Deployment: `deploy-production.yml` deploys the exact CI-validated
  commit via wrangler after CI succeeds and verifies the served
  service-worker SHA, headers, and fixtures (inert until Cloudflare
  secrets are configured; cutover documented in the workflow).
- Hygiene: npm dependabot coverage for e2e, explicit read-only CI
  permissions, and a README disclosure of Cloudflare's injected
  NEL/Report-To headers.
- Narrow scans announce themselves: a clear verdict resting on one or two
  present surfaces now says so in the banner instead of reading like a
  full four-surface scan.

## v0.6.0 - 2026-07-09

Result-integrity release from an external audit: every path by which a
degraded scan could still render "No known spyware traces found" is closed.

- **The Rust engine now owns the verdict** (`verdict` in every report,
  `schema_version` 2). Parser failures - an unparseable ps.txt, crash logs
  whose JSON does not parse, tracev3/uuidtext parse failures, inventory cap
  hits - surface as scan limits and force the verdict to inconclusive.
  Previously the UI derived the verdict from findings and scan limits alone,
  so a scan whose parsers failed could read as clear. Indicator matches
  still escalate over a degraded scan, never wash out.
- **Live indicator refresh can no longer reduce coverage.** Each set in
  `manifest.json` carries the reviewed bundled floor (`min_indicators`,
  `min_applicable`); a live file below either floor (empty bundle,
  rate-limit page shaped like JSON, upstream regression) is rejected in
  favor of the snapshot. A CI test (`bundled_iocs`) keeps the floors honest
  against the snapshots themselves.
- **Scan results can no longer attach to the wrong file.** Worker messages
  carry a scan id and stale/foreign messages are dropped; concurrent scan
  starts are refused while one is in flight.
- Tar reader hardening: header checksums are validated (corruption mid-
  archive is inconclusive, not silently misparsed); the entry cap counts
  every header type so directory/PAX floods cannot bypass it; a total
  decompressed-byte budget (8 GB) caps gzip bombs; PAX record lengths use
  checked arithmetic (a crafted length could previously trap the WASM
  module on 32-bit).
- Output hardening: findings are capped at 5,000 (capped scans are
  inconclusive unless a match was already found), the DOM renders at most
  200 finding cards (the exported JSON always has all of them), and
  uuidtext binary paths are truncated at 4 KB.
- `crashes_and_spins` is matched as a path component, so lookalike
  directories in unrelated archives no longer classify as crash logs.
- STIX AND/FOLLOWEDBY rejection is token-based: a multi-line or
  tab-separated `AND` pattern can no longer be half-matched.
- Report accuracy: coverage "examined" lists only surfaces actually present;
  a unified-log-only archive is no longer labeled "not a sysdiagnose";
  device OS provenance prefers the newest crash log (with its timestamp
  recorded) instead of the first encountered.
- UI/UX: verdicts render from the engine verdict; scan errors are announced
  to screen readers (focus + `role="alert"`); the artifact table scrolls
  inside its own container on narrow screens; the live-indicator fetch
  timeout covers the response body, so a stalling server cannot hang
  startup.
- Validation: the real-capture integration test now loads all eight bundled
  indicator sets, so it reproduces the documented zero-false-positive claim;
  `cargo run --example ioc_stats` regenerates the manifest floors.

## v0.5.0 - 2026-07-08

- **Unified log analysis** - the fourth detection surface, and the largest:
  every process that wrote a log entry during the archive window (typically
  days of device history) is inventoried and checked against the process and
  path indicators plus the location heuristics. Implementation is
  catalog-level via Mandiant's `macos-unifiedlogs` (compiled to WASM):
  tracev3 and uuidtext files are reduced to process facts as they stream by
  and dropped, so the 155 MB dsc string cache is never loaded and peak
  memory stays at one file. Log message contents are never rendered.
- Validated against a real iOS 26.5.2 capture: 64 tracev3 files, 2,656
  catalogs, 689 uuidtext files, zero parse failures, 617/617 processes
  resolved to paths, zero false positives (see VALIDATION.md; repeatable via
  the env-gated `real_capture` integration test).
- A sysdiagnose without unified log data reports the surface as missing,
  and unified files cut short by the size cap surface in scan limits.
- WASM module grows ~165 KB for the parser.

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
