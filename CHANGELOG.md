# Changelog

Forensic reports cite the tool version that produced them (`tool.version` in
every exported report), so each release below is an annotated git tag whose
tree is exactly what that version shipped.

## Unreleased

Scanner correctness and hardening. Verified end to end against a real iOS 26.5.2
(23F84) capture, which now parses fully and reads clear with every surface
complete. The report schema is unchanged.

- iOS 26 parser coverage. Three diagnostic .ips families are now understood
  (security analytics bug_type 226, cpu_resource 202, proactive_event_tracker
  303), so a genuine sysdiagnose no longer reports its crash and diagnostic
  files as unparseable. ps.txt accepts the iOS "?" process state (previously
  every row of a real listing was skipped), and unified-log support files for
  firmware coprocessors (AOP, DCP, ...) and trailing-slash .dext bundles are
  recognized instead of counted as parse failures.
- Closed false-clear gaps. Crash .ips outside crashes_and_spins (paired-device
  ProxiedDevice reports, OTA update logs) are scanned and disclosed;
  directory-valued (trailing-slash) file:path indicators match by prefix rather
  than never matching, and relative-path indicators are recorded but not
  counted as checkable; unified-log catalogs with inconsistent internal counts
  degrade the surface instead of silently dropping processes; a PAX header with
  an undecodable record, a ps row whose numeric fields overflow their columns,
  a crash body naming no process, and a shutdown delay header with no client
  lines all keep the scan fail-closed.
- Closed false-positive paths. Indicator matching is case-sensitive, so
  Amnesty's capitalized 'Diagnosticd' no longer matches Apple's legitimate
  'diagnosticd'; a compound STIX pattern can no longer be split into a matchable
  clause at a quote-adjacent AND.
- Hardening. tracev3 chunkset sizes are validated before decompression so a
  crafted file cannot force an unbounded allocation; a WASM trap retires and
  replaces the background worker rather than reusing a poisoned instance; the
  results banner treats any unrecognized verdict as inconclusive, never clear;
  archives dropped at the retention cap and truncated process listings are
  reported accurately instead of as absent or empty.

Review follow-ups. A multi-dimensional review confirmed the engine, parsers, and
detection methodology are sound, and turned up a set of interface, accessibility,
and maintainability fixes. None change verdict semantics or the report schema.

- Restored a green build. A formatting slip in the iOS 26 uuidtext resolver was
  failing `cargo fmt --check`, which gates CI and the production deploy.
- The readable HTML export's "Device metadata redacted" promise now holds even
  when raw technical details are included: the OS build and capture timestamp
  are stripped from artifact details and finding evidence, not only from the
  device section.
- Accessibility. The scan verdict is announced to screen readers by focusing its
  heading; keyboard focus follows the view into the scanning screen instead of
  falling back to the page body; the drop target has a distinct keyboard-focus
  ring; the local-processing dialog has an accessible name; and a declared color
  scheme lets native form controls render correctly in dark mode.
- Maintainability. The reviewed-floor guard (a false-clear safeguard enforced on
  both scan paths), the HTML escaper, and the canonical-path predicate each have
  a single definition again instead of drifting copies, and the background
  worker's finalization phase gets its own watchdog so a slow but healthy finish
  is not failed closed.

Responder-trust and operational-safety work. The report schema and engine-owned
verdict semantics are unchanged.

- Added a responder guide with a five-minute intake checklist, archive/report
  hashing, schema and build checks, exact-commit semantic reproduction, field
  interpretation, evidence-preservation guidance, and explicit unsigned-report
  limits. Added a repository-scoped threat model covering the person, archive,
  browser, parser, indicators, deployment, and responder handoff boundaries.
- Added prominent pre-scan safety guidance: a visit, capture, transfer, and
  download can be observable. The Windows guide now discloses that iCloud
  stores another archive copy and can expose account activity, and phone-only
  scanning is explicitly unvalidated.
- Results now show and copy the engine-computed archive SHA-256. A new readable
  HTML export previews privacy redactions, omits filename, device metadata, raw
  evidence objects, and dedicated source-artifact fields by default, remains
  printable without scripts or remote assets, and explains how responders
  check report consistency by re-scanning.
- Deployment documentation now reflects the completed CI-gated Cloudflare
  cutover and its external configuration invariants instead of the retired
  pre-CI git-integration path.

## v0.7.3 - 2026-07-13

Fail-closed worker handling and real-capture parser coverage. Report schema v3
is unchanged; known iOS diagnostic formats that are fully understood no longer
force an inconclusive verdict.

- **A worker crash can never replay a partially read archive inline.** Worker
  startup failures still fall back before scanning begins, but a crash after
  dispatch is terminal for the page and shows a reload/help message. Structured
  per-scan errors leave a healthy worker reusable. Startup readiness, timeout,
  scan ownership, and stale-message boundaries are covered end to end.
- **`ps_thread.txt` uses the final full-path `COMMAND` column.** Thread rows are
  skipped, wide PIDs are parsed by row shape rather than header byte width, and
  unreadable rows make the listing partial. A one-`COMMAND` header is rejected
  instead of treating its abbreviated value as a full path. Current iOS 26's
  valid header-only `ps_thread.txt` is recognized as empty only when another
  parsed process listing supplies a nonempty inventory; it cannot clear alone.
- **Six ancillary `.ips` families now have strict parsers.** `stacks` and
  `forceReset` process maps, Jetsam process arrays, and disk-write command/path
  reports feed indicator matching. Siri feedback and ResetCounter are
  recognized as metadata-only diagnostics without inventing process identities.
  Empty inventories, malformed rows, PID mismatches, or schema drift remain
  partial and therefore inconclusive.
- **The Pegasus staging heuristic no longer flags Apple's nested execution
  workspace.** Published direct-child `roleaccountd.staging/<process>` shapes
  remain suspicious and exact STIX indicators are unchanged; nested
  `exec/<id>.xpc/...` system paths receive only the ordinary unusual-location
  note. This removes a false positive reproduced on a clean iOS 26.5.2 capture.
- Crash timestamps are compared as offset-aware instants when choosing report
  device metadata; nullable source metadata renders as unavailable instead of
  `null`; and the report schema is included in the offline service-worker shell.
- The release harness passes on two private iOS 26.5.2 captures and EC-DIGIT-
  CSIRC's public iOS 15 capture with all artifacts parsed, all bundled indicator
  sets loaded, and zero match or suspicious findings.

## v0.7.2 - 2026-07-09

Integrity fixes from the post-v0.7.1 audit: four inputs that could read
as clear (or suppress a detection) when they must not. Report v3 shape,
normal fixture output, and the UI are unchanged.

- **uuidtext alone is no longer a unified-log surface.** uuidtext files
  are support data (UUID to binary-path mappings); an archive carrying
  them without any tracev3 has no process activity to check, and
  previously counted the surface as examined and complete. It now reads
  as missing, and uuidtext-only input is "not a sysdiagnose".
- **Structurally empty artifacts are never clear.** A ps.txt with a
  header but zero process rows is `unparsed` (a real listing always has
  processes); a crash log whose JSON parses but names no process
  (`{}` header/body) is `parsed_partial` (every real crash identifies
  its process, or names pids in a panic string); tracev3 that parses to
  an empty process inventory raises a scan limit. All three previously
  produced clear verdicts with zeroed details.
- **A real match now survives a findings flood.** Retention at the
  5,000-finding cap is severity-aware (a Match evicts a Note, then a
  Suspicious; a Suspicious evicts a Note), so a crafted archive raising
  thousands of informational findings can no longer crowd out an exact
  IOC match discovered later - the match survives and controls the
  verdict. Previously the match was silently dropped.
- **Unified-log degradation now marks the surface partial.** Any tracev3
  or uuidtext parse failure, truncated file, or inventory cap downgrades
  the surface status (and therefore `assurance.surfaces`), instead of
  only raising a scan limit while the surface claimed `complete`.
- **`assurance.complete` is false for unrecognizable input**, and its
  schema description now spells out that it means processing
  completeness, not surface coverage.
- Deterministic fake-clock regression coverage for the engine-measured
  duration, and stale pre-v0.7.1 timing comments cleaned up.

## v0.7.1 - 2026-07-09

Two Report v3 corrections; the shape is unchanged.

- **`duration_ms` now measures the whole scan.** It was captured by the
  producers before `finish()`, which is where parsing, indicator
  matching, and verdict assembly actually happen, so it recorded only
  streaming time. The engine now measures duration itself through a
  host-injected millisecond clock (js `Date.now` in the browser wrapper,
  a monotonic timer natively), from the first byte received to the end
  of report assembly. `generated_at` is likewise stamped by the wrapper
  when finalization begins, not when streaming ends.
- **The schema is served at its declared `$id`.** `report.schema.json`
  moved from `docs/` into `web/`, so
  `https://tracescan.pages.dev/report.schema.json` resolves to the
  contract instead of the HTML fallback. The deploy workflow's
  post-deploy verification now checks it.

## v0.7.0 - 2026-07-09

Report v3: the evidence-package foundation. The exported report is now a
single Rust-owned contract; no field is appended by the UI.

- **Rust owns the whole envelope.** `generated_at`, `source_file`,
  `scanned_via`, and `indicator_provenance` were previously appended by
  JavaScript after serialization, unversioned. Producers now hand the
  engine descriptive metadata (file identity, clock readings, catalog
  info) and the engine emits everything; what the UI renders is exactly
  what exports. `schema_version` is 3.
- **The archive is identified by hash.** The engine computes SHA-256 over
  every byte it receives, so a report states exactly which file it
  describes (`source_file.sha256`) - responders can match a report to an
  archive, and two reports to each other.
- **Reports carry build identity.** `tool.build_commit` records the exact
  commit the running scanner was built from (an untagged commit can reach
  production while `tool.version` stays the same). Injected in CI, the
  deploy workflow, and the Cloudflare build command; null for local dev
  builds and dirty trees, which are not any commit.
- **Machine-readable completeness.** A new `assurance` block gives
  comparison tooling per-surface states (complete / partial / absent) and
  an overall completeness flag, derived from the same facts as the
  verdict. Indicator-set provenance (engine-hashed text, catalog date,
  source, upstream freshness) moved inside the envelope, and scans record
  wall-clock duration.
- **The contract is enforced three ways.** `docs/report.schema.json` is
  the checked-in JSON Schema; Rust tests validate real fixture reports
  against it and pin the field shape to a golden list; the browser E2E
  suite holds the worker and inline producers to the same golden, so all
  three producers provably emit one shape.

Verdict semantics and UI behavior are unchanged.

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
