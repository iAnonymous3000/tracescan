# Trace

[![CI](https://github.com/iAnonymous3000/tracescan/actions/workflows/ci.yml/badge.svg)](https://github.com/iAnonymous3000/tracescan/actions/workflows/ci.yml)

**Check an iPhone sysdiagnose for traces of known mercenary spyware - entirely in your browser.**

**Live: https://tracescan.pages.dev/**

Trace makes credible spyware forensics accessible to people who have never opened a terminal, without asking them to trust anyone with their data. Parsing and indicator matching run as a Rust/WebAssembly module inside the browser tab. **There is no upload endpoint - the privacy claim is architectural, not a policy promise**, and you can verify it yourself: load the page, turn on Airplane Mode, and scan.

## How it works

1. Capture a sysdiagnose on the iPhone (hold both volume buttons + side button ~1.5s, wait ~10 minutes, find it under *Settings → Privacy & Security → Analytics & Improvements → Analytics Data*).
2. AirDrop the `sysdiagnose_….tar.gz` file to a computer.
3. Drag it into the Trace page. Analysis takes well under two minutes.

The archive is streamed chunk-by-chunk through a WASM pipeline (gzip → tar → parsers); only the few artifact files being analyzed are held in memory, with hard caps on retained bytes, per-file sizes, entry counts, findings, and total decompressed output, and nothing leaves the machine. A scan that hits a safety cap, or an archive that arrives truncated, is reported as incomplete - never as clean. One known gap: the upstream unified-log parser sizes some allocations from metadata inside the archive, so a deliberately crafted tracev3 file can force a large transient allocation. The worst case is that hostile file aborting its own scan (an availability nuisance, not a result-integrity risk; to be reported upstream). Four artifact types are analyzed:

| Artifact | Signal |
|---|---|
| `system_logs.logarchive/Extra/shutdown.log` (rotated `shutdown.0.log` on iOS 26) | Processes that delayed shutdown, per reboot - the [iShutdown](https://github.com/KasperskyLab/iShutdown) technique; Pegasus artifacts run from `roleaccountd.staging` |
| `crashes_and_spins/*.ips` | Crash and diagnostic reports: target process names/paths and complete process inventories where the format contains them |
| `ps.txt`, `ps_thread.txt` | Processes running at capture time vs. process indicators |
| `system_logs.logarchive` tracev3 + uuidtext | Every process that wrote a unified-log entry during the archive window (typically days of history), via [Mandiant's parser](https://github.com/mandiant/macos-UnifiedLogs) at catalog level - process inventory only, log messages are never rendered, and each file is reduced and dropped so memory stays flat |

Both shutdown.log generations are handled and were verified against a real iOS 26.5.2 capture: the classic one-line format, and the iOS 26 format with rotated filenames, indented client lines, and a trailing binary-UUID path component (stripped before matching, or no name indicator could ever hit).

Indicators are STIX2 bundles from the open threat-intel ecosystem: [Amnesty International's Security Lab](https://github.com/AmnestyTech/investigations) publications plus the [MVT project's aggregated indicator collection](https://github.com/mvt-project/mvt-indicators) (Citizen Lab, Kaspersky, Google Threat Intelligence, Microsoft, iVerify, and others). Eight iOS-relevant campaigns are bundled: Pegasus, Predator, KingSpawn (QuaDream), Operation Triangulation, RCS Lab, Wintego Helios, Coruna, and DarkSword. Scans use only the bundled, reviewed snapshots, and every scan records the SHA-256 of the exact indicator files it used. Live upstream data never reaches a verdict - no runtime check can tell a legitimate update from a feed that swapped reviewed indicators for unreviewed ones - so the app fetches upstream at load solely to tell the user when newer data has been published. Updates ship through a scheduled workflow that PRs upstream changes into the snapshots weekly for review; a CI test pins each set's reviewed indicator floor so a regressing snapshot cannot merge silently.

## Honest epistemics - the part that matters

- **"No matches" is not "clean."** It means no *known* implant left *known* traces in the artifacts this tool reads. The UI says so, prominently, every time.
- Two coverage gaps are stated in every report: the public-IOC time lag, and artifact coverage (domain/URL indicators live in backup artifacts - browsing history, messages - that this version does not read; roughly 2,700 of the ~2,900 loaded indicators are in that category and results never imply they were checked).
- A hit routes to [Access Now's Digital Security Helpline](https://www.accessnow.org/help/) and [Amnesty's Security Lab](https://securitylab.amnesty.org/get-help/), with evidence-preservation guidance (don't wipe; keep the file; export the JSON report for responders).
- A sufficiently compromised device can lie in its own sysdiagnose. Detection is best-effort starting at evidence collection.
- [VALIDATION.md](VALIDATION.md) states exactly what each detection surface has been validated against, and what could not be validated because the data is not public.
- [HELPLINE.md](HELPLINE.md) tells responders how to interpret, preserve, hash-bind, and independently reproduce a report. [THREAT_MODEL.md](THREAT_MODEL.md) documents the system and operational trust boundaries.

## Development

```
./build.sh                 # cargo test + wasm-pack build + regenerate demo fixtures
python3 -m http.server 8973 --directory web

# native CLI harness (same engine the browser runs):
cargo run --release --example scan -- <sysdiagnose.tar.gz> web/iocs/*.stix2

# browser end-to-end tests (needs web/pkg built first):
cd e2e && npm install && npx playwright install chromium && npm test
```

Requires Rust with the `wasm32-unknown-unknown` target, `wasm-pack`, `jq` and `bsdtar` (fixtures; bsdtar is the macOS default tar), and Node (E2E only). The demo fixtures are synthetic sysdiagnose archives, generated deterministically; the "infected" one seeds a real Pegasus process-name indicator so the genuine match path is exercised end-to-end.

Layout:

- `crates/trace-core/` - Rust core: streaming tar/gzip, STIX2 extraction, the four artifact parsers, report assembly, and the verdict (computed in Rust, in one place - the UI renders it and never re-derives safety semantics). `cargo test` covers all of it natively, including proptest property tests over the hostile-input surface (`tests/properties.rs`).
- `web/report.schema.json` - the exported report contract (schema_version 3). The whole envelope is assembled in Rust; every producer (browser worker, inline, native CLI) emits the same shape, pinned by a golden field list (`crates/trace-core/tests/report_v3.rs`) that the browser E2E suite checks too.
- `web/` - the static site (framework-free JS + CSS, service worker for offline, strict CSP). This directory is the entire deployable artifact.
- `e2e/` - Playwright browser tests: demo scans, verdict rendering, report export, scan-limit handling, and offline operation.
- `fixtures/make_fixtures.sh` - synthetic demo archive generator.

CI runs fmt, clippy, tests, `cargo audit`, and the browser E2E suite on every push and PR. A weekly workflow PRs upstream indicator changes into the bundled snapshots (requires the "Allow GitHub Actions to create and approve pull requests" repo setting).

Deployment notes: production is **Cloudflare Pages** (`tracescan.pages.dev`), deployed by [`.github/workflows/deploy-production.yml`](.github/workflows/deploy-production.yml) only after CI succeeds. The workflow checks out the exact validated commit, builds `web/` with that commit embedded in `tool.build_commit`, gives the service worker a per-commit cache name, uploads through pinned wrangler dependencies, and verifies the per-commit service-worker marker, required security headers, schema identifier/version contract, and demo-fixture availability on production.

Cloudflare's repository link is retained, but automatic production and preview branch builds must remain disabled in the Pages dashboard so the CI-gated workflow is the only production writer. The repository secrets `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` supply the deploy credentials; `PRODUCTION_DEPLOY_REQUIRED=true` makes either secret disappearing a hard failure instead of a green skip. These dashboard and repository settings are external configuration and must be re-checked after account or project changes.

The default-branch ruleset blocks deletion and non-fast-forward updates to `main` while still allowing ordinary fast-forward direct pushes. This protects release and report provenance without imposing a pull-request-only workflow.

Cloudflare enforces `web/_headers` automatically, so the CSP, COOP, and nosniff headers are real there; the `<meta>` CSP in `index.html` remains as defense in depth for any host that cannot send headers. The old GitHub Pages URL now serves only a redirect plus a service-worker kill switch (`redirect/`, published by `.github/workflows/deploy.yml`); leave it in place indefinitely so returning visitors with the old origin cached get moved over.

Deploy runs refuse any commit that is no longer the tip of `main` (checked at preflight and again just before upload), queue rather than replace each other (`queue: max` - the default single pending slot would let an older commit's late CI completion evict the newest commit's queued deploy), install wrangler from a committed lockfile before credentials enter the environment, and expose the Cloudflare secrets only to the two steps that need them.

**Hosting privacy note:** Cloudflare injects `NEL`/`Report-To` headers on this origin (Network Error Logging, `success_fraction: 0`), which asks browsers to report *network delivery failures* for the site to Cloudflare's collector. This is edge-level telemetry about connectivity errors, not page content - scanned files and results never leave the tab either way - but it is disclosed here because "no requests beyond indicator downloads" deserves the footnote.

## Scope (v1)

Deliberate non-goals: real-time monitoring, removal claims, Android, backup parsing. Unified-log analysis is catalog-level by design (process inventory, no message rendering): message-content indicators are domains and URLs, which belong to the backup-artifact scope. See [docs/design-unified-logs.md](docs/design-unified-logs.md) for that trade-off.

## Acknowledgements

Built on public research and data from Amnesty International's Security Lab, the [Mobile Verification Toolkit](https://github.com/mvt-project/mvt) project, Kaspersky's iShutdown research, and Citizen Lab's publications. Trace is a front-end to the open threat-intel ecosystem, not a replacement for it.
