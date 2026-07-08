# Trace

[![CI](https://github.com/iAnonymous3000/tracescan/actions/workflows/ci.yml/badge.svg)](https://github.com/iAnonymous3000/tracescan/actions/workflows/ci.yml)

**Check an iPhone sysdiagnose for traces of known mercenary spyware - entirely in your browser.**

**Live: https://tracescan.pages.dev/**

Trace makes credible spyware forensics accessible to people who have never opened a terminal, without asking them to trust anyone with their data. Parsing and indicator matching run as a Rust/WebAssembly module inside the browser tab. **There is no upload endpoint - the privacy claim is architectural, not a policy promise**, and you can verify it yourself: load the page, turn on Airplane Mode, and scan.

## How it works

1. Capture a sysdiagnose on the iPhone (hold both volume buttons + side button ~1.5s, wait ~10 minutes, find it under *Settings → Privacy & Security → Analytics & Improvements → Analytics Data*).
2. AirDrop the `sysdiagnose_….tar.gz` file to a computer.
3. Drag it into the Trace page. Analysis takes well under two minutes.

The archive is streamed chunk-by-chunk through a WASM pipeline (gzip → tar → parsers); only the few artifact files being analyzed are held in memory (hard-capped, so a crafted archive cannot exhaust it), and nothing leaves the machine. A scan that hits a safety cap, or an archive that arrives truncated, is reported as incomplete - never as clean. Three artifact types are analyzed:

| Artifact | Signal |
|---|---|
| `system_logs.logarchive/Extra/shutdown.log` (rotated `shutdown.0.log` on iOS 26) | Processes that delayed shutdown, per reboot - the [iShutdown](https://github.com/KasperskyLab/iShutdown) technique; Pegasus artifacts run from `roleaccountd.staging` |
| `crashes_and_spins/*.ips` | Crashing process names/paths vs. process indicators |
| `ps.txt`, `ps_thread.txt` | Processes running at capture time vs. process indicators |

Both shutdown.log generations are handled and were verified against a real iOS 26.5.2 capture: the classic one-line format, and the iOS 26 format with rotated filenames, indented client lines, and a trailing binary-UUID path component (stripped before matching, or no name indicator could ever hit).

Indicators are STIX2 bundles published by [Amnesty International's Security Lab](https://github.com/AmnestyTech/investigations) (Pegasus, Predator, Wintego Helios). Bundled snapshots are the offline floor; a scheduled workflow PRs upstream changes into the snapshots weekly, the app opportunistically refreshes them live at load, and every scan records the SHA-256 of the exact indicator files it used.

## Honest epistemics - the part that matters

- **"No matches" is not "clean."** It means no *known* implant left *known* traces in the artifacts this tool reads. The UI says so, prominently, every time.
- Two coverage gaps are stated in every report: the public-IOC time lag, and artifact coverage (domain/URL indicators live in backup artifacts - browsing history, messages - that this version does not read; ~2,000 of the loaded indicators are in that category and results never imply they were checked).
- A hit routes to [Access Now's Digital Security Helpline](https://www.accessnow.org/help/) and [Amnesty's Security Lab](https://securitylab.amnesty.org/get-help/), with evidence-preservation guidance (don't wipe; keep the file; export the JSON report for responders).
- A sufficiently compromised device can lie in its own sysdiagnose. Detection is best-effort starting at evidence collection.

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

- `crates/trace-core/` - Rust core: streaming tar/gzip, STIX2 extraction, the three parsers, report assembly. `cargo test` covers all of it natively, including proptest property tests over the hostile-input surface (`tests/properties.rs`).
- `web/` - the static site (framework-free JS + CSS, service worker for offline, strict CSP). This directory is the entire deployable artifact.
- `e2e/` - Playwright browser tests: demo scans, verdict rendering, report export, scan-limit handling, and offline operation.
- `fixtures/make_fixtures.sh` - synthetic demo archive generator.

CI runs fmt, clippy, tests, `cargo audit`, and the browser E2E suite on every push and PR. A weekly workflow PRs upstream indicator changes into the bundled snapshots (requires the "Allow GitHub Actions to create and approve pull requests" repo setting).

Deployment notes: production is **Cloudflare Pages** (`tracescan.pages.dev`), built by its git integration on every push to `main` (build command installs Rust and wasm-pack, builds the WASM module, and stamps the service-worker cache name with the commit SHA; output directory `web/`). Cloudflare enforces `web/_headers` automatically, so the CSP, COOP, and nosniff headers are real there; the `<meta>` CSP in `index.html` remains as defense in depth for any host that cannot send headers. Note that Cloudflare builds track `main` directly rather than waiting for CI, so don't push to `main` with CI red. The old GitHub Pages URL now serves only a redirect plus a service-worker kill switch (`redirect/`, published by `.github/workflows/deploy.yml`); leave it in place indefinitely so returning visitors with the old origin cached get moved over.

## Scope (v1)

Deliberate non-goals: real-time monitoring, removal claims, Android, backup parsing. Planned next: unified log (`tracev3`) parsing via Mandiant's `macos-unifiedlogs` Rust crate - the richest artifact in a sysdiagnose, already in the right language for this stack.

## Acknowledgements

Built on public research and data from Amnesty International's Security Lab, the [Mobile Verification Toolkit](https://github.com/mvt-project/mvt) project, Kaspersky's iShutdown research, and Citizen Lab's publications. Trace is a front-end to the open threat-intel ecosystem, not a replacement for it.
