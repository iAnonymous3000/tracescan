# Trace

[![CI](https://github.com/iAnonymous3000/tracescan/actions/workflows/ci.yml/badge.svg)](https://github.com/iAnonymous3000/tracescan/actions/workflows/ci.yml)

**Check an iPhone sysdiagnose for traces of known mercenary spyware, locally in
your browser.**

**Live: https://tracescan.pages.dev/**

Trace is a private, first-pass triage tool. It is not proof that a phone is
clean, and it is not a replacement for expert mobile forensics. Archive parsing,
indicator matching, verdict generation, and report assembly run in a
Rust/WebAssembly module inside the browser tab. The intended application has no
upload endpoint and sends neither archive bytes nor report contents to one.

Loading the application and then scanning offline demonstrates that the loaded
code has no scan-time server dependency. It does not authenticate code that was
already served or prove what a different build would do. Reviewing the exact
served build and observing the browser Network panel provide stronger audit
evidence, but still depend on the browser and host being trustworthy. Ordinary
site-resource requests occur while loading the page, and optional public-
indicator comparison requests can continue while the page is online, including
alongside a scan. Those requests do not contain archive or report data.

## How it works

1. Capture a sysdiagnose on the iPhone. Hold both volume buttons and the side
   button for about 1 to 1.5 seconds, then release. The archive commonly takes
   10 to 15 minutes to appear under *Settings -> Privacy & Security -> Analytics
   & Improvements -> Analytics Data*, but timing varies by device.
2. Move the `sysdiagnose_....tar.gz` archive to a computer using a route that
   fits the person's risk. AirDrop keeps the transfer local. The Windows path
   described in the app uses iCloud Drive, creates another cloud copy, and can
   expose account activity. Visiting Trace, triggering the capture, and moving
   the archive can all be observable.
3. Drop the archive into Trace. Scan time varies with archive size, browser, and
   computer. Direct scanning on an iPhone has not been validated, so the current
   workflow requires a computer.

The archive streams through a bounded WASM pipeline: gzip -> tar -> artifact
parsers. Trace retains only selected artifact files and reduces unified-log
files to process facts as they pass. Limits cover retained bytes, individual
files, archive entries, findings, unified-log allocations, and total
decompressed output. A parser failure, truncated archive, or reached safety cap
is disclosed as incomplete and can never produce a `clear` verdict.

The browser keeps file, drop, and demo controls disabled until WASM and every
bundled indicator floor validate. A worker or streaming read can be cancelled
and its result discarded. The inline fallback's final WASM analysis is still a
blocking operation; once it starts, the UI disables cancel and explains that
limitation.

Trace has four primary phone surfaces. Paired-device reports are supplemental;
they can contribute evidence but never substitute for phone coverage.

| Scope | Artifact | Signal |
|---|---|---|
| Primary | `system_logs.logarchive/Extra/shutdown.log` and rotated `shutdown.N.log` | Processes that delayed shutdown, per reboot: the [iShutdown](https://github.com/KasperskyLab/iShutdown) technique. Pegasus artifacts have run from `roleaccountd.staging`. |
| Primary | `crashes_and_spins/**/*.ips` | Target process names and paths, plus complete process inventories in diagnostic formats that contain them. |
| Supplemental | `logs/ProxiedDevice*/*.ips` | Process identities or inventories from paired-device diagnostic formats that contain them, normally from an Apple Watch. Metadata-only reports provide no process evidence; all paired reports are labeled separately and excluded from phone metadata and phone crash-surface completeness. |
| Primary | `ps.txt`, `ps_thread.txt` | Processes running at capture time. |
| Primary | `system_logs.logarchive` tracev3 and uuidtext | Process identities represented in successfully parsed catalog data, resolved to canonical paths through uuidtext. Trace derives no precise log window or event timestamps; messages are never rendered, and each input file is reduced and dropped. |

The rotated iOS 26 shutdown format, including indented client lines and trailing
binary-UUID path components, was validated against a private iOS 26.5.2
capture. The classic one-line format is covered by published iShutdown examples,
synthetic fixtures, and automated tests; Trace does not claim a public or private
real-capture receipt for that older format.

## Indicator and matching policy

Trace bundles reviewed STIX2 snapshots from [Amnesty International's Security
Lab](https://github.com/AmnestyTech/investigations) and the [MVT indicator
collection](https://github.com/mvt-project/mvt-indicators). The eight bundled
campaign sets are Pegasus, Predator, KingSpawn (QuaDream), Operation
Triangulation, RCS Lab, Wintego Helios, Coruna, and DarkSword.

The snapshots dated 2026-07-08 contain 2,887 extracted indicators. Of those, 148
are applicable to the process activity Trace observes: 83 process names, 15 file
names, and 50 canonical file paths. The RCS Lab and Wintego Helios snapshots
currently contribute no applicable process or file indicator, although their
non-applicable indicators remain visible in per-set accounting. Each report
records the actual counts and SHA-256 of every exact snapshot used, so report
values take precedence over these dated README totals.

Matching is deliberately narrow:

- STIX extraction accepts one fully anchored equality clause. Compound,
  qualified, malformed, or non-STIX patterns are rejected before extraction
  rather than partially matched; the raw-versus-extracted source accounting
  makes those rejections visible without presenting them as individual
  non-applicable indicators.
- Process and file names use exact, case-sensitive equality. This preserves
  distinctions such as the published `Diagnosticd` indicator versus Apple's
  legitimate `diagnosticd` process.
- File paths must be canonical absolute paths. Directory-valued indicators with
  a trailing slash match canonical descendants by prefix. Relative, dot-segment,
  or slash-bearing name indicators remain in totals but are not called
  checkable.
- File-name indicators are compared with observed process identities and
  executable basenames. File-path indicators are compared only with canonical
  observed executable paths. A sysdiagnose is not a filesystem inventory, so
  neither rule establishes that an arbitrary file exists on disk.

Most bundled indicators are domains, URLs, email addresses, hashes, or other
values that these surfaces cannot evaluate. Trace v1 neither parses iPhone
backups nor reconstructs unified-log message contents, so it does not attempt
domain or URL matching. Reports state this limit and never imply those values
were checked.

The official browser scanner matches only against its committed snapshots.
Live upstream data never reaches matching; optional upstream requests can
report only that different, plausible content exists and needs review. A hash
difference does not establish that content is newer or safer, and the
comparison does not gate scanner readiness. The browser refuses a bundled set
below its reviewed minimum, while CI requires every committed snapshot to match
the exact reviewed indicator/applicable counts and contain one malware object.
A scheduled workflow proposes upstream changes in a pull request each week; a
human still has to review the content before it ships. The native harness can
instead be given explicit STIX paths, and its report hashes the exact supplied
text.

## Honest epistemics

- **"No matches" is not "clean."** It means no known implant left a known
  trace in the artifacts that this scan successfully examined.
- Missing surface types can be normal, but they remain explicit in every report.
  `assurance.complete` describes processing of available input, not comprehensive
  device coverage.
- Trace has no real infected-device sysdiagnose in its validation corpus. The
  infected demo is synthetic from published patterns and a real published
  process-name indicator.
- A hit routes to [Access Now's Digital Security
  Helpline](https://www.accessnow.org/help/) and [Amnesty's Security
  Lab](https://securitylab.amnesty.org/get-help/), with evidence-preservation
  guidance. Every result shows the archive SHA-256 and offers the complete JSON
  report plus a self-contained HTML handoff with privacy redactions enabled by
  default.
- A sufficiently compromised device can lie in its own sysdiagnose. Detection
  is best effort beginning at evidence collection.
- [VALIDATION.md](VALIDATION.md) separates CI coverage, manual public-capture
  checks, private-capture checks, and remaining validation gaps.
- [HELPLINE.md](HELPLINE.md) explains responder interpretation and
  reproduction. [THREAT_MODEL.md](THREAT_MODEL.md) documents system and
  operational trust boundaries.

## Development

The pinned Rust toolchain, including `wasm32-unknown-unknown`, is declared in
`rust-toolchain.toml`. Local development also needs `wasm-pack` 0.14.0 and
Python 3. Deterministic fixture generation additionally needs `jq`, gzip, and a
compatible BSD tar/`bsdtar`, which the fixture script selects explicitly. macOS
provides BSD tar by default. Browser tests require Node.js; CI uses Node 22.
`cargo audit` additionally requires `cargo-audit`.

Build and serve the WASM application:

```sh
./build.sh
python3 -m http.server 8973 --directory web
```

Regenerate the tracked synthetic fixtures only when their source definition or
indicator seed changes:

```sh
./fixtures/make_fixtures.sh
```

After the build, `web/` contains the static application for local use. A release
deployment also needs a unique service-worker cache identity: the official
production workflow substitutes the commit SHA, while a manual deployment must
change `CACHE` in `web/sw.js` deliberately. The build script runs Rust tests but
is not the full release gate. The remaining local checks are:

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo audit

./fixtures/make_fixtures.sh
git diff --exit-code -- web/fixtures

cd e2e
npm ci
npx playwright install chromium firefox webkit
npm test
```

CI adds Playwright's `--with-deps` option on Linux and runs the WASM build in
separate jobs with the checked-out commit injected into the report metadata.

The native CLI harness uses the same engine as the browser:

```sh
cargo run --release --example scan -- \
  <sysdiagnose.tar.gz> web/iocs/*.stix2
```

Repository layout:

- `crates/trace-core/` - streaming archive reader, artifact parsers, indicator
  matching, findings, report assembly, and the single Rust-owned verdict.
- `web/report.schema.json` - report schema version 3. Browser worker, inline,
  and native producers emit the same envelope, enforced by Rust and browser
  golden-contract tests.
- `web/` - framework-free static site, worker, service worker, styles,
  snapshots, schema, and generated WASM package after a build.
- `e2e/` - Playwright coverage across Chromium, Firefox, and WebKit, including
  demo scans, report export, and limits. Cached offline scanning runs on
  Chromium and Firefox; Playwright WebKit cannot reliably emulate an offline
  service-worker navigation and is explicitly skipped for that case.
- `fixtures/make_fixtures.sh` - explicit deterministic synthetic-fixture
  generator. The infected fixture exercises a real Pegasus process-name
  indicator; CI verifies that regeneration is byte-for-byte reproducible.

## CI and deployment

CI runs formatting, clippy, Rust tests, `cargo audit`, fixture-reproducibility
verification, a WASM build, and the three-browser Playwright suite for every
pull request and every push to `main`.
The active production path is Cloudflare Pages at `tracescan.pages.dev`.
`.github/workflows/deploy-production.yml` deploys only a successful CI commit
that is still the tip of `main`, embeds that commit in `tool.build_commit`, and
verifies the service-worker marker, security headers, the deployed schema
byte-for-byte plus its identity/version, and demo fixture availability after
upload.

Production safety also depends on external settings that source code cannot
enforce. Operators must keep Cloudflare automatic production and preview builds
disabled, configure `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`, and keep
the repository variable `PRODUCTION_DEPLOY_REQUIRED=true`. These invariants and
the default-branch ruleset must be rechecked after account, repository, or Pages
project changes.

Cloudflare applies `web/_headers`; the meta CSP remains defense in depth for
hosts that cannot send headers. The retired GitHub Pages origin serves only the
redirect and service-worker kill switch in `redirect/`. As last verified on
2026-07-14, Cloudflare also injected `NEL`/`Report-To` headers for network
delivery failures. That edge telemetry does not contain scan contents, but it
means the fact of a visit or delivery failure is not purely local and should be
rechecked rather than treated as a permanent platform guarantee.

## Scope

Deliberate v1 non-goals are real-time monitoring, removal claims, Android,
iPhone-backup parsing, filesystem inventory, and unified-log message
reconstruction. See [docs/design-unified-logs.md](docs/design-unified-logs.md)
for the catalog-level trade-off.

## Acknowledgements and license

Trace builds on public research and data from Amnesty International's Security
Lab, the [Mobile Verification Toolkit](https://github.com/mvt-project/mvt),
Kaspersky's iShutdown research, Mandiant's unified-log parser, Citizen Lab, and
other indicator publishers. It is a triage interface to that ecosystem, not a
replacement for it.

Licensed under the [MIT License](LICENSE).
