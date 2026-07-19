# Validation status

Trace is used for decisions that matter. This document separates evidence that
runs on every change from manual compatibility checks and private-capture
receipts. Those categories are not interchangeable:

- **CI-tested** means an automated test runs in GitHub Actions on every pull
  request and push to `main`.
- **Public manual validation** means a named, hash-pinned external archive was
  scanned outside CI and can be obtained independently.
- **Private manual validation** means the ignored release harness was run by a
  maintainer against a private archive. The aggregate result is documented, but
  an outside reviewer cannot reproduce it without access to those bytes.

Report values are per-scan facts. Dated counts below describe the cited revision
and corpus; they are not a promise about every iOS version or future indicator
snapshot.

## Real-capture validation matrix

Privacy-preserving labels distinguish the three private captures without
publishing their filenames or device identifiers.

| Corpus | Access | Scanner revision and run date | Recorded result | Current qualification |
|---|---|---|---|---|
| Private capture A, iOS 26.5.2 | Maintainer only | v0.7.3, `c685cf6`, 2026-07-13 | 64 tracev3 files, 2,656 catalogs, 689 uuidtext files, and 617 of 617 process paths resolved; no match or suspicious finding | Historical v0.7.3 receipt; not an independently reproducible or population-level false-positive study |
| Private capture B, iOS 26.5.2 (23F84) | Maintainer only | v0.7.4 candidate beginning at `8ff0208`, 2026-07-17 | 62 tracev3 files, 4,402 catalogs, 754 uuidtext files, and 623 of 623 process paths resolved; all four primary surfaces complete, no scan limits, verdict `clear`, and no match or suspicious finding | Pre-final candidate receipt for one clean OS build, not an exact final-tree release gate; private bytes prevent independent reproduction |
| Private capture C, iOS 18.7.9 (22H355) | Maintainer only | v0.7.5 scanner tree at `f96bea8`, 2026-07-19 | All eight sets loaded at 2,887/89; two stacks inventories accepted the observed signed-PID and exact terminating-transition variants; 63 tracev3 files, 2,847 catalogs, and 598 uuidtext files parsed with zero failures; 499 of 499 process paths resolved; 11,465 PID samples retained and 11,272 observations dropped under the disclosed evidence-only sampling cap; all four primary surfaces complete, no scan limits, one informational transition-tombstone note, verdict `clear`, and no match or suspicious finding | v0.7.5 release-gate receipt for the exact scanner tree at `f96bea8`; the remaining v0.7.5 commits through `bf4dcf8` change only this receipt and production verification, not scanner code or assets. Later releases must not present it as an exact release-tree run. Private bytes prevent independent reproduction or independent archive-integrity review |
| EC-DIGIT-CSIRC iOS 15 capture | Public, hash-pinned below | v0.7.4 release-candidate tree based on `8ff0208`, 2026-07-17 | All supported artifacts parsed; 27 tracev3 files, 659 catalogs, and 426 uuidtext files parsed with zero failures; 341 of 341 process paths resolved; all eight sets loaded at 2,887/148; no scan limits, verdict `clear`, and no match or suspicious finding | Historical v0.7.4 public compatibility receipt; input bytes remain independently obtainable and hash-pinned, but this is not a current release-tree run |

The private harness reads one archive only from the explicit
`TRACE_REAL_SYSDIAGNOSE` path and is ignored by default:

```sh
TRACE_REAL_SYSDIAGNOSE=/controlled/path/sysdiagnose.tar.gz \
  cargo test --locked --release -p trace-core --test real_capture -- --ignored --nocapture
```

The same opt-in path can exercise the browser file-input, Worker, WASM, and UI
verdict pipeline once in Chromium:

```sh
TRACE_REAL_SYSDIAGNOSE=/controlled/path/sysdiagnose.tar.gz \
  npx playwright test --project=chromium --grep 'opt-in real capture'
```

Run the browser command from `e2e/` after `./build.sh`; the capture path is read
locally and is never committed by the test.

It loads all eight bundled indicator sets and requires all four primary surfaces,
no scan limits, no match or suspicious finding, and a `clear` verdict. A passing
run demonstrates compatibility with that archive; it does not establish that
the archive is truthful or representative.

## What CI validates

| Surface | Automated evidence |
|---|---|
| Archive streaming | Property tests over arbitrary bytes and chunking; unit tests for single and concatenated gzip members, tar streaming, PAX and GNU long names, canonical and undecodable paths, checksums, metadata ambiguity, truncation, end markers, retained-file limits, entry limits, and decompression limits |
| Unified logs | Unit tests for tracev3 framing, catalog-only parser isolation under hostile chunkset size declarations, catalog-count consistency, uuidtext structure and conflicts, canonical path resolution, unresolved processes, detection-relevant identity/path caps, and separately disclosed per-process and aggregate PID-evidence sampling while UUID/path IOC matching remains active; an engine-level regression requires PID-only sample saturation to remain complete and `clear` |
| Shutdown logs | Classic one-line and iOS 26 rotated/header-plus-client parsing; reboot-block boundaries; malformed delay blocks; binary-UUID suffix stripping; direct-child versus nested staging-path heuristics; the exact `roleaccountd.staging/exec/<number>.<number>.xpc/com.apple.NRD.UpdateBrainService` exception and rejection of other leaves, case variants, and deeper shapes |
| Crash and diagnostic `.ips` | Ordinary crash reports, kernel panics, disk-write diagnostics, Jetsam, stacks, forceReset, Siri feedback, ResetCounter, security analytics (`bug_type` 226), CPU resource (`202`), and proactive event tracker (`303`), including signed stack PIDs, the exact type-1 terminating tombstone policy, malformed/alternate rows, schema drift, and the fail-closed 10,000-candidate cap |
| Process listings | Real-format `ps.txt` and `ps_thread.txt`; commands containing spaces; wide and overflowing numeric columns; thread continuations; full-path command columns; iOS 26 `?` process state; malformed rows; valid header-only auxiliary listings |
| STIX extraction and matching | Fully anchored single-equality parsing; rejection of compound, qualified, malformed, and non-STIX patterns; exact case-sensitive names and alias-equivalent canonical paths; `/var`, `/tmp`, and `/etc` compatibility aliases; directory-prefix indicators; exact-positive matching for file indicators that do not establish negative process coverage; non-applicable relative, dot-segment, and slash-bearing name indicators; per-set duplicate-value reduction; exact ordered roster, per-set SHA-256 pins, reviewed counts, and one malware object per snapshot; hostile JSON properties |
| Verdict and report | Fail-closed invalid/inconclusive paths, anchored primary-phone surface classification, severity- and indicator-diversity-aware findings retention, process-bearing versus metadata-only surface accounting, producer parity, schema version 4 validation, engine-measured archive size, archive and indicator hashing, and golden field shape |
| Browser application | Playwright on Chromium, Firefox, and WebKit, including worker and inline producers, demo scans, rendering, accessibility flows, exports, scan limits, and service-worker behavior; cached offline scanning runs on Chromium and Firefox, while Playwright WebKit is skipped because it cannot reliably emulate offline service-worker navigation |

CI fixtures are synthetic. They exercise real parser and indicator paths, but
they are not evidence from an infected device.

## Supported and unsupported `.ips` locations

Phone reports under `crashes_and_spins/` are the primary crash/diagnostic
surface. Reports under `logs/ProxiedDevice*` come from a paired device, normally
an Apple Watch. Trace checks process identities and inventories only in formats
that contain them; metadata-only paired diagnostics provide no process evidence.
All paired reports are labeled as supplemental, do not provide phone device
metadata, and do not make the phone crash surface complete.

`logs/OTAUpdateLogs/*.ips` uses an undocumented restore/update text format, not
the supported crash-report schema. Trace does not parse its contents and lists
that scope under `coverage.not_examined`. Other `.ips` files outside the
recognized phone and paired-device locations are likewise not silently treated
as primary phone evidence.

## Public-capture compatibility validation

The public compatibility archive is EC-DIGIT-CSIRC's
[iOS 15 sysdiagnose](https://github.com/EC-DIGIT-CSIRC/sysdiagnose-testdata/blob/main/iOS15/sysdiagnose_2023.05.24_13-29-15-0700_iPhone-OS_iPhone_19H349.tar.gz):

- filename:
  `sysdiagnose_2023.05.24_13-29-15-0700_iPhone-OS_iPhone_19H349.tar.gz`;
- SHA-256:
  `4491d5e4b6f4349311df3b3fc671f1dd040c8ccda9f97e3a0debef151e613114`;
- externally hosted size: approximately 94 MB.

The historical v0.7.4 release-candidate run recorded:

- `ps.txt` and `ps_thread.txt` parsed completely, with 244 process rows each
  and no match or suspicious finding;
- all 11 recognized ancillary `.ips` diagnostics parsed completely. `stacks`
  and `forceReset` supplied process inventories, while `SiriSearchFeedback` and
  `ResetCounter` were treated as metadata-only rather than process identities;
- all 27 tracev3 files, 659 catalogs, and 426 uuidtext files parsed with zero
  failures, and all 341 processes resolved to paths; and
- the eight bundled sets loaded at 2,887 extracted and 148 applicable
  indicators, with verdict `clear`, no scan limits, and no match or suspicious
  finding.

The archive is intentionally not committed to this repository. The filename and
SHA-256 above bind this receipt to the independently obtainable public input;
the matrix records the source-tree basis and run date.

## Current reviewed applicability: 89 of 2,887

The snapshots dated 2026-07-08 contain 2,887 extracted indicators. Under the
v0.7.5 negative-coverage policy, 89 establish reviewed coverage for the
process-bearing evidence Trace observes:

| Applicable kind | Count | Matching rule |
|---|---:|---|
| Process name | 83 | Exact, case-sensitive observed basename |
| File name | 0 | File names remain exact-positive matchable but do not establish negative process-scan coverage |
| Reviewed process-image file path | 6 | Exact, case-sensitive canonical executable path after resolving `/var`, `/tmp`, and `/etc` to `/private/...` for comparison, or a descendant of a reviewed trailing-slash process-image path |
| **Total** | **89** | Coverage available to support a no-match process scan |

The reviewed per-set accounting is:

| Indicator set | Extracted | Applicable to negative process coverage |
|---|---:|---:|
| Pegasus | 1,549 | 81 |
| Predator | 585 | 4 |
| KingSpawn (QuaDream) | 167 | 3 |
| Operation Triangulation | 112 | 1 |
| RCS Lab | 40 | 0 |
| Wintego Helios | 175 | 0 |
| Coruna | 216 | 0 |
| DarkSword | 43 | 0 |
| **Total** | **2,887** | **89** |

The six reviewed process-image path values are:

- Predator: `/private/var/tmp/hooker`,
  `/private/var/tmp/com.apple.WebKit.Networking`,
  `/private/var/tmp/UserEventAgent`, and `/private/var/tmp/takePhoto`;
- KingSpawn: `/private/var/db/com.apple.xpc.roleaccountd.staging/subridged`
  and
  `/private/var/db/com.apple.xpc.roleaccountd.staging/PlugIns/fud.appex/`.

All four primary surfaces enumerate **process activity**. There is no complete
filesystem listing in a sysdiagnose. Safe file-name indicators can still match
an observed process identity or executable basename, and safe file-path
indicators can still match a canonical observed executable path. Those exact
positive matches remain reportable even when the indicator is not in the
reviewed negative-coverage allowlist. The well-known Apple `/var`, `/tmp`, and
`/etc` aliases resolve to `/private/...` only for comparison; reports retain the
raw observed path and published indicator. A plist, database, directory, or
lock-file indicator does not prove file presence and must not inflate what a
no-match scan claims to have checked.

The STIX parser accepts exactly one fully anchored equality clause. It never
turns one side of `AND`, `OR`, `FOLLOWEDBY`, a qualifier, a comment, or malformed
trailing text into a match. Relative paths, paths with dot segments or empty
components, and slash-bearing name indicators remain in extraction accounting
but are not counted as applicable. Per-report `indicator_sets` and
`indicator_provenance` are the authority when snapshots change.

Most of the remaining indicators are domains, URLs, emails, hashes, or other
values these process-oriented surfaces cannot evaluate. Trace neither parses
iPhone backups nor reconstructs unified-log messages, so it does not claim to
have checked those values merely because they were loaded.

## What has not been validated

- **No broad false-positive study.** Two private iOS 26.5.2 captures, one private
  iOS 18.7.9 capture, one public iOS 15 capture, and synthetic fixtures cannot estimate a false-positive rate
  across devices, regions, configurations, and iOS versions.
- **No real infected-device ground truth.** No infected sysdiagnose is included
  in or linked from this validation corpus as of 2026-07-19. Kaspersky published
  iShutdown patterns rather than a raw infected sysdiagnose; MVT's published
  test artifacts and the EC-DIGIT-CSIRC capture do not provide infected-device
  ground truth. The demo is synthetic from published patterns and a real
  published process-name indicator.
- **No phone-only browser validation.** The supported user workflow transfers
  the archive to a computer.
- **No proof of deployed-binary reproducibility.** CI and reports identify the
  source commit, but the repository does not publish a third-party-checkable
  byte-for-byte attestation for the production WASM.
- **No guarantee against an adversarial device.** A compromised phone can omit
  or falsify diagnostics before Trace receives and hashes the archive.

Wider privacy-reviewed clean captures and responsibly shared infected artifacts
remain the most valuable validation contributions. Contact should begin through
the private process in [SECURITY.md](SECURITY.md), not a public issue containing
case data.

## Historical differential comparison with MVT

On 2026-07-08, Trace v0.5.0 and MVT 2026.5.12 were run over the same private iOS
26.5.2 capture. MVT did not ingest the sysdiagnose archive as a whole, so its
`ShutdownLog` parser was driven directly against `shutdown.0.log`, the one
artifact class both tools read in that comparison.

| Metric | Trace | MVT | Agreement |
|---|---:|---:|---|
| Client records parsed | 2,279 | 2,279 | Exact |
| Unique clients after UUID-suffix removal | 72 | 72 | Path sets byte-identical |
| Shutdown events | 50 reboot blocks | 50 SIGTERM markers | Consistent |
| Indicator alerts | 0 of 2,887 loaded indicators | 0 of 11,254 in the full MVT collection | Agree |

The dated comparison observed two MVT 2026.5.12 limitations relevant to that
capture: its filesystem module glob did not include rotated `shutdown.0.log`,
and its parser did not remove the iOS 26 trailing binary-UUID path component.
The second behavior could affect full `file:path` matching even though
per-component process-name matching compensated for name indicators.

This repository does not currently link an upstream MVT issue or pull request
for either observation. Filing and linking those reports remains an external
follow-up, not evidence that Trace's broader methodology has been independently
validated against MVT.

A tool validated against published patterns can still miss what was never
published. That limit is inherent to public threat intelligence and is disclosed
in every result.
