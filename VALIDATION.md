# Validation status

Trace is used by people making decisions that matter, so this file states
plainly what each detection surface has been validated against, and what has
not been validated because the necessary data is not public. "Tested" below
always means an automated test that runs in CI.

The real-capture measurements below were reproduced with the Trace v0.7.3 tree
on 2026-07-13: two private iOS 26.5.2 captures and EC-DIGIT-CSIRC's public
iOS 15 capture. The private archives never enter the repository; the ignored
release harness reads them only from an explicit local path.

## What the pipeline is validated against

| Surface | Evidence |
|---|---|
| Archive streaming (gzip/tar, PAX, GNU long names, caps) | Property tests over arbitrary bytes and chunkings; unit tests for PAX paths, caps, truncation, end-of-archive handling; two private iOS 26.5.2 sysdiagnoses and one public iOS 15 sysdiagnose parsed end to end |
| Unified logs (tracev3 catalog inventory) | On the two iOS 26.5.2 captures: 64 tracev3 files / 2,656 catalogs / 689 uuidtext files / 617 processes, and 62 / 4,402 / 754 / 623 respectively; every file parsed, every process resolved to a binary path, and no indicator or suspicious heuristic fired. The public iOS 15 capture likewise parsed 27 tracev3 files with 341 of 341 paths resolved. Format parsing is delegated to Mandiant's upstream-tested `macos-unifiedlogs`. Repeatable locally with all eight bundled indicator sets loaded: `TRACE_REAL_SYSDIAGNOSE=… cargo test --release --test real_capture -- --ignored` |
| shutdown.log format handling | Both real-world formats verified against a real iOS 26.5.2 capture (rotated `shutdown.N.log`, header plus indented clients, trailing binary-UUID path component) and the classic one-line format from published research |
| Pegasus shutdown.log technique | [Kaspersky's iShutdown research](https://securelist.com/shutdown-log-lightweight-ios-malware-detection-method/111734/) published direct-child processes under `/private/var/db/com.apple.xpc.roleaccountd.staging/`. Unit tests and the demo fixture seed a published Pegasus process-name indicator through that shape; a legitimate nested iOS `exec/<id>.xpc/…` workspace is explicitly not elevated to suspicious |
| Crash and diagnostic `.ips` parsing | Unit tests cover ordinary crashes, kernel panics, disk-write reports, Jetsam, stacks, forceReset, Siri feedback, and ResetCounter, including malformed-row and schema-drift failures. All `.ips` files in the three real captures parse completely; process-bearing formats contribute every validated identity, while metadata-only formats contribute none |
| Process listings | Real-format `ps.txt`/`ps_thread.txt` tests cover commands containing spaces, wide PIDs, thread-continuation rows, the final full-path command column, malformed rows, and iOS 26's valid header-only auxiliary listing |
| STIX2 extraction | Validated against all eight bundled real indicator files (2,887 indicators); AND/FOLLOWEDBY patterns are skipped, never half-matched; property tests over hostile JSON |
| End-to-end, real browser | Playwright suite on Chromium, Firefox, and WebKit, including offline operation and report export |

## Public-capture compatibility validation (2026-07-13)

The v0.7.3 tree was also run against EC-DIGIT-CSIRC's
[public iOS 15 sysdiagnose capture](https://github.com/EC-DIGIT-CSIRC/sysdiagnose-testdata/blob/main/iOS15/sysdiagnose_2023.05.24_13-29-15-0700_iPhone-OS_iPhone_19H349.tar.gz)
(`sysdiagnose_2023.05.24_13-29-15-0700_iPhone-OS_iPhone_19H349.tar.gz`,
SHA-256 `4491d5e4b6f4349311df3b3fc671f1dd040c8ccda9f97e3a0debef151e613114`).
This is a repeatable manual compatibility test rather than a CI fixture because
the 94 MB archive is externally hosted.

- `ps.txt` and `ps_thread.txt` both parsed completely, with 244 process rows
  each and no indicator or suspicious findings.
- All 11 ancillary `.ips` diagnostics parsed completely. `stacks` and
  `forceReset` process inventories were checked; `SiriSearchFeedback` and
  `ResetCounter` were recognized as metadata-only without treating their
  labels as process identities.
- All 27 tracev3 files parsed with zero failures, and 341 of 341 processes
  resolved to paths. With all eight bundled indicator sets loaded, the overall
  verdict was `clear` with zero match or suspicious findings.

## What "148 checkable indicators" means precisely

The applicable indicators are process names (83), file names (15), and file
paths (50). All four surfaces enumerate **process activity** - there is no
filesystem listing in a sysdiagnose - so file name and path indicators are
checked against the paths processes were observed running from, not against
file presence on disk. A plist, database, or lock-file indicator therefore
only matches if something executed from that path. The UI and every report
state this; the number is a ceiling on what can match, not a count of files
examined.

## What has NOT been validated, and why

- **No broad false-positive study across devices and OS versions.** The clean
  validation corpus is two private iOS 26.5.2 captures and one public iOS 15
  capture, plus synthetic fixtures. That is enough to reproduce these parser
  and heuristic results, not to estimate false-positive rates across the iOS
  population. Wider privacy-reviewed clean captures remain the highest-value
  contribution a tester can make.

- **No scan of a real infected device.** No real spyware-infected sysdiagnose
  (or shutdown.log) is public anywhere we could find: Kaspersky published
  tooling and excerpt patterns, not raw logs; MVT's test artifacts are a
  clean iOS backup; EC-DIGIT-CSIRC's public sysdiagnose test capture has no
  infected-device ground truth. The infected demo fixture is synthetic,
  built to the published patterns and seeded with a real published indicator.
  If you are a researcher holding real infected artifacts and can share them
  (even hashed or redacted), please open contact via SECURITY.md.

## Differential comparison against MVT (2026-07-08)

Trace v0.5.0 and MVT 2026.5.12 were run over the same real iOS 26.5.2
capture. MVT cannot ingest a sysdiagnose archive (its filesystem modules
target full filesystem dumps), so its `ShutdownLog` parser was driven
directly against the capture's `shutdown.0.log` - the one artifact class
both tools read:

| Metric | Trace | MVT | Agreement |
|---|---|---|---|
| Client records parsed | 2,279 | 2,279 | exact |
| Unique clients (UUID-stripped) | 72 | 72 | path sets byte-identical |
| Shutdown events | 50 reboot blocks | 50 SIGTERM markers | consistent |
| Indicator alerts | 0 (2,887 indicators) | 0 (11,254 indicators, full MVT collection) | agree |

Two MVT-side gaps surfaced during the comparison, both relevant to iOS 26
captures: its module globs only `private/var/db/diagnostics/shutdown.log`
(the rotated `shutdown.0.log` name would not be found even in a filesystem
dump), and it does not strip the iOS 26 trailing binary-UUID path component
(its per-component process matching compensates for process-name
indicators, but `file:path` indicators would not match). Both are worth
reporting upstream.

A "validated against published patterns" tool can still miss what was never
published. That limit is inherent to public threat intelligence and is
disclosed in the app itself.
