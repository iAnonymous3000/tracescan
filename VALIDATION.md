# Validation status

Trace is used by people making decisions that matter, so this file states
plainly what each detection surface has been validated against, and what has
not been validated because the necessary data is not public. "Tested" below
always means an automated test that runs in CI.

## What the pipeline is validated against

| Surface | Evidence |
|---|---|
| Archive streaming (gzip/tar, PAX, GNU long names, caps) | Property tests over arbitrary bytes and chunkings; unit tests for PAX paths, caps, truncation, end-of-archive handling; a real iOS 26.5.2 sysdiagnose parsed end to end |
| Unified logs (tracev3 catalog inventory) | Validated against a real iOS 26.5.2 capture: 64 tracev3 files (2,656 catalogs) and 689 uuidtext files parsed with zero failures; 617 of 617 processes resolved to binary paths; zero false positives from indicators or path heuristics across the full log window. Format parsing is delegated to Mandiant's upstream-tested `macos-unifiedlogs`. Repeatable locally: `TRACE_REAL_SYSDIAGNOSE=… cargo test --release --test real_capture -- --ignored` |
| shutdown.log format handling | Both real-world formats verified against a real iOS 26.5.2 capture (rotated `shutdown.N.log`, header plus indented clients, trailing binary-UUID path component) and the classic one-line format from published research |
| Pegasus shutdown.log technique | Pattern published by Kaspersky (iShutdown, Jan 2024): processes running from `/private/var/db/com.apple.xpc.roleaccountd.staging/`. Unit tests and the demo fixture seed a real published Pegasus process-name indicator through this path |
| Crash log and ps.txt parsing | Unit tests over real-format samples, including kernel panics (`panicString`), hyphenated process names, and commands containing spaces |
| STIX2 extraction | Validated against all eight bundled real indicator files (2,887 indicators); AND/FOLLOWEDBY patterns are skipped, never half-matched; property tests over hostile JSON |
| End-to-end, real browser | Playwright suite on Chromium, Firefox, and WebKit, including offline operation and report export |

## What has NOT been validated, and why

- **No scan of a real infected device.** No real spyware-infected sysdiagnose
  (or shutdown.log) is public anywhere we could find: Kaspersky published
  tooling and excerpt patterns, not raw logs; MVT's test artifacts are a
  clean iOS backup; EC-DIGIT-CSIRC's sysdiagnose test data is private. The
  infected demo fixture is synthetic, built to the published patterns and
  seeded with a real published indicator. If you are a researcher holding
  real infected artifacts and can share them (even hashed or redacted),
  please open contact via SECURITY.md.

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
