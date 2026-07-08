# Validation status

Trace is used by people making decisions that matter, so this file states
plainly what each detection surface has been validated against, and what has
not been validated because the necessary data is not public. "Tested" below
always means an automated test that runs in CI.

## What the pipeline is validated against

| Surface | Evidence |
|---|---|
| Archive streaming (gzip/tar, PAX, GNU long names, caps) | Property tests over arbitrary bytes and chunkings; unit tests for PAX paths, caps, truncation, end-of-archive handling; a real iOS 26.5.2 sysdiagnose parsed end to end |
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
- **No differential run against MVT on the same capture.** Planned: run
  Trace and MVT over the same real sysdiagnose and compare findings. Needs a
  real capture, which is personal data and therefore not committed to this
  repository.

A "validated against published patterns" tool can still miss what was never
published. That limit is inherent to public threat intelligence and is
disclosed in the app itself.
