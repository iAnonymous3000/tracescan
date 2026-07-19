# Trace responder guide

This is the canonical, repository-controlled guidance for a responder who
receives a Trace JSON report and, when appropriate, the corresponding iPhone
sysdiagnose archive. It is written so the same content can later be rendered as
a static responder page without weakening its caveats.

This guide applies only to Trace report schema version 4. For any other
`schema_version`, do not extrapolate these instructions. Resolve the claimed
source revision, inspect its checked-in schema, source, and changelog in an
isolated review environment, and seek technical review.

## Five-minute verification checklist

1. **Consider the person's immediate safety first.** A visit to the Trace site,
   creation of a sysdiagnose, transfer of a large file, browser history, and a
   downloaded report can all be observable. If another person may control the
   phone, network, computer, Apple account, or cloud storage, agree on a safer
   device and transfer route before asking for another capture.
2. **Preserve what was received.** Keep the original JSON report and archive
   unchanged. Work from copies. Do not unzip, rename and repackage, edit, or
   “clean up” the archive.
3. **Record two SHA-256 hashes at intake.** Hash the JSON report and the archive,
   and put both values in the case record. The report hash fingerprints the
   report as received. It is not stored inside the report and is not a
   signature.
4. **Compare the claimed archive identity.** Independently hash the archive. The
   result must exactly equal `source_file.sha256` in the JSON report. A mismatch
   means the report describes different bytes; stop and resolve it. A match
   shows only that the supplied archive matches the hash value currently written
   in the unsigned report, not that Trace actually scanned those bytes.
5. **Read the result with its limits.** Check `verdict`, `scan_limits`,
   `assurance`, `missing_artifacts`, and `coverage` together. In particular,
   `clear` never means that the phone is clean, and `assurance.complete` does
   not mean every possible evidence source was present or examined.
6. **Re-scan safely for consequential decisions.** Treat `tool.build_commit` as
   an unsigned, untrusted claim. Accept it only when it is exactly 40 lowercase
   hexadecimal characters and exists in the public repository. Review and build
   that revision only in a disposable environment with no credentials, host
   mounts, or case data. Build before introducing the archive, disconnect the
   environment, scan a copy, and destroy the environment afterward. Never build
   report-selected source on the casework host. If the commit is `null`, exact
   reproduction is impossible; compare with a separately trusted release and
   document the weaker provenance.
7. **Escalate discrepancies.** A hash mismatch, unexplained version/commit
   relationship, changed indicator hashes, materially different re-scan, or
   report that does not validate against the schema is a provenance problem.
   Preserve both copies and seek technical review; do not silently choose the
   more reassuring result.

## What Trace is

Trace is an open-source, browser-based scanner for an iPhone sysdiagnose. Its
Rust/WebAssembly engine streams the archive, reads a limited set of diagnostic
artifacts, and compares observed process names and paths with reviewed snapshots
of published mercenary-spyware indicators. The current browser architecture has
no upload endpoint: archive parsing, matching, verdict generation, and report
assembly happen in the browser tab.

The browser can make ordinary requests to load the site and its reviewed
indicator snapshots, and it may compare them with public upstream indicator
URLs. That advisory check can detect different plausible content; it cannot
establish that the content is newer, safer, or appropriate to ship. Live
upstream content does not enter matching. The archive and scan result are not
intentionally sent in those requests. This privacy property still depends on
the browser receiving the intended Trace code; a compromised host, service
worker, browser, extension, or device can invalidate it.

Trace is **not**:

- proof that a device is clean, compromised, or attributable to a particular
  operator;
- a full forensic examination, evidence-acquisition system, or chain-of-custody
  product;
- a removal, remediation, real-time monitoring, Android, or iPhone-backup tool;
- able to detect unpublished spyware or evidence absent from the sysdiagnose;
- a substitute for a responder's threat assessment or specialist examination.

The repository does not currently establish the operator's legal identity,
funding, governance, or continuity plan. This guide does not infer or supply
those facts. An organization evaluating Trace should verify them separately.
The repository also does not currently provide a published independent audit
or a procedure proving that deployed WebAssembly is byte-for-byte reproducible
from source.

## Which report file to use

The JSON export is the canonical technical record. It carries the complete
schema-versioned envelope and is the input for validation and semantic
reproduction. The responder-readable HTML export is a convenience copy derived
locally from that same envelope. It is designed for printing and review, and it
leaves the source filename, device metadata, raw finding-evidence objects, and
dedicated source-artifact fields out unless the person preparing it opts in.
It always retains the verdict, finding summaries, archive hash, coverage,
limits, and indicator provenance. Finding summaries can themselves name
processes or paths relevant to the result, so the default is data minimization,
not anonymization.

When a report contains more than 200 findings, the readable copy shows the
first 200 in engine severity order and says how many remain; the JSON retains
the full report list, subject to the engine's 5,000-finding safety cap. Hitting
that cap is disclosed in `scan_limits`. The readable copy separately shows at
most 200 artifacts and states how many were omitted; the JSON retains the full
artifact inventory that the engine retained. Both formats are unsigned and
editable. For a consistency check or consequential decision, request the JSON
and, when it is safe and necessary, the original archive. Do not treat the
readable HTML alone as an authenticated or complete forensic record.

## Verdict semantics

The Rust engine decides the verdict. The browser displays that value rather
than deriving a new one from the findings. Verdict precedence matters: an
indicator match or suspicious finding remains visible even when another part
of the scan was incomplete.

| Verdict | Exact meaning | Responder action |
| --- | --- | --- |
| `match` | At least one observed process identity, executable basename, or canonical executable path matched a published indicator loaded for this scan. Names use exact, case-sensitive equality. Full file paths use exact, case-sensitive equality after treating Apple's `/var`, `/tmp`, and `/etc` aliases as equivalent to `/private/...`; a trailing-slash directory path matches descendants under the same comparison. Raw observed paths and published IOC values remain unchanged in evidence. A match can coexist with `scan_limits`; it is a serious signal, not final proof of compromise or attribution. | Preserve the phone, archive, and report; avoid wiping or updating the phone; review the matched indicator and provenance; escalate to a digital-security specialist. |
| `suspicious` | No published-indicator match was found, but at least one anomaly documented in public spyware research was found. It can have a benign cause and can coexist with an incomplete scan. | Review the evidence in context. Escalate when the person's risk, other observations, or scan limits warrant it. |
| `clear` | At least one primary process-bearing iPhone detection surface was examined; every **present** supported artifact parsed without a verdict-relevant limit; process-observable indicators accepted by this build's negative-coverage policy were loaded; and no indicator-match or suspicious finding was found. Paired-only or metadata-only diagnostics cannot satisfy the primary-surface prerequisite. Informational `note` findings and disclosed evidence-sampling limits may remain, and other supported surface types can still be absent. The official browser additionally requires its reviewed, hash-pinned roster before scanning. | Treat it only as “no known traces in the artifacts examined.” Check missing surfaces and threat context before deciding whether to close or escalate. |
| `inconclusive` | No match or suspicious finding was found, but parsing failed or was partial, a safety cap that could hide detection evidence was hit, the archive was truncated or corrupt, or no process-observable indicators accepted by this build's negative-coverage policy were loaded. | Read every `scan_limits` entry. Preserve the failed input, try one fresh capture when safe, and escalate if the problem repeats or risk is high. |
| `invalid` | The input contained none of the supported artifacts needed to recognize it as a sysdiagnose. | Confirm that the correct, unmodified `sysdiagnose_….tar.gz` was selected. Do not describe this as a negative scan. |

`assurance.complete` means that the recognizable input was processed without a
recorded parser or verdict-relevant resource-limit failure. It is a processing
statement, not a coverage statement. A report can have
`assurance.complete: true` while bounded evidence samples were truncated or one
or more entries in `assurance.surfaces` are `absent`. Use
`assurance.surfaces`, `missing_artifacts`, and `coverage` to understand what was
actually available.

For unified logs, `identity_cap_hit` (and its legacy alias `cap_hit`) means a
matchable UUID or path may have been lost and is verdict-relevant.
`pid_retention_cap_hit` with `pid_observations_dropped` means only that bounded
PID evidence samples were shortened after their UUID/path identities were
retained; it does not by itself make the scan inconclusive.

Stackshot diagnostics can contain an Apple type-1 transition tombstone whose
process name is empty and whose threads are all terminating. Trace accepts only
the exact validated tombstone shape, records the count as
`unidentified_transitional_processes`, and emits a visible informational note;
it does not invent or IOC-match an identity. Other blank rows remain partial,
and an inventory containing only transition tombstones cannot satisfy the
primary process-bearing prerequisite for `clear`.

Finding severities are similarly descriptive:

- `match` is a published-indicator match under the name/path rules above;
- `suspicious` is a research-documented anomaly, not an indicator match;
- `note` is context that is often benign and does not by itself control the
  verdict.

## What was checked

The report's `coverage.examined` list is the engine-generated declaration for
that individual scan. Because a received report is unsigned and editable,
confirm it through reproduction before consequential use. Trace currently
knows how to examine four primary iPhone sysdiagnose surfaces:

| Surface | What Trace derives from it |
| --- | --- |
| `shutdown.log` and rotated `shutdown.N.log` files | Processes that delayed shutdown across recorded reboot events |
| `crashes_and_spins/*.ips` | Target process names and paths, and process inventories in diagnostic formats that contain them |
| `ps.txt` and `ps_thread.txt` | Processes running at capture time |
| `system_logs.logarchive` tracev3 and uuidtext files | Process identities represented in successfully parsed catalog data and resolved through uuidtext; Trace derives no precise log window or event timestamps, and message contents are not read |

Trace also scans crash and diagnostic reports under
`logs/ProxiedDevice*/*.ips` as supplemental paired-device evidence. A report
labels these artifacts with `details.paired_device: true` and identifies them
separately in `coverage.examined`. They may describe an Apple Watch or another
paired device. Only formats containing process identities or inventories
contribute process evidence; metadata-only reports do not. Paired reports do not
supply the iPhone's device metadata, do not count as the iPhone crash-report
surface, and must not be interpreted as phone coverage.

Files under `logs/OTAUpdateLogs/*.ips` are different. They use an undocumented
update or restore text format, not the crash-report schema, so Trace does not
parse or match their contents. The report always discloses that exclusion in
`coverage.not_examined`; their presence must never be described as checked
evidence.

The report's `stats.applicable_indicators` is the number of loaded
process-observable indicators accepted by that build's negative-coverage
policy for a no-match process scan. In the official browser's current reviewed,
hash-pinned snapshots that means 89 total: 83 process names and six reviewed
process-image paths, not every syntactically safe file indicator. A native or
custom report binds supplied indicator text by hash but does not attest that the
source or its policy was reviewed.
File-name indicators can still match observed process identities or executable
basenames, and file-path indicators can still match canonical observed
executable paths, resolving the well-known Apple `/var`, `/tmp`, and `/etc`
aliases to `/private/...` for comparison and using descendant matching for a
trailing-slash directory indicator. Such an exact positive match remains a
`match` even when that indicator is not counted as applicable; a sysdiagnose
does not provide a complete filesystem inventory, so it cannot establish the
corresponding negative coverage.

Trace does not currently examine, among other things:

- arbitrary filesystem presence;
- unified-log message contents;
- Safari history;
- SMS or iMessage link payloads;
- per-process network-usage databases;
- installed-app or configuration-profile inventories;
- most domain, URL, email, and other network indicators that live in iPhone
  backup artifacts.

The exact list for a report is in `coverage.not_examined`. Public indicators
also have an unavoidable publication and review delay. A sufficiently
compromised phone can omit or falsify its own diagnostic data.

## Preserve evidence and protect the person

- Do not factory-reset, wipe, update, or otherwise modify the phone solely in
  response to a Trace result before a specialist has advised on safety and
  evidence needs.
- Keep the original archive and report read-only where practicable. Make a
  working copy, record who received it and when, and record SHA-256 hashes for
  every retained copy.
- A sysdiagnose can contain much more sensitive device information than Trace
  reads. Do not send it through ordinary email, public issue trackers, online
  JSON validators, or general-purpose file-sharing services. Use the receiving
  organization's approved confidential channel and minimize access and
  retention.
- The JSON report does **not** contain the archive, but it can include the
  device OS version, diagnostic paths and timestamps, observed process names or
  paths, finding evidence, and indicator matches. Treat it as sensitive case
  data.
- Visiting the site can leave DNS, network, hosting-edge, browser-history,
  download-history, recent-file, and local-storage traces. Loading the app and
  then scanning offline prevents scan-time network requests by the intended
  code, but the initial visit remains observable.
- Capturing a sysdiagnose occurs on the phone under investigation. A capable
  adversary on that phone may observe the capture, suppress or falsify data, or
  notice the resulting file.
- The documented Windows transfer path can place the archive in iCloud Drive
  and create Apple-account activity. If the account or a synchronized device
  may be monitored, do not assume that route is safe; choose a transfer plan
  with the person and, when needed, a specialist.
- On a shared computer, private-browsing mode does not erase downloaded files,
  operating-system recent-file records, cloud synchronization, endpoint
  monitoring, or network logs. Do not promise that a “private” window leaves no
  trace.

## Technical verification

### 1. Hash the received files

Use the exact files as received. Examples:

macOS:

```sh
shasum -a 256 "trace-report-2026-07-14.json"
shasum -a 256 "sysdiagnose_….tar.gz"
```

Linux:

```sh
sha256sum -- "trace-report-2026-07-14.json"
sha256sum -- "sysdiagnose_….tar.gz"
```

Windows PowerShell:

```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath '.\trace-report-2026-07-14.json'
Get-FileHash -Algorithm SHA256 -LiteralPath '.\sysdiagnose_….tar.gz'
```

Record both results outside the two files. Extract the archive hash claimed by
the report with either:

```sh
jq -r '.source_file.sha256' trace-report-2026-07-14.json
```

```powershell
(Get-Content -Raw -LiteralPath '.\trace-report-2026-07-14.json' |
  ConvertFrom-Json).source_file.sha256
```

The independently calculated archive hash and `source_file.sha256` must be the
same 64 hexadecimal characters. Windows commonly displays SHA-256 in uppercase;
normalize both values to one case or compare them case-insensitively.
`source_file.name` is descriptive metadata supplied by the report producer.
`source_file.size` and `source_file.sha256` are calculated by the engine over
the archive bytes it actually receives and parses. As with every field in an
unsigned report, a responder should confirm both by hashing and measuring the
preserved archive independently.

### 2. Inspect the identity claims without executing them

Read the relevant fields as data:

```sh
jq '{schema_version, tool, source_file, verdict,
     scan_limits, assurance, missing_artifacts, coverage,
     indicator_provenance}' trace-report-2026-07-14.json
```

The following local check rejects a build value that is not `null` or exactly
40 lowercase hexadecimal characters. It prints the value; it never evaluates
report text as a shell command:

```sh
python3 - <<'PY'
import json, re

with open("trace-report-2026-07-14.json", encoding="utf-8") as handle:
    report = json.load(handle)

if report.get("schema_version") != 4:
    raise SystemExit("This guide supports schema version 4 only")
if report.get("tool", {}).get("name") != "Trace":
    raise SystemExit("Unexpected tool name")

commit = report.get("tool", {}).get("build_commit")
if commit is not None and not re.fullmatch(r"[0-9a-f]{40}", commit):
    raise SystemExit("Invalid build_commit claim")
print(commit or "NO_EXACT_BUILD_COMMIT")
PY
```

- A valid-looking `tool.build_commit` is still an unsigned claim until it is
  resolved and reviewed in the public repository. The official build path
  injects its checked-out commit, but custom builds and edited reports can claim
  anything.
- A `null` commit means only that an exact revision was not recorded. It does
  not prove that the build was local, dirty, clean, official, or safe.
- `tool.version` is descriptive context, not a safe shell value and not an
  exact build identity. Never paste a raw report value into a shell command.
- Each `indicator_provenance[].sha256` claims the exact loaded indicator text
  used. Establish that it was the reviewed snapshot by resolving the claimed
  source revision and comparing hashes; a custom producer can load different
  STIX. `indicator_provenance[].upstream` is only an advisory upstream-
  comparison observation; it does not prove recency and does not affect
  matching.

### 3. Resolve the claimed revision and its pinned schema

Do this in a disposable review workspace with no case files or credentials.
Cloning does not make a revision trustworthy, and building Rust source can run
build scripts and procedural macros, so inspect the revision and its dependency
changes before executing it.

```sh
git clone https://github.com/iAnonymous3000/tracescan.git
cd tracescan
git fetch --tags --force

printf 'Type the already validated 40-lowercase-hex commit: '
IFS= read -r commit
case "$commit" in
  *[!0-9a-f]*|'') echo "invalid commit" >&2; exit 1 ;;
esac
[ "${#commit}" -eq 40 ] || { echo "invalid commit length" >&2; exit 1; }

git cat-file -e "${commit}^{commit}"
git tag --points-at "$commit"
git show "${commit}:crates/trace-core/Cargo.toml" | sed -n 's/^version = //p'

if git cat-file -e "${commit}:web/report.schema.json" 2>/dev/null; then
  schema_path=web/report.schema.json
elif git cat-file -e "${commit}:docs/report.schema.json" 2>/dev/null; then
  schema_path=docs/report.schema.json
else
  echo "the claimed revision has no known schema-v4 contract path" >&2
  exit 1
fi
git show "${commit}:${schema_path}" > ../report.schema.pinned.json
jq '{id: .["$id"], schema_version: .properties.schema_version.const}' \
  ../report.schema.pinned.json
```

Type only the commit that passed the local validation in step 2; do not paste a
raw field from an uninspected report. Compare the declared package version with
the report as data and record whether a tag points at the commit. An untagged
recorded build commit is possible and does not by itself prove tampering.

Schema v3 lived under `docs/` in v0.7.0 and moved to `web/` in v0.7.1, so the
fixed fallback above is intentional. The extracted file is written outside the
checkout to keep the build tree clean. Validate the report locally, using a JSON
Schema Draft 2020-12 implementation and that `report.schema.pinned.json`. Do not
upload a sensitive report to a public validator. The live schema identifier
<https://tracescan.pages.dev/report.schema.json> should resolve, but its current
contents are not the trust root for an older report. Schema validation proves
only structure and basic value constraints, not origin, truth, or absence of
editing.

If `tool.build_commit` is `null`, exact source identity cannot be recovered from
the report. Select a release through a separately trusted repository review,
inspect its checked-in schema, and document that any scan is only a comparison
against that release. Do not construct a shell command from the report's version
string.

### 4. Re-scan in an isolated, disposable environment

Do not build report-selected source or introduce an untrusted archive on the
casework host. Use a disposable virtual machine or equivalent environment with
no credentials, host mounts, synchronized folders, or unrelated case data:

1. While the archive is absent, review the resolved revision and build it with
   the network access needed for dependencies. A build executes untrusted code.
2. Start Trace from that clean checkout in a fresh browser profile, or clear all
   site data for the local origin so an older service worker cannot supply
   cached files.
3. Let the reviewed indicator snapshots load, then disconnect the environment
   from the network.
4. Introduce only a working copy of the archive through a controlled read-only
   transfer. Recalculate its SHA-256 inside the environment before scanning.
5. Export the new JSON report, remove the archive copy, and destroy or clear the
   disposable environment according to case policy.

After the revision has been reviewed, these commands run **inside that
disposable environment**:

```sh
printf 'Type the already validated 40-lowercase-hex commit again: '
IFS= read -r commit
case "$commit" in
  *[!0-9a-f]*|'') echo "invalid commit" >&2; exit 1 ;;
esac
[ "${#commit}" -eq 40 ] || { echo "invalid commit length" >&2; exit 1; }
git cat-file -e "${commit}^{commit}"

git switch --detach "$commit"
test -z "$(git status --porcelain)"
./build.sh
python3 -m http.server 8973 --directory web
```

Follow the prerequisites in [`README.md`](README.md). Open
<http://127.0.0.1:8973/> in the fresh browser profile, then follow the isolation
sequence above. This is a semantic reproduction of the scanner result. It does
not prove that locally built WebAssembly is byte-for-byte identical to the file
served when the original scan ran. With no valid recorded commit, exact
reproduction is impossible.

### 5. Compare the reports

The following security-relevant values should agree:

- `source_file.sha256` and `source_file.size`;
- `tool.version` and, when recorded by both builds, `tool.build_commit`;
- each indicator set's identity and `indicator_provenance[].sha256`;
- `verdict`, `findings`, `artifacts`, `missing_artifacts`, and `scan_limits`;
- every field under `stats` (all current stats are content-derived);
- `assurance` and `coverage`.

Expected non-security differences include `generated_at`, `duration_ms`,
`scanned_via`, a renamed `source_file.name`, and the informational
`indicator_provenance[].upstream` value. With `jq`, a useful normalized
comparison is:

```sh
jq -S 'del(.generated_at, .duration_ms, .scanned_via, .source_file.name)
  | .indicator_provenance |= map(del(.upstream))' original-report.json > original.normalized.json
jq -S 'del(.generated_at, .duration_ms, .scanned_via, .source_file.name)
  | .indicator_provenance |= map(del(.upstream))' rescan-report.json > rescan.normalized.json
diff -u original.normalized.json rescan.normalized.json
```

When the original `tool.build_commit` is `null`, a locally rebuilt tagged
revision will normally record a commit. Compare that field separately rather
than deleting the provenance limitation from the case record.

## Report schema map

The checked-in JSON Schema defines the report structure for the source revision
being examined. Because both a received report and its claimed revision are
untrusted until verified, schema conformance does not authenticate either one.
This map explains how responders should use the top-level fields.

| Field | Responder meaning |
| --- | --- |
| `schema_version` | Incompatible report-contract version; currently `4`. v0.7.4 and earlier used schema v3, where applicability had the older broad-matchability meaning. |
| `tool` | Tool name, package version, and exact build commit when recorded |
| `verdict` | Engine-owned outcome described above |
| `generated_at`, `duration_ms`, `scanned_via` | Nullable host/time/producer metadata; useful context, not evidence of authenticity |
| `source_file` | Producer-supplied name plus engine-computed size and SHA-256 of every archive byte received |
| `device` | Optional OS metadata derived from an artifact in the archive, including its source and sometimes a timestamp |
| `indicator_sets` | Counts for every loaded STIX set, including how many process-observable indicators the producing build accepted for negative process-scan coverage; other safe file indicators can still produce exact positive matches. Only the official browser's pinned roster carries Trace's reviewed-bundle claim. |
| `indicator_provenance` | Source metadata and engine-computed SHA-256 for the exact loaded indicator text; `upstream` is informational only |
| `artifacts` | Retained and processed artifacts plus the reduced unified-log summary, with parser status and details; artifacts dropped at a cap are disclosed through `scan_limits` rather than listed individually |
| `missing_artifacts` | Primary detection surfaces unavailable to this scan and the consequence; a surface can be unavailable even when related metadata-only files exist |
| `findings` | Severity, kind, source artifact, summary, evidence, and an optional matched-indicator reference |
| `stats` | Content-derived byte, archive-entry, retained non-unified artifact, and indicator counts; `artifacts_found` excludes the synthesized unified-log summary |
| `scan_limits` | Every parser, truncation, corruption, or resource condition that made processing incomplete; a match or suspicious verdict can still have entries here |
| `assurance` | Processing completeness plus `absent`/`partial`/`complete` state for each of the four supported surfaces |
| `coverage` | Plain-language lists of what this scan examined and did not examine, plus the non-cleanliness caveat |

All top-level fields are required by schema version 4 except the content-derived
`device` field. A finding's `indicator` is present only for an indicator-backed
match under the rules above. Producer metadata is retained as explicit `null`
when unavailable.
Parser-specific `details` and finding-specific `evidence` intentionally have no
fixed sub-schema.

## Escalation

For a `match`, a contextually concerning `suspicious` result, a repeated
`inconclusive` result, or serious concern despite `clear`, preserve the evidence
and contact a specialist through an independently verified channel:

- [Access Now Digital Security Helpline](https://www.accessnow.org/help/)
- [Amnesty International Security Lab](https://securitylab.amnesty.org/get-help/)

Do not open a public issue containing a real archive, report, exploit, or
personally identifying evidence. Potential Trace vulnerabilities should be
reported through the repository's GitHub private vulnerability-reporting
channel as described in [`SECURITY.md`](SECURITY.md).

## Tamper and reproducibility limits

- A Trace JSON report is not digitally signed. Anyone who can edit it can alter
  the verdict, findings, hashes, or metadata.
- An intake SHA-256 proves that a file has not changed **since that hash was
  recorded**. It does not prove who created the file or whether it was modified
  earlier.
- The embedded archive SHA-256 claims to identify exact archive bytes.
  Independently matching it shows only that the supplied archive matches the
  hash value currently written in the unsigned report. It does not prove that
  Trace scanned those bytes, that they came from the claimed phone, that they
  were captured at the claimed time, or that they are truthful. A compromised
  phone can lie in its own diagnostics.
- Schema validation proves structure, not origin or truth.
- A version tag maps a release name to public source. Unless its signature is
  independently verified, it is not by itself proof of operator identity.
- Re-scanning the same bytes with the recorded commit and indicator hashes can
  reproduce the security semantics and expose ordinary report tampering. It
  cannot recover evidence omitted before or during capture, detect unpublished
  indicators, or prove deployed-binary reproducibility.
- Hashes and reproducibility support responder trust; they do not create a
  formal forensic chain of custody.
