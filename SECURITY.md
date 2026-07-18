# Security policy

Trace parses untrusted archives in the browser and is used by people who may
be at real risk. Bugs here can have consequences beyond broken software.

The repository-scoped assets, trust boundaries, attacker stories, and severity
calibration are documented in [THREAT_MODEL.md](THREAT_MODEL.md). Responder
interpretation and report-verification guidance lives in
[HELPLINE.md](HELPLINE.md).

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting on this repository
(Security tab, "Report a vulnerability"). Do not open a public issue for
anything exploitable.

Especially relevant classes of issues:

- Parser bugs reachable from a crafted archive (the tar/gzip/JSON paths in
  `crates/trace-core`)
- Anything that causes a request containing scan data or file contents to
  leave the browser
- Findings logic that could produce a false "no known traces" verdict
  (a false negative is a safety issue for this tool, not a cosmetic bug)
- Service worker or CSP weaknesses that would let a compromised dependency
  or host inject code

## Scope notes

Trace reads a sysdiagnose produced by the device under investigation. A
sufficiently compromised device can lie in its own diagnostics; that
limitation is documented and out of scope. The inherent publication and review
lag of public threat intelligence is likewise a disclosed limitation, not by
itself a vulnerability.

Indicator-handling defects remain in scope when they can affect verdict or
provenance integrity. Examples include unreviewed live upstream data entering
matching, a bundled snapshot falling below the enforced review floor, a failed
or incomplete snapshot load still permitting a reassuring result, and
upstream-comparison, hash, or source metadata that materially misrepresents what
was actually loaded.
