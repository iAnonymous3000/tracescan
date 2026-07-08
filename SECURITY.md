# Security policy

Trace parses untrusted archives in the browser and is used by people who may
be at real risk. Bugs here can have consequences beyond broken software.

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
limitation is documented and out of scope. Reports about the inherent lag of
public threat intelligence are likewise out of scope: that trade-off is
deliberate and disclosed in the UI.
