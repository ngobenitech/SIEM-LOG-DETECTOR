# Detection Engineering Notes

## Scope

The detector accepts OpenSSH authentication records from a Linux `auth.log`-style
file. It converts supported records into a common event model before applying
time-window rules.

Normalized fields:

| Field | Purpose |
|---|---|
| `timestamp` | Orders events and defines correlation windows |
| `hostname` | Identifies the system that produced the event |
| `username` | Supports account-focused analysis |
| `source_ip` | Supports source-focused aggregation |
| `source_port` | Preserves network context |
| `status` | Distinguishes authentication failure from success |
| `auth_method` | Distinguishes password and public-key authentication |
| `raw` | Preserves evidence for validation |

## Rule SSH-BF-001: repeated failures

### Analytic

Group failed SSH authentications by source address. For each source, find the
highest-volume sliding window. Alert when the window contains at least five
events within five minutes.

### Reasoning

The time bound prevents unrelated failures over a long period from being treated
as one attack. The rule intentionally alerts on both valid and invalid usernames
because attackers may enumerate accounts while guessing credentials.

### Likely false positives

- approved vulnerability scanners;
- administrators using an outdated stored password;
- automation with expired credentials;
- shared jump hosts with multiple mistyped logins.

### Tuning

- allow-list known scanners only after ownership is confirmed;
- increase the threshold for high-volume shared administration hosts;
- reduce the threshold for internet-facing privileged systems;
- enrich with asset criticality before changing severity.

## Rule SSH-PS-002: possible password spraying

### Analytic

Group failed SSH authentications by source address. Alert when one source targets
at least four distinct usernames within ten minutes.

### Reasoning

The distinct-account count separates broad account targeting from repeated
guessing against one account. Authentication logs do not expose the attempted
password, so the result is labelled **possible** password spraying.

### Likely false positives

- identity or access audits;
- misconfigured orchestration using several service accounts;
- shared administration sources;
- approved security testing.

### Tuning

- baseline the normal number of accounts reached from administration subnets;
- correlate with MFA, identity-provider, and endpoint telemetry;
- exclude approved tests by change ticket and time range, not permanently by
  source address.

## Rule SSH-SAF-003: success after failures

### Analytic

For the same host, source address, and username, correlate at least three failed
authentications followed by a successful authentication within ten minutes.

### Reasoning

A successful login following repeated failures is higher priority than failures
alone. It may represent an attacker finding the correct password, but can also
represent a legitimate user correcting a typing error. The alert therefore says
that investigation is required and does not state that compromise occurred.

### Likely false positives

- legitimate users correcting a password;
- password-manager or keyboard-layout errors;
- password rotation followed by a successful retry;
- support personnel assisting the account owner.

### Tuning

- increase confidence with an unknown device, unusual location, or new source;
- compare the source with the user's authentication history;
- correlate the login with process, command, privilege, and network telemetry;
- lower the threshold for privileged accounts only when alert volume is measured.

## ATT&CK references

- [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)
- [T1110.001 — Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
- [T1110.003 — Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
- [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/)

ATT&CK mappings describe relevant adversary behavior; they do not prove intent or
attribution.

## Detection gaps

Current rules do not identify:

- distributed attacks where each source remains below threshold;
- authentication methods or SSH implementations with different message formats;
- success from an address different from the failure source;
- low-and-slow activity spanning longer windows;
- activity hidden by log loss, forwarding delay, or clock drift.

Closing a gap requires a defined analytic, suitable telemetry, representative test
data, and negative tests to control false positives.
