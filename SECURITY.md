# Security policy

Proof-It reads untrusted repositories and, with `--allow-exec`, runs their code
in a sandbox. A bug that lets an analysed repository escape the sandbox, read or
write outside it, tamper with evidence, or make Proof-It report PROVEN or PASSED
for something it did not establish is a security vulnerability.

## Reporting

Please **do not open a public issue**. Report privately through GitHub:
**Security → Report a vulnerability** on this repository (private vulnerability
reporting). Include the Proof-It version (`proof-it version`), the command, and a
minimal repository or snippet that reproduces the problem.

We aim to acknowledge reports within 5 working days and to agree a disclosure
date with you.

## What counts

- Sandbox escapes or host access from analysed code (`--allow-exec`).
- Analysed code influencing Proof-It's own output beyond its findings (forged
  evidence, injected report content, suppressed results).
- **Soundness bugs**: PROVEN for a property that does not hold in the extracted
  model, PASSED for a run that skipped code, or an AUTO-MERGE decision that the
  merge policy forbids. These are treated as vulnerabilities, not ordinary bugs.

Missed detections (false negatives) and false positives are ordinary issues:
please report them publicly with a reproducer.
