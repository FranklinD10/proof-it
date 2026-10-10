# Threat model

Two threat models are relevant: the applications Proof-It analyses, and
Proof-It itself.

## 1. Applications under analysis

Properties carry a threat model in their YAML (`threat_model`): an actor, its
capabilities and its goal. The default actors are:

| Actor | Capabilities | Properties |
|---|---|---|
| Authenticated user | Send HTTP requests; change identifiers in path/query/body; replay requests | AUTHZ-001, AUTHZ-004 (read/modify another user's resource), STATE-001/002 (illegal transitions) |
| Authenticated non-admin | Call admin routes | AUTHZ-002 |
| Account holder | Choose transfer amounts and accounts, repeat requests | PAY-001, PAY-003 |
| Remote attacker | Arbitrary request data | DATA-001 (injection), API-001 (SSRF), API-003 (XSS), DATA-003 (path traversal), DATA-004 (deserialization/XXE), API-005 (ReDoS) |

The chain from threat to evidence is:

```text
threat model → property → extractor / detector → attack inputs → counterexample → (Lean certificate)
```

## 2. Proof-It itself

| Adversary | Goal | Mitigation (see security-model.md) |
|---|---|---|
| Malicious repository | Execute code on the developer's or CI machine; read secrets; write outside the repo | No shell, sandboxing, opt-in execution, hardened git, symlink refusal, env scrubbing |
| Malicious repository | Make Proof-It report PROVEN for vulnerable code | Kernel check + axiom audit; non-vacuity; opaque conditions never yield PROVEN; translation listed as unverified |
| AI coding agent | Pass the merge gate without fixing the code | Policy-change detection; protected properties from the organisation policy; proof hints cannot change statements; agent claims are never evidence |
| AI coding agent | Hide code from analysis | New `exclude` globs are reported as policy changes; parse errors are reported |
| Compromised external tool | Report "clean" | External tools add evidence; they never remove other evidence or produce PROVEN |
| Bug in Proof-It | Wrong verdict | Model self-check (Lean vs evaluator), refinement test of the decision logic against Lean, mutation testing, benchmark suite, real-world recall measurement |

## Out of scope

Compromise of the Lean toolchain, the Rust toolchain, the host OS or the
organisation policy file; side channels; denial of service against Proof-It by
extremely large repositories (bounded by file-size and file-count limits, and
timeouts).
