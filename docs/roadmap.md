# Roadmap

## Alpha (current)

- [x] Rust core, oxc TypeScript/JavaScript adapter, Lean 4 verification with kernel acceptance, axiom audit, non-vacuity
- [x] Formal properties: state machines, read/write IDOR, admin authorization, ledger conservation and non-negativity
- [x] 40+ security detector rules, templates, app-level configuration checks, Semgrep/gitleaks/osv-scanner adapters
- [x] Sandboxed attack engine (replay + adversarial inputs), model self-check, mutation testing
- [x] Change assurance for AI agents: affected properties, regressions, policy-change detection, protected properties, merge decision, change bundles, agent protocol
- [x] Lean-specified decision logic with a refinement test
- [x] Benchmarks, real-world recall harness, CI, release workflow, documentation
- [x] Three held-out recall measurements (39%, 50%, 56% untuned)
- [x] First public alpha `v0.1.0-alpha.1`
- [ ] Per-file recall benchmark from Juice Shop challenge variants; location-based scoring
- [ ] Measured precision on real codebases

## Next

- Cross-module taint (beyond local helpers) and taint into imported functions
- Python adapter (FastAPI/Django/Flask), then Go (net/http, gin, echo)
- Formal models: idempotency (SOS-001, MS-002), token revocation (AUTH-004), session lifecycle
- Excessive data exposure (OWASP API3): sensitive fields in responses
- HTTP-level attack mode against a running test instance (opt-in)
- Proof-It analysing its own Rust code (Rust adapter)

## Not planned

GUI, web dashboard, SaaS. Proof-It is a command-line tool.
