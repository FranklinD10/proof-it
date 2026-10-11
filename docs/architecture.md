# Architecture

Proof-It is a single Rust binary. Lean 4 is the only trusted proof checker; every
other component produces *evidence* that is labelled with its strength.

```text
proof-it (crates/cli)
   │
   ▼
pipeline (crates/engine/src/pipeline.rs)
   │  discover → parse → analyse → verify → attack → self-test → change → verdict
   │
   ├── language adapter (crates/lang-ts) ─────────► language-neutral facts (crates/core/src/facts.rs)
   │      oxc parser, guarded walker,                 state writes, handlers, lookups, sinks,
   │      security + static detectors                 ledger statements, mounts, enums …
   │
   ├── secrets / app-level checks / external tools (Semgrep, gitleaks, osv-scanner)
   │
   ├── formal engine (crates/model)
   │      extractors: facts → obligations (model IR)
   │      Lean emitter → `lean` subprocess → acceptance check (KernelAcceptance)
   │      counterexample search → robustness → Lean certificate
   │
   ├── attack engine (crates/engine/src/attack.rs, exec.rs)
   │      sandboxed execution of counterexamples and adversarial inputs
   │
   ├── self-tests: model self-check, mutation testing
   │
   ├── change assurance (change.rs): affected properties, regressions,
   │      policy-change detection, merge decision
   │
   └── verdict, assurance level, proof debt, evidence store, reports
```

## Crates

| Crate | Responsibility | Trust |
|---|---|---|
| `proof-it-core` | Result types, configuration, property registry, facts IR, process sandbox, evidence store, the Lean-specified decision functions | Trusted code (small, tested, decision logic refined against Lean) |
| `proof-it-lang-ts` | TypeScript/JavaScript adapter (oxc): facts, security detectors, static checks, mutation operators, transpiler | Untrusted *translation*: its output is labelled as unverified in every proof |
| `proof-it-lang-go` | Go adapter (tree-sitter-go): functions, type-based request sources, taint, security detectors. No route/handler facts yet, so formal properties do not cover Go | Untrusted analysis; findings carry evidence kinds |
| `proof-it-model` | Model IR, evaluator, extractors, Lean emitter/runner, formal engine | The Lean kernel is trusted; the emitter is checked by the model self-check |
| `proof-it-engine` | Orchestration, external tools, attack engine, change assurance, reports | Untrusted analyses; all results carry evidence kinds |
| `proof-it` (cli) | Command-line interface | — |

## Design rules

1. **Facts, not ASTs, cross crate boundaries.** Adapters own parsing; extractors
   see only owned, language-neutral facts. Adding a language means writing an
   adapter that produces facts (see [language-adapters.md](language-adapters.md)).
2. **PROVEN is a capability, not a flag.** `PropertyResult::prove` requires a
   `KernelAcceptance`, which only the Lean runner constructs, after the
   forbidden-construct scan, a clean compile and the axiom audit; vacuous
   theorems are refused.
3. **Every finding states its evidence kind** (`kernel-checked`,
   `kernel-checked-counterexample`, `replayed-against-code`, `bounded-search`,
   `static-pattern`, `external-tool`, `assumption`).
4. **The analysed repository is hostile.** Its configuration is untrusted input,
   symlinks are not followed, git is not executed inside it except with
   hardened options, external tools run sandboxed, and its code is executed
   only when explicitly allowed (see [security-model.md](security-model.md)).
5. **Failure is never success.** A missing tool is `not-installed`, an internal
   error is `ERROR`, an unmodelable construct is `UNPROVEN` with the reason.
