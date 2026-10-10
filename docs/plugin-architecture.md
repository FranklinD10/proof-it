# Extension points

Proof-It is extended by adding code at well-defined seams; analysed
repositories can only add *data* (properties, configuration, proof hints).

| To add | Where | Contract |
|---|---|---|
| A language | `crates/lang-*`, registered in `pipeline::analyze_files` | Produce `ModuleFacts` + findings; see language-adapters.md |
| A formal property family | `crates/model/src/extract/*.rs` + `Extractor` enum + library YAML | Return `Extraction`s with an `Obligation`, assumptions, a trace function and (optionally) a `ReplaySpec`; add good/bad benchmarks |
| A security detector | `crates/lang-ts/src/security.rs` (`RULES` + detection) | Rule id, CWE, severity, recommendation, property; a vulnerable and a safe test case in `tests/detectors.rs`; an entry in `coverage/coverage.yaml` |
| An application-level check | `crates/engine/src/appchecks.rs` | Protections count only when used in uncommented code |
| An external analyzer | `crates/engine/src/external.rs` | Optional (`not-installed` when missing), sandboxed, timed out, normalised to `Finding`s, raw output stored as evidence, secrets redacted |
| A report format | `crates/engine/src/report.rs` | Never drop the status labels or the assumptions |

Every extension must keep the honesty rules: no PROVEN without the Lean
runner's `KernelAcceptance`; unknown means UNPROVEN, not PASSED; missing tools
are reported as not run.
