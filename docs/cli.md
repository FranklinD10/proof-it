# CLI reference

```text
proof-it <command> [path] [options]
```

## Commands

| Command | Stages | Purpose |
|---|---|---|
| `init` | — | Create `.proof-it/` (documented `config.yaml`, `suppressions.yaml`, `properties/`, `proof-hints/`) |
| `scan` | static, security, secrets, dependencies, external | Fast analysis without Lean |
| `verify` | formal, self-check | Lean verification of modeled properties |
| `attack` | formal, attack | Replay counterexamples and adversarial inputs against the code (needs `--allow-exec`) |
| `test` | formal, self-check, attack (+ mutation with `--mutate`) | Self-testing |
| `assure` | everything (mutation with `--deep`) | Complete pipeline |
| `check` | as `assure` | Agent protocol: prints structured JSON failures (`proof-it/agent@1`) |
| `report` | — | Re-render a run: `--format terminal|json|markdown|sarif|agent`, `--run <id|latest>`, `-o file` |
| `properties` | — | List the property library and project properties |
| `explain <id>` | — | Explain a property, finding id or rule id (8 questions: what, why, analysed, evidence, assumptions, why this status, source, what to do) |
| `counterexample <id> [--save]` | — | Show a counterexample; `--save` copies it to `.proof-it/counterexamples/` |
| `replay <file>` | — | Re-check a saved counterexample (model and Lean certificate) |
| `history [PROPERTY]` | — | Property status across recorded runs |
| `coverage` | — | OWASP Top 10, OWASP API Top 10, CWE Top 25 coverage |
| `doctor` | — | Check Lean, bubblewrap, Node, git, external tools |
| `version` | — | Versions, including the pinned Lean toolchain |

## Options (run commands)

| Option | Meaning |
|---|---|
| `--safe` | Never execute repository code |
| `--allow-exec` | Allow sandboxed execution (attack/replay) |
| `--quick` / `--deep` | Fast local feedback / larger budgets and mutation testing |
| `--offline` | No network (skips osv-scanner) |
| `--seed N` | Seed for all randomised search (default 1337) |
| `-p, --property ID|category` | Restrict properties (repeatable) |
| `--diff base...head` | Change mode: affected properties, regressions, merge decision, change bundle |
| `--baseline latest|<run-id>|report.json` | Baseline for regression detection |
| `--policy FILE` | Trusted organisation policy (must be outside the repository) |
| `--agent NAME` | Record the author of the change (never trusted) |
| `--security` / `--formal` | Only security / only formal stages |
| `--no-external` | Skip Semgrep, gitleaks, osv-scanner |
| `--out DIR` | Evidence directory (default `<repo>/.proof-it`) |
| `--no-cache` | Do not reuse cached kernel-checked proofs |
| `--timeout SECONDS` | Lean timeout per file |
| `--sarif FILE` | Also write SARIF |

Global: `--plain`, `--json`, `-q/--quiet`, `--ci` (plain output; writes
`report.sarif` and `report.md` into the run directory), `-v/--verbose`,
`--min-severity low|medium|high|critical`, `--log-level`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Assurance passed (possibly with warnings) |
| 1 | Property violation, failing security finding, regression, or protected-property weakening |
| 2 | Analysis error, or **INCOMPLETE**: some source files could not be parsed or were skipped. Such a run is never PASSED; the unanalysed files are listed under NOT ANALYSED. Fix them or exclude them explicitly (`exclude`), which is itself a reported policy change. |
| 3 | Configuration or usage error |
| 4 | Tool/environment error (e.g. `doctor` without Lean) |

## Configuration (`.proof-it/config.yaml`)

All keys are optional; unknown keys are errors. See the template written by
`proof-it init`. Sections: `project`, `languages`, `exclude`, `analysis`
(`static`, `security`, `secrets`, `dependencies`, `formal`, `fuzzing`,
`mutation`, `external.{semgrep,gitleaks,osv}`), `verification` (`timeout`,
`parallel`, `max_proofs`), `testing` (`allow_execution`, `iterations`, `seed`),
`properties` (`include`, `exclude`), `state_machines` (`type`, `initial`,
`terminal`, `forbidden`), `authorization` (`ownership_fields`,
`principal_paths`, `admin_roles`, `guard_functions`), `policy` (`violated`,
`critical_security`, `high_security`, `unproven`, `error`: `fail|warn|ignore`).

`suppressions.yaml`: `suppressions: [{ finding, file?, reason }]` — the reason
is mandatory (≥ 10 characters). Protected properties cannot be suppressed.

## Organisation policy

```yaml
protected_properties: [AUTHZ-001, PAY-001]
merge_policy:
  critical: [formal_proof, security_pass, adversarial_test, regression_pass, no_violation]
  high: [security_pass, regression_pass, no_violation]
  normal: [regression_pass, no_violation]
  policy_changes_require_human: true
state_machines: []   # organisation-wide specifications
```

Loaded from `--policy`, `$PROOF_IT_POLICY` or `~/.config/proof-it/policy.yaml`;
refused if it lives inside the analysed repository.

## CI example (GitHub Actions)

```yaml
- name: Proof-It
  run: proof-it assure --ci --safe --diff origin/main...HEAD --baseline latest --policy /etc/proof-it/policy.yaml
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: .proof-it/runs }
```
