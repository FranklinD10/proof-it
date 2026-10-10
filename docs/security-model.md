# Security model of Proof-It itself

Proof-It analyses code written by others — including AI agents and attackers.
It treats the analysed repository as **hostile**.

## Trusted, analysed, assumed

| Category | Items |
|---|---|
| **Trusted** | The Lean 4 kernel (`lean`, pinned by `lean/lean-toolchain`); Lean's foundation axioms (`propext`, `Quot.sound`, `Classical.choice`); the Proof-It binary; the organisation policy file (outside the repository); the OS sandbox (bubblewrap) |
| **Analysed** | Source files (parsed, never executed unless allowed); repository configuration (validated as untrusted input); dependency lockfiles (via osv-scanner) |
| **Assumed** (listed in every result) | Correctness of the code→model translation; semantics of unanalysed middleware and data layers; JavaScript semantics outside the model (attacked, not proven); external analyzers' correctness; the runtime and infrastructure |

## Controls

| Threat | Control |
|---|---|
| Command injection via repository content | No shell anywhere: every process is started with an argument vector (`core/src/process.rs`) |
| Runaway or hostile subprocesses | Timeouts enforced on the whole process group; output caps; scrubbed environment (no inherited secrets) |
| Tools reading/writing outside the repo | External tools run under bubblewrap: read-only root, private `/tmp`, no network (except osv-scanner), private HOME |
| Executing repository code | Off by default; `--allow-exec` or `testing.allow_execution`; refused under `--safe`. Code is transpiled (no build scripts, no installs) into a private directory and run under Node's permission model (read-only to that directory and `node_modules`; no writes, child processes, workers or addons), a 512 MB heap, per-case and per-batch timeouts, inside bubblewrap without network |
| Malicious git configuration (`core.fsmonitor`, hooks) | HEAD is read from `.git` files; git commands run with `core.fsmonitor=false`, `core.hooksPath=/dev/null`, no external diff/textconv, no system/global config, no prompts; revision ranges are validated |
| Symlink attacks | Discovery never follows symlinks; `.proof-it/`, `runs/`, `cache/`, `changes/` must be real directories; config files that are symlinks are refused |
| Path traversal in evidence names | All artifact names are sanitised and joined with `safe_join` (no `..`, no absolute paths, no NUL) |
| Configuration as an attack vector | `config.yaml` has no field naming a program, command or absolute path; unknown keys are errors; YAML alias expansion is budgeted; size limits |
| Property files | Pure data; may only bind to extractors shipped with Proof-It; signal regexes are size-limited; cannot shadow library properties |
| Proof forgery | Forbidden-construct scan, kernel check, axiom audit, non-vacuity witness; agent proof hints cannot change statements |
| Secret leakage through reports | Secrets are redacted inside the scanner before a finding exists; gitleaks runs with `--redact` and its output is re-redacted |
| Weakening the verification policy | Policy changes are detected semantically and reported separately; protected properties come from the organisation policy outside the repository and cannot be excluded or suppressed from the repository |

## `--safe`

Use for untrusted repositories: repository code is never executed (attack
stage skipped), everything else runs. External tools are still sandboxed.
