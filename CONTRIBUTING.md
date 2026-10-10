# Contributing

Thanks for helping. Proof-It's value is that its results can be trusted, so the
bar is evidence, not plausibility.

## Build and test

Requirements: Rust (see `rust-version` in `Cargo.toml`), Lean 4 via
[elan](https://github.com/leanprover/elan) for the formal tests, and optionally
`bwrap` and Node.js for the attack engine.

```bash
cargo build
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace                     # includes benchmarks and the Lean refinement test
cargo test --release -p proof-it --test real_world -- --ignored --nocapture   # recall (clones apps)
```

CI runs all of these except the recall test, which runs weekly.

## Rules for changes

- **Every detector change needs a vulnerable and a safe case**: a test in
  `crates/lang-ts/tests/detectors.rs` and, for authorization or formal
  changes, a benchmark pair in `benchmarks/` with its expected status in
  `benchmarks/expected.yaml`.
- **Never tune on a held-out application.** New real-world applications are
  added to `benchmarks/real-world/manifest.yaml` with their ground truth written
  from their own documentation and committed *before* the first run; the
  untuned score is recorded in `docs/validation.md` before any fix.
- **Names are not evidence.** Do not credit a guard, sanitizer or check because
  of what it is called; read its code, or report the result as UNPROVEN with the
  assumption stated.
- **Never weaken a status.** A change that turns UNPROVEN into PROVEN, or
  INCOMPLETE into PASSED, must say exactly what new evidence justifies it.
- Changes to the status or merge logic must be made in
  `lean/ProofIt/Models/Assurance.lean` and `crates/core/src/decision.rs`
  together; the refinement test checks they agree.

## Pull requests

Describe the problem, the evidence (tests, benchmarks, before/after results on
the recall set), and anything that got worse. Small, focused PRs are reviewed
fastest.

By contributing you agree that your contributions are licensed under the
Apache License 2.0.
