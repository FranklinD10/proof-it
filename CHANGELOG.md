# Changelog

## 0.1.0-alpha.1

First public alpha. Command-line code assurance for TypeScript/JavaScript services.

- Formal verification with Lean 4: state machines (STATE-001/002), read and
  write IDOR (AUTHZ-001/004), admin authorization (AUTHZ-002), ledger
  conservation and non-negativity (PAY-001/003). Kernel acceptance with axiom
  audit, non-vacuity witnesses, Lean-certified counterexamples, untrusted
  agent proof hints.
- Security analysis: taint (intra-procedural + two-level local
  interprocedural) to SQL/NoSQL/shell/eval/vm/template/filesystem/network/
  redirect/HTML sinks; XXE, ReDoS, deserialization, prototype pollution, mass
  assignment, JWT/crypto/TLS/CORS/cookie/session misuse, unrestricted uploads,
  zip slip, XPath and XML/SOAP injection, response-header injection, GraphQL
  introspection; framework sources for GraphQL resolvers and RPC methods;
  option objects resolved by name; template scanner; application-level header/CSRF/rate-limit checks;
  secret scanner with redaction (incl. weak dotenv secrets); Semgrep, gitleaks, osv-scanner adapters.
- Attack engine: sandboxed replay and property-directed adversarial inputs.
- AI-agent assurance: affected properties via the import graph, regressions,
  semantic policy-change detection, protected properties, merge decisions,
  change bundles, `proof-it check` agent protocol.
- Self-assurance: Lean-specified decision logic with a refinement test, model
  self-check, mutation testing, 44 benchmarks, real-world recall harness
  (NodeGoat, DVNA, Juice Shop, DVWS-node, nodejs-goof; untuned held-out
  baselines 56%, 39% and 50%).
- PROVEN never rests on assumptions alone: hypotheses are tagged as read from
  code or assumed by Proof-It, and a theorem whose conclusion follows from the
  assumptions alone is UNPROVEN ("by assumption only"). Specified in Lean
  (`proven_requires_code`) and refinement-tested.
- Middleware and sanitizers are judged by their code, not their names: a
  no-op guard protects nothing (and the route is analysed rather than treated
  as public), an admin guard must read a role, library guards cannot support a
  proof, and local functions propagate taint unless they actually transform
  the value.
- Runs that leave source code unanalysed (parse errors, including recoverable
  ones, or files skipped by size/count limits) are INCOMPLETE (exit 2),
  never PASSED; the files are listed, the assurance level is 0 and changes are
  not auto-merge eligible. JSX is parsed in `.js`/`.mjs`/`.cjs` files.
- GraphQL resolvers (`Query`/`Mutation` resolver maps) are analysed as
  handlers for object-level authorization: `args` is client input,
  `context.user` the principal.
- Lookups assigned to an existing local or returned directly are modelled;
  presence tests (`typeof x === 'undefined'`, `x == null`) are treated like
  `!x` (authentication and not-found checks).
- Rate limits keyed on a spoofable client IP (raw X-Forwarded-For and
  similar headers, `keyGenerator`, `trust proxy` set to `true`).
- Personal data committed to the repository (SEC-COMMITTED-PERSONAL-DATA):
  CSV/JSON exports with real email addresses or phone numbers (or a
  personal-data header with real values), pg_dump/MySQL/SQLite dumps; counts
  only, values never shown; test fixtures downgraded.
- Reachable vulnerable dependency APIs: a known-vulnerable installed version
  is reported only where the affected function is called (offline, curated).
- Plaintext password storage (password used as a query filter or compared in
  SQL); the whole request object passed as template locals; session cookies
  without `secure`; taint through regular-expression matches.
- Express route chains (`router.route(p).get(…)`) with ordered middleware;
  guards registered after the handler are reported as ineffective.
- Reports: terminal, JSON, Markdown, SARIF 2.1.0; explain, counterexample,
  replay, history, coverage, doctor.
