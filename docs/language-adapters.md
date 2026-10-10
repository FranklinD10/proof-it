# Language adapters

An adapter turns one source file into `ModuleAnalysis` = language-neutral
`ModuleFacts` + language-specific `Finding`s (`crates/core/src/facts.rs`).

## TypeScript/JavaScript (`crates/lang-ts`, oxc 0.152)

Purely syntactic (no type checker, no module resolution beyond relative
imports, no execution).

1. **Pass 1** — function names by span (declarations, `const f = () =>`,
   object/class members, `this.f = …`, `exports.f = …`, handler factories
   `function f() { return (req, res) => … }`), exports, enums/unions,
   transition tables, imports, router mounts (`app.use(prefix, mw, router)`),
   route registrations (Express/Koa/Fastify style, NestJS decorators) and
   `@proof-it` annotations.
2. **Pass 2** — for every function, the **guarded walker** walks the body
   top-down with a stack of path conditions (branches, early exits, switch
   cases, assertion-style calls, path merging after non-exiting branches,
   `try`/`catch` handling) and records state writes, response/write sinks,
   lookups (including callback and promise-chain styles), ledger statements and
   request-field overrides. Local aliases and destructuring are resolved.
3. **Detectors** — intra-procedural taint with two-level interprocedural
   seeding into local helpers; static checks; mutation operators; an oxc
   transpiler for sandboxed execution.

## Writing an adapter for another language

Produce the same facts. Most of the work is the guarded walker: for each
interesting program point, the conditions under which it is reached, as
`Cond`/`Val` values with normalised access paths. Then register the adapter in
`pipeline::analyze_files` and add the language to `Language::from_extension`
(Python, Go and Rust are already recognised by discovery). Every formal
property works unchanged once facts exist; detectors are per language.

Contract: never execute code, never follow symlinks, report parse errors
instead of failing, keep paths repository-relative, and never claim more
precision than the walker has (unknown conditions become `Cond::Other`).
