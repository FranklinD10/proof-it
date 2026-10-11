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

## Go (`crates/lang-go`, tree-sitter-go) — security only

Purely syntactic, like the TypeScript adapter. Any syntax error (including
recovered ones) makes the file a coverage gap, so the run is INCOMPLETE.

- **Facts:** functions and methods. Route and handler facts are **not** produced
  yet, so the authorization models (AUTHZ-*), state machines and ledgers do not
  apply to Go code; every run containing Go says so in its warnings.
- **Sources** come from the *declared type* of parameters, never from names:
  `*http.Request` (`FormValue`, `URL.Query().Get`, `Header.Get`, `PathValue`,
  `Cookie`, `URL.Path`, `Body` via `io.ReadAll`), `*gin.Context` /
  `echo.Context` / `*fiber.Ctx` (`Param`, `Query`, `PostForm`, `GetHeader`,
  `QueryParam`, …, and `ShouldBind*` / `Bind*` / `BodyParser` targets),
  `json.NewDecoder(r.Body).Decode(&x)`, `json.Unmarshal(tainted, &x)`,
  `mux.Vars`, `chi.URLParam`.
- **Propagation:** assignments (`:=`, `=`, `+=`, `var`), `range`, string
  building (`+`, `fmt.Sprintf`, `strings.*`), conversions, method calls on
  tainted values, and functions in the same file whose result carries a tainted
  argument (judged from their bodies; "sanitizers" that return their input
  unchanged do not clear taint). Sanitizers: `strconv.Atoi`/`Parse*`,
  `filepath.Base`, `url.*Escape`, `html.EscapeString`, `template.*Escape*`,
  `uuid.Parse`, bluemonday.
- **Detectors:** SQL injection and dynamic SQL (database/sql, sqlx, pgx, gorm
  `Raw`/`Exec`/`Where`/`Order`), command injection (`exec.Command` with a shell
  or a tainted program), path traversal (`os.*`, `http.ServeFile`, framework
  file helpers), SSRF (`http.Get`/`NewRequest`/clients), open redirect, reflected
  XSS (`fmt.Fprintf(w, …)`, `w.Write`, `template.HTML`), template injection,
  `InsecureSkipVerify: true`, MD5/SHA-1 for passwords, `math/rand` for tokens.
  Secrets and committed personal data are checked for every file regardless of
  language.
- **Not yet:** taint across packages or files, goroutine/channel flows,
  interface dispatch, struct fields written in one function and read in
  another, and recall measured on a held-out Go application.

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
