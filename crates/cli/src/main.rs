//! `proof-it` command-line interface. Exit codes (docs/cli.md):
//! 0 assurance passed · 1 property/security failure · 2 analysis error ·
//! 3 configuration/usage error · 4 tool/environment error.

use clap::{Args, Parser, Subcommand, ValueEnum};
use proof_it_core::config::{CONFIG_DIR, CONFIG_FILE, init_template};
use proof_it_core::log::{self, Level};
use proof_it_core::process::{sandbox_available, which};
use proof_it_core::property::Registry;
use proof_it_core::store::{RunStore, evidence_base};
use proof_it_core::types::ProofStatus;
use proof_it_core::{Error, ExitCode, Result};
use proof_it_engine::pipeline::{self, Options, Report, Stage};
use proof_it_engine::report::{self, Style};
use proof_it_model::formal::{CX_FORMAT, CounterexampleFile, recheck};
use std::collections::BTreeSet;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "proof-it", version, about = "Command-line code assurance: Lean-checked properties, security analysis, adversarial testing, reproducible counterexamples.", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
    #[command(flatten)]
    out: OutputArgs,
}

#[derive(Args, Clone)]
struct OutputArgs {
    /// ASCII only, no colour (CI logs, screen readers).
    #[arg(long, global = true)]
    plain: bool,
    /// Machine-readable JSON on stdout (logs go to stderr).
    #[arg(long, global = true)]
    json: bool,
    /// One-line summary.
    #[arg(long, short, global = true)]
    quiet: bool,
    /// CI mode: plain output, SARIF + JSON written to the run directory, meaningful exit codes.
    #[arg(long, global = true)]
    ci: bool,
    /// Show every finding and every property, including NOT APPLICABLE.
    #[arg(long, short, global = true)]
    verbose: bool,
    #[arg(long, global = true, value_enum, default_value = "warn")]
    log_level: LogLevel,
    /// Only display findings at or above this severity (evidence files keep everything).
    #[arg(long, global = true, value_enum)]
    min_severity: Option<MinSeverity>,
}

#[derive(Clone, Copy, ValueEnum)]
enum MinSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Copy, ValueEnum)]
enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
    Silent,
}

#[derive(Args, Clone)]
struct RunArgs {
    /// Repository to analyse (default: current directory).
    path: Option<PathBuf>,
    /// Treat the repository as hostile: never execute its code.
    #[arg(long)]
    safe: bool,
    /// Allow sandboxed execution of repository code (replay, adversarial testing).
    #[arg(long)]
    allow_exec: bool,
    /// Fast local feedback: no network tools, fewer test iterations.
    #[arg(long, conflicts_with = "deep")]
    quick: bool,
    /// Deep analysis: larger search budgets, more iterations, mutation testing.
    #[arg(long)]
    deep: bool,
    /// Never use the network (skips osv-scanner).
    #[arg(long)]
    offline: bool,
    /// Seed for every randomised search (default: fixed, so runs are reproducible).
    #[arg(long)]
    seed: Option<u64>,
    /// Restrict to properties (ids or categories); repeatable.
    #[arg(long = "property", short = 'p')]
    properties: Vec<String>,
    /// Change mode: analyse the effect of `base...head` (affected properties, regressions, merge policy).
    #[arg(long)]
    diff: Option<String>,
    /// Baseline run (`latest`, a run id, or a report.json path) for regression detection.
    #[arg(long)]
    baseline: Option<String>,
    /// Evidence directory (default: <repo>/.proof-it).
    #[arg(long)]
    out: Option<PathBuf>,
    /// Do not reuse cached kernel-checked proofs.
    #[arg(long)]
    no_cache: bool,
    /// Lean timeout per file, seconds.
    #[arg(long)]
    timeout: Option<u64>,
    /// Trusted organisation policy (outside the repository): protected properties, merge policy.
    #[arg(long)]
    policy: Option<PathBuf>,
    /// Name of the agent/author of the change (recorded; never trusted).
    #[arg(long)]
    agent: Option<String>,
    /// Only security analysis stages.
    #[arg(long, conflicts_with = "formal")]
    security: bool,
    /// Only formal stages.
    #[arg(long)]
    formal: bool,
    /// Skip external analyzers (Semgrep, gitleaks, osv-scanner).
    #[arg(long)]
    no_external: bool,
    /// Also write SARIF to this file.
    #[arg(long)]
    sarif: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// Create .proof-it/ with a documented config, suppressions and property folders.
    Init {
        path: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Static, security, secret and dependency analysis (fast).
    Scan(RunArgs),
    /// Formal verification of modeled properties with Lean.
    Verify(RunArgs),
    /// Try to violate properties: replay counterexamples and adversarial inputs against the code.
    Attack(RunArgs),
    /// Model self-check, property-based attack testing and (with --mutate) mutation testing.
    Test {
        #[command(flatten)]
        run: RunArgs,
        /// Measure whether Proof-It detects injected bugs.
        #[arg(long)]
        mutate: bool,
    },
    /// The complete pipeline.
    Assure(RunArgs),
    /// Agent protocol: run the pipeline and print structured failures (JSON) an AI agent can act on.
    Check(RunArgs),
    /// Render a previous run (`--format terminal|json|markdown|sarif|agent`).
    Report {
        path: Option<PathBuf>,
        #[arg(long, default_value = "latest")]
        run: String,
        #[arg(long, value_enum, default_value = "terminal")]
        format: Format,
        #[arg(long, short)]
        output: Option<PathBuf>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// List the property library (and project properties).
    Properties { path: Option<PathBuf> },
    /// Explain a property, finding or rule from the latest run.
    Explain {
        id: String,
        #[arg(long)]
        path: Option<PathBuf>,
        #[arg(long, default_value = "latest")]
        run: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Show (and optionally save) a counterexample from the latest run.
    Counterexample {
        id: String,
        #[arg(long)]
        path: Option<PathBuf>,
        #[arg(long, default_value = "latest")]
        run: String,
        /// Copy to .proof-it/counterexamples/<id>.json (kept across runs).
        #[arg(long)]
        save: bool,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Re-check a saved counterexample (model + Lean certificate).
    Replay { file: PathBuf },
    /// Status of properties across runs (semantic history).
    History {
        property: Option<String>,
        #[arg(long)]
        path: Option<PathBuf>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Coverage of OWASP Top 10, OWASP API Top 10 and CWE Top 25 by Proof-It.
    Coverage,
    /// Check the environment: Lean, sandbox, Node, external analyzers.
    Doctor,
    /// Print version information.
    Version,
}

#[derive(Clone, Copy, ValueEnum, PartialEq, Eq)]
enum Format {
    Terminal,
    Json,
    Markdown,
    Sarif,
    Agent,
}

fn style(o: &OutputArgs) -> Style {
    let plain = o.plain || o.ci;
    Style { plain, color: !plain && std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none() }
}

fn repo(p: Option<&PathBuf>) -> PathBuf {
    p.cloned().unwrap_or_else(|| PathBuf::from("."))
}

fn stages(cmd: &str, a: &RunArgs, mutate: bool) -> BTreeSet<Stage> {
    use Stage::*;
    let scan = [Static, Security, Secrets, Dependencies, External];
    let mut s: BTreeSet<Stage> = match cmd {
        "scan" => scan.into_iter().collect(),
        "verify" => [Formal, Selfcheck].into_iter().collect(),
        "attack" => [Formal, Attack].into_iter().collect(),
        "test" => [Formal, Selfcheck, Attack].into_iter().collect(),
        _ => scan.into_iter().chain([Formal, Selfcheck, Attack]).collect(),
    };
    if a.security {
        s.retain(|x| scan.contains(x));
    }
    if a.formal {
        s.retain(|x| matches!(x, Formal | Selfcheck));
    }
    if a.no_external {
        s.remove(&External);
    }
    if mutate || (a.deep && cmd != "scan") {
        s.insert(Mutation);
    }
    s
}

fn run_pipeline(cmd: &str, a: &RunArgs, mutate: bool) -> Result<Report> {
    let opts = Options {
        path: repo(a.path.as_ref()),
        command: cmd.into(),
        stages: stages(cmd, a, mutate),
        seed: a.seed,
        safe: a.safe,
        allow_exec: a.allow_exec,
        quick: a.quick,
        deep: a.deep,
        offline: a.offline,
        properties: a.properties.clone(),
        diff: a.diff.clone(),
        baseline: a.baseline.clone(),
        out_dir: a.out.clone(),
        no_cache: a.no_cache,
        timeout: a.timeout,
        policy: a.policy.clone(),
        agent: a.agent.clone(),
    };
    pipeline::run(&opts)
}

fn emit(r: &Report, o: &OutputArgs, a: &RunArgs) -> Result<u8> {
    let sarif = report::sarif(r);
    let sarif_text = serde_json::to_string_pretty(&sarif).unwrap_or_default();
    if o.ci {
        let dir = PathBuf::from(&r.run_dir);
        std::fs::write(dir.join("report.sarif"), &sarif_text).map_err(|e| Error::io(dir.join("report.sarif"), e))?;
        std::fs::write(dir.join("report.md"), report::markdown(r)).map_err(|e| Error::io(dir.join("report.md"), e))?;
    }
    if let Some(p) = &a.sarif {
        std::fs::write(p, &sarif_text).map_err(|e| Error::io(p, e))?;
    }
    if o.json {
        println!("{}", serde_json::to_string_pretty(r).unwrap_or_default());
    } else {
        let shown = filtered(r, o.min_severity);
        print!("{}", report::terminal(&shown, &style(o), o.verbose, o.quiet || o.ci));
        if o.ci {
            println!("report: {}/report.json  sarif: {}/report.sarif", r.run_dir, r.run_dir);
        }
    }
    Ok(r.verdict.exit_code)
}

fn filtered(r: &Report, min: Option<MinSeverity>) -> Report {
    use proof_it_core::types::Severity;
    let Some(m) = min else { return r.clone() };
    let floor = match m {
        MinSeverity::Low => Severity::Low,
        MinSeverity::Medium => Severity::Medium,
        MinSeverity::High => Severity::High,
        MinSeverity::Critical => Severity::Critical,
    };
    let mut out = r.clone();
    out.findings.retain(|f| f.severity >= floor);
    out
}

fn load_report(path: Option<&PathBuf>, out: Option<&PathBuf>, run: &str) -> Result<Report> {
    let root = repo(path);
    let base = match out {
        Some(o) => o.clone(),
        None => root.join(CONFIG_DIR),
    };
    RunStore::open(&base, run)?.read_json("report.json")
}

fn init(path: &Path, force: bool) -> Result<u8> {
    let root = path.canonicalize().map_err(|e| Error::Usage(format!("{}: {e}", path.display())))?;
    let dir = evidence_base(&root, None)?;
    let cfg = dir.join(CONFIG_FILE);
    if cfg.exists() && !force {
        return Err(Error::Usage(format!("{} already exists (use --force to overwrite)", cfg.display())));
    }
    let name = root.file_name().map_or_else(|| "project".into(), |n| n.to_string_lossy().into_owned());
    std::fs::write(&cfg, init_template(&name)).map_err(|e| Error::io(&cfg, e))?;
    let sup = dir.join("suppressions.yaml");
    if !sup.exists() {
        std::fs::write(&sup, "# Every suppression needs a reason (at least 10 characters). Suppressions are\n# reported as verification-policy changes in change mode.\nsuppressions: []\n#  - finding: SEC-103          # finding id, rule id or property id\n#    file: src/public.ts       # optional\n#    reason: >\n#      This endpoint is intentionally public.\n").map_err(|e| Error::io(&sup, e))?;
    }
    for d in ["properties", "proof-hints", "cache"] {
        let p = dir.join(d);
        if !p.exists() {
            std::fs::create_dir(&p).map_err(|e| Error::io(&p, e))?;
        }
    }
    let readme = dir.join("proof-hints").join("README.md");
    if !readme.exists() {
        std::fs::write(&readme, "Proof hints: `<theorem>.lean` files containing a Lean tactic script for a theorem\nthat Proof-It generated. Hints are UNTRUSTED: they cannot change the statement,\nare scanned for forbidden constructs, and must pass the Lean kernel and axiom audit.\n").map_err(|e| Error::io(&readme, e))?;
    }
    let gi = dir.join(".gitignore");
    if !gi.exists() {
        std::fs::write(&gi, "runs/\ncache/\n").map_err(|e| Error::io(&gi, e))?;
    }
    println!(
        "Initialised {}\n  config.yaml        project configuration (untrusted input; changes are reported)\n  suppressions.yaml  suppressions with mandatory reasons\n  properties/        project-specific properties\n  proof-hints/       untrusted Lean tactic hints\n\nNext: proof-it assure",
        dir.display()
    );
    Ok(0)
}

fn doctor(s: &Style) -> u8 {
    let mut missing_required = false;
    let mut line = |name: &str, found: Option<String>, required: bool, note: &str| {
        let ok = found.is_some();
        if !ok && required {
            missing_required = true;
        }
        println!(
            "{} {:<14} {}{}",
            if ok {
                s.green(s.ok())
            } else if required {
                s.red(s.bad())
            } else {
                s.yellow(s.warn())
            },
            name,
            found.unwrap_or_else(|| "not found".into()),
            if ok { String::new() } else { format!("  — {note}") }
        );
    };
    line(
        "lean",
        proof_it_model::lean::runner::toolchain().map(|t| t.version.clone()),
        true,
        "nothing can be PROVEN without Lean: install elan (https://github.com/leanprover/elan)",
    );
    line("bwrap", sandbox_available().then(|| "available".into()), false, "external tools and executed code run without OS isolation");
    line("node", which("node").map(|p| p.display().to_string()), false, "needed only for --allow-exec (attack/replay)");
    line("git", which("git").map(|p| p.display().to_string()), false, "needed for --diff");
    line("semgrep", which("semgrep").map(|p| p.display().to_string()), false, "Semgrep rules will not run");
    line("gitleaks", which("gitleaks").map(|p| p.display().to_string()), false, "only the built-in secret scanner will run");
    line("osv-scanner", which("osv-scanner").map(|p| p.display().to_string()), false, "dependency vulnerabilities will not be checked");
    u8::from(missing_required) * ExitCode::EnvironmentError as u8
}

fn main_inner(cli: &Cli) -> Result<u8> {
    let o = &cli.out;
    log::init(
        match o.log_level {
            LogLevel::Debug => Level::Debug,
            LogLevel::Info => Level::Info,
            LogLevel::Warn => Level::Warn,
            LogLevel::Error => Level::Error,
            LogLevel::Silent => Level::Silent,
        },
        o.json || o.ci,
    );
    let s = style(o);
    match &cli.command {
        Command::Init { path, force } => init(&repo(path.as_ref()), *force),
        Command::Scan(a) => emit(&run_pipeline("scan", a, false)?, o, a),
        Command::Verify(a) => emit(&run_pipeline("verify", a, false)?, o, a),
        Command::Attack(a) => {
            if !a.allow_exec && !a.safe {
                eprintln!("note: `attack` executes repository code only with --allow-exec; without it, only model-level counterexamples are produced.");
            }
            emit(&run_pipeline("attack", a, false)?, o, a)
        }
        Command::Test { run, mutate } => emit(&run_pipeline("test", run, *mutate)?, o, run),
        Command::Assure(a) => emit(&run_pipeline("assure", a, false)?, o, a),
        Command::Check(a) => {
            let r = run_pipeline("check", a, false)?;
            println!("{}", serde_json::to_string_pretty(&report::agent_response(&r)).unwrap_or_default());
            Ok(r.verdict.exit_code)
        }
        Command::Report { path, run, format, output, out } => {
            let r = load_report(path.as_ref(), out.as_ref(), run)?;
            let text = match format {
                Format::Terminal => report::terminal(&filtered(&r, o.min_severity), &s, o.verbose, o.quiet),
                Format::Json => serde_json::to_string_pretty(&r).unwrap_or_default(),
                Format::Markdown => report::markdown(&r),
                Format::Sarif => serde_json::to_string_pretty(&report::sarif(&r)).unwrap_or_default(),
                Format::Agent => serde_json::to_string_pretty(&report::agent_response(&r)).unwrap_or_default(),
            };
            match output {
                Some(p) => std::fs::write(p, text).map_err(|e| Error::io(p, e))?,
                None => println!("{text}"),
            }
            Ok(0)
        }
        Command::Properties { path } => {
            let root = repo(path.as_ref());
            let reg = Registry::load(root.join(CONFIG_DIR).is_dir().then_some(root.as_path()))?;
            if o.json {
                println!("{}", serde_json::to_string_pretty(&reg.properties.values().collect::<Vec<_>>()).unwrap_or_default());
                return Ok(0);
            }
            let mut cat = String::new();
            for p in reg.properties.values() {
                if p.spec.category != cat {
                    cat.clone_from(&p.spec.category);
                    println!("\n{}", s.bold(&cat));
                }
                println!(
                    "  {:<11} {:<9} {:<8} {}{}",
                    p.id(),
                    p.severity.label(),
                    if p.spec.formal.is_some() { "formal" } else { "checks" },
                    p.name(),
                    if p.source.label() != "library" { s.dim(&format!(" [{}]", p.source.label())) } else { String::new() }
                );
            }
            println!("\n{}", s.dim("formal = has a Lean model and extractor; checks = evidence from detectors only (NOT MODELED)."));
            Ok(0)
        }
        Command::Explain { id, path, run, out } => {
            let r = load_report(path.as_ref(), out.as_ref(), run)?;
            let root = repo(path.as_ref());
            let reg = Registry::load(root.join(CONFIG_DIR).is_dir().then_some(root.as_path()))?;
            match report::explain(&r, id, &s, &reg) {
                Some(t) => {
                    print!("{t}");
                    Ok(0)
                }
                None => Err(Error::Usage(format!("{id} is not a property, finding id or rule id in run {}", r.run_id))),
            }
        }
        Command::Counterexample { id, path, run, save, out } => {
            let r = load_report(path.as_ref(), out.as_ref(), run)?;
            let hits: Vec<_> = r.results.iter().filter(|x| (x.property_id.eq_ignore_ascii_case(id) || x.key() == *id) && x.counterexample.is_some()).collect();
            if hits.is_empty() {
                return Err(Error::Usage(format!("no counterexample for {id} in run {}", r.run_id)));
            }
            for x in &hits {
                let Some(cx) = &x.counterexample else {
                    continue;
                };
                if o.json {
                    println!("{}", serde_json::to_string_pretty(cx).unwrap_or_default());
                } else {
                    println!(
                        "{}\n{}\nProperty: {}\nTarget:   {}\nStatus:   {}\n",
                        s.bold("COUNTEREXAMPLE"),
                        s.dim(&s.rule()),
                        x.property_id,
                        x.target,
                        x.status().label()
                    );
                    println!("Assignment: {}", serde_json::to_string(&cx.assignment).unwrap_or_default());
                    for (i, st) in cx.steps.iter().enumerate() {
                        println!("{:>2}. {}{}", i + 1, st.action, st.location.as_ref().map(|l| format!("  ({}:{})", l.file, l.line)).unwrap_or_default());
                    }
                    println!("\nViolated: {}\nSeed: {}", cx.violated_invariant, cx.seed);
                }
                if *save {
                    let root = repo(path.as_ref()).canonicalize().map_err(|e| Error::io(path.clone().unwrap_or_default(), e))?;
                    let dir = evidence_base(&root, out.as_deref())?.join("counterexamples");
                    proof_it_core::paths::ensure_real_dir(&dir)?;
                    let src_json = format!("{}__{}.json", x.property_id, x.target);
                    let rel = format!("counterexamples/{}", proof_it_core::paths::safe_file_name(&src_json, 140));
                    let from = proof_it_core::paths::safe_join(Path::new(&r.run_dir), &rel)?;
                    let to = dir.join(proof_it_core::paths::safe_file_name(&src_json, 140));
                    if from.exists() {
                        std::fs::copy(&from, &to).map_err(|e| Error::io(&to, e))?;
                    } else {
                        std::fs::write(&to, serde_json::to_string_pretty(cx).unwrap_or_default()).map_err(|e| Error::io(&to, e))?;
                    }
                    println!("saved: {}", to.display());
                }
            }
            Ok(0)
        }
        Command::Replay { file } => {
            let text = std::fs::read_to_string(file).map_err(|e| Error::io(file, e))?;
            let cx: CounterexampleFile =
                serde_json::from_str(&text).map_err(|e| Error::Usage(format!("{}: not a counterexample file: {e}", file.display())))?;
            if cx.format != CX_FORMAT {
                return Err(Error::Usage(format!("{}: unsupported format {}", file.display(), cx.format)));
            }
            let ok = recheck(&cx).map_err(Error::Usage)?;
            println!(
                "{} model re-evaluation: the assignment {} the property",
                if ok { s.red(s.bad()) } else { s.green(s.ok()) },
                if ok { "STILL VIOLATES" } else { "no longer violates" }
            );
            if let Some(cert) = &cx.counterexample.lean_certificate {
                let cert_path = file.parent().unwrap_or(Path::new(".")).join(Path::new(cert).file_name().unwrap_or_default());
                if cert_path.exists() {
                    let thm: Vec<String> = std::fs::read_to_string(&cert_path)
                        .unwrap_or_default()
                        .lines()
                        .filter_map(|l| l.strip_prefix("#print axioms ").map(str::to_owned))
                        .collect();
                    let c = proof_it_model::lean::runner::check_file(&cert_path, &thm, std::time::Duration::from_secs(120));
                    println!("{} Lean certificate: {}", if c.accepted { s.green(s.ok()) } else { s.yellow(s.warn()) }, c.reason);
                }
            }
            println!(
                "Seed: {}  (re-run `proof-it attack --seed {} --allow-exec` to replay against the implementation)",
                cx.counterexample.seed, cx.counterexample.seed
            );
            Ok(if ok { 1 } else { 0 })
        }
        Command::History { property, path, out } => {
            let root = repo(path.as_ref());
            let base = out.clone().unwrap_or_else(|| root.join(CONFIG_DIR));
            let runs = RunStore::list(&base);
            if runs.is_empty() {
                return Err(Error::Usage("no runs recorded yet".into()));
            }
            println!("{:<22} {:<10} {:<10} PROPERTIES", "RUN", "COMMIT", "VERDICT");
            for id in runs {
                let Ok(st) = RunStore::open(&base, &id) else {
                    continue;
                };
                let Ok(r) = st.read_json::<Report>("report.json") else {
                    continue;
                };
                let rel: Vec<String> = r
                    .results
                    .iter()
                    .filter(|x| property.as_ref().is_none_or(|p| x.property_id.eq_ignore_ascii_case(p)))
                    .filter(|x| !matches!(x.status(), ProofStatus::NotApplicable | ProofStatus::NotModeled))
                    .map(|x| format!("{} {}{}", s.sym(x.status()), x.property_id, if property.is_some() { format!(" {}", x.target) } else { String::new() }))
                    .collect();
                println!(
                    "{:<22} {:<10} {:<10} {}",
                    id,
                    r.project.commit.as_deref().map_or("-", |c| &c[..c.len().min(8)]),
                    r.verdict.verdict.label().split(' ').next().unwrap_or(""),
                    rel.join("  ")
                );
            }
            Ok(0)
        }
        Command::Coverage => {
            let c = proof_it_engine::coverage::load();
            for cat in &c.catalogues {
                println!("\n{}\n{}", s.bold(&cat.name), s.dim(&s.rule()));
                for it in &cat.items {
                    let tag = match it.how.as_str() {
                        "proven" => s.green("PROVEN  "),
                        "detected" => s.green("DETECTED"),
                        "external" => s.yellow("EXTERNAL"),
                        "partial" => s.yellow("PARTIAL "),
                        _ => s.red("NONE    "),
                    };
                    println!("{tag} {:<8} {}{}", it.id, it.title, s.dim(&it.gaps.as_ref().or(it.why.as_ref()).map(|g| format!("  — {g}")).unwrap_or_default()));
                }
            }
            println!("\n{}", s.bold("Summary"));
            for (name, full, partial, total) in proof_it_engine::coverage::summary(&c) {
                println!("  {name}: {full}/{total} covered, {partial} partial, {} not covered", total - full - partial);
            }
            println!("{}", s.dim("\nPROVEN = Lean-checked for the patterns the extractor models; DETECTED = pattern/dataflow evidence;\nEXTERNAL = integrated tool; PARTIAL/NONE list their gaps. Coverage is not a guarantee of absence of bugs."));
            Ok(0)
        }
        Command::Doctor => Ok(doctor(&s)),
        Command::Version => {
            println!("proof-it {}", proof_it_core::VERSION);
            println!("lean     {}", proof_it_model::lean::runner::toolchain().map_or_else(|| "not found".to_owned(), |t| t.version.clone()));
            println!("pinned   {}", proof_it_core::property::LEAN_TOOLCHAIN.trim());
            Ok(0)
        }
    }
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    match main_inner(&cli) {
        Ok(code) => std::process::ExitCode::from(code),
        Err(e) => {
            eprintln!("proof-it: {e}");
            std::process::ExitCode::from(e.exit_code() as u8)
        }
    }
}
