//! Report renderers: terminal, Markdown, SARIF 2.1.0, the agent failure
//! protocol, `explain`, and assurance history.

use crate::change::MergeDecision;
use crate::pipeline::Report;
use proof_it_core::types::*;
use serde::Serialize;
use std::fmt::Write as _;

pub struct Style {
    pub plain: bool,
    pub color: bool,
}

impl Style {
    fn paint(&self, code: &str, s: &str) -> String {
        if self.color && !self.plain { format!("\x1b[{code}m{s}\x1b[0m") } else { s.to_owned() }
    }
    pub fn bold(&self, s: &str) -> String {
        self.paint("1", s)
    }
    pub fn dim(&self, s: &str) -> String {
        self.paint("2", s)
    }
    pub fn red(&self, s: &str) -> String {
        self.paint("31", s)
    }
    pub fn green(&self, s: &str) -> String {
        self.paint("32", s)
    }
    pub fn yellow(&self, s: &str) -> String {
        self.paint("33", s)
    }
    pub fn rule(&self) -> String {
        (if self.plain { "-" } else { "─" }).repeat(50)
    }
    pub fn sym(&self, st: ProofStatus) -> &'static str {
        match (self.plain, st) {
            (false, ProofStatus::Proven) => "✓",
            (false, ProofStatus::Violated) => "✗",
            (false, ProofStatus::Unproven) => "⚠",
            (false, ProofStatus::NotModeled) => "○",
            (false, ProofStatus::NotApplicable) => "·",
            (false, ProofStatus::Error) => "!",
            (true, ProofStatus::Proven) => "[PROVEN]",
            (true, ProofStatus::Violated) => "[VIOLATED]",
            (true, ProofStatus::Unproven) => "[UNPROVEN]",
            (true, ProofStatus::NotModeled) => "[NOT-MODELED]",
            (true, ProofStatus::NotApplicable) => "[N/A]",
            (true, ProofStatus::Error) => "[ERROR]",
        }
    }
    pub fn ok(&self) -> &'static str {
        if self.plain { "[ok]" } else { "✓" }
    }
    pub fn bad(&self) -> &'static str {
        if self.plain { "[x]" } else { "✗" }
    }
    pub fn warn(&self) -> &'static str {
        if self.plain { "[!]" } else { "⚠" }
    }
    fn status(&self, st: ProofStatus, s: &str) -> String {
        match st {
            ProofStatus::Proven => self.green(s),
            ProofStatus::Violated | ProofStatus::Error => self.red(s),
            ProofStatus::Unproven => self.yellow(s),
            _ => self.dim(s),
        }
    }
    fn sev(&self, sev: Severity, s: &str) -> String {
        match sev {
            Severity::Critical | Severity::High => self.red(s),
            Severity::Medium => self.yellow(s),
            _ => self.dim(s),
        }
    }
}

fn at(l: Option<&SourceLocation>) -> String {
    l.map(|l| format!("{}:{}", l.file, l.line)).unwrap_or_default()
}

fn section(out: &mut String, s: &Style, title: &str) {
    let _ = write!(out, "\n{}\n{}\n", s.bold(title), s.dim(&s.rule()));
}

pub fn terminal(r: &Report, s: &Style, verbose: bool, quiet: bool) -> String {
    let mut o = String::new();
    let v = &r.verdict;
    let count = |k: &str| v.counts.get(k).copied().unwrap_or(0);
    let sev = |k: &str| v.severities.get(k).copied().unwrap_or(0);
    if quiet {
        let _ = writeln!(
            o,
            "ASSURANCE: {}  proven={} violated={} unproven={} critical={} high={} level={} run={}",
            v.verdict.label(),
            count("PROVEN"),
            count("VIOLATED"),
            count("UNPROVEN"),
            sev("CRITICAL"),
            sev("HIGH"),
            r.assurance_level.level,
            r.run_id
        );
        if let Some(c) = &r.change {
            let _ = writeln!(o, "MERGE POLICY: {}", c.merge.decision.label());
        }
        for x in &v.reasons {
            let _ = writeln!(o, "  - {x}");
        }
        return o;
    }
    let _ = writeln!(o, "{}{}", s.bold("PROOF-IT"), s.dim(&format!(" v{}", r.environment.proof_it)));
    let _ = writeln!(o, "{}", s.dim(&s.rule()));
    let _ = writeln!(o, "Project:   {}", r.project.name);
    let langs: Vec<String> = r.project.languages.iter().map(|(k, n)| format!("{k} ({n})")).collect();
    let _ = writeln!(o, "Languages: {}", if langs.is_empty() { "none detected".into() } else { langs.join(", ") });
    let _ = writeln!(
        o,
        "Commit:    {}{}",
        r.project.commit.as_deref().map_or("unknown", |c| &c[..c.len().min(12)]),
        r.project.branch.as_ref().map(|b| format!(" ({b})")).unwrap_or_default()
    );
    let _ = writeln!(
        o,
        "Analysed:  {} file(s), {} function(s){}",
        r.project.files,
        r.project.functions,
        if r.project.parse_errors.is_empty() { String::new() } else { format!(", {} parse error(s)", r.project.parse_errors.len()) }
    );
    let _ = writeln!(o, "Lean:      {}", r.environment.lean.clone().unwrap_or_else(|| s.yellow("not installed — nothing can be PROVEN")));
    let _ = writeln!(o, "Seed:      {}{}", r.seed, if r.options.get("safe").and_then(|x| x.as_bool()) == Some(true) { "   mode: --safe" } else { "" });
    if let Some(p) = &r.org_policy.source {
        let _ = writeln!(
            o,
            "Policy:    {p} ({} protected propert{})",
            r.org_policy.protected_properties.len(),
            if r.org_policy.protected_properties.len() == 1 { "y" } else { "ies" }
        );
    }

    if let Some(c) = &r.change {
        section(&mut o, s, "CHANGE");
        let _ = writeln!(
            o,
            "Range:               {}{}",
            c.range,
            c.agent.as_ref().map(|a| format!("   (author: {a} — claims are not evidence)")).unwrap_or_default()
        );
        let _ = writeln!(o, "Files changed:       {} ({} code, {} verification-policy)", c.changed_files.len(), c.code_files.len(), c.policy_files.len());
        let _ = writeln!(o, "Affected modules:    {} (via import graph)", c.affected_modules.len());
        let _ = writeln!(o, "Affected properties: {}", if c.affected_properties.is_empty() { "none".into() } else { c.affected_properties.join(", ") });
        for p in &c.policy_changes {
            let _ = writeln!(o, "  {} {}policy change: {}", s.yellow(s.warn()), if p.protected { s.red("PROTECTED ") } else { String::new() }, p.what);
        }
    }

    let ran = |n: &str| r.stages.iter().find(|x| x.name == n);
    if ran("static").is_some() {
        section(&mut o, s, "STATIC ANALYSIS");
        let fs: Vec<&Finding> = r.findings.iter().filter(|f| f.source == FindingSource::Static && f.suppressed.is_none()).collect();
        if fs.is_empty() {
            let _ = writeln!(o, "{} No static-analysis findings", s.green(s.ok()));
        }
        for f in fs.iter().take(if verbose { usize::MAX } else { 12 }) {
            let _ = writeln!(
                o,
                "{} {:<26} {} {}",
                s.sev(f.severity, if f.severity >= Severity::High { s.bad() } else { s.warn() }),
                f.rule_id,
                f.title,
                s.dim(&at(f.location.as_ref()))
            );
        }
        if !verbose && fs.len() > 12 {
            let _ = writeln!(o, "{}", s.dim(&format!("  … {} more (use --verbose or proof-it report)", fs.len() - 12)));
        }
    }
    let sec_stages: Vec<&StageRun> = ["security", "secrets", "semgrep", "gitleaks", "osv-scanner"].iter().filter_map(|n| ran(n)).collect();
    if !sec_stages.is_empty() {
        section(&mut o, s, "SECURITY ANALYSIS");
        for st in sec_stages.iter().filter(|x| x.status != StageStatus::Ran) {
            let _ = writeln!(o, "{} {}: {}", s.dim("○"), st.name, s.dim(&format!("{:?} — {}", st.status, st.detail.clone().unwrap_or_default())));
        }
        let mut fs: Vec<&Finding> = r
            .findings
            .iter()
            .filter(|f| {
                matches!(f.source, FindingSource::Security | FindingSource::Secrets | FindingSource::Dependencies | FindingSource::External)
                    && f.suppressed.is_none()
            })
            .collect();
        fs.sort_by_key(|f| std::cmp::Reverse(f.severity));
        if fs.is_empty() {
            let _ = writeln!(o, "{} No security findings from the analyzers that ran", s.green(s.ok()));
        }
        let shown = if verbose { fs.len() } else { fs.len().min(15) };
        for f in &fs[..shown] {
            let _ = writeln!(
                o,
                "{} {} {:<26} {} {}{}",
                s.sev(f.severity, if f.severity >= Severity::High { s.bad() } else { s.warn() }),
                s.sev(f.severity, &format!("{:<8}", f.severity.label())),
                f.rule_id,
                f.title,
                s.dim(&at(f.location.as_ref())),
                if f.baseline == Some(BaselineState::Existing) { s.dim(" (inherited)") } else { String::new() }
            );
        }
        if fs.len() > shown {
            let _ = writeln!(o, "{}", s.dim(&format!("  … {} more (use --verbose or proof-it report)", fs.len() - shown)));
        }
        let sup = r.findings.iter().filter(|f| f.suppressed.is_some()).count();
        if sup > 0 {
            let _ = writeln!(o, "{}", s.dim(&format!("  {sup} finding(s) suppressed with a recorded reason")));
        }
    }
    if ran("formal").is_some() {
        section(&mut o, s, "FORMAL VERIFICATION");
        let shown: Vec<&PropertyResult> =
            r.results.iter().filter(|x| verbose || !matches!(x.status(), ProofStatus::NotApplicable | ProofStatus::NotModeled)).collect();
        let width = shown.iter().map(|x| x.target.chars().count()).max().unwrap_or(10).clamp(10, 64);
        for x in &shown {
            let tag = match x.spec_source {
                SpecSource::Inferred => s.dim(" [inferred spec]"),
                SpecSource::AiGenerated => s.yellow(" [AI-generated spec]"),
                _ => String::new(),
            };
            let hint = if x.quality.as_ref().is_some_and(|q| q.proof_from_hint) { s.dim(" [proof hint]") } else { String::new() };
            let sup = if x.suppressed.is_some() { s.dim(" [suppressed]") } else { String::new() };
            let target: String = x.target.chars().take(width).collect();
            let _ = writeln!(
                o,
                "{} {:<10} {:<width$} {}{tag}{hint}{sup}",
                s.status(x.status(), s.sym(x.status())),
                x.property_id,
                target,
                s.status(x.status(), x.status().label())
            );
            if !matches!(x.status(), ProofStatus::Proven | ProofStatus::NotApplicable | ProofStatus::NotModeled) {
                let reason: String = x.reason.chars().take(220).collect();
                let _ = writeln!(o, "    {}", s.dim(&reason));
            }
        }
        let nm = r.results.iter().filter(|x| x.status() == ProofStatus::NotModeled).count();
        let na = r.results.iter().filter(|x| x.status() == ProofStatus::NotApplicable).count();
        if !verbose && nm + na > 0 {
            let _ = writeln!(o, "{}", s.dim(&format!("  {nm} property(ies) not modeled, {na} not applicable (--verbose to list)")));
        }
        let _ = writeln!(o, "{}", s.dim(&format!("  Highest formalization level reached: {} (docs/formal-verification.md)", r.max_formalization_level)));
    }
    if ran("attack").is_some() || ran("selfcheck").is_some() || r.mutation.is_some() {
        section(&mut o, s, "ADVERSARIAL / SELF-TESTING");
        if let Some(a) = ran("attack") {
            let _ = writeln!(
                o,
                "{} attack: {:?} — {}",
                if a.status == StageStatus::Ran { s.green(s.ok()) } else { s.dim("○") },
                a.status,
                a.detail.clone().unwrap_or_default()
            );
        }
        if let Some(sc) = ran("selfcheck") {
            let _ = writeln!(o, "{} model self-check: {}", s.green(s.ok()), sc.detail.clone().unwrap_or_default());
        }
        if let Some(m) = &r.mutation {
            let _ = writeln!(
                o,
                "{} mutation: {}/{} injected bug(s) detected{}",
                if m.survived == 0 { s.green(s.ok()) } else { s.yellow(s.warn()) },
                m.killed,
                m.total,
                m.score.map(|x| format!(" (score {:.0}%)", x * 100.0)).unwrap_or_default()
            );
            for x in m.mutants.iter().filter(|x| !x.killed).take(if verbose { 100 } else { 5 }) {
                let _ = writeln!(o, "{}", s.dim(&format!("    survived: {} at {}:{} — {}", x.operator, x.location.file, x.location.line, x.description)));
            }
        }
    }
    let worst = r
        .results
        .iter()
        .filter(|x| x.status() == ProofStatus::Violated && x.counterexample.is_some() && x.suppressed.is_none())
        .max_by_key(|x| (x.spec_source.is_authoritative(), x.severity));
    if let Some(w) = worst {
        section(&mut o, s, &format!("{} COUNTEREXAMPLE", w.severity.label()));
        let _ = writeln!(o, "Property: {} — {}", w.property_id, w.property_name);
        let _ = writeln!(o, "Target:   {}\n", w.target);
        if let Some(cx) = &w.counterexample {
            for (i, st) in cx.steps.iter().enumerate() {
                let _ = writeln!(
                    o,
                    "{:>2}. {}{}",
                    i + 1,
                    st.action,
                    st.location.as_ref().map(|l| s.dim(&format!("  ({}:{})", l.file, l.line))).unwrap_or_default()
                );
            }
            if let Some(rp) = cx.replay.as_ref().filter(|x| x.attempted) {
                let what = match rp.reproduced {
                    Some(true) => "REPRODUCED",
                    Some(false) => "not reproduced",
                    None => "could not run",
                };
                let _ = writeln!(
                    o,
                    "{}",
                    s.dim(&format!("\n   Replay against the implementation: {what} — {}", rp.observed.clone().unwrap_or_else(|| rp.reason.clone())))
                );
            }
            if let Some(c) = &cx.lean_certificate {
                let _ = writeln!(o, "{}", s.dim(&format!("   Lean-certified in the model: {c}")));
            }
        }
    }
    if let Some(c) = &r.change {
        section(&mut o, s, "REGRESSION");
        match &c.baseline {
            None => {
                let _ = writeln!(o, "{}", s.dim("No baseline run: regressions cannot be established (pass --baseline <run-id|latest>)."));
            }
            Some(b) if c.regressions.is_empty() => {
                let _ = writeln!(o, "{} All previously proven properties are still proven (baseline {b})", s.green(s.ok()));
            }
            Some(_) => {
                for g in &c.regressions {
                    let _ = writeln!(o, "{} REGRESSION {} {}: {} → {}", s.red(s.bad()), g.property_id, g.target, g.before, g.after);
                }
            }
        }
    }
    let d = &r.proof_debt;
    if d.critical_unproven + d.high_unproven + d.not_modeled > 0 {
        section(&mut o, s, "PROOF DEBT");
        let _ = writeln!(
            o,
            "Critical unproven: {}   High unproven: {}   Not modeled: {}   (proven {}/{} applicable)",
            d.critical_unproven, d.high_unproven, d.not_modeled, d.proven, d.total_applicable
        );
    }
    let _ = writeln!(o, "\n{}", s.dim(&s.rule()));
    let vc = match v.verdict {
        AssuranceVerdict::Passed => s.green(v.verdict.label()),
        AssuranceVerdict::Failed | AssuranceVerdict::Incomplete => s.red(v.verdict.label()),
        AssuranceVerdict::PassedWithWarnings => s.yellow(v.verdict.label()),
    };
    let _ = writeln!(o, "{}\n", s.bold(&format!("ASSURANCE: {vc}")));
    if !v.gaps.is_empty() {
        let _ = writeln!(o, "{}", s.red(&format!("NOT ANALYSED ({} source file(s)) — no result covers this code:", v.gaps.len())));
        for g in v.gaps.iter().take(if verbose { usize::MAX } else { 10 }) {
            let _ = writeln!(o, "  - {g}");
        }
        if v.gaps.len() > 10 && !verbose {
            let _ = writeln!(o, "{}", s.dim(&format!("  … {} more (--verbose)", v.gaps.len() - 10)));
        }
        let _ = writeln!(o);
    }
    for (k, label) in
        [("PROVEN", "Proven"), ("VIOLATED", "Violated"), ("UNPROVEN", "Unproven"), ("NOT_MODELED", "Not modeled"), ("NOT_APPLICABLE", "Not applicable")]
    {
        let n = v.counts.get(k).or_else(|| v.counts.get(&k.replace('_', " "))).copied().unwrap_or(0);
        let _ = writeln!(o, "{:<16}{n}", format!("{label}:"));
    }
    if count("ERROR") > 0 {
        let _ = writeln!(o, "Errors:         {}", count("ERROR"));
    }
    let _ = writeln!(o, "Findings:       {} critical, {} high, {} medium, {} low", sev("CRITICAL"), sev("HIGH"), sev("MEDIUM"), sev("LOW"));
    let _ = writeln!(
        o,
        "Assurance level: {} — {}{}",
        r.assurance_level.level,
        r.assurance_level.label,
        r.assurance_level.next.as_ref().map(|n| s.dim(&format!(" (next: {n})"))).unwrap_or_default()
    );
    if let Some(c) = &r.change {
        let m = &c.merge;
        let col = match m.decision {
            MergeDecision::AutoMergeEligible => s.green(m.decision.label()),
            MergeDecision::Blocked => s.red(m.decision.label()),
            MergeDecision::HumanReviewRequired => s.yellow(m.decision.label()),
        };
        let _ = writeln!(o, "\nMerge policy: {}", s.bold(&col));
        for why in m.reasons.iter().take(if verbose { usize::MAX } else { 8 }) {
            let _ = writeln!(o, "{}", s.dim(&format!("  - {why}")));
        }
    }
    if !v.reasons.is_empty() {
        let _ = writeln!(o, "\n{}", s.red("Failed because:"));
        for x in v.reasons.iter().take(10) {
            let _ = writeln!(o, "  - {x}");
        }
        if v.reasons.len() > 10 {
            let _ = writeln!(o, "  … {} more", v.reasons.len() - 10);
        }
    }
    let _ = writeln!(o, "{}", s.dim("\nA PROVEN result means the stated property holds for the extracted model under the listed\nassumptions, checked by the Lean kernel. It is not a claim that the program is bug-free."));
    let _ = writeln!(o, "{}", s.dim(&format!("\nEvidence: {}", r.run_dir)));
    let first = r
        .results
        .iter()
        .find(|x| x.status() == ProofStatus::Violated && x.suppressed.is_none())
        .map(|x| x.property_id.clone())
        .or_else(|| r.findings.iter().find(|f| f.suppressed.is_none() && f.severity >= Severity::High).map(|f| f.id.clone()));
    if let Some(id) = first {
        let _ = writeln!(o, "\nRun:\n\n  proof-it explain {id}\n\nto inspect it.");
    }
    o
}

pub fn markdown(r: &Report) -> String {
    let esc = |s: &str| s.replace('|', "\\|").replace('\n', " ");
    let mut o = String::new();
    let _ = writeln!(o, "# Proof-It assurance report\n");
    let _ = writeln!(
        o,
        "**Verdict: {}**{} · Assurance level {} ({})\n",
        r.verdict.verdict.label(),
        r.change.as_ref().map(|c| format!(" · Merge policy: **{}**", c.merge.decision.label())).unwrap_or_default(),
        r.assurance_level.level,
        r.assurance_level.label
    );
    let _ = writeln!(
        o,
        "| | |\n|---|---|\n| Project | {} |\n| Commit | `{}` |\n| Proof-It | {} |\n| Lean | {} |\n| Seed | {} |\n| Run | `{}` |\n",
        esc(&r.project.name),
        r.project.commit.as_deref().map_or("unknown", |c| &c[..c.len().min(12)]),
        r.environment.proof_it,
        r.environment.lean.clone().unwrap_or_else(|| "not installed".into()),
        r.seed,
        r.run_id
    );
    if let Some(c) = &r.change {
        let _ = writeln!(
            o,
            "## Change\n\n- Range: `{}` — {} file(s) changed, {} module(s) affected\n- Affected properties: {}",
            c.range,
            c.changed_files.len(),
            c.affected_modules.len(),
            if c.affected_properties.is_empty() { "none".into() } else { c.affected_properties.join(", ") }
        );
        for p in &c.policy_changes {
            let _ = writeln!(o, "- ⚠️ Verification-policy change{}: {}", if p.protected { " (PROTECTED)" } else { "" }, esc(&p.what));
        }
        if !c.regressions.is_empty() {
            let _ = writeln!(o, "\n### Regressions");
            for g in &c.regressions {
                let _ = writeln!(o, "- ❌ **{}** {}: {} → {}", g.property_id, esc(&g.target), g.before, g.after);
            }
        }
        let _ = writeln!(o, "\n**Merge decision: {}**", c.merge.decision.label());
        for w in &c.merge.reasons {
            let _ = writeln!(o, "- {}", esc(w));
        }
        let _ = writeln!(o);
    }
    let _ = writeln!(o, "## Properties\n\n| Status | Property | Target | Spec source | Evidence |\n|---|---|---|---|---|");
    for x in r.results.iter().filter(|x| x.status() != ProofStatus::NotApplicable) {
        let icon = match x.status() {
            ProofStatus::Proven => "✅",
            ProofStatus::Violated => "❌",
            ProofStatus::Unproven => "⚠️",
            ProofStatus::NotModeled => "⚪",
            ProofStatus::NotApplicable => "➖",
            ProofStatus::Error => "❗",
        };
        let mut kinds: Vec<String> =
            x.evidence.iter().map(|e| serde_json::to_value(e.kind).ok().and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_default()).collect();
        kinds.dedup();
        let _ = writeln!(
            o,
            "| {icon} {} | {} {} | {} | {} | {} |",
            x.status().label(),
            x.property_id,
            esc(&x.property_name),
            esc(&x.target),
            x.spec_source.label(),
            if kinds.is_empty() { "—".into() } else { kinds.join(", ") }
        );
    }
    let cx: Vec<&PropertyResult> = r.results.iter().filter(|x| x.status() == ProofStatus::Violated && x.counterexample.is_some()).collect();
    if !cx.is_empty() {
        let _ = writeln!(o, "\n## Counterexamples");
        for x in cx {
            let _ = writeln!(o, "\n### {} — {}", x.property_id, esc(&x.target));
            for (i, st) in x.counterexample.iter().flat_map(|c| &c.steps).enumerate() {
                let _ =
                    writeln!(o, "{}. {}{}", i + 1, esc(&st.action), st.location.as_ref().map(|l| format!(" (`{}:{}`)", l.file, l.line)).unwrap_or_default());
            }
        }
    }
    let fs: Vec<&Finding> = r.findings.iter().filter(|f| f.suppressed.is_none()).collect();
    let _ = writeln!(o, "\n## Findings ({})", fs.len());
    if !fs.is_empty() {
        let _ = writeln!(o, "\n| Severity | Rule | Location | Description |\n|---|---|---|---|");
        for f in fs {
            let desc: String = esc(&f.description).chars().take(200).collect();
            let _ = writeln!(
                o,
                "| {} | {} | {} | {desc} |",
                f.severity.label(),
                f.rule_id,
                f.location.as_ref().map(|l| format!("`{}:{}`", l.file, l.line)).unwrap_or_default()
            );
        }
    }
    let _ = writeln!(o, "\n## Stages");
    for st in &r.stages {
        let _ = writeln!(
            o,
            "- **{}**: {:?}{}{}",
            st.name,
            st.status,
            st.detail.as_ref().map(|d| format!(" — {}", esc(d))).unwrap_or_default(),
            st.version.as_ref().map(|v| format!(" ({v})")).unwrap_or_default()
        );
    }
    let _ = writeln!(
        o,
        "\n> A PROVEN result means the stated property holds for the extracted model under the listed assumptions; it is not a claim that the program is bug-free. UNPROVEN is not evidence of a bug."
    );
    o
}

pub fn sarif(r: &Report) -> serde_json::Value {
    let level = |s: Severity| match s {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        _ => "note",
    };
    let loc = |l: Option<&SourceLocation>| match l {
        Some(l) => {
            serde_json::json!([{ "physicalLocation": { "artifactLocation": { "uri": l.file, "uriBaseId": "%SRCROOT%" }, "region": { "startLine": l.line.max(1) } } }])
        }
        None => serde_json::json!([]),
    };
    let mut rules: std::collections::BTreeMap<String, serde_json::Value> = Default::default();
    let mut results = Vec::new();
    for f in &r.findings {
        rules.entry(f.rule_id.clone()).or_insert_with(|| serde_json::json!({ "id": f.rule_id, "name": f.rule_id.replace(|c: char| !c.is_alphanumeric(), ""), "shortDescription": { "text": f.title }, "help": { "text": f.recommendation.clone().unwrap_or_default() }, "properties": { "tags": std::iter::once("security".to_owned()).chain(f.cwe.iter().cloned()).collect::<Vec<_>>(), "security-severity": match f.severity { Severity::Critical => "9.5", Severity::High => "8.0", Severity::Medium => "5.5", Severity::Low => "3.0", Severity::Info => "1.0" } } }));
        let mut res = serde_json::json!({ "ruleId": f.rule_id, "level": level(f.severity), "message": { "text": f.description }, "locations": loc(f.location.as_ref()), "partialFingerprints": { "proofItFinding": f.id }, "properties": { "source": f.source, "confidence": f.confidence, "severity": f.severity } });
        if let Some(reason) = &f.suppressed {
            res["suppressions"] = serde_json::json!([{ "kind": "external", "justification": reason }]);
        }
        results.push(res);
    }
    for x in r.results.iter().filter(|x| matches!(x.status(), ProofStatus::Violated | ProofStatus::Unproven)) {
        rules.entry(x.property_id.clone()).or_insert_with(|| serde_json::json!({ "id": x.property_id, "name": x.property_id.replace('-', ""), "shortDescription": { "text": x.property_name }, "help": { "text": x.recommendation.clone().unwrap_or_default() }, "properties": { "tags": ["proof-it-property"] } }));
        results.push(serde_json::json!({ "ruleId": x.property_id, "level": if x.status() == ProofStatus::Violated { level(x.severity) } else { "note" }, "message": { "text": format!("{} {} at {}: {}", x.property_id, x.status().label(), x.target, x.reason) }, "locations": loc(x.location.as_ref()), "partialFingerprints": { "proofItProperty": x.key() }, "properties": { "status": x.status(), "specSource": x.spec_source, "assumptions": x.assumptions } }));
    }
    serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{ "tool": { "driver": { "name": "proof-it", "version": r.environment.proof_it, "rules": rules.into_values().collect::<Vec<_>>() } }, "automationDetails": { "id": format!("proof-it/{}", r.run_id) }, "results": results, "properties": { "verdict": r.verdict.verdict, "seed": r.seed, "commit": r.project.commit } }]
    })
}

/// Structured failures for AI coding agents: one entry per actionable problem.
#[derive(Debug, Serialize)]
pub struct AgentFailure {
    pub kind: &'static str,
    pub status: String,
    pub id: String,
    pub property: Option<String>,
    pub severity: Severity,
    pub reason: String,
    pub source: Option<SourceLocation>,
    pub counterexample: Option<serde_json::Value>,
    pub assumptions: Vec<String>,
    pub spec_source: Option<SpecSource>,
    pub recommended_action: String,
    pub explain: String,
}

#[derive(Debug, Serialize)]
pub struct AgentResponse {
    pub protocol: &'static str,
    pub status: &'static str,
    pub verdict: AssuranceVerdict,
    pub merge_decision: Option<MergeDecision>,
    pub assurance_level: u8,
    pub run_id: String,
    pub failures: Vec<AgentFailure>,
    pub note: &'static str,
}

pub fn agent_response(r: &Report) -> AgentResponse {
    let mut failures = Vec::new();
    for x in r.results.iter().filter(|x| x.suppressed.is_none() && matches!(x.status(), ProofStatus::Violated | ProofStatus::Unproven | ProofStatus::Error)) {
        let action = match x.status() {
            ProofStatus::Violated => x.recommendation.clone().unwrap_or_else(|| "Fix the code path shown in the counterexample.".into()),
            ProofStatus::Unproven => "Make the deciding check analysable (inline it, or ask a human to declare the guard in config) or supply a proof hint for the generated theorem. UNPROVEN is not a bug report.".into(),
            _ => "Proof-It failed on this target; report it.".into(),
        };
        failures.push(AgentFailure {
            kind: "property",
            status: x.status().label().to_ascii_lowercase(),
            id: x.key(),
            property: Some(x.property_id.clone()),
            severity: x.severity,
            reason: x.reason.clone(),
            source: x.location.clone(),
            counterexample: x.counterexample.as_ref().map(|c| serde_json::json!({ "assignment": c.assignment, "steps": c.steps.iter().map(|s| format!("{}{}", s.action, s.location.as_ref().map(|l| format!(" ({}:{})", l.file, l.line)).unwrap_or_default())).collect::<Vec<_>>(), "reproduced_against_code": c.replay.as_ref().and_then(|r| r.reproduced), "lean_certificate": c.lean_certificate })),
            assumptions: x.assumptions.clone(),
            spec_source: Some(x.spec_source),
            recommended_action: action,
            explain: format!("proof-it explain {}", x.property_id),
        });
    }
    for f in r.findings.iter().filter(|f| f.suppressed.is_none() && f.severity >= Severity::High) {
        failures.push(AgentFailure {
            kind: "finding",
            status: "finding".into(),
            id: f.id.clone(),
            property: f.property_id.clone(),
            severity: f.severity,
            reason: f.description.clone(),
            source: f.location.clone(),
            counterexample: None,
            assumptions: vec![],
            spec_source: None,
            recommended_action: f.recommendation.clone().unwrap_or_default(),
            explain: format!("proof-it explain {}", f.id),
        });
    }
    if let Some(c) = &r.change {
        for g in &c.regressions {
            failures.push(AgentFailure {
                kind: "regression",
                status: "regression".into(),
                id: format!("{}::{}", g.property_id, g.target),
                property: Some(g.property_id.clone()),
                severity: g.severity,
                reason: format!("previously {}, now {}", g.before, g.after),
                source: None,
                counterexample: None,
                assumptions: vec![],
                spec_source: None,
                recommended_action: "Restore the invariant; the change broke a previously established property.".into(),
                explain: format!("proof-it explain {}", g.property_id),
            });
        }
        for p in &c.policy_changes {
            failures.push(AgentFailure {
                kind: "policy",
                status: "policy-change".into(),
                id: p.what.clone(),
                property: None,
                severity: if p.protected { Severity::Critical } else { Severity::High },
                reason: p.what.clone(),
                source: None,
                counterexample: None,
                assumptions: vec![],
                spec_source: None,
                recommended_action: "Verification-policy changes require human authority; revert them instead of weakening the specification.".into(),
                explain: "proof-it explain --policy".into(),
            });
        }
    }
    AgentResponse {
        protocol: "proof-it/agent@1",
        status: match r.verdict.verdict {
            AssuranceVerdict::Failed => "failed",
            AssuranceVerdict::Incomplete => "incomplete",
            _ => "passed",
        },
        verdict: r.verdict.verdict,
        merge_decision: r.change.as_ref().map(|c| c.merge.decision),
        assurance_level: r.assurance_level.level,
        run_id: r.run_id.clone(),
        failures,
        note: "Only Proof-It's pipeline can mark a property PROVEN. Agent claims are not evidence.",
    }
}

/// `proof-it explain <id>`: property id, finding id or rule id.
pub fn explain(r: &Report, id: &str, s: &Style, registry: &proof_it_core::property::Registry) -> Option<String> {
    let mut o = String::new();
    let results: Vec<&PropertyResult> = r.results.iter().filter(|x| x.property_id.eq_ignore_ascii_case(id)).collect();
    if let Some(p) = registry.get(id) {
        let _ = writeln!(o, "{}\n{}", s.bold(&format!("{} — {}", p.id(), p.name())), s.dim(&s.rule()));
        let _ = writeln!(
            o,
            "Severity: {}   Category: {}   Source: {}{}",
            p.severity,
            p.spec.category,
            p.source.label(),
            if r.org_policy.protected_properties.iter().any(|x| x.eq_ignore_ascii_case(id)) { "   PROTECTED" } else { "" }
        );
        let _ = writeln!(o, "\n1. WHAT IS THE PROPERTY?\n   {}", p.spec.description);
        let _ = writeln!(o, "\n2. WHY DOES IT MATTER?\n   {}", if p.spec.rationale.is_empty() { "—" } else { &p.spec.rationale });
        if let Some(t) = &p.spec.threat_model {
            let _ = writeln!(o, "   Threat model: {} with capabilities [{}] trying to {}.", t.actor, t.capabilities.join(", "), t.goal);
        }
        if results.is_empty() {
            let _ = writeln!(o, "\n3. WHAT DID PROOF-IT ANALYSE?\n   Not evaluated in run {}.", r.run_id);
        }
        for x in &results {
            let _ = writeln!(
                o,
                "\n{}",
                s.bold(&format!("── {} — {} {}", x.target, s.status(x.status(), s.sym(x.status())), s.status(x.status(), x.status().label())))
            );
            let _ = writeln!(
                o,
                "\n3. WHAT DID PROOF-IT ANALYSE?\n   Target {} {}; specification source: {}.",
                x.target,
                x.location.as_ref().map(|l| format!("at {l}")).unwrap_or_default(),
                x.spec_source.label()
            );
            if let Some(t) = &x.theorem {
                let _ = writeln!(o, "   Theorem: {t}");
            }
            let _ = writeln!(o, "\n4. WHAT EVIDENCE EXISTS?");
            if x.evidence.is_empty() {
                let _ = writeln!(o, "   none");
            }
            for e in &x.evidence {
                let _ = writeln!(
                    o,
                    "   - [{}] {}{}",
                    serde_json::to_value(e.kind).ok().and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_default(),
                    e.summary,
                    e.artifact.as_ref().map(|a| format!("  ({}/{a})", r.run_dir)).unwrap_or_default()
                );
            }
            let _ = writeln!(o, "\n5. WHAT IS ASSUMED?");
            for a in &x.assumptions {
                let _ = writeln!(o, "   - {a}");
            }
            if let Some(q) = &x.quality
                && x.status() != ProofStatus::Proven
            {
                // The theorem was attempted and refused; a failed tactic shows up as `sorryAx`.
                let _ = writeln!(
                    o,
                    "   Proof attempt: not accepted by the Lean kernel{} (expected when the property does not hold or could not be proven in the model).",
                    if q.extra_axioms.is_empty() { String::new() } else { format!("; failed proof reported [{}]", q.extra_axioms.join(", ")) }
                );
            } else if let Some(q) = &x.quality {
                let _ = writeln!(
                    o,
                    "   Proof quality: kernel-checked={} axioms=[{}] extra-axioms=[{}] non-vacuity={:?} unverified-translation={} opaque-predicates={}{}",
                    q.kernel_checked,
                    q.axioms.join(", "),
                    q.extra_axioms.join(", "),
                    q.non_vacuity,
                    q.unverified_translation,
                    q.opaque_predicates.len(),
                    if q.proof_from_hint { " proof-script-from-untrusted-hint" } else { "" }
                );
            }
            let _ = writeln!(o, "\n6. WHY {}?", x.status().label());
            let why = match x.status() {
                ProofStatus::Proven => format!(
                    "The implementation was abstracted into a model; the theorem states the property for that model; the Lean kernel accepted the proof under the assumptions above, and a concrete state satisfying the hypotheses exists (non-vacuous). {}",
                    x.reason
                ),
                ProofStatus::Violated => format!(
                    "A concrete assignment satisfies every hypothesis and falsifies the property for every value of every unanalysed condition. {}",
                    x.reason
                ),
                ProofStatus::Unproven => format!("No proof and no robust counterexample. Do NOT interpret this as a bug. {}", x.reason),
                _ => x.reason.clone(),
            };
            let _ = writeln!(o, "   {why}");
            if let Some(cx) = &x.counterexample {
                let _ = writeln!(o, "\n7. WHAT SOURCE CODE CAUSED THE RESULT?");
                for (i, st) in cx.steps.iter().enumerate() {
                    let _ =
                        writeln!(o, "   {:>2}. {}{}", i + 1, st.action, st.location.as_ref().map(|l| format!("  ({}:{})", l.file, l.line)).unwrap_or_default());
                }
            }
            let _ = writeln!(o, "\n8. WHAT SHOULD THE DEVELOPER DO?\n   {}", x.recommendation.clone().unwrap_or_else(|| p.spec.recommendation.clone()));
        }
        let rel: Vec<&Finding> = r.findings.iter().filter(|f| f.property_id.as_deref().is_some_and(|x| x.eq_ignore_ascii_case(id))).collect();
        if !rel.is_empty() {
            let _ = writeln!(o, "\nRelated non-formal findings ({}):", rel.len());
            for f in rel.iter().take(20) {
                let _ = writeln!(o, "  {} {} {} {}", f.severity.label(), f.rule_id, f.title, at(f.location.as_ref()));
            }
        }
        return Some(o);
    }
    let f = r.findings.iter().find(|f| f.id == id || f.rule_id.eq_ignore_ascii_case(id))?;
    let _ = writeln!(o, "{}\n{}", s.bold(&format!("{} — {}", f.rule_id, f.title)), s.dim(&s.rule()));
    let _ = writeln!(
        o,
        "Finding id: {}\nSeverity: {}   Confidence: {:?}   Source: {:?}\nLocation: {}\n",
        f.id,
        f.severity,
        f.confidence,
        f.source,
        at(f.location.as_ref())
    );
    let _ = writeln!(o, "{}\n", f.description);
    if let Some(snip) = f.location.as_ref().and_then(|l| l.snippet.as_ref()) {
        let _ = writeln!(o, "    {snip}\n");
    }
    for e in &f.evidence {
        let _ = writeln!(o, "Evidence: {}", e.summary);
    }
    if !f.cwe.is_empty() {
        let _ = writeln!(o, "CWE: {}", f.cwe.join(", "));
    }
    let _ = writeln!(o, "\nRecommendation: {}", f.recommendation.clone().unwrap_or_default());
    let _ = writeln!(o, "{}", s.dim("\nThis is a non-formal finding (pattern/dataflow/tool evidence), not a proof. Suppress it with a reason in .proof-it/suppressions.yaml if it is intended."));
    Some(o)
}
