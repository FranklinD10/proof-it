//! Non-security static checks: cheap, syntactic, low false-positive bug patterns.

use crate::expr::inner;
use crate::text::Source;
use oxc::ast::ast::*;
use oxc::ast_visit::{Visit, walk};
use oxc::span::{GetSpan, Span};
use oxc::syntax::operator::{AssignmentOperator, BinaryOperator, UnaryOperator};
use proof_it_core::facts::EnumFact;
use proof_it_core::types::{Confidence, Evidence, EvidenceKind, Finding, FindingSource, Severity, fingerprint};
use regex::Regex;
use std::sync::LazyLock;

/// Rule ids produced by this module.
pub const RULE_IDS: &[&str] = &[
    "STATIC-EMPTY-CATCH",
    "STATIC-SELF-COMPARE",
    "STATIC-ASSIGN-IN-CONDITION",
    "STATIC-DEAD-AUTHZ",
    "STATIC-CONSTANT-CONDITION",
    "STATIC-UNREACHABLE",
    "STATIC-ASYNC-FOREACH",
    "STATIC-SWITCH-EXHAUSTIVE",
];

static AUTH_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)authori[sz]e|authenticate|checkPermission|requireAuth|verifyToken|isAdmin|assertOwner|canAccess|hasRole|ensureAuth").expect("static regex")
});
static STATE_SUBJECT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\.(status|state|phase|stage)$").expect("static regex"));

struct C<'c, 's> {
    src: &'c Source<'s>,
    enums: &'c [EnumFact],
    out: Vec<Finding>,
}

impl C<'_, '_> {
    #[allow(clippy::too_many_arguments)]
    fn f(&mut self, rule: &str, title: &str, sev: Severity, at: Span, desc: String, rec: &str, prop: Option<&str>) {
        let location = self.src.loc(at);
        self.out.push(Finding {
            id: fingerprint(rule, Some(&location), ""),
            rule_id: rule.to_owned(),
            property_id: prop.map(str::to_owned),
            title: title.to_owned(),
            source: FindingSource::Static,
            severity: sev,
            confidence: Confidence::High,
            evidence: vec![Evidence::new(EvidenceKind::StaticPattern, location.snippet.clone().unwrap_or_default())],
            location: Some(location),
            description: desc,
            recommendation: Some(rec.to_owned()),
            cwe: vec![],
            suppressed: None,
            baseline: None,
        });
    }
}

fn constant(e: &Expression<'_>) -> Option<bool> {
    match inner(e) {
        Expression::BooleanLiteral(b) => Some(b.value),
        Expression::NumericLiteral(n) => Some(n.value != 0.0),
        Expression::UnaryExpression(u) if u.operator == UnaryOperator::LogicalNot => constant(&u.argument).map(|b| !b),
        _ => None,
    }
}

fn norm(src: &Source<'_>, e: &Expression<'_>) -> String {
    src.slice(e.span()).split_whitespace().collect::<String>().replace("?.", ".")
}

impl<'a> Visit<'a> for C<'_, '_> {
    fn visit_catch_clause(&mut self, c: &CatchClause<'a>) {
        if c.body.body.is_empty() && !self.src.slice(c.body.span).contains("//") && !self.src.slice(c.body.span).contains("/*") {
            self.f(
                "STATIC-EMPTY-CATCH",
                "Error silently swallowed",
                Severity::Low,
                c.span,
                "An empty catch block discards the error; failures (including failed authorization or persistence) become invisible.".into(),
                "Handle, log, or rethrow the error; comment why if ignoring is intended.",
                Some("CONC-002"),
            );
        }
        walk::walk_catch_clause(self, c);
    }

    fn visit_binary_expression(&mut self, b: &BinaryExpression<'a>) {
        if matches!(b.operator, BinaryOperator::StrictEquality | BinaryOperator::Equality | BinaryOperator::StrictInequality | BinaryOperator::Inequality) {
            let (l, r) = (norm(self.src, &b.left), norm(self.src, &b.right));
            if l == r
                && !matches!(
                    inner(&b.left),
                    Expression::StringLiteral(_) | Expression::NumericLiteral(_) | Expression::BooleanLiteral(_) | Expression::NullLiteral(_)
                )
            {
                let always = if matches!(b.operator, BinaryOperator::StrictEquality | BinaryOperator::Equality) { "true" } else { "false" };
                self.f(
                    "STATIC-SELF-COMPARE",
                    "Comparison of a value with itself",
                    Severity::Medium,
                    b.span,
                    format!("`{}` is always {always} (except NaN); one side is probably wrong.", self.src.short(b, 80)),
                    "Compare against the intended value (e.g. the principal id).",
                    None,
                );
            }
        }
        walk::walk_binary_expression(self, b);
    }

    fn visit_if_statement(&mut self, i: &IfStatement<'a>) {
        if let Expression::AssignmentExpression(a) = &i.test
            && a.operator == AssignmentOperator::Assign
        {
            self.f(
                "STATIC-ASSIGN-IN-CONDITION",
                "Assignment used as a condition",
                Severity::Medium,
                i.span,
                "`=` in a condition assigns instead of comparing.".into(),
                "Use === to compare.",
                None,
            );
        }
        if let Some(truth) = constant(&i.test) {
            let dead = if truth { i.alternate.as_ref().map(|a| a.span()) } else { Some(i.consequent.span()) };
            let dead_text = dead.map(|s| self.src.slice(s)).unwrap_or("");
            if AUTH_CALL.is_match(dead_text) {
                self.f(
                    "STATIC-DEAD-AUTHZ",
                    "Dead authorization branch",
                    Severity::High,
                    i.span,
                    format!("The condition is always {truth}; the branch containing an authorization check can never run."),
                    "Remove the constant condition so the check executes.",
                    Some("AUTHZ-001"),
                );
            } else if dead.is_some() {
                self.f(
                    "STATIC-CONSTANT-CONDITION",
                    "Constant condition",
                    Severity::Low,
                    i.span,
                    format!("The condition is always {truth}; one branch is dead code."),
                    "Remove the dead branch or the debugging toggle.",
                    None,
                );
            }
        }
        walk::walk_if_statement(self, i);
    }

    fn visit_block_statement(&mut self, b: &BlockStatement<'a>) {
        if let Some(idx) = b.body.iter().position(|s| matches!(s, Statement::ReturnStatement(_) | Statement::ThrowStatement(_)))
            && let Some(next) = b.body.get(idx + 1)
            && !matches!(next, Statement::FunctionDeclaration(_) | Statement::EmptyStatement(_))
        {
            let auth = AUTH_CALL.is_match(self.src.slice(next.span()));
            let kind = if matches!(b.body[idx], Statement::ReturnStatement(_)) { "return" } else { "throw" };
            self.f(
                "STATIC-UNREACHABLE",
                "Unreachable code",
                if auth { Severity::High } else { Severity::Low },
                next.span(),
                format!("This statement follows a {kind} and never runs.{}", if auth { " It contains an authorization check." } else { "" }),
                "Move the statement before the return or delete it.",
                None,
            );
        }
        walk::walk_block_statement(self, b);
    }

    fn visit_call_expression(&mut self, c: &CallExpression<'a>) {
        if let Some(m) = c.callee.get_inner_expression().as_member_expression()
            && m.static_property_name() == Some("forEach")
            && let Some(Expression::ArrowFunctionExpression(f)) = c.arguments.first().and_then(|a| a.as_expression()).map(inner)
            && f.r#async
        {
            self.f(
                "STATIC-ASYNC-FOREACH",
                "async callback in forEach",
                Severity::Medium,
                c.span,
                "forEach does not wait for async callbacks; work continues before the writes finish and errors are unhandled.".into(),
                "Use for...of with await, or Promise.all(items.map(...)).",
                Some("CONC-002"),
            );
        }
        walk::walk_call_expression(self, c);
    }

    fn visit_switch_statement(&mut self, s: &SwitchStatement<'a>) {
        let subj = norm(self.src, &s.discriminant);
        if STATE_SUBJECT.is_match(&subj) && !s.cases.iter().any(|c| c.test.is_none()) {
            let lits: Vec<String> = s
                .cases
                .iter()
                .filter_map(|c| c.test.as_ref())
                .filter_map(|t| match inner(t) {
                    Expression::StringLiteral(x) => Some(x.value.as_str().to_owned()),
                    Expression::StaticMemberExpression(m) => Some(m.property.name.as_str().to_owned()),
                    _ => None,
                })
                .collect();
            if !lits.is_empty()
                && let Some(e) = self.enums.iter().filter(|e| lits.iter().all(|l| e.members.contains(l))).min_by_key(|e| e.members.len())
            {
                let missing: Vec<&String> = e.members.iter().filter(|m| !lits.contains(m)).collect();
                if !missing.is_empty() {
                    let desc = format!(
                        "switch over {subj} handles {}/{} states of {}; missing: {}.",
                        lits.len(),
                        e.members.len(),
                        e.name,
                        missing.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                    );
                    self.f(
                        "STATIC-SWITCH-EXHAUSTIVE",
                        "Non-exhaustive state handling",
                        Severity::Low,
                        s.span,
                        desc,
                        "Handle every state or add a default that fails loudly.",
                        Some("STATE-003"),
                    );
                }
            }
        }
        walk::walk_switch_statement(self, s);
    }
}

pub fn check(program: &Program<'_>, src: &Source<'_>, enums: &[EnumFact]) -> Vec<Finding> {
    let mut c = C { src, enums, out: vec![] };
    c.visit_program(program);
    c.out
}
