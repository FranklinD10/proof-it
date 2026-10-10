//! Mutation operators: small, known bug classes injected to measure whether
//! Proof-It notices them (mutation testing of the assurance system itself).

use crate::text::Source;
use crate::walker::exits;
use oxc::ast::ast::*;
use oxc::ast_visit::{Visit, walk};
use oxc::span::GetSpan;
use oxc::syntax::operator::{BinaryOperator, LogicalOperator};
use proof_it_core::facts::Mutant;
use regex::Regex;
use std::sync::LazyLock;

static CHECK_CALL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)assert|ensure|check|verify|authori[sz]e|require|guard").expect("static regex"));

struct M<'c, 's, 'l> {
    src: &'c Source<'s>,
    lines: &'l dyn Fn(u32) -> bool,
    out: Vec<Mutant>,
}

impl M<'_, '_, '_> {
    fn push(&mut self, op: &str, at: oxc::span::Span, start: u32, end: u32, replacement: String, desc: String) {
        let loc = self.src.loc(at);
        if !(self.lines)(loc.line) {
            return;
        }
        self.out.push(Mutant {
            id: format!("{}:{}:{op}@{start}", loc.file, loc.line),
            operator: op.to_owned(),
            location: loc,
            description: desc,
            start: start as usize,
            end: end as usize,
            replacement,
        });
    }
}

impl<'a> Visit<'a> for M<'_, '_, '_> {
    fn visit_if_statement(&mut self, i: &IfStatement<'a>) {
        let test = self.src.short(&i.test, 60);
        if i.alternate.is_none() && exits(&i.consequent, self.src, true) {
            self.push("remove-guard", i.span, i.span.start, i.span.end, ";".into(), format!("delete guard `{test}`"));
        }
        let (s, e) = (i.test.span().start, i.test.span().end);
        self.push("negate-condition", i.span, s, e, format!("!({})", self.src.slice(i.test.span())), format!("negate `{test}`"));
        walk::walk_if_statement(self, i);
    }

    fn visit_binary_expression(&mut self, b: &BinaryExpression<'a>) {
        let swap = match b.operator {
            BinaryOperator::StrictEquality => Some(("===", "!==")),
            BinaryOperator::StrictInequality => Some(("!==", "===")),
            BinaryOperator::GreaterEqualThan => Some((">=", ">")),
            BinaryOperator::GreaterThan => Some((">", ">=")),
            BinaryOperator::LessEqualThan => Some(("<=", "<")),
            BinaryOperator::LessThan => Some(("<", "<=")),
            _ => None,
        };
        if let Some((from, to)) = swap {
            let between = self.src.slice(oxc::span::Span::new(b.left.span().end, b.right.span().start));
            if let Some(off) = between.find(from) {
                let start = b.left.span().end + u32::try_from(off).unwrap_or(0);
                let end = start + u32::try_from(from.len()).unwrap_or(0);
                self.push(&format!("swap {from}→{to}"), b.span, start, end, to.into(), format!("`{}`: {from} → {to}", self.src.short(b, 60)));
            }
        }
        walk::walk_binary_expression(self, b);
    }

    fn visit_logical_expression(&mut self, l: &LogicalExpression<'a>) {
        if l.operator == LogicalOperator::And {
            let between = self.src.slice(oxc::span::Span::new(l.left.span().end, l.right.span().start));
            if let Some(off) = between.find("&&") {
                let start = l.left.span().end + u32::try_from(off).unwrap_or(0);
                self.push("swap &&→||", l.span, start, start + 2, "||".into(), format!("`{}`: && → ||", self.src.short(l, 60)));
            }
        }
        walk::walk_logical_expression(self, l);
    }

    fn visit_expression_statement(&mut self, s: &ExpressionStatement<'a>) {
        let call = match crate::expr::inner(&s.expression) {
            Expression::CallExpression(c) => Some(c),
            _ => None,
        };
        if let Some(c) = call
            && CHECK_CALL.is_match(self.src.slice(c.callee.span()))
        {
            self.push("remove-check-call", s.span, s.span.start, s.span.end, ";".into(), format!("delete `{}`", self.src.short(&**c, 60)));
        }
        walk::walk_expression_statement(self, s);
    }
}

pub fn generate(program: &Program<'_>, src: &Source<'_>, lines: &dyn Fn(u32) -> bool) -> Vec<Mutant> {
    let mut m = M { src, lines, out: vec![] };
    m.visit_program(program);
    m.out
}
