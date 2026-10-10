//! The guarded walker.
//!
//! Walks one function body top-down, maintaining the stack of conditions that
//! must hold to reach the current statement (branch conditions, preceding
//! early exits, switch-case selection, preceding assertion-style calls), and
//! records owned facts at interesting program points.
//!
//! Soundness direction: a guard is only pushed when the code certainly enforces
//! it. When unsure (an exit inside a `try` whose `catch` may swallow it) the
//! guard is dropped, which can only make a proof harder, never easier.
//!
//! Conditions inside expressions (ternaries, `&&`) are not tracked as guards;
//! nested functions are walked separately with their own (empty) guard stack.

use crate::expr::{Aliases, Conv, binding_names, inner};
use crate::text::Source;
use oxc::ast::ast::*;
use oxc::ast_visit::{Visit, walk};
use oxc::span::{GetSpan, Span};
use oxc::syntax::operator::AssignmentOperator;
use oxc::syntax::scope::ScopeFlags;
use proof_it_core::facts::*;
use regex::Regex;
use std::collections::{BTreeSet, HashSet};
use std::sync::LazyLock;

pub static STATE_FIELD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^(status|state|phase|stage|lifecycle|lifecycleState)$").expect("static regex"));
static UPDATE_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^(update|updateOne|updateMany|findOneAndUpdate|findByIdAndUpdate|findOneAndModify|upsert|patch|set|save|modify)$").expect("static regex")
});
static CREATE_CALL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^(create|createMany|insert|insertOne|insertMany|add|build)$").expect("static regex"));
static SQL_UPDATE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?is)\bUPDATE\s+["`]?(\w+)["`]?\s+SET\s+(.*?)(?:\bWHERE\b(.*))?$"#).expect("static regex"));
static SQL_SET_STATE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(status|state|phase|stage)\s*=\s*(?:'([\w-]+)'|(\$\d+|\?|\$\{[^}]*\}))").expect("static regex"));
static ERROR_RESPONSE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(res|reply|response|resp)\s*\.\s*(status|code|sendStatus)\s*\(\s*[45]\d\d\s*\)").expect("static regex"));
static NEXT_ERR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^next\s*\(\s*[A-Za-z_$][\w$.]*\s*\)$").expect("static regex"));
static RESPONDER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(res|reply|response|resp|ctx|h)\b").expect("static regex"));
static WRITE_METHOD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(save|update|updateOne|updateMany|destroy|delete|deleteOne|deleteMany|remove|findByIdAndUpdate|findByIdAndDelete|findByIdAndRemove|findOneAndUpdate|findOneAndDelete|findOneAndRemove|upsert|increment|decrement)$").expect("static regex")
});
static ASSERT_LIKE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)assert|ensure|check|verify|authori[sz]|require|guard|permit|^can[A-Z]|own|validate").expect("static regex"));
static ERROR_STATUS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\.(status|code)\s*\(\s*[45]\d\d\s*\)").expect("static regex"));

/// Facts recorded for one function.
#[derive(Debug, Default)]
pub struct FnWalk {
    pub state_writes: Vec<StateWriteFact>,
    pub sinks: Vec<SinkFact>,
    pub lookups: Vec<LookupFact>,
    pub derived: Vec<(String, String)>,
    pub body_paths: BTreeSet<String>,
}

pub struct FnInfo<'x> {
    pub name: &'x str,
    pub params: &'x [String],
    /// Simple type name of each parameter's annotation, if any.
    pub param_types: &'x [Option<String>],
    pub exported: bool,
    pub is_constructor: bool,
}

/// Is `s` an early exit (throw/return, or an error response in HTTP code)?
pub fn exits(s: &Statement<'_>, src: &Source<'_>, http: bool) -> bool {
    match s {
        Statement::ThrowStatement(_) | Statement::ReturnStatement(_) => true,
        Statement::BlockStatement(b) => match b.body.last() {
            None => false,
            Some(last) if exits(last, src, http) => true,
            Some(_) => http && b.body.iter().any(|x| is_error_response(x, src)),
        },
        Statement::IfStatement(i) => i.alternate.as_ref().is_some_and(|alt| exits(&i.consequent, src, http) && exits(alt, src, http)),
        _ => http && is_error_response(s, src),
    }
}

/// Like [`exits`], but only via `return`/error responses: a `throw` inside a
/// `try` whose `catch` swallows it does not leave the function.
pub fn exits_without_throw(s: &Statement<'_>, src: &Source<'_>, http: bool) -> bool {
    match s {
        Statement::ThrowStatement(_) => false,
        Statement::ReturnStatement(_) => true,
        Statement::BlockStatement(b) => match b.body.last() {
            None => false,
            Some(last) if exits_without_throw(last, src, http) => true,
            Some(_) => http && b.body.iter().any(|x| is_error_response(x, src)),
        },
        Statement::IfStatement(i) => {
            i.alternate.as_ref().is_some_and(|alt| exits_without_throw(&i.consequent, src, http) && exits_without_throw(alt, src, http))
        }
        _ => http && is_error_response(s, src),
    }
}

/// `res.status(4xx).json(...)`, `res.sendStatus(4xx)`, `next(err)`.
/// In Express a later `res.json(resource)` fails with ERR_HTTP_HEADERS_SENT, so
/// the resource is not disclosed on that path.
pub fn is_error_response(s: &Statement<'_>, src: &Source<'_>) -> bool {
    let Statement::ExpressionStatement(e) = s else {
        return false;
    };
    let text = src.slice(e.expression.span());
    ERROR_RESPONSE.is_match(text) || (NEXT_ERR.is_match(text.trim()) && !text.replace(' ', "").starts_with("next()"))
}

pub struct Walker<'c, 's> {
    pub src: &'c Source<'s>,
    pub aliases: &'c Aliases,
    pub info: FnInfo<'c>,
    pub http: bool,
    guards: Vec<Guard>,
    swallow_depth: usize,
    fresh: HashSet<String>,
    comparisons: Vec<(String, String)>,
    /// Paths mentioned in the initialiser (and later field assignments) of each local.
    local_paths: std::collections::HashMap<String, Vec<String>>,
    pub out: FnWalk,
}

impl<'c, 's> Walker<'c, 's> {
    pub fn new(src: &'c Source<'s>, aliases: &'c Aliases, info: FnInfo<'c>, http: bool) -> Self {
        Self {
            src,
            aliases,
            info,
            http,
            guards: vec![],
            swallow_depth: 0,
            fresh: HashSet::new(),
            comparisons: vec![],
            local_paths: Default::default(),
            out: FnWalk::default(),
        }
    }

    fn conv(&self) -> Conv<'c, 's> {
        Conv::new(self.src, self.aliases)
    }

    fn guard(&self, kind: GuardKind, e: &Expression<'_>, positive: bool, at: Span) -> Guard {
        Guard { kind, cond: self.conv().cond(e), positive, text: self.src.short(e, 140), location: self.src.loc(at) }
    }

    pub fn walk_body(&mut self, stmts: &[Statement<'_>]) {
        self.prepass(stmts);
        let _ = self.block(stmts);
    }

    pub fn walk_expression_body(&mut self, e: &Expression<'_>) {
        self.scan(e);
        self.sink_return(e, e.span());
    }

    /// Fresh objects (initialisation detection), literal comparisons, body paths.
    fn prepass(&mut self, stmts: &[Statement<'_>]) {
        struct P<'q, 'c, 's> {
            w: &'q mut Walker<'c, 's>,
        }
        impl<'a> Visit<'a> for P<'_, '_, '_> {
            fn visit_variable_declarator(&mut self, d: &VariableDeclarator<'a>) {
                if let (BindingPattern::BindingIdentifier(id), Some(init)) = (&d.id, &d.init) {
                    let i = inner(init);
                    let fresh = match i {
                        Expression::ObjectExpression(_) | Expression::NewExpression(_) => true,
                        Expression::CallExpression(c) => {
                            let callee = self.w.conv().callee(c);
                            let last = callee.rsplit('.').next().unwrap_or("");
                            last.starts_with("create") || last.starts_with("build") || last.starts_with("make") || last.starts_with("new")
                        }
                        _ => false,
                    };
                    if fresh {
                        self.w.fresh.insert(id.name.as_str().to_owned());
                    }
                }
                walk::walk_variable_declarator(self, d);
            }
            fn visit_binary_expression(&mut self, b: &BinaryExpression<'a>) {
                let conv = self.w.conv();
                for (x, y) in [(&b.left, &b.right), (&b.right, &b.left)] {
                    if let (Some(p), Some(l)) = (conv.path(x), conv.val(y).literal().map(str::to_owned)) {
                        self.w.comparisons.push((p, l));
                    }
                }
                walk::walk_binary_expression(self, b);
            }
            fn visit_expression(&mut self, e: &Expression<'a>) {
                if let Some(p) = self.w.conv().path(e) {
                    self.w.out.body_paths.insert(p);
                }
                walk::walk_expression(self, e);
            }
            fn visit_function(&mut self, _: &Function<'a>, _: ScopeFlags) {}
            fn visit_arrow_function_expression(&mut self, _: &ArrowFunctionExpression<'a>) {}
        }
        let mut p = P { w: self };
        for s in stmts {
            p.visit_statement(s);
        }
    }

    /// Walk a statement list; returns the guards it establishes for code after it.
    fn block(&mut self, stmts: &[Statement<'_>]) -> Vec<Guard> {
        let saved = self.guards.len();
        for s in stmts {
            let branches = self.stmt(s);
            // Path merging: after `if (C) { ...G }` (no exit) the continuation knows ¬C ∨ (C ∧ G);
            // after `if (C) { ...G1 } else { ...G2 }`: (C ∧ G1) ∨ (¬C ∧ G2).
            if let (Statement::IfStatement(i), Some((g_then, g_else))) = (s, branches) {
                let then_exits = self.exits_here(&i.consequent);
                let else_exits = i.alternate.as_ref().is_some_and(|a| self.exits_here(a));
                if !then_exits && !else_exits && (!g_then.is_empty() || !g_else.is_empty()) {
                    let c = self.conv().cond(&i.test);
                    // Only conditions and assertion-like calls carry meaning across the merge.
                    let keep = |g: &&Guard| {
                        g.kind != GuardKind::AssertCall
                            || matches!(&g.cond, Cond::Call { callee, .. } if ASSERT_LIKE.is_match(callee.rsplit('.').next().unwrap_or("")))
                    };
                    let g_then: Vec<Guard> = g_then.iter().filter(keep).cloned().collect();
                    let g_else: Vec<Guard> = g_else.iter().filter(keep).cloned().collect();
                    let as_cond = |g: &Guard| {
                        if g.positive { g.cond.clone() } else { Cond::Not { c: Box::new(g.cond.clone()) } }
                    };
                    let then_side = Cond::And { cs: std::iter::once(c.clone()).chain(g_then.iter().map(as_cond)).collect() };
                    let else_side = Cond::And { cs: std::iter::once(Cond::Not { c: Box::new(c) }).chain(g_else.iter().map(as_cond)).collect() };
                    let text = format!("{} branches of `if ({})`", if i.alternate.is_some() { "both" } else { "either" }, self.src.short(&i.test, 80));
                    self.guards.push(Guard {
                        kind: GuardKind::EarlyExit,
                        cond: Cond::Or { cs: vec![then_side, else_side] },
                        positive: true,
                        text,
                        location: self.src.loc(i.span),
                    });
                }
            }
            // Guards established by this statement for the rest of the block.
            match s {
                Statement::IfStatement(i) => {
                    let then_exits = self.exits_here(&i.consequent);
                    let else_exits = i.alternate.as_ref().is_some_and(|a| self.exits_here(a));
                    if then_exits && !else_exits {
                        let g = self.guard(GuardKind::EarlyExit, &i.test, false, i.span);
                        self.guards.push(g);
                    } else if !then_exits && else_exits {
                        let g = self.guard(GuardKind::EarlyExit, &i.test, true, i.span);
                        self.guards.push(g);
                    }
                }
                Statement::ExpressionStatement(e) => {
                    if let Expression::CallExpression(c) = inner(&e.expression) {
                        let g = self.call_guard(c, e.span);
                        self.guards.push(g);
                    }
                }
                Statement::VariableDeclaration(v) => {
                    for d in &v.declarations {
                        if let Some(Expression::CallExpression(c)) = d.init.as_ref().map(inner) {
                            let g = self.call_guard(c, v.span);
                            self.guards.push(g);
                        }
                    }
                }
                _ => {}
            }
        }

        self.guards.split_off(saved)
    }

    /// Exit test that respects swallowing `catch` blocks around us.
    fn exits_here(&self, s: &Statement<'_>) -> bool {
        if self.swallow_depth > 0 { exits_without_throw(s, self.src, self.http) } else { exits(s, self.src, self.http) }
    }

    fn call_guard(&self, c: &CallExpression<'_>, at: Span) -> Guard {
        let conv = self.conv();
        Guard {
            kind: GuardKind::AssertCall,
            cond: Cond::Call {
                callee: conv.callee(c),
                args: c.arguments.iter().filter_map(|a| a.as_expression()).map(|a| conv.val(a)).collect(),
                text: self.src.short(c, 140),
            },
            positive: true,
            text: self.src.short(c, 140),
            location: self.src.loc(at),
        }
    }

    /// Guards established by a statement used as a branch body.
    fn branch(&mut self, s: &Statement<'_>) -> Vec<Guard> {
        match s {
            Statement::BlockStatement(b) => self.block(&b.body),
            other => self.block(std::slice::from_ref(other)),
        }
    }

    /// For an `if`, returns the guards established at the end of each branch.
    fn stmt(&mut self, s: &Statement<'_>) -> Option<(Vec<Guard>, Vec<Guard>)> {
        match s {
            Statement::BlockStatement(b) => {
                // A nested block's guards still hold after it.
                let g = self.block(&b.body);
                self.guards.extend(g);
            }
            Statement::IfStatement(i) => {
                self.scan(&i.test);
                let g = self.guard(GuardKind::Branch, &i.test, true, i.span);
                self.guards.push(g);
                let g_then = self.branch(&i.consequent);
                self.guards.pop();
                let mut g_else = Vec::new();
                if let Some(alt) = &i.alternate {
                    let g = self.guard(GuardKind::Branch, &i.test, false, i.span);
                    self.guards.push(g);
                    g_else = self.branch(alt);
                    self.guards.pop();
                }
                return Some((g_then, g_else));
            }
            Statement::SwitchStatement(sw) => {
                self.scan(&sw.discriminant);
                let all: Vec<&Expression<'_>> = sw.cases.iter().filter_map(|c| c.test.as_ref()).collect();
                for (idx, case) in sw.cases.iter().enumerate() {
                    // Fall-through: preceding non-terminating cases also select this body.
                    let mut tests: Vec<&Expression<'_>> = Vec::new();
                    let mut is_default = case.test.is_none();
                    if let Some(t) = &case.test {
                        tests.push(t);
                    }
                    for prev in sw.cases[..idx].iter().rev() {
                        let terminated = prev.consequent.last().is_some_and(|l| matches!(l, Statement::BreakStatement(_)) || exits(l, self.src, false));
                        if !prev.consequent.is_empty() && terminated {
                            break;
                        }
                        match &prev.test {
                            Some(t) => tests.push(t),
                            None => is_default = true,
                        }
                        if !prev.consequent.is_empty() {
                            break;
                        }
                    }
                    let conv = self.conv();
                    let eq = |t: &Expression<'_>| Cond::Cmp { op: CmpOp::Eq, l: conv.val(&sw.discriminant), r: conv.val(t) };
                    let (cond, positive) = if is_default {
                        (Cond::Or { cs: all.iter().map(|t| eq(t)).filter(|c| !tests.is_empty() || matches!(c, Cond::Cmp { .. })).collect() }, false)
                    } else {
                        (Cond::Or { cs: tests.iter().map(|t| eq(t)).collect() }, true)
                    };
                    // A default reached by fall-through from a case cannot be summarised; drop the guard.
                    let skip = is_default && !tests.is_empty();
                    if !skip {
                        self.guards.push(Guard {
                            kind: GuardKind::Case,
                            cond,
                            positive,
                            text: format!("switch ({})", self.src.short(&sw.discriminant, 60)),
                            location: self.src.loc(case.span),
                        });
                    }
                    let _ = self.block(&case.consequent);
                    if !skip {
                        self.guards.pop();
                    }
                }
            }
            Statement::TryStatement(t) => {
                let swallows = t.handler.as_ref().is_some_and(|h| !h.body.body.last().is_some_and(|l| exits(l, self.src, false)));
                if swallows {
                    self.swallow_depth += 1;
                }
                // Guards established inside `try` hold after it only if the catch rethrows.
                let g_try = self.block(&t.block.body);
                if swallows {
                    self.swallow_depth -= 1;
                } else {
                    self.guards.extend(g_try);
                }
                if let Some(h) = &t.handler {
                    let _ = self.block(&h.body.body);
                }
                if let Some(f) = &t.finalizer {
                    let _ = self.block(&f.body);
                }
            }
            Statement::ReturnStatement(r) => {
                if let Some(arg) = &r.argument {
                    self.scan(arg);
                    self.sink_return(arg, r.span);
                }
            }
            Statement::ThrowStatement(t) => self.scan(&t.argument),
            Statement::ExpressionStatement(e) => {
                if !self.assignment(&e.expression) {
                    self.scan(&e.expression)
                }
            }
            Statement::VariableDeclaration(v) => self.declaration(v),
            // Guards established inside a loop body do not hold after the loop.
            Statement::ForStatement(f) => {
                if let Some(t) = &f.test {
                    self.scan(t);
                }
                let _ = self.branch(&f.body);
            }
            Statement::ForOfStatement(f) => {
                self.scan(&f.right);
                let _ = self.branch(&f.body);
            }
            Statement::ForInStatement(f) => {
                self.scan(&f.right);
                let _ = self.branch(&f.body);
            }
            Statement::WhileStatement(w) => {
                self.scan(&w.test);
                let _ = self.branch(&w.body);
            }
            Statement::DoWhileStatement(w) => {
                let _ = self.branch(&w.body);
                self.scan(&w.test);
            }
            Statement::LabeledStatement(l) => {
                let _ = self.branch(&l.body);
            }
            Statement::ExportDeclaration(e) => {
                if let Declaration::VariableDeclaration(v) = &e.declaration {
                    self.declaration(v);
                }
            }
            _ => {}
        }
        None
    }

    fn declaration(&mut self, v: &VariableDeclaration<'_>) {
        for d in &v.declarations {
            let Some(init) = &d.init else { continue };
            self.scan(init);
            self.bind(binding_names(&d.id), init, d.span);
        }
    }

    /// `x = await Model.find(...)` (assignment to a local, e.g. a `let` declared earlier).
    fn assignment(&mut self, e: &Expression<'_>) -> bool {
        if let Expression::AssignmentExpression(a) = inner(e)
            && a.operator == AssignmentOperator::Assign
            && let AssignmentTarget::AssignmentTargetIdentifier(id) = &a.left
        {
            self.scan(&a.right);
            self.bind(vec![id.name.as_str().to_owned()], &a.right, a.span);
            return true;
        }
        false
    }

    /// Record what `names` now hold: a lookup result, the paths it contains, what it derives from.
    fn bind(&mut self, names: Vec<String>, init: &Expression<'_>, at: Span) {
        // Lookups: `const x = await <call>(...)`, unwrapping `.lean()`, `.exec()`, ...
        let mut call_expr = inner(init);
        while let Expression::CallExpression(c) = call_expr {
            match inner(&c.callee) {
                Expression::StaticMemberExpression(m)
                    if matches!(m.property.name.as_str(), "lean" | "exec" | "populate" | "select" | "first" | "single" | "maybeSingle" | "orFail" | "then") =>
                {
                    call_expr = inner(&m.object)
                }
                _ => break,
            }
        }
        let is_responder = matches!(call_expr, Expression::CallExpression(cc) if RESPONDER.is_match(self.src.slice(cc.callee.span()).trim_start()));
        if matches!(call_expr, Expression::CallExpression(_)) && !is_responder {
            let conv = self.conv();
            let mut arg_paths = conv.paths_in(call_expr);
            // `findMany({ where: whereClause })`: include what the local contains.
            let expand: Vec<String> =
                arg_paths.iter().filter_map(|p| self.local_paths.get(p.split(['.', '[']).next().unwrap_or(""))).flatten().cloned().collect();
            arg_paths.extend(expand);
            self.out.lookups.push(LookupFact { names: names.clone(), arg_paths, text: self.src.short(call_expr, 140), location: self.src.loc(at) });
        }
        let contents = self.conv().paths_in(init);
        for n in &names {
            self.local_paths.entry(n.clone()).or_default().extend(contents.iter().cloned());
        }
        // Derived values: any local whose initialiser references another local
        // (`const record = rows[0]`, `const loc = { lat: e.lat }`, `const v = f(e)`).
        // Data built from a resource is the resource for disclosure purposes.
        for name in &names {
            for r in idents(init) {
                if &r != name {
                    self.out.derived.push((name.clone(), r));
                }
            }
        }
    }

    fn sink_return(&mut self, arg: &Expression<'_>, at: Span) {
        if let Expression::CallExpression(c) = inner(arg) {
            // `return res.json(x)` is recorded as a response sink by `scan`.
            if RESPONDER.is_match(self.src.slice(c.callee.span()).trim_start()) {
                return;
            }
            // `return Model.findById(args.id)`: the lookup result itself is returned.
            const RETURNED: &str = "<returned>";
            self.bind(vec![RETURNED.to_owned()], arg, at);
            if self.out.lookups.last().is_some_and(|l| l.names.iter().any(|n| n == RETURNED)) {
                self.out.sinks.push(SinkFact {
                    kind: SinkKind::Return,
                    refs: vec![RETURNED.to_owned()],
                    error_status: false,
                    text: self.src.short(arg, 120),
                    location: self.src.loc(at),
                    guards: self.guards.clone(),
                });
            }
            return;
        }
        let refs = idents(arg);
        self.out.sinks.push(SinkFact {
            kind: SinkKind::Return,
            refs,
            error_status: false,
            text: self.src.short(arg, 120),
            location: self.src.loc(at),
            guards: self.guards.clone(),
        });
    }

    /// Visit an expression (not entering nested functions) for writes and sinks.
    fn scan(&mut self, e: &Expression<'_>) {
        struct S<'q, 'c, 's> {
            w: &'q mut Walker<'c, 's>,
        }
        impl<'a> Visit<'a> for S<'_, '_, '_> {
            fn visit_assignment_expression(&mut self, a: &AssignmentExpression<'a>) {
                self.w.on_assign(a);
                walk::walk_assignment_expression(self, a);
            }
            fn visit_call_expression(&mut self, c: &CallExpression<'a>) {
                self.w.on_call(c);
                walk::walk_call_expression(self, c);
            }
            fn visit_string_literal(&mut self, s: &StringLiteral<'a>) {
                self.w.on_sql(s.value.as_str(), s.span);
            }
            fn visit_template_literal(&mut self, t: &TemplateLiteral<'a>) {
                let text = self.w.src.slice(t.span).to_owned();
                self.w.on_sql(&text, t.span);
                walk::walk_template_literal(self, t);
            }
            fn visit_function(&mut self, _: &Function<'a>, _: ScopeFlags) {}
            fn visit_arrow_function_expression(&mut self, _: &ArrowFunctionExpression<'a>) {}
        }
        S { w: self }.visit_expression(e);
    }

    #[allow(clippy::too_many_arguments)]
    fn write_fact(
        &self,
        kind: WriteKind,
        field: String,
        receiver: Option<String>,
        entity: String,
        value: WriteValue,
        where_states: Option<WhereStates>,
        init: bool,
        at: Span,
    ) -> StateWriteFact {
        let subject = receiver.as_ref().map(|r| format!("{r}.{field}"));
        let value_type = match &value {
            WriteValue::Ident { name } => self.info.params.iter().position(|p| p == name).and_then(|i| self.info.param_types.get(i).cloned().flatten()),
            _ => None,
        };
        let compared: BTreeSet<String> = self
            .comparisons
            .iter()
            .filter(|(p, _)| subject.as_deref().is_some_and(|s| s == p) || (subject.is_none() && p.ends_with(&format!(".{field}"))))
            .map(|(_, l)| l.clone())
            .collect();
        StateWriteFact {
            kind,
            field,
            receiver,
            entity,
            value,
            where_states,
            guards: self.guards.clone(),
            init,
            function: self.info.name.to_owned(),
            function_params: self.info.params.to_vec(),
            function_exported: self.info.exported,
            location: self.src.loc(at),
            compared_literals: compared.into_iter().collect(),
            value_type,
        }
    }

    fn write_value(&self, e: &Expression<'_>) -> WriteValue {
        let conv = self.conv();
        if let Some(l) = conv.val(e).literal() {
            return WriteValue::Lits { values: vec![l.to_owned()] };
        }
        if let Expression::ConditionalExpression(c) = inner(e)
            && let (Some(a), Some(b)) = (conv.val(&c.consequent).literal().map(str::to_owned), conv.val(&c.alternate).literal().map(str::to_owned))
        {
            return WriteValue::Lits { values: vec![a, b] };
        }
        if let Expression::Identifier(id) = inner(e) {
            return WriteValue::Ident { name: id.name.as_str().to_owned() };
        }
        WriteValue::Other { text: self.src.short(e, 80) }
    }

    fn on_assign(&mut self, a: &AssignmentExpression<'_>) {
        // `whereClause.userId = req.user.id`: remember what flows into the local.
        if let Some(m) = a.left.as_member_expression()
            && let Some(head) = self.conv().raw_path(m.object()).map(|p| p.split(['.', '[']).next().unwrap_or("").to_owned())
            && self.local_paths.contains_key(&head)
        {
            let ps = self.conv().paths_in(&a.right);
            self.local_paths.entry(head).or_default().extend(ps);
        }
        let Some(member) = a.left.as_member_expression() else {
            return;
        };
        let Some(field) = member.static_property_name() else {
            return;
        };
        let field = field.to_string();
        // ctx.body = x  (Koa response sink)
        if field == "body" && matches!(member.object(), Expression::Identifier(id) if id.name.as_str() == "ctx") {
            self.out.sinks.push(SinkFact {
                kind: SinkKind::ContextBody,
                refs: idents(&a.right),
                error_status: false,
                text: self.src.short(a, 120),
                location: self.src.loc(a.span),
                guards: self.guards.clone(),
            });
            return;
        }
        if a.operator != AssignmentOperator::Assign || !STATE_FIELD.is_match(&field) {
            return;
        }
        let Some(raw_recv) = self.conv().raw_path(member.object()) else {
            return;
        };
        let recv = self.aliases.resolve(&raw_recv);
        let head = raw_recv.split(['.', '[']).next().unwrap_or("").to_owned();
        let init = self.info.is_constructor || self.info.name == "<module>" || (raw_recv == head && self.fresh.contains(&head));
        let value = self.write_value(&a.right);
        let f = self.write_fact(WriteKind::Assignment, field, Some(recv.clone()), entity_of(&recv), value, None, init, a.span);
        self.out.state_writes.push(f);
    }

    fn on_call(&mut self, c: &CallExpression<'_>) {
        let callee = self.conv().callee(c);
        let Some(member) = c.callee.get_inner_expression().as_member_expression() else {
            return;
        };
        let Some(method) = member.static_property_name() else {
            return;
        };
        let method = method.to_string();

        // Callback-style data access in handlers: `dao.get(id, (err, data) => { ... res.render(..., data) })`.
        // The callback's parameters (after an error parameter) carry the looked-up data; its body
        // runs on the same path, so it is walked with the current guards.
        let responder_call = RESPONDER.is_match(self.src.slice(c.callee.span()).trim_start());
        if self.http {
            // Promise chains: `Model.find({...}).then(user => ...)` — the lookup's arguments are those of the inner call.
            let chained: Vec<String> = match member.object() {
                Expression::CallExpression(inner_call) if matches!(method.as_str(), "then" | "success" | "exec" | "done") => {
                    inner_call.arguments.iter().filter_map(|x| x.as_expression()).flat_map(|x| self.conv().paths_in(x)).collect()
                }
                _ => vec![],
            };
            for a in c.arguments.iter().filter_map(|a| a.as_expression()) {
                let (params, body): (Vec<String>, Option<&oxc::allocator::Vec<'_, Statement<'_>>>) = match inner(a) {
                    Expression::ArrowFunctionExpression(f) => (
                        f.params.items.iter().filter_map(|p| p.pattern.get_identifier_name().map(|n| n.as_str().to_owned())).collect(),
                        match &f.body {
                            ArrowFunctionBody::FunctionBody(b) => Some(&b.statements),
                            _ => None,
                        },
                    ),
                    Expression::FunctionExpression(f) => (
                        f.params.items.iter().filter_map(|p| p.pattern.get_identifier_name().map(|n| n.as_str().to_owned())).collect(),
                        f.body.as_ref().map(|b| &b.statements),
                    ),
                    _ => continue,
                };
                let data: Vec<String> = params.into_iter().filter(|p| !matches!(p.as_str(), "err" | "error" | "e" | "_err" | "_")).collect();
                let mut others: Vec<String> = c
                    .arguments
                    .iter()
                    .filter_map(|x| x.as_expression())
                    .filter(|x| !matches!(inner(x), Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)))
                    .flat_map(|x| self.conv().paths_in(x))
                    .collect();
                others.extend(chained.iter().cloned());
                if !data.is_empty() && !others.is_empty() && !responder_call {
                    let mut arg_paths = others.clone();
                    let expand: Vec<String> =
                        arg_paths.iter().filter_map(|p| self.local_paths.get(p.split(['.', '[']).next().unwrap_or(""))).flatten().cloned().collect();
                    arg_paths.extend(expand);
                    self.out.lookups.push(LookupFact { names: data, arg_paths, text: self.src.short(c, 140), location: self.src.loc(c.span) });
                }
                if let Some(stmts) = body {
                    let saved = self.guards.len();
                    let _ = self.block(stmts);
                    self.guards.truncate(saved);
                }
            }
        }

        // Write sinks (handlers only): `record.save()`, `user.destroy()`, `Model.update({ where: { id } }, ...)`.
        if self.http && WRITE_METHOD.is_match(&method) && !responder_call {
            let at = self.src.loc(c.span);
            match member.object() {
                Expression::Identifier(id)
                    if id.name.as_str().starts_with(char::is_lowercase)
                        && !matches!(id.name.as_str(), "db" | "prisma" | "knex" | "sequelize" | "mongoose" | "repo" | "repository" | "model") =>
                {
                    self.out.sinks.push(SinkFact {
                        kind: SinkKind::Write,
                        refs: vec![id.name.as_str().to_owned()],
                        error_status: false,
                        text: self.src.short(c, 120),
                        location: at,
                        guards: self.guards.clone(),
                    });
                }
                _ => {
                    let name = format!("__write{}", at.line);
                    let mut arg_paths: Vec<String> = c.arguments.iter().filter_map(|x| x.as_expression()).flat_map(|x| self.conv().paths_in(x)).collect();
                    let expand: Vec<String> =
                        arg_paths.iter().filter_map(|p| self.local_paths.get(p.split(['.', '[']).next().unwrap_or(""))).flatten().cloned().collect();
                    arg_paths.extend(expand);
                    self.out.lookups.push(LookupFact { names: vec![name.clone()], arg_paths, text: self.src.short(c, 140), location: at.clone() });
                    self.out.sinks.push(SinkFact {
                        kind: SinkKind::Write,
                        refs: vec![name],
                        error_status: false,
                        text: self.src.short(c, 120),
                        location: at,
                        guards: self.guards.clone(),
                    });
                }
            }
        }

        // Response sinks: res.json(x), res.status(200).send(x), reply.send(x), res.render(view, x)
        if matches!(method.as_str(), "json" | "send" | "jsonp" | "render") {
            let callee_text = self.src.slice(c.callee.span());
            if RESPONDER.is_match(callee_text.trim_start()) {
                let refs = c.arguments.iter().filter_map(|a| a.as_expression()).flat_map(idents).collect();
                self.out.sinks.push(SinkFact {
                    kind: SinkKind::Response,
                    refs,
                    error_status: ERROR_STATUS.is_match(callee_text),
                    text: self.src.short(c, 120),
                    location: self.src.loc(c.span),
                    guards: self.guards.clone(),
                });
            }
        }

        let conv = self.conv();
        // ORM updates.
        let is_update = UPDATE_CALL.is_match(&method);
        let is_create = CREATE_CALL.is_match(&method);
        if !is_update && !is_create {
            return;
        }
        let objs: Vec<&ObjectExpression<'_>> = c
            .arguments
            .iter()
            .filter_map(|a| a.as_expression())
            .filter_map(|e| if let Expression::ObjectExpression(o) = inner(e) { Some(&**o) } else { None })
            .collect();
        let entity = entity_of(&conv.raw_path(member.object()).unwrap_or_else(|| callee.clone()));
        for (i, obj) in objs.iter().enumerate() {
            let data = prop(obj, |k| matches!(k, "data" | "$set" | "values"));
            let target: &ObjectExpression<'_> = match data.map(|d| inner(&d.value)) {
                Some(Expression::ObjectExpression(o)) => o,
                _ => obj,
            };
            let Some(sp) = prop(target, |k| STATE_FIELD.is_match(k)) else {
                continue;
            };
            let field = sp.key.static_name().map(|k| k.into_owned()).unwrap_or_default();
            let mut where_expr: Option<&Expression<'_>> = prop(obj, |k| k == "where").map(|p| &p.value);
            if where_expr.is_none()
                && std::ptr::eq(target, *obj)
                && let Some(other) = objs.iter().enumerate().find(|(j, _)| *j != i).map(|(_, o)| *o)
            {
                where_expr = prop(other, |k| k == "where").map(|p| &p.value);
                if where_expr.is_none() && (method.starts_with("update") || method.starts_with("findOneAnd")) {
                    let f = self.write_fact(
                        WriteKind::OrmUpdate,
                        field.clone(),
                        None,
                        entity.clone(),
                        self.write_value(&sp.value),
                        where_states_of_obj(other, &field, &conv),
                        is_create,
                        sp.span,
                    );
                    self.out.state_writes.push(f);
                    continue;
                }
            }
            let ws = where_expr.and_then(|w| if let Expression::ObjectExpression(o) = inner(w) { where_states_of_obj(o, &field, &conv) } else { None });
            let f = self.write_fact(WriteKind::OrmUpdate, field, None, entity.clone(), self.write_value(&sp.value), ws, is_create, sp.span);
            self.out.state_writes.push(f);
        }
    }

    fn on_sql(&mut self, text: &str, at: Span) {
        let Some(m) = SQL_UPDATE.captures(text) else {
            return;
        };
        let set_part = m.get(2).map_or("", |x| x.as_str());
        let Some(sm) = SQL_SET_STATE.captures(set_part) else {
            return;
        };
        let field = sm.get(1).map_or("status", |x| x.as_str()).to_owned();
        let value = match sm.get(2) {
            Some(v) => WriteValue::Lits { values: vec![v.as_str().to_owned()] },
            None => WriteValue::QueryParam,
        };
        let where_part = m.get(3).map_or("", |x| x.as_str());
        let f = regex::escape(&field);
        let eq =
            Regex::new(&format!(r"(?i)\b{f}\s*=\s*'([\w-]+)'")).ok().and_then(|r| r.captures(where_part)).and_then(|c| c.get(1)).map(|x| x.as_str().to_owned());
        let in_list = Regex::new(&format!(r"(?i)\b{f}\s+IN\s*\(([^)]*)\)"))
            .ok()
            .and_then(|r| r.captures(where_part))
            .and_then(|c| c.get(1))
            .map(|x| x.as_str().to_owned());
        let ne = Regex::new(&format!(r"(?i)\b{f}\s*(?:<>|!=)\s*'([\w-]+)'"))
            .ok()
            .and_then(|r| r.captures(where_part))
            .and_then(|c| c.get(1))
            .map(|x| x.as_str().to_owned());
        let ws = if let Some(v) = eq {
            Some(WhereStates::In { values: vec![v] })
        } else if let Some(list) = in_list {
            let vals: Vec<String> = list
                .split(',')
                .map(|s| s.trim().trim_matches('\'').to_owned())
                .filter(|s| !s.is_empty() && s.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-'))
                .collect();
            (!vals.is_empty()).then_some(WhereStates::In { values: vals })
        } else {
            ne.map(|v| WhereStates::NotIn { values: vec![v] })
        };
        let table = m.get(1).map_or("", |x| x.as_str()).to_ascii_lowercase();
        let entity = singular(&table);
        let fact = self.write_fact(WriteKind::Sql, field, None, entity, value, ws, false, at);
        self.out.state_writes.push(fact);
    }
}

fn prop<'x, 'a>(o: &'x ObjectExpression<'a>, f: impl Fn(&str) -> bool) -> Option<&'x ObjectProperty<'a>> {
    o.properties.iter().find_map(|p| match p {
        ObjectPropertyKind::ObjectProperty(op) if op.key.static_name().is_some_and(|k| f(&k)) => Some(&**op),
        _ => None,
    })
}

fn where_states_of_obj(o: &ObjectExpression<'_>, field: &str, conv: &Conv<'_, '_>) -> Option<WhereStates> {
    let p = prop(o, |k| k == field)?;
    if let Some(l) = conv.val(&p.value).literal() {
        return Some(WhereStates::In { values: vec![l.to_owned()] });
    }
    if let Expression::ObjectExpression(inner_o) = inner(&p.value) {
        if let Some(inp) = prop(inner_o, |k| k == "in" || k == "$in")
            && let Expression::ArrayExpression(arr) = inner(&inp.value)
        {
            let vals: Option<Vec<String>> = arr.elements.iter().map(|el| el.as_expression().and_then(|x| conv.val(x).literal().map(str::to_owned))).collect();
            return vals.map(|values| WhereStates::In { values });
        }
        if let Some(np) = prop(inner_o, |k| k == "not" || k == "$ne")
            && let Some(l) = conv.val(&np.value).literal()
        {
            return Some(WhereStates::NotIn { values: vec![l.to_owned()] });
        }
    }
    None
}

/// Identifiers referenced in an expression (excluding property names), nested functions included.
pub fn idents(e: &Expression<'_>) -> Vec<String> {
    struct I(BTreeSet<String>);
    impl<'a> Visit<'a> for I {
        fn visit_identifier_reference(&mut self, id: &IdentifierReference<'a>) {
            self.0.insert(id.name.as_str().to_owned());
        }
    }
    let mut v = I(BTreeSet::new());
    v.visit_expression(e);
    v.0.into_iter().collect()
}

fn singular(s: &str) -> String {
    if let Some(stem) = s.strip_suffix("ies") {
        format!("{stem}y")
    } else if let Some(stem) = s.strip_suffix('s') {
        stem.to_owned()
    } else {
        s.to_owned()
    }
}

/// `this.emergency` → `emergency`, `emergencies[0]` → `emergency`.
pub fn entity_of(path: &str) -> String {
    let cleaned: String = {
        let mut out = String::new();
        let mut depth = 0;
        for c in path.chars() {
            match c {
                '[' => depth += 1,
                ']' => depth -= 1,
                _ if depth == 0 => out.push(c),
                _ => {}
            }
        }
        out
    };
    let last = cleaned.split('.').rfind(|p| !p.is_empty() && *p != "this").unwrap_or("entity");
    singular(&last.trim_start_matches('_').to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn entities() {
        assert_eq!(entity_of("this.emergencies[0]"), "emergency");
        assert_eq!(entity_of("prisma.payment"), "payment");
        assert_eq!(entity_of("e"), "e");
    }
}
