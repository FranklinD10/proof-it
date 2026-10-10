//! oxc expressions → language-neutral `Val` / `Cond` (proof_it_core::facts).
//!
//! Access paths are normalised: optional chaining and TS wrappers are dropped,
//! computed numeric indices become `[n]`, string-keyed computed members become
//! `.key`. Local aliases (`const s = e.status`, `const { id } = req.params`)
//! are resolved, so conditions on aliases are recognised as conditions on the
//! underlying path.

use crate::text::{Source, collapse};
use oxc::ast::ast::*;
use oxc::ast_visit::{Visit, walk};
use oxc::span::GetSpan;
use oxc::syntax::operator::{BinaryOperator, LogicalOperator, UnaryOperator};
use oxc::syntax::scope::ScopeFlags;
use proof_it_core::facts::{ArithOp, CmpOp, Cond, Val};
use std::collections::HashMap;

#[derive(Debug, Default, Clone)]
pub struct Aliases {
    map: HashMap<String, String>,
}

impl Aliases {
    /// Expand a leading alias: `userId` → `req.user.id`, `u.id` → `req.user.id`.
    pub fn resolve(&self, path: &str) -> String {
        let (head, rest) = match path.find(['.', '[']) {
            Some(i) => (&path[..i], &path[i..]),
            None => (path, ""),
        };
        match self.map.get(head) {
            Some(a) if a != path => format!("{a}{rest}"),
            _ => path.to_owned(),
        }
    }
    pub fn insert(&mut self, name: &str, target: String) {
        if name != target {
            self.map.insert(name.to_owned(), target);
        }
    }
    pub fn names_for(&self, target: &str) -> Vec<String> {
        self.map.iter().filter(|(_, t)| t.as_str() == target).map(|(k, _)| k.clone()).collect()
    }
}

/// Strip parentheses, TS wrappers and `await`.
pub fn inner<'x, 'a>(e: &'x Expression<'a>) -> &'x Expression<'a> {
    let mut cur = e.get_inner_expression();
    while let Expression::AwaitExpression(a) = cur {
        cur = a.argument.get_inner_expression();
    }
    cur
}

pub struct Conv<'c, 's> {
    pub src: &'c Source<'s>,
    pub aliases: &'c Aliases,
}

fn is_conversion(name: &str) -> bool {
    matches!(name, "String" | "Number" | "parseInt" | "BigInt" | "Math.trunc" | "Math.floor")
}

impl<'c, 's> Conv<'c, 's> {
    pub fn new(src: &'c Source<'s>, aliases: &'c Aliases) -> Self {
        Self { src, aliases }
    }

    /// Unresolved, normalised access path of a member/identifier chain.
    pub fn raw_path(&self, e: &Expression<'_>) -> Option<String> {
        let e = inner(e);
        match e {
            Expression::Identifier(id) => Some(id.name.as_str().to_owned()),
            Expression::ThisExpression(_) => Some("this".into()),
            Expression::StaticMemberExpression(m) => Some(format!("{}.{}", self.raw_path(&m.object)?, m.property.name.as_str())),
            Expression::ComputedMemberExpression(m) => {
                let base = self.raw_path(&m.object)?;
                match inner(&m.expression) {
                    Expression::NumericLiteral(n) => Some(format!("{base}[{}]", n.value)),
                    Expression::StringLiteral(s) => Some(format!("{base}.{}", s.value.as_str())),
                    _ => None,
                }
            }
            Expression::ChainExpression(c) => self.chain_path(&c.expression),
            _ => None,
        }
    }

    fn chain_path(&self, c: &ChainElement<'_>) -> Option<String> {
        match c {
            ChainElement::StaticMemberExpression(m) => Some(format!("{}.{}", self.raw_path(&m.object)?, m.property.name.as_str())),
            ChainElement::ComputedMemberExpression(m) => match inner(&m.expression) {
                Expression::NumericLiteral(n) => Some(format!("{}[{}]", self.raw_path(&m.object)?, n.value)),
                Expression::StringLiteral(s) => Some(format!("{}.{}", self.raw_path(&m.object)?, s.value.as_str())),
                _ => None,
            },
            ChainElement::TSNonNullExpression(n) => self.raw_path(&n.expression),
            _ => None,
        }
    }

    /// Alias-resolved path.
    pub fn path(&self, e: &Expression<'_>) -> Option<String> {
        self.raw_path(e).map(|p| self.aliases.resolve(&p))
    }

    /// Text used to identify a callee: its path if it has one, else collapsed source.
    pub fn callee(&self, call: &CallExpression<'_>) -> String {
        self.raw_path(&call.callee).unwrap_or_else(|| self.src.short(&call.callee, 80))
    }

    /// Strip `String(x)`, `Number(x)`, `parseInt(x)`, `x.toString()`, `+x`.
    pub fn strip_conversions<'x, 'a>(&self, e: &'x Expression<'a>) -> &'x Expression<'a> {
        let mut cur = inner(e);
        loop {
            match cur {
                Expression::CallExpression(c) if c.arguments.len() <= 2 && self.raw_path(&c.callee).is_some_and(|n| is_conversion(&n)) => {
                    match c.arguments.first().and_then(|a| a.as_expression()) {
                        Some(x) => cur = inner(x),
                        None => return cur,
                    }
                }
                Expression::CallExpression(c) if c.arguments.is_empty() => match inner(&c.callee) {
                    Expression::StaticMemberExpression(m) if matches!(m.property.name.as_str(), "toString" | "toHexString" | "valueOf") => {
                        cur = inner(&m.object)
                    }
                    _ => return cur,
                },
                Expression::UnaryExpression(u) if u.operator == UnaryOperator::UnaryPlus => cur = inner(&u.argument),
                _ => return cur,
            }
        }
    }

    /// Access paths mentioned anywhere in an expression (resolved).
    pub fn paths_in(&self, e: &Expression<'_>) -> Vec<String> {
        struct P<'q, 'c, 's> {
            conv: &'q Conv<'c, 's>,
            out: Vec<String>,
        }
        impl<'a> Visit<'a> for P<'_, '_, '_> {
            fn visit_expression(&mut self, e: &Expression<'a>) {
                if let Some(p) = self.conv.path(e) {
                    self.out.push(p);
                    // still descend into computed keys
                    if let Expression::ComputedMemberExpression(m) = e.get_inner_expression() {
                        self.visit_expression(&m.expression);
                    }
                    return;
                }
                walk::walk_expression(self, e);
            }
        }
        let mut v = P { conv: self, out: vec![] };
        v.visit_expression(e);
        v.out
    }

    pub fn val(&self, e: &Expression<'_>) -> Val {
        let e = self.strip_conversions(e);
        if let Some(p) = self.raw_path(e) {
            // Enum member: `Status.ACTIVE` (capitalised object, no alias)
            if let Expression::StaticMemberExpression(m) = e {
                if let Expression::Identifier(obj) = inner(&m.object) {
                    let o = obj.name.as_str();
                    if o.chars().next().is_some_and(char::is_uppercase)
                        && !o.chars().all(|c| c.is_uppercase() || c == '_')
                        && o != "Math"
                        && o != "JSON"
                        && o != "Number"
                    {
                        return Val::EnumMember { enum_name: o.to_owned(), member: m.property.name.as_str().to_owned() };
                    }
                }
                if m.property.name.as_str() == "length"
                    && let Some(base) = self.path(&m.object)
                {
                    return Val::Len { path: base };
                }
            }
            if p == "undefined" {
                return Val::Undefined;
            }
            return Val::Path { path: self.aliases.resolve(&p) };
        }
        match e {
            Expression::StringLiteral(s) => Val::Str { v: s.value.as_str().to_owned() },
            Expression::TemplateLiteral(t) if t.expressions.is_empty() => Val::Str { v: t.quasis.iter().map(|q| q.value.raw.as_str()).collect() },
            Expression::NumericLiteral(n) => {
                if n.value.fract() == 0.0 && n.value.abs() < 9.0e15 {
                    #[allow(clippy::cast_possible_truncation)]
                    Val::Int { v: n.value as i64 }
                } else {
                    Val::Float { text: self.src.slice(n.span).to_owned() }
                }
            }
            Expression::BooleanLiteral(b) => Val::Bool { v: b.value },
            Expression::NullLiteral(_) => Val::Null,
            Expression::UnaryExpression(u) if u.operator == UnaryOperator::UnaryNegation => Val::Neg { e: Box::new(self.val(&u.argument)) },
            Expression::BinaryExpression(b) => {
                let op = match b.operator {
                    BinaryOperator::Addition => Some(ArithOp::Add),
                    BinaryOperator::Subtraction => Some(ArithOp::Sub),
                    BinaryOperator::Multiplication => Some(ArithOp::Mul),
                    BinaryOperator::Division => Some(ArithOp::Div),
                    BinaryOperator::Remainder => Some(ArithOp::Mod),
                    _ => None,
                };
                match op {
                    Some(op) => Val::Bin { op, l: Box::new(self.val(&b.left)), r: Box::new(self.val(&b.right)) },
                    None => self.other(e),
                }
            }
            Expression::CallExpression(c) => {
                Val::Call { callee: self.callee(c), args: c.arguments.iter().filter_map(|a| a.as_expression()).map(|a| self.val(a)).collect() }
            }
            _ => self.other(e),
        }
    }

    fn other(&self, e: &Expression<'_>) -> Val {
        Val::Other { text: self.src.short(e, 120), paths: self.paths_in(e) }
    }

    pub fn cond(&self, e: &Expression<'_>) -> Cond {
        let e = inner(e);
        match e {
            Expression::UnaryExpression(u) if u.operator == UnaryOperator::LogicalNot => Cond::Not { c: Box::new(self.cond(&u.argument)) },
            Expression::LogicalExpression(l) if l.operator != LogicalOperator::Coalesce => {
                let (a, b) = (self.cond(&l.left), self.cond(&l.right));
                let and = l.operator == LogicalOperator::And;
                let mut cs = Vec::new();
                for c in [a, b] {
                    match c {
                        Cond::And { cs: inner } if and => cs.extend(inner),
                        Cond::Or { cs: inner } if !and => cs.extend(inner),
                        c => cs.push(c),
                    }
                }
                if and { Cond::And { cs } } else { Cond::Or { cs } }
            }
            Expression::BinaryExpression(b) => {
                let op = match b.operator {
                    BinaryOperator::Equality | BinaryOperator::StrictEquality => Some(CmpOp::Eq),
                    BinaryOperator::Inequality | BinaryOperator::StrictInequality => Some(CmpOp::Ne),
                    BinaryOperator::LessThan => Some(CmpOp::Lt),
                    BinaryOperator::LessEqualThan => Some(CmpOp::Le),
                    BinaryOperator::GreaterThan => Some(CmpOp::Gt),
                    BinaryOperator::GreaterEqualThan => Some(CmpOp::Ge),
                    _ => None,
                };
                // Presence tests: `typeof x === 'undefined'`, `x === undefined`, `x == null`
                // mean `!x` (and `!==` means `x`), as `if (!req.user)` / `if (!record)` do.
                if let Some(op @ (CmpOp::Eq | CmpOp::Ne)) = op
                    && let Some(x) = presence_operand(&b.left, &b.right).or_else(|| presence_operand(&b.right, &b.left))
                {
                    let present = Cond::Truthy { v: self.val(x) };
                    return if op == CmpOp::Eq { Cond::Not { c: Box::new(present) } } else { present };
                }
                match op {
                    Some(op) => Cond::Cmp { op, l: self.val(&b.left), r: self.val(&b.right) },
                    None => self.other_cond(e),
                }
            }
            Expression::CallExpression(c) => self.call_cond(c, e),
            Expression::ChainExpression(ch) => match &ch.expression {
                ChainElement::CallExpression(c) => self.call_cond(c, e),
                _ => match self.path(e) {
                    Some(p) => Cond::Truthy { v: Val::Path { path: p } },
                    None => self.other_cond(e),
                },
            },
            Expression::Identifier(_) | Expression::StaticMemberExpression(_) | Expression::ComputedMemberExpression(_) => Cond::Truthy { v: self.val(e) },
            Expression::BooleanLiteral(b) => Cond::Truthy { v: Val::Bool { v: b.value } },
            _ => self.other_cond(e),
        }
    }

    fn call_cond(&self, c: &CallExpression<'_>, whole: &Expression<'_>) -> Cond {
        let args: Vec<&Expression<'_>> = c.arguments.iter().filter_map(|a| a.as_expression()).collect();
        let callee_inner = match &c.callee {
            Expression::ChainExpression(_) => &c.callee,
            other => inner(other),
        };
        if let Expression::StaticMemberExpression(m) = callee_inner {
            let method = m.property.name.as_str();
            if method == "includes" && args.len() == 1 {
                if let Expression::ArrayExpression(arr) = inner(&m.object) {
                    let lits: Option<Vec<String>> =
                        arr.elements.iter().map(|el| el.as_expression().and_then(|x| self.val(x).literal().map(str::to_owned))).collect();
                    if let Some(list) = lits {
                        return Cond::InList { list, item: self.val(args[0]) };
                    }
                }
                if let Expression::ComputedMemberExpression(cm) = inner(&m.object)
                    && let Expression::Identifier(t) = inner(&cm.object)
                {
                    return Cond::TableHas { table: t.name.as_str().to_owned(), key: self.val(&cm.expression), item: self.val(args[0]) };
                }
            }
            if method == "equals" && args.len() == 1 {
                return Cond::Cmp { op: CmpOp::Eq, l: self.val(&m.object), r: self.val(args[0]) };
            }
        }
        Cond::Call { callee: self.callee(c), args: args.iter().map(|a| self.val(a)).collect(), text: self.src.short(whole, 140) }
    }

    fn other_cond(&self, e: &Expression<'_>) -> Cond {
        Cond::Other { text: self.src.short(e, 120), paths: self.paths_in(e) }
    }
}

/// Collect aliases declared in a function body: `const x = <path>`,
/// `const x = String(<path>)`, `const { a, b: c } = <path>`.
pub fn collect_aliases(src: &Source<'_>, stmts: &[Statement<'_>]) -> Aliases {
    struct A<'c, 's> {
        src: &'c Source<'s>,
        aliases: Aliases,
    }
    impl<'a> Visit<'a> for A<'_, '_> {
        fn visit_variable_declarator(&mut self, d: &VariableDeclarator<'a>) {
            if let Some(init) = &d.init {
                let conv = Conv::new(self.src, &self.aliases);
                let target = conv.strip_conversions(init);
                let resolved = match target {
                    Expression::AwaitExpression(_) | Expression::CallExpression(_) => None,
                    t => conv.path(t),
                };
                if let Some(base) = resolved {
                    match &d.id {
                        BindingPattern::BindingIdentifier(id) => self.aliases.insert(id.name.as_str(), base),
                        BindingPattern::ObjectPattern(op) => {
                            for p in &op.properties {
                                let key = p.key.static_name().map(|k| k.into_owned());
                                if let (Some(key), Some(local)) = (key, p.value.get_identifier_name()) {
                                    self.aliases.insert(local.as_str(), format!("{base}.{key}"));
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            walk::walk_variable_declarator(self, d);
        }
        fn visit_function(&mut self, _f: &Function<'a>, _flags: ScopeFlags) {}
    }
    let mut a = A { src, aliases: Aliases::default() };
    for s in stmts {
        a.visit_statement(s);
    }
    a.aliases
}

pub fn binding_names(p: &BindingPattern<'_>) -> Vec<String> {
    p.get_binding_identifiers().iter().map(|b| b.name.as_str().to_owned()).collect()
}

pub fn collapse_text(src: &Source<'_>, e: &impl GetSpan, max: usize) -> String {
    collapse(src.slice(e.span()), max)
}

/// A string literal or a template literal without substitutions.
pub fn lit_str<'x>(e: &'x Expression<'_>) -> Option<&'x str> {
    match inner(e) {
        Expression::StringLiteral(s) => Some(s.value.as_str()),
        Expression::TemplateLiteral(t) if t.expressions.is_empty() => t.quasis.first().map(|q| q.value.raw.as_str()),
        _ => None,
    }
}

/// `x` when `(x, other)` is a presence test: `typeof x` vs `'undefined'`, or `x` vs `null`/`undefined`.
fn presence_operand<'x, 'a>(x: &'x Expression<'a>, other: &Expression<'_>) -> Option<&'x Expression<'a>> {
    let other = inner(other);
    if let Expression::UnaryExpression(u) = inner(x)
        && u.operator == UnaryOperator::Typeof
    {
        return matches!(other, Expression::StringLiteral(s) if s.value == "undefined").then_some(&u.argument);
    }
    let nullish = matches!(other, Expression::NullLiteral(_)) || matches!(other, Expression::Identifier(id) if id.name == "undefined");
    let operand = matches!(
        inner(x),
        Expression::Identifier(_) | Expression::StaticMemberExpression(_) | Expression::ComputedMemberExpression(_) | Expression::ChainExpression(_)
    );
    (nullish && operand && !matches!(inner(x), Expression::Identifier(id) if id.name == "undefined")).then_some(x)
}
