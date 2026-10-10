//! State-machine extraction (STATE-001 terminal absorption, STATE-002 forbidden transitions).
//!
//! 1. Every non-initialising write to a state field becomes a transition edge
//!    whose source set comes from the dominating guards (and, for ORM/SQL
//!    writes, the where-clause) and whose target set comes from the written value.
//! 2. Edges are grouped into machines by declared state type (enum/union) or,
//!    failing that, by entity + field (states then INFERRED from literals).
//! 3. Guards that mention the state but cannot be interpreted become OPAQUE
//!    gates: a violation needing a gate to be true is UNPROVEN, not VIOLATED.
//!    Guards that do not mention the state (auth checks, validation) are
//!    satisfiable preconditions, listed in the trace.

use super::{EdgeReplay, ExtractContext, Extraction, ReplaySpec, entity_of, show_cond};
use crate::eval::{Assignment, Value};
use crate::ir::*;
use proof_it_core::facts::*;
use proof_it_core::property::{Extractor, Property};
use proof_it_core::types::{CounterexampleStep, ProofStatus, SourceLocation, SpecSource};
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, LazyLock};

static TERMINAL_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^(RESOLVED|CANCELL?ED|COMPLETED?|CLOSED|FAILED|REJECTED|EXPIRED|DELETED|ARCHIVED|REFUNDED|DONE|FINISHED|TERMINATED|ABORTED|VOID(ED)?|DECLINED|SETTLED)$").expect("static regex")
});

type States = Option<BTreeSet<String>>; // None = any state

#[derive(Debug, Clone)]
struct Edge {
    from: States,
    to: States,
    gates: Vec<String>,
    preconditions: Vec<String>,
    table: Option<String>,
    location: SourceLocation,
    function: String,
    replay: Option<EdgeReplay>,
    exported: bool,
}

#[derive(Debug, Clone)]
struct Machine {
    type_name: String,
    entity: String,
    field: String,
    members: Vec<String>,
    declared: Option<EnumFact>,
    edges: Vec<Edge>,
    unattributed: usize,
}

#[derive(Debug, Default, Clone)]
struct Interp {
    set: States,
    gates: Vec<String>,
    pre: Vec<String>,
    table: Option<String>,
}

impl Interp {
    fn pure(&self) -> bool {
        self.gates.is_empty() && self.pre.is_empty() && self.table.is_none()
    }
}

fn intersect(a: &States, b: &States) -> States {
    match (a, b) {
        (None, x) | (x, None) => x.clone(),
        (Some(x), Some(y)) => Some(x.intersection(y).cloned().collect()),
    }
}

fn complement(s: &States, members: &[String]) -> States {
    match s {
        None => Some(BTreeSet::new()), // ¬true = false: no state passes
        Some(x) => Some(members.iter().filter(|m| !x.contains(*m)).cloned().collect()),
    }
}

struct Subj<'x> {
    paths: BTreeSet<String>,
    value_var: Option<&'x str>,
    tables: &'x BTreeMap<String, TransitionTableFact>,
    members: &'x [String],
}

impl Subj<'_> {
    fn is(&self, v: &Val) -> bool {
        matches!(v, Val::Path { path } if self.paths.contains(path))
    }
    fn mentions(&self, c: &Cond) -> bool {
        c.all_paths().iter().any(|p| self.paths.contains(p) || self.value_var.is_some_and(|vv| p == vv))
    }
    fn opaque(&self, c: &Cond) -> Interp {
        let t = show_cond(c);
        if self.mentions(c) { Interp { gates: vec![t], ..Interp::default() } } else { Interp { pre: vec![t], ..Interp::default() } }
    }
    fn interp(&self, c: &Cond) -> Interp {
        match c {
            Cond::Not { c: inner } => {
                let i = self.interp(inner);
                if i.pure() { Interp { set: complement(&i.set, self.members), ..Interp::default() } } else { self.opaque(c) }
            }
            Cond::And { cs } => cs.iter().map(|x| self.interp(x)).fold(Interp::default(), |acc, i| Interp {
                set: intersect(&acc.set, &i.set),
                gates: [acc.gates, i.gates].concat(),
                pre: [acc.pre, i.pre].concat(),
                table: acc.table.or(i.table),
            }),
            Cond::Or { cs } => {
                let is: Vec<Interp> = cs.iter().map(|x| self.interp(x)).collect();
                if is.iter().all(Interp::pure) {
                    let set = if is.iter().any(|i| i.set.is_none()) { None } else { Some(is.iter().flat_map(|i| i.set.clone().unwrap_or_default()).collect()) };
                    Interp { set, ..Interp::default() }
                } else {
                    self.opaque(c)
                }
            }
            Cond::Cmp { op: op @ (CmpOp::Eq | CmpOp::Ne), l, r } => {
                let (s, other) = if self.is(l) {
                    (true, r)
                } else if self.is(r) {
                    (true, l)
                } else {
                    (false, l)
                };
                match (s, other.literal()) {
                    (true, Some(lit)) => {
                        let one: States = Some([lit.to_owned()].into_iter().collect());
                        Interp { set: if *op == CmpOp::Eq { one } else { complement(&one, self.members) }, ..Interp::default() }
                    }
                    _ => self.opaque(c),
                }
            }
            Cond::InList { list, item } if self.is(item) => Interp { set: Some(list.iter().cloned().collect()), ..Interp::default() },
            Cond::TableHas { table, key, item }
                if self.is(key) && self.tables.contains_key(table) && self.value_var.is_some_and(|vv| matches!(item, Val::Path { path } if path == vv)) =>
            {
                Interp { table: Some(table.clone()), ..Interp::default() }
            }
            _ => self.opaque(c),
        }
    }

    fn apply(&self, guards: &[Guard]) -> Interp {
        let mut acc = Interp::default();
        for g in guards {
            let r = match g.kind {
                GuardKind::Branch | GuardKind::EarlyExit => {
                    let i = self.interp(&g.cond);
                    if g.positive {
                        i
                    } else if i.pure() {
                        Interp { set: complement(&i.set, self.members), ..Interp::default() }
                    } else if let Cond::Not { c } = &g.cond {
                        // `if (!X) throw` ⇒ X holds afterwards
                        self.interp(c)
                    } else {
                        let t = format!("!({})", g.text);
                        if i.gates.is_empty() { Interp { pre: vec![t], ..Interp::default() } } else { Interp { gates: vec![t], ..Interp::default() } }
                    }
                }
                GuardKind::Case => {
                    if !self.mentions(&g.cond) {
                        continue;
                    }
                    let i = self.interp(&g.cond);
                    if !i.pure() {
                        Interp { gates: vec![format!("{} case", g.text)], ..Interp::default() }
                    } else if g.positive {
                        i
                    } else {
                        Interp { set: complement(&i.set, self.members), ..Interp::default() }
                    }
                }
                GuardKind::AssertCall => {
                    if !self.mentions(&g.cond) {
                        continue;
                    }
                    Interp { gates: vec![g.text.clone()], ..Interp::default() }
                }
            };
            acc =
                Interp { set: intersect(&acc.set, &r.set), gates: [acc.gates, r.gates].concat(), pre: [acc.pre, r.pre].concat(), table: acc.table.or(r.table) };
        }
        acc.gates.sort();
        acc.gates.dedup();
        acc.pre.sort();
        acc.pre.dedup();
        acc
    }
}

fn camel(entity: &str, field: &str) -> String {
    format!("{entity}_{field}")
        .split('_')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let mut c = p.chars();
            c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default()
        })
        .collect()
}

fn build(ctx: &ExtractContext<'_>) -> (Vec<Machine>, BTreeMap<String, TransitionTableFact>) {
    let modules: Vec<&ModuleFacts> = ctx.facts.modules.iter().collect();
    let enums: Vec<&EnumFact> = modules.iter().flat_map(|m| &m.enums).filter(|e| e.members.len() >= 2).collect();
    let tables: BTreeMap<String, TransitionTableFact> = modules.iter().flat_map(|m| m.tables.iter().cloned()).map(|t| (t.name.clone(), t)).collect();
    let writes: Vec<(&ModuleFacts, &StateWriteFact)> = modules.iter().flat_map(|m| m.state_writes.iter().filter(|w| !w.init).map(move |w| (*m, w))).collect();

    let enum_for = |vals: &[String]| -> Option<&EnumFact> {
        enums
            .iter()
            .copied()
            .filter(|e| vals.iter().all(|v| e.members.contains(v)))
            .min_by_key(|e| (e.members.len(), !e.name.to_ascii_lowercase().contains("status")))
    };
    let mut machines: BTreeMap<String, Machine> = BTreeMap::new();
    let mut assigned: Vec<(usize, String)> = Vec::new(); // write index → machine key
    let lits = |w: &StateWriteFact| match &w.value {
        WriteValue::Lits { values } => Some(values.clone()),
        _ => None,
    };
    for (i, (_, w)) in writes.iter().enumerate() {
        if let Some(vals) = lits(w) {
            let declared = enum_for(&vals);
            let key = declared.map_or_else(|| format!("{}.{}", w.entity, w.field), |e| format!("enum:{}", e.name));
            machines.entry(key.clone()).or_insert_with(|| Machine {
                type_name: declared.map_or_else(|| format!("{}.{}", w.entity, w.field), |e| e.name.clone()),
                entity: w.entity.clone(),
                field: w.field.clone(),
                members: declared.map(|e| e.members.clone()).unwrap_or_default(),
                declared: declared.cloned(),
                edges: vec![],
                unattributed: 0,
            });
            assigned.push((i, key));
        }
    }
    for (i, (m, w)) in writes.iter().enumerate() {
        if lits(w).is_some() {
            continue;
        }
        // Attribute by the value's declared type (`next: Status`) or by the states of a
        // transition table that guards the write, to a declared enum.
        let table_states: Vec<String> = w
            .guards
            .iter()
            .filter_map(|g| match &g.cond {
                Cond::TableHas { table, .. } => tables.get(table),
                Cond::Not { c } => match &**c {
                    Cond::TableHas { table, .. } => tables.get(table),
                    _ => None,
                },
                _ => None,
            })
            .flat_map(|t| t.edges.iter().flat_map(|(a, b)| [a.clone(), b.clone()]))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let declared = w
            .value_type
            .as_ref()
            .and_then(|t| enums.iter().copied().find(|e| &e.name == t))
            .or_else(|| (!table_states.is_empty()).then(|| enum_for(&table_states)).flatten());
        if let Some(d) = declared {
            let key = format!("enum:{}", d.name);
            machines.entry(key.clone()).or_insert_with(|| Machine {
                type_name: d.name.clone(),
                entity: w.entity.clone(),
                field: w.field.clone(),
                members: d.members.clone(),
                declared: Some(d.clone()),
                edges: vec![],
                unattributed: 0,
            });
            assigned.push((i, key));
            continue;
        }
        // Attribute by same entity+field, then by same module, else a new (inferred) machine.
        let by_entity = machines.iter().find(|(_, mm)| mm.field == w.field && mm.entity == w.entity).map(|(k, _)| k.clone());
        let by_module = assigned.iter().find(|(j, _)| writes[*j].0.file == m.file && writes[*j].1.field == w.field).map(|(_, k)| k.clone());
        let key = by_entity.or(by_module).unwrap_or_else(|| {
            let key = format!("{}.{}", w.entity, w.field);
            let mm = machines.entry(key.clone()).or_insert_with(|| Machine {
                type_name: key.clone(),
                entity: w.entity.clone(),
                field: w.field.clone(),
                members: vec![],
                declared: None,
                edges: vec![],
                unattributed: 0,
            });
            mm.unattributed += 1;
            key
        });
        assigned.push((i, key));
    }
    // Inferred machines learn their states from written and compared literals.
    for (i, key) in &assigned {
        let w = writes[*i].1;
        if let Some(mm) = machines.get_mut(key)
            && mm.declared.is_none()
        {
            for x in lits(w).unwrap_or_default().into_iter().chain(w.compared_literals.iter().cloned()) {
                if !mm.members.contains(&x) {
                    mm.members.push(x);
                }
            }
        }
    }
    for (i, key) in &assigned {
        let (_, w) = writes[*i];
        let Some(mm) = machines.get(key) else {
            continue;
        };
        let members = mm.members.clone();
        let value_var = match &w.value {
            WriteValue::Ident { name } => Some(name.as_str()),
            _ => None,
        };
        let mut paths = BTreeSet::new();
        match &w.receiver {
            Some(r) => {
                paths.insert(format!("{r}.{}", w.field));
            }
            None => {
                // ORM/SQL: a guard on a loaded record of the same entity constrains the source state.
                for g in &w.guards {
                    for p in g.cond.all_paths() {
                        if let Some(prefix) = p.strip_suffix(&format!(".{}", w.field))
                            && entity_of(prefix) == w.entity
                        {
                            paths.insert(p);
                        }
                    }
                }
            }
        }
        let subj = Subj { paths, value_var, tables: &tables, members: &members };
        let mut interp = subj.apply(&w.guards);
        if let Some(ws) = &w.where_states {
            let from: States = match ws {
                WhereStates::In { values } => Some(values.iter().cloned().collect()),
                WhereStates::NotIn { values } => Some(members.iter().filter(|m| !values.contains(m)).cloned().collect()),
            };
            interp.set = intersect(&interp.set, &from);
        }
        let to: States = lits(w).map(|v| v.into_iter().collect());
        let mut gates = interp.gates.clone();
        if to.is_none() && interp.table.is_none() {
            gates.push(match &w.value {
                WriteValue::Ident { name } => format!("new state is the unchecked value `{name}`"),
                WriteValue::Other { text } => {
                    format!("new state is the non-literal value `{text}`")
                }
                WriteValue::QueryParam => "new state is a query parameter".into(),
                WriteValue::Lits { .. } => String::new(),
            });
        }
        let replay = w.receiver.as_ref().and_then(|r| {
            let head = r.split(['.', '[']).next().unwrap_or("");
            let rp = w.function_params.iter().position(|p| p == head)?;
            if r != head {
                return None;
            }
            let vp = value_var.and_then(|v| w.function_params.iter().position(|p| p == v));
            // Satisfy simple equality preconditions on other parameters.
            let mut param_values = Vec::new();
            for g in &w.guards {
                let Cond::Cmp { op, l, r } = &g.cond else {
                    continue;
                };
                let (Val::Path { path }, Some(lit)) = (l, r.literal()) else {
                    continue;
                };
                let Some(pi) = w.function_params.iter().position(|q| q == path) else {
                    continue;
                };
                if pi == rp || Some(pi) == vp {
                    continue;
                }
                let must_equal = match (g.kind, g.positive, op) {
                    (GuardKind::EarlyExit | GuardKind::Branch, false, CmpOp::Ne) | (GuardKind::Branch, true, CmpOp::Eq) => Some(true),
                    (GuardKind::EarlyExit | GuardKind::Branch, false, CmpOp::Eq) | (GuardKind::Branch, true, CmpOp::Ne) => Some(false),
                    _ => None,
                };
                match must_equal {
                    Some(true) => param_values.push((pi, serde_json::json!(lit))),
                    Some(false) if !param_values.iter().any(|(i, _)| *i == pi) => param_values.push((pi, serde_json::json!(format!("{lit}-other")))),
                    _ => {}
                }
            }
            Some(EdgeReplay {
                function: w.function.clone(),
                receiver_param: rp,
                value_param: vp,
                field: w.field.clone(),
                from: interp.set.clone().map(|s| s.into_iter().collect()),
                to: to.clone().map(|s| s.into_iter().collect()),
                param_values,
            })
        });
        let edge = Edge {
            from: interp.set,
            to,
            gates,
            preconditions: interp.pre,
            table: interp.table,
            location: w.location.clone(),
            function: w.function.clone(),
            replay,
            exported: w.function_exported,
        };
        if let Some(mm) = machines.get_mut(key) {
            mm.edges.push(edge);
        }
    }
    (machines.into_values().filter(|m| m.members.len() >= 2 && !m.edges.is_empty()).collect(), tables)
}

struct Model {
    enum_name: String,
    triples: Vec<(String, String, usize)>,
    gates: Vec<String>,
    def: Def,
}

impl Model {
    fn gate_var(&self, g: &str) -> String {
        format!("gate{}", self.gates.iter().position(|x| x == g).map_or(0, |i| i + 1))
    }
}

fn model(m: &Machine, tables: &BTreeMap<String, TransitionTableFact>) -> Model {
    let enum_name = m.declared.as_ref().map_or_else(|| camel(&m.entity, &m.field), |e| e.name.clone());
    let mut triples = Vec::new();
    for (i, e) in m.edges.iter().enumerate() {
        let froms: Vec<String> = match &e.from {
            None => m.members.clone(),
            Some(s) => s.iter().filter(|x| m.members.contains(x)).cloned().collect(),
        };
        if let Some(t) = e.table.as_ref().and_then(|t| tables.get(t)) {
            for (a, b) in &t.edges {
                if froms.contains(a) && m.members.contains(b) {
                    triples.push((a.clone(), b.clone(), i));
                }
            }
            continue;
        }
        let tos: Vec<String> = match &e.to {
            None => m.members.clone(),
            Some(s) => s.iter().filter(|x| m.members.contains(x)).cloned().collect(),
        };
        for a in &froms {
            for b in &tos {
                triples.push((a.clone(), b.clone(), i));
            }
        }
    }
    let gates: Vec<String> = m.edges.iter().flat_map(|e| e.gates.clone()).collect::<BTreeSet<_>>().into_iter().collect();
    let sort = Sort::Enum { name: enum_name.clone() };
    let mut mm = Model {
        enum_name: enum_name.clone(),
        triples,
        gates,
        def: Def { name: String::new(), params: vec![], body: DefBody::Expr { e: Expr::Bool { v: false } } },
    };
    let def = if mm.gates.is_empty() {
        Def {
            name: "validTransition".into(),
            params: vec![("s".into(), sort.clone()), ("t".into(), sort)],
            body: DefBody::Table {
                rows: mm.triples.iter().map(|(a, b, _)| vec![a.clone(), b.clone()]).collect(),
                origins: mm.triples.iter().map(|(_, _, i)| m.edges.get(*i).map(|e| e.location.clone())).collect(),
            },
        }
    } else {
        let disj: Vec<Expr> = mm
            .triples
            .iter()
            .map(|(a, b, i)| {
                let mut conj = vec![eq(var("s"), enum_lit(&enum_name, a)), eq(var("t"), enum_lit(&enum_name, b))];
                if let Some(e) = m.edges.get(*i) {
                    conj.extend(e.gates.iter().map(|g| var(&mm.gate_var(g))));
                }
                and(conj)
            })
            .collect();
        let mut params = vec![("s".into(), sort.clone()), ("t".into(), sort)];
        params.extend(mm.gates.iter().map(|g| (mm.gate_var(g), Sort::Bool)));
        Def { name: "validTransition".into(), params, body: DefBody::Expr { e: if disj.is_empty() { Expr::Bool { v: false } } else { or(disj) } } }
    };
    mm.def = def;
    mm
}

fn trace(m: &Machine, md: &Model, violated: String) -> super::TraceFn {
    let m = m.clone();
    let triples = md.triples.clone();
    let gate_vars: Vec<(String, String)> = md.gates.iter().map(|g| (g.clone(), md.gate_var(g))).collect();
    Arc::new(move |asg: &Assignment| {
        let sym = |k: &str| match asg.get(k) {
            Some(Value::Sym(s)) => s.clone(),
            _ => "?".into(),
        };
        let (s, t) = (sym("s"), sym("t"));
        let gate_ok = |e: &Edge| e.gates.iter().all(|g| gate_vars.iter().find(|(x, _)| x == g).is_none_or(|(_, v)| asg.get(v) != Some(&Value::Bool(false))));
        let edge = triples
            .iter()
            .filter(|(a, b, _)| *a == s && *b == t)
            .map(|(_, _, i)| &m.edges[*i])
            .find(|e| gate_ok(e))
            .or_else(|| triples.iter().find(|(a, b, _)| *a == s && *b == t).map(|(_, _, i)| &m.edges[*i]));
        let mut steps =
            vec![CounterexampleStep { action: format!("{} is in state {s}", m.entity), location: None, values: Some(serde_json::json!({ &m.field: s })) }];
        if let Some(e) = edge {
            for p in &e.preconditions {
                steps.push(CounterexampleStep::new(format!("precondition (assumed satisfiable): {p}")).at(Some(e.location.clone())));
            }
            for g in &e.gates {
                steps.push(CounterexampleStep::new(format!("unanalysed condition assumed true: {g}")).at(Some(e.location.clone())));
            }
            let how = match (&e.table, &e.from) {
                (Some(t), _) => format!("allowed by transition table {t}"),
                (None, None) => "no guard restricts the current state".into(),
                (None, Some(f)) => format!("guard allows {}", f.iter().cloned().collect::<Vec<_>>().join(", ")),
            };
            steps.push(CounterexampleStep::new(format!("call {}() — {how}", e.function)).at(Some(e.location.clone())));
        }
        steps.push(CounterexampleStep {
            action: format!("{}.{} becomes {t}", m.entity, m.field),
            location: None,
            values: Some(serde_json::json!({ &m.field: t })),
        });
        steps.push(CounterexampleStep::new(violated.clone()));
        steps
    })
}

pub fn extract(p: &Property, ctx: &ExtractContext<'_>) -> Vec<Extraction> {
    let Some(kind) = p.spec.formal.as_ref().map(|f| f.extractor) else {
        return vec![];
    };
    let (machines, tables) = build(ctx);
    let mut out = Vec::new();
    for m in &machines {
        let md = model(m, &tables);
        let specs =
            ctx.org.state_machines.iter().map(|s| (s, SpecSource::Organization)).chain(ctx.config.state_machines.iter().map(|s| (s, SpecSource::Project)));
        let declared = specs
            .into_iter()
            .find(|(s, _)| s.r#type == m.type_name || Some(&s.r#type) == m.declared.as_ref().map(|d| &d.name) || s.r#type.eq_ignore_ascii_case(&m.entity));
        let loc = m.declared.as_ref().map(|d| d.location.clone()).or_else(|| m.edges.first().map(|e| e.location.clone()));
        let files: Vec<String> = m
            .edges
            .iter()
            .map(|e| e.location.file.clone())
            .chain(m.declared.iter().map(|d| d.location.file.clone()))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let summary = vec![
            format!(
                "State type {} with states {{{}}}{}.",
                m.type_name,
                m.members.join(", "),
                m.declared
                    .as_ref()
                    .map_or_else(|| " (inferred from string literals)".to_owned(), |d| format!(" declared at {}:{}", d.location.file, d.location.line))
            ),
            format!("{} write(s) to .{} extracted → {} concrete transition edge(s).", m.edges.len(), m.field, md.triples.len()),
        ]
        .into_iter()
        .chain((!md.gates.is_empty()).then(|| format!("{} guard(s) could not be interpreted and are modeled as opaque conditions.", md.gates.len())))
        .chain((m.unattributed > 0).then(|| format!("{} write(s) with non-literal values could not be attributed to a declared type.", m.unattributed)))
        .collect::<Vec<_>>();
        let mut assumptions = p.spec.assumptions.clone();
        let pre: BTreeSet<&String> = m.edges.iter().flat_map(|e| &e.preconditions).collect();
        if !pre.is_empty() {
            assumptions.push(format!("Guards not involving the state are treated as satisfiable preconditions ({} found).", pre.len()));
        }
        let sort = Sort::Enum { name: md.enum_name.clone() };
        let mut vars = vec![
            ModelVar::new("s", sort.clone(), format!("{}.{} before the transition", m.entity, m.field)),
            ModelVar::new("t", sort, format!("{}.{} after the transition", m.entity, m.field)),
        ];
        vars.extend(md.gates.iter().map(|g| ModelVar::opaque(&md.gate_var(g), Sort::Bool, format!("unanalysed condition: {g}"))));
        let mut step_args = vec![var("s"), var("t")];
        step_args.extend(md.gates.iter().map(|g| var(&md.gate_var(g))));
        let step = Expr::Call { f: "validTransition".into(), args: step_args };
        let enum_decl = EnumDecl { name: md.enum_name.clone(), members: m.members.clone() };
        let replay = {
            let edges: Vec<EdgeReplay> = m.edges.iter().filter(|e| e.exported).filter_map(|e| e.replay.clone()).collect();
            let module = m.edges.iter().find(|e| e.exported && e.replay.is_some()).map(|e| e.location.file.clone());
            module.map(|module| ReplaySpec::StateTransition { edges: edges.into_iter().filter(|_| true).collect(), module, field: m.field.clone() })
        };
        let base = |target: String, ob: Option<Obligation>, spec_source: SpecSource, extra_assumption: Option<String>, violated: String| Extraction {
            property_id: p.id().to_owned(),
            target,
            location: loc.clone(),
            obligation: ob,
            status: None,
            reason: None,
            assumptions: assumptions.iter().cloned().chain(extra_assumption).collect(),
            spec_source,
            trace: Some(trace(m, &md, violated)),
            replay: replay.clone(),
            model_summary: summary.clone(),
            files: files.clone(),
        };
        match kind {
            Extractor::StateMachineTerminal => {
                let (terminals, source) = match &declared {
                    Some((s, src)) => (s.terminal.clone(), *src),
                    None => (m.members.iter().filter(|x| TERMINAL_NAME.is_match(x)).cloned().collect(), SpecSource::Inferred),
                };
                if terminals.is_empty() {
                    let mut e = Extraction::not_modeled(
                        p,
                        &m.type_name,
                        ProofStatus::NotApplicable,
                        format!("no terminal states declared in config or recognisable by name among {{{}}}", m.members.join(", ")),
                        loc.clone(),
                    );
                    e.model_summary = summary.clone();
                    out.push(e);
                    continue;
                }
                for term in terminals {
                    if !m.members.contains(&term) {
                        out.push(Extraction::not_modeled(
                            p,
                            &format!("{}:{term}", m.type_name),
                            ProofStatus::Unproven,
                            format!("configured terminal state {term} is not one of {{{}}}", m.members.join(", ")),
                            loc.clone(),
                        ));
                        continue;
                    }
                    let t = enum_lit(&md.enum_name, &term);
                    let extras = if md.gates.is_empty() {
                        vec![LeanExtra::Absorbing {
                            enum_name: md.enum_name.clone(),
                            relation: "validTransition".into(),
                            state: term.clone(),
                            theorem: format!("{term}_is_absorbing"),
                        }]
                    } else {
                        vec![]
                    };
                    let ob = Obligation {
                        theorem: format!("{term}_has_no_exit"),
                        property_id: p.id().to_owned(),
                        statement: format!(
                            "For the transition relation extracted from the code, a {} in state {term} can only \"transition\" to {term} itself.{}",
                            m.entity,
                            if extras.is_empty() {
                                String::new()
                            } else {
                                format!(" Also proved: every sequence of valid transitions starting in {term} stays in {term}.")
                            }
                        ),
                        enums: vec![enum_decl.clone()],
                        defs: vec![md.def.clone()],
                        vars: vars.clone(),
                        hypotheses: vec![
                            Hypothesis { assumed: false, expr: step.clone(), label: "the code performs a transition s → t".into(), location: None },
                            Hypothesis {
                                assumed: false,
                                expr: eq(var("s"), t.clone()),
                                label: format!("the {} is currently {term}", m.entity),
                                location: None,
                            },
                        ],
                        conclusion: eq(var("t"), t),
                        extras,
                        meaningful_if: Some(vec![Hypothesis {
                            assumed: false,
                            expr: step.clone(),
                            label: "the extracted transition relation is non-empty".into(),
                            location: None,
                        }]),
                    };
                    let extra = (source == SpecSource::Inferred)
                        .then(|| format!("{term} was INFERRED to be terminal from its name; declare it in state_machines to make this a requirement."));
                    out.push(base(
                        format!("{}:{term}", m.type_name),
                        Some(ob),
                        source,
                        extra,
                        format!("property violated: {term} is terminal but the {} left it", m.entity),
                    ));
                }
            }
            Extractor::StateMachineForbidden => {
                let Some((spec, source)) = declared.filter(|(s, _)| !s.forbidden.is_empty()) else {
                    out.push(Extraction::not_modeled(
                        p,
                        &m.type_name,
                        ProofStatus::NotApplicable,
                        "no forbidden transitions declared for this state type",
                        loc.clone(),
                    ));
                    continue;
                };
                for (a, b) in &spec.forbidden {
                    let ob = Obligation {
                        theorem: format!("no_{a}_to_{b}"),
                        property_id: p.id().to_owned(),
                        statement: format!("No code path extracted from the repository transitions a {} from {a} to {b}.", m.entity),
                        enums: vec![enum_decl.clone()],
                        defs: vec![md.def.clone()],
                        vars: vars.clone(),
                        hypotheses: vec![Hypothesis {
                            assumed: false,
                            expr: step.clone(),
                            label: "the code performs a transition s → t".into(),
                            location: None,
                        }],
                        conclusion: not(and(vec![eq(var("s"), enum_lit(&md.enum_name, a)), eq(var("t"), enum_lit(&md.enum_name, b))])),
                        extras: vec![],
                        meaningful_if: None,
                    };
                    out.push(base(format!("{}:{a}->{b}", m.type_name), Some(ob), source, None, format!("property violated: {a} → {b} is declared forbidden")));
                }
            }
            _ => {}
        }
    }
    out
}
