use std::collections::HashSet;

fn analyze() -> proof_it_core::facts::ModuleAnalysis {
    let text = include_str!("fixtures/sample.ts");
    let known: HashSet<String> = ["db.ts".to_owned()].into_iter().collect();
    proof_it_lang_ts::analyze("sample.ts", text, &known).expect("parse")
}

#[test]
fn extracts_enums_tables_and_imports() {
    let a = analyze();
    let f = &a.facts;
    assert!(f.enums.iter().any(|e| e.name == "EmergencyStatus" && e.members.len() == 4));
    let t = f.tables.iter().find(|t| t.name == "ALLOWED").expect("table");
    assert!(t.edges.contains(&("CREATED".into(), "ACTIVE".into())));
    assert_eq!(f.imports, vec!["db.ts".to_owned()]);
}

#[test]
fn state_writes_carry_guards() {
    let a = analyze();
    let w: Vec<_> = a.facts.state_writes.iter().filter(|w| !w.init).collect();
    let reopen = w.iter().find(|w| w.function == "reopen").expect("reopen write");
    assert_eq!(reopen.receiver.as_deref(), Some("e"));
    assert!(reopen.function_exported);
    assert_eq!(reopen.guards.len(), 1, "{:#?}", reopen.guards);
    assert!(!reopen.guards[0].positive);
    let tr = w.iter().find(|w| w.function == "transition").expect("transition write");
    assert!(matches!(&tr.guards[0].cond, proof_it_core::facts::Cond::Not { .. }));
}

#[test]
fn handlers_lookups_and_sinks() {
    let a = analyze();
    let hs = &a.facts.handlers;
    assert_eq!(hs.len(), 2, "{hs:#?}");
    let unsafe_h = hs.iter().find(|h| h.path == "/records/:id").expect("h1");
    assert_eq!(unsafe_h.middleware, vec!["requireAuth".to_owned()]);
    assert_eq!(unsafe_h.lookups.len(), 1);
    assert!(unsafe_h.lookups[0].arg_paths.iter().any(|p| p == "req.params.id"));
    let sink = unsafe_h.sinks.iter().find(|s| s.refs.contains(&"record".to_owned()) && !s.error_status).expect("sink");
    let conds: Vec<_> = sink.guards.iter().filter(|g| g.kind != proof_it_core::facts::GuardKind::AssertCall).collect();
    assert_eq!(conds.len(), 1, "{conds:#?}");
    assert_eq!(conds[0].kind, proof_it_core::facts::GuardKind::EarlyExit);
    let safe_h = hs.iter().find(|h| h.path == "/safe/:id").expect("h2");
    assert!(safe_h.lookups[0].arg_paths.iter().any(|p| p == "req.params.id"), "{:?}", safe_h.lookups);
    let ssink = safe_h.sinks.iter().find(|s| s.refs.contains(&"record".to_owned()) && !s.error_status).expect("sink2");
    let texts: Vec<_> = ssink.guards.iter().map(|g| &g.text).collect();
    assert!(texts.iter().any(|t| t.contains("ownerId")), "{texts:?}");
    let g = ssink.guards.iter().find(|g| g.text.contains("ownerId")).expect("owner guard");
    let paths = g.cond.all_paths();
    assert!(paths.contains(&"req.user.id".to_owned()), "{paths:?}");
}

#[test]
fn ledger_statements() {
    let a = analyze();
    let l = a.facts.ledger_functions.iter().find(|l| l.name == "transfer").expect("ledger");
    assert_eq!(l.stmts.len(), 3, "{:#?}", l.stmts);
}
