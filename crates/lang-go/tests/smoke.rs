#[test]
fn grammar_loads() {
    let mut p = tree_sitter::Parser::new();
    p.set_language(&tree_sitter_go::LANGUAGE.into()).expect("language");
    let t = p.parse("package main\nfunc main() { println(1) }\n", None).expect("parse");
    assert!(!t.root_node().has_error());
}
