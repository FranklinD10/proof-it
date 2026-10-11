//! Debugging aid: print the tree-sitter S-expression of a Go file.
fn main() {
    let path = std::env::args().nth(1).expect("usage: sexp <file.go>");
    let text = std::fs::read_to_string(path).expect("read");
    let mut p = tree_sitter::Parser::new();
    p.set_language(&tree_sitter_go::LANGUAGE.into()).expect("language");
    let t = p.parse(&text, None).expect("parse");
    println!("{}", t.root_node().to_sexp());
}
