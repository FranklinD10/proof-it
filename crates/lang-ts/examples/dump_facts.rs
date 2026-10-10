//! Debugging aid: print the facts extracted from one file as JSON.
//! `cargo run -p proof-it-lang-ts --example dump_facts -- path/to/file.js`
use std::collections::HashSet;

fn main() {
    let path = std::env::args().nth(1).expect("usage: dump_facts <file>");
    let text = std::fs::read_to_string(&path).expect("read");
    match proof_it_lang_ts::analyze(&path, &text, &HashSet::new()) {
        Ok(a) => println!("{}", serde_json::to_string_pretty(&a.facts).expect("json")),
        Err(e) => eprintln!("{e}"),
    }
}
