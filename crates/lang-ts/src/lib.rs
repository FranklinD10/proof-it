//! TypeScript/JavaScript language adapter, built on oxc.
//!
//! Parsing is purely syntactic (no type checker, no module resolution beyond
//! relative imports, no code execution), so it is safe on hostile repositories.
//! Output is owned, language-neutral facts plus language-specific findings.

/// A regex compiled once (patterns are literals, so failure is a programming error).
macro_rules! re {
    ($p:literal) => {{
        static R: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new($p).expect("static regex"));
        &*R
    }};
}

pub mod expr;
pub mod module;
pub mod mutate;
pub mod security;
pub mod static_checks;
pub mod text;
pub mod transpile;
pub mod walker;

use oxc::allocator::Allocator;
use oxc::parser::{ParseOptions, Parser};
use oxc::span::SourceType;
use proof_it_core::facts::{ModuleAnalysis, Mutant};
use std::collections::HashSet;
use std::path::Path;

/// Source type for `file`. Plain `.js`/`.mjs`/`.cjs` files may contain JSX (React,
/// React Native), so JSX is enabled for them; `.ts` stays without it (`<T>x` casts).
pub fn source_type(file: &str) -> Result<SourceType, String> {
    let st = SourceType::from_path(Path::new(file)).map_err(|e| e.to_string())?;
    let ext = Path::new(file).extension().and_then(|e| e.to_str()).unwrap_or("");
    Ok(if matches!(ext, "js" | "mjs" | "cjs") { st.with_jsx(true) } else { st })
}

/// Parse `text` (repository-relative `file`) and extract facts and findings.
pub fn analyze(file: &str, text: &str, known_files: &HashSet<String>) -> Result<ModuleAnalysis, String> {
    let allocator = Allocator::default();
    let source_type = source_type(file)?;
    let ret = Parser::new(&allocator, text, source_type).with_options(ParseOptions { allow_return_outside_function: true, ..ParseOptions::default() }).parse();
    // A recovered parse is a partial program: analysing it as if complete would
    // silently skip whatever the parser dropped, so any syntax error is a failure.
    if ret.fatal_error || !ret.diagnostics.is_empty() {
        let msg = ret.diagnostics.first().map_or_else(|| "parse failed".to_owned(), |e| e.to_string());
        return Err(msg);
    }
    let src = text::Source::new(file, text);
    let facts = module::analyze_program(&ret.program, &src, known_files);
    let mut findings = security::detect(&ret.program, &src);
    findings.extend(static_checks::check(&ret.program, &src, &facts.enums));
    Ok(ModuleAnalysis { facts, findings, text: text.to_owned() })
}

/// Mutants for lines in `lines` (mutation testing of Proof-It's own detection).
pub fn mutants(file: &str, text: &str, lines: &dyn Fn(u32) -> bool) -> Vec<Mutant> {
    let allocator = Allocator::default();
    let Ok(source_type) = source_type(file) else {
        return vec![];
    };
    let ret = Parser::new(&allocator, text, source_type).parse();
    if ret.fatal_error {
        return vec![];
    }
    let src = text::Source::new(file, text);
    mutate::generate(&ret.program, &src, lines)
}
