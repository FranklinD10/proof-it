//! TypeScript → JavaScript (ESM) for sandboxed execution of target code.
//! Uses oxc's TypeScript transform (type stripping); no tsc, no build scripts.

use oxc::allocator::Allocator;
use oxc::codegen::Codegen;
use oxc::parser::Parser;
use oxc::semantic::SemanticBuilder;
use oxc::transformer::{TransformOptions, Transformer};
use std::path::Path;

pub fn to_esm(file: &str, text: &str) -> Result<String, String> {
    let allocator = Allocator::default();
    let st = crate::source_type(file)?;
    let ret = Parser::new(&allocator, text, st).parse();
    if ret.fatal_error {
        return Err(ret.diagnostics.first().map_or_else(|| "parse failed".into(), |d| d.to_string()));
    }
    let mut program = ret.program;
    let scoping = SemanticBuilder::new().build(&program).semantic.into_scoping();
    let opts = TransformOptions::default();
    let t = Transformer::new(&allocator, Path::new(file), &opts).build_with_scoping(scoping, &mut program);
    if !t.diagnostics.is_empty() {
        return Err(t.diagnostics.first().map_or_else(String::new, |d| d.to_string()));
    }
    Ok(Codegen::new().build(&program).code)
}

#[cfg(test)]
mod tests {
    #[test]
    fn strips_types() {
        let js = super::to_esm("a.ts", "export function f(x: number): number { return x + 1 }\ntype T = string;").expect("transpile");
        assert!(js.contains("export function f(x)"), "{js}");
        assert!(!js.contains(": number"));
    }
}
