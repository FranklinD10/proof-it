//! Source text, spans and locations.

use oxc::span::{GetSpan, Span};
use proof_it_core::types::SourceLocation;

pub struct Source<'s> {
    pub file: &'s str,
    pub text: &'s str,
    line_starts: Vec<u32>,
}

impl<'s> Source<'s> {
    pub fn new(file: &'s str, text: &'s str) -> Self {
        let mut line_starts = vec![0u32];
        for (i, b) in text.bytes().enumerate() {
            if b == b'\n' {
                line_starts.push(u32::try_from(i + 1).unwrap_or(u32::MAX));
            }
        }
        Self { file, text, line_starts }
    }

    /// 1-based (line, column) of a byte offset.
    pub fn line_col(&self, offset: u32) -> (u32, u32) {
        let idx = match self.line_starts.binary_search(&offset) {
            Ok(i) => i,
            Err(i) => i.saturating_sub(1),
        };
        let start = self.line_starts.get(idx).copied().unwrap_or(0);
        (u32::try_from(idx + 1).unwrap_or(u32::MAX), offset - start + 1)
    }

    pub fn line_text(&self, line: u32) -> &'s str {
        let i = (line as usize).saturating_sub(1);
        let start = self.line_starts.get(i).copied().unwrap_or(0) as usize;
        let end = self.line_starts.get(i + 1).map_or(self.text.len(), |e| (*e as usize).saturating_sub(1));
        self.text.get(start..end.max(start)).unwrap_or("")
    }

    pub fn loc(&self, span: Span) -> SourceLocation {
        let (line, col) = self.line_col(span.start);
        let (end_line, _) = self.line_col(span.end);
        let snippet: String = self.line_text(line).trim().chars().take(200).collect();
        SourceLocation { file: self.file.to_owned(), line, column: Some(col), end_line: Some(end_line), snippet: Some(snippet) }
    }

    pub fn loc_of<T: GetSpan>(&self, node: &T) -> SourceLocation {
        self.loc(node.span())
    }

    pub fn slice(&self, span: Span) -> &'s str {
        self.text.get(span.start as usize..span.end as usize).unwrap_or("")
    }

    /// Source text with whitespace collapsed, truncated for display.
    pub fn short<T: GetSpan>(&self, node: &T, max: usize) -> String {
        collapse(self.slice(node.span()), max)
    }
}

pub fn collapse(s: &str, max: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max));
    let mut ws = false;
    for c in s.chars() {
        if c.is_whitespace() {
            if !ws && !out.is_empty() {
                out.push(' ');
            }
            ws = true;
        } else {
            out.push(c);
            ws = false;
        }
        if out.chars().count() >= max {
            break;
        }
    }
    out.trim_end().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lines() {
        let s = Source::new("f.ts", "a\nbb\nccc");
        assert_eq!(s.line_col(0), (1, 1));
        assert_eq!(s.line_col(2), (2, 1));
        assert_eq!(s.line_col(6), (3, 2));
        assert_eq!(s.line_text(2), "bb");
        assert_eq!(collapse("a   b\n  c", 100), "a b c");
    }
}
