//! The property system. A property is the unit of assurance.
//!
//! Properties are pure data: a property names an extractor (code shipped with
//! Proof-It) and never contains executable content, so project-local property
//! files from an untrusted repository are safe to load. Project properties
//! cannot shadow library properties, and must say who wrote them
//! (`origin: human | ai-generated`) — AI-generated properties are candidates.

use crate::config::parse_yaml;
use crate::error::{Error, Result};
use crate::types::{Severity, SpecSource};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::LazyLock;

mod embedded {
    include!(concat!(env!("OUT_DIR"), "/embedded.rs"));
}
pub use embedded::{COVERAGE, LEAN_TOOLCHAIN, PROPERTY_LIBRARY, SEMGREP_RULES};

/// Extractors shipped with Proof-It. A property can only bind to one of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Extractor {
    #[serde(rename = "state-machine.terminal")]
    StateMachineTerminal,
    #[serde(rename = "state-machine.forbidden")]
    StateMachineForbidden,
    #[serde(rename = "authz.ownership")]
    AuthzOwnership,
    #[serde(rename = "authz.admin")]
    AuthzAdmin,
    #[serde(rename = "authz.write")]
    AuthzWrite,
    #[serde(rename = "ledger.conservation")]
    LedgerConservation,
    #[serde(rename = "ledger.non-negative")]
    LedgerNonNegative,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FormalSpec {
    pub extractor: Extractor,
    pub model: String,
    pub theorem: String,
    #[serde(default)]
    pub reference: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ThreatModel {
    pub actor: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    pub goal: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct TestingSpec {
    pub fuzz: bool,
    pub mutation: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Origin {
    #[default]
    Human,
    AiGenerated,
}

/// The on-disk schema.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PropertyFile {
    pub id: String,
    pub name: String,
    pub category: String,
    pub severity: String,
    #[serde(default = "one")]
    pub version: u32,
    pub description: String,
    #[serde(default)]
    pub rationale: String,
    #[serde(default)]
    pub languages: Vec<String>,
    #[serde(default)]
    pub signals: Vec<String>,
    #[serde(default)]
    pub formal: Option<FormalSpec>,
    #[serde(default)]
    pub detectors: Vec<String>,
    #[serde(default)]
    pub proof_strategy: String,
    #[serde(default)]
    pub attack_strategy: String,
    #[serde(default)]
    pub testing: TestingSpec,
    #[serde(default)]
    pub assumptions: Vec<String>,
    #[serde(default)]
    pub threat_model: Option<ThreatModel>,
    #[serde(default)]
    pub recommendation: String,
    #[serde(default)]
    pub origin: Origin,
}

fn one() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize)]
pub struct Property {
    #[serde(flatten)]
    pub spec: PropertyFile,
    pub severity: Severity,
    pub source: SpecSource,
    pub file: String,
    #[serde(skip)]
    pub signals: Vec<Regex>,
}

impl Property {
    pub fn id(&self) -> &str {
        &self.spec.id
    }
    pub fn name(&self) -> &str {
        &self.spec.name
    }
    /// Whether any applicability signal matches `text`.
    pub fn signal_matches(&self, text: &str) -> bool {
        self.signals.is_empty() || self.signals.iter().any(|r| r.is_match(text))
    }
}

static ID_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Z][A-Z0-9]*-\d{3}$").expect("static regex"));

/// Compile a signal regex; a leading `(?i)` is supported natively by the regex crate.
/// Size limits guard against pathological patterns from untrusted property files.
pub fn compile_signal(s: &str) -> std::result::Result<Regex, String> {
    if s.len() > 200 {
        return Err("signal regex longer than 200 characters".into());
    }
    regex::RegexBuilder::new(s).size_limit(1 << 20).dfa_size_limit(1 << 20).build().map_err(|e| e.to_string())
}

pub fn parse_property(text: &str, file: &str, source: SpecSource) -> Result<Property> {
    let spec: PropertyFile = parse_yaml(text, Path::new(file))?;
    if !ID_RE.is_match(&spec.id) {
        return Err(Error::Config(format!("{file}: invalid id {:?} (expected e.g. AUTHZ-001)", spec.id)));
    }
    let severity = Severity::parse(&spec.severity).ok_or_else(|| Error::Config(format!("{file}: invalid severity {:?}", spec.severity)))?;
    let signals =
        spec.signals.iter().map(|s| compile_signal(s).map_err(|e| Error::Config(format!("{file}: invalid signal {s:?}: {e}")))).collect::<Result<Vec<_>>>()?;
    let source = match (source, spec.origin) {
        (SpecSource::Project, Origin::AiGenerated) => SpecSource::AiGenerated,
        (s, _) => s,
    };
    Ok(Property { spec, severity, source, file: file.to_owned(), signals })
}

#[derive(Debug, Default)]
pub struct Registry {
    pub properties: BTreeMap<String, Property>,
}

impl Registry {
    /// Library properties (embedded in the binary) plus project properties from
    /// `<root>/.proof-it/properties/**/*.yaml`.
    pub fn load(project_root: Option<&Path>) -> Result<Self> {
        let mut reg = Self::default();
        for (file, text) in PROPERTY_LIBRARY {
            reg.add(parse_property(text, file, SpecSource::Library)?)?;
        }
        if let Some(root) = project_root {
            let dir = root.join(".proof-it").join("properties");
            let mut files = Vec::new();
            collect_yaml(&dir, &mut files);
            for f in files {
                let text = std::fs::read_to_string(&f).map_err(|e| Error::io(&f, e))?;
                let p = parse_property(&text, &f.display().to_string(), SpecSource::Project)?;
                if reg.properties.get(p.id()).is_some_and(|x| x.source == SpecSource::Library) {
                    return Err(Error::Config(format!("{}: property {} collides with a library property; choose another id", f.display(), p.id())));
                }
                reg.add(p)?;
            }
        }
        Ok(reg)
    }

    pub fn add(&mut self, p: Property) -> Result<()> {
        if self.properties.contains_key(p.id()) {
            return Err(Error::Config(format!("duplicate property id {} ({})", p.id(), p.file)));
        }
        self.properties.insert(p.spec.id.clone(), p);
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&Property> {
        self.properties.get(&id.to_ascii_uppercase())
    }

    /// Properties selected by include/exclude lists of ids or categories.
    pub fn select(&self, include: &[String], exclude: &[String]) -> Vec<&Property> {
        let matches = |p: &Property, sel: &str| sel.eq_ignore_ascii_case(p.id()) || sel.eq_ignore_ascii_case(&p.spec.category);
        self.properties
            .values()
            .filter(|p| include.is_empty() || include.iter().any(|s| matches(p, s)))
            .filter(|p| !exclude.iter().any(|s| matches(p, s)))
            .collect()
    }
}

fn collect_yaml(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let Ok(ft) = e.file_type() else { continue };
        let p = e.path();
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            collect_yaml(&p, out);
        } else if p.extension().is_some_and(|x| x == "yaml" || x == "yml") && e.metadata().map(|m| m.len() < 128 * 1024).unwrap_or(false) {
            out.push(p);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn library_loads_and_is_well_formed() {
        let reg = Registry::load(None).expect("library must load");
        assert!(reg.properties.len() >= 30);
        let p = reg.get("AUTHZ-001").expect("AUTHZ-001");
        assert_eq!(p.spec.formal.as_ref().map(|f| f.extractor), Some(Extractor::AuthzOwnership));
        assert_eq!(p.severity, Severity::Critical);
    }

    #[test]
    fn ai_generated_project_properties_are_labelled() {
        let text = "id: X-001\nname: n\ncategory: c\nseverity: high\ndescription: d\norigin: ai-generated\n";
        let p = parse_property(text, "x.yaml", SpecSource::Project).expect("parse");
        assert_eq!(p.source, SpecSource::AiGenerated);
    }

    #[test]
    fn unknown_extractors_are_rejected() {
        let text = "id: X-001\nname: n\ncategory: c\nseverity: high\ndescription: d\nformal:\n  extractor: run.my.script\n  model: m\n  theorem: t\n";
        assert!(parse_property(text, "x.yaml", SpecSource::Project).is_err());
    }
}
