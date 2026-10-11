//! Proof-It core: result vocabulary, configuration, property registry,
//! language-neutral IR and facts, safe process execution, evidence storage.

pub mod config;
pub mod decision;
pub mod error;
pub mod facts;
pub mod log;
pub mod paths;
pub mod process;
pub mod project;
pub mod property;
pub mod redact;
pub mod rng;
pub mod rules;
pub mod store;
pub mod types;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub use error::{Error, ExitCode, Result};
