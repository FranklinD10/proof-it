//! Errors and the CI exit-code contract (docs/cli.md).

use thiserror::Error;

/// Process exit codes. Stable: CI pipelines depend on them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExitCode {
    Passed = 0,
    AssuranceFailed = 1,
    AnalysisError = 2,
    ConfigError = 3,
    EnvironmentError = 4,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("usage error: {0}")]
    Usage(String),
    #[error("environment error: {0}")]
    Environment(String),
    #[error("analysis error: {0}")]
    Analysis(String),
    #[error("I/O error on {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

impl Error {
    pub fn exit_code(&self) -> ExitCode {
        match self {
            Self::Config(_) | Self::Usage(_) => ExitCode::ConfigError,
            Self::Environment(_) => ExitCode::EnvironmentError,
            Self::Analysis(_) | Self::Io { .. } => ExitCode::AnalysisError,
        }
    }
    pub fn io(path: impl AsRef<std::path::Path>, source: std::io::Error) -> Self {
        Self::Io { path: path.as_ref().display().to_string(), source }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
