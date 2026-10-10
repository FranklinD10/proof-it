//! Structured logging to stderr. stdout is reserved for command output, so
//! `proof-it assure --json | jq` always works.

use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Debug = 0,
    Info = 1,
    Warn = 2,
    Error = 3,
    Silent = 4,
}

static LEVEL: AtomicU8 = AtomicU8::new(Level::Warn as u8);
static JSON: AtomicU8 = AtomicU8::new(0);

pub fn init(level: Level, json: bool) {
    LEVEL.store(level as u8, Ordering::Relaxed);
    JSON.store(u8::from(json), Ordering::Relaxed);
}

pub fn log(level: Level, msg: &str, fields: &[(&str, &str)]) {
    if (level as u8) < LEVEL.load(Ordering::Relaxed) || level == Level::Silent {
        return;
    }
    let name = match level {
        Level::Debug => "debug",
        Level::Info => "info",
        Level::Warn => "warn",
        Level::Error => "error",
        Level::Silent => return,
    };
    if JSON.load(Ordering::Relaxed) == 1 {
        let mut m = serde_json::Map::new();
        m.insert("level".into(), name.into());
        m.insert("msg".into(), msg.into());
        for (k, v) in fields {
            m.insert((*k).into(), (*v).into());
        }
        eprintln!("{}", serde_json::Value::Object(m));
    } else if fields.is_empty() {
        eprintln!("[{name}] {msg}");
    } else {
        let f: Vec<String> = fields.iter().map(|(k, v)| format!("{k}={v}")).collect();
        eprintln!("[{name}] {msg} {}", f.join(" "));
    }
}

#[macro_export]
macro_rules! info { ($msg:expr $(, $k:expr => $v:expr)*) => { $crate::log::log($crate::log::Level::Info, &$msg, &[$(($k, &$v.to_string())),*]) }; }
#[macro_export]
macro_rules! warn { ($msg:expr $(, $k:expr => $v:expr)*) => { $crate::log::log($crate::log::Level::Warn, &$msg, &[$(($k, &$v.to_string())),*]) }; }
#[macro_export]
macro_rules! debug { ($msg:expr $(, $k:expr => $v:expr)*) => { $crate::log::log($crate::log::Level::Debug, &$msg, &[$(($k, &$v.to_string())),*]) }; }
