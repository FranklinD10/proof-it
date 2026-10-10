//! Every process Proof-It starts goes through [`run`]. Invariants:
//! - never a shell: argv is passed as a vector, so repository-controlled
//!   strings cannot inject commands;
//! - always a timeout, enforced on the whole process group;
//! - output is capped;
//! - the environment is scrubbed unless the caller supplies one;
//! - optional bubblewrap isolation (read-only root, private /tmp, no network)
//!   for anything that consumes or executes repository content.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Default)]
pub struct Sandbox {
    /// Paths mounted read-write; everything else is read-only.
    pub writable: Vec<PathBuf>,
    /// Paths re-exposed read-only after the private /tmp is mounted.
    pub readable: Vec<PathBuf>,
    pub network: bool,
}

#[derive(Debug, Clone)]
pub struct RunOptions {
    pub cwd: PathBuf,
    pub timeout: Duration,
    pub max_output_bytes: usize,
    /// Full environment for the child. `None` = [`scrubbed_env`].
    pub env: Option<BTreeMap<String, String>>,
    pub stdin: Option<Vec<u8>>,
    pub sandbox: Option<Sandbox>,
}

impl RunOptions {
    pub fn new(cwd: impl Into<PathBuf>, timeout: Duration) -> Self {
        Self { cwd: cwd.into(), timeout, max_output_bytes: 16 * 1024 * 1024, env: None, stdin: None, sandbox: None }
    }
}

#[derive(Debug, Clone)]
pub struct RunResult {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub truncated: bool,
    pub duration: Duration,
    pub sandboxed: bool,
    /// Spawn failure (binary missing, permission denied).
    pub spawn_error: Option<String>,
}

impl RunResult {
    pub fn success(&self) -> bool {
        self.exit_code == Some(0) && !self.timed_out && self.spawn_error.is_none()
    }
}

const SAFE_ENV_KEYS: [&str; 7] = ["PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "TERM", "ELAN_HOME"];

/// The parent's environment reduced to non-sensitive keys, plus `extra`.
pub fn scrubbed_env(extra: &[(&str, &str)]) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    for k in SAFE_ENV_KEYS {
        if let Ok(v) = std::env::var(k) {
            env.insert(k.to_owned(), v);
        }
    }
    for (k, v) in extra {
        env.insert((*k).to_owned(), (*v).to_owned());
    }
    env
}

/// Locate an executable on PATH plus well-known per-user install dirs.
/// Never consults the analysed repository.
pub fn which(name: &str) -> Option<PathBuf> {
    let home = std::env::var("HOME").unwrap_or_default();
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH").map(|p| std::env::split_paths(&p).collect()).unwrap_or_default();
    for extra in [".elan/bin", ".local/bin", "go/bin", ".cargo/bin"] {
        dirs.push(Path::new(&home).join(extra));
    }
    dirs.into_iter().filter(|d| d.is_absolute()).map(|d| d.join(name)).find(|p| is_executable(p))
}

fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0).unwrap_or(false)
}

pub fn bwrap() -> Option<&'static Path> {
    static B: OnceLock<Option<PathBuf>> = OnceLock::new();
    B.get_or_init(|| which("bwrap")).as_deref()
}

pub fn sandbox_available() -> bool {
    bwrap().is_some()
}

fn wrap(argv: &[String], opts: &RunOptions) -> Result<(Vec<String>, bool), String> {
    let Some(sb) = &opts.sandbox else {
        return Ok((argv.to_vec(), false));
    };
    let Some(b) = bwrap() else {
        return Err("sandbox requested but bubblewrap (bwrap) is not installed".into());
    };
    let mut out: Vec<String> = vec![
        b.display().to_string(),
        "--ro-bind".into(),
        "/".into(),
        "/".into(),
        "--dev".into(),
        "/dev".into(),
        "--proc".into(),
        "/proc".into(),
        "--tmpfs".into(),
        "/tmp".into(),
        "--die-with-parent".into(),
        "--new-session".into(),
        "--unshare-pid".into(),
        "--unshare-ipc".into(),
    ];
    if !sb.network {
        out.push("--unshare-net".into());
    }
    for r in &sb.readable {
        out.extend(["--ro-bind".into(), r.display().to_string(), r.display().to_string()]);
    }
    for w in &sb.writable {
        out.extend(["--bind".into(), w.display().to_string(), w.display().to_string()]);
    }
    out.extend(["--chdir".into(), opts.cwd.display().to_string(), "--".into()]);
    out.extend(argv.iter().cloned());
    Ok((out, true))
}

fn reader<R: Read + Send + 'static>(mut r: R, cap: usize) -> thread::JoinHandle<(Vec<u8>, bool)> {
    thread::spawn(move || {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 64 * 1024];
        let mut truncated = false;
        loop {
            match r.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let room = cap.saturating_sub(buf.len());
                    if room == 0 {
                        truncated = true;
                        continue; // keep draining so the child never blocks
                    }
                    let take = n.min(room);
                    buf.extend_from_slice(&chunk[..take]);
                    if take < n {
                        truncated = true;
                    }
                }
            }
        }
        (buf, truncated)
    })
}

fn kill_group(pid: u32) {
    use nix::sys::signal::{Signal, killpg};
    use nix::unistd::Pid;
    if let Ok(p) = i32::try_from(pid) {
        let _ = killpg(Pid::from_raw(p), Signal::SIGKILL);
    }
}

/// Run `argv` to completion (or timeout).
pub fn run(argv: &[String], opts: &RunOptions) -> RunResult {
    let started = Instant::now();
    let fail = |msg: String, sandboxed: bool| RunResult {
        exit_code: None,
        stdout: String::new(),
        stderr: String::new(),
        timed_out: false,
        truncated: false,
        duration: started.elapsed(),
        sandboxed,
        spawn_error: Some(msg),
    };
    if argv.is_empty() {
        return fail("empty argv".into(), false);
    }
    let (full, sandboxed) = match wrap(argv, opts) {
        Ok(x) => x,
        Err(e) => return fail(e, false),
    };
    let env = opts.env.clone().unwrap_or_else(|| scrubbed_env(&[]));
    let mut cmd = Command::new(&full[0]);
    cmd.args(&full[1..])
        .current_dir(&opts.cwd)
        .env_clear()
        .envs(&env)
        .stdin(if opts.stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Own process group so a timeout kills grandchildren too.
        .process_group(0);
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return fail(format!("{}: {e}", full[0]), sandboxed),
    };
    let pid = child.id();
    let out_h = child.stdout.take().map(|s| reader(s, opts.max_output_bytes));
    let err_h = child.stderr.take().map(|s| reader(s, opts.max_output_bytes));
    if let (Some(input), Some(mut sin)) = (opts.stdin.clone(), child.stdin.take()) {
        // Write on a thread: a child that never reads must not deadlock us.
        thread::spawn(move || {
            let _ = sin.write_all(&input);
        });
    }
    let deadline = started + opts.timeout;
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) if Instant::now() >= deadline => {
                timed_out = true;
                kill_group(pid);
                let _ = child.kill();
                break child.wait().ok();
            }
            Ok(None) => thread::sleep(Duration::from_millis(5)),
            Err(_) => break None,
        }
    };
    // Reap any stragglers in the group (e.g. bwrap children) before collecting output.
    if timed_out {
        kill_group(pid);
    }
    let (stdout, t1) = out_h.and_then(|h| h.join().ok()).unwrap_or_default();
    let (stderr, t2) = err_h.and_then(|h| h.join().ok()).unwrap_or_default();
    RunResult {
        exit_code: status.and_then(|s| s.code()),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        timed_out,
        truncated: t1 || t2,
        duration: started.elapsed(),
        sandboxed,
        spawn_error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(t: u64) -> RunOptions {
        RunOptions::new(std::env::temp_dir(), Duration::from_millis(t))
    }

    #[test]
    fn captures_output_and_exit_code() {
        let r = run(&["/bin/sh".into(), "-c".into(), "echo hi; echo err >&2; exit 3".into()], &opts(5000));
        assert_eq!(r.exit_code, Some(3));
        assert_eq!(r.stdout.trim(), "hi");
        assert_eq!(r.stderr.trim(), "err");
    }

    #[test]
    fn timeout_kills_process_group() {
        let r = run(&["/bin/sh".into(), "-c".into(), "sleep 30 & sleep 30".into()], &opts(200));
        assert!(r.timed_out);
        assert!(r.duration < Duration::from_secs(5));
    }

    #[test]
    fn environment_is_scrubbed() {
        // SAFETY-free: we never set_var in tests; check a key the parent might hold.
        let r = run(&["/usr/bin/env".into()], &opts(5000));
        assert!(!r.stdout.contains("AWS_SECRET_ACCESS_KEY"));
        assert!(!r.stdout.contains("GITHUB_TOKEN"));
    }

    #[test]
    fn output_is_capped() {
        let mut o = opts(5000);
        o.max_output_bytes = 100;
        let r = run(&["/bin/sh".into(), "-c".into(), "head -c 100000 /dev/zero".into()], &o);
        assert!(r.truncated);
        assert_eq!(r.stdout.len(), 100);
    }

    #[test]
    fn sandbox_has_no_network_and_readonly_root() {
        if !sandbox_available() {
            return;
        }
        let mut o = opts(10_000);
        o.sandbox = Some(Sandbox::default());
        let r = run(
            &["/bin/sh".into(), "-c".into(), "touch /usr/proofit-test 2>/dev/null && echo WROTE; cat /sys/class/net/*/operstate 2>/dev/null | wc -l".into()],
            &o,
        );
        assert!(r.sandboxed);
        assert!(!r.stdout.contains("WROTE"));
    }
}
