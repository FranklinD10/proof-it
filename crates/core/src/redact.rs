//! Secret redaction. Proof-It never prints a full credential, in any format.

/// Keep a short non-sensitive prefix so the developer can locate the secret.
pub fn redact_secret(value: &str) -> String {
    let v = value.trim();
    let n = v.chars().count();
    if n <= 8 {
        return "*".repeat(n.max(4));
    }
    let keep = (n / 5).min(4);
    let prefix: String = v.chars().take(keep).collect();
    format!("{prefix}{}", "*".repeat((n - keep).min(20)))
}

/// Replace every occurrence of each secret in `text` with its redacted form.
pub fn redact_all(text: &str, secrets: &[&str]) -> String {
    let mut out = text.to_owned();
    for s in secrets.iter().filter(|s| s.len() >= 4) {
        out = out.replace(s, &redact_secret(s));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_reveals_more_than_four_chars() {
        let secret = "AKIAABCDEFGHIJKLMNOP";
        let r = redact_secret(secret);
        assert!(r.starts_with("AKIA"));
        assert!(!r.contains("ABCD"));
        assert_eq!(redact_all(&format!("key={secret};"), &[secret]), format!("key={r};"));
    }
}
