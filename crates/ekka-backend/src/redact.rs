//! Redaction of a desk's log line before the adapter answers with it: a
//! network log line may carry what a program sent, and nothing secret it
//! carries leaves the adapter. A line is read word by word (split on
//! whitespace, which is kept), and a word loses:
//!
//! - its value, when it is `key=value` or `key:value` and the key names a
//!   secret (token, secret, password, key, auth, credential, signature,
//!   session, cookie, code);
//! - a URL's user and password (`scheme://user:pass@host`) and its whole
//!   query (`?...`), which is where credentials ride in a URL;
//! - itself, when it follows `Bearer`, `Basic` or `Token`, or looks like a
//!   credential on its own (a JWT, or a well-known token prefix).
//!
//! Every control character becomes a space, so a line stays one line.
//! What remains is the host, the port, the path and the program: what a
//! reviewer needs to judge a connection.

/// What a redacted part reads as.
pub const REDACTED: &str = "[REDACTED]";

/// Words in a key that mark its value secret, matched in lowercase.
const SECRET_KEYS: [&str; 13] = [
    "token",
    "secret",
    "passw",
    "pwd",
    "key",
    "auth",
    "credential",
    "signature",
    "sig",
    "session",
    "cookie",
    "code",
    "bearer",
];

/// Prefixes of well-known credentials, matched case-sensitively.
const TOKEN_PREFIXES: [&str; 12] = [
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "glpat-",
    "xoxb-",
    "xoxp-",
    "sk-",
    "AKIA",
    "ASIA",
];

/// `line`, redacted.
#[must_use]
pub fn line(line: &str) -> String {
    let clean: String = line
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let mut out = String::with_capacity(clean.len());
    let mut after_scheme = false;
    for (i, part) in clean.split(' ').enumerate() {
        if i > 0 {
            out.push(' ');
        }
        if part.is_empty() {
            continue;
        }
        let bare = part.trim_matches(|c: char| !c.is_alphanumeric());
        let scheme_word =
            ["bearer", "basic", "token"].contains(&bare.to_ascii_lowercase().as_str());
        if after_scheme {
            // `Authorization: Bearer <x>`: the scheme stays, the secret after it goes.
            if scheme_word {
                out.push_str(part);
            } else {
                out.push_str(REDACTED);
                after_scheme = false;
            }
            continue;
        }
        // `Bearer <x>`, and `Cookie: <x>` or `password= <x>`: the next word is the secret.
        let names_next =
            scheme_word || ((part.ends_with(':') || part.ends_with('=')) && secret_key(bare));
        if names_next {
            out.push_str(part);
            after_scheme = true;
            continue;
        }
        out.push_str(&word(part));
    }
    out
}

fn secret_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    SECRET_KEYS.iter().any(|s| k.contains(s))
}

/// Whether `w` starts with a URL scheme (`https://`, `git+ssh://`).
fn starts_with_scheme(w: &str) -> bool {
    w.find("://").is_some_and(|i| {
        i > 0
            && w[..i]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
    })
}

/// One word, redacted.
fn word(w: &str) -> String {
    if looks_like_credential(w) {
        return REDACTED.to_string();
    }
    if starts_with_scheme(w) {
        return url(w);
    }
    if let Some(i) = w.find(['=', ':']) {
        let (key, rest) = w.split_at(i);
        let (sep, value) = rest.split_at(1);
        if value.is_empty() {
            return w.to_string();
        }
        if secret_key(key) || looks_like_credential(value) {
            return format!("{key}{sep}{REDACTED}");
        }
        if starts_with_scheme(value) {
            return format!("{key}{sep}{}", url(value));
        }
        // A query string outside a URL (`path=/a?token=x`).
        if let Some(q) = value.find('?') {
            return format!("{key}{sep}{}?{REDACTED}", &value[..q]);
        }
    }
    if let Some(q) = w.find('?') {
        return format!("{}?{REDACTED}", &w[..q]);
    }
    w.to_string()
}

/// A URL's user and password and its query, redacted. `w` starts with a
/// scheme.
fn url(w: &str) -> String {
    let start = w.find("://").unwrap_or(0);
    let (scheme, rest) = w.split_at(start + 3);
    let (authority_end, _) = rest
        .char_indices()
        .find(|(_, c)| matches!(c, '/' | '?' | '#'))
        .unwrap_or((rest.len(), ' '));
    let (authority, tail) = rest.split_at(authority_end);
    let host = match authority.rfind('@') {
        Some(at) => format!("{REDACTED}@{}", &authority[at + 1..]),
        None => authority.to_string(),
    };
    let tail = match tail.find(['?', '#']) {
        Some(q) => format!("{}?{REDACTED}", &tail[..q]),
        None => tail.to_string(),
    };
    format!("{scheme}{host}{tail}")
}

/// A JWT (three base64url parts, the first a JSON header), or a word that
/// starts with a well-known credential prefix.
fn looks_like_credential(w: &str) -> bool {
    let w = w.trim_matches(|c: char| matches!(c, '"' | '\'' | ',' | ';' | ')' | '('));
    let jwt = w.starts_with("eyJ")
        && w.split('.').count() == 3
        && w.split('.').all(|p| {
            !p.is_empty()
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    jwt || TOKEN_PREFIXES
        .iter()
        .any(|p| w.starts_with(p) && w.len() >= p.len() + 8)
}

#[cfg(test)]
#[path = "redact_tests.rs"]
mod tests;
