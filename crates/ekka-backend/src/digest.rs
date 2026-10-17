//! `sha256:<hex>` over canonical JSON, the one hash every digest here uses,
//! as the contract defines it: SHA-256 of the JSON value with object keys
//! sorted and no insignificant whitespace.

use serde_json::Value;

/// `sha256:<hex>` over canonical JSON: object keys sorted, no whitespace.
/// For an OpenShell message, normalize it first ([`crate::normalize`]).
#[must_use]
pub fn json_digest(v: &Value) -> String {
    use sha2::{Digest, Sha256};
    let mut out = String::new();
    canonical(v, &mut out);
    let d = Sha256::digest(out.as_bytes());
    format!(
        "sha256:{}",
        d.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}

fn canonical(v: &Value, out: &mut String) {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String((*k).clone()).to_string());
                out.push(':');
                canonical(&m[*k], out);
            }
            out.push('}');
        }
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical(x, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}
