//! `ekka-backend digest policy|provider <file|->`: the digests a desk grant's limits hold, computed by
//! the SAME functions the adapter enforces them with, so the kit that writes a
//! grant's limits and the adapter that checks them can never disagree. The kit
//! runs it from the pinned image: `docker run --rm -i <image> digest policy -`.
//!
//! - `policy`: an NVIDIA OpenShell `SandboxPolicy` in its proto JSON; prints
//!   [`policy_digest`], what `policy_digests` holds.
//! - `provider`: `{"name", "provider", "profile"}`; prints
//!   [`crate::providers::config_digest_of`], what `provider_config_digests`
//!   holds for that name.
//!
//! One line on stdout, exit 0; a refusal is one line on stderr starting with
//! its code, exit 2.

use std::io::Read as _;

use serde_json::Value;

use crate::normalize::{digest, POLICY};

/// The largest input read.
const MAX_INPUT: u64 = 1024 * 1024;

/// What `digest` was asked to compute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Policy,
    Provider,
}

/// A create's policy digest: the one function the enforcer and this command
/// share.
#[must_use]
pub fn policy_digest(policy: &Value) -> Option<String> {
    digest(POLICY, policy)
}

/// The digest of `bytes` as `kind`.
///
/// # Errors
/// The refusal, starting with its code.
pub fn compute(kind: Kind, bytes: &[u8]) -> Result<String, String> {
    let v: Value = serde_json::from_slice(bytes)
        .map_err(|e| format!("INPUT_INVALID: the input is not JSON: {e}"))?;
    match kind {
        Kind::Policy => policy_digest(&v).ok_or_else(|| {
            "POLICY_INVALID: the input is not an NVIDIA OpenShell SandboxPolicy this release reads (an unknown field included)"
                .to_string()
        }),
        Kind::Provider => {
            let input: crate::providers::Input = serde_json::from_value(v).map_err(|e| {
                format!("PROVIDER_INPUT_INVALID: the input is not {{\"name\", \"provider\", \"profile\"}}: {e}")
            })?;
            crate::providers::config_digest_of(&input)
        }
    }
}

/// The longest client secret read from stdin.
const MAX_SECRET: u64 = 4096;

/// The client secret of `ekka-desk-admin`, from stdin only: never an
/// argument, an environment variable or a file, so it is in no process list
/// and no shell history. One line; the line ending is dropped.
///
/// # Errors
/// `SECRET_INVALID`, naming what is wrong, never the value.
pub fn read_secret(mut from: impl std::io::Read) -> Result<zeroize::Zeroizing<String>, String> {
    let mut buf = zeroize::Zeroizing::new(Vec::new());
    from.by_ref()
        .take(MAX_SECRET + 1)
        .read_to_end(&mut buf)
        .map_err(|_| "SECRET_INVALID: stdin could not be read".to_string())?;
    if buf.len() as u64 > MAX_SECRET {
        return Err(format!(
            "SECRET_INVALID: stdin carries more than {MAX_SECRET} bytes"
        ));
    }
    let text = std::str::from_utf8(&buf)
        .map_err(|_| "SECRET_INVALID: the secret is not text".to_string())?;
    let line = text.strip_suffix('\n').unwrap_or(text);
    let line = line.strip_suffix('\r').unwrap_or(line);
    if line.is_empty() {
        return Err("SECRET_INVALID: stdin carries no client secret".into());
    }
    if !line.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(
            "SECRET_INVALID: the secret is one line of printable characters, with no space".into(),
        );
    }
    Ok(zeroize::Zeroizing::new(line.to_string()))
}

/// `digest provider --from-gateway <name>`: ONE provider's configuration
/// digest, read from the gateway over the same calls and computed by the same
/// function the adapter enforces with, so the kit
/// writing a grant and the adapter checking it share one source.
///
/// # Errors
/// The refusal, starting with its code. Never the secret or the token.
pub async fn from_gateway(
    tokens: &crate::signin::Tokens,
    gw: &crate::gateway::Gateway,
    secret: &str,
    name: &str,
) -> Result<String, String> {
    if !crate::routes::plain_name(name) {
        return Err("PROVIDER_INPUT_INVALID: name must be a plain provider name".into());
    }
    let bearer = tokens.bearer(secret).await.map_err(|e| e.to_string())?;
    let (p, profile) = match crate::providers::read(gw, &bearer, name).await {
        Ok(found) => found,
        Err((e, why)) => {
            if e == crate::gateway::GatewayError::Unauthenticated {
                tokens.rejected();
            }
            return Err(why);
        }
    };
    crate::providers::config_digest(name, &p, &profile)
}

/// Read `path`, or stdin for `-`, up to [`MAX_INPUT`].
///
/// # Errors
/// `INPUT_UNREADABLE` or `INPUT_TOO_LARGE`.
pub fn read(path: &str) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    let read = if path == "-" {
        std::io::stdin().take(MAX_INPUT + 1).read_to_end(&mut buf)
    } else {
        std::fs::File::open(path).and_then(|f| f.take(MAX_INPUT + 1).read_to_end(&mut buf))
    };
    read.map_err(|e| format!("INPUT_UNREADABLE: {path}: {e}"))?;
    if buf.len() as u64 > MAX_INPUT {
        return Err(format!(
            "INPUT_TOO_LARGE: {path} is larger than {MAX_INPUT} bytes"
        ));
    }
    Ok(buf)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use serde_json::json;

    use super::{compute, policy_digest, Kind};
    use crate::normalize::{digest, POLICY};

    fn policy() -> serde_json::Value {
        json!({ "version": 1, "filesystem": { "readOnly": ["/usr"], "readWrite": ["/sandbox"] } })
    }

    /// The command's output and the enforcer's digest are one function's, for
    /// the same bytes.
    #[test]
    fn the_policy_command_prints_what_the_enforcer_computes() {
        let bytes = serde_json::to_vec(&policy()).unwrap();
        let printed = compute(Kind::Policy, &bytes).unwrap();
        assert_eq!(Some(printed.clone()), policy_digest(&policy()));
        assert_eq!(Some(printed.clone()), digest(POLICY, &policy()));
        assert!(
            printed.starts_with("sha256:") && printed.len() == 71,
            "{printed}"
        );
        // Defaults written out or left out: one digest.
        let mut written = policy();
        written["landlock"] = json!(null);
        assert_eq!(
            compute(Kind::Policy, &serde_json::to_vec(&written).unwrap()).unwrap(),
            printed
        );
    }

    /// The client secret: one line from stdin, its line ending dropped; an
    /// empty, multi-line, spaced or oversized one is refused, and a refusal
    /// never repeats the value.
    #[test]
    fn the_client_secret_is_one_line_from_stdin() {
        use super::read_secret;
        assert_eq!(read_secret(&b"abc+/=\n"[..]).unwrap().as_str(), "abc+/=");
        assert_eq!(read_secret(&b"abc\r\n"[..]).unwrap().as_str(), "abc");
        assert_eq!(read_secret(&b"abc"[..]).unwrap().as_str(), "abc");
        for bad in [
            &b""[..],
            &b"\n"[..],
            &b"PLANTED one\n"[..],
            &b"PLANTED\nsecond\n"[..],
            &b"PLANTED\t\n"[..],
            &[0xff, 0xfe][..],
        ] {
            let e = read_secret(bad).unwrap_err();
            assert!(
                e.starts_with("SECRET_INVALID") && !e.contains("PLANTED"),
                "{e}"
            );
        }
        assert!(read_secret(&vec![b'a'; 4097][..])
            .unwrap_err()
            .starts_with("SECRET_INVALID"));
        assert_eq!(read_secret(&vec![b'a'; 4096][..]).unwrap().len(), 4096);
    }

    #[test]
    fn a_malformed_input_is_refused_with_its_code() {
        assert!(compute(Kind::Policy, b"{ not json")
            .unwrap_err()
            .starts_with("INPUT_INVALID"));
        let unknown = serde_json::to_vec(&json!({ "version": 1, "notAField": true })).unwrap();
        assert!(compute(Kind::Policy, &unknown)
            .unwrap_err()
            .starts_with("POLICY_INVALID"));
        assert!(compute(Kind::Provider, b"{}")
            .unwrap_err()
            .starts_with("PROVIDER_INPUT_INVALID"));
    }
}
