//! The adapter's configuration, published as
//! `backend/adapter-config.v1.schema.json` (contracts, vendored).
//!
//! ONE JSON file, written by the desks kit at install and mounted read-only.
//! It holds no credential: the backend's credential arrives with each call.
//! The file is refused, and the adapter does not start, when it is a symlink,
//! is writable by group or others, belongs to a user that is neither this
//! process's nor root, or carries a key this build does not know.

use std::path::{Path, PathBuf};

use base64::Engine as _;
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Where the kit mounts the file.
pub const DEFAULT_PATH: &str = "/etc/ekka-backend/config.json";
/// A config file larger than this is refused unread.
const MAX_FILE: u64 = 64 * 1024;
/// The adapter's own deadline must stay below the Enclave's 180 s for a
/// Unix connection, with room to answer: 150 s or more is refused (T4).
pub const DEADLINE_CEILING_SECONDS: u64 = 150;

fn default_deadline() -> u64 {
    120
}
fn default_socket() -> PathBuf {
    PathBuf::from("/run/ekka-backend/backend.sock")
}
fn default_state() -> PathBuf {
    PathBuf::from("/var/lib/ekka-backend")
}

/// One of Govern's gate-token signing keys.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernKey {
    /// Matched EXACTLY against the token's `key_id`; a token naming a key not
    /// listed here is refused, never tried against another key.
    pub key_id: String,
    /// The 32-byte Ed25519 public key, standard base64.
    pub public_key_b64: String,
}

/// The desk backend's gateway this adapter administers: the identity the
/// adapter's operation ids are bound to.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendGateway {
    pub url: String,
    pub client_id: String,
    pub workspace: String,
    /// The sign-in service the adapter gets its gateway token from, exactly
    /// as the gateway checks a token's `iss`. Pinned by the kit; never
    /// learned from the gateway, because the client credential is sent here.
    pub issuer: String,
    #[serde(default)]
    pub ca_pem_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub config_version: u32,
    /// A token's `tenant_id` must equal it.
    pub organization_id: String,
    /// A token's `scope.instance` must equal it.
    pub api_gate_instance: String,
    pub govern_keys: Vec<GovernKey>,
    pub backend_gateway: BackendGateway,
    #[serde(default = "default_deadline")]
    pub deadline_seconds: u64,
    #[serde(default = "default_socket")]
    pub socket_path: PathBuf,
    #[serde(default = "default_state")]
    pub state_dir: PathBuf,
}

/// A loaded, checked config, and the digest of the exact bytes read.
#[derive(Debug, Clone)]
pub struct Loaded {
    pub config: Config,
    /// `sha256:<hex>` of the file as read: logged at start, so an operator
    /// can tell which config is live.
    pub digest: String,
}

impl Loaded {
    /// The line logged at start: the digest and the key ids, never a key.
    #[must_use]
    pub fn start_line(&self) -> String {
        let ids: Vec<&str> = self
            .config
            .govern_keys
            .iter()
            .map(|k| k.key_id.as_str())
            .collect();
        format!(
            "config {} loaded: organization {}, api gate {}, govern key ids [{}], deadline {} s",
            self.digest,
            self.config.organization_id,
            self.config.api_gate_instance,
            ids.join(", "),
            self.config.deadline_seconds
        )
    }
}

/// Read and check the config at `path`, as user `uid`.
///
/// # Errors
/// Why the adapter must not start: the file's place or permissions, its
/// shape, or a value it may not hold.
pub fn load(path: &Path, uid: u32) -> Result<Loaded, String> {
    use std::os::unix::fs::MetadataExt;
    let shown = path.display();
    let meta =
        std::fs::symlink_metadata(path).map_err(|e| format!("CONFIG_UNREADABLE: {shown}: {e}"))?;
    if meta.file_type().is_symlink() {
        return Err(format!("CONFIG_UNSAFE: {shown} is a symlink"));
    }
    if !meta.is_file() {
        return Err(format!("CONFIG_UNSAFE: {shown} is not a file"));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(format!(
            "CONFIG_UNSAFE: {shown} is writable by group or others (mode {:o}); fix: chmod go-w {shown}",
            meta.mode() & 0o777
        ));
    }
    if meta.uid() != uid && meta.uid() != 0 {
        return Err(format!(
            "CONFIG_UNSAFE: {shown} belongs to uid {}, neither this process's ({uid}) nor root's; fix: chown {uid} {shown}",
            meta.uid()
        ));
    }
    if meta.len() > MAX_FILE {
        return Err(format!(
            "CONFIG_INVALID: {shown} is larger than {MAX_FILE} bytes"
        ));
    }
    let raw = std::fs::read(path).map_err(|e| format!("CONFIG_UNREADABLE: {shown}: {e}"))?;
    let config: Config =
        serde_json::from_slice(&raw).map_err(|e| format!("CONFIG_INVALID: {shown}: {e}"))?;
    check(&config).map_err(|why| format!("CONFIG_INVALID: {shown}: {why}"))?;
    Ok(Loaded {
        config,
        digest: format!("sha256:{:x}", Sha256::digest(&raw)),
    })
}

/// A CA bundle larger than this is refused unread.
const MAX_CA: u64 = 1024 * 1024;

/// The CA bundle `ca_pem_path` names, trusted for the gateway and its
/// sign-in service, or `None` when the config names none. The kit mounts it
/// read-only; a symlink or anything but a file is refused.
///
/// # Errors
/// `CA_UNREADABLE` or `CA_UNSAFE`.
pub fn ca_pem(g: &BackendGateway) -> Result<Option<Vec<u8>>, String> {
    let Some(path) = &g.ca_pem_path else {
        return Ok(None);
    };
    let shown = path.display();
    let meta =
        std::fs::symlink_metadata(path).map_err(|e| format!("CA_UNREADABLE: {shown}: {e}"))?;
    if !meta.is_file() {
        return Err(format!(
            "CA_UNSAFE: {shown} is not a file (a symlink is refused)"
        ));
    }
    if meta.len() > MAX_CA {
        return Err(format!("CA_UNSAFE: {shown} is larger than {MAX_CA} bytes"));
    }
    let pem = std::fs::read(path).map_err(|e| format!("CA_UNREADABLE: {shown}: {e}"))?;
    // A file with no certificate would quietly leave only the public roots,
    // for the gateway and for its sign-in service alike.
    match reqwest::Certificate::from_pem_bundle(&pem) {
        Ok(certs) if !certs.is_empty() => Ok(Some(pem)),
        _ => Err(format!("CA_UNSAFE: {shown} holds no PEM certificate")),
    }
}

/// One plain identifier: 1 to 128 printable ASCII characters, no spaces
/// (the schema's `^[!-~]{1,128}$`).
fn plain(s: &str) -> bool {
    (1..=128).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_graphic())
}

/// A lowercase hyphenated UUID (the schema's `$defs.uuid`).
fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(c),
        })
}

/// `^enclave[0-9a-f]{8}Api$`: the Enclave's own API-gate instance, as the
/// runner names it (`gate_report::local_instance_id`).
fn is_api_gate_instance(s: &str) -> bool {
    s.strip_prefix("enclave")
        .and_then(|r| r.strip_suffix("Api"))
        .is_some_and(|h| {
            h.len() == 8
                && h.bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        })
}

/// `^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$`, at most 512 characters: an
/// origin, https only, no path.
fn is_https_origin(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("https://") else {
        return false;
    };
    let (host, port) = match rest.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (rest, None),
    };
    s.len() <= 512
        && !host.is_empty()
        && host
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-')
        && port.is_none_or(|p| (1..=5).contains(&p.len()) && p.bytes().all(|c| c.is_ascii_digit()))
}

/// The schema's `issuer`: `^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~-]+)*$`,
/// no `.` or `..` segment, at most 512 characters: an https origin and an
/// optional path, with no user, query, fragment or trailing slash.
fn is_issuer(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("https://") else {
        return false;
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => rest.split_at(i),
        None => (rest, ""),
    };
    s.len() <= 512
        && is_https_origin(&format!("https://{authority}"))
        && path.split('/').skip(1).all(|seg| {
            !seg.is_empty()
                && seg != "."
                && seg != ".."
                && seg
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"._~-".contains(&c))
        })
}

/// `^[a-z0-9][a-z0-9._-]{0,62}$`.
fn is_name(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=63).contains(&b.len())
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._-".contains(c))
}

/// The schema's `absolute_path`: `^(/[A-Za-z0-9_.-]+)+$`, at most 255
/// characters, no `.` or `..` part.
fn is_absolute_path(p: &Path) -> bool {
    let Some(s) = p.to_str() else {
        return false;
    };
    s.len() <= 255
        && s.starts_with('/')
        && s[1..].split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
        })
}

/// The values a well-formed file may still not hold: the published schema's
/// rules (`backend/adapter-config.v1.schema.json`, contracts 0.60.0), checked
/// by `the_checks_are_the_published_schemas` against the vendored file.
///
/// # Errors
/// The first value refused, by name.
pub fn check(c: &Config) -> Result<(), String> {
    if c.config_version != 1 {
        return Err(format!(
            "config_version {} is not one this build reads (1)",
            c.config_version
        ));
    }
    if !is_uuid(&c.organization_id) {
        return Err("organization_id must be a lowercase hyphenated UUID".into());
    }
    if !is_api_gate_instance(&c.api_gate_instance) {
        return Err(
            "api_gate_instance must be enclave<8 lowercase hex>Api, the Enclave's own API gate"
                .into(),
        );
    }
    if c.govern_keys.is_empty() || c.govern_keys.len() > 2 {
        return Err("govern_keys must hold 1 or 2 keys (2 only while a rotation overlaps)".into());
    }
    for (i, k) in c.govern_keys.iter().enumerate() {
        if !plain(&k.key_id) {
            return Err(format!(
                "govern_keys[{i}].key_id must be 1 to 128 plain characters"
            ));
        }
        if c.govern_keys[..i].iter().any(|o| o.key_id == k.key_id) {
            return Err(format!("govern_keys names key_id '{}' twice", k.key_id));
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&k.public_key_b64)
            .map_err(|_| format!("govern_keys[{i}].public_key_b64 is not base64"))?;
        if bytes.len() != 32 || k.public_key_b64.len() != 44 {
            return Err(format!(
                "govern_keys[{i}].public_key_b64 must be a 32-byte Ed25519 key in 44 base64 characters"
            ));
        }
    }
    let g = &c.backend_gateway;
    if !is_https_origin(&g.url) {
        return Err("backend_gateway.url must be an https origin with no path".into());
    }
    if g.client_id != "ekka-desk-admin" {
        return Err("backend_gateway.client_id must be ekka-desk-admin".into());
    }
    if !is_name(&g.workspace) {
        return Err("backend_gateway.workspace must be a plain lowercase name".into());
    }
    if !is_issuer(&g.issuer) {
        return Err("backend_gateway.issuer must be https, a host, an optional port and an optional path, with no user, query, fragment, trailing slash or dot segment".into());
    }
    if g.ca_pem_path
        .as_deref()
        .is_some_and(|p| !is_absolute_path(p))
    {
        return Err("backend_gateway.ca_pem_path must be an absolute path".into());
    }
    if c.deadline_seconds == 0 || c.deadline_seconds >= DEADLINE_CEILING_SECONDS {
        return Err(format!(
            "deadline_seconds must be 1 to {}; the Enclave's call limit must not be reached first",
            DEADLINE_CEILING_SECONDS - 1
        ));
    }
    if !is_absolute_path(&c.socket_path) || !is_absolute_path(&c.state_dir) {
        return Err("socket_path and state_dir must be absolute paths of plain parts".into());
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "config_tests.rs"]
mod tests;
