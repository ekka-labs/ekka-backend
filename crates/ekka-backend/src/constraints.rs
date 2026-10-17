//! The desk grant's limits (`governance/grant-constraints/desks.v1`), as a
//! token carries them under `constraints.grant`. The schema is CLOSED: an
//! unknown key is refused, never ignored, because an ignored limit is a limit
//! nobody enforces.
//!
//! The same checks EKKA runs on a limits file before a grant is made; here
//! they run on what Govern signed. `the_mirror_is_the_vendored_schema`
//! compares them with the vendored schema.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;

/// The six policy parts a desk's policy may never change; all of them.
pub(crate) const MUST_EQUAL: [&str; 6] = [
    "filesystem",
    "process",
    "user_namespaces",
    "enforcement",
    "driver",
    "runtime",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeskConstraints {
    pub image_digests: Vec<String>,
    pub policy_digests: Vec<String>,
    pub allowed_hosts: Vec<String>,
    pub providers: Vec<String>,
    pub provider_config_digests: BTreeMap<String, String>,
    pub environment_keys: Vec<String>,
    pub repo_hosts: Vec<String>,
    pub policy_baseline: PolicyBaseline,
    pub requires_role: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PolicyBaseline {
    pub must_equal: Vec<String>,
    pub network: Network,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Network {
    pub allowed_hosts: Vec<String>,
    pub allowed_ports: Vec<u32>,
    pub allowed_cidrs: Vec<String>,
    pub provider_added: String,
}

/// The schema's rules, on a parsed value.
///
/// # Errors
/// The first rule broken, naming the field.
pub(crate) fn check(value: &Value) -> Result<(), String> {
    let c: DeskConstraints = serde_json::from_value(value.clone())
        .map_err(|e| format!("not desk grant limits (desks.v1): {e}"))?;
    list("image_digests", &c.image_digests, 1, 32, is_digest)?;
    list("policy_digests", &c.policy_digests, 1, 32, is_digest)?;
    list(
        "allowed_hosts",
        &c.allowed_hosts,
        1,
        64,
        is_host_or_wildcard,
    )?;
    list("providers", &c.providers, 0, 16, is_name)?;
    if c.provider_config_digests.len() > 16 {
        return Err("provider_config_digests has more than 16 entries".into());
    }
    for (name, digest) in &c.provider_config_digests {
        if !is_name(name) {
            return Err(format!(
                "provider_config_digests: '{}' is not a provider name",
                name.escape_debug()
            ));
        }
        if !is_digest(digest) {
            return Err(format!(
                "provider_config_digests.{name}: not sha256:<64 lowercase hex>"
            ));
        }
    }
    list("environment_keys", &c.environment_keys, 0, 64, is_env_key)?;
    list("repo_hosts", &c.repo_hosts, 0, 16, is_host)?;
    let b = &c.policy_baseline;
    let mut must: Vec<&str> = b.must_equal.iter().map(String::as_str).collect();
    must.sort_unstable();
    let mut want = MUST_EQUAL;
    want.sort_unstable();
    if must != want {
        return Err(format!(
            "policy_baseline.must_equal must list all six, once each: {}",
            MUST_EQUAL.join(", ")
        ));
    }
    let n = &b.network;
    list(
        "policy_baseline.network.allowed_hosts",
        &n.allowed_hosts,
        0,
        64,
        is_host_or_wildcard,
    )?;
    if n.allowed_ports.is_empty() || n.allowed_ports.len() > 16 {
        return Err("policy_baseline.network.allowed_ports must name 1 to 16 ports".into());
    }
    if n.allowed_ports.iter().any(|p| !(1..=65_535).contains(p)) {
        return Err("policy_baseline.network.allowed_ports: a port is 1 to 65535".into());
    }
    if has_duplicates(&n.allowed_ports) {
        return Err("policy_baseline.network.allowed_ports names a port twice".into());
    }
    list(
        "policy_baseline.network.allowed_cidrs",
        &n.allowed_cidrs,
        0,
        16,
        is_cidr,
    )?;
    if n.provider_added != "listed_only" {
        return Err("policy_baseline.network.provider_added must be \"listed_only\"".into());
    }
    if c.requires_role != "admin" {
        return Err("requires_role must be \"admin\"".into());
    }
    Ok(())
}

fn list(
    field: &str,
    items: &[String],
    min: usize,
    max: usize,
    ok: fn(&str) -> bool,
) -> Result<(), String> {
    if items.len() < min || items.len() > max {
        return Err(format!("{field} must have {min} to {max} entries"));
    }
    if let Some(bad) = items.iter().find(|i| !ok(i)) {
        return Err(format!(
            "{field}: '{}' is not allowed there",
            bad.escape_debug()
        ));
    }
    if has_duplicates(items) {
        return Err(format!("{field} names an entry twice"));
    }
    Ok(())
}

fn has_duplicates<T: Ord>(items: &[T]) -> bool {
    let mut seen: Vec<&T> = items.iter().collect();
    seen.sort_unstable();
    seen.windows(2).any(|w| w[0] == w[1])
}

/// `sha256:<64 lowercase hex>`.
fn is_digest(s: &str) -> bool {
    s.strip_prefix("sha256:").is_some_and(|h| {
        h.len() == 64
            && h.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
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

/// `^[A-Za-z_][A-Za-z0-9_]{0,127}$`.
fn is_env_key(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=128).contains(&b.len())
        && (b[0].is_ascii_alphabetic() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
}

/// One DNS label: `[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?`.
fn is_label(l: &str) -> bool {
    let b = l.as_bytes();
    let edge = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    (1..=63).contains(&b.len())
        && edge(b[0])
        && edge(b[b.len() - 1])
        && b.iter().all(|c| edge(*c) || *c == b'-')
}

/// Two or more labels joined by dots.
fn is_host(s: &str) -> bool {
    let labels: Vec<&str> = s.split('.').collect();
    labels.len() >= 2 && labels.iter().all(|l| is_label(l))
}

/// A host, or `*.` and a host.
fn is_host_or_wildcard(s: &str) -> bool {
    is_host(s.strip_prefix("*.").unwrap_or(s))
}

/// An IPv4 address range, `a.b.c.d/n` with n from 0 to 32, no leading zeros
/// beyond what the schema's pattern allows.
fn is_cidr(s: &str) -> bool {
    let Some((addr, bits)) = s.split_once('/') else {
        return false;
    };
    let octet = |o: &str| {
        !o.is_empty()
            && o.len() <= 3
            && o.bytes().all(|b| b.is_ascii_digit())
            && o.parse::<u16>().is_ok_and(|n| n <= 255)
            && !(o.len() == 3 && o.starts_with('0'))
    };
    let parts: Vec<&str> = addr.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|o| octet(o))
        && !bits.is_empty()
        && bits.len() <= 2
        && bits.bytes().all(|b| b.is_ascii_digit())
        && bits.parse::<u8>().is_ok_and(|n| n <= 32)
        && !(bits.len() == 2 && bits.starts_with('0'))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "constraints_tests.rs"]
mod tests;
