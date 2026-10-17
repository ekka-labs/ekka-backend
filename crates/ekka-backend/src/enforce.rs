//! The constraint enforcer: what a
//! verified call may ask, against the limits Govern signed into its token
//! (`constraints.grant`, desks.v1). Every check here runs BEFORE the desk
//! backend is called; a refusal names the limit that refused it.
//!
//! The meaning of desks.v1's names in NVIDIA OpenShell's proto (pin 5a7728c,
//! v0.1.4) is the README's table:
//!
//! - `filesystem`, `process`: the policy's fields, byte-equal (canonical JSON)
//!   to the baseline: on a change, the desk's CREATION policy.
//! - `enforcement`: the policy's `landlock` equal to the baseline, AND every
//!   network endpoint ENFORCE (an AUDIT or unset endpoint is refused).
//! - `user_namespaces`, `driver`, `runtime`: template fields the adapter never
//!   sets and a policy change cannot reach; the post-write comparison answers
//!   `unknown` if a resulting sandbox carries any of them, or `resources`.
//!
//! The policy is read in one canonical form (`normalize`), so a rule sees the
//! same JSON whatever spelling the caller used.

use std::collections::BTreeSet;

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::answer::Code;
use crate::constraints::DeskConstraints;
use crate::digest_cmd::policy_digest;
use crate::normalize::{canonical, POLICY};

/// The gateway adds a rule under this prefix for each attached provider; a
/// caller's policy never carries one (OpenShell refuses them and adds them
/// back itself).
pub(crate) const PROVIDER_RULE: &str = "_provider_";
/// NVIDIA OpenShell's name for an enforced endpoint, in canonical JSON.
const ENFORCE: &str = "NETWORK_ENFORCEMENT_MODE_ENFORCE";

/// A create's body: the contract's `create_body`, strictly.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateBody {
    pub name: String,
    pub image: String,
    pub policy: Value,
    pub providers: Vec<String>,
    #[serde(default)]
    pub environment: Map<String, Value>,
    #[serde(default)]
    pub repo: Option<String>,
}

/// A policy change's body: the contract's `policy_set_body`. Its fields are
/// read by the driver.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PolicySetBody {
    pub policy: Value,
    pub expected_resource_version: String,
}

/// The grant's limits, from a verified token.
///
/// # Errors
/// `CONSTRAINTS_INVALID`: absent, or not desks.v1 (already checked at
/// verification; checked again, never assumed).
pub(crate) fn grant(v: Option<&Value>) -> Result<DeskConstraints, Code> {
    let v = v.ok_or(Code::ConstraintsInvalid)?;
    crate::constraints::check(v).map_err(|_| Code::ConstraintsInvalid)?;
    serde_json::from_value(v.clone()).map_err(|_| Code::ConstraintsInvalid)
}

/// A body of type `T`, or the contract's refusal: an unknown field is
/// `FIELD_NOT_ALLOWED`, anything else malformed is `REQUEST_INVALID`.
///
/// # Errors
/// As above.
pub(crate) fn body<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, Code> {
    serde_json::from_slice(bytes).map_err(|e| {
        if e.to_string().contains("unknown field") {
            Code::FieldNotAllowed
        } else {
            Code::RequestInvalid
        }
    })
}

/// A create, before the backend is called.
///
/// # Errors
/// The limit that refused it.
pub(crate) fn create(g: &DeskConstraints, b: &CreateBody) -> Result<Value, Code> {
    if !crate::routes::plain_name(&b.name) {
        return Err(Code::RequestInvalid);
    }
    let digest = image_digest(&b.image).ok_or(Code::RequestInvalid)?;
    if !g.image_digests.contains(&digest) {
        return Err(Code::ConstraintImageDigests);
    }
    let policy = canonical(POLICY, &b.policy).ok_or(Code::RequestInvalid)?;
    let pd = policy_digest(&b.policy).ok_or(Code::RequestInvalid)?;
    if !g.policy_digests.contains(&pd) {
        return Err(Code::ConstraintPolicyDigests);
    }
    network(g, &policy)?;
    let mut seen = BTreeSet::new();
    for p in &b.providers {
        if !seen.insert(p) || !crate::routes::plain_name(p) {
            return Err(Code::RequestInvalid);
        }
        if !g.providers.contains(p) {
            return Err(Code::ConstraintProviders);
        }
    }
    for (k, v) in &b.environment {
        if !v.is_string() {
            return Err(Code::RequestInvalid);
        }
        if !g.environment_keys.contains(k) {
            return Err(Code::ConstraintEnvironmentKeys);
        }
    }
    // Contracts 0.65.0: nothing on a desk reads `repo` (repositories reach a
    // desk through a setup plan); one given is refused, never accepted and
    // dropped. The grant's `repo_hosts` is unused.
    if b.repo.as_deref().is_some_and(|r| !r.is_empty()) {
        return Err(Code::FieldNotAllowed);
    }
    Ok(policy)
}

/// A policy change, against the desk's creation policy `baseline`, before the
/// backend is called. Returns the new policy in canonical form. Called by the
/// driver, which reads the baseline.
///
/// # Errors
/// The limit that refused it.
pub(crate) fn policy_change(
    g: &DeskConstraints,
    baseline: &Value,
    new: &Value,
) -> Result<Value, Code> {
    let base = canonical(POLICY, baseline).ok_or(Code::BackendRefused)?;
    let next = canonical(POLICY, new).ok_or(Code::RequestInvalid)?;
    for part in ["filesystem", "process", "landlock"] {
        if base.get(part) != next.get(part) {
            return Err(Code::ConstraintPolicyBaseline);
        }
    }
    network(g, &next)?;
    let allowed = programs(&base);
    if !programs(&next).is_subset(&allowed) {
        return Err(Code::ConstraintPolicyBaseline);
    }
    // A rule with no programs is open to ANY program (OpenShell,
    // openshell-policy merge.rs:1537 at e1f3c82), and an empty set is a
    // subset of every baseline: so it is checked on its own.
    if any_program(&next) && !any_program(&base) {
        return Err(Code::ConstraintPolicyBaseline);
    }
    let kept = credentialed(&base);
    if !credentialed(&next).iter().all(|e| kept.contains(e)) {
        return Err(Code::ConstraintCredentialEndpoint);
    }
    Ok(next)
}

/// Endpoint fields that let a request carry a provider's credentials
/// (`NetworkEndpoint`, pin 5a7728c, v0.1.4), in canonical JSON. desks.v1 names none
/// of them, so a change may not reach them: see [`credentialed`].
const CREDENTIAL_FIELDS: [&str; 9] = [
    "credentialBinding",
    "allowUninspectedCredentials",
    "providerCredentialed",
    "credentialSigning",
    "signingService",
    "signingRegion",
    "tokenGrantOwner",
    "websocketCredentialRewrite",
    "requestBodyCredentialRewrite",
];

/// Every endpoint that carries a credential field, with the rule it sits in
/// and that rule's programs. A policy change keeps each one exactly as the
/// creation policy has it, or drops it: adding, changing or moving one, or
/// giving its rule another program, would send a provider's credentials
/// somewhere the creation policy (whose digest the grant lists) never did.
fn credentialed(policy: &Value) -> Vec<(&String, Option<&Value>, &Value)> {
    rules(policy)
        .flat_map(|(name, r)| {
            r.get("endpoints")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter(|e| {
                    CREDENTIAL_FIELDS
                        .iter()
                        .any(|f| e.get(f).is_some_and(|v| !v.is_null()))
                })
                .map(move |e| (name, r.get("binaries"), e))
        })
        .collect()
}

/// A caller's rule reaches an endpoint with no `binaries`, which OpenShell
/// reads as any program.
fn any_program(policy: &Value) -> bool {
    rules(policy).any(|(_, r)| {
        let reaches = r
            .get("endpoints")
            .and_then(Value::as_array)
            .is_some_and(|e| !e.is_empty());
        let named = r
            .get("binaries")
            .and_then(Value::as_array)
            .is_some_and(|b| !b.is_empty());
        reaches && !named
    })
}

/// Every program a policy's network rules name, the gateway's provider rules
/// left out.
fn programs(policy: &Value) -> BTreeSet<String> {
    rules(policy)
        .flat_map(|(_, r)| {
            r.get("binaries")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
        })
        .filter_map(|b| b.get("path").and_then(Value::as_str).map(str::to_string))
        .collect()
}

/// The caller's own network rules: every rule but the gateway's provider
/// rules (which a caller's policy may not carry at all; see [`network`]).
fn rules(policy: &Value) -> impl Iterator<Item = (&String, &Value)> {
    policy
        .get("networkPolicies")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter(|(k, _)| !k.starts_with(PROVIDER_RULE))
}

/// The network rules every policy must keep, at create and after a change.
fn network(g: &DeskConstraints, policy: &Value) -> Result<(), Code> {
    let all = policy.get("networkPolicies").and_then(Value::as_object);
    if all.is_some_and(|m| m.keys().any(|k| k.starts_with(PROVIDER_RULE))) {
        return Err(Code::FieldNotAllowed);
    }
    if policy
        .get("networkMiddlewares")
        .and_then(Value::as_object)
        .is_some_and(|m| !m.is_empty())
    {
        return Err(Code::FieldNotAllowed);
    }
    let net = &g.policy_baseline.network;
    for (_, rule) in rules(policy) {
        for e in rule
            .get("endpoints")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if e.get("enforcement").and_then(Value::as_str) != Some(ENFORCE) {
                return Err(Code::ConstraintPolicyBaseline);
            }
            let host = e.get("host").and_then(Value::as_str).unwrap_or_default();
            let ips: Vec<&str> = e
                .get("allowedIps")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            if host.is_empty() && ips.is_empty() {
                return Err(Code::ConstraintAllowedHosts);
            }
            if !host.is_empty() && !host_allowed(&g.allowed_hosts, host) {
                return Err(Code::ConstraintAllowedHosts);
            }
            if !ips.iter().all(|ip| cidr_allowed(&net.allowed_cidrs, ip)) {
                return Err(Code::ConstraintPolicyBaseline);
            }
            let mut ports: Vec<u64> = e
                .get("ports")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_u64)
                .collect();
            if let Some(p) = e.get("port").and_then(Value::as_u64) {
                ports.push(p);
            }
            // No port at all reaches every port: refused.
            if ports.is_empty()
                || !ports
                    .iter()
                    .all(|p| net.allowed_ports.iter().any(|a| u64::from(*a) == *p))
            {
                return Err(Code::ConstraintPolicyBaseline);
            }
        }
    }
    Ok(())
}

/// `host` is inside the ceiling: equal to an entry, or under a `*.` entry. A
/// wildcard host is inside only a wildcard that covers it.
#[must_use]
pub(crate) fn host_allowed(ceiling: &[String], host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    ceiling.iter().any(|c| {
        if c == &host {
            return true;
        }
        let Some(domain) = c.strip_prefix("*.") else {
            return false;
        };
        let under = |h: &str| h.len() > domain.len() + 1 && h.ends_with(&format!(".{domain}"));
        match host.strip_prefix("*.") {
            Some(inner) => inner == domain || under(inner),
            None => under(&host),
        }
    })
}

/// An IPv4 address in the one spelling every parser reads alike: the
/// standard library's, which refuses a sign, a leading zero (octal to some
/// parsers) and whitespace.
fn parse_v4(s: &str) -> Option<u32> {
    s.parse::<std::net::Ipv4Addr>().ok().map(u32::from)
}

fn parse_cidr(s: &str) -> Option<(u32, u32)> {
    let (addr, bits) = s.split_once('/').unwrap_or((s, "32"));
    let plain = bits.bytes().all(|b| b.is_ascii_digit()) && (bits == "0" || !bits.starts_with('0'));
    let bits: u32 = Some(bits)
        .filter(|_| plain)
        .and_then(|b| b.parse().ok())
        .filter(|b| *b <= 32)?;
    let mask = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    };
    Some((parse_v4(addr)? & mask, mask))
}

/// `ip` (an address or a range) is inside one of `allowed`. Empty means none;
/// anything that is not IPv4 is refused.
#[must_use]
pub(crate) fn cidr_allowed(allowed: &[String], ip: &str) -> bool {
    let Some((net, mask)) = parse_cidr(ip) else {
        return false;
    };
    allowed
        .iter()
        .filter_map(|a| parse_cidr(a))
        .any(|(an, am)| {
            // The asked range is inside the allowed one: at least as narrow, and
            // its network falls in the allowed network.
            mask & am == am && net & am == an
        })
}

/// The image's digest, as the contract's `create_body.image` pattern reads
/// it (`^([a-z0-9][a-z0-9._/:-]{0,255}@)?sha256:[0-9a-f]{64}$`): after `@`
/// for `<name>@sha256:<64 hex>`, an image from a registry; or the whole
/// value for `sha256:<64 hex>` alone, an image the machine built itself, by
/// its local content ID (contracts 0.62.0). Anything else is `None`.
fn image_digest(image: &str) -> Option<String> {
    let (name, digest) = match image.rsplit_once('@') {
        Some((name, digest)) => (Some(name), digest),
        None => (None, image),
    };
    let name_ok = name.is_none_or(|n| {
        let b = n.as_bytes();
        (1..=256).contains(&b.len())
            && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
            && b.iter()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._/:-".contains(c))
    });
    let hex = digest.strip_prefix("sha256:")?;
    let hex_ok = hex.len() == 64
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    (name_ok && hex_ok).then(|| format!("sha256:{hex}"))
}

/// What a create asked for, to compare with the sandbox the backend made.
/// Used by the driver.
pub(crate) struct Expected<'a> {
    pub image: &'a str,
    pub policy: &'a Value,
    pub providers: &'a [String],
}

/// The POST-WRITE comparison: the sandbox the backend reports
/// (NVIDIA OpenShell's `Sandbox`, proto JSON) is what was asked, and carries
/// none of the template fields the adapter never sets. `false` means the
/// change completed but the desk does not match: the answer is `unknown`.
#[must_use]
pub(crate) fn result_matches(e: &Expected<'_>, sandbox: &Value) -> bool {
    let spec = &sandbox["spec"];
    let template = &spec["template"];
    let image_ok = template["image"].as_str() == Some(e.image);
    let mut want: Vec<&String> = e.providers.iter().collect();
    want.sort();
    let mut got: Vec<&str> = spec["providers"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    got.sort_unstable();
    let providers_ok = want.iter().map(|s| s.as_str()).eq(got.iter().copied());
    let policy_ok = match (policy_digest(e.policy), policy_digest(&spec["policy"])) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    };
    let forbidden = [
        "userNamespaces",
        "driverConfig",
        "runtimeClassName",
        "resources",
    ];
    let template_ok = forbidden
        .iter()
        .all(|f| template.get(f).is_none_or(Value::is_null))
        && spec.get("resourceRequirements").is_none_or(Value::is_null);
    image_ok && providers_ok && policy_ok && template_ok
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "enforce_tests.rs"]
mod tests;
