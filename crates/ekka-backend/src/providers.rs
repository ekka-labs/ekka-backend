//! Provider digests, as the contract defines them, so the Enclave, the
//! adapter and an installer build ONE entry the same way.
//!
//! For every provider a desk carries, by the name it carries it under, the
//! entry is: the record's name, type, profile workspace and non-secret
//! `config`; the NAMES of its credentials, never a value; and its profile in
//! canonical JSON without the fields that change with no effect.
//!
//! - [`desk_digest`]: one digest over a desk's providers, sorted by name: the
//!   digest the Enclave pins.
//! - [`config_digest`]: ONE provider's configuration digest, `json_digest` of
//!   exactly its one entry: what a desk
//!   grant's `provider_config_digests` holds, and what `ekka-backend digest
//!   provider` prints for the kit.
//!
//! A credential VALUE that is not the literal `REDACTED` (what NVIDIA
//! OpenShell answers in place of every value) is refused, named by key and
//! never hashed, kept or printed.

use serde::Deserialize;
use serde_json::{json, Value};

use openshell_proto::openshell::datamodel::v1::Provider;
use openshell_proto::openshell::v1::ProviderProfile;

use crate::digest::json_digest;
use crate::normalize::{message, message_json, PROVIDER_PROFILE};

/// What OpenShell answers in place of every credential value.
pub const REDACTED: &str = "REDACTED";
/// The provider record's type name in the vendored proto.
pub const PROVIDER: &str = "openshell.datamodel.v1.Provider";

/// Profile fields that change without changing what a provider adds to a
/// sandbox, in both JSON spellings.
const VOLATILE: [&str; 10] = [
    "resourceVersion",
    "resource_version",
    "source",
    "scope",
    "annotations",
    "displayName",
    "display_name",
    "description",
    "category",
    "discovery",
];

fn without_volatile(mut v: Value) -> Value {
    if let Value::Object(m) = &mut v {
        for k in VOLATILE {
            m.remove(k);
        }
    }
    v
}

/// One provider's entry, exactly as the runner's `digest_of` builds it.
///
/// # Errors
/// `PROVIDER_CREDENTIAL_NOT_REDACTED` naming the key, or
/// `PROVIDER_PROFILE_UNREADABLE`.
fn entry(name: &str, p: &Provider, profile: &ProviderProfile) -> Result<Value, String> {
    if let Some(key) = p
        .credentials
        .iter()
        .find_map(|(k, v)| (v != REDACTED).then_some(k))
    {
        return Err(format!(
            "PROVIDER_CREDENTIAL_NOT_REDACTED: provider '{name}': credential '{key}' carries a value, not `{REDACTED}`; it is refused, never hashed"
        ));
    }
    let profile = message_json(PROVIDER_PROFILE, profile)
        .map(without_volatile)
        .ok_or_else(|| {
            format!("PROVIDER_PROFILE_UNREADABLE: provider '{name}': its profile could not be read as JSON")
        })?;
    let mut credential_names: Vec<&String> = p.credentials.keys().collect();
    credential_names.sort();
    let config: std::collections::BTreeMap<&String, &String> = p.config.iter().collect();
    Ok(json!({
        "name": name,
        "type": p.r#type,
        "profile_workspace": p.profile_workspace,
        "config": config,
        "credential_names": credential_names,
        "profile": profile,
    }))
}

/// One digest over a desk's providers, sorted by name: the runner's
/// `desk_providers::digest_of`. `status` answers it.
///
/// # Errors
/// As [`entry`].
pub fn desk_digest(items: &[(&str, &Provider, &ProviderProfile)]) -> Result<String, String> {
    let mut sorted: Vec<&(&str, &Provider, &ProviderProfile)> = items.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    let mut entries = Vec::with_capacity(items.len());
    for (name, p, profile) in sorted {
        entries.push(entry(name, p, profile)?);
    }
    Ok(json_digest(&json!({ "providers": entries })))
}

/// ONE provider's configuration digest: `json_digest` of its one entry.
///
/// # Errors
/// As [`entry`].
pub fn config_digest(
    name: &str,
    p: &Provider,
    profile: &ProviderProfile,
) -> Result<String, String> {
    entry(name, p, profile).map(|e| json_digest(&e))
}

/// The input `ekka-backend digest provider` reads, which the kit builds from
/// the gateway's own reads: the name a desk carries the provider under, its
/// record and its profile, each in NVIDIA OpenShell's proto JSON.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub name: String,
    pub provider: Value,
    pub profile: Value,
}

/// [`config_digest`] of an [`Input`].
///
/// # Errors
/// `PROVIDER_INPUT_INVALID` when the record or profile is not its proto
/// type (an unknown field included), or as [`entry`].
pub fn config_digest_of(input: &Input) -> Result<String, String> {
    if !crate::routes::plain_name(&input.name) {
        return Err("PROVIDER_INPUT_INVALID: name must be a plain provider name".into());
    }
    let p: Provider = message(PROVIDER, &input.provider).ok_or_else(|| {
        "PROVIDER_INPUT_INVALID: provider is not an NVIDIA OpenShell Provider record".to_string()
    })?;
    let profile: ProviderProfile = message(PROVIDER_PROFILE, &input.profile).ok_or_else(|| {
        "PROVIDER_INPUT_INVALID: profile is not an NVIDIA OpenShell ProviderProfile".to_string()
    })?;
    config_digest(&input.name, &p, &profile)
}

/// The profile OpenShell applies to a provider whose `profile_workspace` is
/// empty, from the profiles the desk workspace sees: the one with that id
/// whose scope is `static`, else `platform`, as the gateway's own
/// `scoped_type_profile_for_scope` chooses (e1f3c82). Ids compare trimmed and
/// lower case, as OpenShell compares them, so the Enclave and the adapter
/// choose the same profile.
///
/// # Errors
/// `PROVIDER_PROFILE_AMBIGUOUS` or `PROVIDER_PROFILE_NOT_FOUND`: EKKA never
/// guesses which profile the gateway applies.
pub fn platform_profile(id: &str, seen: Vec<ProviderProfile>) -> Result<ProviderProfile, String> {
    let norm = |x: &str| x.trim().to_ascii_lowercase();
    let want = norm(id);
    let mut same: Vec<ProviderProfile> = seen.into_iter().filter(|p| norm(&p.id) == want).collect();
    for scope in ["static", "platform"] {
        let n = same.iter().filter(|p| p.scope == scope).count();
        if n > 1 {
            return Err(format!(
                "PROVIDER_PROFILE_AMBIGUOUS: the desk backend lists {n} {scope} profiles '{id}'; which one it applies cannot be told"
            ));
        }
        if let Some(i) = same.iter().position(|p| p.scope == scope) {
            return Ok(same.swap_remove(i));
        }
    }
    Err(format!(
        "PROVIDER_PROFILE_NOT_FOUND: no static or platform profile '{id}' is listed in the desk workspace"
    ))
}

/// One provider by the name a desk carries it under, and the profile the
/// gateway applies to it, read over the same calls the Enclave makes: the record from the desk workspace; its profile
/// from its `profile_workspace`, or, when that is empty, the platform profile
/// the workspace sees.
///
/// # Errors
/// `PROVIDER_NOT_FOUND`, a profile refusal, or `PROVIDER_UNREADABLE` with the
/// gateway's code (`UNAUTHENTICATED` drops the token).
pub async fn read(
    gw: &crate::gateway::Gateway,
    bearer: &str,
    name: &str,
) -> Result<(Provider, ProviderProfile), (crate::gateway::GatewayError, String)> {
    let unreadable = |e: crate::gateway::GatewayError, what: &str| {
        let why = format!("PROVIDER_UNREADABLE: {what} could not be read: {e}");
        (e, why)
    };
    let p = gw
        .provider(bearer, name)
        .await
        .map_err(|e| unreadable(e, &format!("provider '{name}'")))?
        .ok_or_else(|| {
            (
                crate::gateway::GatewayError::NotFound,
                format!("PROVIDER_NOT_FOUND: the desk backend has no provider '{name}' in the desk workspace; connect '{name}' on the desk backend, then try again"),
            )
        })?;
    let what = format!("provider '{name}': its profile '{}'", p.r#type);
    let profile = if p.profile_workspace.is_empty() {
        let seen = gw
            .provider_profiles(bearer)
            .await
            .map_err(|e| unreadable(e, &what))?;
        platform_profile(&p.r#type, seen).map_err(|why| {
            (
                crate::gateway::GatewayError::NotFound,
                format!("{why} ({what})"),
            )
        })?
    } else {
        gw.provider_profile(bearer, &p.r#type, &p.profile_workspace)
            .await
            .map_err(|e| unreadable(e, &what))?
            .ok_or_else(|| {
                (
                    crate::gateway::GatewayError::NotFound,
                    format!("PROVIDER_PROFILE_NOT_FOUND: {what} does not exist"),
                )
            })?
    };
    Ok((p, profile))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "providers_tests.rs"]
mod tests;
