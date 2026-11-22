//! Local-only metadata for governed provider setup; never credential/config values.
use crate::answer::{Answer, Code, DeskFacts};
use crate::driver::Backend;
use crate::providers;
use crate::token::Admitted;
use openshell_proto::openshell::datamodel::v1::Provider;
use openshell_proto::openshell::v1::ProviderProfile;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialDescriptor {
    pub name: String,
    pub env_vars: Vec<String>,
    pub required: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderInfo {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub profile_workspace: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configuration_digest: Option<String>,
    pub credential_names: Vec<String>,
    pub credentials: Vec<CredentialDescriptor>,
    pub enforced: bool,
}

pub(crate) fn enforced(profile: &ProviderProfile) -> bool {
    use openshell_proto::openshell::sandbox::v1::NetworkEnforcementMode;
    profile
        .endpoints
        .iter()
        .all(|e| e.enforcement == NetworkEnforcementMode::Enforce as i32)
}

impl Backend {
    pub(crate) async fn provider_info(&self, a: &Admitted, name: &str) -> Answer {
        let refuse = Answer::refused;
        let bearer = match self.tokens.bearer(a.verified().credential.expose()).await {
            Ok(b) => b,
            Err(_) => return refuse(Code::BackendUnavailable),
        };
        let existing = match self.gateway.provider(&bearer, name).await {
            Ok(p) => p,
            Err(_) => return refuse(Code::BackendUnavailable),
        };
        let kind = existing.as_ref().map_or(name, |p| p.r#type.as_str());
        if !crate::routes::plain_name(kind) {
            return refuse(Code::BackendUnavailable);
        }
        let mut workspace = existing
            .as_ref()
            .map_or(String::new(), |p| p.profile_workspace.clone());
        if !workspace.is_empty() && workspace != self.gateway.workspace() {
            return refuse(Code::BackendUnavailable);
        }
        let profile = if workspace.is_empty() {
            let all = match self.gateway.provider_profiles(&bearer).await {
                Ok(p) => p,
                Err(_) => return refuse(Code::BackendUnavailable),
            };
            match providers::platform_profile(kind, all) {
                Ok(p) => p,
                Err((providers::Miss::Profile, _)) if existing.is_none() => {
                    workspace = self.gateway.workspace().into();
                    match self
                        .gateway
                        .provider_profile(&bearer, kind, &workspace)
                        .await
                    {
                        Ok(Some(p)) => p,
                        _ => return refuse(Code::BackendRefused),
                    }
                }
                Err(_) => return refuse(Code::BackendRefused),
            }
        } else {
            match self
                .gateway
                .provider_profile(&bearer, kind, &workspace)
                .await
            {
                Ok(Some(p)) => p,
                _ => return refuse(Code::BackendRefused),
            }
        };
        let (version, mut names) = match existing.as_ref() {
            Some(p) => {
                if p.credentials.values().any(|v| v != providers::REDACTED) {
                    return refuse(Code::BackendUnavailable);
                }
                let Some(meta) = p
                    .metadata
                    .as_ref()
                    .filter(|m| m.name == name && m.resource_version > 0)
                else {
                    return refuse(Code::BackendUnavailable);
                };
                (
                    Some(meta.resource_version.to_string()),
                    p.credentials.keys().cloned().collect::<Vec<_>>(),
                )
            }
            None => (None, Vec::new()),
        };
        names.sort();
        if names.len() > 64
            || profile.credentials.len() > 8
            || names
                .iter()
                .any(|n| !crate::provider_credentials::key_name(n))
            || profile.credentials.iter().any(|c| {
                !crate::provider_credentials::key_name(&c.name)
                    || c.env_vars.len() > 16
                    || c.env_vars
                        .iter()
                        .any(|n| !crate::provider_credentials::key_name(n))
            })
        {
            return refuse(Code::BackendUnavailable);
        }
        // A first provider can be granted before a key exists. For a single
        // declared credential (or a keyless profile), its default non-secret
        // configuration is unambiguous. No credential value is hashed.
        let configuration_digest = match existing.as_ref() {
            Some(p) => match providers::config_digest(name, p, &profile) {
                Ok(d) => Some(d),
                Err(_) => return refuse(Code::BackendUnavailable),
            },
            None if profile.credentials.len() <= 1 => {
                let credentials = profile
                    .credentials
                    .iter()
                    .map(|c| {
                        (
                            c.env_vars.first().unwrap_or(&c.name).clone(),
                            providers::REDACTED.into(),
                        )
                    })
                    .collect();
                let proposed = Provider {
                    r#type: kind.into(),
                    profile_workspace: workspace.clone(),
                    credentials,
                    ..Default::default()
                };
                match providers::config_digest(name, &proposed, &profile) {
                    Ok(d) => Some(d),
                    Err(_) => return refuse(Code::BackendUnavailable),
                }
            }
            None => None,
        };
        let info = ProviderInfo {
            name: name.into(),
            kind: kind.into(),
            profile_workspace: workspace,
            resource_version: version,
            credential_names: names,
            configuration_digest,
            enforced: enforced(&profile),
            credentials: profile
                .credentials
                .into_iter()
                .map(|c| CredentialDescriptor {
                    name: c.name,
                    env_vars: c.env_vars,
                    required: c.required,
                })
                .collect(),
        };
        Answer::ready(DeskFacts {
            provider_info: Some(info),
            ..Default::default()
        })
    }
}
