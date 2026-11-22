//! Governed provider creation/rotation. Operation bodies contain references only.
use super::*;
use openshell_proto::openshell::datamodel::v1::{ObjectMeta, Provider};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConnectBody {
    pub name: String,
    pub r#type: String,
    pub profile_workspace: String,
    pub credential_refs: BTreeMap<String, String>,
    #[serde(
        default,
        deserialize_with = "present_version",
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_resource_version: Option<String>,
}
fn present_version<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    String::deserialize(d).map(Some)
}

impl ConnectBody {
    pub(crate) fn check(&self, workspace: &str) -> Result<Option<u64>, Code> {
        if !crate::routes::plain_name(&self.name)
            || !crate::routes::plain_name(&self.r#type)
            || (!self.profile_workspace.is_empty() && self.profile_workspace != workspace)
            || self.credential_refs.len() > 8
            || self.credential_refs.iter().any(|(k, v)| {
                !crate::provider_credentials::key_name(k)
                    || uuid::Uuid::parse_str(v).is_err()
                    || v == "00000000-0000-0000-0000-000000000000"
                    || v.bytes().any(|b| b.is_ascii_uppercase())
                    || v.len() != 36
            })
        {
            return Err(Code::RequestInvalid);
        }
        let unique: std::collections::BTreeSet<_> = self.credential_refs.values().collect();
        if unique.len() != self.credential_refs.len() {
            return Err(Code::RequestInvalid);
        }
        self.expected_resource_version
            .as_ref()
            .map(|v| {
                v.parse::<u64>()
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or(Code::RequestInvalid)
            })
            .transpose()
    }
}
impl Backend {
    pub(crate) async fn connect_provider(
        &self,
        a: &Admitted,
        body: &ConnectBody,
        notes: &dyn Notes,
    ) -> Answer {
        let version = match body.check(self.gateway.workspace()) {
            Ok(v) => v,
            Err(c) => return refused(c),
        };
        let g = match enforce::grant(a.verified().grant.as_ref()) {
            Ok(g) => g,
            Err(c) => return refused(c),
        };
        if !g.providers.contains(&body.name) {
            return refused(Code::ConstraintProviders);
        }
        let Some(material) = a.verified().provider_credentials.as_ref() else {
            return refused(Code::CredentialMissing);
        };
        if !material.matches(&body.credential_refs) {
            return refused(Code::RequestInvalid);
        }
        let bearer = match self.bearer(a).await {
            Ok(b) => b,
            Err(a) => return a,
        };
        let existing = match self.gateway.provider(&bearer, &body.name).await {
            Ok(p) => p,
            Err(e) => return self.read_failed(&e),
        };
        let mut candidate = match (&existing, version) {
            (None, None) => Provider {
                metadata: Some(ObjectMeta {
                    name: body.name.clone(),
                    ..Default::default()
                }),
                r#type: body.r#type.clone(),
                profile_workspace: body.profile_workspace.clone(),
                config: HashMap::new(),
                ..Default::default()
            },
            (Some(p), Some(v)) if p.metadata.as_ref().is_some_and(|m| m.resource_version == v) => {
                if p.r#type != body.r#type || p.profile_workspace != body.profile_workspace {
                    return refused(Code::FieldNotAllowed);
                }
                p.clone()
            }
            _ => return refused(Code::VersionConflict),
        };
        if candidate
            .credentials
            .values()
            .any(|v| v != providers::REDACTED)
        {
            return refused(Code::BackendUnavailable);
        }
        let profile = if body.profile_workspace.is_empty() {
            match self.gateway.provider_profiles(&bearer).await {
                Ok(seen) => match providers::platform_profile(&body.r#type, seen) {
                    Ok(p) => p,
                    Err(_) => return refused(Code::BackendRefused),
                },
                Err(e) => return self.read_failed(&e),
            }
        } else {
            match self
                .gateway
                .provider_profile(&bearer, &body.r#type, &body.profile_workspace)
                .await
            {
                Ok(Some(p)) => p,
                Ok(None) => return refused(Code::BackendRefused),
                Err(e) => return self.read_failed(&e),
            }
        };
        if !crate::provider_info::enforced(&profile) {
            return refused(Code::ConstraintCredentialEndpoint);
        }
        for key in body.credential_refs.keys() {
            if !profile
                .credentials
                .iter()
                .any(|c| c.name == *key || c.env_vars.contains(key))
            {
                return refused(Code::FieldNotAllowed);
            }
            candidate
                .credentials
                .insert(key.clone(), providers::REDACTED.into());
        }
        for c in profile.credentials.iter().filter(|c| c.required) {
            if !candidate.credentials.contains_key(&c.name)
                && !c
                    .env_vars
                    .iter()
                    .any(|k| candidate.credentials.contains_key(k))
            {
                return refused(Code::CredentialMissing);
            }
        }
        let digest = match providers::config_digest(&body.name, &candidate, &profile) {
            Ok(d) => d,
            Err(_) => return refused(Code::BackendUnavailable),
        };
        if g.provider_config_digests.get(&body.name) != Some(&digest) {
            return refused(Code::ConstraintProviderConfigDigests);
        }
        // NVIDIA merges supplied credential keys; never send REDACTED values.
        // Provider reads include gateway-internal handles/expiry state. Never
        // submit those internal fields as user-authored provider input.
        candidate = Provider {
            metadata: Some(ObjectMeta {
                name: body.name.clone(),
                resource_version: version.unwrap_or(0),
                ..Default::default()
            }),
            r#type: body.r#type.clone(),
            profile_workspace: body.profile_workspace.clone(),
            config: candidate.config.clone(),
            credentials: material.for_gateway(),
            ..Default::default()
        };
        if !notes.sending() {
            return refused(Code::BackendUnavailable);
        }
        let result = self
            .gateway
            .write_provider(
                &bearer,
                candidate,
                &a.verified().request_id,
                version.is_some(),
            )
            .await;
        notes.sent();
        if let Err(e) = result {
            if e == GatewayError::Unauthenticated {
                self.tokens.rejected();
            }
            return match e {
                GatewayError::Unauthenticated | GatewayError::PermissionDenied => {
                    refused(Code::BackendRefused)
                }
                GatewayError::Refused {
                    code: tonic::Code::AlreadyExists | tonic::Code::Aborted,
                    ..
                } => refused(Code::VersionConflict),
                GatewayError::Refused {
                    code:
                        tonic::Code::InvalidArgument
                        | tonic::Code::FailedPrecondition
                        | tonic::Code::Unimplemented,
                    ..
                }
                | GatewayError::NotFound => refused(Code::BackendRefused),
                _ => Answer::unknown(),
            };
        }
        // Public configuration cannot prove a key was written. This read-back
        // counts only because the gateway acknowledged the preceding write.
        match providers::read(&self.gateway, &bearer, &body.name).await {
            Ok((p, profile))
                if providers::config_digest(&body.name, &p, &profile)
                    .ok()
                    .as_ref()
                    == Some(&digest) =>
            {
                Answer::ready(DeskFacts::default())
            }
            _ => Answer::unknown(),
        }
    }
}
#[cfg(test)]
#[path = "provider_connect_tests.rs"]
mod tests;
