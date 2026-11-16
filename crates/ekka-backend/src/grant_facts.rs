//! `grant_facts`: what a desks grant's limits are built from, computed by the
//! functions the adapter enforces those limits with (contracts 0.83.0).
//!
//! - The baseline policy: read from [`super::BASELINE_POLICY`], never from a
//!   request, at most 1 MiB, and digested by `policy_digest`, the function a
//!   create's policy is checked with.
//! - Every provider in the desk workspace, read whole, each digested by
//!   `providers::config_digest`, the function a create checks a grant's
//!   `provider_config_digests` with. A provider whose digest cannot be
//!   computed carries a code instead, never a digest.
//!
//! Nothing is written and no change is sent. Digests and names only: never a
//! credential, a profile or a policy's content.

use std::collections::BTreeSet;
use std::io::Read as _;
use std::path::Path;

use super::{refused, Backend};
use crate::answer::{Answer, Code, DeskFacts, Fact, FactCode, GrantFacts, ProviderFact};
use crate::digest_cmd::policy_digest;
use crate::gateway::GatewayError;
use crate::providers::{self, Miss};
use crate::token::Admitted;

/// The largest baseline policy read.
const MAX_BASELINE: u64 = 1024 * 1024;

/// The most providers one answer carries; more is refused, never cut.
pub const MAX_PROVIDERS: usize = 64;

/// The baseline policy's digest, from at most [`MAX_BASELINE`] bytes read.
///
/// Opened without blocking, and read only when what was opened is a regular
/// file: a pipe or a device at the path is refused, never waited on. The
/// check is on the opened file, so nothing can swap the path after it.
fn baseline_digest(path: &Path) -> Result<String, Code> {
    use rustix::fs::{fstat, open, FileType, Mode, OFlags};
    let fd = match open(
        path,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOCTTY,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Err(Code::BaselinePolicyMissing),
        Err(_) => return Err(Code::BaselinePolicyUnreadable),
    };
    match fstat(&fd) {
        Ok(st) if FileType::from_raw_mode(st.st_mode) == FileType::RegularFile => {}
        _ => return Err(Code::BaselinePolicyUnreadable),
    }
    let file = std::fs::File::from(fd);
    let mut bytes = Vec::new();
    file.take(MAX_BASELINE + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Code::BaselinePolicyUnreadable)?;
    if bytes.len() as u64 > MAX_BASELINE {
        return Err(Code::BaselinePolicyUnreadable);
    }
    let v: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| Code::BaselinePolicyInvalid)?;
    policy_digest(&v).ok_or(Code::BaselinePolicyInvalid)
}

impl Backend {
    /// `grant_facts`: the baseline first, so a missing one costs no gateway
    /// call; then the provider list, whole or refused; then each provider.
    pub async fn grant_facts(&self, a: &Admitted) -> Answer {
        let path = self.baseline_policy.clone();
        let baseline = match tokio::task::spawn_blocking(move || baseline_digest(&path)).await {
            Ok(Ok(d)) => d,
            Ok(Err(code)) => return refused(code),
            Err(_) => return refused(Code::BaselinePolicyUnreadable),
        };
        let bearer = match self.bearer(a).await {
            Ok(b) => b,
            Err(answer) => return answer,
        };
        let listed = match self.gateway.providers(&bearer).await {
            Ok(l) => l,
            Err(e) => {
                if e == GatewayError::Unauthenticated {
                    self.tokens.rejected();
                }
                return refused(Code::ProvidersUnreadable);
            }
        };
        if listed.len() > MAX_PROVIDERS {
            return refused(Code::ProvidersTooMany);
        }
        // Each provider by its own name, which must be a plain name and
        // appear once: a list that breaks either is not answered at all.
        let mut names = BTreeSet::new();
        for p in &listed {
            let name = p.metadata.as_ref().map_or("", |m| m.name.as_str());
            if !crate::routes::plain_name(name) || !names.insert(name.to_string()) {
                return refused(Code::ProvidersUnreadable);
            }
        }
        let mut providers = Vec::with_capacity(names.len());
        for name in names {
            let fact = self.provider_fact(&bearer, &name).await;
            providers.push(ProviderFact { name, fact });
        }
        Answer::ready(DeskFacts {
            grant_facts: Some(GrantFacts {
                baseline_policy_digest: baseline,
                providers,
            }),
            ..DeskFacts::default()
        })
    }

    /// One provider's digest, read and computed exactly as a create checks
    /// it, or why there is none.
    async fn provider_fact(&self, bearer: &str, name: &str) -> Fact {
        match providers::read(&self.gateway, bearer, name).await {
            Ok((p, profile)) => match providers::config_digest(name, &p, &profile) {
                Ok(d) => Fact::Digest(d),
                // A credential carrying a value, or a profile not readable
                // as JSON: no digest, and nothing of it is answered.
                Err(_) => Fact::Code(FactCode::ProviderUnreadable),
            },
            Err((Miss::Profile, _)) => Fact::Code(FactCode::ProviderProfileMissing),
            Err((Miss::Gateway(e), _)) => {
                if e == GatewayError::Unauthenticated {
                    self.tokens.rejected();
                }
                Fact::Code(FactCode::ProviderUnreadable)
            }
            // Gone since the list, or which profile applies cannot be told.
            Err((Miss::Provider | Miss::Ambiguous, _)) => Fact::Code(FactCode::ProviderUnreadable),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "grant_facts_tests.rs"]
mod tests;
