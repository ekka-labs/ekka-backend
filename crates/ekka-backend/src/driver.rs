//! The NVIDIA OpenShell driver: each admitted call as the
//! gateway calls the plan's table names, between a claim on the desk at the
//! Enclave and its release.
//!
//! A change runs in one order, and every step that refuses says so by the
//! contract's code:
//!
//! 1. its gateway token, minted from the call's own credential (`signin`);
//! 2. its claim on the desk at the Enclave (`claims`); a busy desk is
//!    `DESK_BUSY`, and the claim names the desk's required providers;
//! 3. what must hold before the call (the creation policy a policy change is
//!    held to; a required provider is never detached);
//! 4. the gateway call, with the operation's request id as OpenShell's
//!    `request_id`;
//! 5. a read-back of the desk; its answer written to the operation's record;
//!    and only then the release with its outcome ([`Backend::conclude`]).
//!
//! A refusal before the call releases the claim `refused`: nothing changed.
//! Every release follows the record's settle (the plan's order): a record
//! that cannot be written keeps the desk held.
//! A call whose answer is lost, or that the gateway holds as UNCERTAIN, may
//! still finish: it answers `running` (202, the request id) and its claim is
//! NOT released, so the desk stays held and no person can release it by
//! hand; only recovery (`recover.rs`) frees it. A
//! change that completed but whose desk does not match answers `unknown`.
//! Reads (`status`, `policy_get`) take no claim.

use openshell_proto::openshell::sandbox::v1::SandboxPolicy;
use openshell_proto::openshell::v1::{
    CreateSandboxRequest, Sandbox, SandboxPhase, SandboxSpec, SandboxTemplate,
};
use serde_json::Value;

use crate::answer::{Answer, Code, DeskFacts};
use crate::claims::{ClaimError, Claims, Outcome, ReadBack};
use crate::enforce;
use crate::gateway::{Gateway, GatewayError};
use crate::normalize::{message, message_digest, message_json, POLICY};
use crate::providers;
use crate::signin::{SignInError, Tokens};
use crate::store::PendingRelease;
use crate::token::Admitted;

/// The label that marks a sandbox as an EKKA desk, and the one naming the
/// operation that made it. The Enclave reads both.
pub const DESK_LABEL: &str = "ekka.ai/desk";
pub const OPERATION_LABEL: &str = "ekka.ai/operation";
/// The annotation the Enclave's auto-registration reads as the desk's
/// REQUIRED providers.
pub const PROVIDERS_ANNOTATION: &str = "ekka.ai/desk-providers";
/// How many times a change's result is read back while the gateway is still
/// carrying it out (a delete accepted before the sandbox disappears; a stop
/// before the sandbox stops), and the wait between reads.
const SETTLE_READS: usize = 20;
const SETTLE_WAIT: std::time::Duration = std::time::Duration::from_millis(250);

/// The backend the driver reaches.
pub struct Backend {
    pub gateway: Gateway,
    pub tokens: Tokens,
    pub claims: Claims,
    /// The operation records: a change's answer is written here BEFORE its
    /// claim is released ([`Backend::conclude`]).
    pub records: Records,
}

/// Where the driver writes a change's answer before it releases the claim.
/// A production build has only a store: "no records" cannot be built
/// outside a test, so a release can never skip the write (an optional
/// store would fail open).
pub enum Records {
    Store(std::sync::Arc<crate::store::Store>),
    /// A driver unit test: no record exists, nothing is written first.
    #[cfg(test)]
    Unrecorded,
}

/// What became of a release.
enum Release {
    Done,
    /// Still owed, as it was.
    Owed,
    /// Still owed, now as this outcome.
    OwedAs(Outcome),
}

/// A refusal before any change, by its code.
fn refused(code: Code) -> Answer {
    Answer::refused(code)
}

/// What the driver writes to the operation's record, durably, before it
/// acts. Each says whether it was written: an unwritten note sends
/// nothing.
pub trait Notes: Send + Sync {
    /// The desk's backend id, before a delete is sent (once the desk is
    /// gone it cannot be read).
    fn backend_id(&self, id: &str) -> bool;
    /// That this change is about to be sent: only after its claim and every
    /// check passed, right before the gateway call. A record with no send
    /// noted was never sent, so recovery never re-issues it.
    fn sending(&self) -> bool;
    /// That the gateway call `sending` preceded has RETURNED, whatever it
    /// answered: the send's end, noted right after it. A start with no end
    /// is in flight, and no settle marker counts for it.
    fn sent(&self) {}
    /// Whether this send RE-ISSUES a change sent before. OpenShell checks who
    /// asks and finds the target BEFORE it looks up the original
    /// (`mutation_replay.rs` at e1f3c82, lines 150-170), so a refusal of a
    /// re-issue says nothing about the original.
    fn reissue(&self) -> bool {
        false
    }
}

/// In tests: a FIRST send whose every note succeeds.
#[cfg(test)]
pub struct Noted;

#[cfg(test)]
impl Notes for Noted {
    fn backend_id(&self, _: &str) -> bool {
        true
    }
    fn sending(&self) -> bool {
        true
    }
}

impl Backend {
    /// The gateway token for this call's credential.
    async fn bearer(&self, a: &Admitted) -> Result<zeroize::Zeroizing<String>, Answer> {
        self.tokens
            .bearer(a.verified().credential.expose())
            .await
            .map_err(|e| match e {
                SignInError::Rejected => refused(Code::BackendRefused),
                SignInError::Unreachable(_) | SignInError::Mismatch(_) => {
                    refused(Code::BackendUnavailable)
                }
            })
    }

    /// What a gateway refusal of a READ answers.
    fn read_failed(&self, e: &GatewayError) -> Answer {
        if *e == GatewayError::Unauthenticated {
            self.tokens.rejected();
        }
        match e {
            GatewayError::NotFound => refused(Code::DeskNotFound),
            GatewayError::Unauthenticated | GatewayError::PermissionDenied => {
                refused(Code::BackendRefused)
            }
            _ => refused(Code::BackendUnavailable),
        }
    }

    /// What the desk is now: GetSandbox and its loaded policy revision.
    async fn facts(
        &self,
        bearer: &str,
        name: &str,
    ) -> Result<Option<(Sandbox, DeskFacts)>, GatewayError> {
        let Some(sb) = self.gateway.sandbox(bearer, name).await? else {
            return Ok(None);
        };
        let status = self.gateway.policy_status(bearer, name).await?;
        let rev = status.revision.unwrap_or_default();
        // The wall the desk enforces is the LOADED revision; while a newer one
        // is not loaded, its digest is not reported, as the Enclave reports it.
        let policy_digest = (rev.version == status.active_version)
            .then(|| rev.policy.as_ref().and_then(|p| message_digest(POLICY, p)))
            .flatten();
        let meta = sb.metadata.clone().unwrap_or_default();
        let facts = DeskFacts {
            backend_id: is_uuid(&meta.id).then(|| meta.id.clone()),
            resource_version: Some(meta.resource_version.to_string()),
            policy_digest,
            providers_digest: None,
            providers: Some(
                sb.spec
                    .as_ref()
                    .map(|s| s.providers.clone())
                    .unwrap_or_default(),
            ),
        };
        Ok(Some((sb, facts)))
    }

    /// The digest of the desk's providers, as the Enclave pins it.
    async fn providers_digest(&self, bearer: &str, names: &[String]) -> Option<String> {
        let mut found = Vec::with_capacity(names.len());
        for n in names {
            let (p, f) = providers::read(&self.gateway, bearer, n).await.ok()?;
            found.push((n.clone(), p, f));
        }
        let items: Vec<_> = found.iter().map(|(n, p, f)| (n.as_str(), p, f)).collect();
        providers::desk_digest(&items).ok()
    }

    /// `status`: the desk now, with its providers' digest.
    pub async fn status(&self, a: &Admitted, name: &str) -> Answer {
        let bearer = match self.bearer(a).await {
            Ok(b) => b,
            Err(answer) => return answer,
        };
        match self.facts(&bearer, name).await {
            Ok(Some((_, mut facts))) => {
                let names = facts.providers.clone().unwrap_or_default();
                facts.providers_digest = self.providers_digest(&bearer, &names).await;
                if facts.policy_digest.is_none() || facts.providers_digest.is_none() {
                    // The desk exists, but what it enforces cannot be told now.
                    return Answer::unknown();
                }
                Answer::ready(facts)
            }
            Ok(None) => refused(Code::DeskNotFound),
            Err(e) => self.read_failed(&e),
        }
    }

    /// `policy_get`: the desk's policy digest and version.
    pub async fn policy_get(&self, a: &Admitted, name: &str) -> Answer {
        let bearer = match self.bearer(a).await {
            Ok(b) => b,
            Err(answer) => return answer,
        };
        match self.facts(&bearer, name).await {
            Ok(Some((_, facts))) if facts.policy_digest.is_some() => Answer::ready(DeskFacts {
                providers: None,
                ..facts
            }),
            Ok(Some(_)) => Answer::unknown(),
            Ok(None) => refused(Code::DeskNotFound),
            Err(e) => self.read_failed(&e),
        }
    }

    /// Claim the desk. `Ok` carries its required providers, `None` when the
    /// Enclave did not name them (one older than contracts 0.64.0).
    async fn claim(&self, a: &Admitted, desk: &str) -> Result<Option<Vec<String>>, Answer> {
        match self.claims.claim(desk, &a.verified().request_id).await {
            Ok(required) => Ok(required),
            Err(ClaimError::Refused(code)) if code == "DESK_BUSY" => Err(refused(Code::DeskBusy)),
            Err(ClaimError::Refused(_)) => Err(refused(Code::BackendRefused)),
            Err(ClaimError::Unavailable(_)) => Err(refused(Code::BackendUnavailable)),
        }
    }

    /// CONCLUDE a change: its answer is written to its record FIRST (tried
    /// twice), and only then is its claim released (the plan's order: the
    /// claim is released only after the record is settled). Unwritten, the
    /// desk stays held and the change answers `running`, as its record still
    /// says: recovery settles it later. With no record store (a driver test)
    /// there is nothing to write first.
    async fn conclude(
        &self,
        a: &Admitted,
        desk: &str,
        outcome: Outcome,
        rb: Option<&ReadBack>,
        answer: Answer,
    ) -> Answer {
        let rid = &a.verified().request_id;
        // In a production build this match has ONE arm: there is no
        // "no records" to take (clippy calls an `if let` on it irrefutable).
        let records = match &self.records {
            Records::Store(store) => Some(store),
            #[cfg(test)]
            Records::Unrecorded => None,
        };
        let Some(records) = records else {
            self.try_release(desk, rid, outcome, rb).await;
            return answer;
        };
        // The release is OWED from the moment the answer is written, in the
        // same write: a failed release, or a crash before it, is retried at
        // the next call and at startup (`release_pending`), never by sending
        // the change again.
        let owed = PendingRelease {
            outcome: outcome.name().to_string(),
            read_back: rb.map(ReadBack::wire),
        };
        let written = records.settle_releasing(rid, &answer, &owed).or_else(|e| {
            tracing::warn!(request_id = %rid, error = ?e, "operationSettleRetried");
            records.settle_releasing(rid, &answer, &owed)
        });
        if let Err(e) = written {
            tracing::error!(request_id = %rid, desk, error = ?e, "operationNotSettledDeskKept");
            return Answer::running(rid);
        }
        self.release_owed(records, desk, rid, outcome, rb).await;
        answer
    }

    /// Send the release `request_id` owes and record what became of it.
    async fn release_owed(
        &self,
        records: &crate::store::Store,
        desk: &str,
        request_id: &str,
        outcome: Outcome,
        rb: Option<&ReadBack>,
    ) {
        let noted = match self.try_release(desk, request_id, outcome, rb).await {
            Release::Done => records.released(request_id),
            Release::Owed => return,
            Release::OwedAs(o) => records.note_release(
                request_id,
                &PendingRelease {
                    outcome: o.name().to_string(),
                    read_back: None,
                },
            ),
        };
        if let Err(e) = noted {
            tracing::warn!(request_id, desk, error = ?e, "releaseNotNoted");
        }
    }

    /// One release, read the way a retry must read it.
    ///
    /// - Done: the Enclave released it, or answers that this change no longer
    ///   holds the desk (`DESK_NOT_HELD`, `DESK_HELD_BY_ANOTHER`: an earlier
    ///   release went through and its answer was lost).
    /// - A refusal that a retry would only repeat (`READ_BACK_MISMATCH`,
    ///   `READ_BACK_REQUIRED`) is released `unknown` instead: the desk stays
    ///   held, marked for a person, and is never retried forever.
    /// - Anything else stays owed: the desk stays held, the safe side.
    async fn try_release(
        &self,
        desk: &str,
        request_id: &str,
        outcome: Outcome,
        rb: Option<&ReadBack>,
    ) -> Release {
        match self.claims.release(desk, request_id, outcome, rb).await {
            Ok(_) => Release::Done,
            Err(ClaimError::Refused(code))
                if code == "DESK_NOT_HELD" || code == "DESK_HELD_BY_ANOTHER" =>
            {
                tracing::info!(desk, request_id, code, "deskAlreadyReleased");
                Release::Done
            }
            Err(ClaimError::Refused(code))
                if (code == "READ_BACK_MISMATCH" || code == "READ_BACK_REQUIRED")
                    && outcome != Outcome::Unknown =>
            {
                tracing::warn!(desk, request_id, code, "deskReleasedUnknownForAPerson");
                match self
                    .claims
                    .release(desk, request_id, Outcome::Unknown, None)
                    .await
                {
                    Ok(_) => Release::Done,
                    Err(e) => {
                        tracing::warn!(desk, request_id, error = ?e, "deskReleaseFailed");
                        Release::OwedAs(Outcome::Unknown)
                    }
                }
            }
            Err(e) => {
                tracing::warn!(desk, request_id, error = ?e, "deskReleaseFailed");
                Release::Owed
            }
        }
    }

    /// Retry every release a settled change still owes: before every call,
    /// and at startup. Idempotent: a release that went through answers that
    /// the change no longer holds the desk.
    pub async fn release_pending(&self) {
        let records = match &self.records {
            Records::Store(store) => Some(store),
            #[cfg(test)]
            Records::Unrecorded => None,
        };
        let Some(records) = records else {
            return;
        };
        let owed = match records.releasing() {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!(error = ?e, "releasingUnreadable");
                return;
            }
        };
        for rec in owed {
            let Some(p) = rec.release_pending.as_ref() else {
                continue;
            };
            let Some(outcome) = Outcome::from_name(&p.outcome) else {
                tracing::error!(request_id = %rec.request_id, "releaseOutcomeUnreadable");
                continue;
            };
            let rb = p.read_back.as_ref().and_then(ReadBack::from_wire);
            if p.read_back.is_some() && rb.is_none() {
                tracing::error!(request_id = %rec.request_id, "releaseReadBackUnreadable");
                continue;
            }
            self.release_owed(records, &rec.desk, &rec.request_id, outcome, rb.as_ref())
                .await;
        }
    }

    /// Refuse before any change, freeing the claim.
    async fn refuse_claimed(&self, a: &Admitted, desk: &str, code: Code) -> Answer {
        self.conclude(a, desk, Outcome::Refused, None, refused(code))
            .await
    }

    /// A send that could not be noted is not sent. A first send is refused,
    /// its claim freed; a RE-ISSUE stays running, its desk held (the
    /// original may have run).
    async fn not_noted(&self, a: &Admitted, desk: &str, notes: &dyn Notes) -> Answer {
        if notes.reissue() {
            return Answer::running(&a.verified().request_id);
        }
        self.refuse_claimed(a, desk, Code::BackendUnavailable).await
    }

    /// What a gateway refusal of a CHANGE answers. A change that may still
    /// finish answers `running` and keeps its claim; one the gateway decided
    /// against releases it `refused`.
    ///
    /// A RE-ISSUE is never refused: whatever the gateway answers, NotFound
    /// included (the original delete may have succeeded), it was decided
    /// before the original was looked up. Only a success the read-back
    /// confirms settles a re-issue; until then the change stays running and
    /// its desk held.
    async fn change_failed(
        &self,
        a: &Admitted,
        desk: &str,
        e: GatewayError,
        reissue: bool,
    ) -> Answer {
        if reissue {
            if matches!(e, GatewayError::Unauthenticated) {
                self.tokens.rejected();
            }
            tracing::warn!(request_id = %a.verified().request_id, desk, error = ?e, "reissueRefusedDeskKept");
            return Answer::running(&a.verified().request_id);
        }
        let code = match e {
            GatewayError::Unavailable
            | GatewayError::Uncertain
            | GatewayError::ReplayUnavailable => {
                return Answer::running(&a.verified().request_id);
            }
            // Another payload under this id: whatever ran under it may have
            // changed the desk, so the desk stays held for a person.
            GatewayError::PayloadMismatch => {
                tracing::error!(request_id = %a.verified().request_id, "requestIdPayloadMismatch");
                return Answer::running(&a.verified().request_id);
            }
            GatewayError::NotFound => Code::DeskNotFound,
            GatewayError::Refused {
                code: tonic::Code::AlreadyExists,
                ..
            } => Code::DeskExists,
            GatewayError::Refused {
                code: tonic::Code::Aborted,
                ..
            } => Code::VersionConflict,
            GatewayError::Unauthenticated => {
                self.tokens.rejected();
                Code::BackendRefused
            }
            _ => Code::BackendRefused,
        };
        self.refuse_claimed(a, desk, code).await
    }

    /// Read the desk back until `done` says the change shows, within a bound.
    /// `None` when it never showed: the change is still being carried out.
    async fn settle<F>(
        &self,
        bearer: &str,
        name: &str,
        done: F,
    ) -> Result<Option<Option<(Sandbox, DeskFacts)>>, GatewayError>
    where
        F: Fn(Option<&(Sandbox, DeskFacts)>) -> bool,
    {
        for i in 0..SETTLE_READS {
            if i > 0 {
                tokio::time::sleep(SETTLE_WAIT).await;
            }
            let now = self.facts(bearer, name).await?;
            if done(now.as_ref()) {
                return Ok(Some(now));
            }
        }
        Ok(None)
    }

    /// Answer a change the gateway accepted, from its read-back: `ready` and
    /// released with the read-back, `unknown` (released so) when it does not
    /// match, `running` (claim kept) when it has not shown yet. When the
    /// change is known to have `stopped` (a settle marker), not shown is
    /// final: `unknown`.
    #[allow(clippy::too_many_arguments)]
    async fn finish(
        &self,
        a: &Admitted,
        desk: &str,
        read: Result<Option<Option<(Sandbox, DeskFacts)>>, GatewayError>,
        matches: impl Fn(&Sandbox, &DeskFacts) -> bool,
        providers_moved: bool,
        bearer: &str,
        stopped: bool,
    ) -> Answer {
        match read {
            Ok(Some(Some((sb, mut facts)))) if matches(&sb, &facts) => {
                let Some(backend_id) = facts.backend_id.clone() else {
                    return self
                        .conclude(a, desk, Outcome::Unknown, None, Answer::unknown())
                        .await;
                };
                let Some(policy_digest) = facts.policy_digest.clone() else {
                    return Answer::running(&a.verified().request_id);
                };
                let providers_digest = if providers_moved {
                    let names = facts.providers.clone().unwrap_or_default();
                    let d = self.providers_digest(bearer, &names).await;
                    facts.providers_digest.clone_from(&d);
                    d
                } else {
                    None
                };
                let rb = ReadBack::Live {
                    sandbox_id: backend_id,
                    policy_digest,
                    providers_digest,
                };
                self.conclude(a, desk, Outcome::Ready, Some(&rb), Answer::ready(facts))
                    .await
            }
            Ok(Some(_)) => {
                self.conclude(a, desk, Outcome::Unknown, None, Answer::unknown())
                    .await
            }
            Ok(None) if stopped => {
                self.conclude(a, desk, Outcome::Unknown, None, Answer::unknown())
                    .await
            }
            // Not shown yet, or the read-back was lost: the change may still
            // finish, so the claim stays held.
            Ok(None) | Err(_) => Answer::running(&a.verified().request_id),
        }
    }

    /// `create`, held to its grant before anything.
    pub async fn create(
        &self,
        a: &Admitted,
        body: &enforce::CreateBody,
        notes: &dyn Notes,
    ) -> Answer {
        let grant = match enforce::grant(a.verified().grant.as_ref()) {
            Ok(g) => g,
            Err(code) => return refused(code),
        };
        let Some(policy) = enforce::create(&grant, body)
            .ok()
            .and_then(|p| message::<SandboxPolicy>(POLICY, &p))
        else {
            return refused(
                enforce::create(&grant, body)
                    .err()
                    .unwrap_or(Code::RequestInvalid),
            );
        };
        let bearer = match self.bearer(a).await {
            Ok(b) => b,
            Err(answer) => return answer,
        };
        // Each provider's configuration, as the gateway holds it now, must
        // be the one the grant pins, by the function `ekka-backend digest
        // provider` prints for the kit, so the two never disagree.
        for p in &body.providers {
            let got = match providers::read(&self.gateway, &bearer, p).await {
                Ok((rec, prof)) => providers::config_digest(p, &rec, &prof).ok(),
                Err((GatewayError::NotFound, _)) => None,
                Err((e, _)) => return self.read_failed(&e),
            };
            if got.is_none() || got.as_ref() != grant.provider_config_digests.get(p) {
                return refused(Code::ConstraintProviderConfigDigests);
            }
        }
        if let Err(answer) = self.claim(a, &body.name).await {
            return answer;
        }
        self.create_send(a, &bearer, body, Some(policy), Some(notes))
            .await
    }

    /// The one CreateSandboxRequest a create sends, built only from the body
    /// and the request id, so a re-issue sends the same bytes (the gateway
    /// refuses another payload under a request id it has seen).
    fn create_request(
        body: &enforce::CreateBody,
        policy: SandboxPolicy,
        request_id: &str,
    ) -> CreateSandboxRequest {
        let environment = body
            .environment
            .iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
            .collect();
        CreateSandboxRequest {
            name: body.name.clone(),
            spec: Some(SandboxSpec {
                template: Some(SandboxTemplate {
                    image: body.image.clone(),
                    ..Default::default()
                }),
                policy: Some(policy),
                providers: body.providers.clone(),
                environment,
                ..Default::default()
            }),
            labels: [
                (DESK_LABEL.to_string(), "true".to_string()),
                (OPERATION_LABEL.to_string(), request_id.to_string()),
            ]
            .into_iter()
            .collect(),
            // The agent's required providers are the ones the desk is made
            // with: auto-registration reads this.
            annotations: [(PROVIDERS_ANNOTATION.to_string(), body.providers.join(","))]
                .into_iter()
                .collect(),
            request_id: request_id.to_string(),
            ..Default::default()
        }
    }

    async fn create_send(
        &self,
        a: &Admitted,
        bearer: &str,
        body: &enforce::CreateBody,
        policy: Option<SandboxPolicy>,
        send: Option<&dyn Notes>,
    ) -> Answer {
        let name = body.name.as_str();
        // `None`: a read-back only (a settle marker said the change stopped),
        // nothing is sent. Otherwise noted durably first: not noted, not sent.
        if let Some(notes) = send {
            // A re-issue whose policy cannot be rebuilt is not sent.
            let Some(policy) = policy else {
                return Answer::running(&a.verified().request_id);
            };
            let msg = Self::create_request(body, policy, &a.verified().request_id);
            if !notes.sending() {
                return self.not_noted(a, name, notes).await;
            }
            let sent = self.gateway.create(bearer, msg).await;
            notes.sent();
            if let Err(e) = sent {
                return self.change_failed(a, name, e, notes.reissue()).await;
            }
        }
        let read = self.settle(bearer, name, |d| d.is_some()).await;
        // WHAT WAS APPROVED, not only what was asked for. The policy the
        // desk LOADED must be the approved one (the grant pinned this digest
        // at admission); not loaded yet is still running. And each
        // provider's configuration, read again now the desk exists, must be
        // the one the grant pins: one changed while the desk was made never
        // finishes as approved. A read-back with no grant (a settle marker)
        // cannot confirm the providers: `unknown`, the desk held.
        let approved = self.approved(a, body);
        let approved_policy = approved.as_ref().map(|p| p.policy_digest.clone());
        let providers_ok = match &read {
            Ok(Some(Some(_))) => {
                let pins = approved.as_ref().map(|p| &p.provider_config_digests);
                self.providers_still_approved(bearer, &body.providers, pins)
                    .await
            }
            _ => Ok(false),
        };
        let (read, providers_ok) = match providers_ok {
            Ok(ok) => (read, ok),
            // The providers could not be read: still running, claim kept.
            Err(e) => (Err(e), false),
        };
        let expected = enforce::Expected {
            image: &body.image,
            policy: &body.policy,
            providers: &body.providers,
        };
        self.finish(
            a,
            name,
            read,
            |sb, facts| {
                let json = message_json(crate::normalize::SANDBOX, sb).unwrap_or(Value::Null);
                enforce::result_matches(&expected, &json)
                    && sb.metadata.as_ref().is_some_and(|m| {
                        m.labels.get(OPERATION_LABEL) == Some(&a.verified().request_id)
                    })
                    && providers_ok
                    && (facts.policy_digest.is_none() || facts.policy_digest == approved_policy)
            },
            false,
            bearer,
            send.is_none(),
        )
        .await
    }

    /// What the grant approved for this create: from the grant when this
    /// call holds one, else from the operation's record, where admission
    /// wrote it while the token was verified (a settle marker's read-back
    /// carries no grant, and a Govern key rotated since must not strand the
    /// desk). Neither: `None`, and the create cannot finish as approved.
    fn approved(&self, a: &Admitted, body: &enforce::CreateBody) -> Option<crate::store::Approved> {
        if let Ok(g) = enforce::grant(a.verified().grant.as_ref()) {
            return Some(crate::store::Approved {
                policy_digest: crate::digest_cmd::policy_digest(&body.policy)?,
                provider_config_digests: g.provider_config_digests,
            });
        }
        let records = match &self.records {
            Records::Store(store) => Some(store),
            #[cfg(test)]
            Records::Unrecorded => None,
        }?;
        records
            .get(&a.verified().request_id)
            .ok()
            .flatten()
            .and_then(|r| r.approved)
    }

    /// Whether each of `names` holds, at the gateway now, the configuration
    /// `pins` approves. No pins (a read-back with no grant), a provider
    /// gone, or one changed: `false`. A read that fails: the error, so the
    /// change stays running.
    async fn providers_still_approved(
        &self,
        bearer: &str,
        names: &[String],
        pins: Option<&std::collections::BTreeMap<String, String>>,
    ) -> Result<bool, GatewayError> {
        let Some(pins) = pins else {
            return Ok(false);
        };
        for p in names {
            let now = match providers::read(&self.gateway, bearer, p).await {
                Ok((rec, prof)) => providers::config_digest(p, &rec, &prof).ok(),
                Err((GatewayError::NotFound, _)) => None,
                Err((e, _)) => return Err(e),
            };
            if now.is_none() || now.as_ref() != pins.get(p) {
                tracing::warn!(provider = %p, "providerChangedDuringCreate");
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// `delete`. The desk's id is read first and handed to `note` (the
    /// operation record keeps it) BEFORE the delete is sent, so the release
    /// can say which sandbox is gone even after a restart.
    pub async fn delete(&self, a: &Admitted, name: &str, notes: &dyn Notes) -> Answer {
        let bearer = match self.bearer(a).await {
            Ok(b) => b,
            Err(answer) => return answer,
        };
        if let Err(answer) = self.claim(a, name).await {
            return answer;
        }
        let id = match self.gateway.sandbox(&bearer, name).await {
            Ok(Some(sb)) => sb.metadata.map(|m| m.id).unwrap_or_default(),
            Ok(None) => return self.refuse_claimed(a, name, Code::DeskNotFound).await,
            Err(e) => {
                return self
                    .conclude(a, name, Outcome::Refused, None, self.read_failed(&e))
                    .await;
            }
        };
        if !notes.backend_id(&id) {
            return self.refuse_claimed(a, name, Code::BackendUnavailable).await;
        }
        self.delete_send(a, &bearer, name, id, Some(notes)).await
    }

    async fn delete_send(
        &self,
        a: &Admitted,
        bearer: &str,
        name: &str,
        id: String,
        send: Option<&dyn Notes>,
    ) -> Answer {
        // `None`: a read-back only (a settle marker said the change stopped),
        // nothing is sent. Otherwise noted durably first: not noted, not sent.
        if let Some(notes) = send {
            if !notes.sending() {
                return self.not_noted(a, name, notes).await;
            }
            let sent = self
                .gateway
                .delete(bearer, name, &a.verified().request_id)
                .await;
            notes.sent();
            if let Err(e) = sent {
                return self.change_failed(a, name, e, notes.reissue()).await;
            }
        }
        match self.settle(bearer, name, |d| d.is_none()).await {
            Ok(Some(None)) => {
                let rb = ReadBack::Deleted { sandbox_id: id };
                self.conclude(
                    a,
                    name,
                    Outcome::Ready,
                    Some(&rb),
                    Answer::ready(DeskFacts::default()),
                )
                .await
            }
            // Still there after a settle marker: the delete stopped without
            // removing it.
            Ok(None) if send.is_none() => {
                self.conclude(a, name, Outcome::Unknown, None, Answer::unknown())
                    .await
            }
            // Still there, or not readable: the delete may still finish.
            _ => Answer::running(&a.verified().request_id),
        }
    }

    /// `stop` or `start`.
    pub async fn stop_or_start(
        &self,
        a: &Admitted,
        name: &str,
        start: bool,
        notes: &dyn Notes,
    ) -> Answer {
        let bearer = match self.bearer(a).await {
            Ok(b) => b,
            Err(answer) => return answer,
        };
        if let Err(answer) = self.claim(a, name).await {
            return answer;
        }
        self.stop_or_start_send(a, &bearer, name, start, Some(notes))
            .await
    }

    async fn stop_or_start_send(
        &self,
        a: &Admitted,
        bearer: &str,
        name: &str,
        start: bool,
        send: Option<&dyn Notes>,
    ) -> Answer {
        // `None`: a read-back only (a settle marker said the change stopped),
        // nothing is sent. Otherwise noted durably first: not noted, not sent.
        if let Some(notes) = send {
            if !notes.sending() {
                return self.not_noted(a, name, notes).await;
            }
            let sent = self
                .gateway
                .stop_or_start(bearer, name, &a.verified().request_id, start)
                .await;
            notes.sent();
            if let Err(e) = sent {
                return self.change_failed(a, name, e, notes.reissue()).await;
            }
        }
        let want = if start {
            SandboxPhase::Ready
        } else {
            SandboxPhase::Stopped
        };
        let read = self
            .settle(bearer, name, |d| {
                d.is_some_and(|(sb, _)| phase_is(sb, want))
            })
            .await;
        self.finish(
            a,
            name,
            read,
            |sb, _| phase_is(sb, want),
            false,
            bearer,
            send.is_none(),
        )
        .await
    }

    /// `policy_set`, held to the desk's CREATION policy and the grant.
    pub async fn policy_set(
        &self,
        a: &Admitted,
        name: &str,
        body: &enforce::PolicySetBody,
        notes: &dyn Notes,
    ) -> Answer {
        let Ok(expected) = body.expected_resource_version.parse::<u64>() else {
            return refused(Code::RequestInvalid);
        };
        let grant = match enforce::grant(a.verified().grant.as_ref()) {
            Ok(g) => g,
            Err(code) => return refused(code),
        };
        let bearer = match self.bearer(a).await {
            Ok(b) => b,
            Err(answer) => return answer,
        };
        if let Err(answer) = self.claim(a, name).await {
            return answer;
        }
        // The baseline is the policy the desk was CREATED with: `spec.policy`,
        // which a policy change never moves; the live policy is its revision.
        let baseline = match self.gateway.sandbox(&bearer, name).await {
            Ok(Some(sb)) => sb
                .spec
                .and_then(|s| s.policy)
                .and_then(|p| message_json(POLICY, &p))
                .unwrap_or(Value::Null),
            Ok(None) => return self.refuse_claimed(a, name, Code::DeskNotFound).await,
            Err(e) => {
                return self
                    .conclude(a, name, Outcome::Refused, None, self.read_failed(&e))
                    .await;
            }
        };
        let next = match enforce::policy_change(&grant, &baseline, &body.policy) {
            Ok(p) => p,
            Err(code) => return self.refuse_claimed(a, name, code).await,
        };
        let Some(policy) = message::<SandboxPolicy>(POLICY, &next) else {
            return self.refuse_claimed(a, name, Code::RequestInvalid).await;
        };
        self.policy_send(a, &bearer, name, policy, expected, Some(notes))
            .await
    }

    async fn policy_send(
        &self,
        a: &Admitted,
        bearer: &str,
        name: &str,
        policy: SandboxPolicy,
        expected: u64,
        send: Option<&dyn Notes>,
    ) -> Answer {
        let want = message_digest(POLICY, &policy);
        // `None`: a read-back only (a settle marker said the change stopped),
        // nothing is sent. Otherwise noted durably first: not noted, not sent.
        if let Some(notes) = send {
            if !notes.sending() {
                return self.not_noted(a, name, notes).await;
            }
            let sent = self
                .gateway
                .set_policy(bearer, name, policy, expected, &a.verified().request_id)
                .await;
            notes.sent();
            if let Err(e) = sent {
                return self.change_failed(a, name, e, notes.reissue()).await;
            }
        }
        let read = self
            .settle(bearer, name, |d| {
                d.is_some_and(|(_, f)| f.policy_digest.is_some() && f.policy_digest == want)
            })
            .await;
        self.finish(
            a,
            name,
            read,
            |_, f| f.policy_digest == want,
            false,
            bearer,
            send.is_none(),
        )
        .await
    }

    /// `provider_detach`: never a provider the desk's agent requires.
    pub async fn detach(
        &self,
        a: &Admitted,
        name: &str,
        provider: &str,
        expected_resource_version: &str,
        notes: &dyn Notes,
    ) -> Answer {
        let Ok(expected) = expected_resource_version.parse::<u64>() else {
            return refused(Code::RequestInvalid);
        };
        let bearer = match self.bearer(a).await {
            Ok(b) => b,
            Err(answer) => return answer,
        };
        let required = match self.claim(a, name).await {
            Ok(r) => r,
            Err(answer) => return answer,
        };
        // An Enclave that names no required providers cannot say this one is
        // not required: refused, never assumed (fails closed).
        let Some(required) = required else {
            return self.refuse_claimed(a, name, Code::BackendRefused).await;
        };
        if required.iter().any(|r| r == provider) {
            return self
                .refuse_claimed(a, name, Code::DeskProviderRequired)
                .await;
        }
        self.detach_send(a, &bearer, name, provider, expected, Some(notes))
            .await
    }

    async fn detach_send(
        &self,
        a: &Admitted,
        bearer: &str,
        name: &str,
        provider: &str,
        expected: u64,
        send: Option<&dyn Notes>,
    ) -> Answer {
        // `None`: a read-back only (a settle marker said the change stopped),
        // nothing is sent. Otherwise noted durably first: not noted, not sent.
        if let Some(notes) = send {
            if !notes.sending() {
                return self.not_noted(a, name, notes).await;
            }
            let sent = self
                .gateway
                .detach(bearer, name, provider, expected, &a.verified().request_id)
                .await;
            notes.sent();
            if let Err(e) = sent {
                return self.change_failed(a, name, e, notes.reissue()).await;
            }
        }
        let gone = |f: &DeskFacts| {
            f.providers
                .as_ref()
                .is_some_and(|p| !p.iter().any(|x| x == provider))
        };
        let read = self
            .settle(bearer, name, |d| d.is_some_and(|(_, f)| gone(f)))
            .await;
        self.finish(a, name, read, |_, f| gone(f), true, bearer, send.is_none())
            .await
    }

    /// The backend's id for `name` now, read with the call's own token:
    /// `Ok(None)` when the gateway says it is not there, `Err` when it could
    /// not be asked (never taken for "not there").
    pub async fn desk_now(&self, a: &Admitted, name: &str) -> Result<Option<String>, ()> {
        let bearer = self.bearer(a).await.map_err(|_| ())?;
        match self.gateway.sandbox(&bearer, name).await {
            // There, but naming no id: it cannot be matched, and it is not absent.
            Ok(Some(sb)) => sb
                .metadata
                .map(|m| m.id)
                .filter(|id| !id.is_empty())
                .map(Some)
                .ok_or(()),
            Ok(None) => Ok(None),
            Err(_) => Err(()),
        }
    }

    /// A create proven never applied: refused `NOT_APPLIED`, the claim
    /// released `refused` (nothing changed).
    pub async fn not_applied(&self, a: &Admitted, desk: &str) -> Answer {
        self.refuse_claimed(a, desk, Code::NotApplied).await
    }

    /// RE-ISSUE a stored change under the claim it already holds:
    /// the same request, built the same way from its stored body, under its
    /// own request id, so the gateway replays its recorded success (or
    /// answers UNCERTAIN) and never applies it twice. `a` comes from the
    /// stored token, re-checked (`Admitted::for_recovery`).
    #[allow(clippy::too_many_arguments)]
    pub async fn reissue(
        &self,
        a: &Admitted,
        notes: &dyn Notes,
        operation: crate::routes::Operation,
        desk: &str,
        provider: Option<&str>,
        body: &[u8],
        backend_id: Option<&str>,
    ) -> Answer {
        self.recover(a, operation, desk, provider, body, backend_id, Some(notes))
            .await
    }

    /// READ BACK a stored change a settle marker says has stopped: NOTHING is
    /// sent; the read-back alone decides, and the claim is released. `a` may
    /// be a read-back admission (`Admitted::for_read_back`), with no token.
    pub async fn read_back(
        &self,
        a: &Admitted,
        operation: crate::routes::Operation,
        desk: &str,
        provider: Option<&str>,
        body: &[u8],
        backend_id: Option<&str>,
    ) -> Answer {
        self.recover(a, operation, desk, provider, body, backend_id, None)
            .await
    }

    /// Both, as the first attempt concludes: the checks that read the desk
    /// live are skipped (they decided at admission, and the desk may already
    /// show the change). Anything it cannot rebuild stays `running`, the
    /// claim held.
    #[allow(clippy::too_many_arguments)]
    async fn recover(
        &self,
        a: &Admitted,
        operation: crate::routes::Operation,
        desk: &str,
        provider: Option<&str>,
        body: &[u8],
        backend_id: Option<&str>,
        send: Option<&dyn Notes>,
    ) -> Answer {
        use crate::routes::Operation;
        let bearer = match self.bearer(a).await {
            Ok(b) => b,
            // No token now: nothing was sent; the change stays running.
            Err(_) => return Answer::running(&a.verified().request_id),
        };
        match operation {
            Operation::Create => {
                let Ok(b) = enforce::body::<enforce::CreateBody>(body) else {
                    return Answer::running(&a.verified().request_id);
                };
                // Only a re-issue needs the policy, from the grant: a read-back
                // sends nothing (and its admission carries no grant).
                let policy = enforce::grant(a.verified().grant.as_ref())
                    .ok()
                    .and_then(|g| enforce::create(&g, &b).ok())
                    .and_then(|p| message::<SandboxPolicy>(POLICY, &p));
                self.create_send(a, &bearer, &b, policy, send).await
            }
            Operation::Delete => match backend_id {
                Some(id) => {
                    self.delete_send(a, &bearer, desk, id.to_string(), send)
                        .await
                }
                // Its id was never noted: only the host procedure settles it.
                None => Answer::running(&a.verified().request_id),
            },
            Operation::Stop => self.stop_or_start_send(a, &bearer, desk, false, send).await,
            Operation::Start => self.stop_or_start_send(a, &bearer, desk, true, send).await,
            Operation::PolicySet => {
                let parsed = enforce::body::<enforce::PolicySetBody>(body)
                    .ok()
                    .and_then(|p| {
                        let expected = p.expected_resource_version.parse::<u64>().ok()?;
                        let next = crate::normalize::canonical(POLICY, &p.policy)?;
                        Some((message::<SandboxPolicy>(POLICY, &next)?, expected))
                    });
                match parsed {
                    Some((policy, expected)) => {
                        self.policy_send(a, &bearer, desk, policy, expected, send)
                            .await
                    }
                    None => Answer::running(&a.verified().request_id),
                }
            }
            Operation::ProviderDetach => {
                let expected = serde_json::from_slice::<Value>(body).ok().and_then(|v| {
                    v["expected_resource_version"]
                        .as_str()
                        .and_then(|s| s.parse::<u64>().ok())
                });
                match (provider, expected) {
                    (Some(p), Some(e)) => self.detach_send(a, &bearer, desk, p, e, send).await,
                    _ => Answer::running(&a.verified().request_id),
                }
            }
            _ => Answer::running(&a.verified().request_id),
        }
    }
}

fn phase_is(sb: &Sandbox, want: SandboxPhase) -> bool {
    sb.status
        .as_ref()
        .is_some_and(|st| SandboxPhase::try_from(st.phase) == Ok(want))
}

/// A lowercase hyphenated UUID, as the contract's `backend_id` is.
fn is_uuid(s: &str) -> bool {
    uuid::Uuid::parse_str(s).is_ok_and(|u| u.hyphenated().to_string() == s)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "driver_tests.rs"]
pub(crate) mod tests;
