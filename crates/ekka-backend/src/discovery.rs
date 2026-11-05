//! Desk discovery: a disposable desk, made inside a discovery window, may
//! have its network proposals approved automatically for a while, and what it
//! proposed and reached is then read back as evidence.
//!
//! `approval_mode` to `auto` holds these, ALL of them, before anything is
//! sent, against the signed grant only (never a request field) and the desk
//! as NVIDIA OpenShell's gateway holds it, under the desk's claim:
//!
//! 1. the grant names a discovery window (`constraints.grant.discovery`), and
//!    it has not ended (else `DISCOVERY_WINDOW_CLOSED`);
//! 2. the desk's name carries the window's prefix, `discover-`;
//! 3. the desk is an EKKA desk, made from one of the window's images;
//! 4. every provider attached to it is one the window lists.
//!
//! Any other answer is `DESK_NOT_DISCOVERY`. Then the setting is sent, read
//! back with GetSandboxConfig, and only a read-back of `auto` lets the permit
//! be written (`permits.rs`). Anything else returns the desk to `manual` as
//! far as it can and writes no permit.
//!
//! `approval_mode` to `manual` removes the desk's permit FIRST, before it
//! asks the backend anything, then sends the setting and reads it back. It
//! needs no window: turning automatic approval off is always allowed.
//!
//! A change still running is recovered toward `manual` only: recovery never
//! writes a permit, and never sends `auto`.
//!
//! `discovery_evidence` is read only for a desk with a permit. It waits for
//! the desk's proposals and loaded policy to stop changing, then answers the
//! policy, the proposals, the decisions and the network log lines.

use std::time::Duration;

use chrono::{DateTime, Utc};
use openshell_proto::openshell::v1::{DraftHistoryEntry, PolicyChunk, SandboxLogLine};
use serde::Deserialize;
use serde_json::{json, Value};

use super::{is_uuid, refused, Backend, Notes, DESK_LABEL};
use crate::answer::{Answer, Code, DeskFacts, EVIDENCE_MAX_BYTES};
use crate::claims::{Outcome, ReadBack};
use crate::enforce;
use crate::gateway::GatewayError;
use crate::normalize::{message_digest, message_json, POLICY};
use crate::permits::{Permit, PERMIT_MINUTES, PERMIT_SCHEMA};
use crate::token::Admitted;

/// The two approval modes.
pub const AUTO: &str = "auto";
pub const MANUAL: &str = "manual";

/// A proposed rule, as the gateway types it.
const NETWORK_RULE: &str = "openshell.sandbox.v1.NetworkPolicyRule";
/// The evidence document's schema name.
pub const EVIDENCE_SCHEMA: &str = "ekka.backend.discovery_evidence/v1";
/// The most network log lines the evidence carries, and the most characters
/// in each.
pub const LOG_LINES: usize = 2000;
pub const LOG_LINE_CHARS: usize = 400;
/// A decision this long or less after its proposal was made inside the
/// gateway's automatic approval; a later one, by a person.
const AUTO_DECIDED_WITHIN: chrono::Duration = chrono::Duration::seconds(2);

/// `approval_mode_body`, strictly.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApprovalModeBody {
    pub mode: String,
}

/// How the evidence read waits for a desk to settle: a read every `poll`;
/// settled once nothing changed for `quiet`; given up (`settled: false`) at
/// `give_up`, or earlier when the call's own deadline comes first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvidenceTimings {
    pub poll: Duration,
    pub quiet: Duration,
    pub give_up: Duration,
}

impl Default for EvidenceTimings {
    fn default() -> Self {
        Self {
            poll: Duration::from_secs(2),
            quiet: Duration::from_secs(20),
            give_up: Duration::from_secs(300),
        }
    }
}

/// What the settle compares between two reads: the pending proposals by id,
/// and the loaded policy version.
#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    pending: Vec<String>,
    active_version: u32,
}

fn utc_z(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

impl Backend {
    /// `approval_mode`.
    pub async fn approval_mode(
        &self,
        a: &Admitted,
        name: &str,
        body: &ApprovalModeBody,
        notes: &dyn Notes,
    ) -> Answer {
        // One approval change per desk at a time in this process, so a
        // permit is never written after its removal began.
        let _held = self.permits.lock(name).await;
        match body.mode.as_str() {
            AUTO => self.approval_auto(a, name, notes).await,
            MANUAL => self.approval_manual(a, name, notes).await,
            _ => refused(Code::RequestInvalid),
        }
    }

    async fn approval_auto(&self, a: &Admitted, name: &str, notes: &dyn Notes) -> Answer {
        let grant = match enforce::grant(a.verified().grant.as_ref()) {
            Ok(g) => g,
            Err(code) => return refused(code),
        };
        let (window, ends) = match enforce::discovery_window(&grant, name, Utc::now()) {
            Ok(w) => w,
            Err(code) => return refused(code),
        };
        let bearer = match self.bearer(a).await {
            Ok(b) => b,
            Err(answer) => return answer,
        };
        if let Err(answer) = self.claim(a, name).await {
            return answer;
        }
        // The desk as the backend holds it now, read under the claim, so its
        // image and providers cannot move before the setting is sent.
        let sb = match self.gateway.sandbox(&bearer, name).await {
            Ok(Some(sb)) => sb,
            Ok(None) => return self.refuse_claimed(a, name, Code::DeskNotFound).await,
            Err(e) => {
                return self
                    .conclude(a, name, Outcome::Refused, None, self.read_failed(&e))
                    .await;
            }
        };
        let meta = sb.metadata.clone().unwrap_or_default();
        let id = meta.id.clone();
        if !is_uuid(&id) {
            return self.refuse_claimed(a, name, Code::BackendRefused).await;
        }
        let spec = sb.spec.clone().unwrap_or_default();
        let image = spec.template.map(|t| t.image).unwrap_or_default();
        let ekka_desk = meta.labels.get(DESK_LABEL).map(String::as_str) == Some("true");
        if let Err(code) = enforce::discovery_desk(window, ekka_desk, &image, &spec.providers) {
            return self.refuse_claimed(a, name, code).await;
        }
        if !notes.sending() {
            return self.not_noted(a, name, notes).await;
        }
        let sent = self
            .gateway
            .set_approval_mode(&bearer, name, AUTO, &a.verified().request_id)
            .await;
        notes.sent();
        if let Err(e) = sent {
            return self.change_failed(a, name, e, notes.reissue()).await;
        }
        // NO PERMIT BEFORE THE READ-BACK SAYS `auto`.
        match self.gateway.approval_mode(&bearer, name).await {
            Ok(Some(m)) if m == AUTO => {}
            read => {
                tracing::warn!(desk = %name, read = ?read, "approvalModeNotApplied");
                return self
                    .auto_undone(a, &bearer, name, Code::ApprovalModeNotApplied)
                    .await;
            }
        }
        // The same desk, by its immutable id, with a policy to read back.
        let facts = match self.facts(&bearer, name).await {
            Ok(Some((_, f)))
                if f.backend_id.as_deref() == Some(id.as_str()) && f.policy_digest.is_some() =>
            {
                f
            }
            _ => {
                return self
                    .auto_undone(a, &bearer, name, Code::BackendUnavailable)
                    .await
            }
        };
        let now = Utc::now();
        if now >= ends {
            return self
                .auto_undone(a, &bearer, name, Code::DiscoveryWindowClosed)
                .await;
        }
        let expires = ends.min(now + chrono::Duration::minutes(PERMIT_MINUTES));
        let workspace = self.gateway.workspace();
        if workspace.is_empty() || workspace.len() > 128 {
            return self
                .auto_undone(a, &bearer, name, Code::BackendRefused)
                .await;
        }
        let permit = Permit {
            schema: PERMIT_SCHEMA.to_string(),
            workspace: workspace.to_string(),
            sandbox_id: id.clone(),
            desk: name.to_string(),
            expires_at: utc_z(expires),
            operation_id: a.verified().operation_id.clone(),
        };
        if let Err(why) = self.permits.write(&permit) {
            tracing::error!(desk = %name, why, "discoveryPermitNotWritten");
            return self
                .auto_undone(a, &bearer, name, Code::BackendUnavailable)
                .await;
        }
        tracing::info!(desk = %name, sandbox_id = %id, expires_at = %permit.expires_at, "discoveryPermitWritten");
        let rb = ReadBack::Live {
            sandbox_id: id,
            policy_digest: facts.policy_digest.clone().unwrap_or_default(),
            providers_digest: None,
        };
        let answer = Answer::ready(DeskFacts {
            approval_mode: Some(AUTO.to_string()),
            permit_expires_at: Some(permit.expires_at),
            ..facts
        });
        self.conclude(a, name, Outcome::Ready, Some(&rb), answer)
            .await
    }

    /// `auto` was sent but no permit is written: the desk goes back to
    /// `manual` as far as it can, and the change is refused with `code`.
    async fn auto_undone(&self, a: &Admitted, bearer: &str, name: &str, code: Code) -> Answer {
        if !self.back_to_manual(bearer, name).await {
            tracing::error!(desk = %name, "approvalModeLeftUnknownNoPermit");
        }
        self.refuse_claimed(a, name, code).await
    }

    /// Best effort: send `manual` (with no request id, so it is never taken
    /// for a replay) and read it back.
    async fn back_to_manual(&self, bearer: &str, name: &str) -> bool {
        if let Err(e) = self
            .gateway
            .set_approval_mode(bearer, name, MANUAL, "")
            .await
        {
            tracing::warn!(desk = %name, error = %e, "approvalModeManualNotSent");
            return false;
        }
        matches!(self.gateway.approval_mode(bearer, name).await, Ok(Some(m)) if m == MANUAL)
    }

    async fn approval_manual(&self, a: &Admitted, name: &str, notes: &dyn Notes) -> Answer {
        // FIRST, before the backend is asked anything: every permit naming
        // this desk goes.
        let mut permit_left = match self.permits.remove_for_desk(name) {
            Ok(()) => false,
            Err(why) => {
                tracing::error!(desk = %name, why, "discoveryPermitNotRemoved");
                true
            }
        };
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
        // And the one named by the desk's id, whatever it says inside.
        if is_uuid(&id) {
            if let Err(why) = self.permits.remove(&id) {
                tracing::error!(desk = %name, why, "discoveryPermitNotRemoved");
                permit_left = true;
            }
        }
        if !notes.sending() {
            return self.not_noted(a, name, notes).await;
        }
        let sent = self
            .gateway
            .set_approval_mode(&bearer, name, MANUAL, &a.verified().request_id)
            .await;
        notes.sent();
        if let Err(e) = sent {
            return self.change_failed(a, name, e, notes.reissue()).await;
        }
        self.manual_read_back(a, &bearer, name, permit_left).await
    }

    /// After `manual` was sent: `ready` only when the setting reads `manual`
    /// and no permit can be left; a permit that could not be removed keeps
    /// the desk held for a person (`unknown`).
    async fn manual_read_back(
        &self,
        a: &Admitted,
        bearer: &str,
        name: &str,
        permit_left: bool,
    ) -> Answer {
        match self.gateway.approval_mode(bearer, name).await {
            Ok(Some(m)) if m == MANUAL => {}
            read => {
                tracing::warn!(desk = %name, read = ?read, "approvalModeNotApplied");
                return self
                    .refuse_claimed(a, name, Code::ApprovalModeNotApplied)
                    .await;
            }
        }
        if permit_left {
            return self
                .conclude(a, name, Outcome::Unknown, None, Answer::unknown())
                .await;
        }
        match self.facts(bearer, name).await {
            Ok(Some((_, f))) if f.backend_id.is_some() && f.policy_digest.is_some() => {
                let rb = ReadBack::Live {
                    sandbox_id: f.backend_id.clone().unwrap_or_default(),
                    policy_digest: f.policy_digest.clone().unwrap_or_default(),
                    providers_digest: None,
                };
                let answer = Answer::ready(DeskFacts {
                    approval_mode: Some(MANUAL.to_string()),
                    ..f
                });
                self.conclude(a, name, Outcome::Ready, Some(&rb), answer)
                    .await
            }
            // Set, but the desk cannot be read back now: it stays running,
            // and recovery reads it back.
            _ => Answer::running(&a.verified().request_id),
        }
    }

    /// RECOVER an `approval_mode` change still running: toward `manual`
    /// only. Every permit for the desk goes first; a recovered change never
    /// writes one and never sends `auto`. A stored `manual` is re-issued as
    /// it was (the same request id and payload); a stored `auto` is undone
    /// with a fresh `manual` and settles `APPROVAL_MODE_NOT_APPLIED`. With no
    /// send allowed (a settle marker), a desk not reading `manual` is
    /// `unknown`, held for a person.
    pub(super) async fn approval_recover(
        &self,
        a: &Admitted,
        bearer: &str,
        desk: &str,
        body: &[u8],
        send: Option<&dyn Notes>,
    ) -> Answer {
        let rid = a.verified().request_id.clone();
        let Ok(body) = enforce::body::<ApprovalModeBody>(body) else {
            return Answer::running(&rid);
        };
        let auto = body.mode == AUTO;
        let _held = self.permits.lock(desk).await;
        if self.permits.remove_for_desk(desk).is_err() {
            return Answer::running(&rid);
        }
        match self.gateway.sandbox(bearer, desk).await {
            Ok(Some(sb)) => {
                let id = sb.metadata.map(|m| m.id).unwrap_or_default();
                if is_uuid(&id) && self.permits.remove(&id).is_err() {
                    return Answer::running(&rid);
                }
            }
            Ok(None) => {
                return self
                    .conclude(a, desk, Outcome::Refused, None, refused(Code::DeskNotFound))
                    .await
            }
            Err(_) => return Answer::running(&rid),
        }
        let manual_now = match self.gateway.approval_mode(bearer, desk).await {
            Ok(m) => m.as_deref() == Some(MANUAL),
            Err(_) => return Answer::running(&rid),
        };
        if !manual_now {
            let Some(notes) = send else {
                return self
                    .conclude(a, desk, Outcome::Unknown, None, Answer::unknown())
                    .await;
            };
            if !notes.sending() {
                return self.not_noted(a, desk, notes).await;
            }
            let request_id = if auto { "" } else { rid.as_str() };
            let sent = self
                .gateway
                .set_approval_mode(bearer, desk, MANUAL, request_id)
                .await;
            notes.sent();
            if sent.is_err() {
                return Answer::running(&rid);
            }
        }
        if auto {
            return match self.gateway.approval_mode(bearer, desk).await {
                Ok(Some(m)) if m == MANUAL => {
                    self.refuse_claimed(a, desk, Code::ApprovalModeNotApplied)
                        .await
                }
                _ => Answer::running(&rid),
            };
        }
        match self.gateway.approval_mode(bearer, desk).await {
            Ok(Some(m)) if m == MANUAL => self.manual_read_back(a, bearer, desk, false).await,
            _ => Answer::running(&rid),
        }
    }

    /// Before a desk is deleted, under its claim: its permits go, so none
    /// outlives it.
    pub(super) fn drop_permits(&self, desk: &str, sandbox_id: &str) -> Result<(), String> {
        self.permits.remove_for_desk(desk)?;
        if is_uuid(sandbox_id) {
            self.permits.remove(sandbox_id)?;
        }
        Ok(())
    }

    /// `discovery_evidence`: read only, no claim.
    pub async fn discovery_evidence(&self, a: &Admitted, name: &str) -> Answer {
        let bearer = match self.bearer(a).await {
            Ok(b) => b,
            Err(answer) => return answer,
        };
        let sb = match self.gateway.sandbox(&bearer, name).await {
            Ok(Some(sb)) => sb,
            Ok(None) => return refused(Code::DeskNotFound),
            Err(e) => return self.read_failed(&e),
        };
        let id = sb
            .metadata
            .as_ref()
            .map(|m| m.id.clone())
            .unwrap_or_default();
        if !is_uuid(&id) {
            return refused(Code::DeskNotDiscovery);
        }
        // Only a desk with a permit of its own: present, readable, naming it.
        match self.permits.read(&id) {
            Ok(Some(p)) if p.desk == name => {}
            Ok(_) => return refused(Code::DeskNotDiscovery),
            Err(why) => {
                tracing::warn!(desk = %name, why, "discoveryPermitUnreadable");
                return refused(Code::DeskNotDiscovery);
            }
        }
        let image = sb
            .spec
            .as_ref()
            .and_then(|s| s.template.as_ref())
            .map(|t| t.image.clone())
            .unwrap_or_default();
        let Some(image_digest) = enforce::image_digest(&image) else {
            return refused(Code::DeskNotDiscovery);
        };
        let (settled, settle_seconds) = match self.settle_drafts(a, &bearer, name).await {
            Ok(s) => s,
            Err(e) => return self.read_failed(&e),
        };
        match self
            .evidence(&bearer, name, &id, &image_digest, settled, settle_seconds)
            .await
        {
            Ok(Some(evidence)) => Answer::ready(DeskFacts {
                backend_id: Some(id),
                evidence: Some(evidence),
                ..DeskFacts::default()
            }),
            // No loaded policy to show, or a document over the bound even with
            // no log lines: what the desk did cannot be told whole.
            Ok(None) => Answer::unknown(),
            Err(e) => self.read_failed(&e),
        }
    }

    /// Wait until the pending proposals and the loaded policy version have
    /// not changed for `quiet`, reading every `poll`, until `give_up` (or the
    /// call's own settle window, if that ends first). Returns whether it
    /// settled, and the whole seconds it waited.
    async fn settle_drafts(
        &self,
        a: &Admitted,
        bearer: &str,
        name: &str,
    ) -> Result<(bool, u64), GatewayError> {
        let t = self.evidence;
        let started = tokio::time::Instant::now();
        let mut until = started + t.give_up;
        if let Some(at) = a.admitted_at() {
            until = until.min(at + self.settle_for);
        }
        let mut last: Option<Snapshot> = None;
        let mut since = started;
        let settled = loop {
            let Ok(read) = tokio::time::timeout_at(until, self.snapshot(bearer, name)).await else {
                break false;
            };
            let snap = read?;
            let now = tokio::time::Instant::now();
            if last.as_ref() != Some(&snap) {
                last = Some(snap);
                since = now;
            }
            if now.duration_since(since) >= t.quiet {
                break true;
            }
            if now + t.poll > until {
                break false;
            }
            tokio::time::sleep(t.poll).await;
        };
        Ok((settled, started.elapsed().as_secs()))
    }

    async fn snapshot(&self, bearer: &str, name: &str) -> Result<Snapshot, GatewayError> {
        let mut pending: Vec<String> = self
            .gateway
            .draft_chunks(bearer, name, "pending")
            .await?
            .into_iter()
            .map(|c| c.id)
            .collect();
        pending.sort_unstable();
        let status = self.gateway.policy_status(bearer, name).await?;
        Ok(Snapshot {
            pending,
            active_version: status.active_version,
        })
    }

    /// The evidence document, within [`EVIDENCE_MAX_BYTES`]: the oldest log
    /// lines are left out first. `None` when no loaded policy can be read, or
    /// the document is over the bound with no log lines at all.
    async fn evidence(
        &self,
        bearer: &str,
        name: &str,
        sandbox_id: &str,
        image_digest: &str,
        settled: bool,
        settle_seconds: u64,
    ) -> Result<Option<Value>, GatewayError> {
        let mut status = self.gateway.policy_status(bearer, name).await?;
        let active = status.active_version;
        if status.revision.as_ref().map(|r| r.version) != Some(active) {
            status = self.gateway.policy_revision(bearer, name, active).await?;
        }
        let loaded = status
            .revision
            .filter(|r| r.version == active)
            .and_then(|r| r.policy);
        let Some(policy) = loaded else {
            return Ok(None);
        };
        let (Some(policy_json), Some(policy_digest)) = (
            message_json(POLICY, &policy),
            message_digest(POLICY, &policy),
        ) else {
            return Ok(None);
        };
        let chunks = self.gateway.draft_chunks(bearer, name, "").await?;
        let history = self.gateway.draft_history(bearer, name).await?;
        let logs = self
            .gateway
            .sandbox_logs(bearer, name, u32::try_from(LOG_LINES).unwrap_or(u32::MAX))
            .await?;
        let pending: Vec<Value> = chunks
            .iter()
            .filter(|c| c.status == "pending")
            .map(pending_entry)
            .collect();
        let decided = decided_entries(&chunks, &history);
        let mut doc = json!({
            "schema": EVIDENCE_SCHEMA,
            "sandbox_id": sandbox_id,
            "desk": name,
            "image_digest": image_digest,
            "policy": policy_json,
            "policy_digest": policy_digest,
            "active_version": active,
            "drafts_pending": pending,
            "drafts_decided": decided,
            "network_log": [],
            "settled": settled,
            "settle_seconds": settle_seconds,
        });
        let lines = network_lines(&logs);
        let Some(kept) = fit_lines(&doc, &lines) else {
            return Ok(None);
        };
        doc["network_log"] = json!(kept);
        let fits = serde_json::to_vec(&doc).is_ok_and(|b| b.len() <= EVIDENCE_MAX_BYTES);
        Ok(fits.then_some(doc))
    }
}

/// A chunk as the evidence carries it: the rule it proposes, in the
/// gateway's own form (contracts 0.76.0, `chunk`).
fn chunk_json(c: &PolicyChunk) -> Value {
    c.proposed_rule
        .as_ref()
        .and_then(|r| message_json(NETWORK_RULE, r))
        .unwrap_or_else(|| json!({}))
}

/// A pending proposal: the chunk, its first endpoint's host and port, the
/// program that asked (`null` when none is bound), and its risk findings.
fn pending_entry(c: &PolicyChunk) -> Value {
    let endpoint = c.proposed_rule.as_ref().and_then(|r| r.endpoints.first());
    let host = endpoint.map(|e| e.host.clone()).unwrap_or_default();
    let port = endpoint
        .map(|e| e.ports.first().copied().unwrap_or(e.port))
        .filter(|p| *p <= 65_535)
        .unwrap_or(0);
    let binary = (!c.binary.is_empty()).then(|| c.binary.clone());
    let risk: Vec<String> = c
        .security_notes
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    json!({ "chunk": chunk_json(c), "host": host, "port": port, "binary": binary, "risk": risk })
}

fn time((seconds, nanos): (i64, i32)) -> Option<DateTime<Utc>> {
    DateTime::from_timestamp(seconds, u32::try_from(nanos).ok()?)
}

/// Every decided proposal: its decision, and who made it. The decision's
/// time is its history event's, else the chunk's own. A decision made within
/// [`AUTO_DECIDED_WITHIN`] of the proposal, or whose times are unknown, is
/// `auto`: only a later one is a person's.
fn decided_entries(chunks: &[PolicyChunk], history: &[DraftHistoryEntry]) -> Vec<Value> {
    chunks
        .iter()
        .filter(|c| c.status == "approved" || c.status == "rejected")
        .map(|c| {
            let event = history
                .iter()
                .rev()
                .find(|h| h.chunk_id == c.id && h.event_type == c.status);
            let decided = event
                .and_then(|h| {
                    h.event_time
                        .as_ref()
                        .and_then(|t| time((t.seconds, t.nanos)))
                })
                .or_else(|| {
                    c.decided_time
                        .as_ref()
                        .and_then(|t| time((t.seconds, t.nanos)))
                });
            let created = c
                .created_time
                .as_ref()
                .and_then(|t| time((t.seconds, t.nanos)));
            let by = match (created, decided) {
                (Some(made), Some(at)) if at - made > AUTO_DECIDED_WITHIN => "person",
                _ => "auto",
            };
            json!({ "chunk": chunk_json(c), "decision": c.status, "by": by })
        })
        .collect()
}

/// The network lines of a desk's log: those carrying `OCSF NET:` or
/// `OCSF HTTP:`, the last [`LOG_LINES`] of them, each its time (UTC, when
/// the line has one) and its message, redacted and then cut to
/// [`LOG_LINE_CHARS`] characters.
pub(crate) fn network_lines(logs: &[SandboxLogLine]) -> Vec<String> {
    let matching: Vec<&SandboxLogLine> = logs
        .iter()
        .filter(|l| l.message.contains("OCSF NET:") || l.message.contains("OCSF HTTP:"))
        .collect();
    let skip = matching.len().saturating_sub(LOG_LINES);
    matching
        .into_iter()
        .skip(skip)
        .map(|l| {
            let at = l
                .event_time
                .as_ref()
                .and_then(|t| time((t.seconds, t.nanos)))
                .map(|t| format!("{} ", utc_z(t)))
                .unwrap_or_default();
            crate::redact::line(&format!("{at}{}", l.message))
                .chars()
                .take(LOG_LINE_CHARS)
                .collect()
        })
        .collect()
}

/// The newest of `lines` that fit beside `doc` (whose `network_log` is
/// empty) within [`EVIDENCE_MAX_BYTES`], oldest first. `None` when `doc`
/// alone is over it.
pub(crate) fn fit_lines(doc: &Value, lines: &[String]) -> Option<Vec<String>> {
    let base = serde_json::to_vec(doc).ok()?.len();
    let mut room = EVIDENCE_MAX_BYTES.checked_sub(base)?;
    let mut kept = Vec::new();
    for l in lines.iter().rev() {
        let cost = serde_json::to_string(l).ok()?.len() + usize::from(!kept.is_empty());
        if cost > room {
            break;
        }
        room -= cost;
        kept.push(l.clone());
    }
    kept.reverse();
    Some(kept)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "discovery_tests.rs"]
mod tests;
