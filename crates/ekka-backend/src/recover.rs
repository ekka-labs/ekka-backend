//! Recovery: a change that answered `running` is finished by a
//! later call for its desk, never by the adapter on its own.
//!
//! Before any call for a desk, each change still `running` on it is taken in
//! turn, admitted-first:
//!
//! 1. A SETTLE MARKER for that change (`<state_dir>/settle/<request id>.json`,
//!    contracts `settle-marker.v1`, written by the kit's `up.sh desks settle`)
//!    is checked against the change; a good one means the change has stopped,
//!    and the read-back alone decides. Nothing is sent. The marker is
//!    consumed (renamed `.used`) once the change is settled by it.
//! 2. Otherwise, within [`REISSUE_WITHIN`] of its admission, the change is
//!    RE-ISSUED under its own request id and the claim it already holds:
//!    OpenShell replays a recorded success, or answers UNCERTAIN, and never
//!    applies it twice. Its stored gate token is re-checked first
//!    (`verify_stored`), at its admission time, never consumed.
//! 3. Otherwise it stays `running`: only the host procedure settles it.
//!
//! A change still `running` after that leaves its desk UNRESOLVED: a status
//! answers `running` with that change's request id, and a change is refused
//! `DESK_BUSY` before anything is sent.

use std::collections::HashSet;
use std::io::Read as _;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::answer::{Answer, Outcome};
use crate::config::BackendGateway;
use crate::driver::Backend;
use crate::routes::Operation;
use crate::store::{Record, State, Store};
use crate::token::{Admitted, Credential, Verifier};

/// OpenShell keeps a recorded success for 24 h (`SUCCESS_TTL_MS`,
/// `mutation_replay.rs:41` at e1f3c82); after that the same request id
/// EXECUTES AGAIN. A change is re-issued only within 20 h of its admission:
/// 4 h for the call itself and for the two clocks to disagree.
#[must_use]
pub fn reissue_within() -> chrono::Duration {
    chrono::Duration::hours(20)
}

/// The largest marker read.
const MAX_MARKER: u64 = 64 * 1024;

pub type Clock = Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>;

/// The gateway's identity in a settle marker: `<url>#<workspace>`, the pair
/// a request id binds.
#[must_use]
pub fn gateway_identity(g: &BackendGateway) -> String {
    format!("{}#{}", g.url, g.workspace)
}

/// Where a desk stands after its running changes were taken in turn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Standing {
    /// No change is running on it.
    Clear,
    /// This change (its request id) is still running on it.
    Unresolved(String),
    /// Its records could not be read: never taken for "clear".
    Unreadable,
}

/// `settle-marker.v1`, strictly.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    operation_id: String,
    desk: String,
    /// `null` only for a create whose desk the installer found no container
    /// of. Never absent.
    backend_id: Option<String>,
    gateway_identity: String,
    gateway_restarted_at: String,
    quiet_until: String,
    containers: Vec<Container>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Container {
    id: String,
    state: String,
}

/// `settle-hold.v1`, strictly.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Hold {
    operation_id: String,
    held_at: String,
}

/// A marker's time: RFC 3339 in UTC, `Z` only, as the schema's pattern.
fn utc(s: &str) -> Option<DateTime<Utc>> {
    if !s.ends_with('Z') {
        return None;
    }
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

/// What a marker for a change said.
enum Fence {
    /// None was written.
    None,
    /// One was, and it is refused: why.
    Refused(&'static str),
    /// One was, and it settles this change.
    Stopped,
    /// One was for a create that never reached the desk, and the gateway's
    /// own read-back after its restart agrees: nothing was created.
    NeverApplied,
}

pub struct Recovery {
    store: Arc<Store>,
    verifier: Arc<Verifier>,
    gateway_identity: String,
    settle_dir: PathBuf,
    uid: u32,
    now: Clock,
    /// Changes being recovered now: a second call meeting one answers it
    /// unresolved, never re-issues it beside the first.
    busy: Mutex<HashSet<String>>,
}

/// Removes its id from `busy` when dropped.
pub(crate) struct Taken<'a>(&'a Mutex<HashSet<String>>, String);

impl Drop for Taken<'_> {
    fn drop(&mut self) {
        if let Ok(mut b) = self.0.lock() {
            b.remove(&self.1);
        }
    }
}

impl Recovery {
    /// Recovery over `store`, its markers in `<state_dir>/settle`, made if
    /// missing. That folder must belong to `uid` and be closed to group and
    /// others, as the records' folder.
    ///
    /// # Errors
    /// `STORE_UNSAFE` or `STORE_UNAVAILABLE`: the adapter does not start.
    pub fn new(
        store: Arc<Store>,
        verifier: Arc<Verifier>,
        gateway_identity: String,
        state_dir: &Path,
        uid: u32,
        now: Clock,
    ) -> Result<Self, String> {
        let settle_dir = state_dir.join("settle");
        if !settle_dir.exists() {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&settle_dir)
                .map_err(|e| format!("STORE_UNAVAILABLE: {}: {e}", settle_dir.display()))?;
        }
        let m = std::fs::symlink_metadata(&settle_dir)
            .map_err(|e| format!("STORE_UNAVAILABLE: {}: {e}", settle_dir.display()))?;
        if !m.is_dir() || m.uid() != uid || m.mode() & 0o077 != 0 {
            return Err(format!(
                "STORE_UNSAFE: {} must be a folder owned by uid {uid} and closed to group and others",
                settle_dir.display()
            ));
        }
        Ok(Self {
            store,
            verifier,
            gateway_identity,
            settle_dir,
            uid,
            now,
            busy: Mutex::default(),
        })
    }

    #[must_use]
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// The records, shared with the driver, which writes a change's answer
    /// before it releases the claim.
    #[cfg(test)]
    pub(crate) fn records(&self) -> Arc<Store> {
        self.store.clone()
    }

    /// Mark `request_id` as being worked on (its first attempt, in ops):
    /// recovery leaves it alone until the mark drops. `None` when another
    /// call has it.
    pub(crate) fn take(&self, request_id: &str) -> Option<Taken<'_>> {
        let mut busy = self.busy.lock().ok()?;
        busy.insert(request_id.to_string())
            .then(|| Taken(&self.busy, request_id.to_string()))
    }

    /// Now, by the clock recovery measures a change's age with: a change is
    /// admitted by it too.
    #[must_use]
    pub fn now(&self) -> DateTime<Utc> {
        (self.now)()
    }

    /// Take each change still running on `desk` in turn (all but `except`,
    /// the call's own), with the CURRENT call's credential.
    pub async fn reconcile(
        &self,
        b: &Backend,
        desk: &str,
        credential: &Credential,
        except: Option<&str>,
    ) -> Standing {
        let Ok(running) = self.store.running_for(desk) else {
            return Standing::Unreadable;
        };
        let mut standing = Standing::Clear;
        for rec in running {
            if Some(rec.request_id.as_str()) == except {
                continue;
            }
            if !self.settle_one(b, &rec.request_id, credential).await && standing == Standing::Clear
            {
                standing = Standing::Unresolved(rec.request_id);
            }
        }
        standing
    }

    /// Whether `request_id` is settled when this returns.
    async fn settle_one(&self, b: &Backend, request_id: &str, credential: &Credential) -> bool {
        let Some(_taken) = self.take(request_id) else {
            return false;
        };
        // Read again under the mark: another call may have settled it.
        let rec = match self.store.get(request_id) {
            Ok(Some(r)) if r.state == State::Running => r,
            Ok(Some(_)) => return true,
            _ => return false,
        };
        let Some((answer, by_marker)) = self.recover(b, &rec, credential).await else {
            return false;
        };
        if answer.outcome == Outcome::Running {
            return false;
        }
        if let Err(e) = self.store.settle(request_id, &answer) {
            tracing::error!(request_id, error = ?e, "operationNotSettled");
            return false;
        }
        tracing::info!(request_id, outcome = ?answer.outcome, by_marker, "operationRecovered");
        if by_marker {
            self.consume(request_id);
        }
        true
    }

    /// The change's answer now, and whether a marker decided it; `None` when
    /// nothing could be tried (it stays running).
    async fn recover(
        &self,
        b: &Backend,
        rec: &Record,
        credential: &Credential,
    ) -> Option<(Answer, bool)> {
        let rid = rec.request_id.as_str();
        let operation = Operation::from_name(&rec.operation)?;
        let body = base64::engine::general_purpose::STANDARD
            .decode(&rec.body_b64)
            .ok()?;
        let admitted_at = DateTime::parse_from_rfc3339(&rec.admitted_at)
            .ok()?
            .with_timezone(&Utc);
        // NEVER SENT (no send noted: it stopped before its checks and claim
        // were done, or was refused before sending): nothing reached the
        // desk, so it is never re-issued. It settles NOT_APPLIED and its
        // claim, if it holds one, is released.
        if rec.last_sent_at.is_none() {
            let reader = Admitted::for_read_back(rid, &rec.operation_id_header, credential.clone());
            let answer = b.not_applied(&reader, &rec.desk).await;
            // A marker for it, if any, is consumed with it: harmless.
            return Some((answer, self.read_marker(rid).ok().flatten().is_some()));
        }
        // A marker SENDS NOTHING: it reads the desk back and releases the
        // claim. So it acts without re-checking the stored token, under an
        // admission that can only read (`Backend::read_back`): a Govern key
        // rotated since never holds a settled desk forever.
        let reader = Admitted::for_read_back(rid, &rec.operation_id_header, credential.clone());
        match self.fence(b, &reader, rec, admitted_at).await {
            Fence::Stopped => {
                let answer = b
                    .read_back(
                        &reader,
                        operation,
                        &rec.desk,
                        rec.provider.as_deref(),
                        &body,
                        rec.backend_id.as_deref(),
                    )
                    .await;
                return Some((answer, true));
            }
            Fence::NeverApplied => return Some((b.not_applied(&reader, &rec.desk).await, true)),
            Fence::Refused(why) => tracing::warn!(request_id = rid, why, "settleMarkerRefused"),
            Fence::None => {}
        }
        if (self.now)() - admitted_at >= reissue_within() {
            return None;
        }
        // The kit is settling it: never sent while its hold stands.
        if self.held(rid) {
            return None;
        }
        // A re-issue SENDS: only under the stored token, re-checked.
        let recovered = match self.verifier.verify_stored(
            &rec.gate_token,
            operation,
            &rec.operation_id_header,
            &body,
            admitted_at,
        ) {
            Ok(r) => r,
            Err(code) => {
                tracing::error!(request_id = rid, code = ?code, "storedTokenRefused");
                return None;
            }
        };
        let a = Admitted::for_recovery(recovered, rid, &rec.gate_token, credential.clone());
        // Noted durably BEFORE it is sent: a marker counts only for a gateway
        // restarted after this, so this send can never be inside the gateway
        // when a marker releases the desk. Not noted: not sent.
        if let Err(e) = self.store.note_sent(rid, (self.now)()) {
            tracing::error!(request_id = rid, error = ?e, "sendNotNoted");
            return None;
        }
        let answer = b
            .reissue(
                &a,
                operation,
                &rec.desk,
                rec.provider.as_deref(),
                &body,
                rec.backend_id.as_deref(),
            )
            .await;
        Some((answer, false))
    }

    fn marker_path(&self, request_id: &str) -> PathBuf {
        self.settle_dir.join(format!("{request_id}.json"))
    }

    /// The marker for `rec`, checked against it: its operation, desk, backend
    /// id and gateway; a restart AFTER the change was last sent (one before
    /// fences nothing sent after it); a quiet window that ends after the
    /// restart and has ended; and no container still created (never started),
    /// restarting or removing.
    async fn fence(
        &self,
        b: &Backend,
        a: &Admitted,
        rec: &Record,
        admitted_at: DateTime<Utc>,
    ) -> Fence {
        let raw = match self.read_marker(&rec.request_id) {
            Ok(None) => return Fence::None,
            Ok(Some(raw)) => raw,
            Err(why) => return Fence::Refused(why),
        };
        // `backend_id` may be null, never left out.
        let named = serde_json::from_slice::<serde_json::Value>(&raw)
            .is_ok_and(|v| v.get("backend_id").is_some());
        let (true, Ok(m)) = (named, serde_json::from_slice::<Marker>(&raw)) else {
            return Fence::Refused("not a settle-marker.v1");
        };
        if m.operation_id != rec.request_id {
            return Fence::Refused("another operation");
        }
        if m.desk != rec.desk {
            return Fence::Refused("another desk");
        }
        if m.gateway_identity != self.gateway_identity {
            return Fence::Refused("another desk backend");
        }
        let (Some(restarted), Some(quiet)) = (utc(&m.gateway_restarted_at), utc(&m.quiet_until))
        else {
            return Fence::Refused("a time is not RFC 3339 UTC");
        };
        // The restart must come after the change's LAST send (its admission,
        // or the latest re-issue): a send after the restart may still be in
        // the gateway, and a marker would release the desk under it.
        let last_sent = match rec
            .last_sent_at
            .as_deref()
            .map(DateTime::parse_from_rfc3339)
        {
            Some(Ok(t)) => t.with_timezone(&Utc).max(admitted_at),
            None => admitted_at,
            Some(Err(_)) => return Fence::Refused("the record's last send is unreadable"),
        };
        if restarted <= last_sent {
            return Fence::Refused(
                "NVIDIA OpenShell's gateway restarted before the change was last sent",
            );
        }
        if quiet <= restarted {
            return Fence::Refused("the quiet window does not end after the restart");
        }
        if quiet > (self.now)() {
            return Fence::Refused("the quiet window has not ended");
        }
        if m.containers.len() > 64
            || !m.containers.iter().all(|c| {
                c.id.len() == 64
                    && c.id.bytes().all(|x| matches!(x, b'0'..=b'9' | b'a'..=b'f'))
                    && matches!(c.state.as_str(), "running" | "paused" | "exited" | "dead")
            })
        {
            return Fence::Refused("a container is not settled");
        }
        let Some(marked) = m.backend_id.as_deref() else {
            return self.never_applied(b, a, rec, &m).await;
        };
        // The desk the change targeted: the id noted before a delete was
        // sent, else the desk's id now. Neither: nothing to match it to.
        let target = match &rec.backend_id {
            Some(id) => Some(id.clone()),
            None => b.desk_now(a, &rec.desk).await.ok().flatten(),
        };
        if target.as_deref() != Some(marked) {
            return Fence::Refused("another desk's backend id");
        }
        Fence::Stopped
    }

    /// A marker naming no backend id: only a create's, with no container,
    /// and only when the GATEWAY's own store, asked now (after the restart
    /// the marker proves), has no such desk. The gateway would find a create
    /// it kept even with no container launched yet; after the restart it has
    /// no call in flight, and nothing is sent after a marker: so the create
    /// can never land later.
    async fn never_applied(&self, b: &Backend, a: &Admitted, rec: &Record, m: &Marker) -> Fence {
        if rec.operation != Operation::Create.name() {
            return Fence::Refused("no backend id, and not a create");
        }
        if !m.containers.is_empty() {
            return Fence::Refused("no backend id, yet containers");
        }
        match b.desk_now(a, &rec.desk).await {
            Ok(None) => Fence::NeverApplied,
            Ok(Some(_)) => Fence::Refused("no backend id, yet the desk backend has the desk"),
            Err(()) => Fence::Refused("the desk backend could not be asked"),
        }
    }

    fn read_marker(&self, request_id: &str) -> Result<Option<Vec<u8>>, &'static str> {
        self.read_settle_file(&self.marker_path(request_id))
    }

    /// Whether a VALID settle hold (contracts `settle-hold.v1`) stands for
    /// `request_id`: the kit's `up.sh desks settle` writes it before it
    /// restarts the gateway, and while it stands the change is never
    /// re-issued, so no send can land after that restart. A hold that is
    /// unsafe or malformed counts as none (logged): it can only ever stop
    /// sends, so ignoring a bad one keeps the old behavior.
    fn held(&self, request_id: &str) -> bool {
        let raw = match self.read_settle_file(&self.hold_path(request_id)) {
            Ok(None) => return false,
            Ok(Some(raw)) => raw,
            Err(why) => {
                tracing::warn!(request_id, why, "settleHoldIgnored");
                return false;
            }
        };
        match serde_json::from_slice::<Hold>(&raw) {
            Ok(h) if h.operation_id == request_id && utc(&h.held_at).is_some() => true,
            _ => {
                tracing::warn!(
                    request_id,
                    why = "not a settle-hold.v1 for this operation",
                    "settleHoldIgnored"
                );
                false
            }
        }
    }

    fn hold_path(&self, request_id: &str) -> PathBuf {
        self.settle_dir.join(format!("{request_id}.hold"))
    }

    /// A settle file's bytes, if one was written. It must be a regular file
    /// of this user's, closed to group and others, and the file opened must
    /// be the one checked (a link swapped in between is refused).
    fn read_settle_file(&self, path: &Path) -> Result<Option<Vec<u8>>, &'static str> {
        let before = match std::fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err("unreadable"),
        };
        if !before.file_type().is_file() || before.uid() != self.uid || before.mode() & 0o077 != 0 {
            return Err("not a file of the adapter's user, mode 0600");
        }
        let file = std::fs::File::open(path).map_err(|_| "unreadable")?;
        let opened = file.metadata().map_err(|_| "unreadable")?;
        if (opened.dev(), opened.ino()) != (before.dev(), before.ino()) {
            return Err("changed while read");
        }
        let mut raw = Vec::new();
        file.take(MAX_MARKER + 1)
            .read_to_end(&mut raw)
            .map_err(|_| "unreadable")?;
        if raw.len() as u64 > MAX_MARKER {
            return Err("too large");
        }
        Ok(Some(raw))
    }

    /// The marker has settled its change: never read again. Its hold goes
    /// too, if the kit had not removed it yet (it may stop between writing
    /// the marker and removing the hold).
    fn consume(&self, request_id: &str) {
        let path = self.marker_path(request_id);
        let used = self.settle_dir.join(format!("{request_id}.json.used"));
        if let Err(e) = std::fs::rename(&path, &used) {
            tracing::error!(request_id, error = %e, "settleMarkerNotConsumed");
        }
        let hold = self.hold_path(request_id);
        let used = self.settle_dir.join(format!("{request_id}.hold.used"));
        match std::fs::rename(&hold, &used) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                tracing::error!(request_id, error = %e, "settleHoldNotConsumed");
            }
            _ => {}
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "recover_tests.rs"]
pub(crate) mod tests;
