//! What a verified call does, in this ORDER OF CHECKS: a change is looked up in the operation records
//! FIRST. A recorded answer is delivered again as `duplicate`, a change still
//! running answers `running`, and the same id with another request is
//! refused `OPERATION_ID_REUSED`; none of these is executed or consumes its
//! token. Only a NEW change is admitted (its token consumed), recorded
//! before anything is sent for it, carried out by the driver, and settled
//! with its answer. A read takes no record.
//!
//! Before either runs, the desk's changes still `running` are recovered
//! (`recover.rs`). One that stays unresolved holds the desk: a read
//! answers `running` with that change's request id, and a change is refused
//! `DESK_BUSY` before anything is sent.

use std::sync::Arc;

use bytes::Bytes;
use serde::Deserialize;

use crate::answer::{Answer, Code};
use crate::driver::{Backend, Notes};
use crate::enforce::{self, CreateBody, PolicySetBody};
use crate::recover::{Recovery, Standing};
use crate::routes::{Operation, Route};
use crate::server::Handler;
use crate::store::{self, State, StoreError};
use crate::token::Verified;

/// A detach's body: the contract's `provider_detach_body`, strictly.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DetachBody {
    expected_resource_version: String,
}

/// The adapter's handler for verified calls, over `backend` and the
/// records `recovery` keeps.
#[must_use]
pub fn handler(backend: Arc<Backend>, recovery: Arc<Recovery>) -> Handler {
    Arc::new(move |route, verified, body| {
        let (backend, recovery) = (backend.clone(), recovery.clone());
        Box::pin(async move { answer(&backend, &recovery, &route, verified, &body).await })
    })
}

/// The desk a call is for: its route's, or a create's body's name.
fn desk_of(route: &Route, body: &[u8]) -> Option<String> {
    match route.operation {
        Operation::Create => enforce::body::<CreateBody>(body).ok().map(|c| c.name),
        _ => route.desk.clone(),
    }
}

/// What a record already says about this call, if anything.
fn recorded(rec: &store::Record, route: &Route, body: &[u8]) -> Answer {
    if rec.request_digest != store::request_digest(route, body) {
        return Answer::refused(Code::OperationIdReused);
    }
    match (rec.state, rec.duplicate()) {
        (State::Settled, Some(a)) => a,
        // Still running (here, or before a restart): nothing is sent again.
        _ => Answer::running(&rec.request_id),
    }
}

pub(crate) async fn answer(
    b: &Backend,
    recovery: &Recovery,
    route: &Route,
    verified: Verified,
    body: &Bytes,
) -> Answer {
    let store = recovery.store();
    let desk = desk_of(route, body);
    if !route.operation.mutates() {
        let a = match verified.admit() {
            Ok(a) => a,
            Err(code) => return Answer::refused(code),
        };
        if let Some(d) = desk.as_deref() {
            match recovery
                .reconcile(b, d, &a.verified().credential, None)
                .await
            {
                Standing::Clear => {}
                Standing::Unresolved(id) => return Answer::running(&id),
                Standing::Unreadable => return Answer::refused(Code::BackendUnavailable),
            }
        }
        return dispatch(b, &NoNotes, route, &a, body).await;
    }
    let request_id = verified.request_id.clone();
    match store.get(&request_id) {
        Ok(Some(rec)) => return recorded(&rec, route, body),
        Ok(None) => {}
        // An unreadable record is never taken for "none": nothing executes.
        Err(_) => return Answer::refused(Code::BackendUnavailable),
    }
    let gate_token = verified.gate_token.clone();
    let operation_id_header = verified.operation_id.clone();
    let a = match verified.admit() {
        Ok(a) => a,
        Err(code) => return Answer::refused(code),
    };
    // Marked before it is recorded, and held until it is settled: recovery
    // (another call for this desk) never takes a change while its first
    // attempt is still running here.
    let Some(_attempt) = recovery.take(&request_id) else {
        return Answer::running(&request_id);
    };
    let rec = store::running(
        route,
        desk.as_deref().unwrap_or_default(),
        &request_id,
        &operation_id_header,
        body,
        &gate_token,
        recovery.now(),
    );
    match store.begin(&rec) {
        Ok(()) => {}
        // Another delivery recorded it first: it is that one's to finish.
        Err(StoreError::Exists) => {
            return match store.get(&request_id) {
                Ok(Some(rec)) => recorded(&rec, route, body),
                _ => Answer::running(&request_id),
            };
        }
        Err(StoreError::Io(why)) => {
            tracing::error!(request_id = %request_id, why, "operationNotRecorded");
            return Answer::refused(Code::BackendUnavailable);
        }
    }
    // Recorded first, so a DESK_BUSY delivered twice stays DESK_BUSY.
    let standing = match desk.as_deref() {
        Some(d) => {
            recovery
                .reconcile(b, d, &a.verified().credential, Some(&request_id))
                .await
        }
        None => Standing::Clear,
    };
    let answer = match standing {
        Standing::Clear => {
            let notes = RecordNotes {
                recovery,
                request_id: &request_id,
            };
            dispatch(b, &notes, route, &a, body).await
        }
        Standing::Unresolved(_) => Answer::refused(Code::DeskBusy),
        Standing::Unreadable => Answer::refused(Code::BackendUnavailable),
    };
    if answer.outcome != crate::answer::Outcome::Running {
        // Tried twice. Still unsettled, the record says `running`, so this
        // call says so too (a redelivery answers from the record): recovery
        // settles it later, NOT_APPLIED if nothing was sent, else from the
        // gateway.
        let settled = store.settle(&request_id, &answer).or_else(|e| {
            tracing::warn!(request_id = %request_id, error = ?e, "operationSettleRetried");
            store.settle(&request_id, &answer)
        });
        if let Err(e) = settled {
            tracing::error!(request_id = %request_id, error = ?e, "operationNotSettled");
            return Answer::running(&request_id);
        }
    }
    answer
}

/// A change's notes, written to its record before the driver acts.
struct RecordNotes<'a> {
    recovery: &'a Recovery,
    request_id: &'a str,
}

impl Notes for RecordNotes<'_> {
    fn backend_id(&self, id: &str) -> bool {
        self.recovery
            .store()
            .note_backend_id(self.request_id, id)
            .is_ok()
    }

    fn sending(&self) -> bool {
        self.recovery
            .store()
            .note_sent(self.request_id, self.recovery.now())
            .is_ok()
    }
}

/// A read's notes: it has no record, and never sends, so any note asked
/// of it is refused (fails closed).
struct NoNotes;

impl Notes for NoNotes {
    fn backend_id(&self, _: &str) -> bool {
        false
    }
    fn sending(&self) -> bool {
        false
    }
}

/// `notes` writes to the change's record before the driver acts (a read
/// has none: it never sends).
async fn dispatch(
    b: &Backend,
    notes: &dyn Notes,
    route: &Route,
    a: &crate::token::Admitted,
    body: &Bytes,
) -> Answer {
    let desk = route.desk.as_deref().unwrap_or_default();
    match route.operation {
        Operation::Create => match enforce::body::<CreateBody>(body) {
            Ok(c) => b.create(a, &c, notes).await,
            Err(code) => Answer::refused(code),
        },
        Operation::Delete => b.delete(a, desk, notes).await,
        Operation::Stop => b.stop_or_start(a, desk, false, notes).await,
        Operation::Start => b.stop_or_start(a, desk, true, notes).await,
        Operation::Status => b.status(a, desk).await,
        Operation::PolicyGet => b.policy_get(a, desk).await,
        Operation::PolicySet => match enforce::body::<PolicySetBody>(body) {
            Ok(p) => b.policy_set(a, desk, &p, notes).await,
            Err(code) => Answer::refused(code),
        },
        Operation::ProviderDetach => match enforce::body::<DetachBody>(body) {
            Ok(d) => {
                let provider = route.provider.as_deref().unwrap_or_default();
                b.detach(a, desk, provider, &d.expected_resource_version, notes)
                    .await
            }
            Err(code) => Answer::refused(code),
        },
        // Reserved in v1: providers are set at install.
        Operation::ProviderConnect => Answer::refused(Code::NotAvailable),
    }
}
