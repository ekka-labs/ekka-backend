//! The operation records, through the handler, the driver and the fakes: a
//! change is recorded BEFORE anything is sent for it; a redelivery is
//! answered from the record and never executed again; the same id with
//! another request is refused; a change still running stays running; and
//! the records survive a restart. A read takes no record.

use std::os::unix::fs::PermissionsExt;

use bytes::Bytes;
use serde_json::{json, Value};

use super::{State, Store};
use crate::answer::{Code, Delivery, Outcome};
use crate::driver::tests::{grant, policy, world, World, RID};
use crate::routes::{Operation, Route};
use crate::token::Verified;

const IMAGE: &str =
    "ghcr.io/example/desk@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// The records under the world's state folder, through recovery (whose
/// clock reads now): a new one over the same folder is a restart.
fn store(w: &World) -> crate::recover::Recovery {
    crate::recover::tests::recovery(w, std::sync::Arc::new(chrono::Utc::now))
}

fn create(name: &str) -> Bytes {
    Bytes::from(
        json!({ "name": name, "image": IMAGE, "policy": policy(), "providers": ["github"] })
            .to_string(),
    )
}

fn route(op: Operation, desk: Option<&str>) -> Route {
    Route {
        operation: op,
        desk: desk.map(str::to_string),
        provider: None,
    }
}

/// One delivery of a call: a fresh verification each time, as a redelivery
/// (or a renewed token) for the same operation would be.
async fn deliver(
    w: &World,
    s: &crate::recover::Recovery,
    r: &Route,
    body: &Bytes,
) -> crate::answer::Answer {
    crate::ops::answer(&w.b, s, r, Verified::for_tests(Some(grant())), body).await
}

fn record_path(w: &World) -> std::path::PathBuf {
    w.dir
        .path()
        .join("state/operations")
        .join(format!("{RID}.json"))
}

fn creates(w: &World) -> usize {
    w.gw.lock()
        .unwrap()
        .request_ids
        .iter()
        .filter(|(rpc, _)| rpc == "CreateSandbox")
        .count()
}

/// The record exists, `running`, at the moment the gateway is asked: the
/// fake reads the file before it acts.
#[tokio::test]
async fn a_change_is_recorded_before_anything_is_sent_for_it() {
    let w = world().await;
    let s = store(&w);
    w.gw.lock().unwrap().watch = Some(record_path(&w));
    let a = deliver(
        &w,
        &s,
        &route(Operation::Create, None),
        &create("code-desk"),
    )
    .await;
    assert_eq!(a.outcome, Outcome::Ready, "{a:?}");
    let watched = w.gw.lock().unwrap().watched.clone();
    assert_eq!(watched.len(), 1);
    let (rpc, seen) = &watched[0];
    assert_eq!(rpc, "CreateSandbox");
    let at_call: Value =
        serde_json::from_str(seen.as_deref().expect("no record at the call")).unwrap();
    assert_eq!(at_call["state"], "running");
    assert_eq!(at_call["request_id"], RID);
    // And settled with its answer after.
    let rec = s.store().get(RID).unwrap().unwrap();
    assert_eq!(rec.state, State::Settled);
    assert_eq!(rec.answer.unwrap().outcome, Outcome::Ready);
    let mode = std::fs::metadata(record_path(&w))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
}

/// A redelivery (the same operation, a renewed token) is answered from the
/// record as `duplicate`, with the same outcome and facts, and nothing is
/// sent again: one CreateSandbox, one claim.
#[tokio::test]
async fn a_redelivered_change_is_its_recorded_answer_never_a_second_change() {
    let w = world().await;
    let s = store(&w);
    let r = route(Operation::Create, None);
    let first = deliver(&w, &s, &r, &create("code-desk")).await;
    let again = deliver(&w, &s, &r, &create("code-desk")).await;
    assert_eq!(first.delivery, Delivery::First);
    assert_eq!(again.delivery, Delivery::Duplicate);
    assert_eq!((again.outcome, &again.desk), (first.outcome, &first.desk));
    assert_eq!(creates(&w), 1);
    let claims = w
        .enc
        .lock()
        .unwrap()
        .calls()
        .iter()
        .filter(|(m, _)| m == "runner_desk_claim")
        .count();
    assert_eq!(claims, 1);
}

#[tokio::test]
async fn the_same_operation_with_another_request_is_refused() {
    let w = world().await;
    let s = store(&w);
    let r = route(Operation::Create, None);
    deliver(&w, &s, &r, &create("code-desk")).await;
    let other = deliver(&w, &s, &r, &create("another-desk")).await;
    assert_eq!(other.code, Some(Code::OperationIdReused));
    assert_eq!(creates(&w), 1);
}

/// A refusal is recorded too: delivered twice, it stays refused.
#[tokio::test]
async fn a_refusal_delivered_twice_stays_refused() {
    let w = world().await;
    let s = store(&w);
    let r = route(Operation::Create, None);
    let body = Bytes::from(
        json!({ "name": "code-desk", "image": format!("x@sha256:{}", "c".repeat(64)),
                "policy": policy(), "providers": ["github"] })
        .to_string(),
    );
    let first = deliver(&w, &s, &r, &body).await;
    let again = deliver(&w, &s, &r, &body).await;
    assert_eq!(first.code, Some(Code::ConstraintImageDigests));
    assert_eq!(
        (again.delivery, again.code),
        (Delivery::Duplicate, Some(Code::ConstraintImageDigests))
    );
}

/// A change whose reply was lost stays `running`: a redelivery, even after a
/// restart (a new store over the same folder), sends nothing again.
#[tokio::test]
async fn a_running_change_stays_running_across_redelivery_and_restart() {
    let w = world().await;
    w.gw.lock()
        .unwrap()
        .lose_reply
        .insert("CreateSandbox".into());
    let r = route(Operation::Create, None);
    {
        let s = store(&w);
        let a = deliver(&w, &s, &r, &create("code-desk")).await;
        assert_eq!(a.outcome, Outcome::Running);
        assert_eq!(s.store().get(RID).unwrap().unwrap().state, State::Running);
    }
    let restarted = store(&w);
    let a = deliver(&w, &restarted, &r, &create("code-desk")).await;
    assert_eq!(
        (a.outcome, a.operation_id.as_deref()),
        (Outcome::Running, Some(RID))
    );
    assert_eq!(creates(&w), 1, "never sent again");
}

/// A record that cannot be read is never taken for "none": nothing runs.
#[tokio::test]
async fn an_unreadable_record_stops_the_change() {
    let w = world().await;
    let s = store(&w);
    std::fs::write(record_path(&w), b"{ not a record").unwrap();
    let a = deliver(
        &w,
        &s,
        &route(Operation::Create, None),
        &create("code-desk"),
    )
    .await;
    assert_eq!(a.code, Some(Code::BackendUnavailable));
    assert!(w.gw.lock().unwrap().request_ids.is_empty());
}

#[tokio::test]
async fn a_read_takes_no_record() {
    let w = world().await;
    let s = store(&w);
    deliver(
        &w,
        &s,
        &route(Operation::Status, Some("nope")),
        &Bytes::new(),
    )
    .await;
    assert!(!record_path(&w).exists());
}

#[test]
fn the_store_folder_must_be_this_users_and_closed_to_others() {
    let d = crate::socket::tests::dir();
    let state = d.path().join("state");
    std::fs::create_dir(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(Store::open(&state, uid())
        .unwrap_err()
        .starts_with("STORE_UNSAFE"));
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(Store::open(&state, uid() + 1)
        .unwrap_err()
        .starts_with("STORE_UNSAFE"));
    let s = Store::open(&state, uid()).unwrap();
    let mode = std::fs::metadata(state.join("operations"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o700);
    assert!(
        s.get("../etc/passwd").is_err(),
        "only request ids name records"
    );
}

/// A desk's running changes are found through the running index alone: a
/// change is indexed while it runs and leaves the index once settled, and a
/// record the index does not name is never read (so an old, unreadable one
/// holds no desk, and a call never reads every record ever kept).
#[tokio::test]
async fn running_changes_are_found_through_the_index_only() {
    let w = world().await;
    let s = store(&w);
    let index = w.dir.path().join("state/running").join(RID);
    w.gw.lock()
        .unwrap()
        .lose_reply
        .insert("CreateSandbox".into());
    let r = route(Operation::Create, None);
    assert_eq!(
        deliver(&w, &s, &r, &create("code-desk")).await.outcome,
        Outcome::Running
    );
    assert!(index.exists(), "indexed while running");
    assert_eq!(s.store().running_for("code-desk").unwrap().len(), 1);
    s.store()
        .settle(RID, &crate::answer::Answer::unknown())
        .unwrap();
    assert!(!index.exists(), "out of the index once settled");
    // An unreadable record the index does not name is never read.
    std::fs::write(
        w.dir
            .path()
            .join("state/operations/00000000-0000-5000-8000-0000000000aa.json"),
        b"{ not a record",
    )
    .unwrap();
    assert_eq!(s.store().running_for("code-desk").unwrap(), vec![]);
}

/// The ORDER OF CHECKS: only lookup-first
/// passes them. The calls carry real Govern-signed tokens through ONE
/// verifier, so its replay cache is the one a second delivery meets.
mod lookup_first {
    use bytes::Bytes;

    use super::{store, Code, Delivery, Outcome};
    use crate::driver::tests::world;
    use crate::routes::{Operation, Route};
    use crate::testkit::{call, govern_test_key, header, op_id, token, verifier, NOW};

    fn stop() -> Route {
        Route {
            operation: Operation::Stop,
            desk: Some("code-desk".into()),
            provider: None,
        }
    }

    /// The SAME signed token, delivered twice for a settled operation: the
    /// second is its recorded answer. Admitting first would have answered
    /// TOKEN_REPLAYED, because the first delivery consumed that token.
    #[tokio::test]
    async fn the_same_token_twice_for_a_settled_operation_is_its_recorded_answer() {
        let w = world().await;
        let s = store(&w);
        let k = govern_test_key();
        let v = verifier(&[("govern-gate-token-v1", &k)], NOW);
        let h = header(&token(), "govern-gate-token-v1", &k);
        let id = op_id();
        let deliver = || v.verify(&call(Operation::Stop, &h, &id, b"")).unwrap();
        // No such desk on the fake gateway: refused DESK_NOT_FOUND, settled.
        let first = crate::ops::answer(&w.b, &s, &stop(), deliver(), &Bytes::new()).await;
        assert_eq!(first.code, Some(Code::DeskNotFound));
        assert_eq!(v.consumed(), 1);
        let again = crate::ops::answer(&w.b, &s, &stop(), deliver(), &Bytes::new()).await;
        assert_eq!(
            (again.delivery, again.outcome, again.code),
            (
                Delivery::Duplicate,
                Outcome::Refused,
                Some(Code::DeskNotFound)
            ),
            "not TOKEN_REPLAYED: the record answered before the replay cache"
        );
        assert_eq!(v.consumed(), 1);
    }

    /// A RENEWED token (a new token id) for a change still running answers
    /// `running`, and the new token is NOT consumed: it stays usable.
    #[tokio::test]
    async fn a_renewed_token_for_a_running_operation_is_running_and_not_consumed() {
        let w = world().await;
        let s = store(&w);
        {
            let mut g = w.gw.lock().unwrap();
            g.sandboxes.insert("code-desk".into(), Default::default());
            g.lose_reply.insert("StopSandbox".into());
        }
        let k = govern_test_key();
        let v = verifier(&[("govern-gate-token-v1", &k)], NOW);
        let id = op_id();
        let first_h = header(&token(), "govern-gate-token-v1", &k);
        let first = v
            .verify(&call(Operation::Stop, &first_h, &id, b""))
            .unwrap();
        let a = crate::ops::answer(&w.b, &s, &stop(), first, &Bytes::new()).await;
        assert_eq!(a.outcome, Outcome::Running);
        assert_eq!(v.consumed(), 1);
        let mut renewed = token();
        renewed["token_id"] = serde_json::json!("c99d004b-b342-4447-917d-c5d4264589d6");
        let renewed_h = header(&renewed, "govern-gate-token-v1", &k);
        let again = v
            .verify(&call(Operation::Stop, &renewed_h, &id, b""))
            .unwrap();
        let a = crate::ops::answer(&w.b, &s, &stop(), again, &Bytes::new()).await;
        assert_eq!(a.outcome, Outcome::Running);
        assert_eq!(v.consumed(), 1, "the renewed token was not consumed");
        let stops =
            w.gw.lock()
                .unwrap()
                .request_ids
                .iter()
                .filter(|(rpc, _)| rpc == "StopSandbox")
                .count();
        assert_eq!(stops, 1, "nothing sent again");
    }
}

/// One adapter per state folder: a second lock on the same folder refuses,
/// naming it, and the folder can be locked again once the first is gone.
#[test]
fn a_second_adapter_on_the_same_state_folder_refuses_to_start() {
    let d = tempfile::tempdir().unwrap();
    let first = super::lock_state_dir(d.path()).unwrap();
    let second = super::lock_state_dir(d.path()).unwrap_err();
    assert!(second.starts_with("STATE_IN_USE: "), "{second}");
    drop(first);
    assert!(
        super::lock_state_dir(d.path()).is_ok(),
        "free once the first ended"
    );
}

/// A release's index entry is written before its record settles. A parallel
/// pass that meets the entry while the record is still running keeps it, so
/// the release the record then owes is always indexed and retried.
#[test]
fn a_releasing_entry_for_a_record_still_running_is_kept_until_it_settles() {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let st = Store::open(d.path(), uid()).unwrap();
    let rid = "00000000-0000-5000-8000-0000000000aa";
    let body = create("code-desk");
    let rec = super::running(
        &route(Operation::Create, None),
        "code-desk",
        rid,
        "op",
        &body,
        "token",
        chrono::Utc::now(),
    );
    st.begin(&rec).unwrap();
    // The index entry, as settle_releasing writes it first.
    let entry = d.path().join("releasing").join(rid);
    std::fs::write(&entry, b"").unwrap();
    assert!(st.releasing().unwrap().is_empty(), "nothing owed yet");
    assert!(entry.exists(), "kept while the record is running");
    let owed = super::PendingRelease {
        outcome: "ready".into(),
        read_back: None,
    };
    st.settle_releasing(rid, &crate::answer::Answer::unknown(), &owed)
        .unwrap();
    let found = st.releasing().unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].release_pending.as_ref(), Some(&owed));
    st.released(rid).unwrap();
    assert!(st.releasing().unwrap().is_empty());
    assert!(!entry.exists(), "cleared once released");
}
