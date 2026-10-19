//! Recovery, through the handler, the driver and the fakes, with
//! tokens signed as Govern signs them: a change that answered `running` is
//! re-issued by the next call for its desk (inside the bound), held while it
//! stays unresolved, never sent after the bound, and settled by a settle
//! marker only when that marker is for this change on this machine.

use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};

use super::{gateway_identity, Clock, Recovery};
use crate::answer::{Answer, Code, Outcome};
use crate::driver::tests::{create_body, world, World};
use crate::routes::{Operation, Route};
use crate::store::State;
use crate::testkit::{at, call, config, govern_test_key, header, token, NOW, RUN};
use crate::token::{Verified, Verifier};

const KID: &str = "govern-gate-token-v1";
const DESK: &str = "code-desk";

fn uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// Recovery over the world's state folder with `clock`; a new one over the
/// same folder (with a new verifier) is a COLD restart: no memory kept.
pub(crate) fn recovery(w: &World, clock: Clock) -> Recovery {
    let state = w.dir.path().join("state");
    let store = Arc::new(crate::store::Store::open(&state, uid()).unwrap());
    let k = govern_test_key();
    let v = Arc::new(crate::testkit::verifier(&[(KID, &k)], NOW));
    Recovery::new(
        store,
        v,
        gateway_identity(&config(&[]).backend_gateway),
        &state,
        uid(),
        clock,
    )
    .unwrap()
}

/// A box: a world, its recovery, the verifier calls arrive through, and a
/// clock the test moves.
struct Rig {
    w: World,
    r: Recovery,
    v: Verifier,
    clock: Arc<Mutex<DateTime<Utc>>>,
}

fn clock_of(c: &Arc<Mutex<DateTime<Utc>>>) -> Clock {
    let c = c.clone();
    Arc::new(move || *c.lock().unwrap())
}

async fn rig() -> Rig {
    let w = world().await;
    // The desk, made directly (no record), as an earlier operation made it.
    let made = Verified::for_tests_as(
        Some(crate::driver::tests::grant()),
        "00000000-0000-5000-8000-0000000000ff",
    )
    .admit()
    .unwrap();
    assert_eq!(
        w.b.create(&made, &create_body(json!({})), &crate::driver::Noted)
            .await
            .outcome,
        Outcome::Ready
    );
    let clock = Arc::new(Mutex::new(at(NOW)));
    let r = recovery(&w, clock_of(&clock));
    let mut w = w;
    // The driver writes a change's answer to these before it releases.
    w.b.records = crate::driver::Records::Store(r.records());
    let v = crate::testkit::verifier(&[(KID, &govern_test_key())], NOW);
    Rig { w, r, v, clock }
}

impl Rig {
    /// Another desk, made as `rig` makes its own: directly, by an earlier
    /// operation with no record here, so nothing is written before its claim
    /// is released.
    async fn make_desk(&mut self, name: &str) {
        let records = std::mem::replace(&mut self.w.b.records, crate::driver::Records::Unrecorded);
        let made = Verified::for_tests_as(
            Some(crate::driver::tests::grant()),
            "00000000-0000-5000-8000-0000000000fe",
        )
        .admit()
        .unwrap();
        let a = self
            .w
            .b
            .create(
                &made,
                &create_body(json!({ "name": name })),
                &crate::driver::Noted,
            )
            .await;
        assert_eq!(a.outcome, Outcome::Ready, "{a:?}");
        self.w.b.records = records;
    }

    /// A cold restart: new records, recovery and verifier over the same
    /// folder; the fakes (the gateway, the Enclave) live on.
    fn restart(&mut self) {
        self.r = recovery(&self.w, clock_of(&self.clock));
        self.w.b.records = crate::driver::Records::Store(self.r.records());
        self.v = crate::testkit::verifier(&[(KID, &govern_test_key())], NOW);
    }

    fn advance(&self, d: Duration) {
        *self.clock.lock().unwrap() += d;
    }

    /// Call `op` on `desk` as operation `n` (its own task, so its own
    /// request id), with a token Govern signed for it.
    async fn call(&self, op: Operation, desk: &str, n: u64, body: &[u8], t: &Value) -> Answer {
        let h = header(t, KID, &govern_test_key());
        let id = op_id(n);
        let verified = self.v.verify(&call(op, &h, &id, body)).unwrap();
        let route = Route {
            operation: op,
            desk: (op != Operation::Create).then(|| desk.to_string()),
            provider: None,
        };
        crate::ops::answer(
            &self.w.b,
            &self.r,
            &route,
            verified,
            &Bytes::copy_from_slice(body),
        )
        .await
    }

    async fn stop(&self, desk: &str, n: u64) -> Answer {
        self.call(Operation::Stop, desk, n, b"", &signed(n, "write", None))
            .await
    }

    async fn status(&self, desk: &str, n: u64) -> Answer {
        self.call(Operation::Status, desk, n, b"", &signed(n, "read", None))
            .await
    }

    fn state(&self, rid: &str) -> State {
        self.r.store().get(rid).unwrap().unwrap().state
    }

    fn answer_of(&self, rid: &str) -> Answer {
        self.r.store().get(rid).unwrap().unwrap().answer.unwrap()
    }

    /// Every request id the gateway was sent for `rpc`, in order.
    fn sent(&self, rpc: &str) -> Vec<String> {
        self.w
            .gw
            .lock()
            .unwrap()
            .request_ids
            .iter()
            .filter(|(r, _)| r == rpc)
            .map(|(_, id)| id.clone())
            .collect()
    }

    /// The request ids sent for `rpc` that are `id` (the rig's own setup
    /// create is not counted).
    fn sent_for(&self, rpc: &str, id: &str) -> Vec<String> {
        self.sent(rpc).into_iter().filter(|x| x == id).collect()
    }

    fn held(&self, desk: &str) -> bool {
        self.w.enc.lock().unwrap().held.contains_key(desk)
    }

    fn desk_id(&self, desk: &str) -> String {
        self.w.gw.lock().unwrap().sandboxes[desk]
            .metadata
            .as_ref()
            .unwrap()
            .id
            .clone()
    }

    fn settle_dir(&self) -> std::path::PathBuf {
        self.w.dir.path().join("state/settle")
    }

    /// A settle marker for `rid` on `desk`, good unless `change` spoils it:
    /// the gateway restarted after the change was admitted (NOW), quiet for
    /// 90 s, ended before the clock moved a day on.
    fn marker(&self, rid: &str, desk: &str, change: impl FnOnce(&mut Value)) -> std::path::PathBuf {
        let mut m = json!({
            "operation_id": rid,
            "desk": desk,
            // The desk's id, when the gateway has the desk.
            "backend_id": self.w.gw.lock().unwrap().sandboxes.get(desk)
                .and_then(|sb| sb.metadata.as_ref()).map(|m| m.id.clone()),
            "gateway_identity": gateway_identity(&config(&[]).backend_gateway),
            "gateway_restarted_at": "2026-10-15T01:00:00Z",
            "quiet_until": "2026-10-15T01:01:30Z",
            "containers": [{ "id": "a".repeat(64), "state": "exited" }]
        });
        change(&mut m);
        let path = self.settle_dir().join(format!("{rid}.json"));
        std::fs::write(&path, serde_json::to_vec(&m).unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    }
}

fn task(n: u64) -> String {
    format!("5c1e9a2b-7d3f-4e8a-9b0c-{n:012}")
}

fn op_id(n: u64) -> String {
    format!("{RUN}/call_desk/{}", task(n))
}

/// The request id of operation `n`.
fn rid(n: u64) -> String {
    let c = config(&[]);
    crate::token::request_id(
        &c.organization_id,
        &c.api_gate_instance,
        (&c.backend_gateway.url, &c.backend_gateway.workspace),
        (RUN, "call_desk", &task(n)),
    )
}

/// Operation `n`'s token: its own token id, `op` (write or read), pinned to
/// `body` (none: the empty body).
fn signed(n: u64, op: &str, body: Option<(&[u8], Value)>) -> Value {
    let mut t = token();
    t["token_id"] = json!(format!("b88d004b-b342-4447-917d-{n:012}"));
    t["scope"]["op"] = json!(op);
    if let Some((b, grant)) = body {
        t["constraints"]["body_sha256"] =
            json!(format!("{:x}", <sha2::Sha256 as sha2::Digest>::digest(b)));
        t["constraints"]["grant"] = grant;
    }
    t
}

/// A stop whose gateway finalizer is lost: the desk stopped, but the
/// gateway holds no confirmed result (a re-issue answers UNCERTAIN).
async fn uncertain_stop(r: &Rig, desk: &str, n: u64) {
    r.w.gw
        .lock()
        .unwrap()
        .lose_finalizer
        .insert("StopSandbox".into());
    let a = r.stop(desk, n).await;
    assert_eq!(
        (a.outcome, a.operation_id.clone()),
        (Outcome::Running, Some(rid(n)))
    );
    r.w.gw.lock().unwrap().lose_finalizer.clear();
}

/// A COLD restart: the stored request, token and request id are enough
/// for the next `status`, which re-issues the change and settles it from the
/// gateway's replay. A status for ANOTHER desk does not touch it.
#[tokio::test]
async fn a_cold_restart_recovers_a_lost_reply_at_the_next_status_for_its_desk() {
    let mut r = rig().await;
    r.make_desk("desk-b").await;
    r.w.gw
        .lock()
        .unwrap()
        .lose_reply
        .insert("StopSandbox".into());
    assert_eq!(r.stop(DESK, 1).await.outcome, Outcome::Running);
    r.w.gw.lock().unwrap().lose_reply.clear();
    r.restart();
    r.status("desk-b", 2).await;
    assert_eq!(r.state(&rid(1)), State::Running, "another desk's status");
    assert_eq!(r.sent("StopSandbox"), [rid(1)]);
    let a = r.status(DESK, 3).await;
    assert_eq!(a.outcome, Outcome::Ready, "{a:?}");
    assert_eq!(
        r.sent("StopSandbox"),
        [rid(1), rid(1)],
        "one re-issue, same id"
    );
    assert_eq!(r.state(&rid(1)), State::Settled);
    assert_eq!(r.answer_of(&rid(1)).outcome, Outcome::Ready);
    assert!(!r.held(DESK), "released with the outcome");
}

/// An UNCERTAIN change holds its desk across restarts: status
/// answers `running` with its id, a job is refused DESK_BUSY with nothing
/// sent; the late success, once the gateway has it, settles it inside the
/// bound and the next job runs.
#[tokio::test]
async fn an_uncertain_change_holds_its_desk_until_its_late_success() {
    let mut r = rig().await;
    uncertain_stop(&r, DESK, 1).await;
    for n in [2, 3] {
        r.restart();
        let s = r.status(DESK, n).await;
        assert_eq!(
            (s.outcome, s.operation_id.clone()),
            (Outcome::Running, Some(rid(1)))
        );
    }
    let job = r.stop(DESK, 4).await;
    assert_eq!(job.code, Some(Code::DeskBusy));
    assert!(
        !r.sent("StopSandbox").contains(&rid(4)),
        "nothing sent for it"
    );
    // Refused by the adapter itself, before the Enclave was even asked.
    let asked = r.w.enc.lock().unwrap().calls();
    assert!(
        !asked.iter().any(|(_, p)| p.to_string().contains(&rid(4))),
        "{asked:?}"
    );
    assert_eq!(r.answer_of(&rid(4)).code, Some(Code::DeskBusy), "recorded");
    assert!(r.held(DESK));
    // The late stop: the gateway confirms the success it kept.
    {
        let mut g = r.w.gw.lock().unwrap();
        let sb = g.sandboxes[DESK].clone();
        let reply = openshell_proto::openshell::v1::SandboxResponse {
            sandbox: Some(sb),
            ..Default::default()
        };
        g.applied.get_mut(&rid(1)).unwrap().success = Some(prost::Message::encode_to_vec(&reply));
    }
    assert_eq!(r.status(DESK, 5).await.outcome, Outcome::Ready);
    assert_eq!(r.answer_of(&rid(1)).outcome, Outcome::Ready);
    assert!(!r.held(DESK));
    let next = r
        .call(Operation::Start, DESK, 6, b"", &signed(6, "write", None))
        .await;
    assert_eq!(next.outcome, Outcome::Ready, "the next job runs: {next:?}");
}

/// After the bound nothing is sent: the change stays running and
/// claimed; then a good marker settles it `ready` by read-back alone, once.
/// A second status with the same marker file changes nothing.
#[tokio::test]
async fn after_the_bound_nothing_is_sent_and_a_marker_settles_it_once() {
    let r = rig().await;
    uncertain_stop(&r, DESK, 1).await;
    r.advance(Duration::hours(24));
    let s = r.status(DESK, 2).await;
    assert_eq!(s.outcome, Outcome::Running);
    assert_eq!(r.sent("StopSandbox"), [rid(1)], "zero gateway mutations");
    assert!(r.held(DESK));
    let path = r.marker(&rid(1), DESK, |_| {});
    let s = r.status(DESK, 3).await;
    assert_eq!(s.outcome, Outcome::Ready, "{s:?}");
    assert_eq!(r.sent("StopSandbox"), [rid(1)], "a marker sends nothing");
    assert_eq!(r.answer_of(&rid(1)).outcome, Outcome::Ready);
    assert!(!r.held(DESK));
    assert!(!path.exists() && path.with_extension("json.used").exists());
    // The same marker again: the change is settled, nothing moves.
    std::fs::copy(path.with_extension("json.used"), &path).unwrap();
    let before = r.answer_of(&rid(1));
    r.status(DESK, 4).await;
    assert_eq!(r.answer_of(&rid(1)), before);
    assert!(path.exists(), "not read again");
}

/// The bound is 20 h: at 19 h the change is re-issued, at 20 h it is not.
#[tokio::test]
async fn a_change_is_reissued_inside_twenty_hours_and_never_after() {
    let r = rig().await;
    uncertain_stop(&r, DESK, 1).await;
    r.advance(Duration::hours(19));
    r.status(DESK, 2).await;
    assert_eq!(r.sent("StopSandbox").len(), 2, "re-issued at 19 h");
    r.advance(Duration::hours(1));
    r.status(DESK, 3).await;
    assert_eq!(r.sent("StopSandbox").len(), 2, "not at 20 h");
}

/// With planted cases: each spoiled marker is refused and
/// logged, the change stays running and claimed, the marker stays in place.
#[tokio::test]
async fn a_marker_that_is_not_for_this_change_on_this_machine_is_refused() {
    let r = rig().await;
    uncertain_stop(&r, DESK, 1).await;
    r.advance(Duration::hours(24));
    let id = r.desk_id(DESK);
    type Spoil = Box<dyn Fn(&mut Value)>;
    let cases: Vec<(&str, Spoil)> = vec![
        (
            "another operation",
            Box::new(|m| m["operation_id"] = json!(rid(9))),
        ),
        ("another desk", Box::new(|m| m["desk"] = json!("desk-b"))),
        (
            "another backend id",
            Box::new(|m| m["backend_id"] = json!("6a1f2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d")),
        ),
        (
            "another desk backend",
            Box::new(|m| m["gateway_identity"] = json!("https://gateway.example:8443")),
        ),
        // a restart before admission fences nothing.
        (
            "restart before admission",
            Box::new(|m| m["gateway_restarted_at"] = json!("2026-10-15T00:05:00Z")),
        ),
        (
            "restart at admission",
            Box::new(|m| m["gateway_restarted_at"] = json!(NOW)),
        ),
        (
            "quiet ends at the restart",
            Box::new(|m| m["quiet_until"] = json!("2026-10-15T01:00:00Z")),
        ),
        (
            "quiet not ended",
            Box::new(|m| m["quiet_until"] = json!("2026-10-17T01:00:00Z")),
        ),
        (
            "a time not in UTC",
            Box::new(|m| m["quiet_until"] = json!("2026-10-15T01:01:30+00:00")),
        ),
        (
            "a container removing",
            Box::new(|m| m["containers"][0]["state"] = json!("removing")),
        ),
        (
            "a container restarting",
            Box::new(|m| m["containers"][0]["state"] = json!("restarting")),
        ),
        // Created and never started: something may still start it.
        (
            "a container created",
            Box::new(|m| m["containers"][0]["state"] = json!("created")),
        ),
        (
            "a short container id",
            Box::new(|m| m["containers"][0]["id"] = json!("abc")),
        ),
        ("an unknown field", Box::new(|m| m["extra"] = json!(1))),
        (
            "backend_id left out",
            Box::new(|m| {
                m.as_object_mut().unwrap().remove("backend_id");
            }),
        ),
        // a null id on a non-create is refused.
        (
            "a null id on a stop",
            Box::new(|m| {
                m["backend_id"] = Value::Null;
                m["containers"] = json!([]);
            }),
        ),
    ];
    for (n, (why, spoil)) in (100..).zip(cases) {
        let path = r.marker(&rid(1), DESK, |m| spoil(m));
        let s = r.status(DESK, n).await;
        assert_eq!(s.outcome, Outcome::Running, "{why}");
        assert_eq!(r.state(&rid(1)), State::Running, "{why}");
        assert!(r.held(DESK), "{why}");
        assert!(path.exists(), "{why}: not consumed");
    }
    // A marker open to others, or a link to a good one, is refused too.
    let good = r.marker(&rid(1), DESK, |_| {});
    std::fs::set_permissions(&good, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        r.status(DESK, 3).await.outcome,
        Outcome::Running,
        "mode 0644"
    );
    let elsewhere = r.w.dir.path().join("good.json");
    std::fs::rename(&good, &elsewhere).unwrap();
    std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &good).unwrap();
    assert_eq!(r.status(DESK, 4).await.outcome, Outcome::Running, "a link");
    std::fs::remove_file(&good).unwrap();
    // And the good one, in place, settles it: the cases above were refused
    // for their spoil alone.
    r.marker(&rid(1), DESK, |m| m["backend_id"] = json!(id));
    assert_eq!(r.status(DESK, 5).await.outcome, Outcome::Ready);
}

/// TWO DESKS: a marker for A settles A only; B stays running and
/// claimed, and B's job is still refused.
#[tokio::test]
async fn a_marker_for_one_desk_settles_that_desk_only() {
    let mut r = rig().await;
    r.make_desk("desk-b").await;
    uncertain_stop(&r, DESK, 1).await;
    uncertain_stop(&r, "desk-b", 2).await;
    r.advance(Duration::hours(24));
    r.marker(&rid(1), DESK, |_| {});
    assert_eq!(r.status(DESK, 3).await.outcome, Outcome::Ready);
    let b = r.status("desk-b", 4).await;
    assert_eq!(
        (b.outcome, b.operation_id),
        (Outcome::Running, Some(rid(2)))
    );
    assert!(r.held("desk-b") && !r.held(DESK));
    assert_eq!(r.stop("desk-b", 5).await.code, Some(Code::DeskBusy));
}

/// a good marker, and the change is not on the desk
/// (the stop did not stop it): `unknown`, never `running`.
#[tokio::test]
async fn a_marker_and_a_change_not_on_the_desk_is_unknown() {
    let r = rig().await;
    uncertain_stop(&r, DESK, 1).await;
    {
        let mut g = r.w.gw.lock().unwrap();
        let sb = g.sandboxes.get_mut(DESK).unwrap();
        sb.status.as_mut().unwrap().phase =
            openshell_proto::openshell::v1::SandboxPhase::Ready as i32;
    }
    r.advance(Duration::hours(24));
    r.marker(&rid(1), DESK, |_| {});
    r.status(DESK, 2).await;
    assert_eq!(r.answer_of(&rid(1)).outcome, Outcome::Unknown);
    assert_eq!(r.sent("StopSandbox"), [rid(1)]);
}

/// a re-issue the gateway answers
/// REQUEST_ID_PAYLOAD_MISMATCH stays running, its claim kept: something
/// else ran under its id. Never `refused`.
#[tokio::test]
async fn a_payload_mismatch_on_reissue_stays_running_and_claimed() {
    let r = rig().await;
    uncertain_stop(&r, DESK, 1).await;
    r.w.gw
        .lock()
        .unwrap()
        .applied
        .get_mut(&rid(1))
        .unwrap()
        .payload = b"another request".to_vec();
    let s = r.status(DESK, 2).await;
    assert_eq!(s.outcome, Outcome::Running);
    assert_eq!(r.sent("StopSandbox").len(), 2, "it was re-issued");
    assert_eq!(r.state(&rid(1)), State::Running);
    assert!(r.held(DESK));
}

/// A RE-ISSUE that is refused never settles the change. The
/// original stop lost its reply; its re-issue is refused before OpenShell
/// looks the original up (who asks, then the target), so the refusal says
/// nothing about the original. NotFound too: an original delete that ran
/// would answer it. The change stays running and its desk held until a
/// success the read-back confirms.
#[tokio::test]
async fn a_reissue_refused_before_the_replay_lookup_keeps_the_change_running_and_held() {
    let r = rig().await;
    r.w.gw
        .lock()
        .unwrap()
        .lose_reply
        .insert("StopSandbox".into());
    assert_eq!(r.stop(DESK, 1).await.outcome, Outcome::Running);
    r.w.gw.lock().unwrap().lose_reply.clear();
    let refused_sends = || {
        r.w.gw
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|c| c.starts_with("StopSandbox (planted"))
            .count()
    };
    for (n, code) in [
        (2, tonic::Code::Unauthenticated),
        (3, tonic::Code::PermissionDenied),
        (4, tonic::Code::NotFound),
    ] {
        r.w.gw.lock().unwrap().faults.answer.insert(
            "StopSandbox".into(),
            ekka_backend_fakegw::faults::Planted::Refused { code, reason: None },
        );
        let before = refused_sends();
        let s = r.status(DESK, n).await;
        assert_eq!(
            refused_sends(),
            before + 1,
            "{code:?}: it was re-issued and refused"
        );
        assert_eq!(
            (s.outcome, s.operation_id.clone()),
            (Outcome::Running, Some(rid(1))),
            "{code:?}"
        );
        assert_eq!(r.state(&rid(1)), State::Running, "{code:?}: not settled");
        assert!(r.held(DESK), "{code:?}: the desk stays held");
    }
    // The gateway answers again: the replayed success settles it.
    r.w.gw.lock().unwrap().faults.answer.clear();
    assert_eq!(r.status(DESK, 5).await.outcome, Outcome::Ready);
    assert_eq!(r.answer_of(&rid(1)).outcome, Outcome::Ready);
    assert!(!r.held(DESK), "released with the confirmed outcome");
}

/// Kill points. BEFORE the call (the gateway never saw it): the re-issue
/// carries it out. AFTER the write (the reply lost): the re-issue replays.
/// (The third, during re-pin, is the Enclave's, tested there.)
#[tokio::test]
async fn a_change_killed_before_the_gateway_saw_it_is_carried_out_by_the_reissue() {
    let mut r = rig().await;
    r.w.gw.lock().unwrap().faults.answer.insert(
        "StopSandbox".into(),
        ekka_backend_fakegw::faults::Planted::Refused {
            code: tonic::Code::Unavailable,
            reason: None,
        },
    );
    assert_eq!(r.stop(DESK, 1).await.outcome, Outcome::Running);
    assert!(!r.w.gw.lock().unwrap().applied.contains_key(&rid(1)));
    r.w.gw.lock().unwrap().faults.answer.clear();
    r.restart();
    assert_eq!(r.status(DESK, 2).await.outcome, Outcome::Ready);
    assert_eq!(r.answer_of(&rid(1)).outcome, Outcome::Ready);
}

/// A create is re-issued BYTE FOR BYTE (the gateway refuses another payload
/// under its id): its lost reply is replayed and it settles `ready`.
#[tokio::test]
async fn a_create_is_reissued_byte_for_byte() {
    let mut r = rig().await;
    r.w.gw
        .lock()
        .unwrap()
        .lose_reply
        .insert("CreateSandbox".into());
    let body = serde_json::to_vec(&json!({ "name": "desk-c", "image":
        "ghcr.io/example/desk@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "policy": crate::driver::tests::policy(), "providers": ["github"] }))
    .unwrap();
    let t = signed(1, "write", Some((&body, crate::driver::tests::grant())));
    let a = r.call(Operation::Create, "", 1, &body, &t).await;
    assert_eq!(a.outcome, Outcome::Running, "{a:?}");
    assert_eq!(r.r.store().get(&rid(1)).unwrap().unwrap().desk, "desk-c");
    r.w.gw.lock().unwrap().lose_reply.clear();
    r.restart();
    let s = r.status("desk-c", 2).await;
    assert_eq!(s.outcome, Outcome::Ready, "{s:?}");
    assert_eq!(r.sent_for("CreateSandbox", &rid(1)), [rid(1), rid(1)]);
    assert_eq!(r.answer_of(&rid(1)).outcome, Outcome::Ready);
}

/// A delete notes the desk's backend id BEFORE it is sent, so after its
/// reply is lost the re-issue still releases it with the id that is gone.
#[tokio::test]
async fn a_delete_keeps_the_desks_id_for_its_recovery() {
    let mut r = rig().await;
    let id = r.desk_id(DESK);
    r.w.gw
        .lock()
        .unwrap()
        .lose_reply
        .insert("DeleteSandbox".into());
    let a = r
        .call(Operation::Delete, DESK, 1, b"", &signed(1, "write", None))
        .await;
    assert_eq!(a.outcome, Outcome::Running);
    assert_eq!(
        r.r.store().get(&rid(1)).unwrap().unwrap().backend_id,
        Some(id.clone())
    );
    r.w.gw.lock().unwrap().lose_reply.clear();
    r.restart();
    r.status(DESK, 2).await;
    assert_eq!(r.answer_of(&rid(1)).outcome, Outcome::Ready);
    let last = r.w.enc.lock().unwrap().calls().last().cloned().unwrap();
    assert_eq!(last.0, "runner_desk_release");
    assert_eq!(last.1["read_back"]["sandbox_id"], json!(id), "{last:?}");
}

/// A re-issue racing another call for the same operation runs once: the
/// second call answers it unresolved and sends nothing.
#[tokio::test]
async fn two_calls_recovering_one_change_reissue_it_once() {
    let r = rig().await;
    uncertain_stop(&r, DESK, 1).await;
    let (x, y) = tokio::join!(r.status(DESK, 2), r.status(DESK, 3));
    assert_eq!(r.sent("StopSandbox").len(), 2, "one re-issue: {x:?} {y:?}");
}

/// The absent create: a create whose desk never
/// existed, a marker with a null backend id and no containers, and the
/// GATEWAY's own read-back says no such desk: refused NOT_APPLIED, the
/// claim released. While the gateway has the desk, that marker is refused.
#[tokio::test]
async fn a_create_that_never_reached_the_desk_is_not_applied() {
    let r = rig().await;
    r.w.gw
        .lock()
        .unwrap()
        .lose_finalizer
        .insert("CreateSandbox".into());
    let body = serde_json::to_vec(&json!({ "name": "desk-c", "image":
        "ghcr.io/example/desk@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "policy": crate::driver::tests::policy(), "providers": ["github"] }))
    .unwrap();
    let t = signed(1, "write", Some((&body, crate::driver::tests::grant())));
    assert_eq!(
        r.call(Operation::Create, "", 1, &body, &t).await.outcome,
        Outcome::Running
    );
    r.advance(Duration::hours(24));
    let null = |m: &mut Value| {
        m["backend_id"] = Value::Null;
        m["containers"] = json!([]);
    };
    // The gateway still has the desk: refused, held.
    let path = r.marker(&rid(1), "desk-c", null);
    assert_eq!(r.status("desk-c", 2).await.outcome, Outcome::Running);
    assert!(r.held("desk-c") && path.exists());
    // A null id with containers: refused.
    r.w.gw.lock().unwrap().sandboxes.remove("desk-c");
    r.marker(&rid(1), "desk-c", |m| m["backend_id"] = Value::Null);
    assert_eq!(r.status("desk-c", 3).await.outcome, Outcome::Running);
    // A restart before admission: refused.
    r.marker(&rid(1), "desk-c", |m| {
        null(m);
        m["gateway_restarted_at"] = json!("2026-10-15T00:05:00Z");
    });
    assert_eq!(r.status("desk-c", 4).await.outcome, Outcome::Running);
    assert!(r.held("desk-c"));
    // The desk is not on the gateway, and the marker is good: not applied.
    let path = r.marker(&rid(1), "desk-c", null);
    r.status("desk-c", 5).await;
    let a = r.answer_of(&rid(1));
    assert_eq!(
        (a.outcome, a.code),
        (Outcome::Refused, Some(Code::NotApplied))
    );
    assert!(!r.held("desk-c"), "released");
    assert!(path.with_extension("json.used").exists());
    assert_eq!(
        r.sent_for("CreateSandbox", &rid(1)),
        [rid(1)],
        "nothing sent after it"
    );
}

/// A null backend id is a CREATE's only. A stop whose desk the
/// gateway no longer has, with a null-id marker, is refused and stays held
/// (it never answers NOT_APPLIED: the stop may have run).
#[tokio::test]
async fn a_null_id_marker_settles_nothing_but_a_create() {
    let r = rig().await;
    uncertain_stop(&r, DESK, 1).await;
    r.advance(Duration::hours(24));
    r.w.gw.lock().unwrap().sandboxes.remove(DESK);
    let path = r.marker(&rid(1), DESK, |m| {
        m["backend_id"] = Value::Null;
        m["containers"] = json!([]);
    });
    let s = r.status(DESK, 2).await;
    assert_eq!(
        (s.outcome, s.operation_id),
        (Outcome::Running, Some(rid(1)))
    );
    assert_eq!(r.state(&rid(1)), State::Running);
    assert!(r.held(DESK) && path.exists());
}

/// a re-issue sent AFTER the kit's restart may still be
/// inside the gateway, so a marker from that restart is refused; the record
/// notes each send before it goes. A marker from a restart after the last
/// send settles it.
#[tokio::test]
async fn a_marker_from_a_restart_before_the_last_send_is_refused() {
    let r = rig().await;
    uncertain_stop(&r, DESK, 1).await;
    // At 01:30 a status re-issues it (inside the bound): sent again.
    r.advance(Duration::minutes(80));
    assert_eq!(r.status(DESK, 2).await.outcome, Outcome::Running);
    assert_eq!(r.sent("StopSandbox").len(), 2);
    let noted = r.r.store().get(&rid(1)).unwrap().unwrap().last_sent_at;
    assert_eq!(
        noted.as_deref().map(at),
        Some(at(NOW) + Duration::minutes(80)),
        "noted before the send"
    );
    // The kit restarted at 01:00: after admission, BEFORE that re-issue.
    let path = r.marker(&rid(1), DESK, |_| {});
    let s = r.status(DESK, 3).await;
    assert_eq!(s.outcome, Outcome::Running);
    assert_eq!(r.state(&rid(1)), State::Running);
    assert!(r.held(DESK) && path.exists());
    // A restart after the last send (01:30): settled, nothing sent for it.
    r.advance(Duration::minutes(30));
    let sent = r.sent("StopSandbox").len();
    r.marker(&rid(1), DESK, |m| {
        m["gateway_restarted_at"] = json!("2026-10-15T01:40:00Z");
        m["quiet_until"] = json!("2026-10-15T01:41:30Z");
    });
    assert_eq!(r.status(DESK, 4).await.outcome, Outcome::Ready);
    assert_eq!(r.sent("StopSandbox").len(), sent, "a marker sends nothing");
    assert!(!r.held(DESK));
}

/// only NOT_FOUND says a desk is absent. An OK
/// GetSandbox with no sandbox in it never settles a create NOT_APPLIED, and
/// a status of it is not DESK_NOT_FOUND.
#[tokio::test]
async fn an_ok_answer_with_no_sandbox_is_never_absent() {
    let r = rig().await;
    r.w.gw.lock().unwrap().empty_get.insert(DESK.into());
    let s = r.status(DESK, 9).await;
    assert_eq!(s.code, Some(Code::BackendUnavailable), "{s:?}");
    r.w.gw.lock().unwrap().empty_get.clear();
    r.w.gw
        .lock()
        .unwrap()
        .lose_finalizer
        .insert("CreateSandbox".into());
    let body = serde_json::to_vec(&json!({ "name": "desk-c", "image":
        "ghcr.io/example/desk@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "policy": crate::driver::tests::policy(), "providers": ["github"] }))
    .unwrap();
    let t = signed(1, "write", Some((&body, crate::driver::tests::grant())));
    assert_eq!(
        r.call(Operation::Create, "", 1, &body, &t).await.outcome,
        Outcome::Running
    );
    r.advance(Duration::hours(24));
    {
        let mut g = r.w.gw.lock().unwrap();
        g.sandboxes.remove("desk-c");
        g.empty_get.insert("desk-c".into());
    }
    let null = |m: &mut Value| {
        m["backend_id"] = Value::Null;
        m["containers"] = json!([]);
    };
    let path = r.marker(&rid(1), "desk-c", null);
    assert_eq!(r.status("desk-c", 2).await.outcome, Outcome::Running);
    assert_eq!(r.state(&rid(1)), State::Running);
    assert!(r.held("desk-c") && path.exists());
    // The gateway answers NOT_FOUND now: not applied.
    r.w.gw.lock().unwrap().empty_get.clear();
    r.status("desk-c", 3).await;
    assert_eq!(r.answer_of(&rid(1)).code, Some(Code::NotApplied));
}

/// a marker sends nothing, so it needs no stored
/// token: after the Govern key rotated, a good marker still settles the
/// change. A re-issue, which sends, still needs it: none is sent.
#[tokio::test]
async fn a_marker_settles_after_the_govern_key_rotated_and_a_reissue_does_not() {
    let mut r = rig().await;
    uncertain_stop(&r, DESK, 1).await;
    // The adapter restarts with only a NEW Govern key: the stored token no
    // longer verifies. (Calls still arrive signed with the key they carry.)
    let state = r.w.dir.path().join("state");
    let rotated = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
    r.r = Recovery::new(
        Arc::new(crate::store::Store::open(&state, uid()).unwrap()),
        Arc::new(crate::testkit::verifier(
            &[("govern-gate-token-v2", &rotated)],
            NOW,
        )),
        gateway_identity(&config(&[]).backend_gateway),
        &state,
        uid(),
        clock_of(&r.clock),
    )
    .unwrap();
    r.advance(Duration::hours(1));
    assert_eq!(r.status(DESK, 2).await.outcome, Outcome::Running);
    assert_eq!(
        r.sent("StopSandbox"),
        [rid(1)],
        "no re-issue without its token"
    );
    r.marker(&rid(1), DESK, |_| {});
    let s = r.status(DESK, 3).await;
    assert_eq!(s.outcome, Outcome::Ready, "{s:?}");
    assert_eq!(r.answer_of(&rid(1)).outcome, Outcome::Ready);
    assert!(!r.held(DESK));
}

/// A create settled by its marker after the Govern key rotated still ends
/// `ready` when the desk matches: its approved pins were written to its
/// record at admission, while its token was verified, and the read-back
/// reads them there. Nothing re-verifies the token.
#[tokio::test]
async fn a_create_settled_by_its_marker_after_the_key_rotated_reads_its_pins_from_its_record() {
    let mut r = rig().await;
    r.w.gw
        .lock()
        .unwrap()
        .lose_finalizer
        .insert("CreateSandbox".into());
    let body = serde_json::to_vec(&json!({ "name": "desk-c", "image":
        "ghcr.io/example/desk@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "policy": crate::driver::tests::policy(), "providers": ["github"] }))
    .unwrap();
    let t = signed(1, "write", Some((&body, crate::driver::tests::grant())));
    assert_eq!(
        r.call(Operation::Create, "", 1, &body, &t).await.outcome,
        Outcome::Running
    );
    r.w.gw.lock().unwrap().lose_finalizer.clear();
    let approved = r.r.store().get(&rid(1)).unwrap().unwrap().approved.unwrap();
    assert_eq!(
        approved.provider_config_digests.keys().collect::<Vec<_>>(),
        ["github"],
        "written at admission"
    );
    // The adapter restarts with only a NEW Govern key.
    let state = r.w.dir.path().join("state");
    let rotated = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
    r.r = Recovery::new(
        Arc::new(crate::store::Store::open(&state, uid()).unwrap()),
        Arc::new(crate::testkit::verifier(
            &[("govern-gate-token-v2", &rotated)],
            NOW,
        )),
        gateway_identity(&config(&[]).backend_gateway),
        &state,
        uid(),
        clock_of(&r.clock),
    )
    .unwrap();
    r.w.b.records = crate::driver::Records::Store(r.r.records());
    r.advance(Duration::hours(1));
    assert_eq!(r.status("desk-c", 2).await.outcome, Outcome::Running);
    r.marker(&rid(1), "desk-c", |_| {});
    let s = r.status("desk-c", 3).await;
    assert_eq!(s.outcome, Outcome::Ready, "{s:?}");
    assert_eq!(r.answer_of(&rid(1)).outcome, Outcome::Ready);
    assert!(!r.held("desk-c"));
}

impl Rig {
    /// A settle hold for `rid`, good unless `change` spoils it.
    fn hold(&self, rid: &str, change: impl FnOnce(&mut Value)) -> std::path::PathBuf {
        let mut h = json!({ "operation_id": rid, "held_at": "2026-10-15T00:59:58Z" });
        change(&mut h);
        let path = self.settle_dir().join(format!("{rid}.hold"));
        std::fs::write(&path, serde_json::to_vec(&h).unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    }
}

/// The settle hold: while a valid hold stands, the change is never
/// re-issued inside the bound; once it is removed, it is again.
#[tokio::test]
async fn a_settle_hold_stops_every_reissue_while_it_stands() {
    let r = rig().await;
    uncertain_stop(&r, DESK, 1).await;
    let hold = r.hold(&rid(1), |_| {});
    r.advance(Duration::hours(1));
    for n in [2, 3] {
        let s = r.status(DESK, n).await;
        assert_eq!(
            (s.outcome, s.operation_id),
            (Outcome::Running, Some(rid(1)))
        );
    }
    assert_eq!(r.sent("StopSandbox"), [rid(1)], "never sent while held");
    assert!(r.held(DESK));
    std::fs::remove_file(&hold).unwrap();
    r.status(DESK, 4).await;
    assert_eq!(r.sent("StopSandbox").len(), 2, "sent again once unheld");
}

/// The settle, in the kit's order: hold, gateway restart, a status during
/// the quiet window (which sends nothing), then the marker. The marker
/// counts, and both files are consumed (the kit may stop before removing
/// the hold).
#[tokio::test]
async fn a_hold_then_a_status_then_a_marker_settles_the_change() {
    let r = rig().await;
    uncertain_stop(&r, DESK, 1).await;
    let hold = r.hold(&rid(1), |_| {});
    // 01:01, inside the quiet window after the 01:00 restart.
    r.advance(Duration::minutes(51));
    assert_eq!(r.status(DESK, 2).await.outcome, Outcome::Running);
    assert_eq!(r.sent("StopSandbox"), [rid(1)]);
    let marker = r.marker(&rid(1), DESK, |_| {});
    r.advance(Duration::minutes(1));
    assert_eq!(r.status(DESK, 3).await.outcome, Outcome::Ready);
    assert_eq!(r.answer_of(&rid(1)).outcome, Outcome::Ready);
    assert!(!r.held(DESK));
    assert!(!marker.exists() && marker.with_extension("json.used").exists());
    assert!(!hold.exists() && hold.with_extension("hold.used").exists());
}

/// NO SEND CROSSES A SETTLE. A re-issue is in flight (its reply held, then
/// lost) while the kit holds the change, restarts the gateway and writes its
/// marker. The send ENDED after that restart, so the marker is refused and
/// the desk stays held; a later restart, after the send ended, settles it.
#[tokio::test]
async fn a_reissue_in_flight_across_a_hold_and_a_restart_never_lets_that_marker_count() {
    let r = rig().await;
    r.w.gw
        .lock()
        .unwrap()
        .lose_reply
        .insert("StopSandbox".into());
    assert_eq!(r.stop(DESK, 1).await.outcome, Outcome::Running);
    {
        let mut gw = r.w.gw.lock().unwrap();
        gw.lose_reply.clear();
        gw.faults
            .delay
            .insert("StopSandbox".into(), std::time::Duration::from_millis(400));
        gw.faults.drop_reply.insert("StopSandbox".into());
    }
    let (during, ()) = tokio::join!(r.status(DESK, 2), async {
        // The re-issue has started; it ends only after all of this.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        r.hold(&rid(1), |_| {});
        // 01:00:30: the gateway restarted at 01:00, the marker is written.
        r.advance(Duration::seconds(50 * 60 + 30));
        r.marker(&rid(1), DESK, |_| {});
    });
    assert_eq!(during.outcome, Outcome::Running, "{during:?}");
    {
        let mut gw = r.w.gw.lock().unwrap();
        gw.faults.delay.clear();
        gw.faults.drop_reply.clear();
    }
    let rec = r.r.store().get(&rid(1)).unwrap().unwrap();
    assert!(
        rec.last_send_ended_at.as_deref() > Some("2026-10-15T01:00:00Z"),
        "the re-issue ended after the restart: {rec:?}"
    );
    // 01:02, the quiet window over: the marker is refused, nothing is sent
    // while the hold stands, and the desk stays held.
    r.advance(Duration::seconds(90));
    let sends = r.sent("StopSandbox").len();
    assert_eq!(r.status(DESK, 3).await.outcome, Outcome::Running);
    assert_eq!(r.sent("StopSandbox").len(), sends, "held: not re-issued");
    assert_eq!(r.state(&rid(1)), State::Running);
    assert!(r.held(DESK), "the marker did not count");
    // A restart after the send ended counts.
    let marker = r.marker(&rid(1), DESK, |m| {
        m["gateway_restarted_at"] = json!("2026-10-15T01:03:00Z");
        m["quiet_until"] = json!("2026-10-15T01:04:30Z");
    });
    r.advance(Duration::minutes(3));
    assert_eq!(r.status(DESK, 4).await.outcome, Outcome::Ready);
    assert!(!r.held(DESK));
    assert!(marker.with_extension("json.used").exists());
}

/// A send whose end was never noted (its end note failed, or its process
/// died during it): while THIS adapter runs it is in flight, and no marker
/// counts. After the adapter restarts, it counts only for a gateway
/// restarted after the new adapter started.
#[tokio::test]
async fn a_send_with_no_end_holds_every_marker_until_the_adapter_and_then_the_gateway_restart() {
    let mut r = rig().await;
    uncertain_stop(&r, DESK, 1).await;
    // Started in this process, never ended.
    let started = *r.clock.lock().unwrap();
    r.r.store().note_sent(&rid(1), started, r.r.boot()).unwrap();
    r.hold(&rid(1), |_| {});
    r.marker(&rid(1), DESK, |_| {});
    r.advance(Duration::minutes(52));
    assert_eq!(r.status(DESK, 2).await.outcome, Outcome::Running);
    assert!(r.held(DESK), "in flight in this adapter: refused");
    // A new adapter at 01:02. The 01:00 restart came before it started, when
    // the old process may still have been sending: refused.
    r.restart();
    assert_eq!(r.status(DESK, 3).await.outcome, Outcome::Running);
    assert!(
        r.held(DESK),
        "the gateway restarted before this adapter started"
    );
    // The gateway restarts after the new adapter started: it counts.
    r.marker(&rid(1), DESK, |m| {
        m["gateway_restarted_at"] = json!("2026-10-15T01:03:00Z");
        m["quiet_until"] = json!("2026-10-15T01:04:30Z");
    });
    r.advance(Duration::minutes(3));
    assert_eq!(r.status(DESK, 4).await.outcome, Outcome::Ready);
    assert!(!r.held(DESK));
}

/// Every send is bracketed in its record: its start, the process that sent
/// it, and its end.
#[tokio::test]
async fn a_first_send_notes_its_start_its_process_and_its_end() {
    let r = rig().await;
    assert_eq!(r.stop(DESK, 1).await.outcome, Outcome::Ready);
    let rec = r.r.store().get(&rid(1)).unwrap().unwrap();
    assert_eq!(rec.last_send_boot.as_deref(), Some(r.r.boot()));
    assert!(rec.last_sent_at.is_some());
    assert!(rec.last_send_ended_at >= rec.last_sent_at, "{rec:?}");
    assert_eq!(r.r.boot().len(), 32);
    let other = rig().await;
    assert_ne!(other.r.boot(), r.r.boot(), "a boot id is never reused");
}

/// A SETTLED CHANGE NEVER LOCKS ITS DESK FOREVER. Its release is owed in
/// the same write as its answer; one that fails is retried at the next call,
/// for any desk, and the change is never sent again.
#[tokio::test]
async fn a_release_that_fails_is_owed_and_retried_at_the_next_call_never_resent() {
    let r = rig().await;
    r.w.enc
        .lock()
        .unwrap()
        .release_refusals
        .push("the desk lock cannot be removed: planted".into());
    assert_eq!(
        r.stop(DESK, 1).await.outcome,
        Outcome::Ready,
        "the answer stands"
    );
    assert!(r.held(DESK), "the release failed: still held");
    let rec = r.r.store().get(&rid(1)).unwrap().unwrap();
    assert_eq!(rec.state, State::Settled);
    assert_eq!(
        rec.release_pending.as_ref().map(|p| p.outcome.as_str()),
        Some("ready")
    );
    r.status("desk-elsewhere", 2).await;
    assert!(!r.held(DESK), "released at the next call");
    let rec = r.r.store().get(&rid(1)).unwrap().unwrap();
    assert_eq!(rec.release_pending, None);
    assert_eq!(r.sent("StopSandbox"), [rid(1)], "never sent again");
}

/// An adapter that stops between the settle and the release releases at
/// startup, before any call.
#[tokio::test]
async fn a_release_still_owed_at_startup_is_sent_before_any_call() {
    let mut r = rig().await;
    r.w.enc
        .lock()
        .unwrap()
        .release_refusals
        .push("the desk lock cannot be removed: planted".into());
    assert_eq!(r.stop(DESK, 1).await.outcome, Outcome::Ready);
    assert!(r.held(DESK));
    r.restart();
    r.w.b.release_pending().await;
    assert!(!r.held(DESK), "released at startup");
    assert_eq!(
        r.r.store().get(&rid(1)).unwrap().unwrap().release_pending,
        None
    );
}

/// A retry after a release that went through (its answer lost): the
/// Enclave answers DESK_NOT_HELD, which is released, not retried forever.
#[tokio::test]
async fn a_retried_release_the_enclave_already_took_counts_as_released() {
    let r = rig().await;
    r.w.enc
        .lock()
        .unwrap()
        .release_refusals
        .push("the desk lock cannot be removed: planted".into());
    assert_eq!(r.stop(DESK, 1).await.outcome, Outcome::Ready);
    // The first release went through after all.
    r.w.enc.lock().unwrap().held.remove(DESK);
    r.status(DESK, 2).await;
    assert_eq!(
        r.r.store().get(&rid(1)).unwrap().unwrap().release_pending,
        None
    );
    let releases =
        r.w.enc
            .lock()
            .unwrap()
            .calls()
            .into_iter()
            .filter(|(m, _)| m == "runner_desk_release")
            .count();
    r.status(DESK, 3).await;
    let after =
        r.w.enc
            .lock()
            .unwrap()
            .calls()
            .into_iter()
            .filter(|(m, _)| m == "runner_desk_release")
            .count();
    assert_eq!(after, releases, "nothing owed: not tried again");
}

/// A refusal a retry would only repeat (the read-back does not match the
/// desk's pins) is released UNKNOWN: the desk stays held, for a person.
#[tokio::test]
async fn a_release_refused_for_its_read_back_is_released_unknown_for_a_person() {
    let r = rig().await;
    r.w.enc
        .lock()
        .unwrap()
        .release_refusals
        .push("READ_BACK_MISMATCH: planted".into());
    assert_eq!(r.stop(DESK, 1).await.outcome, Outcome::Ready);
    let releases: Vec<Value> =
        r.w.enc
            .lock()
            .unwrap()
            .calls()
            .into_iter()
            .filter(|(m, _)| m == "runner_desk_release")
            .map(|(_, p)| p)
            .collect();
    let last = releases.last().unwrap();
    assert_eq!(last["outcome"], "unknown", "{releases:?}");
    assert!(last.get("read_back").is_none());
    assert!(r.held(DESK), "held as unknown, for a person");
    assert_eq!(
        r.r.store().get(&rid(1)).unwrap().unwrap().release_pending,
        None
    );
}

/// An unsafe or wrong hold counts as none (logged): the re-issue happens.
#[tokio::test]
async fn an_unsafe_or_wrong_hold_is_ignored() {
    let r = rig().await;
    uncertain_stop(&r, DESK, 1).await;
    r.advance(Duration::hours(1));
    type Spoil = Box<dyn Fn(&std::path::Path)>;
    let mode = |m: u32| -> Spoil {
        Box::new(move |p| std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap())
    };
    let rewrite =
        |v: Value| -> Spoil { Box::new(move |p| std::fs::write(p, v.to_string()).unwrap()) };
    let cases: Vec<(&str, Spoil)> = vec![
        ("open to others", mode(0o644)),
        (
            "another operation",
            rewrite(json!({ "operation_id": rid(9), "held_at": "2026-10-15T00:59:58Z" })),
        ),
        (
            "an unknown field",
            rewrite(json!({ "operation_id": rid(1), "held_at": "2026-10-15T00:59:58Z", "x": 1 })),
        ),
        (
            "a time not in UTC",
            rewrite(json!({ "operation_id": rid(1), "held_at": "2026-10-15T00:59:58+00:00" })),
        ),
        (
            "not JSON",
            Box::new(|p| std::fs::write(p, b"held").unwrap()),
        ),
    ];
    for (n, (why, spoil)) in (10..).zip(cases) {
        let path = r.hold(&rid(1), |_| {});
        spoil(&path);
        let before = r.sent("StopSandbox").len();
        r.status(DESK, n).await;
        assert_eq!(r.sent("StopSandbox").len(), before + 1, "{why}: re-issued");
        std::fs::remove_file(&path).unwrap();
    }
    // A link to a good hold elsewhere is not a hold.
    let elsewhere = r.w.dir.path().join("hold.json");
    std::fs::write(
        &elsewhere,
        json!({ "operation_id": rid(1), "held_at": "2026-10-15T00:59:58Z" }).to_string(),
    )
    .unwrap();
    std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::symlink(&elsewhere, r.settle_dir().join(format!("{}.hold", rid(1))))
        .unwrap();
    let before = r.sent("StopSandbox").len();
    r.status(DESK, 20).await;
    assert_eq!(r.sent("StopSandbox").len(), before + 1, "a link: re-issued");
}

/// A change recorded and then stopped before it was sent (the adapter died
/// between its record and its send, or between a check and the send): the
/// record names no send. Recovery NEVER re-issues it: nothing reached the
/// desk, so it settles NOT_APPLIED and its claim is released. Its checks
/// (here: a detach of a provider the agent REQUIRES) never get skipped.
#[tokio::test]
async fn a_change_never_sent_is_not_applied_and_never_reissued() {
    let r = rig().await;
    r.w.enc
        .lock()
        .unwrap()
        .required
        .insert(DESK.into(), vec!["github".into()]);
    let cases = [
        (Operation::Stop, None, Vec::new(), "StopSandbox"),
        (
            Operation::ProviderDetach,
            Some("github".to_string()),
            br#"{"expected_resource_version":"1"}"#.to_vec(),
            "DetachSandboxProvider",
        ),
    ];
    for (n, (op, provider, body, rpc)) in (1..).zip(cases) {
        let route = Route {
            operation: op,
            desk: Some(DESK.into()),
            provider,
        };
        let rec = crate::store::running(&route, DESK, &rid(n), &op_id(n), &body, "token", at(NOW));
        assert_eq!(rec.last_sent_at, None);
        r.r.store().begin(&rec).unwrap();
        // It held its claim when the adapter died.
        r.w.enc.lock().unwrap().held.insert(DESK.into(), rid(n));
        let s = r.status(DESK, 100 + n).await;
        let a = r.answer_of(&rid(n));
        assert_eq!(
            (a.outcome, a.code),
            (Outcome::Refused, Some(Code::NotApplied)),
            "{op:?}: {s:?}"
        );
        assert!(r.sent_for(rpc, &rid(n)).is_empty(), "{op:?}: never sent");
        assert!(!r.held(DESK), "{op:?}: its claim released");
    }
}

/// a refused change (the creation baseline refuses
/// this policy) whose settle write fails twice answers `running`, never its
/// refusal with the record still running; recovery then settles it
/// NOT_APPLIED and never sends it.
#[tokio::test]
async fn a_refusal_whose_settle_fails_twice_is_running_and_never_sent() {
    let r = rig().await;
    let mut policy = crate::driver::tests::policy();
    policy["filesystem"]["readWrite"] = json!(["/sandbox", "/etc"]);
    let body =
        serde_json::to_vec(&json!({ "policy": policy, "expected_resource_version": "1" })).unwrap();
    let t = signed(1, "write", Some((&body, crate::driver::tests::grant())));
    r.r.store()
        .fail_settles
        .store(2, std::sync::atomic::Ordering::SeqCst);
    let a = r.call(Operation::PolicySet, DESK, 1, &body, &t).await;
    assert_eq!(
        (a.outcome, a.operation_id.clone()),
        (Outcome::Running, Some(rid(1))),
        "{a:?}"
    );
    assert_eq!(r.state(&rid(1)), State::Running);
    // Settle, THEN release: unwritten, the claim is never released.
    assert!(r.held(DESK), "the desk stays held");
    r.status(DESK, 2).await;
    let rec = r.answer_of(&rid(1));
    assert_eq!(
        (rec.outcome, rec.code),
        (Outcome::Refused, Some(Code::NotApplied))
    );
    assert!(r.sent("UpdateConfig").is_empty(), "never sent");
}

/// A status while a change's FIRST attempt is still running here answers
/// `running` with its id, and never takes it (no second send, no early
/// NOT_APPLIED): the first attempt holds the operation's mark.
#[tokio::test]
async fn a_status_during_a_first_attempt_never_takes_it() {
    let r = rig().await;
    r.w.gw
        .lock()
        .unwrap()
        .faults
        .delay
        .insert("StopSandbox".into(), std::time::Duration::from_millis(600));
    let (stop, status) = tokio::join!(r.stop(DESK, 1), async {
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        r.status(DESK, 2).await
    });
    assert_eq!(
        (status.outcome, status.operation_id),
        (Outcome::Running, Some(rid(1)))
    );
    assert_eq!(stop.outcome, Outcome::Ready, "{stop:?}");
    assert_eq!(r.sent("StopSandbox"), [rid(1)], "sent once");
}

/// One failed settle write is retried: the refusal is recorded and answered
/// (here the creation baseline refuses the policy).
#[tokio::test]
async fn a_settle_that_fails_once_is_retried() {
    let r = rig().await;
    let mut policy = crate::driver::tests::policy();
    policy["filesystem"]["readWrite"] = json!(["/sandbox", "/etc"]);
    let body =
        serde_json::to_vec(&json!({ "policy": policy, "expected_resource_version": "1" })).unwrap();
    let t = signed(1, "write", Some((&body, crate::driver::tests::grant())));
    r.r.store()
        .fail_settles
        .store(1, std::sync::atomic::Ordering::SeqCst);
    let a = r.call(Operation::PolicySet, DESK, 1, &body, &t).await;
    assert_eq!(a.code, Some(Code::ConstraintPolicyBaseline), "{a:?}");
    assert_eq!(
        r.answer_of(&rid(1)).code,
        Some(Code::ConstraintPolicyBaseline)
    );
    assert!(r.sent("UpdateConfig").is_empty());
}

fn vendored(path: &str) -> Value {
    let full = format!(
        "{}/../../vendor/contracts/backend/{path}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(full).unwrap()).unwrap()
}

/// Contracts 0.67.0: every settle file the kit writes, as the contract's
/// samples show it, is what recovery reads, strictly: a watched desk's
/// marker, an absent create's marker (null backend id, no containers), and
/// the hold.
#[test]
fn the_contracts_settle_files_are_what_recovery_reads() {
    for sample in [
        "samples/settle-marker.json",
        "samples/settle-marker.create-absent.json",
    ] {
        let m: super::Marker = serde_json::from_value(vendored(sample)).unwrap();
        assert!(super::utc(&m.quiet_until).is_some(), "{sample}");
    }
    let absent: super::Marker =
        serde_json::from_value(vendored("samples/settle-marker.create-absent.json")).unwrap();
    assert_eq!((absent.backend_id, absent.containers.len()), (None, 0));
    let h: super::Hold = serde_json::from_value(vendored("samples/settle-hold.json")).unwrap();
    assert!(super::utc(&h.held_at).is_some());
    // The kit builds the gateway identity as the adapter does.
    let schema = vendored("settle-marker.v1.schema.json");
    let said = schema["properties"]["gateway_identity"]["description"]
        .as_str()
        .unwrap();
    assert!(
        said.contains("<backend_gateway.url>#<backend_gateway.workspace>"),
        "{said}"
    );
}

/// Every refusal code the adapter can answer is one the contract names
/// (0.67.0 adds NOT_APPLIED). The match below fails to compile when a code
/// is added without being listed here.
#[test]
fn every_answer_code_is_the_contracts() {
    use crate::answer::Code::{self, *};
    fn listed(c: Code) {
        match c {
            TokenMissing
            | TokenInvalid
            | TokenExpired
            | TokenReplayed
            | TokenScope
            | CredentialMissing
            | RequestInvalid
            | UnknownOperation
            | NotAvailable
            | ConstraintsInvalid
            | ConstraintImageDigests
            | ConstraintPolicyDigests
            | ConstraintAllowedHosts
            | ConstraintProviders
            | ConstraintProviderConfigDigests
            | ConstraintEnvironmentKeys
            | ConstraintPolicyBaseline
            | ConstraintCredentialEndpoint
            | FieldNotAllowed
            | OperationIdReused
            | DeskNotFound
            | DeskExists
            | DeskProviderRequired
            | DeskBusy
            | VersionConflict
            | BackendUnavailable
            | BackendRefused
            | NotApplied => {}
        }
    }
    let all = [
        TokenMissing,
        TokenInvalid,
        TokenExpired,
        TokenReplayed,
        TokenScope,
        CredentialMissing,
        RequestInvalid,
        UnknownOperation,
        NotAvailable,
        ConstraintsInvalid,
        ConstraintImageDigests,
        ConstraintPolicyDigests,
        ConstraintAllowedHosts,
        ConstraintProviders,
        ConstraintProviderConfigDigests,
        ConstraintEnvironmentKeys,
        ConstraintPolicyBaseline,
        ConstraintCredentialEndpoint,
        FieldNotAllowed,
        OperationIdReused,
        DeskNotFound,
        DeskExists,
        DeskProviderRequired,
        DeskBusy,
        VersionConflict,
        BackendUnavailable,
        BackendRefused,
        NotApplied,
    ];
    let schema = vendored("backend-v1.schema.json");
    let named: Vec<&str> = schema["$defs"]["code"]["enum"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for c in all {
        listed(c);
        let wire = serde_json::to_value(c).unwrap();
        let wire = wire.as_str().unwrap();
        assert!(named.contains(&wire), "{wire} is not a contract code");
    }
}

/// The plan's order: a change's claim is released only after its record is
/// settled. The fake Enclave reads the record at the moment the release
/// arrives: it already says `settled`, with the answer the call gives.
#[tokio::test]
async fn the_record_is_settled_before_the_claim_is_released() {
    let r = rig().await;
    let record =
        r.w.dir
            .path()
            .join("state/operations")
            .join(format!("{}.json", rid(1)));
    r.w.enc.lock().unwrap().watch = Some(record);
    assert_eq!(r.stop(DESK, 1).await.outcome, Outcome::Ready);
    let watched = r.w.enc.lock().unwrap().watched.clone();
    let (_, at_release) = watched
        .iter()
        .find(|(m, _)| m == "runner_desk_release")
        .expect("released");
    let rec: Value = serde_json::from_str(at_release.as_deref().expect("a record")).unwrap();
    assert_eq!(rec["state"], "settled", "{rec}");
    assert_eq!(rec["answer"]["outcome"], "ready");
}
