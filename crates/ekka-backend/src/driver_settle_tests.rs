//! How long a change is read back. A real gateway loads a new desk's policy a
//! moment after the desk exists, and takes more than 5 s to delete one: a
//! change answers `ready` once it shows, within the call's deadline less a
//! margin, and `running`, with the desk still held, only when that ends.

use std::time::{Duration, Instant};

use serde_json::json;

use super::tests::{admitted, code, create_body, methods, then, world, FIRST_ID, RID};
use super::{settle_window, Noted};
use crate::answer::Outcome;

fn policy_reads(w: &super::tests::World) -> usize {
    w.gw.lock()
        .unwrap()
        .calls
        .iter()
        .filter(|c| c.starts_with("GetSandboxPolicyStatus"))
        .count()
}

#[test]
fn the_window_is_the_deadline_less_a_margin_of_at_most_half() {
    assert_eq!(
        settle_window(Duration::from_secs(120)),
        Duration::from_secs(110)
    );
    assert_eq!(
        settle_window(Duration::from_secs(149)),
        Duration::from_secs(139)
    );
    // A short deadline still reads: the margin is at most half of it.
    assert_eq!(
        settle_window(Duration::from_secs(10)),
        Duration::from_secs(5)
    );
    assert_eq!(
        settle_window(Duration::from_secs(1)),
        Duration::from_millis(500)
    );
}

/// The walk box's create: the desk exists before its policy loads. It is
/// `ready` once the policy is loaded, released with that read-back.
#[tokio::test]
async fn a_create_whose_policy_loads_on_the_third_read_is_ready() {
    let w = world().await;
    w.gw.lock().unwrap().create_loads_on_read = Some(3);
    let a =
        w.b.create(&admitted(), &create_body(json!({})), &Noted)
            .await;
    assert_eq!(a.outcome, Outcome::Ready, "{a:?}");
    assert_eq!(a.desk.backend_id.as_deref(), Some(FIRST_ID));
    assert!(a.desk.policy_digest.is_some());
    assert_eq!(
        policy_reads(&w),
        3,
        "read until the policy loaded, no longer"
    );
    assert_eq!(methods(&w), ["runner_desk_claim", "runner_desk_release"]);
}

/// The walk box's delete: accepted at once, gone 8 s later. Read back until it
/// is gone, it is `ready`. PLANTED: the old fixed 5 s window answers `running`
/// for the same delete, and keeps the desk held.
#[tokio::test]
async fn a_delete_that_takes_8_s_is_ready_and_a_5_s_window_was_not() {
    for (window, ready) in [
        (Duration::from_secs(12), true),
        (Duration::from_secs(5), false),
    ] {
        let mut w = world().await;
        w.b.create(&admitted(), &create_body(json!({})), &Noted)
            .await;
        w.gw.lock().unwrap().delete_takes = Some(Duration::from_secs(8));
        w.b.settle_for = window;
        w.enc.lock().unwrap().seen.clear();
        let started = Instant::now();
        let a = w.b.delete(&then(1), "code-desk", &Noted).await;
        if ready {
            assert_eq!(a.outcome, Outcome::Ready, "{a:?}");
            assert!(
                started.elapsed() >= Duration::from_secs(8),
                "not before it was gone"
            );
            let calls = w.enc.lock().unwrap().calls();
            assert_eq!(
                calls.last().unwrap().1["read_back"],
                json!({ "deleted": true, "sandbox_id": FIRST_ID })
            );
        } else {
            assert_eq!(a.outcome, Outcome::Running, "the planted 5 s window: {a:?}");
            assert_eq!(methods(&w), ["runner_desk_claim"], "held, never released");
        }
    }
}

/// A change that never shows answers `running` when the window ends, NOT
/// before it, and keeps the desk held: no release reaches the Enclave.
#[tokio::test]
async fn a_change_that_never_settles_is_running_at_the_end_of_the_window_and_held() {
    let mut w = world().await;
    w.gw.lock().unwrap().create_loads_on_read = Some(usize::MAX);
    // Longer than the 5 s every send is read back for, so the window decides.
    w.b.settle_for = Duration::from_secs(7);
    let started = Instant::now();
    let a =
        w.b.create(&admitted(), &create_body(json!({})), &Noted)
            .await;
    let took = started.elapsed();
    assert_eq!(a.outcome, Outcome::Running, "{a:?}");
    assert_eq!(a.operation_id.as_deref(), Some(RID));
    assert!(
        took >= Duration::from_millis(6_700),
        "answered before the window ended: {took:?}"
    );
    assert!(
        took < Duration::from_secs(9),
        "answered long after the window: {took:?}"
    );
    assert!(policy_reads(&w) > 10, "read all through the window");
    assert_eq!(methods(&w), ["runner_desk_claim"], "never released");
    assert_eq!(
        w.enc
            .lock()
            .unwrap()
            .held
            .get("code-desk")
            .map(String::as_str),
        Some(RID)
    );
}

/// A desk whose policy read says NOT_FOUND while the desk is still there is
/// NOT gone: a delete must not be released as done. PLANTED: taking that
/// NOT_FOUND as "gone" would answer `ready` here.
#[tokio::test]
async fn a_policy_not_found_while_the_desk_is_there_is_not_gone() {
    let mut w = world().await;
    w.b.create(&admitted(), &create_body(json!({})), &Noted)
        .await;
    {
        let mut g = w.gw.lock().unwrap();
        g.delete_takes = Some(Duration::from_secs(3600));
        // The desk stays; its policy can no longer be read.
        g.revisions.remove("code-desk");
    }
    w.b.settle_for = Duration::from_secs(1);
    w.enc.lock().unwrap().seen.clear();
    let a = w.b.delete(&then(1), "code-desk", &Noted).await;
    assert_eq!(a.outcome, Outcome::Running, "{a:?}");
    assert_eq!(code(&a), None);
    assert_eq!(methods(&w), ["runner_desk_claim"], "held, never released");
}

/// THE WALK BOX'S CREATE (NVIDIA OpenShell, 3088aff4): the read right after a
/// create answered an ERROR, and stopping there answered `running`. Each
/// error code that is not a refusal is "not shown yet": read again.
#[tokio::test]
async fn a_create_whose_first_policy_reads_fail_is_read_again_and_ready() {
    for code in [
        tonic::Code::NotFound,
        tonic::Code::FailedPrecondition,
        tonic::Code::Unavailable,
    ] {
        let w = world().await;
        w.gw.lock().unwrap().fail_policy_reads = Some((2, code));
        let a =
            w.b.create(&admitted(), &create_body(json!({})), &Noted)
                .await;
        assert_eq!(a.outcome, Outcome::Ready, "{code:?}: {a:?}");
        assert_eq!(
            methods(&w),
            ["runner_desk_claim", "runner_desk_release"],
            "{code:?}"
        );
    }
}

/// THE WALK BOX'S DELETE: while the desk goes, its policy read errors; once
/// GetSandbox says NOT_FOUND it is gone, and the delete is `ready`.
#[tokio::test]
async fn a_delete_whose_policy_read_errors_while_it_goes_is_ready() {
    let mut w = world().await;
    w.b.create(&admitted(), &create_body(json!({})), &Noted)
        .await;
    {
        let mut g = w.gw.lock().unwrap();
        g.delete_takes = Some(Duration::from_secs(2));
        g.policy_error_while_deleting = Some(tonic::Code::FailedPrecondition);
    }
    w.b.settle_for = Duration::from_secs(12);
    let a = w.b.delete(&then(1), "code-desk", &Noted).await;
    assert_eq!(a.outcome, Outcome::Ready, "{a:?}");
}

/// PLANTED: a gateway that errors all through the window. `running` at its
/// end, never before and never `ready`, and the desk held.
#[tokio::test]
async fn reads_that_fail_until_the_window_ends_are_running_and_held() {
    let mut w = world().await;
    w.gw.lock().unwrap().fail_policy_reads = Some((usize::MAX, tonic::Code::FailedPrecondition));
    w.b.settle_for = Duration::from_secs(6);
    let started = Instant::now();
    let a =
        w.b.create(&admitted(), &create_body(json!({})), &Noted)
            .await;
    let took = started.elapsed();
    assert_eq!(a.outcome, Outcome::Running, "{a:?}");
    assert!(
        took >= Duration::from_millis(5_700),
        "gave up before the window ended: {took:?}"
    );
    assert_eq!(methods(&w), ["runner_desk_claim"], "never released");
}

/// A refused token or client will not pass by waiting: the settle ends at
/// once, `running`, the desk held.
#[tokio::test]
async fn a_refused_token_ends_the_settle_at_once() {
    for code in [tonic::Code::Unauthenticated, tonic::Code::PermissionDenied] {
        let mut w = world().await;
        w.gw.lock().unwrap().fail_policy_reads = Some((usize::MAX, code));
        w.b.settle_for = Duration::from_secs(30);
        let started = Instant::now();
        let a =
            w.b.create(&admitted(), &create_body(json!({})), &Noted)
                .await;
        assert_eq!(a.outcome, Outcome::Running, "{code:?}: {a:?}");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{code:?}: polled a refusal"
        );
        assert_eq!(
            methods(&w),
            ["runner_desk_claim"],
            "{code:?}: never released"
        );
    }
}

/// THE REAL ORDER on NVIDIA OpenShell (walk box, 4d590cc0): CreateSandbox OK;
/// GetSandbox finds the desk; GetSandboxPolicyStatus answers NOT_FOUND until
/// the desk's supervisor reports its policy. The desk exists with no policy
/// yet: read on, and `ready` once the policy is there, after exactly 3
/// policy reads.
#[tokio::test]
async fn a_create_whose_policy_is_not_reported_yet_is_ready_on_the_third_policy_read() {
    let w = world().await;
    w.gw.lock().unwrap().fail_policy_reads = Some((2, tonic::Code::NotFound));
    let a =
        w.b.create(&admitted(), &create_body(json!({})), &Noted)
            .await;
    assert_eq!(a.outcome, Outcome::Ready, "{a:?}");
    assert_eq!(policy_reads(&w), 3);
    assert_eq!(methods(&w), ["runner_desk_claim", "runner_desk_release"]);
}

/// A desk with no policy reported yet EXISTS: `status` says what it enforces
/// cannot be told now (`unknown`). PLANTED: taking that NOT_FOUND as an
/// error answered DESK_NOT_FOUND for a desk that is there.
#[tokio::test]
async fn a_desk_with_no_policy_reported_yet_is_there_and_unknown() {
    let w = world().await;
    w.b.create(&admitted(), &create_body(json!({})), &Noted)
        .await;
    w.gw.lock().unwrap().fail_policy_reads = Some((1, tonic::Code::NotFound));
    let a = w.b.status(&admitted(), "code-desk").await;
    assert_eq!(a.outcome, Outcome::Unknown, "{a:?}");
    assert_eq!(code(&a), None);
}
