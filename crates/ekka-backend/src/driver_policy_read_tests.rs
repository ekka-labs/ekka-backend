//! The policy read sends the live policy itself, beside its digest, and no other answer does (contracts 0.75.0,
//! `result.policy`). It is what lets `ekka desk policy show` answer on the Enclave's own machine through a recorded
//! plan run instead of a person's device sign-in.

use serde_json::{json, Value};

use super::tests::{admitted, create_body, policy, world};
use crate::answer::{Outcome as AnswerOutcome, POLICY_MAX_BYTES};
use crate::normalize::{canonical, digest, POLICY};

#[tokio::test]
async fn the_policy_read_sends_the_loaded_policy_beside_its_digest() {
    let w = world().await;
    w.b.create(&admitted(), &create_body(json!({})), &crate::driver::Noted)
        .await;
    let a = w.b.policy_get(&admitted(), "code-desk").await;
    assert_eq!(a.outcome, AnswerOutcome::Ready, "{a:?}");
    let sent = a
        .desk
        .policy
        .clone()
        .expect("the policy read sends the policy");
    // The document is the canonical form, and the digest beside it is its own.
    assert_eq!(Some(sent.clone()), canonical(POLICY, &policy()));
    assert_eq!(digest(POLICY, &sent), a.desk.policy_digest);
    // On the wire it is `policy`, beside `policy_digest`.
    let wire = serde_json::to_value(&a).unwrap();
    assert!(
        wire["policy"].is_object() && wire["policy_digest"].is_string(),
        "{wire}"
    );
}

#[tokio::test]
async fn no_other_answer_carries_the_policy() {
    let w = world().await;
    let created =
        w.b.create(&admitted(), &create_body(json!({})), &crate::driver::Noted)
            .await;
    assert!(created.desk.policy.is_none(), "{created:?}");
    let status = w.b.status(&admitted(), "code-desk").await;
    assert_eq!(status.outcome, AnswerOutcome::Ready, "{status:?}");
    assert!(status.desk.policy.is_none(), "{status:?}");
    assert!(serde_json::to_value(&status)
        .unwrap()
        .get("policy")
        .is_none());
}

#[tokio::test]
async fn a_policy_not_yet_loaded_is_never_sent() {
    let w = world().await;
    w.b.create(&admitted(), &create_body(json!({})), &crate::driver::Noted)
        .await;
    w.gw.lock().unwrap().loading.insert("code-desk".into());
    w.gw.lock()
        .unwrap()
        .revisions
        .get_mut("code-desk")
        .unwrap()
        .push(Default::default());
    let a = w.b.policy_get(&admitted(), "code-desk").await;
    assert_ne!(a.outcome, AnswerOutcome::Ready, "{a:?}");
    assert!(a.desk.policy.is_none(), "{a:?}");
}

#[test]
fn a_policy_over_the_bound_is_left_out() {
    let small: Value = canonical(POLICY, &policy()).unwrap();
    assert!(super::within_policy_bound(&small));
    let big = json!({ "filesystem": { "readOnly": vec!["/a".repeat(1_000); 70] } });
    assert!(serde_json::to_vec(&big).unwrap().len() > POLICY_MAX_BYTES);
    assert!(!super::within_policy_bound(&big));
    assert_eq!(POLICY_MAX_BYTES, 65_536, "the contract's bound");
}
