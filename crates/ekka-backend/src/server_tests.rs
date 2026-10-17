//! Through the HTTP server, over a real Unix socket: the socket, the routes
//! and the token checks are measured here, not only on the handler.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use super::{not_yet, serve, Handler};
use crate::answer::{Answer, Code};
use crate::socket::{bind, tests::dir};
use crate::testkit::{govern_test_key, header, op_id, token, verifier, NOW};

fn uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// Start a server for `uid` with `handler`; return its socket path.
fn start(serve_uid: u32, deadline: Duration, handler: Handler) -> (tempfile::TempDir, PathBuf) {
    let d = dir();
    let path = d.path().join("backend.sock");
    let listener = bind(&path, uid()).unwrap();
    let k = govern_test_key();
    let v = Arc::new(verifier(&[("govern-gate-token-v1", &k)], NOW));
    tokio::spawn(serve(listener, serve_uid, deadline, v, handler));
    (d, path)
}

/// The four contract headers for one call: a fresh Govern-signed token whose
/// body pin is `body`'s sha256.
fn signed(body: &[u8]) -> Vec<(String, String)> {
    static N: AtomicUsize = AtomicUsize::new(0);
    let mut t = token();
    t["token_id"] = json!(format!("token-{}", N.fetch_add(1, Ordering::SeqCst)));
    t["constraints"]["body_sha256"] = json!(format!("{:x}", Sha256::digest(body)));
    vec![
        (
            "x-ekka-gate-token".into(),
            header(&t, "govern-gate-token-v1", &govern_test_key()),
        ),
        ("authorization".into(), "Bearer backend-credential".into()),
        ("x-ekka-operation-id".into(), op_id()),
        ("x-ekka-backend-contract".into(), "ekka.backend.v1".into()),
    ]
}

/// One raw HTTP/1.1 request; the status and the JSON body, or `None` when the
/// server closed without answering.
async fn call(
    path: &PathBuf,
    method: &str,
    target: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Option<(u16, Value)> {
    let mut s = UnixStream::connect(path).await.unwrap();
    let mut head = format!(
        "{method} {target} HTTP/1.1\r\nHost: adapter\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    s.write_all(head.as_bytes()).await.ok()?;
    let _ = s.write_all(body).await;
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out).await;
    let text = String::from_utf8_lossy(&out).to_string();
    let status: u16 = text.split(' ').nth(1)?.parse().ok()?;
    let json = text.split("\r\n\r\n").nth(1)?;
    Some((status, serde_json::from_str(json).ok()?))
}

fn refused(code: &str) -> Value {
    json!({ "delivery": "first", "outcome": "refused", "desk_ready": false, "code": code })
}

/// A handler that counts the calls it receives: the stand-in for the
/// backend, so "zero gateway calls" is measured.
/// A handler that, like the adapter's, admits a verified call before it
/// executes anything, and counts only what it admitted.
fn counting() -> (Handler, Arc<AtomicUsize>) {
    let n = Arc::new(AtomicUsize::new(0));
    let seen = n.clone();
    let h: Handler = Arc::new(move |_, verified, _| {
        let answer = match verified.admit() {
            Ok(_) => {
                seen.fetch_add(1, Ordering::SeqCst);
                Answer::refused(Code::NotAvailable)
            }
            Err(code) => Answer::refused(code),
        };
        Box::pin(async move { answer })
    });
    (h, n)
}

#[tokio::test]
async fn an_unknown_route_is_the_contracts_unknown_operation() {
    let (_d, p) = start(uid(), Duration::from_secs(5), not_yet());
    for (m, t) in [
        ("GET", "/v1/desks"),
        ("PATCH", "/v1/desks/shop"),
        ("GET", "/healthz"),
    ] {
        assert_eq!(
            call(&p, m, t, &signed(b""), b"").await,
            Some((200, refused("UNKNOWN_OPERATION"))),
            "{m} {t}"
        );
    }
}

/// A verified call reaches its operation; the reserved operation answers
/// NOT_AVAILABLE and never reaches one.
#[tokio::test]
async fn a_verified_call_reaches_its_operation_and_the_reserved_one_does_not() {
    let (h, n) = counting();
    let (_d, p) = start(uid(), Duration::from_secs(5), h);
    for (m, t) in [
        ("POST", "/v1/desks"),
        ("GET", "/v1/desks/shop"),
        ("POST", "/v1/desks/shop/stop"),
        ("PUT", "/v1/desks/shop/policy"),
        ("DELETE", "/v1/desks/shop/providers/github"),
    ] {
        assert_eq!(
            call(&p, m, t, &signed(b"{}"), b"{}").await,
            Some((200, refused("NOT_AVAILABLE"))),
            "{m} {t}"
        );
    }
    assert_eq!(n.load(Ordering::SeqCst), 5);
    assert_eq!(
        call(&p, "POST", "/v1/providers", &signed(b"{}"), b"{}").await,
        Some((200, refused("NOT_AVAILABLE")))
    );
    assert_eq!(n.load(Ordering::SeqCst), 5, "provider_connect is reserved");
}

/// Token checks, through the server: each refused call makes zero
/// calls past verification.
#[tokio::test]
async fn a_call_that_fails_verification_never_reaches_an_operation() {
    let (h, n) = counting();
    let (_d, p) = start(uid(), Duration::from_secs(5), h);
    let without = |name: &str| -> Vec<(String, String)> {
        signed(b"").into_iter().filter(|(k, _)| k != name).collect()
    };
    assert_eq!(
        call(&p, "POST", "/v1/desks/shop/stop", &[], b"").await,
        Some((200, refused("REQUEST_INVALID")))
    );
    assert_eq!(
        call(
            &p,
            "POST",
            "/v1/desks/shop/stop",
            &without("authorization"),
            b""
        )
        .await,
        Some((200, refused("CREDENTIAL_MISSING")))
    );
    assert_eq!(
        call(
            &p,
            "POST",
            "/v1/desks/shop/stop",
            &without("x-ekka-gate-token"),
            b""
        )
        .await,
        Some((200, refused("TOKEN_MISSING")))
    );
    // A body the token's pin does not cover.
    assert_eq!(
        call(
            &p,
            "POST",
            "/v1/desks/shop/stop",
            &signed(b""),
            b"{\"smuggled\":true}"
        )
        .await,
        Some((200, refused("TOKEN_SCOPE")))
    );
    // The same token twice.
    let once = signed(b"");
    call(&p, "POST", "/v1/desks/shop/stop", &once, b"")
        .await
        .unwrap();
    assert_eq!(
        call(&p, "POST", "/v1/desks/shop/stop", &once, b"").await,
        Some((200, refused("TOKEN_REPLAYED")))
    );
    assert_eq!(
        n.load(Ordering::SeqCst),
        1,
        "only the first call was admitted; the replay was refused at admission"
    );
}

#[tokio::test]
async fn a_bad_name_or_a_body_over_one_mib_is_request_invalid() {
    let (_d, p) = start(uid(), Duration::from_secs(5), not_yet());
    assert_eq!(
        call(&p, "GET", "/v1/desks/Shop", &signed(b""), b"").await,
        Some((200, refused("REQUEST_INVALID")))
    );
    let big = vec![b'x'; super::MAX_BODY + 1];
    assert_eq!(
        call(&p, "POST", "/v1/desks", &signed(&big), &big).await,
        Some((200, refused("REQUEST_INVALID")))
    );
    let fits = vec![b' '; super::MAX_BODY];
    assert_eq!(
        call(&p, "POST", "/v1/desks", &signed(&fits), &fits).await,
        Some((200, refused("NOT_AVAILABLE")))
    );
}

/// The deadline is enforced by the server, around the handler: a handler
/// that never answers does not hold the caller past it.
#[tokio::test]
async fn a_request_past_the_deadline_is_answered_at_the_deadline() {
    let slow: Handler = Arc::new(|_, _, _| {
        Box::pin(async {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Answer::refused(Code::NotAvailable)
        })
    });
    let (_d, p) = start(uid(), Duration::from_millis(300), slow);
    let t = Instant::now();
    let got = call(&p, "GET", "/v1/desks/shop", &signed(b""), b"").await;
    assert_eq!(got, Some((200, refused("BACKEND_UNAVAILABLE"))));
    assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
}

/// The deadline covers reading the body too. A caller that
/// sends its headers and then stalls its body is answered at the deadline,
/// not held forever; nothing was admitted, so it is refused.
#[tokio::test]
async fn a_body_that_does_not_arrive_in_time_is_refused_at_the_deadline() {
    let (h, n) = counting();
    let (_d, p) = start(uid(), Duration::from_millis(300), h);
    let mut s = UnixStream::connect(&p).await.unwrap();
    let mut head = "POST /v1/desks/shop/stop HTTP/1.1\r\nHost: adapter\r\nContent-Length: 100\r\nConnection: close\r\n".to_string();
    for (k, v) in signed(b"") {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n{\"");
    s.write_all(head.as_bytes()).await.unwrap();
    let t = Instant::now();
    let mut out = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(3), s.read_to_end(&mut out)).await;
    assert!(
        read.is_ok(),
        "no answer within 3 s: the body read has no deadline"
    );
    let text = String::from_utf8_lossy(&out).to_string();
    assert!(text.contains("REQUEST_INVALID"), "{text}");
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
    assert_eq!(n.load(Ordering::SeqCst), 0);
}

/// Once a change is ADMITTED, the deadline does not cancel
/// it and does not refuse it. The answer is `running` (202) with the
/// operation's request id, and the work goes on to its end.
#[tokio::test]
async fn an_admitted_change_past_the_deadline_answers_running_and_keeps_going() {
    let done = Arc::new(AtomicUsize::new(0));
    let finished = done.clone();
    let slow: Handler = Arc::new(move |_, verified, _| {
        let finished = finished.clone();
        Box::pin(async move {
            let Ok(_admitted) = verified.admit() else {
                return Answer::refused(Code::TokenReplayed);
            };
            tokio::time::sleep(Duration::from_millis(600)).await;
            finished.fetch_add(1, Ordering::SeqCst);
            Answer::refused(Code::NotAvailable)
        })
    });
    let (_d, p) = start(uid(), Duration::from_millis(300), slow);
    let t = Instant::now();
    let got = call(&p, "POST", "/v1/desks/shop/stop", &signed(b""), b"").await;
    assert!(
        t.elapsed() < Duration::from_millis(550),
        "{:?}",
        t.elapsed()
    );
    let (status, body) = got.unwrap();
    assert_eq!(status, 202);
    let id = crate::testkit::request_id();
    assert_eq!(
        body,
        json!({ "delivery": "first", "outcome": "running", "operation_id": id })
    );
    assert_eq!(
        done.load(Ordering::SeqCst),
        0,
        "not finished at the deadline"
    );
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert_eq!(
        done.load(Ordering::SeqCst),
        1,
        "the admitted change was cancelled"
    );
}

/// A change NOT admitted by the deadline is refused, and can never be
/// admitted afterwards: nothing it would have done happens.
#[tokio::test]
async fn a_change_not_admitted_by_the_deadline_is_refused_and_never_admitted_later() {
    let done = Arc::new(AtomicUsize::new(0));
    let admitted = done.clone();
    let late: Handler = Arc::new(move |_, verified, _| {
        let admitted = admitted.clone();
        Box::pin(async move {
            tokio::time::sleep(Duration::from_millis(600)).await;
            if verified.admit().is_ok() {
                admitted.fetch_add(1, Ordering::SeqCst);
            }
            Answer::refused(Code::NotAvailable)
        })
    });
    let (_d, p) = start(uid(), Duration::from_millis(300), late);
    let got = call(&p, "POST", "/v1/desks/shop/stop", &signed(b""), b"").await;
    assert_eq!(got, Some((200, refused("BACKEND_UNAVAILABLE"))));
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert_eq!(done.load(Ordering::SeqCst), 0);
}

/// The plan's acceptance: a planted second uid is refused. The test cannot
/// connect as another user, so it plants the other side: a server that serves
/// only another uid closes this user's connection unanswered.
#[tokio::test]
async fn a_peer_that_is_not_this_user_is_closed_unanswered() {
    let other = uid().wrapping_add(1).max(1);
    let (_d, p) = start(other, Duration::from_secs(5), not_yet());
    assert_eq!(
        call(&p, "GET", "/v1/desks/shop", &signed(b""), b"").await,
        None
    );
}

/// Every answer is the contract's closed shape: the keys the result schema
/// names, and a code from its list.
#[tokio::test]
async fn every_answer_is_the_contracts_closed_shape() {
    let schema = backend_schema();
    let result = &schema["$defs"]["result"];
    assert_eq!(result["additionalProperties"], false);
    let allowed: Vec<&str> = result["properties"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let codes: Vec<&str> = schema["$defs"]["code"]["enum"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let (_d, p) = start(uid(), Duration::from_secs(5), not_yet());
    for (m, t, h) in [
        ("GET", "/nope", signed(b"")),
        ("GET", "/v1/desks/Shop", signed(b"")),
        ("POST", "/v1/desks", signed(b"")),
        ("POST", "/v1/desks", vec![]),
    ] {
        let (_, v) = call(&p, m, t, &h, b"").await.unwrap();
        for k in v.as_object().unwrap().keys() {
            assert!(
                allowed.contains(&k.as_str()),
                "{k} is not in the result schema"
            );
        }
        assert!(codes.contains(&v["code"].as_str().unwrap()), "{v}");
    }
}

fn backend_schema() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vendor/contracts/backend/backend-v1.schema.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// Every code this adapter can answer is one the contract names.
#[test]
fn every_code_is_the_contracts() {
    let schema = backend_schema();
    let codes = schema["$defs"]["code"]["enum"].as_array().unwrap();
    for c in [
        Code::TokenMissing,
        Code::TokenInvalid,
        Code::TokenExpired,
        Code::TokenReplayed,
        Code::TokenScope,
        Code::CredentialMissing,
        Code::RequestInvalid,
        Code::UnknownOperation,
        Code::NotAvailable,
        Code::ConstraintsInvalid,
        Code::ConstraintImageDigests,
        Code::ConstraintPolicyDigests,
        Code::ConstraintAllowedHosts,
        Code::ConstraintProviders,
        Code::ConstraintProviderConfigDigests,
        Code::ConstraintEnvironmentKeys,
        Code::ConstraintPolicyBaseline,
        Code::ConstraintCredentialEndpoint,
        Code::FieldNotAllowed,
        Code::OperationIdReused,
        Code::DeskNotFound,
        Code::DeskExists,
        Code::DeskProviderRequired,
        Code::DeskBusy,
        Code::VersionConflict,
        Code::BackendUnavailable,
        Code::BackendRefused,
    ] {
        let name = serde_json::to_value(c).unwrap();
        assert!(codes.contains(&name), "{name}");
    }
}
