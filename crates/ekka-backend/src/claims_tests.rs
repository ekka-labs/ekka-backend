//! The claim client against a fake Enclave: one JSON-RPC line in, one out,
//! every request recorded; and the socket rules the adapter dials by.

use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

use super::{ClaimError, Claims, Outcome, ReadBack, ENCLAVE_SOCKET};
use crate::socket::tests::dir;

const OP: &str = "228f680e-930e-56f2-9feb-1bc759da6615";

fn uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

type Answer = Arc<dyn Fn(&Value) -> Value + Send + Sync>;

/// A fake Enclave at `<dir>/enclave.sock`, 0600, answering with `answer`.
fn enclave(d: &std::path::Path, answer: Answer) -> Arc<Mutex<Vec<Value>>> {
    let path = d.join(ENCLAVE_SOCKET);
    let l = UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = l.accept().await else {
                return;
            };
            let (r, mut w) = stream.into_split();
            let mut line = String::new();
            BufReader::new(r).read_line(&mut line).await.unwrap();
            let req: Value = serde_json::from_str(line.trim_end()).unwrap();
            s.lock().unwrap().push(req.clone());
            let mut out = answer(&req).to_string();
            out.push('\n');
            let _ = w.write_all(out.as_bytes()).await;
        }
    });
    seen
}

fn ok(result: Value) -> Answer {
    Arc::new(move |req: &Value| json!({ "jsonrpc": "2.0", "id": req["id"], "result": result }))
}

fn refusal(message: &'static str) -> Answer {
    Arc::new(
        move |req: &Value| json!({ "jsonrpc": "2.0", "id": req["id"], "error": { "code": -32000, "message": message } }),
    )
}

#[tokio::test]
async fn a_claim_and_a_release_are_the_contracts_calls_beside_the_adapters_socket() {
    let d = dir();
    let seen = enclave(
        d.path(),
        ok(json!({ "claimed": true, "released": "freed" })),
    );
    let c = Claims::beside(&d.path().join("backend.sock"), uid());
    assert_eq!(c.claim("bench", OP).await.unwrap(), None);
    let rb = ReadBack::Live {
        sandbox_id: "s-1".into(),
        policy_digest: format!("sha256:{}", "a".repeat(64)),
        providers_digest: None,
    };
    assert_eq!(
        c.release("bench", OP, Outcome::Ready, Some(&rb))
            .await
            .unwrap(),
        "freed"
    );
    let s = seen.lock().unwrap();
    assert_eq!(s[0]["method"], "runner_desk_claim");
    assert_eq!(
        s[0]["params"],
        json!({ "desk": "bench", "operation_id": OP })
    );
    assert_eq!(s[1]["method"], "runner_desk_release");
    assert_eq!(
        s[1]["params"],
        json!({ "desk": "bench", "operation_id": OP, "outcome": "ready",
                "read_back": { "sandbox_id": "s-1", "policy_digest": format!("sha256:{}", "a".repeat(64)) } })
    );
    assert!(s.iter().all(|r| r["jsonrpc"] == "2.0"));
}

#[tokio::test]
async fn a_deleted_read_back_and_the_required_providers_travel_as_the_contract_writes_them() {
    let d = dir();
    let seen = enclave(
        d.path(),
        ok(
            json!({ "claimed": true, "required_providers": ["github"], "released": "freed_pins_retired" }),
        ),
    );
    let c = Claims::beside(&d.path().join("backend.sock"), uid());
    assert_eq!(
        c.claim("bench", OP).await.unwrap(),
        Some(vec!["github".to_string()])
    );
    let gone = ReadBack::Deleted {
        sandbox_id: "s-1".into(),
    };
    c.release("bench", OP, Outcome::Ready, Some(&gone))
        .await
        .unwrap();
    assert_eq!(
        seen.lock().unwrap()[1]["params"]["read_back"],
        json!({ "deleted": true, "sandbox_id": "s-1" })
    );
}

#[tokio::test]
async fn a_refusal_is_its_code_and_a_bad_answer_is_unavailable() {
    let d = dir();
    enclave(
        d.path(),
        refusal("DESK_BUSY: desk 'bench' is held by 'attempt-1'"),
    );
    let c = Claims::beside(&d.path().join("backend.sock"), uid());
    assert_eq!(
        c.claim("bench", OP).await.unwrap_err(),
        ClaimError::Refused("DESK_BUSY".into())
    );
    let d2 = dir();
    enclave(d2.path(), Arc::new(|_| json!("not an answer")));
    let c2 = Claims::beside(&d2.path().join("backend.sock"), uid());
    assert!(matches!(
        c2.claim("bench", OP).await.unwrap_err(),
        ClaimError::Unavailable(_)
    ));
}

/// The adapter dials only a socket that is this user's and closed to others,
/// and never one that is missing or a link.
#[tokio::test]
async fn the_enclave_socket_must_be_this_users_and_closed_to_others() {
    let d = dir();
    enclave(d.path(), ok(json!({ "claimed": true })));
    let path = d.path().join(ENCLAVE_SOCKET);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();
    let c = Claims::beside(&d.path().join("backend.sock"), uid());
    assert!(matches!(
        c.claim("bench", OP).await.unwrap_err(),
        ClaimError::Unavailable(_)
    ));
    let other = Claims::beside(&d.path().join("backend.sock"), uid() + 1);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        other.claim("bench", OP).await.unwrap_err(),
        ClaimError::Unavailable(_)
    ));
    let linked = dir();
    std::os::unix::fs::symlink(&path, linked.path().join(ENCLAVE_SOCKET)).unwrap();
    let c3 = Claims::beside(&linked.path().join("backend.sock"), uid());
    assert!(matches!(
        c3.claim("bench", OP).await.unwrap_err(),
        ClaimError::Unavailable(_)
    ));
    let empty = dir();
    let c4 = Claims::beside(&empty.path().join("backend.sock"), uid());
    assert!(matches!(
        c4.claim("bench", OP).await.unwrap_err(),
        ClaimError::Unavailable(_)
    ));
}

/// Contracts 0.64.0: a claim's result always names the required providers,
/// which a detach is held to.
#[test]
fn the_claim_result_names_the_required_providers() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vendor/contracts/backend/desk-claim.v1.schema.json"
    );
    let s: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let r = &s["$defs"]["claim_result"];
    let mut req: Vec<&str> = r["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    req.sort_unstable();
    assert_eq!(req, ["claimed", "required_providers"]);
    assert_eq!(r["properties"]["required_providers"]["type"], "array");
}

/// Every Enclave call has a time limit: an Enclave
/// that reads the claim and never answers fails it at the limit, as
/// unavailable, never a hang.
#[tokio::test]
async fn an_enclave_that_never_answers_fails_at_the_time_limit() {
    let d = dir();
    let enc = ekka_backend_fakegw::fake_enclave::start(d.path());
    enc.lock().unwrap().stall = true;
    let c = Claims::beside(&d.path().join("backend.sock"), uid())
        .within(std::time::Duration::from_millis(300));
    let started = std::time::Instant::now();
    let e = c
        .claim("code-desk", "00000000-0000-5000-8000-000000000001")
        .await;
    assert!(matches!(e, Err(ClaimError::Unavailable(_))), "{e:?}");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
}
