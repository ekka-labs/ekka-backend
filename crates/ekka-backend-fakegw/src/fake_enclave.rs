//! A fake Enclave claim socket for tests (contracts `backend/desk-claim.v1`):
//! JSON-RPC 2.0, one line in and one out, at `<dir>/enclave.sock`, 0600. It
//! records every request, holds a lock per claimed desk, answers a desk's
//! required providers, and can be told a desk is busy or that it names no
//! required providers (an Enclave older than contracts 0.64.0).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

#[derive(Default)]
pub struct Enclave {
    /// Every request, as sent.
    pub seen: Vec<Value>,
    /// Required providers by desk; a desk not here has none.
    pub required: BTreeMap<String, Vec<String>>,
    /// Desks a job holds.
    pub busy: BTreeSet<String>,
    /// The claim answer leaves `required_providers` out.
    pub omit_required: bool,
    /// Desks a change holds now, by operation id.
    pub held: BTreeMap<String, String>,
    /// Read each request and never answer: an Enclave that hangs.
    pub stall: bool,
    /// Read at every request, before it is answered: the test proves what was
    /// on disk at that moment (an operation record).
    pub watch: Option<std::path::PathBuf>,
    /// `(method, the watched file's text then)`, one per request.
    pub watched: Vec<(String, Option<String>)>,
    /// Each release takes the first of these, if any, and is refused with it
    /// (`CODE: why`), changing nothing.
    pub release_refusals: Vec<String>,
}

impl Enclave {
    /// The `(method, params)` of every request, in order.
    #[must_use]
    pub fn calls(&self) -> Vec<(String, Value)> {
        self.seen
            .iter()
            .map(|r| {
                (
                    r["method"].as_str().unwrap_or_default().to_string(),
                    r["params"].clone(),
                )
            })
            .collect()
    }
}

pub type Shared = Arc<Mutex<Enclave>>;

fn answer(st: &Shared, req: &Value) -> Value {
    let mut s = st.lock().unwrap();
    s.seen.push(req.clone());
    if let Some(w) = s.watch.clone() {
        let method = req["method"].as_str().unwrap_or_default().to_string();
        s.watched.push((method, std::fs::read_to_string(w).ok()));
    }
    let p = &req["params"];
    let desk = p["desk"].as_str().unwrap_or_default().to_string();
    let op = p["operation_id"].as_str().unwrap_or_default().to_string();
    let result = match req["method"].as_str() {
        Some("runner_desk_claim") => {
            if s.busy.contains(&desk) || s.held.contains_key(&desk) {
                return json!({ "jsonrpc": "2.0", "id": req["id"], "error": { "code": -32000,
                    "message": format!("DESK_BUSY: desk '{desk}' is held by 'attempt-1'") } });
            }
            s.held.insert(desk.clone(), op);
            let mut r = json!({ "claimed": true });
            if !s.omit_required {
                r["required_providers"] = json!(s.required.get(&desk).cloned().unwrap_or_default());
            }
            r
        }
        Some("runner_desk_release") => {
            if !s.release_refusals.is_empty() {
                let message = s.release_refusals.remove(0);
                return json!({ "jsonrpc": "2.0", "id": req["id"], "error": { "code": -32000,
                    "message": message } });
            }
            if s.held.get(&desk) != Some(&op) {
                return json!({ "jsonrpc": "2.0", "id": req["id"], "error": { "code": -32000,
                    "message": format!("DESK_NOT_HELD: no change holds desk '{desk}'") } });
            }
            if p["outcome"] != "unknown" {
                s.held.remove(&desk);
            }
            json!({ "released": "freed" })
        }
        _ => json!({}),
    };
    json!({ "jsonrpc": "2.0", "id": req["id"], "result": result })
}

/// A fake Enclave at `<dir>/enclave.sock`.
pub fn start(dir: &Path) -> Shared {
    let path = dir.join("enclave.sock");
    let l = UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let st: Shared = Arc::default();
    let s = st.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = l.accept().await else {
                return;
            };
            let s = s.clone();
            tokio::spawn(async move {
                let (r, mut w) = stream.into_split();
                let mut line = String::new();
                if BufReader::new(r).read_line(&mut line).await.is_err() {
                    return;
                }
                let Ok(req) = serde_json::from_str::<Value>(line.trim_end()) else {
                    return;
                };
                if s.lock().unwrap().stall {
                    std::future::pending::<()>().await;
                }
                let mut out = answer(&s, &req).to_string();
                out.push('\n');
                let _ = w.write_all(out.as_bytes()).await;
            });
        }
    });
    st
}
