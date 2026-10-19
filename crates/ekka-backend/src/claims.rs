//! The adapter's claim on a desk at the Enclave (contracts
//! `backend/desk-claim.v1`): before a change the adapter claims the
//! desk, after it releases it, so a change and a job never run on one desk at
//! once.
//!
//! JSON-RPC 2.0, one request and one answer per line, over the Enclave's
//! backend-link socket: `enclave.sock` in the shared socket folder, the
//! folder that holds the adapter's own socket. The adapter
//! dials it only when it is a socket owned by the adapter's own user and
//! closed to group and others, and only talks to a peer with that same uid,
//! as the Enclave checks its peer in the other direction.
//!
//! A refusal is a JSON-RPC error whose message starts with its code and a
//! colon; only the code is kept.

use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// The Enclave's backend-link socket, in the shared socket folder.
pub const ENCLAVE_SOCKET: &str = "enclave.sock";
/// How long one call to the Enclave may take.
const CALL_TIMEOUT: Duration = Duration::from_secs(10);
/// The largest answer read: a claim or release answer is a few fields.
const MAX_ANSWER: u64 = 64 * 1024;

/// Why a claim or release did not happen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimError {
    /// The Enclave refused, by the contract's code (`DESK_BUSY`, …).
    Refused(String),
    /// The Enclave could not be asked, or answered something unreadable.
    Unavailable(String),
}

/// How a change ended, for the release. A change that may still finish is
/// never released: its claim stays held until recovery settles it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Ready,
    Refused,
    Unknown,
}

impl Outcome {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Refused => "refused",
            Self::Unknown => "unknown",
        }
    }

    /// The outcome a pending release names; `None` for anything else.
    pub(crate) fn from_name(name: &str) -> Option<Self> {
        match name {
            "ready" => Some(Self::Ready),
            "refused" => Some(Self::Refused),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }
}

/// What the adapter read back after a `ready` change (contracts 0.63.0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadBack {
    /// The live desk.
    Live {
        sandbox_id: String,
        policy_digest: String,
        providers_digest: Option<String>,
    },
    /// The desk is gone: GetSandbox answered NOT_FOUND for this sandbox id.
    Deleted { sandbox_id: String },
}

impl ReadBack {
    /// The read-back a pending release kept in its wire form.
    pub(crate) fn from_wire(v: &Value) -> Option<Self> {
        let id = v.get("sandbox_id")?.as_str()?.to_string();
        if v.get("deleted") == Some(&json!(true)) {
            return Some(Self::Deleted { sandbox_id: id });
        }
        Some(Self::Live {
            sandbox_id: id,
            policy_digest: v.get("policy_digest")?.as_str()?.to_string(),
            providers_digest: match v.get("providers_digest") {
                None => None,
                Some(p) => Some(p.as_str()?.to_string()),
            },
        })
    }

    pub(crate) fn wire(&self) -> Value {
        match self {
            Self::Live {
                sandbox_id,
                policy_digest,
                providers_digest,
            } => {
                let mut v = json!({ "sandbox_id": sandbox_id, "policy_digest": policy_digest });
                if let Some(p) = providers_digest {
                    v["providers_digest"] = json!(p);
                }
                v
            }
            Self::Deleted { sandbox_id } => json!({ "deleted": true, "sandbox_id": sandbox_id }),
        }
    }
}

/// The Enclave's claims, over its socket.
pub struct Claims {
    path: PathBuf,
    uid: u32,
    /// Each call, connect to answer, fails at this: a claim never hangs.
    limit: Duration,
}

impl Claims {
    /// The Enclave's socket beside the adapter's own `socket_path`.
    #[must_use]
    pub fn beside(socket_path: &Path, uid: u32) -> Self {
        let dir = socket_path.parent().unwrap_or_else(|| Path::new("/"));
        Self {
            path: dir.join(ENCLAVE_SOCKET),
            uid,
            limit: CALL_TIMEOUT,
        }
    }

    /// A shorter time limit: tests only.
    #[cfg(test)]
    #[must_use]
    pub fn within(mut self, limit: Duration) -> Self {
        self.limit = limit;
        self
    }

    async fn connect(&self) -> Result<UnixStream, ClaimError> {
        let shown = self.path.display();
        let m = std::fs::symlink_metadata(&self.path)
            .map_err(|e| ClaimError::Unavailable(format!("{shown}: {e}")))?;
        if !m.file_type().is_socket() || m.uid() != self.uid || m.mode() & 0o077 != 0 {
            return Err(ClaimError::Unavailable(format!(
                "{shown} is not a socket owned by this user and closed to others"
            )));
        }
        let s = UnixStream::connect(&self.path)
            .await
            .map_err(|e| ClaimError::Unavailable(format!("{shown}: {e}")))?;
        match s.peer_cred() {
            Ok(c) if c.uid() == self.uid => Ok(s),
            _ => Err(ClaimError::Unavailable(format!(
                "{shown}: the peer is not this user"
            ))),
        }
    }

    /// One JSON-RPC call: one line out, one line back.
    async fn call(&self, method: &str, params: Value) -> Result<Value, ClaimError> {
        let work = async {
            let mut s = self.connect().await?;
            let req = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
            let mut line = req.to_string();
            line.push('\n');
            s.write_all(line.as_bytes())
                .await
                .map_err(|e| ClaimError::Unavailable(format!("{method}: {e}")))?;
            let (r, _w) = s.into_split();
            let mut reader = BufReader::new(tokio::io::AsyncReadExt::take(r, MAX_ANSWER));
            let mut answer = String::new();
            reader
                .read_line(&mut answer)
                .await
                .map_err(|e| ClaimError::Unavailable(format!("{method}: {e}")))?;
            if !answer.ends_with('\n') {
                return Err(ClaimError::Unavailable(format!(
                    "{method}: the Enclave's answer was cut off or too large"
                )));
            }
            Ok(answer)
        };
        let answer = tokio::time::timeout(self.limit, work).await.map_err(|_| {
            ClaimError::Unavailable(format!("{method}: the Enclave did not answer"))
        })??;
        let v: Value = serde_json::from_str(answer.trim_end())
            .map_err(|_| ClaimError::Unavailable(format!("{method}: the answer is not JSON")))?;
        if let Some(e) = v.get("error") {
            let msg = e.get("message").and_then(Value::as_str).unwrap_or_default();
            return Err(ClaimError::Refused(refusal_code(msg)));
        }
        v.get("result")
            .cloned()
            .ok_or_else(|| ClaimError::Unavailable(format!("{method}: no result")))
    }

    /// Claim `desk` for the operation `request_id`. Returns the desk's
    /// required providers when the Enclave names them (contracts 0.64.0).
    ///
    /// # Errors
    /// The Enclave's refusal (`DESK_BUSY` …), or why it could not be asked.
    pub async fn claim(
        &self,
        desk: &str,
        request_id: &str,
    ) -> Result<Option<Vec<String>>, ClaimError> {
        let r = self
            .call(
                "runner_desk_claim",
                json!({ "desk": desk, "operation_id": request_id }),
            )
            .await?;
        if r.get("claimed") != Some(&json!(true)) {
            return Err(ClaimError::Unavailable(
                "runner_desk_claim: not claimed".into(),
            ));
        }
        Ok(r.get("required_providers")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            }))
    }

    /// Release `desk` with the change's outcome, and its read-back after a
    /// `ready` change. Returns what the Enclave did (`freed`, …).
    ///
    /// # Errors
    /// The Enclave's refusal, or why it could not be asked; the desk then
    /// stays held.
    pub async fn release(
        &self,
        desk: &str,
        request_id: &str,
        outcome: Outcome,
        read_back: Option<&ReadBack>,
    ) -> Result<String, ClaimError> {
        let mut params =
            json!({ "desk": desk, "operation_id": request_id, "outcome": outcome.name() });
        if let Some(rb) = read_back {
            params["read_back"] = rb.wire();
        }
        let r = self.call("runner_desk_release", params).await?;
        r.get("released")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| ClaimError::Unavailable("runner_desk_release: no `released`".into()))
    }
}

/// The code at the start of a refusal's message (`CODE: why`), or
/// `REFUSED` when it names none.
fn refusal_code(message: &str) -> String {
    match message.split_once(':') {
        Some((code, _))
            if !code.is_empty() && code.bytes().all(|b| b.is_ascii_uppercase() || b == b'_') =>
        {
            code.to_string()
        }
        _ => "REFUSED".into(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "claims_tests.rs"]
mod tests;
