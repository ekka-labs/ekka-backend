//! The operation records: one file per change, written BEFORE
//! the change reaches the gateway, so a redelivered call is answered from
//! the record and never executed twice.
//!
//! `<state_dir>/operations/<request id>.json`, mode 0600, in a folder that
//! belongs to the adapter's user and is closed to everyone else (the adapter
//! refuses to start otherwise). A record is created new (a second one for
//! the same id is refused), flushed with its folder, and replaced only by an
//! atomic rename. It holds the change's request in full (its body carries no
//! secret: no credential is ever a plan input), the digest it is
//! matched by, the ORIGINAL signed gate token (a signed authorization pinned
//! to this one operation, re-checked on recovery by `verify_stored`), when
//! it was admitted, and, once settled, the answer. Never the backend
//! credential. Beside it, `<state_dir>/running/<request id>` (an empty file)
//! names each change still running, so recovery reads only those.

use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::answer::{Answer, Delivery};
use crate::routes::Route;

/// The largest record read: a body is at most 1 MiB, the token 16 KiB.
const MAX_RECORD: u64 = 4 * 1024 * 1024;

/// Where an operation stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// Admitted; no final answer yet. It may still be changing the desk.
    Running,
    /// Answered: the recorded answer is final.
    Settled,
}

/// One operation's record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub version: u32,
    pub request_id: String,
    pub operation: String,
    pub desk: String,
    #[serde(default)]
    pub provider: Option<String>,
    /// [`request_digest`] of the call that admitted it.
    pub request_digest: String,
    /// The request body, standard base64.
    pub body_b64: String,
    /// The `X-EKKA-Gate-Token` header exactly as it arrived.
    pub gate_token: String,
    /// The `X-EKKA-Operation-Id` header it arrived with: the stored token's
    /// run is checked against it on recovery (`verify_stored`).
    #[serde(default)]
    pub operation_id_header: String,
    /// When it was admitted, RFC 3339 UTC.
    pub admitted_at: String,
    /// When its latest send STARTED, RFC 3339 UTC: written, durably,
    /// immediately before the gateway call, with nothing awaited between.
    /// None means it was never sent.
    #[serde(default)]
    pub last_sent_at: Option<String>,
    /// The adapter process that started that send: random per process
    /// start, never reused.
    #[serde(default)]
    pub last_send_boot: Option<String>,
    /// When that send ENDED (the gateway call returned, whatever it
    /// answered), RFC 3339 UTC. A start with no end after it is a send still
    /// in flight, or one whose process died during it. A settle marker
    /// counts only for a gateway restarted after the send ended, or, when it
    /// never ended, after the process that sent it was gone.
    #[serde(default)]
    pub last_send_ended_at: Option<String>,
    pub state: State,
    /// The backend's id for the desk, written before a change whose
    /// read-back must name it (a delete: once the desk is gone it cannot be
    /// read).
    #[serde(default)]
    pub backend_id: Option<String>,
    /// The final answer, once settled.
    #[serde(default)]
    pub answer: Option<Answer>,
}

impl Record {
    /// The recorded answer delivered again: the same outcome and facts, as
    /// `duplicate` (a refusal delivered twice stays refused).
    #[must_use]
    pub fn duplicate(&self) -> Option<Answer> {
        self.answer.clone().map(|mut a| {
            a.delivery = Delivery::Duplicate;
            a
        })
    }
}

/// The digest a redelivery is matched by: the operation, its desk, its
/// provider and its body. The same operation id with another digest is
/// another request, refused `OPERATION_ID_REUSED`.
#[must_use]
pub fn request_digest(route: &Route, body: &[u8]) -> String {
    let mut h = Sha256::new();
    for part in [
        route.operation.name().as_bytes(),
        route.desk.as_deref().unwrap_or_default().as_bytes(),
        route.provider.as_deref().unwrap_or_default().as_bytes(),
    ] {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part);
    }
    h.update((body.len() as u64).to_be_bytes());
    h.update(body);
    format!("sha256:{:x}", h.finalize())
}

/// Why the store could not do what was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// A record for this id already exists.
    Exists,
    Io(String),
}

/// The records, under one folder, and beside it the index of the ones still
/// running (`<state_dir>/running/<request id>`, empty files), so finding a
/// desk's running changes never reads every record ever kept.
#[derive(Debug)]
pub struct Store {
    dir: PathBuf,
    running: PathBuf,
    /// Tests only: this many settle writes fail.
    #[cfg(test)]
    pub(crate) fail_settles: std::sync::atomic::AtomicUsize,
}

/// A lowercase hyphenated UUID: the only names a record file has.
fn plain_id(id: &str) -> bool {
    uuid::Uuid::parse_str(id).is_ok_and(|u| u.hyphenated().to_string() == id)
}

impl Store {
    /// The store under `state_dir`, made if missing. The state folder and the
    /// records folder must belong to `uid` and be closed to group and others.
    ///
    /// # Errors
    /// `STORE_UNSAFE` or `STORE_UNAVAILABLE`: the adapter does not start.
    pub fn open(state_dir: &Path, uid: u32) -> Result<Self, String> {
        let dir = state_dir.join("operations");
        let running = state_dir.join("running");
        for d in [state_dir, dir.as_path(), running.as_path()] {
            if !d.exists() {
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .recursive(true)
                    .create(d)
                    .map_err(|e| format!("STORE_UNAVAILABLE: {}: {e}", d.display()))?;
            }
            let m = std::fs::symlink_metadata(d)
                .map_err(|e| format!("STORE_UNAVAILABLE: {}: {e}", d.display()))?;
            if !m.is_dir() || m.uid() != uid || m.mode() & 0o077 != 0 {
                return Err(format!(
                    "STORE_UNSAFE: {} must be a folder owned by uid {uid} and closed to group and others",
                    d.display()
                ));
            }
        }
        Ok(Self {
            dir,
            running,
            #[cfg(test)]
            fail_settles: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    fn path(&self, id: &str) -> Option<PathBuf> {
        plain_id(id).then(|| self.dir.join(format!("{id}.json")))
    }

    /// The record for `request_id`, if any.
    ///
    /// # Errors
    /// The record exists but cannot be read or parsed: never treated as
    /// absent, so an unreadable record is never executed again.
    pub fn get(&self, request_id: &str) -> Result<Option<Record>, StoreError> {
        let path = self
            .path(request_id)
            .ok_or_else(|| StoreError::Io("not a request id".into()))?;
        let file = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(StoreError::Io(e.to_string())),
        };
        let mut raw = Vec::new();
        std::io::Read::read_to_end(&mut std::io::Read::take(file, MAX_RECORD), &mut raw)
            .map_err(|e| StoreError::Io(e.to_string()))?;
        serde_json::from_slice(&raw)
            .map(Some)
            .map_err(|e| StoreError::Io(format!("{}: {e}", path.display())))
    }

    /// Create `rec` as a new record, flushed with its folder, BEFORE anything
    /// is sent for it.
    ///
    /// # Errors
    /// [`StoreError::Exists`] when the id has a record; otherwise the write.
    pub fn begin(&self, rec: &Record) -> Result<(), StoreError> {
        let path = self
            .path(&rec.request_id)
            .ok_or_else(|| StoreError::Io("not a request id".into()))?;
        // Indexed BEFORE the record: a crash between the two leaves an index
        // entry with no record, which is skipped; never a running record no
        // index names.
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(self.running.join(&rec.request_id))
            .and_then(|_| std::fs::File::open(&self.running)?.sync_all())
            .map_err(|e| StoreError::Io(e.to_string()))?;
        let mut f = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(StoreError::Exists)
            }
            Err(e) => return Err(StoreError::Io(e.to_string())),
        };
        let body = serde_json::to_vec(rec).map_err(|e| StoreError::Io(e.to_string()))?;
        f.write_all(&body)
            .and_then(|()| f.sync_all())
            .map_err(|e| StoreError::Io(e.to_string()))?;
        self.sync_dir()
    }

    /// Settle `request_id` with its final answer: replaced in one rename.
    ///
    /// # Errors
    /// The record is missing or the write fails; it then stays `running`.
    pub fn settle(&self, request_id: &str, answer: &Answer) -> Result<(), StoreError> {
        #[cfg(test)]
        {
            use std::sync::atomic::Ordering;
            let left = self.fail_settles.load(Ordering::SeqCst);
            if left > 0 {
                self.fail_settles.store(left - 1, Ordering::SeqCst);
                return Err(StoreError::Io("planted: the settle write fails".into()));
            }
        }
        let mut rec = self
            .get(request_id)?
            .ok_or_else(|| StoreError::Io("no record".into()))?;
        rec.state = State::Settled;
        rec.answer = Some(answer.clone());
        self.replace(&rec)?;
        // Out of the index AFTER the record settled: a crash between the two
        // leaves an entry whose record is settled, which is skipped.
        match std::fs::remove_file(self.running.join(request_id)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                tracing::warn!(request_id, error = %e, "runningIndexNotCleared");
            }
            _ => {}
        }
        Ok(())
    }

    /// Note the backend's id for a running change, before it is sent.
    ///
    /// # Errors
    /// The record is missing or the write fails.
    pub fn note_backend_id(&self, request_id: &str, backend_id: &str) -> Result<(), StoreError> {
        let mut rec = self
            .get(request_id)?
            .ok_or_else(|| StoreError::Io("no record".into()))?;
        rec.backend_id = Some(backend_id.to_string());
        self.replace(&rec)
    }

    /// Note that `request_id`'s send STARTS, at `at`, in process `boot`,
    /// immediately BEFORE the gateway call. Its end is cleared: the send is
    /// in flight until [`Store::note_send_ended`].
    ///
    /// # Errors
    /// The record is missing or the write fails: then it is not sent.
    pub fn note_sent(
        &self,
        request_id: &str,
        at: chrono::DateTime<chrono::Utc>,
        boot: &str,
    ) -> Result<(), StoreError> {
        let mut rec = self
            .get(request_id)?
            .ok_or_else(|| StoreError::Io("no record".into()))?;
        // Full precision: a restart in the same second, before the send,
        // must not pass for one after it.
        rec.last_sent_at = Some(at.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true));
        rec.last_send_boot = Some(boot.to_string());
        rec.last_send_ended_at = None;
        self.replace(&rec)
    }

    /// Note that `request_id`'s send ENDED, at `at`: the gateway call
    /// returned, whatever it answered.
    ///
    /// # Errors
    /// The record is missing or the write fails: the send then stays in
    /// flight, so no marker counts for it while this process runs.
    pub fn note_send_ended(
        &self,
        request_id: &str,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), StoreError> {
        let mut rec = self
            .get(request_id)?
            .ok_or_else(|| StoreError::Io("no record".into()))?;
        rec.last_send_ended_at = Some(at.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true));
        self.replace(&rec)
    }

    /// Every change on `desk` still `running`, found through the index.
    ///
    /// # Errors
    /// The index cannot be read, or a record it names cannot: never taken
    /// for "none", so an unreadable record keeps the desk unresolved.
    pub fn running_for(&self, desk: &str) -> Result<Vec<Record>, StoreError> {
        let mut out = Vec::new();
        for e in std::fs::read_dir(&self.running).map_err(|e| StoreError::Io(e.to_string()))? {
            let e = e.map_err(|e| StoreError::Io(e.to_string()))?;
            let id = e.file_name().to_string_lossy().to_string();
            if !plain_id(&id) {
                continue;
            }
            if let Some(rec) = self.get(&id)? {
                if rec.state == State::Running && rec.desk == desk {
                    out.push(rec);
                }
            }
        }
        out.sort_by(|a, b| a.admitted_at.cmp(&b.admitted_at));
        Ok(out)
    }

    fn replace(&self, rec: &Record) -> Result<(), StoreError> {
        let path = self
            .path(&rec.request_id)
            .ok_or_else(|| StoreError::Io("not a request id".into()))?;
        let tmp = self.dir.join(format!(".{}.tmp", rec.request_id));
        let _ = std::fs::remove_file(&tmp);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| StoreError::Io(e.to_string()))?;
        let body = serde_json::to_vec(rec).map_err(|e| StoreError::Io(e.to_string()))?;
        f.write_all(&body)
            .and_then(|()| f.sync_all())
            .map_err(|e| StoreError::Io(e.to_string()))?;
        std::fs::rename(&tmp, &path).map_err(|e| StoreError::Io(e.to_string()))?;
        self.sync_dir()
    }

    fn sync_dir(&self) -> Result<(), StoreError> {
        std::fs::File::open(&self.dir)
            .and_then(|d| d.sync_all())
            .map_err(|e| StoreError::Io(e.to_string()))
    }
}

/// A new `running` record for an admitted call on `desk` (a create's desk is
/// its body's name: its route names none).
#[must_use]
pub fn running(
    route: &Route,
    desk: &str,
    request_id: &str,
    operation_id_header: &str,
    body: &[u8],
    gate_token: &str,
    admitted_at: chrono::DateTime<chrono::Utc>,
) -> Record {
    Record {
        version: 1,
        request_id: request_id.to_string(),
        operation: route.operation.name().to_string(),
        desk: desk.to_string(),
        provider: route.provider.clone(),
        request_digest: request_digest(route, body),
        body_b64: base64::engine::general_purpose::STANDARD.encode(body),
        gate_token: gate_token.to_string(),
        operation_id_header: operation_id_header.to_string(),
        admitted_at: admitted_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        // Noted by the driver before the first send, after its claim and
        // every check: none means it was never sent.
        last_sent_at: None,
        last_send_boot: None,
        last_send_ended_at: None,
        state: State::Running,
        backend_id: None,
        answer: None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "store_tests.rs"]
mod tests;
