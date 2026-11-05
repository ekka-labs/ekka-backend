//! Discovery permits: the one file that lets a desk's network proposals be
//! approved automatically. The adapter writes one, at
//! `<state_dir>/permits/<sandbox id>.json`, only after NVIDIA OpenShell's
//! gateway reads the desk's approval mode back as `auto`, and removes it
//! before it turns the mode back to `manual` and before it deletes the desk.
//! The Enclave's interceptor reads it on every proposal: no permit, no
//! automatic approval.
//!
//! - A permit is named by the desk's immutable backend id (a lowercase
//!   UUID), never by its name, so a desk made again under the same name never
//!   inherits one.
//! - It is written whole or not at all: a temporary file in the same folder,
//!   synced, then renamed over the name, then the folder synced. Mode 0640:
//!   the interceptor reads it through the folder's group.
//! - The folder must be a real folder of the adapter's user, closed to others
//!   and not writable by its group; it is checked again at every use.
//! - Nothing here follows a symbolic link: a link where a permit should be is
//!   refused, and removing one removes the link, never what it points to.

use std::collections::HashMap;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

/// The permit's schema name.
pub const PERMIT_SCHEMA: &str = "ekka.backend.discovery_permit/v1";
/// The longest a permit lasts: it ends at this, or at its window's end if
/// that comes first.
pub const PERMIT_MINUTES: i64 = 60;
/// A permit file's mode: the interceptor reads it through the group.
const PERMIT_MODE: u32 = 0o640;
/// The permits folder's mode when the adapter makes it.
const DIR_MODE: u32 = 0o750;
/// The largest permit read.
const MAX_PERMIT: u64 = 4096;

/// `discovery-permit.v1`, closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Permit {
    pub schema: String,
    pub workspace: String,
    pub sandbox_id: String,
    pub desk: String,
    pub expires_at: String,
    pub operation_id: String,
}

/// The permits folder, and a lock per desk that keeps a permit's write and
/// its removal in one order inside this process.
pub struct Permits {
    dir: PathBuf,
    uid: u32,
    locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

/// A lowercase hyphenated UUID: the only name a permit file takes.
fn is_uuid(s: &str) -> bool {
    uuid::Uuid::parse_str(s).is_ok_and(|u| u.hyphenated().to_string() == s)
}

impl Permits {
    /// The permits folder under `state_dir`, made (0750) if missing.
    ///
    /// # Errors
    /// `STORE_UNSAFE` or `STORE_UNAVAILABLE`: the adapter does not start.
    pub fn open(state_dir: &Path, uid: u32) -> Result<Self, String> {
        let dir = state_dir.join("permits");
        if std::fs::symlink_metadata(&dir).is_err() {
            std::fs::DirBuilder::new()
                .mode(DIR_MODE)
                .create(&dir)
                .map_err(|e| format!("STORE_UNAVAILABLE: {}: {e}", dir.display()))?;
        }
        let p = Self {
            dir,
            uid,
            locks: Mutex::default(),
        };
        p.checked().map_err(|why| format!("STORE_UNSAFE: {why}"))?;
        Ok(p)
    }

    /// The folder is a real folder of this user, closed to others and not
    /// writable by its group.
    fn checked(&self) -> Result<(), String> {
        let m = std::fs::symlink_metadata(&self.dir)
            .map_err(|e| format!("{}: {e}", self.dir.display()))?;
        if !m.is_dir() || m.uid() != self.uid || m.mode() & 0o027 != 0 {
            return Err(format!(
                "{} must be a folder owned by uid {}, closed to others and not writable by its group",
                self.dir.display(),
                self.uid
            ));
        }
        Ok(())
    }

    /// The lock for `desk`: held across a whole `approval_mode` or a delete's
    /// removal, so a permit is never written after its removal began.
    pub async fn lock(&self, desk: &str) -> tokio::sync::OwnedMutexGuard<()> {
        let m = {
            let mut locks = self
                .locks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // Locks nobody holds or waits on are dropped, so the map stays small.
            locks.retain(|_, l| Arc::strong_count(l) > 1);
            locks.entry(desk.to_string()).or_default().clone()
        };
        m.lock_owned().await
    }

    fn path(&self, sandbox_id: &str) -> Option<PathBuf> {
        is_uuid(sandbox_id).then(|| self.dir.join(format!("{sandbox_id}.json")))
    }

    /// Write `permit` whole, under its sandbox id.
    ///
    /// # Errors
    /// Anything that stops it being written whole: nothing is left under the
    /// permit's name then.
    pub fn write(&self, permit: &Permit) -> Result<(), String> {
        self.checked()?;
        let path = self
            .path(&permit.sandbox_id)
            .ok_or("a permit is named by the desk's backend id, a lowercase UUID")?;
        let tmp = self.dir.join(format!(".{}.tmp", permit.sandbox_id));
        // Removes a link itself, never what it points to.
        match std::fs::remove_file(&tmp) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.to_string()),
            _ => {}
        }
        let body = serde_json::to_vec(permit).map_err(|e| e.to_string())?;
        let written = (|| -> std::io::Result<()> {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(PERMIT_MODE)
                .open(&tmp)?;
            // The mode is set outright: the process umask never narrows or
            // widens it.
            f.set_permissions(std::fs::Permissions::from_mode(PERMIT_MODE))?;
            f.write_all(&body)?;
            f.sync_all()?;
            std::fs::rename(&tmp, &path)?;
            std::fs::File::open(&self.dir)?.sync_all()
        })();
        if let Err(e) = written {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.to_string());
        }
        Ok(())
    }

    /// Remove the permit for `sandbox_id`; none is fine.
    ///
    /// # Errors
    /// The folder is unsafe, the id is not a UUID, or the file is there and
    /// cannot be removed.
    pub fn remove(&self, sandbox_id: &str) -> Result<(), String> {
        self.checked()?;
        let path = self
            .path(sandbox_id)
            .ok_or("a permit is named by the desk's backend id, a lowercase UUID")?;
        self.unlink(&path)
    }

    fn unlink(&self, path: &Path) -> Result<(), String> {
        match std::fs::remove_file(path) {
            Ok(()) => std::fs::File::open(&self.dir)
                .and_then(|d| d.sync_all())
                .map_err(|e| e.to_string()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Remove every permit that names `desk`, read from the folder alone, so
    /// it needs no answer from the desk backend. A file that does not read
    /// as a permit names no desk and is left (its sandbox id's own removal
    /// takes it).
    ///
    /// # Errors
    /// The folder is unsafe or cannot be listed, or a permit naming `desk`
    /// cannot be removed.
    pub fn remove_for_desk(&self, desk: &str) -> Result<(), String> {
        self.checked()?;
        let entries = std::fs::read_dir(&self.dir).map_err(|e| e.to_string())?;
        for entry in entries {
            let entry = entry.map_err(|e| e.to_string())?;
            let name = entry.file_name();
            let Some(id) = name.to_str().and_then(|n| n.strip_suffix(".json")) else {
                continue;
            };
            if !is_uuid(id) {
                continue;
            }
            if let Ok(Some(p)) = self.read(id) {
                if p.desk == desk {
                    self.unlink(&entry.path())?;
                }
            }
        }
        Ok(())
    }

    /// The permit for `sandbox_id`, if one is there.
    ///
    /// # Errors
    /// The folder is unsafe, or a file is there that is not a regular file,
    /// cannot be read, is too large, or is not a `discovery-permit.v1`.
    pub fn read(&self, sandbox_id: &str) -> Result<Option<Permit>, String> {
        self.checked()?;
        let path = self
            .path(sandbox_id)
            .ok_or("a permit is named by the desk's backend id, a lowercase UUID")?;
        let before = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.to_string()),
        };
        if !before.file_type().is_file() || before.uid() != self.uid {
            return Err("a permit must be a regular file of the adapter's user".into());
        }
        let file = std::fs::File::open(&path).map_err(|e| e.to_string())?;
        let opened = file.metadata().map_err(|e| e.to_string())?;
        if (opened.dev(), opened.ino()) != (before.dev(), before.ino()) {
            return Err("the permit changed while it was read".into());
        }
        let mut raw = Vec::new();
        file.take(MAX_PERMIT + 1)
            .read_to_end(&mut raw)
            .map_err(|e| e.to_string())?;
        if raw.len() as u64 > MAX_PERMIT {
            return Err("the permit is too large".into());
        }
        let p: Permit = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
        if p.schema != PERMIT_SCHEMA || p.sandbox_id != sandbox_id {
            return Err("not a discovery permit for this desk backend id".into());
        }
        Ok(Some(p))
    }

    /// The folder, for tests.
    #[cfg(test)]
    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "permits_tests.rs"]
mod tests;
