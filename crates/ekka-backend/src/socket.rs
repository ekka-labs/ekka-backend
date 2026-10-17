//! The adapter's one listening socket: `/run/ekka-backend/
//! backend.sock` by default, the location the Enclave, the kit's volume and
//! the catalog row all name.
//!
//! The adapter refuses to start unless the socket's directory is a real
//! directory owned by this process's user with no group or other bits, and
//! unless the socket path is not a symlink. A socket left by an earlier run of
//! this user is replaced; anything else in its place is refused, never
//! removed. The socket is created 0600.

use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::Path;

use tokio::net::UnixListener;

/// Check the directory and path, then bind.
///
/// # Errors
/// Why the adapter must not listen there.
pub fn bind(path: &Path, uid: u32) -> Result<UnixListener, String> {
    let shown = path.display();
    let dir = path
        .parent()
        .ok_or_else(|| format!("SOCKET_UNSAFE: {shown} has no directory"))?;
    let d = std::fs::symlink_metadata(dir).map_err(|e| {
        format!(
            "SOCKET_UNSAFE: the socket directory {} cannot be read: {e}",
            dir.display()
        )
    })?;
    if d.file_type().is_symlink() || !d.is_dir() {
        return Err(format!(
            "SOCKET_UNSAFE: {} is not a real directory",
            dir.display()
        ));
    }
    if d.uid() != uid {
        return Err(format!(
            "SOCKET_UNSAFE: {} belongs to uid {}, not this process's ({uid}); fix: chown {uid} {}",
            dir.display(),
            d.uid(),
            dir.display()
        ));
    }
    if d.mode() & 0o077 != 0 {
        return Err(format!(
            "SOCKET_UNSAFE: {} is open to group or others (mode {:o}); fix: chmod 0700 {}",
            dir.display(),
            d.mode() & 0o777,
            dir.display()
        ));
    }
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => {
            return Err(format!("SOCKET_UNSAFE: {shown} is a symlink"));
        }
        Ok(m) if m.file_type().is_socket() && m.uid() == uid => {
            std::fs::remove_file(path).map_err(|e| {
                format!("SOCKET_UNSAFE: the old socket {shown} cannot be removed: {e}")
            })?;
        }
        Ok(_) => {
            return Err(format!(
                "SOCKET_UNSAFE: {shown} exists and is not this user's socket; it is left alone"
            ));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("SOCKET_UNSAFE: {shown} cannot be read: {e}")),
    }
    let listener = UnixListener::bind(path)
        .map_err(|e| format!("SOCKET_UNSAFE: cannot listen on {shown}: {e}"))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("SOCKET_UNSAFE: cannot make {shown} 0600: {e}"))?;
    Ok(listener)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "socket_tests.rs"]
pub(crate) mod tests;
