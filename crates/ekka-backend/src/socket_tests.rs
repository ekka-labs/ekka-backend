use std::os::unix::fs::{MetadataExt, PermissionsExt};

use super::bind;

fn uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// A socket directory as the kit makes it: this user's, 0700. Under /tmp: a
/// Unix socket path is limited to about 100 bytes, and macOS's own temporary
/// folders are longer than that.
pub(crate) fn dir() -> tempfile::TempDir {
    let d = tempfile::Builder::new()
        .prefix("eb")
        .tempdir_in("/tmp")
        .unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

#[tokio::test]
async fn it_listens_0600_in_a_closed_directory_and_replaces_its_own_old_socket() {
    let d = dir();
    let path = d.path().join("backend.sock");
    let l = bind(&path, uid()).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
    drop(l);
    // The socket file of an earlier run is still there; a restart replaces it.
    bind(&path, uid()).unwrap();
}

#[tokio::test]
async fn a_directory_open_to_others_or_someone_elses_is_refused() {
    let d = dir();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
    let e = bind(&d.path().join("backend.sock"), uid()).unwrap_err();
    assert!(e.contains("open to group or others"), "{e}");
    assert!(
        e.ends_with(&format!("fix: chmod 0700 {}", d.path().display())),
        "{e}"
    );

    let d = dir();
    let other = uid().wrapping_add(1).max(1);
    let e = bind(&d.path().join("backend.sock"), other).unwrap_err();
    assert!(e.contains("not this process's"), "{e}");
    assert!(
        e.ends_with(&format!("fix: chown {other} {}", d.path().display())),
        "{e}"
    );
}

/// The plan's acceptance: a planted symlink refuses start.
#[tokio::test]
async fn a_symlink_at_the_socket_path_or_as_the_directory_refuses_start() {
    let d = dir();
    let target = d.path().join("elsewhere.sock");
    std::fs::write(&target, b"").unwrap();
    let path = d.path().join("backend.sock");
    std::os::unix::fs::symlink(&target, &path).unwrap();
    let e = bind(&path, uid()).unwrap_err();
    assert!(e.contains("is a symlink"), "{e}");
    assert!(target.exists(), "the link's target is left alone");

    let real = dir();
    let holder = tempfile::Builder::new()
        .prefix("eb")
        .tempdir_in("/tmp")
        .unwrap();
    let linked_dir = holder.path().join("run");
    std::os::unix::fs::symlink(real.path(), &linked_dir).unwrap();
    let e = bind(&linked_dir.join("backend.sock"), uid()).unwrap_err();
    assert!(e.contains("not a real directory"), "{e}");
}

#[tokio::test]
async fn a_file_that_is_not_our_socket_is_refused_and_left_alone() {
    let d = dir();
    let path = d.path().join("backend.sock");
    std::fs::write(&path, b"keep me").unwrap();
    let e = bind(&path, uid()).unwrap_err();
    assert!(e.contains("left alone"), "{e}");
    assert_eq!(std::fs::read(&path).unwrap(), b"keep me");
}
