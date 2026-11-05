use std::os::unix::fs::PermissionsExt;

use super::{Permit, Permits, PERMIT_SCHEMA};

const ID: &str = "00000000-0000-4000-8000-000000000001";
const OTHER: &str = "00000000-0000-4000-8000-000000000002";

fn uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn permit(id: &str, desk: &str) -> Permit {
    Permit {
        schema: PERMIT_SCHEMA.into(),
        workspace: "desks".into(),
        sandbox_id: id.into(),
        desk: desk.into(),
        expires_at: "2026-11-05T15:00:00Z".into(),
        operation_id: "o".into(),
    }
}

/// The vendored sample permit is one this adapter reads, and one it writes
/// back the same.
#[test]
fn the_contracts_sample_permit_reads() {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vendor/contracts/backend/samples/discovery-permit.json"
    ))
    .unwrap();
    let p: Permit = serde_json::from_str(&raw).unwrap();
    assert_eq!(p.schema, PERMIT_SCHEMA);
    let back: serde_json::Value = serde_json::to_value(&p).unwrap();
    assert_eq!(
        back,
        serde_json::from_str::<serde_json::Value>(&raw).unwrap()
    );
}

#[test]
fn a_permit_is_written_whole_as_0640_and_read_back() {
    let dir = tempfile::tempdir().unwrap();
    let p = Permits::open(dir.path(), uid()).unwrap();
    p.write(&permit(ID, "discover-a")).unwrap();
    let path = p.dir().join(format!("{ID}.json"));
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o640
    );
    assert_eq!(p.read(ID).unwrap(), Some(permit(ID, "discover-a")));
    assert_eq!(p.read(OTHER).unwrap(), None);
    // Nothing else is left in the folder.
    assert_eq!(std::fs::read_dir(p.dir()).unwrap().count(), 1);
    p.remove(ID).unwrap();
    assert_eq!(p.read(ID).unwrap(), None);
    // Removing one that is not there is fine.
    p.remove(ID).unwrap();
}

/// A permit is named only by a lowercase UUID: nothing else can name a file,
/// so no name leaves the folder.
#[test]
fn only_a_uuid_names_a_permit() {
    let dir = tempfile::tempdir().unwrap();
    let p = Permits::open(dir.path(), uid()).unwrap();
    for bad in [
        "../x",
        "discover-a",
        "",
        "00000000-0000-4000-8000-00000000000A",
    ] {
        assert!(p.write(&permit(bad, "discover-a")).is_err(), "{bad}");
        assert!(p.remove(bad).is_err(), "{bad}");
        assert!(p.read(bad).is_err(), "{bad}");
    }
    assert_eq!(std::fs::read_dir(p.dir()).unwrap().count(), 0);
}

/// A link where a permit should be is never read as one, and removing it
/// removes the link, not what it points to.
#[test]
fn a_link_is_never_a_permit() {
    let dir = tempfile::tempdir().unwrap();
    let p = Permits::open(dir.path(), uid()).unwrap();
    let target = dir.path().join("elsewhere.json");
    std::fs::write(
        &target,
        serde_json::to_vec(&permit(ID, "discover-a")).unwrap(),
    )
    .unwrap();
    std::os::unix::fs::symlink(&target, p.dir().join(format!("{ID}.json"))).unwrap();
    assert!(p.read(ID).is_err());
    p.remove(ID).unwrap();
    assert!(target.exists());
    assert!(!p.dir().join(format!("{ID}.json")).exists());
}

/// A file that is not a permit for its own id is refused.
#[test]
fn a_permit_for_another_id_or_schema_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let p = Permits::open(dir.path(), uid()).unwrap();
    let path = p.dir().join(format!("{ID}.json"));
    std::fs::write(
        &path,
        serde_json::to_vec(&permit(OTHER, "discover-a")).unwrap(),
    )
    .unwrap();
    assert!(p.read(ID).is_err());
    let mut wrong = permit(ID, "discover-a");
    wrong.schema = "something/v1".into();
    std::fs::write(&path, serde_json::to_vec(&wrong).unwrap()).unwrap();
    assert!(p.read(ID).is_err());
    std::fs::write(&path, b"{\"schema\":").unwrap();
    assert!(p.read(ID).is_err());
}

/// Every permit naming a desk goes, and only those.
#[test]
fn the_permits_of_one_desk_are_removed_by_its_name() {
    let dir = tempfile::tempdir().unwrap();
    let p = Permits::open(dir.path(), uid()).unwrap();
    p.write(&permit(ID, "discover-a")).unwrap();
    p.write(&permit(OTHER, "discover-b")).unwrap();
    p.remove_for_desk("discover-a").unwrap();
    assert_eq!(p.read(ID).unwrap(), None);
    assert!(p.read(OTHER).unwrap().is_some());
}

/// A folder open to others, or writable by its group, stops the adapter, and
/// is refused again at every use.
#[test]
fn an_unsafe_folder_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let p = Permits::open(dir.path(), uid()).unwrap();
    std::fs::set_permissions(p.dir(), std::fs::Permissions::from_mode(0o770)).unwrap();
    assert!(p.write(&permit(ID, "discover-a")).is_err());
    assert!(p.read(ID).is_err());
    assert!(Permits::open(dir.path(), uid())
        .err()
        .unwrap()
        .starts_with("STORE_UNSAFE"));
    std::fs::set_permissions(p.dir(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(Permits::open(dir.path(), uid()).is_err());
    std::fs::set_permissions(p.dir(), std::fs::Permissions::from_mode(0o750)).unwrap();
    assert!(Permits::open(dir.path(), uid()).is_ok());
    assert!(
        Permits::open(dir.path(), uid() + 1).is_err(),
        "another user's folder"
    );
}
