use super::*;
#[test]
fn body_refuses_non_uuid_and_cross_workspace_references() {
    let mut b = ConnectBody {
        name: "github".into(),
        r#type: "github".into(),
        profile_workspace: String::new(),
        config: HashMap::new(),
        credential_refs: BTreeMap::new(),
        expected_resource_version: None,
    };
    assert!(b.check("desks").is_ok());
    b.credential_refs
        .insert("api_key".into(), "API_CREDENTIAL_BACKEND".into());
    assert!(b.check("desks").is_err());
    b.credential_refs.clear();
    b.profile_workspace = "other".into();
    assert!(b.check("desks").is_err());
}
