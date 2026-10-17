use serde_json::{json, Value};

use super::{config_digest_of, desk_digest, Input, PROVIDER};
use crate::digest::json_digest;
use crate::normalize::{message, PROVIDER_PROFILE};

/// `tests/fixtures/provider-github.json`: a GitHub provider and its profile, a record whose credential reads `REDACTED`.
fn input() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/provider-github.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn parts(
    v: &Value,
) -> (
    String,
    openshell_proto::openshell::datamodel::v1::Provider,
    openshell_proto::openshell::v1::ProviderProfile,
) {
    (
        v["name"].as_str().unwrap().to_string(),
        message(PROVIDER, &v["provider"]).unwrap(),
        message(PROVIDER_PROFILE, &v["profile"]).unwrap(),
    )
}

/// THE ENCLAVE'S DIGEST, BYTE FOR BYTE. This value is what the Enclave
/// computes for this exact input; the adapter must give the same, so the
/// Enclave's pin and the adapter's checks never disagree.
#[test]
fn the_desk_digest_is_the_runners() {
    let (name, p, f) = parts(&input());
    assert_eq!(
        desk_digest(&[(&name, &p, &f)]).unwrap(),
        "sha256:714936d534eaa6ecf766f1b0214048e0de0077f155b591ba5231796076ee6b09"
    );
}

/// One provider's config digest is `json_digest` of exactly the one entry the
/// desk digest is built from: the desk digest over one provider is the same
/// entry, wrapped.
#[test]
fn a_config_digest_is_the_one_entry_the_desk_digest_wraps() {
    let v = input();
    let one = config_digest_of(&serde_json::from_value::<Input>(v.clone()).unwrap()).unwrap();
    let (name, p, f) = parts(&v);
    let entry = super::entry(&name, &p, &f).unwrap();
    assert_eq!(one, json_digest(&entry));
    assert_eq!(
        desk_digest(&[(&name, &p, &f)]).unwrap(),
        json_digest(&json!({ "providers": [entry] }))
    );
    assert_ne!(one, desk_digest(&[(&name, &p, &f)]).unwrap());
}

/// A credential value is refused, named by its key, and never appears in the
/// answer.
#[test]
fn a_credential_value_is_refused_and_never_shown() {
    let mut v = input();
    v["provider"]["credentials"]["GITHUB_TOKEN"] = json!("ghp_PLANTEDsecretVALUE0123456789");
    let e = config_digest_of(&serde_json::from_value::<Input>(v).unwrap()).unwrap_err();
    assert!(
        e.starts_with("PROVIDER_CREDENTIAL_NOT_REDACTED") && e.contains("GITHUB_TOKEN"),
        "{e}"
    );
    assert!(!e.contains("ghp_PLANTED"), "{e}");
}

#[test]
fn display_text_does_not_move_it_and_a_host_or_a_setting_does() {
    let base = config_digest_of(&serde_json::from_value::<Input>(input()).unwrap()).unwrap();
    let digest = |f: &dyn Fn(&mut Value)| {
        let mut v = input();
        f(&mut v);
        config_digest_of(&serde_json::from_value::<Input>(v).unwrap()).unwrap()
    };
    assert_eq!(
        base,
        digest(&|v| v["profile"]["displayName"] = json!("GitHub, renamed"))
    );
    assert_ne!(
        base,
        digest(&|v| v["provider"]["config"]["org"] = json!("other"))
    );
    assert_ne!(base, digest(&|v| v["name"] = json!("github-2")));
    assert_ne!(
        base,
        digest(&|v| v["profile"]["endpoints"][0]["host"] = json!("evil.example.com"))
    );
}

#[test]
fn an_input_that_is_not_the_agreed_shape_is_refused() {
    let mut v = input();
    v["extra"] = json!(1);
    assert!(
        serde_json::from_value::<Input>(v).is_err(),
        "an unknown top-level key"
    );
    let mut v = input();
    v["provider"]["notAField"] = json!(true);
    let e = config_digest_of(&serde_json::from_value::<Input>(v).unwrap()).unwrap_err();
    assert!(e.starts_with("PROVIDER_INPUT_INVALID"), "{e}");
    let mut v = input();
    v["name"] = json!("GitHub");
    let e = config_digest_of(&serde_json::from_value::<Input>(v).unwrap()).unwrap_err();
    assert!(e.starts_with("PROVIDER_INPUT_INVALID"), "{e}");
}
