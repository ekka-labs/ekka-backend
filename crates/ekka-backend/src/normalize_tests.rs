#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::json;

use super::*;

fn policy() -> Value {
    json!({
        "version": 1,
        "filesystem": { "readOnly": ["/work"] },
        "networkPolicies": { "anthropic": {
            "name": "anthropic",
            "endpoints": [{ "host": "api.anthropic.com", "port": 443 }]
        } }
    })
}

#[test]
fn a_policy_with_defaults_left_out_and_written_in_has_one_digest() {
    // The same policy as the gateway may re-encode it: defaults spelled out,
    // proto field names instead of JSON names, the port as a string.
    let spelled = json!({
        "version": 1,
        "filesystem": { "include_workdir": false, "read_only": ["/work"], "readWrite": [] },
        "network_policies": { "anthropic": {
            "name": "anthropic",
            "endpoints": [{ "host": "api.anthropic.com", "port": "443", "protocol": "", "allowedIps": [] }],
            "binaries": []
        } },
        "networkMiddlewares": {}
    });
    assert_eq!(digest(POLICY, &policy()), digest(POLICY, &spelled));
    assert!(digest(POLICY, &policy()).is_some());
}

#[test]
fn the_injected_policy_validates_against_itself_after_a_round_trip() {
    // What the modify phase injects is the canonical form; whatever the
    // gateway re-encodes from it must hash the same.
    let injected = canonical(POLICY, &policy()).unwrap();
    assert_eq!(canonical(POLICY, &injected).unwrap(), injected);
    assert_eq!(digest(POLICY, &injected), digest(POLICY, &policy()));
}

#[test]
fn a_different_policy_has_a_different_digest() {
    let mut wider = policy();
    wider["networkPolicies"]["anthropic"]["endpoints"][0]["host"] = json!("*");
    assert_ne!(digest(POLICY, &policy()), digest(POLICY, &wider));
}

#[test]
fn planted_policies_the_pinned_proto_does_not_describe_are_refused() {
    for (what, v) in [
        (
            "an unknown field",
            json!({ "version": 1, "allowAll": true }),
        ),
        ("a wrong type", json!({ "version": "one" })),
        ("not an object", json!(["x"])),
        ("null", Value::Null),
    ] {
        assert_eq!(digest(POLICY, &v), None, "{what}");
    }
    assert_eq!(digest("openshell.v1.NoSuchType", &policy()), None);
}

#[test]
fn a_template_is_normalized_the_same_way() {
    let a = json!({ "image": "agent@sha256:ab" });
    let b = json!({ "image": "agent@sha256:ab", "runtimeClassName": "", "environment": {} });
    assert_eq!(digest(TEMPLATE, &a), digest(TEMPLATE, &b));
    assert!(digest(TEMPLATE, &a).is_some());
}

// A request policy and template, and their digests, exactly as EKKA Govern
// computes them: the guard that stops Govern, the published contracts and
// this adapter drifting. All three must reduce the same objects to the same
// digests, and they move together.
// - The policy is Govern's reference case. OpenShell adds its baseline paths
//   only when a network rule exists, so the mapping always lists them; and a
//   network rule with no binaries matches no program, so each names its
//   exact binaries.
// - The template is the contracts' sample direct request.
// Replace all four together when any of them changes.
const CONTRACTS_POLICY: &str = r#"{"filesystem":{"readOnly":["/app","/dev/urandom","/etc","/lib","/proc","/usr","/var/log"],"readWrite":["/dev/null","/sandbox/work","/tmp"]},"networkPolicies":{"github":{"binaries":[{"path":"/usr/bin/curl"}],"endpoints":[{"access":"NETWORK_ACCESS_PRESET_READ_ONLY","enforcement":"NETWORK_ENFORCEMENT_MODE_ENFORCE","host":"api.github.com","port":443,"protocol":"rest"}],"name":"github"}},"version":1}"#;
const CONTRACTS_TEMPLATE: &str = r#"{"image":"ghcr.io/example/sample-service-runtime@sha256:1111111111111111111111111111111111111111111111111111111111111111"}"#;
const CONTRACTS_POLICY_DIGEST: &str =
    "sha256:62f05344027223855452d985561daaa4ec5607f7f555d90fa643b014badde4f7";
const CONTRACTS_TEMPLATE_DIGEST: &str =
    "sha256:6a6315fe688d27f128484af422e6b85f0926e92d5f3f0c099591dfbc989182e7";

#[test]
fn the_contracts_fixture_reduces_to_the_contracts_digests() {
    let policy: Value = serde_json::from_str(CONTRACTS_POLICY).unwrap();
    let template: Value = serde_json::from_str(CONTRACTS_TEMPLATE).unwrap();
    assert!(canonical(POLICY, &policy).is_some());
    assert!(canonical(TEMPLATE, &template).is_some());
    assert_eq!(
        digest(POLICY, &policy).as_deref(),
        Some(CONTRACTS_POLICY_DIGEST)
    );
    assert_eq!(
        digest(TEMPLATE, &template).as_deref(),
        Some(CONTRACTS_TEMPLATE_DIGEST)
    );
}

#[test]
fn the_sent_message_has_the_digest_that_was_authorized() {
    use openshell_proto::openshell::sandbox::v1::SandboxPolicy;
    let sent: SandboxPolicy = message(POLICY, &policy()).unwrap();
    assert_eq!(message_digest(POLICY, &sent), digest(POLICY, &policy()));
    let mut wider = policy();
    wider["networkPolicies"]["anthropic"]["endpoints"][0]["host"] = json!("*");
    let other: SandboxPolicy = message(POLICY, &wider).unwrap();
    assert_ne!(message_digest(POLICY, &other), digest(POLICY, &policy()));
    assert!(message::<SandboxPolicy>(POLICY, &json!({ "allowAll": true })).is_none());
}
