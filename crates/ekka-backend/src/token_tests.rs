//! Token verification: a Govern-minted token is accepted; each planted
//! wrong key, lifetime, replay, resource, contract and verb is refused with
//! the contract's code, before anything could reach the backend.

use base64::Engine as _;
use chrono::Duration;
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};

use crate::answer::Code;
use crate::routes::Operation;
use crate::testkit::{
    at, b64, call, fixture, govern_test_key, header, op_id, token, verifier, NOW, RUN, TASK,
};

#[test]
fn govern_s_test_key_is_the_one_its_fixture_names() {
    assert_eq!(
        b64(govern_test_key().verifying_key().as_bytes()),
        fixture()["gate_token_public_key_b64"]
    );
}

/// A token MINTED BY GOVERN'S REAL PATH is accepted: signature over
/// its carried bytes, its key id, organization, instance, contract, resource
/// and lifetime, and its grant's limits are the closed desks.v1 shape.
#[test]
fn govern_s_minted_token_verifies() {
    let f = fixture();
    let k = govern_test_key();
    let v = verifier(
        &[("govern-gate-token-v1", &k)],
        f["minted_at"].as_str().unwrap(),
    );
    let header = b64(&serde_json::to_vec(&f["signed"]).unwrap());
    let t = v.verify_signed(&header).unwrap();
    assert_eq!(t.token_id, f["token"]["token_id"]);
    assert_eq!(t.op, "write");
    crate::constraints::check(t.grant.as_ref().unwrap()).unwrap();
}

#[test]
fn a_whole_call_with_a_govern_signed_token_is_verified() {
    let k = govern_test_key();
    let v = verifier(&[("govern-gate-token-v1", &k)], NOW);
    let h = header(&token(), "govern-gate-token-v1", &k);
    let id = op_id();
    let ok = v.verify(&call(Operation::Stop, &h, &id, b"")).unwrap();
    assert_eq!(
        (ok.run_id.as_str(), ok.operation_id.as_str()),
        (RUN, id.as_str())
    );
    assert!(ok.grant.is_some());
}

/// Each planted call is refused with its code: the verifier answers before
/// any operation runs, so nothing reaches the backend.
#[test]
fn each_planted_call_is_refused_with_its_code() {
    let k = govern_test_key();
    let other = SigningKey::from_bytes(&[9; 32]);
    let v = || verifier(&[("govern-gate-token-v1", &k)], NOW);
    let id = op_id();
    let good = || token();
    let with = |f: &dyn Fn(&mut Value)| {
        let mut t = good();
        f(&mut t);
        header(&t, "govern-gate-token-v1", &k)
    };
    let cases: Vec<(&str, Code, String, Operation, Vec<u8>)> = vec![
        (
            "signed by another key",
            Code::TokenInvalid,
            header(&good(), "govern-gate-token-v1", &other),
            Operation::Stop,
            vec![],
        ),
        (
            "a key id the config does not list",
            Code::TokenInvalid,
            header(&good(), "govern-gate-token-v2", &k),
            Operation::Stop,
            vec![],
        ),
        (
            "expired",
            Code::TokenExpired,
            with(&|t| t["expires_at"] = json!("2026-10-15T00:09:00Z")),
            Operation::Stop,
            vec![],
        ),
        (
            "not yet valid",
            Code::TokenExpired,
            with(&|t| t["issued_at"] = json!("2026-10-15T00:11:00Z")),
            Operation::Stop,
            vec![],
        ),
        (
            "another resource",
            Code::TokenScope,
            with(&|t| t["scope"]["resource"] = json!("apis/slack")),
            Operation::Stop,
            vec![],
        ),
        (
            "another contract",
            Code::TokenScope,
            with(&|t| t["scope"]["contract"] = json!("ekka.gate.mcp.v1")),
            Operation::Stop,
            vec![],
        ),
        (
            "another organization",
            Code::TokenScope,
            with(&|t| t["tenant_id"] = json!("22222222-2222-4222-8222-222222222222")),
            Operation::Stop,
            vec![],
        ),
        (
            "another api gate",
            Code::TokenScope,
            with(&|t| t["scope"]["instance"] = json!("enclave00000000Api")),
            Operation::Stop,
            vec![],
        ),
        (
            "a read grant on a write route",
            Code::TokenScope,
            with(&|t| t["scope"]["op"] = json!("read")),
            Operation::Stop,
            vec![],
        ),
        (
            "another run",
            Code::TokenScope,
            with(&|t| t["run_id"] = json!("9b3d5f7a-1c2e-4a6b-8d9f-0e1a2b3c4d5e")),
            Operation::Stop,
            vec![],
        ),
        (
            "a body the pin does not match",
            Code::TokenScope,
            with(&|_| {}),
            Operation::Stop,
            b"{}".to_vec(),
        ),
        (
            "a write with no body pin",
            Code::TokenScope,
            with(&|t| {
                t["constraints"]
                    .as_object_mut()
                    .unwrap()
                    .remove("body_sha256");
            }),
            Operation::Stop,
            vec![],
        ),
        (
            "a write with no grant",
            Code::ConstraintsInvalid,
            with(&|t| {
                t["constraints"].as_object_mut().unwrap().remove("grant");
            }),
            Operation::Stop,
            vec![],
        ),
        (
            "a grant with an unknown limit",
            Code::ConstraintsInvalid,
            with(&|t| t["constraints"]["grant"]["max_desks"] = json!(3)),
            Operation::Stop,
            vec![],
        ),
        // an API-gate token's constraints are CLOSED in the
        // published gate-token schema: `grant` and `body_sha256` only.
        (
            "a correctly signed token with an extra constraint",
            Code::ConstraintsInvalid,
            with(&|t| t["constraints"]["max_desks"] = json!(3)),
            Operation::Stop,
            vec![],
        ),
        (
            "constraints that are not an object",
            Code::ConstraintsInvalid,
            with(&|t| t["constraints"] = json!("grant")),
            Operation::Stop,
            vec![],
        ),
        (
            "a body pin that is not 64 lowercase hex",
            Code::ConstraintsInvalid,
            with(&|t| {
                let pin = t["constraints"]["body_sha256"]
                    .as_str()
                    .unwrap()
                    .to_uppercase();
                t["constraints"]["body_sha256"] = json!(pin);
            }),
            Operation::Stop,
            vec![],
        ),
        (
            "another token schema",
            Code::TokenInvalid,
            with(&|t| t["schema"] = json!("ekka.gate_token.v2")),
            Operation::Stop,
            vec![],
        ),
    ];
    for (why, code, h, op, body) in &cases {
        assert_eq!(
            v().verify(&call(*op, h, &id, body)).unwrap_err(),
            *code,
            "{why}"
        );
    }
}

#[test]
fn a_used_token_is_refused_as_a_replay() {
    let k = govern_test_key();
    let v = verifier(&[("govern-gate-token-v1", &k)], NOW);
    let h = header(&token(), "govern-gate-token-v1", &k);
    let id = op_id();
    v.verify(&call(Operation::Stop, &h, &id, b""))
        .unwrap()
        .admit()
        .unwrap();
    assert_eq!(
        v.verify(&call(Operation::Stop, &h, &id, b""))
            .unwrap()
            .admit()
            .unwrap_err(),
        Code::TokenReplayed
    );
}

/// The ORDER OF CHECKS: verifying a call
/// consumes nothing, so a redelivered call for a KNOWN operation can be
/// answered from the durable store without executing. On main before this
/// change the second `verify` below answered TOKEN_REPLAYED. Only `admit`
/// consumes the token, once.
#[test]
fn a_verified_call_consumes_nothing_until_it_is_admitted() {
    let k = govern_test_key();
    let v = verifier(&[("govern-gate-token-v1", &k)], NOW);
    let h = header(&token(), "govern-gate-token-v1", &k);
    let id = op_id();
    let first = v.verify(&call(Operation::Stop, &h, &id, b"")).unwrap();
    let again = v.verify(&call(Operation::Stop, &h, &id, b"")).unwrap();
    assert_eq!(first.token_id, again.token_id);
    first.admit().unwrap();
    assert_eq!(again.admit().unwrap_err(), Code::TokenReplayed);
}

/// The recovery path's narrow check: a STORED token, re-checked at
/// the time its operation was admitted. Accepted after its expiry when the
/// admission was inside its lifetime; refused for another body, another run
/// or another key; and it never consumes the token.
#[test]
fn a_stored_token_is_rechecked_at_its_admission_time_and_never_consumed() {
    let k = govern_test_key();
    let h = header(&token(), "govern-gate-token-v1", &k);
    let id = op_id();
    let later = (at("2026-10-15T00:30:00Z") + Duration::hours(3)).to_rfc3339();
    let v = verifier(&[("govern-gate-token-v1", &k)], &later);
    let admitted = at(NOW);
    let ok = v
        .verify_stored(&h, Operation::Stop, &id, b"", admitted)
        .unwrap();
    assert_eq!(ok.operation_id, id);
    assert_eq!(ok.token_id, token()["token_id"]);
    assert_eq!(ok.run_id, RUN);
    crate::constraints::check(ok.grant.as_ref().unwrap()).unwrap();
    v.verify_stored(&h, Operation::Stop, &id, b"", admitted)
        .unwrap();
    assert_eq!(
        v.verify_stored(&h, Operation::Stop, &id, b"", at("2026-10-15T00:31:00Z"))
            .unwrap_err(),
        Code::TokenExpired,
        "admitted after the token expired"
    );
    assert_eq!(
        v.verify_stored(&h, Operation::Stop, &id, b"{}", admitted)
            .unwrap_err(),
        Code::TokenScope,
        "another body"
    );
    let other_run = format!("9b3d5f7a-1c2e-4a6b-8d9f-0e1a2b3c4d5e/call/{TASK}");
    assert_eq!(
        v.verify_stored(&h, Operation::Stop, &other_run, b"", admitted)
            .unwrap_err(),
        Code::TokenScope,
        "another run"
    );
    let other = SigningKey::from_bytes(&[9; 32]);
    let forged = header(&token(), "govern-gate-token-v1", &other);
    assert_eq!(
        v.verify_stored(&forged, Operation::Stop, &id, b"", admitted)
            .unwrap_err(),
        Code::TokenInvalid,
        "another key"
    );
    // Never consumed: the live path, inside the lifetime, still admits it.
    let live = verifier(&[("govern-gate-token-v1", &k)], NOW);
    live.verify_stored(&h, Operation::Stop, &id, b"", admitted)
        .unwrap();
    live.verify(&call(Operation::Stop, &h, &id, b""))
        .unwrap()
        .admit()
        .unwrap();
}

/// Only the carried canonical bytes are verified and read: the inlined
/// `token` is ignored, so editing it changes nothing, and editing the
/// carried bytes breaks the signature.
#[test]
fn only_the_carried_bytes_count() {
    let k = govern_test_key();
    let id = op_id();
    let h = header(&token(), "govern-gate-token-v1", &k);
    let mut signed: Value = serde_json::from_slice(
        &base64::engine::general_purpose::STANDARD
            .decode(&h)
            .unwrap(),
    )
    .unwrap();
    signed["token"]["tenant_id"] = json!("22222222-2222-4222-8222-222222222222");
    let edited_inline = b64(&serde_json::to_vec(&signed).unwrap());
    verifier(&[("govern-gate-token-v1", &k)], NOW)
        .verify(&call(Operation::Stop, &edited_inline, &id, b""))
        .unwrap();

    let mut t = token();
    t["scope"]["resource"] = json!("apis/slack");
    signed["token_canonical_b64"] = json!(b64(&serde_json::to_vec(&t).unwrap()));
    let edited_bytes = b64(&serde_json::to_vec(&signed).unwrap());
    assert_eq!(
        verifier(&[("govern-gate-token-v1", &k)], NOW)
            .verify(&call(Operation::Stop, &edited_bytes, &id, b""))
            .unwrap_err(),
        Code::TokenInvalid
    );
}

#[test]
fn a_call_without_its_headers_is_refused_before_the_token_is_read() {
    let k = govern_test_key();
    let v = verifier(&[("govern-gate-token-v1", &k)], NOW);
    let h = header(&token(), "govern-gate-token-v1", &k);
    let id = op_id();
    let base = || call(Operation::Stop, &h, &id, b"");
    let mut c = base();
    c.backend_contract = Some("ekka.backend.v2");
    assert_eq!(v.verify(&c).unwrap_err(), Code::RequestInvalid);
    let mut c = base();
    c.authorization = None;
    assert_eq!(v.verify(&c).unwrap_err(), Code::CredentialMissing);
    let mut c = base();
    c.authorization = Some("Basic dXNlcjpwYXNz");
    assert_eq!(v.verify(&c).unwrap_err(), Code::CredentialMissing);
    for bad in [
        "r-1/call/x",
        &format!("{RUN}/call"),
        &format!("{RUN}/1call/{TASK}"),
        &format!("{}/call/{TASK}", RUN.to_uppercase()),
    ] {
        let mut c = base();
        c.operation_id = Some(bad);
        assert_eq!(v.verify(&c).unwrap_err(), Code::RequestInvalid, "{bad}");
    }
    let mut c = base();
    c.gate_token = None;
    assert_eq!(v.verify(&c).unwrap_err(), Code::TokenMissing);
}

/// A read: a `read` token covers `status` and `policy_get` only, and needs no
/// body pin and no grant when it sends no body.
#[test]
fn a_read_token_reads_and_only_reads() {
    let k = govern_test_key();
    let id = op_id();
    let mut t = token();
    t["scope"]["op"] = json!("read");
    t["constraints"] = json!({});
    let h = header(&t, "govern-gate-token-v1", &k);
    for op in [Operation::Status, Operation::PolicyGet] {
        verifier(&[("govern-gate-token-v1", &k)], NOW)
            .verify(&call(op, &h, &id, b""))
            .unwrap();
    }
    for op in [
        Operation::Create,
        Operation::Delete,
        Operation::PolicySet,
        Operation::ProviderDetach,
    ] {
        assert_eq!(
            verifier(&[("govern-gate-token-v1", &k)], NOW)
                .verify(&call(op, &h, &id, b""))
                .unwrap_err(),
            Code::TokenScope,
            "{op:?}"
        );
    }
}

/// Two keys while a rotation overlaps: a token is checked against the key
/// its id names, and only that one.
#[test]
fn during_a_rotation_each_key_verifies_only_its_own_id() {
    let old = govern_test_key();
    let new = SigningKey::from_bytes(&[3; 32]);
    let v = || {
        verifier(
            &[
                ("govern-gate-token-v1", &old),
                ("govern-gate-token-v2", &new),
            ],
            NOW,
        )
    };
    let id = op_id();
    v().verify(&call(
        Operation::Stop,
        &header(&token(), "govern-gate-token-v2", &new),
        &id,
        b"",
    ))
    .unwrap();
    v().verify(&call(
        Operation::Stop,
        &header(&token(), "govern-gate-token-v1", &old),
        &id,
        b"",
    ))
    .unwrap();
    assert_eq!(
        v().verify(&call(
            Operation::Stop,
            &header(&token(), "govern-gate-token-v1", &new),
            &id,
            b""
        ))
        .unwrap_err(),
        Code::TokenInvalid,
        "signed by the new key under the old key's id"
    );
}

#[test]
fn the_lifetime_allows_thirty_seconds_of_skew_and_no_more() {
    let k = govern_test_key();
    let id = op_id();
    let h = header(&token(), "govern-gate-token-v1", &k);
    let expires = at("2026-10-15T00:30:00Z");
    for (offset, ok) in [(29, true), (30, false), (-30, true)] {
        let now = (expires + Duration::seconds(offset)).to_rfc3339();
        let r = verifier(&[("govern-gate-token-v1", &k)], &now).verify(&call(
            Operation::Stop,
            &h,
            &id,
            b"",
        ));
        assert_eq!(r.is_ok(), ok, "{offset}: {r:?}");
    }
}

/// The closed constraints are the published schema's: an API-gate token's
/// `constraints` takes `grant` and `body_sha256` only, the pin as 64
/// lowercase hex. A contract change to either fails here.
#[test]
fn the_closed_constraints_are_the_published_schemas() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vendor/contracts/governance/gate-token.schema.json"
    );
    let s: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let then = &s["$defs"]["GateToken"]["allOf"][0];
    assert_eq!(
        then["if"]["properties"]["scope"]["properties"]["contract"]["const"],
        "ekka.gate.api.v1"
    );
    let c = &then["then"]["properties"]["constraints"];
    assert_eq!(c["additionalProperties"], false);
    let mut keys: Vec<&str> = c["properties"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["body_sha256", "grant"]);
    assert_eq!(c["properties"]["body_sha256"]["pattern"], "^[0-9a-f]{64}$");
}

/// The handler gets the call's credential, for the driver to sign
/// in with, and the ORIGINAL signed token header, for the operation's record. The
/// credential is request-scoped: its Debug never shows it, and nothing
/// that formats a verified call shows it either.
#[test]
fn a_verified_call_carries_its_credential_unshown_and_its_original_token() {
    let k = govern_test_key();
    let v = verifier(&[("govern-gate-token-v1", &k)], NOW);
    let h = header(&token(), "govern-gate-token-v1", &k);
    let id = op_id();
    let ok = v.verify(&call(Operation::Stop, &h, &id, b"")).unwrap();
    assert_eq!(ok.credential.expose(), "backend-credential");
    assert_eq!(ok.gate_token, h);
    for shown in [format!("{ok:?}"), format!("{:?}", ok.credential)] {
        assert!(!shown.contains("backend-credential"), "{shown}");
    }
    let admitted = ok.admit().unwrap();
    assert!(!format!("{admitted:?}").contains("backend-credential"));
    assert_eq!(
        admitted.verified().credential.expose(),
        "backend-credential"
    );
}

/// The request id never changes for the same inputs (a new derivation would
/// give every recorded operation a new id), and every input moves it.
#[test]
fn the_request_id_is_stable_and_names_every_input() {
    let id = crate::testkit::request_id();
    assert_eq!(id, "228f680e-930e-56f2-9feb-1bc759da6615");
    let base = (
        "11111111-1111-4111-8111-111111111111",
        "enclave3a7e592fApi",
        ("https://gateway.example:8443", "desks"),
        (RUN, "call_desk", TASK),
    );
    let of = |b: (&str, &str, (&str, &str), (&str, &str, &str))| {
        crate::token::request_id(b.0, b.1, b.2, b.3)
    };
    let mut seen = std::collections::BTreeSet::new();
    for b in [
        base,
        (
            "22222222-2222-4222-8222-222222222222",
            base.1,
            base.2,
            base.3,
        ),
        (base.0, "enclave00000000Api", base.2, base.3),
        (
            base.0,
            base.1,
            ("https://other.example:8443", "desks"),
            base.3,
        ),
        (
            base.0,
            base.1,
            ("https://gateway.example:8443", "other"),
            base.3,
        ),
        (base.0, base.1, base.2, (TASK, "call_desk", TASK)),
        (base.0, base.1, base.2, (RUN, "call_other", TASK)),
        (base.0, base.1, base.2, (RUN, "call_desk", RUN)),
    ] {
        let id = of(b);
        assert!(
            uuid::Uuid::parse_str(&id).unwrap().get_version_num() == 5,
            "{id}"
        );
        assert!(seen.insert(id), "two inputs gave one id");
    }
}
