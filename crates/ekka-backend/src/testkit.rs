//! Test support: tokens signed as Govern signs them, with Govern's TEST key
//! (seed 32 bytes of 0x02, as its fixture says), and the adapter config they
//! verify under. Test builds only.

#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

use base64::Engine as _;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{json, Value};

use crate::config::Config;
use crate::routes::Operation;
use crate::token::{Call, Verifier};

pub const NOW: &str = "2026-10-15T00:10:00Z";

pub const ORG: &str = "11111111-1111-4111-8111-111111111111";
pub const INSTANCE: &str = "enclave3a7e592fApi";
pub const RUN: &str = "0b3d5f7a-1c2e-4a6b-8d9f-0e1a2b3c4d5e";
pub const TASK: &str = "5c1e9a2b-7d3f-4e8a-9b0c-1d2e3f4a5b6c";
/// sha256 of zero bytes: the pin of a bodiless change.
pub const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

pub fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// Govern's TEST signing key: 32 bytes of 0x02 (the fixture's README).
pub fn govern_test_key() -> SigningKey {
    SigningKey::from_bytes(&[2; 32])
}

pub fn fixture() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/govern/desk-gate-token.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

pub fn grant() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vendor/contracts/governance/grant-constraints/samples/desks.v1.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

pub fn config(keys: &[(&str, &SigningKey)]) -> Config {
    let govern_keys: Vec<Value> = keys
        .iter()
        .map(|(id, k)| json!({ "key_id": id, "public_key_b64": b64(k.verifying_key().as_bytes()) }))
        .collect();
    serde_json::from_value(json!({
        "config_version": 1,
        "organization_id": ORG,
        "api_gate_instance": INSTANCE,
        "govern_keys": govern_keys,
        "backend_gateway": { "url": "https://gateway.example:8443", "client_id": "ekka-desk-admin", "workspace": "desks", "issuer": "https://desks.example/realms/ekka-desks" }
    }))
    .unwrap()
}

pub fn at(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
}

/// A verifier whose clock reads `now`.
pub fn verifier(keys: &[(&str, &SigningKey)], now: &str) -> Verifier {
    let t = at(now);
    Verifier::new(&config(keys), Box::new(move || t)).unwrap()
}

/// A token as Govern signs it, for a `stop` with no body, unless changed.
pub fn token() -> Value {
    json!({
        "schema": "ekka.gate_token.v1",
        "token_id": "b88d004b-b342-4447-917d-c5d4264589d6",
        "issuer": "ekka-govern",
        "issued_at": "2026-10-15T00:00:00.000Z",
        "expires_at": "2026-10-15T00:30:00.000Z",
        "tenant_id": ORG,
        "run_id": RUN,
        "scope": { "contract": "ekka.gate.api.v1", "instance": INSTANCE, "resource": "apis/desks", "op": "write" },
        "constraints": { "body_sha256": EMPTY, "grant": grant() }
    })
}

/// The `X-EKKA-Gate-Token` header for `token`, signed by `key` as `key_id`.
pub fn header(token: &Value, key_id: &str, key: &SigningKey) -> String {
    let canonical = serde_json::to_vec(token).unwrap();
    let sig = key.sign(&canonical);
    let signed = json!({
        "schema": "SIGNED_GATE_TOKEN",
        "signing_alg": "ed25519",
        "key_id": key_id,
        "token": token,
        "token_canonical_b64": b64(&canonical),
        "signature_b64": b64(&sig.to_bytes()),
    });
    b64(&serde_json::to_vec(&signed).unwrap())
}

pub fn op_id() -> String {
    format!("{RUN}/call_desk/{TASK}")
}

pub fn call<'a>(op: Operation, header: &'a str, op_id: &'a str, body: &'a [u8]) -> Call<'a> {
    Call {
        operation: op,
        gate_token: Some(header),
        authorization: Some("Bearer backend-credential"),
        operation_id: Some(op_id),
        backend_contract: Some("ekka.backend.v1"),
        body,
    }
}

/// The request id of a call made with [`op_id`] under [`config`].
pub fn request_id() -> String {
    let c = config(&[]);
    crate::token::request_id(
        &c.organization_id,
        &c.api_gate_instance,
        (&c.backend_gateway.url, &c.backend_gateway.workspace),
        (RUN, "call_desk", TASK),
    )
}
