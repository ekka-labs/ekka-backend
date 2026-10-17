//! Every call's authorization.
//!
//! A call is refused, before anything reaches the desk backend, unless:
//! - it names the backend protocol this adapter speaks, in its own header;
//! - it carries the backend credential (`Authorization: Bearer`), which is
//!   never logged or kept;
//! - its `X-EKKA-Operation-Id` is `<run uuid>/<step>/<task uuid>`;
//! - its `X-EKKA-Gate-Token` is a Govern-signed gate token: Ed25519 over the
//!   CARRIED canonical bytes (never re-serialized), by the key whose
//!   `key_id` equals the token's exactly (no fallback to another key);
//! - the signed token names this organization, this Enclave's API gate,
//!   `ekka.gate.api.v1` and `apis/desks`, is within its lifetime (±30 s, as
//!   GATE_SPEC §7.4), and its verb covers the route (`write` covers every
//!   route; `read` only `status` and `policy_get`);
//! - the operation id's run is the token's run;
//! - the body's sha256 is the token's `constraints.body_sha256` (required on
//!   every route but the two reads), so a changed body is refused;
//! - `constraints.grant` is the desk grant's closed limits (desks.v1),
//!   required on every route but the two reads;
//! - its `token_id` has not been used: checked when the call is ADMITTED, not
//!   when it is verified.
//!   A verified call is first looked up by its operation in the durable
//!   store; a known operation answers its recorded result without
//!   executing and without consuming its token. Only a NEW operation is
//!   admitted ([`Verified::admit`]), which consumes the token, and only an
//!   [`Admitted`] call executes.
//!
//! The recovery path (re-issuing a stored request under its stored token) has its own narrow check, [`Verifier::verify_stored`]: the same
//! signature, bindings and body pin, the lifetime measured at the stored
//! admission time, and no replay entry; it can never yield an [`Admitted`].
//!
//! Only the token id, run id and operation id are ever logged.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::answer::Code;
use crate::config::Config;
use crate::routes::Operation;

/// The backend protocol, as `x-ekka-backend-contract` names it.
pub const BACKEND_CONTRACT: &str = "ekka.backend.v1";
/// The contract Govern signs for an API-gate call.
pub const GATE_CONTRACT: &str = "ekka.gate.api.v1";
/// The one resource a desk token may name.
pub const RESOURCE: &str = "apis/desks";
/// GATE_SPEC §7.4: a token is checked against its lifetime with this skew.
const SKEW_SECONDS: i64 = 30;
/// The largest token header read (the contract's `maxLength`).
const MAX_TOKEN_HEADER: usize = 16_384;
/// How many unexpired token ids the replay cache holds before it refuses.
const MAX_REMEMBERED: usize = 100_000;
/// The namespace of the adapter's request ids. Chosen once (2026-10-16) and
/// never changed: a new one would give every recorded operation a new id.
const REQUEST_ID_NAMESPACE: uuid::Uuid = uuid::uuid!("8259c45e-1499-41dd-81fc-b5ec7c85ceb8");

/// An operation's request id: a UUIDv5 over
/// the organization, the API-gate instance, the backend gateway (its URL and
/// workspace), the run, the step and the task, joined as one JSON array so no
/// two inputs can collide. A new visit of a looping operation gets a new
/// task, so a new id; an id from another organization or gateway never
/// matches. It is the `operation_id` of a `running` answer, the id in the
/// desk's lock and OpenShell's `request_id`; never the call's
/// `X-EKKA-Operation-Id`, which is only its input.
#[must_use]
pub fn request_id(
    organization_id: &str,
    api_gate_instance: &str,
    gateway: (&str, &str),
    (run, step, task): (&str, &str, &str),
) -> String {
    let name = serde_json::json!([
        "ekka.backend.v1 request",
        organization_id,
        api_gate_instance,
        gateway.0,
        gateway.1,
        run,
        step,
        task
    ])
    .to_string();
    uuid::Uuid::new_v5(&REQUEST_ID_NAMESPACE, name.as_bytes())
        .hyphenated()
        .to_string()
}

/// The signed envelope, as `governance/gate-token.schema.json` writes it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Signed {
    schema: String,
    signing_alg: String,
    key_id: String,
    token_canonical_b64: String,
    signature_b64: String,
    /// The inner token inlined for reading: never trusted, never read.
    #[serde(rename = "token")]
    _token: Value,
}

/// The fields of the signed token this adapter reads. Other fields Govern
/// signs are allowed and ignored.
#[derive(Debug, Deserialize)]
struct Token {
    schema: String,
    token_id: String,
    issued_at: String,
    expires_at: String,
    tenant_id: String,
    run_id: String,
    scope: Scope,
    /// Read strictly as [`Constraints`] once the scope says this is an
    /// API-gate token.
    #[serde(default)]
    constraints: Value,
}

#[derive(Debug, Deserialize)]
struct Scope {
    contract: String,
    instance: String,
    resource: String,
    op: String,
}

/// An API-gate token's constraints: CLOSED in the published gate-token
/// schema (`allOf[0].then`), `grant` and `body_sha256` only.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Constraints {
    #[serde(default)]
    body_sha256: Option<String>,
    #[serde(default)]
    grant: Option<Value>,
}

/// A token whose signature, issuer key, organization, instance, contract,
/// resource and lifetime are checked; not yet bound to a call.
#[derive(Debug)]
pub struct SignedToken {
    pub token_id: String,
    pub run_id: String,
    expires: DateTime<Utc>,
    op: String,
    body_sha256: Option<String>,
    grant: Option<Value>,
}

/// What a call presents.
pub struct Call<'a> {
    pub operation: Operation,
    pub gate_token: Option<&'a str>,
    pub authorization: Option<&'a str>,
    pub operation_id: Option<&'a str>,
    pub backend_contract: Option<&'a str>,
    pub body: &'a [u8],
}

type Clock = Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>;

/// The token ids used by admitted calls, each kept until it expires (and the
/// skew after it), so a replay inside its lifetime is refused.
struct Replay {
    now: Clock,
    seen: Mutex<HashMap<String, DateTime<Utc>>>,
}

impl Replay {
    fn consume(&self, token_id: &str, expires: DateTime<Utc>) -> Result<(), Code> {
        let now = (self.now)();
        let mut seen = self.seen.lock().map_err(|_| Code::TokenReplayed)?;
        seen.retain(|_, exp| *exp + Duration::seconds(SKEW_SECONDS) > now);
        if seen.contains_key(token_id) {
            return Err(Code::TokenReplayed);
        }
        // Full of live ids: refuse rather than forget one that could replay.
        if seen.len() >= MAX_REMEMBERED {
            return Err(Code::TokenReplayed);
        }
        seen.insert(token_id.to_string(), expires);
        Ok(())
    }
}

/// The backend credential a call carried (`Authorization: Bearer`), held for
/// that call only: the driver signs in with it.
/// Zeroed when dropped; its Debug never shows it; it is not `Serialize`, so
/// it cannot be written into the durable record or a log line.
#[derive(Clone)]
pub struct Credential(zeroize::Zeroizing<String>);

impl Credential {
    /// The value, for the one place that sends it: the sign-in request.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credential(withheld)")
    }
}

/// Whether a call was admitted before its deadline. The
/// server closes it at the deadline: a call admitted before then goes on and
/// is answered `running`; one admitted after it is refused. One lock decides
/// both, so a call is never admitted after the server answered for it.
#[derive(Default)]
pub struct Gate(Mutex<GateState>);

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum GateState {
    #[default]
    Open,
    Admitted,
    Closed,
}

impl Gate {
    /// At the deadline: `true` when the call was admitted before it;
    /// otherwise the gate is closed and no admission can follow.
    pub fn close(&self) -> bool {
        let mut g = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *g == GateState::Admitted {
            return true;
        }
        *g = GateState::Closed;
        false
    }
}

/// A call whose authorization holds, not yet admitted: its token is not
/// consumed until [`Verified::admit`].
pub struct Verified {
    pub token_id: String,
    pub run_id: String,
    pub operation_id: String,
    /// The operation's request id: [`request_id`] of this call.
    pub request_id: String,
    /// The grant's limits, checked against desks.v1; absent only on a read.
    pub grant: Option<Value>,
    /// The call's backend credential, for this call only. Read by the
    /// driver.
    pub credential: Credential,
    /// The ORIGINAL `X-EKKA-Gate-Token` header as it arrived, for the durable
    /// record, which re-checks it with [`Verifier::verify_stored`].
    /// A signed authorization pinned to this operation, not a credential.
    pub gate_token: String,
    expires: DateTime<Utc>,
    replay: Arc<Replay>,
    gate: Arc<Gate>,
}

impl std::fmt::Debug for Verified {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Verified")
            .field("token_id", &self.token_id)
            .field("run_id", &self.run_id)
            .field("operation_id", &self.operation_id)
            .finish_non_exhaustive()
    }
}

/// A NEW operation, admitted: its token is consumed, and only this executes.
#[derive(Debug)]
pub struct Admitted(Verified);

impl Verified {
    /// Admit this call as a new operation: consume its token, refusing one
    /// already used. Called only after the durable store has no record of
    /// the operation.
    ///
    /// # Errors
    /// `TOKEN_REPLAYED`.
    ///
    /// `BACKEND_UNAVAILABLE` when the call's deadline has already passed.
    pub fn admit(self) -> Result<Admitted, Code> {
        let mut g = self
            .gate
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *g == GateState::Closed {
            return Err(Code::BackendUnavailable);
        }
        self.replay.consume(&self.token_id, self.expires)?;
        *g = GateState::Admitted;
        drop(g);
        Ok(Admitted(self))
    }

    /// The call's gate, which the server closes at the deadline.
    #[must_use]
    pub fn gate(&self) -> Arc<Gate> {
        self.gate.clone()
    }

    /// [`Verified::for_tests`] under another request id: each operation a
    /// test makes has its own, as each real operation does.
    #[cfg(test)]
    pub fn for_tests_as(grant: Option<Value>, request_id: &str) -> Self {
        let mut v = Self::for_tests(grant);
        v.request_id = request_id.to_string();
        v
    }

    /// A verified call over a replay cache of its own, for tests of what
    /// comes after verification.
    #[cfg(test)]
    pub fn for_tests(grant: Option<Value>) -> Self {
        Self {
            token_id: "t".into(),
            run_id: "r".into(),
            operation_id: "o".into(),
            request_id: "00000000-0000-5000-8000-000000000000".into(),
            grant,
            credential: Credential(zeroize::Zeroizing::new("backend-credential".into())),
            gate_token: String::new(),
            expires: Utc::now() + Duration::minutes(5),
            replay: Arc::new(Replay {
                now: Arc::new(Utc::now),
                seen: Mutex::new(HashMap::new()),
            }),
            gate: Arc::default(),
        }
    }
}

impl Admitted {
    #[must_use]
    pub fn verified(&self) -> &Verified {
        &self.0
    }

    /// A STORED operation's admission for a READ-BACK only (a settle marker
    /// settles it): no token, no grant, its request id and the CURRENT call's
    /// credential, to read the desk and release its claim. The driver takes
    /// it only in `Backend::read_back` and `not_applied`, which send nothing.
    #[must_use]
    pub fn for_read_back(request_id: &str, operation_id: &str, credential: Credential) -> Self {
        Self(Verified {
            token_id: String::new(),
            run_id: String::new(),
            operation_id: operation_id.to_string(),
            request_id: request_id.to_string(),
            grant: None,
            credential,
            gate_token: String::new(),
            expires: Utc::now(),
            replay: Arc::new(Replay {
                now: Arc::new(Utc::now),
                seen: Mutex::new(HashMap::new()),
            }),
            gate: Arc::default(),
        })
    }

    /// A STORED operation, carried out again on recovery: its token
    /// re-checked by [`Verifier::verify_stored`] (the only way to a
    /// [`Recovered`]), its request id the one it was admitted under, and the
    /// CURRENT call's credential. Nothing is consumed: the operation was
    /// admitted once, when it first arrived.
    #[must_use]
    pub fn for_recovery(
        r: Recovered,
        request_id: &str,
        gate_token: &str,
        credential: Credential,
    ) -> Self {
        Self(Verified {
            token_id: r.token_id,
            run_id: r.run_id,
            operation_id: r.operation_id,
            request_id: request_id.to_string(),
            grant: r.grant,
            credential,
            gate_token: gate_token.to_string(),
            expires: Utc::now(),
            replay: Arc::new(Replay {
                now: Arc::new(Utc::now),
                seen: Mutex::new(HashMap::new()),
            }),
            gate: Arc::default(),
        })
    }
}

/// A STORED token re-checked for recovery: never admitted, never consumes.
#[derive(Debug)]
pub struct Recovered {
    pub token_id: String,
    pub run_id: String,
    pub operation_id: String,
    pub grant: Option<Value>,
}

pub struct Verifier {
    organization_id: String,
    api_gate_instance: String,
    /// The backend gateway's URL and workspace: its identity in request ids.
    gateway: (String, String),
    keys: Vec<(String, VerifyingKey)>,
    now: Clock,
    replay: Arc<Replay>,
}

fn b64(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

/// `<uuid>/<step>/<uuid>`, the contract's `x-ekka-operation-id`.
fn operation_id_parts(s: &str) -> Option<(&str, &str, &str)> {
    let mut it = s.split('/');
    let (run, step, task) = (it.next()?, it.next()?, it.next()?);
    if it.next().is_some() || !uuid_lower(run) || !uuid_lower(task) {
        return None;
    }
    let b = step.as_bytes();
    let ok = (1..=64).contains(&b.len())
        && b[0].is_ascii_alphabetic()
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || *c == b'_' || *c == b'-');
    ok.then_some((run, step, task))
}

fn uuid_lower(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(c),
        })
}

impl Verifier {
    /// A verifier for `config`, reading the time from `now`.
    ///
    /// # Errors
    /// A configured key is not an Ed25519 public key.
    pub fn new(
        config: &Config,
        now: Box<dyn Fn() -> DateTime<Utc> + Send + Sync>,
    ) -> Result<Self, String> {
        let mut keys = Vec::with_capacity(config.govern_keys.len());
        for k in &config.govern_keys {
            let bytes: [u8; 32] = b64(&k.public_key_b64)
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| format!("govern key {} is not 32 bytes of base64", k.key_id))?;
            let key = VerifyingKey::from_bytes(&bytes)
                .map_err(|_| format!("govern key {} is not an Ed25519 public key", k.key_id))?;
            keys.push((k.key_id.clone(), key));
        }
        let now: Clock = Arc::from(now);
        Ok(Self {
            organization_id: config.organization_id.clone(),
            api_gate_instance: config.api_gate_instance.clone(),
            gateway: (
                config.backend_gateway.url.clone(),
                config.backend_gateway.workspace.clone(),
            ),
            keys,
            replay: Arc::new(Replay {
                now: now.clone(),
                seen: Mutex::new(HashMap::new()),
            }),
            now,
        })
    }

    /// How many token ids the replay cache holds: tests prove a call did, or
    /// did not, consume its token.
    #[cfg(test)]
    pub fn consumed(&self) -> usize {
        self.replay
            .seen
            .lock()
            .map(|s| s.len())
            .unwrap_or(usize::MAX)
    }

    /// Check a gate token header on its own: the signature over the carried
    /// bytes, by the exact key it names; the organization, instance,
    /// contract and resource it is for; and its lifetime.
    ///
    /// # Errors
    /// `TOKEN_INVALID`, `TOKEN_SCOPE` or `TOKEN_EXPIRED`.
    pub fn verify_signed(&self, header: &str) -> Result<SignedToken, Code> {
        self.signed_at(header, (self.now)())
    }

    /// [`Verifier::verify_signed`], its lifetime measured at `at`.
    fn signed_at(&self, header: &str, at_time: DateTime<Utc>) -> Result<SignedToken, Code> {
        if header.len() > MAX_TOKEN_HEADER {
            return Err(Code::TokenInvalid);
        }
        let raw = b64(header).ok_or(Code::TokenInvalid)?;
        let signed: Signed = serde_json::from_slice(&raw).map_err(|_| Code::TokenInvalid)?;
        if signed.schema != "SIGNED_GATE_TOKEN" || signed.signing_alg != "ed25519" {
            return Err(Code::TokenInvalid);
        }
        let key = self
            .keys
            .iter()
            .find(|(id, _)| *id == signed.key_id)
            .map(|(_, k)| k)
            .ok_or(Code::TokenInvalid)?;
        let canonical = b64(&signed.token_canonical_b64).ok_or(Code::TokenInvalid)?;
        let sig: [u8; 64] = b64(&signed.signature_b64)
            .and_then(|b| b.try_into().ok())
            .ok_or(Code::TokenInvalid)?;
        key.verify(&canonical, &Signature::from_bytes(&sig))
            .map_err(|_| Code::TokenInvalid)?;
        // Only now, and only the signed bytes, are read as the token.
        let t: Token = serde_json::from_slice(&canonical).map_err(|_| Code::TokenInvalid)?;
        if t.schema != "ekka.gate_token.v1" {
            return Err(Code::TokenInvalid);
        }
        if t.tenant_id != self.organization_id
            || t.scope.instance != self.api_gate_instance
            || t.scope.contract != GATE_CONTRACT
            || t.scope.resource != RESOURCE
        {
            return Err(Code::TokenScope);
        }
        let at = |s: &str| DateTime::parse_from_rfc3339(s).map(|d| d.with_timezone(&Utc));
        let (Ok(issued), Ok(expires)) = (at(&t.issued_at), at(&t.expires_at)) else {
            return Err(Code::TokenInvalid);
        };
        let now = at_time;
        let skew = Duration::seconds(SKEW_SECONDS);
        if now + skew < issued || now - skew >= expires {
            return Err(Code::TokenExpired);
        }
        let c: Constraints = if t.constraints.is_null() {
            Constraints::default()
        } else {
            serde_json::from_value(t.constraints).map_err(|_| Code::ConstraintsInvalid)?
        };
        // The schema's `^[0-9a-f]{64}$`.
        if c.body_sha256.as_deref().is_some_and(|h| {
            h.len() != 64
                || !h
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }) {
            return Err(Code::ConstraintsInvalid);
        }
        Ok(SignedToken {
            token_id: t.token_id,
            run_id: t.run_id,
            expires,
            op: t.scope.op,
            body_sha256: c.body_sha256,
            grant: c.grant,
        })
    }

    /// Verify a whole call: its headers, its token, and that the token
    /// covers exactly this call. Nothing is sent to the backend unless this
    /// returns `Ok`.
    ///
    /// # Errors
    /// The contract's code for the first thing that does not hold.
    pub fn verify(&self, c: &Call<'_>) -> Result<Verified, Code> {
        if c.backend_contract != Some(BACKEND_CONTRACT) {
            return Err(Code::RequestInvalid);
        }
        let bearer = c
            .authorization
            .and_then(|a| a.strip_prefix("Bearer "))
            .filter(|t| !t.is_empty() && t.bytes().all(|b| b.is_ascii_graphic()))
            .ok_or(Code::CredentialMissing)?;
        let op_id = c.operation_id.ok_or(Code::RequestInvalid)?;
        let parts = operation_id_parts(op_id).ok_or(Code::RequestInvalid)?;
        let run = parts.0;
        let header = c.gate_token.ok_or(Code::TokenMissing)?;
        let t = self.verify_signed(header)?;
        bind(&t, c.operation, run, c.body)?;
        Ok(Verified {
            token_id: t.token_id,
            run_id: t.run_id,
            operation_id: op_id.to_string(),
            request_id: request_id(
                &self.organization_id,
                &self.api_gate_instance,
                (&self.gateway.0, &self.gateway.1),
                parts,
            ),
            grant: t.grant,
            credential: Credential(zeroize::Zeroizing::new(bearer.to_string())),
            gate_token: header.to_string(),
            expires: t.expires,
            replay: self.replay.clone(),
            gate: Arc::default(),
        })
    }

    /// The recovery path's own check: a STORED request's token,
    /// re-verified for re-issue. The same signature, organization, instance,
    /// contract, resource, run, body pin and grant as [`Verifier::verify`];
    /// the lifetime measured at `admitted_at`, the time the operation was
    /// first admitted, not now; and NO replay entry, so it can never admit.
    ///
    /// # Errors
    /// As [`Verifier::verify`].
    pub fn verify_stored(
        &self,
        header: &str,
        operation: Operation,
        operation_id: &str,
        body: &[u8],
        admitted_at: DateTime<Utc>,
    ) -> Result<Recovered, Code> {
        let (run, _, _) = operation_id_parts(operation_id).ok_or(Code::RequestInvalid)?;
        let t = self.signed_at(header, admitted_at)?;
        bind(&t, operation, run, body)?;
        Ok(Recovered {
            token_id: t.token_id,
            run_id: t.run_id,
            operation_id: operation_id.to_string(),
            grant: t.grant,
        })
    }
}

/// The token covers exactly this call: its verb the route, its run the
/// operation id's, its pin the body, its grant desks.v1.
fn bind(t: &SignedToken, operation: Operation, run: &str, body: &[u8]) -> Result<(), Code> {
    let read_route = matches!(operation, Operation::Status | Operation::PolicyGet);
    let covers = match t.op.as_str() {
        "write" => true,
        "read" => read_route,
        _ => false,
    };
    if !covers || t.run_id != run {
        return Err(Code::TokenScope);
    }
    match (&t.body_sha256, read_route) {
        (Some(pin), _) => {
            if *pin != format!("{:x}", Sha256::digest(body)) {
                return Err(Code::TokenScope);
            }
        }
        (None, true) if body.is_empty() => {}
        (None, _) => return Err(Code::TokenScope),
    }
    match (&t.grant, read_route) {
        (Some(g), _) => crate::constraints::check(g).map_err(|_| Code::ConstraintsInvalid)?,
        (None, true) => {}
        (None, false) => return Err(Code::ConstraintsInvalid),
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "token_tests.rs"]
mod tests;
