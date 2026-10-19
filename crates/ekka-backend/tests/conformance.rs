//! The conformance suite: what any desk backend driver must do,
//! checked from the outside.
//!
//! Each test runs the real `ekka-backend serve` binary with a config the kit
//! would write, and calls it the way the Enclave's API gate does: HTTP/1.1
//! over the adapter's Unix socket, with the four headers, the backend
//! credential as `Authorization: Bearer`, and a gate token signed at test
//! time with Govern's TEST key (32 bytes of 0x02, the key the vendored Govern
//! fixture is signed with). Behind it run the test fakes: the NVIDIA
//! OpenShell gateway and its sign-in service over TLS from one throwaway CA,
//! and the Enclave's claim socket.
//!
//! Every test ends by searching everything the adapter wrote (each log line,
//! each response body, each file under its folders) for the planted backend
//! credential and the gateway token minted from it.
//!
//! Cases that need the durable operation store and its recovery are
//! written out in full and ignored until it lands.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use ekka_backend_fakegw::faults::Planted;
use ekka_backend_fakegw::{fake_enclave, fake_gateway, fake_issuer};

/// The backend credential the Enclave's vault would inject: the sign-in
/// client secret. It must never be shown.
const SECRET: &str = "PLANTED-backend-credential-7Hq2Zx9";
/// The gateway token the sign-in service mints from it. Never shown either.
const GW_TOKEN: &str = "PLANTED-gateway-token-4Kd8Wm";
const ORG: &str = "11111111-1111-4111-8111-111111111111";
const INSTANCE: &str = "enclave3a7e592fApi";
const RUN: &str = "0b3d5f7a-1c2e-4a6b-8d9f-0e1a2b3c4d5e";
/// The key id Govern's fixture names.
const KEY_ID: &str = "govern-gate-token-v1";
const WORKSPACE: &str = "desks";
const DESK: &str = "code-desk";
const IMAGE: &str =
    "ghcr.io/example/desk@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ENFORCE: &str = "NETWORK_ENFORCEMENT_MODE_ENFORCE";
/// The first sandbox id the fake gateway hands out.
const FIRST_ID: &str = "00000000-0000-4000-8000-000000000001";
/// The adapter's request-id namespace (token.rs `REQUEST_ID_NAMESPACE`):
/// fixed for good, so an operator's id for an operation never moves.
const REQUEST_ID_NAMESPACE: &str = "8259c45e-1499-41dd-81fc-b5ec7c85ceb8";

// ---------------------------------------------------------------------------
// Policies, grants and tokens.
// ---------------------------------------------------------------------------

fn endpoint(host: &str, port: u16) -> Value {
    json!({ "host": host, "port": port, "enforcement": ENFORCE })
}

/// A policy of one rule, `github`, with these endpoints and programs.
fn policy_with(endpoints: Vec<Value>, binaries: &[&str]) -> Value {
    let binaries: Vec<Value> = binaries.iter().map(|p| json!({ "path": p })).collect();
    json!({
        "version": 1,
        "filesystem": { "readOnly": ["/usr"], "readWrite": ["/sandbox"] },
        "landlock": { "compatibility": "hard_requirement" },
        "process": { "runAsUser": "1000", "runAsGroup": "1000" },
        "networkPolicies": { "github": {
            "name": "github", "endpoints": endpoints, "binaries": binaries
        } }
    })
}

/// The creation policy: the GitHub API on 443 and 22, for git.
fn base_policy() -> Value {
    policy_with(
        vec![
            endpoint("api.github.com", 443),
            endpoint("api.github.com", 22),
        ],
        &["/usr/bin/git"],
    )
}

/// The creation policy with port 22 dropped: narrower.
fn narrowed_policy() -> Value {
    policy_with(vec![endpoint("api.github.com", 443)], &["/usr/bin/git"])
}

/// Create bodies' policies that are each outside ONE limit, but whose digest
/// the grant lists, so each reaches the limit it breaks.
fn off_host_policy() -> Value {
    policy_with(
        vec![
            endpoint("api.github.com", 443),
            endpoint("evil.example.com", 443),
        ],
        &["/usr/bin/git"],
    )
}
fn off_port_policy() -> Value {
    policy_with(vec![endpoint("api.github.com", 8080)], &["/usr/bin/git"])
}
fn audited_policy() -> Value {
    let mut p = base_policy();
    p["networkPolicies"]["github"]["endpoints"][0]["enforcement"] =
        json!("NETWORK_ENFORCEMENT_MODE_AUDIT");
    p
}
fn provider_rule_policy() -> Value {
    let mut p = base_policy();
    p["networkPolicies"]["_provider_github"] = json!({
        "name": "_provider_github",
        "endpoints": [endpoint("api.github.com", 443)],
        "binaries": [{ "path": "/usr/bin/git" }]
    });
    p
}

/// Run the adapter's own `digest` command, as the kit does.
fn digest(kind: &str, input: &Value) -> String {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ekka-backend"))
        .args(["digest", kind, "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "digest {kind}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

fn provider_fixture() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/provider-github.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn govern_fixture() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/govern/desk-gate-token.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// The desk grant: Govern's fixture's limits, with the digests of this
/// suite's policies and of the gateway's GitHub provider, as `ekka-backend
/// digest` prints them.
fn grant() -> Value {
    let mut g = govern_fixture()["signed"]["token"]["constraints"]["grant"].clone();
    let policies = [
        base_policy(),
        off_host_policy(),
        off_port_policy(),
        audited_policy(),
        provider_rule_policy(),
    ];
    g["policy_digests"] = policies
        .iter()
        .map(|p| json!(digest("policy", p)))
        .collect();
    g["provider_config_digests"] = json!({ "github": digest("provider", &provider_fixture()) });
    g
}

/// Govern's TEST signing key: 32 bytes of 0x02 (the Govern fixture's README).
fn govern_key() -> SigningKey {
    SigningKey::from_bytes(&[2; 32])
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn sha256_hex(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}

/// A fresh lowercase UUID, unique in this test process.
fn fresh_uuid() -> String {
    static N: AtomicU64 = AtomicU64::new(1);
    let n = N.fetch_add(1, Ordering::Relaxed);
    format!("{:08x}-0000-4000-8000-{:012x}", std::process::id(), n)
}

/// What Govern signs for one call.
#[derive(Clone)]
struct Grant {
    op: &'static str,
    grant: Option<Value>,
    tenant: String,
}

impl Grant {
    fn write(grant: &Value) -> Self {
        Self {
            op: "write",
            grant: Some(grant.clone()),
            tenant: ORG.into(),
        }
    }
    fn read() -> Self {
        Self {
            op: "read",
            grant: None,
            tenant: ORG.into(),
        }
    }
}

/// The `X-EKKA-Gate-Token` header Govern would send for `body`.
fn gate_token(g: &Grant, body: &[u8]) -> String {
    let now = chrono::Utc::now();
    let at = |t: chrono::DateTime<chrono::Utc>| t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    let mut constraints = json!({ "body_sha256": sha256_hex(body) });
    if let Some(gr) = &g.grant {
        constraints["grant"] = gr.clone();
    }
    let token = json!({
        "schema": "ekka.gate_token.v1",
        "token_id": fresh_uuid(),
        "issuer": "ekka-govern",
        "issuer_kind": "govern",
        "issued_at": at(now - chrono::Duration::seconds(60)),
        "expires_at": at(now + chrono::Duration::minutes(25)),
        "tenant_id": g.tenant,
        "run_id": RUN,
        "scope": { "contract": "ekka.gate.api.v1", "instance": INSTANCE, "resource": "apis/desks", "op": g.op },
        "constraints": constraints
    });
    let canonical = serde_json::to_vec(&token).unwrap();
    let signed = json!({
        "schema": "SIGNED_GATE_TOKEN",
        "signing_alg": "ed25519",
        "key_id": KEY_ID,
        "token": token,
        "token_canonical_b64": b64(&canonical),
        "signature_b64": b64(&govern_key().sign(&canonical).to_bytes()),
    });
    b64(&serde_json::to_vec(&signed).unwrap())
}

/// `<run>/<step>/<task>`, a fresh task each time.
fn fresh_operation_id() -> String {
    format!("{RUN}/call_desk/{}", fresh_uuid())
}

/// The adapter's request id for an operation id (token.rs `request_id`): a
/// UUIDv5 over the organization, the API gate, the gateway and the
/// operation, which is what an operator, the desk's lock and OpenShell see.
fn request_id_of(gateway_url: &str, operation_id: &str) -> String {
    let mut parts = operation_id.split('/');
    let (run, step, task) = (
        parts.next().unwrap(),
        parts.next().unwrap(),
        parts.next().unwrap(),
    );
    let name = json!([
        "ekka.backend.v1 request",
        ORG,
        INSTANCE,
        gateway_url,
        WORKSPACE,
        run,
        step,
        task
    ])
    .to_string();
    let ns = uuid::Uuid::parse_str(REQUEST_ID_NAMESPACE).unwrap();
    uuid::Uuid::new_v5(&ns, name.as_bytes())
        .hyphenated()
        .to_string()
}

// ---------------------------------------------------------------------------
// The harness: the fakes, the adapter binary, and calls over its socket.
// ---------------------------------------------------------------------------

/// One HTTP answer from the adapter.
#[derive(Debug)]
struct Reply {
    status: u16,
    body: Value,
}

impl Reply {
    fn outcome(&self) -> &str {
        self.body["outcome"].as_str().unwrap_or_default()
    }
    fn code(&self) -> &str {
        self.body["code"].as_str().unwrap_or_default()
    }
    #[track_caller]
    fn assert_ready(&self) {
        assert_eq!(self.status, 200, "{self:?}");
        assert_eq!(self.outcome(), "ready", "{self:?}");
        assert_eq!(self.body["desk_ready"], true, "{self:?}");
        assert!(self.body.get("code").is_none(), "{self:?}");
    }
    #[track_caller]
    fn assert_refused(&self, code: &str) {
        assert_eq!(self.status, 200, "{self:?}");
        assert_eq!(self.outcome(), "refused", "{self:?}");
        assert_eq!(self.body["desk_ready"], false, "{self:?}");
        assert_eq!(self.code(), code, "{self:?}");
    }
    /// `running`: 202, the operation's request id, and nothing else.
    #[track_caller]
    fn assert_running(&self, request_id: &str) {
        assert_eq!(self.status, 202, "{self:?}");
        assert_eq!(
            self.body,
            json!({ "delivery": "first", "outcome": "running", "operation_id": request_id }),
        );
    }
}

/// One call as the API gate makes it.
#[derive(Clone)]
struct Call {
    method: String,
    path: String,
    body: Vec<u8>,
    grant: Grant,
    operation_id: String,
    /// Override the gate token header (None: sign one for this call).
    gate_token: Option<String>,
    credential: String,
}

struct Harness {
    dir: tempfile::TempDir,
    config: PathBuf,
    socket: PathBuf,
    gateway_url: String,
    gw: fake_gateway::Shared,
    idp: fake_issuer::Shared,
    enc: fake_enclave::Shared,
    child: Option<Child>,
    /// Everything the adapter printed, across restarts.
    output: Arc<Mutex<Vec<u8>>>,
    /// Every response body it sent.
    bodies: Vec<String>,
    grant: Value,
    /// How long one call may take before the harness fails it, by name:
    /// ABOVE the adapter's own deadline, so a hang inside the adapter shows
    /// as the adapter's failure (its deadline answer), not the harness's.
    call_limit: Duration,
}

impl Harness {
    async fn start() -> Self {
        Self::start_with(|_| {}).await
    }

    /// The fakes, then the adapter, with `tweak` applied to its config.
    async fn start_with(tweak: impl FnOnce(&mut Value)) -> Self {
        let (ca, cert, key) = fake_issuer::throwaway_ca();
        let idp = fake_issuer::start_tls(
            &fake_issuer::basic("ekka-desk-admin", SECRET),
            cert.clone(),
            key.clone(),
        )
        .await;
        idp.lock().unwrap().token_answer =
            json!({ "access_token": GW_TOKEN, "token_type": "Bearer", "expires_in": 300 });
        let issuer = idp.lock().unwrap().issuer.clone();
        let (addr, gw) = fake_gateway::start_tls(GW_TOKEN, cert, key).await;
        seed_github(&mut gw.lock().unwrap());
        let gateway_url = format!("https://{addr}");

        // A short path: a Unix socket's path is limited to about 100 bytes.
        let dir = tempfile::Builder::new()
            .prefix("ekb")
            .tempdir_in("/tmp")
            .unwrap();
        let sock_dir = dir.path().join("run");
        let state_dir = dir.path().join("state");
        for d in [&sock_dir, &state_dir] {
            std::fs::create_dir(d).unwrap();
            set_mode(d, 0o700);
        }
        let enc = fake_enclave::start(&sock_dir);
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, ca).unwrap();
        let socket = sock_dir.join("backend.sock");
        let mut config = json!({
            "config_version": 1,
            "organization_id": ORG,
            "api_gate_instance": INSTANCE,
            "govern_keys": [{ "key_id": KEY_ID, "public_key_b64": b64(govern_key().verifying_key().as_bytes()) }],
            "backend_gateway": {
                "url": gateway_url, "client_id": "ekka-desk-admin", "workspace": WORKSPACE,
                "issuer": issuer, "ca_pem_path": ca_path,
            },
            "deadline_seconds": 30,
            "socket_path": socket,
            "state_dir": state_dir,
        });
        tweak(&mut config);
        let config_path = dir.path().join("config.json");
        std::fs::write(&config_path, config.to_string()).unwrap();
        set_mode(&config_path, 0o600);
        let deadline = config["deadline_seconds"].as_u64().unwrap();
        let mut h = Self {
            dir,
            config: config_path,
            socket,
            gateway_url,
            gw,
            idp,
            enc,
            child: None,
            output: Arc::default(),
            bodies: Vec::new(),
            grant: grant(),
            call_limit: Duration::from_secs(deadline + 30),
        };
        h.spawn().await;
        h
    }

    /// Start the adapter and wait until it answers on its socket.
    async fn spawn(&mut self) {
        let mut child = Command::new(env!("CARGO_BIN_EXE_ekka-backend"))
            .arg("serve")
            .arg("--config")
            .arg(&self.config)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        for mut pipe in [
            Box::new(child.stdout.take().unwrap()) as Box<dyn std::io::Read + Send>,
            Box::new(child.stderr.take().unwrap()),
        ] {
            let out = self.output.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n) = pipe.read(&mut buf) {
                    if n == 0 {
                        return;
                    }
                    out.lock().unwrap().extend_from_slice(&buf[..n]);
                }
            });
        }
        let started = Instant::now();
        loop {
            if tokio::net::UnixStream::connect(&self.socket).await.is_ok() {
                break;
            }
            if let Some(status) = child.try_wait().unwrap() {
                panic!("the adapter exited {status}: {}", self.logs());
            }
            assert!(
                started.elapsed() < Duration::from_secs(20),
                "the adapter did not listen: {}",
                self.logs()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        self.child = Some(child);
    }

    /// Kill the adapter (no clean shutdown) and start it again on the same
    /// config and folders, with an empty process memory.
    async fn restart(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        self.spawn().await;
    }

    fn logs(&self) -> String {
        String::from_utf8_lossy(&self.output.lock().unwrap()).to_string()
    }

    fn call(&self, method: &str, path: &str, body: Option<&Value>, grant: Grant) -> Call {
        Call {
            method: method.to_string(),
            path: path.to_string(),
            body: body.map(|b| b.to_string().into_bytes()).unwrap_or_default(),
            grant,
            operation_id: fresh_operation_id(),
            gate_token: None,
            credential: SECRET.to_string(),
        }
    }

    /// Send one call over the socket, as the API gate does.
    async fn send(&mut self, c: &Call) -> Reply {
        let token = c
            .gate_token
            .clone()
            .unwrap_or_else(|| gate_token(&c.grant, &c.body));
        let head = format!(
            "{} {} HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\nx-ekka-gate-token: {token}\r\nauthorization: Bearer {}\r\nx-ekka-operation-id: {}\r\nx-ekka-backend-contract: ekka.backend.v1\r\n\r\n",
            c.method,
            c.path,
            c.body.len(),
            c.credential,
            c.operation_id,
        );
        // The whole exchange, connect to the last byte, has one limit; past
        // it the failure names the call and shows what the adapter printed.
        let exchange = async {
            let mut s = tokio::net::UnixStream::connect(&self.socket).await?;
            s.write_all(head.as_bytes()).await?;
            s.write_all(&c.body).await?;
            let mut raw = Vec::new();
            s.read_to_end(&mut raw).await?;
            Ok::<_, std::io::Error>(raw)
        };
        let raw = match tokio::time::timeout(self.call_limit, exchange).await {
            Ok(Ok(raw)) => raw,
            Ok(Err(e)) => panic!(
                "{} {} (operation {}) failed: {e}\n{}",
                c.method,
                c.path,
                c.operation_id,
                self.logs()
            ),
            Err(_) => panic!(
                "{} {} (operation {}) had no answer within {:?}, above the adapter's deadline\n{}",
                c.method,
                c.path,
                c.operation_id,
                self.call_limit,
                self.logs()
            ),
        };
        let text = String::from_utf8(raw).unwrap();
        let (head, body) = text.split_once("\r\n\r\n").unwrap();
        let status: u16 = head.split(' ').nth(1).unwrap().parse().unwrap();
        self.bodies.push(body.to_string());
        Reply {
            status,
            body: serde_json::from_str(body).unwrap_or(Value::Null),
        }
    }

    // --- The operations, as `ekka desk <op>` calls them. ---

    fn create_body(&self, policy: Value) -> Value {
        json!({ "name": DESK, "image": IMAGE, "policy": policy,
                "providers": ["github"], "environment": { "TZ": "UTC" } })
    }

    async fn create(&mut self, body: &Value) -> (Reply, String) {
        let c = self.call("POST", "/v1/desks", Some(body), Grant::write(&self.grant));
        let rid = request_id_of(&self.gateway_url, &c.operation_id);
        (self.send(&c).await, rid)
    }

    async fn create_desk(&mut self) {
        let body = self.create_body(base_policy());
        self.create(&body).await.0.assert_ready();
    }

    async fn change(&mut self, method: &str, path: &str, body: Option<&Value>) -> (Reply, String) {
        let c = self.call(method, path, body, Grant::write(&self.grant));
        let rid = request_id_of(&self.gateway_url, &c.operation_id);
        (self.send(&c).await, rid)
    }

    async fn status(&mut self) -> Reply {
        let c = self.call("GET", &format!("/v1/desks/{DESK}"), None, Grant::read());
        self.send(&c).await
    }

    async fn set_policy(&mut self, policy: Value, expected: &str) -> (Reply, String) {
        let body = json!({ "policy": policy, "expected_resource_version": expected });
        self.change("PUT", &format!("/v1/desks/{DESK}/policy"), Some(&body))
            .await
    }

    // --- What the fakes saw. ---

    /// The gateway calls that carried a request id: every change, by RPC.
    fn mutations(&self) -> Vec<(String, String)> {
        self.gw.lock().unwrap().request_ids.clone()
    }

    fn gateway_calls(&self) -> Vec<String> {
        self.gw.lock().unwrap().calls.clone()
    }

    fn enclave_calls(&self) -> Vec<(String, Value)> {
        self.enc.lock().unwrap().calls()
    }

    fn held(&self) -> Option<String> {
        self.enc.lock().unwrap().held.get(DESK).cloned()
    }

    fn mints(&self) -> usize {
        self.idp.lock().unwrap().mints()
    }

    /// Nothing the adapter wrote holds the credential or the token minted
    /// from it: no log line, no response body, no file under its folders.
    /// The gateway never received the credential either, only the token.
    #[track_caller]
    fn assert_no_secret_shown(&self) {
        let basic = fake_issuer::basic("ekka-desk-admin", SECRET);
        let basic = basic.trim_start_matches("Basic ");
        let planted = [SECRET, GW_TOKEN, basic];
        let logs = self.logs();
        assert!(
            logs.contains("\"answered\"") || logs.contains("answered"),
            "the adapter's log was captured: {logs}"
        );
        for p in planted {
            for (i, line) in logs.lines().enumerate() {
                assert!(!line.contains(p), "log line {i} shows a secret: {line}");
            }
            for b in &self.bodies {
                assert!(!b.contains(p), "a response shows a secret: {b}");
            }
            for f in files_under(self.dir.path()) {
                let bytes = std::fs::read(&f).unwrap_or_default();
                assert!(
                    !String::from_utf8_lossy(&bytes).contains(p),
                    "{} holds a secret",
                    f.display()
                );
            }
        }
        let seen = self.gw.lock().unwrap().seen_tokens.clone();
        assert!(
            seen.iter().all(|t| *t == format!("Bearer {GW_TOKEN}")),
            "the gateway got only the minted token: {seen:?}"
        );
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn set_mode(p: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// Every regular file under `dir`, sockets and the like left out.
fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in entries.flatten() {
        let p = e.path();
        let Ok(m) = std::fs::symlink_metadata(&p) else {
            continue;
        };
        if m.is_dir() {
            out.extend(files_under(&p));
        } else if m.is_file() {
            out.push(p);
        }
    }
    out
}

/// The GitHub provider and its profile, as the gateway holds them after the
/// kit's install (the same fixture the unit tests read).
fn seed_github(g: &mut fake_gateway::State) {
    let f = provider_fixture();
    let pool = prost_reflect::DescriptorPool::decode(openshell_proto::FILE_DESCRIPTOR_SET).unwrap();
    fn decode<T: prost::Message + Default>(
        pool: &prost_reflect::DescriptorPool,
        name: &str,
        v: &Value,
    ) -> T {
        let desc = pool.get_message_by_name(name).unwrap();
        let dynamic = prost_reflect::DynamicMessage::deserialize(desc, v.clone()).unwrap();
        dynamic.transcode_to().unwrap()
    }
    g.providers.insert(
        "github".into(),
        decode(&pool, "openshell.datamodel.v1.Provider", &f["provider"]),
    );
    g.profiles.insert(
        (WORKSPACE.into(), "github".into()),
        decode(&pool, "openshell.v1.ProviderProfile", &f["profile"]),
    );
}

/// Wait up to `limit` for `done`.
async fn eventually(limit: Duration, mut done: impl FnMut() -> bool) -> bool {
    let started = Instant::now();
    while started.elapsed() < limit {
        if done() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    done()
}

// ---------------------------------------------------------------------------
// Authorization: nothing unauthorized reaches anything.
// ---------------------------------------------------------------------------

/// The key the suite signs with is the one Govern's fixture was signed with,
/// and the fixture's own token, as Govern minted it, is verified and refused
/// only because its lifetime is over.
#[tokio::test(flavor = "multi_thread")]
async fn govern_s_own_fixture_token_is_verified_and_refused_only_as_expired() {
    let f = govern_fixture();
    assert_eq!(
        f["gate_token_public_key_b64"],
        b64(govern_key().verifying_key().as_bytes()),
        "the suite signs with Govern's TEST key"
    );
    let mut h = Harness::start().await;
    let mut c = h.call(
        "POST",
        &format!("/v1/desks/{DESK}/stop"),
        None,
        Grant::write(&h.grant.clone()),
    );
    c.gate_token = Some(b64(&serde_json::to_vec(&f["signed"]).unwrap()));
    h.send(&c).await.assert_refused("TOKEN_EXPIRED");
    assert!(h.gateway_calls().is_empty());
    assert!(h.enclave_calls().is_empty());
    h.assert_no_secret_shown();
}

/// A call without a valid authorization is refused before anything: no
/// sign-in, no gateway call, no claim.
#[tokio::test(flavor = "multi_thread")]
async fn a_call_without_a_valid_authorization_reaches_nothing() {
    let mut h = Harness::start().await;
    let stop = format!("/v1/desks/{DESK}/stop");
    let grant = h.grant.clone();

    let mut c = h.call("POST", &stop, None, Grant::write(&grant));
    c.gate_token = Some(String::new());
    h.send(&c).await.assert_refused("TOKEN_INVALID");

    let mut other_org = Grant::write(&grant);
    other_org.tenant = "22222222-2222-4222-8222-222222222222".into();
    let c = h.call("POST", &stop, None, other_org);
    h.send(&c).await.assert_refused("TOKEN_SCOPE");

    // A read token does not cover a change.
    let c = h.call("POST", &stop, None, Grant::read());
    h.send(&c).await.assert_refused("TOKEN_SCOPE");

    // A token signed for another body.
    let mut c = h.call("POST", &stop, None, Grant::write(&grant));
    c.gate_token = Some(gate_token(&c.grant, b"{}"));
    h.send(&c).await.assert_refused("TOKEN_SCOPE");

    // The same token twice: the second is a replay.
    let c = h.call("POST", &stop, None, Grant::write(&grant));
    let token = gate_token(&c.grant, &c.body);
    let c1 = Call {
        gate_token: Some(token.clone()),
        ..h.call("POST", &stop, None, Grant::write(&grant))
    };
    let first = h.send(&c1).await;
    let c2 = Call {
        gate_token: Some(token),
        ..h.call("POST", &stop, None, Grant::write(&grant))
    };
    h.send(&c2).await.assert_refused("TOKEN_REPLAYED");
    // (The first reached the backend: the desk does not exist.)
    first.assert_refused("DESK_NOT_FOUND");
    let reached = h.gateway_calls().len();

    let mut c = h.call("POST", &stop, None, Grant::write(&grant));
    c.credential = String::new();
    h.send(&c).await.assert_refused("CREDENTIAL_MISSING");

    let mut c = h.call("POST", "/v1/providers", None, Grant::write(&grant));
    c.gate_token = None;
    h.send(&c).await.assert_refused("NOT_AVAILABLE");

    let c = h.call(
        "POST",
        "/v1/desks/code-desk/reboot",
        None,
        Grant::write(&grant),
    );
    h.send(&c).await.assert_refused("UNKNOWN_OPERATION");

    assert_eq!(
        h.gateway_calls().len(),
        reached,
        "no refused call reached the gateway"
    );
    assert_eq!(h.mints(), 1, "only the admitted stop signed in");
    h.assert_no_secret_shown();
}

// ---------------------------------------------------------------------------
// create
// ---------------------------------------------------------------------------

/// A create inside its grant is made with ONE CreateSandbox, carrying the
/// operation's request id, between a claim and a release with its read-back.
#[tokio::test(flavor = "multi_thread")]
async fn a_create_inside_its_grant_is_made_once_and_answers_ready() {
    let mut h = Harness::start().await;
    let body = h.create_body(base_policy());
    let (r, rid) = h.create(&body).await;
    r.assert_ready();
    assert_eq!(r.body["delivery"], "first");
    assert_eq!(r.body["backend_id"], FIRST_ID);
    assert_eq!(r.body["resource_version"], "1");
    assert_eq!(r.body["policy_digest"], digest("policy", &base_policy()));
    assert_eq!(r.body["providers"], json!(["github"]));
    assert_eq!(h.mutations(), [("CreateSandbox".to_string(), rid.clone())]);
    {
        let g = h.gw.lock().unwrap();
        let sb = &g.sandboxes[DESK];
        let meta = sb.metadata.as_ref().unwrap();
        assert_eq!(meta.labels["ekka.ai/desk"], "true");
        assert_eq!(meta.labels["ekka.ai/operation"], rid);
        assert_eq!(
            sb.spec.as_ref().unwrap().template.as_ref().unwrap().image,
            IMAGE
        );
    }
    let calls = h.enclave_calls();
    assert_eq!(calls.len(), 2, "{calls:?}");
    assert_eq!(
        calls[0],
        (
            "runner_desk_claim".to_string(),
            json!({ "desk": DESK, "operation_id": rid })
        )
    );
    assert_eq!(calls[1].0, "runner_desk_release");
    assert_eq!(calls[1].1["outcome"], "ready");
    assert_eq!(calls[1].1["read_back"]["sandbox_id"], FIRST_ID);
    assert_eq!(h.held(), None, "the claim is released");
    h.assert_no_secret_shown();
}

/// A create outside ANY one limit of its grant is refused by that limit
/// before anything else: no sign-in, no gateway call, no claim.
#[tokio::test(flavor = "multi_thread")]
async fn a_create_outside_each_limit_is_refused_before_any_gateway_call() {
    let mut h = Harness::start().await;
    let base = h.create_body(base_policy());
    let with = |k: &str, v: Value| {
        let mut b = base.clone();
        b[k] = v;
        b
    };
    let cases = [
        (
            "an unlisted image",
            with(
                "image",
                json!(format!("ghcr.io/x/y@sha256:{}", "c".repeat(64))),
            ),
            "CONSTRAINT_IMAGE_DIGESTS",
        ),
        (
            "an image by tag",
            with("image", json!("ghcr.io/x/y:latest")),
            "REQUEST_INVALID",
        ),
        (
            "a policy whose digest is not listed",
            with("policy", narrowed_policy()),
            "CONSTRAINT_POLICY_DIGESTS",
        ),
        (
            "a host outside allowed_hosts",
            with("policy", off_host_policy()),
            "CONSTRAINT_ALLOWED_HOSTS",
        ),
        (
            "a port outside the baseline",
            with("policy", off_port_policy()),
            "CONSTRAINT_POLICY_BASELINE",
        ),
        (
            "an endpoint not enforced",
            with("policy", audited_policy()),
            "CONSTRAINT_POLICY_BASELINE",
        ),
        (
            "a provider rule the gateway adds itself",
            with("policy", provider_rule_policy()),
            "FIELD_NOT_ALLOWED",
        ),
        (
            "an unlisted provider",
            with("providers", json!(["slack"])),
            "CONSTRAINT_PROVIDERS",
        ),
        (
            "an unlisted environment key",
            with("environment", json!({ "AWS_REGION": "x" })),
            "CONSTRAINT_ENVIRONMENT_KEYS",
        ),
        (
            "a repository (nothing on a desk reads one)",
            with("repo", json!("https://github.com/acme/app.git")),
            "FIELD_NOT_ALLOWED",
        ),
        (
            "an unknown field",
            with("command", json!(["sh"])),
            "FIELD_NOT_ALLOWED",
        ),
    ];
    for (why, body, code) in cases {
        let (r, _) = h.create(&body).await;
        assert_eq!(r.code(), code, "{why}: {r:?}");
        r.assert_refused(code);
        assert!(
            h.gateway_calls().is_empty(),
            "{why}: {:?}",
            h.gateway_calls()
        );
        assert!(h.enclave_calls().is_empty(), "{why}");
        assert_eq!(h.mints(), 0, "{why}: no sign-in");
    }
    h.assert_no_secret_shown();
}

/// A provider whose configuration on the gateway is not the one the grant
/// pins is refused after reading it, and before the claim: nothing changes.
#[tokio::test(flavor = "multi_thread")]
async fn a_create_outside_provider_config_digests_is_refused_before_the_claim() {
    let mut h = Harness::start().await;
    h.grant["provider_config_digests"]["github"] = json!(format!("sha256:{}", "c".repeat(64)));
    let body = h.create_body(base_policy());
    let (r, _) = h.create(&body).await;
    r.assert_refused("CONSTRAINT_PROVIDER_CONFIG_DIGESTS");
    assert!(h.mutations().is_empty());
    assert!(
        h.gateway_calls()
            .iter()
            .all(|c| c.starts_with("GetProvider")),
        "only the provider was read: {:?}",
        h.gateway_calls()
    );
    assert!(h.enclave_calls().is_empty(), "no claim was taken");

    // A provider the gateway does not hold at all: the same refusal.
    let mut h = Harness::start().await;
    h.gw.lock().unwrap().providers.clear();
    let body = h.create_body(base_policy());
    h.create(&body)
        .await
        .0
        .assert_refused("CONSTRAINT_PROVIDER_CONFIG_DIGESTS");
    assert!(h.mutations().is_empty());
    assert!(h.enclave_calls().is_empty());
    h.assert_no_secret_shown();
}

/// A desk that exists already is not made again.
#[tokio::test(flavor = "multi_thread")]
async fn a_create_of_a_desk_that_exists_is_refused_and_released() {
    let mut h = Harness::start().await;
    h.create_desk().await;
    let body = h.create_body(base_policy());
    h.create(&body).await.0.assert_refused("DESK_EXISTS");
    assert_eq!(h.held(), None);
    h.assert_no_secret_shown();
}

// ---------------------------------------------------------------------------
// delete, stop, start
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_delete_removes_the_desk_with_one_delete_sandbox() {
    let mut h = Harness::start().await;
    h.create_desk().await;
    let (r, rid) = h.change("DELETE", &format!("/v1/desks/{DESK}"), None).await;
    r.assert_ready();
    assert!(h.gw.lock().unwrap().sandboxes.is_empty());
    assert_eq!(
        h.mutations().last(),
        Some(&("DeleteSandbox".to_string(), rid.clone()))
    );
    let release = h.enclave_calls().last().unwrap().clone();
    assert_eq!(release.0, "runner_desk_release");
    assert_eq!(release.1["operation_id"], rid);
    assert_eq!(release.1["outcome"], "ready");
    assert_eq!(h.held(), None);

    // A desk that is not there is refused, and nothing is deleted.
    h.change("DELETE", &format!("/v1/desks/{DESK}"), None)
        .await
        .0
        .assert_refused("DESK_NOT_FOUND");
    assert_eq!(
        h.mutations()
            .iter()
            .filter(|(m, _)| m == "DeleteSandbox")
            .count(),
        1
    );
    h.assert_no_secret_shown();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stop_then_a_start_each_make_one_call_and_answer_ready() {
    use openshell_proto::openshell::v1::SandboxPhase;
    let mut h = Harness::start().await;
    h.create_desk().await;
    let phase = |h: &Harness| {
        let g = h.gw.lock().unwrap();
        SandboxPhase::try_from(g.sandboxes[DESK].status.as_ref().unwrap().phase).unwrap()
    };
    let (r, stop_rid) = h
        .change("POST", &format!("/v1/desks/{DESK}/stop"), None)
        .await;
    r.assert_ready();
    assert_eq!(phase(&h), SandboxPhase::Stopped);
    let (r, start_rid) = h
        .change("POST", &format!("/v1/desks/{DESK}/start"), None)
        .await;
    r.assert_ready();
    assert_eq!(phase(&h), SandboxPhase::Ready);
    assert_ne!(stop_rid, start_rid);
    assert_eq!(
        h.mutations()[1..],
        [
            ("StopSandbox".to_string(), stop_rid),
            ("StartSandbox".to_string(), start_rid)
        ]
    );
    assert_eq!(h.held(), None);
    h.assert_no_secret_shown();
}

/// A stop of a desk the gateway does not have: refused, released.
#[tokio::test(flavor = "multi_thread")]
async fn a_change_to_a_desk_the_gateway_does_not_have_is_refused_and_released() {
    let mut h = Harness::start().await;
    h.create_desk().await;
    h.gw.lock()
        .unwrap()
        .faults
        .answer
        .insert("StopSandbox".into(), Planted::NotFound);
    h.change("POST", &format!("/v1/desks/{DESK}/stop"), None)
        .await
        .0
        .assert_refused("DESK_NOT_FOUND");
    assert_eq!(h.held(), None);
    // A read the gateway answers NOT_FOUND for.
    h.gw.lock()
        .unwrap()
        .faults
        .answer
        .insert("GetSandbox".into(), Planted::NotFound);
    h.status().await.assert_refused("DESK_NOT_FOUND");
    h.assert_no_secret_shown();
}

// ---------------------------------------------------------------------------
// policy_set
// ---------------------------------------------------------------------------

/// A narrower policy is applied with one UpdateConfig at the version the
/// plan read, and status then reports it as the desk's accepted policy.
#[tokio::test(flavor = "multi_thread")]
async fn a_narrowing_policy_is_applied_and_status_reports_it() {
    let mut h = Harness::start().await;
    h.create_desk().await;
    let (r, rid) = h.set_policy(narrowed_policy(), "1").await;
    r.assert_ready();
    let narrowed = digest("policy", &narrowed_policy());
    assert_eq!(r.body["policy_digest"], narrowed);
    assert_eq!(r.body["resource_version"], "2");
    assert_eq!(
        h.mutations().last(),
        Some(&("UpdateConfig".to_string(), rid))
    );
    let s = h.status().await;
    s.assert_ready();
    assert_eq!(
        s.body["policy_digest"], narrowed,
        "the ACTIVE policy, not the creation one"
    );
    h.assert_no_secret_shown();
}

/// Every change that widens what the desk may reach, or moves where a
/// provider's credentials go, is refused against the desk's CREATION policy
/// and the grant, after reading the desk and before any UpdateConfig.
#[tokio::test(flavor = "multi_thread")]
async fn a_widening_policy_is_refused_before_any_update() {
    let mut h = Harness::start().await;
    h.create_desk().await;
    let mut extra_program = base_policy();
    extra_program["networkPolicies"]["github"]["binaries"] =
        json!([{ "path": "/usr/bin/git" }, { "path": "/usr/bin/curl" }]);
    let mut wider_files = base_policy();
    wider_files["filesystem"]["readWrite"] = json!(["/sandbox", "/etc"]);
    let mut audited = base_policy();
    audited["networkPolicies"]["github"]["endpoints"][0]["enforcement"] =
        json!("NETWORK_ENFORCEMENT_MODE_AUDIT");
    let cases = [
        (
            "a host outside the grant",
            off_host_policy(),
            "CONSTRAINT_ALLOWED_HOSTS",
        ),
        (
            "a port outside the grant",
            off_port_policy(),
            "CONSTRAINT_POLICY_BASELINE",
        ),
        (
            "a program the creation policy did not name",
            extra_program,
            "CONSTRAINT_POLICY_BASELINE",
        ),
        (
            "a wider filesystem",
            wider_files,
            "CONSTRAINT_POLICY_BASELINE",
        ),
        (
            "an endpoint no longer enforced",
            audited,
            "CONSTRAINT_POLICY_BASELINE",
        ),
        (
            "a provider rule",
            provider_rule_policy(),
            "FIELD_NOT_ALLOWED",
        ),
    ];
    for (why, policy, code) in cases {
        h.set_policy(policy, "1").await.0.assert_refused(code);
        assert!(
            !h.mutations().iter().any(|(m, _)| m == "UpdateConfig"),
            "{why}: no UpdateConfig"
        );
        assert_eq!(h.held(), None, "{why}: released");
        let last = h.enclave_calls().last().unwrap().clone();
        assert_eq!(last.1["outcome"], "refused", "{why}");
    }
    h.assert_no_secret_shown();
}

/// A rule with no programs is open to ANY program in NVIDIA OpenShell: a
/// change that leaves one is refused when the creation policy had none.
#[tokio::test(flavor = "multi_thread")]
async fn an_empty_binaries_policy_is_refused() {
    let mut h = Harness::start().await;
    h.create_desk().await;
    let open = policy_with(vec![endpoint("api.github.com", 443)], &[]);
    h.set_policy(open, "1")
        .await
        .0
        .assert_refused("CONSTRAINT_POLICY_BASELINE");
    assert!(!h.mutations().iter().any(|(m, _)| m == "UpdateConfig"));
    h.assert_no_secret_shown();
}

/// A change never adds, changes or moves an endpoint carrying a provider's
/// credentials: that is a provider change, made at install.
#[tokio::test(flavor = "multi_thread")]
async fn a_credential_endpoint_change_is_refused() {
    let mut h = Harness::start().await;
    h.create_desk().await;
    let mut bound = base_policy();
    bound["networkPolicies"]["github"]["endpoints"][0]["credentialBinding"] =
        json!({ "provider": "github" });
    h.set_policy(bound, "1")
        .await
        .0
        .assert_refused("CONSTRAINT_CREDENTIAL_ENDPOINT");
    let mut uninspected = base_policy();
    uninspected["networkPolicies"]["github"]["endpoints"][0]["allowUninspectedCredentials"] =
        json!(true);
    h.set_policy(uninspected, "1")
        .await
        .0
        .assert_refused("CONSTRAINT_CREDENTIAL_ENDPOINT");
    assert!(!h.mutations().iter().any(|(m, _)| m == "UpdateConfig"));
    h.assert_no_secret_shown();
}

/// Compare-and-set: a change at a version the desk has moved past is
/// refused VERSION_CONFLICT, whether the plan read an old version or the
/// gateway loses the race itself (OpenShell's exact ABORTED status).
#[tokio::test(flavor = "multi_thread")]
async fn a_change_at_a_stale_version_is_refused_version_conflict() {
    let mut h = Harness::start().await;
    h.create_desk().await;
    h.set_policy(narrowed_policy(), "9")
        .await
        .0
        .assert_refused("VERSION_CONFLICT");
    h.gw.lock().unwrap().faults.answer.insert(
        "UpdateConfig".into(),
        Planted::VersionConflict { current: Some(2) },
    );
    h.set_policy(narrowed_policy(), "1")
        .await
        .0
        .assert_refused("VERSION_CONFLICT");
    assert_eq!(
        h.gw.lock().unwrap().revisions[DESK].len(),
        1,
        "nothing applied"
    );
    assert_eq!(h.held(), None);
    h.assert_no_secret_shown();
}

// ---------------------------------------------------------------------------
// provider_detach
// ---------------------------------------------------------------------------

/// A provider the desk's agent does not require is detached, and the answer
/// carries the remaining providers and their digest; one it requires is
/// refused DESK_PROVIDER_REQUIRED with no gateway change.
#[tokio::test(flavor = "multi_thread")]
async fn a_detach_is_made_and_a_required_provider_is_refused() {
    let mut h = Harness::start().await;
    h.create_desk().await;
    {
        let mut g = h.gw.lock().unwrap();
        let spec = g.sandboxes.get_mut(DESK).unwrap().spec.as_mut().unwrap();
        spec.providers = vec!["github".into(), "slack".into()];
    }
    h.enc
        .lock()
        .unwrap()
        .required
        .insert(DESK.into(), vec!["github".into()]);
    let body = json!({ "expected_resource_version": "1" });

    let (r, _) = h
        .change(
            "DELETE",
            &format!("/v1/desks/{DESK}/providers/github"),
            Some(&body),
        )
        .await;
    r.assert_refused("DESK_PROVIDER_REQUIRED");
    assert!(!h
        .mutations()
        .iter()
        .any(|(m, _)| m == "DetachSandboxProvider"));
    assert_eq!(h.held(), None);

    let (r, rid) = h
        .change(
            "DELETE",
            &format!("/v1/desks/{DESK}/providers/slack"),
            Some(&body),
        )
        .await;
    r.assert_ready();
    assert_eq!(r.body["providers"], json!(["github"]));
    assert!(r.body["providers_digest"]
        .as_str()
        .is_some_and(|d| d.starts_with("sha256:")));
    assert_eq!(
        h.mutations().last(),
        Some(&("DetachSandboxProvider".to_string(), rid))
    );
    assert_eq!(h.held(), None);
    h.assert_no_secret_shown();
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

/// status returns the configuration the desk was accepted with, takes no
/// claim, and changes nothing.
#[tokio::test(flavor = "multi_thread")]
async fn status_returns_the_accepted_configuration_and_changes_nothing() {
    let mut h = Harness::start().await;
    h.create_desk().await;
    let before = h.enclave_calls().len();
    let s = h.status().await;
    s.assert_ready();
    assert_eq!(s.body["backend_id"], FIRST_ID);
    assert_eq!(s.body["resource_version"], "1");
    assert_eq!(s.body["policy_digest"], digest("policy", &base_policy()));
    assert_eq!(s.body["providers"], json!(["github"]));
    let pd = s.body["providers_digest"].as_str().unwrap().to_string();
    assert!(pd.starts_with("sha256:") && pd.len() == 71, "{pd}");
    assert_eq!(h.status().await.body["providers_digest"], pd, "stable");
    assert_eq!(h.enclave_calls().len(), before, "a read takes no claim");
    assert_eq!(h.mutations().len(), 1, "only the create changed anything");
    h.status_absent().await;
    h.assert_no_secret_shown();
}

impl Harness {
    async fn status_absent(&mut self) {
        let c = self.call("GET", "/v1/desks/no-such-desk", None, Grant::read());
        self.send(&c).await.assert_refused("DESK_NOT_FOUND");
    }
}

// ---------------------------------------------------------------------------
// A change that may still finish: running, and the desk stays held.
// ---------------------------------------------------------------------------

/// The gateway applies the stop and its reply is lost: the adapter cannot
/// tell, so it answers 202 `running` with the request id, and the desk stays
/// claimed. Nobody releases it by hand.
#[tokio::test(flavor = "multi_thread")]
async fn a_lost_reply_answers_202_running_and_the_claim_is_held() {
    let mut h = Harness::start().await;
    h.create_desk().await;
    h.gw.lock().unwrap().lose_reply.insert("StopSandbox".into());
    let (r, rid) = h
        .change("POST", &format!("/v1/desks/{DESK}/stop"), None)
        .await;
    r.assert_running(&rid);
    assert_eq!(h.held(), Some(rid.clone()), "the desk stays claimed");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(h.held(), Some(rid.clone()), "and stays so");
    let last = h.enclave_calls().last().unwrap().clone();
    assert_eq!(last.0, "runner_desk_claim", "never released");
    assert_eq!(
        h.mutations().last(),
        Some(&("StopSandbox".to_string(), rid))
    );
    h.assert_no_secret_shown();
}

/// The same when the connection drops after the gateway's write, with no
/// gRPC status at all.
#[tokio::test(flavor = "multi_thread")]
async fn a_dropped_connection_after_the_write_answers_running_and_the_claim_is_held() {
    let mut h = Harness::start().await;
    h.create_desk().await;
    h.gw.lock()
        .unwrap()
        .faults
        .drop_reply
        .insert("StopSandbox".into());
    let (r, rid) = h
        .change("POST", &format!("/v1/desks/{DESK}/stop"), None)
        .await;
    r.assert_running(&rid);
    assert_eq!(h.held(), Some(rid));
    h.assert_no_secret_shown();
}

/// A gateway slower than the adapter's deadline: the call answers
/// 202 `running` at the deadline with the desk held, the change goes on, and
/// when it lands the claim is released with its result.
#[tokio::test(flavor = "multi_thread")]
async fn a_change_past_the_deadline_answers_running_and_finishes_on_its_own() {
    let mut h = Harness::start_with(|c| c["deadline_seconds"] = json!(2)).await;
    h.create_desk().await;
    h.gw.lock()
        .unwrap()
        .faults
        .delay
        .insert("StopSandbox".into(), Duration::from_secs(4));
    let started = Instant::now();
    let (r, rid) = h
        .change("POST", &format!("/v1/desks/{DESK}/stop"), None)
        .await;
    let took = started.elapsed();
    r.assert_running(&rid);
    assert!(
        took < Duration::from_secs(4),
        "answered at the deadline, not after the gateway: {took:?}"
    );
    assert_eq!(h.held(), Some(rid.clone()), "held while the stop is out");
    let released = eventually(Duration::from_secs(20), || h.held().is_none()).await;
    assert!(released, "the stop landed and the claim was released");
    let last = h.enclave_calls().last().unwrap().clone();
    assert_eq!(last.0, "runner_desk_release");
    assert_eq!(last.1["operation_id"], rid);
    assert_eq!(last.1["outcome"], "ready");
    h.assert_no_secret_shown();
}

// ---------------------------------------------------------------------------
// No credential is ever shown.
// ---------------------------------------------------------------------------

/// Every operation, refused and admitted, and a lost reply: the planted
/// credential and the gateway token minted from it appear in no log line, no
/// response body and no file under the adapter's folders.
#[tokio::test(flavor = "multi_thread")]
async fn a_planted_credential_never_appears_in_a_log_line_a_response_or_a_file() {
    let mut h = Harness::start().await;
    h.create_desk().await;
    h.status().await.assert_ready();
    let c = h.call(
        "GET",
        &format!("/v1/desks/{DESK}/policy"),
        None,
        Grant::read(),
    );
    h.send(&c).await.assert_ready();
    h.set_policy(narrowed_policy(), "1").await.0.assert_ready();
    h.set_policy(off_host_policy(), "2")
        .await
        .0
        .assert_refused("CONSTRAINT_ALLOWED_HOSTS");
    h.change("POST", &format!("/v1/desks/{DESK}/stop"), None)
        .await
        .0
        .assert_ready();
    // A wrong credential: the sign-in service refuses it.
    let mut c = h.call(
        "POST",
        &format!("/v1/desks/{DESK}/start"),
        None,
        Grant::write(&h.grant.clone()),
    );
    c.credential = "PLANTED-wrong-credential-3Lp0".into();
    h.send(&c).await.assert_refused("BACKEND_REFUSED");
    assert!(!h.logs().contains("PLANTED-wrong-credential-3Lp0"));
    h.gw.lock()
        .unwrap()
        .lose_reply
        .insert("StartSandbox".into());
    let (r, rid) = h
        .change("POST", &format!("/v1/desks/{DESK}/start"), None)
        .await;
    r.assert_running(&rid);
    h.assert_no_secret_shown();
}

// ---------------------------------------------------------------------------
// Recovery: written in full, on until the durable store lands.
// ---------------------------------------------------------------------------

/// The same operation delivered again, with the same token or a renewed
/// one, answers its recorded outcome as `duplicate` and calls nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_redelivered_operation_answers_duplicate_and_calls_nothing() {
    let mut h = Harness::start().await;
    let body = h.create_body(base_policy());
    let c = h.call(
        "POST",
        "/v1/desks",
        Some(&body),
        Grant::write(&h.grant.clone()),
    );
    let token = gate_token(&c.grant, &c.body);
    let c = Call {
        gate_token: Some(token),
        ..c
    };
    let first = h.send(&c).await;
    first.assert_ready();
    // The same token, the same operation.
    let again = h.send(&c).await;
    assert_eq!(again.body["delivery"], "duplicate", "{again:?}");
    assert_eq!(again.body["outcome"], first.body["outcome"]);
    assert_eq!(again.body["backend_id"], first.body["backend_id"]);
    // A renewed token for the same operation.
    let renewed = Call {
        gate_token: None,
        ..c
    };
    let r = h.send(&renewed).await;
    assert_eq!(r.body["delivery"], "duplicate");
    assert_eq!(h.mutations().len(), 1, "one CreateSandbox in all");
    // A refusal delivered twice stays refused.
    let bad = h.create_body(off_port_policy());
    let c = h.call(
        "POST",
        "/v1/desks",
        Some(&bad),
        Grant::write(&h.grant.clone()),
    );
    h.send(&c)
        .await
        .assert_refused("CONSTRAINT_POLICY_BASELINE");
    let r = h
        .send(&Call {
            gate_token: None,
            ..c
        })
        .await;
    assert_eq!(r.body["delivery"], "duplicate");
    assert_eq!(r.outcome(), "refused");
    h.assert_no_secret_shown();
}

/// The same operation id with a different request is refused, and nothing
/// is called.
#[tokio::test(flavor = "multi_thread")]
async fn the_same_operation_id_with_another_request_is_refused() {
    let mut h = Harness::start().await;
    let body = h.create_body(base_policy());
    let c = h.call(
        "POST",
        "/v1/desks",
        Some(&body),
        Grant::write(&h.grant.clone()),
    );
    h.send(&c).await.assert_ready();
    let mut other = h.create_body(base_policy());
    other["environment"] = json!({ "TZ": "Europe/Paris" });
    let c2 = Call {
        body: other.to_string().into_bytes(),
        gate_token: None,
        ..c
    };
    h.send(&c2).await.assert_refused("OPERATION_ID_REUSED");
    assert_eq!(h.mutations().len(), 1);
    h.assert_no_secret_shown();
}

/// A recorded outcome survives a restart: the adapter answers it from its
/// store, without asking the gateway.
#[tokio::test(flavor = "multi_thread")]
async fn a_recorded_outcome_survives_a_restart() {
    let mut h = Harness::start().await;
    let body = h.create_body(base_policy());
    let c = h.call(
        "POST",
        "/v1/desks",
        Some(&body),
        Grant::write(&h.grant.clone()),
    );
    h.send(&c).await.assert_ready();
    h.restart().await;
    let calls = h.gateway_calls().len();
    let r = h
        .send(&Call {
            gate_token: None,
            ..c
        })
        .await;
    assert_eq!(r.body["delivery"], "duplicate");
    assert_eq!(r.outcome(), "ready");
    assert_eq!(h.gateway_calls().len(), calls, "the store answered");
    h.assert_no_secret_shown();
}

/// A lost reply, then a COLD restart: the stored request, token and request
/// id are enough for the next `status` of that desk to re-issue it under the
/// same request id; the gateway's replayed success settles it `ready` and
/// frees the desk. One sandbox in all. A status of ANOTHER desk does not
/// touch the record.
#[tokio::test(flavor = "multi_thread")]
async fn a_lost_reply_is_settled_by_the_next_status_after_a_cold_restart() {
    let mut h = Harness::start().await;
    h.gw.lock()
        .unwrap()
        .lose_reply
        .insert("CreateSandbox".into());
    let body = h.create_body(base_policy());
    let (r, rid) = h.create(&body).await;
    r.assert_running(&rid);
    h.gw.lock().unwrap().lose_reply.clear();
    h.restart().await;
    h.status_absent().await;
    assert_eq!(h.held(), Some(rid.clone()), "another desk's status left it");
    h.status().await.assert_ready();
    let creates: Vec<_> = h
        .mutations()
        .into_iter()
        .filter(|(m, _)| m == "CreateSandbox")
        .collect();
    assert!(
        creates.iter().all(|(_, id)| *id == rid),
        "always the same request id"
    );
    assert_eq!(h.gw.lock().unwrap().sandboxes.len(), 1);
    assert_eq!(h.held(), None, "settled and released");
    h.assert_no_secret_shown();
}

/// The gateway admits a create and loses its finalizer: every re-issue
/// answers REQUEST_OUTCOME_UNCERTAIN, so the record stays `running` across
/// two restarts and a status, and the desk stays held. Only the host's settle
/// marker for THIS operation settles it, by read-back, once.
#[tokio::test(flavor = "multi_thread")]
async fn an_uncertain_change_is_settled_only_by_its_own_marker() {
    let mut h = Harness::start().await;
    // The create runs and its finalizer is lost: the gateway keeps the
    // admission with no recorded success, so every re-issue is UNCERTAIN, as
    // OpenShell answers it (mutation_replay.rs:302, 557-560).
    h.gw.lock()
        .unwrap()
        .lose_finalizer
        .insert("CreateSandbox".into());
    let body = h.create_body(base_policy());
    let (r, rid) = h.create(&body).await;
    r.assert_running(&rid);
    h.gw.lock().unwrap().lose_finalizer.clear();
    // A marker's restart and quiet window, from now, on the adapter's own
    // clock (the real one).
    let at = |s: i64| {
        (chrono::Utc::now() + chrono::Duration::seconds(s))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    };
    // What a status shows of the desk itself is not the point here: the
    // RECORD stays running, so the desk stays held.
    for _ in 0..2 {
        h.restart().await;
        h.status().await;
        assert_eq!(h.held(), Some(rid.clone()));
    }
    // A marker for another desk, another sandbox or another gateway is
    // refused; the record stays running.
    let state = h.dir.path().join("state").join("settle");
    std::fs::create_dir_all(&state).unwrap();
    set_mode(&state, 0o700);
    // Every status below re-issues the change (inside the bound), so a
    // marker counts only for a restart after the LAST of them.
    let marker = |desk: &str, backend: &str, gateway: &str, (restarted, quiet): (&str, &str)| {
        json!({
            "operation_id": rid, "desk": desk, "backend_id": backend,
            "gateway_identity": gateway,
            "gateway_restarted_at": restarted,
            "quiet_until": quiet,
            "containers": [{ "id": "a".repeat(64), "state": "running" }]
        })
    };
    let path = state.join(format!("{rid}.json"));
    let url = h.gateway_url.clone();
    let gateway = format!("{url}#{WORKSPACE}");
    // Each wrong marker has GOOD times (a restart after the last send, a
    // quiet window that has ended), so it is refused for its one fault.
    let wrongs: [(&str, &str, &str); 4] = [
        ("other-desk", FIRST_ID, &gateway),
        (DESK, "00000000-0000-4000-8000-000000000099", &gateway),
        (DESK, FIRST_ID, "https://another.gateway.example#desks"),
        // The gateway's url alone is not its identity: url#workspace.
        (DESK, FIRST_ID, &url),
    ];
    for (desk, backend, gw) in wrongs {
        let (restarted, quiet) = (at(1), at(2));
        tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
        let wrong = marker(desk, backend, gw, (&restarted, &quiet));
        std::fs::write(&path, wrong.to_string()).unwrap();
        set_mode(&path, 0o600);
        h.status().await;
        assert_eq!(h.held(), Some(rid.clone()), "{wrong}");
    }
    let (restarted, quiet) = (at(1), at(2));
    // The quiet window has ended by the adapter's clock.
    tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
    std::fs::write(
        &path,
        marker(DESK, FIRST_ID, &gateway, (&restarted, &quiet)).to_string(),
    )
    .unwrap();
    set_mode(&path, 0o600);
    let creates = h.mutations().len();
    h.status().await.assert_ready();
    assert_eq!(h.mutations().len(), creates, "a settle never re-issues");
    assert_eq!(h.held(), None, "settled by read-back and released");
    assert!(!path.exists(), "the marker is consumed");
    // Consumed once: another status changes nothing.
    let enclave = h.enclave_calls().len();
    h.status().await.assert_ready();
    assert_eq!(h.mutations().len(), creates);
    assert_eq!(h.enclave_calls().len(), enclave);
    h.assert_no_secret_shown();
}

/// ONE ADAPTER PER STATE FOLDER, through the real binary: a second adapter
/// started on the same config refuses to start (STATE_IN_USE), and the first
/// still answers. Recovery's rule for a send from an earlier process relies
/// on it.
#[tokio::test]
async fn a_second_adapter_on_the_same_state_folder_refuses_to_start() {
    let mut h = Harness::start().await;
    let mut second = Command::new(env!("CARGO_BIN_EXE_ekka-backend"))
        .arg("serve")
        .arg("--config")
        .arg(&h.config)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let started = Instant::now();
    let status = loop {
        if let Some(s) = second.try_wait().unwrap() {
            break s;
        }
        if started.elapsed() > Duration::from_secs(20) {
            let _ = second.kill();
            let _ = second.wait();
            panic!("a second adapter on the same state folder kept running");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let mut err = String::new();
    second
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    assert!(!status.success(), "{err}");
    assert!(err.contains("STATE_IN_USE"), "{err}");
    h.status().await;
    assert!(
        h.child.as_mut().unwrap().try_wait().unwrap().is_none(),
        "the first still runs"
    );
}

/// The search itself finds a planted secret, in a file and in a response:
/// a clean result above means something.
#[tokio::test(flavor = "multi_thread")]
async fn the_secret_search_finds_a_planted_secret() {
    let mut h = Harness::start().await;
    h.status_absent().await;
    h.assert_no_secret_shown();
    let planted = h.dir.path().join("state").join("x.json");
    std::fs::write(&planted, format!("{{\"k\":\"{SECRET}\"}}")).unwrap();
    let caught =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| h.assert_no_secret_shown()));
    assert!(caught.is_err(), "a secret in a file is found");
    std::fs::remove_file(&planted).unwrap();
    h.bodies.push(format!("{{\"x\":\"{GW_TOKEN}\"}}"));
    let caught =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| h.assert_no_secret_shown()));
    assert!(caught.is_err(), "a secret in a response is found");
}
