use std::io::Write as _;
use std::os::unix::fs::PermissionsExt;

use serde_json::{json, Value};

use super::{check, load, Config};

const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="; // 32 zero bytes

fn uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn good() -> Value {
    json!({
        "config_version": 1,
        "organization_id": "11111111-1111-4111-8111-111111111111",
        "api_gate_instance": "enclave3a7e592fApi",
        "govern_keys": [{ "key_id": "govern-gate-token-v1", "public_key_b64": KEY }],
        "backend_gateway": {
            "url": "https://gateway.example:8443",
            "client_id": "ekka-desk-admin",
            "workspace": "desks",
            "issuer": "https://desks.example/realms/ekka-desks"
        }
    })
}

fn file(v: &Value, mode: u32) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(v.to_string().as_bytes()).unwrap();
    std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(mode)).unwrap();
    f
}

#[test]
fn a_good_file_loads_with_its_defaults_and_logs_its_digest_and_key_ids_never_a_key() {
    let f = file(&good(), 0o600);
    let l = load(f.path(), uid()).unwrap();
    assert_eq!(l.config.deadline_seconds, 120);
    assert_eq!(
        l.config.socket_path.to_str(),
        Some("/run/ekka-backend/backend.sock")
    );
    assert_eq!(l.config.state_dir.to_str(), Some("/var/lib/ekka-backend"));
    assert!(
        l.digest.starts_with("sha256:") && l.digest.len() == 71,
        "{}",
        l.digest
    );
    let line = l.start_line();
    assert!(
        line.contains(&l.digest) && line.contains("govern-gate-token-v1"),
        "{line}"
    );
    assert!(!line.contains(KEY), "a key is never logged: {line}");
}

#[test]
fn the_same_bytes_give_the_same_digest_and_a_change_moves_it() {
    let a = load(file(&good(), 0o600).path(), uid()).unwrap().digest;
    let b = load(file(&good(), 0o600).path(), uid()).unwrap().digest;
    assert_eq!(a, b);
    let mut v = good();
    v["deadline_seconds"] = json!(60);
    let c = load(file(&v, 0o600).path(), uid()).unwrap().digest;
    assert_ne!(a, c);
}

#[test]
fn a_file_others_can_write_a_symlink_or_another_owner_is_refused() {
    let f = file(&good(), 0o620);
    let e = load(f.path(), uid()).unwrap_err();
    assert!(e.starts_with("CONFIG_UNSAFE"), "{e}");
    // The refusal names the fix, on the very file it refused.
    assert!(
        e.ends_with(&format!("fix: chmod go-w {}", f.path().display())),
        "{e}"
    );
    let f = file(&good(), 0o602);
    assert!(load(f.path(), uid())
        .unwrap_err()
        .starts_with("CONFIG_UNSAFE"));

    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real.json");
    std::fs::write(&real, good().to_string()).unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o600)).unwrap();
    let link = dir.path().join("config.json");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert!(load(&link, uid()).unwrap_err().contains("is a symlink"));

    // Owned by this test's user: refused when the adapter runs as another.
    let other = uid().wrapping_add(1).max(1);
    let f = file(&good(), 0o600);
    let e = load(f.path(), other).unwrap_err();
    assert!(e.contains("neither this process's"), "{e}");
}

#[test]
fn an_unknown_key_is_refused_at_every_level() {
    for (at, key) in [
        (vec![], "debug"),
        (vec!["backend_gateway"], "password"),
        (vec!["govern_keys", "0"], "alg"),
    ] {
        let mut v = good();
        let mut o = &mut v;
        for k in &at {
            o = if let Ok(i) = k.parse::<usize>() {
                &mut o[i]
            } else {
                &mut o[*k]
            };
        }
        o.as_object_mut().unwrap().insert(key.into(), json!(1));
        let e = load(file(&v, 0o600).path(), uid()).unwrap_err();
        assert!(
            e.contains(key) && e.starts_with("CONFIG_INVALID"),
            "{key}: {e}"
        );
    }
}

#[test]
fn each_value_the_adapter_may_not_hold_is_refused_by_name() {
    let base: Config = serde_json::from_value(good()).unwrap();
    check(&base).unwrap();
    type Plant = Box<dyn Fn(&mut Value)>;
    let cases: Vec<(&str, Plant)> = vec![
        (
            "config_version",
            Box::new(|v| v["config_version"] = json!(2)),
        ),
        (
            "organization_id",
            Box::new(|v| v["organization_id"] = json!("")),
        ),
        (
            "api_gate_instance",
            Box::new(|v| v["api_gate_instance"] = json!("a b")),
        ),
        ("1 or 2 keys", Box::new(|v| v["govern_keys"] = json!([]))),
        (
            "1 or 2 keys",
            Box::new(|v| {
                let k = v["govern_keys"][0].clone();
                v["govern_keys"] = json!([k.clone(), { "key_id": "b", "public_key_b64": KEY }, { "key_id": "c", "public_key_b64": KEY }]);
            }),
        ),
        (
            "twice",
            Box::new(|v| {
                let k = v["govern_keys"][0].clone();
                v["govern_keys"] = json!([k.clone(), k]);
            }),
        ),
        (
            "not base64",
            Box::new(|v| v["govern_keys"][0]["public_key_b64"] = json!("!!")),
        ),
        (
            "32",
            Box::new(|v| v["govern_keys"][0]["public_key_b64"] = json!("AAAA")),
        ),
        (
            "https origin",
            Box::new(|v| v["backend_gateway"]["url"] = json!("http://gateway:80")),
        ),
        (
            "ca_pem_path",
            Box::new(|v| v["backend_gateway"]["ca_pem_path"] = json!("ca.pem")),
        ),
        (
            "deadline_seconds",
            Box::new(|v| v["deadline_seconds"] = json!(150)),
        ),
        (
            "deadline_seconds",
            Box::new(|v| v["deadline_seconds"] = json!(0)),
        ),
        (
            "absolute",
            Box::new(|v| v["socket_path"] = json!("backend.sock")),
        ),
        ("absolute", Box::new(|v| v["state_dir"] = json!("state"))),
    ];
    for (want, plant) in cases {
        let mut v = good();
        plant(&mut v);
        let c: Config = serde_json::from_value(v.clone()).unwrap();
        let e = check(&c).unwrap_err();
        assert!(e.contains(want), "{want}: {e}");
    }
    let mut v = good();
    v["deadline_seconds"] = json!(149);
    check(&serde_json::from_value(v).unwrap()).unwrap();
}

fn vendored(rel: &str) -> Value {
    let path = format!(
        "{}/../../vendor/contracts/backend/{rel}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// The contract's own sample file loads.
#[test]
fn the_contracts_sample_config_loads() {
    let f = file(&vendored("samples/adapter-config.json"), 0o600);
    let l = load(f.path(), uid()).unwrap();
    assert_eq!(l.config.api_gate_instance, "enclave1a2b3c4dApi");
}

/// THE CHECKS ARE THE PUBLISHED SCHEMA'S. The adapter has no JSON Schema
/// engine, so `check` restates `adapter-config.v1`; this compares the two,
/// so a contract change to a field, a limit or a pattern fails here.
#[test]
fn the_checks_are_the_published_schemas() {
    let s = vendored("adapter-config.v1.schema.json");
    let keys = |o: &Value| {
        let mut k: Vec<String> = o.as_object().unwrap().keys().cloned().collect();
        k.sort();
        k
    };
    assert_eq!(
        keys(&s["properties"]),
        [
            "api_gate_instance",
            "backend_gateway",
            "config_version",
            "deadline_seconds",
            "govern_keys",
            "organization_id",
            "socket_path",
            "state_dir"
        ]
    );
    let mut req: Vec<&str> = s["required"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    req.sort_unstable();
    assert_eq!(
        req,
        [
            "api_gate_instance",
            "backend_gateway",
            "config_version",
            "govern_keys",
            "organization_id"
        ]
    );
    assert_eq!(s["additionalProperties"], false);
    let p = &s["properties"];
    assert_eq!(p["config_version"]["const"], 1);
    assert_eq!(
        s["$defs"]["uuid"]["pattern"],
        "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    );
    assert_eq!(p["api_gate_instance"]["pattern"], "^enclave[0-9a-f]{8}Api$");
    let k = &p["govern_keys"];
    assert_eq!(
        (k["minItems"].as_u64(), k["maxItems"].as_u64()),
        (Some(1), Some(2))
    );
    assert_eq!(k["items"]["additionalProperties"], false);
    assert_eq!(
        k["items"]["properties"]["key_id"]["pattern"],
        "^[!-~]{1,128}$"
    );
    assert_eq!(
        k["items"]["properties"]["public_key_b64"]["pattern"],
        "^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$"
    );
    let g = &p["backend_gateway"];
    assert_eq!(g["additionalProperties"], false);
    assert_eq!(
        keys(&g["properties"]),
        ["ca_pem_path", "client_id", "issuer", "url", "workspace"]
    );
    let mut greq: Vec<&str> = g["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    greq.sort_unstable();
    assert_eq!(greq, ["client_id", "issuer", "url", "workspace"]);
    let i = &g["properties"]["issuer"];
    assert_eq!(
        i["pattern"],
        "^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~-]+)*$"
    );
    assert_eq!(i["not"]["pattern"], "/\\.\\.?(/|$)");
    assert_eq!(i["maxLength"], 512);
    assert_eq!(
        g["properties"]["url"]["pattern"],
        "^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$"
    );
    assert_eq!(g["properties"]["url"]["maxLength"], 512);
    assert_eq!(g["properties"]["client_id"]["const"], "ekka-desk-admin");
    assert_eq!(
        g["properties"]["workspace"]["pattern"],
        "^[a-z0-9][a-z0-9._-]{0,62}$"
    );
    assert_eq!(
        (
            p["deadline_seconds"]["minimum"].as_u64(),
            p["deadline_seconds"]["maximum"].as_u64()
        ),
        (Some(1), Some(149))
    );
    assert_eq!(p["deadline_seconds"]["default"], 120);
    assert_eq!(
        p["socket_path"]["default"],
        "/run/ekka-backend/backend.sock"
    );
    assert_eq!(p["state_dir"]["default"], "/var/lib/ekka-backend");
    let a = &s["$defs"]["absolute_path"];
    assert_eq!(a["pattern"], "^(/[A-Za-z0-9_.-]+)+$");
    assert_eq!(a["maxLength"], 255);
    assert_eq!(a["not"]["pattern"], "(^|/)\\.\\.?(/|$)");
}

/// The issuer is required: the adapter has nowhere else to learn where its
/// client credential may be sent.
#[test]
fn a_file_without_the_gateways_issuer_is_refused() {
    let mut v = good();
    v["backend_gateway"]
        .as_object_mut()
        .unwrap()
        .remove("issuer");
    let e = serde_json::from_value::<Config>(v).unwrap_err().to_string();
    assert!(e.contains("issuer"), "{e}");
    // And a good one, with a port and no path, is accepted.
    let mut v = good();
    v["backend_gateway"]["issuer"] = json!("https://host.openshell.internal:8443");
    check(&serde_json::from_value::<Config>(v).unwrap()).unwrap();
}

/// The published schema's stricter values, each refused by name.
#[test]
fn the_published_schemas_values_are_refused_by_name() {
    let cases = vec![
        ("organization_id", "/organization_id", json!("org-7f2c")),
        (
            "organization_id",
            "/organization_id",
            json!("11111111-1111-4111-8111-11111111111A"),
        ),
        (
            "api_gate_instance",
            "/api_gate_instance",
            json!("api-gate-desks"),
        ),
        (
            "api_gate_instance",
            "/api_gate_instance",
            json!("enclave3A7E592FApi"),
        ),
        (
            "https origin",
            "/backend_gateway/url",
            json!("https://gateway:8443/path"),
        ),
        (
            "https origin",
            "/backend_gateway/url",
            json!("https://user@gateway"),
        ),
        (
            "https origin",
            "/backend_gateway/url",
            json!("https://gateway:123456"),
        ),
        (
            "client_id",
            "/backend_gateway/client_id",
            json!("someone-else"),
        ),
        ("workspace", "/backend_gateway/workspace", json!("Desks")),
        (
            "issuer",
            "/backend_gateway/issuer",
            json!("http://desks.example/realms/ekka-desks"),
        ),
        (
            "issuer",
            "/backend_gateway/issuer",
            json!("https://desks.example/realms/ekka-desks/"),
        ),
        (
            "issuer",
            "/backend_gateway/issuer",
            json!("https://desks.example/realms/ekka-desks?x=1"),
        ),
        (
            "issuer",
            "/backend_gateway/issuer",
            json!("https://desks.example/realms/ekka-desks#f"),
        ),
        (
            "issuer",
            "/backend_gateway/issuer",
            json!("https://user@desks.example/realms/ekka-desks"),
        ),
        (
            "issuer",
            "/backend_gateway/issuer",
            json!("https://desks.example/realms//ekka-desks"),
        ),
        (
            "issuer",
            "/backend_gateway/issuer",
            json!("https://desks.example/realms/../x"),
        ),
        (
            "issuer",
            "/backend_gateway/issuer",
            json!("https://desks.example/./realms"),
        ),
        (
            "issuer",
            "/backend_gateway/issuer",
            json!("https://desks.example/realms/%2e%2e"),
        ),
        (
            "issuer",
            "/backend_gateway/issuer",
            json!("https://desks.example:123456/realms"),
        ),
        (
            "issuer",
            "/backend_gateway/issuer",
            json!(format!("https://a.example/{}", "r".repeat(512))),
        ),
        ("absolute", "/state_dir", json!("/var/lib/../etc")),
        (
            "absolute",
            "/socket_path",
            json!("/run/ekka backend/b.sock"),
        ),
        (
            "absolute",
            "/state_dir",
            json!(format!("/{}", "a".repeat(255))),
        ),
    ];
    for (want, at, bad) in cases {
        let mut v = good();
        match v.pointer_mut(at) {
            Some(slot) => *slot = bad.clone(),
            // A key left to its default is not in `good()`: set it.
            None => v[&at[1..]] = bad.clone(),
        }
        let c: Config = serde_json::from_value(v).unwrap();
        let e = check(&c).unwrap_err();
        assert!(e.contains(want), "{at} = {bad}: {e}");
    }
}

/// The CA file: none named is none; a file with no certificate, a symlink or
/// a missing file is refused, never read as "trust the public roots only".
#[test]
fn the_ca_bundle_is_a_file_holding_a_certificate() {
    let mut g: super::BackendGateway =
        serde_json::from_value(good()["backend_gateway"].clone()).unwrap();
    assert_eq!(super::ca_pem(&g).unwrap(), None);
    let dir = tempfile::tempdir().unwrap();
    let empty = dir.path().join("empty.pem");
    std::fs::write(&empty, "not pem\n").unwrap();
    g.ca_pem_path = Some(empty.clone());
    assert!(super::ca_pem(&g).unwrap_err().starts_with("CA_UNSAFE"));
    let (ca, _, _) = crate::fake_issuer::throwaway_ca();
    let good_pem = dir.path().join("ca.pem");
    std::fs::write(&good_pem, &ca).unwrap();
    g.ca_pem_path = Some(good_pem.clone());
    assert_eq!(super::ca_pem(&g).unwrap().unwrap(), ca.as_bytes());
    let link = dir.path().join("link.pem");
    std::os::unix::fs::symlink(&good_pem, &link).unwrap();
    g.ca_pem_path = Some(link);
    assert!(super::ca_pem(&g).unwrap_err().starts_with("CA_UNSAFE"));
    g.ca_pem_path = Some(dir.path().join("missing.pem"));
    assert!(super::ca_pem(&g).unwrap_err().starts_with("CA_UNREADABLE"));
}
