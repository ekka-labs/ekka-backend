use serde_json::{json, Value};

use super::{check, MUST_EQUAL};

fn vendored(rel: &str) -> Value {
    let path = format!(
        "{}/../../vendor/contracts/governance/grant-constraints/{rel}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn sample() -> Value {
    vendored("samples/desks.v1.json")
}

#[test]
fn the_contracts_own_sample_passes() {
    check(&sample()).unwrap();
}

/// The schema is closed: an unknown key is refused by name, at every level,
/// before any request.
#[test]
fn an_unknown_key_is_refused_by_name_at_every_level() {
    for (at, key) in [
        (vec![], "max_desks"),
        (vec!["policy_baseline"], "extra"),
        (vec!["policy_baseline", "network"], "allowed_protocols"),
    ] {
        let mut v = sample();
        let mut o = &mut v;
        for k in &at {
            o = o.get_mut(*k).unwrap();
        }
        o.as_object_mut().unwrap().insert(key.into(), json!(true));
        let e = check(&v).unwrap_err();
        assert!(e.contains(key), "{key}: {e}");
    }
}

#[test]
fn a_missing_required_list_is_refused() {
    let mut v = sample();
    v.as_object_mut().unwrap().remove("image_digests");
    assert!(check(&v).unwrap_err().contains("image_digests"));
    let mut v = sample();
    v["image_digests"] = json!([]);
    assert!(check(&v)
        .unwrap_err()
        .contains("image_digests must have 1 to 32"));
}

/// Each planted value breaks one rule of the schema and is refused naming
/// its field.
#[test]
fn a_value_the_schema_refuses_is_refused_here() {
    let d = |c: char| format!("sha256:{}", c.to_string().repeat(64));
    for (field, bad, names) in [
        ("/image_digests/0", json!("sha256:ABC"), "image_digests"),
        ("/image_digests/0", json!(d('g')), "image_digests"),
        ("/policy_digests", json!([d('b'), d('b')]), "twice"),
        ("/allowed_hosts/0", json!("API.github.com"), "allowed_hosts"),
        ("/allowed_hosts/0", json!("github"), "allowed_hosts"),
        ("/allowed_hosts/0", json!("*.*.github.com"), "allowed_hosts"),
        ("/providers/0", json!("GitHub"), "providers"),
        ("/environment_keys/0", json!("1TZ"), "environment_keys"),
        ("/repo_hosts/0", json!("*.github.com"), "repo_hosts"),
        (
            "/policy_baseline/must_equal/5",
            json!("filesystem"),
            "all six",
        ),
        (
            "/policy_baseline/network/allowed_ports/0",
            json!(0),
            "1 to 65535",
        ),
        (
            "/policy_baseline/network/allowed_ports/0",
            json!(22),
            "twice",
        ),
        (
            "/policy_baseline/network/allowed_cidrs",
            json!(["10.0.0.0/33"]),
            "allowed_cidrs",
        ),
        (
            "/policy_baseline/network/allowed_cidrs",
            json!(["256.0.0.0/8"]),
            "allowed_cidrs",
        ),
        (
            "/policy_baseline/network/allowed_cidrs",
            json!(["010.0.0.0/8"]),
            "allowed_cidrs",
        ),
        (
            "/policy_baseline/network/provider_added",
            json!("any"),
            "listed_only",
        ),
        ("/requires_role", json!("member"), "admin"),
        (
            "/provider_config_digests/github",
            json!("sha256:x"),
            "provider_config_digests",
        ),
    ] {
        let mut v = sample();
        *v.pointer_mut(field).unwrap() = bad;
        let e = check(&v).unwrap_err();
        assert!(e.contains(names), "{field}: {e}");
    }
    let mut v = sample();
    v["policy_baseline"]["network"]["allowed_cidrs"] = json!(["10.0.0.0/8", "192.168.1.0/24"]);
    check(&v).unwrap();
}

/// THE MIRROR IS THE VENDORED SCHEMA. The runner has no JSON Schema engine,
/// so `check` restates the schema; this compares the two, so a contract bump
/// that adds, removes or re-limits a field fails here, not at the adapter.
#[test]
fn the_mirror_is_the_vendored_schema() {
    let s = vendored("desks.v1.schema.json");
    let keys = |o: &Value| {
        let mut k: Vec<String> = o.as_object().unwrap().keys().cloned().collect();
        k.sort();
        k
    };
    let req = |o: &Value| {
        let mut r: Vec<String> = o["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_string())
            .collect();
        r.sort();
        r
    };
    let top = [
        "allowed_hosts",
        "environment_keys",
        "image_digests",
        "policy_baseline",
        "policy_digests",
        "provider_config_digests",
        "providers",
        "repo_hosts",
        "requires_role",
    ];
    assert_eq!(keys(&s["properties"]), top);
    assert_eq!(req(&s), top, "every top-level field is required");
    assert_eq!(s["additionalProperties"], false);
    let b = &s["properties"]["policy_baseline"];
    assert_eq!(keys(&b["properties"]), ["must_equal", "network"]);
    assert_eq!(b["additionalProperties"], false);
    let n = &b["properties"]["network"];
    let net = [
        "allowed_cidrs",
        "allowed_hosts",
        "allowed_ports",
        "provider_added",
    ];
    assert_eq!(keys(&n["properties"]), net);
    assert_eq!(req(n), net);
    assert_eq!(n["additionalProperties"], false);

    let p = &s["properties"];
    let lim = |v: &Value| {
        (
            v["minItems"].as_u64().unwrap_or(0),
            v["maxItems"].as_u64().unwrap(),
        )
    };
    assert_eq!(lim(&p["image_digests"]), (1, 32));
    assert_eq!(lim(&p["policy_digests"]), (1, 32));
    assert_eq!(lim(&p["allowed_hosts"]), (1, 64));
    assert_eq!(lim(&p["providers"]), (0, 16));
    assert_eq!(lim(&p["environment_keys"]), (0, 64));
    assert_eq!(lim(&p["repo_hosts"]), (0, 16));
    assert_eq!(p["provider_config_digests"]["maxProperties"], 16);
    assert_eq!(lim(&n["properties"]["allowed_hosts"]), (0, 64));
    assert_eq!(lim(&n["properties"]["allowed_ports"]), (1, 16));
    assert_eq!(lim(&n["properties"]["allowed_cidrs"]), (0, 16));
    assert_eq!(n["properties"]["provider_added"]["const"], "listed_only");
    assert_eq!(p["requires_role"]["const"], "admin");
    let must: Vec<&str> = b["properties"]["must_equal"]["items"]["enum"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap())
        .collect();
    assert_eq!(must, MUST_EQUAL);

    // The patterns the checks above restate, as the schema writes them.
    let label = "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?";
    assert_eq!(s["$defs"]["digest"]["pattern"], "^sha256:[0-9a-f]{64}$");
    assert_eq!(s["$defs"]["name"]["pattern"], "^[a-z0-9][a-z0-9._-]{0,62}$");
    assert_eq!(
        p["allowed_hosts"]["items"]["pattern"],
        format!("^(\\*\\.)?{label}(\\.{label})+$")
    );
    assert_eq!(
        p["repo_hosts"]["items"]["pattern"],
        format!("^{label}(\\.{label})+$")
    );
    assert_eq!(
        p["environment_keys"]["items"]["pattern"],
        "^[A-Za-z_][A-Za-z0-9_]{0,127}$"
    );
    assert_eq!(
        n["properties"]["allowed_cidrs"]["items"]["pattern"],
        "^((25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})/([0-9]|[12][0-9]|3[0-2])$"
    );
}
