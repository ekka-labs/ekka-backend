//! The limits: one planted violation per rule, each refused with
//! the code of the limit, before any backend call; one planted post-write
//! mismatch for each compared part answers `unknown`.

use serde_json::{json, Value};

use super::{
    body, cidr_allowed, create, grant, host_allowed, policy_change, result_matches, CreateBody,
    Expected,
};
use crate::answer::Code;
use crate::constraints::DeskConstraints;
use crate::digest_cmd::policy_digest;

type Plant = Box<dyn Fn(&mut Value)>;

const IMAGE: &str =
    "ghcr.io/example/desk@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ENFORCE: &str = "NETWORK_ENFORCEMENT_MODE_ENFORCE";

/// The baseline a desk starts from: git reaching api.github.com:443.
fn policy() -> Value {
    json!({
        "version": 1,
        "filesystem": { "readOnly": ["/usr"], "readWrite": ["/sandbox"] },
        "landlock": { "compatibility": "hard_requirement" },
        "process": { "runAsUser": "1000", "runAsGroup": "1000" },
        "networkPolicies": {
            "github": {
                "name": "github",
                "endpoints": [{ "host": "api.github.com", "port": 443, "enforcement": ENFORCE }],
                "binaries": [{ "path": "/usr/bin/git" }]
            }
        }
    })
}

/// The contract's sample grant, with `policies` as its baseline digests.
fn grant_for(policies: &[&Value]) -> DeskConstraints {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vendor/contracts/governance/grant-constraints/samples/desks.v1.json"
    );
    let mut g: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    g["policy_digests"] = json!(policies
        .iter()
        .map(|p| policy_digest(p).unwrap())
        .collect::<Vec<_>>());
    g["policy_baseline"]["network"]["allowed_cidrs"] = json!(["10.20.0.0/16"]);
    grant(Some(&g)).unwrap()
}

fn create_body(policy: &Value) -> Value {
    json!({ "name": "code-desk", "image": IMAGE, "policy": policy, "providers": ["github"],
            "environment": { "TZ": "UTC" } })
}

fn try_create(g: &DeskConstraints, b: &Value) -> Result<Value, Code> {
    let b: CreateBody = body(&serde_json::to_vec(b).unwrap())?;
    create(g, &b)
}

#[test]
fn a_create_inside_every_limit_passes() {
    let g = grant_for(&[&policy()]);
    try_create(&g, &create_body(&policy())).unwrap();
}

/// Contracts 0.62.0: an image the machine built itself is named by its local
/// content ID alone, `sha256:<64 hex>` (Docker's image ID), and that whole
/// value must be in `image_digests`. Every other spelling the contract's
/// pattern refuses is REQUEST_INVALID, never a lookup.
#[test]
fn an_image_is_a_registry_digest_or_a_local_content_id() {
    let g = grant_for(&[&policy()]);
    let with = |image: String| {
        let mut b = create_body(&policy());
        b["image"] = json!(image);
        try_create(&g, &b)
    };
    let listed = "a".repeat(64);
    with(format!("sha256:{listed}")).unwrap();
    assert_eq!(
        with(format!("sha256:{}", "c".repeat(64))).unwrap_err(),
        Code::ConstraintImageDigests
    );
    for bad in [
        format!("SHA256:{listed}"),
        format!("sha256:{}", "a".repeat(63)),
        format!("sha256:{}", "A".repeat(64)),
        "sha256:".to_string(),
        format!("desk:sha256:{listed}"),
        format!("@sha256:{listed}"),
        format!(".desk@sha256:{listed}"),
        format!("-desk@sha256:{listed}"),
        format!("Desk@sha256:{listed}"),
        format!("{}@sha256:{listed}", "d".repeat(257)),
        format!(" sha256:{listed}"),
    ] {
        assert_eq!(
            with(bad.clone()).unwrap_err(),
            Code::RequestInvalid,
            "{bad}"
        );
    }
    with(format!("{}@sha256:{listed}", "d".repeat(256))).unwrap();
}

/// The image rule is the contract's create_body pattern, as published.
#[test]
fn the_image_rule_is_the_contracts_pattern() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vendor/contracts/backend/backend-v1.schema.json"
    );
    let s: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let image = &s["$defs"]["create_body"]["properties"]["image"];
    assert_eq!(
        image["pattern"],
        "^([a-z0-9][a-z0-9._/:-]{0,255}@)?sha256:[0-9a-f]{64}$"
    );
    assert_eq!(image["maxLength"], 512);
}

/// Each planted create breaks exactly one limit. Where the policy itself is
/// planted, the grant lists the planted policy's digest, so the rule under
/// test is the one that answers.
#[test]
fn each_planted_create_is_refused_by_the_limit_it_breaks() {
    let ep = |e: Value| {
        let mut p = policy();
        p["networkPolicies"]["github"]["endpoints"] = json!([e]);
        p
    };
    let cases: Vec<(&str, Code, Value, bool)> = vec![
        (
            "an image by tag",
            Code::RequestInvalid,
            json!({ "image": "ghcr.io/example/desk:1" }),
            false,
        ),
        (
            "an image not in image_digests",
            Code::ConstraintImageDigests,
            json!({ "image": format!("x@sha256:{}", "c".repeat(64)) }),
            false,
        ),
        (
            "a policy not in policy_digests",
            Code::ConstraintPolicyDigests,
            json!({ "policy": { "version": 2 } }),
            false,
        ),
        (
            "a host outside allowed_hosts",
            Code::ConstraintAllowedHosts,
            json!({ "policy": ep(json!({ "host": "evil.example.com", "port": 443, "enforcement": ENFORCE })) }),
            true,
        ),
        (
            "a port outside allowed_ports",
            Code::ConstraintPolicyBaseline,
            json!({ "policy": ep(json!({ "host": "api.github.com", "port": 8080, "enforcement": ENFORCE })) }),
            true,
        ),
        (
            "no port: every port",
            Code::ConstraintPolicyBaseline,
            json!({ "policy": ep(json!({ "host": "api.github.com", "enforcement": ENFORCE })) }),
            true,
        ),
        (
            "an audited endpoint",
            Code::ConstraintPolicyBaseline,
            json!({ "policy": ep(json!({ "host": "api.github.com", "port": 443, "enforcement": "NETWORK_ENFORCEMENT_MODE_AUDIT" })) }),
            true,
        ),
        (
            "an endpoint with no enforcement",
            Code::ConstraintPolicyBaseline,
            json!({ "policy": ep(json!({ "host": "api.github.com", "port": 443 })) }),
            true,
        ),
        (
            "an address outside allowed_cidrs",
            Code::ConstraintPolicyBaseline,
            json!({ "policy": ep(json!({ "host": "api.github.com", "port": 443, "enforcement": ENFORCE, "allowedIps": ["10.21.0.1"] })) }),
            true,
        ),
        (
            "a provider rule in the caller's policy",
            Code::FieldNotAllowed,
            json!({ "policy": { "version": 1, "networkPolicies": { "_provider_github": { "name": "x" } } } }),
            true,
        ),
        (
            "a network middleware",
            Code::FieldNotAllowed,
            json!({ "policy": { "version": 1, "networkMiddlewares": { "m": {} } } }),
            true,
        ),
        (
            "a provider not in providers",
            Code::ConstraintProviders,
            json!({ "providers": ["github", "claude-code"] }),
            false,
        ),
        (
            "an environment key not allowed",
            Code::ConstraintEnvironmentKeys,
            json!({ "environment": { "TZ": "UTC", "HTTP_PROXY": "x" } }),
            false,
        ),
        (
            "a repo (contracts 0.65.0: nothing on a desk reads it)",
            Code::FieldNotAllowed,
            json!({ "repo": "https://github.com/acme/app.git" }),
            false,
        ),
        (
            "an unknown field",
            Code::FieldNotAllowed,
            json!({ "keep_alive": false }),
            false,
        ),
    ];
    for (why, code, change, grant_lists_policy) in cases {
        let mut b = create_body(&policy());
        for (k, v) in change.as_object().unwrap() {
            b[k] = v.clone();
        }
        let g = if grant_lists_policy {
            grant_for(&[&policy(), &b["policy"]])
        } else {
            grant_for(&[&policy()])
        };
        assert_eq!(try_create(&g, &b).unwrap_err(), code, "{why}");
    }
}

#[test]
fn a_policy_change_keeps_the_baseline_and_stays_inside_the_ceiling() {
    let g = grant_for(&[&policy()]);
    // Allowed: git also reaches github.com:22 (a host and port inside).
    let mut ok = policy();
    ok["networkPolicies"]["ssh"] = json!({ "name": "ssh", "endpoints": [{ "host": "raw.githubusercontent.com", "port": 22, "enforcement": ENFORCE }], "binaries": [{ "path": "/usr/bin/git" }] });
    policy_change(&g, &policy(), &ok).unwrap();
    let cases: Vec<(&str, Code, Plant)> = vec![
        (
            "filesystem changed",
            Code::ConstraintPolicyBaseline,
            Box::new(|p| p["filesystem"]["readWrite"] = json!(["/sandbox", "/etc"])),
        ),
        (
            "process changed",
            Code::ConstraintPolicyBaseline,
            Box::new(|p| p["process"]["runAsUser"] = json!("0")),
        ),
        (
            "landlock loosened",
            Code::ConstraintPolicyBaseline,
            Box::new(|p| p["landlock"]["compatibility"] = json!("best_effort")),
        ),
        (
            "a program the baseline never allowed",
            Code::ConstraintPolicyBaseline,
            Box::new(|p| {
                p["networkPolicies"]["github"]["binaries"] = json!([{ "path": "/usr/bin/curl" }])
            }),
        ),
        (
            "a host outside the ceiling",
            Code::ConstraintAllowedHosts,
            Box::new(|p| {
                p["networkPolicies"]["github"]["endpoints"][0]["host"] = json!("api.gitlab.com")
            }),
        ),
        (
            "an audited endpoint",
            Code::ConstraintPolicyBaseline,
            Box::new(|p| {
                p["networkPolicies"]["github"]["endpoints"][0]["enforcement"] =
                    json!("NETWORK_ENFORCEMENT_MODE_AUDIT")
            }),
        ),
        (
            "a provider's credential bound to a new endpoint",
            Code::ConstraintCredentialEndpoint,
            Box::new(|p| {
                p["networkPolicies"]["leak"] = json!({ "name": "leak", "endpoints": [{ "host": "raw.githubusercontent.com", "port": 443, "enforcement": ENFORCE, "credentialBinding": { "provider": "github" } }], "binaries": [{ "path": "/usr/bin/git" }] });
            }),
        ),
        (
            "a provider's credential bound to the baseline's endpoint",
            Code::ConstraintCredentialEndpoint,
            Box::new(|p| {
                p["networkPolicies"]["github"]["endpoints"][0]["credentialBinding"] =
                    json!({ "provider": "github" })
            }),
        ),
        (
            "uninspected credentials allowed",
            Code::ConstraintCredentialEndpoint,
            Box::new(|p| {
                p["networkPolicies"]["github"]["endpoints"][0]["allowUninspectedCredentials"] =
                    json!(true)
            }),
        ),
    ];
    for (why, code, plant) in cases {
        let mut p = policy();
        plant(&mut p);
        assert_eq!(policy_change(&g, &policy(), &p).unwrap_err(), code, "{why}");
    }
}

/// OpenShell reads a rule with no `binaries` as ANY program (openshell-policy
/// merge.rs:1537, v0.1.3 and v0.1.4). An empty program set is a subset of
/// every baseline, so a subset check alone would pass it. A change may carry an
/// any-program rule only where the creation policy already had one.
#[test]
fn a_policy_change_never_opens_a_rule_to_any_program() {
    let g = grant_for(&[&policy()]);
    for (why, plant) in [
        (
            "binaries dropped, endpoint kept",
            Box::new(|p: &mut Value| {
                p["networkPolicies"]["github"]
                    .as_object_mut()
                    .unwrap()
                    .remove("binaries");
            }) as Plant,
        ),
        (
            "binaries emptied",
            Box::new(|p: &mut Value| p["networkPolicies"]["github"]["binaries"] = json!([])),
        ),
        (
            "a new rule with no binaries",
            Box::new(|p: &mut Value| {
                p["networkPolicies"]["any"] = json!({ "name": "any", "endpoints": [{ "host": "api.github.com", "port": 443, "enforcement": ENFORCE }] });
            }),
        ),
    ] {
        let mut p = policy();
        plant(&mut p);
        assert_eq!(
            policy_change(&g, &policy(), &p).unwrap_err(),
            Code::ConstraintPolicyBaseline,
            "{why}"
        );
    }
    // A baseline that already let any program reach a host may keep it.
    let mut open = policy();
    open["networkPolicies"]["github"]
        .as_object_mut()
        .unwrap()
        .remove("binaries");
    let g = grant_for(&[&open]);
    policy_change(&g, &open, &open).unwrap();
}

/// A credentialed endpoint (one that lets a request carry a provider's
/// credentials) may be kept exactly as the creation policy has it, or
/// dropped; never added, changed, moved, or given to another program.
#[test]
fn a_policy_change_never_sends_a_credential_anywhere_new() {
    let mut base = policy();
    base["networkPolicies"]["github"]["endpoints"][0]["credentialBinding"] =
        json!({ "provider": "github" });
    base["networkPolicies"]["tools"] = json!({ "name": "tools", "endpoints": [{ "host": "raw.githubusercontent.com", "port": 443, "enforcement": ENFORCE }], "binaries": [{ "path": "/usr/bin/curl" }] });
    let g = grant_for(&[&base]);
    policy_change(&g, &base, &base).unwrap();
    let mut dropped = base.clone();
    dropped["networkPolicies"]["github"]["endpoints"] = json!([]);
    policy_change(&g, &base, &dropped).unwrap();

    let cases: Vec<(&str, Plant)> = vec![
        (
            "moved into another rule",
            Box::new(|p| {
                let e = p["networkPolicies"]["github"]["endpoints"][0].clone();
                p["networkPolicies"]["tools"]["endpoints"]
                    .as_array_mut()
                    .unwrap()
                    .push(e);
            }),
        ),
        (
            "its rule given another program",
            Box::new(|p| {
                p["networkPolicies"]["github"]["binaries"] =
                    json!([{ "path": "/usr/bin/git" }, { "path": "/usr/bin/curl" }])
            }),
        ),
        (
            "bound to another provider",
            Box::new(|p| {
                p["networkPolicies"]["github"]["endpoints"][0]["credentialBinding"]["provider"] =
                    json!("slack")
            }),
        ),
        (
            "its port changed",
            Box::new(|p| p["networkPolicies"]["github"]["endpoints"][0]["port"] = json!(22)),
        ),
    ];
    for (why, plant) in cases {
        let mut p = base.clone();
        plant(&mut p);
        assert_eq!(
            policy_change(&g, &base, &p).unwrap_err(),
            Code::ConstraintCredentialEndpoint,
            "{why}"
        );
    }
}

#[test]
fn a_host_is_inside_the_ceiling_exactly_or_under_a_wildcard() {
    let c = vec![
        "api.github.com".to_string(),
        "*.githubusercontent.com".to_string(),
    ];
    for h in [
        "api.github.com",
        "API.GitHub.com",
        "raw.githubusercontent.com",
        "a.b.githubusercontent.com",
        "*.raw.githubusercontent.com",
        "*.githubusercontent.com",
    ] {
        assert!(host_allowed(&c, h), "{h}");
    }
    for h in [
        "github.com",
        "githubusercontent.com",
        "evilgithubusercontent.com",
        "x.api.github.com",
        "*.com",
        "*.github.com",
    ] {
        assert!(!host_allowed(&c, h), "{h}");
    }
}

#[test]
fn an_address_is_inside_an_allowed_range_or_refused() {
    let a = vec!["10.0.0.0/8".to_string()];
    for ip in ["10.1.2.3", "10.1.0.0/16", "10.0.0.0/8"] {
        assert!(cidr_allowed(&a, ip), "{ip}");
    }
    for ip in [
        "11.0.0.1",
        "10.0.0.0/7",
        "0.0.0.0/0",
        "::1",
        "10.1",
        "10.1.2.3/33",
        // Spellings a backend's parser may read differently (or as octal).
        "+10.1.2.3",
        "010.1.2.3",
        "10.1.2.3/+8",
        "10.1.0.0/016",
        " 10.1.2.3",
    ] {
        assert!(!cidr_allowed(&a, ip), "{ip}");
    }
    assert!(!cidr_allowed(&[], "10.1.2.3"), "empty means none");
}

/// The post-write comparison: the sandbox the backend made is
/// what was asked, or the answer is `unknown`.
#[test]
fn a_resulting_desk_that_differs_from_the_request_does_not_match() {
    let providers = vec!["github".to_string()];
    let e = Expected {
        image: IMAGE,
        policy: &policy(),
        providers: &providers,
    };
    let made = || json!({ "spec": { "template": { "image": IMAGE }, "providers": ["github"], "policy": policy() } });
    assert!(result_matches(&e, &made()));
    // The gateway's canonical spelling of the same policy still matches.
    let mut spelled = made();
    spelled["spec"]["policy"]["landlock"] = json!({ "compatibility": "hard_requirement" });
    assert!(result_matches(&e, &spelled));
    let plants: Vec<(&str, Plant)> = vec![
        (
            "another image",
            Box::new(|s| {
                s["spec"]["template"]["image"] = json!("evil@sha256:".to_string() + &"d".repeat(64))
            }),
        ),
        (
            "another provider",
            Box::new(|s| s["spec"]["providers"] = json!(["github", "claude-code"])),
        ),
        (
            "another policy",
            Box::new(|s| s["spec"]["policy"]["process"]["runAsUser"] = json!("0")),
        ),
        (
            "user namespaces set",
            Box::new(|s| s["spec"]["template"]["userNamespaces"] = json!(true)),
        ),
        (
            "a driver config",
            Box::new(|s| s["spec"]["template"]["driverConfig"] = json!({ "docker": {} })),
        ),
        (
            "a runtime class",
            Box::new(|s| s["spec"]["template"]["runtimeClassName"] = json!("runc")),
        ),
        (
            "template resources",
            Box::new(|s| s["spec"]["template"]["resources"] = json!({ "cpu": "8" })),
        ),
        (
            "resource requirements",
            Box::new(|s| s["spec"]["resourceRequirements"] = json!({ "cpu": "8" })),
        ),
    ];
    for (why, plant) in plants {
        let mut s = made();
        plant(&mut s);
        assert!(!result_matches(&e, &s), "{why}");
    }
}

/// Contracts 0.65.0: the create's `repo` may only be absent or empty.
#[test]
fn a_create_repo_is_the_contracts_empty_field() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vendor/contracts/backend/backend-v1.schema.json"
    );
    let s: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(
        s["$defs"]["create_body"]["properties"]["repo"]["maxLength"],
        0
    );
    let g = grant_for(&[&policy()]);
    let mut b = create_body(&policy());
    b["repo"] = json!("");
    try_create(&g, &b).unwrap();
}
