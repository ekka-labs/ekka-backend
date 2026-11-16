//! `grant_facts` over the fake gateway: the digests are the create check's
//! own, every refusal is by name, and nothing is written or changed.

use ekka_backend_fakegw::faults::Planted;
use openshell_proto::openshell::v1::ProviderProfile;
use serde_json::{json, Value};

use crate::answer::{Answer, Code, Outcome};
use crate::digest_cmd::policy_digest;
use crate::driver::tests::{admitted, code, methods, policy, world, World};
use crate::providers::{config_digest_of, Input};

fn fixture() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/provider-github.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn backend_schema() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vendor/contracts/backend/backend-v1.schema.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// A world whose baseline is the driver tests' policy and whose provider
/// records carry their own names, as a real gateway's do.
async fn ready_world() -> World {
    let w = world().await;
    std::fs::write(&w.b.baseline_policy, policy().to_string()).unwrap();
    let mut g = w.gw.lock().unwrap();
    for (k, p) in &mut g.providers {
        p.metadata.get_or_insert_with(Default::default).name = k.clone();
    }
    drop(g);
    w
}

/// Another provider, a copy of the fixture's `github` record under `name`.
fn add(
    w: &World,
    name: &str,
    change: impl FnOnce(&mut openshell_proto::openshell::datamodel::v1::Provider),
) {
    let mut g = w.gw.lock().unwrap();
    let mut p = g.providers["github"].clone();
    p.metadata.get_or_insert_with(Default::default).name = name.into();
    change(&mut p);
    g.providers.insert(name.into(), p);
}

async fn facts(w: &World) -> Answer {
    w.b.grant_facts(&admitted()).await
}

fn json_of(a: &Answer) -> Value {
    serde_json::to_value(a).unwrap()
}

fn is_digest(s: &str) -> bool {
    s.len() == 71
        && s.starts_with("sha256:")
        && s[7..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The answer against the vendored schema's own lists: the result's keys,
/// grant_facts' keys, at most `maxItems` providers, each with a name and
/// EITHER a digest OR a code from the contract's list, names sorted and
/// each once.
fn assert_contract_shape(v: &Value) {
    let schema = backend_schema();
    let defs = &schema["$defs"];
    for k in v.as_object().unwrap().keys() {
        assert!(
            defs["result"]["properties"].get(k).is_some(),
            "{k} is not in the result schema"
        );
    }
    let gf = &v["grant_facts"];
    let mut keys: Vec<&String> = gf.as_object().unwrap().keys().collect();
    keys.sort();
    assert_eq!(keys, ["baseline_policy_digest", "providers"]);
    assert!(is_digest(gf["baseline_policy_digest"].as_str().unwrap()));
    let list = gf["providers"].as_array().unwrap();
    assert!(
        list.len() as u64
            <= defs["grant_facts"]["properties"]["providers"]["maxItems"]
                .as_u64()
                .unwrap()
    );
    let codes = defs["provider_fact"]["properties"]["code"]["enum"]
        .as_array()
        .unwrap();
    let mut names = Vec::new();
    for p in list {
        for k in p.as_object().unwrap().keys() {
            assert!(defs["provider_fact"]["properties"].get(k).is_some(), "{k}");
        }
        match (p.get("digest"), p.get("code")) {
            (Some(d), None) => assert!(is_digest(d.as_str().unwrap()), "{p}"),
            (None, Some(c)) => assert!(codes.contains(c), "{p}"),
            _ => unreachable!("a digest XOR a code: {p}"),
        }
        names.push(p["name"].as_str().unwrap().to_string());
    }
    let mut sorted = names.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(names, sorted, "sorted, each name once");
}

/// Nothing changed, nothing claimed, nothing but reads sent.
fn assert_read_only(w: &World) {
    let g = w.gw.lock().unwrap();
    assert!(g.request_ids.is_empty(), "no change sent");
    for c in &g.calls {
        assert!(
            c.starts_with("ListProviders ")
                || c.starts_with("GetProvider ")
                || c.starts_with("GetProviderProfile ")
                || c.starts_with("ListProviderProfiles "),
            "only reads: {c}"
        );
    }
    drop(g);
    assert!(methods(w).is_empty(), "no desk claimed: {:?}", methods(w));
}

/// THE FACTS ARE THE CREATE CHECK'S OWN: the baseline by `policy_digest`,
/// each provider by the function `ekka-backend digest provider` prints, so a
/// grant built from them is one the adapter accepts. A provider whose profile
/// is gone carries a code, never a digest.
#[tokio::test]
async fn the_facts_are_the_digests_the_create_check_computes() {
    let w = ready_world().await;
    add(&w, "bitbucket", |p| {
        p.r#type = "bitbucket".into();
        p.profile_workspace = "desks".into();
    });
    let a = facts(&w).await;
    assert_eq!(
        (a.outcome, a.desk_ready),
        (Outcome::Ready, Some(true)),
        "{a:?}"
    );
    let v = json_of(&a);
    assert_contract_shape(&v);
    let input: Input = serde_json::from_value(fixture()).unwrap();
    assert_eq!(
        v["grant_facts"],
        json!({
            "baseline_policy_digest": policy_digest(&policy()).unwrap(),
            "providers": [
                { "name": "bitbucket", "code": "PROVIDER_PROFILE_MISSING" },
                { "name": "github", "digest": config_digest_of(&input).unwrap() },
            ]
        })
    );
    assert_read_only(&w);
    // Digests and names only: no credential name or value, no profile.
    let text = v.to_string();
    for k in fixture()["provider"]["credentials"]
        .as_object()
        .unwrap()
        .keys()
    {
        assert!(!text.contains(k.as_str()), "credential {k} answered");
    }
    assert!(!text.contains("REDACTED"));
}

/// An empty workspace answers an empty list, not a refusal.
#[tokio::test]
async fn a_workspace_with_no_provider_answers_an_empty_list() {
    let w = ready_world().await;
    w.gw.lock().unwrap().providers.clear();
    let v = json_of(&facts(&w).await);
    assert_contract_shape(&v);
    assert_eq!(v["grant_facts"]["providers"], json!([]));
}

/// No baseline, no answer: each problem refused by name, before any gateway
/// call. An oversized file is refused from what was read, never trusted
/// from its size.
#[tokio::test]
async fn each_baseline_problem_is_refused_by_name_before_any_gateway_call() {
    let big = format!(
        "{{\"version\": 1, \"pad\": \"{}\"}}",
        "x".repeat(1024 * 1024)
    );
    let cases: Vec<(&str, Option<Vec<u8>>, Code)> = vec![
        ("no file", None, Code::BaselinePolicyMissing),
        (
            "over 1 MiB",
            Some(big.into_bytes()),
            Code::BaselinePolicyUnreadable,
        ),
        (
            "not JSON",
            Some(b"{ not json".to_vec()),
            Code::BaselinePolicyInvalid,
        ),
        (
            "not a SandboxPolicy",
            Some(br#"{"version": 1, "notAField": true}"#.to_vec()),
            Code::BaselinePolicyInvalid,
        ),
    ];
    for (what, bytes, want) in cases {
        let w = ready_world().await;
        std::fs::remove_file(&w.b.baseline_policy).unwrap();
        if let Some(b) = bytes {
            std::fs::write(&w.b.baseline_policy, b).unwrap();
        }
        let a = facts(&w).await;
        assert_eq!(
            (a.outcome, code(&a)),
            (Outcome::Refused, Some(want)),
            "{what}"
        );
        assert!(
            w.gw.lock().unwrap().calls.is_empty(),
            "{what}: no gateway call"
        );
    }
    let w = ready_world().await;
    std::fs::remove_file(&w.b.baseline_policy).unwrap();
    std::fs::create_dir(&w.b.baseline_policy).unwrap();
    assert_eq!(
        code(&facts(&w).await),
        Some(Code::BaselinePolicyUnreadable),
        "a folder"
    );
}

/// A pipe at the baseline's path is refused at once, never waited on: no
/// writer ever opens it here.
#[tokio::test]
async fn a_pipe_at_the_baseline_path_is_refused_never_waited_on() {
    let w = ready_world().await;
    std::fs::remove_file(&w.b.baseline_policy).unwrap();
    let made = std::process::Command::new("mkfifo")
        .arg(&w.b.baseline_policy)
        .status()
        .unwrap();
    assert!(made.success());
    let a = tokio::time::timeout(std::time::Duration::from_secs(5), facts(&w))
        .await
        .expect("answered at once, not blocked on the pipe");
    assert_eq!(code(&a), Some(Code::BaselinePolicyUnreadable));
    assert!(w.gw.lock().unwrap().calls.is_empty());
}

/// A list not read whole is refused, never answered short: a refusal on the
/// first or a later page, or a list with no end.
#[tokio::test]
async fn a_provider_list_not_read_whole_is_refused() {
    for page in [0, 1] {
        let w = ready_world().await;
        add(&w, "gitlab", |_| {});
        {
            let mut g = w.gw.lock().unwrap();
            g.provider_page_size = Some(1);
            g.fail_provider_page = Some((page, tonic::Code::Unavailable));
        }
        assert_eq!(
            code(&facts(&w).await),
            Some(Code::ProvidersUnreadable),
            "page {page}"
        );
        assert_read_only(&w);
    }
    let w = ready_world().await;
    w.gw.lock().unwrap().endless_provider_pages = true;
    assert_eq!(code(&facts(&w).await), Some(Code::ProvidersUnreadable));
}

/// Sixty-four providers are answered; sixty-five are refused, never cut.
#[tokio::test]
async fn sixty_four_providers_are_answered_and_sixty_five_refused() {
    let w = ready_world().await;
    for i in 1..64 {
        add(&w, &format!("p{i:02}"), |_| {});
    }
    let v = json_of(&facts(&w).await);
    assert_contract_shape(&v);
    assert_eq!(v["grant_facts"]["providers"].as_array().unwrap().len(), 64);
    add(&w, "p64", |_| {});
    let a = facts(&w).await;
    assert_eq!(
        (a.outcome, code(&a)),
        (Outcome::Refused, Some(Code::ProvidersTooMany))
    );
}

/// What a case plants in a world.
type Plant = (&'static str, fn(&World));

/// A list that names a provider badly, or names one twice, is not answered
/// at all.
#[tokio::test]
async fn a_list_with_a_bad_or_repeated_name_is_refused_whole() {
    let cases: [Plant; 3] = [
        ("no name", |w| {
            add(w, "nameless", |p| p.metadata = None);
        }),
        ("not a plain name", |w| {
            add(w, "spaced", |p| {
                p.metadata.as_mut().unwrap().name = "Bad Name".into()
            });
        }),
        ("twice", |w| {
            add(w, "again", |p| {
                p.metadata.as_mut().unwrap().name = "github".into()
            });
        }),
    ];
    for (what, plant) in cases {
        let w = ready_world().await;
        plant(&w);
        assert_eq!(
            code(&facts(&w).await),
            Some(Code::ProvidersUnreadable),
            "{what}"
        );
    }
}

/// A provider whose digest cannot be computed carries PROVIDER_UNREADABLE,
/// never a digest, beside the others' digests: a profile that cannot be told
/// apart from another, or a credential carrying a value (never answered).
#[tokio::test]
async fn an_unreadable_provider_carries_a_code_beside_the_others_digests() {
    let w = ready_world().await;
    add(&w, "twin", |p| {
        p.r#type = "twin".into();
        p.profile_workspace = String::new();
    });
    add(&w, "leaky", |p| {
        p.credentials
            .insert("api_token".into(), "PLANTED-SECRET-VALUE".into());
    });
    {
        let mut g = w.gw.lock().unwrap();
        for ws in ["", "desks"] {
            g.profiles.insert(
                (ws.into(), "twin".into()),
                ProviderProfile {
                    id: "twin".into(),
                    scope: "static".into(),
                    ..Default::default()
                },
            );
        }
    }
    let v = json_of(&facts(&w).await);
    assert_contract_shape(&v);
    let list = &v["grant_facts"]["providers"];
    assert_eq!(
        list[0],
        json!({ "name": "github", "digest": list[0]["digest"] })
    );
    assert_eq!(
        list[1],
        json!({ "name": "leaky", "code": "PROVIDER_UNREADABLE" })
    );
    assert_eq!(
        list[2],
        json!({ "name": "twin", "code": "PROVIDER_UNREADABLE" })
    );
    assert!(!v.to_string().contains("PLANTED-SECRET-VALUE"));
}

/// A provider read the gateway refuses carries PROVIDER_UNREADABLE; the
/// refusal itself is never answered.
#[tokio::test]
async fn a_refused_provider_read_carries_a_code_and_not_the_refusal() {
    let w = ready_world().await;
    w.gw.lock().unwrap().faults.answer.insert(
        "GetProvider".into(),
        Planted::Refused {
            code: tonic::Code::Unavailable,
            reason: Some("PLANTED_REASON".into()),
        },
    );
    let v = json_of(&facts(&w).await);
    assert_contract_shape(&v);
    assert_eq!(
        v["grant_facts"]["providers"],
        json!([{ "name": "github", "code": "PROVIDER_UNREADABLE" }])
    );
    assert!(!v.to_string().contains("PLANTED_REASON"));
}
