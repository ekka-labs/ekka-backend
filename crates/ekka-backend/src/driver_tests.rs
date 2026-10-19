//! The driver: each operation makes exactly the gateway calls the README's
//! table lists, between a claim and its release at the Enclave, and every
//! refusal says why by the contract's code. A change whose reply is lost, or
//! held UNCERTAIN, answers `running` and keeps its claim.

use serde_json::{json, Value};

use ekka_backend_fakegw::faults::Planted;
use ekka_backend_fakegw::{fake_enclave, fake_gateway, fake_issuer};

use super::Backend;
use crate::answer::{Answer, Code, Outcome as AnswerOutcome};
use crate::claims::Claims;
use crate::digest_cmd::policy_digest;
use crate::enforce::{CreateBody, PolicySetBody};
use crate::gateway::Gateway;
use crate::signin::{Issuer, Tokens};
use crate::token::{Admitted, Verified};

const IMAGE: &str =
    "ghcr.io/example/desk@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ENFORCE: &str = "NETWORK_ENFORCEMENT_MODE_ENFORCE";
/// `Verified::for_tests`' request id.
pub(crate) const RID: &str = "00000000-0000-5000-8000-000000000000";
const FIRST_ID: &str = "00000000-0000-4000-8000-000000000001";

fn uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

pub(crate) fn policy() -> Value {
    json!({
        "version": 1,
        "filesystem": { "readOnly": ["/usr"], "readWrite": ["/sandbox"] },
        "landlock": { "compatibility": "hard_requirement" },
        "process": { "runAsUser": "1000", "runAsGroup": "1000" },
        "networkPolicies": { "github": {
            "name": "github",
            "endpoints": [{ "host": "api.github.com", "port": 443, "enforcement": ENFORCE }],
            "binaries": [{ "path": "/usr/bin/git" }]
        } }
    })
}

pub(crate) fn grant() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vendor/contracts/governance/grant-constraints/samples/desks.v1.json"
    );
    let mut g: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    g["policy_digests"] = json!([policy_digest(&policy()).unwrap()]);
    // The github fixture's configuration, as `digest provider` prints it.
    g["provider_config_digests"] = json!({ "github": GITHUB_CONFIG });
    g
}

const GITHUB_CONFIG: &str =
    "sha256:b2a3df945ba9e782b8175bb0f7a140b00db8b957d528200882a66fa2ac054866";

fn admitted() -> Admitted {
    Verified::for_tests(Some(grant())).admit().unwrap()
}

/// The `n`th operation after the first: its own request id, as every real
/// operation has (the gateway replays a request id it has seen).
fn then(n: u64) -> Admitted {
    Verified::for_tests_as(Some(grant()), &format!("00000000-0000-5000-8000-{n:012}"))
        .admit()
        .unwrap()
}

pub(crate) fn create_body(extra: Value) -> CreateBody {
    let mut b = json!({ "name": "code-desk", "image": IMAGE, "policy": policy(),
                        "providers": ["github"], "environment": { "TZ": "UTC" } });
    if let (Some(o), Some(e)) = (b.as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            o.insert(k.clone(), v.clone());
        }
    }
    serde_json::from_value(b).unwrap()
}

pub(crate) struct World {
    pub(crate) b: Backend,
    pub(crate) gw: fake_gateway::Shared,
    pub(crate) enc: fake_enclave::Shared,
    pub(crate) dir: tempfile::TempDir,
}

pub(crate) async fn world() -> World {
    let idp =
        fake_issuer::start(&fake_issuer::basic("ekka-desk-admin", "backend-credential")).await;
    let issuer = idp.lock().unwrap().issuer.clone();
    let tokens =
        Tokens::new(Issuer::plaintext_for_tests(&issuer, "ekka-desk-admin")).with_backoff(vec![]);
    let (addr, gw) = fake_gateway::start("gw-token-1").await;
    provider_records(&mut gw.lock().unwrap());
    let ch = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect_lazy();
    let dir = crate::socket::tests::dir();
    let enc = fake_enclave::start(dir.path());
    let b = Backend {
        gateway: Gateway::over_test_channel(ch, "desks"),
        tokens,
        claims: Claims::beside(&dir.path().join("backend.sock"), uid()),
        // No record: a driver test concludes with nothing to write first.
        records: super::Records::Unrecorded,
    };
    World { b, gw, enc, dir }
}

fn methods(w: &World) -> Vec<String> {
    w.enc
        .lock()
        .unwrap()
        .calls()
        .into_iter()
        .map(|(m, _)| m)
        .collect()
}

fn mutations(w: &World) -> Vec<String> {
    w.gw.lock()
        .unwrap()
        .request_ids
        .iter()
        .map(|(rpc, _)| rpc.clone())
        .collect()
}

fn code(a: &Answer) -> Option<Code> {
    a.code
}

#[tokio::test]
async fn a_create_inside_its_grant_is_made_claimed_and_released_with_its_read_back() {
    let w = world().await;
    let a =
        w.b.create(&admitted(), &create_body(json!({})), &crate::driver::Noted)
            .await;
    assert_eq!(a.outcome, AnswerOutcome::Ready, "{a:?}");
    assert_eq!(a.desk.backend_id.as_deref(), Some(FIRST_ID));
    assert_eq!(a.desk.resource_version.as_deref(), Some("1"));
    assert_eq!(a.desk.policy_digest, policy_digest(&policy()));
    assert_eq!(a.desk.providers, Some(vec!["github".to_string()]));
    let g = w.gw.lock().unwrap();
    // One CreateSandbox, carrying the operation's request id, the desk label,
    // the operation label, the required providers, and no command.
    assert_eq!(
        g.request_ids,
        [("CreateSandbox".to_string(), RID.to_string())]
    );
    let sb = &g.sandboxes["code-desk"];
    let meta = sb.metadata.as_ref().unwrap();
    assert_eq!(meta.labels["ekka.ai/desk"], "true");
    assert_eq!(meta.labels["ekka.ai/operation"], RID);
    assert_eq!(meta.annotations["ekka.ai/desk-providers"], "github");
    let spec = sb.spec.as_ref().unwrap();
    assert!(spec.command.is_empty());
    assert_eq!(spec.template.as_ref().unwrap().image, IMAGE);
    assert_eq!(spec.environment["TZ"], "UTC");
    // The gateway saw the minted token only, never the backend credential.
    assert!(
        g.seen_tokens.iter().all(|t| t == "Bearer gw-token-1"),
        "{:?}",
        g.seen_tokens
    );
    drop(g);
    let calls = w.enc.lock().unwrap().calls();
    assert_eq!(calls[0].0, "runner_desk_claim");
    assert_eq!(
        calls[0].1,
        json!({ "desk": "code-desk", "operation_id": RID })
    );
    assert_eq!(calls[1].0, "runner_desk_release");
    assert_eq!(
        calls[1].1,
        json!({ "desk": "code-desk", "operation_id": RID, "outcome": "ready",
                "read_back": { "sandbox_id": FIRST_ID, "policy_digest": policy_digest(&policy()).unwrap() } })
    );
}

/// Each refusal before the backend: no gateway call, and no claim either.
#[tokio::test]
async fn a_create_refused_by_its_body_or_its_grant_reaches_nothing() {
    for (why, extra, want) in [
        (
            "a repo (contracts 0.65.0)",
            json!({ "repo": "https://github.com/acme/app.git" }),
            Code::FieldNotAllowed,
        ),
        (
            "an unlisted image",
            json!({ "image": format!("x@sha256:{}", "c".repeat(64)) }),
            Code::ConstraintImageDigests,
        ),
        (
            "an unlisted provider",
            json!({ "providers": ["slack"] }),
            Code::ConstraintProviders,
        ),
    ] {
        let w = world().await;
        let a =
            w.b.create(&admitted(), &create_body(extra), &crate::driver::Noted)
                .await;
        assert_eq!(code(&a), Some(want), "{why}");
        assert!(w.gw.lock().unwrap().calls.is_empty(), "{why}");
        assert!(methods(&w).is_empty(), "{why}");
    }
}

/// The grant pins each provider's configuration by digest: a provider whose
/// configuration changed since (another org, another base URL) is refused
/// before any claim, as is one the gateway does not have.
#[tokio::test]
async fn a_provider_whose_configuration_is_not_the_pinned_one_is_refused() {
    let w = world().await;
    w.gw.lock()
        .unwrap()
        .providers
        .get_mut("github")
        .unwrap()
        .config
        .insert("org".into(), "someone-else".into());
    let a =
        w.b.create(&admitted(), &create_body(json!({})), &crate::driver::Noted)
            .await;
    assert_eq!(code(&a), Some(Code::ConstraintProviderConfigDigests));
    assert!(mutations(&w).is_empty());
    assert!(methods(&w).is_empty(), "no claim");
    w.gw.lock().unwrap().providers.clear();
    let a =
        w.b.create(&admitted(), &create_body(json!({})), &crate::driver::Noted)
            .await;
    assert_eq!(code(&a), Some(Code::ConstraintProviderConfigDigests));
}

/// WHAT WAS APPROVED, after the create too: a provider whose configuration
/// changes while the desk is being made (here, while the create's reply is
/// held) never finishes as approved. It ends `unknown`, released so: the
/// desk stays held for a person.
#[tokio::test]
async fn a_provider_changed_during_create_cannot_finish_as_approved() {
    let w = world().await;
    w.gw.lock().unwrap().faults.delay.insert(
        "CreateSandbox".into(),
        std::time::Duration::from_millis(300),
    );
    let body = create_body(json!({}));
    let admitted = admitted();
    let (a, ()) = tokio::join!(w.b.create(&admitted, &body, &crate::driver::Noted), async {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        w.gw.lock()
            .unwrap()
            .providers
            .get_mut("github")
            .unwrap()
            .config
            .insert("org".into(), "someone-else".into());
    });
    assert_eq!(a.outcome, AnswerOutcome::Unknown, "{a:?}");
    let releases: Vec<Value> = methods_params(&w, "runner_desk_release");
    assert_eq!(
        releases.last().unwrap()["outcome"],
        "unknown",
        "{releases:?}"
    );
    assert!(
        w.enc.lock().unwrap().held.contains_key("code-desk"),
        "held for a person"
    );
}

/// The policy the desk LOADED must be the approved one, not only some policy:
/// a desk whose loaded revision is another policy than the grant approved
/// ends `unknown`, never `ready`.
#[tokio::test]
async fn a_desk_that_loaded_another_policy_than_the_approved_one_is_unknown() {
    let w = world().await;
    w.gw.lock().unwrap().faults.delay.insert(
        "CreateSandbox".into(),
        std::time::Duration::from_millis(300),
    );
    let body = create_body(json!({}));
    let admitted = admitted();
    let (a, ()) = tokio::join!(w.b.create(&admitted, &body, &crate::driver::Noted), async {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let mut g = w.gw.lock().unwrap();
        let revs = g
            .revisions
            .get_mut("code-desk")
            .expect("the create took effect");
        let mut other = revs[0].clone();
        other.network_policies.clear();
        revs.push(other);
    });
    assert_eq!(a.outcome, AnswerOutcome::Unknown, "{a:?}");
}

#[tokio::test]
async fn a_busy_desk_is_refused_desk_busy_before_any_change() {
    let w = world().await;
    w.enc.lock().unwrap().busy.insert("code-desk".into());
    let a =
        w.b.create(&admitted(), &create_body(json!({})), &crate::driver::Noted)
            .await;
    assert_eq!(code(&a), Some(Code::DeskBusy));
    assert!(mutations(&w).is_empty());
}

/// A change whose reply is lost, or that
/// the gateway holds UNCERTAIN, may still finish. It answers `running` with
/// its request id and is NOT released: the desk stays held.
#[tokio::test]
async fn a_lost_or_uncertain_change_answers_running_and_keeps_its_claim() {
    for uncertain in [false, true] {
        let w = world().await;
        {
            let mut g = w.gw.lock().unwrap();
            if uncertain {
                g.faults.answer.insert(
                    "CreateSandbox".into(),
                    Planted::Refused {
                        code: tonic::Code::FailedPrecondition,
                        reason: Some("REQUEST_OUTCOME_UNCERTAIN".into()),
                    },
                );
            } else {
                g.lose_reply.insert("CreateSandbox".into());
            }
        }
        let a =
            w.b.create(&admitted(), &create_body(json!({})), &crate::driver::Noted)
                .await;
        assert_eq!(a.outcome, AnswerOutcome::Running, "uncertain={uncertain}");
        assert_eq!(a.operation_id.as_deref(), Some(RID));
        assert_eq!(a.http_status(), 202);
        assert_eq!(methods(&w), ["runner_desk_claim"], "never released");
        assert_eq!(
            w.enc
                .lock()
                .unwrap()
                .held
                .get("code-desk")
                .map(String::as_str),
            Some(RID)
        );
    }
}

#[tokio::test]
async fn a_gateway_decision_against_a_change_is_its_code_and_frees_the_desk() {
    let w = world().await;
    w.b.create(&admitted(), &create_body(json!({})), &crate::driver::Noted)
        .await;
    let a =
        w.b.create(&then(1), &create_body(json!({})), &crate::driver::Noted)
            .await;
    assert_eq!(code(&a), Some(Code::DeskExists));
    assert!(w.enc.lock().unwrap().held.is_empty(), "released refused");
}

/// The post-write comparison: a desk the backend made otherwise than asked
/// is `unknown`, and stays held marked unknown.
#[tokio::test]
async fn a_desk_made_otherwise_than_asked_is_unknown() {
    let w = world().await;
    w.gw.lock().unwrap().rewrite_created = Some(|sb| {
        sb.spec.as_mut().unwrap().template.as_mut().unwrap().image =
            format!("evil@sha256:{}", "d".repeat(64));
    });
    let a =
        w.b.create(&admitted(), &create_body(json!({})), &crate::driver::Noted)
            .await;
    assert_eq!(a.outcome, AnswerOutcome::Unknown);
    let calls = w.enc.lock().unwrap().calls();
    assert_eq!(calls.last().unwrap().1["outcome"], "unknown");
}

#[tokio::test]
async fn a_delete_reads_back_that_the_desk_is_gone() {
    let w = world().await;
    w.b.create(&admitted(), &create_body(json!({})), &crate::driver::Noted)
        .await;
    w.enc.lock().unwrap().seen.clear();
    let a =
        w.b.delete(&then(1), "code-desk", &crate::driver::Noted)
            .await;
    assert_eq!(a.outcome, AnswerOutcome::Ready, "{a:?}");
    assert!(!w.gw.lock().unwrap().sandboxes.contains_key("code-desk"));
    let calls = w.enc.lock().unwrap().calls();
    assert_eq!(
        calls.last().unwrap().1["read_back"],
        json!({ "deleted": true, "sandbox_id": FIRST_ID })
    );
    let w2 = world().await;
    assert_eq!(
        code(
            &w2.b
                .delete(&admitted(), "nope", &crate::driver::Noted)
                .await
        ),
        Some(Code::DeskNotFound)
    );
    assert!(w2.enc.lock().unwrap().held.is_empty());
}

#[tokio::test]
async fn a_stop_then_a_start_read_the_desk_back_each_time() {
    let w = world().await;
    w.b.create(&admitted(), &create_body(json!({})), &crate::driver::Noted)
        .await;
    let stopped =
        w.b.stop_or_start(&then(1), "code-desk", false, &crate::driver::Noted)
            .await;
    assert_eq!(stopped.outcome, AnswerOutcome::Ready, "{stopped:?}");
    let started =
        w.b.stop_or_start(&then(2), "code-desk", true, &crate::driver::Noted)
            .await;
    assert_eq!(started.outcome, AnswerOutcome::Ready, "{started:?}");
    assert_eq!(
        mutations(&w),
        ["CreateSandbox", "StopSandbox", "StartSandbox"]
    );
    // Every release after a ready change carries the read-back.
    let releases: Vec<Value> = w
        .enc
        .lock()
        .unwrap()
        .calls()
        .into_iter()
        .filter(|(m, _)| m == "runner_desk_release")
        .map(|(_, p)| p)
        .collect();
    assert!(releases
        .iter()
        .all(|p| p["read_back"]["sandbox_id"] == FIRST_ID));
}

fn policy_body(policy: Value, version: &str) -> PolicySetBody {
    serde_json::from_value(json!({ "policy": policy, "expected_resource_version": version }))
        .unwrap()
}

#[tokio::test]
async fn a_policy_change_is_held_to_the_creation_policy_then_applied_at_its_version() {
    let w = world().await;
    w.b.create(&admitted(), &create_body(json!({})), &crate::driver::Noted)
        .await;
    // Narrowing: drop nothing that matters, change nothing the baseline holds.
    let same =
        w.b.policy_set(
            &then(1),
            "code-desk",
            &policy_body(policy(), "1"),
            &crate::driver::Noted,
        )
        .await;
    assert_eq!(same.outcome, AnswerOutcome::Ready, "{same:?}");
    assert_eq!(same.desk.resource_version.as_deref(), Some("2"));
    // A stale version: the gateway's compare-and-set refuses it.
    let stale =
        w.b.policy_set(
            &then(2),
            "code-desk",
            &policy_body(policy(), "1"),
            &crate::driver::Noted,
        )
        .await;
    assert_eq!(code(&stale), Some(Code::VersionConflict));
    // A widening the creation policy does not allow never reaches UpdateConfig.
    let mut wider = policy();
    wider["process"]["runAsUser"] = json!("0");
    let before = mutations(&w).len();
    let refused =
        w.b.policy_set(
            &then(3),
            "code-desk",
            &policy_body(wider, "2"),
            &crate::driver::Noted,
        )
        .await;
    assert_eq!(code(&refused), Some(Code::ConstraintPolicyBaseline));
    assert_eq!(mutations(&w).len(), before);
    assert!(w.enc.lock().unwrap().held.is_empty());
}

fn provider_records(g: &mut fake_gateway::State) {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/provider-github.json"
    );
    let f: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let p = crate::normalize::message(crate::providers::PROVIDER, &f["provider"]).unwrap();
    let prof =
        crate::normalize::message(crate::normalize::PROVIDER_PROFILE, &f["profile"]).unwrap();
    g.providers.insert("github".into(), p);
    g.profiles.insert(("desks".into(), "github".into()), prof);
}

#[tokio::test]
async fn a_required_provider_is_never_detached_and_another_is_with_the_providers_digest() {
    let w = world().await;
    w.b.create(&admitted(), &create_body(json!({})), &crate::driver::Noted)
        .await;
    {
        let mut g = w.gw.lock().unwrap();
        g.sandboxes
            .get_mut("code-desk")
            .unwrap()
            .spec
            .as_mut()
            .unwrap()
            .providers = vec!["github".into(), "slack".into()];
    }
    w.enc
        .lock()
        .unwrap()
        .required
        .insert("code-desk".into(), vec!["github".into()]);
    let a =
        w.b.detach(&then(1), "code-desk", "github", "1", &crate::driver::Noted)
            .await;
    assert_eq!(code(&a), Some(Code::DeskProviderRequired));
    assert_eq!(mutations(&w), ["CreateSandbox"], "no detach was sent");
    let a =
        w.b.detach(&then(2), "code-desk", "slack", "1", &crate::driver::Noted)
            .await;
    assert_eq!(a.outcome, AnswerOutcome::Ready, "{a:?}");
    assert_eq!(a.desk.providers, Some(vec!["github".to_string()]));
    let release = w.enc.lock().unwrap().calls().last().unwrap().1.clone();
    assert!(
        release["read_back"]["providers_digest"]
            .as_str()
            .is_some_and(|d| d.starts_with("sha256:")),
        "{release}"
    );
}

/// An Enclave that names no required providers cannot say one is not
/// required: the detach is refused, never assumed allowed.
#[tokio::test]
async fn a_detach_is_refused_when_the_enclave_names_no_required_providers() {
    let w = world().await;
    w.b.create(&admitted(), &create_body(json!({})), &crate::driver::Noted)
        .await;
    w.enc.lock().unwrap().omit_required = true;
    let a =
        w.b.detach(&then(1), "code-desk", "github", "1", &crate::driver::Noted)
            .await;
    assert_eq!(code(&a), Some(Code::BackendRefused));
    assert_eq!(mutations(&w), ["CreateSandbox"]);
}

#[tokio::test]
async fn status_reports_the_desk_and_its_providers_digest_and_takes_no_claim() {
    let w = world().await;
    w.b.create(&admitted(), &create_body(json!({})), &crate::driver::Noted)
        .await;
    w.enc.lock().unwrap().seen.clear();
    let a = w.b.status(&admitted(), "code-desk").await;
    assert_eq!(a.outcome, AnswerOutcome::Ready, "{a:?}");
    assert!(a.desk.providers_digest.is_some());
    assert!(methods(&w).is_empty(), "a read takes no claim");
    // A newer policy stored but not loaded: what the desk enforces cannot be told.
    w.gw.lock().unwrap().loading.insert("code-desk".into());
    w.gw.lock()
        .unwrap()
        .revisions
        .get_mut("code-desk")
        .unwrap()
        .push(Default::default());
    assert_eq!(
        w.b.status(&admitted(), "code-desk").await.outcome,
        AnswerOutcome::Unknown
    );
    let w2 = world().await;
    assert_eq!(
        code(&w2.b.status(&admitted(), "nope").await),
        Some(Code::DeskNotFound)
    );
}

/// The params of every Enclave call to `method`, in order.
fn methods_params(w: &World, method: &str) -> Vec<Value> {
    w.enc
        .lock()
        .unwrap()
        .calls()
        .into_iter()
        .filter(|(m, _)| m == method)
        .map(|(_, p)| p)
        .collect()
}
