#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
use crate::answer::Outcome;
use crate::driver::tests::{world, World};
use crate::provider_credentials::Material;
use crate::token::Verified;

fn setup(w: &World, create: bool) -> ConnectBody {
    let mut gw = w.gw.lock().unwrap();
    let provider = gw.providers.get_mut("github").unwrap();
    provider.metadata = Some(ObjectMeta {
        name: "github".into(),
        workspace: "desks".into(),
        resource_version: 1,
        ..Default::default()
    });
    let body = ConnectBody {
        name: "github".into(),
        r#type: "github".into(),
        profile_workspace: "desks".into(),
        credential_refs: BTreeMap::from([(
            "GITHUB_TOKEN".into(),
            "36c7c8fe-80d7-4410-8e39-c483cad8bd76".into(),
        )]),
        expected_resource_version: (!create).then(|| "1".into()),
    };
    if create {
        gw.providers.remove("github");
    }
    body
}
fn verified(grant: Option<Value>) -> Verified {
    let mut v = Verified::for_tests(grant);
    v.provider_credentials = Some(
        Material::parse(Some(&crate::testkit::b64(
            br#"{"GITHUB_TOKEN":"PLANTED_PROVIDER_KEY"}"#,
        )))
        .unwrap(),
    );
    v
}
fn admitted(grant: Option<Value>) -> Admitted {
    verified(grant).admit().unwrap()
}
fn grant() -> Value {
    crate::driver::tests::grant()
}
fn grant_for(body: &ConnectBody) -> Value {
    let mut g = grant();
    if body.expected_resource_version.is_none() {
        let fixture: Value =
            serde_json::from_str(include_str!("../../tests/fixtures/provider-github.json"))
                .unwrap();
        let mut p: Provider =
            crate::normalize::message(crate::providers::PROVIDER, &fixture["provider"]).unwrap();
        p.config.clear();
        let profile =
            crate::normalize::message(crate::normalize::PROVIDER_PROFILE, &fixture["profile"])
                .unwrap();
        g["provider_config_digests"]["github"] =
            serde_json::json!(providers::config_digest("github", &p, &profile).unwrap());
    }
    g
}
fn writes(w: &World) -> Vec<String> {
    w.gw.lock()
        .unwrap()
        .request_ids
        .iter()
        .map(|(m, _)| m.clone())
        .collect()
}
#[test]
fn body_refuses_non_uuid_cross_workspace_and_duplicate_references() {
    let mut b = ConnectBody {
        name: "github".into(),
        r#type: "github".into(),
        profile_workspace: String::new(),
        credential_refs: BTreeMap::new(),
        expected_resource_version: None,
    };
    assert!(b.check("desks").is_ok());
    b.credential_refs
        .insert("api_key".into(), "API_CREDENTIAL_BACKEND".into());
    assert!(b.check("desks").is_err());
    b.credential_refs.clear();
    b.profile_workspace = "other".into();
    assert!(b.check("desks").is_err());
    b.profile_workspace.clear();
    b.credential_refs = BTreeMap::from([
        ("one".into(), "36c7c8fe-80d7-4410-8e39-c483cad8bd76".into()),
        ("two".into(), "36c7c8fe-80d7-4410-8e39-c483cad8bd76".into()),
    ]);
    assert!(b.check("desks").is_err());
}
#[tokio::test]
async fn acknowledged_create_and_rotation_set_the_key_and_check_redacted_read_back() {
    for create in [true, false] {
        let w = world().await;
        let body = setup(&w, create);
        let answer =
            w.b.connect_provider(&admitted(Some(grant_for(&body))), &body, &Noted)
                .await;
        assert_eq!(answer.outcome, Outcome::Ready, "{answer:?}");
        assert_eq!(
            writes(&w),
            [if create {
                "CreateProvider"
            } else {
                "UpdateProvider"
            }]
        );
        let gw = w.gw.lock().unwrap();
        assert_eq!(
            gw.provider_written_credentials["github"]["GITHUB_TOKEN"],
            "PLANTED_PROVIDER_KEY"
        );
        assert_eq!(
            gw.providers["github"].credentials["GITHUB_TOKEN"],
            "REDACTED"
        );
        assert!(!serde_json::to_string(&answer)
            .unwrap()
            .contains("PLANTED_PROVIDER_KEY"));
    }
}
#[tokio::test]
async fn no_grant_or_mismatched_material_has_no_gateway_io() {
    for missing_grant in [true, false] {
        let w = world().await;
        let mut body = setup(&w, true);
        if !missing_grant {
            body.credential_refs.clear();
        }
        let answer =
            w.b.connect_provider(&admitted((!missing_grant).then(grant)), &body, &Noted)
                .await;
        assert_eq!(answer.outcome, Outcome::Refused);
        assert!(w.gw.lock().unwrap().calls.is_empty());
    }
}
#[tokio::test]
async fn a_changed_profile_digest_or_stale_version_never_writes() {
    for stale in [true, false] {
        let w = world().await;
        let mut body = setup(&w, false);
        let mut g = grant();
        if stale {
            body.expected_resource_version = Some("2".into());
        } else {
            g["provider_config_digests"]["github"] =
                serde_json::json!(format!("sha256:{}", "a".repeat(64)));
        }
        let answer =
            w.b.connect_provider(&admitted(Some(g)), &body, &Noted)
                .await;
        assert_eq!(
            answer.code,
            Some(if stale {
                Code::VersionConflict
            } else {
                Code::ConstraintProviderConfigDigests
            })
        );
        assert!(writes(&w).is_empty());
    }
}
#[tokio::test]
async fn matching_public_configuration_does_not_turn_a_lost_write_reply_into_success() {
    let w = world().await;
    let body = setup(&w, false);
    w.gw.lock().unwrap().provider_apply_then_error = Some(tonic::Code::Unavailable);
    let answer =
        w.b.connect_provider(&admitted(Some(grant())), &body, &Noted)
            .await;
    assert_eq!(answer.outcome, Outcome::Unknown);
    assert_eq!(writes(&w), ["UpdateProvider"]);
    assert_eq!(
        w.gw.lock().unwrap().provider_written_credentials["github"]["GITHUB_TOKEN"],
        "PLANTED_PROVIDER_KEY"
    );
}

fn recovery(w: &World) -> crate::recover::Recovery {
    let state = w.dir.path().join("provider-state");
    let uid = rustix::process::geteuid().as_raw();
    let store = std::sync::Arc::new(crate::store::Store::open(&state, uid).unwrap());
    let key = crate::testkit::govern_test_key();
    let verifier = std::sync::Arc::new(crate::testkit::verifier(
        &[("govern-gate-token-v1", &key)],
        crate::testkit::NOW,
    ));
    crate::recover::Recovery::new(
        store,
        verifier,
        "provider-test-gateway".into(),
        &state,
        uid,
        std::sync::Arc::new(chrono::Utc::now),
    )
    .unwrap()
}
fn route() -> crate::routes::Route {
    crate::routes::Route {
        operation: crate::routes::Operation::ProviderConnect,
        desk: None,
        provider: None,
    }
}
#[tokio::test]
async fn duplicate_delivers_record_without_resending_or_persisting_any_key() {
    let w = world().await;
    let body = bytes::Bytes::from(serde_json::to_vec(&setup(&w, true)).unwrap());
    let r = recovery(&w);
    let first = crate::ops::answer(
        &w.b,
        &r,
        &route(),
        verified(Some(grant_for(&serde_json::from_slice(&body).unwrap()))),
        &body,
    )
    .await;
    assert_eq!(first.outcome, Outcome::Ready, "{first:?}");
    let second = crate::ops::answer(
        &w.b,
        &r,
        &route(),
        verified(Some(grant_for(&serde_json::from_slice(&body).unwrap()))),
        &body,
    )
    .await;
    assert_eq!(second.outcome, Outcome::Ready);
    assert_eq!(second.delivery, crate::answer::Delivery::Duplicate);
    assert_eq!(writes(&w), ["CreateProvider"]);
    let record = r.store().get(crate::driver::tests::RID).unwrap().unwrap();
    let stored = serde_json::to_string(&record).unwrap();
    assert!(!stored.contains("PLANTED_PROVIDER_KEY"));
    assert!(!stored.contains("backend-credential"));
    assert!(!stored.contains(&crate::testkit::b64(
        br#"{"GITHUB_TOKEN":"PLANTED_PROVIDER_KEY"}"#
    )));
}
#[tokio::test]
async fn cold_unfinished_provider_write_becomes_unknown_without_any_gateway_io() {
    let w = world().await;
    let body = bytes::Bytes::from(serde_json::to_vec(&setup(&w, false)).unwrap());
    let r = recovery(&w);
    let rec = crate::store::running(
        &route(),
        "",
        crate::driver::tests::RID,
        "original-operation",
        &body,
        "signed-token",
        r.now(),
    );
    r.store().begin(&rec).unwrap();
    let result = crate::ops::answer(&w.b, &r, &route(), verified(Some(grant())), &body).await;
    assert_eq!(result.outcome, Outcome::Unknown);
    assert!(w.gw.lock().unwrap().calls.is_empty());
    let second = crate::ops::answer(&w.b, &r, &route(), verified(Some(grant())), &body).await;
    assert_eq!(second.outcome, Outcome::Unknown);
    assert_eq!(second.delivery, crate::answer::Delivery::Duplicate);
    assert!(writes(&w).is_empty());
}
#[tokio::test]
async fn in_flight_provider_write_is_neither_settled_nor_sent_again_by_a_duplicate() {
    let w = world().await;
    let body = bytes::Bytes::from(serde_json::to_vec(&setup(&w, false)).unwrap());
    let r = recovery(&w);
    let rec = crate::store::running(
        &route(),
        "",
        crate::driver::tests::RID,
        "original-operation",
        &body,
        "signed-token",
        r.now(),
    );
    r.store().begin(&rec).unwrap();
    let _in_flight = r.take(crate::driver::tests::RID).unwrap();
    let result = crate::ops::answer(&w.b, &r, &route(), verified(Some(grant())), &body).await;
    assert_eq!(result.outcome, Outcome::Running);
    assert!(w.gw.lock().unwrap().calls.is_empty());
}

#[tokio::test]
async fn plaintext_credential_fields_are_refused_before_a_record_or_gateway_call() {
    let w = world().await;
    let mut body = serde_json::to_value(setup(&w, true)).unwrap();
    body["credentials"] = serde_json::json!({"GITHUB_TOKEN":"PLANTED_PROVIDER_KEY"});
    let body = bytes::Bytes::from(serde_json::to_vec(&body).unwrap());
    let r = recovery(&w);
    let result = crate::ops::answer(&w.b, &r, &route(), verified(Some(grant())), &body).await;
    assert_eq!(result.code, Some(Code::FieldNotAllowed));
    assert!(r.store().get(crate::driver::tests::RID).unwrap().is_none());
    assert!(w.gw.lock().unwrap().calls.is_empty());
}
#[tokio::test]
async fn an_internal_error_after_a_write_is_unknown_even_when_the_key_was_applied() {
    let w = world().await;
    let body = setup(&w, false);
    w.gw.lock().unwrap().provider_apply_then_error = Some(tonic::Code::Internal);
    let result =
        w.b.connect_provider(&admitted(Some(grant())), &body, &Noted)
            .await;
    assert_eq!(result.outcome, Outcome::Unknown);
    assert_eq!(writes(&w), ["UpdateProvider"]);
}

#[tokio::test]
async fn a_provider_outside_the_grant_is_refused_before_gateway_io() {
    let w = world().await;
    let body = setup(&w, false);
    let mut g = grant();
    g["providers"] = serde_json::json!(["other"]);
    g["provider_config_digests"] =
        serde_json::json!({"other":format!("sha256:{}", "a".repeat(64))});
    let result =
        w.b.connect_provider(&admitted(Some(g)), &body, &Noted)
            .await;
    assert_eq!(result.code, Some(Code::ConstraintProviders));
    assert!(w.gw.lock().unwrap().calls.is_empty());
}
#[tokio::test]
async fn rotation_keeps_customer_config_local_and_does_not_forward_gateway_handles() {
    let w = world().await;
    let body = setup(&w, false);
    let metadata = serde_json::to_string(&body).unwrap();
    assert!(!metadata.contains("acme"));
    assert!(!metadata.contains("base_url"));
    w.gw.lock()
        .unwrap()
        .providers
        .get_mut("github")
        .unwrap()
        .credential_handles
        .insert("GITHUB_TOKEN".into(), Default::default());
    let result =
        w.b.connect_provider(&admitted(Some(grant())), &body, &Noted)
            .await;
    assert_eq!(result.outcome, Outcome::Ready, "{result:?}");
    assert_eq!(
        w.gw.lock().unwrap().providers["github"].config["org"],
        "acme"
    );
}

#[tokio::test]
async fn metadata_read_exposes_descriptors_and_version_but_neither_keys_nor_customer_config() {
    let w = world().await;
    setup(&w, false);
    let result =
        w.b.provider_info(&Verified::for_tests(None).admit().unwrap(), "github")
            .await;
    assert_eq!(result.outcome, Outcome::Ready, "{result:?}");
    let info = result.desk.provider_info.as_ref().unwrap();
    assert_eq!(info.resource_version.as_deref(), Some("1"));
    assert_eq!(info.credentials[0].name, "api_token");
    assert_eq!(
        info.configuration_digest.as_deref(),
        grant()["provider_config_digests"]["github"].as_str()
    );
    let serialized = serde_json::to_string(&result).unwrap();
    assert!(!serialized.contains("acme"));
    assert!(!serialized.contains("base_url"));
    assert!(!serialized.contains("PLANTED_PROVIDER_KEY"));
    assert!(writes(&w).is_empty());
}
#[tokio::test]
async fn metadata_can_describe_a_not_yet_connected_workspace_profile() {
    let w = world().await;
    setup(&w, true);
    let result =
        w.b.provider_info(&Verified::for_tests(None).admit().unwrap(), "github")
            .await;
    assert_eq!(result.outcome, Outcome::Ready, "{result:?}");
    let info = result.desk.provider_info.as_ref().unwrap();
    assert!(info.resource_version.is_none());
    assert_eq!(info.profile_workspace, "desks");
    let requested: ConnectBody = serde_json::from_value(serde_json::json!({"name":"github","type":"github","profile_workspace":"desks","credential_refs":{}})).unwrap();
    assert_eq!(
        info.configuration_digest.as_deref(),
        grant_for(&requested)["provider_config_digests"]["github"].as_str()
    );
    assert!(writes(&w).is_empty());
}

#[tokio::test]
async fn an_unenforced_profile_is_refused_even_if_the_grant_pins_its_digest() {
    let w = world().await;
    let body = setup(&w, false);
    let mut g = grant();
    {
        let mut gw = w.gw.lock().unwrap();
        gw.profiles
            .get_mut(&("desks".into(), "github".into()))
            .unwrap()
            .endpoints[0]
            .enforcement = 0;
        let p = &gw.providers["github"];
        let profile = &gw.profiles[&("desks".into(), "github".into())];
        g["provider_config_digests"]["github"] =
            serde_json::json!(providers::config_digest("github", p, profile).unwrap());
    }
    let result =
        w.b.connect_provider(&admitted(Some(g)), &body, &Noted)
            .await;
    assert_eq!(result.code, Some(Code::ConstraintCredentialEndpoint));
    assert!(writes(&w).is_empty());
}
