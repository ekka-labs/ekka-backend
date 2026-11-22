//! Real adapter binary, signed requests, local HTTP and TLS test gateway.
use super::*;
const PROVIDER_KEY: &str = "PLANTED-provider-key-5Cv9";

async fn setup() -> Harness {
    let h = Harness::start().await;
    h.gw.lock()
        .unwrap()
        .providers
        .get_mut("github")
        .unwrap()
        .metadata = Some(openshell_proto::openshell::datamodel::v1::ObjectMeta {
        name: "github".into(),
        workspace: WORKSPACE.into(),
        resource_version: 1,
        ..Default::default()
    });
    h
}
fn connect(h: &Harness) -> Call {
    let body = json!({"name":"github", "type":"github", "profile_workspace":WORKSPACE,
        "expected_resource_version":"1",
        "credential_refs":{"GITHUB_TOKEN":"36c7c8fe-80d7-4410-8e39-c483cad8bd76"}});
    let mut call = h.call("POST", "/v1/providers", Some(&body), Grant::write(&h.grant));
    call.provider_header = Some(b64(json!({"GITHUB_TOKEN":PROVIDER_KEY})
        .to_string()
        .as_bytes()));
    call
}
fn assert_provider_key_private(h: &Harness) {
    h.assert_no_secret_shown();
    let encoded = b64(json!({"GITHUB_TOKEN":PROVIDER_KEY}).to_string().as_bytes());
    for secret in [PROVIDER_KEY, encoded.as_str()] {
        assert!(!h.logs().contains(secret));
        assert!(h.bodies.iter().all(|b| !b.contains(secret)));
        for file in files_under(h.dir.path()) {
            assert!(!String::from_utf8_lossy(&std::fs::read(file).unwrap()).contains(secret));
        }
    }
}
#[tokio::test]
async fn provider_key_is_written_once_over_the_local_header_and_never_recorded() {
    let mut h = setup().await;
    let call = connect(&h);
    h.send(&call).await.assert_ready();
    assert_eq!(
        h.gw.lock().unwrap().provider_written_credentials["github"]["GITHUB_TOKEN"],
        PROVIDER_KEY
    );
    let replay = h.send(&call).await;
    assert_eq!(replay.body["delivery"], "duplicate");
    replay.assert_ready();
    h.restart().await;
    let replay = h.send(&call).await;
    replay.assert_ready();
    assert_eq!(replay.body["delivery"], "duplicate");
    assert_eq!(h.mutations().len(), 1);
    assert_provider_key_private(&h);
}
#[tokio::test]
async fn provider_metadata_read_has_no_configuration_and_rejects_the_secret_header() {
    let mut h = setup().await;
    let call = h.call("GET", "/v1/providers/github", None, Grant::read());
    let answer = h.send(&call).await;
    answer.assert_ready();
    assert_eq!(answer.body["provider_info"]["resource_version"], "1");
    assert!(answer.body["provider_info"].get("config").is_none());
    assert_eq!(
        answer.body["provider_info"]["credential_names"],
        json!(["GITHUB_TOKEN"])
    );
    let mut with_secret = h.call("GET", "/v1/providers/github", None, Grant::read());
    with_secret.provider_header = connect(&h).provider_header;
    let calls_before = h.gateway_calls().len();
    let refusal = h.send(&with_secret).await;
    assert_eq!(refusal.outcome(), "refused");
    assert_eq!(h.gateway_calls().len(), calls_before);
    assert_provider_key_private(&h);
}
#[tokio::test]
async fn a_lost_provider_acknowledgement_stays_unknown_across_restart() {
    let mut h = setup().await;
    h.gw.lock().unwrap().provider_apply_then_error = Some(tonic::Code::Unavailable);
    let call = connect(&h);
    assert_eq!(h.send(&call).await.outcome(), "unknown");
    assert_eq!(
        h.gw.lock().unwrap().provider_written_credentials["github"]["GITHUB_TOKEN"],
        PROVIDER_KEY
    );
    h.restart().await;
    let replay = h.send(&call).await;
    assert_eq!(replay.outcome(), "unknown");
    assert_eq!(replay.body["delivery"], "duplicate");
    assert_eq!(h.mutations().len(), 1);
    assert_provider_key_private(&h);
}
