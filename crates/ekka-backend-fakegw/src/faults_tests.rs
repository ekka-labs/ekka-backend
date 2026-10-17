//! Each fault proven on its own, through a real gRPC client of the fake.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use openshell_proto::openshell::datamodel::v1::{workspace_selector, WorkspaceSelector};
use openshell_proto::openshell::sandbox::v1::SandboxPolicy;
use openshell_proto::openshell::v1::{
    open_shell_client::OpenShellClient, CreateSandboxRequest, GetSandboxRequest, SandboxPhase,
    SandboxSpec, StopSandboxRequest, UpdateConfigRequest,
};
use tonic::transport::Channel;

use super::{wire, Planted, ERROR_DOMAIN};
use crate::fake_gateway::{self, Shared};

const TOKEN: &str = "gw-token-1";
const RID: &str = "6a1f2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";

fn ws() -> Option<WorkspaceSelector> {
    Some(WorkspaceSelector {
        selection: Some(workspace_selector::Selection::Workspace("desks".into())),
    })
}

fn req<T>(t: T) -> tonic::Request<T> {
    let mut r = tonic::Request::new(t);
    r.metadata_mut()
        .insert("authorization", format!("Bearer {TOKEN}").parse().unwrap());
    r
}

fn client(addr: SocketAddr) -> OpenShellClient<Channel> {
    let ch = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect_lazy();
    OpenShellClient::new(ch)
}

/// A gateway holding one ready sandbox, `d`, at resource version 1.
async fn gateway() -> (SocketAddr, Shared) {
    let (addr, st) = fake_gateway::start(TOKEN).await;
    client(addr)
        .create_sandbox(req(CreateSandboxRequest {
            workspace_scope: ws(),
            name: "d".into(),
            spec: Some(SandboxSpec {
                policy: Some(SandboxPolicy::default()),
                ..Default::default()
            }),
            request_id: RID.into(),
            ..Default::default()
        }))
        .await
        .unwrap();
    (addr, st)
}

fn phase(st: &Shared) -> SandboxPhase {
    let s = st.lock().unwrap();
    SandboxPhase::try_from(s.sandboxes["d"].status.as_ref().unwrap().phase).unwrap()
}

fn stop() -> tonic::Request<StopSandboxRequest> {
    req(StopSandboxRequest {
        workspace_scope: ws(),
        name: "d".into(),
        request_id: "0b3d5f7a-1c2e-4a6b-8d9f-0e1a2b3c4d5e".into(),
    })
}

fn update(expected: u64) -> tonic::Request<UpdateConfigRequest> {
    req(UpdateConfigRequest {
        workspace_scope: ws(),
        sandbox: "d".into(),
        policy: Some(SandboxPolicy::default()),
        expected_resource_version: expected,
        request_id: "5c1e9a2b-7d3f-4e8a-9b0c-1d2e3f4a5b6c".into(),
        ..Default::default()
    })
}

/// A delayed reply: the effect is there before the answer, which comes late
/// and whole.
#[tokio::test(flavor = "multi_thread")]
async fn a_delayed_reply_comes_late_after_its_effect() {
    let (addr, st) = gateway().await;
    st.lock()
        .unwrap()
        .faults
        .delay
        .insert("StopSandbox".into(), Duration::from_millis(600));
    let started = Instant::now();
    let call = tokio::spawn(async move { client(addr).stop_sandbox(stop()).await });
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!call.is_finished(), "the reply is still held");
    assert_eq!(phase(&st), SandboxPhase::Stopped, "the effect came first");
    let answer = call.await.unwrap().unwrap().into_inner();
    assert!(started.elapsed() >= Duration::from_millis(600));
    let phase = answer.sandbox.unwrap().status.unwrap().phase;
    assert_eq!(phase, SandboxPhase::Stopped as i32);
}

/// A dropped reply: the effect is kept, the connection closes, and the
/// client gets no status from the gateway, only its own transport's.
#[tokio::test(flavor = "multi_thread")]
async fn a_dropped_reply_keeps_the_effect_and_never_answers() {
    let (addr, st) = gateway().await;
    st.lock()
        .unwrap()
        .faults
        .drop_reply
        .insert("StopSandbox".into());
    let err = tokio::time::timeout(Duration::from_secs(10), client(addr).stop_sandbox(stop()))
        .await
        .expect("the client sees the closed connection, not a hang")
        .unwrap_err();
    // No gateway status: nothing in the details, and a code the gateway
    // never chose. tonic 0.14 reads a connection closed mid-call as UNKNOWN
    // ("transport error"), which the adapter's client reads as UNAVAILABLE:
    // the change may or may not have happened (ekka-backend gateway.rs).
    assert!(err.details().is_empty(), "{err:?}");
    assert_eq!(err.code(), tonic::Code::Unknown, "{err:?}");
    assert_eq!(phase(&st), SandboxPhase::Stopped, "the write was kept");
    {
        let s = st.lock().unwrap();
        assert!(s.calls.iter().any(|c| c == "StopSandbox desks/d"));
        assert!(s.request_ids.iter().any(|(rpc, _)| rpc == "StopSandbox"));
    }
    // Only the reply was lost: a new connection reads the stopped desk.
    let read = client(addr)
        .get_sandbox(req(GetSandboxRequest {
            workspace_scope: ws(),
            name: "d".into(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        read.sandbox.unwrap().status.unwrap().phase,
        SandboxPhase::Stopped as i32
    );
}

/// NOT_FOUND before any effect, on a change and on a read, for a sandbox
/// the fake does have.
#[tokio::test(flavor = "multi_thread")]
async fn not_found_is_answered_before_any_effect() {
    let (addr, st) = gateway().await;
    {
        let mut s = st.lock().unwrap();
        s.faults
            .answer
            .insert("StopSandbox".into(), Planted::NotFound);
        s.faults
            .answer
            .insert("GetSandbox".into(), Planted::NotFound);
    }
    let err = client(addr).stop_sandbox(stop()).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
    assert_eq!(err.message(), "sandbox not found");
    let err = client(addr)
        .get_sandbox(req(GetSandboxRequest {
            workspace_scope: ws(),
            name: "d".into(),
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
    assert_eq!(phase(&st), SandboxPhase::Ready, "nothing changed");
    let s = st.lock().unwrap();
    assert!(s
        .calls
        .contains(&"StopSandbox (planted NotFound)".to_string()));
    assert!(
        !s.request_ids.iter().any(|(rpc, _)| rpc == "StopSandbox"),
        "the handler never ran"
    );
}

fn error_info(st: &tonic::Status) -> wire::ErrorInfo {
    let env: wire::RpcStatus = prost::Message::decode(st.details()).unwrap();
    // OpenShell's own decoder refuses an envelope that disagrees with the
    // status (rpc_error.rs:23).
    assert_eq!(env.code, st.code() as i32);
    assert_eq!(env.message, st.message());
    assert_eq!(env.details.len(), 1);
    assert_eq!(
        env.details[0].type_url,
        "type.googleapis.com/google.rpc.ErrorInfo"
    );
    prost::Message::decode(env.details[0].value.as_slice()).unwrap()
}

/// ABORTED with RESOURCE_VERSION_CONFLICT, in OpenShell's exact shape
/// (rpc_error.rs:77-87), before any effect.
#[tokio::test(flavor = "multi_thread")]
async fn a_version_conflict_is_openshells_exact_status_and_changes_nothing() {
    let (addr, st) = gateway().await;
    for current in [Some(7), None] {
        st.lock()
            .unwrap()
            .faults
            .answer
            .insert("UpdateConfig".into(), Planted::VersionConflict { current });
        let err = client(addr).update_config(update(1)).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Aborted);
        let shown = current.map_or_else(|| "unknown".to_string(), |v| v.to_string());
        assert_eq!(
            err.message(),
            format!("UpdateConfig failed due to concurrent modification (current resource_version: {shown})")
        );
        let info = error_info(&err);
        assert_eq!(info.reason, "RESOURCE_VERSION_CONFLICT");
        assert_eq!(info.domain, ERROR_DOMAIN);
        let mut want = HashMap::from([("recovery".to_string(), "REFRESH_STATE".to_string())]);
        if let Some(v) = current {
            want.insert("current_resource_version".into(), v.to_string());
        }
        assert_eq!(info.metadata, want);
    }
    let s = st.lock().unwrap();
    assert_eq!(s.revisions["d"].len(), 1, "no revision was made");
    assert_eq!(
        s.sandboxes["d"].metadata.as_ref().unwrap().resource_version,
        1
    );
}

/// Without a fault the fake answers as before: the faults change nothing
/// they were not asked to.
#[tokio::test(flavor = "multi_thread")]
async fn with_no_fault_planted_every_call_is_answered_as_before() {
    let (addr, st) = gateway().await;
    client(addr).stop_sandbox(stop()).await.unwrap();
    client(addr).update_config(update(1)).await.unwrap();
    let s = st.lock().unwrap();
    assert_eq!(
        s.calls,
        [
            "CreateSandbox desks/d",
            "StopSandbox desks/d",
            "UpdateConfig desks/d"
        ]
    );
}

/// The TLS gateway answers a client that trusts only the throwaway CA, the
/// one the fake issuer's certificate comes from.
#[tokio::test(flavor = "multi_thread")]
async fn the_tls_gateway_is_trusted_through_the_issuers_ca() {
    let (ca, cert, key) = crate::fake_issuer::throwaway_ca();
    let (addr, st) = fake_gateway::start_tls(TOKEN, cert, key).await;
    let tls = tonic::transport::ClientTlsConfig::new()
        .ca_certificate(tonic::transport::Certificate::from_pem(ca));
    let ch = tonic::transport::Endpoint::from_shared(format!("https://{addr}"))
        .unwrap()
        .tls_config(tls)
        .unwrap()
        .connect()
        .await
        .unwrap();
    OpenShellClient::new(ch)
        .create_sandbox(req(CreateSandboxRequest {
            workspace_scope: ws(),
            name: "d".into(),
            request_id: RID.into(),
            ..Default::default()
        }))
        .await
        .unwrap();
    assert_eq!(st.lock().unwrap().calls, ["CreateSandbox desks/d"]);
}
