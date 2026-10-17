//! A fake NVIDIA OpenShell gateway for tests, built from the same vendored
//! protos and routed by gRPC path. It answers only the calls
//! the adapter makes, records every one with the token it carried, and
//! refuses a call whose token is not the one it was given.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use openshell_proto::openshell::datamodel::v1::{
    workspace_selector::Selection, Provider, WorkspaceSelector,
};
use openshell_proto::openshell::v1::{
    GetProviderProfileRequest, GetProviderRequest, ListProviderProfilesRequest,
    ListProviderProfilesResponse, ProviderProfile, ProviderProfileResponse, ProviderResponse,
};
use tonic::server::{Grpc, NamedService, UnaryService};
use tonic::{Request, Response, Status};

type Fut<T> = Pin<Box<dyn Future<Output = T> + Send>>;

#[derive(Default)]
pub struct State {
    /// The one bearer token the gateway accepts.
    pub token: String,
    /// Every call, in order: `"<Rpc> <what>"`.
    pub calls: Vec<String>,
    /// Every `authorization` value received.
    pub seen_tokens: Vec<String>,
    /// Provider records in the desk workspace, by name.
    pub providers: BTreeMap<String, Provider>,
    /// Profiles by (workspace, id); "" is what the workspace's list sees as
    /// platform and static profiles, each with its own `scope`.
    pub profiles: BTreeMap<(String, String), ProviderProfile>,
    /// Every provider read is refused with this code.
    pub refuse_reads: Option<tonic::Code>,
    /// Sandboxes in the desk workspace, by name (`sandboxes.rs`).
    pub sandboxes: BTreeMap<String, openshell_proto::openshell::v1::Sandbox>,
    /// Each sandbox's policy revisions, the creation policy first.
    pub revisions: BTreeMap<String, Vec<openshell_proto::openshell::sandbox::v1::SandboxPolicy>>,
    /// Sandboxes whose newest revision is stored but not loaded yet.
    pub loading: std::collections::BTreeSet<String>,
    /// The last sandbox id number handed out.
    pub next_id: u64,
    /// RPCs whose effect is committed and whose reply is then lost.
    pub lose_reply: std::collections::BTreeSet<String>,
    /// Every request id a change carried: (rpc, request id).
    pub request_ids: Vec<(String, String)>,
    /// Every request id the gateway admitted, as OpenShell keeps it for
    /// replay (`sandboxes::Admission`).
    pub applied: BTreeMap<String, crate::sandboxes::Admission>,
    /// RPCs whose effect is committed with NO confirmed success and whose
    /// reply is lost: the same request id later is REQUEST_OUTCOME_UNCERTAIN.
    pub lose_finalizer: std::collections::BTreeSet<String>,
    /// Sandbox names whose GetSandbox answers OK with NO sandbox in it: a
    /// malformed answer, never "absent" (only NOT_FOUND is).
    pub empty_get: std::collections::BTreeSet<String>,
    /// Read at every change, before its effect: the test proves what was on
    /// disk at that moment (an operation record).
    pub watch: Option<std::path::PathBuf>,
    /// (rpc, the watched file's content then, or `None` when absent).
    pub watched: Vec<(String, Option<String>)>,
    /// Applied to a created sandbox before it is kept: a gateway whose result
    /// is not what it was asked.
    pub rewrite_created: Option<fn(&mut openshell_proto::openshell::v1::Sandbox)>,
    /// Faults planted around the handlers: a delayed or dropped reply, or an
    /// answer before any effect (`faults.rs`).
    pub faults: crate::faults::Faults,
}

pub type Shared = Arc<Mutex<State>>;

pub(crate) fn workspace(w: Option<&WorkspaceSelector>) -> String {
    match w.and_then(|w| w.selection.as_ref()) {
        Some(Selection::Workspace(w)) => w.clone(),
        _ => String::new(),
    }
}

pub(crate) fn authorized<T>(st: &Shared, r: &Request<T>) -> Result<(), Status> {
    let got = r
        .metadata()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let mut s = st.lock().unwrap();
    s.seen_tokens.push(got.clone());
    if got == format!("Bearer {}", s.token) {
        Ok(())
    } else {
        Err(Status::unauthenticated("bad token"))
    }
}

fn refused(st: &Shared) -> Result<(), Status> {
    match st.lock().unwrap().refuse_reads {
        Some(c) => Err(Status::new(c, "refused")),
        None => Ok(()),
    }
}

fn get_provider(
    st: &Shared,
    r: Request<GetProviderRequest>,
) -> Result<Response<ProviderResponse>, Status> {
    authorized(st, &r)?;
    let q = r.into_inner();
    let ws = workspace(q.workspace_scope.as_ref());
    st.lock()
        .unwrap()
        .calls
        .push(format!("GetProvider {ws}/{}", q.name));
    refused(st)?;
    let p = st.lock().unwrap().providers.get(&q.name).cloned();
    match p {
        Some(p) => Ok(Response::new(ProviderResponse {
            provider: Some(p),
            ..Default::default()
        })),
        None => Err(Status::not_found("no such provider")),
    }
}

fn get_profile(
    st: &Shared,
    r: Request<GetProviderProfileRequest>,
) -> Result<Response<ProviderProfileResponse>, Status> {
    authorized(st, &r)?;
    let q = r.into_inner();
    let ws = workspace(q.workspace_scope.as_ref());
    st.lock()
        .unwrap()
        .calls
        .push(format!("GetProviderProfile {ws}/{}", q.id));
    refused(st)?;
    let p = st.lock().unwrap().profiles.get(&(ws, q.id)).cloned();
    match p {
        Some(p) => Ok(Response::new(ProviderProfileResponse { profile: Some(p) })),
        None => Err(Status::not_found("no such profile")),
    }
}

fn list_profiles(
    st: &Shared,
    r: Request<ListProviderProfilesRequest>,
) -> Result<Response<ListProviderProfilesResponse>, Status> {
    authorized(st, &r)?;
    let q = r.into_inner();
    let ws = workspace(q.workspace_scope.as_ref());
    st.lock()
        .unwrap()
        .calls
        .push(format!("ListProviderProfiles {ws}"));
    refused(st)?;
    let s = st.lock().unwrap();
    let profiles = s
        .profiles
        .iter()
        .filter(|((w, _), _)| w.is_empty() || *w == ws)
        .map(|(_, p)| p.clone())
        .collect();
    Ok(Response::new(ListProviderProfilesResponse {
        profiles,
        next_page_token: String::new(),
    }))
}

struct Unary<F>(Shared, F);
impl<Q: Send + 'static, P: Send + 'static, F> UnaryService<Q> for Unary<F>
where
    F: Fn(&Shared, Request<Q>) -> Result<Response<P>, Status> + Copy + Send + 'static,
{
    type Response = P;
    type Future = Fut<Result<Response<P>, Status>>;
    fn call(&mut self, r: Request<Q>) -> Self::Future {
        let (st, f) = (self.0.clone(), self.1);
        Box::pin(async move { f(&st, r) })
    }
}

#[derive(Clone)]
struct Fake(Shared);

impl NamedService for Fake {
    const NAME: &'static str = "openshell.v1.OpenShell";
}

impl<B> tonic::codegen::Service<http::Request<B>> for Fake
where
    B: tonic::codegen::Body<Data = tonic::codegen::Bytes> + Send + 'static,
    B::Error: Into<tonic::codegen::StdError> + Send + 'static,
{
    type Response = http::Response<tonic::body::Body>;
    type Error = Infallible;
    type Future = Fut<Result<Self::Response, Infallible>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, req: http::Request<B>) -> Self::Future {
        let st = self.0.clone();
        Box::pin(async move {
            let rpc = crate::faults::rpc_of(req.uri().path()).to_string();
            if let Some(planted) = crate::faults::before(&st, &rpc) {
                return Ok(planted.into_http());
            }
            let faulted = st.clone();
            let reply = match req.uri().path() {
                "/openshell.v1.OpenShell/CreateSandbox" => {
                    Grpc::new(tonic_prost::ProstCodec::default())
                        .unary(Unary(st, crate::sandboxes::create), req)
                        .await
                }
                "/openshell.v1.OpenShell/GetSandbox" => {
                    Grpc::new(tonic_prost::ProstCodec::default())
                        .unary(Unary(st, crate::sandboxes::get), req)
                        .await
                }
                "/openshell.v1.OpenShell/DeleteSandbox" => {
                    Grpc::new(tonic_prost::ProstCodec::default())
                        .unary(Unary(st, crate::sandboxes::delete), req)
                        .await
                }
                "/openshell.v1.OpenShell/StopSandbox" => {
                    Grpc::new(tonic_prost::ProstCodec::default())
                        .unary(Unary(st, crate::sandboxes::stop), req)
                        .await
                }
                "/openshell.v1.OpenShell/StartSandbox" => {
                    Grpc::new(tonic_prost::ProstCodec::default())
                        .unary(Unary(st, crate::sandboxes::start), req)
                        .await
                }
                "/openshell.v1.OpenShell/UpdateConfig" => {
                    Grpc::new(tonic_prost::ProstCodec::default())
                        .unary(Unary(st, crate::sandboxes::update_config), req)
                        .await
                }
                "/openshell.v1.OpenShell/GetSandboxPolicyStatus" => {
                    Grpc::new(tonic_prost::ProstCodec::default())
                        .unary(Unary(st, crate::sandboxes::policy_status), req)
                        .await
                }
                "/openshell.v1.OpenShell/DetachSandboxProvider" => {
                    Grpc::new(tonic_prost::ProstCodec::default())
                        .unary(Unary(st, crate::sandboxes::detach), req)
                        .await
                }
                "/openshell.v1.OpenShell/GetProvider" => {
                    Grpc::new(tonic_prost::ProstCodec::default())
                        .unary(Unary(st, get_provider), req)
                        .await
                }
                "/openshell.v1.OpenShell/GetProviderProfile" => {
                    Grpc::new(tonic_prost::ProstCodec::default())
                        .unary(Unary(st, get_profile), req)
                        .await
                }
                "/openshell.v1.OpenShell/ListProviderProfiles" => {
                    Grpc::new(tonic_prost::ProstCodec::default())
                        .unary(Unary(st, list_profiles), req)
                        .await
                }
                other => {
                    st.lock().unwrap().calls.push(format!("UNEXPECTED {other}"));
                    Status::unimplemented(other.to_string()).into_http()
                }
            };
            Ok(crate::faults::after(&faulted, &rpc, reply).await)
        })
    }
}

/// A gateway on 127.0.0.1 over plaintext HTTP/2 that accepts `token`.
pub async fn start(token: &str) -> (SocketAddr, Shared) {
    let state: Shared = Arc::new(Mutex::new(State {
        token: token.into(),
        ..Default::default()
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let svc = Fake(state.clone());
    let svc_state = state.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let svc = hyper_util::service::TowerToHyperService::new(svc.clone());
            let cut = state_cut(&svc_state);
            tokio::spawn(crate::faults::serve_h2(stream, svc, cut));
        }
    });
    (addr, state)
}

fn state_cut(st: &Shared) -> Arc<tokio::sync::Notify> {
    st.lock().unwrap().faults.cut.clone()
}

/// A gateway on 127.0.0.1 over TLS (HTTP/2 by ALPN) that accepts `token`,
/// with `cert_der` and `key_der`: [`crate::fake_issuer::throwaway_ca`]'s, so
/// one CA bundle trusts the gateway and its sign-in service, as the kit's
/// `ca_pem_path` does.
pub async fn start_tls(token: &str, cert_der: Vec<u8>, key_der: Vec<u8>) -> (SocketAddr, Shared) {
    use tokio_rustls::rustls;
    let state: Shared = Arc::new(Mutex::new(State {
        token: token.into(),
        ..Default::default()
    }));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert_der.into()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key_der.into()),
        )
        .unwrap();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let svc = Fake(state.clone());
    let svc_state = state.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let svc = hyper_util::service::TowerToHyperService::new(svc.clone());
            let (acceptor, cut) = (acceptor.clone(), state_cut(&svc_state));
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(stream).await {
                    crate::faults::serve_h2(tls, svc, cut).await;
                }
            });
        }
    });
    (addr, state)
}
