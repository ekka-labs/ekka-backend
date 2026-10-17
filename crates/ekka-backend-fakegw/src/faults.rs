//! Faults a test can plant on the fake gateway, per RPC by its gRPC method
//! name (`StopSandbox`, `UpdateConfig`, ...), for the recovery paths. They
//! sit around the handlers in `sandboxes.rs` and
//! never change what a handler does:
//!
//! - [`Faults::delay`]: the handler runs (its effect is kept), then the reply
//!   waits this long. A read made meanwhile already sees the effect.
//! - [`Faults::drop_reply`]: the handler runs (its effect is kept), then the
//!   connection is closed with no reply at all, as when the gateway's process
//!   dies after its write. Unlike `State::lose_reply`, which answers
//!   UNAVAILABLE, the client gets no gRPC status from the gateway.
//! - [`Faults::answer`]: answered before any effect, in the exact shape NVIDIA
//!   OpenShell sends at e1f3c82: NOT_FOUND, or ABORTED with the
//!   `RESOURCE_VERSION_CONFLICT` reason and its metadata.
//!
//! Request-id replay (a recorded success, `REQUEST_OUTCOME_UNCERTAIN`) is
//! not here: it belongs with the replay rules in the fake itself.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use tonic::Status;

use crate::fake_gateway::Shared;

/// The domain OpenShell names its reasons under
/// (`crates/openshell-core/src/rpc_error.rs:17` at e1f3c82).
pub const ERROR_DOMAIN: &str = "openshell.nvidia.com";

/// An answer planted before any effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Planted {
    /// `NOT_FOUND`, as OpenShell answers a sandbox it does not have
    /// (`Status::not_found("sandbox not found")`, for example
    /// `crates/openshell-server/src/grpc/provider_readiness.rs:269`).
    NotFound,
    /// `ABORTED` with `RESOURCE_VERSION_CONFLICT`: a compare-and-set lost
    /// (`rpc_error.rs:77-87`). `current` is the version the gateway reports
    /// in the metadata, or none, as OpenShell sends both.
    VersionConflict { current: Option<u64> },
    /// Any other refusal: `code`, with an ErrorInfo `reason` when given (as
    /// OpenShell names one), else a bare status.
    Refused {
        code: tonic::Code,
        reason: Option<String>,
    },
}

/// The faults planted on one fake gateway.
#[derive(Default)]
pub struct Faults {
    /// RPC name to how long its reply waits after the effect.
    pub delay: BTreeMap<String, Duration>,
    /// RPCs whose effect is kept and whose connection is then closed with no
    /// reply.
    pub drop_reply: BTreeSet<String>,
    /// RPC name to the answer it gets before any effect.
    pub answer: BTreeMap<String, Planted>,
    /// Wakes every open connection to close it (`drop_reply`).
    pub(crate) cut: Arc<tokio::sync::Notify>,
}

/// One `google.rpc` message each, encoded by hand as `rpc_error.rs` builds
/// them through `tonic_types::ErrorDetails` (`rpc_error.rs:68-87`):
/// `google.rpc.Status { code, message, details: [Any(ErrorInfo)] }`.
mod wire {
    use std::collections::HashMap;

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct RpcStatus {
        #[prost(int32, tag = "1")]
        pub code: i32,
        #[prost(string, tag = "2")]
        pub message: String,
        #[prost(message, repeated, tag = "3")]
        pub details: Vec<Any>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Any {
        #[prost(string, tag = "1")]
        pub type_url: String,
        #[prost(bytes = "vec", tag = "2")]
        pub value: Vec<u8>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct ErrorInfo {
        #[prost(string, tag = "1")]
        pub reason: String,
        #[prost(string, tag = "2")]
        pub domain: String,
        #[prost(map = "string, string", tag = "3")]
        pub metadata: HashMap<String, String>,
    }
}

/// A status with one `ErrorInfo` detail: `reason`, [`ERROR_DOMAIN`] and
/// `metadata`, its envelope's code and message equal to the status's own, as
/// `openshell_core::rpc_error::decode_details` requires (`rpc_error.rs:23`).
#[must_use]
pub fn error_info_status(
    code: tonic::Code,
    reason: &str,
    message: &str,
    metadata: HashMap<String, String>,
) -> Status {
    let info = prost::Message::encode_to_vec(&wire::ErrorInfo {
        reason: reason.into(),
        domain: ERROR_DOMAIN.into(),
        metadata,
    });
    let envelope = wire::RpcStatus {
        code: code as i32,
        message: message.into(),
        details: vec![wire::Any {
            type_url: "type.googleapis.com/google.rpc.ErrorInfo".into(),
            value: info,
        }],
    };
    Status::with_details(
        code,
        message,
        prost::Message::encode_to_vec(&envelope).into(),
    )
}

/// OpenShell's `resource_version_conflict` (`rpc_error.rs:77-87`), with the
/// message its persistence layer writes (`grpc/mod.rs:92-98`).
#[must_use]
pub fn version_conflict(operation: &str, current: Option<u64>) -> Status {
    let mut metadata = HashMap::from([("recovery".to_string(), "REFRESH_STATE".to_string())]);
    if let Some(v) = current {
        metadata.insert("current_resource_version".into(), v.to_string());
    }
    let message = format!(
        "{operation} failed due to concurrent modification (current resource_version: {})",
        current.map_or_else(|| "unknown".to_string(), |v| v.to_string())
    );
    error_info_status(
        tonic::Code::Aborted,
        "RESOURCE_VERSION_CONFLICT",
        &message,
        metadata,
    )
}

/// The status a planted answer sends for `rpc`.
#[must_use]
pub fn planted_status(rpc: &str, p: &Planted) -> Status {
    match p {
        Planted::NotFound => Status::not_found("sandbox not found"),
        Planted::VersionConflict { current } => version_conflict(rpc, *current),
        Planted::Refused {
            code,
            reason: Some(r),
        } => error_info_status(*code, r, r, HashMap::new()),
        Planted::Refused { code, reason: None } => Status::new(*code, "refused"),
    }
}

/// The RPC name of a gRPC path: `/openshell.v1.OpenShell/StopSandbox` is
/// `StopSandbox`.
#[must_use]
pub fn rpc_of(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or_default()
}

/// Before the handler: a planted answer for `rpc`, recorded in the call log
/// as `"<rpc> (planted <answer>)"`; the handler never runs.
#[must_use]
pub fn before(st: &Shared, rpc: &str) -> Option<Status> {
    let mut s = st.lock().unwrap();
    let p = s.faults.answer.get(rpc).cloned()?;
    s.calls.push(format!("{rpc} (planted {p:?})"));
    Some(planted_status(rpc, &p))
}

/// After the handler, its effect kept: wait the planted delay, then, if the
/// reply is to be dropped, close every connection and never answer.
pub async fn after<T>(st: &Shared, rpc: &str, reply: T) -> T {
    let (delay, drop, cut) = {
        let s = st.lock().unwrap();
        (
            s.faults.delay.get(rpc).copied(),
            s.faults.drop_reply.contains(rpc),
            s.faults.cut.clone(),
        )
    };
    if let Some(d) = delay {
        tokio::time::sleep(d).await;
    }
    if drop {
        cut.notify_waiters();
        // The connection is closed under this future, which is dropped with
        // it: no reply is ever written.
        std::future::pending::<()>().await;
    }
    reply
}

/// Serve one accepted connection over HTTP/2 until it ends, or until a
/// `drop_reply` fault closes it.
pub async fn serve_h2<I, S>(io: I, svc: S, cut: Arc<tokio::sync::Notify>)
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    S: hyper::service::HttpService<hyper::body::Incoming> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::ResBody: Send + 'static,
    <S::ResBody as hyper::body::Body>::Data: Send,
    <S::ResBody as hyper::body::Body>::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let conn = hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
        .serve_connection(hyper_util::rt::TokioIo::new(io), svc);
    let cut = cut.notified();
    tokio::select! {
        _ = conn => {}
        () = cut => {}
    }
}

#[cfg(test)]
#[path = "faults_tests.rs"]
mod tests;
