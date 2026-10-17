//! The contract server: HTTP/1.1 and JSON over the adapter's
//! Unix socket, one accept loop.
//!
//! - Every connection's peer must be this process's own user (`SO_PEERCRED`);
//!   any other is closed before a byte is read.
//! - A request body over 1 MiB is refused `REQUEST_INVALID`, unread past the cap.
//! - Each request has the configured deadline. A change admitted before it
//!   answers `running` and goes on; anything else is refused
//!   `BACKEND_UNAVAILABLE`.
//! - Routes are exactly the contract's; every answer is its closed shape.
//! - Every call is verified before any handler runs: a
//!   refused call never reaches an operation, so it never reaches the
//!   backend.
//! - Nothing a caller sent is logged: only the method, the operation, the
//!   outcome, and for a verified call its token, run and operation ids.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::UnixListener;

use crate::answer::{Answer, Code};
use crate::routes::{route, Miss, Operation, Route};
use crate::token::{Call, Verified, Verifier};

/// The largest request body read.
pub const MAX_BODY: usize = 1024 * 1024;

/// What runs an operation the adapter understood, for a verified call: the
/// driver in `serve`.
pub type Handler = Arc<
    dyn Fn(Route, Verified, Bytes) -> Pin<Box<dyn Future<Output = Answer> + Send>> + Send + Sync,
>;

/// A placeholder handler: every operation is refused `NOT_AVAILABLE`, so the adapter
/// can be installed and reached before it changes anything.
#[cfg(test)]
#[must_use]
pub fn not_yet() -> Handler {
    Arc::new(|_, _, _| Box::pin(async { Answer::refused(Code::NotAvailable) }))
}

/// Serve `listener` until it fails: connections only from `uid`, each request
/// answered within `deadline`.
///
/// # Errors
/// The listener cannot accept any more connections.
pub async fn serve(
    listener: UnixListener,
    uid: u32,
    deadline: Duration,
    verifier: Arc<Verifier>,
    handler: Handler,
) -> std::io::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        match stream.peer_cred() {
            Ok(c) if c.uid() == uid => {}
            Ok(c) => {
                tracing::warn!(
                    peer_uid = c.uid(),
                    "connection refused: peer is not this process's user"
                );
                continue;
            }
            Err(e) => {
                tracing::warn!(error = %e, "connection refused: peer credentials cannot be read");
                continue;
            }
        }
        let handler = handler.clone();
        let verifier = verifier.clone();
        tokio::spawn(async move {
            let svc =
                service_fn(move |req| respond(req, verifier.clone(), handler.clone(), deadline));
            if let Err(e) = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), svc)
                .await
            {
                tracing::debug!(error = %e, "connection ended");
            }
        });
    }
}

async fn respond(
    req: Request<Incoming>,
    verifier: Arc<Verifier>,
    handler: Handler,
    deadline: Duration,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();
    let answer = match route(&method, &path) {
        Err(Miss::Unknown) => Answer::refused(Code::UnknownOperation),
        Err(Miss::BadName) => Answer::refused(Code::RequestInvalid),
        Ok(r) => {
            let op = r.operation.name();
            let a = answer_route(r, req, &verifier, handler, deadline).await;
            tracing::info!(method = %method, operation = op, outcome = ?a.outcome, code = ?a.code, "answered");
            a
        }
    };
    Ok(reply(&answer))
}

async fn answer_route(
    r: Route,
    req: Request<Incoming>,
    verifier: &Verifier,
    handler: Handler,
    deadline: Duration,
) -> Answer {
    // ONE deadline for the whole call, the body's arrival included: a body that is too large, broken or late is refused, since
    // nothing has been admitted yet.
    let until = tokio::time::Instant::now() + deadline;
    let (parts, body) = req.into_parts();
    let Ok(Ok(collected)) =
        tokio::time::timeout_at(until, Limited::new(body, MAX_BODY).collect()).await
    else {
        return Answer::refused(Code::RequestInvalid);
    };
    if r.operation == Operation::ProviderConnect {
        return Answer::refused(Code::NotAvailable);
    }
    let body = collected.to_bytes();
    let header = |name: &str| parts.headers.get(name).and_then(|v| v.to_str().ok());
    let call = Call {
        operation: r.operation,
        gate_token: header("x-ekka-gate-token"),
        authorization: header("authorization"),
        operation_id: header("x-ekka-operation-id"),
        backend_contract: header("x-ekka-backend-contract"),
        body: &body,
    };
    let verified = match verifier.verify(&call) {
        Ok(v) => v,
        Err(code) => return Answer::refused(code),
    };
    tracing::info!(
        operation = r.operation.name(),
        operation_id = %verified.operation_id,
        run_id = %verified.run_id,
        token_id = %verified.token_id,
        "verified"
    );
    // The handler runs as its own task, so the deadline never cancels an
    // admitted change part way through a backend call.
    let gate = verified.gate();
    let request_id = verified.request_id.clone();
    let mutates = r.operation.mutates();
    let mut work = tokio::spawn(handler(r, verified, body));
    match tokio::time::timeout_at(until, &mut work).await {
        Ok(Ok(a)) => a,
        // The work failed part way: after an admission nothing says what it
        // did; before one, nothing happened.
        Ok(Err(_)) => {
            if gate.close() {
                Answer::unknown()
            } else {
                Answer::refused(Code::BackendUnavailable)
            }
        }
        Err(_) => {
            if gate.close() && mutates {
                // Admitted before the deadline: the change goes on, and its
                // result is the operation's to report.
                Answer::running(&request_id)
            } else {
                // Not admitted (and now never can be), or a read.
                work.abort();
                Answer::refused(Code::BackendUnavailable)
            }
        }
    }
}

fn reply(a: &Answer) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(a).unwrap_or_else(|_| b"{}".to_vec());
    let mut resp = Response::new(Full::new(Bytes::from(body)));
    *resp.status_mut() =
        hyper::StatusCode::from_u16(a.http_status()).unwrap_or(hyper::StatusCode::OK);
    resp.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/json"),
    );
    resp
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "server_tests.rs"]
mod tests;
