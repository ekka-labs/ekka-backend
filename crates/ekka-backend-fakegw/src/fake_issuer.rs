//! A fake sign-in service for tests: a discovery document and a
//! client-credentials token endpoint, over plain HTTP or over TLS with a
//! certificate from a throwaway CA. It records every request and lets a test
//! plant a wrong document, a refusal, a redirect or an oversized answer.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use http_body_util::{BodyExt as _, Full};
use hyper::body::{Bytes, Incoming};
use serde_json::{json, Value};

/// One request as the issuer received it.
#[derive(Debug, Clone)]
pub struct Seen {
    pub method: String,
    pub path: String,
    pub authorization: Option<String>,
    pub body: String,
}

pub struct State {
    /// `<scheme>://127.0.0.1:<port>/realms/ekka-desks`, set once bound.
    pub issuer: String,
    /// The discovery document; `None` answers the right one.
    pub document: Option<Value>,
    pub discovery_status: u16,
    /// The discovery answer is a redirect to this location.
    pub redirect: Option<String>,
    /// The discovery answer is larger than any cap.
    pub huge: bool,
    /// The client credentials the token endpoint accepts, as the Basic
    /// header it expects.
    pub expect_basic: String,
    pub token_status: u16,
    pub token_answer: Value,
    pub seen: Vec<Seen>,
    /// Every answer waits this long first: an issuer that does not answer.
    pub stall: Option<std::time::Duration>,
}

pub type Shared = Arc<Mutex<State>>;

pub const REALM: &str = "/realms/ekka-desks";
pub const TOKEN_PATH: &str = "/realms/ekka-desks/protocol/openid-connect/token";

impl State {
    /// How many token requests arrived.
    pub fn mints(&self) -> usize {
        self.seen.iter().filter(|s| s.path == TOKEN_PATH).count()
    }
}

fn answer(status: u16, body: Vec<u8>) -> http::Response<Full<Bytes>> {
    http::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

async fn handle(
    st: Shared,
    req: http::Request<Incoming>,
) -> Result<http::Response<Full<Bytes>>, Infallible> {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let authorization = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = req
        .into_body()
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();
    let body = String::from_utf8_lossy(&body).to_string();
    let stall = st.lock().unwrap().stall;
    if let Some(d) = stall {
        tokio::time::sleep(d).await;
    }
    let mut s = st.lock().unwrap();
    s.seen.push(Seen {
        method: method.clone(),
        path: path.clone(),
        authorization: authorization.clone(),
        body: body.clone(),
    });
    if path == format!("{REALM}/.well-known/openid-configuration") {
        if let Some(to) = &s.redirect {
            return Ok(http::Response::builder()
                .status(302)
                .header("location", to)
                .body(Full::new(Bytes::new()))
                .unwrap());
        }
        if s.huge {
            return Ok(answer(200, vec![b' '; 70 * 1024]));
        }
        let doc = s.document.clone().unwrap_or_else(|| {
            let origin = s.issuer.trim_end_matches(REALM);
            json!({ "issuer": s.issuer, "token_endpoint": format!("{origin}{TOKEN_PATH}") })
        });
        return Ok(answer(s.discovery_status, doc.to_string().into_bytes()));
    }
    if path == TOKEN_PATH && method == "POST" {
        if authorization.as_deref() != Some(s.expect_basic.as_str())
            || body != "grant_type=client_credentials"
        {
            return Ok(answer(401, br#"{"error":"invalid_client"}"#.to_vec()));
        }
        return Ok(answer(
            s.token_status,
            s.token_answer.to_string().into_bytes(),
        ));
    }
    Ok(answer(404, b"{}".to_vec()))
}

fn state(expect_basic: &str) -> Shared {
    Arc::new(Mutex::new(State {
        issuer: String::new(),
        document: None,
        discovery_status: 200,
        redirect: None,
        huge: false,
        expect_basic: expect_basic.to_string(),
        token_status: 200,
        token_answer: json!({ "access_token": "gw-token-1", "token_type": "Bearer", "expires_in": 300 }),
        seen: Vec::new(),
        stall: None,
    }))
}

/// The Basic header for `client_id` and `secret`, form-encoded first.
pub fn basic(client_id: &str, secret: &str) -> String {
    use base64::Engine as _;
    let enc = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!(
            "{}:{}",
            enc(client_id),
            enc(secret)
        ))
    )
}

/// An issuer over plain HTTP accepting `expect_basic`.
pub async fn start(expect_basic: &str) -> Shared {
    let st = state(expect_basic);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    st.lock().unwrap().issuer = format!("http://{addr}{REALM}");
    let shared = st.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let st = shared.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |r| handle(st.clone(), r));
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    st
}

/// A CA and a server certificate for 127.0.0.1 signed by it: `(ca_pem,
/// cert_der, key_der)`.
pub fn throwaway_ca() -> (String, Vec<u8>, Vec<u8>) {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
    let ca_key = KeyPair::generate().unwrap();
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca.self_signed(&ca_key).unwrap();
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["127.0.0.1".to_string()])
        .unwrap()
        .signed_by(&key, &ca_cert, &ca_key)
        .unwrap();
    (ca_cert.pem(), cert.der().to_vec(), key.serialize_der())
}

/// An issuer over TLS with `cert_der` and `key_der`, accepting `expect_basic`.
pub async fn start_tls(expect_basic: &str, cert_der: Vec<u8>, key_der: Vec<u8>) -> Shared {
    use tokio_rustls::rustls;
    let st = state(expect_basic);
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert_der.into()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key_der.into()),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    st.lock().unwrap().issuer = format!("https://{addr}{REALM}");
    let shared = st.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let (st, acceptor) = (shared.clone(), acceptor.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let svc = hyper::service::service_fn(move |r| handle(st.clone(), r));
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    st
}
