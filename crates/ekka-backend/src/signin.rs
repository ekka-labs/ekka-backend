//! The adapter's gateway token, minted from the client
//! credential the Enclave's API gate injects into each call, at the sign-in
//! service the installer pinned (`backend_gateway.issuer`), with the OAuth 2.0
//! client-credentials grant (RFC 6749 4.4).
//!
//! The issuer's discovery document (`<issuer>/.well-known/openid-configuration`)
//! names the token endpoint. It is refused unless its `issuer` is EXACTLY the
//! configured one and its token endpoint is on the issuer's own origin, so
//! neither the gateway nor a changed document can send the client secret
//! anywhere else. No redirect is followed, no proxy is used, an answer is
//! capped at 64 KiB, and nothing the issuer says is put in an error.
//!
//! ONE token is kept, in memory only, with a digest of the secret that minted
//! it: it is reused for that secret until 60 s before the lifetime its
//! endpoint stated, and never for another secret (a rotated credential mints
//! anew). A token whose answer stated no lifetime is used once. The gateway
//! refusing a token drops it. Neither the token nor the secret is ever logged
//! or put in an error.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// How long before its stated expiry a token is replaced.
pub const REFRESH_EARLY: Duration = Duration::from_secs(60);
/// The waits between attempts when the issuer cannot be reached: three
/// attempts in all.
pub const RETRY_BACKOFF: [Duration; 2] = [Duration::from_millis(500), Duration::from_millis(1000)];
/// A discovery document or a token answer is a handful of short strings.
const CAP_BYTES: usize = 64 * 1024;
/// How long one request to the issuer may take.
const TIMEOUT: Duration = Duration::from_secs(10);
/// The longest token accepted, and so the longest header it becomes.
const MAX_TOKEN: usize = 16 * 1024;
const TRACE_TARGET: &str = "ekka.backend.signin";

/// Why no token could be had. Its text starts with its code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignInError {
    /// `ISSUER_UNREACHABLE`: the issuer or its token endpoint did not answer
    /// usefully, after the retries.
    Unreachable(String),
    /// `ISSUER_MISMATCH`: the document names another issuer, or a token
    /// endpoint off the issuer's origin.
    Mismatch(String),
    /// `CLIENT_REJECTED`: the token endpoint refused the client (400 or 401).
    /// Never retried: the same secret would be refused again.
    Rejected,
}

impl SignInError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unreachable(_) => "ISSUER_UNREACHABLE",
            Self::Mismatch(_) => "ISSUER_MISMATCH",
            Self::Rejected => "CLIENT_REJECTED",
        }
    }
}

impl std::fmt::Display for SignInError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable(why) | Self::Mismatch(why) => write!(f, "{}: {why}", self.code()),
            Self::Rejected => write!(
                f,
                "{}: the token endpoint refused the client ekka-desk-admin and its credential",
                self.code()
            ),
        }
    }
}

/// `(scheme, lowercase host, port)` of a URL: what "the same origin" means.
fn origin(u: &url::Url) -> (String, Option<String>, Option<u16>) {
    (
        u.scheme().to_string(),
        u.host_str().map(str::to_ascii_lowercase),
        u.port_or_known_default(),
    )
}

#[derive(Deserialize)]
struct Document {
    issuer: String,
    token_endpoint: String,
}

#[derive(Deserialize)]
struct TokenAnswer {
    access_token: String,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
}

struct Minted {
    token: Zeroizing<String>,
    expires_in: Option<Duration>,
}

/// The sign-in service the kit pinned.
pub struct Issuer {
    issuer: String,
    client_id: String,
    http: reqwest::Client,
    /// The discovered token endpoint; read again after a failed mint.
    token_endpoint: Mutex<Option<String>>,
}

impl Issuer {
    /// Over https only, trusting the public roots and `ca_pem`.
    ///
    /// # Errors
    /// An issuer that is not https, or a CA that is not PEM.
    pub fn new(issuer: &str, client_id: &str, ca_pem: Option<&[u8]>) -> Result<Self, String> {
        if !issuer.starts_with("https://") {
            return Err(
                "the issuer must be https: the client secret would otherwise travel in the clear"
                    .into(),
            );
        }
        Self::build(issuer, client_id, ca_pem, true, TIMEOUT)
    }

    /// Plain http allowed: tests only.
    #[cfg(test)]
    #[allow(clippy::expect_used)]
    pub fn plaintext_for_tests(issuer: &str, client_id: &str) -> Self {
        Self::build(issuer, client_id, None, false, TIMEOUT).expect("a test issuer")
    }

    /// Plain http, with a shorter time limit: tests only.
    #[cfg(test)]
    #[allow(clippy::expect_used)]
    pub fn plaintext_for_tests_within(issuer: &str, client_id: &str, limit: Duration) -> Self {
        Self::build(issuer, client_id, None, false, limit).expect("a test issuer")
    }

    fn build(
        issuer: &str,
        client_id: &str,
        ca_pem: Option<&[u8]>,
        https_only: bool,
        limit: Duration,
    ) -> Result<Self, String> {
        // Every request to the issuer (discovery and the token) fails at
        // `limit`: a sign-in never hangs.
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(limit)
            .connect_timeout(limit)
            .https_only(https_only);
        if let Some(pem) = ca_pem {
            let certs = reqwest::Certificate::from_pem_bundle(pem)
                .map_err(|_| "the CA bundle is not PEM".to_string())?;
            // An empty bundle would quietly leave only the public roots.
            if certs.is_empty() {
                return Err("the CA bundle holds no certificate".into());
            }
            for cert in certs {
                builder = builder.add_root_certificate(cert);
            }
        }
        let http = builder
            .build()
            .map_err(|_| "the sign-in client could not be built".to_string())?;
        Ok(Self {
            issuer: issuer.to_string(),
            client_id: client_id.to_string(),
            http,
            token_endpoint: Mutex::new(None),
        })
    }

    /// The issuer's scheme, host and port, for a log line: never its path.
    #[must_use]
    pub fn origin_text(&self) -> String {
        url::Url::parse(&self.issuer).map_or_else(
            |_| "the issuer".into(),
            |u| u.origin().ascii_serialization(),
        )
    }

    /// One GET of `<issuer>/.well-known/openid-configuration`: the token
    /// endpoint, once the document names this issuer exactly and an endpoint
    /// on its origin. Kept for later mints.
    ///
    /// # Errors
    /// [`SignInError::Unreachable`] or [`SignInError::Mismatch`].
    pub async fn discover(&self) -> Result<String, SignInError> {
        let issuer = url::Url::parse(&self.issuer)
            .map_err(|_| SignInError::Mismatch("the configured issuer is not a URL".into()))?;
        let at = format!("{}/.well-known/openid-configuration", self.issuer);
        let unreachable = |why: &str| SignInError::Unreachable(format!("{at} {why}"));
        let response = self
            .http
            .get(&at)
            .send()
            .await
            .map_err(|_| unreachable("did not answer"))?;
        if !response.status().is_success() {
            return Err(unreachable(&format!(
                "answered HTTP {}",
                response.status().as_u16()
            )));
        }
        let body = capped(response).await.map_err(|why| unreachable(&why))?;
        let doc: Document = serde_json::from_slice(&body).map_err(|_| {
            unreachable("is not a discovery document with issuer and token_endpoint")
        })?;
        if doc.issuer != self.issuer {
            return Err(SignInError::Mismatch(format!(
                "{at} names another issuer, not {}",
                self.issuer
            )));
        }
        let endpoint = url::Url::parse(&doc.token_endpoint).map_err(|_| {
            SignInError::Mismatch(format!("{at} names a token endpoint that is not a URL"))
        })?;
        if origin(&endpoint) != origin(&issuer) {
            return Err(SignInError::Mismatch(format!(
                "{at} names a token endpoint off the issuer's origin ({})",
                self.origin_text()
            )));
        }
        *self
            .token_endpoint
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(doc.token_endpoint.clone());
        Ok(doc.token_endpoint)
    }

    async fn endpoint(&self) -> Result<String, SignInError> {
        let kept = self
            .token_endpoint
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        match kept {
            Some(e) => Ok(e),
            None => self.discover().await,
        }
    }

    fn forget_endpoint(&self) {
        *self
            .token_endpoint
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    /// One client-credentials token (RFC 6749 4.4), the client authenticated
    /// with HTTP Basic, its id and secret form-encoded first (2.3.1).
    async fn mint(&self, secret: &str) -> Result<Minted, SignInError> {
        let endpoint = self.endpoint().await?;
        let enc = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
        let basic = Zeroizing::new(format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(
                Zeroizing::new(format!("{}:{}", enc(&self.client_id), enc(secret))).as_bytes()
            )
        ));
        let unreachable = |why: &str| SignInError::Unreachable(format!("the token endpoint {why}"));
        let response = self
            .http
            .post(&endpoint)
            .header("authorization", basic.as_str())
            .header("content-type", "application/x-www-form-urlencoded")
            .body("grant_type=client_credentials")
            .send()
            .await
            .map_err(|_| unreachable("did not answer"))?;
        let status = response.status().as_u16();
        if status == 400 || status == 401 {
            return Err(SignInError::Rejected);
        }
        if !(200..300).contains(&status) {
            return Err(unreachable(&format!("answered HTTP {status}")));
        }
        let body = Zeroizing::new(capped(response).await.map_err(|why| unreachable(&why))?);
        let a: TokenAnswer =
            serde_json::from_slice(&body).map_err(|_| unreachable("answered no access_token"))?;
        let token = Zeroizing::new(a.access_token);
        if token.is_empty()
            || token.len() > MAX_TOKEN
            || !token.bytes().all(|b| b.is_ascii_graphic())
            || a.token_type
                .as_deref()
                .is_some_and(|t| !t.eq_ignore_ascii_case("bearer"))
        {
            return Err(unreachable(
                "answered a token that is not a usable bearer token",
            ));
        }
        Ok(Minted {
            token,
            expires_in: a.expires_in.map(Duration::from_secs),
        })
    }
}

/// The body, refused past [`CAP_BYTES`].
async fn capped(mut response: reqwest::Response) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "broke off its answer".to_string())?
    {
        body.extend_from_slice(&chunk);
        if body.len() > CAP_BYTES {
            return Err(format!("answered more than {} KiB", CAP_BYTES / 1024));
        }
    }
    Ok(body)
}

struct Held {
    secret: [u8; 32],
    token: Zeroizing<String>,
    replace_at: Instant,
}

/// The adapter's gateway tokens: one kept, minted one at a time.
pub struct Tokens {
    issuer: Issuer,
    backoff: Vec<Duration>,
    held: Mutex<Option<Held>>,
    minting: tokio::sync::Mutex<()>,
}

impl Tokens {
    #[must_use]
    pub fn new(issuer: Issuer) -> Self {
        Self {
            issuer,
            backoff: RETRY_BACKOFF.to_vec(),
            held: Mutex::new(None),
            minting: tokio::sync::Mutex::new(()),
        }
    }

    /// The same with other waits between attempts, for tests.
    #[cfg(test)]
    #[must_use]
    pub fn with_backoff(mut self, backoff: Vec<Duration>) -> Self {
        self.backoff = backoff;
        self
    }

    #[must_use]
    pub fn issuer(&self) -> &Issuer {
        &self.issuer
    }

    /// Discover now, retrying an unreachable issuer: run at start, so a wrong
    /// issuer stops the adapter before it listens.
    ///
    /// # Errors
    /// The last failure.
    pub async fn discover_now(&self) -> Result<(), SignInError> {
        let mut last = None;
        for wait in std::iter::once(None).chain(self.backoff.iter().copied().map(Some)) {
            if let Some(w) = wait {
                tokio::time::sleep(w).await;
            }
            match self.issuer.discover().await {
                Ok(_) => return Ok(()),
                Err(e @ SignInError::Unreachable(_)) => last = Some(e),
                Err(e) => return Err(e),
            }
        }
        Err(last.unwrap_or_else(|| SignInError::Unreachable("discovery made no attempt".into())))
    }

    fn current(&self, secret: &[u8; 32]) -> Option<Zeroizing<String>> {
        let held = self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        held.as_ref()
            .filter(|h| &h.secret == secret && Instant::now() < h.replace_at)
            .map(|h| h.token.clone())
    }

    /// A bearer token for the gateway, from `secret` (the client credential
    /// the call carried).
    ///
    /// # Errors
    /// Why none could be had.
    pub async fn bearer(&self, secret: &str) -> Result<Zeroizing<String>, SignInError> {
        let digest: [u8; 32] = Sha256::digest(secret.as_bytes()).into();
        if let Some(t) = self.current(&digest) {
            return Ok(t);
        }
        let _one = self.minting.lock().await;
        if let Some(t) = self.current(&digest) {
            return Ok(t);
        }
        let mut last = None;
        for wait in std::iter::once(None).chain(self.backoff.iter().copied().map(Some)) {
            if let Some(w) = wait {
                tokio::time::sleep(w).await;
            }
            match self.issuer.mint(secret).await {
                Ok(m) => {
                    let life = m.expires_in;
                    tracing::info!(
                        target: TRACE_TARGET,
                        issuer = %self.issuer.origin_text(),
                        lifetime_s = %life.map_or_else(|| "none stated".to_string(), |d| d.as_secs().to_string()),
                        "gatewayTokenMinted"
                    );
                    let token = m.token.clone();
                    *self
                        .held
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) =
                        life.filter(|d| *d > REFRESH_EARLY).map(|d| Held {
                            secret: digest,
                            token: m.token,
                            replace_at: Instant::now() + d - REFRESH_EARLY,
                        });
                    return Ok(token);
                }
                Err(e @ (SignInError::Rejected | SignInError::Mismatch(_))) => {
                    last = Some(e);
                    break;
                }
                Err(e) => last = Some(e),
            }
        }
        // Read the document again next time: the endpoint may have moved.
        self.issuer.forget_endpoint();
        let e = last
            .unwrap_or_else(|| SignInError::Unreachable("the token endpoint was not asked".into()));
        tracing::warn!(
            target: TRACE_TARGET,
            issuer = %self.issuer.origin_text(),
            code = e.code(),
            reason = %e,
            "gatewayTokenRefused"
        );
        Err(e)
    }

    /// The gateway refused the token: drop it, so the next call mints anew.
    pub fn rejected(&self) {
        *self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "signin_tests.rs"]
mod tests;
