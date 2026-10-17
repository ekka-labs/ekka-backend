//! The sign-in rules, each against a fake issuer: the document must name this
//! issuer and an endpoint on its origin; no redirect, no oversized answer; a
//! refused client is not retried; one token per secret, reused until near
//! its stated end; and neither the secret nor a token is ever in an error.

use serde_json::json;

use super::{Issuer, SignInError, Tokens};
use crate::fake_issuer::{self, basic, TOKEN_PATH};

/// `+` and `/` are what a client secret must be form-encoded for (RFC 6749
/// 2.3.1): a lax server accepts them raw, a strict one refuses them.
const SECRET: &str = "s3cr3t+PLANTED/value";
const CLIENT: &str = "ekka-desk-admin";

async fn issuer() -> (fake_issuer::Shared, Tokens) {
    let idp = fake_issuer::start(&basic(CLIENT, SECRET)).await;
    let url = idp.lock().unwrap().issuer.clone();
    let tokens = Tokens::new(Issuer::plaintext_for_tests(&url, CLIENT)).with_backoff(vec![]);
    (idp, tokens)
}

fn no_secret(e: &SignInError) {
    let t = e.to_string();
    assert!(!t.contains(SECRET) && !t.contains("gw-token"), "{t}");
}

#[tokio::test]
async fn a_token_is_minted_with_the_client_form_encoded_in_basic() {
    let (idp, tokens) = issuer().await;
    assert_eq!(tokens.bearer(SECRET).await.unwrap().as_str(), "gw-token-1");
    let s = idp.lock().unwrap();
    let mint = s.seen.iter().find(|x| x.path == TOKEN_PATH).unwrap();
    assert_eq!(mint.method, "POST");
    assert_eq!(mint.body, "grant_type=client_credentials");
    assert_eq!(
        mint.authorization.as_deref(),
        Some(basic(CLIENT, SECRET).as_str())
    );
    assert!(basic(CLIENT, SECRET) != basic(CLIENT, "s3cr3t PLANTED/value"));
}

/// Each planted document is refused ISSUER_MISMATCH, and no token is asked
/// for: the secret goes nowhere the configured issuer did not name.
#[tokio::test]
async fn a_document_naming_another_issuer_or_endpoint_is_refused() {
    let (idp, tokens) = issuer().await;
    let url = idp.lock().unwrap().issuer.clone();
    let origin = url.trim_end_matches(fake_issuer::REALM).to_string();
    let port: u16 = origin.rsplit(':').next().unwrap().parse().unwrap();
    for (why, doc) in [
        (
            "a trailing slash",
            json!({ "issuer": format!("{url}/"), "token_endpoint": format!("{origin}{TOKEN_PATH}") }),
        ),
        (
            "another realm",
            json!({ "issuer": format!("{origin}/realms/other"), "token_endpoint": format!("{origin}{TOKEN_PATH}") }),
        ),
        (
            "an endpoint on another host",
            json!({ "issuer": url, "token_endpoint": format!("http://evil.example{TOKEN_PATH}") }),
        ),
        (
            "an endpoint on another port",
            json!({ "issuer": url, "token_endpoint": format!("http://127.0.0.1:{}{TOKEN_PATH}", port + 1) }),
        ),
        (
            "an endpoint on another scheme",
            json!({ "issuer": url, "token_endpoint": format!("https://127.0.0.1:{port}{TOKEN_PATH}") }),
        ),
        (
            "an endpoint that is not a URL",
            json!({ "issuer": url, "token_endpoint": "token" }),
        ),
    ] {
        idp.lock().unwrap().document = Some(doc);
        let e = tokens.bearer(SECRET).await.unwrap_err();
        assert!(matches!(e, SignInError::Mismatch(_)), "{why}: {e}");
        no_secret(&e);
    }
    assert_eq!(idp.lock().unwrap().mints(), 0);
}

#[tokio::test]
async fn a_redirect_an_oversized_or_a_failed_document_is_unreachable() {
    let (idp, tokens) = issuer().await;
    idp.lock().unwrap().redirect =
        Some("http://evil.example/.well-known/openid-configuration".into());
    let e = tokens.issuer().discover().await.unwrap_err();
    assert!(e.to_string().contains("HTTP 302"), "{e}");
    assert_eq!(
        idp.lock().unwrap().seen.len(),
        1,
        "the redirect was not followed"
    );

    idp.lock().unwrap().redirect = None;
    idp.lock().unwrap().huge = true;
    let e = tokens.issuer().discover().await.unwrap_err();
    assert!(e.to_string().contains("more than 64 KiB"), "{e}");

    idp.lock().unwrap().huge = false;
    idp.lock().unwrap().discovery_status = 503;
    let e = tokens.issuer().discover().await.unwrap_err();
    assert!(matches!(e, SignInError::Unreachable(_)), "{e}");
}

/// At start, an unreachable issuer is asked three times; a mismatch once.
#[tokio::test]
async fn discovery_at_start_retries_only_an_unreachable_issuer() {
    let (idp, _) = issuer().await;
    let tokens = Tokens::new(Issuer::plaintext_for_tests(
        &idp.lock().unwrap().issuer,
        CLIENT,
    ))
    .with_backoff(vec![std::time::Duration::ZERO; 2]);
    idp.lock().unwrap().discovery_status = 500;
    assert!(matches!(
        tokens.discover_now().await,
        Err(SignInError::Unreachable(_))
    ));
    assert_eq!(idp.lock().unwrap().seen.len(), 3);
    idp.lock().unwrap().discovery_status = 200;
    tokens.discover_now().await.unwrap();
    let _ = tokens;
}

#[tokio::test]
async fn a_refused_client_is_not_retried_and_an_error_is_retried() {
    let (idp, _) = issuer().await;
    let tokens = Tokens::new(Issuer::plaintext_for_tests(
        &idp.lock().unwrap().issuer,
        CLIENT,
    ))
    .with_backoff(vec![std::time::Duration::ZERO; 2]);
    let e = tokens.bearer("wrong-secret").await.unwrap_err();
    assert_eq!(e, SignInError::Rejected);
    assert_eq!(idp.lock().unwrap().mints(), 1);
    no_secret(&e);

    idp.lock().unwrap().token_status = 500;
    let e = tokens.bearer(SECRET).await.unwrap_err();
    assert!(matches!(e, SignInError::Unreachable(_)), "{e}");
    assert_eq!(idp.lock().unwrap().mints(), 4);
}

#[tokio::test]
async fn one_token_is_kept_for_its_own_secret_until_near_its_end() {
    let (idp, tokens) = issuer().await;
    tokens.bearer(SECRET).await.unwrap();
    tokens.bearer(SECRET).await.unwrap();
    assert_eq!(idp.lock().unwrap().mints(), 1, "reused");
    // Another secret never gets the kept token: it mints, and is refused.
    assert_eq!(
        tokens.bearer("rotated").await.unwrap_err(),
        SignInError::Rejected
    );
    assert_eq!(idp.lock().unwrap().mints(), 2);
    // The gateway refused it: dropped.
    tokens.rejected();
    tokens.bearer(SECRET).await.unwrap();
    assert_eq!(idp.lock().unwrap().mints(), 3);
}

#[tokio::test]
async fn a_token_with_no_or_a_short_lifetime_is_used_once() {
    for answer in [
        json!({ "access_token": "gw-token-1", "token_type": "Bearer" }),
        json!({ "access_token": "gw-token-1", "token_type": "Bearer", "expires_in": 60 }),
    ] {
        let (idp, tokens) = issuer().await;
        idp.lock().unwrap().token_answer = answer.clone();
        tokens.bearer(SECRET).await.unwrap();
        tokens.bearer(SECRET).await.unwrap();
        assert_eq!(idp.lock().unwrap().mints(), 2, "{answer}");
    }
}

#[tokio::test]
async fn an_answer_that_is_not_a_bearer_token_is_refused() {
    for answer in [
        json!({ "access_token": "gw-token-1", "token_type": "mac", "expires_in": 300 }),
        json!({ "access_token": "gw token", "expires_in": 300 }),
        json!({ "access_token": "", "expires_in": 300 }),
        json!({ "token_type": "Bearer" }),
    ] {
        let (idp, tokens) = issuer().await;
        idp.lock().unwrap().token_answer = answer.clone();
        let e = tokens.bearer(SECRET).await.unwrap_err();
        assert!(matches!(e, SignInError::Unreachable(_)), "{answer}: {e}");
        no_secret(&e);
    }
}

/// TLS: the issuer proves itself with a certificate from the configured CA.
/// Without that CA, or with another one, nothing is sent.
#[tokio::test]
async fn the_issuer_is_trusted_through_the_configured_ca_only() {
    let (ca, cert, key) = fake_issuer::throwaway_ca();
    let (other_ca, _, _) = fake_issuer::throwaway_ca();
    let idp = fake_issuer::start_tls(&basic(CLIENT, SECRET), cert, key).await;
    let url = idp.lock().unwrap().issuer.clone();
    assert!(url.starts_with("https://"));
    Issuer::new(&url, CLIENT, Some(ca.as_bytes()))
        .unwrap()
        .discover()
        .await
        .unwrap();
    for (why, pem) in [
        ("the public roots only", None),
        ("another CA", Some(other_ca.as_bytes())),
    ] {
        let e = Issuer::new(&url, CLIENT, pem)
            .unwrap()
            .discover()
            .await
            .unwrap_err();
        assert!(matches!(e, SignInError::Unreachable(_)), "{why}: {e}");
    }
    assert!(Issuer::new("http://127.0.0.1/realms/x", CLIENT, None).is_err());
    assert!(Issuer::new(&url, CLIENT, Some(b"not pem")).is_err());
}

/// Every request to the issuer has a time limit:
/// an issuer that takes discovery and never answers fails it at the limit.
#[tokio::test]
async fn an_issuer_that_never_answers_fails_at_the_time_limit() {
    let idp = fake_issuer::start(&basic(CLIENT, SECRET)).await;
    idp.lock().unwrap().stall = Some(std::time::Duration::from_secs(30));
    let url = idp.lock().unwrap().issuer.clone();
    let tokens = Tokens::new(Issuer::plaintext_for_tests_within(
        &url,
        CLIENT,
        std::time::Duration::from_millis(300),
    ))
    .with_backoff(vec![]);
    let started = std::time::Instant::now();
    let e = tokens.discover_now().await.unwrap_err();
    no_secret(&e);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
}
