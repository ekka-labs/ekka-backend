//! The gateway client and what is read through it: one provider and the
//! profile the gateway applies, over a fake gateway that checks the token,
//! with the token minted by a fake issuer from the client secret.

use std::time::Duration;

use openshell_proto::openshell::datamodel::v1::Provider;
use openshell_proto::openshell::v1::ProviderProfile;
use serde_json::{json, Value};

use crate::digest_cmd::from_gateway;
use crate::fake_gateway::{self, Shared};
use crate::fake_issuer;
use crate::normalize::{message, PROVIDER_PROFILE};
use crate::providers::{config_digest_of, Input, PROVIDER};
use crate::signin::{Issuer, Tokens};

const SECRET: &str = "s3cr3t+PLANTED/value";
const GW_TOKEN: &str = "gw-token-1";
/// `json_digest` of the fixture's one entry, as `ekka-backend digest
/// provider` prints it for the same records (measured 2026-10-16).
const FIXTURE_CONFIG_DIGEST: &str =
    "sha256:b2a3df945ba9e782b8175bb0f7a140b00db8b957d528200882a66fa2ac054866";

fn fixture() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/provider-github.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn records() -> (Provider, ProviderProfile) {
    let f = fixture();
    (
        message(PROVIDER, &f["provider"]).unwrap(),
        message(PROVIDER_PROFILE, &f["profile"]).unwrap(),
    )
}

/// A client of the fake gateway at `addr`, in `workspace`. It stays in this
/// crate because it builds the adapter's own `Gateway`; the fake itself lives
/// in `ekka-backend-fakegw`.
fn client(addr: std::net::SocketAddr, workspace: &str) -> crate::gateway::Gateway {
    let ch = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect_lazy();
    crate::gateway::Gateway::over_test_channel(ch, workspace)
}

async fn setup() -> (Tokens, crate::gateway::Gateway, Shared, fake_issuer::Shared) {
    let idp = fake_issuer::start(&fake_issuer::basic("ekka-desk-admin", SECRET)).await;
    let issuer = idp.lock().unwrap().issuer.clone();
    let tokens =
        Tokens::new(Issuer::plaintext_for_tests(&issuer, "ekka-desk-admin")).with_backoff(vec![]);
    let (addr, gw) = fake_gateway::start(GW_TOKEN).await;
    (tokens, client(addr, "desks"), gw, idp)
}

/// Read from the gateway, the digest is the one the file form prints for the
/// same records, so the installer and the enforcer share one source.
#[tokio::test]
async fn a_provider_read_from_the_gateway_has_the_digest_the_file_form_prints() {
    let (tokens, client, gw, idp) = setup().await;
    let (p, profile) = records();
    {
        let mut s = gw.lock().unwrap();
        s.providers.insert("github".into(), p);
        s.profiles
            .insert(("desks".into(), "github".into()), profile);
    }
    let got = from_gateway(&tokens, &client, SECRET, "github")
        .await
        .unwrap();
    let input: Input = serde_json::from_value(fixture()).unwrap();
    assert_eq!(got, config_digest_of(&input).unwrap());
    assert_eq!(got, FIXTURE_CONFIG_DIGEST);
    let s = gw.lock().unwrap();
    assert_eq!(
        s.calls,
        [
            "GetProvider desks/github",
            "GetProviderProfile desks/github"
        ]
    );
    // The gateway saw the minted token, never the client secret.
    assert!(
        s.seen_tokens.iter().all(|t| t == "Bearer gw-token-1"),
        "{:?}",
        s.seen_tokens
    );
    assert_eq!(idp.lock().unwrap().mints(), 1);
}

fn platform(id: &str, scope: &str, binary: &str) -> ProviderProfile {
    message(
        PROVIDER_PROFILE,
        &json!({ "id": id, "scope": scope, "binaries": [{ "path": binary }] }),
    )
    .unwrap()
}

/// A provider with no profile workspace gets the profile the desk workspace
/// lists, static before platform, as the runner and the gateway choose.
#[tokio::test]
async fn a_platform_profile_is_chosen_as_the_gateway_chooses_it() {
    let (tokens, client, gw, _idp) = setup().await;
    let (mut p, _) = records();
    p.profile_workspace = String::new();
    {
        let mut s = gw.lock().unwrap();
        s.providers.insert("github".into(), p.clone());
        s.profiles.insert(
            ("".into(), "a".into()),
            platform("github", "platform", "/usr/bin/gh"),
        );
        s.profiles.insert(
            ("".into(), "b".into()),
            platform("GitHub ", "static", "/usr/bin/git"),
        );
    }
    let got = from_gateway(&tokens, &client, SECRET, "github")
        .await
        .unwrap();
    let want = crate::providers::config_digest(
        "github",
        &p,
        &platform("GitHub ", "static", "/usr/bin/git"),
    )
    .unwrap();
    assert_eq!(got, want);
    assert_eq!(
        gw.lock().unwrap().calls,
        ["GetProvider desks/github", "ListProviderProfiles desks"]
    );

    gw.lock().unwrap().profiles.insert(
        ("".into(), "c".into()),
        platform("github", "static", "/bin/other"),
    );
    let e = from_gateway(&tokens, &client, SECRET, "github")
        .await
        .unwrap_err();
    assert!(e.starts_with("PROVIDER_PROFILE_AMBIGUOUS"), "{e}");

    gw.lock().unwrap().profiles.clear();
    let e = from_gateway(&tokens, &client, SECRET, "github")
        .await
        .unwrap_err();
    assert!(e.starts_with("PROVIDER_PROFILE_NOT_FOUND"), "{e}");
}

#[tokio::test]
async fn each_missing_or_refused_read_is_refused_by_name() {
    let (tokens, client, gw, _idp) = setup().await;
    let e = from_gateway(&tokens, &client, SECRET, "github")
        .await
        .unwrap_err();
    assert!(e.starts_with("PROVIDER_NOT_FOUND"), "{e}");
    assert!(
        e.ends_with("connect 'github' on the desk backend, then try again"),
        "{e}"
    );

    let (p, _) = records();
    gw.lock().unwrap().providers.insert("github".into(), p);
    let e = from_gateway(&tokens, &client, SECRET, "github")
        .await
        .unwrap_err();
    assert!(e.starts_with("PROVIDER_PROFILE_NOT_FOUND"), "{e}");

    gw.lock().unwrap().refuse_reads = Some(tonic::Code::PermissionDenied);
    let e = from_gateway(&tokens, &client, SECRET, "github")
        .await
        .unwrap_err();
    assert!(
        e.starts_with("PROVIDER_UNREADABLE") && e.contains("PERMISSION_DENIED"),
        "{e}"
    );

    let e = from_gateway(&tokens, &client, SECRET, "../github")
        .await
        .unwrap_err();
    assert!(e.starts_with("PROVIDER_INPUT_INVALID"), "{e}");
}

/// A credential VALUE from the gateway (one that stopped redacting) is
/// refused by key, never hashed and never shown.
#[tokio::test]
async fn a_credential_value_from_the_gateway_is_refused_never_shown() {
    let (tokens, client, gw, _idp) = setup().await;
    let (mut p, profile) = records();
    p.credentials
        .insert("GITHUB_TOKEN".into(), "ghp_PLANTEDVALUE".into());
    {
        let mut s = gw.lock().unwrap();
        s.providers.insert("github".into(), p);
        s.profiles
            .insert(("desks".into(), "github".into()), profile);
    }
    let e = from_gateway(&tokens, &client, SECRET, "github")
        .await
        .unwrap_err();
    assert!(
        e.starts_with("PROVIDER_CREDENTIAL_NOT_REDACTED") && e.contains("GITHUB_TOKEN"),
        "{e}"
    );
    assert!(!e.contains("ghp_PLANTEDVALUE"), "{e}");
}

/// The gateway refusing the token drops it: the next read mints anew.
#[tokio::test]
async fn a_token_the_gateway_refuses_is_dropped() {
    let (tokens, client, gw, idp) = setup().await;
    gw.lock().unwrap().token = "another".into();
    let e = from_gateway(&tokens, &client, SECRET, "github")
        .await
        .unwrap_err();
    assert!(e.contains("UNAUTHENTICATED"), "{e}");
    assert!(!e.contains(SECRET) && !e.contains(GW_TOKEN), "{e}");
    let _ = from_gateway(&tokens, &client, SECRET, "github").await;
    assert_eq!(idp.lock().unwrap().mints(), 2);
}

#[test]
fn the_gateway_is_reached_over_https_only() {
    let e = crate::gateway::tls_channel("http://gateway:8080", None).unwrap_err();
    assert!(e.contains("https"), "{e}");
    let _ = Duration::from_secs(0);
}

/// Every gateway call has a time limit: a gateway
/// that takes the call and never answers fails it at the limit, as
/// unavailable, never a hang. Over TLS, as production connects.
#[tokio::test]
async fn a_gateway_call_that_never_answers_fails_at_its_time_limit() {
    let (ca, cert, key) = fake_issuer::throwaway_ca();
    let (addr, gw) = fake_gateway::start_tls(GW_TOKEN, cert, key).await;
    gw.lock()
        .unwrap()
        .faults
        .delay
        .insert("GetSandbox".into(), Duration::from_secs(30));
    let g = crate::gateway::Gateway::connect_within(
        &format!("https://{addr}"),
        Some(ca.as_bytes()),
        "desks",
        Duration::from_secs(5),
        Duration::from_millis(300),
    )
    .unwrap();
    let started = std::time::Instant::now();
    let got = g.sandbox(GW_TOKEN, "code-desk").await;
    assert_eq!(got.err(), Some(crate::gateway::GatewayError::Unavailable));
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
}
