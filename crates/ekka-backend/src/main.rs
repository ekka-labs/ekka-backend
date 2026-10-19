//! `ekka-backend`: the EKKA desk backend adapter.
//!
//! It runs beside the customer's desk backend, on the customer's machine. The
//! Enclave's API gate calls it over a Unix socket; it verifies the call's
//! Govern-signed gate token, enforces the grant's limits, and only then makes
//! the change on the desk backend. Its protocol is `ekka.backend.v1` (the
//! vendored contract, `vendor/contracts/backend/`).
//!
//! Commands: `--version`, `health`, `digest`, and `serve`, which listens on
//! the contract's socket, verifies every call's Govern-signed token, checks
//! the grant's limits and runs the operation on the gateway, recording each
//! change first and finishing one still `running` at the next call for its
//! desk.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

mod answer;
mod claims;
mod config;
mod constraints;
mod digest;
mod digest_cmd;
mod driver;
mod enforce;
// The fakes live in their own test-only crate, so the binary-level tests
// under tests/ use the same ones (one copy).
#[cfg(test)]
use ekka_backend_fakegw::{fake_gateway, fake_issuer};
mod gateway;
mod health;
mod normalize;
mod ops;
mod providers;
mod recover;
mod routes;
mod server;
mod signin;
mod socket;
mod store;
#[cfg(test)]
mod testkit;
mod token;

/// The backend protocol this adapter speaks: the value of the
/// `x-ekka-backend-contract` header it accepts.
pub const CONTRACT: &str = "ekka.backend.v1";

/// The most files the adapter keeps open: one listener, the connections the
/// Enclave makes, and the state files. A leak stops at this, not at the box's.
const MAX_OPEN_FILES: u64 = 1024;

/// What a command line asks for.
#[derive(Debug, PartialEq, Eq)]
enum Command {
    /// Printed to stdout, exit 0.
    Out(String),
    /// Printed to stderr, exit 64 (a usage error).
    Usage(String),
    /// Serve, with the config at this path.
    Serve(PathBuf),
    /// Is the adapter answering on the socket the config at this path names?
    Health(PathBuf),
    /// Print a digest of this file (`-`: stdin).
    Digest(digest_cmd::Kind, String),
    /// Print one provider's configuration digest, read from the gateway the
    /// config at this path names; the client secret comes on stdin.
    DigestFromGateway { name: String, config: PathBuf },
}

fn version_line() -> String {
    format!(
        "ekka-backend {} (contract {CONTRACT})",
        env!("CARGO_PKG_VERSION")
    )
}

const USAGE: &str = "usage: ekka-backend --version | serve [--config <path>] | health [--config <path>] | digest policy|provider <file|-> | digest provider --from-gateway <name> [--config <path>] (client secret on stdin)";

fn command(args: &[String]) -> Command {
    match args {
        [flag] if flag == "--version" || flag == "-V" => Command::Out(version_line()),
        [flag] if flag == "--help" || flag == "-h" => Command::Out(format!(
            "{}\n\nThe EKKA desk backend adapter.\n\n{USAGE}\n  serve reads {} unless --config names another file.",
            version_line(),
            config::DEFAULT_PATH
        )),
        [serve] if serve == "serve" => Command::Serve(PathBuf::from(config::DEFAULT_PATH)),
        [h] if h == "health" => Command::Health(PathBuf::from(config::DEFAULT_PATH)),
        [h, flag, path] if h == "health" && flag == "--config" && !path.is_empty() => {
            Command::Health(PathBuf::from(path))
        }
        [serve, flag, path] if serve == "serve" && flag == "--config" && !path.is_empty() => {
            Command::Serve(PathBuf::from(path))
        }
        [d, p, flag, name] if d == "digest" && p == "provider" && flag == "--from-gateway" && !name.is_empty() => {
            Command::DigestFromGateway {
                name: name.clone(),
                config: PathBuf::from(config::DEFAULT_PATH),
            }
        }
        [d, p, flag, name, c, path]
            if d == "digest"
                && p == "provider"
                && flag == "--from-gateway"
                && !name.is_empty()
                && c == "--config"
                && !path.is_empty() =>
        {
            Command::DigestFromGateway {
                name: name.clone(),
                config: PathBuf::from(path),
            }
        }
        [d, kind, path] if d == "digest" && !path.is_empty() && !path.starts_with("--") => match kind.as_str() {
            "policy" => Command::Digest(digest_cmd::Kind::Policy, path.clone()),
            "provider" => Command::Digest(digest_cmd::Kind::Provider, path.clone()),
            _ => Command::Usage(USAGE.to_string()),
        },
        _ => Command::Usage(USAGE.to_string()),
    }
}

/// Cap the open files at [`MAX_OPEN_FILES`], or lower if the box's limit is.
fn limit_open_files() -> Result<(), String> {
    use rustix::process::{getrlimit, setrlimit, Resource, Rlimit};
    let now = getrlimit(Resource::Nofile);
    let cap = now
        .maximum
        .map_or(MAX_OPEN_FILES, |m| m.min(MAX_OPEN_FILES));
    setrlimit(
        Resource::Nofile,
        Rlimit {
            current: Some(cap),
            maximum: Some(cap),
        },
    )
    .map_err(|e| format!("the open-file limit cannot be set: {e}"))
}

/// The sign-in service and the gateway the config names, over TLS that
/// trusts the public roots and the config's CA.
fn backend(c: &config::Config) -> Result<(signin::Tokens, gateway::Gateway), String> {
    let g = &c.backend_gateway;
    let ca = config::ca_pem(g)?;
    let issuer = signin::Issuer::new(&g.issuer, &g.client_id, ca.as_deref())?;
    let gw = gateway::Gateway::connect(&g.url, ca.as_deref(), &g.workspace)?;
    Ok((signin::Tokens::new(issuer), gw))
}

async fn digest_from_gateway(name: &str, path: &std::path::Path) -> Result<String, String> {
    let uid = rustix::process::geteuid().as_raw();
    let loaded = config::load(path, uid)?;
    let secret = digest_cmd::read_secret(std::io::stdin())?;
    let (tokens, gw) = backend(&loaded.config)?;
    digest_cmd::from_gateway(&tokens, &gw, &secret, name).await
}

async fn run(path: PathBuf) -> Result<(), String> {
    let uid = rustix::process::geteuid().as_raw();
    let loaded = config::load(&path, uid)?;
    tracing::info!("{}", loaded.start_line());
    limit_open_files()?;
    let c = &loaded.config;
    // The issuer is checked before the adapter listens: a document that
    // names another issuer, or a token endpoint off its origin, stops it.
    let (tokens, gateway) = backend(c)?;
    tokens.discover_now().await.map_err(|e| e.to_string())?;
    tracing::info!(issuer = %tokens.issuer().origin_text(), "issuerDiscovered");
    // The Enclave's claim socket is `enclave.sock` beside the adapter's own.
    // The operation records: an unsafe or unreadable store stops the adapter.
    let store = std::sync::Arc::new(store::Store::open(&c.state_dir, uid)?);
    // Held until the process ends: one adapter per state folder.
    let _state_lock = store::lock_state_dir(&c.state_dir)?;
    let driver = std::sync::Arc::new(driver::Backend {
        gateway,
        tokens,
        claims: claims::Claims::beside(&c.socket_path, uid),
        // A change's answer is written here before its claim is released.
        records: driver::Records::Store(store.clone()),
        settle_for: driver::settle_window(Duration::from_secs(c.deadline_seconds)),
    });
    let verifier = std::sync::Arc::new(token::Verifier::new(c, Box::new(chrono::Utc::now))?);
    // Recovery of a change still running, and its settle markers.
    let recovery = std::sync::Arc::new(recover::Recovery::new(
        store,
        verifier.clone(),
        recover::gateway_identity(&c.backend_gateway),
        &c.state_dir,
        uid,
        std::sync::Arc::new(chrono::Utc::now),
    )?);
    // Every release a settled change still owes, before the first call.
    driver.release_pending().await;
    let listener = socket::bind(&c.socket_path, uid)?;
    tracing::info!(socket = %c.socket_path.display(), "listening");
    server::serve(
        listener,
        uid,
        Duration::from_secs(c.deadline_seconds),
        verifier,
        ops::handler(driver, recovery),
    )
    .await
    .map_err(|e| format!("the socket stopped accepting: {e}"))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match command(&args) {
        Command::Out(s) => {
            println!("{s}");
            ExitCode::SUCCESS
        }
        Command::Usage(s) => {
            eprintln!("{s}");
            ExitCode::from(64)
        }
        Command::Digest(kind, path) => {
            match digest_cmd::read(&path).and_then(|b| digest_cmd::compute(kind, &b)) {
                Ok(d) => {
                    println!("{d}");
                    ExitCode::SUCCESS
                }
                Err(why) => {
                    eprintln!("{why}");
                    ExitCode::from(2)
                }
            }
        }
        Command::Health(path) => {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("HEALTH_DOWN: the runtime cannot start: {e}");
                    return ExitCode::from(1);
                }
            };
            let uid = rustix::process::geteuid().as_raw();
            let checked = config::load(&path, uid)
                .map_err(|e| format!("HEALTH_DOWN: {e}"))
                .and_then(|l| rt.block_on(health::check(&l.config.socket_path)));
            match checked {
                Ok(()) => ExitCode::SUCCESS,
                Err(why) => {
                    eprintln!("{why}");
                    ExitCode::from(1)
                }
            }
        }
        Command::DigestFromGateway { name, config } => {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("RUNTIME_UNAVAILABLE: {e}");
                    return ExitCode::from(70);
                }
            };
            match rt.block_on(digest_from_gateway(&name, &config)) {
                Ok(d) => {
                    println!("{d}");
                    ExitCode::SUCCESS
                }
                Err(why) => {
                    eprintln!("{why}");
                    ExitCode::from(2)
                }
            }
        }
        Command::Serve(path) => {
            tracing_subscriber::fmt()
                .json()
                .with_writer(std::io::stderr)
                .init();
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("ekka-backend: the runtime cannot start: {e}");
                    return ExitCode::from(70);
                }
            };
            match rt.block_on(run(path)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(why) => {
                    tracing::error!("{why}");
                    eprintln!("ekka-backend: {why}");
                    ExitCode::from(78)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{command, Command, CONTRACT};

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn version_names_the_build_and_the_contract() {
        let want = format!(
            "ekka-backend {} (contract ekka.backend.v1)",
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(command(&args(&["--version"])), Command::Out(want.clone()));
        assert_eq!(command(&args(&["-V"])), Command::Out(want));
        assert_eq!(CONTRACT, "ekka.backend.v1");
    }

    #[test]
    fn serve_reads_the_kits_file_unless_one_is_named() {
        assert_eq!(
            command(&args(&["serve"])),
            Command::Serve(PathBuf::from("/etc/ekka-backend/config.json"))
        );
        assert_eq!(
            command(&args(&["serve", "--config", "/tmp/c.json"])),
            Command::Serve(PathBuf::from("/tmp/c.json"))
        );
    }

    /// `--from-gateway` reads the kit's config unless one is named; the
    /// client secret is never an argument.
    #[test]
    fn digest_from_gateway_names_the_provider_and_maybe_the_config() {
        assert_eq!(
            command(&args(&["digest", "provider", "--from-gateway", "github"])),
            Command::DigestFromGateway {
                name: "github".into(),
                config: PathBuf::from("/etc/ekka-backend/config.json")
            }
        );
        assert_eq!(
            command(&args(&[
                "digest",
                "provider",
                "--from-gateway",
                "github",
                "--config",
                "/tmp/c.json"
            ])),
            Command::DigestFromGateway {
                name: "github".into(),
                config: PathBuf::from("/tmp/c.json")
            }
        );
    }

    #[test]
    fn health_reads_the_kits_file_unless_one_is_named() {
        assert_eq!(
            command(&args(&["health"])),
            Command::Health(PathBuf::from("/etc/ekka-backend/config.json"))
        );
        assert_eq!(
            command(&args(&["health", "--config", "/tmp/c.json"])),
            Command::Health(PathBuf::from("/tmp/c.json"))
        );
        assert!(matches!(
            command(&args(&["health", "--config"])),
            Command::Usage(_)
        ));
    }

    #[test]
    fn anything_else_is_a_usage_error_never_a_silent_start() {
        for a in [
            vec![],
            vec!["--version", "x"],
            vec!["--Version"],
            vec!["serve", "--config"],
            vec!["serve", "--config", ""],
            vec!["serve", "--socket", "/tmp/x"],
            vec!["digest", "image", "-"],
            vec!["digest", "policy"],
            vec!["digest", "provider", "--from-gateway"],
            vec!["digest", "provider", "--from-gateway", ""],
            vec!["digest", "policy", "--from-gateway", "github"],
            vec![
                "digest",
                "provider",
                "--from-gateway",
                "github",
                "--secret",
                "x",
            ],
            vec!["digest", "provider", "--from-gateway", "github", "--config"],
        ] {
            assert!(matches!(command(&args(&a)), Command::Usage(_)), "{a:?}");
        }
    }
}
