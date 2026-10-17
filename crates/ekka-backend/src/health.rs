//! `ekka-backend health [--config <path>]`: is the adapter
//! answering on its own socket? The container's healthcheck runs it; the
//! image is distroless, so there is no shell to do it any other way.
//!
//! It reads the same config `serve` reads, connects to `socket_path` as this
//! user (the only peer the server accepts), and asks for a route no desk call
//! uses. The server answers that from its route table alone, before any token
//! is read and without any gateway call. Any HTTP answer means the adapter is
//! serving: exit 0. Anything else is one line on stderr and exit 1. Nothing
//! it prints carries a secret: the config holds none, and no credential is
//! ever sent.

use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// How long the whole check may take.
const TIMEOUT: Duration = Duration::from_secs(5);

/// Ask the adapter at `socket` whether it is serving.
///
/// # Errors
/// `HEALTH_DOWN`, naming what failed.
pub async fn check(socket: &Path) -> Result<(), String> {
    let work = async {
        let mut s = UnixStream::connect(socket)
            .await
            .map_err(|e| format!("{}: {e}", socket.display()))?;
        s.write_all(b"GET /v1/health HTTP/1.1\r\nHost: adapter\r\nConnection: close\r\n\r\n")
            .await
            .map_err(|e| format!("{}: {e}", socket.display()))?;
        let mut head = [0u8; 12];
        s.read_exact(&mut head)
            .await
            .map_err(|_| format!("{}: no answer", socket.display()))?;
        if head.starts_with(b"HTTP/1.1 ") {
            Ok(())
        } else {
            Err(format!("{}: not an HTTP answer", socket.display()))
        }
    };
    match tokio::time::timeout(TIMEOUT, work).await {
        Ok(r) => r.map_err(|why| format!("HEALTH_DOWN: {why}")),
        Err(_) => Err(format!(
            "HEALTH_DOWN: {}: no answer within {} s",
            socket.display(),
            TIMEOUT.as_secs()
        )),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::check;
    use crate::socket::{bind, tests::dir};
    use crate::testkit::{govern_test_key, verifier, NOW};

    fn uid() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    #[tokio::test]
    async fn a_serving_adapter_is_healthy() {
        let d = dir();
        let path = d.path().join("backend.sock");
        let listener = bind(&path, uid()).unwrap();
        let v = Arc::new(verifier(
            &[("govern-gate-token-v1", &govern_test_key())],
            NOW,
        ));
        tokio::spawn(crate::server::serve(
            listener,
            uid(),
            Duration::from_secs(5),
            v,
            crate::server::not_yet(),
        ));
        check(&path).await.unwrap();
    }

    #[tokio::test]
    async fn no_adapter_is_unhealthy_by_name() {
        let d = dir();
        let e = check(&d.path().join("backend.sock")).await.unwrap_err();
        assert!(e.starts_with("HEALTH_DOWN"), "{e}");
    }

    /// A socket that accepts and never answers is not healthy either.
    #[tokio::test]
    async fn a_socket_that_never_answers_is_unhealthy() {
        let d = dir();
        let path = d.path().join("backend.sock");
        let l = tokio::net::UnixListener::bind(&path).unwrap();
        tokio::spawn(async move {
            let _held = l.accept().await;
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let e = check(&path).await.unwrap_err();
        assert!(e.starts_with("HEALTH_DOWN"), "{e}");
    }
}
