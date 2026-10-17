//! The adapter's one connection to NVIDIA OpenShell's gateway: TLS that the
//! gateway proves with a certificate from the public roots or the
//! installer's CA, and a bearer token on every call, which the caller passes
//! in. The client keeps no token.
//!
//! A gateway refusal is reduced to its gRPC code and, when OpenShell gives
//! one, the stable reason in its `google.rpc.ErrorInfo` detail (OpenShell's
//! `rpc_error.rs` attaches one to every refusal it means callers to act on).
//! Its message is never kept, because the contract forwards no backend text,
//! and never matched, because it is prose.

use std::time::Duration;

use openshell_proto::openshell::datamodel::v1::{workspace_selector, Provider, WorkspaceSelector};
use openshell_proto::openshell::sandbox::v1::SandboxPolicy;
use openshell_proto::openshell::v1::{
    open_shell_client::OpenShellClient, CreateSandboxRequest, DeleteSandboxRequest,
    DetachSandboxProviderRequest, GetProviderProfileRequest, GetProviderRequest,
    GetSandboxPolicyStatusRequest, GetSandboxPolicyStatusResponse, GetSandboxRequest,
    ListProviderProfilesRequest, ProviderProfile, Sandbox, StartSandboxRequest, StopSandboxRequest,
    UpdateConfigRequest,
};
use tonic::metadata::MetadataValue;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};

/// How long a connection may take to open, and a call to answer.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// The most pages a list reads before it refuses: a partial list is never
/// returned as the whole one.
const MAX_PAGES: usize = 100;

/// What a gateway call came to, when it did not answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayError {
    /// `NOT_FOUND`.
    NotFound,
    /// `UNAUTHENTICATED`: the token was refused. The token source drops it.
    Unauthenticated,
    /// `PERMISSION_DENIED`.
    PermissionDenied,
    /// The call never reached an answer we can read: `UNAVAILABLE`,
    /// `DEADLINE_EXCEEDED`, `CANCELLED`, `UNKNOWN`. A change may or may not
    /// have happened.
    Unavailable,
    /// `REQUEST_OUTCOME_UNCERTAIN`: the gateway admitted this request id and
    /// holds no confirmed result. A change may still finish.
    Uncertain,
    /// `REQUEST_REPLAY_UNAVAILABLE`: the id is fenced and its result can no
    /// longer be replayed. Nothing ran again.
    ReplayUnavailable,
    /// More pages than [`MAX_PAGES`].
    Incomplete,
    /// Anything else the gateway decided: its code and its ErrorInfo reason.
    Refused {
        code: tonic::Code,
        reason: Option<String>,
    },
    /// The gateway holds ANOTHER payload under this request id
    /// (`REQUEST_ID_PAYLOAD_MISMATCH`): a change may have run under it, so
    /// this is never "nothing changed".
    PayloadMismatch,
    /// An OK answer that carries nothing where the call promises a value: it
    /// says neither "there" nor "absent".
    Empty,
}

/// The two `google.rpc` messages a status's details carry, decoded by hand
/// with their published field numbers, so no extra crate is needed.
#[derive(Clone, PartialEq, prost::Message)]
struct RpcStatus {
    #[prost(int32, tag = "1")]
    code: i32,
    #[prost(string, tag = "2")]
    message: String,
    #[prost(message, repeated, tag = "3")]
    details: Vec<Any>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct Any {
    #[prost(string, tag = "1")]
    type_url: String,
    #[prost(bytes = "vec", tag = "2")]
    value: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct ErrorInfo {
    #[prost(string, tag = "1")]
    reason: String,
    #[prost(string, tag = "2")]
    domain: String,
}

/// The `ErrorInfo.reason` in a status's details, if it carries one.
#[must_use]
pub fn reason(status: &tonic::Status) -> Option<String> {
    let decoded = <RpcStatus as prost::Message>::decode(status.details()).ok()?;
    decoded
        .details
        .iter()
        .filter(|a| a.type_url == "type.googleapis.com/google.rpc.ErrorInfo")
        .find_map(|a| <ErrorInfo as prost::Message>::decode(a.value.as_slice()).ok())
        .map(|i| i.reason)
}

impl From<tonic::Status> for GatewayError {
    fn from(s: tonic::Status) -> Self {
        let why = reason(&s);
        match (s.code(), why.as_deref()) {
            (_, Some("REQUEST_OUTCOME_UNCERTAIN")) => Self::Uncertain,
            (_, Some("REQUEST_REPLAY_UNAVAILABLE")) => Self::ReplayUnavailable,
            (_, Some("REQUEST_ID_PAYLOAD_MISMATCH")) => Self::PayloadMismatch,
            (tonic::Code::NotFound, _) => Self::NotFound,
            (tonic::Code::Unauthenticated, _) => Self::Unauthenticated,
            (tonic::Code::PermissionDenied, _) => Self::PermissionDenied,
            (
                tonic::Code::Unavailable
                | tonic::Code::DeadlineExceeded
                | tonic::Code::Cancelled
                | tonic::Code::Unknown,
                _,
            ) => Self::Unavailable,
            (code, reason) => Self::Refused {
                code,
                reason: reason.map(str::to_string),
            },
        }
    }
}

impl std::fmt::Display for GatewayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => f.write_str("not found"),
            Self::Unauthenticated => f.write_str("the desk backend refused the token (UNAUTHENTICATED)"),
            Self::PermissionDenied => {
                f.write_str("the desk backend refused the client (PERMISSION_DENIED)")
            }
            Self::Unavailable => f.write_str("the desk backend did not answer (UNAVAILABLE)"),
            Self::Uncertain => f.write_str("the desk backend holds no confirmed result for this request (REQUEST_OUTCOME_UNCERTAIN)"),
            Self::ReplayUnavailable => f.write_str("the desk backend can no longer replay this request (REQUEST_REPLAY_UNAVAILABLE)"),
            Self::Empty => f.write_str("the desk backend answered OK with nothing in it"),
            Self::PayloadMismatch => f.write_str("the desk backend holds another request under this request id (REQUEST_ID_PAYLOAD_MISMATCH)"),
            Self::Incomplete => write!(f, "the list has more than {MAX_PAGES} pages"),
            Self::Refused { code, reason } => match reason {
                Some(r) => write!(f, "the desk backend answered {code:?} ({r})"),
                None => write!(f, "the desk backend answered {code:?}"),
            },
        }
    }
}

/// The TLS channel to the gateway. Nothing is sent until the first call.
///
/// # Errors
/// A URL that is not https, or a CA that is not PEM.
pub fn tls_channel(url: &str, ca_pem: Option<&[u8]>) -> Result<Channel, String> {
    tls_channel_within(url, ca_pem, CONNECT_TIMEOUT, CALL_TIMEOUT)
}

/// [`tls_channel`] with its time limits given: every call on the channel
/// fails at `call`, a connection at `connect`, so no gateway call can hang.
fn tls_channel_within(
    url: &str,
    ca_pem: Option<&[u8]>,
    connect: Duration,
    call: Duration,
) -> Result<Channel, String> {
    if !url.starts_with("https://") {
        return Err(
            "the desk backend's URL must be https, so the token never travels unencrypted".into(),
        );
    }
    let mut tls = ClientTlsConfig::new().with_webpki_roots();
    if let Some(pem) = ca_pem {
        tls = tls.ca_certificate(Certificate::from_pem(pem));
    }
    let endpoint = Endpoint::from_shared(url.to_string())
        .map_err(|e| format!("the desk backend's URL: {e}"))?
        .tls_config(tls)
        .map_err(|e| format!("the desk backend's TLS settings: {e}"))?
        .connect_timeout(connect)
        .timeout(call);
    Ok(endpoint.connect_lazy())
}

/// The gateway, in the organization's desk workspace.
#[derive(Clone)]
pub struct Gateway {
    grpc: OpenShellClient<Channel>,
    workspace: String,
}

impl Gateway {
    /// Over TLS. Nothing is sent until the first call.
    ///
    /// # Errors
    /// As [`tls_channel`].
    pub fn connect(url: &str, ca_pem: Option<&[u8]>, workspace: &str) -> Result<Self, String> {
        Ok(Self::over(tls_channel(url, ca_pem)?, workspace))
    }

    /// Over TLS with shorter time limits: tests only.
    #[cfg(test)]
    pub fn connect_within(
        url: &str,
        ca_pem: Option<&[u8]>,
        workspace: &str,
        connect: Duration,
        call: Duration,
    ) -> Result<Self, String> {
        Ok(Self::over(
            tls_channel_within(url, ca_pem, connect, call)?,
            workspace,
        ))
    }

    /// Over any channel, plaintext included: tests only. Production goes
    /// through [`Gateway::connect`], which refuses a URL that is not https.
    #[cfg(test)]
    pub fn over_test_channel(channel: Channel, workspace: &str) -> Self {
        Self::over(channel, workspace)
    }

    fn over(channel: Channel, workspace: &str) -> Self {
        Self {
            grpc: OpenShellClient::new(channel),
            workspace: workspace.to_string(),
        }
    }

    fn scope(&self) -> Option<WorkspaceSelector> {
        in_workspace(&self.workspace)
    }

    /// `msg` with `authorization: Bearer <token>`.
    fn request<T>(msg: T, bearer: &str) -> Result<tonic::Request<T>, GatewayError> {
        let value = MetadataValue::try_from(format!("Bearer {bearer}"))
            .map_err(|_| GatewayError::Unauthenticated)?;
        let mut req = tonic::Request::new(msg);
        req.metadata_mut().insert("authorization", value);
        Ok(req)
    }

    /// One provider record by name in the desk workspace, or `None`. The
    /// record carries credentials, which OpenShell answers as `REDACTED`
    /// (grpc/provider.rs:54 at the pin); a caller reads its non-secret fields.
    ///
    /// # Errors
    /// Any answer other than found or not found; an OK answer with nothing
    /// in it is [`GatewayError::Empty`], never absent (only `NOT_FOUND` is).
    pub async fn provider(
        &self,
        bearer: &str,
        name: &str,
    ) -> Result<Option<Provider>, GatewayError> {
        let req = Self::request(
            GetProviderRequest {
                workspace_scope: self.scope(),
                name: name.to_string(),
            },
            bearer,
        )?;
        match self.grpc.clone().get_provider(req).await {
            Ok(r) => r.into_inner().provider.map(Some).ok_or(GatewayError::Empty),
            Err(s) => match GatewayError::from(s) {
                GatewayError::NotFound => Ok(None),
                e => Err(e),
            },
        }
    }

    /// A provider profile by id, in `workspace` (a provider's
    /// `profile_workspace`), or `None`.
    ///
    /// # Errors
    /// Any answer other than found or not found; an OK answer with nothing
    /// in it is [`GatewayError::Empty`], never absent (only `NOT_FOUND` is).
    pub async fn provider_profile(
        &self,
        bearer: &str,
        id: &str,
        workspace: &str,
    ) -> Result<Option<ProviderProfile>, GatewayError> {
        let req = Self::request(
            GetProviderProfileRequest {
                workspace_scope: in_workspace(workspace),
                id: id.to_string(),
            },
            bearer,
        )?;
        match self.grpc.clone().get_provider_profile(req).await {
            Ok(r) => r.into_inner().profile.map(Some).ok_or(GatewayError::Empty),
            Err(s) => match GatewayError::from(s) {
                GatewayError::NotFound => Ok(None),
                e => Err(e),
            },
        }
    }

    /// Every profile the desk workspace sees, all pages, each with the
    /// `scope` OpenShell sets. Asked in the workspace: a read with no
    /// workspace needs a platform admin, which the adapter never is.
    ///
    /// # Errors
    /// Any refusal, and [`GatewayError::Incomplete`] past [`MAX_PAGES`].
    pub async fn provider_profiles(
        &self,
        bearer: &str,
    ) -> Result<Vec<ProviderProfile>, GatewayError> {
        let mut out = Vec::new();
        let mut page_token = String::new();
        for _ in 0..MAX_PAGES {
            let req = Self::request(
                ListProviderProfilesRequest {
                    workspace_scope: self.scope(),
                    page_size: 1000,
                    page_token: page_token.clone(),
                },
                bearer,
            )?;
            let page = self
                .grpc
                .clone()
                .list_provider_profiles(req)
                .await?
                .into_inner();
            out.extend(page.profiles);
            if page.next_page_token.is_empty() {
                return Ok(out);
            }
            page_token = page.next_page_token;
        }
        Err(GatewayError::Incomplete)
    }
}

impl Gateway {
    /// The sandbox by name in the desk workspace, or `None`: ONLY a
    /// `NOT_FOUND` says it is absent.
    ///
    /// # Errors
    /// Any answer other than found or not found, and an OK answer that
    /// carries no sandbox ([`GatewayError::Empty`]): never taken for absent.
    pub async fn sandbox(&self, bearer: &str, name: &str) -> Result<Option<Sandbox>, GatewayError> {
        let req = Self::request(
            GetSandboxRequest {
                workspace_scope: self.scope(),
                name: name.to_string(),
            },
            bearer,
        )?;
        match self.grpc.clone().get_sandbox(req).await {
            Ok(r) => r.into_inner().sandbox.map(Some).ok_or(GatewayError::Empty),
            Err(s) => match GatewayError::from(s) {
                GatewayError::NotFound => Ok(None),
                e => Err(e),
            },
        }
    }

    /// The sandbox's newest policy revision and the one it has loaded.
    ///
    /// # Errors
    /// The gateway's refusal.
    pub async fn policy_status(
        &self,
        bearer: &str,
        name: &str,
    ) -> Result<GetSandboxPolicyStatusResponse, GatewayError> {
        let req = Self::request(
            GetSandboxPolicyStatusRequest {
                workspace_scope: self.scope(),
                sandbox: name.to_string(),
                version: 0,
                global: false,
            },
            bearer,
        )?;
        Ok(self
            .grpc
            .clone()
            .get_sandbox_policy_status(req)
            .await?
            .into_inner())
    }

    /// CreateSandbox, in the desk workspace.
    ///
    /// # Errors
    /// The gateway's refusal.
    pub async fn create(
        &self,
        bearer: &str,
        mut msg: CreateSandboxRequest,
    ) -> Result<(), GatewayError> {
        msg.workspace_scope = self.scope();
        let req = Self::request(msg, bearer)?;
        self.grpc.clone().create_sandbox(req).await?;
        Ok(())
    }

    /// DeleteSandbox. A sandbox already gone is NOT_FOUND, never "allowed".
    ///
    /// # Errors
    /// The gateway's refusal.
    pub async fn delete(
        &self,
        bearer: &str,
        name: &str,
        request_id: &str,
    ) -> Result<(), GatewayError> {
        let req = Self::request(
            DeleteSandboxRequest {
                workspace_scope: self.scope(),
                name: name.to_string(),
                allow_missing: false,
                request_id: request_id.to_string(),
            },
            bearer,
        )?;
        self.grpc.clone().delete_sandbox(req).await?;
        Ok(())
    }

    /// StopSandbox, or StartSandbox when `start`.
    ///
    /// # Errors
    /// The gateway's refusal.
    pub async fn stop_or_start(
        &self,
        bearer: &str,
        name: &str,
        request_id: &str,
        start: bool,
    ) -> Result<(), GatewayError> {
        if start {
            let req = Self::request(
                StartSandboxRequest {
                    workspace_scope: self.scope(),
                    name: name.to_string(),
                    request_id: request_id.to_string(),
                },
                bearer,
            )?;
            self.grpc.clone().start_sandbox(req).await?;
        } else {
            let req = Self::request(
                StopSandboxRequest {
                    workspace_scope: self.scope(),
                    name: name.to_string(),
                    request_id: request_id.to_string(),
                },
                bearer,
            )?;
            self.grpc.clone().stop_sandbox(req).await?;
        }
        Ok(())
    }

    /// UpdateConfig with the whole new policy, only if the sandbox is still
    /// at `expected_resource_version` (a race is ABORTED, never retried).
    ///
    /// # Errors
    /// The gateway's refusal.
    pub async fn set_policy(
        &self,
        bearer: &str,
        name: &str,
        policy: SandboxPolicy,
        expected_resource_version: u64,
        request_id: &str,
    ) -> Result<(), GatewayError> {
        let req = Self::request(
            UpdateConfigRequest {
                workspace_scope: self.scope(),
                sandbox: name.to_string(),
                policy: Some(policy),
                expected_resource_version,
                request_id: request_id.to_string(),
                ..Default::default()
            },
            bearer,
        )?;
        self.grpc.clone().update_config(req).await?;
        Ok(())
    }

    /// DetachSandboxProvider, only if the sandbox is still at
    /// `expected_resource_version`.
    ///
    /// # Errors
    /// The gateway's refusal.
    pub async fn detach(
        &self,
        bearer: &str,
        name: &str,
        provider: &str,
        expected_resource_version: u64,
        request_id: &str,
    ) -> Result<(), GatewayError> {
        let req = Self::request(
            DetachSandboxProviderRequest {
                workspace_scope: self.scope(),
                sandbox: name.to_string(),
                provider: provider.to_string(),
                expected_resource_version,
                request_id: request_id.to_string(),
            },
            bearer,
        )?;
        self.grpc.clone().detach_sandbox_provider(req).await?;
        Ok(())
    }
}

/// The selector for one named workspace; none for an empty name.
fn in_workspace(workspace: &str) -> Option<WorkspaceSelector> {
    (!workspace.is_empty()).then(|| WorkspaceSelector {
        selection: Some(workspace_selector::Selection::Workspace(
            workspace.to_string(),
        )),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "gateway_tests.rs"]
mod tests;
