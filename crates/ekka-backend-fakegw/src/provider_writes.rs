//! Provider mutations with redacted reads, including an applied-but-lost reply.
use crate::fake_gateway::{authorized, workspace, Shared};
use openshell_proto::openshell::datamodel::v1::Provider;
use openshell_proto::openshell::v1::{
    CreateProviderRequest, ProviderResponse, UpdateProviderRequest,
};
use tonic::{Request, Response, Status};

pub fn create(
    st: &Shared,
    r: Request<CreateProviderRequest>,
) -> Result<Response<ProviderResponse>, Status> {
    authorized(st, &r)?;
    let q = r.into_inner();
    write(
        st,
        q.provider,
        &workspace(q.workspace_scope.as_ref()),
        &q.request_id,
        false,
    )
}
pub fn update(
    st: &Shared,
    r: Request<UpdateProviderRequest>,
) -> Result<Response<ProviderResponse>, Status> {
    authorized(st, &r)?;
    let q = r.into_inner();
    write(
        st,
        q.provider,
        &workspace(q.workspace_scope.as_ref()),
        &q.request_id,
        true,
    )
}
fn write(
    st: &Shared,
    p: Option<Provider>,
    ws: &str,
    rid: &str,
    update: bool,
) -> Result<Response<ProviderResponse>, Status> {
    let mut p = p.ok_or_else(|| Status::invalid_argument("missing provider"))?;
    if !p.credential_handles.is_empty() {
        return Err(Status::invalid_argument(
            "gateway handles are internal state",
        ));
    }
    let meta = p
        .metadata
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("missing name"))?;
    let name = meta.name.clone();
    let mut s = st
        .lock()
        .map_err(|_| Status::internal("test gateway state is poisoned"))?;
    let rpc = if update {
        "UpdateProvider"
    } else {
        "CreateProvider"
    };
    s.calls.push(format!("{rpc} {ws}/{name}"));
    s.request_ids.push((rpc.into(), rid.into()));
    if let Some(code) = s.provider_write_error {
        return Err(Status::new(code, "planted provider refusal"));
    }
    match (s.providers.get(&name), update) {
        (Some(old), true)
            if old
                .metadata
                .as_ref()
                .is_some_and(|m| m.resource_version == meta.resource_version) => {}
        (None, false) => {}
        _ => return Err(Status::aborted("provider version conflict")),
    }
    let values = s
        .provider_written_credentials
        .entry(name.clone())
        .or_default();
    values.extend(p.credentials.clone());
    let keys: Vec<_> = values.keys().cloned().collect();
    p.credentials = keys.into_iter().map(|k| (k, "REDACTED".into())).collect();
    let m = p
        .metadata
        .as_mut()
        .ok_or_else(|| Status::invalid_argument("missing name"))?;
    m.resource_version += 1;
    m.workspace = ws.into();
    s.providers.insert(name, p.clone());
    if let Some(code) = s.provider_apply_then_error {
        return Err(Status::new(code, "planted lost acknowledgement"));
    }
    Ok(Response::new(ProviderResponse {
        provider: Some(p),
        ..Default::default()
    }))
}
