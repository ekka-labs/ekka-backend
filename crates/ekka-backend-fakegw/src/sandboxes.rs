//! The fake gateway's sandbox calls: create, get, delete, stop,
//! start, a policy change, its revisions, and detaching a provider, answered
//! as NVIDIA OpenShell answers them at e1f3c82. A policy change and a detach
//! are compare-and-set on the sandbox's resource version (ABORTED with
//! `RESOURCE_VERSION_CONFLICT` otherwise), and every revision a policy change
//! makes is kept, the newest loaded. A test can refuse a call before any
//! effect (`refuse`), or commit its effect and lose the reply (`lose_reply`).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use openshell_proto::openshell::datamodel::v1::ObjectMeta;
use openshell_proto::openshell::sandbox::v1::SandboxPolicy;
use openshell_proto::openshell::v1::{
    CreateSandboxRequest, DeleteSandboxRequest, DeleteSandboxResponse,
    DetachSandboxProviderRequest, DetachSandboxProviderResponse, GetSandboxPolicyStatusRequest,
    GetSandboxPolicyStatusResponse, GetSandboxRequest, PolicyStatus, Sandbox, SandboxPhase,
    SandboxPolicyRevision, SandboxResponse, SandboxStatus, StartSandboxRequest, StopSandboxRequest,
    UpdateConfigRequest, UpdateConfigResponse,
};
use tonic::{Request, Response, Status};

use crate::fake_gateway::{authorized, workspace, Shared, State};

/// One request id the gateway admitted, as OpenShell's `mutation_replay.rs`
/// keeps it: the RPC, its payload, and its success once confirmed.
#[derive(Debug, Clone)]
pub struct Admission {
    pub rpc: String,
    pub payload: Vec<u8>,
    /// The encoded reply, once the success is confirmed; `None` after a lost
    /// finalizer.
    pub success: Option<Vec<u8>>,
}

/// OpenShell's replay of a request id it has admitted (`mutation_replay.rs`
/// :285-307 at e1f3c82): another payload is REQUEST_ID_PAYLOAD_MISMATCH; a
/// confirmed success is replayed with `openshell-replayed: true` and no
/// second effect; no confirmed success is REQUEST_OUTCOME_UNCERTAIN.
fn replayed<T: prost::Message + Default>(
    s: &State,
    rpc: &str,
    request_id: &str,
    payload: &[u8],
) -> Option<Result<Response<T>, Status>> {
    if request_id.is_empty() {
        return None;
    }
    let a = s.applied.get(request_id)?;
    if a.rpc != rpc || a.payload != payload {
        return Some(Err(crate::faults::error_info_status(
            tonic::Code::FailedPrecondition,
            "REQUEST_ID_PAYLOAD_MISMATCH",
            "REQUEST_ID_PAYLOAD_MISMATCH",
            std::collections::HashMap::new(),
        )));
    }
    Some(match &a.success {
        Some(bytes) => {
            let mut r = Response::new(T::decode(bytes.as_slice()).unwrap());
            r.metadata_mut()
                .insert("openshell-replayed", "true".parse().unwrap());
            Ok(r)
        }
        None => Err(crate::faults::error_info_status(
            tonic::Code::FailedPrecondition,
            "REQUEST_OUTCOME_UNCERTAIN",
            "REQUEST_OUTCOME_UNCERTAIN",
            std::collections::HashMap::new(),
        )),
    })
}

/// OpenShell's fingerprint of a mutation (`mutation_replay.rs` `fingerprint`
/// and `hash_json`): the request decoded, its `request_id` cleared, as JSON
/// with EVERY map sorted. So the order a client's map fields happen to
/// encode in (prost's maps are `HashMap`s) never makes two sends of one
/// request differ.
fn fingerprint(type_name: &str, q: &impl prost::Message) -> Vec<u8> {
    fingerprint_bytes(type_name, &q.encode_to_vec())
}

fn fingerprint_bytes(type_name: &str, encoded: &[u8]) -> Vec<u8> {
    fn sorted(v: serde_json::Value) -> serde_json::Value {
        match v {
            serde_json::Value::Object(m) => {
                let mut kv: Vec<_> = m.into_iter().collect();
                kv.sort_by(|a, b| a.0.cmp(&b.0));
                serde_json::Value::Object(kv.into_iter().map(|(k, v)| (k, sorted(v))).collect())
            }
            serde_json::Value::Array(a) => {
                serde_json::Value::Array(a.into_iter().map(sorted).collect())
            }
            v => v,
        }
    }
    let pool = prost_reflect::DescriptorPool::decode(openshell_proto::FILE_DESCRIPTOR_SET).unwrap();
    let d = pool
        .get_message_by_name(&format!("openshell.v1.{type_name}"))
        .unwrap();
    let mut m = prost_reflect::DynamicMessage::decode(d, encoded).unwrap();
    m.clear_field_by_name("request_id");
    serde_json::to_vec(&sorted(serde_json::to_value(&m).unwrap())).unwrap()
}

/// After the effect: the admission is kept, with its success unless the
/// test lost the finalizer (then the reply is lost too); and the reply is
/// lost when the test asked for it.
fn reply<T: prost::Message>(
    s: &mut State,
    rpc: &str,
    request_id: &str,
    payload: &[u8],
    t: T,
) -> Result<Response<T>, Status> {
    let lost_finalizer = s.lose_finalizer.contains(rpc);
    if !request_id.is_empty() {
        s.applied.insert(
            request_id.to_string(),
            Admission {
                rpc: rpc.to_string(),
                payload: payload.to_vec(),
                success: (!lost_finalizer).then(|| t.encode_to_vec()),
            },
        );
    }
    if lost_finalizer || s.lose_reply.contains(rpc) {
        return Err(Status::unavailable("reply lost"));
    }
    Ok(Response::new(t))
}

fn record(s: &mut State, rpc: &str, ws: &str, name: &str, request_id: &str) {
    s.calls.push(format!("{rpc} {ws}/{name}"));
    if let Some(w) = s.watch.clone() {
        let seen = std::fs::read_to_string(w).ok();
        s.watched.push((rpc.to_string(), seen));
    }
    if !request_id.is_empty() {
        s.request_ids
            .push((rpc.to_string(), request_id.to_string()));
    }
}

/// Every sandbox whose delete has run its course is gone now.
fn reap(s: &mut State) {
    let now = std::time::Instant::now();
    let gone: Vec<String> = s
        .vanishing
        .iter()
        .filter(|(_, at)| **at <= now)
        .map(|(n, _)| n.clone())
        .collect();
    for n in gone {
        s.vanishing.remove(&n);
        s.sandboxes.remove(&n);
        s.revisions.remove(&n);
    }
}

fn phase(sb: &mut Sandbox, p: SandboxPhase) {
    sb.status.get_or_insert_with(SandboxStatus::default).phase = p as i32;
}

fn bump(sb: &mut Sandbox) {
    let m = sb.metadata.get_or_insert_with(ObjectMeta::default);
    m.resource_version += 1;
}

pub fn create(
    st: &Shared,
    r: Request<CreateSandboxRequest>,
) -> Result<Response<SandboxResponse>, Status> {
    authorized(st, &r)?;
    let q = r.into_inner();
    let payload = fingerprint("CreateSandboxRequest", &q);
    let rid = q.request_id.clone();
    let ws = workspace(q.workspace_scope.as_ref());
    let mut s = st.lock().unwrap();
    record(&mut s, "CreateSandbox", &ws, &q.name, &q.request_id);
    if let Some(r) = replayed(&s, "CreateSandbox", &rid, &payload) {
        return r;
    }
    if s.sandboxes.contains_key(&q.name) {
        return Err(Status::already_exists("sandbox exists"));
    }
    s.next_id += 1;
    let mut sb = Sandbox {
        metadata: Some(ObjectMeta {
            id: format!("00000000-0000-4000-8000-{:012}", s.next_id),
            name: q.name.clone(),
            workspace: ws,
            resource_version: 1,
            labels: q.labels,
            annotations: q.annotations,
            ..Default::default()
        }),
        spec: q.spec,
        ..Default::default()
    };
    phase(&mut sb, SandboxPhase::Ready);
    if let Some(rewrite) = s.rewrite_created {
        rewrite(&mut sb);
    }
    let policy = sb
        .spec
        .as_ref()
        .and_then(|x| x.policy.clone())
        .unwrap_or_default();
    s.revisions.insert(q.name.clone(), vec![policy]);
    if let Some(n) = s.create_loads_on_read {
        s.loading.insert(q.name.clone());
        s.reads_until_loaded.insert(q.name.clone(), n);
    }
    s.sandboxes.insert(q.name, sb.clone());
    reply(
        &mut s,
        "CreateSandbox",
        &rid,
        &payload,
        SandboxResponse {
            sandbox: Some(sb),
            ..Default::default()
        },
    )
}

pub fn get(
    st: &Shared,
    r: Request<GetSandboxRequest>,
) -> Result<Response<SandboxResponse>, Status> {
    authorized(st, &r)?;
    let q = r.into_inner();
    let ws = workspace(q.workspace_scope.as_ref());
    let mut s = st.lock().unwrap();
    reap(&mut s);
    s.calls.push(format!("GetSandbox {ws}/{}", q.name));
    if s.empty_get.contains(&q.name) {
        return Ok(Response::new(SandboxResponse::default()));
    }
    match s.sandboxes.get(&q.name) {
        Some(sb) => Ok(Response::new(SandboxResponse {
            sandbox: Some(sb.clone()),
            ..Default::default()
        })),
        None => Err(Status::not_found("no such sandbox")),
    }
}

pub fn delete(
    st: &Shared,
    r: Request<DeleteSandboxRequest>,
) -> Result<Response<DeleteSandboxResponse>, Status> {
    authorized(st, &r)?;
    let q = r.into_inner();
    let payload = fingerprint("DeleteSandboxRequest", &q);
    let ws = workspace(q.workspace_scope.as_ref());
    let mut s = st.lock().unwrap();
    record(&mut s, "DeleteSandbox", &ws, &q.name, &q.request_id);
    if let Some(r) = replayed(&s, "DeleteSandbox", &q.request_id, &payload) {
        return r;
    }
    reap(&mut s);
    let id = if let Some(takes) = s.delete_takes {
        // Accepted; the sandbox stays readable until it is gone.
        let Some(sb) = s.sandboxes.get(&q.name) else {
            return Err(Status::not_found("no such sandbox"));
        };
        let id = sb
            .metadata
            .as_ref()
            .map(|m| m.id.clone())
            .unwrap_or_default();
        let at = std::time::Instant::now() + takes;
        s.vanishing.entry(q.name.clone()).or_insert(at);
        id
    } else {
        let Some(sb) = s.sandboxes.remove(&q.name) else {
            return Err(Status::not_found("no such sandbox"));
        };
        s.revisions.remove(&q.name);
        sb.metadata.map(|m| m.id).unwrap_or_default()
    };
    reply(
        &mut s,
        "DeleteSandbox",
        &q.request_id,
        &payload,
        DeleteSandboxResponse {
            sandbox_id: id,
            ..Default::default()
        },
    )
}

fn stop_or_start(
    st: &Shared,
    rpc: &str,
    ws: &str,
    name: &str,
    request_id: &str,
    payload: &[u8],
    to: SandboxPhase,
) -> Result<Response<SandboxResponse>, Status> {
    let mut s = st.lock().unwrap();
    record(&mut s, rpc, ws, name, request_id);
    if let Some(r) = replayed(&s, rpc, request_id, payload) {
        return r;
    }
    let Some(sb) = s.sandboxes.get_mut(name) else {
        return Err(Status::not_found("no such sandbox"));
    };
    phase(sb, to);
    let sb = sb.clone();
    reply(
        &mut s,
        rpc,
        request_id,
        payload,
        SandboxResponse {
            sandbox: Some(sb),
            ..Default::default()
        },
    )
}

pub fn stop(
    st: &Shared,
    r: Request<StopSandboxRequest>,
) -> Result<Response<SandboxResponse>, Status> {
    authorized(st, &r)?;
    let q = r.into_inner();
    let ws = workspace(q.workspace_scope.as_ref());
    stop_or_start(
        st,
        "StopSandbox",
        &ws,
        &q.name,
        &q.request_id,
        &fingerprint("StopSandboxRequest", &q),
        SandboxPhase::Stopped,
    )
}

pub fn start(
    st: &Shared,
    r: Request<StartSandboxRequest>,
) -> Result<Response<SandboxResponse>, Status> {
    authorized(st, &r)?;
    let q = r.into_inner();
    let ws = workspace(q.workspace_scope.as_ref());
    stop_or_start(
        st,
        "StartSandbox",
        &ws,
        &q.name,
        &q.request_id,
        &fingerprint("StartSandboxRequest", &q),
        SandboxPhase::Ready,
    )
}

fn cas(sb: &Sandbox, expected: u64) -> Result<(), Status> {
    let now = sb.metadata.as_ref().map_or(0, |m| m.resource_version);
    if now == expected {
        Ok(())
    } else {
        Err(crate::faults::error_info_status(
            tonic::Code::Aborted,
            "RESOURCE_VERSION_CONFLICT",
            "RESOURCE_VERSION_CONFLICT",
            std::collections::HashMap::new(),
        ))
    }
}

pub fn update_config(
    st: &Shared,
    r: Request<UpdateConfigRequest>,
) -> Result<Response<UpdateConfigResponse>, Status> {
    authorized(st, &r)?;
    let q = r.into_inner();
    let payload = fingerprint("UpdateConfigRequest", &q);
    let rid = q.request_id.clone();
    let ws = workspace(q.workspace_scope.as_ref());
    let mut s = st.lock().unwrap();
    record(&mut s, "UpdateConfig", &ws, &q.sandbox, &q.request_id);
    if let Some(r) = replayed(&s, "UpdateConfig", &rid, &payload) {
        return r;
    }
    let Some(sb) = s.sandboxes.get_mut(&q.sandbox) else {
        return Err(Status::not_found("no such sandbox"));
    };
    cas(sb, q.expected_resource_version)?;
    bump(sb);
    let policy: SandboxPolicy = q.policy.unwrap_or_default();
    let revisions = s.revisions.entry(q.sandbox.clone()).or_default();
    revisions.push(policy);
    let version = u32::try_from(revisions.len()).unwrap();
    reply(
        &mut s,
        "UpdateConfig",
        &rid,
        &payload,
        UpdateConfigResponse {
            version,
            ..Default::default()
        },
    )
}

pub fn policy_status(
    st: &Shared,
    r: Request<GetSandboxPolicyStatusRequest>,
) -> Result<Response<GetSandboxPolicyStatusResponse>, Status> {
    authorized(st, &r)?;
    let q = r.into_inner();
    let ws = workspace(q.workspace_scope.as_ref());
    let mut s = st.lock().unwrap();
    reap(&mut s);
    s.calls
        .push(format!("GetSandboxPolicyStatus {ws}/{}", q.sandbox));
    if let Some((left, code)) = s.fail_policy_reads {
        if left > 0 {
            s.fail_policy_reads = Some((left - 1, code));
            return Err(Status::new(code, "not yet"));
        }
    }
    if let Some(code) = s.policy_error_while_deleting {
        if s.vanishing.contains_key(&q.sandbox) {
            return Err(Status::new(code, "being deleted"));
        }
    }
    // A policy that loads on a later read: count this read.
    if let Some(left) = s.reads_until_loaded.get_mut(&q.sandbox) {
        *left = left.saturating_sub(1);
        if *left == 0 {
            s.reads_until_loaded.remove(&q.sandbox);
            s.loading.remove(&q.sandbox);
        }
    }
    let Some(revs) = s.revisions.get(&q.sandbox) else {
        return Err(Status::not_found("no such sandbox"));
    };
    let version = u32::try_from(revs.len()).unwrap();
    let active = if s.loading.contains(&q.sandbox) {
        version - 1
    } else {
        version
    };
    Ok(Response::new(GetSandboxPolicyStatusResponse {
        revision: Some(SandboxPolicyRevision {
            version,
            status: if active == version {
                PolicyStatus::Loaded
            } else {
                PolicyStatus::Pending
            } as i32,
            policy: revs.last().cloned(),
            ..Default::default()
        }),
        active_version: active,
    }))
}

pub fn detach(
    st: &Shared,
    r: Request<DetachSandboxProviderRequest>,
) -> Result<Response<DetachSandboxProviderResponse>, Status> {
    authorized(st, &r)?;
    let q = r.into_inner();
    let payload = fingerprint("DetachSandboxProviderRequest", &q);
    let ws = workspace(q.workspace_scope.as_ref());
    let mut s = st.lock().unwrap();
    record(
        &mut s,
        "DetachSandboxProvider",
        &ws,
        &format!("{}/{}", q.sandbox, q.provider),
        &q.request_id,
    );
    if let Some(r) = replayed(&s, "DetachSandboxProvider", &q.request_id, &payload) {
        return r;
    }
    let Some(sb) = s.sandboxes.get_mut(&q.sandbox) else {
        return Err(Status::not_found("no such sandbox"));
    };
    cas(sb, q.expected_resource_version)?;
    let spec = sb.spec.get_or_insert_with(Default::default);
    let before = spec.providers.len();
    spec.providers.retain(|p| *p != q.provider);
    let detached = spec.providers.len() != before;
    bump(sb);
    let sb = sb.clone();
    reply(
        &mut s,
        "DetachSandboxProvider",
        &q.request_id,
        &payload,
        DetachSandboxProviderResponse {
            sandbox: Some(sb),
            detached,
            ..Default::default()
        },
    )
}

#[cfg(test)]
mod tests {
    use openshell_proto::openshell::v1::CreateSandboxRequest;
    use prost::Message as _;

    fn labelled(k: &str, rid: &str) -> Vec<u8> {
        CreateSandboxRequest {
            name: "code-desk".into(),
            labels: [(k.to_string(), "v".to_string())].into_iter().collect(),
            request_id: rid.into(),
            ..Default::default()
        }
        .encode_to_vec()
    }

    /// One request, its two map entries sent in either order (protobuf
    /// merges a map across concatenated messages): one fingerprint, as
    /// OpenShell's. Raw bytes would call them two payloads.
    #[test]
    fn a_requests_fingerprint_ignores_its_map_order() {
        let ab = [labelled("a", "r"), labelled("b", "r")].concat();
        let ba = [labelled("b", "r"), labelled("a", "r")].concat();
        assert_ne!(ab, ba);
        assert_eq!(
            super::fingerprint_bytes("CreateSandboxRequest", &ab),
            super::fingerprint_bytes("CreateSandboxRequest", &ba)
        );
        // Another label is another payload; the request id is not part of it.
        let other = [labelled("a", "r"), labelled("c", "r")].concat();
        assert_ne!(
            super::fingerprint_bytes("CreateSandboxRequest", &ab),
            super::fingerprint_bytes("CreateSandboxRequest", &other)
        );
        let renamed = [labelled("a", "x"), labelled("b", "x")].concat();
        assert_eq!(
            super::fingerprint_bytes("CreateSandboxRequest", &ab),
            super::fingerprint_bytes("CreateSandboxRequest", &renamed)
        );
    }
}
