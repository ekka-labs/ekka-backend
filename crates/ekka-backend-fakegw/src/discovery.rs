//! The fake gateway's calls for desk discovery: a sandbox setting kept by
//! UpdateConfig and read back by GetSandboxConfig, the draft policy and its
//! decision history, and the sandbox's log lines. A test plants the drafts,
//! the history and the logs in `State`; `draft_churn` makes each pending read
//! find one more proposal, as a desk still asking for hosts does.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use openshell_proto::openshell::sandbox::v1::{
    setting_value, EffectiveSetting, GetSandboxConfigRequest, GetSandboxConfigResponse,
    SettingScope, SettingValue,
};
use openshell_proto::openshell::v1::{
    GetDraftHistoryRequest, GetDraftHistoryResponse, GetDraftPolicyRequest, GetDraftPolicyResponse,
    GetSandboxLogsRequest, GetSandboxLogsResponse, PolicyChunk, UpdateConfigRequest,
    UpdateConfigResponse,
};
use tonic::{Request, Response, Status};

use crate::fake_gateway::{authorized, workspace, Shared, State};

/// The string a setting value carries, or `None` for any other kind.
fn string_of(v: Option<&SettingValue>) -> Option<String> {
    match v.and_then(|v| v.value.as_ref()) {
        Some(setting_value::Value::StringValue(s)) => Some(s.clone()),
        _ => None,
    }
}

/// UpdateConfig with one setting and no policy: the value is kept for the
/// sandbox (unless `ignore_settings`). Its call reads
/// `UpdateConfig <ws>/<name> <key>=<value>`.
pub(crate) fn update_setting(
    s: &mut State,
    q: &UpdateConfigRequest,
    request_id: &str,
    payload: &[u8],
) -> Result<Response<UpdateConfigResponse>, Status> {
    let ws = workspace(q.workspace_scope.as_ref());
    let value = string_of(q.setting_value.as_ref()).unwrap_or_default();
    s.calls.pop();
    s.calls.push(format!(
        "UpdateConfig {ws}/{} {}={value}",
        q.sandbox, q.setting_key
    ));
    if !s.ignore_settings {
        s.settings
            .entry(q.sandbox.clone())
            .or_default()
            .insert(q.setting_key.clone(), value);
    }
    crate::sandboxes::reply(
        s,
        "UpdateConfig",
        request_id,
        payload,
        UpdateConfigResponse {
            settings_revision: 1,
            ..Default::default()
        },
    )
}

pub fn get_config(
    st: &Shared,
    r: Request<GetSandboxConfigRequest>,
) -> Result<Response<GetSandboxConfigResponse>, Status> {
    authorized(st, &r)?;
    let q = r.into_inner();
    let ws = workspace(q.workspace_scope.as_ref());
    let mut s = st.lock().unwrap();
    crate::sandboxes::record(&mut s, "GetSandboxConfig", &ws, &q.name, "");
    if !s.sandboxes.contains_key(&q.name) {
        return Err(Status::not_found("no such sandbox"));
    }
    let settings = s
        .settings
        .get(&q.name)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|(k, v)| {
            (
                k,
                EffectiveSetting {
                    value: Some(SettingValue {
                        value: Some(setting_value::Value::StringValue(v)),
                    }),
                    scope: SettingScope::Sandbox as i32,
                },
            )
        })
        .collect();
    Ok(Response::new(GetSandboxConfigResponse {
        settings,
        workspace: ws,
        ..Default::default()
    }))
}

pub fn get_drafts(
    st: &Shared,
    r: Request<GetDraftPolicyRequest>,
) -> Result<Response<GetDraftPolicyResponse>, Status> {
    authorized(st, &r)?;
    let q = r.into_inner();
    let ws = workspace(q.workspace_scope.as_ref());
    let mut s = st.lock().unwrap();
    s.calls.push(format!(
        "GetDraftPolicy {ws}/{} {}",
        q.sandbox, q.status_filter
    ));
    if !s.sandboxes.contains_key(&q.sandbox) {
        return Err(Status::not_found("no such sandbox"));
    }
    if q.status_filter == "pending" && s.draft_churn > 0 {
        s.draft_churn -= 1;
        let drafts = s.drafts.entry(q.sandbox.clone()).or_default();
        let n = drafts.len();
        drafts.push(PolicyChunk {
            id: format!("churn-{n}"),
            status: "pending".into(),
            rule_name: format!("churn-{n}"),
            ..Default::default()
        });
    }
    let chunks = s
        .drafts
        .get(&q.sandbox)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|c| q.status_filter.is_empty() || c.status == q.status_filter)
        .collect();
    Ok(Response::new(GetDraftPolicyResponse {
        chunks,
        ..Default::default()
    }))
}

pub fn get_history(
    st: &Shared,
    r: Request<GetDraftHistoryRequest>,
) -> Result<Response<GetDraftHistoryResponse>, Status> {
    authorized(st, &r)?;
    let q = r.into_inner();
    let ws = workspace(q.workspace_scope.as_ref());
    let mut s = st.lock().unwrap();
    s.calls.push(format!("GetDraftHistory {ws}/{}", q.sandbox));
    if !s.sandboxes.contains_key(&q.sandbox) {
        return Err(Status::not_found("no such sandbox"));
    }
    let entries = s.history.get(&q.sandbox).cloned().unwrap_or_default();
    Ok(Response::new(GetDraftHistoryResponse { entries }))
}

/// The newest `lines` lines (0: 2000, OpenShell's default), oldest first.
pub fn get_logs(
    st: &Shared,
    r: Request<GetSandboxLogsRequest>,
) -> Result<Response<GetSandboxLogsResponse>, Status> {
    authorized(st, &r)?;
    let q = r.into_inner();
    let ws = workspace(q.workspace_scope.as_ref());
    let mut s = st.lock().unwrap();
    s.calls.push(format!("GetSandboxLogs {ws}/{}", q.sandbox));
    s.log_reads.push(q.lines);
    if !s.sandboxes.contains_key(&q.sandbox) {
        return Err(Status::not_found("no such sandbox"));
    }
    let all = s.logs.get(&q.sandbox).cloned().unwrap_or_default();
    let want = if q.lines == 0 { 2000 } else { q.lines as usize };
    let logs = all[all.len().saturating_sub(want)..].to_vec();
    Ok(Response::new(GetSandboxLogsResponse {
        buffer_total: u32::try_from(all.len()).unwrap(),
        logs,
    }))
}
