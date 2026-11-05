//! Desk discovery against the fake gateway: `approval_mode` writes a permit
//! only after the backend reads `auto` back, and only for a desk the grant's
//! discovery window covers; `manual` and a delete remove it first; the
//! evidence is read only for a desk with a permit, waits for the desk to
//! settle, and stays within its bounds.

use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use chrono::Utc;
use openshell_proto::openshell::sandbox::v1::{NetworkEndpoint, NetworkPolicyRule};
use openshell_proto::openshell::v1::{DraftHistoryEntry, PolicyChunk, SandboxLogLine};
use serde_json::{json, Value};

use ekka_backend_fakegw::faults::Planted;

use super::{ApprovalModeBody, EvidenceTimings, LOG_LINES, LOG_LINE_CHARS};
use crate::answer::{Answer, Code, Outcome, EVIDENCE_MAX_BYTES};
use crate::driver::tests::{code, create_body, grant, methods, world, World, FIRST_ID};
use crate::driver::Noted;
use crate::token::{Admitted, Verified};

const DESK: &str = "discover-0b3d5f7a";
const IMAGE_DIGEST: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// A grant whose discovery window lists the test image and `github`, and
/// ends `minutes` from now.
fn window_grant(minutes: i64) -> Value {
    let mut g = grant();
    g["discovery"] = json!({
        "image_digests": [IMAGE_DIGEST],
        "providers": ["github"],
        "name_prefix": "discover-",
        "expires_at": (Utc::now() + chrono::Duration::minutes(minutes))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    });
    g
}

/// The `n`th operation, under `g`.
fn as_op(g: &Value, n: u64) -> Admitted {
    Verified::for_tests_as(Some(g.clone()), &format!("00000000-0000-5000-8000-{n:012}"))
        .admit()
        .unwrap()
}

fn mode(m: &str) -> ApprovalModeBody {
    ApprovalModeBody { mode: m.into() }
}

/// A world with the discovery desk `name` made through the adapter's own
/// create (an EKKA desk, the test image, `github`), and fast evidence
/// timings.
async fn desk_world(name: &str) -> World {
    let mut w = world().await;
    w.b.evidence = EvidenceTimings {
        poll: Duration::from_millis(20),
        quiet: Duration::from_millis(150),
        give_up: Duration::from_secs(3),
    };
    let made =
        w.b.create(
            &as_op(&grant(), 900),
            &create_body(json!({ "name": name })),
            &Noted,
        )
        .await;
    assert_eq!(made.outcome, Outcome::Ready, "{made:?}");
    w.gw.lock().unwrap().calls.clear();
    // The create filed the desk's first pin; only what comes after counts.
    let mut enc = w.enc.lock().unwrap();
    assert_eq!(enc.repins.len(), 1);
    enc.repins.clear();
    enc.seen.clear();
    drop(enc);
    w
}

fn permit_path(w: &World) -> std::path::PathBuf {
    w.b.permits.dir().join(format!("{FIRST_ID}.json"))
}

fn sent_modes(w: &World) -> Vec<String> {
    w.gw.lock()
        .unwrap()
        .calls
        .iter()
        .filter_map(|c| {
            c.strip_prefix(&format!(
                "UpdateConfig desks/{DESK} proposal_approval_mode="
            ))
            .map(str::to_string)
        })
        .collect()
}

async fn auto_on(w: &World, n: u64) -> Answer {
    w.b.approval_mode(&as_op(&window_grant(120), n), DESK, &mode("auto"), &Noted)
        .await
}

#[tokio::test]
async fn auto_is_read_back_before_its_permit_is_written() {
    let w = desk_world(DESK).await;
    let path = permit_path(&w);
    // What the permit file was at every change and at the read-back.
    w.gw.lock().unwrap().watch = Some(path.clone());
    let a = auto_on(&w, 1).await;
    assert_eq!(a.outcome, Outcome::Ready, "{a:?}");
    assert_eq!(a.desk.approval_mode.as_deref(), Some("auto"));
    assert_eq!(a.desk.backend_id.as_deref(), Some(FIRST_ID));
    let watched = w.gw.lock().unwrap().watched.clone();
    let rpcs: Vec<&str> = watched.iter().map(|(r, _)| r.as_str()).collect();
    assert_eq!(rpcs, ["UpdateConfig", "GetSandboxConfig"]);
    assert!(
        watched.iter().all(|(_, seen)| seen.is_none()),
        "no permit before the read-back: {watched:?}"
    );
    assert_eq!(sent_modes(&w), ["auto"]);
    // The permit: the gateway's id, never the name; 0640; the window's
    // workspace, the call's operation, at most 60 minutes.
    let meta = std::fs::symlink_metadata(&path).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o640);
    let p: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        p,
        json!({
            "schema": "ekka.backend.discovery_permit/v1",
            "workspace": "desks",
            "sandbox_id": FIRST_ID,
            "desk": DESK,
            "expires_at": a.desk.permit_expires_at.clone().unwrap(),
            "operation_id": "o",
        })
    );
    let ends = crate::constraints::utc(p["expires_at"].as_str().unwrap()).unwrap();
    assert!(ends <= Utc::now() + chrono::Duration::minutes(60));
    assert!(ends > Utc::now() + chrono::Duration::minutes(58));
    // No temporary file is left beside it.
    let left: Vec<_> = std::fs::read_dir(w.b.permits.dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(left, [format!("{FIRST_ID}.json")]);
    // Claimed, and released ready with the desk read back.
    let calls = w.enc.lock().unwrap().calls();
    assert_eq!(calls[0].0, "runner_desk_claim");
    assert_eq!(calls[1].0, "runner_desk_release");
    // Released with no read-back: the desk's pins stay as they were.
    assert_eq!(
        calls[1].1,
        json!({ "desk": DESK, "operation_id": "00000000-0000-5000-8000-000000000001", "outcome": "refused" })
    );
    assert!(w.enc.lock().unwrap().repins.is_empty());
}

/// A window that ends before the 60 minutes: the permit ends with it.
#[tokio::test]
async fn a_permit_never_outlives_its_window() {
    let w = desk_world(DESK).await;
    let g = window_grant(10);
    let a =
        w.b.approval_mode(&as_op(&g, 1), DESK, &mode("auto"), &Noted)
            .await;
    assert_eq!(a.outcome, Outcome::Ready, "{a:?}");
    let ends = crate::constraints::utc(a.desk.permit_expires_at.as_deref().unwrap()).unwrap();
    let window = crate::constraints::utc(g["discovery"]["expires_at"].as_str().unwrap()).unwrap();
    assert!(ends <= window);
    assert!(ends > Utc::now() + chrono::Duration::minutes(9));
}

/// Each rule of the discovery check, planted one at a time: refused by its
/// code, with no setting sent and no permit written. The check reads the
/// signed grant and the desk as the backend holds it, nothing else.
#[tokio::test]
async fn each_discovery_rule_refuses_auto_with_nothing_sent() {
    type Plant = Box<dyn Fn(&mut Value, &World)>;
    let cases: Vec<(&str, &str, Code, Plant)> = vec![
        (
            "no window in the grant",
            DESK,
            Code::DeskNotDiscovery,
            Box::new(|g, _| {
                g.as_object_mut().unwrap().remove("discovery");
            }),
        ),
        (
            "a window that has ended",
            DESK,
            Code::DiscoveryWindowClosed,
            Box::new(|g, _| {
                g["discovery"]["expires_at"] = json!((Utc::now() - chrono::Duration::minutes(1))
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
            }),
        ),
        (
            "a desk without the prefix",
            "code-desk",
            Code::DeskNotDiscovery,
            Box::new(|_, _| {}),
        ),
        (
            "an image outside the window",
            DESK,
            Code::DeskNotDiscovery,
            Box::new(|g, _| {
                g["discovery"]["image_digests"] = json!([format!("sha256:{}", "b".repeat(64))]);
            }),
        ),
        (
            "a provider outside the window",
            DESK,
            Code::DeskNotDiscovery,
            Box::new(|g, _| g["discovery"]["providers"] = json!([])),
        ),
        (
            "a sandbox that is not an EKKA desk",
            DESK,
            Code::DeskNotDiscovery,
            Box::new(|_, w| {
                w.gw.lock()
                    .unwrap()
                    .sandboxes
                    .get_mut(DESK)
                    .unwrap()
                    .metadata
                    .as_mut()
                    .unwrap()
                    .labels
                    .remove(crate::driver::DESK_LABEL);
            }),
        ),
    ];
    for (why, desk, want, plant) in cases {
        let w = desk_world(desk).await;
        let mut g = window_grant(120);
        plant(&mut g, &w);
        let a =
            w.b.approval_mode(&as_op(&g, 1), desk, &mode("auto"), &Noted)
                .await;
        assert_eq!(code(&a), Some(want), "{why}: {a:?}");
        let calls = w.gw.lock().unwrap().calls.clone();
        assert!(
            !calls.iter().any(|c| c.starts_with("UpdateConfig")),
            "{why}: {calls:?}"
        );
        assert!(!permit_path(&w).exists(), "{why}");
        // A claim taken is released `refused`: the desk is free again.
        let enc = w.enc.lock().unwrap();
        assert!(enc.held.is_empty(), "{why}");
    }
}

/// The body carries the mode and nothing else: a window in a request body
/// is refused before anything, never read.
#[test]
fn a_body_naming_more_than_the_mode_is_refused() {
    let b = br#"{"mode":"auto","discovery":{"image_digests":[],"providers":[]}}"#;
    assert_eq!(
        crate::enforce::body::<ApprovalModeBody>(b).unwrap_err(),
        Code::FieldNotAllowed
    );
}

/// The read-back is not `auto`: refused APPROVAL_MODE_NOT_APPLIED, `manual`
/// sent back, and NO PERMIT.
#[tokio::test]
async fn a_read_back_that_is_not_auto_writes_no_permit() {
    let w = desk_world(DESK).await;
    w.gw.lock().unwrap().ignore_settings = true;
    let a = auto_on(&w, 1).await;
    assert_eq!(code(&a), Some(Code::ApprovalModeNotApplied), "{a:?}");
    assert!(!permit_path(&w).exists());
    assert_eq!(sent_modes(&w), ["auto", "manual"]);
    assert!(w.enc.lock().unwrap().held.is_empty());
}

/// The gateway refuses the setting: refused, no permit.
#[tokio::test]
async fn a_refused_setting_writes_no_permit() {
    let w = desk_world(DESK).await;
    w.gw.lock().unwrap().faults.answer.insert(
        "UpdateConfig".into(),
        Planted::Refused {
            code: tonic::Code::PermissionDenied,
            reason: None,
        },
    );
    let a = auto_on(&w, 1).await;
    assert_eq!(code(&a), Some(Code::BackendRefused), "{a:?}");
    assert!(!permit_path(&w).exists());
}

/// A permits folder that cannot be written: `auto` goes back to `manual`
/// and is refused.
#[tokio::test]
async fn a_permit_that_cannot_be_written_undoes_auto() {
    let w = desk_world(DESK).await;
    let dir = w.b.permits.dir().to_path_buf();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o550)).unwrap();
    let a = auto_on(&w, 1).await;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750)).unwrap();
    assert_eq!(code(&a), Some(Code::BackendUnavailable), "{a:?}");
    assert!(!permit_path(&w).exists());
    assert_eq!(sent_modes(&w), ["auto", "manual"]);
    assert_eq!(
        w.gw.lock().unwrap().settings[DESK]["proposal_approval_mode"],
        "manual"
    );
}

/// `manual` removes the permit BEFORE the setting is sent.
#[tokio::test]
async fn manual_removes_the_permit_before_the_setting() {
    let w = desk_world(DESK).await;
    assert_eq!(auto_on(&w, 1).await.outcome, Outcome::Ready);
    let path = permit_path(&w);
    assert!(path.exists());
    w.gw.lock().unwrap().watch = Some(path.clone());
    let a =
        w.b.approval_mode(&as_op(&grant(), 2), DESK, &mode("manual"), &Noted)
            .await;
    assert_eq!(a.outcome, Outcome::Ready, "{a:?}");
    assert_eq!(a.desk.approval_mode.as_deref(), Some("manual"));
    assert!(a.desk.permit_expires_at.is_none());
    let watched = w.gw.lock().unwrap().watched.clone();
    assert_eq!(watched[0].0, "UpdateConfig");
    assert!(
        watched.iter().all(|(_, seen)| seen.is_none()),
        "{watched:?}"
    );
    assert!(!path.exists());
    assert_eq!(sent_modes(&w), ["auto", "manual"]);
}

/// The permit goes even when the setting call then fails, and even when the
/// desk is busy and nothing is sent at all.
#[tokio::test]
async fn manual_removes_the_permit_even_when_the_setting_fails() {
    let w = desk_world(DESK).await;
    assert_eq!(auto_on(&w, 1).await.outcome, Outcome::Ready);
    w.gw.lock().unwrap().faults.answer.insert(
        "UpdateConfig".into(),
        Planted::Refused {
            code: tonic::Code::Internal,
            reason: None,
        },
    );
    let a =
        w.b.approval_mode(&as_op(&grant(), 2), DESK, &mode("manual"), &Noted)
            .await;
    assert_eq!(a.outcome, Outcome::Refused, "{a:?}");
    assert!(!permit_path(&w).exists());

    let w = desk_world(DESK).await;
    assert_eq!(auto_on(&w, 1).await.outcome, Outcome::Ready);
    w.enc.lock().unwrap().busy.insert(DESK.into());
    let a =
        w.b.approval_mode(&as_op(&grant(), 2), DESK, &mode("manual"), &Noted)
            .await;
    assert_eq!(code(&a), Some(Code::DeskBusy), "{a:?}");
    assert!(!permit_path(&w).exists());
}

/// A delete removes the desk's permit before the delete is sent.
#[tokio::test]
async fn a_delete_removes_the_permit_first() {
    let w = desk_world(DESK).await;
    assert_eq!(auto_on(&w, 1).await.outcome, Outcome::Ready);
    let path = permit_path(&w);
    w.gw.lock().unwrap().watch = Some(path.clone());
    let a = w.b.delete(&as_op(&grant(), 2), DESK, &Noted).await;
    assert_eq!(a.outcome, Outcome::Ready, "{a:?}");
    let watched = w.gw.lock().unwrap().watched.clone();
    assert_eq!(watched[0], ("DeleteSandbox".to_string(), None));
    assert!(!path.exists());
}

/// RECOVERY never turns `auto` on: a stored `auto` still running is undone
/// to `manual`, its permit removed, and settles APPROVAL_MODE_NOT_APPLIED.
#[tokio::test]
async fn a_recovered_auto_ends_manual_with_no_permit() {
    let w = desk_world(DESK).await;
    assert_eq!(auto_on(&w, 1).await.outcome, Outcome::Ready);
    w.enc
        .lock()
        .unwrap()
        .held
        .insert(DESK.into(), crate::driver::tests::RID.into());
    let a = Verified::for_tests(Some(window_grant(120)))
        .admit()
        .unwrap();
    let r =
        w.b.reissue(
            &a,
            &Noted,
            crate::routes::Operation::ApprovalMode,
            DESK,
            None,
            br#"{"mode":"auto"}"#,
            None,
        )
        .await;
    assert_eq!(code(&r), Some(Code::ApprovalModeNotApplied), "{r:?}");
    assert!(!permit_path(&w).exists());
    assert_eq!(sent_modes(&w), ["auto", "manual"]);
    assert_eq!(
        w.gw.lock().unwrap().settings[DESK]["proposal_approval_mode"],
        "manual"
    );
}

#[tokio::test]
async fn evidence_is_refused_for_a_desk_with_no_permit() {
    let w = desk_world(DESK).await;
    let a = w.b.discovery_evidence(&as_op(&grant(), 1), DESK).await;
    assert_eq!(code(&a), Some(Code::DeskNotDiscovery), "{a:?}");
    let calls = w.gw.lock().unwrap().calls.clone();
    assert!(
        !calls
            .iter()
            .any(|c| c.starts_with("GetDraft") || c.starts_with("GetSandboxLogs")),
        "{calls:?}"
    );
    assert!(methods(&w).is_empty(), "a read takes no claim");
}

fn rule(host: &str, port: u32) -> NetworkPolicyRule {
    NetworkPolicyRule {
        name: host.into(),
        endpoints: vec![NetworkEndpoint {
            host: host.into(),
            port,
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn log(message: &str) -> SandboxLogLine {
    SandboxLogLine {
        message: message.into(),
        ..Default::default()
    }
}

/// The evidence, read once the desk has stopped changing: its policy, the
/// pending proposal (unbound: `binary: null`), the decisions, and only the
/// network log lines, redacted. Its keys are the vendored evidence schema's.
#[tokio::test]
async fn evidence_waits_for_the_desk_to_settle_and_answers_what_it_did() {
    let w = desk_world(DESK).await;
    assert_eq!(auto_on(&w, 1).await.outcome, Outcome::Ready);
    {
        let mut g = w.gw.lock().unwrap();
        g.drafts.insert(
            DESK.into(),
            vec![
                PolicyChunk {
                    id: "c1".into(),
                    status: "pending".into(),
                    proposed_rule: Some(rule("10.0.4.12", 5432)),
                    security_notes: "private_address\ndatabase_port".into(),
                    ..Default::default()
                },
                PolicyChunk {
                    id: "c2".into(),
                    status: "approved".into(),
                    proposed_rule: Some(rule("registry.npmjs.org", 443)),
                    binary: "/usr/bin/node".into(),
                    ..Default::default()
                },
            ],
        );
        g.history.insert(
            DESK.into(),
            vec![DraftHistoryEntry {
                event_type: "approved".into(),
                chunk_id: "c2".into(),
                ..Default::default()
            }],
        );
        g.logs.insert(
            DESK.into(),
            vec![
                log("OCSF NET: DENIED /usr/bin/node -> 10.0.4.12:5432"),
                log("supervisor started"),
                log("OCSF HTTP: ALLOWED /usr/bin/node GET https://registry.npmjs.org/x?token=s3cr3t-value Authorization: Bearer abc.def"),
            ],
        );
        // The desk is still proposing for the first reads.
        g.draft_churn = 3;
    }
    let a = w.b.discovery_evidence(&as_op(&grant(), 2), DESK).await;
    assert_eq!(a.outcome, Outcome::Ready, "{a:?}");
    let e = a.desk.evidence.clone().unwrap();
    assert_eq!(e["settled"], true, "{e}");
    assert_eq!(e["sandbox_id"], FIRST_ID);
    assert_eq!(e["desk"], DESK);
    assert_eq!(e["image_digest"], IMAGE_DIGEST);
    assert_eq!(
        e["policy_digest"],
        crate::digest_cmd::policy_digest(&crate::driver::tests::policy()).unwrap()
    );
    assert_eq!(e["active_version"], 1);
    let pending = e["drafts_pending"].as_array().unwrap();
    let real = pending.iter().find(|p| p["host"] == "10.0.4.12").unwrap();
    assert_eq!(real["port"], 5432);
    assert_eq!(real["binary"], Value::Null);
    assert_eq!(real["risk"], json!(["private_address", "database_port"]));
    assert_eq!(real["chunk"]["endpoints"][0]["host"], "10.0.4.12");
    assert_eq!(
        e["drafts_decided"],
        json!([{ "chunk": { "name": "registry.npmjs.org", "endpoints": [{ "host": "registry.npmjs.org", "port": 443 }] }, "decision": "approved", "by": "auto" }])
    );
    let lines = e["network_log"].as_array().unwrap();
    assert_eq!(lines.len(), 2, "{lines:?}");
    let http = lines[1].as_str().unwrap();
    assert!(!http.contains("s3cr3t"), "{http}");
    assert!(!http.contains("abc.def"), "{http}");
    assert!(
        http.contains("https://registry.npmjs.org/x?[REDACTED]"),
        "{http}"
    );
    // The keys are exactly the vendored schema's, every one required.
    let schema: Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vendor/contracts/backend/discovery-evidence.v1.schema.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let mut want: Vec<&str> = schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    want.sort_unstable();
    let mut got: Vec<&str> = e.as_object().unwrap().keys().map(String::as_str).collect();
    got.sort_unstable();
    assert_eq!(got, want);
    assert_eq!(e["schema"], schema["properties"]["schema"]["const"]);
    for (list, item) in [
        ("drafts_pending", &pending[0]),
        ("drafts_decided", &e["drafts_decided"][0]),
    ] {
        let mut want: Vec<&str> = schema["properties"][list]["items"]["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        want.sort_unstable();
        let mut got: Vec<&str> = item
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        got.sort_unstable();
        assert_eq!(got, want, "{list}");
    }
    // A read: no claim, nothing changed.
    assert_eq!(methods(&w), ["runner_desk_claim", "runner_desk_release"]);
}

/// A desk still proposing at `give_up`: answered with `settled: false`.
#[tokio::test]
async fn evidence_gives_up_on_a_desk_that_never_settles() {
    let mut w = desk_world(DESK).await;
    assert_eq!(auto_on(&w, 1).await.outcome, Outcome::Ready);
    w.b.evidence.give_up = Duration::from_millis(400);
    w.gw.lock().unwrap().draft_churn = usize::MAX;
    let started = std::time::Instant::now();
    let a = w.b.discovery_evidence(&as_op(&grant(), 2), DESK).await;
    assert_eq!(a.outcome, Outcome::Ready, "{a:?}");
    let e = a.desk.evidence.unwrap();
    assert_eq!(e["settled"], false);
    assert_eq!(e["settle_seconds"], 0);
    assert!(started.elapsed() < Duration::from_secs(3));
}

/// The give-up is never past the call's own settle window: the server
/// would answer for it first.
#[tokio::test]
async fn evidence_gives_up_within_the_calls_deadline() {
    let mut w = desk_world(DESK).await;
    assert_eq!(auto_on(&w, 1).await.outcome, Outcome::Ready);
    w.b.evidence.give_up = Duration::from_secs(300);
    w.b.settle_for = Duration::from_millis(400);
    w.gw.lock().unwrap().draft_churn = usize::MAX;
    let started = std::time::Instant::now();
    let a = w.b.discovery_evidence(&as_op(&grant(), 2), DESK).await;
    assert_eq!(a.desk.evidence.unwrap()["settled"], false);
    assert!(started.elapsed() < Duration::from_secs(3));
}

/// THE BOUNDS: at most 2000 lines of at most 400 characters, newest kept,
/// and the whole document within 256 KiB.
#[tokio::test]
async fn evidence_stays_within_its_bounds() {
    let w = desk_world(DESK).await;
    assert_eq!(auto_on(&w, 1).await.outcome, Outcome::Ready);
    let lines: Vec<SandboxLogLine> = (0..2500)
        .map(|i| log(&format!("OCSF NET: line {i:05} {}", "x".repeat(600))))
        .collect();
    w.gw.lock().unwrap().logs.insert(DESK.into(), lines);
    let a = w.b.discovery_evidence(&as_op(&grant(), 2), DESK).await;
    let e = a.desk.evidence.unwrap();
    assert!(serde_json::to_vec(&e).unwrap().len() <= EVIDENCE_MAX_BYTES);
    let kept = e["network_log"].as_array().unwrap();
    assert!(!kept.is_empty() && kept.len() <= LOG_LINES);
    assert!(kept
        .iter()
        .all(|l| l.as_str().unwrap().chars().count() <= LOG_LINE_CHARS));
    // The newest line is kept; lines are left out from the oldest.
    assert!(kept
        .last()
        .unwrap()
        .as_str()
        .unwrap()
        .contains("line 02499"));
    assert_eq!(w.gw.lock().unwrap().log_reads, [2000]);
    // A full 2000 short lines fit whole.
    let w = desk_world(DESK).await;
    assert_eq!(auto_on(&w, 1).await.outcome, Outcome::Ready);
    let lines: Vec<SandboxLogLine> = (0..2500).map(|i| log(&format!("OCSF NET: {i}"))).collect();
    w.gw.lock().unwrap().logs.insert(DESK.into(), lines);
    let a = w.b.discovery_evidence(&as_op(&grant(), 2), DESK).await;
    let kept = a.desk.evidence.unwrap()["network_log"]
        .as_array()
        .unwrap()
        .len();
    assert_eq!(kept, LOG_LINES);
}

/// The contract's own sample answers are this adapter's answer shape, field
/// for field.
#[test]
fn the_contracts_sample_answers_are_this_answer_shape() {
    for sample in [
        "result.approval-mode-ready.json",
        "result.discovery-evidence-ready.json",
    ] {
        let raw: Value = serde_json::from_str(
            &std::fs::read_to_string(format!(
                "{}/../../vendor/contracts/backend/samples/{sample}",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap(),
        )
        .unwrap();
        let a: Answer = serde_json::from_value(raw.clone()).unwrap();
        assert_eq!(serde_json::to_value(&a).unwrap(), raw, "{sample}");
    }
}

/// TURNING AUTO OFF NEVER BLESSES THE WIDENED WALL. A discovery run widened
/// the desk's live policy (an automatic approval merged a rule); `manual`,
/// and a recovered change toward it, release the claim with no read-back, so
/// the Enclave files no re-pin and its pins still name the policy from
/// before `auto`: work stays refused on the desk until it is deleted.
#[tokio::test]
async fn manual_never_re_pins_the_desk_to_its_widened_policy() {
    let w = desk_world(DESK).await;
    assert_eq!(auto_on(&w, 1).await.outcome, Outcome::Ready);
    let mut widened = crate::driver::tests::policy();
    widened["networkPolicies"]["npm"] = json!({
        "name": "npm",
        "endpoints": [{ "host": "registry.npmjs.org", "port": 443, "enforcement": "NETWORK_ENFORCEMENT_MODE_ENFORCE" }],
        "binaries": [{ "path": "/usr/bin/node" }]
    });
    let widened_digest = crate::digest_cmd::policy_digest(&widened).unwrap();
    w.gw.lock()
        .unwrap()
        .revisions
        .get_mut(DESK)
        .unwrap()
        .push(crate::normalize::message(crate::normalize::POLICY, &widened).unwrap());
    let a =
        w.b.approval_mode(&as_op(&grant(), 2), DESK, &mode("manual"), &Noted)
            .await;
    assert_eq!(a.outcome, Outcome::Ready, "{a:?}");
    // The answer says what the desk is: its widened policy.
    assert_eq!(
        a.desk.policy_digest.as_deref(),
        Some(widened_digest.as_str())
    );
    // The release files no re-pin, to the widened policy or any other.
    {
        let enc = w.enc.lock().unwrap();
        assert!(enc.repins.is_empty(), "{:?}", enc.repins);
        let release = enc.calls().last().unwrap().clone();
        assert_eq!(release.0, "runner_desk_release");
        assert_eq!(release.1["outcome"], "refused");
        assert!(release.1.get("read_back").is_none(), "{release:?}");
        assert!(enc.held.is_empty(), "the desk is free to be deleted");
    }
    // Recovery toward manual: the same.
    w.gw.lock()
        .unwrap()
        .settings
        .get_mut(DESK)
        .unwrap()
        .insert("proposal_approval_mode".into(), "auto".into());
    w.enc
        .lock()
        .unwrap()
        .held
        .insert(DESK.into(), crate::driver::tests::RID.into());
    let r =
        w.b.reissue(
            &Verified::for_tests(Some(grant())).admit().unwrap(),
            &Noted,
            crate::routes::Operation::ApprovalMode,
            DESK,
            None,
            br#"{"mode":"manual"}"#,
            None,
        )
        .await;
    assert_eq!(r.outcome, Outcome::Ready, "{r:?}");
    assert!(w.enc.lock().unwrap().repins.is_empty());
}
