//! A desk's CPU and memory limit (contracts 0.86.0), from the outside: the create sends it to the gateway, a limit above the
//! grant (or under a grant with none) reaches nothing, and a desk the backend
//! holds with another limit is never answered ready.
use super::*;

/// `{"limits": {"cpu": .., "memory": ..}}`, as the gateway stores a template's `resources`.
fn limits_of(s: &prost_types::Struct) -> Option<(String, String)> {
    use prost_types::value::Kind;
    let text = |v: Option<&prost_types::Value>| match v.and_then(|v| v.kind.as_ref()) {
        Some(Kind::StringValue(s)) => Some(s.clone()),
        _ => None,
    };
    if s.fields.len() != 1 {
        return None;
    }
    let Some(Kind::StructValue(limits)) = s.fields.get("limits").and_then(|v| v.kind.as_ref())
    else {
        return None;
    };
    if limits.fields.len() != 2 {
        return None;
    }
    Some((
        text(limits.fields.get("cpu"))?,
        text(limits.fields.get("memory"))?,
    ))
}

/// The create carries the limit to NVIDIA OpenShell as the template's
/// `resources` limits, and only limits: 2000 millicores as `2000m`, 4096 MiB
/// as `4096Mi`. The ready answer, and a later status, say what the backend
/// holds.
#[tokio::test(flavor = "multi_thread")]
async fn a_create_sends_its_limit_to_the_backend_and_answers_the_limit_it_holds() {
    let mut h = Harness::start().await;
    let body = h.create_body(base_policy());
    let (r, rid) = h.create(&body).await;
    r.assert_ready();
    assert_eq!(h.mutations(), [("CreateSandbox".to_string(), rid)]);
    {
        let g = h.gw.lock().unwrap();
        let template = g.sandboxes[DESK]
            .spec
            .as_ref()
            .unwrap()
            .template
            .as_ref()
            .unwrap();
        let sent = template
            .resources
            .as_ref()
            .expect("the create sent a limit");
        assert_eq!(
            limits_of(sent),
            Some(("2000m".to_string(), "4096Mi".to_string())),
            "{sent:?}"
        );
    }
    let limit = json!({ "cpu_millicores": 2000, "memory_mib": 4096 });
    assert_eq!(r.body["resources"], limit, "{r:?}");
    let s = h.status().await;
    s.assert_ready();
    assert_eq!(s.body["resources"], limit, "{s:?}");
    h.assert_no_secret_shown();
}

/// A create above its grant's `resources`, or under a grant with none, is
/// refused CONSTRAINT_RESOURCES; one with no limit, or one outside the
/// contract's bounds, is refused as the contract's body. Each before any
/// sign-in, gateway call or claim.
#[tokio::test(flavor = "multi_thread")]
async fn a_create_asking_more_than_its_grant_reaches_nothing() {
    let mut h = Harness::start().await;
    let base = h.create_body(base_policy());
    let with = |limit: Value| {
        let mut b = base.clone();
        b["resources"] = limit;
        b
    };
    let without = {
        let mut b = base.clone();
        b.as_object_mut().unwrap().remove("resources");
        b
    };
    let cases = [
        (
            "one millicore over the grant",
            with(json!({ "cpu_millicores": 4001, "memory_mib": 4096 })),
            "CONSTRAINT_RESOURCES",
        ),
        (
            "one MiB over the grant",
            with(json!({ "cpu_millicores": 2000, "memory_mib": 8193 })),
            "CONSTRAINT_RESOURCES",
        ),
        ("no limit at all", without, "REQUEST_INVALID"),
        (
            "below a tenth of a CPU",
            with(json!({ "cpu_millicores": 99, "memory_mib": 4096 })),
            "REQUEST_INVALID",
        ),
        (
            "a fraction",
            with(json!({ "cpu_millicores": 1500.5, "memory_mib": 4096 })),
            "REQUEST_INVALID",
        ),
        (
            "a quantity string",
            with(json!({ "cpu_millicores": 2000, "memory_mib": "4Gi" })),
            "REQUEST_INVALID",
        ),
        (
            "a swap limit, which the contract does not have",
            with(json!({ "cpu_millicores": 2000, "memory_mib": 4096, "memory_swap_mib": 0 })),
            "FIELD_NOT_ALLOWED",
        ),
    ];
    for (why, body, code) in cases {
        let (r, _) = h.create(&body).await;
        r.assert_refused(code);
        assert!(
            h.gateway_calls().is_empty(),
            "{why}: {:?}",
            h.gateway_calls()
        );
        assert!(h.enclave_calls().is_empty(), "{why}");
        assert_eq!(h.mints(), 0, "{why}: no sign-in");
    }
    // The grant's own ceiling is allowed: at most, not below.
    let (r, _) = h
        .create(&with(json!({ "cpu_millicores": 4000, "memory_mib": 8192 })))
        .await;
    r.assert_ready();
    h.assert_no_secret_shown();
}

/// A grant written before contracts 0.86.0 carries no `resources`: it allows
/// no create, whatever the limit asked.
#[tokio::test(flavor = "multi_thread")]
async fn a_grant_without_a_resource_ceiling_allows_no_create() {
    let mut h = Harness::start().await;
    h.grant.as_object_mut().unwrap().remove("resources");
    let body = h.create_body(base_policy());
    let (r, _) = h.create(&body).await;
    r.assert_refused("CONSTRAINT_RESOURCES");
    assert!(h.gateway_calls().is_empty(), "{:?}", h.gateway_calls());
    assert!(h.enclave_calls().is_empty());
    h.assert_no_secret_shown();
}

/// What a gateway does to a created sandbox before it keeps it.
type Rewrite = fn(&mut openshell_proto::openshell::v1::Sandbox);

/// The backend's record of the desk must carry exactly the limit asked. A
/// gateway that keeps another one, or none, made a desk that is not the one
/// approved: `unknown`, released so, never `ready`.
#[tokio::test(flavor = "multi_thread")]
async fn a_desk_the_backend_holds_with_another_limit_is_unknown() {
    let rewrites: [(&str, Rewrite); 3] = [
        ("more memory", |sb| {
            let r = sb.spec.as_mut().unwrap().template.as_mut().unwrap();
            let limits = r
                .resources
                .as_mut()
                .unwrap()
                .fields
                .get_mut("limits")
                .unwrap();
            if let Some(prost_types::value::Kind::StructValue(l)) = limits.kind.as_mut() {
                l.fields.insert(
                    "memory".into(),
                    prost_types::Value {
                        kind: Some(prost_types::value::Kind::StringValue("8192Mi".into())),
                    },
                );
            }
        }),
        ("no limit", |sb| {
            sb.spec
                .as_mut()
                .unwrap()
                .template
                .as_mut()
                .unwrap()
                .resources = None;
        }),
        ("a request beside the limit", |sb| {
            let r = sb.spec.as_mut().unwrap().template.as_mut().unwrap();
            r.resources.as_mut().unwrap().fields.insert(
                "requests".into(),
                prost_types::Value {
                    kind: Some(prost_types::value::Kind::StructValue(prost_types::Struct {
                        fields: [(
                            "cpu".to_string(),
                            prost_types::Value {
                                kind: Some(prost_types::value::Kind::StringValue("500m".into())),
                            },
                        )]
                        .into_iter()
                        .collect(),
                    })),
                },
            );
        }),
    ];
    for (why, rewrite) in rewrites {
        let mut h = Harness::start().await;
        h.gw.lock().unwrap().rewrite_created = Some(rewrite);
        let body = h.create_body(base_policy());
        let (r, _) = h.create(&body).await;
        assert_eq!(r.outcome(), "unknown", "{why}: {r:?}");
        assert!(r.body.get("resources").is_none(), "{why}: {r:?}");
        let calls = h.enclave_calls();
        assert_eq!(calls.last().unwrap().1["outcome"], "unknown", "{why}");
        // A later status reports the limit the backend holds, and a desk
        // holding none, or one the contract cannot state, is never ready.
        let st = h.status().await;
        if why == "more memory" {
            st.assert_ready();
            assert_eq!(
                st.body["resources"],
                json!({ "cpu_millicores": 2000, "memory_mib": 8192 })
            );
        } else {
            assert_eq!(st.outcome(), "unknown", "{why}: {st:?}");
        }
        h.assert_no_secret_shown();
    }
}
