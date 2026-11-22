//! The limit's shape on the wire and in the backend's record.

use serde_json::{json, Value};

use super::{Ceiling, Held, Resources};

const ASKED: Resources = Resources {
    cpu_millicores: 2000,
    memory_mib: 4096,
};

fn held(v: Value) -> Held {
    Held::read(Some(&v))
}

/// The create sends limits only, in the two keys NVIDIA OpenShell reads, as
/// whole millicores and whole MiB.
#[test]
fn a_create_sends_cpu_and_memory_limits_and_nothing_else() {
    let s = ASKED.template();
    let json = super::json(&s);
    assert_eq!(
        json,
        json!({ "limits": { "cpu": "2000m", "memory": "4096Mi" } })
    );
    assert_eq!(held(json), Held::Limit(ASKED));
}

/// The backend's record is read as the same two whole numbers in any
/// spelling the gateway might keep, and as nothing it cannot state.
#[test]
fn the_backends_record_is_read_exactly_or_not_at_all() {
    for (spelled, why) in [
        (
            json!({ "limits": { "cpu": "2", "memory": "4Gi" } }),
            "whole CPUs and GiB",
        ),
        (
            json!({ "limits": { "cpu": "2000m", "memory": "4294967296" } }),
            "bytes",
        ),
    ] {
        assert_eq!(held(spelled), Held::Limit(ASKED), "{why}");
    }
    assert_eq!(Held::read(None), Held::None);
    assert_eq!(Held::read(Some(&Value::Null)), Held::None);
    for (v, why) in [
        (
            json!({ "limits": { "cpu": "1.5", "memory": "4096Mi" } }),
            "a fraction of a CPU",
        ),
        (
            json!({ "limits": { "cpu": "2000m", "memory": "4G" } }),
            "decimal gigabytes",
        ),
        (
            json!({ "limits": { "cpu": "2000m", "memory": "4294967295" } }),
            "not a whole MiB",
        ),
        (json!({ "limits": { "cpu": "2000m" } }), "no memory"),
        (json!({ "limits": { "memory": "4096Mi" } }), "no CPU"),
        (
            json!({ "limits": { "cpu": "2000m", "memory": "4096Mi", "nvidia.com/gpu": "1" } }),
            "another limit",
        ),
        (
            json!({ "limits": { "cpu": "2000m", "memory": "4096Mi" }, "requests": { "cpu": "500m" } }),
            "a request",
        ),
        (json!({ "cpu": "8" }), "no limits object"),
        (
            json!({ "limits": { "cpu": "-2000m", "memory": "4096Mi" } }),
            "a sign",
        ),
        (
            json!({ "limits": { "cpu": 2000, "memory": "4096Mi" } }),
            "a number, not a quantity",
        ),
        (
            json!({ "limits": { "cpu": "50m", "memory": "4096Mi" } }),
            "below the contract's bounds",
        ),
        (json!([]), "not an object"),
    ] {
        assert_eq!(held(v), Held::Other, "{why}");
    }
}

/// At most the ceiling, each value; the ceiling itself is allowed.
#[test]
fn a_limit_is_at_most_its_grants_ceiling() {
    let c = Ceiling {
        max_cpu_millicores: 4000,
        max_memory_mib: 8192,
    };
    assert!(ASKED.within(&c));
    let at = Resources {
        cpu_millicores: 4000,
        memory_mib: 8192,
    };
    assert!(at.within(&c));
    assert!(!Resources {
        cpu_millicores: 4001,
        ..at
    }
    .within(&c));
    assert!(!Resources {
        memory_mib: 8193,
        ..at
    }
    .within(&c));
}

/// The contract's bounds: a tenth of a CPU to 256 CPUs, 256 MiB to 4 TiB.
#[test]
fn the_bounds_are_the_contracts() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vendor/contracts/backend/backend-v1.schema.json"
    );
    let s: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let p = &s["$defs"]["resources"]["properties"];
    assert_eq!(
        p["cpu_millicores"]["minimum"],
        *super::CPU_MILLICORES.start()
    );
    assert_eq!(p["cpu_millicores"]["maximum"], *super::CPU_MILLICORES.end());
    assert_eq!(p["memory_mib"]["minimum"], *super::MEMORY_MIB.start());
    assert_eq!(p["memory_mib"]["maximum"], *super::MEMORY_MIB.end());
    assert_eq!(s["$defs"]["resources"]["additionalProperties"], false);
    assert!(Resources {
        cpu_millicores: 100,
        memory_mib: 256
    }
    .in_bounds());
    assert!(!Resources {
        cpu_millicores: 99,
        memory_mib: 256
    }
    .in_bounds());
    assert!(!Resources {
        cpu_millicores: 100,
        memory_mib: 4_194_305
    }
    .in_bounds());
}
