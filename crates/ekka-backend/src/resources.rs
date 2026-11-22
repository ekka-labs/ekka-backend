//! A desk's CPU and memory limit (contracts 0.86.0 `resources`): what a
//! create asks, the most its grant allows, how
//! the limit is sent to NVIDIA OpenShell, and how the backend's record of a
//! desk is read back.
//!
//! SENT AS LIMITS ONLY. A create sends `SandboxTemplate.resources` =
//! `{"limits": {"cpu": "<cpu_millicores>m", "memory": "<memory_mib>Mi"}}`.
//! NVIDIA OpenShell v0.1.9 turns those two keys into the driver's
//! `cpu_limit` and `memory_limit` (`openshell-server` `compute/mod.rs`
//! `extract_typed_resources`), and its Docker driver sets the sandbox
//! container's `NanoCpus` and `Memory` from them (`openshell-driver-docker`
//! `docker_resource_limits`). It refuses a `requests` value, so none is sent.
//!
//! READ BACK EXACTLY. The backend's record is read as the same two whole
//! numbers, or not at all: another key, a request, a fraction or a value that
//! is not a whole MiB is a limit this contract cannot state, and a create
//! whose desk holds one is `unknown`. This is the backend's RECORD of the
//! desk; the kernel's own values are read by the Enclave, on the machine,
//! before any work starts on the desk.

use std::ops::RangeInclusive;

use prost_types::value::Kind;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// `cpu_millicores`: a tenth of a CPU to 256 CPUs (contracts 0.86.0).
pub(crate) const CPU_MILLICORES: RangeInclusive<u64> = 100..=256_000;
/// `memory_mib`: 256 MiB to 4 TiB (contracts 0.86.0).
pub(crate) const MEMORY_MIB: RangeInclusive<u64> = 256..=4_194_304;

/// A desk's limit, as a create asks it and an answer reports it. Closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resources {
    pub cpu_millicores: u64,
    pub memory_mib: u64,
}

/// The most one desk may ask (desks.v1 `resources`). Closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Ceiling {
    pub max_cpu_millicores: u64,
    pub max_memory_mib: u64,
}

impl Ceiling {
    /// The schema's bounds, which a grant's ceiling keeps too.
    pub(crate) fn in_bounds(&self) -> bool {
        CPU_MILLICORES.contains(&self.max_cpu_millicores)
            && MEMORY_MIB.contains(&self.max_memory_mib)
    }
}

impl Resources {
    /// Inside the contract's bounds.
    pub(crate) fn in_bounds(&self) -> bool {
        CPU_MILLICORES.contains(&self.cpu_millicores) && MEMORY_MIB.contains(&self.memory_mib)
    }

    /// At most the ceiling, each value.
    pub(crate) fn within(&self, c: &Ceiling) -> bool {
        self.cpu_millicores <= c.max_cpu_millicores && self.memory_mib <= c.max_memory_mib
    }

    /// The template's `resources` a create sends: limits only.
    pub(crate) fn template(&self) -> prost_types::Struct {
        let text = |s: String| prost_types::Value {
            kind: Some(Kind::StringValue(s)),
        };
        let limits = prost_types::Struct {
            fields: [
                ("cpu".to_string(), text(format!("{}m", self.cpu_millicores))),
                ("memory".to_string(), text(format!("{}Mi", self.memory_mib))),
            ]
            .into_iter()
            .collect(),
        };
        prost_types::Struct {
            fields: [(
                "limits".to_string(),
                prost_types::Value {
                    kind: Some(Kind::StructValue(limits)),
                },
            )]
            .into_iter()
            .collect(),
        }
    }
}

/// What the backend holds for a desk, read from its template's `resources`
/// in proto JSON (`spec.template.resources`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Held {
    /// No limit: absent or null.
    None,
    /// Exactly a CPU and a memory limit this contract states.
    Limit(Resources),
    /// Anything else: another key, a request, a value it cannot state.
    Other,
}

impl Held {
    /// Read the template's `resources` as proto JSON renders a `Struct`.
    pub(crate) fn read(v: Option<&Value>) -> Self {
        let Some(v) = v.filter(|v| !v.is_null()) else {
            return Self::None;
        };
        let only = |o: &serde_json::Map<String, Value>, keys: &[&str]| {
            o.len() == keys.len() && keys.iter().all(|k| o.contains_key(*k))
        };
        let Some(top) = v.as_object().filter(|o| only(o, &["limits"])) else {
            return Self::Other;
        };
        let Some(limits) = top["limits"]
            .as_object()
            .filter(|o| only(o, &["cpu", "memory"]))
        else {
            return Self::Other;
        };
        let (Some(cpu), Some(memory)) = (
            limits["cpu"].as_str().and_then(millicores),
            limits["memory"].as_str().and_then(mebibytes),
        ) else {
            return Self::Other;
        };
        let r = Resources {
            cpu_millicores: cpu,
            memory_mib: memory,
        };
        if r.in_bounds() {
            Self::Limit(r)
        } else {
            Self::Other
        }
    }

    /// The limit, when the backend holds one this contract states.
    pub(crate) fn limit(self) -> Option<Resources> {
        match self {
            Self::Limit(r) => Some(r),
            Self::None | Self::Other => None,
        }
    }
}

/// A `google.protobuf.Struct` as proto JSON renders it: the form
/// [`Held::read`] reads, whichever way the backend's record was reached.
pub(crate) fn json(s: &prost_types::Struct) -> Value {
    fn value(v: &prost_types::Value) -> Value {
        match &v.kind {
            None | Some(Kind::NullValue(_)) => Value::Null,
            Some(Kind::NumberValue(n)) => {
                serde_json::Number::from_f64(*n).map_or(Value::Null, Value::Number)
            }
            Some(Kind::StringValue(s)) => Value::String(s.clone()),
            Some(Kind::BoolValue(b)) => Value::Bool(*b),
            Some(Kind::StructValue(s)) => json(s),
            Some(Kind::ListValue(l)) => Value::Array(l.values.iter().map(value).collect()),
        }
    }
    Value::Object(
        s.fields
            .iter()
            .map(|(k, v)| (k.clone(), value(v)))
            .collect(),
    )
}

/// `<digits>` or `<digits>.<digits>` times `num / den`, when that is exactly
/// a whole number; anything else (a sign, an exponent, a remainder) is `None`.
fn exact(coefficient: &str, num: u128, den: u128) -> Option<u64> {
    let (w, f) = coefficient.split_once('.').unwrap_or((coefficient, ""));
    let digits = |t: &str| t.bytes().all(|b| b.is_ascii_digit());
    if w.is_empty() || !digits(w) || !digits(f) || f.len() > 18 || coefficient.ends_with('.') {
        return None;
    }
    let scale = 10u128.checked_pow(u32::try_from(f.len()).ok()?)?;
    let value: u128 = format!("{w}{f}").parse().ok()?;
    let top = value.checked_mul(num)?;
    let bottom = scale.checked_mul(den)?;
    (top % bottom == 0)
        .then(|| u64::try_from(top / bottom).ok())
        .flatten()
}

/// A Kubernetes-style CPU quantity in thousandths of a CPU: `<n>m`, or CPUs,
/// whole or decimal, that come to whole millicores exactly (`1.5`, `1.5000`).
fn millicores(s: &str) -> Option<u64> {
    match s.strip_suffix('m') {
        Some(m) => exact(m, 1, 1),
        None => exact(s, 1000, 1),
    }
}

/// A Kubernetes-style memory quantity in whole MiB, in any binary or decimal
/// unit NVIDIA OpenShell reads (`4Gi`, `1.5Gi`, `4096Mi`, `4194304Ki`, bytes,
/// or `M`, `G` and the like), when it comes to whole MiB exactly.
fn mebibytes(s: &str) -> Option<u64> {
    const MIB: u128 = 1024 * 1024;
    let units: [(&str, u128); 8] = [
        ("Ki", 1024),
        ("Mi", MIB),
        ("Gi", MIB * 1024),
        ("Ti", MIB * 1024 * 1024),
        ("K", 1_000),
        ("M", 1_000_000),
        ("G", 1_000_000_000),
        ("T", 1_000_000_000_000),
    ];
    for (suffix, bytes) in units {
        if let Some(n) = s.strip_suffix(suffix) {
            return exact(n, bytes, MIB);
        }
    }
    exact(s, 1, MIB)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "resources_tests.rs"]
mod tests;
