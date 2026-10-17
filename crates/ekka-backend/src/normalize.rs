//! One canonical form for an OpenShell message, as the contract defines a
//! policy's digest: the form the adapter digests a policy in, and the form
//! `ekka-backend digest` prints.
//!
//! The gateway decodes our patched operation into its protobuf type and
//! re-encodes it before the validate phase. Defaults written or left out, an
//! enum by number or by name, a 64-bit number as a string or not: all can
//! differ from the JSON Govern produced. NVIDIA's own governance example says
//! its signed hash and the gateway's are not expected to match for this
//! reason. So both sides go through the same step: decode as the vendored
//! message type, re-encode with fixed options, then hash. A field the pinned
//! proto does not know is refused, never dropped.

use std::sync::OnceLock;

use prost_reflect::{DescriptorPool, DynamicMessage, SerializeOptions};
use serde_json::Value;

use crate::digest::json_digest;

/// The sandbox policy, as OpenShell's gateway types it.
pub const POLICY: &str = "openshell.sandbox.v1.SandboxPolicy";
/// The sandbox template (image, runtime class, environment): the normalize
/// tests read it.
#[cfg(test)]
pub const TEMPLATE: &str = "openshell.v1.SandboxTemplate";
/// A sandbox as the gateway reports it: the post-write comparison reads it.
pub const SANDBOX: &str = "openshell.v1.Sandbox";
/// A provider profile: which hosts a kind of credential is injected at, for
/// which programs.
pub const PROVIDER_PROFILE: &str = "openshell.v1.ProviderProfile";

fn pool() -> Option<&'static DescriptorPool> {
    static POOL: OnceLock<Option<DescriptorPool>> = OnceLock::new();
    POOL.get_or_init(|| DescriptorPool::decode(openshell_proto::FILE_DESCRIPTOR_SET).ok())
        .as_ref()
}

/// `v` decoded as `type_name` and written back in one fixed form: proto3 JSON
/// names, defaults left out, enums by name. `None` when `v` is not a valid
/// message of that type, including any field the pinned proto does not have.
#[must_use]
pub fn canonical(type_name: &str, v: &Value) -> Option<Value> {
    let descriptor = pool()?.get_message_by_name(type_name)?;
    let message = DynamicMessage::deserialize(descriptor, v.clone()).ok()?;
    message
        .serialize_with_options(serde_json::value::Serializer, &SerializeOptions::new())
        .ok()
}

/// `sha256:<hex>` of the canonical form; `None` when `v` is not a valid
/// message of that type.
#[must_use]
pub fn digest(type_name: &str, v: &Value) -> Option<String> {
    canonical(type_name, v).map(|c| json_digest(&c))
}

/// `v` decoded as `type_name` into its generated type, by the same decode
/// the digest uses, so the message an executor sends is the message whose
/// digest was authorized. `None` when `v` is not a valid message of that type.
#[must_use]
pub fn message<T: prost::Message + Default>(type_name: &str, v: &Value) -> Option<T> {
    let descriptor = pool()?.get_message_by_name(type_name)?;
    DynamicMessage::deserialize(descriptor, v.clone())
        .ok()?
        .transcode_to::<T>()
        .ok()
}

/// The digest of a message the gateway returned, in the same canonical form
/// as [`digest`], so what the runtime reports can be compared with what was
/// authorized. Used by `status`.
#[must_use]
pub fn message_digest<T: prost::Message>(type_name: &str, m: &T) -> Option<String> {
    message_json(type_name, m).map(|c| json_digest(&c))
}

/// A typed message in the same canonical JSON form as [`canonical`]: what the
/// gateway's interceptor sees, so a rule written for that JSON can be run on
/// a message a caller holds.
#[must_use]
pub fn message_json<T: prost::Message>(type_name: &str, m: &T) -> Option<Value> {
    let descriptor = pool()?.get_message_by_name(type_name)?;
    let dynamic = DynamicMessage::decode(descriptor, m.encode_to_vec().as_slice()).ok()?;
    dynamic
        .serialize_with_options(serde_json::value::Serializer, &SerializeOptions::new())
        .ok()
}

#[cfg(test)]
#[path = "normalize_tests.rs"]
mod tests;
