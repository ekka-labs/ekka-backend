#![allow(clippy::unwrap_used, clippy::expect_used)]

use prost_reflect::{DescriptorPool, DynamicMessage};

#[test]
fn the_descriptor_set_names_the_types_the_adapter_reads() {
    let pool = DescriptorPool::decode(super::FILE_DESCRIPTOR_SET).unwrap();
    for name in [
        "openshell.sandbox.v1.SandboxPolicy",
        "openshell.v1.SandboxTemplate",
        "openshell.v1.CreateSandboxRequest",
        "openshell.v1.SandboxResponse",
        "openshell.v1.DeleteSandboxResponse",
        "openshell.gateway_interceptor.v1.InterceptorEvaluation",
    ] {
        assert!(pool.get_message_by_name(name).is_some(), "{name} missing");
    }
    let d = pool
        .get_message_by_name("openshell.sandbox.v1.SandboxPolicy")
        .unwrap();
    let m = DynamicMessage::deserialize(
        d,
        serde_json::json!({ "version": 1, "filesystem": { "readOnly": ["/work"] } }),
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(&m).unwrap(),
        serde_json::json!({ "version": 1, "filesystem": { "readOnly": ["/work"] } })
    );
}

#[test]
fn the_gateway_interceptor_service_and_the_openshell_client_are_generated() {
    use super::openshell::gateway_interceptor::v1::gateway_interceptor_server::GatewayInterceptorServer;
    use super::openshell::v1::open_shell_client::OpenShellClient;
    let _server = GatewayInterceptorServer::<()>::new;
    let _client = OpenShellClient::<tonic::transport::Channel>::new;
}
