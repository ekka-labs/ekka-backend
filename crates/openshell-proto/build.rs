//! Generates OpenShell's types from the vendored .proto files with protox, a
//! protobuf compiler written in Rust, so the build needs no `protoc` binary
//! and compiles none of OpenShell's Rust code.

// A build script fails a build by panicking: the workspace's no-panic rule is
// for code that ships, which this is not.
#![allow(clippy::panic)]

use prost::Message as _;

fn main() {
    println!("cargo:rerun-if-changed=proto");
    let fds = match protox::compile(["gateway_interceptor.proto", "openshell.proto"], ["proto"]) {
        Ok(fds) => fds,
        Err(e) => panic!("the vendored NVIDIA OpenShell protos do not compile: {e:?}"),
    };
    let Some(out) = std::env::var_os("OUT_DIR") else {
        panic!("cargo did not set OUT_DIR");
    };
    let path = std::path::Path::new(&out).join("openshell_descriptor.bin");
    // The descriptor compiled into the binary carries no source comments. It
    // is only for reflection (the canonical JSON encoding the digests use),
    // which never reads them, and OpenShell's comments would otherwise ship as
    // text in the binary. The generated types below still get their docs.
    let mut shipped = fds.clone();
    for file in &mut shipped.file {
        file.source_code_info = None;
    }
    if let Err(e) = std::fs::write(&path, shipped.encode_to_vec()) {
        panic!("cannot write {}: {e}", path.display());
    }
    if let Err(e) = tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_fds(fds)
    {
        panic!("cannot generate the NVIDIA OpenShell types: {e}");
    }
}
