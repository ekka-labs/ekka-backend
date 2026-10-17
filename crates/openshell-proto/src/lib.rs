//! NVIDIA OpenShell's gRPC types, for the OpenShell client the adapter calls.
//!
//! Every type here is generated at build time from OpenShell's own .proto
//! files, vendored byte for byte at ONE pinned commit (5a7728c, v0.1.4). No
//! OpenShell Rust code is compiled. The vendored files are never edited by
//! hand: `ci/openshell-proto-is-vendored.sh` holds the commit and the hash of
//! every file, and refuses any other bytes. A new OpenShell version is a new
//! pin: copy the files from that commit, and update the gate's commit and
//! hashes in the same change.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

/// The generated code, as protox and tonic-prost-build emit it.
#[allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    unreachable_pub,
    unused_qualifications
)]
pub mod openshell {
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/openshell.v1.rs"));
    }
    pub mod datamodel {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/openshell.datamodel.v1.rs"));
        }
    }
    pub mod extension {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/openshell.extension.v1.rs"));
        }
    }
    pub mod gateway_interceptor {
        pub mod v1 {
            include!(concat!(
                env!("OUT_DIR"),
                "/openshell.gateway_interceptor.v1.rs"
            ));
        }
    }
    pub mod options {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/openshell.options.v1.rs"));
        }
    }
    pub mod sandbox {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/openshell.sandbox.v1.rs"));
        }
    }
}

/// The compiled descriptor set of every vendored file, for reading and
/// writing OpenShell's protobuf JSON by message name.
pub const FILE_DESCRIPTOR_SET: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/openshell_descriptor.bin"));

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
