//! Test fakes for `ekka-backend`, in their own crate so the adapter's unit
//! tests and its binary-level tests under `tests/` use ONE copy. A
//! dev-dependency only: the release image builds `-p ekka-backend` without
//! dev-dependencies, so none of this ships.

pub mod fake_enclave;
pub mod fake_gateway;
pub mod fake_issuer;
pub mod faults;
pub mod sandboxes;
