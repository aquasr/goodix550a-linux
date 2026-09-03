//! Standalone Rust support for the Goodix 27c6:550a / GF3258 WN2 sensor.
//!
//! Reusable algorithm modules expose concrete domain errors. Driver
//! verification uses an opaque validated gallery rather than caller-assembled
//! matcher policy state. Executable command handling lives in the doc-hidden
//! [`app`] module because Cargo binary targets are separate crates.
//! Validation fixture plumbing is likewise feature-gated and doc-hidden.

#[doc(hidden)]
pub mod app;

mod bootstrap;
mod chicago_h;
mod crypto;
mod device;
pub mod driver;
pub mod enrollment;
mod enrollment_add;
mod enrollment_graph;
mod fdt;
pub mod feature;
mod feature_enrollment;
pub mod firmware;
pub mod firmware_auth;
pub mod image;
pub mod libfprint;
pub mod libfprint_wire;
#[cfg(test)]
mod persistence_capture;
pub mod preprocess;
mod protocol;
mod registration;
mod template_decode;
mod template_persistence;
mod template_storage;
mod trace;
mod transport;
#[cfg(feature = "validation-tools")]
#[doc(hidden)]
pub mod validation_support;
pub mod verification;
