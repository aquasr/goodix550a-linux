//! Executable adapters for the project binaries.
//!
//! This module is public only because Cargo binary targets are separate crates
//! and must call through the library crate. It is not the reusable driver API.
//! Domain/library code should not depend on `app`.

mod cli;
mod error;
mod standalone_enroll;
mod standalone_verify;

use std::os::unix::fs::MetadataExt;

pub use error::{AppError, AppErrorKind, AppResult};

/// Refuse to open the sensor from an elevated standalone process.
///
/// libfprint owns its own service boundary and does not call this application
/// helper. It applies only to repository binaries and diagnostic probes.
pub fn require_unprivileged_hardware_access() -> AppResult<()> {
    let elevated = std::env::var_os("SUDO_UID").is_some()
        || std::env::var_os("PKEXEC_UID").is_some()
        || std::fs::metadata("/proc/self").is_ok_and(|metadata| metadata.uid() == 0);

    if elevated {
        return Err(AppError::invalid_input(
            "refusing to access the fingerprint reader as root; install the packaged udev rule, stop fprintd from a separate administrative terminal, and run this executable as the logged-in user",
        )
        .into());
    }

    Ok(())
}

pub fn run_cli() -> AppResult<()> {
    cli::run()
}

pub fn run_standalone_enroll() -> AppResult<()> {
    standalone_enroll::run()
}

pub fn run_standalone_verify() -> AppResult<()> {
    standalone_verify::run()
}
