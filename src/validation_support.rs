//! Shared support for offline validation tools.
//!
//! This module is compiled only with the `validation-tools` feature. It keeps
//! fixture discovery and binary fixture I/O consistent across the parity
//! executables without adding those concerns to the production build.

use std::{
    env,
    ffi::OsString,
    fs, io,
    path::{Path, PathBuf},
};

const VALIDATION_ROOT_ENV: &str = "GOODIX_VALIDATION_ROOT";
const DEFAULT_VALIDATION_ROOT: &str = "../traces/validation";

/// Resolve the validation fixture root.
///
/// Precedence is explicit CLI argument, `GOODIX_VALIDATION_ROOT`, then the
/// repository-relative `../traces/validation` default.
pub fn validation_root(argument: Option<OsString>) -> PathBuf {
    argument
        .map(PathBuf::from)
        .or_else(|| env::var_os(VALIDATION_ROOT_ENV).map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_VALIDATION_ROOT))
}

pub fn read_exact(path: &Path, expected_bytes: usize) -> io::Result<Vec<u8>> {
    let bytes = fs::read(path)?;
    if bytes.len() != expected_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{}: expected {} bytes, found {}",
                path.display(),
                expected_bytes,
                bytes.len()
            ),
        ));
    }
    Ok(bytes)
}

pub fn read_i32_le(path: &Path, expected_values: usize) -> io::Result<Vec<i32>> {
    Ok(read_exact(path, expected_values * 4)?
        .chunks_exact(4)
        .map(|b| i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .collect())
}

pub fn read_u16_le(path: &Path, expected_values: usize) -> io::Result<Vec<u16>> {
    Ok(read_exact(path, expected_values * 2)?
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect())
}

pub fn read_u32_le(path: &Path, expected_values: usize) -> io::Result<Vec<u32>> {
    Ok(read_exact(path, expected_values * 4)?
        .chunks_exact(4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .collect())
}

pub fn write_i32_le(path: &Path, values: &[i32]) -> io::Result<()> {
    let mut bytes = Vec::with_capacity(values.len() * 4);
    for &value in values {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    fs::write(path, bytes)
}

pub fn write_u16_le(path: &Path, values: &[u16]) -> io::Result<()> {
    let mut bytes = Vec::with_capacity(values.len() * 2);
    for &value in values {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    fs::write(path, bytes)
}

pub fn write_u32_le(path: &Path, values: &[u32]) -> io::Result<()> {
    let mut bytes = Vec::with_capacity(values.len() * 4);
    for &value in values {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    fs::write(path, bytes)
}

pub fn byte_mismatches(actual: &[u8], expected: &[u8]) -> Vec<(usize, u8, u8)> {
    actual
        .iter()
        .zip(expected)
        .enumerate()
        .filter_map(|(index, (&a, &e))| (a != e).then_some((index, a, e)))
        .collect()
}

pub fn u32_mismatches(actual: &[u32], expected: &[u32]) -> Vec<(usize, u32, u32)> {
    actual
        .iter()
        .zip(expected)
        .enumerate()
        .filter_map(|(index, (&a, &e))| (a != e).then_some((index, a, e)))
        .collect()
}
