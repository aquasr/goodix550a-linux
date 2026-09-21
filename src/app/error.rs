//! Application-layer error classification.
//!
//! Domain code keeps its own concrete error types. The executable adapter
//! only uses [`AppError`] for failures authored by command-line/application
//! policy itself, such as invalid arguments or inconsistent data discovered
//! while assembling a user-facing operation.

use std::{error::Error, fmt};

pub type AppResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppErrorKind {
    InvalidInput,
    InvalidData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppError {
    kind: AppErrorKind,
    message: String,
}

impl AppError {
    #[must_use]
    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self {
            kind: AppErrorKind::InvalidInput,
            message: message.into(),
        }
    }

    #[must_use]
    pub fn invalid_data(message: impl Into<String>) -> Self {
        Self {
            kind: AppErrorKind::InvalidData,
            message: message.into(),
        }
    }

    #[must_use]
    pub const fn kind(&self) -> AppErrorKind {
        self.kind
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for AppError {}

pub(super) fn invalid_input(message: impl Into<String>) -> AppError {
    AppError::invalid_input(message)
}

pub(super) fn invalid_data(message: impl Into<String>) -> AppError {
    AppError::invalid_data(message)
}
