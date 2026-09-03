//! libfprint-facing operation contract for the GF3258 driver core.
//!
//! This module intentionally contains no GLib/GObject FFI. It defines the
//! stable semantic boundary that a thin libfprint adapter must implement:
//! one persistent device session, one active enrollment or verification
//! transaction, validated driver-private TGLA print data, progress/retry
//! events, final match reporting, and operation-scoped cancellation.
//!
//! The actual libfprint C/GObject shim remains a separate integration layer so
//! the Rust biometric core can continue to forbid unsafe code.

use std::{
    error::Error,
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use crate::{
    device::{GOODIX_550A_PID, GOODIX_VID},
    driver::{
        Gf3258DeviceSession, Gf3258EnrollmentTransaction, Gf3258EnrollmentTransactionError,
        Gf3258SessionError, Gf3258SessionStartup, Gf3258VerificationTransaction,
        Gf3258VerificationTransactionError,
    },
    enrollment::{
        GF3258_ENROLLMENT_TARGET_SAMPLES, Gf3258EnrollmentFrameOutcome, Gf3258EnrollmentRejection,
    },
    verification::{
        Gf3258GalleryVerificationDecision, Gf3258LiveVerificationRejection,
        Gf3258RawFrameVerificationOutcome, Gf3258VerificationTemplate,
        Gf3258VerificationTemplateError,
    },
};

/// libfprint driver identifier intended for the upstream C/GObject class.
pub const GF3258_LIBFPRINT_DRIVER_ID: &str = "goodix550a";
/// Human-readable libfprint device name.
pub const GF3258_LIBFPRINT_FULL_NAME: &str = "Goodix GF3258 WN2 Fingerprint Sensor";
/// USB vendor ID registered by the libfprint driver class.
pub const GF3258_LIBFPRINT_USB_VID: u16 = GOODIX_VID;
/// USB product ID registered by the libfprint driver class.
pub const GF3258_LIBFPRINT_USB_PID: u16 = GOODIX_550A_PID;
/// Enrollment stage count exposed through `FpDeviceClass::nr_enroll_stages`.
pub const GF3258_LIBFPRINT_ENROLL_STAGES: usize = GF3258_ENROLLMENT_TARGET_SAMPLES;

/// Monotonic identifier for one active libfprint-style operation.
///
/// Cancellation is scoped to an operation ID so a stale cancel request cannot
/// accidentally cancel a later enrollment or verification action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Gf3258LibfprintOperationId(u64);

impl Gf3258LibfprintOperationId {
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Kind of interactive operation currently owned by the adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gf3258LibfprintOperationKind {
    Enrollment,
    Verification,
}

impl fmt::Display for Gf3258LibfprintOperationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Enrollment => f.write_str("enrollment"),
            Self::Verification => f.write_str("verification"),
        }
    }
}

/// High-level ownership state intended to mirror an `FpDevice` instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gf3258LibfprintState {
    Closed,
    Idle,
    Enrollment {
        operation: Gf3258LibfprintOperationId,
    },
    Verification {
        operation: Gf3258LibfprintOperationId,
    },
}

/// libfprint retry class used for ordinary biometric scan rejection.
///
/// The recovered GF3258 rejection paths prove that another touch is required,
/// but do not consistently prove a more specific UI instruction such as
/// `CENTER_FINGER` or `REMOVE_FINGER`. Map them conservatively to libfprint's
/// general retry class instead of inventing semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gf3258LibfprintRetry {
    General,
}

/// Validated driver-private print payload stored by libfprint/fprintd.
///
/// The byte representation is the existing fresh TGLA envelope. Keeping that
/// exact envelope avoids creating a second persistence format merely for the
/// GObject boundary. Construction performs production verification-template
/// validation, including the empty-gallery guard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gf3258LibfprintPrint {
    tgla: Vec<u8>,
    sample_count: usize,
}

impl Gf3258LibfprintPrint {
    /// Construct a libfprint print payload from persisted TGLA bytes.
    ///
    /// # Errors
    ///
    /// Returns the same strict template error used by production verification.
    pub fn from_tgla(bytes: &[u8]) -> Result<Self, Gf3258VerificationTemplateError> {
        let template = Gf3258VerificationTemplate::from_tgla(bytes)?;
        Ok(Self {
            tgla: bytes.to_vec(),
            sample_count: template.sample_count(),
        })
    }

    #[must_use]
    pub fn tgla(&self) -> &[u8] {
        &self.tgla
    }

    #[must_use]
    pub const fn sample_count(&self) -> usize {
        self.sample_count
    }

    #[must_use]
    pub fn into_tgla(self) -> Vec<u8> {
        self.tgla
    }

    fn from_completed_enrollment(tgla: &[u8]) -> Result<Self, Gf3258VerificationTemplateError> {
        Self::from_tgla(tgla)
    }
}

/// Event emitted after one enrollment touch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gf3258LibfprintEnrollmentEvent {
    /// The touch was a valid interaction but must be retried. Enrollment state
    /// remains active and the completed-stage count is unchanged.
    Retry {
        reason: Gf3258LibfprintRetry,
        completed_stages: usize,
        total_stages: usize,
    },
    /// One sample was retained and more stages are required.
    Progress {
        completed_stages: usize,
        total_stages: usize,
        progress_percent: usize,
    },
    /// The recovered 12-stage target was reached and the final TGLA print is
    /// ready to place in libfprint's driver-private `FpPrint` data.
    Complete {
        completed_stages: usize,
        total_stages: usize,
        print: Gf3258LibfprintPrint,
    },
}

/// Event emitted after one verification touch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gf3258LibfprintVerificationEvent {
    /// The capture should be retried; no authentication result was produced.
    Retry { reason: Gf3258LibfprintRetry },
    /// Final persisted-gallery arbitration produced MATCH.
    Match { score: i32 },
    /// Final persisted-gallery arbitration produced NO_MATCH.
    NoMatch { score: i32 },
}

/// Cloneable cancellation signal intended to be held by the libfprint main
/// thread while the Rust operation executes on a worker.
///
/// The current USB transaction layer is still synchronous. Cancellation can be
/// observed before a touch begins and immediately after a blocking capture
/// returns; making individual USB transfers cancellable belongs to the later
/// GUsb transport integration rather than this semantic adapter.
#[derive(Debug, Clone, Default)]
pub struct Gf3258LibfprintCancellation {
    cancelled_operation: Arc<AtomicU64>,
}

impl Gf3258LibfprintCancellation {
    pub fn cancel(&self, operation: Gf3258LibfprintOperationId) {
        self.cancelled_operation
            .store(operation.get(), Ordering::Release);
    }

    fn reset_for(&self, operation: Gf3258LibfprintOperationId) {
        let _ = self.cancelled_operation.compare_exchange(
            operation.get(),
            0,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    fn is_cancelled(&self, operation: Gf3258LibfprintOperationId) -> bool {
        self.cancelled_operation.load(Ordering::Acquire) == operation.get()
    }
}

/// Driver-facing error classification for the libfprint ownership layer.
#[derive(Debug)]
pub enum Gf3258LibfprintError {
    AlreadyOpen,
    NotOpen,
    OperationActive {
        operation: Gf3258LibfprintOperationKind,
    },
    NoActiveOperation,
    WrongOperation {
        expected: Gf3258LibfprintOperationKind,
        actual: Gf3258LibfprintOperationKind,
    },
    Cancelled {
        operation: Gf3258LibfprintOperationId,
    },
    Session(Gf3258SessionError),
    Enrollment(Gf3258EnrollmentTransactionError),
    Verification(Gf3258VerificationTransactionError),
    Template(Gf3258VerificationTemplateError),
}

impl fmt::Display for Gf3258LibfprintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyOpen => f.write_str("GF3258 libfprint adapter is already open"),
            Self::NotOpen => f.write_str("GF3258 libfprint adapter is not open"),
            Self::OperationActive { operation } => {
                write!(f, "GF3258 {operation} operation is already active")
            }
            Self::NoActiveOperation => f.write_str("GF3258 has no active libfprint operation"),
            Self::WrongOperation { expected, actual } => write!(
                f,
                "GF3258 active operation is {actual}; expected {expected}"
            ),
            Self::Cancelled { operation } => {
                write!(f, "GF3258 operation {} was cancelled", operation.get())
            }
            Self::Session(error) => error.fmt(f),
            Self::Enrollment(error) => error.fmt(f),
            Self::Verification(error) => error.fmt(f),
            Self::Template(error) => error.fmt(f),
        }
    }
}

impl Error for Gf3258LibfprintError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Session(error) => Some(error),
            Self::Enrollment(error) => Some(error),
            Self::Verification(error) => Some(error),
            Self::Template(error) => Some(error),
            Self::AlreadyOpen
            | Self::NotOpen
            | Self::OperationActive { .. }
            | Self::NoActiveOperation
            | Self::WrongOperation { .. }
            | Self::Cancelled { .. } => None,
        }
    }
}

impl From<Gf3258SessionError> for Gf3258LibfprintError {
    fn from(value: Gf3258SessionError) -> Self {
        Self::Session(value)
    }
}

impl From<Gf3258EnrollmentTransactionError> for Gf3258LibfprintError {
    fn from(value: Gf3258EnrollmentTransactionError) -> Self {
        Self::Enrollment(value)
    }
}

impl From<Gf3258VerificationTransactionError> for Gf3258LibfprintError {
    fn from(value: Gf3258VerificationTransactionError) -> Self {
        Self::Verification(value)
    }
}

impl From<Gf3258VerificationTemplateError> for Gf3258LibfprintError {
    fn from(value: Gf3258VerificationTemplateError) -> Self {
        Self::Template(value)
    }
}

enum ActiveOperation {
    Enrollment {
        id: Gf3258LibfprintOperationId,
        transaction: Gf3258EnrollmentTransaction,
    },
    Verification {
        id: Gf3258LibfprintOperationId,
        transaction: Gf3258VerificationTransaction,
    },
}

impl ActiveOperation {
    const fn id(&self) -> Gf3258LibfprintOperationId {
        match self {
            Self::Enrollment { id, .. } | Self::Verification { id, .. } => *id,
        }
    }

    const fn kind(&self) -> Gf3258LibfprintOperationKind {
        match self {
            Self::Enrollment { .. } => Gf3258LibfprintOperationKind::Enrollment,
            Self::Verification { .. } => Gf3258LibfprintOperationKind::Verification,
        }
    }
}

/// Safe Rust ownership/state adapter for the libfprint `FpDevice` class.
///
/// It intentionally does not expose libfprint/GLib pointers and does not own a
/// firmware filesystem path. The caller decides whether to use the APP-only
/// open path or provide exact APP15045 bytes.
pub struct Gf3258LibfprintAdapter {
    session: Option<Gf3258DeviceSession>,
    operation: Option<ActiveOperation>,
    cancellation: Gf3258LibfprintCancellation,
    next_operation_id: u64,
}

impl Default for Gf3258LibfprintAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl Gf3258LibfprintAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            session: None,
            operation: None,
            cancellation: Gf3258LibfprintCancellation::default(),
            next_operation_id: 1,
        }
    }

    #[must_use]
    pub fn state(&self) -> Gf3258LibfprintState {
        match (&self.session, &self.operation) {
            (None, _) => Gf3258LibfprintState::Closed,
            (Some(_), None) => Gf3258LibfprintState::Idle,
            (Some(_), Some(ActiveOperation::Enrollment { id, .. })) => {
                Gf3258LibfprintState::Enrollment { operation: *id }
            }
            (Some(_), Some(ActiveOperation::Verification { id, .. })) => {
                Gf3258LibfprintState::Verification { operation: *id }
            }
        }
    }

    /// Clone the operation-scoped cancellation signal for the libfprint main
    /// thread or other supervising owner.
    #[must_use]
    pub fn cancellation(&self) -> Gf3258LibfprintCancellation {
        self.cancellation.clone()
    }

    /// Open an already-APP device.
    ///
    /// # Errors
    ///
    /// Returns `AlreadyOpen` if this adapter already owns a session, otherwise
    /// forwards the production session-open error.
    pub fn open(&mut self) -> Result<Gf3258SessionStartup, Gf3258LibfprintError> {
        self.ensure_closed()?;
        let session = Gf3258DeviceSession::open()?;
        let startup = session.startup();
        self.session = Some(session);
        Ok(startup)
    }

    /// Open a device with caller-supplied exact APP15045 firmware available for
    /// the supported IAP recovery path.
    ///
    /// # Errors
    ///
    /// Returns `AlreadyOpen` if this adapter already owns a session, otherwise
    /// forwards the production bootstrap/open error.
    pub fn open_with_firmware(
        &mut self,
        firmware_blob: &[u8],
    ) -> Result<Gf3258SessionStartup, Gf3258LibfprintError> {
        self.ensure_closed()?;
        let session = Gf3258DeviceSession::open_with_firmware(firmware_blob)?;
        let startup = session.startup();
        self.session = Some(session);
        Ok(startup)
    }

    /// Drop the claimed session after the active operation has completed.
    ///
    /// # Errors
    ///
    /// Returns `NotOpen` for a duplicate close and `OperationActive` if an
    /// interactive operation still owns transaction state.
    pub fn close(&mut self) -> Result<(), Gf3258LibfprintError> {
        if self.session.is_none() {
            return Err(Gf3258LibfprintError::NotOpen);
        }
        if let Some(operation) = &self.operation {
            return Err(Gf3258LibfprintError::OperationActive {
                operation: operation.kind(),
            });
        }

        self.session = None;
        Ok(())
    }

    /// Start one 12-stage enrollment operation.
    ///
    /// # Errors
    ///
    /// Returns `NotOpen` when no device session exists or `OperationActive`
    /// when another interactive operation is already in progress.
    pub fn start_enrollment(&mut self) -> Result<Gf3258LibfprintOperationId, Gf3258LibfprintError> {
        self.ensure_idle()?;
        let id = self.allocate_operation_id();
        self.cancellation.reset_for(id);
        self.operation = Some(ActiveOperation::Enrollment {
            id,
            transaction: Gf3258EnrollmentTransaction::new(),
        });
        Ok(id)
    }

    /// Advance enrollment by exactly one physical touch.
    ///
    /// Accepted samples report progress. Ordinary biometric rejection reports a
    /// retry without ending the enrollment action. The 12th retained sample is
    /// finalized immediately into a validated TGLA print and ends the action.
    ///
    /// # Errors
    ///
    /// Returns state/cancellation errors or forwards session/enrollment
    /// transaction failures. Transaction failures terminate the active action.
    pub fn enroll_touch(
        &mut self,
        operation: Gf3258LibfprintOperationId,
    ) -> Result<Gf3258LibfprintEnrollmentEvent, Gf3258LibfprintError> {
        self.require_operation(operation, Gf3258LibfprintOperationKind::Enrollment)?;
        if self.cancellation.is_cancelled(operation) {
            self.operation = None;
            return Err(Gf3258LibfprintError::Cancelled { operation });
        }

        let active = self
            .operation
            .take()
            .ok_or(Gf3258LibfprintError::NoActiveOperation)?;
        let (id, mut transaction) = match active {
            ActiveOperation::Enrollment { id, transaction } => (id, transaction),
            other => {
                return Err(Gf3258LibfprintError::WrongOperation {
                    expected: Gf3258LibfprintOperationKind::Enrollment,
                    actual: other.kind(),
                });
            }
        };

        let result = {
            let session = self.session.as_mut().ok_or(Gf3258LibfprintError::NotOpen)?;
            transaction.capture_next(session)
        };

        let touch = match result {
            Ok(touch) => touch,
            Err(error) => return Err(Gf3258LibfprintError::Enrollment(error)),
        };

        if self.cancellation.is_cancelled(operation) {
            return Err(Gf3258LibfprintError::Cancelled { operation });
        }

        match touch.outcome() {
            Gf3258EnrollmentFrameOutcome::Rejected(rejection) => {
                let completed_stages = transaction.sample_count();
                self.operation = Some(ActiveOperation::Enrollment { id, transaction });
                Ok(Gf3258LibfprintEnrollmentEvent::Retry {
                    reason: enrollment_retry(rejection),
                    completed_stages,
                    total_stages: GF3258_LIBFPRINT_ENROLL_STAGES,
                })
            }
            Gf3258EnrollmentFrameOutcome::Accepted(commit) => {
                if transaction.is_complete() {
                    let completed_stages = commit.sample_count;
                    let artifacts = transaction.finish()?;
                    let print =
                        Gf3258LibfprintPrint::from_completed_enrollment(artifacts.tgla_template())?;
                    Ok(Gf3258LibfprintEnrollmentEvent::Complete {
                        completed_stages,
                        total_stages: GF3258_LIBFPRINT_ENROLL_STAGES,
                        print,
                    })
                } else {
                    let event = Gf3258LibfprintEnrollmentEvent::Progress {
                        completed_stages: commit.sample_count,
                        total_stages: GF3258_LIBFPRINT_ENROLL_STAGES,
                        progress_percent: commit.progress_percent,
                    };
                    self.operation = Some(ActiveOperation::Enrollment { id, transaction });
                    Ok(event)
                }
            }
        }
    }

    /// Start verification against one validated driver-private print.
    ///
    /// # Errors
    ///
    /// Returns state errors or a strict template error if the print somehow no
    /// longer satisfies production verification decoding.
    pub fn start_verification(
        &mut self,
        print: &Gf3258LibfprintPrint,
    ) -> Result<Gf3258LibfprintOperationId, Gf3258LibfprintError> {
        self.ensure_idle()?;
        let transaction = Gf3258VerificationTransaction::from_tgla(print.tgla())?;
        let id = self.allocate_operation_id();
        self.cancellation.reset_for(id);
        self.operation = Some(ActiveOperation::Verification { id, transaction });
        Ok(id)
    }

    /// Capture and resolve one verification action.
    ///
    /// Every returned event ends the verification action. Biometric rejection
    /// maps to a retry event; only final gallery arbitration maps to MATCH or
    /// NO_MATCH.
    ///
    /// # Errors
    ///
    /// Returns state/cancellation errors or forwards session/verification
    /// transaction failures. Failures terminate the active action.
    pub fn verify_touch(
        &mut self,
        operation: Gf3258LibfprintOperationId,
    ) -> Result<Gf3258LibfprintVerificationEvent, Gf3258LibfprintError> {
        self.require_operation(operation, Gf3258LibfprintOperationKind::Verification)?;
        if self.cancellation.is_cancelled(operation) {
            self.operation = None;
            return Err(Gf3258LibfprintError::Cancelled { operation });
        }

        let active = self
            .operation
            .take()
            .ok_or(Gf3258LibfprintError::NoActiveOperation)?;
        let mut transaction = match active {
            ActiveOperation::Verification { transaction, .. } => transaction,
            other => {
                return Err(Gf3258LibfprintError::WrongOperation {
                    expected: Gf3258LibfprintOperationKind::Verification,
                    actual: other.kind(),
                });
            }
        };

        let result = {
            let session = self.session.as_mut().ok_or(Gf3258LibfprintError::NotOpen)?;
            transaction.capture_next(session)
        };

        let touch = match result {
            Ok(touch) => touch,
            Err(error) => return Err(Gf3258LibfprintError::Verification(error)),
        };

        if self.cancellation.is_cancelled(operation) {
            return Err(Gf3258LibfprintError::Cancelled { operation });
        }

        match touch.outcome() {
            Gf3258RawFrameVerificationOutcome::Rejected(rejection) => {
                Ok(Gf3258LibfprintVerificationEvent::Retry {
                    reason: verification_retry(rejection),
                })
            }
            Gf3258RawFrameVerificationOutcome::Verified(result) => match result.decision() {
                Gf3258GalleryVerificationDecision::Match => {
                    Ok(Gf3258LibfprintVerificationEvent::Match {
                        score: result.score(),
                    })
                }
                Gf3258GalleryVerificationDecision::NoMatch => {
                    Ok(Gf3258LibfprintVerificationEvent::NoMatch {
                        score: result.score(),
                    })
                }
            },
        }
    }

    fn ensure_closed(&self) -> Result<(), Gf3258LibfprintError> {
        if self.session.is_some() {
            return Err(Gf3258LibfprintError::AlreadyOpen);
        }
        Ok(())
    }

    fn ensure_idle(&self) -> Result<(), Gf3258LibfprintError> {
        if self.session.is_none() {
            return Err(Gf3258LibfprintError::NotOpen);
        }
        if let Some(operation) = &self.operation {
            return Err(Gf3258LibfprintError::OperationActive {
                operation: operation.kind(),
            });
        }
        Ok(())
    }

    fn allocate_operation_id(&mut self) -> Gf3258LibfprintOperationId {
        let id = Gf3258LibfprintOperationId(self.next_operation_id);
        self.next_operation_id = self.next_operation_id.wrapping_add(1).max(1);
        id
    }

    fn require_operation(
        &self,
        operation: Gf3258LibfprintOperationId,
        expected: Gf3258LibfprintOperationKind,
    ) -> Result<(), Gf3258LibfprintError> {
        let Some(active) = &self.operation else {
            return Err(Gf3258LibfprintError::NoActiveOperation);
        };
        let actual = active.kind();
        if actual != expected {
            return Err(Gf3258LibfprintError::WrongOperation { expected, actual });
        }
        if active.id() != operation {
            return Err(Gf3258LibfprintError::NoActiveOperation);
        }
        Ok(())
    }
}

fn enrollment_retry(_rejection: &Gf3258EnrollmentRejection) -> Gf3258LibfprintRetry {
    Gf3258LibfprintRetry::General
}

fn verification_retry(_rejection: &Gf3258LiveVerificationRejection) -> Gf3258LibfprintRetry {
    Gf3258LibfprintRetry::General
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::preprocess::PreprocessError;

    #[test]
    fn libfprint_identity_matches_target_device() {
        assert_eq!(GF3258_LIBFPRINT_DRIVER_ID, "goodix550a");
        assert_eq!(GF3258_LIBFPRINT_USB_VID, 0x27c6);
        assert_eq!(GF3258_LIBFPRINT_USB_PID, 0x550a);
        assert_eq!(GF3258_LIBFPRINT_ENROLL_STAGES, 12);
    }

    #[test]
    fn new_adapter_is_closed() {
        let adapter = Gf3258LibfprintAdapter::new();
        assert_eq!(adapter.state(), Gf3258LibfprintState::Closed);
    }

    #[test]
    fn closed_adapter_rejects_interactive_operations() {
        let mut adapter = Gf3258LibfprintAdapter::new();
        assert!(matches!(
            adapter.start_enrollment(),
            Err(Gf3258LibfprintError::NotOpen)
        ));
        assert!(matches!(
            adapter.close(),
            Err(Gf3258LibfprintError::NotOpen)
        ));
    }

    #[test]
    fn operation_ids_are_monotonic_and_skip_zero() {
        let mut adapter = Gf3258LibfprintAdapter::new();
        let first = adapter.allocate_operation_id();
        let second = adapter.allocate_operation_id();
        assert_eq!(first.get(), 1);
        assert_eq!(second.get(), 2);
    }

    #[test]
    fn cancellation_is_scoped_to_exact_operation() {
        let cancellation = Gf3258LibfprintCancellation::default();
        let first = Gf3258LibfprintOperationId(41);
        let second = Gf3258LibfprintOperationId(42);

        cancellation.cancel(first);
        assert!(cancellation.is_cancelled(first));
        assert!(!cancellation.is_cancelled(second));
    }

    #[test]
    fn stale_cancellation_does_not_cancel_later_operation() {
        let cancellation = Gf3258LibfprintCancellation::default();
        let first = Gf3258LibfprintOperationId(7);
        let second = Gf3258LibfprintOperationId(8);

        cancellation.cancel(first);
        cancellation.reset_for(second);
        assert!(!cancellation.is_cancelled(second));
    }

    #[test]
    fn enrollment_rejections_map_to_general_retry() {
        let rejection = Gf3258EnrollmentRejection::Preprocess(PreprocessError::InvalidRawFrame {
            good_pixels: 0,
            tested_pixels: 1,
        });
        assert_eq!(enrollment_retry(&rejection), Gf3258LibfprintRetry::General);
    }

    #[test]
    fn verification_rejections_map_to_general_retry() {
        let rejection =
            Gf3258LiveVerificationRejection::Preprocess(PreprocessError::InvalidRawFrame {
                good_pixels: 0,
                tested_pixels: 1,
            });
        assert_eq!(
            verification_retry(&rejection),
            Gf3258LibfprintRetry::General
        );
    }
}
