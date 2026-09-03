//! Driver-facing GF3258 device session and capture transaction.
//!
//! Owns the boundary between the Goodix 27c6:550a device lifecycle and the
//! biometric workflows: USB claim lifetime, APP/IAP mode handling, optional
//! cold bootstrap, volatile ChicagoH recovery, D2 session setup, finger
//! sequencing, protected-image validation and decryption, and raw 80x64
//! reconstruction.
//!
//! Enrollment and verification algorithms remain in their dedicated modules. This
//! layer owns only driver-facing transaction orchestration around those validated workflows.

use std::{error::Error, fmt, time::Duration};

use crate::bootstrap::{
    BootstrapTimeouts, EXPECTED_APP_VERSION, EXPECTED_IAP_VERSION, cold_bootstrap,
};
use crate::chicago_h;
use crate::crypto::{ImageSession, decrypt_image};
use crate::device::{GoodixDevice, UsbLayout};
use crate::enrollment::{
    GF3258_ENROLLMENT_TARGET_SAMPLES, Gf3258EnrollmentArtifacts, Gf3258EnrollmentCommit,
    Gf3258EnrollmentFrameOutcome, Gf3258EnrollmentGraphDiagnostics, Gf3258EnrollmentPreparation,
    Gf3258EnrollmentWorkflow, Gf3258EnrollmentWorkflowError, Gf3258PreparedEnrollmentSample,
};
use crate::fdt::{FDT_DOWN_PAYLOAD, FDT_UP_PAYLOAD, GET_IMAGE_PAYLOAD};
use crate::image::{IMAGE_HEIGHT, IMAGE_WIDTH, ProtectedImage, restructure_gf3258_wn2};
use crate::protocol::Command;
use crate::trace::TraceLogger;
use crate::transport::GoodixTransport;
use crate::verification::{
    Gf3258DetailedRawFrameVerificationOutcome, Gf3258RawFrameVerificationError,
    Gf3258RawFrameVerificationOutcome, Gf3258VerificationTemplate, Gf3258VerificationTemplateError,
    Gf3258VerificationWorkflow,
};

const VERSION_TIMEOUT: Duration = Duration::from_secs(3);
const CHICAGO_H_INIT_TIMEOUT: Duration = Duration::from_secs(3);
const IMAGE_SESSION_TIMEOUT: Duration = Duration::from_secs(3);
const FDT_TIMEOUT: Duration = Duration::from_secs(30);
const IMAGE_TIMEOUT: Duration = Duration::from_secs(5);
const BOOTSTRAP_PSK_READ_TIMEOUT: Duration = Duration::from_secs(5);
const BOOTSTRAP_F0_TIMEOUT: Duration = Duration::from_secs(5);
const BOOTSTRAP_F4_TIMEOUT: Duration = Duration::from_secs(5);
const BOOTSTRAP_RESET_MCU_ACK_TIMEOUT: Duration = Duration::from_secs(3);
const BOOTSTRAP_RESET_FINGERPRINT_TIMEOUT: Duration = Duration::from_secs(3);
const BOOTSTRAP_CHIP_ID_TIMEOUT: Duration = Duration::from_secs(3);

/// Exact APP firmware build for which the standalone 27c6:550a path is validated.
pub const GF3258_SUPPORTED_APP_FIRMWARE: &str = EXPECTED_APP_VERSION;

/// Exact IAP firmware build supported by the recovered cold-bootstrap path.
pub const GF3258_SUPPORTED_IAP_FIRMWARE: &str = EXPECTED_IAP_VERSION;

/// How the current driver session reached validated APP mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gf3258SessionStartup {
    /// The USB device was already running the validated APP firmware.
    AlreadyApp,
    /// The device started in IAP and was upgraded through the recovered
    /// authenticated F0/F4 + reset/re-enumeration path.
    ColdBootstrapped {
        chip_id: u32,
        f0_chunks_sent: usize,
        firmware_check_result: u8,
    },
}

impl fmt::Display for Gf3258SessionStartup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyApp => f.write_str("AlreadyApp"),
            Self::ColdBootstrapped {
                chip_id,
                f0_chunks_sent,
                firmware_check_result,
            } => write!(
                f,
                "ColdBootstrapped chip_id=0x{chip_id:08x} f0_chunks={f0_chunks_sent} f4_result=0x{firmware_check_result:02x}"
            ),
        }
    }
}

/// Stable USB endpoint description for the claimed 27c6:550a interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf3258UsbLayout {
    interface: u8,
    bulk_in: u8,
    bulk_out: u8,
    max_packet_size: u16,
}

impl Gf3258UsbLayout {
    #[must_use]
    pub const fn interface(self) -> u8 {
        self.interface
    }

    #[must_use]
    pub const fn bulk_in(self) -> u8 {
        self.bulk_in
    }

    #[must_use]
    pub const fn bulk_out(self) -> u8 {
        self.bulk_out
    }

    #[must_use]
    pub const fn max_packet_size(self) -> u16 {
        self.max_packet_size
    }
}

impl From<UsbLayout> for Gf3258UsbLayout {
    fn from(value: UsbLayout) -> Self {
        Self {
            interface: value.interface,
            bulk_in: value.bulk_in,
            bulk_out: value.bulk_out,
            max_packet_size: value.max_packet_size,
        }
    }
}

/// Stage at which a driver-facing APP session operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gf3258SessionStage {
    OpenUsb,
    ReadVersion,
    ColdBootstrap,
    RestoreVolatileConfig,
    GenerateImageSession,
    InstallImageSession,
    FingerDown,
    ReadImage,
    FingerUp,
    ParseProtectedImage,
    DecryptImage,
    ValidateImageCrc,
    ReconstructImage,
}

impl fmt::Display for Gf3258SessionStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::OpenUsb => "open USB device",
            Self::ReadVersion => "read firmware version",
            Self::ColdBootstrap => "cold-bootstrap IAP firmware into APP mode",
            Self::RestoreVolatileConfig => "restore volatile sensor configuration",
            Self::GenerateImageSession => "generate image session",
            Self::InstallImageSession => "install image session",
            Self::FingerDown => "wait for finger down",
            Self::ReadImage => "read protected image",
            Self::FingerUp => "wait for finger up",
            Self::ParseProtectedImage => "parse protected image",
            Self::DecryptImage => "decrypt image",
            Self::ValidateImageCrc => "validate image CRC",
            Self::ReconstructImage => "reconstruct GF3258 image",
        };
        f.write_str(name)
    }
}

/// Error returned by the stable APP-mode device-session boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gf3258SessionError {
    /// The device could not be opened/claimed or a transport/configuration
    /// operation failed at the named stage.
    Stage {
        stage: Gf3258SessionStage,
        message: String,
    },
    /// The APP-only constructor encountered the supported IAP build and needs
    /// caller-supplied APP firmware bytes to perform the cold bootstrap.
    BootstrapFirmwareRequired { current: String },
    /// The discovered device is neither the validated APP nor supported IAP build.
    UnsupportedFirmware {
        expected: &'static str,
        actual: String,
    },
    /// A boot image was returned where a live fingerprint image was expected.
    BootImage,
    /// The reconstructed frame length violates the fixed 80x64 GF3258 shape.
    UnexpectedPixelCount { expected: usize, actual: usize },
}

impl Gf3258SessionError {
    fn stage(stage: Gf3258SessionStage, error: impl fmt::Display) -> Self {
        Self::Stage {
            stage,
            message: error.to_string(),
        }
    }
}

impl fmt::Display for Gf3258SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stage { stage, message } => {
                write!(
                    f,
                    "GF3258 session failed while trying to {stage}: {message}"
                )
            }
            Self::BootstrapFirmwareRequired { current } => write!(
                f,
                "GF3258 device is running {current}; cold bootstrap requires caller-supplied {GF3258_SUPPORTED_APP_FIRMWARE} firmware bytes"
            ),
            Self::UnsupportedFirmware { expected, actual } => write!(
                f,
                "GF3258 session requires firmware {expected}; device reported {actual}"
            ),
            Self::BootImage => {
                f.write_str("GF3258 returned a boot image instead of a fingerprint image")
            }
            Self::UnexpectedPixelCount { expected, actual } => write!(
                f,
                "GF3258 reconstructed image has {actual} pixels; expected {expected}"
            ),
        }
    }
}

impl Error for Gf3258SessionError {}

/// Diagnostics attached to one successfully reconstructed capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf3258CaptureDiagnostics {
    protected_bytes: usize,
    stored_crc: u32,
}

impl Gf3258CaptureDiagnostics {
    #[must_use]
    pub const fn protected_bytes(self) -> usize {
        self.protected_bytes
    }

    #[must_use]
    pub const fn stored_crc(self) -> u32 {
        self.stored_crc
    }
}

/// One owned 80x64 reconstructed GF3258 sensor frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gf3258CapturedFrame {
    raw_u16: Vec<u16>,
    diagnostics: Gf3258CaptureDiagnostics,
}

impl Gf3258CapturedFrame {
    /// Reconstructed 12-bit sensor samples represented in `u16` storage.
    #[must_use]
    pub fn pixels(&self) -> &[u16] {
        &self.raw_u16
    }

    #[must_use]
    pub const fn diagnostics(&self) -> Gf3258CaptureDiagnostics {
        self.diagnostics
    }
}

/// Error returned while composing sensor capture with the enrollment workflow.
#[derive(Debug)]
pub enum Gf3258EnrollmentTransactionError {
    Session(Gf3258SessionError),
    Workflow(Gf3258EnrollmentWorkflowError),
    Incomplete {
        sample_count: usize,
        target_samples: usize,
    },
}

impl fmt::Display for Gf3258EnrollmentTransactionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Session(error) => fmt::Display::fmt(error, f),
            Self::Workflow(error) => fmt::Display::fmt(error, f),
            Self::Incomplete {
                sample_count,
                target_samples,
            } => write!(
                f,
                "GF3258 enrollment is incomplete: {sample_count}/{target_samples} retained samples"
            ),
        }
    }
}

impl Error for Gf3258EnrollmentTransactionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Session(error) => Some(error),
            Self::Workflow(error) => Some(error),
            Self::Incomplete { .. } => None,
        }
    }
}

impl From<Gf3258SessionError> for Gf3258EnrollmentTransactionError {
    fn from(value: Gf3258SessionError) -> Self {
        Self::Session(value)
    }
}

impl From<Gf3258EnrollmentWorkflowError> for Gf3258EnrollmentTransactionError {
    fn from(value: Gf3258EnrollmentWorkflowError) -> Self {
        Self::Workflow(value)
    }
}

/// Result of one complete sensor capture + enrollment-processing touch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gf3258EnrollmentTouchResult {
    capture: Gf3258CaptureDiagnostics,
    outcome: Gf3258EnrollmentFrameOutcome,
}

impl Gf3258EnrollmentTouchResult {
    #[must_use]
    pub const fn capture_diagnostics(&self) -> Gf3258CaptureDiagnostics {
        self.capture
    }

    #[must_use]
    pub const fn outcome(&self) -> &Gf3258EnrollmentFrameOutcome {
        &self.outcome
    }
}

/// Detailed split-phase enrollment touch used by diagnostic applications.
///
/// Production integrations should use [`Gf3258EnrollmentTransaction::capture_next`].
pub(crate) struct Gf3258DetailedEnrollmentTouch {
    capture: Gf3258CaptureDiagnostics,
    preparation: Gf3258EnrollmentPreparation,
}

impl Gf3258DetailedEnrollmentTouch {
    pub(crate) const fn capture_diagnostics(&self) -> Gf3258CaptureDiagnostics {
        self.capture
    }

    pub(crate) fn into_parts(self) -> (Gf3258CaptureDiagnostics, Gf3258EnrollmentPreparation) {
        (self.capture, self.preparation)
    }
}

/// Stateful enrollment operation suitable for driver callback integration.
///
/// The transaction owns biometric enrollment state but deliberately does not own
/// the USB device. A callback adapter can therefore keep one persistent
/// [`Gf3258DeviceSession`] and store this transaction only while enrollment is
/// active, advancing one touch per callback without a self-referential borrow.
pub struct Gf3258EnrollmentTransaction {
    workflow: Gf3258EnrollmentWorkflow,
}

impl Default for Gf3258EnrollmentTransaction {
    fn default() -> Self {
        Self::new()
    }
}

impl Gf3258EnrollmentTransaction {
    #[must_use]
    pub fn new() -> Self {
        Self {
            workflow: Gf3258EnrollmentWorkflow::new(),
        }
    }

    #[must_use]
    pub fn sample_count(&self) -> usize {
        self.workflow.sample_count()
    }

    #[must_use]
    pub fn progress_percent(&self) -> usize {
        self.workflow.progress_percent()
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.workflow.is_complete()
    }

    #[must_use]
    pub fn graph_diagnostics(&self) -> Gf3258EnrollmentGraphDiagnostics {
        self.workflow.graph_diagnostics()
    }

    /// Capture and process one enrollment touch.
    ///
    /// A normal biometric rejection is returned inside the touch outcome and
    /// does not advance enrollment state. Transport/crypto/persistence-pipeline
    /// failures are returned as transaction errors.
    ///
    /// # Errors
    ///
    /// Returns an error when capture fails or the reusable enrollment workflow
    /// cannot process/commit the reconstructed frame.
    pub fn capture_next(
        &mut self,
        session: &mut Gf3258DeviceSession,
    ) -> Result<Gf3258EnrollmentTouchResult, Gf3258EnrollmentTransactionError> {
        let detailed = self.capture_next_prepared(session)?;
        let (capture, preparation) = detailed.into_parts();

        let outcome = match preparation {
            Gf3258EnrollmentPreparation::Rejected(rejection) => {
                Gf3258EnrollmentFrameOutcome::Rejected(rejection)
            }
            Gf3258EnrollmentPreparation::Prepared(prepared) => {
                Gf3258EnrollmentFrameOutcome::Accepted(self.commit_prepared(prepared)?)
            }
        };

        Ok(Gf3258EnrollmentTouchResult { capture, outcome })
    }

    pub(crate) fn capture_next_prepared(
        &mut self,
        session: &mut Gf3258DeviceSession,
    ) -> Result<Gf3258DetailedEnrollmentTouch, Gf3258EnrollmentTransactionError> {
        let frame = session.capture_frame()?;
        let capture = frame.diagnostics();
        let preparation = self.workflow.prepare_raw_frame(frame.pixels())?;

        Ok(Gf3258DetailedEnrollmentTouch {
            capture,
            preparation,
        })
    }

    pub(crate) fn commit_prepared(
        &mut self,
        prepared: Gf3258PreparedEnrollmentSample,
    ) -> Result<Gf3258EnrollmentCommit, Gf3258EnrollmentTransactionError> {
        Ok(self.workflow.commit_prepared(prepared)?)
    }

    /// Finish a completed enrollment and return validated in-memory template
    /// artifacts. Filesystem/storage policy remains outside this transaction.
    ///
    /// Consuming the transaction prevents further enrollment touches after the
    /// final template has been materialized.
    ///
    /// # Errors
    ///
    /// Returns [`Gf3258EnrollmentTransactionError::Incomplete`] unless the
    /// recovered 12-sample completion target has been reached, or a workflow
    /// error if final persistence encoding/validation fails.
    pub fn finish(self) -> Result<Gf3258EnrollmentArtifacts, Gf3258EnrollmentTransactionError> {
        let sample_count = self.workflow.sample_count();
        if sample_count < GF3258_ENROLLMENT_TARGET_SAMPLES {
            return Err(Gf3258EnrollmentTransactionError::Incomplete {
                sample_count,
                target_samples: GF3258_ENROLLMENT_TARGET_SAMPLES,
            });
        }

        Ok(self.workflow.encode_artifacts()?)
    }
}

/// Error returned while composing sensor capture with persisted-gallery verification.
#[derive(Debug)]
pub enum Gf3258VerificationTransactionError {
    Session(Gf3258SessionError),
    Verification(Gf3258RawFrameVerificationError),
}

impl fmt::Display for Gf3258VerificationTransactionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Session(error) => fmt::Display::fmt(error, f),
            Self::Verification(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl Error for Gf3258VerificationTransactionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Session(error) => Some(error),
            Self::Verification(error) => Some(error),
        }
    }
}

impl From<Gf3258SessionError> for Gf3258VerificationTransactionError {
    fn from(value: Gf3258SessionError) -> Self {
        Self::Session(value)
    }
}

impl From<Gf3258RawFrameVerificationError> for Gf3258VerificationTransactionError {
    fn from(value: Gf3258RawFrameVerificationError) -> Self {
        Self::Verification(value)
    }
}

/// Result of one complete sensor capture + persisted-gallery verification touch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gf3258VerificationTouchResult {
    capture: Gf3258CaptureDiagnostics,
    outcome: Gf3258RawFrameVerificationOutcome,
}

impl Gf3258VerificationTouchResult {
    #[must_use]
    pub const fn capture_diagnostics(&self) -> Gf3258CaptureDiagnostics {
        self.capture
    }

    #[must_use]
    pub const fn outcome(&self) -> &Gf3258RawFrameVerificationOutcome {
        &self.outcome
    }
}

/// Detailed verification touch used only by diagnostic applications.
pub(crate) struct Gf3258DetailedVerificationTouch {
    capture: Gf3258CaptureDiagnostics,
    pixel_count: usize,
    outcome: Gf3258DetailedRawFrameVerificationOutcome,
}

impl Gf3258DetailedVerificationTouch {
    pub(crate) const fn capture_diagnostics(&self) -> Gf3258CaptureDiagnostics {
        self.capture
    }

    pub(crate) const fn pixel_count(&self) -> usize {
        self.pixel_count
    }

    pub(crate) fn into_outcome(self) -> Gf3258DetailedRawFrameVerificationOutcome {
        self.outcome
    }
}

/// Stateful verification operation suitable for driver callback integration.
///
/// The transaction owns one validated persisted gallery plus the stateful live
/// verification workflow. The USB device remains independently owned by
/// [`Gf3258DeviceSession`], allowing an adapter to keep the
/// session for its lifetime and store this transaction only while an
/// authentication operation is active.
pub struct Gf3258VerificationTransaction {
    template: Gf3258VerificationTemplate,
    workflow: Gf3258VerificationWorkflow,
}

impl Gf3258VerificationTransaction {
    /// Start verification with an already-validated opaque gallery.
    #[must_use]
    pub fn new(template: Gf3258VerificationTemplate) -> Self {
        Self {
            template,
            workflow: Gf3258VerificationWorkflow::new(),
        }
    }

    /// Decode persisted TGLA bytes and start a verification transaction.
    ///
    /// Template validation happens before any device/session operation so an
    /// empty or malformed gallery cannot cause USB access.
    ///
    /// # Errors
    ///
    /// Returns a template error when strict TGLA decoding fails or the gallery
    /// contains no enrolled samples.
    pub fn from_tgla(bytes: &[u8]) -> Result<Self, Gf3258VerificationTemplateError> {
        Ok(Self::new(Gf3258VerificationTemplate::from_tgla(bytes)?))
    }

    /// Number of persisted samples available to this transaction.
    #[must_use]
    pub fn sample_count(&self) -> usize {
        self.template.sample_count()
    }

    pub(crate) fn configured_max_samples(&self) -> usize {
        self.template.configured_max_samples()
    }

    /// Capture and verify one touch against the owned gallery.
    ///
    /// A live-feature rejection is returned inside the verification outcome;
    /// session failures and evaluator failures are transaction errors. Only the
    /// final gallery decision contained in a verified outcome is an
    /// authentication result.
    ///
    /// # Errors
    ///
    /// Returns an error when capture fails or the persisted-gallery verifier
    /// cannot prepare/evaluate the reconstructed frame.
    pub fn capture_next(
        &mut self,
        session: &mut Gf3258DeviceSession,
    ) -> Result<Gf3258VerificationTouchResult, Gf3258VerificationTransactionError> {
        let frame = session.capture_frame()?;
        let capture = frame.diagnostics();
        let outcome = self
            .workflow
            .verify_raw_frame(&self.template, frame.pixels())?;

        Ok(Gf3258VerificationTouchResult { capture, outcome })
    }

    pub(crate) fn capture_next_detailed(
        &mut self,
        session: &mut Gf3258DeviceSession,
    ) -> Result<Gf3258DetailedVerificationTouch, Gf3258VerificationTransactionError> {
        let frame = session.capture_frame()?;
        let capture = frame.diagnostics();
        let pixel_count = frame.pixels().len();
        let outcome = self
            .workflow
            .verify_raw_frame_detailed(&self.template, frame.pixels())?;

        Ok(Gf3258DetailedVerificationTouch {
            capture,
            pixel_count,
            outcome,
        })
    }
}

/// Claimed APP-mode 27c6:550a session suitable for driver transactions.
///
/// The USB device remains claimed for the lifetime of this value. Individual
/// MCU transports are intentionally short-lived borrows, avoiding a
/// self-referential device/transport owner while preserving one physical USB
/// session across multiple captures.
pub struct Gf3258DeviceSession {
    device: GoodixDevice,
    trace: TraceLogger,
    firmware_version: String,
    layout: Gf3258UsbLayout,
    mcu_power_lost_on_open: bool,
    startup: Gf3258SessionStartup,
}

impl Gf3258DeviceSession {
    /// Open and initialize a device that is already running the validated APP.
    ///
    /// This constructor deliberately does not guess where firmware should live.
    /// If the device is in the supported IAP build it returns
    /// [`Gf3258SessionError::BootstrapFirmwareRequired`]. Use
    /// [`Self::open_with_firmware`] when the caller has the exact APP15045 blob.
    ///
    /// # Errors
    ///
    /// Returns an error when the USB device cannot be opened, version probing
    /// fails, the device is in IAP without supplied firmware, an unsupported
    /// build is reported, or ChicagoH recovery fails.
    pub fn open() -> Result<Self, Gf3258SessionError> {
        Self::open_with_trace(TraceLogger::quiet())
    }

    /// Open a 27c6:550a device and automatically recover supported IAP mode.
    ///
    /// The firmware bytes are used only when the opening device reports exact
    /// `MILAN_GM168SEC_IAP_10007`. An already-running APP device is never
    /// rewritten. The supplied resource is hard-preflighted against the exact
    /// recovered APP15045 size/CRC/package invariants before F0/F4 transmission.
    ///
    /// # Errors
    ///
    /// Returns a stage-specific error when open/version probing, cold bootstrap,
    /// USB re-enumeration, post-bootstrap APP validation, or ChicagoH recovery
    /// fails.
    pub fn open_with_firmware(firmware_blob: &[u8]) -> Result<Self, Gf3258SessionError> {
        Self::open_with_firmware_and_trace(firmware_blob, TraceLogger::quiet())
    }

    pub(crate) fn open_with_trace(trace: TraceLogger) -> Result<Self, Gf3258SessionError> {
        let device = Self::open_usb()?;
        let (version, mcu_power_lost) = Self::read_version(&device, &trace)?;

        match version.as_str() {
            GF3258_SUPPORTED_APP_FIRMWARE => Self::finish_app_open(
                device,
                trace,
                version,
                mcu_power_lost,
                Gf3258SessionStartup::AlreadyApp,
            ),
            GF3258_SUPPORTED_IAP_FIRMWARE => {
                Err(Gf3258SessionError::BootstrapFirmwareRequired { current: version })
            }
            _ => Err(Gf3258SessionError::UnsupportedFirmware {
                expected: GF3258_SUPPORTED_APP_FIRMWARE,
                actual: version,
            }),
        }
    }

    pub(crate) fn open_with_firmware_and_trace(
        firmware_blob: &[u8],
        trace: TraceLogger,
    ) -> Result<Self, Gf3258SessionError> {
        let device = Self::open_usb()?;
        let (version, mcu_power_lost) = Self::read_version(&device, &trace)?;

        if version == GF3258_SUPPORTED_APP_FIRMWARE {
            return Self::finish_app_open(
                device,
                trace,
                version,
                mcu_power_lost,
                Gf3258SessionStartup::AlreadyApp,
            );
        }

        if version != GF3258_SUPPORTED_IAP_FIRMWARE {
            return Err(Gf3258SessionError::UnsupportedFirmware {
                expected: GF3258_SUPPORTED_APP_FIRMWARE,
                actual: version,
            });
        }

        let bootstrap = cold_bootstrap(device, trace, firmware_blob, bootstrap_timeouts())
            .map_err(|error| Gf3258SessionError::stage(Gf3258SessionStage::ColdBootstrap, error))?;
        let startup = Gf3258SessionStartup::ColdBootstrapped {
            chip_id: bootstrap.result.chip_id,
            f0_chunks_sent: bootstrap.result.f0_chunks_sent,
            firmware_check_result: bootstrap.result.firmware_check_result,
        };
        let (app_version, app_mcu_power_lost) =
            Self::read_version(&bootstrap.device, &bootstrap.trace)?;

        if app_version != GF3258_SUPPORTED_APP_FIRMWARE {
            return Err(Gf3258SessionError::UnsupportedFirmware {
                expected: GF3258_SUPPORTED_APP_FIRMWARE,
                actual: app_version,
            });
        }

        Self::finish_app_open(
            bootstrap.device,
            bootstrap.trace,
            app_version,
            app_mcu_power_lost,
            startup,
        )
    }

    fn open_usb() -> Result<GoodixDevice, Gf3258SessionError> {
        GoodixDevice::open()
            .map_err(|error| Gf3258SessionError::stage(Gf3258SessionStage::OpenUsb, error))
    }

    fn read_version(
        device: &GoodixDevice,
        trace: &TraceLogger,
    ) -> Result<(String, bool), Gf3258SessionError> {
        let mut transport = GoodixTransport::new(device, trace.clone());
        let (version, ack) = transport
            .get_version_with_ack(VERSION_TIMEOUT)
            .map_err(|error| Gf3258SessionError::stage(Gf3258SessionStage::ReadVersion, error))?;
        Ok((version, ack.mcu_power_lost))
    }

    fn finish_app_open(
        device: GoodixDevice,
        trace: TraceLogger,
        firmware_version: String,
        mcu_power_lost_on_open: bool,
        startup: Gf3258SessionStartup,
    ) -> Result<Self, Gf3258SessionError> {
        let layout = device.layout().into();

        if mcu_power_lost_on_open {
            let mut transport = GoodixTransport::new(&device, trace.clone());
            chicago_h::initialize(&mut transport, CHICAGO_H_INIT_TIMEOUT).map_err(|error| {
                Gf3258SessionError::stage(Gf3258SessionStage::RestoreVolatileConfig, error)
            })?;
        }

        Ok(Self {
            device,
            trace,
            firmware_version,
            layout,
            mcu_power_lost_on_open,
            startup,
        })
    }

    /// Firmware version reported when this APP session was opened.
    #[must_use]
    pub fn firmware_version(&self) -> &str {
        &self.firmware_version
    }

    /// Claimed USB interface/endpoints for this session.
    #[must_use]
    pub const fn usb_layout(&self) -> Gf3258UsbLayout {
        self.layout
    }

    /// Whether the opening version ACK reported lost MCU volatile state.
    #[must_use]
    pub const fn mcu_power_lost_on_open(&self) -> bool {
        self.mcu_power_lost_on_open
    }

    /// How this session reached validated APP mode.
    #[must_use]
    pub const fn startup(&self) -> Gf3258SessionStartup {
        self.startup
    }

    /// Capture, authenticate, decrypt, validate, and reconstruct one live frame.
    ///
    /// A fresh D2 image session is generated for every capture, matching the
    /// proven standalone acquisition path. Finger-up is armed immediately after
    /// the protected image leaves the device, before CPU-heavy processing.
    ///
    /// # Errors
    ///
    /// Returns a stage-specific session error for D2 setup, FDT/image transport,
    /// protected-image parsing/decryption/CRC validation, or reconstruction.
    pub fn capture_frame(&mut self) -> Result<Gf3258CapturedFrame, Gf3258SessionError> {
        let session = ImageSession::generate().map_err(|error| {
            Gf3258SessionError::stage(Gf3258SessionStage::GenerateImageSession, error)
        })?;

        let mut transport = GoodixTransport::new(&self.device, self.trace.clone());
        transport
            .install_image_session(&session, IMAGE_SESSION_TIMEOUT)
            .map_err(|error| {
                Gf3258SessionError::stage(Gf3258SessionStage::InstallImageSession, error)
            })?;

        transport
            .transact(Command::FdtDown, &FDT_DOWN_PAYLOAD, FDT_TIMEOUT)
            .map_err(|error| Gf3258SessionError::stage(Gf3258SessionStage::FingerDown, error))?;

        let image_packet = transport
            .transact(Command::GetImage, &GET_IMAGE_PAYLOAD, IMAGE_TIMEOUT)
            .map_err(|error| Gf3258SessionError::stage(Gf3258SessionStage::ReadImage, error))?;

        transport
            .transact(Command::FdtUp, &FDT_UP_PAYLOAD, FDT_TIMEOUT)
            .map_err(|error| Gf3258SessionError::stage(Gf3258SessionStage::FingerUp, error))?;

        let protected = ProtectedImage::parse(&image_packet.payload).map_err(|error| {
            Gf3258SessionError::stage(Gf3258SessionStage::ParseProtectedImage, error)
        })?;
        if protected.is_boot_image() {
            return Err(Gf3258SessionError::BootImage);
        }

        let image_key = session.image_key();
        let decrypted = decrypt_image(protected.ciphertext(), &image_key)
            .map_err(|error| Gf3258SessionError::stage(Gf3258SessionStage::DecryptImage, error))?;
        protected.validate_crc(&decrypted).map_err(|error| {
            Gf3258SessionError::stage(Gf3258SessionStage::ValidateImageCrc, error)
        })?;

        let raw_u16 = restructure_gf3258_wn2(&decrypted).map_err(|error| {
            Gf3258SessionError::stage(Gf3258SessionStage::ReconstructImage, error)
        })?;

        let expected = IMAGE_WIDTH * IMAGE_HEIGHT;
        if raw_u16.len() != expected {
            return Err(Gf3258SessionError::UnexpectedPixelCount {
                expected,
                actual: raw_u16.len(),
            });
        }

        Ok(Gf3258CapturedFrame {
            raw_u16,
            diagnostics: Gf3258CaptureDiagnostics {
                protected_bytes: image_packet.payload.len(),
                stored_crc: protected.stored_crc(),
            },
        })
    }
}

fn bootstrap_timeouts() -> BootstrapTimeouts {
    BootstrapTimeouts {
        version: VERSION_TIMEOUT,
        psk_read: BOOTSTRAP_PSK_READ_TIMEOUT,
        f0: BOOTSTRAP_F0_TIMEOUT,
        f4: BOOTSTRAP_F4_TIMEOUT,
        reset_mcu_ack: BOOTSTRAP_RESET_MCU_ACK_TIMEOUT,
        reset_fingerprint: BOOTSTRAP_RESET_FINGERPRINT_TIMEOUT,
        chip_id: BOOTSTRAP_CHIP_ID_TIMEOUT,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usb_layout_projects_internal_layout_without_reinterpreting_endpoints() {
        let layout = Gf3258UsbLayout::from(UsbLayout {
            interface: 0,
            bulk_in: 0x83,
            bulk_out: 0x01,
            max_packet_size: 64,
        });

        assert_eq!(layout.interface(), 0);
        assert_eq!(layout.bulk_in(), 0x83);
        assert_eq!(layout.bulk_out(), 0x01);
        assert_eq!(layout.max_packet_size(), 64);
    }

    #[test]
    fn session_errors_preserve_stage_and_message() {
        let error = Gf3258SessionError::stage(Gf3258SessionStage::ReadVersion, "bad response");
        assert_eq!(
            error.to_string(),
            "GF3258 session failed while trying to read firmware version: bad response"
        );
    }

    #[test]
    fn supported_iap_version_is_exact() {
        assert_eq!(GF3258_SUPPORTED_IAP_FIRMWARE, "MILAN_GM168SEC_IAP_10007");
    }

    #[test]
    fn bootstrap_required_error_keeps_iap_version() {
        let error = Gf3258SessionError::BootstrapFirmwareRequired {
            current: GF3258_SUPPORTED_IAP_FIRMWARE.to_owned(),
        };
        assert!(error.to_string().contains(GF3258_SUPPORTED_IAP_FIRMWARE));
        assert!(error.to_string().contains(GF3258_SUPPORTED_APP_FIRMWARE));
    }

    #[test]
    fn unsupported_firmware_error_keeps_reported_version() {
        let error = Gf3258SessionError::UnsupportedFirmware {
            expected: GF3258_SUPPORTED_APP_FIRMWARE,
            actual: "MILAN_GM168SEC_IAP_10007".to_owned(),
        };
        assert!(error.to_string().contains("MILAN_GM168SEC_IAP_10007"));
    }

    #[test]
    fn enrollment_transaction_starts_empty_and_refuses_incomplete_finish() {
        let transaction = Gf3258EnrollmentTransaction::new();
        assert_eq!(transaction.sample_count(), 0);
        assert_eq!(transaction.progress_percent(), 0);
        assert!(!transaction.is_complete());

        let error = transaction.finish().unwrap_err();
        assert!(matches!(
            error,
            Gf3258EnrollmentTransactionError::Incomplete {
                sample_count: 0,
                target_samples: GF3258_ENROLLMENT_TARGET_SAMPLES,
            }
        ));
    }

    #[test]
    fn verification_transaction_rejects_empty_gallery_before_device_access() {
        let enrollment = Gf3258EnrollmentWorkflow::new();
        let artifacts = enrollment.encode_artifacts().unwrap();

        let error = match Gf3258VerificationTransaction::from_tgla(artifacts.tgla_template()) {
            Ok(_) => panic!("empty gallery must be rejected"),
            Err(error) => error,
        };
        assert_eq!(error, Gf3258VerificationTemplateError::EmptyGallery);
    }
}
