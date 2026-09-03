//! Backend-independent libfprint wire helpers for the GF3258 startup and capture paths.
//!
//! libfprint owns USB scheduling and cancellation. This module owns the Goodix
//! protocol bytes and interpretation used by that scheduler. Keeping those
//! responsibilities separate lets the C driver submit asynchronous
//! `FpiUsbTransfer` operations without duplicating recovered packet semantics.

use std::{error::Error, fmt, str};

use crate::{
    bootstrap::EXPECTED_APP_VERSION,
    chicago_h::{ChicagoHConfig, generate_config, validate_download_completion},
    crypto::{ImageSession, decrypt_image},
    enrollment::{
        GF3258_ENROLLMENT_TARGET_SAMPLES, Gf3258EnrollmentFrameOutcome, Gf3258EnrollmentWorkflow,
    },
    fdt::{FDT_DOWN_PAYLOAD, FDT_UP_PAYLOAD, GET_IMAGE_PAYLOAD},
    firmware::{AppTransferPackage, F4_TAG_LEN, FirmwareBlob},
    firmware_auth::{firmware_f4_tag, unseal_psk, verify_psk_hash},
    image::{
        IMAGE_HEIGHT, IMAGE_WIDTH, PROTECTED_IMAGE_LEN, ProtectedImage, normalize_12bit_to_u8,
        restructure_gf3258_wn2,
    },
    protocol::{Command, McuPacket, decode_a0_packet, encode_a0_packet, encode_a0_single},
    transport::{
        OTP_LEN, PSK_HASH_OBJECT, PSK_HASH_SIZE, PSK_READ_CHUNK_SIZE, READ_OTP_PAYLOAD,
        SEALED_PSK_OBJECT, SEALED_PSK_SIZE, build_psk_read_payload, make_usb_out_block,
        parse_psk_read_payload,
    },
    verification::{
        Gf3258GalleryVerificationDecision, Gf3258RawFrameVerificationOutcome,
        Gf3258VerificationTemplate, Gf3258VerificationWorkflow,
    },
};

const GET_VERSION_PAYLOAD: [u8; 2] = [0x00, 0x00];
const BOOTSTRAP_RESET_PAYLOAD: [u8; 2] = [0x02, 0x32];
const POSTBOOT_RESET_PAYLOAD: [u8; 2] = [0x05, 0x14];
const CHIP_ID_READ_PAYLOAD: [u8; 5] = [0x00, 0x00, 0x00, 0x04, 0x00];
pub const GF3258_LIBFPRINT_POSTBOOT_RESET_DELAY_MS: u32 = 10;
pub const GF3258_LIBFPRINT_EXPECTED_CHIP_ID: u32 = 0x0025_03a8;
const ACK_FLAG_MCU_POWER_LOST: u8 = 0x02;
const OUT_TRANSFER_TIMEOUT_MS: u32 = 1_000;
const ACK_TRANSFER_TIMEOUT_MS: u32 = 3_000;
const IMAGE_SESSION_TIMEOUT_MS: u32 = 3_000;
const FDT_TIMEOUT_MS: u32 = 30_000;
const IMAGE_TIMEOUT_MS: u32 = 5_000;
const OUTER_HEADER_LEN: usize = 4;
const MCU_HEADER_LEN: usize = 3;
const RECOVERY_SHORT_READ_SIZE: usize = 128;
const RECOVERY_ACK_TIMEOUT_MS: u32 = 3_000;
const RECOVERY_COMPLETION_TIMEOUT_MS: u32 = 3_000;
const DOWNLOAD_CONFIG_PACKET_SIZE: usize = 264;

const BOOTSTRAP_BLOB_SIZE: usize = 0x611d;
const BOOTSTRAP_APP_SIZE: usize = 0x6100;
const BOOTSTRAP_BLOB_CRC: u32 = 0x4bd5_12b0;
const BOOTSTRAP_APP_CRC: u32 = 0x4d44_46c1;
const BOOTSTRAP_HEADER_CRC: u32 = 0xa2b6_9ee2;
const BOOTSTRAP_PACKAGE_SIZE: usize = 0x610c;
const BOOTSTRAP_F0_CHUNKS: usize = 98;
const BOOTSTRAP_SHORT_READ_SIZE: usize = 128;
const BOOTSTRAP_PSK_TIMEOUT_MS: u32 = 5_000;
const BOOTSTRAP_ACK_TIMEOUT_MS: u32 = 5_000;
const BOOTSTRAP_COMPLETION_TIMEOUT_MS: u32 = 5_000;
const BOOTSTRAP_FIRMWARE_TIMEOUT_MS: u32 = 5_000;

/// Physical endpoint used for host-to-device Goodix bulk traffic.
pub const GF3258_LIBFPRINT_BULK_OUT: u8 = 0x01;
/// Physical endpoint used for device-to-host Goodix bulk traffic.
pub const GF3258_LIBFPRINT_BULK_IN: u8 = 0x83;
/// Physical size of one captured Goodix OUT block.
pub const GF3258_LIBFPRINT_USB_OUT_BLOCK_SIZE: usize = 64;
/// Read allocation used by short ACK/completion transfers.
pub const GF3258_LIBFPRINT_A8_READ_SIZE: usize = 64;
/// Per-transfer timeout used by the bounded A8 startup probe.
pub const GF3258_LIBFPRINT_A8_TIMEOUT_MS: u32 = 1_000;
/// Exact physical length of a complete incoming GetImage packet.
pub const GF3258_LIBFPRINT_IMAGE_PACKET_SIZE: usize =
    OUTER_HEADER_LEN + MCU_HEADER_LEN + PROTECTED_IMAGE_LEN;
/// Number of reconstructed GF3258 WN2 pixels returned by one capture.
pub const GF3258_LIBFPRINT_CAPTURE_PIXEL_COUNT: usize = IMAGE_WIDTH * IMAGE_HEIGHT;

/// Exact supported firmware identities for the recovered 27c6:550a lifecycle.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gf3258LibfprintFirmwareIdentity {
    App15045 = 1,
    Iap10007 = 2,
}

impl Gf3258LibfprintFirmwareIdentity {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::App15045 => "GFUSB_GM168SEC_APP_15045",
            Self::Iap10007 => "MILAN_GM168SEC_IAP_10007",
        }
    }
}

/// Immutable metadata for the only APP resource accepted by cold bootstrap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf3258LibfprintBootstrapFirmwareInfo {
    blob_bytes: usize,
    app_bytes: usize,
    blob_crc: u32,
    app_crc: u32,
    header_crc: u32,
    package_bytes: usize,
    f0_chunks: usize,
}

impl Gf3258LibfprintBootstrapFirmwareInfo {
    #[must_use]
    pub const fn blob_bytes(self) -> usize {
        self.blob_bytes
    }

    #[must_use]
    pub const fn app_bytes(self) -> usize {
        self.app_bytes
    }

    #[must_use]
    pub const fn blob_crc(self) -> u32 {
        self.blob_crc
    }

    #[must_use]
    pub const fn app_crc(self) -> u32 {
        self.app_crc
    }

    #[must_use]
    pub const fn header_crc(self) -> u32 {
        self.header_crc
    }

    #[must_use]
    pub const fn package_bytes(self) -> usize {
        self.package_bytes
    }

    #[must_use]
    pub const fn f0_chunks(self) -> usize {
        self.f0_chunks
    }
}

/// Prepared cold-bootstrap firmware state for the libfprint async executor.
///
/// Construction is deliberately offline: it validates the exact APP15045 resource
/// and builds the recovered WriteApp package without exposing any USB operation.
/// F0 payloads and the F4 tag remain inaccessible until the live persisted PSK has
/// been authenticated against object `0xbb020001`.
pub struct Gf3258LibfprintBootstrapPlan {
    package: AppTransferPackage,
    info: Gf3258LibfprintBootstrapFirmwareInfo,
    f4_tag: Option<[u8; F4_TAG_LEN]>,
}

impl Gf3258LibfprintBootstrapPlan {
    /// Validate the exact recovered APP15045 resource before any firmware write can be exposed.
    pub fn new(firmware_blob: &[u8]) -> Result<Self, Gf3258LibfprintWireError> {
        let blob = FirmwareBlob::parse(firmware_blob)
            .map_err(|error| Gf3258LibfprintWireError::BootstrapFirmware(error.to_string()))?;
        let metadata = str::from_utf8(blob.metadata())
            .map_err(|_| Gf3258LibfprintWireError::BootstrapFirmwareMetadataEncoding)?
            .trim_end_matches('\0');

        if metadata != EXPECTED_APP_VERSION {
            return Err(Gf3258LibfprintWireError::BootstrapFirmwareMetadata {
                expected: EXPECTED_APP_VERSION,
                actual: metadata.to_owned(),
            });
        }

        let package = AppTransferPackage::build(&blob)
            .map_err(|error| Gf3258LibfprintWireError::BootstrapFirmware(error.to_string()))?;
        let info = Gf3258LibfprintBootstrapFirmwareInfo {
            blob_bytes: firmware_blob.len(),
            app_bytes: blob.app().len(),
            blob_crc: blob.stored_crc(),
            app_crc: package.app_crc(),
            header_crc: package.header_crc(),
            package_bytes: package.len(),
            f0_chunks: package.f0_chunk_count(),
        };

        validate_bootstrap_firmware_info(info)?;

        Ok(Self {
            package,
            info,
            f4_tag: None,
        })
    }

    /// Authenticate the persisted PSK and derive the F4 tag for this exact package.
    pub fn authenticate_persisted_psk(
        &mut self,
        sealed_psk: &[u8],
        stored_psk_hash: &[u8],
    ) -> Result<(), Gf3258LibfprintWireError> {
        if self.f4_tag.is_some() {
            return Err(Gf3258LibfprintWireError::BootstrapAlreadyAuthenticated);
        }

        let psk = unseal_psk(sealed_psk)
            .map_err(|error| Gf3258LibfprintWireError::BootstrapPsk(error.to_string()))?;

        if !verify_psk_hash(&psk, stored_psk_hash) {
            return Err(Gf3258LibfprintWireError::BootstrapPskHashMismatch);
        }

        self.f4_tag = Some(firmware_f4_tag(&psk, self.package.bytes()));
        Ok(())
    }

    #[must_use]
    pub const fn firmware_info(&self) -> Gf3258LibfprintBootstrapFirmwareInfo {
        self.info
    }

    #[must_use]
    pub const fn is_authenticated(&self) -> bool {
        self.f4_tag.is_some()
    }

    #[must_use]
    pub const fn f0_chunk_count(&self) -> usize {
        self.info.f0_chunks
    }

    /// Return one exact F0 command payload after live PSK authentication succeeds.
    pub fn f0_payload(&self, index: usize) -> Result<Vec<u8>, Gf3258LibfprintWireError> {
        self.require_authenticated()?;
        self.package.f0_payloads().nth(index).ok_or(
            Gf3258LibfprintWireError::BootstrapF0IndexOutOfRange {
                index,
                count: self.info.f0_chunks,
            },
        )
    }

    /// Return the exact F4 HMAC tag derived from the live persisted PSK.
    pub fn f4_tag(&self) -> Result<&[u8; F4_TAG_LEN], Gf3258LibfprintWireError> {
        self.f4_tag
            .as_ref()
            .ok_or(Gf3258LibfprintWireError::BootstrapNotAuthenticated)
    }

    fn require_authenticated(&self) -> Result<(), Gf3258LibfprintWireError> {
        if self.f4_tag.is_some() {
            Ok(())
        } else {
            Err(Gf3258LibfprintWireError::BootstrapNotAuthenticated)
        }
    }
}

fn validate_bootstrap_firmware_info(
    info: Gf3258LibfprintBootstrapFirmwareInfo,
) -> Result<(), Gf3258LibfprintWireError> {
    let checks = [
        (
            "blob bytes",
            BOOTSTRAP_BLOB_SIZE as u64,
            info.blob_bytes as u64,
        ),
        (
            "APP bytes",
            BOOTSTRAP_APP_SIZE as u64,
            info.app_bytes as u64,
        ),
        ("blob CRC", BOOTSTRAP_BLOB_CRC as u64, info.blob_crc as u64),
        ("APP CRC", BOOTSTRAP_APP_CRC as u64, info.app_crc as u64),
        (
            "header CRC",
            BOOTSTRAP_HEADER_CRC as u64,
            info.header_crc as u64,
        ),
        (
            "package bytes",
            BOOTSTRAP_PACKAGE_SIZE as u64,
            info.package_bytes as u64,
        ),
        (
            "F0 chunks",
            BOOTSTRAP_F0_CHUNKS as u64,
            info.f0_chunks as u64,
        ),
    ];

    for (field, expected, actual) in checks {
        if actual != expected {
            return Err(Gf3258LibfprintWireError::BootstrapFirmwareInvariant {
                field,
                expected,
                actual,
            });
        }
    }

    Ok(())
}

/// Stable stage identifier for the pre-reset cold-bootstrap transfer engine.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gf3258LibfprintBootstrapStage {
    ReadSealedPskWrite = 1,
    ReadSealedPskAck = 2,
    ReadSealedPskCompletion = 3,
    ReadPskHashWrite = 4,
    ReadPskHashAck = 5,
    ReadPskHashCompletion = 6,
    FirmwareWriteBlock = 7,
    FirmwareWriteAck = 8,
    FirmwareWriteCompletion = 9,
    FirmwareCheckWrite = 10,
    FirmwareCheckAck = 11,
    FirmwareCheckCompletion = 12,
    Complete = 13,
}

impl Gf3258LibfprintBootstrapStage {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadSealedPskWrite => "E4 sealed-PSK write",
            Self::ReadSealedPskAck => "E4 sealed-PSK ACK",
            Self::ReadSealedPskCompletion => "E4 sealed-PSK completion",
            Self::ReadPskHashWrite => "E4 PSK-hash write",
            Self::ReadPskHashAck => "E4 PSK-hash ACK",
            Self::ReadPskHashCompletion => "E4 PSK-hash completion",
            Self::FirmwareWriteBlock => "F0 firmware block",
            Self::FirmwareWriteAck => "F0 ACK",
            Self::FirmwareWriteCompletion => "F0 completion",
            Self::FirmwareCheckWrite => "F4 firmware-check write",
            Self::FirmwareCheckAck => "F4 ACK",
            Self::FirmwareCheckCompletion => "F4 completion",
            Self::Complete => "complete before reset",
        }
    }
}

/// One physical transfer requested by the pre-reset cold-bootstrap engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf3258LibfprintBootstrapAction {
    direction: Gf3258LibfprintTransferDirection,
    stage: Gf3258LibfprintBootstrapStage,
    endpoint: u8,
    transfer_length: usize,
    timeout_ms: u32,
    short_is_error: bool,
}

impl Gf3258LibfprintBootstrapAction {
    #[must_use]
    pub const fn direction(self) -> Gf3258LibfprintTransferDirection {
        self.direction
    }

    #[must_use]
    pub const fn stage(self) -> Gf3258LibfprintBootstrapStage {
        self.stage
    }

    #[must_use]
    pub const fn endpoint(self) -> u8 {
        self.endpoint
    }

    #[must_use]
    pub const fn transfer_length(self) -> usize {
        self.transfer_length
    }

    #[must_use]
    pub const fn timeout_ms(self) -> u32 {
        self.timeout_ms
    }

    #[must_use]
    pub const fn short_is_error(self) -> bool {
        self.short_is_error
    }
}

/// Whether one completed physical transfer advanced the bootstrap engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gf3258LibfprintBootstrapProgress {
    Advanced,
    Ignored,
}

/// Final result of the E4 -> F0* -> F4 half of cold bootstrap.
///
/// Reaching this result does not reset the MCU and does not imply that APP has
/// detached, re-enumerated, or passed post-reset version/chip-ID validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf3258LibfprintBootstrapTransferResult {
    f0_chunks_sent: usize,
    firmware_check_result: u8,
}

impl Gf3258LibfprintBootstrapTransferResult {
    #[must_use]
    pub const fn f0_chunks_sent(self) -> usize {
        self.f0_chunks_sent
    }

    #[must_use]
    pub const fn firmware_check_result(self) -> u8 {
        self.firmware_check_result
    }
}

/// Callback-driven pre-reset cold-bootstrap transfer engine.
///
/// The engine performs only the already-recovered persisted-PSK reads and
/// authenticated WriteApp transfer:
///
/// ```text
/// E4 0xbb010002
/// -> E4 0xbb020001
/// -> authenticate PSK
/// -> F0 x 98
/// -> F4 non-zero result
/// -> stop
/// ```
///
/// Every firmware OUT action is exactly one 64-byte physical USB block. Large
/// logical F0 A0 frames are split into sequential blocks and the final block is
/// zero padded through the same helper used by the standalone transport.
/// This engine deliberately contains no A2/ResetChip state.
pub struct Gf3258LibfprintBootstrapEngine {
    plan: Gf3258LibfprintBootstrapPlan,
    stage: Gf3258LibfprintBootstrapStage,
    sealed_psk: Vec<u8>,
    psk_hash: Vec<u8>,
    f0_chunk_index: usize,
    f0_block_index: usize,
    f0_chunks_sent: usize,
    result: Option<Gf3258LibfprintBootstrapTransferResult>,
}

impl Gf3258LibfprintBootstrapEngine {
    /// Validate the exact APP resource and prepare the first read-only E4 action.
    pub fn new(firmware_blob: &[u8]) -> Result<Self, Gf3258LibfprintWireError> {
        Self::from_plan(Gf3258LibfprintBootstrapPlan::new(firmware_blob)?)
    }

    fn from_plan(plan: Gf3258LibfprintBootstrapPlan) -> Result<Self, Gf3258LibfprintWireError> {
        if plan.is_authenticated() {
            return Err(Gf3258LibfprintWireError::BootstrapAlreadyAuthenticated);
        }

        Ok(Self {
            plan,
            stage: Gf3258LibfprintBootstrapStage::ReadSealedPskWrite,
            sealed_psk: Vec::with_capacity(SEALED_PSK_SIZE),
            psk_hash: Vec::with_capacity(PSK_HASH_SIZE),
            f0_chunk_index: 0,
            f0_block_index: 0,
            f0_chunks_sent: 0,
            result: None,
        })
    }

    #[must_use]
    pub const fn stage(&self) -> Gf3258LibfprintBootstrapStage {
        self.stage
    }

    #[must_use]
    pub const fn f0_chunk_index(&self) -> usize {
        self.f0_chunk_index
    }

    #[must_use]
    pub const fn f0_block_index(&self) -> usize {
        self.f0_block_index
    }

    #[must_use]
    pub const fn f0_chunks_sent(&self) -> usize {
        self.f0_chunks_sent
    }

    /// Describe the next physical libfprint-owned transfer.
    pub fn next_action(
        &self,
        output: &mut [u8],
    ) -> Result<Gf3258LibfprintBootstrapAction, Gf3258LibfprintWireError> {
        match self.stage {
            Gf3258LibfprintBootstrapStage::ReadSealedPskWrite => self.psk_read_action(
                SEALED_PSK_OBJECT,
                SEALED_PSK_SIZE,
                self.sealed_psk.len(),
                output,
            ),
            Gf3258LibfprintBootstrapStage::ReadSealedPskAck
            | Gf3258LibfprintBootstrapStage::ReadPskHashAck
            | Gf3258LibfprintBootstrapStage::FirmwareWriteAck
            | Gf3258LibfprintBootstrapStage::FirmwareCheckAck => {
                Ok(bootstrap_in_action(self.stage, BOOTSTRAP_ACK_TIMEOUT_MS))
            }
            Gf3258LibfprintBootstrapStage::ReadSealedPskCompletion
            | Gf3258LibfprintBootstrapStage::ReadPskHashCompletion
            | Gf3258LibfprintBootstrapStage::FirmwareWriteCompletion
            | Gf3258LibfprintBootstrapStage::FirmwareCheckCompletion => Ok(bootstrap_in_action(
                self.stage,
                BOOTSTRAP_COMPLETION_TIMEOUT_MS,
            )),
            Gf3258LibfprintBootstrapStage::ReadPskHashWrite => {
                self.psk_read_action(PSK_HASH_OBJECT, PSK_HASH_SIZE, self.psk_hash.len(), output)
            }
            Gf3258LibfprintBootstrapStage::FirmwareWriteBlock => {
                let frame = self.current_f0_frame()?;
                let chunk = frame
                    .chunks(GF3258_LIBFPRINT_USB_OUT_BLOCK_SIZE)
                    .nth(self.f0_block_index)
                    .ok_or(Gf3258LibfprintWireError::BootstrapF0BlockOutOfRange {
                        chunk: self.f0_chunk_index,
                        block: self.f0_block_index,
                    })?;
                let block = make_usb_out_block(chunk);
                copy_bootstrap_out(self.stage, &block, output, BOOTSTRAP_FIRMWARE_TIMEOUT_MS)
            }
            Gf3258LibfprintBootstrapStage::FirmwareCheckWrite => {
                let tag = self.plan.f4_tag()?;
                let frame = encode_a0_packet(Command::FirmwareCheck, tag)
                    .map_err(|error| Gf3258LibfprintWireError::Protocol(error.to_string()))?;
                if frame.len() > GF3258_LIBFPRINT_USB_OUT_BLOCK_SIZE {
                    return Err(Gf3258LibfprintWireError::BootstrapFirmwareFrameTooLarge {
                        command: Command::FirmwareCheck.as_u8(),
                        length: frame.len(),
                    });
                }
                let block = make_usb_out_block(&frame);
                copy_bootstrap_out(self.stage, &block, output, BOOTSTRAP_FIRMWARE_TIMEOUT_MS)
            }
            Gf3258LibfprintBootstrapStage::Complete => Ok(Gf3258LibfprintBootstrapAction {
                direction: Gf3258LibfprintTransferDirection::Complete,
                stage: self.stage,
                endpoint: 0,
                transfer_length: 0,
                timeout_ms: 0,
                short_is_error: false,
            }),
        }
    }

    /// Feed one completed physical transfer into the transaction engine.
    pub fn complete_transfer(
        &mut self,
        bytes: &[u8],
    ) -> Result<Gf3258LibfprintBootstrapProgress, Gf3258LibfprintWireError> {
        match self.stage {
            Gf3258LibfprintBootstrapStage::ReadSealedPskWrite => {
                self.complete_out(Gf3258LibfprintBootstrapStage::ReadSealedPskAck, bytes)
            }
            Gf3258LibfprintBootstrapStage::ReadSealedPskAck => self.complete_ack(
                bytes,
                Command::PskRead,
                Gf3258LibfprintBootstrapStage::ReadSealedPskCompletion,
            ),
            Gf3258LibfprintBootstrapStage::ReadSealedPskCompletion => {
                let Some(packet) = matching_completion(bytes, Command::PskRead)? else {
                    return Ok(Gf3258LibfprintBootstrapProgress::Ignored);
                };
                let finished = append_psk_read(
                    &packet,
                    SEALED_PSK_OBJECT,
                    SEALED_PSK_SIZE,
                    &mut self.sealed_psk,
                )?;
                self.stage = if finished {
                    Gf3258LibfprintBootstrapStage::ReadPskHashWrite
                } else {
                    Gf3258LibfprintBootstrapStage::ReadSealedPskWrite
                };
                Ok(Gf3258LibfprintBootstrapProgress::Advanced)
            }
            Gf3258LibfprintBootstrapStage::ReadPskHashWrite => {
                self.complete_out(Gf3258LibfprintBootstrapStage::ReadPskHashAck, bytes)
            }
            Gf3258LibfprintBootstrapStage::ReadPskHashAck => self.complete_ack(
                bytes,
                Command::PskRead,
                Gf3258LibfprintBootstrapStage::ReadPskHashCompletion,
            ),
            Gf3258LibfprintBootstrapStage::ReadPskHashCompletion => {
                let Some(packet) = matching_completion(bytes, Command::PskRead)? else {
                    return Ok(Gf3258LibfprintBootstrapProgress::Ignored);
                };
                let finished =
                    append_psk_read(&packet, PSK_HASH_OBJECT, PSK_HASH_SIZE, &mut self.psk_hash)?;
                if finished {
                    self.plan
                        .authenticate_persisted_psk(&self.sealed_psk, &self.psk_hash)?;
                    self.sealed_psk.fill(0);
                    self.sealed_psk.clear();
                    self.psk_hash.fill(0);
                    self.psk_hash.clear();
                    self.stage = Gf3258LibfprintBootstrapStage::FirmwareWriteBlock;
                } else {
                    self.stage = Gf3258LibfprintBootstrapStage::ReadPskHashWrite;
                }
                Ok(Gf3258LibfprintBootstrapProgress::Advanced)
            }
            Gf3258LibfprintBootstrapStage::FirmwareWriteBlock => {
                if !bytes.is_empty() {
                    return Err(Gf3258LibfprintWireError::BootstrapUnexpectedTransferData {
                        stage: self.stage,
                        length: bytes.len(),
                    });
                }
                let frame = self.current_f0_frame()?;
                let block_count = frame.len().div_ceil(GF3258_LIBFPRINT_USB_OUT_BLOCK_SIZE);
                if self.f0_block_index + 1 < block_count {
                    self.f0_block_index += 1;
                } else {
                    self.f0_block_index = 0;
                    self.stage = Gf3258LibfprintBootstrapStage::FirmwareWriteAck;
                }
                Ok(Gf3258LibfprintBootstrapProgress::Advanced)
            }
            Gf3258LibfprintBootstrapStage::FirmwareWriteAck => self.complete_ack(
                bytes,
                Command::FirmwareWrite,
                Gf3258LibfprintBootstrapStage::FirmwareWriteCompletion,
            ),
            Gf3258LibfprintBootstrapStage::FirmwareWriteCompletion => {
                let Some(_packet) = matching_completion(bytes, Command::FirmwareWrite)? else {
                    return Ok(Gf3258LibfprintBootstrapProgress::Ignored);
                };

                self.f0_chunks_sent += 1;
                self.f0_chunk_index += 1;
                self.stage = if self.f0_chunk_index < self.plan.f0_chunk_count() {
                    Gf3258LibfprintBootstrapStage::FirmwareWriteBlock
                } else {
                    Gf3258LibfprintBootstrapStage::FirmwareCheckWrite
                };
                Ok(Gf3258LibfprintBootstrapProgress::Advanced)
            }
            Gf3258LibfprintBootstrapStage::FirmwareCheckWrite => {
                self.complete_out(Gf3258LibfprintBootstrapStage::FirmwareCheckAck, bytes)
            }
            Gf3258LibfprintBootstrapStage::FirmwareCheckAck => self.complete_ack(
                bytes,
                Command::FirmwareCheck,
                Gf3258LibfprintBootstrapStage::FirmwareCheckCompletion,
            ),
            Gf3258LibfprintBootstrapStage::FirmwareCheckCompletion => {
                let Some(packet) = matching_completion(bytes, Command::FirmwareCheck)? else {
                    return Ok(Gf3258LibfprintBootstrapProgress::Ignored);
                };
                let [firmware_check_result] = packet.payload.as_slice() else {
                    return Err(Gf3258LibfprintWireError::BootstrapFirmwareCheckLength {
                        actual: packet.payload.len(),
                    });
                };
                if *firmware_check_result == 0 {
                    return Err(Gf3258LibfprintWireError::BootstrapFirmwareCheckRejected);
                }
                if self.f0_chunks_sent != self.plan.f0_chunk_count() {
                    return Err(Gf3258LibfprintWireError::BootstrapF0CountMismatch {
                        expected: self.plan.f0_chunk_count(),
                        actual: self.f0_chunks_sent,
                    });
                }
                self.result = Some(Gf3258LibfprintBootstrapTransferResult {
                    f0_chunks_sent: self.f0_chunks_sent,
                    firmware_check_result: *firmware_check_result,
                });
                self.stage = Gf3258LibfprintBootstrapStage::Complete;
                Ok(Gf3258LibfprintBootstrapProgress::Advanced)
            }
            Gf3258LibfprintBootstrapStage::Complete => {
                Err(Gf3258LibfprintWireError::BootstrapTransferAlreadyComplete)
            }
        }
    }

    /// Return the F0/F4 result after a non-zero F4 completion is accepted.
    pub fn result(
        &self,
    ) -> Result<Gf3258LibfprintBootstrapTransferResult, Gf3258LibfprintWireError> {
        self.result
            .ok_or(Gf3258LibfprintWireError::BootstrapTransferResultNotReady)
    }

    fn psk_read_action(
        &self,
        object_type: u32,
        total: usize,
        received: usize,
        output: &mut [u8],
    ) -> Result<Gf3258LibfprintBootstrapAction, Gf3258LibfprintWireError> {
        let remaining = total
            .checked_sub(received)
            .ok_or(Gf3258LibfprintWireError::BootstrapPskReadOverflow { total, received })?;
        if remaining == 0 {
            return Err(Gf3258LibfprintWireError::BootstrapPskReadOverflow { total, received });
        }
        let requested = remaining.min(PSK_READ_CHUNK_SIZE);
        let offset = u32::try_from(received)
            .map_err(|_| Gf3258LibfprintWireError::BootstrapPskReadOffset(received))?;
        let requested_u32 = u32::try_from(requested)
            .map_err(|_| Gf3258LibfprintWireError::BootstrapPskReadOffset(requested))?;
        let payload = build_psk_read_payload(object_type, offset, requested_u32);
        let frame = encode_a0_packet(Command::PskRead, &payload)
            .map_err(|error| Gf3258LibfprintWireError::Protocol(error.to_string()))?;
        if frame.len() > GF3258_LIBFPRINT_USB_OUT_BLOCK_SIZE {
            return Err(Gf3258LibfprintWireError::BootstrapFirmwareFrameTooLarge {
                command: Command::PskRead.as_u8(),
                length: frame.len(),
            });
        }
        let block = make_usb_out_block(&frame);
        copy_bootstrap_out(self.stage, &block, output, BOOTSTRAP_PSK_TIMEOUT_MS)
    }

    fn current_f0_frame(&self) -> Result<Vec<u8>, Gf3258LibfprintWireError> {
        let payload = self.plan.f0_payload(self.f0_chunk_index)?;
        encode_a0_packet(Command::FirmwareWrite, &payload)
            .map_err(|error| Gf3258LibfprintWireError::Protocol(error.to_string()))
    }

    fn complete_out(
        &mut self,
        next: Gf3258LibfprintBootstrapStage,
        bytes: &[u8],
    ) -> Result<Gf3258LibfprintBootstrapProgress, Gf3258LibfprintWireError> {
        if !bytes.is_empty() {
            return Err(Gf3258LibfprintWireError::BootstrapUnexpectedTransferData {
                stage: self.stage,
                length: bytes.len(),
            });
        }
        self.stage = next;
        Ok(Gf3258LibfprintBootstrapProgress::Advanced)
    }

    fn complete_ack(
        &mut self,
        bytes: &[u8],
        command: Command,
        next: Gf3258LibfprintBootstrapStage,
    ) -> Result<Gf3258LibfprintBootstrapProgress, Gf3258LibfprintWireError> {
        match matching_bootstrap_ack(bytes, command)? {
            PacketDisposition::Accepted => {
                self.stage = next;
                Ok(Gf3258LibfprintBootstrapProgress::Advanced)
            }
            PacketDisposition::Ignored => Ok(Gf3258LibfprintBootstrapProgress::Ignored),
        }
    }
}

fn append_psk_read(
    packet: &McuPacket,
    object_type: u32,
    total: usize,
    output: &mut Vec<u8>,
) -> Result<bool, Gf3258LibfprintWireError> {
    let remaining = total.checked_sub(output.len()).ok_or(
        Gf3258LibfprintWireError::BootstrapPskReadOverflow {
            total,
            received: output.len(),
        },
    )?;
    let requested = remaining.min(PSK_READ_CHUNK_SIZE);
    let data = parse_psk_read_payload(&packet.payload, object_type, requested, remaining)
        .map_err(|error| Gf3258LibfprintWireError::BootstrapPskRead(error.to_string()))?;
    if data.is_empty() {
        return Err(Gf3258LibfprintWireError::BootstrapPskReadEmpty {
            object_type,
            received: output.len(),
            total,
        });
    }
    output.extend_from_slice(data);
    Ok(output.len() == total)
}

fn copy_bootstrap_out(
    stage: Gf3258LibfprintBootstrapStage,
    block: &[u8; GF3258_LIBFPRINT_USB_OUT_BLOCK_SIZE],
    output: &mut [u8],
    timeout_ms: u32,
) -> Result<Gf3258LibfprintBootstrapAction, Gf3258LibfprintWireError> {
    if output.len() < block.len() {
        return Err(Gf3258LibfprintWireError::BootstrapOutputBufferTooSmall {
            required: block.len(),
            actual: output.len(),
        });
    }
    output[..block.len()].copy_from_slice(block);
    Ok(Gf3258LibfprintBootstrapAction {
        direction: Gf3258LibfprintTransferDirection::Out,
        stage,
        endpoint: GF3258_LIBFPRINT_BULK_OUT,
        transfer_length: block.len(),
        timeout_ms,
        short_is_error: true,
    })
}

fn bootstrap_in_action(
    stage: Gf3258LibfprintBootstrapStage,
    timeout_ms: u32,
) -> Gf3258LibfprintBootstrapAction {
    Gf3258LibfprintBootstrapAction {
        direction: Gf3258LibfprintTransferDirection::In,
        stage,
        endpoint: GF3258_LIBFPRINT_BULK_IN,
        transfer_length: BOOTSTRAP_SHORT_READ_SIZE,
        timeout_ms,
        short_is_error: false,
    }
}

fn matching_bootstrap_ack(
    bytes: &[u8],
    expected: Command,
) -> Result<PacketDisposition, Gf3258LibfprintWireError> {
    let packet = decode_packet(bytes)?;
    if packet.is_command(Command::Ack) {
        let [command, _flags] = packet.payload.as_slice() else {
            return Err(Gf3258LibfprintWireError::MalformedAck {
                payload_len: packet.payload.len(),
            });
        };
        if *command == expected.as_u8() {
            return Ok(PacketDisposition::Accepted);
        }
        return Ok(PacketDisposition::Ignored);
    }
    if packet.command == expected.as_u8() {
        return Err(Gf3258LibfprintWireError::BootstrapResponseBeforeAck {
            command: expected.as_u8(),
        });
    }
    Ok(PacketDisposition::Ignored)
}

/// Parsed B0 state for the post-re-enumeration qualification commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf3258LibfprintPostbootAck {
    flags: u8,
}

impl Gf3258LibfprintPostbootAck {
    #[must_use]
    pub const fn flags(self) -> u8 {
        self.flags
    }

    #[must_use]
    pub const fn mcu_power_lost(self) -> bool {
        self.flags & ACK_FLAG_MCU_POWER_LOST != 0
    }
}

/// Parsed B0 state returned by the post-F4 A2 bootstrap reset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf3258LibfprintBootstrapResetAck {
    flags: u8,
}

impl Gf3258LibfprintBootstrapResetAck {
    #[must_use]
    pub const fn flags(self) -> u8 {
        self.flags
    }

    #[must_use]
    pub const fn mcu_power_lost(self) -> bool {
        self.flags & ACK_FLAG_MCU_POWER_LOST != 0
    }
}

/// Parsed B0 state returned by A8 GetVersion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf3258LibfprintVersionAck {
    flags: u8,
}

impl Gf3258LibfprintVersionAck {
    #[must_use]
    pub const fn flags(self) -> u8 {
        self.flags
    }

    #[must_use]
    pub const fn mcu_power_lost(self) -> bool {
        (self.flags & ACK_FLAG_MCU_POWER_LOST) != 0
    }
}

/// Direction of the next libfprint-owned physical transfer.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gf3258LibfprintTransferDirection {
    Complete = 0,
    Out = 1,
    In = 2,
}

/// Stable capture-engine stage identifier exposed only for diagnostics.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gf3258LibfprintCaptureStage {
    D2Write = 1,
    D2Ack = 2,
    D2Completion = 3,
    FingerDownWrite = 4,
    FingerDownAck = 5,
    FingerDownCompletion = 6,
    GetImageWrite = 7,
    GetImageAck = 8,
    GetImageCompletion = 9,
    FingerUpWrite = 10,
    FingerUpAck = 11,
    FingerUpCompletion = 12,
    Complete = 13,
}

impl Gf3258LibfprintCaptureStage {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::D2Write => "D2 write",
            Self::D2Ack => "D2 ACK",
            Self::D2Completion => "D2 completion",
            Self::FingerDownWrite => "FDT-down write",
            Self::FingerDownAck => "FDT-down ACK",
            Self::FingerDownCompletion => "finger-down completion",
            Self::GetImageWrite => "GetImage write",
            Self::GetImageAck => "GetImage ACK",
            Self::GetImageCompletion => "GetImage completion",
            Self::FingerUpWrite => "FDT-up write",
            Self::FingerUpAck => "FDT-up ACK",
            Self::FingerUpCompletion => "finger-up completion",
            Self::Complete => "complete",
        }
    }
}

/// One physical transfer requested by the callback-driven Rust capture engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf3258LibfprintCaptureAction {
    direction: Gf3258LibfprintTransferDirection,
    stage: Gf3258LibfprintCaptureStage,
    endpoint: u8,
    transfer_length: usize,
    timeout_ms: u32,
    short_is_error: bool,
}

impl Gf3258LibfprintCaptureAction {
    #[must_use]
    pub const fn direction(self) -> Gf3258LibfprintTransferDirection {
        self.direction
    }

    #[must_use]
    pub const fn stage(self) -> Gf3258LibfprintCaptureStage {
        self.stage
    }

    #[must_use]
    pub const fn endpoint(self) -> u8 {
        self.endpoint
    }

    #[must_use]
    pub const fn transfer_length(self) -> usize {
        self.transfer_length
    }

    #[must_use]
    pub const fn timeout_ms(self) -> u32 {
        self.timeout_ms
    }

    #[must_use]
    pub const fn short_is_error(self) -> bool {
        self.short_is_error
    }
}

/// Whether one incoming packet advanced the logical capture transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gf3258LibfprintCaptureProgress {
    Advanced,
    Ignored,
}

/// Stable ChicagoH volatile-recovery stage identifier exposed for diagnostics.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gf3258LibfprintRecoveryStage {
    ReadOtpWrite = 1,
    ReadOtpAck = 2,
    ReadOtpCompletion = 3,
    DownloadConfigWrite = 4,
    DownloadConfigAck = 5,
    DownloadConfigCompletion = 6,
    Complete = 7,
}

impl Gf3258LibfprintRecoveryStage {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOtpWrite => "A6 GetOtp write",
            Self::ReadOtpAck => "A6 GetOtp ACK",
            Self::ReadOtpCompletion => "A6 GetOtp completion",
            Self::DownloadConfigWrite => "0x90 DownloadConfig write",
            Self::DownloadConfigAck => "0x90 DownloadConfig ACK",
            Self::DownloadConfigCompletion => "0x90 DownloadConfig completion",
            Self::Complete => "complete",
        }
    }
}

/// One physical transfer requested by the callback-driven ChicagoH recovery engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf3258LibfprintRecoveryAction {
    direction: Gf3258LibfprintTransferDirection,
    stage: Gf3258LibfprintRecoveryStage,
    endpoint: u8,
    transfer_length: usize,
    timeout_ms: u32,
    short_is_error: bool,
}

impl Gf3258LibfprintRecoveryAction {
    #[must_use]
    pub const fn direction(self) -> Gf3258LibfprintTransferDirection {
        self.direction
    }
    #[must_use]
    pub const fn stage(self) -> Gf3258LibfprintRecoveryStage {
        self.stage
    }
    #[must_use]
    pub const fn endpoint(self) -> u8 {
        self.endpoint
    }
    #[must_use]
    pub const fn transfer_length(self) -> usize {
        self.transfer_length
    }
    #[must_use]
    pub const fn timeout_ms(self) -> u32 {
        self.timeout_ms
    }
    #[must_use]
    pub const fn short_is_error(self) -> bool {
        self.short_is_error
    }
}

/// Final calibration/configuration summary after volatile ChicagoH recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf3258LibfprintRecoveryResult {
    tcode: u16,
    diff: u16,
    fdt_offset: u8,
    checksum: u16,
}

impl Gf3258LibfprintRecoveryResult {
    #[must_use]
    pub const fn tcode(self) -> u16 {
        self.tcode
    }
    #[must_use]
    pub const fn diff(self) -> u16 {
        self.diff
    }
    #[must_use]
    pub const fn fdt_offset(self) -> u8 {
        self.fdt_offset
    }
    #[must_use]
    pub const fn checksum(self) -> u16 {
        self.checksum
    }
}

/// Final image material after FDT-up has been armed and the protected frame has
/// passed the existing AES/CRC/reconstruction path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gf3258LibfprintCaptureResult {
    raw_u16: Vec<u16>,
    normalized_u8: Vec<u8>,
    protected_bytes: usize,
    stored_crc: u32,
}

impl Gf3258LibfprintCaptureResult {
    /// Reconstructed 12-bit GF3258 frame used by the biometric verifier.
    #[must_use]
    pub fn raw_u16(&self) -> &[u16] {
        &self.raw_u16
    }

    #[must_use]
    pub fn normalized_u8(&self) -> &[u8] {
        &self.normalized_u8
    }

    #[must_use]
    pub const fn protected_bytes(&self) -> usize {
        self.protected_bytes
    }

    #[must_use]
    pub const fn stored_crc(&self) -> u32 {
        self.stored_crc
    }

    #[must_use]
    pub fn pixel_count(&self) -> usize {
        self.normalized_u8.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gf3258LibfprintWireError {
    Protocol(String),
    UnexpectedCommand {
        expected: u8,
        actual: u8,
    },
    MalformedAck {
        payload_len: usize,
    },
    AckForWrongCommand {
        command: u8,
    },
    VersionMissingNul,
    VersionUtf8,
    UnsupportedFirmware(String),
    BootstrapFirmware(String),
    BootstrapFirmwareMetadataEncoding,
    BootstrapFirmwareMetadata {
        expected: &'static str,
        actual: String,
    },
    BootstrapFirmwareInvariant {
        field: &'static str,
        expected: u64,
        actual: u64,
    },
    BootstrapPsk(String),
    BootstrapPskHashMismatch,
    BootstrapAlreadyAuthenticated,
    BootstrapNotAuthenticated,
    BootstrapF0IndexOutOfRange {
        index: usize,
        count: usize,
    },
    BootstrapOutputBufferTooSmall {
        required: usize,
        actual: usize,
    },
    BootstrapUnexpectedTransferData {
        stage: Gf3258LibfprintBootstrapStage,
        length: usize,
    },
    BootstrapResponseBeforeAck {
        command: u8,
    },
    BootstrapPskRead(String),
    BootstrapPskReadEmpty {
        object_type: u32,
        received: usize,
        total: usize,
    },
    BootstrapPskReadOverflow {
        total: usize,
        received: usize,
    },
    BootstrapPskReadOffset(usize),
    BootstrapF0BlockOutOfRange {
        chunk: usize,
        block: usize,
    },
    BootstrapFirmwareFrameTooLarge {
        command: u8,
        length: usize,
    },
    BootstrapFirmwareCheckLength {
        actual: usize,
    },
    BootstrapFirmwareCheckRejected,
    BootstrapF0CountMismatch {
        expected: usize,
        actual: usize,
    },
    BootstrapTransferResultNotReady,
    BootstrapTransferAlreadyComplete,
    RecoveryOutputBufferTooSmall {
        required: usize,
        actual: usize,
    },
    RecoveryUnexpectedTransferData {
        stage: Gf3258LibfprintRecoveryStage,
        length: usize,
    },
    RecoveryResponseBeforeAck {
        command: u8,
    },
    RecoveryOtpLength {
        expected: usize,
        actual: usize,
    },
    RecoveryChicagoH(String),
    RecoveryConfigNotReady,
    RecoveryAlreadyComplete,
    RecoveryResultNotReady,
    CaptureRandom(String),
    CaptureOutputBufferTooSmall {
        required: usize,
        actual: usize,
    },
    CaptureUnexpectedTransferData {
        stage: Gf3258LibfprintCaptureStage,
        length: usize,
    },
    CaptureResponseBeforeAck {
        command: u8,
    },
    CaptureAlreadyComplete,
    CaptureResultNotReady,
    BootImage,
    Image(String),
    Crypto(String),
    UnexpectedPixelCount {
        expected: usize,
        actual: usize,
    },
    Enrollment(String),
    EnrollmentResultNotReady,
    EnrollmentNextTouchNotReady,
    EnrollmentAlreadyComplete,
    EnrollmentTglaNotReady,
    VerificationTemplate(String),
    Verification(String),
    VerificationResultNotReady,
}

impl fmt::Display for Gf3258LibfprintWireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(message) => write!(f, "Goodix protocol error: {message}"),
            Self::UnexpectedCommand { expected, actual } => write!(
                f,
                "Goodix command mismatch: expected 0x{expected:02x}, received 0x{actual:02x}",
            ),
            Self::MalformedAck { payload_len } => {
                write!(f, "A8 ACK payload has {payload_len} bytes, expected 2")
            }
            Self::AckForWrongCommand { command } => {
                write!(f, "A8 ACK echoed command 0x{command:02x}")
            }
            Self::VersionMissingNul => f.write_str("A8 version response is not NUL terminated"),
            Self::VersionUtf8 => f.write_str("A8 version response is not valid UTF-8"),
            Self::UnsupportedFirmware(version) => {
                write!(f, "unsupported Goodix firmware identity: {version}")
            }
            Self::BootstrapFirmware(message) => {
                write!(f, "cold-bootstrap firmware error: {message}")
            }
            Self::BootstrapFirmwareMetadataEncoding => {
                f.write_str("cold-bootstrap firmware metadata is not valid UTF-8")
            }
            Self::BootstrapFirmwareMetadata { expected, actual } => write!(
                f,
                "cold-bootstrap firmware metadata mismatch: expected {expected}, received {actual}",
            ),
            Self::BootstrapFirmwareInvariant {
                field,
                expected,
                actual,
            } => write!(
                f,
                "cold-bootstrap firmware invariant mismatch for {field}: expected 0x{expected:x}, received 0x{actual:x}",
            ),
            Self::BootstrapPsk(message) => write!(f, "cold-bootstrap PSK error: {message}"),
            Self::BootstrapPskHashMismatch => {
                f.write_str("cold-bootstrap persisted PSK failed SHA-256 verification")
            }
            Self::BootstrapAlreadyAuthenticated => {
                f.write_str("cold-bootstrap PSK is already authenticated")
            }
            Self::BootstrapNotAuthenticated => {
                f.write_str("cold-bootstrap firmware transfer is not authenticated")
            }
            Self::BootstrapF0IndexOutOfRange { index, count } => write!(
                f,
                "cold-bootstrap F0 index {index} is out of range for {count} chunks",
            ),
            Self::BootstrapOutputBufferTooSmall { required, actual } => write!(
                f,
                "cold-bootstrap OUT buffer is too small: required {required} bytes, received {actual}",
            ),
            Self::BootstrapUnexpectedTransferData { stage, length } => write!(
                f,
                "cold-bootstrap stage {} completed with unexpected host data ({length} bytes)",
                stage.as_str(),
            ),
            Self::BootstrapResponseBeforeAck { command } => write!(
                f,
                "cold-bootstrap command 0x{command:02x} completion arrived before its ACK",
            ),
            Self::BootstrapPskRead(message) => {
                write!(f, "cold-bootstrap E4 read error: {message}")
            }
            Self::BootstrapPskReadEmpty {
                object_type,
                received,
                total,
            } => write!(
                f,
                "cold-bootstrap E4 object 0x{object_type:08x} returned no progress at {received}/{total} bytes",
            ),
            Self::BootstrapPskReadOverflow { total, received } => write!(
                f,
                "cold-bootstrap E4 read state exceeds object length: received {received}, total {total}",
            ),
            Self::BootstrapPskReadOffset(value) => write!(
                f,
                "cold-bootstrap E4 offset/length does not fit u32: {value}",
            ),
            Self::BootstrapF0BlockOutOfRange { chunk, block } => write!(
                f,
                "cold-bootstrap F0 chunk {chunk} has no physical block {block}",
            ),
            Self::BootstrapFirmwareFrameTooLarge { command, length } => write!(
                f,
                "cold-bootstrap command 0x{command:02x} unexpectedly requires {length} bytes in a single physical block",
            ),
            Self::BootstrapFirmwareCheckLength { actual } => write!(
                f,
                "cold-bootstrap F4 completion has {actual} payload bytes; expected exactly one",
            ),
            Self::BootstrapFirmwareCheckRejected => {
                f.write_str("cold-bootstrap F4 firmware check returned zero")
            }
            Self::BootstrapF0CountMismatch { expected, actual } => write!(
                f,
                "cold-bootstrap F0 count mismatch: expected {expected}, completed {actual}",
            ),
            Self::BootstrapTransferResultNotReady => {
                f.write_str("cold-bootstrap F0/F4 result is not ready")
            }
            Self::BootstrapTransferAlreadyComplete => {
                f.write_str("cold-bootstrap F0/F4 transaction is already complete")
            }
            Self::RecoveryOutputBufferTooSmall { required, actual } => write!(
                f,
                "ChicagoH recovery OUT buffer is too small: required {required} bytes, received {actual}",
            ),
            Self::RecoveryUnexpectedTransferData { stage, length } => write!(
                f,
                "ChicagoH recovery stage {} completed with unexpected host data ({length} bytes)",
                stage.as_str(),
            ),
            Self::RecoveryResponseBeforeAck { command } => write!(
                f,
                "ChicagoH command 0x{command:02x} completion arrived before its ACK",
            ),
            Self::RecoveryOtpLength { expected, actual } => write!(
                f,
                "ChicagoH A6 returned {actual} OTP bytes, expected {expected}",
            ),
            Self::RecoveryChicagoH(message) => write!(f, "ChicagoH recovery error: {message}"),
            Self::RecoveryConfigNotReady => {
                f.write_str("ChicagoH generated configuration is not ready")
            }
            Self::RecoveryAlreadyComplete => f.write_str("ChicagoH recovery is already complete"),
            Self::RecoveryResultNotReady => f.write_str("ChicagoH recovery result is not ready"),
            Self::CaptureRandom(message) => {
                write!(f, "failed to generate D2 image-session material: {message}")
            }
            Self::CaptureOutputBufferTooSmall { required, actual } => write!(
                f,
                "capture OUT buffer is too small: required {required} bytes, received {actual}",
            ),
            Self::CaptureUnexpectedTransferData { stage, length } => write!(
                f,
                "capture stage {} completed with unexpected host data ({length} bytes)",
                stage.as_str(),
            ),
            Self::CaptureResponseBeforeAck { command } => write!(
                f,
                "capture command 0x{command:02x} completion arrived before its ACK",
            ),
            Self::CaptureAlreadyComplete => f.write_str("capture transaction is already complete"),
            Self::CaptureResultNotReady => f.write_str("capture result is not ready"),
            Self::BootImage => {
                f.write_str("sensor returned a boot image instead of a fingerprint frame")
            }
            Self::Image(message) => write!(f, "fingerprint image error: {message}"),
            Self::Crypto(message) => write!(f, "fingerprint decryption error: {message}"),
            Self::UnexpectedPixelCount { expected, actual } => write!(
                f,
                "unexpected reconstructed pixel count: expected {expected}, received {actual}",
            ),
            Self::Enrollment(message) => write!(f, "enrollment error: {message}"),
            Self::EnrollmentResultNotReady => f.write_str("enrollment touch result is not ready"),
            Self::EnrollmentNextTouchNotReady => {
                f.write_str("enrollment is not waiting for the next touch")
            }
            Self::EnrollmentAlreadyComplete => f.write_str("enrollment is already complete"),
            Self::EnrollmentTglaNotReady => f.write_str("enrollment TGLA is not ready"),
            Self::VerificationTemplate(message) => {
                write!(f, "verification template error: {message}")
            }
            Self::Verification(message) => write!(f, "verification error: {message}"),
            Self::VerificationResultNotReady => f.write_str("verification result is not ready"),
        }
    }
}

impl Error for Gf3258LibfprintWireError {}

fn gf3258_libfprint_parse_postboot_ack_for(
    bytes: &[u8],
    expected: Command,
) -> Result<Gf3258LibfprintPostbootAck, Gf3258LibfprintWireError> {
    let packet = decode_a0_packet(bytes)
        .map_err(|error| Gf3258LibfprintWireError::Protocol(error.to_string()))?;

    if !packet.is_command(Command::Ack) {
        return Err(Gf3258LibfprintWireError::UnexpectedCommand {
            expected: Command::Ack.as_u8(),
            actual: packet.command,
        });
    }

    let [command, flags] = packet.payload.as_slice() else {
        return Err(Gf3258LibfprintWireError::MalformedAck {
            payload_len: packet.payload.len(),
        });
    };

    if *command != expected.as_u8() {
        return Err(Gf3258LibfprintWireError::AckForWrongCommand { command: *command });
    }

    Ok(Gf3258LibfprintPostbootAck { flags: *flags })
}

/// Build the exact 64-byte `McuResetFingerPrint` request used after APP
/// re-enumeration.
///
/// # Errors
///
/// Returns a protocol error if the recovered `A2 05 14` request can no longer
/// be represented as one Goodix USB OUT block.
pub fn gf3258_libfprint_build_postboot_reset_request()
-> Result<[u8; GF3258_LIBFPRINT_USB_OUT_BLOCK_SIZE], Gf3258LibfprintWireError> {
    encode_a0_single(Command::ResetChip, &POSTBOOT_RESET_PAYLOAD)
        .map_err(|error| Gf3258LibfprintWireError::Protocol(error.to_string()))
}

/// Parse the matching B0 ACK for `McuResetFingerPrint`.
///
/// # Errors
///
/// Returns an error for malformed framing, a non-B0 packet, malformed ACK
/// payload, or an ACK for a command other than A2 ResetChip.
pub fn gf3258_libfprint_parse_postboot_reset_ack(
    bytes: &[u8],
) -> Result<Gf3258LibfprintPostbootAck, Gf3258LibfprintWireError> {
    gf3258_libfprint_parse_postboot_ack_for(bytes, Command::ResetChip)
}

/// Validate the A2 completion that follows `McuResetFingerPrint`.
///
/// The recovered standalone path does not assign semantics to the completion
/// payload; only valid Goodix framing and the matching A2 command identity are
/// required here.
///
/// # Errors
///
/// Returns an error for malformed framing or a completion for another command.
pub fn gf3258_libfprint_parse_postboot_reset_response(
    bytes: &[u8],
) -> Result<(), Gf3258LibfprintWireError> {
    let packet = decode_a0_packet(bytes)
        .map_err(|error| Gf3258LibfprintWireError::Protocol(error.to_string()))?;
    if !packet.is_command(Command::ResetChip) {
        return Err(Gf3258LibfprintWireError::UnexpectedCommand {
            expected: Command::ResetChip.as_u8(),
            actual: packet.command,
        });
    }
    Ok(())
}

/// Build `_McuReadRegister(address=0x0000, length=4)` used by McuGetChipId.
///
/// # Errors
///
/// Returns a protocol error if the recovered read-register request can no longer
/// be represented as one Goodix USB OUT block.
pub fn gf3258_libfprint_build_chip_id_request()
-> Result<[u8; GF3258_LIBFPRINT_USB_OUT_BLOCK_SIZE], Gf3258LibfprintWireError> {
    encode_a0_single(Command::ReadRegister, &CHIP_ID_READ_PAYLOAD)
        .map_err(|error| Gf3258LibfprintWireError::Protocol(error.to_string()))
}

/// Parse the matching B0 ACK for McuGetChipId.
///
/// # Errors
///
/// Returns an error for malformed framing, a non-B0 packet, malformed ACK
/// payload, or an ACK for a command other than 0x82 ReadRegister.
pub fn gf3258_libfprint_parse_chip_id_ack(
    bytes: &[u8],
) -> Result<Gf3258LibfprintPostbootAck, Gf3258LibfprintWireError> {
    gf3258_libfprint_parse_postboot_ack_for(bytes, Command::ReadRegister)
}

/// Parse and strictly validate the GF3258 WN2 chip-ID completion.
///
/// The four payload bytes are converted exactly like the recovered vendor helper:
/// bytes are swapped within each 16-bit word before interpreting the result as a
/// little-endian u32. Only `0x002503a8` is accepted for this target.
///
/// # Errors
///
/// Returns an error for malformed framing, a non-0x82 response, a payload length
/// other than four bytes, or a chip ID other than the recovered GF3258 value.
pub fn gf3258_libfprint_validate_chip_id_response(
    bytes: &[u8],
) -> Result<u32, Gf3258LibfprintWireError> {
    let packet = decode_a0_packet(bytes)
        .map_err(|error| Gf3258LibfprintWireError::Protocol(error.to_string()))?;
    if !packet.is_command(Command::ReadRegister) {
        return Err(Gf3258LibfprintWireError::UnexpectedCommand {
            expected: Command::ReadRegister.as_u8(),
            actual: packet.command,
        });
    }

    let [b0, b1, b2, b3] = packet.payload.as_slice() else {
        return Err(Gf3258LibfprintWireError::Protocol(format!(
            "malformed 0x82 chip-ID response: expected exactly 4 payload bytes, received {}",
            packet.payload.len()
        )));
    };

    let chip_id = u32::from_le_bytes([*b1, *b0, *b3, *b2]);
    if chip_id != GF3258_LIBFPRINT_EXPECTED_CHIP_ID {
        return Err(Gf3258LibfprintWireError::Protocol(format!(
            "unexpected Goodix chip ID: expected 0x{GF3258_LIBFPRINT_EXPECTED_CHIP_ID:08x}, received 0x{chip_id:08x}"
        )));
    }

    Ok(chip_id)
}

/// Build the exact 64-byte A2 request that commits a verified APP package.
///
/// This is the recovered post-F4 `A2 02 32` transaction. Sending it invalidates
/// the current USB instance; detach/re-enumeration remains a separate lifecycle
/// responsibility and is deliberately not performed by this function.
///
/// # Errors
///
/// Returns a protocol error if the recovered request can no longer be represented
/// as one Goodix USB OUT block.
pub fn gf3258_libfprint_build_bootstrap_reset_request()
-> Result<[u8; GF3258_LIBFPRINT_USB_OUT_BLOCK_SIZE], Gf3258LibfprintWireError> {
    encode_a0_single(Command::ResetChip, &BOOTSTRAP_RESET_PAYLOAD)
        .map_err(|error| Gf3258LibfprintWireError::Protocol(error.to_string()))
}

/// Build the exact captured 64-byte A8 GetVersion OUT transfer.
///
/// # Errors
///
/// Returns a protocol error if the recovered two-byte request can no longer be
/// represented as a single Goodix USB block.
pub fn gf3258_libfprint_build_get_version_request()
-> Result<[u8; GF3258_LIBFPRINT_USB_OUT_BLOCK_SIZE], Gf3258LibfprintWireError> {
    encode_a0_single(Command::GetVersion, &GET_VERSION_PAYLOAD)
        .map_err(|error| Gf3258LibfprintWireError::Protocol(error.to_string()))
}

/// Parse the matching B0 ACK for an A8 GetVersion transaction.
///
/// The second B0 byte remains a flag field. In particular, bit `0x02` reports
/// MCU volatile-state loss and is not a transaction failure.
///
/// # Errors
///
/// Returns an error for malformed Goodix framing, a non-B0 packet, malformed
/// ACK payload, or an ACK for a different command.
pub fn gf3258_libfprint_parse_get_version_ack(
    bytes: &[u8],
) -> Result<Gf3258LibfprintVersionAck, Gf3258LibfprintWireError> {
    let packet = decode_packet(bytes)?;

    if !packet.is_command(Command::Ack) {
        return Err(Gf3258LibfprintWireError::UnexpectedCommand {
            expected: Command::Ack.as_u8(),
            actual: packet.command,
        });
    }

    let [command, flags] = packet.payload.as_slice() else {
        return Err(Gf3258LibfprintWireError::MalformedAck {
            payload_len: packet.payload.len(),
        });
    };

    if *command != Command::GetVersion.as_u8() {
        return Err(Gf3258LibfprintWireError::AckForWrongCommand { command: *command });
    }

    Ok(Gf3258LibfprintVersionAck { flags: *flags })
}

/// Parse the matching B0 ACK for the post-F4 A2 bootstrap reset.
///
/// The second B0 byte remains a flag field exactly as it does for other Goodix
/// acknowledgements; bit `0x02` reports volatile-state loss and is not treated as
/// generic transaction failure.
///
/// # Errors
///
/// Returns an error for malformed Goodix framing, a non-B0 packet, malformed ACK
/// payload, or an ACK for a command other than A2 ResetChip.
pub fn gf3258_libfprint_parse_bootstrap_reset_ack(
    bytes: &[u8],
) -> Result<Gf3258LibfprintBootstrapResetAck, Gf3258LibfprintWireError> {
    let packet = decode_a0_packet(bytes)
        .map_err(|error| Gf3258LibfprintWireError::Protocol(error.to_string()))?;

    if !packet.is_command(Command::Ack) {
        return Err(Gf3258LibfprintWireError::UnexpectedCommand {
            expected: Command::Ack.as_u8(),
            actual: packet.command,
        });
    }

    let [command, flags] = packet.payload.as_slice() else {
        return Err(Gf3258LibfprintWireError::MalformedAck {
            payload_len: packet.payload.len(),
        });
    };

    if *command != Command::ResetChip.as_u8() {
        return Err(Gf3258LibfprintWireError::AckForWrongCommand { command: *command });
    }

    Ok(Gf3258LibfprintBootstrapResetAck { flags: *flags })
}

/// Parse and classify the A8 GetVersion completion packet.
///
/// The recovered APP/IAP identities are intentionally exact. Unknown firmware
/// is rejected before later lifecycle operations can run.
///
/// # Errors
///
/// Returns an error for malformed Goodix framing, a non-A8 completion,
/// missing NUL termination, invalid UTF-8, or an unsupported firmware string.
pub fn gf3258_libfprint_parse_get_version_response(
    bytes: &[u8],
) -> Result<Gf3258LibfprintFirmwareIdentity, Gf3258LibfprintWireError> {
    let packet = decode_packet(bytes)?;

    if !packet.is_command(Command::GetVersion) {
        return Err(Gf3258LibfprintWireError::UnexpectedCommand {
            expected: Command::GetVersion.as_u8(),
            actual: packet.command,
        });
    }

    let Some(version_bytes) = packet.payload.strip_suffix(&[0]) else {
        return Err(Gf3258LibfprintWireError::VersionMissingNul);
    };

    let version =
        str::from_utf8(version_bytes).map_err(|_| Gf3258LibfprintWireError::VersionUtf8)?;

    match version {
        "GFUSB_GM168SEC_APP_15045" => Ok(Gf3258LibfprintFirmwareIdentity::App15045),
        "MILAN_GM168SEC_IAP_10007" => Ok(Gf3258LibfprintFirmwareIdentity::Iap10007),
        _ => Err(Gf3258LibfprintWireError::UnsupportedFirmware(
            version.to_owned(),
        )),
    }
}

/// Callback-driven APP volatile-state recovery engine.
///
/// This reproduces the validated ChicagoH path without giving USB ownership to
/// Rust: A6 GetOtp -> exact OTP validation/config derivation -> one exact
/// 264-byte 0x90 DownloadConfig transaction -> success payload [01 00].
pub struct Gf3258LibfprintRecoveryEngine {
    stage: Gf3258LibfprintRecoveryStage,
    config: Option<ChicagoHConfig>,
    result: Option<Gf3258LibfprintRecoveryResult>,
}

impl Gf3258LibfprintRecoveryEngine {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            stage: Gf3258LibfprintRecoveryStage::ReadOtpWrite,
            config: None,
            result: None,
        }
    }

    #[must_use]
    pub const fn stage(&self) -> Gf3258LibfprintRecoveryStage {
        self.stage
    }

    /// Describe the next physical transfer and populate OUT bytes when needed.
    ///
    /// # Errors
    ///
    /// Returns an error when the caller's scratch buffer is too small or when
    /// the recovered protocol packet can no longer be encoded exactly.
    pub fn next_action(
        &self,
        output: &mut [u8],
    ) -> Result<Gf3258LibfprintRecoveryAction, Gf3258LibfprintWireError> {
        match self.stage {
            Gf3258LibfprintRecoveryStage::ReadOtpWrite => {
                let frame = encode_a0_single(Command::ReadOtp, &READ_OTP_PAYLOAD)
                    .map_err(|error| Gf3258LibfprintWireError::Protocol(error.to_string()))?;
                copy_recovery_out(self.stage, &frame, output, OUT_TRANSFER_TIMEOUT_MS)
            }
            Gf3258LibfprintRecoveryStage::ReadOtpAck => Ok(recovery_in_action(
                self.stage,
                GF3258_LIBFPRINT_A8_READ_SIZE,
                RECOVERY_ACK_TIMEOUT_MS,
            )),
            Gf3258LibfprintRecoveryStage::ReadOtpCompletion => Ok(recovery_in_action(
                self.stage,
                RECOVERY_SHORT_READ_SIZE,
                RECOVERY_COMPLETION_TIMEOUT_MS,
            )),
            Gf3258LibfprintRecoveryStage::DownloadConfigWrite => {
                let config = self
                    .config
                    .as_ref()
                    .ok_or(Gf3258LibfprintWireError::RecoveryConfigNotReady)?;
                let frame = encode_a0_packet(Command::DownloadConfig, &config.bytes)
                    .map_err(|error| Gf3258LibfprintWireError::Protocol(error.to_string()))?;
                if frame.len() != DOWNLOAD_CONFIG_PACKET_SIZE {
                    return Err(Gf3258LibfprintWireError::RecoveryChicagoH(format!(
                        "0x90 packet length is {}, expected {DOWNLOAD_CONFIG_PACKET_SIZE}",
                        frame.len()
                    )));
                }
                copy_recovery_out(self.stage, &frame, output, OUT_TRANSFER_TIMEOUT_MS)
            }
            Gf3258LibfprintRecoveryStage::DownloadConfigAck => Ok(recovery_in_action(
                self.stage,
                GF3258_LIBFPRINT_A8_READ_SIZE,
                RECOVERY_ACK_TIMEOUT_MS,
            )),
            Gf3258LibfprintRecoveryStage::DownloadConfigCompletion => Ok(recovery_in_action(
                self.stage,
                GF3258_LIBFPRINT_A8_READ_SIZE,
                RECOVERY_COMPLETION_TIMEOUT_MS,
            )),
            Gf3258LibfprintRecoveryStage::Complete => Ok(Gf3258LibfprintRecoveryAction {
                direction: Gf3258LibfprintTransferDirection::Complete,
                stage: self.stage,
                endpoint: 0,
                transfer_length: 0,
                timeout_ms: 0,
                short_is_error: false,
            }),
        }
    }

    /// Feed one completed libfprint-owned transfer into the recovery engine.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed ordering/framing, invalid OTP, failed
    /// ChicagoH configuration derivation, or an unexpected 0x90 completion.
    pub fn complete_transfer(
        &mut self,
        bytes: &[u8],
    ) -> Result<Gf3258LibfprintCaptureProgress, Gf3258LibfprintWireError> {
        match self.stage {
            Gf3258LibfprintRecoveryStage::ReadOtpWrite => {
                self.complete_out(bytes, Gf3258LibfprintRecoveryStage::ReadOtpAck)
            }
            Gf3258LibfprintRecoveryStage::ReadOtpAck => self.complete_ack(
                bytes,
                Command::ReadOtp,
                Gf3258LibfprintRecoveryStage::ReadOtpCompletion,
            ),
            Gf3258LibfprintRecoveryStage::ReadOtpCompletion => {
                let Some(packet) = matching_completion(bytes, Command::ReadOtp)? else {
                    return Ok(Gf3258LibfprintCaptureProgress::Ignored);
                };
                if packet.payload.len() != OTP_LEN {
                    return Err(Gf3258LibfprintWireError::RecoveryOtpLength {
                        expected: OTP_LEN,
                        actual: packet.payload.len(),
                    });
                }
                let mut otp = [0u8; OTP_LEN];
                otp.copy_from_slice(&packet.payload);
                let config = generate_config(&otp).map_err(|error| {
                    Gf3258LibfprintWireError::RecoveryChicagoH(error.to_string())
                })?;
                self.config = Some(config);
                self.stage = Gf3258LibfprintRecoveryStage::DownloadConfigWrite;
                Ok(Gf3258LibfprintCaptureProgress::Advanced)
            }
            Gf3258LibfprintRecoveryStage::DownloadConfigWrite => {
                self.complete_out(bytes, Gf3258LibfprintRecoveryStage::DownloadConfigAck)
            }
            Gf3258LibfprintRecoveryStage::DownloadConfigAck => self.complete_ack(
                bytes,
                Command::DownloadConfig,
                Gf3258LibfprintRecoveryStage::DownloadConfigCompletion,
            ),
            Gf3258LibfprintRecoveryStage::DownloadConfigCompletion => {
                let Some(packet) = matching_completion(bytes, Command::DownloadConfig)? else {
                    return Ok(Gf3258LibfprintCaptureProgress::Ignored);
                };
                validate_download_completion(&packet).map_err(|error| {
                    Gf3258LibfprintWireError::RecoveryChicagoH(error.to_string())
                })?;
                let config = self
                    .config
                    .as_ref()
                    .ok_or(Gf3258LibfprintWireError::RecoveryConfigNotReady)?;
                self.result = Some(Gf3258LibfprintRecoveryResult {
                    tcode: config.calibration.tcode,
                    diff: config.calibration.diff,
                    fdt_offset: config.calibration.fdt_offset,
                    checksum: config.checksum,
                });
                self.stage = Gf3258LibfprintRecoveryStage::Complete;
                Ok(Gf3258LibfprintCaptureProgress::Advanced)
            }
            Gf3258LibfprintRecoveryStage::Complete => {
                Err(Gf3258LibfprintWireError::RecoveryAlreadyComplete)
            }
        }
    }

    /// Return the generated ChicagoH calibration/configuration summary.
    ///
    /// # Errors
    ///
    /// Returns `RecoveryResultNotReady` until the 0x90 completion is accepted.
    pub fn result(&self) -> Result<Gf3258LibfprintRecoveryResult, Gf3258LibfprintWireError> {
        self.result
            .ok_or(Gf3258LibfprintWireError::RecoveryResultNotReady)
    }

    fn complete_out(
        &mut self,
        bytes: &[u8],
        next: Gf3258LibfprintRecoveryStage,
    ) -> Result<Gf3258LibfprintCaptureProgress, Gf3258LibfprintWireError> {
        if !bytes.is_empty() {
            return Err(Gf3258LibfprintWireError::RecoveryUnexpectedTransferData {
                stage: self.stage,
                length: bytes.len(),
            });
        }
        self.stage = next;
        Ok(Gf3258LibfprintCaptureProgress::Advanced)
    }

    fn complete_ack(
        &mut self,
        bytes: &[u8],
        command: Command,
        next: Gf3258LibfprintRecoveryStage,
    ) -> Result<Gf3258LibfprintCaptureProgress, Gf3258LibfprintWireError> {
        match matching_recovery_ack(bytes, command)? {
            PacketDisposition::Accepted => {
                self.stage = next;
                Ok(Gf3258LibfprintCaptureProgress::Advanced)
            }
            PacketDisposition::Ignored => Ok(Gf3258LibfprintCaptureProgress::Ignored),
        }
    }
}

impl Default for Gf3258LibfprintRecoveryEngine {
    fn default() -> Self {
        Self::new()
    }
}

fn copy_recovery_out(
    stage: Gf3258LibfprintRecoveryStage,
    frame: &[u8],
    output: &mut [u8],
    timeout_ms: u32,
) -> Result<Gf3258LibfprintRecoveryAction, Gf3258LibfprintWireError> {
    if output.len() < frame.len() {
        return Err(Gf3258LibfprintWireError::RecoveryOutputBufferTooSmall {
            required: frame.len(),
            actual: output.len(),
        });
    }
    output[..frame.len()].copy_from_slice(frame);
    Ok(Gf3258LibfprintRecoveryAction {
        direction: Gf3258LibfprintTransferDirection::Out,
        stage,
        endpoint: GF3258_LIBFPRINT_BULK_OUT,
        transfer_length: frame.len(),
        timeout_ms,
        short_is_error: true,
    })
}

fn recovery_in_action(
    stage: Gf3258LibfprintRecoveryStage,
    transfer_length: usize,
    timeout_ms: u32,
) -> Gf3258LibfprintRecoveryAction {
    Gf3258LibfprintRecoveryAction {
        direction: Gf3258LibfprintTransferDirection::In,
        stage,
        endpoint: GF3258_LIBFPRINT_BULK_IN,
        transfer_length,
        timeout_ms,
        short_is_error: false,
    }
}

/// Callback-driven D2/FDT/GetImage transaction engine.
///
/// The engine owns transaction ordering, packet construction/parsing, the fresh
/// D2 key material, protected-frame validation, decryption, CRC validation, and
/// GF3258 WN2 reconstruction. libfprint remains responsible for executing each
/// returned physical transfer and feeding the completed bytes back in.
pub struct Gf3258LibfprintCaptureEngine {
    session: ImageSession,
    stage: Gf3258LibfprintCaptureStage,
    protected_image: Option<Vec<u8>>,
    result: Option<Gf3258LibfprintCaptureResult>,
}

impl Gf3258LibfprintCaptureEngine {
    /// Create a new capture with fresh D2 session material.
    ///
    /// # Errors
    ///
    /// Returns an error if operating-system randomness is unavailable.
    pub fn new() -> Result<Self, Gf3258LibfprintWireError> {
        let session = ImageSession::generate()
            .map_err(|error| Gf3258LibfprintWireError::CaptureRandom(error.to_string()))?;

        Ok(Self {
            session,
            stage: Gf3258LibfprintCaptureStage::D2Write,
            protected_image: None,
            result: None,
        })
    }

    #[must_use]
    pub const fn stage(&self) -> Gf3258LibfprintCaptureStage {
        self.stage
    }

    /// Describe the next physical transfer and write its OUT bytes when needed.
    ///
    /// # Errors
    ///
    /// Returns an error when the supplied OUT scratch buffer cannot hold one
    /// exact 64-byte Goodix block or when packet construction fails.
    pub fn next_action(
        &self,
        output: &mut [u8],
    ) -> Result<Gf3258LibfprintCaptureAction, Gf3258LibfprintWireError> {
        match self.stage {
            Gf3258LibfprintCaptureStage::D2Write => self.out_action(
                Command::TlsPovImage,
                self.session.d2_payload(),
                output,
                OUT_TRANSFER_TIMEOUT_MS,
            ),
            Gf3258LibfprintCaptureStage::D2Ack => {
                Ok(short_in_action(self.stage, ACK_TRANSFER_TIMEOUT_MS))
            }
            Gf3258LibfprintCaptureStage::D2Completion => {
                Ok(short_in_action(self.stage, IMAGE_SESSION_TIMEOUT_MS))
            }
            Gf3258LibfprintCaptureStage::FingerDownWrite => self.out_action(
                Command::FdtDown,
                &FDT_DOWN_PAYLOAD,
                output,
                OUT_TRANSFER_TIMEOUT_MS,
            ),
            Gf3258LibfprintCaptureStage::FingerDownAck => {
                Ok(short_in_action(self.stage, ACK_TRANSFER_TIMEOUT_MS))
            }
            Gf3258LibfprintCaptureStage::FingerDownCompletion => {
                Ok(short_in_action(self.stage, FDT_TIMEOUT_MS))
            }
            Gf3258LibfprintCaptureStage::GetImageWrite => self.out_action(
                Command::GetImage,
                &GET_IMAGE_PAYLOAD,
                output,
                OUT_TRANSFER_TIMEOUT_MS,
            ),
            Gf3258LibfprintCaptureStage::GetImageAck => {
                Ok(short_in_action(self.stage, ACK_TRANSFER_TIMEOUT_MS))
            }
            Gf3258LibfprintCaptureStage::GetImageCompletion => Ok(Gf3258LibfprintCaptureAction {
                direction: Gf3258LibfprintTransferDirection::In,
                stage: self.stage,
                endpoint: GF3258_LIBFPRINT_BULK_IN,
                transfer_length: GF3258_LIBFPRINT_IMAGE_PACKET_SIZE,
                timeout_ms: IMAGE_TIMEOUT_MS,
                short_is_error: false,
            }),
            Gf3258LibfprintCaptureStage::FingerUpWrite => self.out_action(
                Command::FdtUp,
                &FDT_UP_PAYLOAD,
                output,
                OUT_TRANSFER_TIMEOUT_MS,
            ),
            Gf3258LibfprintCaptureStage::FingerUpAck => {
                Ok(short_in_action(self.stage, ACK_TRANSFER_TIMEOUT_MS))
            }
            Gf3258LibfprintCaptureStage::FingerUpCompletion => {
                Ok(short_in_action(self.stage, FDT_TIMEOUT_MS))
            }
            Gf3258LibfprintCaptureStage::Complete => Ok(Gf3258LibfprintCaptureAction {
                direction: Gf3258LibfprintTransferDirection::Complete,
                stage: self.stage,
                endpoint: 0,
                transfer_length: 0,
                timeout_ms: 0,
                short_is_error: false,
            }),
        }
    }

    /// Feed one completed physical transfer back into the transaction engine.
    ///
    /// OUT stages require an empty input slice. IN stages parse the supplied
    /// Goodix packet. Unrelated packets are ignored so the caller can submit the
    /// same requested IN action again, matching the proven standalone transport.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed packets, completion-before-ACK ordering,
    /// unexpected host data on an OUT stage, image authentication/decryption
    /// failures, boot images, or invalid reconstructed geometry.
    pub fn complete_transfer(
        &mut self,
        bytes: &[u8],
    ) -> Result<Gf3258LibfprintCaptureProgress, Gf3258LibfprintWireError> {
        match self.stage {
            Gf3258LibfprintCaptureStage::D2Write => {
                self.complete_out(bytes, Gf3258LibfprintCaptureStage::D2Ack)
            }
            Gf3258LibfprintCaptureStage::D2Ack => self.complete_ack(
                bytes,
                Command::TlsPovImage,
                Gf3258LibfprintCaptureStage::D2Completion,
            ),
            Gf3258LibfprintCaptureStage::D2Completion => self.complete_command(
                bytes,
                Command::TlsPovImage,
                Gf3258LibfprintCaptureStage::FingerDownWrite,
            ),
            Gf3258LibfprintCaptureStage::FingerDownWrite => {
                self.complete_out(bytes, Gf3258LibfprintCaptureStage::FingerDownAck)
            }
            Gf3258LibfprintCaptureStage::FingerDownAck => self.complete_ack(
                bytes,
                Command::FdtDown,
                Gf3258LibfprintCaptureStage::FingerDownCompletion,
            ),
            Gf3258LibfprintCaptureStage::FingerDownCompletion => self.complete_command(
                bytes,
                Command::FdtDown,
                Gf3258LibfprintCaptureStage::GetImageWrite,
            ),
            Gf3258LibfprintCaptureStage::GetImageWrite => {
                self.complete_out(bytes, Gf3258LibfprintCaptureStage::GetImageAck)
            }
            Gf3258LibfprintCaptureStage::GetImageAck => self.complete_ack(
                bytes,
                Command::GetImage,
                Gf3258LibfprintCaptureStage::GetImageCompletion,
            ),
            Gf3258LibfprintCaptureStage::GetImageCompletion => {
                let Some(packet) = matching_completion(bytes, Command::GetImage)? else {
                    return Ok(Gf3258LibfprintCaptureProgress::Ignored);
                };
                self.protected_image = Some(packet.payload);
                self.stage = Gf3258LibfprintCaptureStage::FingerUpWrite;
                Ok(Gf3258LibfprintCaptureProgress::Advanced)
            }
            Gf3258LibfprintCaptureStage::FingerUpWrite => {
                self.complete_out(bytes, Gf3258LibfprintCaptureStage::FingerUpAck)
            }
            Gf3258LibfprintCaptureStage::FingerUpAck => self.complete_ack(
                bytes,
                Command::FdtUp,
                Gf3258LibfprintCaptureStage::FingerUpCompletion,
            ),
            Gf3258LibfprintCaptureStage::FingerUpCompletion => {
                let Some(_packet) = matching_completion(bytes, Command::FdtUp)? else {
                    return Ok(Gf3258LibfprintCaptureProgress::Ignored);
                };
                self.finish_capture()?;
                self.stage = Gf3258LibfprintCaptureStage::Complete;
                Ok(Gf3258LibfprintCaptureProgress::Advanced)
            }
            Gf3258LibfprintCaptureStage::Complete => {
                Err(Gf3258LibfprintWireError::CaptureAlreadyComplete)
            }
        }
    }

    /// Return the final normalized 80x64 image after the transaction completes.
    ///
    /// # Errors
    ///
    /// Returns `CaptureResultNotReady` until FDT-up has completed and image
    /// authentication/reconstruction has succeeded.
    pub fn result(&self) -> Result<&Gf3258LibfprintCaptureResult, Gf3258LibfprintWireError> {
        self.result
            .as_ref()
            .ok_or(Gf3258LibfprintWireError::CaptureResultNotReady)
    }

    fn out_action(
        &self,
        command: Command,
        payload: &[u8],
        output: &mut [u8],
        timeout_ms: u32,
    ) -> Result<Gf3258LibfprintCaptureAction, Gf3258LibfprintWireError> {
        if output.len() < GF3258_LIBFPRINT_USB_OUT_BLOCK_SIZE {
            return Err(Gf3258LibfprintWireError::CaptureOutputBufferTooSmall {
                required: GF3258_LIBFPRINT_USB_OUT_BLOCK_SIZE,
                actual: output.len(),
            });
        }

        let frame = encode_a0_single(command, payload)
            .map_err(|error| Gf3258LibfprintWireError::Protocol(error.to_string()))?;
        output[..frame.len()].copy_from_slice(&frame);

        Ok(Gf3258LibfprintCaptureAction {
            direction: Gf3258LibfprintTransferDirection::Out,
            stage: self.stage,
            endpoint: GF3258_LIBFPRINT_BULK_OUT,
            transfer_length: frame.len(),
            timeout_ms,
            short_is_error: true,
        })
    }

    fn complete_out(
        &mut self,
        bytes: &[u8],
        next: Gf3258LibfprintCaptureStage,
    ) -> Result<Gf3258LibfprintCaptureProgress, Gf3258LibfprintWireError> {
        if !bytes.is_empty() {
            return Err(Gf3258LibfprintWireError::CaptureUnexpectedTransferData {
                stage: self.stage,
                length: bytes.len(),
            });
        }
        self.stage = next;
        Ok(Gf3258LibfprintCaptureProgress::Advanced)
    }

    fn complete_ack(
        &mut self,
        bytes: &[u8],
        command: Command,
        next: Gf3258LibfprintCaptureStage,
    ) -> Result<Gf3258LibfprintCaptureProgress, Gf3258LibfprintWireError> {
        match matching_ack(bytes, command)? {
            PacketDisposition::Accepted => {
                self.stage = next;
                Ok(Gf3258LibfprintCaptureProgress::Advanced)
            }
            PacketDisposition::Ignored => Ok(Gf3258LibfprintCaptureProgress::Ignored),
        }
    }

    fn complete_command(
        &mut self,
        bytes: &[u8],
        command: Command,
        next: Gf3258LibfprintCaptureStage,
    ) -> Result<Gf3258LibfprintCaptureProgress, Gf3258LibfprintWireError> {
        if matching_completion(bytes, command)?.is_some() {
            self.stage = next;
            Ok(Gf3258LibfprintCaptureProgress::Advanced)
        } else {
            Ok(Gf3258LibfprintCaptureProgress::Ignored)
        }
    }

    fn finish_capture(&mut self) -> Result<(), Gf3258LibfprintWireError> {
        let protected_bytes = self
            .protected_image
            .as_deref()
            .ok_or(Gf3258LibfprintWireError::CaptureResultNotReady)?;
        let protected = ProtectedImage::parse(protected_bytes)
            .map_err(|error| Gf3258LibfprintWireError::Image(error.to_string()))?;

        if protected.is_boot_image() {
            return Err(Gf3258LibfprintWireError::BootImage);
        }

        let stored_crc = protected.stored_crc();
        let image_key = self.session.image_key();
        let decrypted = decrypt_image(protected.ciphertext(), &image_key)
            .map_err(|error| Gf3258LibfprintWireError::Crypto(error.to_string()))?;
        protected
            .validate_crc(&decrypted)
            .map_err(|error| Gf3258LibfprintWireError::Image(error.to_string()))?;
        let raw_u16 = restructure_gf3258_wn2(&decrypted)
            .map_err(|error| Gf3258LibfprintWireError::Image(error.to_string()))?;

        if raw_u16.len() != GF3258_LIBFPRINT_CAPTURE_PIXEL_COUNT {
            return Err(Gf3258LibfprintWireError::UnexpectedPixelCount {
                expected: GF3258_LIBFPRINT_CAPTURE_PIXEL_COUNT,
                actual: raw_u16.len(),
            });
        }

        let normalized_u8 = normalize_12bit_to_u8(&raw_u16);
        self.result = Some(Gf3258LibfprintCaptureResult {
            raw_u16,
            normalized_u8,
            protected_bytes: protected_bytes.len(),
            stored_crc,
        });
        Ok(())
    }
}

/// Semantic result after one physical enrollment touch.
///
/// Retry does not mutate the recovered enrollment template. Progress means one
/// sample was retained but the GeneralSamples target has not yet been reached.
/// Complete means the twelfth retained sample was committed and a validated
/// fresh TGLA gallery is ready for persistence in the returned `FpPrint`.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gf3258LibfprintEnrollmentDisposition {
    Retry = 1,
    Progress = 2,
    Complete = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf3258LibfprintEnrollmentResult {
    disposition: Gf3258LibfprintEnrollmentDisposition,
    sample_count: usize,
    progress_percent: usize,
    protected_bytes: usize,
    pixel_count: usize,
    stored_crc: u32,
    tgla_bytes: usize,
}

impl Gf3258LibfprintEnrollmentResult {
    #[must_use]
    pub const fn disposition(self) -> Gf3258LibfprintEnrollmentDisposition {
        self.disposition
    }

    #[must_use]
    pub const fn sample_count(self) -> usize {
        self.sample_count
    }

    #[must_use]
    pub const fn progress_percent(self) -> usize {
        self.progress_percent
    }

    #[must_use]
    pub const fn protected_bytes(self) -> usize {
        self.protected_bytes
    }

    #[must_use]
    pub const fn pixel_count(self) -> usize {
        self.pixel_count
    }

    #[must_use]
    pub const fn stored_crc(self) -> u32 {
        self.stored_crc
    }

    #[must_use]
    pub const fn tgla_bytes(self) -> usize {
        self.tgla_bytes
    }
}

/// Callback-driven 12-touch enrollment transaction for libfprint.
///
/// Each touch delegates physical D2/FDT/GetImage/FDT-up ordering to a fresh
/// capture engine. Only after FDT-up completes is the reconstructed frame passed
/// into the validated enrollment workflow. Rejected touches preserve enrollment
/// state. The twelfth accepted touch is encoded through the existing raw-template
/// and fresh-TGLA persistence path before `Complete` is exposed to the caller.
pub struct Gf3258LibfprintEnrollmentEngine {
    capture: Gf3258LibfprintCaptureEngine,
    workflow: Gf3258EnrollmentWorkflow,
    result: Option<Gf3258LibfprintEnrollmentResult>,
    tgla: Option<Vec<u8>>,
}

impl Gf3258LibfprintEnrollmentEngine {
    /// Start a new 12-sample enrollment with fresh D2 material for the first touch.
    pub fn new() -> Result<Self, Gf3258LibfprintWireError> {
        Ok(Self {
            capture: Gf3258LibfprintCaptureEngine::new()?,
            workflow: Gf3258EnrollmentWorkflow::new(),
            result: None,
            tgla: None,
        })
    }

    #[must_use]
    pub const fn stage(&self) -> Gf3258LibfprintCaptureStage {
        self.capture.stage()
    }

    #[must_use]
    pub fn sample_count(&self) -> usize {
        self.workflow.sample_count()
    }

    /// Forward the next physical action for the current touch.
    pub fn next_action(
        &self,
        output: &mut [u8],
    ) -> Result<Gf3258LibfprintCaptureAction, Gf3258LibfprintWireError> {
        self.capture.next_action(output)
    }

    /// Feed one completed libfprint-owned transfer into the current touch.
    ///
    /// Enrollment processing runs exactly once after FDT-up completion.
    pub fn complete_transfer(
        &mut self,
        bytes: &[u8],
    ) -> Result<Gf3258LibfprintCaptureProgress, Gf3258LibfprintWireError> {
        let progress = self.capture.complete_transfer(bytes)?;
        if self.capture.stage() == Gf3258LibfprintCaptureStage::Complete && self.result.is_none() {
            self.finish_touch()?;
        }
        Ok(progress)
    }

    /// Return the semantic result of the just-completed touch.
    pub fn result(&self) -> Result<Gf3258LibfprintEnrollmentResult, Gf3258LibfprintWireError> {
        self.result
            .ok_or(Gf3258LibfprintWireError::EnrollmentResultNotReady)
    }

    /// Prepare a fresh D2/FDT/GetImage transaction for the next touch.
    ///
    /// This is valid only after Retry or Progress has been consumed by the
    /// libfprint progress callback. Completed enrollment cannot be restarted.
    pub fn start_next_touch(&mut self) -> Result<(), Gf3258LibfprintWireError> {
        let result = self
            .result
            .ok_or(Gf3258LibfprintWireError::EnrollmentNextTouchNotReady)?;
        if result.disposition == Gf3258LibfprintEnrollmentDisposition::Complete {
            return Err(Gf3258LibfprintWireError::EnrollmentAlreadyComplete);
        }

        self.capture = Gf3258LibfprintCaptureEngine::new()?;
        self.result = None;
        Ok(())
    }

    /// Exact validated TGLA bytes after the twelfth accepted sample.
    pub fn tgla(&self) -> Result<&[u8], Gf3258LibfprintWireError> {
        self.tgla
            .as_deref()
            .ok_or(Gf3258LibfprintWireError::EnrollmentTglaNotReady)
    }

    fn finish_touch(&mut self) -> Result<(), Gf3258LibfprintWireError> {
        let capture = self.capture.result()?;
        let outcome = self
            .workflow
            .process_raw_frame(capture.raw_u16())
            .map_err(|error| Gf3258LibfprintWireError::Enrollment(error.to_string()))?;

        let disposition = match outcome {
            Gf3258EnrollmentFrameOutcome::Rejected(_) => {
                Gf3258LibfprintEnrollmentDisposition::Retry
            }
            Gf3258EnrollmentFrameOutcome::Accepted(_) if self.workflow.is_complete() => {
                let artifacts = self
                    .workflow
                    .encode_artifacts()
                    .map_err(|error| Gf3258LibfprintWireError::Enrollment(error.to_string()))?;
                let tgla = artifacts.tgla_template().to_vec();

                // Reopen the encoded gallery through the verification decoder
                // before exposing the completed print.
                Gf3258VerificationTemplate::from_tgla(&tgla)
                    .map_err(|error| Gf3258LibfprintWireError::Enrollment(error.to_string()))?;
                self.tgla = Some(tgla);
                Gf3258LibfprintEnrollmentDisposition::Complete
            }
            Gf3258EnrollmentFrameOutcome::Accepted(_) => {
                Gf3258LibfprintEnrollmentDisposition::Progress
            }
        };

        let sample_count = self.workflow.sample_count();
        let progress_percent = self.workflow.progress_percent();
        debug_assert!(sample_count <= GF3258_ENROLLMENT_TARGET_SAMPLES);
        self.result = Some(Gf3258LibfprintEnrollmentResult {
            disposition,
            sample_count,
            progress_percent,
            protected_bytes: capture.protected_bytes(),
            pixel_count: capture.pixel_count(),
            stored_crc: capture.stored_crc(),
            tgla_bytes: self.tgla.as_ref().map_or(0, Vec::len),
        });
        Ok(())
    }
}

/// Final semantic result of one libfprint verify action.
///
/// Retry is a biometric acquisition rejection, not an authentication result.
/// Match and NoMatch are emitted only from the terminal gallery decision.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gf3258LibfprintVerificationDisposition {
    Retry = 1,
    Match = 2,
    NoMatch = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf3258LibfprintVerificationResult {
    disposition: Gf3258LibfprintVerificationDisposition,
    score: i32,
    protected_bytes: usize,
    pixel_count: usize,
    stored_crc: u32,
}

impl Gf3258LibfprintVerificationResult {
    #[must_use]
    pub const fn disposition(self) -> Gf3258LibfprintVerificationDisposition {
        self.disposition
    }

    #[must_use]
    pub const fn score(self) -> i32 {
        self.score
    }

    #[must_use]
    pub const fn protected_bytes(self) -> usize {
        self.protected_bytes
    }

    #[must_use]
    pub const fn pixel_count(self) -> usize {
        self.pixel_count
    }

    #[must_use]
    pub const fn stored_crc(self) -> u32 {
        self.stored_crc
    }
}

/// Callback-driven verification transaction for a single libfprint touch.
///
/// Construction strictly decodes the driver-private TGLA gallery before any
/// USB action is exposed. Physical capture is delegated to the validated
/// 12-stage capture engine. Only after FDT-up completes is the reconstructed
/// u16 frame evaluated by the verification workflow.
pub struct Gf3258LibfprintVerificationEngine {
    capture: Gf3258LibfprintCaptureEngine,
    template: Gf3258VerificationTemplate,
    workflow: Gf3258VerificationWorkflow,
    result: Option<Gf3258LibfprintVerificationResult>,
}

impl Gf3258LibfprintVerificationEngine {
    /// Decode one persisted TGLA print and prepare a single-touch verification.
    ///
    /// # Errors
    ///
    /// Returns before any transfer can be requested if TGLA decoding fails or
    /// the gallery is empty. D2 random generation failures are also returned at
    /// construction time.
    pub fn new(tgla: &[u8]) -> Result<Self, Gf3258LibfprintWireError> {
        let template = Gf3258VerificationTemplate::from_tgla(tgla)
            .map_err(|error| Gf3258LibfprintWireError::VerificationTemplate(error.to_string()))?;
        let capture = Gf3258LibfprintCaptureEngine::new()?;
        Ok(Self {
            capture,
            template,
            workflow: Gf3258VerificationWorkflow::new(),
            result: None,
        })
    }

    #[must_use]
    pub const fn stage(&self) -> Gf3258LibfprintCaptureStage {
        self.capture.stage()
    }

    /// Forward the next physical action from the capture engine.
    pub fn next_action(
        &self,
        output: &mut [u8],
    ) -> Result<Gf3258LibfprintCaptureAction, Gf3258LibfprintWireError> {
        self.capture.next_action(output)
    }

    /// Feed one completed libfprint-owned transfer into verification.
    ///
    /// The biometric workflow executes exactly once, after the capture engine
    /// has consumed the FDT-up completion and finalized the reconstructed frame.
    pub fn complete_transfer(
        &mut self,
        bytes: &[u8],
    ) -> Result<Gf3258LibfprintCaptureProgress, Gf3258LibfprintWireError> {
        let progress = self.capture.complete_transfer(bytes)?;
        if self.capture.stage() == Gf3258LibfprintCaptureStage::Complete && self.result.is_none() {
            self.finish_verification()?;
        }
        Ok(progress)
    }

    /// Return the final verification outcome.
    pub fn result(&self) -> Result<Gf3258LibfprintVerificationResult, Gf3258LibfprintWireError> {
        self.result
            .ok_or(Gf3258LibfprintWireError::VerificationResultNotReady)
    }

    fn finish_verification(&mut self) -> Result<(), Gf3258LibfprintWireError> {
        let capture = self.capture.result()?;
        let outcome = self
            .workflow
            .verify_raw_frame(&self.template, capture.raw_u16())
            .map_err(|error| Gf3258LibfprintWireError::Verification(error.to_string()))?;

        let (disposition, score) = match outcome {
            Gf3258RawFrameVerificationOutcome::Rejected(_) => {
                (Gf3258LibfprintVerificationDisposition::Retry, 0)
            }
            Gf3258RawFrameVerificationOutcome::Verified(result) => match result.decision() {
                Gf3258GalleryVerificationDecision::Match => (
                    Gf3258LibfprintVerificationDisposition::Match,
                    result.score(),
                ),
                Gf3258GalleryVerificationDecision::NoMatch => (
                    Gf3258LibfprintVerificationDisposition::NoMatch,
                    result.score(),
                ),
            },
        };

        self.result = Some(Gf3258LibfprintVerificationResult {
            disposition,
            score,
            protected_bytes: capture.protected_bytes(),
            pixel_count: capture.pixel_count(),
            stored_crc: capture.stored_crc(),
        });
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PacketDisposition {
    Accepted,
    Ignored,
}

fn decode_packet(bytes: &[u8]) -> Result<McuPacket, Gf3258LibfprintWireError> {
    decode_a0_packet(bytes).map_err(|error| Gf3258LibfprintWireError::Protocol(error.to_string()))
}

fn short_in_action(
    stage: Gf3258LibfprintCaptureStage,
    timeout_ms: u32,
) -> Gf3258LibfprintCaptureAction {
    Gf3258LibfprintCaptureAction {
        direction: Gf3258LibfprintTransferDirection::In,
        stage,
        endpoint: GF3258_LIBFPRINT_BULK_IN,
        transfer_length: GF3258_LIBFPRINT_A8_READ_SIZE,
        timeout_ms,
        short_is_error: false,
    }
}

fn matching_ack(
    bytes: &[u8],
    expected: Command,
) -> Result<PacketDisposition, Gf3258LibfprintWireError> {
    let packet = decode_packet(bytes)?;

    if packet.is_command(Command::Ack) {
        let [command, _flags] = packet.payload.as_slice() else {
            return Err(Gf3258LibfprintWireError::MalformedAck {
                payload_len: packet.payload.len(),
            });
        };
        if *command == expected.as_u8() {
            return Ok(PacketDisposition::Accepted);
        }
        return Ok(PacketDisposition::Ignored);
    }

    if packet.command == expected.as_u8() {
        return Err(Gf3258LibfprintWireError::CaptureResponseBeforeAck {
            command: expected.as_u8(),
        });
    }

    Ok(PacketDisposition::Ignored)
}

fn matching_recovery_ack(
    bytes: &[u8],
    expected: Command,
) -> Result<PacketDisposition, Gf3258LibfprintWireError> {
    let packet = decode_packet(bytes)?;
    if packet.is_command(Command::Ack) {
        let [command, _flags] = packet.payload.as_slice() else {
            return Err(Gf3258LibfprintWireError::MalformedAck {
                payload_len: packet.payload.len(),
            });
        };
        if *command == expected.as_u8() {
            return Ok(PacketDisposition::Accepted);
        }
        return Ok(PacketDisposition::Ignored);
    }
    if packet.command == expected.as_u8() {
        return Err(Gf3258LibfprintWireError::RecoveryResponseBeforeAck {
            command: expected.as_u8(),
        });
    }
    Ok(PacketDisposition::Ignored)
}

fn matching_completion(
    bytes: &[u8],
    expected: Command,
) -> Result<Option<McuPacket>, Gf3258LibfprintWireError> {
    let packet = decode_packet(bytes)?;
    if packet.command == expected.as_u8() {
        Ok(Some(packet))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use aes::{
        Aes128,
        cipher::{BlockModeEncrypt, KeyIvInit, block_padding::NoPadding},
    };

    use super::*;
    use crate::firmware::crc32_mpeg2;
    use crate::firmware_auth::EXPECTED_CAPTURED_PSK_SHA256;
    use crate::image::goodix_image_crc;
    use crate::protocol::encode_a0_packet;

    type Aes128CbcEncryptor = cbc::Encryptor<Aes128>;

    const APP_RESPONSE: [u8; 33] = [
        0xa0, 0x1d, 0x00, 0xbd, 0xa8, 0x1a, 0x00, 0x47, 0x46, 0x55, 0x53, 0x42, 0x5f, 0x47, 0x4d,
        0x31, 0x36, 0x38, 0x53, 0x45, 0x43, 0x5f, 0x41, 0x50, 0x50, 0x5f, 0x31, 0x35, 0x30, 0x34,
        0x35, 0x00, 0x66,
    ];

    const CAPTURED_SEALED_PSK: [u8; 102] = [
        0x7c, 0x2e, 0x1d, 0x39, 0xce, 0xdc, 0x06, 0x97, 0x83, 0x0c, 0x97, 0x94, 0x50, 0xc2, 0x7a,
        0xf2, 0x36, 0x57, 0xc5, 0x54, 0xfe, 0x46, 0x8f, 0x31, 0xeb, 0x39, 0xbf, 0xca, 0x2a, 0x6a,
        0x00, 0x86, 0x01, 0xff, 0x20, 0x00, 0x00, 0x00, 0x2a, 0x8c, 0x71, 0xd2, 0xa9, 0x79, 0x34,
        0xb5, 0x92, 0xdc, 0x33, 0x25, 0x94, 0x31, 0x59, 0xe4, 0x53, 0x90, 0xd7, 0x8b, 0x63, 0x4d,
        0x1d, 0x32, 0x7c, 0x3f, 0x29, 0xfc, 0xa5, 0x75, 0xed, 0x96, 0x83, 0xf3, 0xb3, 0x57, 0xd7,
        0x03, 0x43, 0xc8, 0xb7, 0x6e, 0x9d, 0xd4, 0x01, 0x5c, 0x54, 0x06, 0x07, 0xb8, 0x6a, 0xc9,
        0x65, 0x88, 0x69, 0x50, 0x1c, 0x12, 0x48, 0xaf, 0x25, 0xb6, 0x0b, 0xc8,
    ];

    fn synthetic_firmware_blob(metadata: &[u8], app: &[u8]) -> Vec<u8> {
        assert!(metadata.len() <= u8::MAX as usize);
        let mut raw = Vec::with_capacity(1 + metadata.len() + app.len() + 4);
        raw.push(metadata.len() as u8);
        raw.extend_from_slice(metadata);
        raw.extend_from_slice(app);
        let crc = crc32_mpeg2(&raw);
        raw.extend_from_slice(&crc.to_le_bytes());
        raw
    }

    fn synthetic_bootstrap_plan() -> Gf3258LibfprintBootstrapPlan {
        let package = AppTransferPackage::from_app(&vec![0x42; BOOTSTRAP_APP_SIZE]).unwrap();
        Gf3258LibfprintBootstrapPlan {
            info: Gf3258LibfprintBootstrapFirmwareInfo {
                blob_bytes: BOOTSTRAP_BLOB_SIZE,
                app_bytes: BOOTSTRAP_APP_SIZE,
                blob_crc: BOOTSTRAP_BLOB_CRC,
                app_crc: package.app_crc(),
                header_crc: package.header_crc(),
                package_bytes: package.len(),
                f0_chunks: package.f0_chunk_count(),
            },
            package,
            f4_tag: None,
        }
    }

    #[test]
    fn bootstrap_target_invariants_are_pinned() {
        let info = Gf3258LibfprintBootstrapFirmwareInfo {
            blob_bytes: BOOTSTRAP_BLOB_SIZE,
            app_bytes: BOOTSTRAP_APP_SIZE,
            blob_crc: BOOTSTRAP_BLOB_CRC,
            app_crc: BOOTSTRAP_APP_CRC,
            header_crc: BOOTSTRAP_HEADER_CRC,
            package_bytes: BOOTSTRAP_PACKAGE_SIZE,
            f0_chunks: BOOTSTRAP_F0_CHUNKS,
        };
        validate_bootstrap_firmware_info(info).unwrap();
        assert_eq!(info.f0_chunks(), 98);
    }

    #[test]
    fn bootstrap_target_invariant_rejects_modified_app_crc() {
        let info = Gf3258LibfprintBootstrapFirmwareInfo {
            blob_bytes: BOOTSTRAP_BLOB_SIZE,
            app_bytes: BOOTSTRAP_APP_SIZE,
            blob_crc: BOOTSTRAP_BLOB_CRC,
            app_crc: BOOTSTRAP_APP_CRC ^ 1,
            header_crc: BOOTSTRAP_HEADER_CRC,
            package_bytes: BOOTSTRAP_PACKAGE_SIZE,
            f0_chunks: BOOTSTRAP_F0_CHUNKS,
        };
        assert!(matches!(
            validate_bootstrap_firmware_info(info),
            Err(Gf3258LibfprintWireError::BootstrapFirmwareInvariant {
                field: "APP CRC",
                ..
            })
        ));
    }

    #[test]
    #[ignore = "requires the local exact APP15045 firmware resource"]
    fn bootstrap_plan_accepts_exact_app_resource() {
        let path = std::env::var_os("GOODIX550A_APP_RESOURCE")
            .expect("GOODIX550A_APP_RESOURCE must name the APP15045 firmware blob");
        let raw = std::fs::read(path).unwrap();
        let plan = Gf3258LibfprintBootstrapPlan::new(&raw).unwrap();
        let info = plan.firmware_info();
        assert_eq!(info.blob_bytes(), BOOTSTRAP_BLOB_SIZE);
        assert_eq!(info.app_bytes(), BOOTSTRAP_APP_SIZE);
        assert_eq!(info.blob_crc(), BOOTSTRAP_BLOB_CRC);
        assert_eq!(info.app_crc(), BOOTSTRAP_APP_CRC);
        assert_eq!(info.header_crc(), BOOTSTRAP_HEADER_CRC);
        assert_eq!(info.package_bytes(), BOOTSTRAP_PACKAGE_SIZE);
        assert_eq!(info.f0_chunks(), BOOTSTRAP_F0_CHUNKS);
        assert!(!plan.is_authenticated());
    }

    #[test]
    fn bootstrap_plan_rejects_wrong_firmware_metadata_before_transfer() {
        let raw = synthetic_firmware_blob(b"GFUSB_GM168SEC_APP_15044", &[0x42; 32]);
        assert!(matches!(
            Gf3258LibfprintBootstrapPlan::new(&raw),
            Err(Gf3258LibfprintWireError::BootstrapFirmwareMetadata { .. })
        ));
    }

    #[test]
    fn bootstrap_plan_rejects_non_target_app_with_correct_metadata() {
        let raw = synthetic_firmware_blob(EXPECTED_APP_VERSION.as_bytes(), &[0x42; 32]);
        assert!(matches!(
            Gf3258LibfprintBootstrapPlan::new(&raw),
            Err(Gf3258LibfprintWireError::BootstrapFirmwareInvariant {
                field: "blob bytes",
                ..
            })
        ));
    }

    #[test]
    fn bootstrap_plan_hides_firmware_write_material_until_psk_is_authenticated() {
        let plan = synthetic_bootstrap_plan();
        assert!(!plan.is_authenticated());
        assert_eq!(
            plan.f0_payload(0),
            Err(Gf3258LibfprintWireError::BootstrapNotAuthenticated)
        );
        assert_eq!(
            plan.f4_tag(),
            Err(Gf3258LibfprintWireError::BootstrapNotAuthenticated)
        );
    }

    #[test]
    fn bootstrap_plan_authenticates_captured_persisted_psk() {
        let mut plan = synthetic_bootstrap_plan();
        plan.authenticate_persisted_psk(&CAPTURED_SEALED_PSK, &EXPECTED_CAPTURED_PSK_SHA256)
            .unwrap();
        assert!(plan.is_authenticated());
        assert_eq!(plan.f4_tag().unwrap().len(), F4_TAG_LEN);
        assert!(matches!(
            plan.authenticate_persisted_psk(&CAPTURED_SEALED_PSK, &EXPECTED_CAPTURED_PSK_SHA256),
            Err(Gf3258LibfprintWireError::BootstrapAlreadyAuthenticated)
        ));
    }

    #[test]
    fn bootstrap_plan_exposes_exact_f0_payload_shape_after_authentication() {
        let mut plan = synthetic_bootstrap_plan();
        plan.authenticate_persisted_psk(&CAPTURED_SEALED_PSK, &EXPECTED_CAPTURED_PSK_SHA256)
            .unwrap();
        let first = plan.f0_payload(0).unwrap();
        assert_eq!(&first[0..4], &0u32.to_le_bytes());
        assert_eq!(&first[4..8], &0x100u32.to_le_bytes());
        assert_eq!(&first[8..12], &2u32.to_le_bytes());
        assert_eq!(first.len(), 12 + 0x100);
        assert!(matches!(
            plan.f0_payload(plan.f0_chunk_count()),
            Err(Gf3258LibfprintWireError::BootstrapF0IndexOutOfRange { .. })
        ));
    }

    fn bootstrap_engine_from_synthetic_plan() -> Gf3258LibfprintBootstrapEngine {
        Gf3258LibfprintBootstrapEngine::from_plan(synthetic_bootstrap_plan()).unwrap()
    }

    fn bootstrap_psk_completion(object_type: u32, data: &[u8]) -> Vec<u8> {
        let mut payload = Vec::with_capacity(9 + data.len());
        payload.push(0);
        payload.extend_from_slice(&object_type.to_le_bytes());
        payload.extend_from_slice(&(data.len() as u32).to_le_bytes());
        payload.extend_from_slice(data);
        encode_a0_packet(Command::PskRead, &payload).unwrap()
    }

    fn bootstrap_ack(command: Command) -> Vec<u8> {
        encode_a0_packet(Command::Ack, &[command.as_u8(), 0x01]).unwrap()
    }

    fn advance_bootstrap_psk_reads(engine: &mut Gf3258LibfprintBootstrapEngine) {
        engine.complete_transfer(&[]).unwrap();
        engine
            .complete_transfer(&bootstrap_ack(Command::PskRead))
            .unwrap();
        engine
            .complete_transfer(&bootstrap_psk_completion(
                SEALED_PSK_OBJECT,
                &CAPTURED_SEALED_PSK,
            ))
            .unwrap();
        engine.complete_transfer(&[]).unwrap();
        engine
            .complete_transfer(&bootstrap_ack(Command::PskRead))
            .unwrap();
        engine
            .complete_transfer(&bootstrap_psk_completion(
                PSK_HASH_OBJECT,
                &EXPECTED_CAPTURED_PSK_SHA256,
            ))
            .unwrap();
    }

    #[test]
    fn bootstrap_engine_starts_with_read_only_sealed_psk_e4() {
        let engine = bootstrap_engine_from_synthetic_plan();
        let mut out = [0u8; GF3258_LIBFPRINT_USB_OUT_BLOCK_SIZE];
        let action = engine.next_action(&mut out).unwrap();
        assert_eq!(
            action.stage(),
            Gf3258LibfprintBootstrapStage::ReadSealedPskWrite
        );
        assert_eq!(action.direction(), Gf3258LibfprintTransferDirection::Out);
        assert_eq!(action.endpoint(), GF3258_LIBFPRINT_BULK_OUT);
        assert_eq!(action.transfer_length(), 64);
        assert_eq!(out[4], Command::PskRead.as_u8());
        assert_eq!(&out[7..11], &(SEALED_PSK_SIZE as u32).to_le_bytes());
        assert_eq!(&out[15..19], &SEALED_PSK_OBJECT.to_le_bytes());
    }

    #[test]
    fn bootstrap_engine_authenticates_both_persisted_e4_objects_before_f0() {
        let mut engine = bootstrap_engine_from_synthetic_plan();
        advance_bootstrap_psk_reads(&mut engine);
        assert_eq!(
            engine.stage(),
            Gf3258LibfprintBootstrapStage::FirmwareWriteBlock
        );
        assert_eq!(engine.f0_chunk_index(), 0);
        assert_eq!(engine.f0_chunks_sent(), 0);
        assert!(engine.plan.is_authenticated());
        assert!(engine.sealed_psk.is_empty());
        assert!(engine.psk_hash.is_empty());
    }

    #[test]
    fn bootstrap_engine_splits_first_f0_into_five_physical_blocks() {
        let mut engine = bootstrap_engine_from_synthetic_plan();
        advance_bootstrap_psk_reads(&mut engine);
        let mut out = [0u8; GF3258_LIBFPRINT_USB_OUT_BLOCK_SIZE];
        for expected_block in 0..5 {
            let action = engine.next_action(&mut out).unwrap();
            assert_eq!(action.direction(), Gf3258LibfprintTransferDirection::Out);
            assert_eq!(action.transfer_length(), 64);
            assert_eq!(engine.f0_block_index(), expected_block);
            if expected_block == 0 {
                assert_eq!(out[4], Command::FirmwareWrite.as_u8());
            }
            engine.complete_transfer(&[]).unwrap();
        }
        assert_eq!(
            engine.stage(),
            Gf3258LibfprintBootstrapStage::FirmwareWriteAck
        );
        assert_eq!(engine.f0_block_index(), 0);
    }

    #[test]
    fn bootstrap_engine_ignores_f0_completion_payload_but_counts_transaction() {
        let mut engine = bootstrap_engine_from_synthetic_plan();
        advance_bootstrap_psk_reads(&mut engine);
        for _ in 0..5 {
            engine.complete_transfer(&[]).unwrap();
        }
        engine
            .complete_transfer(&bootstrap_ack(Command::FirmwareWrite))
            .unwrap();
        let completion = encode_a0_packet(Command::FirmwareWrite, &[0x00, 0x55]).unwrap();
        engine.complete_transfer(&completion).unwrap();
        assert_eq!(engine.f0_chunks_sent(), 1);
        assert_eq!(engine.f0_chunk_index(), 1);
        assert_eq!(
            engine.stage(),
            Gf3258LibfprintBootstrapStage::FirmwareWriteBlock
        );
    }

    #[test]
    fn bootstrap_engine_final_f0_is_one_zero_padded_block() {
        let mut engine = bootstrap_engine_from_synthetic_plan();
        engine
            .plan
            .authenticate_persisted_psk(&CAPTURED_SEALED_PSK, &EXPECTED_CAPTURED_PSK_SHA256)
            .unwrap();
        engine.stage = Gf3258LibfprintBootstrapStage::FirmwareWriteBlock;
        engine.f0_chunk_index = BOOTSTRAP_F0_CHUNKS - 1;
        engine.f0_chunks_sent = BOOTSTRAP_F0_CHUNKS - 1;
        let mut out = [0u8; GF3258_LIBFPRINT_USB_OUT_BLOCK_SIZE];
        let action = engine.next_action(&mut out).unwrap();
        assert_eq!(action.transfer_length(), 64);
        assert_eq!(out[4], Command::FirmwareWrite.as_u8());
        assert!(out[32..].iter().all(|byte| *byte == 0));
        engine.complete_transfer(&[]).unwrap();
        assert_eq!(
            engine.stage(),
            Gf3258LibfprintBootstrapStage::FirmwareWriteAck
        );
    }

    #[test]
    fn bootstrap_engine_rejects_completion_before_matching_ack() {
        let mut engine = bootstrap_engine_from_synthetic_plan();
        engine.complete_transfer(&[]).unwrap();
        let completion = bootstrap_psk_completion(SEALED_PSK_OBJECT, &CAPTURED_SEALED_PSK);
        assert!(matches!(
            engine.complete_transfer(&completion),
            Err(Gf3258LibfprintWireError::BootstrapResponseBeforeAck { command: 0xe4 })
        ));
    }

    #[test]
    fn bootstrap_engine_requires_nonzero_one_byte_f4_result() {
        let mut zero = bootstrap_engine_from_synthetic_plan();
        zero.plan
            .authenticate_persisted_psk(&CAPTURED_SEALED_PSK, &EXPECTED_CAPTURED_PSK_SHA256)
            .unwrap();
        zero.stage = Gf3258LibfprintBootstrapStage::FirmwareCheckCompletion;
        zero.f0_chunks_sent = BOOTSTRAP_F0_CHUNKS;
        zero.f0_chunk_index = BOOTSTRAP_F0_CHUNKS;
        let rejected = encode_a0_packet(Command::FirmwareCheck, &[0]).unwrap();
        assert_eq!(
            zero.complete_transfer(&rejected),
            Err(Gf3258LibfprintWireError::BootstrapFirmwareCheckRejected)
        );

        let mut good = bootstrap_engine_from_synthetic_plan();
        good.plan
            .authenticate_persisted_psk(&CAPTURED_SEALED_PSK, &EXPECTED_CAPTURED_PSK_SHA256)
            .unwrap();
        good.stage = Gf3258LibfprintBootstrapStage::FirmwareCheckCompletion;
        good.f0_chunks_sent = BOOTSTRAP_F0_CHUNKS;
        good.f0_chunk_index = BOOTSTRAP_F0_CHUNKS;
        let accepted = encode_a0_packet(Command::FirmwareCheck, &[0x7f]).unwrap();
        good.complete_transfer(&accepted).unwrap();
        assert_eq!(good.stage(), Gf3258LibfprintBootstrapStage::Complete);
        assert_eq!(good.result().unwrap().f0_chunks_sent(), 98);
        assert_eq!(good.result().unwrap().firmware_check_result(), 0x7f);
    }

    #[test]
    fn bootstrap_engine_stops_after_f4_without_exposing_reset() {
        let mut engine = bootstrap_engine_from_synthetic_plan();
        engine
            .plan
            .authenticate_persisted_psk(&CAPTURED_SEALED_PSK, &EXPECTED_CAPTURED_PSK_SHA256)
            .unwrap();
        engine.stage = Gf3258LibfprintBootstrapStage::FirmwareCheckCompletion;
        engine.f0_chunks_sent = BOOTSTRAP_F0_CHUNKS;
        engine.f0_chunk_index = BOOTSTRAP_F0_CHUNKS;
        let accepted = encode_a0_packet(Command::FirmwareCheck, &[1]).unwrap();
        engine.complete_transfer(&accepted).unwrap();
        let mut out = [0xa5u8; GF3258_LIBFPRINT_USB_OUT_BLOCK_SIZE];
        let action = engine.next_action(&mut out).unwrap();
        assert_eq!(
            action.direction(),
            Gf3258LibfprintTransferDirection::Complete
        );
        assert_eq!(action.transfer_length(), 0);
        assert!(out.iter().all(|byte| *byte == 0xa5));
    }

    #[test]
    fn builds_exact_postboot_a2_reset_request() {
        let request = gf3258_libfprint_build_postboot_reset_request().unwrap();
        assert_eq!(
            &request[..10],
            &[0xa0, 0x06, 0x00, 0xa6, 0xa2, 0x03, 0x00, 0x05, 0x14, 0xec]
        );
        assert!(request[10..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn parses_postboot_a2_reset_ack() {
        let ack = gf3258_libfprint_parse_postboot_reset_ack(&[
            0xa0, 0x06, 0x00, 0xa6, 0xb0, 0x03, 0x00, 0xa2, 0x01, 0x54,
        ])
        .unwrap();
        assert_eq!(ack.flags(), 0x01);
        assert!(!ack.mcu_power_lost());
    }

    #[test]
    fn validates_postboot_a2_completion_by_command_identity() {
        let response = encode_a0_packet(Command::ResetChip, &[0x00, 0x00, 0x00]).unwrap();
        gf3258_libfprint_parse_postboot_reset_response(&response).unwrap();
    }

    #[test]
    fn postboot_a2_completion_rejects_other_command() {
        let response = encode_a0_packet(Command::GetVersion, &[0x00]).unwrap();
        assert!(matches!(
            gf3258_libfprint_parse_postboot_reset_response(&response),
            Err(Gf3258LibfprintWireError::UnexpectedCommand {
                expected,
                actual,
            }) if expected == Command::ResetChip.as_u8()
                && actual == Command::GetVersion.as_u8()
        ));
    }

    #[test]
    fn builds_exact_chip_id_read_request() {
        let request = gf3258_libfprint_build_chip_id_request().unwrap();
        assert_eq!(
            &request[..13],
            &[
                0xa0, 0x09, 0x00, 0xa9, 0x82, 0x06, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x1e,
            ]
        );
        assert!(request[13..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn parses_chip_id_read_ack() {
        let ack = gf3258_libfprint_parse_chip_id_ack(&[
            0xa0, 0x06, 0x00, 0xa6, 0xb0, 0x03, 0x00, 0x82, 0x01, 0x74,
        ])
        .unwrap();
        assert_eq!(ack.flags(), 0x01);
        assert!(!ack.mcu_power_lost());
    }

    #[test]
    fn validates_live_gf3258_chip_id_payload() {
        let response = encode_a0_packet(Command::ReadRegister, &[0x03, 0xa8, 0x00, 0x25]).unwrap();
        assert_eq!(
            gf3258_libfprint_validate_chip_id_response(&response).unwrap(),
            GF3258_LIBFPRINT_EXPECTED_CHIP_ID
        );
    }

    #[test]
    fn rejects_unexpected_chip_id() {
        let response = encode_a0_packet(Command::ReadRegister, &[0x03, 0xa8, 0x00, 0x24]).unwrap();
        assert!(gf3258_libfprint_validate_chip_id_response(&response).is_err());
    }

    #[test]
    fn postboot_reset_delay_matches_recovered_loader_delay() {
        assert_eq!(GF3258_LIBFPRINT_POSTBOOT_RESET_DELAY_MS, 10);
    }

    #[test]
    fn builds_exact_bootstrap_a2_reset_request() {
        let request = gf3258_libfprint_build_bootstrap_reset_request().unwrap();
        assert_eq!(
            &request[..10],
            &[0xa0, 0x06, 0x00, 0xa6, 0xa2, 0x03, 0x00, 0x02, 0x32, 0xd1]
        );
        assert!(request[10..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn parses_bootstrap_a2_reset_ack() {
        let ack = gf3258_libfprint_parse_bootstrap_reset_ack(&[
            0xa0, 0x06, 0x00, 0xa6, 0xb0, 0x03, 0x00, 0xa2, 0x01, 0x54,
        ])
        .unwrap();
        assert_eq!(ack.flags(), 0x01);
        assert!(!ack.mcu_power_lost());
    }

    #[test]
    fn bootstrap_a2_reset_ack_preserves_power_lost_flag() {
        let ack = gf3258_libfprint_parse_bootstrap_reset_ack(&[
            0xa0, 0x06, 0x00, 0xa6, 0xb0, 0x03, 0x00, 0xa2, 0x03, 0x52,
        ])
        .unwrap();
        assert_eq!(ack.flags(), 0x03);
        assert!(ack.mcu_power_lost());
    }

    #[test]
    fn bootstrap_a2_reset_ack_rejects_ack_for_other_command() {
        let error = gf3258_libfprint_parse_bootstrap_reset_ack(&[
            0xa0, 0x06, 0x00, 0xa6, 0xb0, 0x03, 0x00, 0xa8, 0x01, 0x4e,
        ])
        .unwrap_err();
        assert!(matches!(
            error,
            Gf3258LibfprintWireError::AckForWrongCommand { command }
                if command == Command::GetVersion.as_u8()
        ));
    }

    #[test]
    fn builds_exact_live_a8_request() {
        let request = gf3258_libfprint_build_get_version_request().unwrap();
        assert_eq!(
            &request[..10],
            &[0xa0, 0x06, 0x00, 0xa6, 0xa8, 0x03, 0x00, 0x00, 0x00, 0xff]
        );
        assert!(request[10..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn parses_live_a8_ack() {
        let ack = gf3258_libfprint_parse_get_version_ack(&[
            0xa0, 0x06, 0x00, 0xa6, 0xb0, 0x03, 0x00, 0xa8, 0x01, 0x4e,
        ])
        .unwrap();
        assert_eq!(ack.flags(), 0x01);
        assert!(!ack.mcu_power_lost());
    }

    #[test]
    fn preserves_power_lost_flag_semantics() {
        let ack = gf3258_libfprint_parse_get_version_ack(&[
            0xa0, 0x06, 0x00, 0xa6, 0xb0, 0x03, 0x00, 0xa8, 0x03, 0x4c,
        ])
        .unwrap();
        assert_eq!(ack.flags(), 0x03);
        assert!(ack.mcu_power_lost());
    }

    #[test]
    fn parses_exact_live_app_identity() {
        assert_eq!(
            gf3258_libfprint_parse_get_version_response(&APP_RESPONSE).unwrap(),
            Gf3258LibfprintFirmwareIdentity::App15045
        );
    }

    #[test]
    fn rejects_missing_version_nul() {
        let mut response = APP_RESPONSE;
        response[31] = b'X';
        response[32] = 0x0e;
        assert!(matches!(
            gf3258_libfprint_parse_get_version_response(&response),
            Err(Gf3258LibfprintWireError::VersionMissingNul)
        ));
    }

    #[test]
    fn capture_engine_starts_with_fresh_d2_out_transfer() {
        let engine = Gf3258LibfprintCaptureEngine::new().unwrap();
        let mut out = [0u8; GF3258_LIBFPRINT_USB_OUT_BLOCK_SIZE];
        let action = engine.next_action(&mut out).unwrap();

        assert_eq!(action.stage(), Gf3258LibfprintCaptureStage::D2Write);
        assert_eq!(action.direction(), Gf3258LibfprintTransferDirection::Out);
        assert_eq!(action.endpoint(), GF3258_LIBFPRINT_BULK_OUT);
        assert_eq!(action.transfer_length(), 64);
        assert!(action.short_is_error());
        assert_eq!(out[0], 0xa0);
        assert_eq!(out[4], Command::TlsPovImage.as_u8());
    }

    #[test]
    fn capture_engine_ignores_ack_for_unrelated_command() {
        let mut engine = Gf3258LibfprintCaptureEngine::new().unwrap();
        engine.complete_transfer(&[]).unwrap();
        let unrelated =
            encode_a0_packet(Command::Ack, &[Command::GetVersion.as_u8(), 0x01]).unwrap();

        assert_eq!(
            engine.complete_transfer(&unrelated).unwrap(),
            Gf3258LibfprintCaptureProgress::Ignored
        );
        assert_eq!(engine.stage(), Gf3258LibfprintCaptureStage::D2Ack);
    }

    #[test]
    fn capture_engine_rejects_completion_before_ack() {
        let mut engine = Gf3258LibfprintCaptureEngine::new().unwrap();
        engine.complete_transfer(&[]).unwrap();
        let completion = encode_a0_packet(Command::TlsPovImage, &[0x00]).unwrap();

        assert!(matches!(
            engine.complete_transfer(&completion),
            Err(Gf3258LibfprintWireError::CaptureResponseBeforeAck { command: 0xd2 })
        ));
    }

    #[test]
    fn capture_engine_requires_full_out_scratch_block() {
        let engine = Gf3258LibfprintCaptureEngine::new().unwrap();
        let mut short = [0u8; 63];

        assert_eq!(
            engine.next_action(&mut short),
            Err(Gf3258LibfprintWireError::CaptureOutputBufferTooSmall {
                required: 64,
                actual: 63,
            })
        );
    }

    #[test]
    fn capture_engine_requires_finger_up_before_image_result() {
        let mut engine = Gf3258LibfprintCaptureEngine::new().unwrap();

        advance_out(&mut engine);
        advance_ack(&mut engine, Command::TlsPovImage);
        advance_completion(&mut engine, Command::TlsPovImage, &[0x00]);
        advance_out(&mut engine);
        advance_ack(&mut engine, Command::FdtDown);
        advance_completion(&mut engine, Command::FdtDown, &[0x00; 16]);
        advance_out(&mut engine);
        advance_ack(&mut engine, Command::GetImage);

        let protected = synthetic_protected_image(&engine);
        let image_response = incoming_get_image(&protected);
        engine.complete_transfer(&image_response).unwrap();

        assert_eq!(engine.stage(), Gf3258LibfprintCaptureStage::FingerUpWrite);
        assert_eq!(
            engine.result(),
            Err(Gf3258LibfprintWireError::CaptureResultNotReady)
        );

        let mut out = [0u8; GF3258_LIBFPRINT_USB_OUT_BLOCK_SIZE];
        let action = engine.next_action(&mut out).unwrap();
        assert_eq!(action.stage(), Gf3258LibfprintCaptureStage::FingerUpWrite);
        assert_eq!(action.direction(), Gf3258LibfprintTransferDirection::Out);
        assert_eq!(out[4], Command::FdtUp.as_u8());
    }

    #[test]
    fn capture_engine_completes_valid_protected_image_after_finger_up() {
        let mut engine = Gf3258LibfprintCaptureEngine::new().unwrap();

        advance_out(&mut engine);
        advance_ack(&mut engine, Command::TlsPovImage);
        advance_completion(&mut engine, Command::TlsPovImage, &[0x00]);
        advance_out(&mut engine);
        advance_ack(&mut engine, Command::FdtDown);
        advance_completion(&mut engine, Command::FdtDown, &[0x00; 16]);
        advance_out(&mut engine);
        advance_ack(&mut engine, Command::GetImage);

        let protected = synthetic_protected_image(&engine);
        let image_response = incoming_get_image(&protected);
        assert_eq!(
            engine.complete_transfer(&image_response).unwrap(),
            Gf3258LibfprintCaptureProgress::Advanced
        );
        assert_eq!(engine.stage(), Gf3258LibfprintCaptureStage::FingerUpWrite);

        advance_out(&mut engine);
        advance_ack(&mut engine, Command::FdtUp);
        advance_completion(&mut engine, Command::FdtUp, &[0x00; 16]);

        assert_eq!(engine.stage(), Gf3258LibfprintCaptureStage::Complete);
        let result = engine.result().unwrap();
        assert_eq!(result.protected_bytes(), PROTECTED_IMAGE_LEN);
        assert_eq!(result.pixel_count(), GF3258_LIBFPRINT_CAPTURE_PIXEL_COUNT);
        assert_eq!(result.raw_u16().len(), GF3258_LIBFPRINT_CAPTURE_PIXEL_COUNT);
        assert!(result.raw_u16().iter().all(|pixel| *pixel == 0));
        assert!(result.normalized_u8().iter().all(|pixel| *pixel == 0));
    }

    #[test]
    fn verification_engine_rejects_malformed_tgla_before_capture() {
        assert!(matches!(
            Gf3258LibfprintVerificationEngine::new(b"not-a-template"),
            Err(Gf3258LibfprintWireError::VerificationTemplate(_))
        ));
    }

    #[test]
    fn verification_engine_accepts_valid_tgla_before_exposing_d2() {
        let tgla = synthetic_nonempty_tgla();
        let engine = Gf3258LibfprintVerificationEngine::new(&tgla).unwrap();
        let mut out = [0u8; GF3258_LIBFPRINT_USB_OUT_BLOCK_SIZE];
        let action = engine.next_action(&mut out).unwrap();

        assert_eq!(action.stage(), Gf3258LibfprintCaptureStage::D2Write);
        assert_eq!(action.direction(), Gf3258LibfprintTransferDirection::Out);
        assert_eq!(out[4], Command::TlsPovImage.as_u8());
    }

    #[test]
    fn verification_result_is_unavailable_before_capture_finishes() {
        let tgla = synthetic_nonempty_tgla();
        let engine = Gf3258LibfprintVerificationEngine::new(&tgla).unwrap();

        assert_eq!(
            engine.result(),
            Err(Gf3258LibfprintWireError::VerificationResultNotReady)
        );
    }

    const LIVE_OTP: [u8; OTP_LEN] = [
        0x57, 0x43, 0x47, 0x34, 0x33, 0x38, 0x2e, 0x00, 0xc0, 0x74, 0x8b, 0xab, 0x42, 0xeb, 0x16,
        0x0a, 0x01, 0x05, 0x03, 0x06, 0x00, 0x00, 0x79, 0x00, 0x00, 0x00, 0x00, 0x0c, 0xf1, 0x73,
        0x8c, 0x0c, 0x07, 0x00, 0x00, 0x00, 0xe5, 0x73, 0xdf, 0xfc, 0x08, 0x76, 0xad, 0x52, 0x06,
        0xad, 0xae, 0xaf, 0xad, 0xae, 0xae, 0xaf, 0xad, 0xae, 0x00, 0x00, 0xe5, 0x1a, 0xdf, 0x20,
        0x16, 0x5f, 0x79, 0xff,
    ];

    #[test]
    fn recovery_engine_starts_with_exact_a6_get_otp_request() {
        let engine = Gf3258LibfprintRecoveryEngine::new();
        let mut out = [0u8; DOWNLOAD_CONFIG_PACKET_SIZE];
        let action = engine.next_action(&mut out).unwrap();
        assert_eq!(action.stage(), Gf3258LibfprintRecoveryStage::ReadOtpWrite);
        assert_eq!(action.direction(), Gf3258LibfprintTransferDirection::Out);
        assert_eq!(action.transfer_length(), 64);
        assert_eq!(
            &out[..10],
            &[0xa0, 0x06, 0x00, 0xa6, 0xa6, 0x03, 0x00, 0x40, 0x00, 0xc1]
        );
        assert!(out[10..64].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn recovery_engine_rejects_a6_completion_before_ack() {
        let mut engine = Gf3258LibfprintRecoveryEngine::new();
        engine.complete_transfer(&[]).unwrap();
        let completion = encode_a0_packet(Command::ReadOtp, &LIVE_OTP).unwrap();
        assert!(matches!(
            engine.complete_transfer(&completion),
            Err(Gf3258LibfprintWireError::RecoveryResponseBeforeAck { command: 0xa6 })
        ));
    }

    #[test]
    fn recovery_engine_generates_exact_264_byte_chicago_h_download() {
        let mut engine = Gf3258LibfprintRecoveryEngine::new();
        engine.complete_transfer(&[]).unwrap();
        let ack = encode_a0_packet(Command::Ack, &[Command::ReadOtp.as_u8(), 0x03]).unwrap();
        engine.complete_transfer(&ack).unwrap();
        let completion = encode_a0_packet(Command::ReadOtp, &LIVE_OTP).unwrap();
        engine.complete_transfer(&completion).unwrap();

        let mut out = [0u8; DOWNLOAD_CONFIG_PACKET_SIZE];
        let action = engine.next_action(&mut out).unwrap();
        assert_eq!(
            action.stage(),
            Gf3258LibfprintRecoveryStage::DownloadConfigWrite
        );
        assert_eq!(action.transfer_length(), DOWNLOAD_CONFIG_PACKET_SIZE);
        assert_eq!(&out[..7], &[0xa0, 0x04, 0x01, 0xa5, 0x90, 0x01, 0x01]);
        assert_eq!(out[DOWNLOAD_CONFIG_PACKET_SIZE - 1], 0x6f);
        assert_eq!(
            &out[DOWNLOAD_CONFIG_PACKET_SIZE - 3..DOWNLOAD_CONFIG_PACKET_SIZE - 1],
            &[0x48, 0x1e]
        );
    }

    #[test]
    fn recovery_engine_completes_exact_live_chicago_h_path() {
        let mut engine = Gf3258LibfprintRecoveryEngine::new();
        engine.complete_transfer(&[]).unwrap();
        let a6_ack = encode_a0_packet(Command::Ack, &[Command::ReadOtp.as_u8(), 0x03]).unwrap();
        engine.complete_transfer(&a6_ack).unwrap();
        let otp = encode_a0_packet(Command::ReadOtp, &LIVE_OTP).unwrap();
        engine.complete_transfer(&otp).unwrap();
        engine.complete_transfer(&[]).unwrap();
        let config_ack =
            encode_a0_packet(Command::Ack, &[Command::DownloadConfig.as_u8(), 0x03]).unwrap();
        engine.complete_transfer(&config_ack).unwrap();
        let config_done = encode_a0_packet(Command::DownloadConfig, &[0x01, 0x00]).unwrap();
        engine.complete_transfer(&config_done).unwrap();

        assert_eq!(engine.stage(), Gf3258LibfprintRecoveryStage::Complete);
        let result = engine.result().unwrap();
        assert_eq!(result.tcode(), 0x00f0);
        assert_eq!(result.diff(), 0x0021);
        assert_eq!(result.fdt_offset(), 0);
        assert_eq!(result.checksum(), 0x1e48);
    }

    #[test]
    fn enrollment_engine_starts_at_zero_samples() {
        let engine = Gf3258LibfprintEnrollmentEngine::new().unwrap();
        assert_eq!(engine.sample_count(), 0);
        assert_eq!(engine.stage(), Gf3258LibfprintCaptureStage::D2Write);
        assert!(matches!(
            engine.result(),
            Err(Gf3258LibfprintWireError::EnrollmentResultNotReady)
        ));
        assert!(matches!(
            engine.tgla(),
            Err(Gf3258LibfprintWireError::EnrollmentTglaNotReady)
        ));
    }

    #[test]
    fn enrollment_workflow_completes_with_verification_readable_tgla() {
        let raw = vec![1000u16; IMAGE_WIDTH * IMAGE_HEIGHT];
        let mut workflow = Gf3258EnrollmentWorkflow::new();
        for expected in 1..=GF3258_ENROLLMENT_TARGET_SAMPLES {
            let outcome = workflow.process_raw_frame(&raw).unwrap();
            let Gf3258EnrollmentFrameOutcome::Accepted(commit) = outcome else {
                panic!("synthetic enrollment frame was rejected");
            };
            assert_eq!(commit.sample_count, expected);
        }
        assert!(workflow.is_complete());
        let artifacts = workflow.encode_artifacts().unwrap();
        let template = Gf3258VerificationTemplate::from_tgla(artifacts.tgla_template()).unwrap();
        assert_eq!(template.sample_count(), GF3258_ENROLLMENT_TARGET_SAMPLES);
    }

    #[test]
    fn completed_enrollment_cannot_start_another_touch() {
        let raw = vec![1000u16; IMAGE_WIDTH * IMAGE_HEIGHT];
        let mut engine = Gf3258LibfprintEnrollmentEngine::new().unwrap();
        for _ in 0..GF3258_ENROLLMENT_TARGET_SAMPLES {
            assert!(matches!(
                engine.workflow.process_raw_frame(&raw).unwrap(),
                Gf3258EnrollmentFrameOutcome::Accepted(_)
            ));
        }
        let artifacts = engine.workflow.encode_artifacts().unwrap();
        engine.tgla = Some(artifacts.tgla_template().to_vec());
        engine.result = Some(Gf3258LibfprintEnrollmentResult {
            disposition: Gf3258LibfprintEnrollmentDisposition::Complete,
            sample_count: GF3258_ENROLLMENT_TARGET_SAMPLES,
            progress_percent: 100,
            protected_bytes: PROTECTED_IMAGE_LEN,
            pixel_count: GF3258_LIBFPRINT_CAPTURE_PIXEL_COUNT,
            stored_crc: 0,
            tgla_bytes: engine.tgla.as_ref().unwrap().len(),
        });
        assert!(matches!(
            engine.start_next_touch(),
            Err(Gf3258LibfprintWireError::EnrollmentAlreadyComplete)
        ));
    }

    fn synthetic_nonempty_tgla() -> Vec<u8> {
        let raw = vec![1000u16; IMAGE_WIDTH * IMAGE_HEIGHT];
        let mut enrollment = crate::enrollment::Gf3258EnrollmentWorkflow::new();
        assert!(matches!(
            enrollment.process_raw_frame(&raw).unwrap(),
            crate::enrollment::Gf3258EnrollmentFrameOutcome::Accepted(_)
        ));
        enrollment
            .encode_artifacts()
            .unwrap()
            .tgla_template()
            .to_vec()
    }

    fn advance_out(engine: &mut Gf3258LibfprintCaptureEngine) {
        assert_eq!(
            engine.complete_transfer(&[]).unwrap(),
            Gf3258LibfprintCaptureProgress::Advanced
        );
    }

    fn advance_ack(engine: &mut Gf3258LibfprintCaptureEngine, command: Command) {
        let ack = encode_a0_packet(Command::Ack, &[command.as_u8(), 0x01]).unwrap();
        assert_eq!(
            engine.complete_transfer(&ack).unwrap(),
            Gf3258LibfprintCaptureProgress::Advanced
        );
    }

    fn advance_completion(
        engine: &mut Gf3258LibfprintCaptureEngine,
        command: Command,
        payload: &[u8],
    ) {
        let completion = encode_a0_packet(command, payload).unwrap();
        assert_eq!(
            engine.complete_transfer(&completion).unwrap(),
            Gf3258LibfprintCaptureProgress::Advanced
        );
    }

    fn synthetic_protected_image(engine: &Gf3258LibfprintCaptureEngine) -> Vec<u8> {
        let decrypted = vec![0u8; 10_560];
        let key = engine.session.image_key();
        let encryptor = Aes128CbcEncryptor::new_from_slices(&key, &[0u8; 16]).unwrap();
        let ciphertext = encryptor.encrypt_padded_vec::<NoPadding>(&decrypted);
        let crc = goodix_image_crc(&decrypted);
        let wire_crc = [
            (crc >> 8) as u8,
            crc as u8,
            (crc >> 24) as u8,
            (crc >> 16) as u8,
        ];

        let mut protected = Vec::with_capacity(PROTECTED_IMAGE_LEN);
        protected.extend_from_slice(&[0u8; 5]);
        protected.extend_from_slice(&ciphertext);
        protected.extend_from_slice(&wire_crc);
        assert_eq!(protected.len(), PROTECTED_IMAGE_LEN);
        protected
    }

    fn incoming_get_image(protected: &[u8]) -> Vec<u8> {
        let encoded_len = u16::try_from(protected.len()).unwrap();
        let mut inner = Vec::with_capacity(MCU_HEADER_LEN + protected.len());
        inner.push(Command::GetImage.as_u8());
        inner.extend_from_slice(&encoded_len.to_le_bytes());
        inner.extend_from_slice(protected);

        let outer_len = u16::try_from(inner.len()).unwrap();
        let [lo, hi] = outer_len.to_le_bytes();
        let mut frame = Vec::with_capacity(OUTER_HEADER_LEN + inner.len());
        frame.extend_from_slice(&[0xa0, lo, hi, 0xa0u8.wrapping_add(lo).wrapping_add(hi)]);
        frame.extend_from_slice(&inner);
        frame
    }
}
