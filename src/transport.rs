use std::{
    error::Error,
    fmt, io, str, thread,
    time::{Duration, Instant},
};

use crate::{
    crypto::ImageSession,
    device::{GoodixDevice, GoodixUsbError, GoodixUsbErrorKind, GoodixUsbIo},
    firmware::{
        AppTransferPackage, F4_TAG_LEN, FirmwareTransferCommand, WriteAppTransferError,
        WriteAppTransferResult, write_app_transfer,
    },
    protocol::{
        Command, McuPacket, ProtocolError, decode_a0_packet, encode_a0_packet, encode_a0_single,
    },
    trace::{Direction, TraceLogger},
};

const READ_BUFFER_SIZE: usize = 0x8000;
const WRITE_TIMEOUT: Duration = Duration::from_secs(1);
const READ_SLICE_TIMEOUT: Duration = Duration::from_millis(500);

/// Geneva McuWriteRaw emits every physical USB OUT transfer as exactly
/// one 64-byte block, zero-padding the last block when the logical A0
/// packet does not end on a block boundary.
const USB_OUT_BLOCK_SIZE: usize = 0x40;

/// In Geneva McuParseMsg, the second B0 payload byte is a flag field, not a
/// success/failure status.
///
/// For a normal B0 message the vendor parser:
///
/// - marks the message as an ACK unconditionally;
/// - copies payload[0] as the echoed command;
/// - tests only bit 1 (0x02) of payload[1] as the MCU-power-lost indication.
///
/// Therefore both observed values 0x01 and 0x03 are valid ACKs. 0x03 simply
/// has the power-lost flag set. Other bits are ignored by McuParseMsg.
const ACK_FLAG_MCU_POWER_LOST: u8 = 0x02;

const GET_VERSION_PAYLOAD: [u8; 2] = [0x00, 0x00];

/// ChicagoHGetOtp request used by GF3258 WN2:
///
///     A6 03 00 40 00 C1
///
/// The two payload bytes request exactly 0x40 raw OTP bytes.
pub(crate) const READ_OTP_PAYLOAD: [u8; 2] = [0x40, 0x00];

pub(crate) const OTP_LEN: usize = 0x40;

/// Geneva McuResetMcu payload for command A2.
///
/// Vendor WriteApp sends exactly `02 32`, receives only the matching B0 ACK,
/// and then waits for USB detach -> attach instead of an A2 completion packet.
const RESET_MCU_PAYLOAD: [u8; 2] = [0x02, 0x32];

/// Geneva McuResetFingerPrint payload for command A2.
///
/// The loader performs this reset after firmware update/re-enumeration, then
/// sleeps exactly 10 ms before reading the chip ID.
const RESET_FINGERPRINT_PAYLOAD: [u8; 2] = [0x05, 0x14];

/// `_McuReadRegister(address=0x0000, length=4)` payload used by
/// McuGetChipId.
const GET_CHIP_ID_PAYLOAD: [u8; 5] = [0x00, 0x00, 0x00, 0x04, 0x00];

/// Exact loader delay between McuResetFingerPrint and McuGetChipId.
const CHIP_ID_RESET_DELAY: Duration = Duration::from_millis(10);

/// GM168SEC / GF3258 WN2 chip ID recovered from the real 27c6:550a.
///
/// The 0x82 response bytes on the wire are `03 a8 00 25`; the vendor helper
/// swaps the byte order inside each 16-bit word before interpreting the u32,
/// yielding `a8 03 25 00` -> 0x002503a8.
const EXPECTED_CHIP_ID: u32 = 0x0025_03a8;

/// PresetPskReadG reads object data in chunks of at most 0x100 bytes.
pub(crate) const PSK_READ_CHUNK_SIZE: usize = 0x100;

/// E4 completion payload:
///
///     +0x00  u8      MCU execution status
///     +0x01  u32 LE  echoed object ID
///     +0x05  u32 LE  returned object-data length
///     +0x09  N bytes returned object data
///
const PSK_READ_RESPONSE_HEADER_SIZE: usize = 9;

const PSK_READ_STATUS_OK: u8 = 0x00;

/// Objects used by PresetPskIsVaildG.
pub(crate) const SEALED_PSK_OBJECT: u32 = 0xbb01_0002;
pub(crate) const PSK_HASH_OBJECT: u32 = 0xbb02_0001;

/// Sizes observed in the vendor implementation/capture.
pub(crate) const SEALED_PSK_SIZE: usize = 0x66;
pub(crate) const PSK_HASH_SIZE: usize = 0x20;

#[derive(Debug)]
pub(crate) enum TransportError {
    Usb(GoodixUsbError),
    Trace(io::Error),
    Protocol(ProtocolError),

    ShortWrite {
        expected: usize,
        actual: usize,
    },

    MalformedAck {
        payload_len: usize,
    },

    MalformedOtpResponse {
        payload_len: usize,
    },

    ResponseBeforeAck {
        command: u8,
    },

    InvalidFirmwareCommand {
        command: u8,
    },

    TimedOut {
        command: u8,
        timeout: Duration,
    },

    InvalidPskObjectLength {
        length: usize,
    },

    MalformedPskReadResponse {
        payload_len: usize,
    },

    PskReadRejected {
        status: u8,
    },

    PskReadObjectMismatch {
        expected: u32,
        actual: u32,
    },

    PskReadZeroLength {
        object_type: u32,
        offset: u32,
    },

    PskReadTruncated {
        declared: usize,
        available: usize,
    },

    PskReadReturnedTooMuch {
        requested: usize,
        returned: usize,
        remaining: usize,
    },

    MalformedChipIdResponse {
        payload_len: usize,
    },

    UnexpectedChipId {
        expected: u32,
        actual: u32,
    },

    Utf8(str::Utf8Error),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usb(error) => {
                write!(f, "USB error: {error}")
            }

            Self::Trace(error) => {
                write!(f, "trace error: {error}")
            }

            Self::Protocol(error) => {
                write!(f, "protocol error: {error}")
            }

            Self::ShortWrite { expected, actual } => {
                write!(
                    f,
                    "short USB write: expected {expected} bytes, \
                     wrote {actual}"
                )
            }

            Self::MalformedAck { payload_len } => {
                write!(
                    f,
                    "malformed ACK: expected 2-byte payload, \
                     received {payload_len}"
                )
            }

            Self::MalformedOtpResponse { payload_len } => {
                write!(
                    f,
                    "malformed A6 OTP response: expected {OTP_LEN} payload bytes, \
                     received {payload_len}"
                )
            }

            Self::ResponseBeforeAck { command } => {
                write!(
                    f,
                    "received response for command 0x{command:02x} \
                     before its ACK"
                )
            }

            Self::InvalidFirmwareCommand { command } => {
                write!(
                    f,
                    "command 0x{command:02x} is not an F0/F4 firmware command"
                )
            }

            Self::TimedOut { command, timeout } => {
                write!(
                    f,
                    "timed out after {timeout:?} waiting for \
                     command 0x{command:02x}"
                )
            }

            Self::InvalidPskObjectLength { length } => {
                write!(f, "invalid PSK object length: {length} bytes")
            }

            Self::MalformedPskReadResponse { payload_len } => {
                write!(
                    f,
                    "malformed E4 PSK-read response: expected at least \
                     {PSK_READ_RESPONSE_HEADER_SIZE} payload bytes, \
                     received {payload_len}"
                )
            }

            Self::PskReadRejected { status } => {
                write!(
                    f,
                    "MCU rejected E4 PSK-read operation with \
                     execution status 0x{status:02x}"
                )
            }

            Self::PskReadObjectMismatch { expected, actual } => {
                write!(
                    f,
                    "E4 PSK-read returned object 0x{actual:08x}, \
                     expected 0x{expected:08x}"
                )
            }

            Self::PskReadZeroLength {
                object_type,
                offset,
            } => {
                write!(
                    f,
                    "E4 PSK-read returned zero bytes for object \
                     0x{object_type:08x} at offset 0x{offset:x}"
                )
            }

            Self::PskReadTruncated {
                declared,
                available,
            } => {
                write!(
                    f,
                    "truncated E4 PSK-read response: MCU declared \
                     {declared} object bytes but only {available} \
                     are present"
                )
            }

            Self::PskReadReturnedTooMuch {
                requested,
                returned,
                remaining,
            } => {
                write!(
                    f,
                    "invalid E4 PSK-read length: requested {requested} \
                     bytes, MCU returned {returned}, with {remaining} \
                     bytes remaining"
                )
            }

            Self::MalformedChipIdResponse { payload_len } => {
                write!(
                    f,
                    "malformed 0x82 chip-ID response: expected exactly 4 \
                     payload bytes, received {payload_len}"
                )
            }

            Self::UnexpectedChipId { expected, actual } => {
                write!(
                    f,
                    "unexpected Goodix chip ID: expected 0x{expected:08x}, \
                     received 0x{actual:08x}"
                )
            }

            Self::Utf8(error) => {
                write!(f, "firmware version is not valid UTF-8: {error}")
            }
        }
    }
}

impl Error for TransportError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Usb(error) => Some(error),
            Self::Trace(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::Utf8(error) => Some(error),
            _ => None,
        }
    }
}

impl From<GoodixUsbError> for TransportError {
    fn from(error: GoodixUsbError) -> Self {
        Self::Usb(error)
    }
}

impl From<io::Error> for TransportError {
    fn from(error: io::Error) -> Self {
        Self::Trace(error)
    }
}

impl From<ProtocolError> for TransportError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<str::Utf8Error> for TransportError {
    fn from(error: str::Utf8Error) -> Self {
        Self::Utf8(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ack {
    pub(crate) command: u8,
    pub(crate) flags: u8,
    pub(crate) mcu_power_lost: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Transaction {
    pub(crate) ack: Ack,
    pub(crate) completion: McuPacket,
}

pub(crate) struct GoodixTransport<'a, D: GoodixUsbIo + ?Sized = GoodixDevice> {
    device: &'a D,
    trace: TraceLogger,
    read_buffer: Vec<u8>,
}

impl<'a, D: GoodixUsbIo + ?Sized> GoodixTransport<'a, D> {
    pub(crate) fn new(device: &'a D, trace: TraceLogger) -> Self {
        Self {
            device,
            trace,
            read_buffer: vec![0; READ_BUFFER_SIZE],
        }
    }

    /// Execute a normal MCU transaction and return only the completion packet.
    ///
    /// This preserves the original API for existing callers. Use
    /// `transact_with_ack()` when the higher layer needs the B0 flag state.
    pub(crate) fn transact(
        &mut self,
        command: Command,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<McuPacket, TransportError> {
        Ok(self
            .transact_with_ack(command, payload, timeout)?
            .completion)
    }

    /// Execute a normal MCU transaction while preserving the matching B0 ACK.
    ///
    /// Geneva McuParseMsg proves that B0 payload[1] is a flag byte, not a
    /// success status. In particular, bit 0x02 reports MCU volatile-state
    /// loss. Higher layers can therefore decide whether recovery such as
    /// ChicagoH A6 -> 0x90 initialization is required without embedding that
    /// policy in the transport.
    pub(crate) fn transact_with_ack(
        &mut self,
        command: Command,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<Transaction, TransportError> {
        self.send_command(command, payload)?;
        self.wait_for_completion_with_ack(command, timeout)
    }

    /// Execute an F0/F4 firmware transaction without exposing firmware
    /// writes through the CLI.
    ///
    /// Unlike ordinary commands, an F0 logical A0 packet can be larger
    /// than one USB transfer. Geneva McuWriteRaw splits that logical packet
    /// into exactly 64-byte physical OUT transfers and zero-pads only the
    /// final block. F4 normally fits in one block but uses the same path.
    ///
    /// The receive side deliberately applies only the transport semantics
    /// proved from the vendor driver:
    ///
    /// - require the matching B0 ACK;
    /// - treat the second B0 payload byte as flags, matching McuParseMsg;
    ///   bit 0x02 reports MCU power-lost but does not reject the ACK;
    /// - then require a completion packet whose command is the original
    ///   F0/F4 command;
    /// - return the parsed completion payload unchanged.
    ///
    /// Higher layers decide what the completion payload means. In
    /// particular, WriteApp ignores the F0 completion byte, while F4 treats
    /// a zero result as failure and any non-zero result as success.
    #[allow(dead_code)]
    pub(crate) fn transact_firmware(
        &mut self,
        command: Command,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<McuPacket, TransportError> {
        if !matches!(command, Command::FirmwareWrite | Command::FirmwareCheck) {
            return Err(TransportError::InvalidFirmwareCommand {
                command: command.as_u8(),
            });
        }

        let frame = encode_a0_packet(command, payload)?;

        self.send_padded_a0_frame(&frame)?;
        self.wait_for_completion(command, timeout)
    }

    /// Adapter between the transport-independent firmware WriteApp stage and
    /// the live Goodix USB transport.
    ///
    /// This method is intentionally not called by any CLI action. Merely
    /// compiling it does not transmit F0 or F4.
    #[allow(dead_code)]
    pub(crate) fn write_app_transfer(
        &mut self,
        package: &AppTransferPackage,
        f4_tag: &[u8; F4_TAG_LEN],
        f0_timeout: Duration,
        f4_timeout: Duration,
    ) -> Result<WriteAppTransferResult, WriteAppTransferError<TransportError>> {
        write_app_transfer(
            package,
            f4_tag,
            f0_timeout,
            f4_timeout,
            |firmware_command, payload, timeout| {
                let command = match firmware_command {
                    FirmwareTransferCommand::F0Write => Command::FirmwareWrite,
                    FirmwareTransferCommand::F4Check => Command::FirmwareCheck,
                };

                let packet = self.transact_firmware(command, payload, timeout)?;
                Ok(packet.payload)
            },
        )
    }

    /// Send Geneva McuResetMcu: command A2 with payload `02 32`.
    ///
    /// This transaction is intentionally ACK-only. The successful vendor
    /// sequence is:
    ///
    ///     A2 02 32
    ///     -> B0 ACK for A2
    ///     -> USB detach
    ///     -> USB attach
    ///
    /// There is no normal A2 completion packet before re-enumeration, so using
    /// `transact()` here would incorrectly wait until timeout. Device
    /// detach/attach and reopening are handled above this borrowed transport.
    #[allow(dead_code)]
    pub(crate) fn reset_mcu(&mut self, timeout: Duration) -> Result<(), TransportError> {
        self.send_command(Command::ResetChip, &RESET_MCU_PAYLOAD)?;

        let deadline = Instant::now() + timeout;
        let _ack = self.wait_for_ack_until(Command::ResetChip, deadline, timeout)?;
        Ok(())
    }

    /// Reproduce loader McuResetFingerPrint: A2 with payload `05 14`.
    ///
    /// Unlike McuResetMcu (`02 32`), this is a normal command transaction: the
    /// device returns both a B0 ACK and an A2 completion packet. The vendor
    /// loader only cares that the command succeeds; the completion payload is
    /// not interpreted here.
    #[allow(dead_code)]
    pub(crate) fn reset_fingerprint(&mut self, timeout: Duration) -> Result<(), TransportError> {
        let _completion = self.transact(Command::ResetChip, &RESET_FINGERPRINT_PAYLOAD, timeout)?;

        Ok(())
    }

    /// Reproduce McuGetChipId using `_McuReadRegister(0x0000, 4)`.
    ///
    /// The MCU returns four register bytes. The vendor then calls the helper
    /// recovered as `SwapU16ByteOrderInPlace`, swapping bytes inside each
    /// 16-bit word before interpreting the resulting four bytes as little-endian
    /// u32.
    #[allow(dead_code)]
    pub(crate) fn read_chip_id(&mut self, timeout: Duration) -> Result<u32, TransportError> {
        let packet = self.transact(Command::ReadRegister, &GET_CHIP_ID_PAYLOAD, timeout)?;
        parse_chip_id_payload(&packet.payload)
    }

    /// Perform the loader's post-re-enumeration sensor validation sequence:
    ///
    /// ```text
    /// McuResetFingerPrint  (A2 05 14)
    /// sleep 10 ms
    /// McuGetChipId         (82, address 0, length 4)
    /// require 0x002503a8
    /// ```
    ///
    /// This method is intentionally not reachable from the CLI. It assumes the
    /// caller has already completed McuResetMcu and USB detach -> attach, and is
    /// using a fresh transport bound to the re-enumerated device.
    #[allow(dead_code)]
    pub(crate) fn validate_post_reenumeration(
        &mut self,
        reset_timeout: Duration,
        chip_id_timeout: Duration,
    ) -> Result<u32, TransportError> {
        self.reset_fingerprint(reset_timeout)?;

        thread::sleep(CHIP_ID_RESET_DELAY);

        let chip_id = self.read_chip_id(chip_id_timeout)?;

        if chip_id != EXPECTED_CHIP_ID {
            return Err(TransportError::UnexpectedChipId {
                expected: EXPECTED_CHIP_ID,
                actual: chip_id,
            });
        }

        Ok(chip_id)
    }

    fn wait_for_completion(
        &mut self,
        command: Command,
        timeout: Duration,
    ) -> Result<McuPacket, TransportError> {
        Ok(self
            .wait_for_completion_with_ack(command, timeout)?
            .completion)
    }

    fn wait_for_completion_with_ack(
        &mut self,
        command: Command,
        timeout: Duration,
    ) -> Result<Transaction, TransportError> {
        let command_byte = command.as_u8();
        let deadline = Instant::now() + timeout;

        let ack = self.wait_for_ack_until(command, deadline, timeout)?;

        loop {
            let now = Instant::now();

            if now >= deadline {
                return Err(TransportError::TimedOut {
                    command: command_byte,
                    timeout,
                });
            }

            let read_timeout = (deadline - now).min(READ_SLICE_TIMEOUT);

            let Some(packet) = self.read_packet(read_timeout)? else {
                continue;
            };

            if packet.command == command_byte {
                return Ok(Transaction {
                    ack,
                    completion: packet,
                });
            }
        }
    }

    /// Wait only for the matching B0 ACK, sharing the caller's existing
    /// deadline. Geneva McuParseMsg treats the second B0 payload byte as flags,
    /// not as a success code: a normal B0 message is an ACK regardless of that
    /// byte, while bit 0x02 separately reports MCU power-lost.
    ///
    /// A completion for the same command arriving before its ACK remains a
    /// protocol error, matching the normal transaction path.
    fn wait_for_ack_until(
        &mut self,
        command: Command,
        deadline: Instant,
        timeout: Duration,
    ) -> Result<Ack, TransportError> {
        let command_byte = command.as_u8();

        loop {
            let now = Instant::now();

            if now >= deadline {
                return Err(TransportError::TimedOut {
                    command: command_byte,
                    timeout,
                });
            }

            let read_timeout = (deadline - now).min(READ_SLICE_TIMEOUT);

            let Some(packet) = self.read_packet(read_timeout)? else {
                continue;
            };

            if packet.is_command(Command::Ack) {
                let ack = parse_ack(&packet)?;

                if ack.command != command_byte {
                    continue;
                }

                /*
                 * McuParseMsg marks every normal B0 message as an ACK and
                 * interprets payload[1] only as flags. In particular, bit
                 * 0x02 reports MCU power-lost but does not reject the ACK.
                 *
                 * Return the parsed ACK intact so policy remains above the
                 * transport layer.
                 */
                return Ok(ack);
            }

            if packet.command == command_byte {
                return Err(TransportError::ResponseBeforeAck {
                    command: command_byte,
                });
            }
        }
    }

    pub(crate) fn get_version(&mut self, timeout: Duration) -> Result<String, TransportError> {
        let (version, _ack) = self.get_version_with_ack(timeout)?;
        Ok(version)
    }

    /// Read the firmware version while preserving the matching B0 ACK flags.
    ///
    /// This is the preferred startup probe for APP mode because a cold MCU
    /// reports a valid version response while setting ACK bit 0x02. The
    /// caller can then perform ChicagoH volatile-state recovery only when
    /// `ack.mcu_power_lost` is true.
    pub(crate) fn get_version_with_ack(
        &mut self,
        timeout: Duration,
    ) -> Result<(String, Ack), TransportError> {
        let transaction =
            self.transact_with_ack(Command::GetVersion, &GET_VERSION_PAYLOAD, timeout)?;

        let payload = transaction
            .completion
            .payload
            .strip_suffix(&[0])
            .unwrap_or(&transaction.completion.payload);

        Ok((str::from_utf8(payload)?.to_owned(), transaction.ack))
    }

    /// Read the raw 64-byte ChicagoH OTP using command A6.
    ///
    /// This is the exact read-only request proven on the live GF3258 WN2:
    ///
    /// ```text
    /// A0 06 00 A6 A6 03 00 40 00 C1
    /// ```
    ///
    /// This method only validates the transport-level response length.
    /// ChicagoH CP/FT/MT CRC validation belongs to the sensor/configuration
    /// layer above GoodixTransport.
    pub(crate) fn read_otp(&mut self, timeout: Duration) -> Result<[u8; OTP_LEN], TransportError> {
        let packet = self.transact(Command::ReadOtp, &READ_OTP_PAYLOAD, timeout)?;

        if packet.payload.len() != OTP_LEN {
            return Err(TransportError::MalformedOtpResponse {
                payload_len: packet.payload.len(),
            });
        }

        let mut otp = [0u8; OTP_LEN];
        otp.copy_from_slice(&packet.payload);

        Ok(otp)
    }

    /// Download one generated 0x100-byte volatile GF3258 WN2 chip
    /// configuration using command 0x90.
    ///
    /// Unlike ordinary short commands, the resulting logical A0 packet is
    /// 264 bytes:
    ///
    /// ```text
    /// A0 04 01 A5
    /// 90 01 01
    /// <256-byte config>
    /// <ordinary MCU checksum>
    /// ```
    ///
    /// The first standalone cold-config experiment proved that this packet
    /// is accepted when submitted as one exact libusb bulk transfer. Do not
    /// route it through the F0/F4 64-byte padded-block path: that path models
    /// Geneva firmware transfer semantics and remains intentionally separate.
    ///
    /// The returned 0x90 completion packet is left uninterpreted here.
    /// The sensor/configuration layer must require the recovered success
    /// payload `[0x01, 0x00]`.
    pub(crate) fn download_config(
        &mut self,
        config: &[u8; 0x100],
        timeout: Duration,
    ) -> Result<McuPacket, TransportError> {
        let frame = encode_a0_packet(Command::DownloadConfig, config)?;

        self.write_exact_a0_frame(&frame)?;
        self.wait_for_completion(Command::DownloadConfig, timeout)
    }

    pub(crate) fn install_image_session(
        &mut self,
        session: &ImageSession,
        timeout: Duration,
    ) -> Result<McuPacket, TransportError> {
        self.transact(Command::TlsPovImage, session.d2_payload(), timeout)
    }

    /// Read persisted object 0xbb010002.
    ///
    /// The object contains the sealed PSK consumed by
    /// PresetPskIsVaildG.
    ///
    /// This operation is read-only.
    pub(crate) fn read_sealed_psk(&mut self, timeout: Duration) -> Result<Vec<u8>, TransportError> {
        self.read_psk_object(SEALED_PSK_OBJECT, SEALED_PSK_SIZE, timeout)
    }

    /// Read persisted object 0xbb020001.
    ///
    /// This object contains SHA-256(plaintext PSK).
    ///
    /// This operation is read-only.
    pub(crate) fn read_psk_hash(
        &mut self,
        timeout: Duration,
    ) -> Result<[u8; PSK_HASH_SIZE], TransportError> {
        let bytes = self.read_psk_object(PSK_HASH_OBJECT, PSK_HASH_SIZE, timeout)?;

        Ok(bytes.try_into().expect(
            "read_psk_object returned the requested \
                 32-byte PSK hash",
        ))
    }

    /// Reproduce Geneva PresetPskReadG using command E4.
    ///
    /// Request payload:
    ///
    ///     +0x00  u32 LE  requested chunk length
    ///     +0x04  u32 LE  object offset
    ///     +0x08  u32 LE  object ID
    ///     +0x0c  u32 LE  zero/reserved
    ///
    /// Response payload:
    ///
    ///     +0x00  u8      MCU status
    ///     +0x01  u32 LE  echoed object ID
    ///     +0x05  u32 LE  returned data length
    ///     +0x09  N bytes object data
    ///
    /// Vendor code requests at most 0x100 bytes at a time and
    /// advances the offset using the ACTUAL number of bytes returned.
    ///
    /// This function performs no writes to persistent MCU state.
    pub(crate) fn read_psk_object(
        &mut self,
        object_type: u32,
        expected_length: usize,
        timeout: Duration,
    ) -> Result<Vec<u8>, TransportError> {
        if expected_length == 0 || expected_length > u32::MAX as usize {
            return Err(TransportError::InvalidPskObjectLength {
                length: expected_length,
            });
        }

        let deadline = Instant::now() + timeout;

        let mut output = Vec::with_capacity(expected_length);

        let mut offset = 0u32;

        while output.len() < expected_length {
            let now = Instant::now();

            if now >= deadline {
                return Err(TransportError::TimedOut {
                    command: Command::PskRead.as_u8(),
                    timeout,
                });
            }

            let remaining = expected_length - output.len();

            let requested = remaining.min(PSK_READ_CHUNK_SIZE);

            let request = build_psk_read_payload(object_type, offset, requested as u32);

            let packet = self.transact(Command::PskRead, &request, deadline - now)?;

            let data = parse_psk_read_payload(&packet.payload, object_type, requested, remaining)?;

            if data.is_empty() {
                return Err(TransportError::PskReadZeroLength {
                    object_type,
                    offset,
                });
            }

            output.extend_from_slice(data);

            offset = offset
                .checked_add(u32::try_from(data.len()).expect("E4 chunk length is at most 0x100"))
                .ok_or(TransportError::InvalidPskObjectLength {
                    length: expected_length,
                })?;
        }

        Ok(output)
    }

    fn send_command(&mut self, command: Command, payload: &[u8]) -> Result<(), TransportError> {
        let frame = encode_a0_single(command, payload)?;

        self.write_usb_out_block(&frame)
    }

    fn send_padded_a0_frame(&mut self, frame: &[u8]) -> Result<(), TransportError> {
        for chunk in frame.chunks(USB_OUT_BLOCK_SIZE) {
            let block = make_usb_out_block(chunk);
            self.write_usb_out_block(&block)?;
        }

        Ok(())
    }

    /// Submit one complete logical A0 packet as one backend bulk transfer.
    ///
    /// This path is currently used only for the proven 264-byte 0x90
    /// DownloadConfig transaction. USB itself splits the transfer into
    /// endpoint-sized packets; no host-side zero padding is appended.
    fn write_exact_a0_frame(&mut self, frame: &[u8]) -> Result<(), TransportError> {
        let endpoint = self.device.layout().bulk_out;

        let actual = match self.device.write_bulk(frame, WRITE_TIMEOUT) {
            Ok(actual) => actual,

            Err(error) => {
                self.record_usb_error("bulk OUT", &error);

                return Err(TransportError::Usb(error));
            }
        };

        self.trace
            .transfer(Direction::Out, endpoint, &frame[..actual])?;

        if actual != frame.len() {
            return Err(TransportError::ShortWrite {
                expected: frame.len(),
                actual,
            });
        }

        Ok(())
    }

    fn write_usb_out_block(
        &mut self,
        block: &[u8; USB_OUT_BLOCK_SIZE],
    ) -> Result<(), TransportError> {
        let endpoint = self.device.layout().bulk_out;

        let actual = match self.device.write_bulk(block, WRITE_TIMEOUT) {
            Ok(actual) => actual,

            Err(error) => {
                self.record_usb_error("bulk OUT", &error);

                return Err(TransportError::Usb(error));
            }
        };

        self.trace
            .transfer(Direction::Out, endpoint, &block[..actual])?;

        if actual != block.len() {
            return Err(TransportError::ShortWrite {
                expected: block.len(),
                actual,
            });
        }

        Ok(())
    }

    /// Reads one MCU packet.
    ///
    /// A USB timeout is normal while an event-driven command waits
    /// for activity from the sensor and is represented as Ok(None).
    fn read_packet(&mut self, timeout: Duration) -> Result<Option<McuPacket>, TransportError> {
        let endpoint = self.device.layout().bulk_in;

        let actual = match self.device.read_bulk(&mut self.read_buffer, timeout) {
            Ok(actual) => actual,

            Err(error) if error.kind() == GoodixUsbErrorKind::Timeout => {
                self.trace.timeout(endpoint)?;

                return Ok(None);
            }

            Err(error) => {
                self.record_usb_error("bulk IN", &error);

                return Err(TransportError::Usb(error));
            }
        };

        let data = &self.read_buffer[..actual];

        self.trace.transfer(Direction::In, endpoint, data)?;

        // A bulk endpoint may terminate a transfer with a zero-length packet.
        // It carries no Goodix framing and is not an MCU response; keep waiting
        // under the caller's existing transaction deadline.
        if data.is_empty() {
            return Ok(None);
        }

        Ok(Some(decode_a0_packet(data)?))
    }

    fn record_usb_error(&mut self, operation: &str, error: &GoodixUsbError) {
        if let Err(trace_error) = self.trace.usb_error(operation, error) {
            eprintln!(
                "warning: failed to record USB error in trace: \
                 {trace_error}"
            );
        }
    }
}

pub(crate) fn make_usb_out_block(chunk: &[u8]) -> [u8; USB_OUT_BLOCK_SIZE] {
    assert!(
        chunk.len() <= USB_OUT_BLOCK_SIZE,
        "USB OUT chunk exceeds one 64-byte block"
    );

    let mut block = [0u8; USB_OUT_BLOCK_SIZE];
    block[..chunk.len()].copy_from_slice(chunk);
    block
}

/// Construct the exact 16-byte PresetPskReadG E4 payload.
pub(crate) fn build_psk_read_payload(
    object_type: u32,
    offset: u32,
    requested_length: u32,
) -> [u8; 16] {
    let mut payload = [0u8; 16];

    payload[0..4].copy_from_slice(&requested_length.to_le_bytes());

    payload[4..8].copy_from_slice(&offset.to_le_bytes());

    payload[8..12].copy_from_slice(&object_type.to_le_bytes());

    // payload[12..16] intentionally remains zero.

    payload
}

/// Parse the payload returned by command E4.
///
/// The outer A0 framing, command byte, encoded length and ordinary
/// Goodix checksum have already been removed by decode_a0_packet().
///
/// Live device traffic established the exact E4 completion layout:
///
///     status
///     || echoed_object_id
///     || returned_length
///     || object_data
///
pub(crate) fn parse_psk_read_payload(
    payload: &[u8],
    expected_object_type: u32,
    requested: usize,
    remaining: usize,
) -> Result<&[u8], TransportError> {
    if payload.len() < PSK_READ_RESPONSE_HEADER_SIZE {
        return Err(TransportError::MalformedPskReadResponse {
            payload_len: payload.len(),
        });
    }

    let status = payload[0];

    if status != PSK_READ_STATUS_OK {
        return Err(TransportError::PskReadRejected { status });
    }

    let returned_object_type = u32::from_le_bytes(
        payload[1..5]
            .try_into()
            .expect("E4 object ID field is four bytes"),
    );

    if returned_object_type != expected_object_type {
        return Err(TransportError::PskReadObjectMismatch {
            expected: expected_object_type,
            actual: returned_object_type,
        });
    }

    let returned = u32::from_le_bytes(
        payload[5..9]
            .try_into()
            .expect("E4 response length field is four bytes"),
    ) as usize;

    let available = payload.len() - PSK_READ_RESPONSE_HEADER_SIZE;

    if returned > available {
        return Err(TransportError::PskReadTruncated {
            declared: returned,
            available,
        });
    }

    if returned > requested || returned > remaining {
        return Err(TransportError::PskReadReturnedTooMuch {
            requested,
            returned,
            remaining,
        });
    }

    Ok(&payload[PSK_READ_RESPONSE_HEADER_SIZE..PSK_READ_RESPONSE_HEADER_SIZE + returned])
}

/// Convert the four bytes returned by McuGetChipId into the vendor's u32.
///
/// Wire bytes from the real device:
///
/// ```text
/// 03 a8 00 25
/// ```
///
/// `SwapU16ByteOrderInPlace` produces:
///
/// ```text
/// a8 03 25 00
/// ```
///
/// which is little-endian `0x002503a8`.
fn parse_chip_id_payload(payload: &[u8]) -> Result<u32, TransportError> {
    let [b0, b1, b2, b3] = payload else {
        return Err(TransportError::MalformedChipIdResponse {
            payload_len: payload.len(),
        });
    };

    let converted = [*b1, *b0, *b3, *b2];
    Ok(u32::from_le_bytes(converted))
}

/// Parse the two-byte payload produced by a B0 message.
///
/// Geneva McuParseMsg proves this layout:
///
///     payload[0]  echoed/original command
///     payload[1]  flags
///
/// A normal B0 packet is classified as an ACK independently of payload[1].
/// Only bit 0x02 is consumed by McuParseMsg, where it becomes the separate
/// MCU-power-lost indication.
fn parse_ack(packet: &McuPacket) -> Result<Ack, TransportError> {
    let [command, flags] = packet.payload.as_slice() else {
        return Err(TransportError::MalformedAck {
            payload_len: packet.payload.len(),
        });
    };

    Ok(Ack {
        command: *command,
        flags: *flags,
        mcu_power_lost: (*flags & ACK_FLAG_MCU_POWER_LOST) != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, collections::VecDeque};

    struct MockUsbIo {
        layout: crate::device::UsbLayout,
        writes: RefCell<Vec<Vec<u8>>>,
        reads: RefCell<VecDeque<Result<Vec<u8>, GoodixUsbError>>>,
    }

    impl MockUsbIo {
        fn new(reads: impl IntoIterator<Item = Result<Vec<u8>, GoodixUsbError>>) -> Self {
            Self {
                layout: crate::device::UsbLayout {
                    interface: 0,
                    bulk_in: 0x83,
                    bulk_out: 0x01,
                    max_packet_size: 64,
                },
                writes: RefCell::new(Vec::new()),
                reads: RefCell::new(reads.into_iter().collect()),
            }
        }

        fn writes(&self) -> Vec<Vec<u8>> {
            self.writes.borrow().clone()
        }
    }

    impl GoodixUsbIo for MockUsbIo {
        fn layout(&self) -> crate::device::UsbLayout {
            self.layout
        }

        fn write_bulk(&self, data: &[u8], _timeout: Duration) -> Result<usize, GoodixUsbError> {
            self.writes.borrow_mut().push(data.to_vec());
            Ok(data.len())
        }

        fn read_bulk(
            &self,
            buffer: &mut [u8],
            _timeout: Duration,
        ) -> Result<usize, GoodixUsbError> {
            let next = self.reads.borrow_mut().pop_front().ok_or_else(|| {
                GoodixUsbError::new(GoodixUsbErrorKind::Timeout, "mock read queue exhausted")
            })?;
            let data = next?;
            buffer[..data.len()].copy_from_slice(&data);
            Ok(data.len())
        }
    }

    fn encoded_reply(command: Command, payload: &[u8]) -> Vec<u8> {
        encode_a0_packet(command, payload).unwrap()
    }

    #[test]
    fn backend_neutral_transport_reads_version_and_ack_flags() {
        let backend = MockUsbIo::new([
            Ok(encoded_reply(
                Command::Ack,
                &[Command::GetVersion.as_u8(), 0x03],
            )),
            Ok(encoded_reply(
                Command::GetVersion,
                b"GFUSB_GM168SEC_APP_15045\0",
            )),
        ]);
        let mut transport = GoodixTransport::new(&backend, TraceLogger::quiet());

        let (version, ack) = transport
            .get_version_with_ack(Duration::from_secs(1))
            .unwrap();

        assert_eq!(version, "GFUSB_GM168SEC_APP_15045");
        assert!(ack.mcu_power_lost);
        assert_eq!(backend.writes().len(), 1);
        assert_eq!(backend.writes()[0].len(), USB_OUT_BLOCK_SIZE);
    }

    #[test]
    fn backend_neutral_timeout_is_a_normal_wait_slice() {
        let timeout = GoodixUsbError::new(GoodixUsbErrorKind::Timeout, "mock timeout");
        let backend = MockUsbIo::new([
            Err(timeout),
            Ok(encoded_reply(
                Command::Ack,
                &[Command::GetVersion.as_u8(), 0x01],
            )),
            Ok(encoded_reply(
                Command::GetVersion,
                b"GFUSB_GM168SEC_APP_15045\0",
            )),
        ]);
        let mut transport = GoodixTransport::new(&backend, TraceLogger::quiet());

        let version = transport.get_version(Duration::from_secs(1)).unwrap();

        assert_eq!(version, "GFUSB_GM168SEC_APP_15045");
    }

    #[test]
    fn backend_neutral_zero_length_packet_is_ignored() {
        let backend = MockUsbIo::new([
            Ok(Vec::new()),
            Ok(encoded_reply(
                Command::Ack,
                &[Command::GetVersion.as_u8(), 0x01],
            )),
            Ok(encoded_reply(
                Command::GetVersion,
                b"GFUSB_GM168SEC_APP_15045\0",
            )),
        ]);
        let mut transport = GoodixTransport::new(&backend, TraceLogger::quiet());

        let version = transport.get_version(Duration::from_secs(1)).unwrap();

        assert_eq!(version, "GFUSB_GM168SEC_APP_15045");
    }

    #[test]
    fn backend_neutral_firmware_write_preserves_64_byte_physical_blocks() {
        let backend = MockUsbIo::new([
            Ok(encoded_reply(
                Command::Ack,
                &[Command::FirmwareWrite.as_u8(), 0x01],
            )),
            Ok(encoded_reply(Command::FirmwareWrite, &[0x00])),
        ]);
        let mut transport = GoodixTransport::new(&backend, TraceLogger::quiet());
        let payload = vec![0u8; 12 + 0x100];

        let completion = transport
            .transact_firmware(Command::FirmwareWrite, &payload, Duration::from_secs(1))
            .unwrap();

        assert_eq!(completion.payload, vec![0x00]);
        let writes = backend.writes();
        assert_eq!(writes.len(), 5);
        assert!(writes.iter().all(|block| block.len() == USB_OUT_BLOCK_SIZE));
    }

    #[test]
    fn b0_01_is_ack_without_power_lost() {
        let packet = McuPacket {
            command: Command::Ack.as_u8(),
            payload: vec![Command::GetVersion.as_u8(), 0x01],
            trailer: Some(0x4e),
        };

        let ack = parse_ack(&packet).unwrap();

        assert_eq!(ack.command, Command::GetVersion.as_u8());
        assert_eq!(ack.flags, 0x01);
        assert!(!ack.mcu_power_lost);
    }

    #[test]
    fn b0_03_is_ack_with_power_lost_flag() {
        let packet = McuPacket {
            command: Command::Ack.as_u8(),
            payload: vec![Command::TlsPovImage.as_u8(), 0x03],
            trailer: Some(0x22),
        };

        let ack = parse_ack(&packet).unwrap();

        assert_eq!(ack.command, Command::TlsPovImage.as_u8());
        assert_eq!(ack.flags, 0x03);
        assert!(ack.mcu_power_lost);
    }

    #[test]
    fn transaction_preserves_ack_and_completion() {
        let ack = Ack {
            command: Command::GetVersion.as_u8(),
            flags: 0x03,
            mcu_power_lost: true,
        };

        let completion = McuPacket {
            command: Command::GetVersion.as_u8(),
            payload: b"GFUSB_GM168SEC_APP_15045\0".to_vec(),
            trailer: Some(0x66),
        };

        let transaction = Transaction {
            ack,
            completion: completion.clone(),
        };

        assert_eq!(transaction.ack, ack);
        assert!(transaction.ack.mcu_power_lost);
        assert_eq!(transaction.completion, completion);
    }

    #[test]
    fn b0_parser_ignores_uninterpreted_flag_bits_like_vendor_mcu_parse_msg() {
        let packet = McuPacket {
            command: Command::Ack.as_u8(),
            payload: vec![Command::FdtDown.as_u8(), 0xfd],
            trailer: Some(0x00),
        };

        let ack = parse_ack(&packet).unwrap();

        assert_eq!(ack.command, Command::FdtDown.as_u8());
        assert_eq!(ack.flags, 0xfd);
        assert!(!ack.mcu_power_lost);
    }

    #[test]
    fn b0_parser_detects_power_lost_bit_independently_of_other_bits() {
        let packet = McuPacket {
            command: Command::Ack.as_u8(),
            payload: vec![Command::FdtDown.as_u8(), 0xfe],
            trailer: Some(0x00),
        };

        let ack = parse_ack(&packet).unwrap();

        assert_eq!(ack.command, Command::FdtDown.as_u8());
        assert_eq!(ack.flags, 0xfe);
        assert!(ack.mcu_power_lost);
    }

    #[test]
    fn read_otp_frame_matches_live_capture() {
        let frame = encode_a0_single(Command::ReadOtp, &READ_OTP_PAYLOAD).unwrap();

        assert_eq!(
            &frame[..10],
            &[0xa0, 0x06, 0x00, 0xa6, 0xa6, 0x03, 0x00, 0x40, 0x00, 0xc1]
        );

        assert!(frame[10..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn download_config_logical_packet_is_264_bytes() {
        let config = [0u8; 0x100];

        let frame = encode_a0_packet(Command::DownloadConfig, &config).unwrap();

        assert_eq!(frame.len(), 264);
        assert_eq!(&frame[..7], &[0xa0, 0x04, 0x01, 0xa5, 0x90, 0x01, 0x01]);
    }

    #[test]
    fn sealed_psk_request_matches_vendor_capture() {
        let payload = build_psk_read_payload(SEALED_PSK_OBJECT, 0, SEALED_PSK_SIZE as u32);

        assert_eq!(
            payload,
            [
                0x66, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0xbb, 0x00, 0x00,
                0x00, 0x00,
            ]
        );
    }

    #[test]
    fn psk_hash_request_matches_vendor_capture() {
        let payload = build_psk_read_payload(PSK_HASH_OBJECT, 0, PSK_HASH_SIZE as u32);

        assert_eq!(
            payload,
            [
                0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0xbb, 0x00, 0x00,
                0x00, 0x00,
            ]
        );
    }

    #[test]
    fn psk_read_payload_parser_extracts_object_bytes() {
        let mut payload = vec![
            0x00, // echoed object ID = 0xbb010002
            0x02, 0x00, 0x01, 0xbb, // returned length = 4
            0x04, 0x00, 0x00, 0x00,
        ];

        payload.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);

        let data = parse_psk_read_payload(&payload, SEALED_PSK_OBJECT, 4, 4).unwrap();

        assert_eq!(data, [0x11, 0x22, 0x33, 0x44]);
    }

    #[test]
    fn psk_read_payload_parser_rejects_mcu_error() {
        let payload = [0x03, 0x02, 0x00, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x00];

        assert!(matches!(
            parse_psk_read_payload(&payload, SEALED_PSK_OBJECT, 32, 32,),
            Err(TransportError::PskReadRejected { status: 0x03 })
        ));
    }

    #[test]
    fn psk_read_payload_parser_rejects_object_mismatch() {
        let payload = [
            0x00, // MCU echoed PSK_HASH_OBJECT instead.
            0x01, 0x00, 0x02, 0xbb, 0x00, 0x00, 0x00, 0x00,
        ];

        assert!(matches!(
            parse_psk_read_payload(&payload, SEALED_PSK_OBJECT, 32, 32,),
            Err(TransportError::PskReadObjectMismatch {
                expected: SEALED_PSK_OBJECT,
                actual: PSK_HASH_OBJECT,
            })
        ));
    }

    #[test]
    fn psk_read_payload_parser_rejects_truncation() {
        let payload = [
            0x00, 0x02, 0x00, 0x01, 0xbb, // declares four bytes
            0x04, 0x00, 0x00, 0x00, // only two available
            0x11, 0x22,
        ];

        assert!(matches!(
            parse_psk_read_payload(&payload, SEALED_PSK_OBJECT, 4, 4,),
            Err(TransportError::PskReadTruncated {
                declared: 4,
                available: 2,
            })
        ));
    }

    #[test]
    fn psk_read_payload_parser_rejects_more_than_requested() {
        let payload = [
            0x00, 0x02, 0x00, 0x01, 0xbb, // returned length = 4
            0x04, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44,
        ];

        assert!(matches!(
            parse_psk_read_payload(&payload, SEALED_PSK_OBJECT, 2, 4,),
            Err(TransportError::PskReadReturnedTooMuch {
                requested: 2,
                returned: 4,
                remaining: 4,
            })
        ));
    }

    #[test]
    fn reset_fingerprint_frame_matches_vendor_capture() {
        let frame = encode_a0_single(Command::ResetChip, &RESET_FINGERPRINT_PAYLOAD).unwrap();

        assert_eq!(
            &frame[..10],
            &[0xa0, 0x06, 0x00, 0xa6, 0xa2, 0x03, 0x00, 0x05, 0x14, 0xec]
        );
        assert!(frame[10..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn get_chip_id_frame_matches_vendor_capture() {
        let frame = encode_a0_single(Command::ReadRegister, &GET_CHIP_ID_PAYLOAD).unwrap();

        assert_eq!(
            &frame[..13],
            &[
                0xa0, 0x09, 0x00, 0xa9, 0x82, 0x06, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x1e,
            ]
        );
        assert!(frame[13..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn chip_id_parser_matches_live_gf3258_wn2_response() {
        let chip_id = parse_chip_id_payload(&[0x03, 0xa8, 0x00, 0x25]).unwrap();

        assert_eq!(chip_id, EXPECTED_CHIP_ID);
        assert_eq!(chip_id >> 8, 0x2503);
    }

    #[test]
    fn chip_id_parser_rejects_wrong_payload_length() {
        assert!(matches!(
            parse_chip_id_payload(&[0x03, 0xa8, 0x00]),
            Err(TransportError::MalformedChipIdResponse { payload_len: 3 })
        ));
    }

    #[test]
    fn reset_mcu_frame_matches_vendor_capture() {
        let frame = encode_a0_single(Command::ResetChip, &RESET_MCU_PAYLOAD).unwrap();

        assert_eq!(
            &frame[..10],
            &[0xa0, 0x06, 0x00, 0xa6, 0xa2, 0x03, 0x00, 0x02, 0x32, 0xd1]
        );
        assert!(frame[10..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn firmware_check_frame_matches_vendor_capture() {
        let tag = [
            0x55, 0xc3, 0xfd, 0x0c, 0xa4, 0xab, 0x6c, 0xb5, 0xaf, 0xaa, 0x29, 0x48, 0x1a, 0xfd,
            0xb1, 0x96, 0x5b, 0x65, 0xd4, 0x8c, 0x0c, 0xd6, 0xc2, 0xff, 0x67, 0xb6, 0xa3, 0x5f,
            0x55, 0x07, 0x50, 0x7e,
        ];

        let frame = encode_a0_packet(Command::FirmwareCheck, &tag).unwrap();

        assert_eq!(
            frame.as_slice(),
            &[
                0xa0, 0x24, 0x00, 0xc4, 0xf4, 0x21, 0x00, 0x55, 0xc3, 0xfd, 0x0c, 0xa4, 0xab, 0x6c,
                0xb5, 0xaf, 0xaa, 0x29, 0x48, 0x1a, 0xfd, 0xb1, 0x96, 0x5b, 0x65, 0xd4, 0x8c, 0x0c,
                0xd6, 0xc2, 0xff, 0x67, 0xb6, 0xa3, 0x5f, 0x55, 0x07, 0x50, 0x7e, 0xd0,
            ]
        );
    }

    #[test]
    fn firmware_write_frame_spans_five_usb_blocks() {
        let payload = vec![0u8; 12 + 0x100];
        let frame = encode_a0_packet(Command::FirmwareWrite, &payload).unwrap();

        assert_eq!(frame.len(), 276);
        assert_eq!(&frame[..7], &[0xa0, 0x10, 0x01, 0xb1, 0xf0, 0x0d, 0x01]);
        assert_eq!(frame.chunks(USB_OUT_BLOCK_SIZE).count(), 5);

        let final_chunk = frame.chunks(USB_OUT_BLOCK_SIZE).last().unwrap();
        assert_eq!(final_chunk.len(), 20);

        let final_block = make_usb_out_block(final_chunk);
        assert_eq!(&final_block[..20], final_chunk);
        assert!(final_block[20..].iter().all(|byte| *byte == 0));
    }
}
