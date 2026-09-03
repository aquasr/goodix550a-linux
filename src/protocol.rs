//! Goodix MCU packet encoding and A0 USB framing.

use std::{error::Error, fmt};

const A0_MARKER: u8 = 0xA0;
const CHECKSUM_TARGET: u8 = 0xAA;
const SPECIAL_CHECK_BYTE: u8 = 0x88;

const OUTER_HEADER_LEN: usize = 4;
const MCU_HEADER_LEN: usize = 3;
const MCU_TRAILER_LEN: usize = 1;

const MIN_PACKET_LEN: usize = OUTER_HEADER_LEN + MCU_HEADER_LEN + MCU_TRAILER_LEN;

const USB_OUT_FRAME_SIZE: usize = 64;
const MAX_SINGLE_FRAME_INNER_LEN: usize = USB_OUT_FRAME_SIZE - OUTER_HEADER_LEN;

#[allow(dead_code)]
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Command {
    Nop = 0x00,

    GetImage = 0x20,

    FdtDown = 0x32,
    FdtUp = 0x34,
    FdtManual = 0x36,

    Sleep = 0x60,
    Idle = 0x70,

    WriteRegister = 0x80,
    ReadRegister = 0x82,

    DownloadConfig = 0x90,

    ResetChip = 0xA2,
    EraseApp = 0xA4,
    ReadOtp = 0xA6,
    GetVersion = 0xA8,

    Ack = 0xB0,

    DriverState = 0xC4,

    TlsConnection = 0xD0,
    TlsPovImage = 0xD2,

    PskWrite = 0xE0,
    PskRead = 0xE4,

    FirmwareWrite = 0xF0,
    FirmwareCheck = 0xF4,
}

impl Command {
    pub(crate) const fn as_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct McuPacket {
    pub(crate) command: u8,
    pub(crate) payload: Vec<u8>,

    /// Ordinary MCU packets carry a one-byte trailer/checksum.
    ///
    /// Incoming GetImage (0x20) responses are different: their encoded
    /// length is the complete protected-image payload length and there is
    /// no ordinary MCU trailer byte.
    #[allow(dead_code)]
    pub(crate) trailer: Option<u8>,
}

impl McuPacket {
    pub(crate) fn is_command(&self, command: Command) -> bool {
        self.command == command.as_u8()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProtocolError {
    PayloadTooLarge { length: usize },

    FrameTooLarge { length: usize, maximum: usize },

    PacketTooShort { actual: usize, minimum: usize },

    UnsupportedOuterMarker { marker: u8 },

    OuterChecksumMismatch { expected: u8, actual: u8 },

    OuterLengthMismatch { declared: usize, actual: usize },

    InnerPacketTooShort { actual: usize },

    InvalidEncodedLength,

    InnerLengthMismatch { declared: usize, actual: usize },

    InnerChecksumMismatch { expected: u8, actual: u8 },
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadTooLarge { length } => {
                write!(f, "MCU payload is too large: {length} bytes")
            }

            Self::FrameTooLarge { length, maximum } => {
                write!(
                    f,
                    "MCU packet is too large for a single USB frame: \
                     {length} bytes, maximum {maximum}"
                )
            }

            Self::PacketTooShort { actual, minimum } => {
                write!(
                    f,
                    "A0 packet is too short: {actual} bytes, \
                     minimum {minimum}"
                )
            }

            Self::UnsupportedOuterMarker { marker } => {
                write!(f, "unsupported outer packet marker 0x{marker:02x}")
            }

            Self::OuterChecksumMismatch { expected, actual } => {
                write!(
                    f,
                    "outer checksum mismatch: expected 0x{expected:02x}, \
                     received 0x{actual:02x}"
                )
            }

            Self::OuterLengthMismatch { declared, actual } => {
                write!(
                    f,
                    "outer length mismatch: declared {declared} bytes, \
                     received {actual}"
                )
            }

            Self::InnerPacketTooShort { actual } => {
                write!(f, "inner MCU packet is too short: {actual} bytes")
            }

            Self::InvalidEncodedLength => f.write_str("inner MCU encoded length is zero"),

            Self::InnerLengthMismatch { declared, actual } => {
                write!(
                    f,
                    "inner MCU length mismatch: declared {declared} bytes, \
                     received {actual}"
                )
            }

            Self::InnerChecksumMismatch { expected, actual } => {
                write!(
                    f,
                    "inner MCU checksum mismatch: expected 0x{expected:02x}, \
                     received 0x{actual:02x}"
                )
            }
        }
    }
}

impl Error for ProtocolError {}

/// Encode one complete logical Goodix A0 packet.
///
/// This function performs protocol framing only. It does not impose the
/// physical 64-byte USB OUT transfer size used by Geneva McuWriteRaw.
/// Large firmware commands such as F0 therefore return a Vec spanning
/// multiple physical USB blocks.
pub(crate) fn encode_a0_packet(command: Command, payload: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let inner = encode_mcu_packet(command, payload)?;

    let inner_len = u16::try_from(inner.len()).map_err(|_| ProtocolError::FrameTooLarge {
        length: inner.len(),
        maximum: usize::from(u16::MAX),
    })?;

    let [len_lo, len_hi] = inner_len.to_le_bytes();

    let mut frame = Vec::with_capacity(OUTER_HEADER_LEN + inner.len());

    frame.push(A0_MARKER);
    frame.push(len_lo);
    frame.push(len_hi);
    frame.push(outer_checksum(len_lo, len_hi));
    frame.extend_from_slice(&inner);

    Ok(frame)
}

/// Encode an A0 packet that must fit in exactly one physical 64-byte USB
/// OUT transfer, padding unused bytes with zero as the vendor driver does.
pub(crate) fn encode_a0_single(
    command: Command,
    payload: &[u8],
) -> Result<[u8; USB_OUT_FRAME_SIZE], ProtocolError> {
    let logical = encode_a0_packet(command, payload)?;
    let inner_len = logical.len() - OUTER_HEADER_LEN;

    if inner_len > MAX_SINGLE_FRAME_INNER_LEN {
        return Err(ProtocolError::FrameTooLarge {
            length: inner_len,
            maximum: MAX_SINGLE_FRAME_INNER_LEN,
        });
    }

    let mut frame = [0; USB_OUT_FRAME_SIZE];
    frame[..logical.len()].copy_from_slice(&logical);

    Ok(frame)
}

pub(crate) fn decode_a0_packet(data: &[u8]) -> Result<McuPacket, ProtocolError> {
    if data.len() < MIN_PACKET_LEN {
        return Err(ProtocolError::PacketTooShort {
            actual: data.len(),
            minimum: MIN_PACKET_LEN,
        });
    }

    if data[0] != A0_MARKER {
        return Err(ProtocolError::UnsupportedOuterMarker { marker: data[0] });
    }

    let expected_outer_checksum = outer_checksum(data[1], data[2]);

    if data[3] != expected_outer_checksum {
        return Err(ProtocolError::OuterChecksumMismatch {
            expected: expected_outer_checksum,
            actual: data[3],
        });
    }

    let outer_len = usize::from(u16::from_le_bytes([data[1], data[2]]));
    let actual_outer_len = data.len() - OUTER_HEADER_LEN;

    if outer_len != actual_outer_len {
        return Err(ProtocolError::OuterLengthMismatch {
            declared: outer_len,
            actual: actual_outer_len,
        });
    }

    decode_mcu_packet(&data[OUTER_HEADER_LEN..])
}

fn encode_mcu_packet(command: Command, payload: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let encoded_len = payload
        .len()
        .checked_add(MCU_TRAILER_LEN)
        .and_then(|length| u16::try_from(length).ok())
        .ok_or(ProtocolError::PayloadTooLarge {
            length: payload.len(),
        })?;

    let command = command.as_u8();
    let checksum = checksum_aa(command, encoded_len, payload);

    let mut packet = Vec::with_capacity(MCU_HEADER_LEN + usize::from(encoded_len));

    packet.push(command);
    packet.extend_from_slice(&encoded_len.to_le_bytes());
    packet.extend_from_slice(payload);
    packet.push(checksum);

    Ok(packet)
}

fn decode_mcu_packet(inner: &[u8]) -> Result<McuPacket, ProtocolError> {
    if inner.len() < MCU_HEADER_LEN + MCU_TRAILER_LEN {
        return Err(ProtocolError::InnerPacketTooShort {
            actual: inner.len(),
        });
    }

    let command = inner[0];
    let encoded_len = u16::from_le_bytes([inner[1], inner[2]]);

    if encoded_len == 0 {
        return Err(ProtocolError::InvalidEncodedLength);
    }

    let expected_inner_len = MCU_HEADER_LEN + usize::from(encoded_len);

    if inner.len() != expected_inner_len {
        return Err(ProtocolError::InnerLengthMismatch {
            declared: expected_inner_len,
            actual: inner.len(),
        });
    }

    /*
     * Incoming GetImage (0x20) responses do not use the ordinary MCU
     * trailer/checksum byte.
     *
     * Proven live packet:
     *
     *   outer length  = 0x294c = 10572
     *   command       = 0x20
     *   encoded_len   = 0x2949 = 10569
     *
     *   3-byte MCU header + 10569-byte protected image = 10572
     *
     * The complete 10569 bytes after the MCU header are:
     *
     *   5-byte image header
     *   10560-byte AES ciphertext
     *   4-byte image CRC
     *
     * There is no additional ordinary one-byte MCU trailer to remove.
     */
    if command == Command::GetImage.as_u8() {
        let payload = &inner[MCU_HEADER_LEN..];

        return Ok(McuPacket {
            command,
            payload: payload.to_vec(),
            trailer: None,
        });
    }

    let payload_end = inner.len() - MCU_TRAILER_LEN;
    let payload = &inner[MCU_HEADER_LEN..payload_end];
    let trailer = inner[payload_end];

    validate_trailer(command, encoded_len, payload, trailer)?;

    Ok(McuPacket {
        command,
        payload: payload.to_vec(),
        trailer: Some(trailer),
    })
}

fn validate_trailer(
    command: u8,
    encoded_len: u16,
    payload: &[u8],
    trailer: u8,
) -> Result<(), ProtocolError> {
    let expected = checksum_aa(command, encoded_len, payload);

    if trailer == expected || trailer == SPECIAL_CHECK_BYTE {
        return Ok(());
    }

    Err(ProtocolError::InnerChecksumMismatch {
        expected,
        actual: trailer,
    })
}

fn checksum_aa(command: u8, encoded_len: u16, payload: &[u8]) -> u8 {
    let [len_lo, len_hi] = encoded_len.to_le_bytes();

    let sum = payload.iter().fold(
        command.wrapping_add(len_lo).wrapping_add(len_hi),
        |sum, byte| sum.wrapping_add(*byte),
    );

    CHECKSUM_TARGET.wrapping_sub(sum)
}

fn outer_checksum(len_lo: u8, len_hi: u8) -> u8 {
    A0_MARKER.wrapping_add(len_lo).wrapping_add(len_hi)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GET_VERSION_REQUEST: [u8; 10] =
        [0xA0, 0x06, 0x00, 0xA6, 0xA8, 0x03, 0x00, 0x00, 0x00, 0xFF];

    const GET_VERSION_ACK: [u8; 10] = [0xA0, 0x06, 0x00, 0xA6, 0xB0, 0x03, 0x00, 0xA8, 0x01, 0x4E];

    #[test]
    fn encodes_captured_get_version_request() {
        let frame = encode_a0_single(Command::GetVersion, &[0, 0]).unwrap();

        assert_eq!(&frame[..GET_VERSION_REQUEST.len()], &GET_VERSION_REQUEST);

        assert!(
            frame[GET_VERSION_REQUEST.len()..]
                .iter()
                .all(|byte| *byte == 0)
        );
    }

    #[test]
    fn decodes_captured_get_version_ack() {
        let packet = decode_a0_packet(&GET_VERSION_ACK).unwrap();

        assert!(packet.is_command(Command::Ack));

        assert_eq!(packet.payload, [Command::GetVersion.as_u8(), 0x01]);

        assert_eq!(packet.trailer, Some(0x4E));
    }

    #[test]
    fn decodes_captured_get_version_response() {
        let bytes = decode_hex(
            "a01d00bd\
             a81a00\
             47465553425f474d3136385345435f4150505f313530343500\
             66",
        );

        let packet = decode_a0_packet(&bytes).unwrap();

        assert!(packet.is_command(Command::GetVersion));
        assert_eq!(packet.trailer, Some(0x66));

        let version = packet.payload.strip_suffix(&[0]).unwrap();

        assert_eq!(
            std::str::from_utf8(version).unwrap(),
            "GFUSB_GM168SEC_APP_15045"
        );
    }

    #[test]
    fn logical_get_version_packet_is_unpadded() {
        let packet = encode_a0_packet(Command::GetVersion, &[0, 0]).unwrap();

        assert_eq!(packet, GET_VERSION_REQUEST);
    }

    #[test]
    fn encodes_captured_firmware_check_packet() {
        let tag = [
            0x55, 0xc3, 0xfd, 0x0c, 0xa4, 0xab, 0x6c, 0xb5, 0xaf, 0xaa, 0x29, 0x48, 0x1a, 0xfd,
            0xb1, 0x96, 0x5b, 0x65, 0xd4, 0x8c, 0x0c, 0xd6, 0xc2, 0xff, 0x67, 0xb6, 0xa3, 0x5f,
            0x55, 0x07, 0x50, 0x7e,
        ];

        let packet = encode_a0_packet(Command::FirmwareCheck, &tag).unwrap();

        assert_eq!(
            packet,
            [
                0xa0, 0x24, 0x00, 0xc4, 0xf4, 0x21, 0x00, 0x55, 0xc3, 0xfd, 0x0c, 0xa4, 0xab, 0x6c,
                0xb5, 0xaf, 0xaa, 0x29, 0x48, 0x1a, 0xfd, 0xb1, 0x96, 0x5b, 0x65, 0xd4, 0x8c, 0x0c,
                0xd6, 0xc2, 0xff, 0x67, 0xb6, 0xa3, 0x5f, 0x55, 0x07, 0x50, 0x7e, 0xd0,
            ]
        );
    }

    #[test]
    fn firmware_write_logical_packet_can_span_usb_blocks() {
        // F0 payload = 12-byte firmware chunk header + 0x100 bytes data.
        let payload = vec![0u8; 12 + 0x100];
        let packet = encode_a0_packet(Command::FirmwareWrite, &payload).unwrap();

        assert_eq!(packet.len(), 276);
        assert_eq!(&packet[..7], &[0xa0, 0x10, 0x01, 0xb1, 0xf0, 0x0d, 0x01]);
        assert!(packet.len() > USB_OUT_FRAME_SIZE);
    }

    #[test]
    fn single_frame_encoder_rejects_multi_block_firmware_write() {
        let payload = vec![0u8; 12 + 0x100];

        assert!(matches!(
            encode_a0_single(Command::FirmwareWrite, &payload),
            Err(ProtocolError::FrameTooLarge { .. })
        ));
    }

    #[test]
    fn checksum_completes_packet_sum_to_aa() {
        let payload = [0x00, 0x00];
        let encoded_len = 3_u16;
        let command = Command::GetVersion.as_u8();

        let checksum = checksum_aa(command, encoded_len, &payload);
        let [len_lo, len_hi] = encoded_len.to_le_bytes();

        let sum = payload.iter().fold(
            command.wrapping_add(len_lo).wrapping_add(len_hi),
            |sum, byte| sum.wrapping_add(*byte),
        );

        assert_eq!(sum.wrapping_add(checksum), CHECKSUM_TARGET);
    }

    #[test]
    fn rejects_invalid_outer_checksum() {
        let mut bytes = GET_VERSION_ACK;

        bytes[3] ^= 0x01;

        assert!(matches!(
            decode_a0_packet(&bytes),
            Err(ProtocolError::OuterChecksumMismatch { .. })
        ));
    }

    #[test]
    fn rejects_invalid_inner_checksum() {
        let mut bytes = GET_VERSION_ACK;

        bytes[9] ^= 0x01;

        assert!(matches!(
            decode_a0_packet(&bytes),
            Err(ProtocolError::InnerChecksumMismatch { .. })
        ));
    }

    #[test]
    fn image_response_has_no_mcu_trailer() {
        /*
         * For an incoming 0x20 response, encoded_len is the complete payload
         * length. There is no ordinary MCU checksum/trailer after it.
         */
        let bytes = [0xA0, 0x06, 0x00, 0xA6, 0x20, 0x03, 0x00, 0x11, 0x22, 0x33];

        let packet = decode_a0_packet(&bytes).unwrap();

        assert!(packet.is_command(Command::GetImage));
        assert_eq!(packet.payload, [0x11, 0x22, 0x33]);
        assert_eq!(packet.trailer, None);
    }

    #[test]
    fn image_response_keeps_final_payload_byte() {
        /*
         * Regression test for the cold-capture bug: the old decoder treated
         * the final image byte as a trailer and returned encoded_len - 1
         * payload bytes.
         */
        let bytes = [
            0xA0, 0x08, 0x00, 0xA8, 0x20, 0x05, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        ];

        let packet = decode_a0_packet(&bytes).unwrap();

        assert!(packet.is_command(Command::GetImage));
        assert_eq!(packet.payload.len(), 5);
        assert_eq!(packet.payload, [0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(packet.trailer, None);
    }

    #[test]
    fn rejects_trailing_bytes_after_outer_packet() {
        let mut bytes = GET_VERSION_ACK.to_vec();

        bytes.push(0x00);

        assert!(matches!(
            decode_a0_packet(&bytes),
            Err(ProtocolError::OuterLengthMismatch { .. })
        ));
    }

    fn decode_hex(input: &str) -> Vec<u8> {
        let compact: String = input.chars().filter(|c| !c.is_whitespace()).collect();

        assert_eq!(compact.len() % 2, 0);

        (0..compact.len())
            .step_by(2)
            .map(|offset| u8::from_str_radix(&compact[offset..offset + 2], 16).unwrap())
            .collect()
    }
}
