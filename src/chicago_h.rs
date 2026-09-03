use std::{error::Error, fmt, time::Duration};

use crate::{
    device::GoodixUsbIo,
    protocol::{Command, McuPacket},
    transport::{GoodixTransport, OTP_LEN, TransportError},
};

const CONFIG_LEN: usize = 0x100;
const CONFIG_SUM_TARGET: u16 = 0x5a5b;

const EXPECTED_BASE_CHECKSUM: u16 = 0x0e53;

const IMAGE_TCODE_KEY: u16 = 0x005c;
const FDT_DELTA_KEY: u16 = 0x0082;
const FDT_OFFSET_KEY: u16 = 0x0056;

/// Exact 0x100-byte base configuration constructed by ChicagoH GetChipConfig.
///
/// The vendor builds this as 32 qwords and stores them little-endian.
/// The final hard-coded qword initially contains 0xffbc in the last u16,
/// but GetChipConfig immediately replaces that word with the computed
/// configuration checksum before applying OTP-derived patches.
const CHICAGO_H_BASE_QWORDS: [u64; 32] = [
    0xc92c9d2c716011b0,
    0xfd00fd00fd18e51c,
    0x0400ca800100ba03,
    0x000086b315008400,
    0x00008aba000088c4,
    0x00008eaa00008cb2,
    0xb10092bbbb0090c1,
    0x000096a8000094b1,
    0x00009a00000098b6,
    0x0000d4000000d200,
    0x0000d8000000d600,
    0x0000d00501005000,
    0x7800720000007000,
    0x1000201234007456,
    0x0100220402012a40,
    0x0100800032002420,
    0x2400560080005c00,
    0x0c00320203005820,
    0x00007c0003006602,
    0x82012a1580008258,
    0x1400242001002203,
    0x00005c0001008000,
    0x0300582004005601,
    0x030066020c003202,
    0x8000825800007c00,
    0x80005c0008012a15,
    0x0400620110005400,
    0x0300660019006403,
    0x08012a5801007c00,
    0x0800520100005c00,
    0x0300660100005400,
    0xffbc005801007c00,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChicagoHCalibration {
    pub(crate) tcode: u16,
    pub(crate) diff: u16,
    pub(crate) fdt_offset: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChicagoHConfig {
    pub(crate) bytes: [u8; CONFIG_LEN],
    pub(crate) calibration: ChicagoHCalibration,
    pub(crate) checksum: u16,
}

#[derive(Debug)]
pub(crate) enum ChicagoHError {
    Transport(TransportError),

    OtpCrcMismatch {
        section: &'static str,
        calculated: u8,
        stored: u8,
    },

    InvalidTcodeDiffCopies {
        source: u8,
        redundant: u8,
    },

    InvalidFdtOffsetEncoding {
        encoded: u8,
    },

    ArithmeticOverflow,

    ConfigKeyMissing {
        key: u16,
        start: usize,
        end: usize,
    },

    UnexpectedBaseChecksum {
        expected: u16,
        actual: u16,
    },

    ConfigChecksumInvariant {
        expected: u16,
        actual: u16,
    },

    UnexpectedDownloadCompletion {
        command: u8,
        payload: Vec<u8>,
    },
}

impl fmt::Display for ChicagoHError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => {
                write!(
                    f,
                    "Goodix transport error during ChicagoH initialization: {error}"
                )
            }

            Self::OtpCrcMismatch {
                section,
                calculated,
                stored,
            } => {
                write!(
                    f,
                    "ChicagoH {section} OTP CRC mismatch: calculated \
                     0x{calculated:02x}, stored 0x{stored:02x}"
                )
            }

            Self::InvalidTcodeDiffCopies { source, redundant } => {
                write!(
                    f,
                    "ChicagoH OTP T-code/diff copies are invalid: \
                     OTP[0x2a]=0x{source:02x}, OTP[0x2d]=0x{redundant:02x}"
                )
            }

            Self::InvalidFdtOffsetEncoding { encoded } => {
                write!(
                    f,
                    "ChicagoH OTP FDT-offset encoding 0x{encoded:02x} has no majority"
                )
            }

            Self::ArithmeticOverflow => f.write_str("ChicagoH calibration arithmetic overflow"),

            Self::ConfigKeyMissing { key, start, end } => {
                write!(
                    f,
                    "ChicagoH configuration key 0x{key:04x} not found in \
                     section 0x{start:02x}..0x{end:02x}"
                )
            }

            Self::UnexpectedBaseChecksum { expected, actual } => {
                write!(
                    f,
                    "ChicagoH base configuration checksum mismatch: expected \
                     0x{expected:04x}, calculated 0x{actual:04x}"
                )
            }

            Self::ConfigChecksumInvariant { expected, actual } => {
                write!(
                    f,
                    "ChicagoH configuration u16 sum mismatch: expected \
                     0x{expected:04x}, calculated 0x{actual:04x}"
                )
            }

            Self::UnexpectedDownloadCompletion { command, payload } => {
                write!(
                    f,
                    "unexpected 0x90 DownloadConfig completion: command \
                     0x{command:02x}, payload {:02x?}; expected command \
                     0x90 with payload [01, 00]",
                    payload
                )
            }
        }
    }
}

impl Error for ChicagoHError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            _ => None,
        }
    }
}

impl From<TransportError> for ChicagoHError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

/// Reproduce the complete volatile GF3258 WN2 / ChicagoH cold configuration:
///
/// ```text
/// A6 GetOtp
///   -> validate CP / FT / MT CRCs
///   -> derive T-code / diff / FDT offset
///   -> generate 0x100-byte ChicagoH config
///   -> verify config checksum invariant
///   -> 0x90 DownloadConfig
///   -> require completion payload [01 00]
/// ```
///
/// This does not perform firmware writes, PSK writes, register writes, D2,
/// FDT, or image capture. Command 0x90 restores volatile sensor configuration.
pub(crate) fn initialize<D: GoodixUsbIo + ?Sized>(
    transport: &mut GoodixTransport<'_, D>,
    timeout: Duration,
) -> Result<ChicagoHConfig, ChicagoHError> {
    let otp = transport.read_otp(timeout)?;
    let config = generate_config(&otp)?;

    let completion = transport.download_config(&config.bytes, timeout)?;
    validate_download_completion(&completion)?;

    Ok(config)
}

pub(crate) fn generate_config(otp: &[u8; OTP_LEN]) -> Result<ChicagoHConfig, ChicagoHError> {
    validate_otp(otp)?;

    let calibration = decode_calibration(otp)?;

    let mut config = base_config();

    let base_checksum = recompute_config_checksum(&mut config);

    if base_checksum != EXPECTED_BASE_CHECKSUM {
        return Err(ChicagoHError::UnexpectedBaseChecksum {
            expected: EXPECTED_BASE_CHECKSUM,
            actual: base_checksum,
        });
    }

    let (fdt_start, fdt_end) = section_bounds(&config, 5, 6);
    let (image_start, image_end) = section_bounds(&config, 9, 10);

    replace_config_value(
        &mut config,
        image_start,
        image_end,
        IMAGE_TCODE_KEY,
        calibration.tcode,
    )?;

    let fdt_delta = (calibration.diff << 8) | 0x0080;

    replace_config_value(&mut config, fdt_start, fdt_end, FDT_DELTA_KEY, fdt_delta)?;

    /*
     * ChicagoH GetChipConfig only calls _MilanFSerModifyFdtOffset when the
     * decoded OTP offset is non-zero.
     *
     * The modifier preserves the upper byte of key 0x0056 and replaces the
     * low byte with decoded_offset + 8.
     */
    if calibration.fdt_offset != 0 {
        let old_value = find_config_value(&config, fdt_start, fdt_end, FDT_OFFSET_KEY).ok_or(
            ChicagoHError::ConfigKeyMissing {
                key: FDT_OFFSET_KEY,
                start: fdt_start,
                end: fdt_end,
            },
        )?;

        let new_value = (old_value & 0xff00) | u16::from(calibration.fdt_offset + 8);

        replace_config_value(&mut config, fdt_start, fdt_end, FDT_OFFSET_KEY, new_value)?;
    }

    let checksum = u16::from_le_bytes([config[0xfe], config[0xff]]);
    let sum = config_word_sum(&config);

    if sum != CONFIG_SUM_TARGET {
        return Err(ChicagoHError::ConfigChecksumInvariant {
            expected: CONFIG_SUM_TARGET,
            actual: sum,
        });
    }

    Ok(ChicagoHConfig {
        bytes: config,
        calibration,
        checksum,
    })
}

/// Reproduce ChicagoH CheckOtp.
///
/// CP input:
///   OTP[00..0A] + OTP[24..27], stored at OTP[3C]
///
/// FT input:
///   OTP[0B..13] + OTP[1C] + OTP[32..35] + OTP[38..3B] + OTP[3E],
///   stored at OTP[3D]
///
/// MT input:
///   OTP[14..1B] + OTP[1D..23] + OTP[28..31] + OTP[36..37],
///   stored at OTP[3F]
pub(crate) fn validate_otp(otp: &[u8; OTP_LEN]) -> Result<(), ChicagoHError> {
    let mut cp = Vec::with_capacity(15);
    cp.extend_from_slice(&otp[0x00..0x0b]);
    cp.extend_from_slice(&otp[0x24..0x28]);

    check_otp_crc("CP", goodix_crc8(&cp), otp[0x3c])?;

    let mut ft = Vec::with_capacity(19);
    ft.extend_from_slice(&otp[0x0b..0x14]);
    ft.push(otp[0x1c]);
    ft.extend_from_slice(&otp[0x32..0x36]);
    ft.extend_from_slice(&otp[0x38..0x3c]);
    ft.push(otp[0x3e]);

    check_otp_crc("FT", goodix_crc8(&ft), otp[0x3d])?;

    let mut mt = Vec::with_capacity(27);
    mt.extend_from_slice(&otp[0x14..0x1c]);
    mt.extend_from_slice(&otp[0x1d..0x24]);
    mt.extend_from_slice(&otp[0x28..0x32]);
    mt.extend_from_slice(&otp[0x36..0x38]);

    check_otp_crc("MT", goodix_crc8(&mt), otp[0x3f])?;

    Ok(())
}

fn check_otp_crc(section: &'static str, calculated: u8, stored: u8) -> Result<(), ChicagoHError> {
    if calculated == stored {
        return Ok(());
    }

    Err(ChicagoHError::OtpCrcMismatch {
        section,
        calculated,
        stored,
    })
}

fn decode_calibration(otp: &[u8; OTP_LEN]) -> Result<ChicagoHCalibration, ChicagoHError> {
    let source = otp[0x2a];
    let redundant = otp[0x2d];

    /*
     * The real GF3258 WN2 has valid, equal, non-zero copies.
     *
     * For the first integrated implementation, reject the fallback/default
     * path rather than silently generating a configuration for an OTP layout
     * we have not yet tested live.
     */
    if source == 0 || source != redundant {
        return Err(ChicagoHError::InvalidTcodeDiffCopies { source, redundant });
    }

    let high = i32::from(source >> 4);
    let low = i32::from(source & 0x0f);

    // FUN_00201cf0(high, 5): checked signed i32 addition.
    let tcode_base = high
        .checked_add(5)
        .ok_or(ChicagoHError::ArithmeticOverflow)?;

    let tcode_i32 = tcode_base
        .checked_mul(16)
        .ok_or(ChicagoHError::ArithmeticOverflow)?;

    let tcode = u16::try_from(tcode_i32).map_err(|_| ChicagoHError::ArithmeticOverflow)?;

    // FUN_00201cf0(low, 2).
    let diff_base = low
        .checked_add(2)
        .ok_or(ChicagoHError::ArithmeticOverflow)?;

    // FUN_00201dc0(diff_base, 100): checked signed i32 multiplication.
    let scaled = diff_base
        .checked_mul(100)
        .ok_or(ChicagoHError::ArithmeticOverflow)?;

    let numerator = scaled
        .checked_mul(256)
        .ok_or(ChicagoHError::ArithmeticOverflow)?;

    let divided = numerator / i32::from(tcode);

    let diff = (((divided as u32) & 0xffff) / 0x30) as u16;

    let fdt_offset = decode_fdt_offset(otp[0x1b])
        .ok_or(ChicagoHError::InvalidFdtOffsetEncoding { encoded: otp[0x1b] })?;

    Ok(ChicagoHCalibration {
        tcode,
        diff,
        fdt_offset,
    })
}

/// Reproduce _MilanFSerGetFdtOffsetFromOtp for the ChicagoH call:
/// size=0x40, index=0x1b.
fn decode_fdt_offset(encoded: u8) -> Option<u8> {
    let a = encoded & 0x03;
    let b = (!(encoded >> 2)) & 0x03;
    let c = (encoded >> 4) & 0x03;

    if a == c || a == b {
        Some(a)
    } else if b == c {
        Some(c)
    } else {
        None
    }
}

/// FUN_0010f950:
///
/// CRC-8 poly 0x07, init 0x00, non-reflected, final complement.
fn goodix_crc8(data: &[u8]) -> u8 {
    let mut crc = 0u8;

    for &byte in data {
        crc ^= byte;

        for _ in 0..8 {
            crc = if crc & 0x80 != 0 {
                (crc << 1) ^ 0x07
            } else {
                crc << 1
            };
        }
    }

    !crc
}

fn base_config() -> [u8; CONFIG_LEN] {
    let mut config = [0u8; CONFIG_LEN];

    for (index, qword) in CHICAGO_H_BASE_QWORDS.iter().enumerate() {
        let offset = index * 8;
        config[offset..offset + 8].copy_from_slice(&qword.to_le_bytes());
    }

    config
}

fn section_bounds(
    config: &[u8; CONFIG_LEN],
    start_field: usize,
    length_field: usize,
) -> (usize, usize) {
    let start = usize::from(config[start_field]);
    let length = usize::from(config[length_field]);

    (start, start + length)
}

/// Recovered FUN_0012e210 semantics.
///
/// Search 4-byte records:
///
///   u16 LE key
///   u16 LE value
///
/// Replace the matching value and immediately regenerate the config checksum.
fn replace_config_value(
    config: &mut [u8; CONFIG_LEN],
    start: usize,
    end: usize,
    key: u16,
    new_value: u16,
) -> Result<u16, ChicagoHError> {
    let mut offset = start;

    while offset + 4 <= end {
        let record_key = u16::from_le_bytes([config[offset], config[offset + 1]]);

        if record_key == key {
            let old_value = u16::from_le_bytes([config[offset + 2], config[offset + 3]]);

            config[offset + 2..offset + 4].copy_from_slice(&new_value.to_le_bytes());

            recompute_config_checksum(config);

            return Ok(old_value);
        }

        offset += 4;
    }

    Err(ChicagoHError::ConfigKeyMissing { key, start, end })
}

fn find_config_value(config: &[u8; CONFIG_LEN], start: usize, end: usize, key: u16) -> Option<u16> {
    let mut offset = start;

    while offset + 4 <= end {
        let record_key = u16::from_le_bytes([config[offset], config[offset + 1]]);

        if record_key == key {
            return Some(u16::from_le_bytes([config[offset + 2], config[offset + 3]]));
        }

        offset += 4;
    }

    None
}

/// Vendor checksum invariant:
///
///   sum(all 128 little-endian u16 words) mod 65536 == 0x5a5b
///
/// config[0xfe..0xff] is the generated checksum word.
fn recompute_config_checksum(config: &mut [u8; CONFIG_LEN]) -> u16 {
    let mut sum = 0u16;

    for chunk in config[..0xfe].chunks_exact(2) {
        let word = u16::from_le_bytes([chunk[0], chunk[1]]);
        sum = sum.wrapping_add(word);
    }

    let checksum = CONFIG_SUM_TARGET.wrapping_sub(sum);

    config[0xfe..0x100].copy_from_slice(&checksum.to_le_bytes());

    checksum
}

fn config_word_sum(config: &[u8; CONFIG_LEN]) -> u16 {
    let mut sum = 0u16;

    for chunk in config.chunks_exact(2) {
        let word = u16::from_le_bytes([chunk[0], chunk[1]]);
        sum = sum.wrapping_add(word);
    }

    sum
}

pub(crate) fn validate_download_completion(packet: &McuPacket) -> Result<(), ChicagoHError> {
    if packet.is_command(Command::DownloadConfig) && packet.payload.as_slice() == [0x01, 0x00] {
        return Ok(());
    }

    Err(ChicagoHError::UnexpectedDownloadCompletion {
        command: packet.command,
        payload: packet.payload.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIVE_OTP: [u8; OTP_LEN] = [
        0x57, 0x43, 0x47, 0x34, 0x33, 0x38, 0x2e, 0x00, 0xc0, 0x74, 0x8b, 0xab, 0x42, 0xeb, 0x16,
        0x0a, 0x01, 0x05, 0x03, 0x06, 0x00, 0x00, 0x79, 0x00, 0x00, 0x00, 0x00, 0x0c, 0xf1, 0x73,
        0x8c, 0x0c, 0x07, 0x00, 0x00, 0x00, 0xe5, 0x73, 0xdf, 0xfc, 0x08, 0x76, 0xad, 0x52, 0x06,
        0xad, 0xae, 0xaf, 0xad, 0xae, 0xae, 0xaf, 0xad, 0xae, 0x00, 0x00, 0xe5, 0x1a, 0xdf, 0x20,
        0x16, 0x5f, 0x79, 0xff,
    ];

    #[test]
    fn crc_matches_recovered_check_vector() {
        assert_eq!(goodix_crc8(b"123456789"), 0x0b);
    }

    #[test]
    fn live_otp_passes_chicago_h_checks() {
        assert!(validate_otp(&LIVE_OTP).is_ok());
    }

    #[test]
    fn live_otp_calibration_matches_recovered_values() {
        let calibration = decode_calibration(&LIVE_OTP).unwrap();

        assert_eq!(
            calibration,
            ChicagoHCalibration {
                tcode: 0x00f0,
                diff: 0x0021,
                fdt_offset: 0,
            }
        );
    }

    #[test]
    fn live_otp_generates_exact_verified_config_values() {
        let generated = generate_config(&LIVE_OTP).unwrap();

        let (fdt_start, fdt_end) = section_bounds(&generated.bytes, 5, 6);

        let (image_start, image_end) = section_bounds(&generated.bytes, 9, 10);

        assert_eq!(
            find_config_value(&generated.bytes, image_start, image_end, IMAGE_TCODE_KEY,),
            Some(0x00f0)
        );

        assert_eq!(
            find_config_value(&generated.bytes, fdt_start, fdt_end, FDT_DELTA_KEY,),
            Some(0x2180)
        );

        assert_eq!(
            find_config_value(&generated.bytes, fdt_start, fdt_end, FDT_OFFSET_KEY,),
            Some(0x2004)
        );

        assert_eq!(generated.checksum, 0x1e48);
        assert_eq!(config_word_sum(&generated.bytes), 0x5a5b);

        assert_eq!(
            &generated.bytes[..8],
            &[0xb0, 0x11, 0x60, 0x71, 0x2c, 0x9d, 0x2c, 0xc9]
        );
        assert_eq!(&generated.bytes[0xfe..], &[0x48, 0x1e]);
    }

    #[test]
    fn corrupted_live_otp_is_rejected() {
        let mut otp = LIVE_OTP;
        otp[0] ^= 0x01;

        assert!(matches!(
            validate_otp(&otp),
            Err(ChicagoHError::OtpCrcMismatch { section: "CP", .. })
        ));
    }

    #[test]
    fn invalid_tcode_redundancy_is_rejected() {
        let mut otp = LIVE_OTP;
        otp[0x2d] ^= 0x01;

        assert!(matches!(
            decode_calibration(&otp),
            Err(ChicagoHError::InvalidTcodeDiffCopies { .. })
        ));
    }

    #[test]
    fn successful_download_completion_is_accepted() {
        let packet = McuPacket {
            command: Command::DownloadConfig.as_u8(),
            payload: vec![0x01, 0x00],
            trailer: Some(0x16),
        };

        assert!(validate_download_completion(&packet).is_ok());
    }

    #[test]
    fn failed_download_completion_is_rejected() {
        let packet = McuPacket {
            command: Command::DownloadConfig.as_u8(),
            payload: vec![0x00, 0x00],
            trailer: Some(0x17),
        };

        assert!(matches!(
            validate_download_completion(&packet),
            Err(ChicagoHError::UnexpectedDownloadCompletion { .. })
        ));
    }
}
