use std::{error::Error, fmt};

pub const IMAGE_WIDTH: usize = 80;
pub const IMAGE_HEIGHT: usize = 64;

pub(crate) const IMAGE_HEADER_LEN: usize = 5;
pub(crate) const ENCRYPTED_IMAGE_LEN: usize = 10_560;
pub(crate) const IMAGE_CRC_LEN: usize = 4;

pub(crate) const PROTECTED_IMAGE_LEN: usize =
    IMAGE_HEADER_LEN + ENCRYPTED_IMAGE_LEN + IMAGE_CRC_LEN;

const RAW_ROWS: usize = 80;
const RAW_ROW_BYTES: usize = 132;
const PACKED_ROW_BYTES: usize = 96;

const DECRYPTED_IMAGE_BYTES: usize = RAW_ROWS * RAW_ROW_BYTES;
const PACKED_IMAGE_BYTES: usize = RAW_ROWS * PACKED_ROW_BYTES;
const PIXEL_COUNT: usize = IMAGE_WIDTH * IMAGE_HEIGHT;

const CRC32_POLYNOMIAL: u32 = 0x04C1_1DB7;
const CRC32_INITIAL: u32 = 0xFFFF_FFFF;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProtectedImage<'a> {
    header: &'a [u8; IMAGE_HEADER_LEN],
    ciphertext: &'a [u8],
    crc: &'a [u8; IMAGE_CRC_LEN],
}

impl<'a> ProtectedImage<'a> {
    pub(crate) fn parse(data: &'a [u8]) -> Result<Self, ImageError> {
        if data.len() != PROTECTED_IMAGE_LEN {
            return Err(ImageError::UnexpectedProtectedLength {
                expected: PROTECTED_IMAGE_LEN,
                actual: data.len(),
            });
        }

        let header = data[..IMAGE_HEADER_LEN]
            .try_into()
            .expect("image header slice has fixed length");

        let ciphertext_start = IMAGE_HEADER_LEN;
        let ciphertext_end = ciphertext_start + ENCRYPTED_IMAGE_LEN;

        let ciphertext = &data[ciphertext_start..ciphertext_end];

        let crc = data[ciphertext_end..]
            .try_into()
            .expect("image CRC slice has fixed length");

        Ok(Self {
            header,
            ciphertext,
            crc,
        })
    }

    pub(crate) fn header(&self) -> &[u8; IMAGE_HEADER_LEN] {
        self.header
    }

    pub(crate) fn ciphertext(&self) -> &'a [u8] {
        self.ciphertext
    }

    pub(crate) fn crc(&self) -> &[u8; IMAGE_CRC_LEN] {
        self.crc
    }

    pub(crate) fn stored_crc(&self) -> u32 {
        /*
         * CheckImageCrc reconstructs the four bytes as:
         *
         *   crc[2] << 24
         * | crc[3] << 16
         * | crc[0] << 8
         * | crc[1]
         *
         * Example:
         *
         *   wire: c1 58 46 54
         *   u32:  0x4654c158
         */
        (u32::from(self.crc[2]) << 24)
            | (u32::from(self.crc[3]) << 16)
            | (u32::from(self.crc[0]) << 8)
            | u32::from(self.crc[1])
    }

    pub(crate) fn validate_crc(&self, decrypted: &[u8]) -> Result<(), ImageError> {
        if decrypted.len() != DECRYPTED_IMAGE_BYTES {
            return Err(ImageError::UnexpectedDecryptedLength {
                expected: DECRYPTED_IMAGE_BYTES,
                actual: decrypted.len(),
            });
        }

        let stored = self.stored_crc();
        let calculated = goodix_image_crc(decrypted);

        if calculated != stored {
            return Err(ImageError::CrcMismatch { stored, calculated });
        }

        Ok(())
    }

    pub(crate) fn is_boot_image(&self) -> bool {
        self.header[0] == 0xAA
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ImageError {
    UnexpectedProtectedLength { expected: usize, actual: usize },

    UnexpectedDecryptedLength { expected: usize, actual: usize },

    CrcMismatch { stored: u32, calculated: u32 },
}

impl fmt::Display for ImageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedProtectedLength { expected, actual } => {
                write!(
                    f,
                    "unexpected protected image length: expected \
                     {expected} bytes, received {actual}"
                )
            }

            Self::UnexpectedDecryptedLength { expected, actual } => {
                write!(
                    f,
                    "unexpected decrypted image length: expected \
                     {expected} bytes, received {actual}"
                )
            }

            Self::CrcMismatch { stored, calculated } => {
                write!(
                    f,
                    "fingerprint image CRC mismatch: stored \
                     0x{stored:08x}, calculated 0x{calculated:08x}"
                )
            }
        }
    }
}

impl Error for ImageError {}

pub(crate) fn goodix_image_crc(data: &[u8]) -> u32 {
    /*
     * Reverse engineered from:
     *
     *   FUN_0010f7b0 - CRC table generation
     *   FUN_0010f820 - CRC calculation
     *
     * Parameters correspond to CRC-32/MPEG-2:
     *
     *   polynomial = 0x04C11DB7
     *   initial    = 0xFFFFFFFF
     *   refin      = false
     *   refout     = false
     *   xorout     = 0
     *
     * The vendor implementation uses a 256-entry lookup table.
     * This bitwise implementation is mathematically equivalent.
     */
    let mut crc = CRC32_INITIAL;

    for &byte in data {
        crc ^= u32::from(byte) << 24;

        for _ in 0..8 {
            if crc & 0x8000_0000 != 0 {
                crc = crc.wrapping_shl(1) ^ CRC32_POLYNOMIAL;
            } else {
                crc = crc.wrapping_shl(1);
            }
        }
    }

    crc
}

pub(crate) fn restructure_gf3258_wn2(decrypted: &[u8]) -> Result<Vec<u16>, ImageError> {
    if decrypted.len() != DECRYPTED_IMAGE_BYTES {
        return Err(ImageError::UnexpectedDecryptedLength {
            expected: DECRYPTED_IMAGE_BYTES,
            actual: decrypted.len(),
        });
    }

    let packed = compact_rows(decrypted);

    let mut pixels = vec![0_u16; PIXEL_COUNT];

    let mut source_pixel = 0_usize;

    for bytes in packed.chunks_exact(6) {
        let b0 = u16::from(bytes[0]);
        let b1 = u16::from(bytes[1]);
        let b2 = u16::from(bytes[2]);
        let b3 = u16::from(bytes[3]);
        let b4 = u16::from(bytes[4]);
        let b5 = u16::from(bytes[5]);

        let unpacked = [
            ((b0 & 0x0f) << 8) | b1,
            (b3 << 4) | (b0 >> 4),
            ((b5 & 0x0f) << 8) | b2,
            (b4 << 4) | (b5 >> 4),
        ];

        for pixel in unpacked {
            let source_row = source_pixel >> 6;

            let source_column = source_pixel & 0x3f;

            let destination = source_column * IMAGE_WIDTH + source_row;

            pixels[destination] = pixel;

            source_pixel += 1;
        }
    }

    debug_assert_eq!(source_pixel, PIXEL_COUNT,);

    Ok(pixels)
}

pub(crate) fn normalize_12bit_to_u8(pixels: &[u16]) -> Vec<u8> {
    let Some((&minimum, &maximum)) = pixels.iter().min().zip(pixels.iter().max()) else {
        return Vec::new();
    };

    if minimum == maximum {
        return vec![0; pixels.len()];
    }

    let minimum = u32::from(minimum);

    let range = u32::from(maximum) - minimum;

    pixels
        .iter()
        .map(|&pixel| {
            let value = u32::from(pixel) - minimum;

            ((value * u32::from(u8::MAX) + range / 2) / range) as u8
        })
        .collect()
}

fn compact_rows(decrypted: &[u8]) -> Vec<u8> {
    let mut packed = Vec::with_capacity(PACKED_IMAGE_BYTES);

    for row in decrypted.chunks_exact(RAW_ROW_BYTES) {
        packed.extend_from_slice(&row[..PACKED_ROW_BYTES]);
    }

    debug_assert_eq!(packed.len(), PACKED_IMAGE_BYTES,);

    packed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_matches_standard_check_vector() {
        /*
         * CRC-32/MPEG-2 check value for ASCII:
         *
         *     "123456789"
         *
         * is 0x0376E6E7.
         */
        assert_eq!(goodix_image_crc(b"123456789"), 0x0376_E6E7,);
    }

    #[test]
    fn crc_of_empty_data_is_initial_value() {
        assert_eq!(goodix_image_crc(&[]), 0xFFFF_FFFF,);
    }

    #[test]
    fn decodes_vendor_crc_byte_order() {
        let mut data = vec![0_u8; PROTECTED_IMAGE_LEN];

        let crc_offset = IMAGE_HEADER_LEN + ENCRYPTED_IMAGE_LEN;

        data[crc_offset..].copy_from_slice(&[0xC1, 0x58, 0x46, 0x54]);

        let image = ProtectedImage::parse(&data).unwrap();

        assert_eq!(image.stored_crc(), 0x4654_C158,);
    }

    #[test]
    fn validates_matching_image_crc() {
        let decrypted = vec![0_u8; DECRYPTED_IMAGE_BYTES];

        let calculated = goodix_image_crc(&decrypted);

        let mut data = vec![0_u8; PROTECTED_IMAGE_LEN];

        let crc_offset = IMAGE_HEADER_LEN + ENCRYPTED_IMAGE_LEN;

        let bytes = calculated.to_be_bytes();

        /*
         * Vendor wire representation:
         *
         * integer bytes:
         *   B0 B1 B2 B3
         *
         * wire:
         *   B2 B3 B0 B1
         */
        data[crc_offset..].copy_from_slice(&[bytes[2], bytes[3], bytes[0], bytes[1]]);

        let image = ProtectedImage::parse(&data).unwrap();

        assert_eq!(image.validate_crc(&decrypted), Ok(()),);
    }

    #[test]
    fn rejects_bad_image_crc() {
        let decrypted = vec![0_u8; DECRYPTED_IMAGE_BYTES];

        let data = vec![0_u8; PROTECTED_IMAGE_LEN];

        let image = ProtectedImage::parse(&data).unwrap();

        assert!(matches!(
            image.validate_crc(&decrypted),
            Err(ImageError::CrcMismatch { .. })
        ));
    }

    #[test]
    fn parses_protected_image_layout() {
        let mut data = vec![0_u8; PROTECTED_IMAGE_LEN];

        data[..IMAGE_HEADER_LEN].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05]);

        data[IMAGE_HEADER_LEN] = 0x11;

        data[IMAGE_HEADER_LEN + ENCRYPTED_IMAGE_LEN - 1] = 0x22;

        data[IMAGE_HEADER_LEN + ENCRYPTED_IMAGE_LEN..].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);

        let image = ProtectedImage::parse(&data).unwrap();

        assert_eq!(image.header(), &[0x01, 0x02, 0x03, 0x04, 0x05,],);

        assert_eq!(image.ciphertext().len(), ENCRYPTED_IMAGE_LEN,);

        assert_eq!(image.ciphertext()[0], 0x11,);

        assert_eq!(image.ciphertext()[ENCRYPTED_IMAGE_LEN - 1], 0x22,);

        assert_eq!(image.crc(), &[0xAA, 0xBB, 0xCC, 0xDD,],);
    }

    #[test]
    fn rejects_unexpected_protected_image_length() {
        let data = vec![0_u8; PROTECTED_IMAGE_LEN - 1];

        assert_eq!(
            ProtectedImage::parse(&data),
            Err(ImageError::UnexpectedProtectedLength {
                expected: PROTECTED_IMAGE_LEN,

                actual: PROTECTED_IMAGE_LEN - 1,
            },),
        );
    }

    #[test]
    fn detects_boot_image_header() {
        let mut data = vec![0_u8; PROTECTED_IMAGE_LEN];

        data[0] = 0xAA;

        let image = ProtectedImage::parse(&data).unwrap();

        assert!(image.is_boot_image(),);
    }

    #[test]
    fn normal_image_header_is_not_boot_image() {
        let data = vec![0_u8; PROTECTED_IMAGE_LEN];

        let image = ProtectedImage::parse(&data).unwrap();

        assert!(!image.is_boot_image(),);
    }

    #[test]
    fn rejects_unexpected_decrypted_image_length() {
        let decrypted = vec![0; DECRYPTED_IMAGE_BYTES - 1];

        assert_eq!(
            restructure_gf3258_wn2(&decrypted,),
            Err(ImageError::UnexpectedDecryptedLength {
                expected: DECRYPTED_IMAGE_BYTES,

                actual: DECRYPTED_IMAGE_BYTES - 1,
            },),
        );
    }

    #[test]
    fn strips_unused_bytes_from_each_raw_row() {
        let mut decrypted = vec![0; DECRYPTED_IMAGE_BYTES];

        for row in decrypted.chunks_exact_mut(RAW_ROW_BYTES) {
            row[PACKED_ROW_BYTES..].fill(0xff);
        }

        let pixels = restructure_gf3258_wn2(&decrypted).unwrap();

        assert!(pixels.iter().all(|&pixel| pixel == 0));
    }

    #[test]
    fn unpacks_four_12bit_samples_from_six_bytes() {
        let mut decrypted = vec![0; DECRYPTED_IMAGE_BYTES];

        decrypted[..6].copy_from_slice(&[0x61, 0x23, 0x89, 0x45, 0xab, 0xc7]);

        let pixels = restructure_gf3258_wn2(&decrypted).unwrap();

        assert_eq!(pixels[0], 0x123,);

        assert_eq!(pixels[IMAGE_WIDTH], 0x456,);

        assert_eq!(pixels[IMAGE_WIDTH * 2], 0x789,);

        assert_eq!(pixels[IMAGE_WIDTH * 3], 0xabc,);
    }

    #[test]
    fn transposes_sensor_order_into_80_pixel_rows() {
        let mut decrypted = vec![0; DECRYPTED_IMAGE_BYTES];

        decrypted[..6].copy_from_slice(&[0x20, 0x01, 0x03, 0x00, 0x00, 0x40]);

        let pixels = restructure_gf3258_wn2(&decrypted).unwrap();

        assert_eq!(pixels[0], 1,);

        assert_eq!(pixels[80], 2,);

        assert_eq!(pixels[160], 3,);

        assert_eq!(pixels[240], 4,);
    }

    #[test]
    fn normalizes_pixel_range_to_full_u8_range() {
        let pixels = [0x0100, 0x0800, 0x0f00];

        assert_eq!(normalize_12bit_to_u8(&pixels,), [0, 128, 255,],);
    }

    #[test]
    fn uniform_image_normalizes_to_black() {
        let pixels = [0x0555; 4];

        assert_eq!(normalize_12bit_to_u8(&pixels,), [0, 0, 0, 0,],);
    }
}
