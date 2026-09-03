use aes::Aes128;
use aes::cipher::{Block, BlockCipherDecrypt, KeyInit};
use sha2::{Digest, Sha256};
use std::fmt;

/// Fixed mode-1 sealing root recovered from the proprietary Goodix driver.
///
/// Unlike the runtime firmware PSK, this value is static.
///
/// The driver derives this 32-byte value through:
///
///     FUN_001ff990(1, root[0..16])
///     FUN_001feea0(root[16..32])
///
/// It is then used by GfSealData/GfUnsealData as the HMAC-SHA256
/// root for the 384-bit key-derivation operation.
pub const SEAL_ROOT_MODE1: [u8; 32] = [
    0x5c, 0xba, 0x6e, 0x25, 0x81, 0x95, 0x18, 0xde, 0x2d, 0x53, 0xe9, 0x6d, 0xc0, 0x34, 0x7a, 0xb0,
    0xd4, 0x27, 0xd4, 0x08, 0x4b, 0xda, 0x4f, 0xae, 0x1b, 0xff, 0x2b, 0x09, 0x11, 0x2a, 0x57, 0xe5,
];

/// SHA-256 of the PSK recovered from the captured provisioning flow.
///
/// The captured PSK itself was 32 zero bytes. This constant is a
/// regression vector only; production code must read and unseal the
/// PSK from object 0xbb010002.
pub const EXPECTED_CAPTURED_PSK_SHA256: [u8; 32] = [
    0x66, 0x68, 0x7a, 0xad, 0xf8, 0x62, 0xbd, 0x77, 0x6c, 0x8f, 0xc1, 0x8b, 0x8e, 0x9f, 0x8e, 0x20,
    0x08, 0x97, 0x14, 0x85, 0x6e, 0xe2, 0x33, 0xb3, 0x90, 0x2a, 0x59, 0x1d, 0x0d, 0x5f, 0x29, 0x25,
];

/// GetPmkHmac result for the 32-byte zero PSK recovered from the
/// captured provisioning flow.
pub const EXPECTED_CAPTURED_PMK_HMAC: [u8; 32] = [
    0x0a, 0xc3, 0x90, 0x58, 0xf7, 0xe4, 0xbc, 0x00, 0x25, 0xa1, 0x8b, 0xd0, 0x69, 0xe7, 0xa0, 0x4e,
    0xa4, 0x39, 0x95, 0x31, 0x17, 0x5a, 0x3b, 0x17, 0x26, 0xb2, 0x2e, 0x4e, 0x42, 0x66, 0x98, 0x3a,
];

/// F4 tag observed from the proprietary driver for the validated
/// GFUSB_GM168SEC_APP_15045 transfer package.
///
/// This is retained as a regression vector. The `firmware_info` validation
/// tool checks a supplied APP resource against this value.
pub const EXPECTED_VENDOR_F4: [u8; 32] = [
    0x55, 0xc3, 0xfd, 0x0c, 0xa4, 0xab, 0x6c, 0xb5, 0xaf, 0xaa, 0x29, 0x48, 0x1a, 0xfd, 0xb1, 0x96,
    0x5b, 0x65, 0xd4, 0x8c, 0x0c, 0xd6, 0xc2, 0xff, 0x67, 0xb6, 0xa3, 0x5f, 0x55, 0x07, 0x50, 0x7e,
];

const SEALED_TAG_LEN: usize = 0x20;
const SEALED_MARKER_OFFSET: usize = 0x20;
const SEALED_LENGTH_OFFSET: usize = 0x22;
const SEALED_IV_OFFSET: usize = 0x26;
const SEALED_CIPHERTEXT_OFFSET: usize = 0x36;

/// Stored little-endian u16 value 0xff01.
const SEALED_MARKER: [u8; 2] = [0x01, 0xff];

/// KDF strings recovered from FUN_00201750.
///
/// The first string is passed with length 10, so its terminating NUL
/// is intentionally included.
const KDF_LABEL_1: &[u8; 10] = b"kgoodwixg\0";
const KDF_LABEL_2: &[u8; 15] = b"kaelrgnoerlithm";

/// Requested KDF output size in bits: 384 bits = 48 bytes.
const KDF_OUTPUT_BITS: u32 = 0x180;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirmwareAuthError {
    SealedObjectTooShort { actual: usize },

    InvalidSealedMarker([u8; 2]),

    InvalidCiphertextLength { actual: usize },

    SealedObjectHmacMismatch,

    InvalidPkcs7Padding,

    PlaintextLengthMismatch { declared: usize, actual: usize },
}

impl fmt::Display for FirmwareAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SealedObjectTooShort { actual } => {
                write!(f, "sealed object is too short: {actual} bytes")
            }

            Self::InvalidSealedMarker(marker) => {
                write!(
                    f,
                    "invalid sealed-object marker: {:02x} {:02x}",
                    marker[0], marker[1]
                )
            }

            Self::InvalidCiphertextLength { actual } => {
                write!(
                    f,
                    "sealed-object ciphertext length is not AES-block aligned: {actual}"
                )
            }

            Self::SealedObjectHmacMismatch => {
                write!(f, "sealed-object HMAC verification failed")
            }

            Self::InvalidPkcs7Padding => {
                write!(f, "sealed-object plaintext has invalid PKCS#7 padding")
            }

            Self::PlaintextLengthMismatch { declared, actual } => {
                write!(
                    f,
                    "sealed-object plaintext length mismatch: \
                     declared {declared}, recovered {actual}"
                )
            }
        }
    }
}

impl std::error::Error for FirmwareAuthError {}

/// Derive the AES-128 and HMAC-SHA256 keys used by GfSealData and
/// GfUnsealData.
///
/// Recovered vendor construction:
///
///     K1 = HMAC-SHA256(
///         root,
///         BE32(1)
///         || "kgoodwixg\0"
///         || "kaelrgnoerlithm"
///         || BE32(0x180)
///     )
///
///     K2 = HMAC-SHA256(
///         root,
///         BE32(2)
///         || "kgoodwixg\0"
///         || "kaelrgnoerlithm"
///         || BE32(0x180)
///     )
///
///     derived = K1 || K2[0..16]
///
/// Then:
///
///     derived[0..16]  -> AES-128-CBC key
///     derived[16..48] -> HMAC-SHA256 key
pub fn derive_seal_keys() -> ([u8; 16], [u8; 32]) {
    derive_seal_keys_from_root(&SEAL_ROOT_MODE1)
}

pub fn derive_seal_keys_from_root(root: &[u8; 32]) -> ([u8; 16], [u8; 32]) {
    let mut material = [0u8; 48];

    for counter in 1u32..=2 {
        let mut input = [0u8; 33];

        input[0..4].copy_from_slice(&counter.to_be_bytes());

        input[4..14].copy_from_slice(KDF_LABEL_1);

        input[14..29].copy_from_slice(KDF_LABEL_2);

        input[29..33].copy_from_slice(&KDF_OUTPUT_BITS.to_be_bytes());

        let block = hmac_sha256(root, &input);

        if counter == 1 {
            material[..32].copy_from_slice(&block);
        } else {
            material[32..48].copy_from_slice(&block[..16]);
        }
    }

    let mut aes_key = [0u8; 16];
    let mut hmac_key = [0u8; 32];

    aes_key.copy_from_slice(&material[..16]);
    hmac_key.copy_from_slice(&material[16..48]);

    (aes_key, hmac_key)
}

/// Authenticate and unseal a Goodix 0xbb010002 PSK object.
///
/// Recovered sealed layout:
///
///     +0x00  32 bytes  HMAC-SHA256
///     +0x20   2 bytes  marker = LE16(0xff01)
///     +0x22   4 bytes  plaintext length, LE
///     +0x26  16 bytes  AES-CBC IV
///     +0x36   N bytes  ciphertext
///
/// HMAC input:
///
///     marker
///     || plaintext_length
///     || ciphertext
///
/// The IV is deliberately NOT included in the authenticated input,
/// matching the proprietary implementation.
pub fn unseal_psk(sealed: &[u8]) -> Result<Vec<u8>, FirmwareAuthError> {
    unseal_psk_with_root(sealed, &SEAL_ROOT_MODE1)
}

pub fn unseal_psk_with_root(sealed: &[u8], root: &[u8; 32]) -> Result<Vec<u8>, FirmwareAuthError> {
    /*
     * We require at least one encrypted AES block after the 0x36-byte
     * sealed header.
     */
    if sealed.len() < SEALED_CIPHERTEXT_OFFSET + 16 {
        return Err(FirmwareAuthError::SealedObjectTooShort {
            actual: sealed.len(),
        });
    }

    let marker = [
        sealed[SEALED_MARKER_OFFSET],
        sealed[SEALED_MARKER_OFFSET + 1],
    ];

    if marker != SEALED_MARKER {
        return Err(FirmwareAuthError::InvalidSealedMarker(marker));
    }

    let declared_len = u32::from_le_bytes(
        sealed[SEALED_LENGTH_OFFSET..SEALED_LENGTH_OFFSET + 4]
            .try_into()
            .expect("four-byte sealed length slice"),
    ) as usize;

    let ciphertext = &sealed[SEALED_CIPHERTEXT_OFFSET..];

    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
        return Err(FirmwareAuthError::InvalidCiphertextLength {
            actual: ciphertext.len(),
        });
    }

    let (aes_key, hmac_key) = derive_seal_keys_from_root(root);

    /*
     * Vendor GfUnsealData authenticates:
     *
     *     sealed[0x20..0x26]
     *     || sealed[0x36..]
     *
     * i.e. marker + plaintext length + ciphertext.
     */
    let mut authenticated = Vec::with_capacity(6 + ciphertext.len());

    authenticated.extend_from_slice(&sealed[SEALED_MARKER_OFFSET..SEALED_IV_OFFSET]);

    authenticated.extend_from_slice(ciphertext);

    let calculated_tag = hmac_sha256(&hmac_key, &authenticated);

    if !constant_time_eq(&calculated_tag, &sealed[..SEALED_TAG_LEN]) {
        return Err(FirmwareAuthError::SealedObjectHmacMismatch);
    }

    let mut iv = [0u8; 16];

    iv.copy_from_slice(&sealed[SEALED_IV_OFFSET..SEALED_CIPHERTEXT_OFFSET]);

    let padded_plaintext = aes128_cbc_decrypt(&aes_key, &iv, ciphertext);

    let plaintext = strip_pkcs7(&padded_plaintext)?;

    if plaintext.len() != declared_len {
        return Err(FirmwareAuthError::PlaintextLengthMismatch {
            declared: declared_len,
            actual: plaintext.len(),
        });
    }

    Ok(plaintext.to_vec())
}

/// SHA-256 of the plaintext PSK.
///
/// PresetPskIsVaildG compares this value against MCU object
/// 0xbb020001 before calling PresetPskPskSet.
pub fn psk_sha256(psk: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(psk);

    let mut result = [0u8; 32];
    result.copy_from_slice(&digest);

    result
}

/// Compare a plaintext PSK with the 32-byte verification hash read
/// from MCU object 0xbb020001.
pub fn verify_psk_hash(psk: &[u8], expected_hash: &[u8]) -> bool {
    if expected_hash.len() != 32 {
        return false;
    }

    constant_time_eq(&psk_sha256(psk), expected_hash)
}

/// Reproduce vendor GetPmkHmac for the actual runtime PSK.
///
/// Recovered algorithm:
///
/// 1. Allocate zeroed 0x44-byte input.
/// 2. Set:
///
///        input[0x01] = 0x20
///        input[0x23] = 0x20
///
/// 3. Copy PSK to input + 0x24.
///
///    The vendor uses __memcpy_chk with destination size 0x20,
///    therefore the PSK must be <= 32 bytes.
///
/// 4. SHA256 the entire 0x44-byte input.
/// 5. Copy that 32-byte digest into the beginning of a zeroed
///    64-byte buffer.
/// 6. HMAC-SHA256 that 64-byte key over:
///
///        01 02 03 ... 40
///
/// For the captured 32-byte zero PSK this produces:
///
///     0ac39058f7e4bc0025a18bd069e7a04e
///     a4399531175a3b1726b22e4e4266983a
///
/// # Panics
///
/// Panics when `psk` exceeds the vendor's fixed 32-byte input buffer.
pub fn get_pmk_hmac_from_psk(psk: &[u8]) -> [u8; 32] {
    assert!(
        psk.len() <= 0x20,
        "PSK is too large for vendor GetPmkHmac input"
    );

    let mut input = [0u8; 0x44];

    input[0x01] = 0x20;
    input[0x23] = 0x20;

    input[0x24..0x24 + psk.len()].copy_from_slice(psk);

    let digest = Sha256::digest(input);

    /*
     * Vendor allocates 0x40 zeroed bytes and writes only the
     * 32-byte SHA-256 digest into the beginning.
     */
    let mut hmac_key = [0u8; 64];

    hmac_key[..32].copy_from_slice(&digest);

    let mut message = [0u8; 64];

    for (index, byte) in message.iter_mut().enumerate() {
        *byte = (index + 1) as u8;
    }

    hmac_sha256(&hmac_key, &message)
}

/// Compute the exact 32-byte authentication tag used as the F4
/// payload after all F0 APP-package chunks have been transferred.
///
/// Vendor WriteApp performs:
///
///     pmk_hmac = GetPmkHmac(actual_runtime_psk)
///
///     f4 = HMAC-SHA256(
///         key     = pmk_hmac,
///         message = complete APP transfer package
///     )
///
/// The package is:
///
///     header_crc
///     || app_len
///     || app_crc
///     || APP
///
/// The PSK is intentionally an explicit parameter. Production code
/// must not fall back to the `_McuCreateContext` placeholder
/// { 0x12, 0x34, 0x56 }.
pub fn firmware_f4_tag(psk: &[u8], package: &[u8]) -> [u8; 32] {
    let key = get_pmk_hmac_from_psk(psk);

    hmac_sha256(&key, package)
}

/// AES-128-CBC decryption matching FUN_001fc6b0.
///
/// The input must already be block aligned. PKCS#7 removal is
/// intentionally handled separately because FUN_00201750 validates
/// the recovered plaintext length after decryption.
fn aes128_cbc_decrypt(key: &[u8; 16], iv: &[u8; 16], ciphertext: &[u8]) -> Vec<u8> {
    debug_assert_eq!(ciphertext.len() % 16, 0);

    let cipher = Aes128::new_from_slice(key).expect("AES-128 key must be exactly 16 bytes");

    let mut previous = *iv;
    let mut plaintext = Vec::with_capacity(ciphertext.len());

    for chunk in ciphertext.chunks_exact(16) {
        let mut block = Block::<Aes128>::try_from(chunk)
            .expect("chunks_exact(16) guarantees a 16-byte AES block");

        cipher.decrypt_block(&mut block);

        for i in 0..16 {
            plaintext.push(block[i] ^ previous[i]);
        }

        // CBC chaining:
        // the current ciphertext becomes the IV for the next block.
        previous.copy_from_slice(chunk);
    }

    plaintext
}

fn strip_pkcs7(data: &[u8]) -> Result<&[u8], FirmwareAuthError> {
    let Some(&padding_byte) = data.last() else {
        return Err(FirmwareAuthError::InvalidPkcs7Padding);
    };

    let padding_len = padding_byte as usize;

    if padding_len == 0 || padding_len > 16 || padding_len > data.len() {
        return Err(FirmwareAuthError::InvalidPkcs7Padding);
    }

    if !data[data.len() - padding_len..]
        .iter()
        .all(|&byte| byte == padding_byte)
    {
        return Err(FirmwareAuthError::InvalidPkcs7Padding);
    }

    Ok(&data[..data.len() - padding_len])
}

/// Small constant-time comparison helper for authentication data.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut difference = 0u8;

    for (&a, &b) in left.iter().zip(right) {
        difference |= a ^ b;
    }

    difference == 0
}

/// Generic HMAC-SHA256 implementation.
///
/// Kept local so the firmware authentication implementation depends
/// only on sha2 and the already-present AES crate.
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;

    let mut block_key = [0u8; BLOCK_SIZE];

    if key.len() > BLOCK_SIZE {
        let digest = Sha256::digest(key);

        block_key[..32].copy_from_slice(&digest);
    } else {
        block_key[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK_SIZE];

    let mut opad = [0x5cu8; BLOCK_SIZE];

    for i in 0..BLOCK_SIZE {
        ipad[i] ^= block_key[i];
        opad[i] ^= block_key[i];
    }

    let mut inner = Sha256::new();

    inner.update(ipad);
    inner.update(message);

    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();

    outer.update(opad);
    outer.update(inner_digest);

    let digest = outer.finalize();

    let mut result = [0u8; 32];

    result.copy_from_slice(&digest);

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Complete 102-byte 0xbb010002 object reconstructed from the
    /// vendor E0 provisioning transaction at frames 167-173.
    const CAPTURED_SEALED_PSK: [u8; 102] = [
        0x7c, 0x2e, 0x1d, 0x39, 0xce, 0xdc, 0x06, 0x97, 0x83, 0x0c, 0x97, 0x94, 0x50, 0xc2, 0x7a,
        0xf2, 0x36, 0x57, 0xc5, 0x54, 0xfe, 0x46, 0x8f, 0x31, 0xeb, 0x39, 0xbf, 0xca, 0x2a, 0x6a,
        0x00, 0x86, 0x01, 0xff, 0x20, 0x00, 0x00, 0x00, 0x2a, 0x8c, 0x71, 0xd2, 0xa9, 0x79, 0x34,
        0xb5, 0x92, 0xdc, 0x33, 0x25, 0x94, 0x31, 0x59, 0xe4, 0x53, 0x90, 0xd7, 0x8b, 0x63, 0x4d,
        0x1d, 0x32, 0x7c, 0x3f, 0x29, 0xfc, 0xa5, 0x75, 0xed, 0x96, 0x83, 0xf3, 0xb3, 0x57, 0xd7,
        0x03, 0x43, 0xc8, 0xb7, 0x6e, 0x9d, 0xd4, 0x01, 0x5c, 0x54, 0x06, 0x07, 0xb8, 0x6a, 0xc9,
        0x65, 0x88, 0x69, 0x50, 0x1c, 0x12, 0x48, 0xaf, 0x25, 0xb6, 0x0b, 0xc8,
    ];

    #[test]
    fn hmac_sha256_known_vector() {
        // RFC 4231 test case 1.
        let key = [0x0b; 20];

        let result = hmac_sha256(&key, b"Hi There");

        assert_eq!(
            result,
            [
                0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
                0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
                0x2e, 0x32, 0xcf, 0xf7,
            ]
        );
    }

    #[test]
    fn seal_root_matches_recovered_value() {
        assert_eq!(
            SEAL_ROOT_MODE1,
            [
                0x5c, 0xba, 0x6e, 0x25, 0x81, 0x95, 0x18, 0xde, 0x2d, 0x53, 0xe9, 0x6d, 0xc0, 0x34,
                0x7a, 0xb0, 0xd4, 0x27, 0xd4, 0x08, 0x4b, 0xda, 0x4f, 0xae, 0x1b, 0xff, 0x2b, 0x09,
                0x11, 0x2a, 0x57, 0xe5,
            ]
        );
    }

    #[test]
    fn seal_kdf_matches_recovered_vendor_keys() {
        let (aes_key, hmac_key) = derive_seal_keys();

        assert_eq!(
            aes_key,
            [
                0x58, 0xf0, 0x13, 0xee, 0xb7, 0xe2, 0x16, 0xe2, 0xc1, 0xcd, 0x0e, 0x8f, 0xff, 0xa7,
                0xdb, 0xd6,
            ]
        );

        assert_eq!(
            hmac_key,
            [
                0x79, 0x9c, 0xd9, 0x2a, 0xa1, 0x49, 0x01, 0x3e, 0xa0, 0xe9, 0xf9, 0xfd, 0x7d, 0xc6,
                0xd9, 0x4e, 0x3e, 0xf6, 0x3a, 0x75, 0x98, 0xc2, 0xa4, 0x93, 0x31, 0x29, 0xe8, 0x71,
                0xea, 0x03, 0x04, 0x3b,
            ]
        );
    }

    #[test]
    fn captured_sealed_psk_authenticates_and_unseals() {
        let psk = unseal_psk(&CAPTURED_SEALED_PSK).unwrap();

        assert_eq!(psk, vec![0u8; 32]);

        assert_eq!(psk_sha256(&psk), EXPECTED_CAPTURED_PSK_SHA256);
    }

    #[test]
    fn captured_psk_hash_verification_succeeds() {
        let psk = [0u8; 32];

        assert!(verify_psk_hash(&psk, &EXPECTED_CAPTURED_PSK_SHA256,));
    }

    #[test]
    fn get_pmk_hmac_matches_captured_runtime_psk() {
        let psk = [0u8; 32];

        assert_eq!(get_pmk_hmac_from_psk(&psk), EXPECTED_CAPTURED_PMK_HMAC);
    }

    #[test]
    fn tampered_sealed_psk_is_rejected() {
        let mut sealed = CAPTURED_SEALED_PSK;

        sealed[SEALED_CIPHERTEXT_OFFSET] ^= 0x01;

        assert_eq!(
            unseal_psk(&sealed),
            Err(FirmwareAuthError::SealedObjectHmacMismatch)
        );
    }

    #[test]
    fn wrong_sealed_marker_is_rejected() {
        let mut sealed = CAPTURED_SEALED_PSK;

        sealed[SEALED_MARKER_OFFSET] = 0x00;

        assert_eq!(
            unseal_psk(&sealed),
            Err(FirmwareAuthError::InvalidSealedMarker([0x00, 0xff]))
        );
    }
}
