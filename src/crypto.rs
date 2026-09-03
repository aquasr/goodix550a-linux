use std::{error::Error, fmt};

use aes::{
    Aes128,
    cipher::{BlockModeDecrypt, KeyIvInit, block_padding::NoPadding},
};

const D2_MATERIAL_LEN: usize = 32;
const AES_KEY_LEN: usize = 16;
const AES_BLOCK_LEN: usize = 16;

const IMAGE_KEY_OFFSET: usize = 16;
const ZERO_IV: [u8; AES_BLOCK_LEN] = [0; AES_BLOCK_LEN];

type Aes128CbcDecryptor = cbc::Decryptor<Aes128>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ImageSession {
    material: [u8; D2_MATERIAL_LEN],
}

impl ImageSession {
    pub(crate) fn generate() -> Result<Self, getrandom::Error> {
        let mut material = [0_u8; D2_MATERIAL_LEN];

        getrandom::fill(&mut material)?;

        Ok(Self { material })
    }

    pub(crate) fn d2_payload(&self) -> &[u8; D2_MATERIAL_LEN] {
        &self.material
    }

    pub(crate) fn image_key(&self) -> [u8; AES_KEY_LEN] {
        self.material[IMAGE_KEY_OFFSET..]
            .try_into()
            .expect("D2 image key range is exactly 16 bytes")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CryptoError {
    CiphertextNotBlockAligned { length: usize, block_size: usize },

    DecryptionFailed,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CiphertextNotBlockAligned { length, block_size } => {
                write!(
                    f,
                    "AES-CBC ciphertext length {length} is not a multiple of \
                     the {block_size}-byte AES block size"
                )
            }

            Self::DecryptionFailed => f.write_str("AES-128-CBC image decryption failed"),
        }
    }
}

impl Error for CryptoError {}

pub(crate) fn decrypt_image(
    ciphertext: &[u8],
    key: &[u8; AES_KEY_LEN],
) -> Result<Vec<u8>, CryptoError> {
    if (ciphertext.len() & (AES_BLOCK_LEN - 1)) != 0 {
        return Err(CryptoError::CiphertextNotBlockAligned {
            length: ciphertext.len(),
            block_size: AES_BLOCK_LEN,
        });
    }

    let decryptor = Aes128CbcDecryptor::new_from_slices(key, &ZERO_IV)
        .expect("AES-128 key and IV lengths are fixed and valid");

    decryptor
        .decrypt_padded_vec::<NoPadding>(ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_key_is_second_half_of_d2_material() {
        let session = ImageSession {
            material: [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f,
            ],
        };

        assert_eq!(
            session.image_key(),
            [
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
                0x1e, 0x1f,
            ]
        );
    }

    #[test]
    fn decrypts_aes128_cbc_with_zero_iv_and_no_padding() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];

        let ciphertext = [
            0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66,
            0xef, 0x97,
        ];

        let plaintext = decrypt_image(&ciphertext, &key).unwrap();

        assert_eq!(
            plaintext,
            [
                0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
                0x17, 0x2a,
            ]
        );
    }

    #[test]
    fn rejects_ciphertext_that_is_not_block_aligned() {
        let key = [0_u8; AES_KEY_LEN];
        let ciphertext = [0_u8; 17];

        assert_eq!(
            decrypt_image(&ciphertext, &key),
            Err(CryptoError::CiphertextNotBlockAligned {
                length: 17,
                block_size: 16,
            })
        );
    }
}
