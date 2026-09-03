//! GF3258 WN2 fresh TGLA template-node encoding.
//!
//! This module implements the recovered fresh-node path used by the Goodix
//! algorithm CommitTemplate flow.
//!
//! The raw algorithm template is produced by `template_persistence.rs`.
//! This module wraps those bytes in the outer TGLA node.
//!
//! Recovered normal-enrollment layout:
//!
//! ```text
//! +0x00      4    "TGLA"
//! +0x04      4    total node size = raw_len + 0x88
//! +0x08      4    CRC-32/MPEG-2 over raw template bytes only
//! +0x0c      4    raw template length
//! +0x10     16    zero
//! +0x20     32    zero
//! +0x40     64    "Milan_v_3.02.00.20\0" + zero padding
//! +0x80      4    zero
//! +0x84      N    raw algorithm template
//! +0x84+N    4    zero allocation tail
//! ```
//!
//! Important recovered facts:
//!
//! - `_LogicAlgConvert2TemplateNode` allocates `raw_len + 0x88` with calloc.
//! - Raw template bytes begin at `+0x84`.
//! - Therefore four zero bytes remain after the raw template.
//! - TGLA `+0x10..+0x1f` is AlgorithmConfig `+0x07..+0x16`.
//!   The GF3258 CreateAlgConfig caller constructs those bytes as zero.
//! - EAadapter_commit_enroll creates a 0xa8-byte zero metadata block.
//!   CommitTemplate special mode `0xf0 == -0x10` copies bytes +2..+33
//!   from that block, therefore TGLA `+0x20..+0x3f` is exactly 32 zeros
//!   on the normal enrollment path.
//! - The version buffer is populated from newTemp +0x88bc and contains
//!   "Milan_v_3.02.00.20\0", with the remaining bytes zero.
//!
//! Vendor GdxEnc sealing is intentionally not implemented here. It is an
//! outer proprietary compatibility layer and is not required for standalone
//! persistence of templates produced and consumed by this driver.

use std::{error::Error, fmt};

use crate::firmware::crc32_mpeg2;

pub const GF3258_TGLA_MAGIC: [u8; 4] = *b"TGLA";

pub const GF3258_TGLA_TOTAL_SIZE_OFFSET: usize = 0x04;
pub const GF3258_TGLA_RAW_CRC_OFFSET: usize = 0x08;
pub const GF3258_TGLA_RAW_LENGTH_OFFSET: usize = 0x0c;

pub const GF3258_TGLA_CONFIG_PREFIX_OFFSET: usize = 0x10;
pub const GF3258_TGLA_CONFIG_PREFIX_BYTES: usize = 16;

pub const GF3258_TGLA_COMMIT_METADATA_OFFSET: usize = 0x20;
pub const GF3258_TGLA_COMMIT_METADATA_BYTES: usize = 32;

pub const GF3258_TGLA_VERSION_OFFSET: usize = 0x40;
pub const GF3258_TGLA_VERSION_BYTES: usize = 64;

pub const GF3258_TGLA_FRESH_FIELD_80_OFFSET: usize = 0x80;
pub const GF3258_TGLA_FRESH_FIELD_80_BYTES: usize = 4;

pub const GF3258_TGLA_RAW_OFFSET: usize = 0x84;

/// Vendor allocation is raw length + 0x88.
///
/// Raw begins at +0x84, leaving four zero bytes after the raw template.
pub const GF3258_TGLA_ALLOCATION_OVERHEAD: usize = 0x88;

pub const GF3258_TGLA_TRAILING_ZERO_BYTES: usize =
    GF3258_TGLA_ALLOCATION_OVERHEAD - GF3258_TGLA_RAW_OFFSET;

pub const GF3258_TGLA_ALGORITHM_VERSION: &[u8; 19] = b"Milan_v_3.02.00.20\0";

pub const GF3258_TEMPLATE_STORAGE_REVISION: &str = "gf3258-tgla-fresh-node";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gf3258TemplateStorageError {
    LengthOverflow {
        raw_length: usize,
    },

    NodeTooShort {
        actual: usize,
    },

    BadMagic {
        actual: [u8; 4],
    },

    TotalSizeMismatch {
        stored: usize,
        actual: usize,
    },

    RawLengthSizeMismatch {
        raw_length: usize,
        expected_total: usize,
        actual_total: usize,
    },

    RawCrcMismatch {
        stored: u32,
        computed: u32,
    },

    NonZeroFreshConfigPrefix {
        offset: usize,
        value: u8,
    },

    NonZeroFreshCommitMetadata {
        offset: usize,
        value: u8,
    },

    VersionBufferMismatch,

    NonZeroFreshField80 {
        offset: usize,
        value: u8,
    },

    NonZeroTrailingSlack {
        offset: usize,
        value: u8,
    },
}

impl fmt::Display for Gf3258TemplateStorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthOverflow { raw_length } => write!(
                f,
                "GF3258 TGLA raw template length {raw_length} cannot be represented by the recovered u32 size fields"
            ),

            Self::NodeTooShort { actual } => write!(
                f,
                "GF3258 TGLA node is too short: {actual} bytes; minimum fresh allocation is 0x{GF3258_TGLA_ALLOCATION_OVERHEAD:x}"
            ),

            Self::BadMagic { actual } => write!(
                f,
                "GF3258 TGLA magic mismatch: got {:02x?}, expected {:02x?}",
                actual, GF3258_TGLA_MAGIC
            ),

            Self::TotalSizeMismatch { stored, actual } => write!(
                f,
                "GF3258 TGLA total-size mismatch: header says {stored} bytes, buffer contains {actual}"
            ),

            Self::RawLengthSizeMismatch {
                raw_length,
                expected_total,
                actual_total,
            } => write!(
                f,
                "GF3258 TGLA raw-length invariant failed: raw length {raw_length} requires total {expected_total}, buffer contains {actual_total}"
            ),

            Self::RawCrcMismatch { stored, computed } => write!(
                f,
                "GF3258 TGLA raw CRC mismatch: stored 0x{stored:08x}, computed 0x{computed:08x}"
            ),

            Self::NonZeroFreshConfigPrefix { offset, value } => write!(
                f,
                "GF3258 fresh TGLA config-prefix byte +0x{offset:02x} is nonzero: 0x{value:02x}"
            ),

            Self::NonZeroFreshCommitMetadata { offset, value } => write!(
                f,
                "GF3258 fresh TGLA commit-metadata byte +0x{offset:02x} is nonzero: 0x{value:02x}"
            ),

            Self::VersionBufferMismatch => write!(
                f,
                "GF3258 fresh TGLA 64-byte algorithm-version buffer does not match Milan_v_3.02.00.20 plus zero padding"
            ),

            Self::NonZeroFreshField80 { offset, value } => write!(
                f,
                "GF3258 fresh TGLA byte +0x{offset:02x} must be zero but is 0x{value:02x}"
            ),

            Self::NonZeroTrailingSlack { offset, value } => write!(
                f,
                "GF3258 fresh TGLA trailing calloc byte +0x{offset:x} must be zero but is 0x{value:02x}"
            ),
        }
    }
}

impl Error for Gf3258TemplateStorageError {}

/// Borrowed view of a validated fresh GF3258 TGLA node.
#[derive(Debug, Clone, Copy)]
pub struct Gf3258FreshTglaNode<'a> {
    bytes: &'a [u8],
    raw_length: usize,
    raw_crc: u32,
}

impl<'a> Gf3258FreshTglaNode<'a> {
    pub fn total_size(&self) -> usize {
        self.bytes.len()
    }

    pub fn raw_length(&self) -> usize {
        self.raw_length
    }

    pub fn raw_crc(&self) -> u32 {
        self.raw_crc
    }

    pub fn config_prefix(&self) -> &'a [u8] {
        &self.bytes[GF3258_TGLA_CONFIG_PREFIX_OFFSET
            ..GF3258_TGLA_CONFIG_PREFIX_OFFSET + GF3258_TGLA_CONFIG_PREFIX_BYTES]
    }

    pub fn commit_metadata(&self) -> &'a [u8] {
        &self.bytes[GF3258_TGLA_COMMIT_METADATA_OFFSET
            ..GF3258_TGLA_COMMIT_METADATA_OFFSET + GF3258_TGLA_COMMIT_METADATA_BYTES]
    }

    pub fn raw_template(&self) -> &'a [u8] {
        &self.bytes[GF3258_TGLA_RAW_OFFSET..GF3258_TGLA_RAW_OFFSET + self.raw_length]
    }

    pub fn trailing_zero_slack(&self) -> &'a [u8] {
        let start = GF3258_TGLA_RAW_OFFSET + self.raw_length;
        &self.bytes[start..]
    }
}

/// Exact recovered fresh-node allocation size.
pub fn gf3258_tgla_total_size(raw_length: usize) -> Result<usize, Gf3258TemplateStorageError> {
    let total = raw_length
        .checked_add(GF3258_TGLA_ALLOCATION_OVERHEAD)
        .ok_or(Gf3258TemplateStorageError::LengthOverflow { raw_length })?;

    if u32::try_from(raw_length).is_err() || u32::try_from(total).is_err() {
        return Err(Gf3258TemplateStorageError::LengthOverflow { raw_length });
    }

    Ok(total)
}

/// Build the exact normal-enrollment fresh TGLA wrapper.
///
/// The normal vendor enrollment path supplies zero for both:
///
/// - TGLA +0x10..+0x1f
/// - TGLA +0x20..+0x3f
///
/// therefore no caller metadata parameter is required.
pub fn gf3258_wrap_fresh_tgla(raw_template: &[u8]) -> Result<Vec<u8>, Gf3258TemplateStorageError> {
    let total_size = gf3258_tgla_total_size(raw_template.len())?;

    let raw_length_u32 = u32::try_from(raw_template.len()).map_err(|_| {
        Gf3258TemplateStorageError::LengthOverflow {
            raw_length: raw_template.len(),
        }
    })?;

    let total_size_u32 =
        u32::try_from(total_size).map_err(|_| Gf3258TemplateStorageError::LengthOverflow {
            raw_length: raw_template.len(),
        })?;

    // Vendor FUN_0010baf0 is calloc(1, size), therefore every field starts
    // zero and only explicitly populated fields need writes here.
    let mut node = vec![0u8; total_size];

    node[0x00..0x04].copy_from_slice(&GF3258_TGLA_MAGIC);

    node[GF3258_TGLA_TOTAL_SIZE_OFFSET..GF3258_TGLA_TOTAL_SIZE_OFFSET + 4]
        .copy_from_slice(&total_size_u32.to_le_bytes());

    let raw_crc = crc32_mpeg2(raw_template);

    node[GF3258_TGLA_RAW_CRC_OFFSET..GF3258_TGLA_RAW_CRC_OFFSET + 4]
        .copy_from_slice(&raw_crc.to_le_bytes());

    node[GF3258_TGLA_RAW_LENGTH_OFFSET..GF3258_TGLA_RAW_LENGTH_OFFSET + 4]
        .copy_from_slice(&raw_length_u32.to_le_bytes());

    // +0x10..+0x1f stays zero.
    //
    // Proven source:
    // AlgorithmConfig input +0x07..+0x16 is never written after the caller
    // zero-initializes its full 24-byte temporary object.

    // +0x20..+0x3f stays zero.
    //
    // Proven source:
    // EAadapter_commit_enroll zero-initializes a 0xa8-byte local block and
    // CommitTemplate copies bytes +2..+33 from that block.

    // Destination is calloc-zeroed. Vendor strcpy writes the NUL-terminated
    // version and leaves the remainder of the 64-byte buffer zero.
    node[GF3258_TGLA_VERSION_OFFSET
        ..GF3258_TGLA_VERSION_OFFSET + GF3258_TGLA_ALGORITHM_VERSION.len()]
        .copy_from_slice(GF3258_TGLA_ALGORITHM_VERSION);

    // +0x80..+0x83 remains zero on the fresh-node path.

    let raw_end = GF3258_TGLA_RAW_OFFSET + raw_template.len();

    node[GF3258_TGLA_RAW_OFFSET..raw_end].copy_from_slice(raw_template);

    // raw_end..raw_end+4 remains zero from calloc.
    debug_assert_eq!(total_size - raw_end, GF3258_TGLA_TRAILING_ZERO_BYTES);

    Ok(node)
}

/// Parse and strictly validate the recovered normal-enrollment fresh TGLA
/// representation.
///
/// This intentionally validates the invariants of the exact normal enrollment
/// path rather than attempting to accept every possible vendor clone/import
/// variant.
pub fn gf3258_parse_fresh_tgla(
    node: &[u8],
) -> Result<Gf3258FreshTglaNode<'_>, Gf3258TemplateStorageError> {
    if node.len() < GF3258_TGLA_ALLOCATION_OVERHEAD {
        return Err(Gf3258TemplateStorageError::NodeTooShort { actual: node.len() });
    }

    let actual_magic: [u8; 4] = node[0x00..0x04].try_into().expect("four-byte magic slice");

    if actual_magic != GF3258_TGLA_MAGIC {
        return Err(Gf3258TemplateStorageError::BadMagic {
            actual: actual_magic,
        });
    }

    let stored_total_size = u32::from_le_bytes(
        node[GF3258_TGLA_TOTAL_SIZE_OFFSET..GF3258_TGLA_TOTAL_SIZE_OFFSET + 4]
            .try_into()
            .expect("four-byte total-size slice"),
    ) as usize;

    if stored_total_size != node.len() {
        return Err(Gf3258TemplateStorageError::TotalSizeMismatch {
            stored: stored_total_size,
            actual: node.len(),
        });
    }

    let stored_raw_crc = u32::from_le_bytes(
        node[GF3258_TGLA_RAW_CRC_OFFSET..GF3258_TGLA_RAW_CRC_OFFSET + 4]
            .try_into()
            .expect("four-byte CRC slice"),
    );

    let raw_length = u32::from_le_bytes(
        node[GF3258_TGLA_RAW_LENGTH_OFFSET..GF3258_TGLA_RAW_LENGTH_OFFSET + 4]
            .try_into()
            .expect("four-byte raw-length slice"),
    ) as usize;

    let expected_total = raw_length
        .checked_add(GF3258_TGLA_ALLOCATION_OVERHEAD)
        .ok_or(Gf3258TemplateStorageError::LengthOverflow { raw_length })?;

    if expected_total != node.len() {
        return Err(Gf3258TemplateStorageError::RawLengthSizeMismatch {
            raw_length,
            expected_total,
            actual_total: node.len(),
        });
    }

    for (relative, &value) in node[GF3258_TGLA_CONFIG_PREFIX_OFFSET
        ..GF3258_TGLA_CONFIG_PREFIX_OFFSET + GF3258_TGLA_CONFIG_PREFIX_BYTES]
        .iter()
        .enumerate()
    {
        if value != 0 {
            return Err(Gf3258TemplateStorageError::NonZeroFreshConfigPrefix {
                offset: GF3258_TGLA_CONFIG_PREFIX_OFFSET + relative,
                value,
            });
        }
    }

    for (relative, &value) in node[GF3258_TGLA_COMMIT_METADATA_OFFSET
        ..GF3258_TGLA_COMMIT_METADATA_OFFSET + GF3258_TGLA_COMMIT_METADATA_BYTES]
        .iter()
        .enumerate()
    {
        if value != 0 {
            return Err(Gf3258TemplateStorageError::NonZeroFreshCommitMetadata {
                offset: GF3258_TGLA_COMMIT_METADATA_OFFSET + relative,
                value,
            });
        }
    }

    let version_buffer =
        &node[GF3258_TGLA_VERSION_OFFSET..GF3258_TGLA_VERSION_OFFSET + GF3258_TGLA_VERSION_BYTES];

    if &version_buffer[..GF3258_TGLA_ALGORITHM_VERSION.len()] != GF3258_TGLA_ALGORITHM_VERSION
        || version_buffer[GF3258_TGLA_ALGORITHM_VERSION.len()..]
            .iter()
            .any(|&byte| byte != 0)
    {
        return Err(Gf3258TemplateStorageError::VersionBufferMismatch);
    }

    for (relative, &value) in node[GF3258_TGLA_FRESH_FIELD_80_OFFSET
        ..GF3258_TGLA_FRESH_FIELD_80_OFFSET + GF3258_TGLA_FRESH_FIELD_80_BYTES]
        .iter()
        .enumerate()
    {
        if value != 0 {
            return Err(Gf3258TemplateStorageError::NonZeroFreshField80 {
                offset: GF3258_TGLA_FRESH_FIELD_80_OFFSET + relative,
                value,
            });
        }
    }

    let raw_end = GF3258_TGLA_RAW_OFFSET + raw_length;
    let raw_template = &node[GF3258_TGLA_RAW_OFFSET..raw_end];

    let computed_raw_crc = crc32_mpeg2(raw_template);

    if stored_raw_crc != computed_raw_crc {
        return Err(Gf3258TemplateStorageError::RawCrcMismatch {
            stored: stored_raw_crc,
            computed: computed_raw_crc,
        });
    }

    for (relative, &value) in node[raw_end..].iter().enumerate() {
        if value != 0 {
            return Err(Gf3258TemplateStorageError::NonZeroTrailingSlack {
                offset: raw_end + relative,
                value,
            });
        }
    }

    debug_assert_eq!(node.len() - raw_end, GF3258_TGLA_TRAILING_ZERO_BYTES);

    Ok(Gf3258FreshTglaNode {
        bytes: node,
        raw_length,
        raw_crc: stored_raw_crc,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_fresh_layout_round_trips() {
        let raw_template = b"\x87\x11\x22\x33\x44\x86\x03\x00\x00\x00abc";

        let node = gf3258_wrap_fresh_tgla(raw_template).unwrap();

        assert_eq!(
            node.len(),
            raw_template.len() + GF3258_TGLA_ALLOCATION_OVERHEAD
        );

        assert_eq!(&node[0x00..0x04], b"TGLA");

        assert_eq!(
            u32::from_le_bytes(node[0x04..0x08].try_into().unwrap()) as usize,
            node.len()
        );

        assert_eq!(
            u32::from_le_bytes(node[0x0c..0x10].try_into().unwrap()) as usize,
            raw_template.len()
        );

        assert_eq!(
            u32::from_le_bytes(node[0x08..0x0c].try_into().unwrap()),
            crc32_mpeg2(raw_template)
        );

        assert_eq!(&node[0x10..0x20], &[0u8; 16]);
        assert_eq!(&node[0x20..0x40], &[0u8; 32]);

        assert_eq!(
            &node[0x40..0x40 + GF3258_TGLA_ALGORITHM_VERSION.len()],
            GF3258_TGLA_ALGORITHM_VERSION
        );

        assert!(
            node[0x40 + GF3258_TGLA_ALGORITHM_VERSION.len()..0x80]
                .iter()
                .all(|&byte| byte == 0)
        );

        assert_eq!(&node[0x80..0x84], &[0u8; 4]);

        assert_eq!(
            &node[GF3258_TGLA_RAW_OFFSET..GF3258_TGLA_RAW_OFFSET + raw_template.len()],
            raw_template
        );

        assert_eq!(
            &node[GF3258_TGLA_RAW_OFFSET + raw_template.len()..],
            &[0u8; 4]
        );

        let parsed = gf3258_parse_fresh_tgla(&node).unwrap();

        assert_eq!(parsed.total_size(), node.len());
        assert_eq!(parsed.raw_length(), raw_template.len());
        assert_eq!(parsed.raw_crc(), crc32_mpeg2(raw_template));
        assert_eq!(parsed.config_prefix(), &[0u8; 16]);
        assert_eq!(parsed.commit_metadata(), &[0u8; 32]);
        assert_eq!(parsed.raw_template(), raw_template);
        assert_eq!(parsed.trailing_zero_slack(), &[0u8; 4]);
    }

    #[test]
    fn latest_39809_byte_raw_template_has_exact_recovered_total_size() {
        // Latest successful standalone fixture:
        //
        // raw N = 39809 = 0x9b81
        // TGLA allocation = N + 0x88
        //                 = 39945 = 0x9c09
        let raw_template = vec![0u8; 39_809];

        let node = gf3258_wrap_fresh_tgla(&raw_template).unwrap();

        assert_eq!(node.len(), 39_945);

        assert_eq!(
            u32::from_le_bytes(node[0x04..0x08].try_into().unwrap()),
            0x0000_9c09
        );

        assert_eq!(
            u32::from_le_bytes(node[0x0c..0x10].try_into().unwrap()),
            0x0000_9b81
        );

        assert_eq!(&node[0x10..0x20], &[0u8; 16]);
        assert_eq!(&node[0x20..0x40], &[0u8; 32]);
        assert_eq!(&node[node.len() - 4..], &[0u8; 4]);
    }

    #[test]
    fn tampering_raw_template_is_detected_by_tgla_crc() {
        let raw_template = b"raw-template";

        let mut node = gf3258_wrap_fresh_tgla(raw_template).unwrap();

        node[GF3258_TGLA_RAW_OFFSET] ^= 0x80;

        let error = gf3258_parse_fresh_tgla(&node).unwrap_err();

        assert!(matches!(
            error,
            Gf3258TemplateStorageError::RawCrcMismatch { .. }
        ));
    }

    #[test]
    fn nonzero_fresh_config_prefix_is_rejected() {
        let raw_template = b"raw-template";

        let mut node = gf3258_wrap_fresh_tgla(raw_template).unwrap();

        node[GF3258_TGLA_CONFIG_PREFIX_OFFSET + 7] = 1;

        let error = gf3258_parse_fresh_tgla(&node).unwrap_err();

        assert_eq!(
            error,
            Gf3258TemplateStorageError::NonZeroFreshConfigPrefix {
                offset: GF3258_TGLA_CONFIG_PREFIX_OFFSET + 7,
                value: 1,
            }
        );
    }

    #[test]
    fn nonzero_trailing_calloc_slack_is_rejected() {
        let raw_template = b"raw-template";

        let mut node = gf3258_wrap_fresh_tgla(raw_template).unwrap();

        let last = node.len() - 1;
        node[last] = 0x5a;

        let error = gf3258_parse_fresh_tgla(&node).unwrap_err();

        assert_eq!(
            error,
            Gf3258TemplateStorageError::NonZeroTrailingSlack {
                offset: last,
                value: 0x5a,
            }
        );
    }
}
