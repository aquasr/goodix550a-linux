//! Strict semantic decoder for persisted GF3258 type-0x18 templates.
//!
//! This module decodes the exact raw 0x87/0x86 envelope produced by the
//! recovered EncodeFingerTemplate path and the normal fresh TGLA wrapper.
//! The original pre-serialization point geometry is not invertible, but
//! DecodeFingerTemplate proves the exact quantized geometry that the vendor
//! reconstructs for matcher use after loading a type-0x18 template.

use std::{error::Error, fmt};

use crate::enrollment_add::Gf3258EnrollmentTemplateCore;
use crate::feature::GF3258_PI_Q12;
use crate::registration::{
    GF3258_QUARTER_VALIDITY_CELLS, GF3258_REGISTRATION_PACKED_BYTES,
    gf3258_expand_quarter_validity, gf3258_pack_active_validity,
};
use crate::template_persistence::{
    GF3258_FIXED_PACKED_SIZE, GF3258_PERSISTENT_POINT_BYTES, GF3258_PERSISTENT_RELATION_BYTES,
    GF3258_TEMPLATE_DEFAULT_SAMPLE_CAPACITY, GF3258_TEMPLATE_HEIGHT,
    GF3258_TEMPLATE_POINT_CAPACITY, GF3258_TEMPLATE_TYPE, GF3258_TEMPLATE_WIDTH,
    gf3258_raw_template_crc32,
};
use crate::template_storage::{
    GF3258_TGLA_ALGORITHM_VERSION, Gf3258TemplateStorageError, gf3258_parse_fresh_tgla,
};

const TOP_TAGS: [u8; 15] = [
    0x81, 0x88, 0x89, 0x98, 0x9a, 0x9b, 0x91, 0x97, 0x92, 0x9e, 0x9f, 0x9c, 0x9d, 0xfa, 0xfb,
];
const TEMPLATE_00: u32 = 0x002e_14f4;
const TEMPLATE_04: u32 = 0x002d_f160;
const QUARTER_VALIDITY_PACKED_BYTES: usize = GF3258_QUARTER_VALIDITY_CELLS / 8;
const SECTION_94_ACTIVE_SLOT_BYTES: usize = GF3258_TEMPLATE_DEFAULT_SAMPLE_CAPACITY * 4;
const SECTION_94_VERSION_BYTES: usize = 64;
const SECTION_94_ZERO_BLOCK_BYTES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gf3258PersistedTemplateHeader {
    pub sample_count: usize,
    pub configured_max_samples: usize,
    /// Vendor template+0x2c / tag 0x92 triangular relation-table cursor.
    pub relation_table_cursor: usize,
    pub max_point_count: usize,
    pub point_capacity: usize,
}

/// Exact information retained by one 32-byte type-0x18 persistent point.
///
/// `geometry_word` is not an invertible serialization of the original
/// FeaturePoint60 x/y/orientation. Use [`Gf3258PersistedPoint::matcher_geometry`]
/// for the exact quantized geometry reconstructed by DecodeFingerTemplate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf3258PersistedPoint {
    pub geometry_word: u32,
    /// Exact inverse of the recovered bf5d0 nibble permutation.
    pub descriptor_10_1f: [u8; 16],
    pub hash20: u32,
    pub hash28: u32,
    pub hash2c: u32,
}

/// Geometry written into FeaturePoint60 by DecodeFingerTemplate for one
/// persisted type-0x18 point.
///
/// These values are the vendor's matcher-facing reconstruction, not the
/// original pre-serialization Q8/Q12 values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf3258PersistedMatcherGeometry {
    pub x_q8: u16,
    pub y_q8: u16,
    pub orientation_q12: u16,
}

impl Gf3258PersistedPoint {
    pub fn matcher_geometry(self) -> Gf3258PersistedMatcherGeometry {
        gf3258_decode_persistent_geometry_word(self.geometry_word)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gf3258PersistedSample {
    pub primary_registration_map: [u8; GF3258_REGISTRATION_PACKED_BYTES],
    pub secondary_registration_map: Option<[u8; GF3258_REGISTRATION_PACKED_BYTES]>,
    pub low_threshold_registration_map: Option<[u8; GF3258_REGISTRATION_PACKED_BYTES]>,
    pub quarter_validity_packed: [u8; QUARTER_VALIDITY_PACKED_BYTES],
    /// Deterministically reconstructed from the persisted 20x16 quarter mask.
    pub active_validity_packed: [u8; GF3258_REGISTRATION_PACKED_BYTES],
    pub points: Vec<Gf3258PersistedPoint>,
    pub canonical_member: bool,
    pub relation_checkpoint: i32,
    pub scalar_108: i32,
    pub c2d40_param3: i32,
    pub c2d40_param4: i32,
    pub status_114: i32,
    pub scalar_118: i32,
    pub sample_index: i32,
    pub scalar_120: i32,
    pub scalar_124: i32,
    pub scalar_13c: i32,
    pub embedded_state_140: Option<i32>,
}

impl Gf3258PersistedSample {
    /// Feature+0x108 after DecodeFingerTemplate's post-load normalization.
    ///
    /// For non-empty GF3258 samples the vendor clamps a stored split at or
    /// beyond point_count to point_count - 1 before rewriting per-point
    /// polarity. Decoded templates already reject negative stored splits.
    pub fn matcher_polarity_split(&self) -> usize {
        if self.points.is_empty() {
            return 0;
        }
        usize::try_from(self.scalar_108)
            .unwrap_or(0)
            .min(self.points.len() - 1)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf3258PersistedRelation {
    pub relation_index: usize,
    pub high: usize,
    pub low: usize,
    pub relation_value: i32,
    /// Q8 affine `[a,b,tx,c,d,ty]`, canonical persisted direction high -> low.
    pub transform_higher_to_lower: [i32; 6],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf3258PersistedGraphState {
    pub canonical_anchor: Option<usize>,
    pub canonical_established: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gf3258PersistedStorageState {
    pub active_slots: [i32; GF3258_TEMPLATE_DEFAULT_SAMPLE_CAPACITY],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gf3258PersistedTemplate {
    pub raw_crc32: u32,
    pub header: Gf3258PersistedTemplateHeader,
    pub samples: Vec<Gf3258PersistedSample>,
    pub relations: Vec<Gf3258PersistedRelation>,
    pub graph: Gf3258PersistedGraphState,
    pub storage: Gf3258PersistedStorageState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gf3258TemplateDecodeError {
    Storage(Gf3258TemplateStorageError),
    RawTooShort {
        actual: usize,
    },
    Truncated {
        context: &'static str,
        offset: usize,
        needed: usize,
        remaining: usize,
    },
    UnexpectedTag {
        context: &'static str,
        offset: usize,
        expected: u8,
        actual: u8,
    },
    RawPayloadLengthMismatch {
        stored: usize,
        actual: usize,
    },
    RawCrcMismatch {
        stored: u32,
        computed: u32,
    },
    ContainerLengthMismatch {
        context: &'static str,
        declared: usize,
        consumed: usize,
    },
    UnexpectedScalar {
        tag: u8,
        expected: u32,
        actual: u32,
    },
    InvalidValue {
        field: &'static str,
        value: i64,
    },
    BlobLengthMismatch {
        tag: u8,
        expected: usize,
        actual: usize,
    },
    PointBlobLengthMismatch {
        sample: usize,
        point_count: usize,
        actual: usize,
    },
    SampleIndexMismatch {
        expected: usize,
        actual: i32,
    },
    RelationCheckpointMismatch {
        sample: usize,
        expected: i32,
        actual: i32,
    },
    RelationCursorMismatch {
        sample_count: usize,
        expected: usize,
        actual: usize,
    },
    RelationIndexOutOfRange {
        index: usize,
        sample_count: usize,
    },
    DuplicateRelationIndex {
        index: usize,
    },
    NegativePersistedRelation {
        index: usize,
        value: i32,
    },
    InvalidGraphAnchor {
        anchor: i32,
        sample_count: usize,
    },
    ActiveSlotMismatch {
        slot: usize,
        expected: i32,
        actual: i32,
    },
    VersionBufferMismatch,
    NonZeroReservedBlob {
        tag: u8,
        index: usize,
        value: u8,
    },
    PackedSizeMismatch {
        expected: usize,
        actual: usize,
    },
}

impl fmt::Display for Gf3258TemplateDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(error) => write!(f, "GF3258 TGLA validation failed: {error}"),
            Self::RawTooShort { actual } => {
                write!(f, "GF3258 raw template is too short: {actual} bytes")
            }
            Self::Truncated {
                context,
                offset,
                needed,
                remaining,
            } => write!(
                f,
                "GF3258 {context} is truncated at +0x{offset:x}: need {needed} bytes, have {remaining}"
            ),
            Self::UnexpectedTag {
                context,
                offset,
                expected,
                actual,
            } => write!(
                f,
                "GF3258 {context} tag mismatch at +0x{offset:x}: expected 0x{expected:02x}, got 0x{actual:02x}"
            ),
            Self::RawPayloadLengthMismatch { stored, actual } => write!(
                f,
                "GF3258 raw payload length mismatch: header says {stored} bytes, buffer contains {actual}"
            ),
            Self::RawCrcMismatch { stored, computed } => write!(
                f,
                "GF3258 raw-template CRC mismatch: stored 0x{stored:08x}, computed 0x{computed:08x}"
            ),
            Self::ContainerLengthMismatch {
                context,
                declared,
                consumed,
            } => write!(
                f,
                "GF3258 {context} length mismatch: declared {declared} bytes, consumed {consumed}"
            ),
            Self::UnexpectedScalar {
                tag,
                expected,
                actual,
            } => write!(
                f,
                "GF3258 scalar 0x{tag:02x} mismatch: expected 0x{expected:08x}, got 0x{actual:08x}"
            ),
            Self::InvalidValue { field, value } => {
                write!(f, "GF3258 persisted {field} has invalid value {value}")
            }
            Self::BlobLengthMismatch {
                tag,
                expected,
                actual,
            } => write!(
                f,
                "GF3258 blob 0x{tag:02x} length mismatch: expected {expected}, got {actual}"
            ),
            Self::PointBlobLengthMismatch {
                sample,
                point_count,
                actual,
            } => write!(
                f,
                "GF3258 sample {sample} point blob is {actual} bytes for {point_count} points"
            ),
            Self::SampleIndexMismatch { expected, actual } => write!(
                f,
                "GF3258 sample-index scalar mismatch: expected {expected}, got {actual}"
            ),
            Self::RelationCheckpointMismatch {
                sample,
                expected,
                actual,
            } => write!(
                f,
                "GF3258 sample {sample} relation checkpoint mismatch: expected {expected}, got {actual}"
            ),
            Self::RelationCursorMismatch {
                sample_count,
                expected,
                actual,
            } => write!(
                f,
                "GF3258 relation-table cursor mismatch for {sample_count} samples: expected {expected}, got {actual}"
            ),
            Self::RelationIndexOutOfRange {
                index,
                sample_count,
            } => write!(
                f,
                "GF3258 persisted relation index {index} is outside the triangular table for {sample_count} samples"
            ),
            Self::DuplicateRelationIndex { index } => {
                write!(
                    f,
                    "GF3258 persisted relation index {index} appears more than once"
                )
            }
            Self::NegativePersistedRelation { index, value } => write!(
                f,
                "GF3258 emitted relation {index} has negative value {value}"
            ),
            Self::InvalidGraphAnchor {
                anchor,
                sample_count,
            } => write!(
                f,
                "GF3258 canonical anchor {anchor} is invalid for {sample_count} samples"
            ),
            Self::ActiveSlotMismatch {
                slot,
                expected,
                actual,
            } => write!(
                f,
                "GF3258 active-slot table mismatch at slot {slot}: expected {expected}, got {actual}"
            ),
            Self::VersionBufferMismatch => write!(
                f,
                "GF3258 persisted 0xa3 algorithm-version buffer is not the recovered Milan version plus zero padding"
            ),
            Self::NonZeroReservedBlob { tag, index, value } => write!(
                f,
                "GF3258 reserved blob 0x{tag:02x} byte {index} is nonzero: 0x{value:02x}"
            ),
            Self::PackedSizeMismatch { expected, actual } => write!(
                f,
                "GF3258 raw-template size grammar mismatch: expected {expected}, got {actual}"
            ),
        }
    }
}

impl Error for Gf3258TemplateDecodeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Storage(error) => Some(error),
            _ => None,
        }
    }
}

impl From<Gf3258TemplateStorageError> for Gf3258TemplateDecodeError {
    fn from(value: Gf3258TemplateStorageError) -> Self {
        Self::Storage(value)
    }
}

#[derive(Clone, Copy)]
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
    base: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], base: usize) -> Self {
        Self {
            bytes,
            pos: 0,
            base,
        }
    }

    fn absolute_offset(&self) -> usize {
        self.base + self.pos
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    fn peek(&self, context: &'static str) -> Result<u8, Gf3258TemplateDecodeError> {
        self.bytes
            .get(self.pos)
            .copied()
            .ok_or(Gf3258TemplateDecodeError::Truncated {
                context,
                offset: self.absolute_offset(),
                needed: 1,
                remaining: 0,
            })
    }

    fn take(
        &mut self,
        count: usize,
        context: &'static str,
    ) -> Result<&'a [u8], Gf3258TemplateDecodeError> {
        let remaining = self.remaining();
        if count > remaining {
            return Err(Gf3258TemplateDecodeError::Truncated {
                context,
                offset: self.absolute_offset(),
                needed: count,
                remaining,
            });
        }
        let start = self.pos;
        self.pos += count;
        Ok(&self.bytes[start..start + count])
    }

    fn expect_tag(
        &mut self,
        expected: u8,
        context: &'static str,
    ) -> Result<(), Gf3258TemplateDecodeError> {
        let offset = self.absolute_offset();
        let actual = self.take(1, context)?[0];
        if actual != expected {
            return Err(Gf3258TemplateDecodeError::UnexpectedTag {
                context,
                offset,
                expected,
                actual,
            });
        }
        Ok(())
    }

    fn u32(&mut self, context: &'static str) -> Result<u32, Gf3258TemplateDecodeError> {
        Ok(u32::from_le_bytes(
            self.take(4, context)?.try_into().expect("four-byte slice"),
        ))
    }

    fn scalar(&mut self, tag: u8, context: &'static str) -> Result<u32, Gf3258TemplateDecodeError> {
        self.expect_tag(tag, context)?;
        self.u32(context)
    }

    fn blob(
        &mut self,
        tag: u8,
        context: &'static str,
    ) -> Result<&'a [u8], Gf3258TemplateDecodeError> {
        self.expect_tag(tag, context)?;
        let length = self.u32(context)? as usize;
        self.take(length, context)
    }
}

fn require_scalar(tag: u8, actual: u32, expected: u32) -> Result<(), Gf3258TemplateDecodeError> {
    if actual != expected {
        return Err(Gf3258TemplateDecodeError::UnexpectedScalar {
            tag,
            expected,
            actual,
        });
    }
    Ok(())
}

fn signed(value: u32) -> i32 {
    value as i32
}

fn copy_array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    bytes.try_into().expect("validated fixed-size slice")
}

/// Reproduce DecodeFingerTemplate's type-0x18 geometry import exactly.
///
/// The first four persisted bytes are lossy. This function does not recover
/// the original source point; it produces the quantized x/y/orientation that
/// the vendor writes into the loaded FeaturePoint60 before matcher geometry.
///
/// Recovered operations:
/// - x = `(word >> 16) & 0xfff0`;
/// - y = `(word & 0x000f_ff00) >> 4`;
/// - orientation is rebuilt from the signed low byte at Q8 precision;
/// - a negative rebuilt orientation is normalized by adding pi (`0x3244`).
pub fn gf3258_decode_persistent_geometry_word(
    geometry_word: u32,
) -> Gf3258PersistedMatcherGeometry {
    let x_q8 = ((geometry_word >> 16) as u16) & 0xfff0;
    let y_q8 = ((geometry_word & 0x000f_ff00) >> 4) as u16;

    let shifted_low_byte = ((geometry_word << 8) as u16) as i16;
    let mut orientation = if (geometry_word as u8 as i8) < 0 {
        (-(i32::from(shifted_low_byte) - 0x8000)) as i16
    } else {
        shifted_low_byte
    };
    if orientation < 0 {
        orientation = orientation.wrapping_add(GF3258_PI_Q12 as i16);
    }

    Gf3258PersistedMatcherGeometry {
        x_q8,
        y_q8,
        orientation_q12: orientation as u16,
    }
}

/// Exact inverse of the descriptor-only bf5d0 nibble permutation plus exact
/// extraction of the fields that the persistent point actually contains.
pub fn gf3258_decode_persistent_point(
    raw: &[u8; GF3258_PERSISTENT_POINT_BYTES],
) -> Gf3258PersistedPoint {
    let geometry_word = u32::from_le_bytes(raw[0..4].try_into().expect("geometry word"));
    let encoded_descriptor = &raw[4..20];
    const SWAP: [bool; 8] = [false, true, true, false, true, false, false, true];
    let mut descriptor_10_1f = [0u8; 16];

    for k in 0..8 {
        let first = encoded_descriptor[2 * k];
        let second = encoded_descriptor[2 * k + 1];
        let (p, q) = if SWAP[k] {
            (second, first)
        } else {
            (first, second)
        };
        descriptor_10_1f[k] = (q & 0xf0) | (p & 0x0f);
        descriptor_10_1f[8 + k] = (p & 0xf0) | (q & 0x0f);
    }

    Gf3258PersistedPoint {
        geometry_word,
        descriptor_10_1f,
        hash20: u32::from_le_bytes(raw[20..24].try_into().expect("hash20")),
        hash28: u32::from_le_bytes(raw[24..28].try_into().expect("hash28")),
        hash2c: u32::from_le_bytes(raw[28..32].try_into().expect("hash2c")),
    }
}

fn parse_registration_mat(
    reader: &mut Reader<'_>,
    tag: u8,
    context: &'static str,
) -> Result<[u8; GF3258_REGISTRATION_PACKED_BYTES], Gf3258TemplateDecodeError> {
    reader.expect_tag(tag, context)?;
    let payload_len = reader.u32(context)? as usize;
    let payload_start = reader.absolute_offset();
    let payload = reader.take(payload_len, context)?;
    let mut nested = Reader::new(payload, payload_start);

    require_scalar(0xc1, nested.scalar(0xc1, context)?, 40)?;
    require_scalar(0xc2, nested.scalar(0xc2, context)?, 32)?;
    require_scalar(0xc3, nested.scalar(0xc3, context)?, 0xffff_ffff)?;
    require_scalar(0xc4, nested.scalar(0xc4, context)?, 8)?;
    let data = nested.blob(0xc5, context)?;
    if data.len() != GF3258_REGISTRATION_PACKED_BYTES {
        return Err(Gf3258TemplateDecodeError::BlobLengthMismatch {
            tag: 0xc5,
            expected: GF3258_REGISTRATION_PACKED_BYTES,
            actual: data.len(),
        });
    }
    if nested.remaining() != 0 {
        return Err(Gf3258TemplateDecodeError::ContainerLengthMismatch {
            context,
            declared: payload_len,
            consumed: nested.pos,
        });
    }
    Ok(copy_array(data))
}

fn unpack_quarter_validity(
    packed: &[u8; QUARTER_VALIDITY_PACKED_BYTES],
) -> [u8; GF3258_QUARTER_VALIDITY_CELLS] {
    let mut quarter = [0u8; GF3258_QUARTER_VALIDITY_CELLS];
    for index in 0..GF3258_QUARTER_VALIDITY_CELLS {
        quarter[index] = (packed[index >> 3] >> (index & 7)) & 1;
    }
    quarter
}

fn parse_sample(
    reader: &mut Reader<'_>,
    sample_index: usize,
) -> Result<(Gf3258PersistedSample, usize), Gf3258TemplateDecodeError> {
    let envelope_start = reader.absolute_offset();
    reader.expect_tag(0x95, "sample envelope")?;
    let payload_len = reader.u32("sample envelope")? as usize;
    let payload_start = reader.absolute_offset();
    let payload = reader.take(payload_len, "sample payload")?;
    let mut sample = Reader::new(payload, payload_start);

    let primary_registration_map = parse_registration_mat(&mut sample, 0xb2, "primary map")?;
    let secondary_registration_map = if sample.peek("sample payload")? == 0xcf {
        Some(parse_registration_mat(&mut sample, 0xcf, "secondary map")?)
    } else {
        None
    };

    let quarter_blob = sample.blob(0xce, "quarter validity")?;
    if quarter_blob.len() != QUARTER_VALIDITY_PACKED_BYTES {
        return Err(Gf3258TemplateDecodeError::BlobLengthMismatch {
            tag: 0xce,
            expected: QUARTER_VALIDITY_PACKED_BYTES,
            actual: quarter_blob.len(),
        });
    }
    let quarter_validity_packed = copy_array(quarter_blob);

    let low_threshold_registration_map = if sample.peek("sample payload")? == 0xcd {
        Some(parse_registration_mat(
            &mut sample,
            0xcd,
            "low-threshold map",
        )?)
    } else {
        None
    };

    let point_count = sample.scalar(0xb3, "sample point count")? as usize;
    if point_count > GF3258_TEMPLATE_POINT_CAPACITY {
        return Err(Gf3258TemplateDecodeError::InvalidValue {
            field: "point count",
            value: point_count as i64,
        });
    }

    let points_blob = sample.blob(0xb4, "persistent points")?;
    let expected_point_bytes = point_count * GF3258_PERSISTENT_POINT_BYTES;
    if points_blob.len() != expected_point_bytes {
        return Err(Gf3258TemplateDecodeError::PointBlobLengthMismatch {
            sample: sample_index,
            point_count,
            actual: points_blob.len(),
        });
    }
    let points = points_blob
        .chunks_exact(GF3258_PERSISTENT_POINT_BYTES)
        .map(|chunk| {
            let raw: &[u8; GF3258_PERSISTENT_POINT_BYTES] =
                chunk.try_into().expect("exact point chunk");
            gf3258_decode_persistent_point(raw)
        })
        .collect();

    let canonical_raw = sample.scalar(0xb5, "canonical-member scalar")?;
    let canonical_member = match canonical_raw {
        0 => false,
        1 => true,
        _ => {
            return Err(Gf3258TemplateDecodeError::InvalidValue {
                field: "canonical-member flag",
                value: i64::from(canonical_raw),
            });
        }
    };

    let relation_checkpoint = signed(sample.scalar(0xb6, "relation checkpoint")?);
    let expected_checkpoint =
        Gf3258EnrollmentTemplateCore::relation_table_cursor_for_sample_count(sample_index) as i32;
    if relation_checkpoint != expected_checkpoint {
        return Err(Gf3258TemplateDecodeError::RelationCheckpointMismatch {
            sample: sample_index,
            expected: expected_checkpoint,
            actual: relation_checkpoint,
        });
    }

    let scalar_108 = signed(sample.scalar(0xb7, "sample scalar 0x108")?);
    if scalar_108 < 0 || scalar_108 as usize > point_count {
        return Err(Gf3258TemplateDecodeError::InvalidValue {
            field: "sample scalar 0x108 / polarity split",
            value: i64::from(scalar_108),
        });
    }
    let c2d40_param3 = signed(sample.scalar(0xb8, "c2d40 parameter 3")?);
    let c2d40_param4 = signed(sample.scalar(0xb9, "c2d40 parameter 4")?);
    let status_114 = signed(sample.scalar(0xba, "sample status")?);
    let scalar_118 = signed(sample.scalar(0xbb, "sample scalar 0x118")?);
    let decoded_index = signed(sample.scalar(0xbc, "sample index")?);
    if decoded_index != sample_index as i32 {
        return Err(Gf3258TemplateDecodeError::SampleIndexMismatch {
            expected: sample_index,
            actual: decoded_index,
        });
    }
    let scalar_120 = signed(sample.scalar(0xbd, "sample scalar 0x120")?);
    let scalar_124 = signed(sample.scalar(0xbe, "sample scalar 0x124")?);
    let scalar_13c = signed(sample.scalar(0xc0, "sample scalar 0x13c")?);
    let embedded_state_140 = if sample.remaining() != 0 {
        if sample.peek("sample optional scalar")? != 0xc7 {
            let actual = sample.peek("sample optional scalar")?;
            return Err(Gf3258TemplateDecodeError::UnexpectedTag {
                context: "sample optional scalar",
                offset: sample.absolute_offset(),
                expected: 0xc7,
                actual,
            });
        }
        let value = signed(sample.scalar(0xc7, "embedded state 0x140")?);
        if value == 0 {
            return Err(Gf3258TemplateDecodeError::InvalidValue {
                field: "embedded state 0x140",
                value: 0,
            });
        }
        Some(value)
    } else {
        None
    };

    if sample.remaining() != 0 {
        return Err(Gf3258TemplateDecodeError::ContainerLengthMismatch {
            context: "sample payload",
            declared: payload_len,
            consumed: sample.pos,
        });
    }

    let quarter = unpack_quarter_validity(&quarter_validity_packed);
    let active = gf3258_expand_quarter_validity(&quarter);
    let active_validity_packed = gf3258_pack_active_validity(&active);

    Ok((
        Gf3258PersistedSample {
            primary_registration_map,
            secondary_registration_map,
            low_threshold_registration_map,
            quarter_validity_packed,
            active_validity_packed,
            points,
            canonical_member,
            relation_checkpoint,
            scalar_108,
            c2d40_param3,
            c2d40_param4,
            status_114,
            scalar_118,
            sample_index: decoded_index,
            scalar_120,
            scalar_124,
            scalar_13c,
            embedded_state_140,
        },
        reader.absolute_offset() - envelope_start,
    ))
}

fn relation_indices(index: usize, sample_count: usize) -> Option<(usize, usize)> {
    for high in 1..sample_count {
        let base = high * (high - 1) / 2;
        let next = (high + 1) * high / 2;
        if index >= base && index < next {
            return Some((high, index - base));
        }
    }
    None
}

fn parse_relation(
    reader: &mut Reader<'_>,
    sample_count: usize,
) -> Result<Gf3258PersistedRelation, Gf3258TemplateDecodeError> {
    reader.expect_tag(0x96, "relation envelope")?;
    let payload_len = reader.u32("relation envelope")? as usize;
    let payload_start = reader.absolute_offset();
    let payload = reader.take(payload_len, "relation payload")?;
    let mut relation = Reader::new(payload, payload_start);

    let relation_index = relation.scalar(0xe3, "relation index")? as usize;
    let relation_value = signed(relation.scalar(0xe1, "relation value")?);
    if relation_value < 0 {
        return Err(Gf3258TemplateDecodeError::NegativePersistedRelation {
            index: relation_index,
            value: relation_value,
        });
    }

    let mut transform_higher_to_lower = [0i32; 6];
    for (slot, tag) in (0xe4u8..=0xe9).enumerate() {
        transform_higher_to_lower[slot] = signed(relation.scalar(tag, "relation affine")?);
    }
    if relation.remaining() != 0 {
        return Err(Gf3258TemplateDecodeError::ContainerLengthMismatch {
            context: "relation payload",
            declared: payload_len,
            consumed: relation.pos,
        });
    }

    let Some((high, low)) = relation_indices(relation_index, sample_count) else {
        return Err(Gf3258TemplateDecodeError::RelationIndexOutOfRange {
            index: relation_index,
            sample_count,
        });
    };

    Ok(Gf3258PersistedRelation {
        relation_index,
        high,
        low,
        relation_value,
        transform_higher_to_lower,
    })
}

fn parse_section_93(
    reader: &mut Reader<'_>,
    sample_count: usize,
) -> Result<Gf3258PersistedGraphState, Gf3258TemplateDecodeError> {
    reader.expect_tag(0x93, "section 0x93")?;
    let payload_len = reader.u32("section 0x93")? as usize;
    let payload_start = reader.absolute_offset();
    let payload = reader.take(payload_len, "section 0x93 payload")?;
    let mut section = Reader::new(payload, payload_start);

    let anchor_raw = signed(section.scalar(0xf2, "canonical anchor")?);
    require_scalar(0xf3, section.scalar(0xf3, "section 0x93")?, 0xffff_ffff)?;
    require_scalar(0xf4, section.scalar(0xf4, "section 0x93")?, 0xffff_ffff)?;
    let established_raw = section.scalar(0xf5, "canonical-established flag")?;
    let canonical_established = match established_raw {
        0 => false,
        1 => true,
        _ => {
            return Err(Gf3258TemplateDecodeError::InvalidValue {
                field: "canonical-established flag",
                value: i64::from(established_raw),
            });
        }
    };
    if section.remaining() != 0 {
        return Err(Gf3258TemplateDecodeError::ContainerLengthMismatch {
            context: "section 0x93 payload",
            declared: payload_len,
            consumed: section.pos,
        });
    }

    let canonical_anchor = if canonical_established {
        if anchor_raw < 0 || anchor_raw as usize >= sample_count {
            return Err(Gf3258TemplateDecodeError::InvalidGraphAnchor {
                anchor: anchor_raw,
                sample_count,
            });
        }
        Some(anchor_raw as usize)
    } else {
        if anchor_raw != -1 {
            return Err(Gf3258TemplateDecodeError::InvalidGraphAnchor {
                anchor: anchor_raw,
                sample_count,
            });
        }
        None
    };

    Ok(Gf3258PersistedGraphState {
        canonical_anchor,
        canonical_established,
    })
}

fn parse_section_94(
    reader: &mut Reader<'_>,
    sample_count: usize,
) -> Result<Gf3258PersistedStorageState, Gf3258TemplateDecodeError> {
    reader.expect_tag(0x94, "section 0x94")?;
    let payload_len = reader.u32("section 0x94")? as usize;
    let payload_start = reader.absolute_offset();
    let payload = reader.take(payload_len, "section 0x94 payload")?;
    let mut section = Reader::new(payload, payload_start);

    let active_blob = section.blob(0xa1, "active-slot table")?;
    if active_blob.len() != SECTION_94_ACTIVE_SLOT_BYTES {
        return Err(Gf3258TemplateDecodeError::BlobLengthMismatch {
            tag: 0xa1,
            expected: SECTION_94_ACTIVE_SLOT_BYTES,
            actual: active_blob.len(),
        });
    }
    let mut active_slots = [-1i32; GF3258_TEMPLATE_DEFAULT_SAMPLE_CAPACITY];
    for (slot, chunk) in active_blob.chunks_exact(4).enumerate() {
        let actual = i32::from_le_bytes(chunk.try_into().expect("active-slot i32"));
        let expected = if slot < sample_count { slot as i32 } else { -1 };
        if actual != expected {
            return Err(Gf3258TemplateDecodeError::ActiveSlotMismatch {
                slot,
                expected,
                actual,
            });
        }
        active_slots[slot] = actual;
    }

    require_scalar(0xa2, section.scalar(0xa2, "section 0x94")?, 0xffff_ffff)?;
    let version = section.blob(0xa3, "algorithm-version buffer")?;
    if version.len() != SECTION_94_VERSION_BYTES {
        return Err(Gf3258TemplateDecodeError::BlobLengthMismatch {
            tag: 0xa3,
            expected: SECTION_94_VERSION_BYTES,
            actual: version.len(),
        });
    }
    if &version[..GF3258_TGLA_ALGORITHM_VERSION.len()] != GF3258_TGLA_ALGORITHM_VERSION
        || version[GF3258_TGLA_ALGORITHM_VERSION.len()..]
            .iter()
            .any(|&byte| byte != 0)
    {
        return Err(Gf3258TemplateDecodeError::VersionBufferMismatch);
    }

    let zero_block = section.blob(0xa4, "section 0x94 zero block")?;
    if zero_block.len() != SECTION_94_ZERO_BLOCK_BYTES {
        return Err(Gf3258TemplateDecodeError::BlobLengthMismatch {
            tag: 0xa4,
            expected: SECTION_94_ZERO_BLOCK_BYTES,
            actual: zero_block.len(),
        });
    }
    if let Some((index, &value)) = zero_block
        .iter()
        .enumerate()
        .find(|(_, value)| **value != 0)
    {
        return Err(Gf3258TemplateDecodeError::NonZeroReservedBlob {
            tag: 0xa4,
            index,
            value,
        });
    }

    for tag in 0xa5u8..=0xa8 {
        require_scalar(tag, section.scalar(tag, "section 0x94")?, 0)?;
    }
    if section.remaining() != 0 {
        return Err(Gf3258TemplateDecodeError::ContainerLengthMismatch {
            context: "section 0x94 payload",
            declared: payload_len,
            consumed: section.pos,
        });
    }

    Ok(Gf3258PersistedStorageState { active_slots })
}

/// Decode and strictly validate one raw type-0x18 GF3258 algorithm template.
pub fn gf3258_decode_raw_template(
    raw: &[u8],
) -> Result<Gf3258PersistedTemplate, Gf3258TemplateDecodeError> {
    if raw.len() < 10 {
        return Err(Gf3258TemplateDecodeError::RawTooShort { actual: raw.len() });
    }
    if raw[0] != 0x87 {
        return Err(Gf3258TemplateDecodeError::UnexpectedTag {
            context: "raw envelope",
            offset: 0,
            expected: 0x87,
            actual: raw[0],
        });
    }
    if raw[5] != 0x86 {
        return Err(Gf3258TemplateDecodeError::UnexpectedTag {
            context: "raw payload envelope",
            offset: 5,
            expected: 0x86,
            actual: raw[5],
        });
    }

    let stored_crc = u32::from_le_bytes(raw[1..5].try_into().expect("raw CRC"));
    let payload_len = u32::from_le_bytes(raw[6..10].try_into().expect("payload length")) as usize;
    if payload_len != raw.len() - 10 {
        return Err(Gf3258TemplateDecodeError::RawPayloadLengthMismatch {
            stored: payload_len,
            actual: raw.len() - 10,
        });
    }
    let payload = &raw[10..];
    let computed_crc = gf3258_raw_template_crc32(payload);
    if stored_crc != computed_crc {
        return Err(Gf3258TemplateDecodeError::RawCrcMismatch {
            stored: stored_crc,
            computed: computed_crc,
        });
    }

    let mut reader = Reader::new(payload, 10);
    let mut top = [0u32; TOP_TAGS.len()];
    for (index, tag) in TOP_TAGS.into_iter().enumerate() {
        top[index] = reader.scalar(tag, "top-level scalar")?;
    }

    require_scalar(0x81, top[0], TEMPLATE_00)?;
    require_scalar(0x88, top[1], TEMPLATE_00)?;
    require_scalar(0x89, top[2], TEMPLATE_04)?;
    require_scalar(0x98, top[3], GF3258_TEMPLATE_TYPE)?;
    require_scalar(0x9a, top[4], GF3258_TEMPLATE_HEIGHT)?;
    require_scalar(0x9b, top[5], GF3258_TEMPLATE_WIDTH)?;
    require_scalar(0x9e, top[9], GF3258_TEMPLATE_POINT_CAPACITY as u32)?;
    require_scalar(0x9f, top[10], GF3258_TEMPLATE_POINT_CAPACITY as u32)?;
    require_scalar(0x9c, top[11], 1)?;
    require_scalar(0x9d, top[12], 1)?;
    require_scalar(0xfa, top[13], 0)?;
    require_scalar(0xfb, top[14], 0)?;

    let sample_count = top[6] as usize;
    let configured_max_samples = top[7] as usize;
    if configured_max_samples > GF3258_TEMPLATE_DEFAULT_SAMPLE_CAPACITY {
        return Err(Gf3258TemplateDecodeError::InvalidValue {
            field: "configured sample capacity",
            value: configured_max_samples as i64,
        });
    }
    if sample_count > configured_max_samples {
        return Err(Gf3258TemplateDecodeError::InvalidValue {
            field: "sample count",
            value: sample_count as i64,
        });
    }
    let relation_table_cursor = top[8] as usize;
    let expected_cursor =
        Gf3258EnrollmentTemplateCore::relation_table_cursor_for_sample_count(sample_count);
    if relation_table_cursor != expected_cursor {
        return Err(Gf3258TemplateDecodeError::RelationCursorMismatch {
            sample_count,
            expected: expected_cursor,
            actual: relation_table_cursor,
        });
    }

    let mut samples = Vec::with_capacity(sample_count);
    let mut sample_bytes = 0usize;
    for sample_index in 0..sample_count {
        let (sample, encoded_size) = parse_sample(&mut reader, sample_index)?;
        sample_bytes += encoded_size;
        samples.push(sample);
    }

    let triangular_capacity = sample_count.saturating_mul(sample_count.saturating_sub(1)) / 2;
    let mut seen_relations = vec![false; triangular_capacity];
    let mut relations = Vec::new();
    while reader.remaining() != 0 && reader.peek("post-sample section")? == 0x96 {
        let relation = parse_relation(&mut reader, sample_count)?;
        if seen_relations[relation.relation_index] {
            return Err(Gf3258TemplateDecodeError::DuplicateRelationIndex {
                index: relation.relation_index,
            });
        }
        seen_relations[relation.relation_index] = true;
        relations.push(relation);
    }

    let graph = parse_section_93(&mut reader, sample_count)?;
    let storage = parse_section_94(&mut reader, sample_count)?;
    if reader.remaining() != 0 {
        return Err(Gf3258TemplateDecodeError::ContainerLengthMismatch {
            context: "raw template payload",
            declared: payload_len,
            consumed: reader.pos,
        });
    }

    let expected_size = GF3258_FIXED_PACKED_SIZE
        + sample_bytes
        + GF3258_PERSISTENT_RELATION_BYTES * relations.len();
    if raw.len() != expected_size {
        return Err(Gf3258TemplateDecodeError::PackedSizeMismatch {
            expected: expected_size,
            actual: raw.len(),
        });
    }

    Ok(Gf3258PersistedTemplate {
        raw_crc32: stored_crc,
        header: Gf3258PersistedTemplateHeader {
            sample_count,
            configured_max_samples,
            relation_table_cursor,
            max_point_count: top[9] as usize,
            point_capacity: top[10] as usize,
        },
        samples,
        relations,
        graph,
        storage,
    })
}

/// Validate the normal fresh TGLA wrapper and then semantically decode its raw
/// type-0x18 algorithm template.
pub fn gf3258_decode_fresh_tgla(
    tgla: &[u8],
) -> Result<Gf3258PersistedTemplate, Gf3258TemplateDecodeError> {
    let node = gf3258_parse_fresh_tgla(tgla)?;
    gf3258_decode_raw_template(node.raw_template())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrollment_add::{Gf3258EnrollmentFeaturePoint, Gf3258PersistentSampleState};
    use crate::enrollment_graph::Gf3258EnrollmentSample;
    use crate::feature::{
        GF3258_DESCRIPTOR_CENTRAL_LEN, GF3258_DESCRIPTOR_LEN, Gf3258CompactDescriptor,
        Gf3258FeaturePointCore,
    };
    use crate::registration::{GF3258_REGISTRATION_PACKED_BYTES, Gf3258AffineQ8};
    use crate::template_persistence::{
        GF3258_TEMPLATE_CONFIGURED_MAX_SAMPLES, gf3258_encode_persistent_point,
        gf3258_encode_raw_template,
    };
    use crate::template_storage::gf3258_wrap_fresh_tgla;

    fn point() -> Gf3258EnrollmentFeaturePoint {
        Gf3258EnrollmentFeaturePoint {
            core: Gf3258FeaturePointCore {
                x_q8: 0x1234,
                y_q8: 0x0567,
                orientation_q12: 0x2345,
                ranking_score: 0,
            },
            compact: Gf3258CompactDescriptor {
                norm_128: 0,
                clip_128: 0,
                normalized_128: [0; GF3258_DESCRIPTOR_LEN],
                hadamard_128_words: [0x0302_0100, 0x0706_0504, 0x0b0a_0908, 0x0f0e_0d0c],
                median_hash_128: 0x1312_1110,
                norm_32: 0,
                clip_32: 0,
                normalized_32: [0; GF3258_DESCRIPTOR_CENTRAL_LEN],
                hadamard_hash_32: 0x1b1a_1918,
                median_hash_32: 0x1f1e_1d1c,
            },
        }
    }

    fn persistent_sample(index: usize) -> Gf3258PersistentSampleState {
        let mut quarter_validity_packed = [0u8; QUARTER_VALIDITY_PACKED_BYTES];
        quarter_validity_packed[0] = 0b0000_0101;
        Gf3258PersistentSampleState {
            points: vec![point()],
            primary_registration_map: [0x11; GF3258_REGISTRATION_PACKED_BYTES],
            secondary_registration_map: Some([0x22; GF3258_REGISTRATION_PACKED_BYTES]),
            low_threshold_registration_map: [0x33; GF3258_REGISTRATION_PACKED_BYTES],
            quarter_validity_packed,
            active_validity_packed: [0; GF3258_REGISTRATION_PACKED_BYTES],
            canonical_member: false,
            relation_checkpoint: 0,
            sample_index: index as i32,
            scalar_108: 1,
            c2d40_param3: 7,
            c2d40_param4: 9,
            scalar_13c: 0,
            embedded_state_140: 0x1234,
        }
    }

    fn template_with_samples(count: usize) -> Gf3258EnrollmentTemplateCore {
        let mut template = Gf3258EnrollmentTemplateCore::new_with_configured_max_samples(
            GF3258_TEMPLATE_DEFAULT_SAMPLE_CAPACITY,
            GF3258_TEMPLATE_CONFIGURED_MAX_SAMPLES,
        );
        for index in 0..count {
            let p = point();
            template
                .add_persistent_sample(
                    vec![p.registration_point()],
                    Gf3258EnrollmentSample::default(),
                    persistent_sample(index),
                    209,
                )
                .unwrap();
        }
        template
    }

    #[test]
    fn persistent_point_decode_reverses_descriptor_nibble_permutation() {
        let source = point();
        let encoded = gf3258_encode_persistent_point(&source);
        let decoded = gf3258_decode_persistent_point(&encoded);
        let compact = source.compact.feature_point_bytes_10_2f();

        assert_eq!(decoded.descriptor_10_1f.as_slice(), &compact[..16]);
        assert_eq!(decoded.hash20, 0x1312_1110);
        assert_eq!(decoded.hash28, 0x1b1a_1918);
        assert_eq!(decoded.hash2c, 0x1f1e_1d1c);
        assert_eq!(
            decoded.geometry_word,
            u32::from_le_bytes(encoded[..4].try_into().unwrap())
        );

        // DecodeFingerTemplate does not recover the original point geometry.
        // It reconstructs this exact quantized/overlapped matcher geometry.
        assert_eq!(
            decoded.matcher_geometry(),
            Gf3258PersistedMatcherGeometry {
                x_q8: 0x1230,
                y_q8: 0x4560,
                orientation_q12: 0x7300,
            }
        );
    }

    #[test]
    fn persistent_geometry_negative_orientation_is_normalized_by_pi() {
        // This word is the persisted form of x=0x1200, y=0x0500,
        // orientation=-0x0200 when the non-overlap low nibbles are zero.
        let geometry_word = (0x1200u32 << 16) | (0x0500u32 << 4) | 0x82;
        assert_eq!(
            gf3258_decode_persistent_geometry_word(geometry_word),
            Gf3258PersistedMatcherGeometry {
                x_q8: 0x1200,
                y_q8: 0x0500,
                orientation_q12: 0x3044,
            }
        );
    }

    #[test]
    fn persisted_sample_split_is_clamped_like_decode_finger_template() {
        let source_point = point();
        let mut source_sample = persistent_sample(0);
        source_sample.points = vec![
            source_point.clone(),
            source_point.clone(),
            source_point.clone(),
        ];
        source_sample.scalar_108 = 3;

        let mut template = Gf3258EnrollmentTemplateCore::new_with_configured_max_samples(
            GF3258_TEMPLATE_DEFAULT_SAMPLE_CAPACITY,
            GF3258_TEMPLATE_CONFIGURED_MAX_SAMPLES,
        );
        template
            .add_persistent_sample(
                vec![source_point.registration_point()],
                Gf3258EnrollmentSample::default(),
                source_sample,
                209,
            )
            .unwrap();

        let raw = gf3258_encode_raw_template(&template).unwrap();
        let decoded = gf3258_decode_raw_template(&raw).unwrap();
        let sample = &decoded.samples[0];

        // The serialized scalar remains exact; matcher import applies the
        // vendor's post-load clamp to point_count - 1.
        assert_eq!(sample.scalar_108, 3);
        assert_eq!(sample.points.len(), 3);
        assert_eq!(sample.matcher_polarity_split(), 2);
    }

    #[test]
    fn empty_encoded_template_decodes_exact_header_and_tails() {
        let template = template_with_samples(0);
        let raw = gf3258_encode_raw_template(&template).unwrap();
        let decoded = gf3258_decode_raw_template(&raw).unwrap();

        assert_eq!(decoded.header.sample_count, 0);
        assert_eq!(decoded.header.configured_max_samples, 40);
        assert_eq!(decoded.header.relation_table_cursor, 0);
        assert_eq!(decoded.header.max_point_count, 120);
        assert!(decoded.samples.is_empty());
        assert!(decoded.relations.is_empty());
        assert_eq!(decoded.graph.canonical_anchor, None);
        assert!(!decoded.graph.canonical_established);
        assert!(decoded.storage.active_slots.iter().all(|&slot| slot == -1));
    }

    #[test]
    fn encoded_sample_decodes_maps_validity_scalars_and_points() {
        let template = template_with_samples(1);
        let raw = gf3258_encode_raw_template(&template).unwrap();
        let decoded = gf3258_decode_raw_template(&raw).unwrap();
        let sample = &decoded.samples[0];

        assert_eq!(
            sample.primary_registration_map,
            [0x11; GF3258_REGISTRATION_PACKED_BYTES]
        );
        assert_eq!(
            sample.secondary_registration_map,
            Some([0x22; GF3258_REGISTRATION_PACKED_BYTES])
        );
        assert_eq!(
            sample.low_threshold_registration_map,
            Some([0x33; GF3258_REGISTRATION_PACKED_BYTES])
        );
        assert_eq!(sample.quarter_validity_packed[0], 0b0000_0101);
        assert_eq!(sample.active_validity_packed[0], 0x33);
        assert_eq!(sample.active_validity_packed[5], 0x33);
        assert_eq!(sample.points.len(), 1);
        assert_eq!(sample.scalar_108, 1);
        assert_eq!(sample.c2d40_param3, 7);
        assert_eq!(sample.c2d40_param4, 9);
        assert_eq!(sample.sample_index, 0);
        assert_eq!(sample.embedded_state_140, Some(0x1234));
        assert_eq!(decoded.storage.active_slots[0], 0);
        assert!(
            decoded.storage.active_slots[1..]
                .iter()
                .all(|&slot| slot == -1)
        );
    }

    #[test]
    fn encoded_relation_decodes_triangular_index_and_affine() {
        let mut template = template_with_samples(2);
        let transform = Gf3258AffineQ8 {
            a: 256,
            b: 3,
            tx: 17,
            c: -4,
            d: 255,
            ty: -9,
        };
        assert!(
            template
                .graph
                .set_relation_source_to_target(1, 0, 3, transform)
        );

        let raw = gf3258_encode_raw_template(&template).unwrap();
        let decoded = gf3258_decode_raw_template(&raw).unwrap();
        assert_eq!(decoded.relations.len(), 1);
        assert_eq!(decoded.relations[0].relation_index, 0);
        assert_eq!(
            (decoded.relations[0].high, decoded.relations[0].low),
            (1, 0)
        );
        assert_eq!(decoded.relations[0].relation_value, 3);
        assert_eq!(
            decoded.relations[0].transform_higher_to_lower,
            transform.as_array()
        );
    }

    #[test]
    fn raw_template_decoder_rejects_crc_corruption() {
        let template = template_with_samples(0);
        let mut raw = gf3258_encode_raw_template(&template).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;

        assert!(matches!(
            gf3258_decode_raw_template(&raw),
            Err(Gf3258TemplateDecodeError::RawCrcMismatch { .. })
        ));
    }

    #[test]
    fn fresh_tgla_decoder_reaches_semantic_template() {
        let template = template_with_samples(1);
        let raw = gf3258_encode_raw_template(&template).unwrap();
        let tgla = gf3258_wrap_fresh_tgla(&raw).unwrap();
        let decoded = gf3258_decode_fresh_tgla(&tgla).unwrap();

        assert_eq!(decoded.header.sample_count, 1);
        assert_eq!(decoded.samples[0].points.len(), 1);
        assert_eq!(decoded.raw_crc32, gf3258_raw_template_crc32(&raw[10..]));
    }
}
