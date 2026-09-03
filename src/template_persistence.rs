//! GF3258 WN2 raw algorithm-template persistence.
//!
//! This module implements the recovered type-0x18 EncodeFingerTemplate grammar:
//! persistent Feature points, sample TLVs, serialization-forest relations,
//! fixed 0x93/0x94 tails, and the outer 0x87/0x86 CRC envelope.

use std::{error::Error, fmt};

use crate::enrollment_add::{
    Gf3258EnrollmentFeaturePoint, Gf3258EnrollmentTemplateCore, Gf3258PersistentSampleState,
};
use crate::registration::{
    GF3258_REGISTRATION_PACKED_BYTES, Gf3258PairRelation, Gf3258PairRelationTable,
};

pub const GF3258_TEMPLATE_PERSISTENCE_REVISION: &str = "gf3258-template-persistence-v2";

pub const GF3258_TEMPLATE_TYPE: u32 = 0x18;
pub const GF3258_TEMPLATE_WIDTH: u32 = 80;
pub const GF3258_TEMPLATE_HEIGHT: u32 = 64;
pub const GF3258_TEMPLATE_POINT_CAPACITY: usize = 120;
pub const GF3258_TEMPLATE_DEFAULT_SAMPLE_CAPACITY: usize = 50;
#[cfg(test)]
pub const GF3258_TEMPLATE_CONFIGURED_MAX_SAMPLES: usize = 40;
pub const GF3258_PERSISTENT_POINT_BYTES: usize = 32;
pub const GF3258_PERSISTENT_RELATION_BYTES: usize = 45;
pub const GF3258_FIXED_PACKED_SIZE: usize = 0x5a3;

const TEMPLATE_00: u32 = 0x002e_14f4;
const TEMPLATE_04: u32 = 0x002d_f160;
const TEMPLATE_14: u32 = 1;
const TEMPLATE_18: u32 = 1;
const TEMPLATE_1C: u32 = 120;
const TEMPLATE_20: u32 = 120;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gf3258TemplatePersistenceError {
    IncompletePersistentSample { index: usize },
    TooManyPoints { index: usize, actual: usize },
    LengthOverflow { length: usize },
    PackedSizeMismatch { expected: usize, actual: usize },
}

impl fmt::Display for Gf3258TemplatePersistenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncompletePersistentSample { index } => write!(
                f,
                "GF3258 sample {index} has registration state but no persistence-complete Feature state"
            ),
            Self::TooManyPoints { index, actual } => write!(
                f,
                "GF3258 sample {index} has {actual} points; persistent capacity is {GF3258_TEMPLATE_POINT_CAPACITY}"
            ),
            Self::LengthOverflow { length } => {
                write!(f, "GF3258 encoded length {length} does not fit u32")
            }
            Self::PackedSizeMismatch { expected, actual } => write!(
                f,
                "GF3258 packed-size invariant failed: expected {expected} bytes, encoder produced {actual}"
            ),
        }
    }
}

impl Error for Gf3258TemplatePersistenceError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf3258SelectedPersistentRelation {
    pub high: usize,
    pub low: usize,
    pub relation_index: usize,
    pub record: Gf3258PairRelation,
}

fn as_u32_len(length: usize) -> Result<u32, Gf3258TemplatePersistenceError> {
    u32::try_from(length).map_err(|_| Gf3258TemplatePersistenceError::LengthOverflow { length })
}

#[inline]
fn push_u32_le(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

#[inline]
fn push_i32_bits_le(out: &mut Vec<u8>, value: i32) {
    out.extend_from_slice(&(value as u32).to_le_bytes());
}

#[inline]
fn push_scalar(out: &mut Vec<u8>, tag: u8, value: u32) {
    out.push(tag);
    push_u32_le(out, value);
}

fn push_blob(
    out: &mut Vec<u8>,
    tag: u8,
    data: &[u8],
) -> Result<(), Gf3258TemplatePersistenceError> {
    out.push(tag);
    push_u32_le(out, as_u32_len(data.len())?);
    out.extend_from_slice(data);
    Ok(())
}

fn push_registration_mat(
    out: &mut Vec<u8>,
    outer_tag: u8,
    data: &[u8; GF3258_REGISTRATION_PACKED_BYTES],
) -> Result<(), Gf3258TemplatePersistenceError> {
    out.push(outer_tag);
    // c1/c2/c3/c4 are four five-byte scalar TLVs. c5 is a five-byte blob
    // header plus 160 bytes, so the nested payload is 20 + 165 = 185.
    push_u32_le(out, 25 + GF3258_REGISTRATION_PACKED_BYTES as u32);
    push_scalar(out, 0xc1, 40);
    push_scalar(out, 0xc2, 32);
    push_scalar(out, 0xc3, 0xffff_ffff);
    push_scalar(out, 0xc4, 8);
    push_blob(out, 0xc5, data)?;
    Ok(())
}

/// Standard reflected CRC-32/ISO-HDLC used by the recovered raw-template
/// envelope. Polynomial 0x04c11db7 / reflected 0xedb88320, init/xorout all 1.
pub fn gf3258_raw_template_crc32(payload: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in payload {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

/// Exact 32-byte type-0x18 point encoder.
pub fn gf3258_encode_persistent_point(point: &Gf3258EnrollmentFeaturePoint) -> [u8; 32] {
    let mut out = [0u8; 32];

    let orientation = point.core.orientation_q12 as i16;
    let o8 = if orientation < 0 {
        (((-(orientation as i32) >> 8) - 0x80) & 0xff) as u32
    } else {
        (u32::from(point.core.orientation_q12) >> 8) & 0xff
    };
    let geometry = (u32::from(point.core.y_q8) << 4) | (u32::from(point.core.x_q8) << 16) | o8;
    out[0..4].copy_from_slice(&geometry.to_le_bytes());

    let compact = point.compact.feature_point_bytes_10_2f();
    let descriptor = &compact[..16];
    const SWAP: [bool; 8] = [false, true, true, false, true, false, false, true];
    for k in 0..8 {
        let a = descriptor[k];
        let b = descriptor[8 + k];
        let p = (b & 0xf0) | (a & 0x0f);
        let q = (a & 0xf0) | (b & 0x0f);
        let pair = if SWAP[k] { [q, p] } else { [p, q] };
        out[4 + 2 * k..4 + 2 * k + 2].copy_from_slice(&pair);
    }

    // FeaturePoint+0x24 is intentionally not serialized in this format.
    out[20..24].copy_from_slice(&compact[0x10..0x14]);
    out[24..28].copy_from_slice(&compact[0x18..0x1c]);
    out[28..32].copy_from_slice(&compact[0x1c..0x20]);
    out
}

fn encode_sample(
    sample: &Gf3258PersistentSampleState,
    sample_index: usize,
) -> Result<Vec<u8>, Gf3258TemplatePersistenceError> {
    if sample.points.len() > GF3258_TEMPLATE_POINT_CAPACITY {
        return Err(Gf3258TemplatePersistenceError::TooManyPoints {
            index: sample_index,
            actual: sample.points.len(),
        });
    }

    let mut payload = Vec::new();
    push_registration_mat(&mut payload, 0xb2, &sample.primary_registration_map)?;
    if let Some(secondary) = sample.secondary_registration_map.as_ref() {
        push_registration_mat(&mut payload, 0xcf, secondary)?;
    }
    push_blob(&mut payload, 0xce, &sample.quarter_validity_packed)?;
    push_registration_mat(&mut payload, 0xcd, &sample.low_threshold_registration_map)?;
    push_scalar(&mut payload, 0xb3, sample.points.len() as u32);

    let mut points = Vec::with_capacity(sample.points.len() * GF3258_PERSISTENT_POINT_BYTES);
    for point in &sample.points {
        points.extend_from_slice(&gf3258_encode_persistent_point(point));
    }
    push_blob(&mut payload, 0xb4, &points)?;

    push_scalar(
        &mut payload,
        0xb5,
        if sample.canonical_member { 1 } else { 0 },
    );
    push_scalar(&mut payload, 0xb6, sample.relation_checkpoint as u32);
    push_scalar(&mut payload, 0xb7, sample.scalar_108 as u32);
    push_scalar(&mut payload, 0xb8, sample.c2d40_param3 as u32);
    push_scalar(&mut payload, 0xb9, sample.c2d40_param4 as u32);
    push_scalar(&mut payload, 0xba, 0);
    push_scalar(&mut payload, 0xbb, 0);
    push_scalar(&mut payload, 0xbc, sample.sample_index as u32);
    push_scalar(&mut payload, 0xbd, 0);
    push_scalar(&mut payload, 0xbe, 0);
    push_scalar(&mut payload, 0xc0, sample.scalar_13c as u32);
    if sample.embedded_state_140 != 0 {
        push_scalar(&mut payload, 0xc7, sample.embedded_state_140 as u32);
    }

    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(0x95);
    push_u32_le(&mut out, as_u32_len(payload.len())?);
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Recovered ac970 serialization forest. Strong edges are relation_value > 2
/// and are traversed DFS/LIFO with candidates descending. The weak direct-to-
/// root fallback accepts relation_value >= 0 with candidates ascending and does
/// not recursively expand those assignments.
pub fn gf3258_select_persistent_relations(
    template: &Gf3258EnrollmentTemplateCore,
) -> Vec<Gf3258SelectedPersistentRelation> {
    let count = template.sample_count();
    let mut group_root = vec![-1isize; count];
    let mut parent = vec![-1isize; count];

    for root in 0..count {
        if group_root[root] != -1 {
            continue;
        }
        group_root[root] = root as isize;
        parent[root] = -1;

        let mut stack = vec![root];
        while let Some(current) = stack.pop() {
            for candidate in (0..count).rev() {
                if candidate == current || group_root[candidate] != -1 {
                    continue;
                }
                let Some(record) = template
                    .graph
                    .relations
                    .canonical_record(current, candidate)
                else {
                    continue;
                };
                if record.relation_value > 2 {
                    group_root[candidate] = root as isize;
                    parent[candidate] = current as isize;
                    stack.push(candidate);
                }
            }
        }

        for candidate in 0..count {
            if candidate == root || group_root[candidate] != -1 {
                continue;
            }
            let Some(record) = template.graph.relations.canonical_record(root, candidate) else {
                continue;
            };
            if record.relation_value >= 0 {
                group_root[candidate] = root as isize;
                parent[candidate] = root as isize;
            }
        }
    }

    // The recovered encoder addresses relation records by triangular index.
    // Emit selected records in that same ascending storage order.
    let mut selected = Vec::new();
    for high in 1..count {
        for low in 0..high {
            let connected = parent[high] == low as isize || parent[low] == high as isize;
            let both_roots = group_root[high] == high as isize && group_root[low] == low as isize;
            if !connected || both_roots {
                continue;
            }
            let Some(record) = template.graph.relations.canonical_record(high, low) else {
                continue;
            };
            if record.relation_value < 0 {
                continue;
            }
            selected.push(Gf3258SelectedPersistentRelation {
                high,
                low,
                relation_index: Gf3258PairRelationTable::row_base(high) + low,
                record,
            });
        }
    }
    selected
}

fn encode_relation(relation: Gf3258SelectedPersistentRelation) -> Vec<u8> {
    let mut out = Vec::with_capacity(GF3258_PERSISTENT_RELATION_BYTES);
    out.push(0x96);
    push_u32_le(&mut out, 40);
    push_scalar(&mut out, 0xe3, relation.relation_index as u32);
    push_scalar(&mut out, 0xe1, relation.record.relation_value as u32);
    let affine = relation.record.transform_higher_to_lower.as_array();
    for (tag, value) in (0xe4u8..=0xe9).zip(affine) {
        out.push(tag);
        push_i32_bits_le(&mut out, value);
    }
    debug_assert_eq!(out.len(), GF3258_PERSISTENT_RELATION_BYTES);
    out
}

fn encode_section_93(template: &Gf3258EnrollmentTemplateCore) -> Vec<u8> {
    let mut out = Vec::with_capacity(25);
    out.push(0x93);
    push_u32_le(&mut out, 20);
    let anchor = if template.graph.canonical_established {
        template.graph.canonical_anchor as i32
    } else {
        -1
    };
    push_scalar(&mut out, 0xf2, anchor as u32);
    push_scalar(&mut out, 0xf3, 0xffff_ffff);
    push_scalar(&mut out, 0xf4, 0xffff_ffff);
    push_scalar(
        &mut out,
        0xf5,
        if template.graph.canonical_established {
            1
        } else {
            0
        },
    );
    debug_assert_eq!(out.len(), 25);
    out
}

fn encode_section_94(
    template: &Gf3258EnrollmentTemplateCore,
) -> Result<Vec<u8>, Gf3258TemplatePersistenceError> {
    let mut payload = Vec::with_capacity(1328);

    // Vendor ba520 refreshes template+0x87f0 as a 50*i32 active-slot table:
    // [0,1,...,sample_count-1,-1,...].  The fresh constructor initializes all
    // 200 bytes to 0xff; live 12-touch vendor output proves 0..11 then -1.
    let mut a1 = [0xffu8; 200];
    for index in 0..template
        .sample_count()
        .min(GF3258_TEMPLATE_DEFAULT_SAMPLE_CAPACITY)
    {
        let start = index * 4;
        a1[start..start + 4].copy_from_slice(&(index as i32).to_le_bytes());
    }
    push_blob(&mut payload, 0xa1, &a1)?;
    push_scalar(&mut payload, 0xa2, 0xffff_ffff);

    let mut a3 = [0u8; 64];
    const A3_PREFIX: &[u8] = b"Milan_v_3.02.00.20\0";
    a3[..A3_PREFIX.len()].copy_from_slice(A3_PREFIX);
    push_blob(&mut payload, 0xa3, &a3)?;

    let a4 = [0u8; 1024];
    push_blob(&mut payload, 0xa4, &a4)?;
    push_scalar(&mut payload, 0xa5, 0);
    push_scalar(&mut payload, 0xa6, 0);
    push_scalar(&mut payload, 0xa7, 0);
    push_scalar(&mut payload, 0xa8, 0);

    debug_assert_eq!(payload.len(), 1328);
    let mut out = Vec::with_capacity(1333);
    out.push(0x94);
    push_u32_le(&mut out, as_u32_len(payload.len())?);
    out.extend_from_slice(&payload);
    debug_assert_eq!(out.len(), 1333);
    Ok(out)
}

fn persistent_samples(
    template: &Gf3258EnrollmentTemplateCore,
) -> Result<Vec<&Gf3258PersistentSampleState>, Gf3258TemplatePersistenceError> {
    let mut samples = Vec::with_capacity(template.sample_count());
    for index in 0..template.sample_count() {
        samples.push(
            template
                .persistent_sample(index)
                .ok_or(Gf3258TemplatePersistenceError::IncompletePersistentSample { index })?,
        );
    }
    Ok(samples)
}

fn encode_payload(
    template: &Gf3258EnrollmentTemplateCore,
) -> Result<(Vec<u8>, usize, usize), Gf3258TemplatePersistenceError> {
    let samples = persistent_samples(template)?;
    let selected_relations = gf3258_select_persistent_relations(template);

    let mut encoded_samples = Vec::with_capacity(samples.len());
    let mut sample_bytes = 0usize;
    for (index, sample) in samples.iter().enumerate() {
        let encoded = encode_sample(sample, index)?;
        sample_bytes += encoded.len();
        encoded_samples.push(encoded);
    }

    let max_point_count = samples
        .iter()
        .map(|sample| sample.points.len())
        .fold(TEMPLATE_1C as usize, usize::max);

    let mut payload = Vec::new();
    push_scalar(&mut payload, 0x81, TEMPLATE_00);
    push_scalar(&mut payload, 0x88, TEMPLATE_00);
    push_scalar(&mut payload, 0x89, TEMPLATE_04);
    push_scalar(&mut payload, 0x98, GF3258_TEMPLATE_TYPE);
    push_scalar(&mut payload, 0x9a, GF3258_TEMPLATE_HEIGHT);
    push_scalar(&mut payload, 0x9b, GF3258_TEMPLATE_WIDTH);
    push_scalar(&mut payload, 0x91, template.sample_count() as u32);
    push_scalar(&mut payload, 0x97, template.configured_max_samples() as u32);
    push_scalar(&mut payload, 0x92, template.relation_table_cursor() as u32);
    push_scalar(&mut payload, 0x9e, max_point_count as u32);
    push_scalar(&mut payload, 0x9f, TEMPLATE_20);
    push_scalar(&mut payload, 0x9c, TEMPLATE_14);
    push_scalar(&mut payload, 0x9d, TEMPLATE_18);
    push_scalar(&mut payload, 0xfa, 0);
    push_scalar(&mut payload, 0xfb, 0);

    for encoded in encoded_samples {
        payload.extend_from_slice(&encoded);
    }
    for relation in selected_relations.iter().copied() {
        payload.extend_from_slice(&encode_relation(relation));
    }
    payload.extend_from_slice(&encode_section_93(template));
    payload.extend_from_slice(&encode_section_94(template)?);

    Ok((payload, sample_bytes, selected_relations.len()))
}

/// Exact raw algorithm-template envelope produced before TGLA wrapping.
pub fn gf3258_encode_raw_template(
    template: &Gf3258EnrollmentTemplateCore,
) -> Result<Vec<u8>, Gf3258TemplatePersistenceError> {
    let (payload, sample_bytes, selected_relation_count) = encode_payload(template)?;
    let crc = gf3258_raw_template_crc32(&payload);

    let mut out = Vec::with_capacity(payload.len() + 10);
    out.push(0x87);
    push_u32_le(&mut out, crc);
    out.push(0x86);
    push_u32_le(&mut out, as_u32_len(payload.len())?);
    out.extend_from_slice(&payload);

    let expected = GF3258_FIXED_PACKED_SIZE
        + sample_bytes
        + GF3258_PERSISTENT_RELATION_BYTES * selected_relation_count;
    if out.len() != expected {
        return Err(Gf3258TemplatePersistenceError::PackedSizeMismatch {
            expected,
            actual: out.len(),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrollment_add::{Gf3258EnrollmentFeaturePoint, Gf3258PersistentSampleState};
    use crate::feature::{
        GF3258_DESCRIPTOR_CENTRAL_LEN, GF3258_DESCRIPTOR_LEN, Gf3258CompactDescriptor,
        Gf3258FeaturePointCore,
    };

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

    fn persistent_sample() -> Gf3258PersistentSampleState {
        Gf3258PersistentSampleState {
            points: vec![point()],
            primary_registration_map: [0; GF3258_REGISTRATION_PACKED_BYTES],
            secondary_registration_map: Some([0; GF3258_REGISTRATION_PACKED_BYTES]),
            low_threshold_registration_map: [0; GF3258_REGISTRATION_PACKED_BYTES],
            quarter_validity_packed: [0; 40],
            active_validity_packed: [0xff; GF3258_REGISTRATION_PACKED_BYTES],
            canonical_member: false,
            relation_checkpoint: 0,
            sample_index: 0,
            scalar_108: 0,
            c2d40_param3: 0,
            c2d40_param4: 0,
            scalar_13c: 0,
            embedded_state_140: 0,
        }
    }

    #[test]
    fn crc32_iso_hdlc_check_vector_is_exact() {
        assert_eq!(gf3258_raw_template_crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn point_encoder_uses_recovered_geometry_and_hash_layout() {
        let encoded = gf3258_encode_persistent_point(&point());
        let geometry = (0x0567u32 << 4) | (0x1234u32 << 16) | 0x23;
        assert_eq!(&encoded[..4], &geometry.to_le_bytes());
        assert_eq!(&encoded[20..24], &0x1312_1110u32.to_le_bytes());
        assert_eq!(&encoded[24..28], &0x1b1a_1918u32.to_le_bytes());
        assert_eq!(&encoded[28..32], &0x1f1e_1d1cu32.to_le_bytes());
    }

    #[test]
    fn c0910_quantized_geometry_round_trips_through_persistence() {
        let mut point = point();
        point.core.x_q8 = 0x1230;
        point.core.y_q8 = 0x0560;
        point.core.orientation_q12 = 0x2300;

        let encoded = gf3258_encode_persistent_point(&point);
        let decoded = crate::template_decode::gf3258_decode_persistent_point(&encoded);
        let geometry = decoded.matcher_geometry();

        assert_eq!(geometry.x_q8, point.core.x_q8);
        assert_eq!(geometry.y_q8, point.core.y_q8);
        assert_eq!(geometry.orientation_q12, point.core.orientation_q12);
    }

    #[test]
    fn fixed_94_tail_is_exact_size_and_zero_padded() {
        let template = Gf3258EnrollmentTemplateCore::new_with_configured_max_samples(50, 40);
        let section = encode_section_94(&template).unwrap();
        assert_eq!(section.len(), 0x535);
        assert_eq!(section[0], 0x94);
        assert_eq!(u32::from_le_bytes(section[1..5].try_into().unwrap()), 1328);
        assert!(section.windows(19).any(|w| w == b"Milan_v_3.02.00.20\0"));
    }

    #[test]
    fn sample_with_three_maps_has_recovered_size_formula() {
        let encoded = encode_sample(&persistent_sample(), 0).unwrap();
        // 685 fixed bytes for a normal sample with b2/cf/cd and no c7,
        // plus 32 bytes for the one persistent point.
        assert_eq!(encoded.len(), 685 + 32);
        assert_eq!(encoded[0], 0x95);
    }

    #[test]
    fn empty_fresh_template_has_recovered_fixed_packed_size() {
        let template = Gf3258EnrollmentTemplateCore::new_with_configured_max_samples(
            GF3258_TEMPLATE_DEFAULT_SAMPLE_CAPACITY,
            GF3258_TEMPLATE_CONFIGURED_MAX_SAMPLES,
        );
        let encoded = gf3258_encode_raw_template(&template).unwrap();
        assert_eq!(encoded.len(), GF3258_FIXED_PACKED_SIZE);
        assert_eq!(encoded[0], 0x87);
        assert_eq!(encoded[5], 0x86);
        assert_eq!(
            u32::from_le_bytes(encoded[6..10].try_into().unwrap()) as usize,
            encoded.len() - 10
        );
    }
}
