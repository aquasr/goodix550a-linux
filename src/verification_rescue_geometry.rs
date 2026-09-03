//! GF3258 verification rescue geometry.
//!
//! This module owns the type-0x18 `FUN_00170a80` geometry and quality path:
//! weak edge-crossed seeding (`b1d40`), strong rescue correspondence
//! generation (`b1fd0`), rescue quality (`b21b0`), and the recovered affine
//! admission gates.

use super::{
    Gf3258NormalLoopPostGeometryDisposition, Gf3258NormalLoopSampleInput,
    Gf3258VerificationRegistrationEvidence, Gf3258VerificationRegistrationInput,
    gf3258_affine_q16_raw, gf3258_finalize_geometry_work_metric,
    gf3258_generate_persisted_sample_candidates, gf3258_persisted_geometry_points,
    gf3258_primary_work_stage_from_candidates, gf3258_registration_evidence_replaces,
    gf3258_round_q16_coordinate_to_pixel, gf3258_terminal_recovery_affine_metrics,
    gf3258_update_refined_top_two, gf3258_verification_registration_evidence,
    gf3258_wrapping_abs_i32,
};
use crate::feature::matching::{
    Gf3258MatcherEdgeClass, Gf3258RescuePointData, gf3258_matcher_edge_class,
};
use crate::feature::{
    GF3258_HEIGHT, GF3258_MATCH_MAX_CANDIDATE_PAIRS, GF3258_MATCH_SCORE_MATRIX_STRIDE,
    GF3258_MATCH_SCORE_SENTINEL, GF3258_WIDTH, Gf3258CandidateGeneration,
    Gf3258CandidateMatchError, Gf3258CandidateMatcherConfig, Gf3258MatcherFeatureSet,
    Gf3258MatcherPoint, Gf3258OwnedVerificationMatcherFeature,
    gf3258_select_correspondences_from_top_two,
};
use crate::registration::{
    Gf3258AffineQ8, Gf3258MatcherGeometryError, Gf3258MatcherGeometryResult,
    gf3258_matcher_geometry_from_pair_slots,
};
use crate::template_decode::Gf3258PersistedSample;

const GF3258_RESCUE_HASH_HAMMING_MAX: i32 = 16;
const GF3258_RESCUE_AMBIGUITY_BEST_MULTIPLIER: i32 = 40;
const GF3258_RESCUE_AMBIGUITY_SECOND_MULTIPLIER: i32 = 38;
const GF3258_RESCUE_MAX_PRIMARY_INLIERS: usize = 8;
const GF3258_RESCUE_MIN_SEED_INLIERS: usize = 3;
const GF3258_RESCUE_MATCH_MAX_DELTA_Q8: i32 = 0x1500;
const GF3258_RESCUE_MAX_ORTHOGONALITY_Q16: i32 = 0x28f5;
const GF3258_RESCUE_MIN_SCALE_Q8: i32 = 0xea;
const GF3258_RESCUE_MAX_SCALE_Q8: i32 = 0x119;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Gf3258RescueSeed {
    inlier_count: usize,
    transform_live_to_enrolled: Gf3258AffineQ8,
}

impl From<&Gf3258MatcherGeometryResult> for Gf3258RescueSeed {
    fn from(value: &Gf3258MatcherGeometryResult) -> Self {
        Self {
            inlier_count: value.final_inlier_count,
            transform_live_to_enrolled: value.transform_live_to_enrolled,
        }
    }
}

/// Quality summary produced by `FUN_001b21b0` for a primary or rescue geometry.
///
/// The vendor stores this record at `work+0x124`; the percentage fields are
/// derived from the live points admitted by the transformed-image bounds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Gf3258VerificationGeometryQuality {
    pub admitted_points: i32,
    pub matched_points: i32,
    pub matched_percent: i32,
    /// Geometry-count ratio against admitted live points. This recovered ratio
    /// is not bounded to 100 and can legitimately exceed it.
    pub geometry_ratio_percent: i32,
    pub average_hash_hamming: i32,
}

/// Configuration required to reproduce one GF3258 normal verification work
/// record through `FUN_00172700 -> FUN_00170a80`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Gf3258VerificationSampleConfig {
    pub candidate_matcher: Gf3258CandidateMatcherConfig,
    /// Recognition-config `+0x30`, multiplied by a9a50 coverage and shifted by
    /// eight before storage in the work record.
    pub quality_scale_q8: i32,
}

/// Semantic projection of the work-record fields established by the primary
/// and rescue geometry producers plus the caller's post-rescue max merge.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Gf3258VerificationWorkRecord {
    /// `work+0x00`, including weak-seed promotion and the 70a80 bonus/cap.
    pub geometry_count: i32,
    /// `work+0x04` after the 70a80 bonus/cap and caller max with rescue count.
    pub verification_metric: i32,
    /// `work+0x08`, zero unless strong rescue passes its quality/affine gates.
    pub rescue_count: i32,
    /// `work+0x10`, selected a9a50 map score.
    pub map_score: i32,
    /// `work+0x14`, selected a9a50 third scalar output.
    pub evidence: i32,
    /// `work+0x24`, recognition quality scale times a9a50 coverage, Q8.
    pub scaled_coverage_q8: i32,
    /// `work+0x28`, active b21b0 matched percentage.
    pub matched_percent: i32,
    /// `work+0x2c`, active b21b0 geometry-count percentage.
    pub geometry_percent: i32,
    /// `work+0x30`, unsigned scale-outside-0xea..=0x119 indicator.
    pub scale_penalty: i32,
    /// `work+0x34`, affine orthogonality > 0x147a indicator.
    pub orthogonality_penalty: i32,
    /// `work+0x38`, affine orthogonality > 0x28f5 indicator.
    pub severe_orthogonality: i32,
    /// `work+0x134`, active b21b0 average central-hash Hamming distance.
    pub average_hash_hamming: i32,
}

/// Complete geometry/evidence state produced for one persisted GF3258 sample
/// before the later policy-specific caller helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Gf3258PersistedVerificationWork {
    pub initial_geometry: Gf3258MatcherGeometryResult,
    /// Count-selected primary geometry corresponding to pre-bonus `work+0x04`.
    pub primary_geometry: Gf3258MatcherGeometryResult,
    /// Affine retained by the caller's evidence comparison. It can differ from
    /// `primary_geometry.transform_live_to_enrolled`.
    pub policy_transform_live_to_enrolled: Gf3258AffineQ8,
    pub registration_evidence: Option<Gf3258VerificationRegistrationEvidence>,
    /// b21b0 quality produced by the primary path, when that path runs it.
    pub primary_quality: Option<Gf3258VerificationGeometryQuality>,
    pub rescue_seed_inlier_count: usize,
    pub rescue_candidate_inlier_count: usize,
    /// b21b0 quality for a strong rescue candidate that improves its seed.
    pub rescue_candidate_quality: Option<Gf3258VerificationGeometryQuality>,
    pub admitted_rescue: Option<Gf3258MatcherGeometryResult>,
    /// Quality record active after 70a80. Admitted rescue overwrites primary
    /// quality; rejected rescue leaves primary quality intact.
    pub active_quality: Option<Gf3258VerificationGeometryQuality>,
    pub record: Gf3258VerificationWorkRecord,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Gf3258PersistedVerificationWorkError {
    Candidate(Gf3258CandidateMatchError),
    Geometry(Gf3258MatcherGeometryError),
}

impl std::fmt::Display for Gf3258PersistedVerificationWorkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Candidate(error) => write!(f, "GF3258 verification candidate error: {error}"),
            Self::Geometry(error) => write!(f, "GF3258 verification geometry error: {error:?}"),
        }
    }
}

impl std::error::Error for Gf3258PersistedVerificationWorkError {}

impl From<Gf3258CandidateMatchError> for Gf3258PersistedVerificationWorkError {
    fn from(value: Gf3258CandidateMatchError) -> Self {
        Self::Candidate(value)
    }
}

impl From<Gf3258MatcherGeometryError> for Gf3258PersistedVerificationWorkError {
    fn from(value: Gf3258MatcherGeometryError) -> Self {
        Self::Geometry(value)
    }
}

fn gf3258_persisted_rescue_data(sample: &Gf3258PersistedSample) -> Vec<Gf3258RescuePointData> {
    sample
        .points
        .iter()
        .map(|point| {
            let geometry = point.matcher_geometry();
            Gf3258RescuePointData {
                edge_class: gf3258_matcher_edge_class(geometry.y_q8),
                hash2c: point.hash2c,
                hash34: point.hash2c.swap_bytes(),
            }
        })
        .collect()
}

#[inline]
fn gf3258_hamming64_words(a0: u32, a1: u32, b0: u32, b1: u32) -> i32 {
    ((a0 ^ b0).count_ones() + (a1 ^ b1).count_ones()) as i32
}

#[inline]
fn gf3258_rescue_hash_hamming(
    enrolled: &Gf3258MatcherPoint,
    enrolled_rescue: Gf3258RescuePointData,
    live: &Gf3258MatcherPoint,
    live_rescue: Gf3258RescuePointData,
) -> i32 {
    let normal = gf3258_hamming64_words(
        enrolled.hash28,
        enrolled_rescue.hash2c,
        live.hash28,
        live_rescue.hash2c,
    );
    let alternate = gf3258_hamming64_words(
        enrolled.hash28,
        enrolled_rescue.hash2c,
        live.hash30,
        live_rescue.hash34,
    );
    normal.min(alternate)
}

#[inline]
fn gf3258_weak_rescue_hash_hamming(
    enrolled: &Gf3258MatcherPoint,
    enrolled_rescue: Gf3258RescuePointData,
    live: &Gf3258MatcherPoint,
    live_rescue: Gf3258RescuePointData,
    normal_mode: bool,
) -> i32 {
    if normal_mode {
        gf3258_hamming64_words(
            enrolled.hash28,
            enrolled_rescue.hash2c,
            live.hash28,
            live_rescue.hash2c,
        )
    } else {
        gf3258_hamming64_words(
            enrolled.hash28,
            enrolled_rescue.hash2c,
            live.hash30,
            live_rescue.hash34,
        )
    }
}

// Inputs correspond directly to the recovered rescue selector domains.
#[allow(clippy::too_many_arguments)]
fn gf3258_weak_rescue_pair_slots(
    enrolled: &[Gf3258MatcherPoint],
    enrolled_rescue: &[Gf3258RescuePointData],
    enrolled_polarity_split: usize,
    live: Gf3258MatcherFeatureSet<'_>,
    live_rescue: &[Gf3258RescuePointData],
    candidates: &Gf3258CandidateGeneration,
    enrolled_edge: Gf3258MatcherEdgeClass,
    live_edge: Gf3258MatcherEdgeClass,
) -> [[i32; 2]; GF3258_MATCH_MAX_CANDIDATE_PAIRS] {
    debug_assert_eq!(enrolled.len(), enrolled_rescue.len());
    debug_assert_eq!(live.points.len(), live_rescue.len());

    let mut best_scores = vec![[GF3258_MATCH_SCORE_SENTINEL; 2]; enrolled.len()];
    let mut best_live_indices = vec![[-1; 2]; enrolled.len()];

    for (enrolled_range, live_range) in [
        (0..enrolled_polarity_split, 0..live.polarity_split),
        (
            enrolled_polarity_split..enrolled.len(),
            live.polarity_split..live.points.len(),
        ),
    ] {
        for enrolled_index in enrolled_range {
            if enrolled_rescue[enrolled_index].edge_class != enrolled_edge {
                continue;
            }
            let row = enrolled_index * GF3258_MATCH_SCORE_MATRIX_STRIDE;
            for live_index in live_range.clone() {
                if live_rescue[live_index].edge_class != live_edge {
                    continue;
                }
                let matrix_index = row + live_index;
                if candidates.pair_score_matrix[matrix_index] == 0xff {
                    continue;
                }

                let score = gf3258_weak_rescue_hash_hamming(
                    &enrolled[enrolled_index],
                    enrolled_rescue[enrolled_index],
                    &live.points[live_index],
                    live_rescue[live_index],
                    candidates.pair_normal_mode_matrix[matrix_index],
                );
                if score > GF3258_RESCUE_HASH_HAMMING_MAX {
                    continue;
                }
                gf3258_update_refined_top_two(
                    &mut best_scores[enrolled_index],
                    &mut best_live_indices[enrolled_index],
                    score,
                    live_index as i32,
                );
            }
        }
    }

    let selected = gf3258_select_correspondences_from_top_two(
        live.points,
        &best_scores,
        &best_live_indices,
        GF3258_RESCUE_AMBIGUITY_BEST_MULTIPLIER,
        GF3258_RESCUE_AMBIGUITY_SECOND_MULTIPLIER,
    );
    let mut pair_slots = [[-1; 2]; GF3258_MATCH_MAX_CANDIDATE_PAIRS];
    for (slot, candidate) in selected.iter().enumerate() {
        pair_slots[slot] = [candidate.enrolled_index, candidate.live_index];
    }
    pair_slots
}

fn gf3258_strong_rescue_pair_slots(
    enrolled: &[Gf3258MatcherPoint],
    enrolled_rescue: &[Gf3258RescuePointData],
    enrolled_polarity_split: usize,
    live: Gf3258MatcherFeatureSet<'_>,
    live_rescue: &[Gf3258RescuePointData],
    seed_live_to_enrolled: Gf3258AffineQ8,
) -> [[i32; 2]; GF3258_MATCH_MAX_CANDIDATE_PAIRS] {
    debug_assert_eq!(enrolled.len(), enrolled_rescue.len());
    debug_assert_eq!(live.points.len(), live_rescue.len());

    let inverse = seed_live_to_enrolled.inverse();
    let enrolled_x_limit = GF3258_WIDTH as i32 - 5;
    let enrolled_y_limit = GF3258_HEIGHT as i32 - 5;
    let live_x_limit = GF3258_WIDTH as i32 - 4;
    let live_y_limit = GF3258_HEIGHT as i32 - 4;
    let mut best_scores = vec![[GF3258_MATCH_SCORE_SENTINEL; 2]; enrolled.len()];
    let mut best_live_indices = vec![[-1; 2]; enrolled.len()];

    for (enrolled_range, live_range) in [
        (0..enrolled_polarity_split, 0..live.polarity_split),
        (
            enrolled_polarity_split..enrolled.len(),
            live.polarity_split..live.points.len(),
        ),
    ] {
        for enrolled_index in enrolled_range {
            let enrolled_point = &enrolled[enrolled_index];
            let (inverse_x, inverse_y) =
                gf3258_affine_q16_raw(inverse, enrolled_point.x_q8, enrolled_point.y_q8);
            let inverse_x = gf3258_round_q16_coordinate_to_pixel(inverse_x);
            let inverse_y = gf3258_round_q16_coordinate_to_pixel(inverse_y);
            if inverse_x <= 5
                || inverse_y <= 5
                || inverse_x >= enrolled_x_limit
                || inverse_y >= enrolled_y_limit
            {
                continue;
            }

            for live_index in live_range.clone() {
                let live_point = &live.points[live_index];
                let (transformed_x, transformed_y) =
                    gf3258_affine_q16_raw(seed_live_to_enrolled, live_point.x_q8, live_point.y_q8);
                let transformed_x_q8 = transformed_x >> 8;
                let transformed_y_q8 = transformed_y >> 8;
                if gf3258_wrapping_abs_i32(
                    transformed_x_q8.wrapping_sub(i32::from(enrolled_point.x_q8)),
                ) > GF3258_RESCUE_MATCH_MAX_DELTA_Q8
                    || gf3258_wrapping_abs_i32(
                        transformed_y_q8.wrapping_sub(i32::from(enrolled_point.y_q8)),
                    ) > GF3258_RESCUE_MATCH_MAX_DELTA_Q8
                {
                    continue;
                }

                let transformed_x = gf3258_round_q16_coordinate_to_pixel(transformed_x);
                let transformed_y = gf3258_round_q16_coordinate_to_pixel(transformed_y);
                if transformed_x <= 5
                    || transformed_y <= 5
                    || transformed_x >= live_x_limit
                    || transformed_y >= live_y_limit
                {
                    continue;
                }

                let score = gf3258_rescue_hash_hamming(
                    enrolled_point,
                    enrolled_rescue[enrolled_index],
                    live_point,
                    live_rescue[live_index],
                );
                if score > GF3258_RESCUE_HASH_HAMMING_MAX {
                    continue;
                }
                gf3258_update_refined_top_two(
                    &mut best_scores[enrolled_index],
                    &mut best_live_indices[enrolled_index],
                    score,
                    live_index as i32,
                );
            }
        }
    }

    let selected = gf3258_select_correspondences_from_top_two(
        live.points,
        &best_scores,
        &best_live_indices,
        GF3258_RESCUE_AMBIGUITY_BEST_MULTIPLIER,
        GF3258_RESCUE_AMBIGUITY_SECOND_MULTIPLIER,
    );
    let mut pair_slots = [[-1; 2]; GF3258_MATCH_MAX_CANDIDATE_PAIRS];
    for (slot, candidate) in selected.iter().enumerate() {
        pair_slots[slot] = [candidate.enrolled_index, candidate.live_index];
    }
    pair_slots
}

#[inline]
fn gf3258_round_q16_to_q8_i64(value: i64) -> i32 {
    if value <= 0 {
        -(((0x80i64 - value) >> 8) as i32)
    } else {
        ((value + 0x80) >> 8) as i32
    }
}

#[inline]
fn gf3258_transform_q8_rounded_i64(transform: Gf3258AffineQ8, x_q8: u16, y_q8: u16) -> (i32, i32) {
    let x = i64::from(x_q8);
    let y = i64::from(y_q8);
    let raw_x =
        i64::from(transform.a) * x + i64::from(transform.b) * y + (i64::from(transform.tx) << 8);
    let raw_y =
        i64::from(transform.c) * x + i64::from(transform.d) * y + (i64::from(transform.ty) << 8);
    (
        gf3258_round_q16_to_q8_i64(raw_x),
        gf3258_round_q16_to_q8_i64(raw_y),
    )
}

fn gf3258_verification_geometry_quality(
    enrolled: &[Gf3258MatcherPoint],
    enrolled_rescue: &[Gf3258RescuePointData],
    live: Gf3258MatcherFeatureSet<'_>,
    live_rescue: &[Gf3258RescuePointData],
    transform_live_to_enrolled: Gf3258AffineQ8,
    geometry_count: usize,
) -> Gf3258VerificationGeometryQuality {
    debug_assert_eq!(enrolled.len(), enrolled_rescue.len());
    debug_assert_eq!(live.points.len(), live_rescue.len());

    let x_limit_q8 = ((GF3258_WIDTH as i32 - 7) << 8) - 1;
    let y_limit_q8 = ((GF3258_HEIGHT as i32 - 7) << 8) - 1;
    let mut quality = Gf3258VerificationGeometryQuality::default();
    let mut hash_hamming_sum = 0i32;

    for (live_index, live_point) in live.points.iter().enumerate() {
        let (transformed_x, transformed_y) = gf3258_transform_q8_rounded_i64(
            transform_live_to_enrolled,
            live_point.x_q8,
            live_point.y_q8,
        );
        if transformed_x <= 0x5ff
            || transformed_y <= 0x5ff
            || transformed_x > x_limit_q8
            || transformed_y > y_limit_q8
        {
            continue;
        }
        quality.admitted_points = quality.admitted_points.wrapping_add(1);

        let mut best_index = None;
        let mut best_distance = i32::MAX;
        for (enrolled_index, enrolled_point) in enrolled.iter().enumerate() {
            if ((live_point.polarity ^ enrolled_point.polarity) & 3) != 0 {
                continue;
            }
            let dx = transformed_x.wrapping_sub(i32::from(enrolled_point.x_q8));
            let dy = transformed_y.wrapping_sub(i32::from(enrolled_point.y_q8));
            if gf3258_wrapping_abs_i32(dx) > 0x200 || gf3258_wrapping_abs_i32(dy) > 0x200 {
                continue;
            }
            let distance = dx.wrapping_mul(dx).wrapping_add(dy.wrapping_mul(dy));
            if distance < best_distance {
                best_distance = distance;
                best_index = Some(enrolled_index);
            }
        }

        let Some(enrolled_index) = best_index else {
            continue;
        };
        if best_distance > 0x3ffff {
            continue;
        }

        quality.matched_points = quality.matched_points.wrapping_add(1);
        hash_hamming_sum = hash_hamming_sum.wrapping_add(gf3258_rescue_hash_hamming(
            &enrolled[enrolled_index],
            enrolled_rescue[enrolled_index],
            live_point,
            live_rescue[live_index],
        ));
    }

    if quality.matched_points > 0 {
        quality.average_hash_hamming = hash_hamming_sum / quality.matched_points;
    }
    if quality.admitted_points > 0 {
        quality.matched_percent =
            quality.matched_points.wrapping_mul(100) / quality.admitted_points;
        quality.geometry_ratio_percent =
            (geometry_count as i32).wrapping_mul(100) / quality.admitted_points;
    }
    quality
}

fn gf3258_fallback_label_map(points: &[Gf3258MatcherPoint]) -> Vec<i32> {
    let mut labels = vec![-1; GF3258_WIDTH * GF3258_HEIGHT];
    for (index, point) in points.iter().enumerate() {
        let x = (i32::from(point.x_q8).wrapping_add(0x80)) >> 8;
        let y = (i32::from(point.y_q8).wrapping_add(0x80)) >> 8;
        let x0 = (x - 2).max(0);
        let x1 = (x + 2).min(GF3258_WIDTH as i32 - 1);
        let y0 = (y - 2).max(0);
        let y1 = (y + 2).min(GF3258_HEIGHT as i32 - 1);
        for row in y0..=y1 {
            for column in x0..=x1 {
                labels[row as usize * GF3258_WIDTH + column as usize] = index as i32;
            }
        }
    }
    labels
}

#[inline]
fn gf3258_inverse_project_rounded_q8(
    transform: Gf3258AffineQ8,
    x_q8: u16,
    y_q8: u16,
) -> (i32, i32) {
    let inverse = transform.inverse();
    let x = i64::from(inverse.a)
        .wrapping_mul(i64::from(x_q8))
        .wrapping_add(i64::from(inverse.b).wrapping_mul(i64::from(y_q8)))
        .wrapping_add(0x80);
    let y = i64::from(inverse.c)
        .wrapping_mul(i64::from(x_q8))
        .wrapping_add(i64::from(inverse.d).wrapping_mul(i64::from(y_q8)))
        .wrapping_add(0x80);
    let x = ((x >> 8) as i32)
        .wrapping_add(inverse.tx)
        .wrapping_add(0x80)
        >> 8;
    let y = ((y >> 8) as i32)
        .wrapping_add(inverse.ty)
        .wrapping_add(0x80)
        >> 8;
    (x, y)
}

fn gf3258_fit_fallback_similarity(
    enrolled: &[Gf3258MatcherPoint],
    live: &[Gf3258MatcherPoint],
    pairs: &[(usize, usize)],
    current: Gf3258AffineQ8,
) -> Gf3258AffineQ8 {
    if pairs.len() <= 2 {
        return current;
    }

    let mut source_x_sum = 0i32;
    let mut source_y_sum = 0i32;
    let mut target_x_sum = 0i32;
    let mut target_y_sum = 0i32;
    let mut source_square_sum = 0i64;
    let mut dot_sum = 0i64;
    let mut cross_sum = 0i64;

    for &(enrolled_index, live_index) in pairs {
        let enrolled_point = enrolled[enrolled_index];
        let live_point = live[live_index];
        let source_x = i32::from(live_point.x_q8);
        let source_y = i32::from(live_point.y_q8);
        let target_x = i32::from(enrolled_point.x_q8);
        let target_y = i32::from(enrolled_point.y_q8);

        source_x_sum = source_x_sum.wrapping_add(source_x);
        source_y_sum = source_y_sum.wrapping_add(source_y);
        target_x_sum = target_x_sum.wrapping_add(target_x);
        target_y_sum = target_y_sum.wrapping_add(target_y);
        source_square_sum = source_square_sum
            .wrapping_add(i64::from(source_x).wrapping_mul(i64::from(source_x)))
            .wrapping_add(i64::from(source_y).wrapping_mul(i64::from(source_y)));
        dot_sum = dot_sum
            .wrapping_add(i64::from(source_x).wrapping_mul(i64::from(target_x)))
            .wrapping_add(i64::from(source_y).wrapping_mul(i64::from(target_y)));
        cross_sum = cross_sum
            .wrapping_add(i64::from(source_x).wrapping_mul(i64::from(target_y)))
            .wrapping_sub(i64::from(source_y).wrapping_mul(i64::from(target_x)));
    }

    let count = pairs.len() as i64;
    let source_mean_x = source_x_sum.wrapping_add(0x80) >> 8;
    let source_mean_y = source_y_sum.wrapping_add(0x80) >> 8;
    let source_square_pixels = source_square_sum.wrapping_add(0x8000) >> 16;
    let denominator = source_square_pixels
        .wrapping_mul(count)
        .wrapping_sub(i64::from(source_mean_x).wrapping_mul(i64::from(source_mean_x)))
        .wrapping_sub(i64::from(source_mean_y).wrapping_mul(i64::from(source_mean_y)));
    if denominator == 0 {
        return current;
    }

    let reciprocal = ((denominator >> 1).wrapping_add(0x8_0000_0000)) / denominator;
    let dot_pixels = dot_sum.wrapping_add(0x8000) >> 16;
    let cross_pixels = cross_sum.wrapping_add(0x8000) >> 16;
    let target_sum_x = target_x_sum.wrapping_add(0x80) >> 8;
    let target_sum_y = target_y_sum.wrapping_add(0x80) >> 8;
    let mean_square = i64::from(source_mean_x)
        .wrapping_mul(i64::from(source_mean_x))
        .wrapping_add(i64::from(source_mean_y).wrapping_mul(i64::from(source_mean_y)));
    let centroid_scale = mean_square
        .wrapping_mul(reciprocal)
        .wrapping_add(0x8_0000_0000)
        / count;
    let negative_reciprocal = reciprocal.wrapping_neg();

    let covariance_dot = dot_pixels
        .wrapping_mul(count)
        .wrapping_sub(i64::from(source_mean_x).wrapping_mul(i64::from(target_sum_x)))
        .wrapping_sub(i64::from(source_mean_y).wrapping_mul(i64::from(target_sum_y)));
    let covariance_cross = cross_pixels
        .wrapping_mul(count)
        .wrapping_add(i64::from(source_mean_y).wrapping_mul(i64::from(target_sum_x)))
        .wrapping_sub(i64::from(source_mean_x).wrapping_mul(i64::from(target_sum_y)));
    let a = covariance_dot.wrapping_mul(reciprocal) >> 27;
    let c = covariance_cross.wrapping_mul(reciprocal) >> 27;

    let scaled_mean_x = i64::from(source_mean_x).wrapping_mul(negative_reciprocal);
    let scaled_mean_y = negative_reciprocal.wrapping_mul(i64::from(source_mean_y));
    let tx = dot_pixels
        .wrapping_mul(scaled_mean_x)
        .wrapping_sub(cross_pixels.wrapping_mul(scaled_mean_y))
        .wrapping_add(i64::from(target_sum_x).wrapping_mul(centroid_scale))
        >> 27;
    let ty = dot_pixels
        .wrapping_mul(scaled_mean_y)
        .wrapping_add(cross_pixels.wrapping_mul(scaled_mean_x))
        .wrapping_add(i64::from(target_sum_y).wrapping_mul(centroid_scale))
        >> 27;

    Gf3258AffineQ8 {
        a: a as i32,
        b: (c as i32).wrapping_neg(),
        tx: tx as i32,
        c: c as i32,
        d: a as i32,
        ty: ty as i32,
    }
}

/// Reproduce raw `FUN_001aa830`: recover polarity-compatible correspondences
/// near the current policy affine and fit the vendor's fixed-point similarity
/// transform. Two or fewer correspondences leave the affine unchanged.
pub(crate) fn gf3258_fallback_policy_affine(
    sample: &Gf3258PersistedSample,
    live: &Gf3258OwnedVerificationMatcherFeature,
    current: Gf3258AffineQ8,
) -> Gf3258AffineQ8 {
    let enrolled = gf3258_persisted_geometry_points(sample);
    let live_set = live.as_feature_set();
    let enrolled_split = sample.matcher_polarity_split().min(enrolled.len());
    let live_split = live_set.polarity_split.min(live_set.points.len());
    let live_maps = [
        gf3258_fallback_label_map(&live_set.points[..live_split]),
        gf3258_fallback_label_map(&live_set.points[live_split..]),
    ];

    let mut pairs = Vec::new();
    for (partition, range) in [0..enrolled_split, enrolled_split..enrolled.len()]
        .into_iter()
        .enumerate()
    {
        let live_offset = if partition == 0 { 0 } else { live_split };
        for enrolled_index in range {
            let point = enrolled[enrolled_index];
            let (x, y) = gf3258_inverse_project_rounded_q8(current, point.x_q8, point.y_q8);
            if x < 0 || x >= GF3258_WIDTH as i32 || y < 0 || y >= GF3258_HEIGHT as i32 {
                continue;
            }
            let label = live_maps[partition][y as usize * GF3258_WIDTH + x as usize];
            if label >= 0 {
                pairs.push((enrolled_index, live_offset + label as usize));
            }
        }
    }

    gf3258_fit_fallback_similarity(&enrolled, live_set.points, &pairs, current)
}

#[inline]
fn gf3258_rescue_is_admitted(
    rescue_count: usize,
    quality: Gf3258VerificationGeometryQuality,
    transform: Gf3258AffineQ8,
) -> bool {
    let affine = gf3258_terminal_recovery_affine_metrics(transform);
    if affine.orthogonality_q16 > GF3258_RESCUE_MAX_ORTHOGONALITY_Q16
        || affine.scale_q8 < GF3258_RESCUE_MIN_SCALE_Q8
        || affine.scale_q8 > GF3258_RESCUE_MAX_SCALE_Q8
    {
        return false;
    }

    (quality.matched_points > 23 && quality.matched_percent > 40)
        || (quality.matched_points > 11 && quality.matched_percent > 45)
        || quality.matched_percent > 75
        || rescue_count > 16
}

#[inline]
fn gf3258_apply_work_quality_bonus(
    mut value: i32,
    quality: Option<Gf3258VerificationGeometryQuality>,
) -> i32 {
    let Some(quality) = quality else {
        return value;
    };
    if quality.matched_percent <= 0x1e {
        return value;
    }
    if quality.average_hash_hamming <= 9 {
        value = value.wrapping_add(1);
    }
    value.min(31)
}

fn gf3258_build_work_record(
    geometry_count_00: i32,
    primary_count_04: i32,
    rescue_count_08: i32,
    registration: Option<Gf3258VerificationRegistrationEvidence>,
    active_quality: Option<Gf3258VerificationGeometryQuality>,
) -> Gf3258VerificationWorkRecord {
    let geometry_count = gf3258_apply_work_quality_bonus(geometry_count_00, active_quality);
    let verification_metric = gf3258_finalize_geometry_work_metric(
        primary_count_04,
        rescue_count_08,
        active_quality.map_or(0, |quality| quality.matched_percent),
        active_quality.map_or(0, |quality| quality.average_hash_hamming),
    );
    let quality = active_quality.unwrap_or_default();

    let Some(registration) = registration else {
        return Gf3258VerificationWorkRecord {
            geometry_count,
            verification_metric,
            rescue_count: rescue_count_08,
            matched_percent: quality.matched_percent,
            geometry_percent: quality.geometry_ratio_percent,
            average_hash_hamming: quality.average_hash_hamming,
            ..Gf3258VerificationWorkRecord::default()
        };
    };

    Gf3258VerificationWorkRecord {
        geometry_count,
        verification_metric,
        rescue_count: rescue_count_08,
        map_score: registration.map_score,
        evidence: registration.evidence,
        scaled_coverage_q8: registration.scaled_coverage_q8,
        matched_percent: quality.matched_percent,
        geometry_percent: quality.geometry_ratio_percent,
        scale_penalty: registration.scale_penalty(),
        orthogonality_penalty: registration.orthogonality_penalty(),
        severe_orthogonality: registration.severe_orthogonality(),
        average_hash_hamming: quality.average_hash_hamming,
    }
}

/// Apply the GF3258 `FUN_001aabd0` fallback-preparation refresh to a mutable
/// policy work snapshot. The fallback affine is used only to recompute work
/// evidence and quality; it never replaces the caller's active policy affine.
pub(crate) fn gf3258_refresh_fallback_policy_work(
    record: &mut Gf3258VerificationWorkRecord,
    sample: &Gf3258PersistedSample,
    live: &Gf3258OwnedVerificationMatcherFeature,
    registration: Gf3258VerificationRegistrationInput<'_>,
    quality_scale_q8: i32,
    policy_transform_live_to_enrolled: Gf3258AffineQ8,
) -> Option<Gf3258AffineQ8> {
    let fallback = gf3258_fallback_policy_affine(sample, live, policy_transform_live_to_enrolled);
    let candidate =
        gf3258_verification_registration_evidence(sample, registration, fallback, quality_scale_q8);

    let replaces = candidate.map_score != 0x80
        && (record.map_score == 0x80 || candidate.evidence > record.evidence);
    if !replaces {
        return None;
    }

    record.map_score = candidate.map_score;
    record.evidence = candidate.evidence;
    record.scaled_coverage_q8 = candidate.scaled_coverage_q8;

    let enrolled = gf3258_persisted_geometry_points(sample);
    let enrolled_rescue = gf3258_persisted_rescue_data(sample);
    let quality = gf3258_verification_geometry_quality(
        &enrolled,
        &enrolled_rescue,
        live.as_feature_set(),
        live.rescue_data(),
        fallback,
        usize::try_from(record.verification_metric).unwrap_or(0),
    );
    record.matched_percent = quality.matched_percent;
    record.geometry_percent = quality.geometry_ratio_percent;
    record.average_hash_hamming = quality.average_hash_hamming;
    Some(fallback)
}

impl Gf3258PersistedVerificationWork {
    /// Convert the completed geometry/work state into the normal-loop input
    /// consumed by the already-recovered caller state machine.
    ///
    /// The state machine intentionally receives the pre-bonus primary count
    /// plus the active quality record because it reproduces the vendor's
    /// 70a80 bonus and caller max internally.
    pub fn normal_loop_sample_input(
        &self,
        post_geometry: Gf3258NormalLoopPostGeometryDisposition,
    ) -> Gf3258NormalLoopSampleInput {
        let quality = self.active_quality.unwrap_or_default();
        Gf3258NormalLoopSampleInput {
            primary_704f0_count: self.primary_geometry.final_inlier_count as i32,
            rescue_704f0_count: self.record.rescue_count,
            quality_28: quality.matched_percent,
            quality_134: quality.average_hash_hamming,
            transform_live_to_enrolled: self.policy_transform_live_to_enrolled,
            post_geometry,
        }
    }
}

/// Produce the GF3258 type-0x18 work state established by
/// `FUN_00172700 -> FUN_00170a80` and the caller's `max(work+0x04, work+0x08)`
/// merge.
///
/// The result preserves the vendor's independent count and evidence
/// selections. A refined or strong geometry can therefore affect an inlier
/// count without becoming the policy affine, or replace the policy affine
/// without being admitted as rescue geometry.
pub(crate) fn gf3258_persisted_sample_verification_work(
    sample: &Gf3258PersistedSample,
    live: &Gf3258OwnedVerificationMatcherFeature,
    registration: Gf3258VerificationRegistrationInput<'_>,
    config: Gf3258VerificationSampleConfig,
) -> Result<Gf3258PersistedVerificationWork, Gf3258PersistedVerificationWorkError> {
    let live_set = live.as_feature_set();
    let live_rescue = live.rescue_data();
    let candidates =
        gf3258_generate_persisted_sample_candidates(sample, live_set, config.candidate_matcher)?;
    let enrolled = gf3258_persisted_geometry_points(sample);
    let enrolled_rescue = gf3258_persisted_rescue_data(sample);
    let primary_stage = gf3258_primary_work_stage_from_candidates(
        sample,
        &enrolled,
        live_set,
        registration,
        config.quality_scale_q8,
        &candidates,
    )?;

    let primary_quality = match primary_stage.refined.as_ref() {
        Some(refined) if refined.final_inlier_count > primary_stage.initial.final_inlier_count => {
            Some(gf3258_verification_geometry_quality(
                &enrolled,
                &enrolled_rescue,
                live_set,
                live_rescue,
                refined.transform_live_to_enrolled,
                refined.final_inlier_count,
            ))
        }
        _ if primary_stage.initial.final_inlier_count > 4 => {
            Some(gf3258_verification_geometry_quality(
                &enrolled,
                &enrolled_rescue,
                live_set,
                live_rescue,
                primary_stage.policy_transform_live_to_enrolled,
                primary_stage.initial.final_inlier_count,
            ))
        }
        _ => None,
    };

    let mut registration_evidence = primary_stage.registration;
    let mut policy_transform_live_to_enrolled = primary_stage.policy_transform_live_to_enrolled;
    let mut active_quality = primary_quality;
    let mut geometry_count_00 = primary_stage.initial.final_inlier_count as i32;
    let primary_count_04 = primary_stage.selected_by_count.final_inlier_count as i32;
    let mut rescue_seed_inlier_count = 0usize;
    let mut rescue_candidate_inlier_count = 0usize;
    let mut rescue_candidate_quality = None;
    let mut admitted_rescue = None;
    let mut rescue_count_08 = 0i32;

    if geometry_count_00 <= GF3258_RESCUE_MAX_PRIMARY_INLIERS as i32
        && primary_count_04 <= GF3258_RESCUE_MAX_PRIMARY_INLIERS as i32
    {
        let seed = if primary_count_04 > 3 {
            Gf3258RescueSeed {
                inlier_count: primary_count_04 as usize,
                transform_live_to_enrolled: policy_transform_live_to_enrolled,
            }
        } else {
            let top_to_bottom = gf3258_weak_rescue_pair_slots(
                &enrolled,
                &enrolled_rescue,
                sample.matcher_polarity_split(),
                live_set,
                live_rescue,
                &candidates,
                Gf3258MatcherEdgeClass::Top,
                Gf3258MatcherEdgeClass::Bottom,
            );
            let bottom_to_top = gf3258_weak_rescue_pair_slots(
                &enrolled,
                &enrolled_rescue,
                sample.matcher_polarity_split(),
                live_set,
                live_rescue,
                &candidates,
                Gf3258MatcherEdgeClass::Bottom,
                Gf3258MatcherEdgeClass::Top,
            );
            let first = gf3258_matcher_geometry_from_pair_slots(
                &enrolled,
                live_set.points,
                &top_to_bottom,
            )?;
            let second = gf3258_matcher_geometry_from_pair_slots(
                &enrolled,
                live_set.points,
                &bottom_to_top,
            )?;
            if first.final_inlier_count > second.final_inlier_count {
                Gf3258RescueSeed::from(&first)
            } else {
                Gf3258RescueSeed::from(&second)
            }
        };

        rescue_seed_inlier_count = seed.inlier_count;
        if seed.inlier_count as i32 > geometry_count_00 {
            geometry_count_00 = seed.inlier_count as i32;
        }

        if seed.inlier_count >= GF3258_RESCUE_MIN_SEED_INLIERS {
            let strong_pair_slots = gf3258_strong_rescue_pair_slots(
                &enrolled,
                &enrolled_rescue,
                sample.matcher_polarity_split(),
                live_set,
                live_rescue,
                seed.transform_live_to_enrolled,
            );
            let strong = gf3258_matcher_geometry_from_pair_slots(
                &enrolled,
                live_set.points,
                &strong_pair_slots,
            )?;
            rescue_candidate_inlier_count = strong.final_inlier_count;

            if strong.final_inlier_count > seed.inlier_count {
                let strong_registration = gf3258_verification_registration_evidence(
                    sample,
                    registration,
                    strong.transform_live_to_enrolled,
                    config.quality_scale_q8,
                );
                if gf3258_registration_evidence_replaces(registration_evidence, strong_registration)
                {
                    registration_evidence = Some(strong_registration);
                    policy_transform_live_to_enrolled = strong.transform_live_to_enrolled;
                }

                let quality = gf3258_verification_geometry_quality(
                    &enrolled,
                    &enrolled_rescue,
                    live_set,
                    live_rescue,
                    strong.transform_live_to_enrolled,
                    strong.final_inlier_count,
                );
                rescue_candidate_quality = Some(quality);
                if gf3258_rescue_is_admitted(
                    strong.final_inlier_count,
                    quality,
                    strong.transform_live_to_enrolled,
                ) {
                    rescue_count_08 = strong.final_inlier_count as i32;
                    active_quality = Some(quality);
                    admitted_rescue = Some(strong);
                }
            }
        }
    }

    let record = gf3258_build_work_record(
        geometry_count_00,
        primary_count_04,
        rescue_count_08,
        registration_evidence,
        active_quality,
    );

    debug_assert_eq!(
        record.verification_metric,
        gf3258_finalize_geometry_work_metric(
            primary_count_04,
            rescue_count_08,
            active_quality.map_or(0, |quality| quality.matched_percent),
            active_quality.map_or(0, |quality| quality.average_hash_hamming),
        )
    );

    Ok(Gf3258PersistedVerificationWork {
        initial_geometry: primary_stage.initial,
        primary_geometry: primary_stage.selected_by_count,
        policy_transform_live_to_enrolled,
        registration_evidence,
        primary_quality,
        rescue_seed_inlier_count,
        rescue_candidate_inlier_count,
        rescue_candidate_quality,
        admitted_rescue,
        active_quality,
        record,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rescue_test_point(
        polarity: u16,
        x_q8: u16,
        y_q8: u16,
        hash28: u32,
        hash30: u32,
    ) -> Gf3258MatcherPoint {
        Gf3258MatcherPoint {
            polarity,
            x_q8,
            y_q8,
            orientation_q12: 0,
            descriptor_10_1f: [0; 16],
            hash20: 0,
            hash24: 0,
            hash28,
            hash30,
        }
    }

    fn rescue_test_data(
        edge_class: Gf3258MatcherEdgeClass,
        hash2c: u32,
        hash34: u32,
    ) -> Gf3258RescuePointData {
        Gf3258RescuePointData {
            edge_class,
            hash2c,
            hash34,
        }
    }

    #[test]
    fn rescue_hash_score_uses_better_normal_or_alternate_live_hash() {
        let enrolled = rescue_test_point(0, 10 << 8, 10 << 8, 0, 0);
        let live = rescue_test_point(0, 10 << 8, 10 << 8, u32::MAX, 0);
        let enrolled_rescue = rescue_test_data(Gf3258MatcherEdgeClass::Interior, 0, 0);
        let live_rescue = rescue_test_data(Gf3258MatcherEdgeClass::Interior, u32::MAX, 0);

        assert_eq!(
            gf3258_rescue_hash_hamming(&enrolled, enrolled_rescue, &live, live_rescue),
            0
        );
        assert_eq!(
            gf3258_weak_rescue_hash_hamming(&enrolled, enrolled_rescue, &live, live_rescue, true,),
            64
        );
        assert_eq!(
            gf3258_weak_rescue_hash_hamming(&enrolled, enrolled_rescue, &live, live_rescue, false,),
            0
        );
    }

    #[test]
    fn weak_rescue_pairs_only_cross_opposite_vertical_edges() {
        let enrolled = [rescue_test_point(0, 10 << 8, 5 << 8, 0, 0)];
        let live = [rescue_test_point(0, 10 << 8, 50 << 8, 0, 0)];
        let enrolled_rescue = [rescue_test_data(Gf3258MatcherEdgeClass::Top, 0, 0)];
        let live_rescue = [rescue_test_data(Gf3258MatcherEdgeClass::Bottom, 0, 0)];
        let mut pair_score_matrix = vec![0xff; GF3258_MATCH_SCORE_MATRIX_STRIDE];
        pair_score_matrix[0] = 0;
        let mut pair_normal_mode_matrix = vec![false; GF3258_MATCH_SCORE_MATRIX_STRIDE];
        pair_normal_mode_matrix[0] = true;
        let candidates = Gf3258CandidateGeneration {
            best_scores: vec![[0, GF3258_MATCH_SCORE_SENTINEL]],
            best_live_indices: vec![[0, -1]],
            pair_score_matrix,
            pair_normal_mode_matrix,
            selected: Vec::new(),
            pair_slots: [[-1; 2]; GF3258_MATCH_MAX_CANDIDATE_PAIRS],
        };
        let live_set = Gf3258MatcherFeatureSet {
            points: &live,
            polarity_split: 1,
        };

        let crossed = gf3258_weak_rescue_pair_slots(
            &enrolled,
            &enrolled_rescue,
            1,
            live_set,
            &live_rescue,
            &candidates,
            Gf3258MatcherEdgeClass::Top,
            Gf3258MatcherEdgeClass::Bottom,
        );
        assert_eq!(crossed[0], [0, 0]);

        let same_direction = gf3258_weak_rescue_pair_slots(
            &enrolled,
            &enrolled_rescue,
            1,
            live_set,
            &live_rescue,
            &candidates,
            Gf3258MatcherEdgeClass::Bottom,
            Gf3258MatcherEdgeClass::Top,
        );
        assert_eq!(same_direction[0], [-1, -1]);
    }

    #[test]
    fn strong_rescue_pairing_uses_seed_geometry_and_central_hashes() {
        let enrolled = [rescue_test_point(0, 20 << 8, 20 << 8, 0x55aa_55aa, 0)];
        let live = [rescue_test_point(0, 20 << 8, 20 << 8, 0x55aa_55aa, 0)];
        let enrolled_rescue = [rescue_test_data(
            Gf3258MatcherEdgeClass::Interior,
            0xaa55_aa55,
            0,
        )];
        let live_rescue = [rescue_test_data(
            Gf3258MatcherEdgeClass::Interior,
            0xaa55_aa55,
            0,
        )];

        let slots = gf3258_strong_rescue_pair_slots(
            &enrolled,
            &enrolled_rescue,
            1,
            Gf3258MatcherFeatureSet {
                points: &live,
                polarity_split: 1,
            },
            &live_rescue,
            Gf3258AffineQ8::IDENTITY,
        );
        assert_eq!(slots[0], [0, 0]);
    }

    #[test]
    fn rescue_quality_identity_counts_matches_and_hash_average() {
        let enrolled = [
            rescue_test_point(0, 12 << 8, 12 << 8, 0, 0),
            rescue_test_point(0, 24 << 8, 24 << 8, u32::MAX, 0),
        ];
        let live = enrolled;
        let enrolled_rescue = [
            rescue_test_data(Gf3258MatcherEdgeClass::Interior, 0, 0),
            rescue_test_data(Gf3258MatcherEdgeClass::Interior, u32::MAX, 0),
        ];
        let live_rescue = enrolled_rescue;
        let quality = gf3258_verification_geometry_quality(
            &enrolled,
            &enrolled_rescue,
            Gf3258MatcherFeatureSet {
                points: &live,
                polarity_split: 2,
            },
            &live_rescue,
            Gf3258AffineQ8::IDENTITY,
            4,
        );

        assert_eq!(
            quality,
            Gf3258VerificationGeometryQuality {
                admitted_points: 2,
                matched_points: 2,
                matched_percent: 100,
                geometry_ratio_percent: 200,
                average_hash_hamming: 0,
            }
        );
    }

    #[test]
    fn rescue_admission_uses_exact_quality_and_affine_thresholds() {
        assert!(gf3258_rescue_is_admitted(
            12,
            Gf3258VerificationGeometryQuality {
                matched_points: 12,
                matched_percent: 46,
                ..Default::default()
            },
            Gf3258AffineQ8::IDENTITY,
        ));
        assert!(!gf3258_rescue_is_admitted(
            12,
            Gf3258VerificationGeometryQuality {
                matched_points: 23,
                matched_percent: 41,
                ..Default::default()
            },
            Gf3258AffineQ8::IDENTITY,
        ));
        assert!(gf3258_rescue_is_admitted(
            17,
            Gf3258VerificationGeometryQuality::default(),
            Gf3258AffineQ8::IDENTITY,
        ));

        let bad_scale = Gf3258AffineQ8 {
            a: 0x120,
            d: 0x120,
            ..Gf3258AffineQ8::IDENTITY
        };
        assert!(!gf3258_rescue_is_admitted(
            31,
            Gf3258VerificationGeometryQuality {
                matched_points: 31,
                matched_percent: 100,
                ..Default::default()
            },
            bad_scale,
        ));
    }

    #[test]
    fn work_record_keeps_primary_quality_when_rescue_is_not_admitted() {
        let quality = Gf3258VerificationGeometryQuality {
            admitted_points: 20,
            matched_points: 10,
            matched_percent: 50,
            geometry_ratio_percent: 40,
            average_hash_hamming: 9,
        };
        let record = gf3258_build_work_record(30, 30, 0, None, Some(quality));

        assert_eq!(record.geometry_count, 31);
        assert_eq!(record.verification_metric, 31);
        assert_eq!(record.rescue_count, 0);
        assert_eq!(record.matched_percent, 50);
        assert_eq!(record.geometry_percent, 40);
        assert_eq!(record.average_hash_hamming, 9);
    }

    #[test]
    fn work_quality_bonus_uses_strict_percent_and_hash_boundaries() {
        let mut quality = Gf3258VerificationGeometryQuality {
            matched_percent: 31,
            average_hash_hamming: 9,
            ..Default::default()
        };
        assert_eq!(gf3258_apply_work_quality_bonus(30, Some(quality)), 31);
        assert_eq!(gf3258_apply_work_quality_bonus(31, Some(quality)), 31);

        quality.average_hash_hamming = 10;
        assert_eq!(gf3258_apply_work_quality_bonus(30, Some(quality)), 30);
        assert_eq!(gf3258_apply_work_quality_bonus(32, Some(quality)), 31);

        quality.matched_percent = 30;
        quality.average_hash_hamming = 9;
        assert_eq!(gf3258_apply_work_quality_bonus(30, Some(quality)), 30);
    }

    #[test]
    fn rescue_quality_rounding_is_symmetric_around_zero() {
        assert_eq!(gf3258_round_q16_to_q8_i64(0x7f), 0);
        assert_eq!(gf3258_round_q16_to_q8_i64(0x80), 1);
        assert_eq!(gf3258_round_q16_to_q8_i64(-0x7f), 0);
        assert_eq!(gf3258_round_q16_to_q8_i64(-0x80), -1);
        assert_eq!(gf3258_round_q16_to_q8_i64(-0x81), -1);
    }

    #[test]
    fn fallback_similarity_keeps_vendor_fixed_point_translation_rounding() {
        let points = [
            rescue_test_point(0, 10 << 8, 10 << 8, 0, 0),
            rescue_test_point(0, 20 << 8, 10 << 8, 0, 0),
            rescue_test_point(0, 10 << 8, 20 << 8, 0, 0),
        ];
        let pairs = [(0usize, 0usize), (1, 1), (2, 2)];

        assert_eq!(
            gf3258_fit_fallback_similarity(&points, &points, &pairs, Gf3258AffineQ8::IDENTITY,),
            Gf3258AffineQ8 {
                a: 256,
                b: 0,
                tx: -1,
                c: 0,
                d: 256,
                ty: -1,
            }
        );
    }

    #[test]
    fn fallback_similarity_preserves_seed_with_two_correspondences() {
        let points = [
            rescue_test_point(0, 10 << 8, 10 << 8, 0, 0),
            rescue_test_point(0, 20 << 8, 20 << 8, 0, 0),
        ];
        let pairs = [(0usize, 0usize), (1, 1)];
        let seed = Gf3258AffineQ8 {
            a: 260,
            b: -3,
            tx: 17,
            c: 3,
            d: 260,
            ty: -9,
        };

        assert_eq!(
            gf3258_fit_fallback_similarity(&points, &points, &pairs, seed),
            seed
        );
    }
}
