//! Candidate generation for GF3258 verification matching.
//!
//! This module reproduces the recovered descriptor/hash candidate stage:
//! `FUN_001b0e90 -> FUN_001afda0 -> FUN_001af9c0 -> FUN_001ae220`.

use super::{Gf3258ExtractedPrimaryPoint, Gf3258PrimaryFeatureExtraction};
use std::{error::Error, fmt};

/// Static-recovery revision for the first GF3258 verification matcher layer.
pub const GF3258_MATCH_CANDIDATES_REVISION: &str = "gf3258-match-candidates-v1";

/// FUN_001704f0 is called with exactly 0x1f pair slots for sensor type 0x18.
pub const GF3258_MATCH_MAX_CANDIDATE_PAIRS: usize = 0x1f;

/// FUN_001afda0 initializes each best/second score slot to 0xc0.
/// A newly measured pair must be strictly lower than this value to enter the
/// per-enrolled-point top-two set.
pub const GF3258_MATCH_SCORE_SENTINEL: i32 = 0xc0;

/// FUN_001afda0 stores the full score/mode table with a fixed live-point row
/// stride of 0xb4 bytes.
pub const GF3258_MATCH_SCORE_MATRIX_STRIDE: usize = 0xb4;

/// FUN_001ae220 treats two selected live locations as spatially colliding when
/// dx^2 + dy^2 <= 0xffff in the FeaturePoint60 Q8 coordinate domain.
pub const GF3258_MATCH_LIVE_DEDUP_DISTANCE_SQ_Q16: i32 = 0xffff;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gf3258MatchDescriptorMode {
    /// `desc[8..16]` is compared as stored. The hash side compares
    /// enrolled {+0x20,+0x28} with live {+0x20,+0x28}.
    Normal,
    /// `desc[8..16]` is compared against the bitwise complement of the live
    /// half. The hash side compares enrolled {+0x20,+0x28} with
    /// live {+0x24,+0x30}.
    Alternate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf3258MatcherPoint {
    /// FeaturePoint60 +0x00. Candidate generation does not read this field
    /// directly; FUN_001b0e90 partitions the point array before afda0.
    pub polarity: u16,
    /// FeaturePoint60 +0x02.
    pub x_q8: u16,
    /// FeaturePoint60 +0x04.
    pub y_q8: u16,
    /// FeaturePoint60 +0x06, signed/unsigned bit pattern of Q12 radians.
    pub orientation_q12: u16,
    /// FeaturePoint60 +0x10..+0x1f.
    pub descriptor_10_1f: [u8; 16],
    /// FeaturePoint60 +0x20.
    pub hash20: u32,
    /// FeaturePoint60 +0x24.
    pub hash24: u32,
    /// FeaturePoint60 +0x28.
    pub hash28: u32,
    /// FeaturePoint60 +0x30. This is required by afda0's alternate hash mode.
    pub hash30: u32,
}

impl Gf3258MatcherPoint {
    /// Build the matcher-facing prefix from the current fixture-free primary
    /// extractor.
    ///
    /// On the recovered GF3258 primary path c7b80/c8040 materialize +0x10..+0x27,
    /// while c7f40 clears +0x28..+0x37 before writing the central outputs. The
    /// current extractor already proves +0x24 is zero; +0x30 remains zero on
    /// this fresh-primary path. Persisted/vendor-decoded matcher points should
    /// instead be constructed explicitly so their stored +0x30 value is kept.
    pub fn from_extracted_primary(point: &Gf3258ExtractedPrimaryPoint, polarity: u16) -> Self {
        let compact = point.compact_descriptor().feature_point_bytes_10_2f();

        let mut descriptor_10_1f = [0u8; 16];
        descriptor_10_1f.copy_from_slice(&compact[..16]);

        let hash20 = u32::from_le_bytes(compact[0x10..0x14].try_into().unwrap());
        let hash24 = u32::from_le_bytes(compact[0x14..0x18].try_into().unwrap());
        let hash28 = u32::from_le_bytes(compact[0x18..0x1c].try_into().unwrap());

        Self {
            polarity,
            x_q8: point.core.x_q8,
            y_q8: point.core.y_q8,
            orientation_q12: point.core.orientation_q12,
            descriptor_10_1f,
            hash20,
            hash24,
            hash28,
            hash30: 0,
        }
    }
}

/// Geometry-free enrolled-point projection used by the recovered candidate
/// matcher. The afda0/ae220 front half reads only these persisted descriptor
/// and hash fields from the enrolled side; enrolled geometry is first needed
/// by the later 704f0/aef60 stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Gf3258EnrolledCandidatePoint {
    pub(crate) descriptor_10_1f: [u8; 16],
    pub(crate) hash20: u32,
    pub(crate) hash28: u32,
}

impl From<&Gf3258MatcherPoint> for Gf3258EnrolledCandidatePoint {
    fn from(point: &Gf3258MatcherPoint) -> Self {
        Self {
            descriptor_10_1f: point.descriptor_10_1f,
            hash20: point.hash20,
            hash28: point.hash28,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Gf3258EnrolledCandidateFeatureSet<'a> {
    pub(crate) points: &'a [Gf3258EnrolledCandidatePoint],
    pub(crate) polarity_split: usize,
}

trait EnrolledCandidatePoint {
    fn descriptor_10_1f(&self) -> &[u8; 16];
    fn hash20(&self) -> u32;
    fn hash28(&self) -> u32;
}

impl EnrolledCandidatePoint for Gf3258MatcherPoint {
    fn descriptor_10_1f(&self) -> &[u8; 16] {
        &self.descriptor_10_1f
    }

    fn hash20(&self) -> u32 {
        self.hash20
    }

    fn hash28(&self) -> u32 {
        self.hash28
    }
}

impl EnrolledCandidatePoint for Gf3258EnrolledCandidatePoint {
    fn descriptor_10_1f(&self) -> &[u8; 16] {
        &self.descriptor_10_1f
    }

    fn hash20(&self) -> u32 {
        self.hash20
    }

    fn hash28(&self) -> u32 {
        self.hash28
    }
}

/// One already-ordered FeaturePoint60 array.
///
/// `polarity_split` is Feature+0x108: points before the split are compared only
/// with the corresponding first partition in the other feature, and points at
/// or after the split only with the second partition. This preserves the vendor
/// behavior without re-sorting the point arrays.
#[derive(Debug, Clone, Copy)]
pub struct Gf3258MatcherFeatureSet<'a> {
    pub points: &'a [Gf3258MatcherPoint],
    pub polarity_split: usize,
}

/// Minimal enrolled-point geometry consumed by the GF3258 recovery-specific
/// `FUN_001b1310 -> FUN_001ae980 -> FUN_001ae550 -> FUN_001ae220` selector.
///
/// Unlike the normal `b0e90` front half, recovery scans the already-populated
/// score matrix in the inverse direction: two best enrolled points are retained
/// for each live point, and ae220's spatial collision rule is applied in the
/// enrolled coordinate domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf3258RecoveryEnrolledPoint {
    pub x_q8: u16,
    pub y_q8: u16,
}

/// Vertical edge band reconstructed for rescue matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Gf3258MatcherEdgeClass {
    Interior,
    Top,
    Bottom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Gf3258RescuePointData {
    pub(crate) edge_class: Gf3258MatcherEdgeClass,
    pub(crate) hash2c: u32,
    pub(crate) hash34: u32,
}

const GF3258_BF420_DESCRIPTOR_CONTROL: [bool; 8] =
    [false, true, true, false, true, false, false, true];

#[inline]
pub(crate) fn gf3258_matcher_edge_class(y_q8: u16) -> Gf3258MatcherEdgeClass {
    const EDGE_BAND_Q8: u16 = 20 << 8;
    const BOTTOM_START_Q8: u16 = ((super::GF3258_HEIGHT - 20) as u16) << 8;

    if y_q8 < EDGE_BAND_Q8 {
        Gf3258MatcherEdgeClass::Top
    } else if y_q8 >= BOTTOM_START_Q8 {
        Gf3258MatcherEdgeClass::Bottom
    } else {
        Gf3258MatcherEdgeClass::Interior
    }
}

pub(crate) fn gf3258_bf420_descriptor(descriptor: [u8; 16]) -> [u8; 16] {
    let mut transformed = [0u8; 16];
    for index in 0..8 {
        let first = descriptor[index * 2];
        let second = descriptor[index * 2 + 1];
        let mixed_low = (second & 0xf0) | (first & 0x0f);
        let mixed_high = (second & 0x0f) | (first & 0xf0);

        if GF3258_BF420_DESCRIPTOR_CONTROL[index] {
            transformed[index] = mixed_high;
            transformed[index + 8] = mixed_low;
        } else {
            transformed[index] = mixed_low;
            transformed[index + 8] = mixed_high;
        }
    }
    transformed
}

/// Owned verification-side matcher projection of one freshly extracted feature.
///
/// Construction applies the recovered raw-response polarity rule, BF420 mode 1,
/// and the vendor polarity partition once. Rescue metadata is kept in lockstep
/// with the public matcher points so later geometry stages cannot desynchronize
/// their indices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gf3258OwnedVerificationMatcherFeature {
    matcher: Gf3258OwnedMatcherFeature,
    rescue: Vec<Gf3258RescuePointData>,
}

impl Gf3258OwnedVerificationMatcherFeature {
    /// Build the exact type-0x18 verification-side matcher projection after
    /// BF420 mode 1. Rescue-only state is retained alongside each matcher
    /// point and follows the same unstable polarity partition.
    pub fn from_primary_extraction(extraction: &Gf3258PrimaryFeatureExtraction) -> Self {
        let mut projected = extraction
            .points
            .iter()
            .map(|point| {
                let polarity =
                    gf3258_matcher_polarity_from_raw_response(point.candidate.raw.response);
                let mut matcher = Gf3258MatcherPoint::from_extracted_primary(point, polarity);
                matcher.descriptor_10_1f = gf3258_bf420_descriptor(matcher.descriptor_10_1f);
                matcher.hash24 = matcher.hash20.reverse_bits();
                matcher.hash30 = matcher.hash28 ^ 0x00ff_ff00;

                let hash2c = point.compact_descriptor().median_hash_32;
                let rescue = Gf3258RescuePointData {
                    edge_class: gf3258_matcher_edge_class(matcher.y_q8),
                    hash2c,
                    hash34: hash2c.swap_bytes(),
                };
                (matcher, rescue)
            })
            .collect::<Vec<_>>();

        let polarity_split = gf3258_partition_by_polarity(&mut projected, |entry| entry.0.polarity);
        let (points, rescue): (Vec<_>, Vec<_>) = projected.into_iter().unzip();

        Self {
            matcher: Gf3258OwnedMatcherFeature {
                points,
                polarity_split,
            },
            rescue,
        }
    }

    pub fn as_feature_set(&self) -> Gf3258MatcherFeatureSet<'_> {
        self.matcher.as_feature_set()
    }

    pub fn point_count(&self) -> usize {
        self.matcher.points.len()
    }

    pub(crate) fn rescue_data(&self) -> &[Gf3258RescuePointData] {
        debug_assert_eq!(self.matcher.points.len(), self.rescue.len());
        &self.rescue
    }
}

/// Owned matcher-facing projection of one freshly extracted feature.
///
/// Construction applies the recovered raw-response polarity rule and the
/// vendor polarity partition exactly once, making this the reusable live-touch
/// boundary for diagnostics and enrollment-side matcher validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gf3258OwnedMatcherFeature {
    pub points: Vec<Gf3258MatcherPoint>,
    pub polarity_split: usize,
}

impl Gf3258OwnedMatcherFeature {
    pub fn from_primary_extraction(extraction: &Gf3258PrimaryFeatureExtraction) -> Self {
        let mut points = extraction
            .points
            .iter()
            .map(|point| {
                let polarity =
                    gf3258_matcher_polarity_from_raw_response(point.candidate.raw.response);
                Gf3258MatcherPoint::from_extracted_primary(point, polarity)
            })
            .collect::<Vec<_>>();
        let polarity_split = gf3258_partition_matcher_points(&mut points);

        Self {
            points,
            polarity_split,
        }
    }

    pub fn as_feature_set(&self) -> Gf3258MatcherFeatureSet<'_> {
        Gf3258MatcherFeatureSet {
            points: &self.points,
            polarity_split: self.polarity_split,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf3258CandidateMatcherConfig {
    /// matcher_config[0], used as the strict first-half prefilter:
    /// reject when d0 > this value.
    pub first_half_hamming_max: i32,
    /// matcher_config[1], applied independently to the normal and alternate
    /// 128-bit descriptor-mode scores.
    pub descriptor_mode_hamming_max: i32,
    /// matcher_config[2], left multiplier in:
    ///   best_multiplier * best < second_multiplier * second.
    pub ambiguity_best_multiplier: i32,
    /// matcher_config[3], right multiplier in the same strict ambiguity test.
    pub ambiguity_second_multiplier: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf3258PointPairScore {
    pub first_half_hamming: i32,
    pub second_half_hamming: i32,
    pub normal_descriptor_hamming: i32,
    pub alternate_descriptor_hamming: i32,
    pub normal_hash_hamming: Option<i32>,
    pub alternate_hash_hamming: Option<i32>,
    pub normal_total: i32,
    pub alternate_total: i32,
    pub selected_total: i32,
    pub selected_mode: Gf3258MatchDescriptorMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf3258SelectedCorrespondence {
    pub enrolled_index: i32,
    pub live_index: i32,
    pub best_score: i32,
    pub second_best_score: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gf3258CandidateGeneration {
    /// Per enrolled point: [best_score, second_best_score].
    pub best_scores: Vec<[i32; 2]>,
    /// Per enrolled point: [best_live_index, second_best_live_index].
    pub best_live_indices: Vec<[i32; 2]>,
    /// Vendor-shaped score matrix, initialized to 0xff. Rows are 0xb4 bytes.
    pub pair_score_matrix: Vec<u8>,
    /// Parallel afda0 mode matrix. `true` means normal_total < alternate_total;
    /// ties therefore record `false` (alternate), exactly like the vendor.
    pub pair_normal_mode_matrix: Vec<bool>,
    /// Surviving global records in vendor-maintained order.
    pub selected: Vec<Gf3258SelectedCorrespondence>,
    /// Exact 31 `(enrolled_index, live_index)` slots consumed by FUN_001704f0.
    /// Unused entries are `[-1, -1]`.
    pub pair_slots: [[i32; 2]; GF3258_MATCH_MAX_CANDIDATE_PAIRS],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gf3258CandidateMatchError {
    InvalidPolaritySplit {
        side: &'static str,
        split: usize,
        point_count: usize,
    },
    TooManyLivePoints {
        actual: usize,
        maximum: usize,
    },
    InvalidThreshold {
        field: &'static str,
        value: i32,
    },
    RecoveryScoreMatrixTooSmall {
        actual: usize,
        required: usize,
    },
}

impl fmt::Display for Gf3258CandidateMatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolaritySplit {
                side,
                split,
                point_count,
            } => write!(
                f,
                "GF3258 matcher {side} polarity split {split} exceeds point count {point_count}"
            ),
            Self::TooManyLivePoints { actual, maximum } => write!(
                f,
                "GF3258 matcher has {actual} live points; vendor score rows hold at most {maximum}"
            ),
            Self::InvalidThreshold { field, value } => {
                write!(
                    f,
                    "GF3258 matcher {field} must be non-negative; got {value}"
                )
            }
            Self::RecoveryScoreMatrixTooSmall { actual, required } => write!(
                f,
                "GF3258 recovery score matrix has {actual} bytes; at least {required} are required"
            ),
        }
    }
}

impl Error for Gf3258CandidateMatchError {}

/// Exact FUN_001af9c0 operation for `param_3 == 2`: XOR two 32-bit words and
/// sum the popcount of all eight bytes. Endianness does not change the result.
#[inline]
pub fn gf3258_hamming64_bytes(a: &[u8; 8], b: &[u8; 8]) -> i32 {
    let a0 = u32::from_ne_bytes(a[..4].try_into().unwrap());
    let a1 = u32::from_ne_bytes(a[4..].try_into().unwrap());
    let b0 = u32::from_ne_bytes(b[..4].try_into().unwrap());
    let b1 = u32::from_ne_bytes(b[4..].try_into().unwrap());

    ((a0 ^ b0).count_ones() + (a1 ^ b1).count_ones()) as i32
}

#[inline]
fn gf3258_hamming64_words(a0: u32, a1: u32, b0: u32, b1: u32) -> i32 {
    ((a0 ^ b0).count_ones() + (a1 ^ b1).count_ones()) as i32
}

/// Exact afda0 point-pair score.
///
/// Returns `None` when the first-half hard gate fails or when both descriptor
/// modes fail `descriptor_mode_hamming_max`.
pub fn gf3258_point_pair_score(
    enrolled: &Gf3258MatcherPoint,
    live: &Gf3258MatcherPoint,
    config: Gf3258CandidateMatcherConfig,
) -> Option<Gf3258PointPairScore> {
    gf3258_point_pair_score_core(enrolled, live, config)
}

fn gf3258_point_pair_score_core<E: EnrolledCandidatePoint>(
    enrolled: &E,
    live: &Gf3258MatcherPoint,
    config: Gf3258CandidateMatcherConfig,
) -> Option<Gf3258PointPairScore> {
    let enrolled_descriptor = enrolled.descriptor_10_1f();
    let enrolled_first: &[u8; 8] = enrolled_descriptor[..8].try_into().unwrap();
    let live_first: &[u8; 8] = live.descriptor_10_1f[..8].try_into().unwrap();
    let d0 = gf3258_hamming64_bytes(enrolled_first, live_first);

    if d0 > config.first_half_hamming_max {
        return None;
    }

    let enrolled_second: &[u8; 8] = enrolled_descriptor[8..].try_into().unwrap();
    let live_second: &[u8; 8] = live.descriptor_10_1f[8..].try_into().unwrap();
    let d1 = gf3258_hamming64_bytes(enrolled_second, live_second);

    let normal_descriptor = d0 + d1;
    let alternate_descriptor = d0 + (64 - d1);

    let normal_pass = normal_descriptor <= config.descriptor_mode_hamming_max;
    let alternate_pass = alternate_descriptor <= config.descriptor_mode_hamming_max;
    if !normal_pass && !alternate_pass {
        return None;
    }

    let normal_hash = normal_pass.then(|| {
        gf3258_hamming64_words(
            enrolled.hash20(),
            enrolled.hash28(),
            live.hash20,
            live.hash28,
        )
    });
    let alternate_hash = alternate_pass.then(|| {
        gf3258_hamming64_words(
            enrolled.hash20(),
            enrolled.hash28(),
            live.hash24,
            live.hash30,
        )
    });

    // A descriptor mode that failed its gate receives the vendor 0xc0
    // hash-side penalty before the lower complete total is selected.
    let normal_total = normal_descriptor + normal_hash.unwrap_or(GF3258_MATCH_SCORE_SENTINEL);
    let alternate_total =
        alternate_descriptor + alternate_hash.unwrap_or(GF3258_MATCH_SCORE_SENTINEL);

    let (selected_total, selected_mode) = if normal_total < alternate_total {
        (normal_total, Gf3258MatchDescriptorMode::Normal)
    } else {
        (alternate_total, Gf3258MatchDescriptorMode::Alternate)
    };

    Some(Gf3258PointPairScore {
        first_half_hamming: d0,
        second_half_hamming: d1,
        normal_descriptor_hamming: normal_descriptor,
        alternate_descriptor_hamming: alternate_descriptor,
        normal_hash_hamming: normal_hash,
        alternate_hash_hamming: alternate_hash,
        normal_total,
        alternate_total,
        selected_total,
        selected_mode,
    })
}

#[inline]
fn gf3258_live_distance_sq_q16(a: &Gf3258MatcherPoint, b: &Gf3258MatcherPoint) -> i32 {
    let dx = i32::from(a.x_q8) - i32::from(b.x_q8);
    let dy = i32::from(a.y_q8) - i32::from(b.y_q8);
    dx.wrapping_mul(dx).wrapping_add(dy.wrapping_mul(dy))
}

fn gf3258_update_top_two(
    best_scores: &mut [i32; 2],
    best_indices: &mut [i32; 2],
    score: i32,
    live_index: i32,
) {
    if score < best_scores[0] {
        best_scores[1] = best_scores[0];
        best_indices[1] = best_indices[0];
        best_scores[0] = score;
        best_indices[0] = live_index;
    } else if score < best_scores[1] {
        best_scores[1] = score;
        best_indices[1] = live_index;
    }
}

// The arguments mirror the recovered partition operation and its mutable outputs.
#[allow(clippy::too_many_arguments)]
fn gf3258_process_candidate_partition<E: EnrolledCandidatePoint>(
    enrolled: &[E],
    live: &[Gf3258MatcherPoint],
    enrolled_range: std::ops::Range<usize>,
    live_range: std::ops::Range<usize>,
    config: Gf3258CandidateMatcherConfig,
    best_scores: &mut [[i32; 2]],
    best_live_indices: &mut [[i32; 2]],
    score_matrix: &mut [u8],
    mode_matrix: &mut [bool],
) {
    for enrolled_index in enrolled_range {
        for live_index in live_range.clone() {
            let Some(score) =
                gf3258_point_pair_score_core(&enrolled[enrolled_index], &live[live_index], config)
            else {
                continue;
            };

            let matrix_index = enrolled_index * GF3258_MATCH_SCORE_MATRIX_STRIDE + live_index;
            score_matrix[matrix_index] = score.selected_total as u8;
            mode_matrix[matrix_index] = score.selected_mode == Gf3258MatchDescriptorMode::Normal;

            gf3258_update_top_two(
                &mut best_scores[enrolled_index],
                &mut best_live_indices[enrolled_index],
                score.selected_total,
                live_index as i32,
            );
        }
    }
}

// ae220 mutates storage by numeric index; preserve its exact scan/replacement order.
#[allow(clippy::needless_range_loop)]
pub(crate) fn gf3258_select_correspondences_from_top_two(
    live: &[Gf3258MatcherPoint],
    best_scores: &[[i32; 2]],
    best_live_indices: &[[i32; 2]],
    ambiguity_best_multiplier: i32,
    ambiguity_second_multiplier: i32,
) -> Vec<Gf3258SelectedCorrespondence> {
    debug_assert_eq!(best_scores.len(), best_live_indices.len());
    let mut selected: Vec<Gf3258SelectedCorrespondence> =
        Vec::with_capacity(GF3258_MATCH_MAX_CANDIDATE_PAIRS);

    for enrolled_index in 0..best_scores.len() {
        let best_live = best_live_indices[enrolled_index][0];
        let best_score = best_scores[enrolled_index][0];
        let second_score = best_scores[enrolled_index][1];

        if best_live < 0 {
            continue;
        }

        // FUN_001ae220 uses a strict scaled best-vs-second test.
        let lhs = ambiguity_best_multiplier.wrapping_mul(best_score);
        let rhs = ambiguity_second_multiplier.wrapping_mul(second_score);
        if lhs >= rhs {
            continue;
        }

        let candidate = Gf3258SelectedCorrespondence {
            enrolled_index: enrolled_index as i32,
            live_index: best_live,
            best_score,
            second_best_score: second_score,
        };

        let candidate_live = &live[best_live as usize];

        // Mirror ae220's in-place collision handling. Before the first
        // replacement, an equal/better existing point discards the new
        // candidate. Once the new candidate has replaced one collision, later
        // worse collisions are removed with swap-with-last semantics.
        let mut handled = false;
        let mut replaced_one = false;
        let mut discard = false;
        let mut i = 0usize;

        while i < selected.len() {
            let existing_live = &live[selected[i].live_index as usize];
            if gf3258_live_distance_sq_q16(candidate_live, existing_live)
                > GF3258_MATCH_LIVE_DEDUP_DISTANCE_SQ_Q16
            {
                i += 1;
                continue;
            }

            if candidate.best_score < selected[i].best_score {
                if replaced_one {
                    let last = selected.pop().unwrap();
                    if i < selected.len() {
                        selected[i] = last;
                    }
                    // The vendor advances after moving the last record into this
                    // slot rather than re-testing the moved record.
                    i += 1;
                } else {
                    selected[i] = candidate;
                    handled = true;
                    replaced_one = true;
                    i += 1;
                }
            } else {
                if !handled {
                    discard = true;
                    break;
                }
                i += 1;
            }
        }

        if discard || handled {
            continue;
        }

        if selected.len() == GF3258_MATCH_MAX_CANDIDATE_PAIRS {
            // ae220 scans in storage order and uses strict `<`, so a tie does
            // not replace the current worst entry.
            let mut worst_index = 0usize;
            let mut worst_score = selected[0].best_score;
            for i in 1..selected.len() {
                if worst_score < selected[i].best_score {
                    worst_index = i;
                    worst_score = selected[i].best_score;
                }
            }

            if candidate.best_score < worst_score {
                selected[worst_index] = candidate;
            }
        } else {
            selected.push(candidate);
        }
    }

    selected
}

/// Reproduce the GF3258 recovery-specific `FUN_001b1310` pair-slot selector
/// from an already-populated vendor-shaped score matrix.
///
/// `b1310` differs materially from the normal `b0e90` selector. It runs
/// `ae980` over the two polarity partitions to retain the best and second-best
/// *enrolled* score for each live point, then calls `ae220` with enrolled-point
/// geometry for collision suppression. `ae550` finally swaps ae220's internal
/// `(live, enrolled)` records back to the `(enrolled, live)` pair-slot order
/// consumed by `FUN_001704f0`.
// Recovery selection preserves the vendor storage-order scan and index-based replacement behavior.
#[allow(clippy::needless_range_loop)]
pub fn gf3258_generate_recovery_pair_slots_from_score_matrix(
    enrolled: &[Gf3258RecoveryEnrolledPoint],
    enrolled_polarity_split: usize,
    live: Gf3258MatcherFeatureSet<'_>,
    config: Gf3258CandidateMatcherConfig,
    score_matrix: &[u8],
) -> Result<[[i32; 2]; GF3258_MATCH_MAX_CANDIDATE_PAIRS], Gf3258CandidateMatchError> {
    if enrolled_polarity_split > enrolled.len() {
        return Err(Gf3258CandidateMatchError::InvalidPolaritySplit {
            side: "enrolled recovery",
            split: enrolled_polarity_split,
            point_count: enrolled.len(),
        });
    }
    if live.polarity_split > live.points.len() {
        return Err(Gf3258CandidateMatchError::InvalidPolaritySplit {
            side: "live recovery",
            split: live.polarity_split,
            point_count: live.points.len(),
        });
    }
    if live.points.len() > GF3258_MATCH_SCORE_MATRIX_STRIDE {
        return Err(Gf3258CandidateMatchError::TooManyLivePoints {
            actual: live.points.len(),
            maximum: GF3258_MATCH_SCORE_MATRIX_STRIDE,
        });
    }
    for (field, value) in [
        (
            "ambiguity_best_multiplier",
            config.ambiguity_best_multiplier,
        ),
        (
            "ambiguity_second_multiplier",
            config.ambiguity_second_multiplier,
        ),
    ] {
        if value < 0 {
            return Err(Gf3258CandidateMatchError::InvalidThreshold { field, value });
        }
    }

    let required = enrolled
        .len()
        .saturating_mul(GF3258_MATCH_SCORE_MATRIX_STRIDE);
    if score_matrix.len() < required {
        return Err(Gf3258CandidateMatchError::RecoveryScoreMatrixTooSmall {
            actual: score_matrix.len(),
            required,
        });
    }

    // ae980 owns one [best, second] pair per live point. Both values start at
    // 0xc0 and both indices at -1; score updates are strict `<`.
    let mut best_scores = vec![[GF3258_MATCH_SCORE_SENTINEL; 2]; live.points.len()];
    let mut best_enrolled_indices = vec![[-1i32; 2]; live.points.len()];

    for (enrolled_range, live_range) in [
        (0..enrolled_polarity_split, 0..live.polarity_split),
        (
            enrolled_polarity_split..enrolled.len(),
            live.polarity_split..live.points.len(),
        ),
    ] {
        for enrolled_index in enrolled_range {
            let row = enrolled_index * GF3258_MATCH_SCORE_MATRIX_STRIDE;
            for live_index in live_range.clone() {
                gf3258_update_top_two(
                    &mut best_scores[live_index],
                    &mut best_enrolled_indices[live_index],
                    i32::from(score_matrix[row + live_index]),
                    enrolled_index as i32,
                );
            }
        }
    }

    // ae220's generic record ordering is [source index, nominated target index,
    // best score, second score]. For b1310, the source index is LIVE while the
    // target index and collision geometry are ENROLLED.
    let mut selected: Vec<[i32; 4]> = Vec::with_capacity(GF3258_MATCH_MAX_CANDIDATE_PAIRS);

    for live_index in 0..live.points.len() {
        let enrolled_index = best_enrolled_indices[live_index][0];
        let best_score = best_scores[live_index][0];
        let second_score = best_scores[live_index][1];
        if enrolled_index < 0 {
            continue;
        }

        let lhs = config.ambiguity_best_multiplier.wrapping_mul(best_score);
        let rhs = config
            .ambiguity_second_multiplier
            .wrapping_mul(second_score);
        if lhs >= rhs {
            continue;
        }

        let candidate = [live_index as i32, enrolled_index, best_score, second_score];
        let candidate_geometry = enrolled[enrolled_index as usize];

        let mut handled = false;
        let mut replaced_one = false;
        let mut discard = false;
        let mut index = 0usize;
        while index < selected.len() {
            let existing = selected[index];
            let existing_geometry = enrolled[existing[1] as usize];
            let dx =
                i32::from(candidate_geometry.x_q8).wrapping_sub(i32::from(existing_geometry.x_q8));
            let dy =
                i32::from(candidate_geometry.y_q8).wrapping_sub(i32::from(existing_geometry.y_q8));
            let distance_sq = dx.wrapping_mul(dx).wrapping_add(dy.wrapping_mul(dy));
            if distance_sq > GF3258_MATCH_LIVE_DEDUP_DISTANCE_SQ_Q16 {
                index += 1;
                continue;
            }

            if best_score < existing[2] {
                if replaced_one {
                    let last = selected.pop().unwrap();
                    if index < selected.len() {
                        selected[index] = last;
                    }
                    index += 1;
                } else {
                    selected[index] = candidate;
                    handled = true;
                    replaced_one = true;
                    index += 1;
                }
            } else {
                if !handled {
                    discard = true;
                    break;
                }
                index += 1;
            }
        }

        if discard || handled {
            continue;
        }

        if selected.len() == GF3258_MATCH_MAX_CANDIDATE_PAIRS {
            let mut worst_index = 0usize;
            let mut worst_score = selected[0][2];
            for index in 1..selected.len() {
                if worst_score < selected[index][2] {
                    worst_index = index;
                    worst_score = selected[index][2];
                }
            }
            if best_score < worst_score {
                selected[worst_index] = candidate;
            }
        } else {
            selected.push(candidate);
        }
    }

    let mut pair_slots = [[-1i32, -1i32]; GF3258_MATCH_MAX_CANDIDATE_PAIRS];
    for (slot, candidate) in selected.into_iter().enumerate() {
        // ae550 swaps ae220's internal `(live, enrolled)` pair.
        pair_slots[slot] = [candidate[1], candidate[0]];
    }
    Ok(pair_slots)
}

/// Exact recovered FeaturePoint polarity source: strict signed raw response < 0.
pub fn gf3258_matcher_polarity_from_raw_response(raw_response: i32) -> u16 {
    u16::from(raw_response < 0)
}

/// Reproduce FUN_001b3970's unstable binary polarity partition.
///
/// Class 0 is placed before class 1. The returned index is the recovered
/// Feature+0x108 partition boundary consumed by matcher candidate generation.
fn gf3258_partition_by_polarity<T, F>(items: &mut [T], polarity: F) -> usize
where
    F: Fn(&T) -> u16,
{
    let mut front = 0usize;
    let mut back = items.len();

    while front < back {
        while front < back && (polarity(&items[front]) & 3) == 0 {
            front += 1;
        }
        while front < back && (polarity(&items[back - 1]) & 3) == 1 {
            back -= 1;
        }
        if front < back {
            items.swap(front, back - 1);
            front += 1;
            back -= 1;
        }
    }

    front
}

pub fn gf3258_partition_matcher_points(points: &mut [Gf3258MatcherPoint]) -> usize {
    gf3258_partition_by_polarity(points, |point| point.polarity)
}

/// Reproduce the GF3258 `b0e90 -> afda0 -> ae220` candidate-generation stage.
///
/// This intentionally stops at the 31 `(enrolled_index, live_index)` slots.
/// The next matcher layer is FUN_001704f0's geometric hypothesis/inlier stage.
pub fn gf3258_generate_match_candidates(
    enrolled: Gf3258MatcherFeatureSet<'_>,
    live: Gf3258MatcherFeatureSet<'_>,
    config: Gf3258CandidateMatcherConfig,
) -> Result<Gf3258CandidateGeneration, Gf3258CandidateMatchError> {
    gf3258_generate_match_candidates_core(enrolled.points, enrolled.polarity_split, live, config)
}

/// Run the exact recovered b0e90 -> afda0 -> ae220 candidate stage against an
/// enrolled sample reconstructed from persistent descriptor/hash bytes.
///
/// The returned pair slots are matcher-ready indices, but the subsequent
/// 704f0/aef60 geometry stage still requires the vendor's persisted-point
/// geometry import semantics.
pub(crate) fn gf3258_generate_enrolled_match_candidates(
    enrolled: Gf3258EnrolledCandidateFeatureSet<'_>,
    live: Gf3258MatcherFeatureSet<'_>,
    config: Gf3258CandidateMatcherConfig,
) -> Result<Gf3258CandidateGeneration, Gf3258CandidateMatchError> {
    gf3258_generate_match_candidates_core(enrolled.points, enrolled.polarity_split, live, config)
}

fn gf3258_generate_match_candidates_core<E: EnrolledCandidatePoint>(
    enrolled: &[E],
    enrolled_polarity_split: usize,
    live: Gf3258MatcherFeatureSet<'_>,
    config: Gf3258CandidateMatcherConfig,
) -> Result<Gf3258CandidateGeneration, Gf3258CandidateMatchError> {
    if enrolled_polarity_split > enrolled.len() {
        return Err(Gf3258CandidateMatchError::InvalidPolaritySplit {
            side: "enrolled",
            split: enrolled_polarity_split,
            point_count: enrolled.len(),
        });
    }
    if live.polarity_split > live.points.len() {
        return Err(Gf3258CandidateMatchError::InvalidPolaritySplit {
            side: "live",
            split: live.polarity_split,
            point_count: live.points.len(),
        });
    }
    if live.points.len() > GF3258_MATCH_SCORE_MATRIX_STRIDE {
        return Err(Gf3258CandidateMatchError::TooManyLivePoints {
            actual: live.points.len(),
            maximum: GF3258_MATCH_SCORE_MATRIX_STRIDE,
        });
    }

    for (field, value) in [
        ("first_half_hamming_max", config.first_half_hamming_max),
        (
            "descriptor_mode_hamming_max",
            config.descriptor_mode_hamming_max,
        ),
        (
            "ambiguity_best_multiplier",
            config.ambiguity_best_multiplier,
        ),
        (
            "ambiguity_second_multiplier",
            config.ambiguity_second_multiplier,
        ),
    ] {
        if value < 0 {
            return Err(Gf3258CandidateMatchError::InvalidThreshold { field, value });
        }
    }

    let mut best_scores = vec![[GF3258_MATCH_SCORE_SENTINEL; 2]; enrolled.len()];
    let mut best_live_indices = vec![[-1; 2]; enrolled.len()];
    let mut pair_score_matrix = vec![0xffu8; enrolled.len() * GF3258_MATCH_SCORE_MATRIX_STRIDE];
    let mut pair_normal_mode_matrix =
        vec![false; enrolled.len() * GF3258_MATCH_SCORE_MATRIX_STRIDE];

    gf3258_process_candidate_partition(
        enrolled,
        live.points,
        0..enrolled_polarity_split,
        0..live.polarity_split,
        config,
        &mut best_scores,
        &mut best_live_indices,
        &mut pair_score_matrix,
        &mut pair_normal_mode_matrix,
    );

    gf3258_process_candidate_partition(
        enrolled,
        live.points,
        enrolled_polarity_split..enrolled.len(),
        live.polarity_split..live.points.len(),
        config,
        &mut best_scores,
        &mut best_live_indices,
        &mut pair_score_matrix,
        &mut pair_normal_mode_matrix,
    );

    let selected = gf3258_select_correspondences_from_top_two(
        live.points,
        &best_scores,
        &best_live_indices,
        config.ambiguity_best_multiplier,
        config.ambiguity_second_multiplier,
    );

    let mut pair_slots = [[-1i32, -1i32]; GF3258_MATCH_MAX_CANDIDATE_PAIRS];
    for (slot, candidate) in selected.iter().enumerate() {
        pair_slots[slot] = [candidate.enrolled_index, candidate.live_index];
    }

    Ok(Gf3258CandidateGeneration {
        best_scores,
        best_live_indices,
        pair_score_matrix,
        pair_normal_mode_matrix,
        selected,
        pair_slots,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn polarity_uses_strict_signed_negative_response() {
        assert_eq!(gf3258_matcher_polarity_from_raw_response(-1), 1);
        assert_eq!(gf3258_matcher_polarity_from_raw_response(0), 0);
        assert_eq!(gf3258_matcher_polarity_from_raw_response(1), 0);
    }

    #[test]
    fn verification_edge_class_matches_decode_finger_template_bands() {
        assert_eq!(gf3258_matcher_edge_class(0), Gf3258MatcherEdgeClass::Top);
        assert_eq!(
            gf3258_matcher_edge_class((20 << 8) - 1),
            Gf3258MatcherEdgeClass::Top
        );
        assert_eq!(
            gf3258_matcher_edge_class(20 << 8),
            Gf3258MatcherEdgeClass::Interior
        );
        assert_eq!(
            gf3258_matcher_edge_class((44 << 8) - 1),
            Gf3258MatcherEdgeClass::Interior
        );
        assert_eq!(
            gf3258_matcher_edge_class(44 << 8),
            Gf3258MatcherEdgeClass::Bottom
        );
        assert_eq!(
            gf3258_matcher_edge_class((64 << 8) - 1),
            Gf3258MatcherEdgeClass::Bottom
        );
    }

    #[test]
    fn bf420_descriptor_permutation_matches_recovered_pair_layout() {
        let descriptor = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        assert_eq!(
            gf3258_bf420_descriptor(descriptor),
            [0, 3, 5, 6, 9, 10, 12, 15, 1, 2, 4, 7, 8, 11, 13, 14]
        );
    }

    #[test]
    fn polarity_partition_preserves_vendor_unstable_order() {
        let mut points = [
            matcher_test_point_with_polarity(1, 1),
            matcher_test_point_with_polarity(2, 0),
            matcher_test_point_with_polarity(3, 1),
            matcher_test_point_with_polarity(4, 0),
        ];

        let split = gf3258_partition_matcher_points(&mut points);
        assert_eq!(split, 2);
        assert_eq!(
            points
                .iter()
                .map(|point| point.polarity)
                .collect::<Vec<_>>(),
            vec![0, 0, 1, 1]
        );
        assert_eq!(
            points.iter().map(|point| point.x_q8).collect::<Vec<_>>(),
            vec![4, 2, 3, 1]
        );
    }

    fn matcher_test_point_with_polarity(id: u16, polarity: u16) -> Gf3258MatcherPoint {
        Gf3258MatcherPoint {
            polarity,
            x_q8: id,
            y_q8: 0,
            orientation_q12: 0,
            descriptor_10_1f: [0; 16],
            hash20: 0,
            hash24: 0,
            hash28: 0,
            hash30: 0,
        }
    }

    #[test]
    fn hamming64_is_exact_xor_popcount() {
        let a = [0x00u8; 8];
        let b = [0xffu8; 8];
        assert_eq!(gf3258_hamming64_bytes(&a, &b), 64);

        let c = [0x55u8; 8];
        let d = [0xaau8; 8];
        assert_eq!(gf3258_hamming64_bytes(&c, &d), 64);

        assert_eq!(gf3258_hamming64_bytes(&c, &c), 0);
    }

    fn matcher_test_point(
        x_q8: u16,
        y_q8: u16,
        descriptor_10_1f: [u8; 16],
        hash20: u32,
        hash24: u32,
        hash28: u32,
        hash30: u32,
    ) -> Gf3258MatcherPoint {
        Gf3258MatcherPoint {
            polarity: 0,
            x_q8,
            y_q8,
            orientation_q12: 0,
            descriptor_10_1f,
            hash20,
            hash24,
            hash28,
            hash30,
        }
    }

    #[test]
    fn normal_and_alternate_pair_scores_are_exact() {
        let enrolled = matcher_test_point(0, 0, [0u8; 16], 0, 0, 0, 0);

        let mut live_desc = [0u8; 16];
        live_desc[8..].fill(0xff);
        let live = matcher_test_point(0, 0, live_desc, 0xffff_ffff, 0, 0xffff_ffff, 0);

        let cfg = Gf3258CandidateMatcherConfig {
            first_half_hamming_max: 64,
            descriptor_mode_hamming_max: 128,
            ambiguity_best_multiplier: 1,
            ambiguity_second_multiplier: 1,
        };

        let score = gf3258_point_pair_score(&enrolled, &live, cfg).unwrap();
        assert_eq!(score.first_half_hamming, 0);
        assert_eq!(score.second_half_hamming, 64);
        assert_eq!(score.normal_descriptor_hamming, 64);
        assert_eq!(score.alternate_descriptor_hamming, 0);
        assert_eq!(score.normal_hash_hamming, Some(64));
        assert_eq!(score.alternate_hash_hamming, Some(0));
        assert_eq!(score.normal_total, 128);
        assert_eq!(score.alternate_total, 0);
        assert_eq!(score.selected_total, 0);
        assert_eq!(score.selected_mode, Gf3258MatchDescriptorMode::Alternate);
    }

    #[test]
    fn candidate_search_retains_two_strictly_best_live_points() {
        let enrolled = [matcher_test_point(0, 0, [0; 16], 0, 0, 0, 0)];
        let mut d1 = [0u8; 16];
        d1[0] = 0x01;
        let mut d2 = [0u8; 16];
        d2[0] = 0x03;

        let live = [
            matcher_test_point(0x0000, 0, [0; 16], 0, 0, 0, 0),
            matcher_test_point(0x0200, 0, d1, 0, 0, 0, 0),
            matcher_test_point(0x0400, 0, d2, 0, 0, 0, 0),
        ];

        let cfg = Gf3258CandidateMatcherConfig {
            first_half_hamming_max: 64,
            descriptor_mode_hamming_max: 128,
            ambiguity_best_multiplier: 1,
            ambiguity_second_multiplier: 2,
        };

        let result = gf3258_generate_match_candidates(
            Gf3258MatcherFeatureSet {
                points: &enrolled,
                polarity_split: 1,
            },
            Gf3258MatcherFeatureSet {
                points: &live,
                polarity_split: 3,
            },
            cfg,
        )
        .unwrap();

        assert_eq!(result.best_live_indices[0], [0, 1]);
        assert_eq!(result.best_scores[0][0], 0);
        assert!(result.best_scores[0][1] > 0);
    }

    #[test]
    fn selected_correspondences_deduplicate_live_points_within_one_pixel() {
        let enrolled = [
            matcher_test_point(0, 0, [0; 16], 0, 0, 0, 0),
            matcher_test_point(0, 0, [0; 16], 0, 0, 0, 0),
        ];
        let mut second_desc = [0u8; 16];
        second_desc[0] = 0x01;
        let live = [
            matcher_test_point(0x1000, 0x1000, [0; 16], 0, 0, 0, 0),
            // 0.5 px away in x: squared Q8 distance is 0x4000 <= 0xffff.
            // Its one-bit descriptor penalty also gives the ratio test a
            // nonzero second-best score.
            matcher_test_point(0x1080, 0x1000, second_desc, 0, 0, 0, 0),
        ];

        let cfg = Gf3258CandidateMatcherConfig {
            first_half_hamming_max: 64,
            descriptor_mode_hamming_max: 128,
            ambiguity_best_multiplier: 1,
            ambiguity_second_multiplier: 2,
        };

        let result = gf3258_generate_match_candidates(
            Gf3258MatcherFeatureSet {
                points: &enrolled,
                polarity_split: 2,
            },
            Gf3258MatcherFeatureSet {
                points: &live,
                polarity_split: 2,
            },
            cfg,
        )
        .unwrap();

        // Both enrolled points nominate the same zero-score live point. ae220
        // keeps only one correspondence at that location.
        assert_eq!(result.selected.len(), 1);
        assert_eq!(result.pair_slots[0][1], 0);
        assert_eq!(result.pair_slots[1], [-1, -1]);
    }

    #[test]
    fn persisted_enrolled_pair_projection_matches_full_point_score() {
        let enrolled = matcher_test_point(
            0x1234,
            0x5678,
            [0x5a; 16],
            0x1122_3344,
            0xaabb_ccdd,
            0x5566_7788,
            0xdead_beef,
        );
        let live = matcher_test_point(
            0x0100,
            0x0200,
            [0xa5; 16],
            0x0102_0304,
            0x1020_3040,
            0x5060_7080,
            0x90a0_b0c0,
        );
        let config = Gf3258CandidateMatcherConfig {
            first_half_hamming_max: 64,
            descriptor_mode_hamming_max: 128,
            ambiguity_best_multiplier: 40,
            ambiguity_second_multiplier: 38,
        };

        let persisted_projection = Gf3258EnrolledCandidatePoint::from(&enrolled);
        assert_eq!(
            gf3258_point_pair_score_core(&persisted_projection, &live, config),
            gf3258_point_pair_score(&enrolled, &live, config)
        );
    }

    #[test]
    fn persisted_enrolled_candidate_generation_matches_full_feature_generation() {
        let enrolled = [
            matcher_test_point(0x1111, 0x2222, [0; 16], 0, 0x1111_1111, 0, 0x2222_2222),
            matcher_test_point(0x3333, 0x4444, [0x55; 16], 0xaaaa_aaaa, 0, 0x5555_5555, 0),
        ];
        let persisted = enrolled
            .iter()
            .map(Gf3258EnrolledCandidatePoint::from)
            .collect::<Vec<_>>();
        let mut d1 = [0u8; 16];
        d1[0] = 1;
        let live = [
            matcher_test_point(0x1000, 0x1000, [0; 16], 0, 0, 0, 0),
            matcher_test_point(0x3000, 0x3000, d1, 0, 0, 0, 0),
            matcher_test_point(0x5000, 0x5000, [0x55; 16], 0xaaaa_aaaa, 0, 0x5555_5555, 0),
        ];
        let config = Gf3258CandidateMatcherConfig {
            first_half_hamming_max: 64,
            descriptor_mode_hamming_max: 128,
            ambiguity_best_multiplier: 1,
            ambiguity_second_multiplier: 2,
        };

        let full = gf3258_generate_match_candidates(
            Gf3258MatcherFeatureSet {
                points: &enrolled,
                polarity_split: 1,
            },
            Gf3258MatcherFeatureSet {
                points: &live,
                polarity_split: 2,
            },
            config,
        )
        .unwrap();
        let reloaded = gf3258_generate_enrolled_match_candidates(
            Gf3258EnrolledCandidateFeatureSet {
                points: &persisted,
                polarity_split: 1,
            },
            Gf3258MatcherFeatureSet {
                points: &live,
                polarity_split: 2,
            },
            config,
        )
        .unwrap();

        assert_eq!(reloaded, full);
    }

    #[test]
    fn recovery_inverse_selector_uses_best_enrolled_point_per_live_point() {
        let enrolled = [
            Gf3258RecoveryEnrolledPoint {
                x_q8: 0x1000,
                y_q8: 0x1000,
            },
            Gf3258RecoveryEnrolledPoint {
                x_q8: 0x3000,
                y_q8: 0x1000,
            },
            Gf3258RecoveryEnrolledPoint {
                x_q8: 0x5000,
                y_q8: 0x1000,
            },
        ];
        let live = [
            matcher_test_point(0x0800, 0x0800, [0; 16], 0, 0, 0, 0),
            matcher_test_point(0x1800, 0x0800, [0; 16], 0, 0, 0, 0),
        ];
        let mut matrix = vec![0xff; enrolled.len() * GF3258_MATCH_SCORE_MATRIX_STRIDE];
        matrix[0] = 10;
        matrix[GF3258_MATCH_SCORE_MATRIX_STRIDE] = 20;
        matrix[2 * GF3258_MATCH_SCORE_MATRIX_STRIDE] = 30;
        matrix[1] = 40;
        matrix[GF3258_MATCH_SCORE_MATRIX_STRIDE + 1] = 5;
        matrix[2 * GF3258_MATCH_SCORE_MATRIX_STRIDE + 1] = 50;
        let config = Gf3258CandidateMatcherConfig {
            first_half_hamming_max: 0,
            descriptor_mode_hamming_max: 0,
            ambiguity_best_multiplier: 1,
            ambiguity_second_multiplier: 2,
        };

        let slots = gf3258_generate_recovery_pair_slots_from_score_matrix(
            &enrolled,
            3,
            Gf3258MatcherFeatureSet {
                points: &live,
                polarity_split: 2,
            },
            config,
            &matrix,
        )
        .unwrap();

        assert_eq!(slots[0], [0, 0]);
        assert_eq!(slots[1], [1, 1]);
        assert_eq!(slots[2], [-1, -1]);
    }

    #[test]
    fn recovery_inverse_selector_deduplicates_in_enrolled_geometry_domain() {
        let enrolled = [
            Gf3258RecoveryEnrolledPoint {
                x_q8: 0x1000,
                y_q8: 0x1000,
            },
            // Within ae220's <= 0xffff collision radius of point 0.
            Gf3258RecoveryEnrolledPoint {
                x_q8: 0x1080,
                y_q8: 0x1000,
            },
        ];
        let live = [
            matcher_test_point(0x0800, 0x0800, [0; 16], 0, 0, 0, 0),
            matcher_test_point(0x7000, 0x7000, [0; 16], 0, 0, 0, 0),
        ];
        let mut matrix = vec![0xff; enrolled.len() * GF3258_MATCH_SCORE_MATRIX_STRIDE];
        matrix[0] = 20;
        matrix[GF3258_MATCH_SCORE_MATRIX_STRIDE] = 50;
        matrix[1] = 40;
        matrix[GF3258_MATCH_SCORE_MATRIX_STRIDE + 1] = 10;
        let config = Gf3258CandidateMatcherConfig {
            first_half_hamming_max: 0,
            descriptor_mode_hamming_max: 0,
            ambiguity_best_multiplier: 1,
            ambiguity_second_multiplier: 2,
        };

        let slots = gf3258_generate_recovery_pair_slots_from_score_matrix(
            &enrolled,
            2,
            Gf3258MatcherFeatureSet {
                points: &live,
                polarity_split: 2,
            },
            config,
            &matrix,
        )
        .unwrap();

        // The second candidate has the lower score, so ae220 replaces the
        // colliding first candidate even though the LIVE points are far apart.
        assert_eq!(slots[0], [1, 1]);
        assert_eq!(slots[1], [-1, -1]);
    }
}
