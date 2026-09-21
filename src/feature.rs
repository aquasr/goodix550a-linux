use std::{error::Error, fmt};

pub const GF3258_WIDTH: usize = 80;
pub const GF3258_HEIGHT: usize = 64;
pub const GF3258_PIXELS: usize = GF3258_WIDTH * GF3258_HEIGHT;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeatureError {
    UnexpectedPixelCount { expected: usize, actual: usize },
}

impl fmt::Display for FeatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedPixelCount { expected, actual } => write!(
                f,
                "GF3258 algorithm image has {actual} pixels; expected {expected} (80x64)"
            ),
        }
    }
}

impl Error for FeatureError {}

mod filter;

mod detector;
pub use detector::{
    FallbackExtremum, GAUSS_300, GAUSS_301, GAUSS_302, GAUSS_303, GAUSS_304, GAUSS_305, GAUSS_306,
    GAUSS_307, GAUSS_308, GF3258_DOG_CONTRAST_THRESHOLD, GF3258_DOG_LEVELS, GF3258_EXTREMA_BORDER,
    GF3258_INTERPOLATED_CONTRAST_MIN, GF3258_INVALID_OFFSET_Q12, GF3258_MAX_REFINED_LEVEL,
    GF3258_MAX_REFINEMENT_ITERS, GF3258_MIN_REFINED_LEVEL, GF3258_PYRAMID_LEVELS,
    GF3258_SETTLED_Q12, Gf3258ScaleSpace, RawExtremum, RefinedExtremum, RefinementFailure,
    RefinementOutcome, exp2_q16,
};

mod orientation;
pub use orientation::{
    GF3258_C6D90_HALF_DEGREE_FACTOR, GF3258_C6D90_TENSOR_RADIUS, GF3258_C7310_DIRECTION_OFFSETS,
    GF3258_C7310_REVISION, GF3258_C7310_WEIGHTS, GF3258_CORDIC_GAIN_INV_Q16,
    GF3258_GRADIENT_GAUSS_0, GF3258_GRADIENT_GAUSS_1, GF3258_GRADIENT_MAGNITUDE_MAX,
    GF3258_GRADIENT_PLANES_REVISION, GF3258_ORIENTATION_BIN_Q9, GF3258_ORIENTATION_BINS,
    GF3258_ORIENTATION_HALF_BINS, GF3258_ORIENTATION_RADIUS_MAX, GF3258_ORIENTATION_TURN_Q9,
    GF3258_PI_Q12, GF3258_TAU_Q12, GF3258_VECTOR_CORDIC_ATAN_Q12, Gf3258GradientPlanes,
    Gf3258OrientationError, Gf3258OrientationResult, Gf3258OrientationWindow,
    gf3258_c6d90_direction_map, gf3258_c7310_gradient_source, gf3258_cordic_atan2_magnitude_q12,
    gf3258_cordic_sin_cos_q14, gf3258_gradient_difference_to_q12, gf3258_gradient_planes,
    gf3258_primary_orientation,
};

mod descriptor;
pub use descriptor::{
    GF3258_COMPACT_DESCRIPTOR_REVISION, GF3258_DESCRIPTOR_CENTRAL_HASH_STRIDE,
    GF3258_DESCRIPTOR_CENTRAL_LEN, GF3258_DESCRIPTOR_COMPACT_LEN, GF3258_DESCRIPTOR_COORD_BIAS_Q9,
    GF3258_DESCRIPTOR_COORD_LIMIT_Q9, GF3258_DESCRIPTOR_FULL_HASH_STRIDE,
    GF3258_DESCRIPTOR_HASH_BITS, GF3258_DESCRIPTOR_LEN, GF3258_DESCRIPTOR_ORIENTATION_BINS,
    GF3258_DESCRIPTOR_PADDED_CELLS, GF3258_DESCRIPTOR_PADDED_LEN,
    GF3258_DESCRIPTOR_PROFILE_SCALE_Q16, GF3258_DESCRIPTOR_RADIUS_MAX,
    GF3258_DESCRIPTOR_SPATIAL_CELLS, Gf3258CompactDescriptor, Gf3258DescriptorError,
    Gf3258DescriptorResult, Gf3258DescriptorWindow, gf3258_compact_descriptor,
    gf3258_primary_descriptor,
};

mod extraction;
pub use extraction::{
    GF3258_C2D40_INPUTS_REVISION, GF3258_C2D40_MODE6_KERNEL, GF3258_PRIMARY_EXTRACTION_REVISION,
    Gf3258C2d40FeatureInputs, Gf3258C0910Inputs, Gf3258ExtractedPrimaryPoint,
    Gf3258PreparedC0910Inputs, Gf3258PrimaryExtractionDiagnostics, Gf3258PrimaryExtractionError,
    Gf3258PrimaryFeatureExtraction, gf3258_c2d40_detector_source, gf3258_extract_primary_features,
    gf3258_extract_primary_features_from_c2d40, gf3258_extract_primary_features_from_c2d40_source,
    gf3258_extract_primary_features_with_descriptor_scale,
    gf3258_prepare_c0910_inputs_from_c2d40_source,
};

mod support;
pub use support::{
    GF3258_FEATURE_POINT_STRIDE, GF3258_POINT_SUPPORT_REVISION, GF3258_SUPPORT_MAX,
    GF3258_SUPPORT_MAX_DISTANCE_SQ, GF3258_SUPPORT_PROXIMITY_TABLE,
    GF3258_SUPPORT_QUALITY_BOOST_THRESHOLD, Gf3258PointSupportError, Gf3258PointSupportResult,
    Gf3258SupportPoint, gf3258_point_support, gf3258_rehabilitate_point_status,
    gf3258_rehabilitate_point_statuses,
};

mod validity;
pub use validity::{
    GF3258_A8200_BLOCK, GF3258_A8200_CELLS, GF3258_A8200_HEIGHT, GF3258_A8200_REVISION,
    GF3258_A8200_WIDTH, GF3258_BD720_BOX_RADIUS, GF3258_BD720_BOX_RECIP_Q16,
    GF3258_BD720_MODE7_KERNEL, GF3258_BD720_REVISION, GF3258_BD720_THRESHOLD, Gf3258Bd720Validity,
    Gf3258EnrollmentValidity, gf3258_a8200_quarter_validity, gf3258_bd720_validity,
    gf3258_enrollment_validity_from_c2d40_source,
};

mod quality;
pub(crate) use quality::gf3258_capture_quality;

pub(crate) mod matching;
pub use matching::{
    GF3258_MATCH_CANDIDATES_REVISION, GF3258_MATCH_LIVE_DEDUP_DISTANCE_SQ_Q16,
    GF3258_MATCH_MAX_CANDIDATE_PAIRS, GF3258_MATCH_SCORE_MATRIX_STRIDE,
    GF3258_MATCH_SCORE_SENTINEL, Gf3258CandidateGeneration, Gf3258CandidateMatchError,
    Gf3258CandidateMatcherConfig, Gf3258MatchDescriptorMode, Gf3258MatcherFeatureSet,
    Gf3258MatcherPoint, Gf3258OwnedMatcherFeature, Gf3258OwnedVerificationMatcherFeature,
    Gf3258PointPairScore, Gf3258RecoveryEnrolledPoint, Gf3258SelectedCorrespondence,
    gf3258_generate_match_candidates, gf3258_generate_recovery_pair_slots_from_score_matrix,
    gf3258_hamming64_bytes, gf3258_matcher_polarity_from_raw_response,
    gf3258_partition_matcher_points, gf3258_point_pair_score,
};
pub(crate) use matching::{
    Gf3258EnrolledCandidateFeatureSet, Gf3258EnrolledCandidatePoint, gf3258_bf420_descriptor,
    gf3258_generate_enrolled_match_candidates, gf3258_select_correspondences_from_top_two,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf3258FeaturePointCore {
    pub x_q8: u16,
    pub y_q8: u16,
    pub orientation_q12: u16,
    pub ranking_score: i32,
}

#[inline]
fn gf3258_c0910_round_coordinate_q8(value: u16) -> u16 {
    value.wrapping_add(8) & 0xfff0
}

#[inline]
fn gf3258_c0910_round_orientation_q12(value: u16) -> u16 {
    let signed = value as i16;
    if signed < 0 {
        let magnitude = i32::from(signed).wrapping_neg();
        ((magnitude.wrapping_add(0x80) & !0xff) as i16).wrapping_neg() as u16
    } else {
        value.wrapping_add(0x80) & 0xff00
    }
}

impl Gf3258FeaturePointCore {
    pub fn from_candidate(
        candidate: &detector::RefinedExtremum,
        orientation: &orientation::Gf3258OrientationResult,
    ) -> Self {
        Self {
            // C0910 rounds the BF830 output geometry before publishing the
            // FeaturePoint60. Persistence relies on the resulting low-nibble
            // zeros because its x/y/orientation bit fields intentionally overlap.
            x_q8: gf3258_c0910_round_coordinate_q8(candidate.x_q8),
            y_q8: gf3258_c0910_round_coordinate_q8(candidate.y_q8),
            orientation_q12: gf3258_c0910_round_orientation_q12(orientation.orientation_q12),
            // Primary candidates already carry abs(response); be410 stores
            // its negative as the ranking/sort score.
            ranking_score: candidate.response.wrapping_neg(),
        }
    }
}

#[cfg(test)]
mod point_core_tests {
    use super::{gf3258_c0910_round_coordinate_q8, gf3258_c0910_round_orientation_q12};

    #[test]
    fn c0910_coordinate_rounding_matches_final_feature_point_store() {
        assert_eq!(gf3258_c0910_round_coordinate_q8(0x1230), 0x1230);
        assert_eq!(gf3258_c0910_round_coordinate_q8(0x1237), 0x1230);
        assert_eq!(gf3258_c0910_round_coordinate_q8(0x1238), 0x1240);
        assert_eq!(gf3258_c0910_round_coordinate_q8(0x123f), 0x1240);
    }

    #[test]
    fn c0910_orientation_rounding_is_signed_and_symmetric() {
        assert_eq!(gf3258_c0910_round_orientation_q12(0x007f), 0x0000);
        assert_eq!(gf3258_c0910_round_orientation_q12(0x0080), 0x0100);
        assert_eq!(
            gf3258_c0910_round_orientation_q12((-0x007f_i16) as u16),
            0x0000
        );
        assert_eq!(
            gf3258_c0910_round_orientation_q12((-0x0080_i16) as u16),
            0xff00
        );
        assert_eq!(
            gf3258_c0910_round_orientation_q12((-0x0180_i16) as u16),
            0xfe00
        );
    }
}
