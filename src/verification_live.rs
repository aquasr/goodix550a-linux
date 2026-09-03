//! Live GF3258 verification-feature preparation.
//!
//! This module closes the boundary between one reconstructed 80x64 sensor
//! frame and the complete live feature consumed by persisted-gallery
//! verification. It owns stateful preprocessing and derives all image-backed
//! matcher, registration, validity, quality and coverage fields from the same
//! processed frame.

use std::{error::Error, fmt};

use crate::feature::{
    FeatureError, Gf3258CandidateMatcherConfig, Gf3258OwnedVerificationMatcherFeature,
    Gf3258PrimaryExtractionError, Gf3258PrimaryFeatureExtraction, gf3258_capture_quality,
    gf3258_enrollment_validity_from_c2d40_source,
    gf3258_extract_primary_features_from_c2d40_source,
    gf3258_prepare_c0910_inputs_from_c2d40_source,
};
use crate::preprocess::{Gf3258Preprocessor, PreprocessError};
use crate::registration::{
    GF3258_QUARTER_VALIDITY_CELLS, GF3258_REGISTRATION_PACKED_BYTES,
    gf3258_expand_quarter_validity, gf3258_low_threshold_registration_map,
    gf3258_pack_active_validity, gf3258_pack_quarter_validity, gf3258_primary_registration_map,
    gf3258_secondary_registration_map,
};

use crate::template_decode::{
    Gf3258PersistedTemplate, Gf3258TemplateDecodeError, gf3258_decode_fresh_tgla,
};

use super::{
    Gf3258GalleryVerificationDecision, Gf3258NormalLoopConfig, Gf3258NormalLoopRecoveryConfig,
    Gf3258NormalPolicyLiveInput, Gf3258PersistedGalleryVerificationInput,
    Gf3258PersistedGalleryVerificationResult, Gf3258PersistedSampleEvaluationError,
    Gf3258PersistedSampleEvaluationInput, Gf3258PersistedSampleEvaluationPolicyConfig,
    Gf3258VerificationRegistrationInput, Gf3258VerificationSampleConfig,
    gf3258_verify_persisted_gallery,
};

/// Current standalone live-feature materialization revision.
pub(crate) const GF3258_LIVE_VERIFICATION_FEATURE_REVISION: &str =
    "gf3258-live-verification-feature-v1";

/// Fresh standalone state for live Feature+0x13c.
///
/// The current open path does not manufacture the vendor's optional historical
/// scalar. Zero follows the same fresh/default state used by enrollment and
/// persisted-template production until additional parity evidence proves a
/// nonzero producer for this field.
pub(crate) const GF3258_FRESH_LIVE_SCALAR_13C: i32 = 0;

/// Fresh standalone state for live Feature+0x158.
///
/// `FUN_001900b0` consumes this already-materialized field but does not produce
/// it. The fresh standalone verifier keeps it zero rather than deriving it from
/// unrelated profile bytes.
pub(crate) const GF3258_FRESH_LIVE_SCALAR_158: i32 = 0;

/// Exact normal-mode type-0x18 recognition thresholds built by raw `0x942a0`.
pub(crate) const GF3258_RECOGNITION_CANDIDATE_CONFIG: Gf3258CandidateMatcherConfig =
    Gf3258CandidateMatcherConfig {
        first_half_hamming_max: 23,
        descriptor_mode_hamming_max: 47,
        ambiguity_best_multiplier: 40,
        ambiguity_second_multiplier: 38,
    };

/// Raw matcher `config+0x30` for a type-0x18 80x64 template.
///
/// `0x942a0` computes this from template height * width with the vendor fixed
/// reciprocal for 9504: `(64 * 80 * 256) / 9504 = 137` under its signed
/// multiply/high-word sequence.
pub(crate) const GF3258_RECOGNITION_QUALITY_SCALE_Q8: i32 = 137;

/// Type-0x18 recognition configuration field used by scalar policy.
pub(crate) const GF3258_RECOGNITION_TYPE: i32 = 0x18;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf3258LiveVerificationDiagnostics {
    pub valid_central_pixels: usize,
    pub tested_central_pixels: usize,
    pub foreground_count: usize,
    pub preprocess_coverage_percent: u16,
    pub active_difference_count: usize,
    pub gain_correction_active: bool,
    pub low_dynamic_range_count: usize,
    pub pathological_edge_samples: usize,
    pub raw_quality: i32,
    pub raw_quality_rejected: bool,
    pub quality: i32,
    pub coverage: i32,
    pub mask_coverage_q16: i32,
    pub coverage_q16: i32,
    pub class4_percent: Option<i32>,
    pub point_count: usize,
    pub quarter_selected_cells: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gf3258LiveVerificationRejection {
    Preprocess(PreprocessError),
    PathologicalEdge { pathological_edge_samples: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gf3258LiveVerificationPreparationError {
    Feature(FeatureError),
    Extraction(Gf3258PrimaryExtractionError),
}

impl fmt::Display for Gf3258LiveVerificationPreparationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Feature(error) => write!(f, "GF3258 live-feature preparation failed: {error}"),
            Self::Extraction(error) => {
                write!(f, "GF3258 live feature extraction failed: {error}")
            }
        }
    }
}

impl Error for Gf3258LiveVerificationPreparationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Feature(error) => Some(error),
            Self::Extraction(error) => Some(error),
        }
    }
}

impl From<FeatureError> for Gf3258LiveVerificationPreparationError {
    fn from(value: FeatureError) -> Self {
        Self::Feature(value)
    }
}

impl From<Gf3258PrimaryExtractionError> for Gf3258LiveVerificationPreparationError {
    fn from(value: Gf3258PrimaryExtractionError) -> Self {
        Self::Extraction(value)
    }
}

// Keep prepared features inline; boxing would add allocation to every verification capture.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub(crate) enum Gf3258LiveVerificationPreparation {
    Rejected(Gf3258LiveVerificationRejection),
    Prepared(Gf3258PreparedVerificationFeature),
}

/// Complete owned live feature consumed by the standalone gallery verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Gf3258PreparedVerificationFeature {
    matcher: Gf3258OwnedVerificationMatcherFeature,
    primary_registration_map: [u8; GF3258_REGISTRATION_PACKED_BYTES],
    secondary_registration_map: [u8; GF3258_REGISTRATION_PACKED_BYTES],
    low_threshold_registration_map: [u8; GF3258_REGISTRATION_PACKED_BYTES],
    quarter_validity_packed: [u8; GF3258_QUARTER_VALIDITY_CELLS / 8],
    active_validity_packed: [u8; GF3258_REGISTRATION_PACKED_BYTES],
    quality: i32,
    coverage: i32,
    scalar_13c: i32,
    scalar_158: i32,
    diagnostics: Gf3258LiveVerificationDiagnostics,
}

impl Gf3258PreparedVerificationFeature {
    pub(crate) fn matcher(&self) -> &Gf3258OwnedVerificationMatcherFeature {
        &self.matcher
    }

    pub(crate) fn diagnostics(&self) -> Gf3258LiveVerificationDiagnostics {
        self.diagnostics
    }

    pub(crate) fn scalar_13c(&self) -> i32 {
        self.scalar_13c
    }

    pub(crate) fn registration_input(&self) -> Gf3258VerificationRegistrationInput<'_> {
        Gf3258VerificationRegistrationInput {
            primary_registration_map: &self.primary_registration_map,
            secondary_registration_map: Some(&self.secondary_registration_map),
            quarter_validity_packed: &self.quarter_validity_packed,
            active_validity_packed: &self.active_validity_packed,
        }
    }

    pub(crate) fn policy_live_input(&self) -> Gf3258NormalPolicyLiveInput<'_> {
        Gf3258NormalPolicyLiveInput {
            low_threshold_registration_map: &self.low_threshold_registration_map,
            quality: self.quality,
            coverage: self.coverage,
            scalar_158: self.scalar_158,
        }
    }
}

/// Opaque validated persisted gallery used by the production verification API.
///
/// Construction decodes one fresh TGLA node and rejects empty galleries before
/// any device or capture operation can begin. The decoded type-0x18 structure
/// remains internal to the verifier so callers cannot accidentally assemble a
/// production authentication request from low-level matcher policy pieces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gf3258VerificationTemplate {
    persisted: Gf3258PersistedTemplate,
}

/// Failure while constructing a production verification gallery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gf3258VerificationTemplateError {
    /// The TGLA/raw template failed strict structural or semantic decoding.
    Decode { message: String },
    /// The template is valid but contains no enrolled samples.
    EmptyGallery,
}

impl fmt::Display for Gf3258VerificationTemplateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode { message } => {
                write!(f, "GF3258 verification template decode failed: {message}")
            }
            Self::EmptyGallery => f.write_str("verification template contains no enrolled samples"),
        }
    }
}

impl Error for Gf3258VerificationTemplateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Decode { .. } | Self::EmptyGallery => None,
        }
    }
}

impl From<Gf3258TemplateDecodeError> for Gf3258VerificationTemplateError {
    fn from(value: Gf3258TemplateDecodeError) -> Self {
        Self::Decode {
            message: value.to_string(),
        }
    }
}

impl Gf3258VerificationTemplate {
    /// Decode and validate one fresh TGLA gallery for production verification.
    ///
    /// # Errors
    ///
    /// Returns [`Gf3258VerificationTemplateError::Decode`] when the persisted
    /// bytes fail strict decoding, or [`Gf3258VerificationTemplateError::EmptyGallery`]
    /// when the template contains zero enrolled samples.
    pub fn from_tgla(bytes: &[u8]) -> Result<Self, Gf3258VerificationTemplateError> {
        let persisted = gf3258_decode_fresh_tgla(bytes)?;
        if persisted.samples.is_empty() {
            return Err(Gf3258VerificationTemplateError::EmptyGallery);
        }
        Ok(Self { persisted })
    }

    /// Number of enrolled samples available to the verifier.
    #[must_use]
    pub fn sample_count(&self) -> usize {
        self.persisted.samples.len()
    }

    /// Recovered configured maximum sample count stored by the template.
    #[must_use]
    pub(crate) fn configured_max_samples(&self) -> usize {
        self.persisted.header.configured_max_samples
    }

    fn persisted(&self) -> &Gf3258PersistedTemplate {
        &self.persisted
    }
}

/// Stateful live-touch preparation. The same preprocessor instance is retained
/// across captures so later adaptive-state recovery can be integrated without
/// changing the verification API.
#[derive(Debug, Clone, Default)]
pub struct Gf3258VerificationWorkflow {
    preprocessor: Gf3258Preprocessor,
}

impl Gf3258VerificationWorkflow {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn prepare_raw_frame(
        &mut self,
        raw_u16: &[u16],
    ) -> Result<Gf3258LiveVerificationPreparation, Gf3258LiveVerificationPreparationError> {
        let preprocessed = match self.preprocessor.process(raw_u16) {
            Ok(value) => value,
            Err(error) => {
                return Ok(Gf3258LiveVerificationPreparation::Rejected(
                    Gf3258LiveVerificationRejection::Preprocess(error),
                ));
            }
        };

        let pathological_edge_samples = preprocessed.pathological_edge_samples();
        if pathological_edge_samples != 0 {
            return Ok(Gf3258LiveVerificationPreparation::Rejected(
                Gf3258LiveVerificationRejection::PathologicalEdge {
                    pathological_edge_samples,
                },
            ));
        }

        let algorithm_image = preprocessed.pixels();
        let extraction = gf3258_extract_primary_features_from_c2d40_source(algorithm_image)?;
        self.prepare_from_processed(&preprocessed, algorithm_image, extraction)
            .map(Gf3258LiveVerificationPreparation::Prepared)
    }

    fn prepare_from_processed(
        &self,
        preprocessed: &crate::preprocess::PreprocessedImage,
        algorithm_image: &[u8],
        extraction: Gf3258PrimaryFeatureExtraction,
    ) -> Result<Gf3258PreparedVerificationFeature, Gf3258LiveVerificationPreparationError> {
        let prepared = gf3258_prepare_c0910_inputs_from_c2d40_source(algorithm_image)?;
        let validity = gf3258_enrollment_validity_from_c2d40_source(algorithm_image)?;
        let capture_quality = gf3258_capture_quality(algorithm_image)?;
        let active_validity = gf3258_expand_quarter_validity(&validity.quarter_validity);
        let matcher = Gf3258OwnedVerificationMatcherFeature::from_primary_extraction(&extraction);

        let diagnostics = Gf3258LiveVerificationDiagnostics {
            valid_central_pixels: preprocessed.valid_central_pixels(),
            tested_central_pixels: preprocessed.tested_central_pixels(),
            foreground_count: preprocessed.foreground_count(),
            preprocess_coverage_percent: preprocessed.coverage_percent(),
            active_difference_count: preprocessed.active_difference_count(),
            gain_correction_active: preprocessed.gain_correction_active(),
            low_dynamic_range_count: preprocessed.low_dynamic_range_count(),
            pathological_edge_samples: 0,
            raw_quality: capture_quality.raw_quality,
            raw_quality_rejected: capture_quality.raw_quality_rejected(),
            quality: capture_quality.quality,
            coverage: capture_quality.coverage,
            mask_coverage_q16: capture_quality.mask_coverage_q16,
            coverage_q16: capture_quality.coverage_q16,
            class4_percent: capture_quality.class4_percent,
            point_count: extraction.points.len(),
            quarter_selected_cells: validity.quarter_selected_cells,
        };

        Ok(Gf3258PreparedVerificationFeature {
            matcher,
            primary_registration_map: gf3258_primary_registration_map(&prepared.detector_source_u8),
            secondary_registration_map: gf3258_secondary_registration_map(
                &prepared.gradient_source_u8,
                &validity.bd720.mask_u8,
            ),
            low_threshold_registration_map: gf3258_low_threshold_registration_map(
                &prepared.detector_source_u8,
            ),
            quarter_validity_packed: gf3258_pack_quarter_validity(&validity.quarter_validity),
            active_validity_packed: gf3258_pack_active_validity(&active_validity),
            quality: capture_quality.quality,
            coverage: capture_quality.coverage,
            scalar_13c: GF3258_FRESH_LIVE_SCALAR_13C,
            scalar_158: GF3258_FRESH_LIVE_SCALAR_158,
            diagnostics,
        })
    }
}

/// Stable public result of one completed GF3258 gallery verification.
///
/// Per-sample policy state and recovery work remain internal diagnostics. A
/// caller deciding authentication needs only the final signed score and its
/// recovered binary interpretation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf3258VerificationResult {
    decision: Gf3258GalleryVerificationDecision,
    score: i32,
    diagnostics: Gf3258LiveVerificationDiagnostics,
}

impl Gf3258VerificationResult {
    /// Final MATCH/NO MATCH interpretation of the signed vendor score.
    #[must_use]
    pub const fn decision(self) -> Gf3258GalleryVerificationDecision {
        self.decision
    }

    /// Final signed vendor-equivalent verification score.
    #[must_use]
    pub const fn score(self) -> i32 {
        self.score
    }

    /// Capture/feature diagnostics for the verified frame.
    #[must_use]
    pub const fn diagnostics(self) -> Gf3258LiveVerificationDiagnostics {
        self.diagnostics
    }
}

/// Public outcome for one raw verification frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gf3258RawFrameVerificationOutcome {
    /// The frame was valid input but was rejected before gallery evaluation.
    Rejected(Gf3258LiveVerificationRejection),
    /// Gallery evaluation completed and produced a final signed score.
    Verified(Gf3258VerificationResult),
}

/// Failure while preparing or evaluating one raw verification frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gf3258RawFrameVerificationError {
    /// Live feature preparation failed.
    Preparation(Gf3258LiveVerificationPreparationError),
    /// Persisted-gallery evaluation failed after successful preparation.
    ///
    /// The detailed recovered evaluator error remains internal so low-level
    /// matcher policy types do not become part of the supported public API.
    Evaluation { message: String },
}

impl fmt::Display for Gf3258RawFrameVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Preparation(error) => error.fmt(f),
            Self::Evaluation { message } => {
                write!(f, "GF3258 gallery verification failed: {message}")
            }
        }
    }
}

impl Error for Gf3258RawFrameVerificationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Preparation(error) => Some(error),
            Self::Evaluation { .. } => None,
        }
    }
}

impl From<Gf3258LiveVerificationPreparationError> for Gf3258RawFrameVerificationError {
    fn from(value: Gf3258LiveVerificationPreparationError) -> Self {
        Self::Preparation(value)
    }
}

impl From<Gf3258PersistedSampleEvaluationError> for Gf3258RawFrameVerificationError {
    fn from(value: Gf3258PersistedSampleEvaluationError) -> Self {
        Self::Evaluation {
            message: value.to_string(),
        }
    }
}

// Detailed diagnostics are an internal path; avoid adding heap allocation solely for enum size.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Gf3258DetailedRawFrameVerificationOutcome {
    Rejected(Gf3258LiveVerificationRejection),
    Verified {
        decision: Gf3258GalleryVerificationDecision,
        diagnostics: Gf3258LiveVerificationDiagnostics,
        result: Gf3258PersistedGalleryVerificationResult,
    },
}

/// Run the validated type-0x18 normal recognition configuration against one
/// already-prepared live feature.
///
/// This is the first production boundary with no caller-supplied biometric
/// thresholds. Optional verification profile and cache rescue remain disabled
/// for the fresh standalone verification path.
pub(crate) fn gf3258_verify_prepared_gallery(
    template: &Gf3258VerificationTemplate,
    live: &Gf3258PreparedVerificationFeature,
) -> Result<Gf3258PersistedGalleryVerificationResult, Gf3258PersistedSampleEvaluationError> {
    let normal_loop = Gf3258NormalLoopConfig {
        recovery: Gf3258NormalLoopRecoveryConfig {
            config_10: 0,
            config_34: 1,
            config_48: 0,
        },
        config_38: 0,
        configured_max_samples: template.persisted().header.configured_max_samples,
    };

    gf3258_verify_persisted_gallery(
        &template.persisted().samples,
        live.matcher(),
        Gf3258PersistedGalleryVerificationInput {
            live_scalar_13c: live.scalar_13c(),
            normal_loop,
            evaluation: Gf3258PersistedSampleEvaluationInput {
                registration: live.registration_input(),
                sample_config: Gf3258VerificationSampleConfig {
                    candidate_matcher: GF3258_RECOGNITION_CANDIDATE_CONFIG,
                    quality_scale_q8: GF3258_RECOGNITION_QUALITY_SCALE_Q8,
                },
                live_policy: live.policy_live_input(),
                profile: None,
                policy_config: Gf3258PersistedSampleEvaluationPolicyConfig {
                    config_00: 0,
                    config_04: 0,
                    config_3c: GF3258_RECOGNITION_TYPE,
                    config_50: 0,
                },
            },
        },
    )
}

impl Gf3258VerificationWorkflow {
    pub(crate) fn verify_raw_frame_detailed(
        &mut self,
        template: &Gf3258VerificationTemplate,
        raw_u16: &[u16],
    ) -> Result<Gf3258DetailedRawFrameVerificationOutcome, Gf3258RawFrameVerificationError> {
        let prepared = match self.prepare_raw_frame(raw_u16)? {
            Gf3258LiveVerificationPreparation::Rejected(rejection) => {
                return Ok(Gf3258DetailedRawFrameVerificationOutcome::Rejected(
                    rejection,
                ));
            }
            Gf3258LiveVerificationPreparation::Prepared(prepared) => prepared,
        };

        let diagnostics = prepared.diagnostics();
        let result = gf3258_verify_prepared_gallery(template, &prepared)?;
        Ok(Gf3258DetailedRawFrameVerificationOutcome::Verified {
            decision: result.decision,
            diagnostics,
            result,
        })
    }

    /// Reconstructed raw sensor frame -> live feature -> persisted gallery ->
    /// signed vendor score -> MATCH/NO MATCH.
    ///
    /// # Errors
    ///
    /// Returns a preparation error when a usable live feature cannot be built,
    /// or an evaluation error when the persisted gallery cannot be evaluated.
    pub fn verify_raw_frame(
        &mut self,
        template: &Gf3258VerificationTemplate,
        raw_u16: &[u16],
    ) -> Result<Gf3258RawFrameVerificationOutcome, Gf3258RawFrameVerificationError> {
        match self.verify_raw_frame_detailed(template, raw_u16)? {
            Gf3258DetailedRawFrameVerificationOutcome::Rejected(rejection) => {
                Ok(Gf3258RawFrameVerificationOutcome::Rejected(rejection))
            }
            Gf3258DetailedRawFrameVerificationOutcome::Verified {
                decision,
                diagnostics,
                result,
            } => Ok(Gf3258RawFrameVerificationOutcome::Verified(
                Gf3258VerificationResult {
                    decision,
                    score: result.arbitration.score,
                    diagnostics,
                },
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::{IMAGE_HEIGHT, IMAGE_WIDTH};

    fn synthetic_raw() -> Vec<u16> {
        vec![1000u16; IMAGE_WIDTH * IMAGE_HEIGHT]
    }

    #[test]
    fn verification_template_rejects_empty_gallery() {
        let enrollment = crate::enrollment::Gf3258EnrollmentWorkflow::new();
        let artifacts = enrollment.encode_artifacts().unwrap();

        let error = Gf3258VerificationTemplate::from_tgla(artifacts.tgla_template()).unwrap_err();
        assert_eq!(error, Gf3258VerificationTemplateError::EmptyGallery);
    }

    #[test]
    fn verification_template_accepts_nonempty_gallery() {
        let raw = synthetic_raw();
        let mut enrollment = crate::enrollment::Gf3258EnrollmentWorkflow::new();
        assert!(matches!(
            enrollment.process_raw_frame(&raw).unwrap(),
            crate::enrollment::Gf3258EnrollmentFrameOutcome::Accepted(_)
        ));
        let artifacts = enrollment.encode_artifacts().unwrap();

        let template = Gf3258VerificationTemplate::from_tgla(artifacts.tgla_template()).unwrap();
        assert_eq!(template.sample_count(), 1);
        assert_eq!(
            template.configured_max_samples(),
            crate::template_persistence::GF3258_TEMPLATE_CONFIGURED_MAX_SAMPLES
        );
    }

    #[test]
    fn fresh_live_scalars_remain_zero() {
        assert_eq!(GF3258_FRESH_LIVE_SCALAR_13C, 0);
        assert_eq!(GF3258_FRESH_LIVE_SCALAR_158, 0);
    }

    #[test]
    fn recognition_config_matches_type_18_constructor() {
        assert_eq!(
            GF3258_RECOGNITION_CANDIDATE_CONFIG.first_half_hamming_max,
            23
        );
        assert_eq!(
            GF3258_RECOGNITION_CANDIDATE_CONFIG.descriptor_mode_hamming_max,
            47
        );
        assert_eq!(
            GF3258_RECOGNITION_CANDIDATE_CONFIG.ambiguity_best_multiplier,
            40
        );
        assert_eq!(
            GF3258_RECOGNITION_CANDIDATE_CONFIG.ambiguity_second_multiplier,
            38
        );
        assert_eq!(GF3258_RECOGNITION_QUALITY_SCALE_Q8, 137);
        assert_eq!(GF3258_RECOGNITION_TYPE, 0x18);
    }

    #[test]
    fn public_result_preserves_terminal_score_interpretation() {
        let raw = synthetic_raw();
        let mut enrollment = crate::enrollment::Gf3258EnrollmentWorkflow::new();
        assert!(matches!(
            enrollment.process_raw_frame(&raw).unwrap(),
            crate::enrollment::Gf3258EnrollmentFrameOutcome::Accepted(_)
        ));
        let artifacts = enrollment.encode_artifacts().unwrap();
        let template = Gf3258VerificationTemplate::from_tgla(artifacts.tgla_template()).unwrap();

        let mut workflow = Gf3258VerificationWorkflow::new();
        let outcome = workflow.verify_raw_frame(&template, &raw).unwrap();
        let Gf3258RawFrameVerificationOutcome::Verified(result) = outcome else {
            panic!("synthetic frame unexpectedly rejected");
        };

        assert_eq!(
            result.decision(),
            Gf3258GalleryVerificationDecision::from_score(result.score())
        );
        assert_eq!(result.diagnostics().point_count, 0);
    }

    #[test]
    fn prepared_feature_projects_one_consistent_policy_view() {
        let mut workflow = Gf3258VerificationWorkflow::new();
        let result = workflow.prepare_raw_frame(&synthetic_raw()).unwrap();
        let Gf3258LiveVerificationPreparation::Prepared(prepared) = result else {
            panic!("synthetic frame unexpectedly rejected");
        };

        let registration = prepared.registration_input();
        let policy = prepared.policy_live_input();
        let diagnostics = prepared.diagnostics();

        assert_eq!(prepared.scalar_13c(), 0);
        assert_eq!(policy.scalar_158, 0);
        assert_eq!(policy.quality, diagnostics.quality);
        assert_eq!(policy.coverage, diagnostics.coverage);
        assert_eq!(prepared.matcher().point_count(), diagnostics.point_count);
        assert_eq!(registration.quarter_validity_packed.len(), 40);
        assert_eq!(
            registration.active_validity_packed.len(),
            GF3258_REGISTRATION_PACKED_BYTES
        );
    }
}
