//! Reusable GF3258 enrollment workflow.
//!
//! This module is the library boundary between a reconstructed 80x64 sensor
//! frame and persistent enrollment-template bytes. It intentionally does not
//! own USB capture, filesystem paths, retry policy, console output, or the
//! current matcher diagnostics used by the standalone application.

use std::{error::Error, fmt};

use crate::enrollment_add::Gf3258EnrollmentTemplateCore;
use crate::feature::{
    FeatureError, Gf3258EnrollmentValidity, Gf3258PrimaryExtractionError,
    Gf3258PrimaryFeatureExtraction, gf3258_enrollment_validity_from_c2d40_source,
    gf3258_extract_primary_features_from_c2d40_source,
};
use crate::feature_enrollment::{
    Gf3258EnrollmentReadyFeature, gf3258_add_extracted_feature, gf3258_new_enrollment_template,
};
use crate::preprocess::{Gf3258Preprocessor, PreprocessError, PreprocessedImage};
use crate::template_persistence::{GF3258_TEMPLATE_POINT_CAPACITY, gf3258_encode_raw_template};
use crate::template_storage::{
    Gf3258FreshTglaNode, gf3258_parse_fresh_tgla, gf3258_wrap_fresh_tgla,
};

pub(crate) use crate::enrollment_add::Gf3258EnrollmentAddKind;
pub use crate::feature_enrollment::Gf3258FeatureEnrollmentError;
pub use crate::template_decode::{
    Gf3258PersistedGraphState, Gf3258PersistedMatcherGeometry, Gf3258PersistedPoint,
    Gf3258PersistedRelation, Gf3258PersistedSample, Gf3258PersistedStorageState,
    Gf3258PersistedTemplate, Gf3258PersistedTemplateHeader, Gf3258TemplateDecodeError,
    gf3258_decode_fresh_tgla, gf3258_decode_persistent_geometry_word,
    gf3258_decode_persistent_point, gf3258_decode_raw_template,
};
pub use crate::template_persistence::{
    GF3258_TEMPLATE_PERSISTENCE_REVISION, Gf3258TemplatePersistenceError,
};
pub use crate::template_storage::{GF3258_TEMPLATE_STORAGE_REVISION, Gf3258TemplateStorageError};

/// Recovered GF3258 AlgoConfig.GeneralSamples value for sensor type 0x0c.
pub const GF3258_ENROLLMENT_TARGET_SAMPLES: usize = 12;

/// Maximum feature points that can be retained in one persisted GF3258 sample.
///
/// This is a semantic enrollment alias for the type-0x18 persistence capacity;
/// persistence remains the single source of truth for the numeric limit.
pub const GF3258_ENROLLMENT_POINT_CAPACITY: usize = GF3258_TEMPLATE_POINT_CAPACITY;

/// Normal retained-sample status used by the validated standalone path.
const GF3258_NORMAL_SAMPLE_STATUS: i32 = 0;

/// Stable diagnostics produced by the stateful preprocessing stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf3258PreprocessDiagnostics {
    pub valid_central_pixels: usize,
    pub tested_central_pixels: usize,
    pub foreground_count: usize,
    pub coverage_percent: u16,
    pub active_difference_count: usize,
    pub gain_correction_active: bool,
    pub low_dynamic_range_count: usize,
    pub pathological_edge_samples: usize,
}

impl Gf3258PreprocessDiagnostics {
    fn from_preprocessed(image: &PreprocessedImage) -> Self {
        Self {
            valid_central_pixels: image.valid_central_pixels(),
            tested_central_pixels: image.tested_central_pixels(),
            foreground_count: image.foreground_count(),
            coverage_percent: image.coverage_percent(),
            active_difference_count: image.active_difference_count(),
            gain_correction_active: image.gain_correction_active(),
            low_dynamic_range_count: image.low_dynamic_range_count(),
            pathological_edge_samples: image.pathological_edge_samples(),
        }
    }
}

/// Compact diagnostics for the recovered bd720 -> a8200 validity path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Gf3258ValidityDiagnostics {
    pub bd720_selected_pixels: usize,
    pub bd720_coverage_q16: u32,
    pub quarter_selected_cells: usize,
}

impl Gf3258ValidityDiagnostics {
    fn from_validity(validity: &Gf3258EnrollmentValidity) -> Self {
        Self {
            bd720_selected_pixels: validity.bd720.selected_pixels,
            bd720_coverage_q16: validity.bd720.coverage_q16,
            quarter_selected_cells: validity.quarter_selected_cells,
        }
    }
}

/// A normal rejected capture. Rejections do not mutate enrollment state and
/// do not advance the recovered GeneralSamples progress counter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gf3258EnrollmentRejection {
    Preprocess(PreprocessError),
    TooManyPoints {
        actual: usize,
        capacity: usize,
    },
    PathologicalEdge {
        diagnostics: Gf3258PreprocessDiagnostics,
    },
}

#[inline]
fn gf3258_enrollment_point_count_rejection(actual: usize) -> Option<Gf3258EnrollmentRejection> {
    (actual > GF3258_ENROLLMENT_POINT_CAPACITY).then_some(
        Gf3258EnrollmentRejection::TooManyPoints {
            actual,
            capacity: GF3258_ENROLLMENT_POINT_CAPACITY,
        },
    )
}

/// Result of the non-mutating preparation half of one enrollment touch.
// Keep prepared samples inline; boxing would add allocation to every enrollment touch.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub(crate) enum Gf3258EnrollmentPreparation {
    Rejected(Gf3258EnrollmentRejection),
    Prepared(Gf3258PreparedEnrollmentSample),
}

/// Prepared sample before enrollment/template mutation.
///
/// Keeping this as a separate object lets applications run diagnostics between
/// extraction and commit without duplicating the production feature pipeline.
#[derive(Debug, Clone)]
pub(crate) struct Gf3258PreparedEnrollmentSample {
    preprocess: Gf3258PreprocessDiagnostics,
    extraction: Gf3258PrimaryFeatureExtraction,
    validity: Gf3258ValidityDiagnostics,
    ready: Gf3258EnrollmentReadyFeature,
}

impl Gf3258PreparedEnrollmentSample {
    pub(crate) fn preprocess_diagnostics(&self) -> Gf3258PreprocessDiagnostics {
        self.preprocess
    }

    pub(crate) fn extraction(&self) -> &Gf3258PrimaryFeatureExtraction {
        &self.extraction
    }

    pub(crate) fn validity_diagnostics(&self) -> Gf3258ValidityDiagnostics {
        self.validity
    }
}

/// Result after a prepared sample has been retained in enrollment state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gf3258EnrollmentCommit {
    pub(crate) step: crate::feature_enrollment::Gf3258EnrollmentStepResult,
    pub sample_count: usize,
    pub progress_percent: usize,
}

/// Convenience result for consumers that do not need a prepare/commit hook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gf3258EnrollmentFrameOutcome {
    Rejected(Gf3258EnrollmentRejection),
    Accepted(Gf3258EnrollmentCommit),
}

/// Current high-level graph state without exposing mutable template internals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf3258EnrollmentGraphDiagnostics {
    pub nodes: usize,
    pub nonnegative_relations: usize,
    pub canonical_nodes: usize,
    pub canonical_anchor: Option<usize>,
}

/// Validated fresh-TGLA metadata used by applications and storage adapters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf3258TglaDiagnostics {
    pub total_size: usize,
    pub raw_length: usize,
    pub raw_crc: u32,
    pub config_prefix_zero: bool,
    pub commit_metadata_zero: bool,
    pub trailing_zero_bytes: usize,
}

impl Gf3258TglaDiagnostics {
    fn from_node(node: &Gf3258FreshTglaNode<'_>) -> Self {
        Self {
            total_size: node.total_size(),
            raw_length: node.raw_length(),
            raw_crc: node.raw_crc(),
            config_prefix_zero: node.config_prefix().iter().all(|&value| value == 0),
            commit_metadata_zero: node.commit_metadata().iter().all(|&value| value == 0),
            trailing_zero_bytes: node.trailing_zero_slack().len(),
        }
    }
}

/// Borrowed validated view used for load-only persistence checks.
#[derive(Debug, Clone, Copy)]
pub struct Gf3258ValidatedTgla<'a> {
    node: Gf3258FreshTglaNode<'a>,
}

impl<'a> Gf3258ValidatedTgla<'a> {
    #[must_use]
    pub fn diagnostics(&self) -> Gf3258TglaDiagnostics {
        Gf3258TglaDiagnostics::from_node(&self.node)
    }

    #[must_use]
    pub fn raw_template(&self) -> &'a [u8] {
        self.node.raw_template()
    }
}

/// Fully encoded in-memory enrollment artifacts. Filesystem policy remains a
/// caller concern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gf3258EnrollmentArtifacts {
    raw_template: Vec<u8>,
    tgla_template: Vec<u8>,
    tgla: Gf3258TglaDiagnostics,
}

impl Gf3258EnrollmentArtifacts {
    #[must_use]
    pub fn raw_template(&self) -> &[u8] {
        &self.raw_template
    }

    #[must_use]
    pub fn tgla_template(&self) -> &[u8] {
        &self.tgla_template
    }

    #[must_use]
    pub fn tgla_diagnostics(&self) -> Gf3258TglaDiagnostics {
        self.tgla
    }

    /// Validate externally stored TGLA bytes and prove that they still contain
    /// the exact raw template represented by this artifact set.
    ///
    /// # Errors
    ///
    /// Returns an enrollment workflow error when the TGLA is malformed or its
    /// decoded raw template differs from this artifact set.
    pub fn validate_tgla_bytes(
        &self,
        bytes: &[u8],
    ) -> Result<Gf3258TglaDiagnostics, Gf3258EnrollmentWorkflowError> {
        let validated = gf3258_validate_fresh_tgla(bytes)?;

        if validated.raw_template() != self.raw_template.as_slice() {
            return Err(Gf3258EnrollmentWorkflowError::RawTemplateMismatch);
        }

        Ok(validated.diagnostics())
    }
}

#[derive(Debug)]
pub enum Gf3258EnrollmentWorkflowError {
    PrimaryExtraction(Gf3258PrimaryExtractionError),
    Validity(FeatureError),
    FeatureEnrollment(Gf3258FeatureEnrollmentError),
    TemplatePersistence(Gf3258TemplatePersistenceError),
    TemplateStorage(Gf3258TemplateStorageError),
    RawTemplateMismatch,
}

impl fmt::Display for Gf3258EnrollmentWorkflowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PrimaryExtraction(error) => {
                write!(f, "GF3258 primary extraction failed: {error}")
            }
            Self::Validity(error) => write!(f, "GF3258 enrollment validity failed: {error}"),
            Self::FeatureEnrollment(error) => write!(f, "GF3258 enrollment bridge failed: {error}"),
            Self::TemplatePersistence(error) => {
                write!(f, "GF3258 raw-template encoding failed: {error}")
            }
            Self::TemplateStorage(error) => write!(f, "GF3258 TGLA storage failed: {error}"),
            Self::RawTemplateMismatch => {
                write!(
                    f,
                    "GF3258 TGLA validation changed the raw algorithm template"
                )
            }
        }
    }
}

impl Error for Gf3258EnrollmentWorkflowError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::PrimaryExtraction(error) => Some(error),
            Self::Validity(error) => Some(error),
            Self::FeatureEnrollment(error) => Some(error),
            Self::TemplatePersistence(error) => Some(error),
            Self::TemplateStorage(error) => Some(error),
            Self::RawTemplateMismatch => None,
        }
    }
}

impl From<Gf3258PrimaryExtractionError> for Gf3258EnrollmentWorkflowError {
    fn from(value: Gf3258PrimaryExtractionError) -> Self {
        Self::PrimaryExtraction(value)
    }
}

impl From<Gf3258FeatureEnrollmentError> for Gf3258EnrollmentWorkflowError {
    fn from(value: Gf3258FeatureEnrollmentError) -> Self {
        Self::FeatureEnrollment(value)
    }
}

impl From<Gf3258TemplatePersistenceError> for Gf3258EnrollmentWorkflowError {
    fn from(value: Gf3258TemplatePersistenceError) -> Self {
        Self::TemplatePersistence(value)
    }
}

impl From<Gf3258TemplateStorageError> for Gf3258EnrollmentWorkflowError {
    fn from(value: Gf3258TemplateStorageError) -> Self {
        Self::TemplateStorage(value)
    }
}

/// Stateful in-memory enrollment engine shared by applications and future
/// driver integration.
#[derive(Debug, Clone)]
pub struct Gf3258EnrollmentWorkflow {
    preprocessor: Gf3258Preprocessor,
    template: Gf3258EnrollmentTemplateCore,
}

impl Default for Gf3258EnrollmentWorkflow {
    fn default() -> Self {
        Self::new()
    }
}

impl Gf3258EnrollmentWorkflow {
    #[must_use]
    pub fn new() -> Self {
        Self {
            preprocessor: Gf3258Preprocessor::default(),
            template: gf3258_new_enrollment_template(),
        }
    }

    #[must_use]
    pub fn sample_count(&self) -> usize {
        self.template.sample_count()
    }

    #[must_use]
    pub fn progress_percent(&self) -> usize {
        gf3258_enrollment_progress_percent(self.sample_count())
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.sample_count() >= GF3258_ENROLLMENT_TARGET_SAMPLES
    }

    /// Run preprocessing, feature extraction, validity and Feature
    /// materialization without mutating the enrollment template.
    pub(crate) fn prepare_raw_frame(
        &mut self,
        raw_u16: &[u16],
    ) -> Result<Gf3258EnrollmentPreparation, Gf3258EnrollmentWorkflowError> {
        let preprocessed = match self.preprocessor.process(raw_u16) {
            Ok(value) => value,
            Err(error) => {
                return Ok(Gf3258EnrollmentPreparation::Rejected(
                    Gf3258EnrollmentRejection::Preprocess(error),
                ));
            }
        };

        let preprocess = Gf3258PreprocessDiagnostics::from_preprocessed(&preprocessed);

        if preprocess.pathological_edge_samples != 0 {
            return Ok(Gf3258EnrollmentPreparation::Rejected(
                Gf3258EnrollmentRejection::PathologicalEdge {
                    diagnostics: preprocess,
                },
            ));
        }

        let local_2b8 = preprocessed.pixels();
        let extraction = gf3258_extract_primary_features_from_c2d40_source(local_2b8)?;

        if let Some(rejection) = gf3258_enrollment_point_count_rejection(extraction.points.len()) {
            return Ok(Gf3258EnrollmentPreparation::Rejected(rejection));
        }

        let validity = gf3258_enrollment_validity_from_c2d40_source(local_2b8)
            .map_err(Gf3258EnrollmentWorkflowError::Validity)?;
        let validity_diagnostics = Gf3258ValidityDiagnostics::from_validity(&validity);

        let ready = Gf3258EnrollmentReadyFeature::from_primary_extraction_from_c2d40_source(
            &extraction,
            local_2b8,
            &validity,
            crate::enrollment_add::Gf3258PersistentSourceScalars::default(),
            GF3258_NORMAL_SAMPLE_STATUS,
        )?;

        Ok(Gf3258EnrollmentPreparation::Prepared(
            Gf3258PreparedEnrollmentSample {
                preprocess,
                extraction,
                validity: validity_diagnostics,
                ready,
            },
        ))
    }

    /// Commit one already-prepared sample. This is the only half of the
    /// prepare/commit pair that mutates enrollment/template state.
    pub(crate) fn commit_prepared(
        &mut self,
        prepared: Gf3258PreparedEnrollmentSample,
    ) -> Result<Gf3258EnrollmentCommit, Gf3258EnrollmentWorkflowError> {
        let step = gf3258_add_extracted_feature(&mut self.template, prepared.ready)?;
        let sample_count = self.sample_count();

        Ok(Gf3258EnrollmentCommit {
            step,
            sample_count,
            progress_percent: gf3258_enrollment_progress_percent(sample_count),
        })
    }

    /// Convenience API for callers that do not need to inspect a prepared
    /// sample before it mutates enrollment state.
    ///
    /// # Errors
    ///
    /// Returns a workflow error when feature extraction, validity materialization,
    /// or enrollment commit fails. Normal capture rejections are returned as
    /// [`Gf3258EnrollmentFrameOutcome::Rejected`] and do not mutate state.
    pub fn process_raw_frame(
        &mut self,
        raw_u16: &[u16],
    ) -> Result<Gf3258EnrollmentFrameOutcome, Gf3258EnrollmentWorkflowError> {
        match self.prepare_raw_frame(raw_u16)? {
            Gf3258EnrollmentPreparation::Rejected(rejection) => {
                Ok(Gf3258EnrollmentFrameOutcome::Rejected(rejection))
            }
            Gf3258EnrollmentPreparation::Prepared(prepared) => Ok(
                Gf3258EnrollmentFrameOutcome::Accepted(self.commit_prepared(prepared)?),
            ),
        }
    }

    #[must_use]
    pub fn graph_diagnostics(&self) -> Gf3258EnrollmentGraphDiagnostics {
        let nodes = self.template.sample_count();
        let canonical_nodes = self
            .template
            .graph
            .samples
            .iter()
            .filter(|sample| sample.canonical_member)
            .count();

        let mut nonnegative_relations = 0usize;
        for source in 0..nodes {
            for target in 0..source {
                if let Some((value, _)) = self
                    .template
                    .graph
                    .relation_source_to_target(source, target)
                {
                    if value >= 0 {
                        nonnegative_relations += 1;
                    }
                }
            }
        }

        let canonical_anchor = self
            .template
            .graph
            .canonical_established
            .then_some(self.template.graph.canonical_anchor);

        Gf3258EnrollmentGraphDiagnostics {
            nodes,
            nonnegative_relations,
            canonical_nodes,
            canonical_anchor,
        }
    }

    /// Encode the complete current in-memory template and validate the fresh
    /// TGLA wrapper before returning either byte vector.
    ///
    /// # Errors
    ///
    /// Returns a workflow error when raw-template persistence, TGLA wrapping,
    /// or the post-encode validation check fails.
    pub fn encode_artifacts(
        &self,
    ) -> Result<Gf3258EnrollmentArtifacts, Gf3258EnrollmentWorkflowError> {
        let raw_template = gf3258_encode_raw_template(&self.template)?;
        let tgla_template = gf3258_wrap_fresh_tgla(&raw_template)?;
        let tgla = {
            let validated = gf3258_validate_fresh_tgla(&tgla_template)?;

            if validated.raw_template() != raw_template.as_slice() {
                return Err(Gf3258EnrollmentWorkflowError::RawTemplateMismatch);
            }

            validated.diagnostics()
        };

        Ok(Gf3258EnrollmentArtifacts {
            raw_template,
            tgla_template,
            tgla,
        })
    }
}

/// Exact vendor progress arithmetic used by EnrollStart/EnrollUpdate.
fn gf3258_enrollment_progress_percent(accepted_samples: usize) -> usize {
    ((accepted_samples * 100) / GF3258_ENROLLMENT_TARGET_SAMPLES).min(100)
}

/// Validate one fresh standalone TGLA node without opening the sensor or
/// making any filesystem assumptions.
///
/// # Errors
///
/// Returns a workflow error when the TGLA wrapper is malformed or violates the
/// recovered fresh-node storage invariants.
pub fn gf3258_validate_fresh_tgla(
    bytes: &[u8],
) -> Result<Gf3258ValidatedTgla<'_>, Gf3258EnrollmentWorkflowError> {
    Ok(Gf3258ValidatedTgla {
        node: gf3258_parse_fresh_tgla(bytes)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::{IMAGE_HEIGHT, IMAGE_WIDTH};

    #[test]
    fn rejected_preprocess_does_not_mutate_enrollment_state() {
        let mut workflow = Gf3258EnrollmentWorkflow::new();
        let raw = vec![0u16; IMAGE_WIDTH * IMAGE_HEIGHT];

        let outcome = workflow.prepare_raw_frame(&raw).unwrap();
        assert!(matches!(
            outcome,
            Gf3258EnrollmentPreparation::Rejected(Gf3258EnrollmentRejection::Preprocess(_))
        ));
        assert_eq!(workflow.sample_count(), 0);
        assert_eq!(workflow.progress_percent(), 0);
    }

    #[test]
    fn point_capacity_guard_accepts_limit_and_rejects_before_commit() {
        assert_eq!(
            gf3258_enrollment_point_count_rejection(GF3258_ENROLLMENT_POINT_CAPACITY),
            None
        );
        assert_eq!(
            gf3258_enrollment_point_count_rejection(GF3258_ENROLLMENT_POINT_CAPACITY + 2),
            Some(Gf3258EnrollmentRejection::TooManyPoints {
                actual: 122,
                capacity: GF3258_ENROLLMENT_POINT_CAPACITY,
            })
        );

        let workflow = Gf3258EnrollmentWorkflow::new();
        assert_eq!(workflow.sample_count(), 0);
        assert_eq!(workflow.progress_percent(), 0);
    }

    #[test]
    fn progress_matches_recovered_general_samples_arithmetic() {
        assert_eq!(gf3258_enrollment_progress_percent(0), 0);
        assert_eq!(gf3258_enrollment_progress_percent(1), 8);
        assert_eq!(gf3258_enrollment_progress_percent(11), 91);
        assert_eq!(gf3258_enrollment_progress_percent(12), 100);
        assert_eq!(gf3258_enrollment_progress_percent(13), 100);
    }
}
