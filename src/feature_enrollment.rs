//! GF3258 WN2 feature-extraction -> incremental-enrollment bridge.
//!
//! This module owns the boundary between the completed feature extractor and
//! enrollment/template state.
//!
//! The current standalone-enrollment path projects extracted points, registration
//! maps, validity, and persistence scalars into template state. The recovered
//! b3970 point partition / `Feature+0x108` boundary is materialized for persisted
//! point order without changing the validated enrollment-registration order.
//! Capture-quality-derived `+0x10c/+0x110` scalars are materialized from the
//! recovered c2d40 quality path. The separate raw-quality acceptance gate remains
//! owned by the enrollment workflow rather than the persistence serializer.
//!
//! The raw algorithm-template serializer remains deliberately separate and
//! consumes already-materialized fields without reinterpreting them.

use std::{error::Error, fmt};

use crate::enrollment_add::{
    Gf3258EnrollmentAddError, Gf3258EnrollmentAddResult, Gf3258EnrollmentTemplateCore,
    Gf3258PersistentSampleState, Gf3258PersistentSourceScalars,
};
use crate::enrollment_graph::Gf3258EnrollmentSample;
#[cfg(test)]
use crate::feature::GF3258_PIXELS;
use crate::feature::{
    FeatureError, Gf3258EnrollmentValidity, Gf3258PrimaryFeatureExtraction,
    gf3258_bf420_descriptor, gf3258_capture_quality, gf3258_matcher_polarity_from_raw_response,
    gf3258_prepare_c0910_inputs_from_c2d40_source,
};

#[cfg(test)]
use crate::registration::GF3258_REGISTRATION_PIXELS;
use crate::registration::{
    GF3258_QUARTER_VALIDITY_CELLS, GF3258_REGISTRATION_PACKED_BYTES, Gf3258RegistrationPoint,
    gf3258_expand_quarter_validity, gf3258_low_threshold_registration_map,
    gf3258_pack_active_validity, gf3258_pack_quarter_validity, gf3258_primary_registration_map,
    gf3258_secondary_registration_map,
};
use crate::template_persistence::GF3258_TEMPLATE_POINT_CAPACITY;

#[inline]
fn gf3258_enrollment_mode0_compact_descriptor(
    compact: &crate::feature::Gf3258CompactDescriptor,
) -> crate::feature::Gf3258CompactDescriptor {
    let mut projected = compact.clone();
    let mut descriptor = [0u8; 16];
    for (index, word) in compact.hadamard_128_words.iter().enumerate() {
        descriptor[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }

    let descriptor = gf3258_bf420_descriptor(descriptor);
    for (index, chunk) in descriptor.chunks_exact(4).enumerate() {
        projected.hadamard_128_words[index] =
            u32::from_le_bytes(chunk.try_into().expect("four-byte descriptor word"));
    }
    projected
}

#[inline]
fn gf3258_enrollment_mode0_point(
    point: &crate::feature::Gf3258ExtractedPrimaryPoint,
) -> Gf3258EnrollmentFeaturePoint {
    Gf3258EnrollmentFeaturePoint {
        core: point.core,
        compact: gf3258_enrollment_mode0_compact_descriptor(&point.descriptor.compact),
    }
}

/// GF3258 newTemp profile: at most 120 FeaturePoint60 records per Feature.
///
/// This is also the persistent type-0x18 point capacity. Production enrollment
/// rejects an oversized extraction before it can mutate the enrollment graph.
///
/// ba520 initializes b9340's score threshold to 0xcd for the GF3258 path.
pub const GF3258_ENROLLMENT_GRAPH_SCORE_THRESHOLD: i32 = 0xcd;

/// Physical newTemp sample-slot allocation for the recovered type-0x18 profile.
pub const GF3258_ENROLLMENT_STORAGE_CAPACITY: usize = 50;

/// Live vendor runtime bound at template+0x28 / serialized tag 0x97.
pub const GF3258_ENROLLMENT_CONFIGURED_MAX_SAMPLES: usize = 40;

pub use crate::enrollment_add::Gf3258EnrollmentFeaturePoint;

/// Enrollment-relevant subset of one completed GF3258 Feature object.
///
/// Field correspondence:
///
/// - points: Feature +0xf8 / FeaturePoint60 records consumed by b0cb0
/// - primary_registration_map: Feature +0x08
/// - secondary_registration_map: optional Feature +0x10
/// - packed_validity: Feature +0x130
/// - source_scalars.scalar_108: Feature +0x108
/// - source_scalars.c2d40_param3: Feature +0x10c
/// - source_scalars.c2d40_param4: Feature +0x110
/// - status: Feature +0x114
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gf3258EnrollmentReadyFeature {
    /// Registration/enrollment order. This remains unchanged by persistence-only
    /// b3970 partitioning so the validated enrollment graph behavior is stable.
    pub points: Vec<Gf3258EnrollmentFeaturePoint>,
    /// Persisted FeaturePoint order after the recovered b3970 polarity partition.
    /// Kept separate because point ordering can affect registration tie/order
    /// behavior even though the serialized template must use vendor partition order.
    persistent_points: Vec<Gf3258EnrollmentFeaturePoint>,
    pub primary_registration_map: [u8; GF3258_REGISTRATION_PACKED_BYTES],
    pub secondary_registration_map: Option<[u8; GF3258_REGISTRATION_PACKED_BYTES]>,
    pub low_threshold_registration_map: [u8; GF3258_REGISTRATION_PACKED_BYTES],
    pub quarter_validity_packed: [u8; GF3258_QUARTER_VALIDITY_CELLS / 8],
    pub packed_validity: [u8; GF3258_REGISTRATION_PACKED_BYTES],
    pub source_scalars: Gf3258PersistentSourceScalars,
    pub status: i32,
    persistence_complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gf3258FeatureEnrollmentError {
    TooManyPoints {
        actual: usize,
        capacity: usize,
    },
    #[cfg(test)]
    UnexpectedAlgorithmImageLength {
        expected: usize,
        actual: usize,
    },
    #[cfg(test)]
    UnexpectedActiveValidityLength {
        expected: usize,
        actual: usize,
    },
    NonBinaryActiveValidity {
        index: usize,
        value: u8,
    },
    NonBinaryQuarterValidity {
        index: usize,
        value: u8,
    },
    #[cfg(test)]
    CaptureQualityRejected {
        raw_quality: i32,
        final_quality: i32,
        coverage: i32,
    },
    Feature(FeatureError),
    PersistenceStateIncomplete,
    EnrollmentAdd(Gf3258EnrollmentAddError),
}

impl fmt::Display for Gf3258FeatureEnrollmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyPoints { actual, capacity } => write!(
                f,
                "GF3258 Feature has {actual} points; recovered capacity is {capacity}"
            ),
            #[cfg(test)]
            Self::UnexpectedAlgorithmImageLength { expected, actual } => {
                write!(
                    f,
                    "GF3258 algorithm image has {actual} bytes; expected {expected}"
                )
            }
            #[cfg(test)]
            Self::UnexpectedActiveValidityLength { expected, actual } => {
                write!(
                    f,
                    "GF3258 active validity map has {actual} cells; expected {expected}"
                )
            }
            Self::NonBinaryActiveValidity { index, value } => write!(
                f,
                "GF3258 active validity cell {index} is {value}; expected binary 0/1"
            ),
            Self::NonBinaryQuarterValidity { index, value } => write!(
                f,
                "GF3258 quarter validity cell {index} is {value}; expected binary 0/1"
            ),
            #[cfg(test)]
            Self::CaptureQualityRejected {
                raw_quality,
                final_quality,
                coverage,
            } => write!(
                f,
                "GF3258 capture rejected by vendor raw-quality gate: \
                 raw={raw_quality} final={final_quality} coverage={coverage}"
            ),
            Self::Feature(error) => {
                write!(f, "GF3258 feature preparation failed: {error}")
            }
            Self::PersistenceStateIncomplete => write!(
                f,
                "GF3258 feature was built through a legacy boundary that does \
                 not retain exact persistence state"
            ),
            Self::EnrollmentAdd(error) => {
                write!(f, "GF3258 enrollment add failed: {error:?}")
            }
        }
    }
}

impl Error for Gf3258FeatureEnrollmentError {}

impl From<Gf3258EnrollmentAddError> for Gf3258FeatureEnrollmentError {
    fn from(value: Gf3258EnrollmentAddError) -> Self {
        Self::EnrollmentAdd(value)
    }
}

impl From<FeatureError> for Gf3258FeatureEnrollmentError {
    fn from(value: FeatureError) -> Self {
        Self::Feature(value)
    }
}

fn validate_point_count(count: usize) -> Result<(), Gf3258FeatureEnrollmentError> {
    if count > GF3258_TEMPLATE_POINT_CAPACITY {
        return Err(Gf3258FeatureEnrollmentError::TooManyPoints {
            actual: count,
            capacity: GF3258_TEMPLATE_POINT_CAPACITY,
        });
    }

    Ok(())
}

fn validate_binary_map(values: &[u8], quarter: bool) -> Result<(), Gf3258FeatureEnrollmentError> {
    for (index, &value) in values.iter().enumerate() {
        if value > 1 {
            return Err(if quarter {
                Gf3258FeatureEnrollmentError::NonBinaryQuarterValidity { index, value }
            } else {
                Gf3258FeatureEnrollmentError::NonBinaryActiveValidity { index, value }
            });
        }
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// FUN_001b3970 — persistent point order and Feature+0x108 / b7
// -----------------------------------------------------------------------------

/// Exact logical core of FUN_001b3970.
///
/// The vendor:
///
/// - advances `front` while `(polarity & 3) == 0`;
/// - retreats `back` while `(polarity & 3) == 1`;
/// - swaps complete FeaturePoint60 records when `front < back`;
/// - does not explicitly advance either cursor after a swap;
/// - when `front == back`, increments `front` iff that point is class 0;
/// - stores the resulting boundary at Feature+0x108.
///
/// The standalone polarity producer is binary 0/1.
fn gf3258_b3970_partition_by<T, F>(points: &mut [T], polarity: F) -> i32
where
    F: Fn(&T) -> u16,
{
    if points.is_empty() {
        return 0;
    }

    let mut front = 0usize;
    let mut back = points.len() - 1;

    loop {
        while front < back && (polarity(&points[front]) & 3) == 0 {
            front += 1;
        }

        while front < back && (polarity(&points[back]) & 3) == 1 {
            back -= 1;
        }

        if front < back {
            points.swap(front, back);

            // Vendor rescans the two records after the swap.
            continue;
        }

        if front == back && (polarity(&points[front]) & 3) == 0 {
            front += 1;
        }

        return front as i32;
    }
}

// -----------------------------------------------------------------------------
// Shared exact filtering helpers for threshold-120 coverage
// -----------------------------------------------------------------------------

/// FUN_001a4670 mode 4 / BORDER_REFLECT_101.
impl Gf3258EnrollmentReadyFeature {
    /// Construct directly from every persistence-relevant Feature field.
    ///
    /// Retained as a test seam for exact field-level persistence regressions; normal
    /// enrollment uses `from_primary_extraction_from_c2d40_source`.
    #[cfg(test)]
    // Field-level persistence seam intentionally exposes every recovered Feature field.
    #[allow(clippy::too_many_arguments)]
    pub fn from_feature_fields(
        points: Vec<Gf3258EnrollmentFeaturePoint>,
        primary_registration_map: [u8; GF3258_REGISTRATION_PACKED_BYTES],
        secondary_registration_map: Option<[u8; GF3258_REGISTRATION_PACKED_BYTES]>,
        low_threshold_registration_map: [u8; GF3258_REGISTRATION_PACKED_BYTES],
        quarter_validity_packed: [u8; GF3258_QUARTER_VALIDITY_CELLS / 8],
        packed_validity: [u8; GF3258_REGISTRATION_PACKED_BYTES],
        source_scalars: Gf3258PersistentSourceScalars,
        status: i32,
    ) -> Result<Self, Gf3258FeatureEnrollmentError> {
        validate_point_count(points.len())?;

        let persistent_points = points.clone();

        Ok(Self {
            points,
            persistent_points,
            primary_registration_map,
            secondary_registration_map,
            low_threshold_registration_map,
            quarter_validity_packed,
            packed_validity,
            source_scalars,
            status,
            persistence_complete: true,
        })
    }

    /// Persistence-capable boundary for the current standalone-enrollment path.
    ///
    /// Registration keeps extractor order. C2D40 BF420 mode 0 is applied before
    /// registration/persistence, persistence independently applies b3970, and
    /// `+0x10c/+0x110` are materialized from the recovered capture-quality path.
    /// Caller-supplied `+0x13c/+0x140` state remains preserved.
    pub fn from_primary_extraction_from_c2d40_source(
        extraction: &Gf3258PrimaryFeatureExtraction,
        c2d40_source: &[u8],
        validity: &Gf3258EnrollmentValidity,
        source_scalars: Gf3258PersistentSourceScalars,
        status: i32,
    ) -> Result<Self, Gf3258FeatureEnrollmentError> {
        validate_point_count(extraction.points.len())?;
        validate_binary_map(&validity.quarter_validity, true)?;

        let prepared = gf3258_prepare_c0910_inputs_from_c2d40_source(c2d40_source)?;
        let capture_quality = gf3258_capture_quality(c2d40_source)?;

        // C2D40's enrollment caller uses BF420 mode 0 before ba520 and
        // persistence. Keep that matcher projection in registration order, then
        // build the separate persisted b3970 partition from the same point state.
        let points = extraction
            .points
            .iter()
            .map(gf3258_enrollment_mode0_point)
            .collect::<Vec<_>>();

        let mut ordered = extraction.points.clone();
        let scalar_108 = gf3258_b3970_partition_by(&mut ordered, |point| {
            gf3258_matcher_polarity_from_raw_response(point.candidate.raw.response)
        });
        let persistent_points = ordered
            .iter()
            .map(gf3258_enrollment_mode0_point)
            .collect::<Vec<_>>();

        let mut source_scalars = source_scalars;
        source_scalars.scalar_108 = scalar_108;
        source_scalars.c2d40_param3 = capture_quality.quality;
        source_scalars.c2d40_param4 = capture_quality.coverage;

        let active = gf3258_expand_quarter_validity(&validity.quarter_validity);

        Ok(Self {
            points,
            persistent_points,
            primary_registration_map: gf3258_primary_registration_map(&prepared.detector_source_u8),
            secondary_registration_map: Some(gf3258_secondary_registration_map(
                &prepared.gradient_source_u8,
                &validity.bd720.mask_u8,
            )),
            low_threshold_registration_map: gf3258_low_threshold_registration_map(
                &prepared.detector_source_u8,
            ),
            quarter_validity_packed: gf3258_pack_quarter_validity(&validity.quarter_validity),
            packed_validity: gf3258_pack_active_validity(&active),
            source_scalars,
            status,
            persistence_complete: true,
        })
    }

    /// Recovered quality-aware enrollment boundary.
    ///
    /// This path is retained under tests until the quality gate and scalar
    /// materialization are deliberately enabled in the production enrollment
    /// policy. It is not part of the current green hardware baseline.
    ///
    /// This method materializes all persistence-required Feature state from:
    ///
    /// - the completed primary extraction,
    /// - the final c2d40 source image,
    /// - exact enrollment validity.
    ///
    /// It performs:
    ///
    /// 1. exact capture-quality/coverage production;
    /// 2. vendor raw-quality rejection (<45);
    /// 3. exact FUN_001b3970 point partition;
    /// 4. exact b7/b8/b9 scalar materialization;
    /// 5. all three persistent registration maps;
    /// 6. quarter and active validity packing.
    #[cfg(test)]
    pub fn from_primary_extraction_for_enrollment(
        extraction: &Gf3258PrimaryFeatureExtraction,
        c2d40_source: &[u8],
        validity: &Gf3258EnrollmentValidity,
        status: i32,
    ) -> Result<Self, Gf3258FeatureEnrollmentError> {
        validate_binary_map(&validity.quarter_validity, true)?;

        let capture_quality = gf3258_capture_quality(c2d40_source)?;

        if !capture_quality.accepted_for_enrollment() {
            return Err(Gf3258FeatureEnrollmentError::CaptureQualityRejected {
                raw_quality: capture_quality.raw_quality,
                final_quality: capture_quality.quality,
                coverage: capture_quality.coverage,
            });
        }

        let prepared = gf3258_prepare_c0910_inputs_from_c2d40_source(c2d40_source)?;

        // Clone complete extracted point records, then reproduce b3970 before
        // projecting into the enrollment representation.
        let mut ordered_points = extraction.points.clone();

        let scalar_108 = gf3258_b3970_partition_by(&mut ordered_points, |point| {
            gf3258_matcher_polarity_from_raw_response(point.candidate.raw.response)
        });

        let points = ordered_points
            .iter()
            .map(gf3258_enrollment_mode0_point)
            .collect::<Vec<_>>();

        let active = gf3258_expand_quarter_validity(&validity.quarter_validity);

        let source_scalars = Gf3258PersistentSourceScalars {
            scalar_108,
            c2d40_param3: capture_quality.quality,
            c2d40_param4: capture_quality.coverage,
            ..Gf3258PersistentSourceScalars::default()
        };

        Self::from_feature_fields(
            points,
            gf3258_primary_registration_map(&prepared.detector_source_u8),
            Some(gf3258_secondary_registration_map(
                &prepared.gradient_source_u8,
                &validity.bd720.mask_u8,
            )),
            gf3258_low_threshold_registration_map(&prepared.detector_source_u8),
            gf3258_pack_quarter_validity(&validity.quarter_validity),
            gf3258_pack_active_validity(&active),
            source_scalars,
            status,
        )
    }

    /// Construct from the natural Rust extractor boundary:
    /// algorithm image + completed points + unpacked active validity.
    ///
    /// This remains a general non-persistence-complete constructor.
    #[cfg(test)]
    pub fn from_algorithm_outputs(
        points: Vec<Gf3258EnrollmentFeaturePoint>,
        algorithm_image: &[u8],
        active_validity: &[u8],
        secondary_registration_map: Option<[u8; GF3258_REGISTRATION_PACKED_BYTES]>,
        status: i32,
    ) -> Result<Self, Gf3258FeatureEnrollmentError> {
        validate_point_count(points.len())?;

        if algorithm_image.len() != GF3258_PIXELS {
            return Err(
                Gf3258FeatureEnrollmentError::UnexpectedAlgorithmImageLength {
                    expected: GF3258_PIXELS,
                    actual: algorithm_image.len(),
                },
            );
        }

        if active_validity.len() != GF3258_REGISTRATION_PIXELS {
            return Err(
                Gf3258FeatureEnrollmentError::UnexpectedActiveValidityLength {
                    expected: GF3258_REGISTRATION_PIXELS,
                    actual: active_validity.len(),
                },
            );
        }

        validate_binary_map(active_validity, false)?;

        let mut active = [0u8; GF3258_REGISTRATION_PIXELS];

        active.copy_from_slice(active_validity);

        let persistent_points = points.clone();

        Ok(Self {
            points,
            persistent_points,
            primary_registration_map: gf3258_primary_registration_map(algorithm_image),
            secondary_registration_map,
            low_threshold_registration_map: gf3258_low_threshold_registration_map(algorithm_image),
            quarter_validity_packed: [0u8; GF3258_QUARTER_VALIDITY_CELLS / 8],
            packed_validity: gf3258_pack_active_validity(&active),
            source_scalars: Gf3258PersistentSourceScalars::default(),
            status,
            persistence_complete: false,
        })
    }

    /// Alternate exact boundary for a c2d40 implementation that exposes the
    /// unpacked 20x16 Feature+0x28 logical validity grid.
    #[cfg(test)]
    pub fn from_algorithm_outputs_with_quarter_validity(
        points: Vec<Gf3258EnrollmentFeaturePoint>,
        algorithm_image: &[u8],
        quarter_validity: &[u8; GF3258_QUARTER_VALIDITY_CELLS],
        secondary_registration_map: Option<[u8; GF3258_REGISTRATION_PACKED_BYTES]>,
        status: i32,
    ) -> Result<Self, Gf3258FeatureEnrollmentError> {
        validate_binary_map(quarter_validity, true)?;

        if algorithm_image.len() != GF3258_PIXELS {
            return Err(
                Gf3258FeatureEnrollmentError::UnexpectedAlgorithmImageLength {
                    expected: GF3258_PIXELS,
                    actual: algorithm_image.len(),
                },
            );
        }

        let active = gf3258_expand_quarter_validity(quarter_validity);

        Self::from_feature_fields(
            points,
            gf3258_primary_registration_map(algorithm_image),
            secondary_registration_map,
            gf3258_low_threshold_registration_map(algorithm_image),
            gf3258_pack_quarter_validity(quarter_validity),
            gf3258_pack_active_validity(&active),
            Gf3258PersistentSourceScalars::default(),
            status,
        )
    }

    pub fn persistent_state(
        &self,
    ) -> Result<Gf3258PersistentSampleState, Gf3258FeatureEnrollmentError> {
        if !self.persistence_complete {
            return Err(Gf3258FeatureEnrollmentError::PersistenceStateIncomplete);
        }

        let scalar_13c = if (self.source_scalars.scalar_13c & 1) != 0
            && self.source_scalars.scalar_13c > 0x3e9
        {
            self.source_scalars.scalar_13c
        } else {
            0
        };

        Ok(Gf3258PersistentSampleState {
            points: self.persistent_points.clone(),
            primary_registration_map: self.primary_registration_map,
            secondary_registration_map: self.secondary_registration_map,
            low_threshold_registration_map: self.low_threshold_registration_map,
            quarter_validity_packed: self.quarter_validity_packed,
            active_validity_packed: self.packed_validity,
            canonical_member: false,
            relation_checkpoint: 0,
            sample_index: 0,
            scalar_108: self.source_scalars.scalar_108,
            c2d40_param3: self.source_scalars.c2d40_param3,
            c2d40_param4: self.source_scalars.c2d40_param4,
            scalar_13c,
            embedded_state_140: self.source_scalars.embedded_state_140,
        })
    }

    pub fn registration_points(&self) -> Vec<Gf3258RegistrationPoint> {
        self.points
            .iter()
            .map(Gf3258EnrollmentFeaturePoint::registration_point)
            .collect()
    }

    pub fn enrollment_sample(&self) -> Gf3258EnrollmentSample {
        Gf3258EnrollmentSample {
            canonical_member: false,
            status: self.status,
            primary_registration_map: self.primary_registration_map,
            secondary_registration_map: self.secondary_registration_map,
            packed_validity: self.packed_validity,
        }
    }

    pub fn diagnostics(&self) -> Gf3258EnrollmentFeatureDiagnostics {
        Gf3258EnrollmentFeatureDiagnostics {
            point_count: self.points.len(),

            primary_foreground_cells: self
                .primary_registration_map
                .iter()
                .map(|byte| byte.count_ones() as usize)
                .sum(),

            valid_cells: self
                .packed_validity
                .iter()
                .map(|byte| byte.count_ones() as usize)
                .sum(),

            has_secondary_map: self.secondary_registration_map.is_some(),

            scalar_108: self.source_scalars.scalar_108,

            c2d40_param3: self.source_scalars.c2d40_param3,

            c2d40_param4: self.source_scalars.c2d40_param4,

            status: self.status,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gf3258EnrollmentFeatureDiagnostics {
    pub point_count: usize,
    pub primary_foreground_cells: usize,
    pub valid_cells: usize,
    pub has_secondary_map: bool,

    /// Feature+0x108 / persisted b7.
    pub scalar_108: i32,

    /// Feature+0x10c / persisted b8.
    pub c2d40_param3: i32,

    /// Feature+0x110 / persisted b9.
    pub c2d40_param4: i32,

    pub status: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gf3258EnrollmentStepResult {
    pub feature: Gf3258EnrollmentFeatureDiagnostics,

    pub enrollment: Gf3258EnrollmentAddResult,
}

/// Add one completed extracted Feature using the exact GF3258 b9340 threshold
/// recovered from ba520 (0xcd).
pub fn gf3258_add_extracted_feature(
    template: &mut Gf3258EnrollmentTemplateCore,
    feature: Gf3258EnrollmentReadyFeature,
) -> Result<Gf3258EnrollmentStepResult, Gf3258FeatureEnrollmentError> {
    let diagnostics = feature.diagnostics();

    let points = feature.registration_points();

    let sample = feature.enrollment_sample();

    let enrollment = if feature.persistence_complete {
        let persistent = feature.persistent_state()?;

        template.add_persistent_sample(
            points,
            sample,
            persistent,
            GF3258_ENROLLMENT_GRAPH_SCORE_THRESHOLD,
        )?
    } else {
        template.add_sample(points, sample, GF3258_ENROLLMENT_GRAPH_SCORE_THRESHOLD)?
    };

    Ok(Gf3258EnrollmentStepResult {
        feature: diagnostics,
        enrollment,
    })
}

/// Convenience constructor for the recovered GF3258 template profile.
pub fn gf3258_new_enrollment_template() -> Gf3258EnrollmentTemplateCore {
    Gf3258EnrollmentTemplateCore::new_with_configured_max_samples(
        GF3258_ENROLLMENT_STORAGE_CAPACITY,
        GF3258_ENROLLMENT_CONFIGURED_MAX_SAMPLES,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::enrollment_add::Gf3258EnrollmentAddKind;

    use crate::feature::{
        GF3258_DESCRIPTOR_CENTRAL_LEN, GF3258_DESCRIPTOR_LEN, Gf3258CompactDescriptor,
        Gf3258FeaturePointCore,
    };

    use crate::registration::{GF3258_REGISTRATION_HEIGHT, GF3258_REGISTRATION_WIDTH};

    fn compact_for(id: usize) -> Gf3258CompactDescriptor {
        Gf3258CompactDescriptor {
            norm_128: 0,
            clip_128: 0,

            normalized_128: [0u16; GF3258_DESCRIPTOR_LEN],

            hadamard_128_words: [
                1u32.rotate_left((id % 31) as u32),
                0x0101_0101u32.wrapping_mul((id + 1) as u32),
                0x8000_0000u32.rotate_right((id % 31) as u32),
                0x1111_1111u32 ^ id as u32,
            ],

            median_hash_128: 0xa5a5_0000u32 ^ id as u32,

            norm_32: 0,
            clip_32: 0,

            normalized_32: [0u16; GF3258_DESCRIPTOR_CENTRAL_LEN],

            hadamard_hash_32: 0,
            median_hash_32: 0,
        }
    }

    fn point(id: usize, x: u16, y: u16) -> Gf3258EnrollmentFeaturePoint {
        Gf3258EnrollmentFeaturePoint {
            core: Gf3258FeaturePointCore {
                x_q8: x << 8,
                y_q8: y << 8,
                orientation_q12: 0,
                ranking_score: -(id as i32) - 1,
            },

            compact: compact_for(id),
        }
    }

    fn six_points() -> Vec<Gf3258EnrollmentFeaturePoint> {
        vec![
            point(0, 10, 10),
            point(1, 20, 10),
            point(2, 30, 10),
            point(3, 10, 20),
            point(4, 20, 20),
            point(5, 30, 20),
        ]
    }

    fn enrollment_friendly_image() -> Vec<u8> {
        let mut image = vec![0u8; GF3258_PIXELS];

        for y in 4..7 {
            for x in 4..28 {
                image[(y * 2) * 80 + x * 2] = 255;
            }
        }

        image
    }

    #[test]
    fn production_point_capacity_accepts_limit_and_rejects_overflow() {
        assert_eq!(validate_point_count(GF3258_TEMPLATE_POINT_CAPACITY), Ok(()));

        assert!(matches!(
            validate_point_count(GF3258_TEMPLATE_POINT_CAPACITY + 1),
            Err(Gf3258FeatureEnrollmentError::TooManyPoints {
                actual: 121,
                capacity: GF3258_TEMPLATE_POINT_CAPACITY,
            })
        ));
    }

    #[test]
    fn quality_aware_bridge_rejects_uniform_capture() {
        let source = vec![255u8; GF3258_PIXELS];
        let extraction =
            crate::feature::gf3258_extract_primary_features_from_c2d40_source(&source).unwrap();
        let validity =
            crate::feature::gf3258_enrollment_validity_from_c2d40_source(&source).unwrap();

        let error = Gf3258EnrollmentReadyFeature::from_primary_extraction_for_enrollment(
            &extraction,
            &source,
            &validity,
            0,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            Gf3258FeatureEnrollmentError::CaptureQualityRejected { .. }
        ));
    }

    #[test]
    fn polarity_is_strict_signed_negative() {
        assert_eq!(gf3258_matcher_polarity_from_raw_response(i32::MIN,), 1);

        assert_eq!(gf3258_matcher_polarity_from_raw_response(-1,), 1);

        assert_eq!(gf3258_matcher_polarity_from_raw_response(0,), 0);

        assert_eq!(gf3258_matcher_polarity_from_raw_response(1,), 0);

        assert_eq!(gf3258_matcher_polarity_from_raw_response(i32::MAX,), 0);
    }

    #[test]
    fn b3970_partition_matches_vendor_swap_shape() {
        let mut values = vec![
            (0usize, 0u16),
            (1usize, 1u16),
            (2usize, 0u16),
            (3usize, 1u16),
            (4usize, 0u16),
        ];

        let boundary = gf3258_b3970_partition_by(&mut values, |value| value.1);

        assert_eq!(boundary, 3);

        let ids: Vec<usize> = values.iter().map(|value| value.0).collect();

        assert_eq!(ids, vec![0, 4, 2, 3, 1]);
    }

    #[test]
    fn b3970_edge_cases_are_exact() {
        let mut empty: Vec<u16> = Vec::new();

        assert_eq!(gf3258_b3970_partition_by(&mut empty, |value| *value,), 0);

        let mut zero = vec![0u16];

        assert_eq!(gf3258_b3970_partition_by(&mut zero, |value| *value,), 1);

        let mut one = vec![1u16];

        assert_eq!(gf3258_b3970_partition_by(&mut one, |value| *value,), 0);
    }

    #[test]
    fn persistence_baseline_derives_scalar_108_instead_of_trusting_caller_default() {
        let source = vec![127u8; GF3258_PIXELS];
        let extraction =
            crate::feature::gf3258_extract_primary_features_from_c2d40_source(&source).unwrap();
        let validity =
            crate::feature::gf3258_enrollment_validity_from_c2d40_source(&source).unwrap();
        assert!(extraction.points.is_empty());

        let feature = Gf3258EnrollmentReadyFeature::from_primary_extraction_from_c2d40_source(
            &extraction,
            &source,
            &validity,
            Gf3258PersistentSourceScalars {
                scalar_108: 99,
                ..Gf3258PersistentSourceScalars::default()
            },
            0,
        )
        .unwrap();

        assert_eq!(feature.diagnostics().scalar_108, 0);
        assert_eq!(feature.persistent_state().unwrap().scalar_108, 0);
    }

    #[test]
    fn persistence_partition_order_is_separate_from_registration_order() {
        let registration_points = vec![point(0, 10, 10), point(1, 20, 20)];
        let persistent_points = vec![
            registration_points[1].clone(),
            registration_points[0].clone(),
        ];
        let feature = Gf3258EnrollmentReadyFeature {
            points: registration_points,
            persistent_points,
            primary_registration_map: [0; GF3258_REGISTRATION_PACKED_BYTES],
            secondary_registration_map: None,
            low_threshold_registration_map: [0; GF3258_REGISTRATION_PACKED_BYTES],
            quarter_validity_packed: [0; GF3258_QUARTER_VALIDITY_CELLS / 8],
            packed_validity: [0; GF3258_REGISTRATION_PACKED_BYTES],
            source_scalars: Gf3258PersistentSourceScalars {
                scalar_108: 1,
                ..Gf3258PersistentSourceScalars::default()
            },
            status: 0,
            persistence_complete: true,
        };

        let registration = feature.registration_points();
        assert_eq!(registration[0].x_q8, 10 << 8);
        assert_eq!(registration[1].x_q8, 20 << 8);

        let persisted = feature.persistent_state().unwrap();
        assert_eq!(persisted.scalar_108, 1);
        assert_eq!(persisted.points[0].core.x_q8, 20 << 8);
        assert_eq!(persisted.points[1].core.x_q8, 10 << 8);
    }

    #[test]
    fn persistence_bridge_materializes_c2d40_quality_scalars() {
        let source = enrollment_friendly_image();
        let extraction =
            crate::feature::gf3258_extract_primary_features_from_c2d40_source(&source).unwrap();
        let validity =
            crate::feature::gf3258_enrollment_validity_from_c2d40_source(&source).unwrap();
        let quality = gf3258_capture_quality(&source).unwrap();

        let feature = Gf3258EnrollmentReadyFeature::from_primary_extraction_from_c2d40_source(
            &extraction,
            &source,
            &validity,
            Gf3258PersistentSourceScalars::default(),
            0,
        )
        .unwrap();
        let persisted = feature.persistent_state().unwrap();

        assert_eq!(persisted.c2d40_param3, quality.quality);
        assert_eq!(persisted.c2d40_param4, quality.coverage);
    }

    #[test]
    fn enrollment_mode0_projection_matches_bf420_descriptor_domain() {
        let compact = compact_for(7);
        let original = compact.feature_point_bytes_10_2f();
        let expected: [u8; 16] =
            gf3258_bf420_descriptor(original[..16].try_into().expect("descriptor prefix"));

        let projected = gf3258_enrollment_mode0_compact_descriptor(&compact);
        let projected_bytes = projected.feature_point_bytes_10_2f();

        assert_eq!(&projected_bytes[..16], &expected);
        assert_eq!(projected.median_hash_128, compact.median_hash_128);
        assert_eq!(projected.hadamard_hash_32, compact.hadamard_hash_32);
        assert_eq!(projected.median_hash_32, compact.median_hash_32);
    }

    #[test]
    fn persisted_enrollment_point_decodes_in_verification_descriptor_domain() {
        let mut p = point(9, 17, 23);
        p.compact = gf3258_enrollment_mode0_compact_descriptor(&p.compact);
        let expected = p.compact.feature_point_bytes_10_2f();

        let encoded = crate::template_persistence::gf3258_encode_persistent_point(&p);
        let decoded = crate::template_decode::gf3258_decode_persistent_point(&encoded);

        assert_eq!(decoded.descriptor_10_1f.as_slice(), &expected[..16]);
        assert_eq!(decoded.hash20, p.compact.median_hash_128);
        assert_eq!(decoded.hash28, p.compact.hadamard_hash_32);
        assert_eq!(decoded.hash2c, p.compact.median_hash_32);
    }

    #[test]
    fn bridge_uses_exact_registration_descriptor_prefix() {
        let p = point(3, 17, 23);

        let expected = p.compact.feature_point_bytes_10_2f();

        let registration = p.registration_point();

        assert_eq!(registration.x_q8, 17 << 8);

        assert_eq!(registration.y_q8, 23 << 8);

        assert_eq!(&registration.descriptor_192[..], &expected[..24]);
    }

    #[test]
    fn algorithm_outputs_build_primary_and_packed_validity() {
        let image = enrollment_friendly_image();

        let active = vec![1u8; GF3258_REGISTRATION_PIXELS];

        let feature = Gf3258EnrollmentReadyFeature::from_algorithm_outputs(
            six_points(),
            &image,
            &active,
            None,
            0,
        )
        .unwrap();

        assert_eq!(
            feature
                .primary_registration_map
                .iter()
                .map(|byte| { byte.count_ones() },)
                .sum::<u32>(),
            72
        );

        assert!(
            feature
                .packed_validity
                .iter()
                .all(|&byte| { byte == 0xff },)
        );

        let diagnostics = feature.diagnostics();

        assert_eq!(diagnostics.point_count, 6);

        assert_eq!(diagnostics.primary_foreground_cells, 72);

        assert_eq!(diagnostics.valid_cells, GF3258_REGISTRATION_PIXELS);
    }

    #[test]
    fn quarter_validity_expands_two_by_two_before_packing() {
        let image = vec![0u8; GF3258_PIXELS];

        let mut quarter = [0u8; GF3258_QUARTER_VALIDITY_CELLS];

        quarter[0] = 1;

        let feature = Gf3258EnrollmentReadyFeature::from_algorithm_outputs_with_quarter_validity(
            Vec::new(),
            &image,
            &quarter,
            None,
            0,
        )
        .unwrap();

        assert_eq!(feature.packed_validity[0] & 0b0000_0011, 0b0000_0011);

        assert_eq!(
            feature.packed_validity[GF3258_REGISTRATION_WIDTH / 8] & 0b0000_0011,
            0b0000_0011
        );

        assert_eq!(feature.diagnostics().valid_cells, 4);
    }

    #[test]
    fn nonbinary_active_validity_is_rejected_before_packing() {
        let image = vec![0u8; GF3258_PIXELS];

        let mut active = vec![1u8; GF3258_REGISTRATION_PIXELS];

        active[37] = 2;

        let error = Gf3258EnrollmentReadyFeature::from_algorithm_outputs(
            Vec::new(),
            &image,
            &active,
            None,
            0,
        )
        .unwrap_err();

        assert_eq!(
            error,
            Gf3258FeatureEnrollmentError::NonBinaryActiveValidity {
                index: 37,
                value: 2,
            }
        );
    }

    #[test]
    fn first_real_feature_enters_template_without_pair_registration() {
        let image = enrollment_friendly_image();

        let active = vec![1u8; GF3258_REGISTRATION_PIXELS];

        let feature = Gf3258EnrollmentReadyFeature::from_algorithm_outputs(
            six_points(),
            &image,
            &active,
            None,
            0,
        )
        .unwrap();

        let mut template = gf3258_new_enrollment_template();

        let result = gf3258_add_extracted_feature(&mut template, feature).unwrap();

        assert_eq!(result.enrollment.kind, Gf3258EnrollmentAddKind::FirstSample);

        assert_eq!(template.sample_count(), 1);

        assert_eq!(result.feature.point_count, 6);
    }

    #[test]
    fn second_identical_feature_uses_real_maps_and_establishes_component() {
        let image = enrollment_friendly_image();

        let active = vec![1u8; GF3258_REGISTRATION_PIXELS];

        let feature = Gf3258EnrollmentReadyFeature::from_algorithm_outputs(
            six_points(),
            &image,
            &active,
            None,
            0,
        )
        .unwrap();

        let mut template = gf3258_new_enrollment_template();

        let first = gf3258_add_extracted_feature(&mut template, feature.clone()).unwrap();

        assert_eq!(first.enrollment.kind, Gf3258EnrollmentAddKind::FirstSample);

        let second = gf3258_add_extracted_feature(&mut template, feature).unwrap();

        assert_eq!(second.enrollment.kind, Gf3258EnrollmentAddKind::Integrated);

        assert_eq!(second.enrollment.successful_previous, vec![0]);

        assert_eq!(second.enrollment.attempts[0].geometric_inliers, 6);

        let scores = second.enrollment.attempts[0].map_scores.as_ref().unwrap();

        assert!(scores.metric_a >= 216);

        assert!(scores.score > GF3258_ENROLLMENT_GRAPH_SCORE_THRESHOLD);

        assert!(template.graph.canonical_established);

        assert_eq!(template.graph.canonical_anchor, 0);

        assert!(template.graph.samples[0].canonical_member);

        assert!(template.graph.samples[1].canonical_member);

        assert_eq!(template.sample_count(), 2);

        assert_eq!(GF3258_REGISTRATION_WIDTH, 40);

        assert_eq!(GF3258_REGISTRATION_HEIGHT, 32);
    }

    #[test]
    fn quarter_boundary_retains_exact_40_byte_persistence_blob() {
        let image = vec![0u8; GF3258_PIXELS];

        let mut quarter = [0u8; GF3258_QUARTER_VALIDITY_CELLS];

        quarter[0] = 1;
        quarter[19] = 1;
        quarter[20] = 1;

        let feature = Gf3258EnrollmentReadyFeature::from_algorithm_outputs_with_quarter_validity(
            Vec::new(),
            &image,
            &quarter,
            None,
            0,
        )
        .unwrap();

        assert_eq!(
            feature.quarter_validity_packed,
            gf3258_pack_quarter_validity(&quarter,)
        );

        assert!(feature.persistent_state().is_ok());
    }
}
