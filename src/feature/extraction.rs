//! Primary GF3258 feature extraction orchestration.
//!
//! This module owns the c2d40-to-c0910 image-role preparation and composes the
//! detector, orientation, and descriptor stages into production primary feature
//! records. It does not reimplement those lower-level algorithms.

use std::{error::Error, fmt};

use super::filter::separable_q16_reflect101;
use super::{
    FeatureError, GF3258_DESCRIPTOR_PROFILE_SCALE_Q16, GF3258_PIXELS, Gf3258CompactDescriptor,
    Gf3258DescriptorError, Gf3258DescriptorResult, Gf3258FeaturePointCore, Gf3258GradientPlanes,
    Gf3258OrientationError, Gf3258OrientationResult, Gf3258ScaleSpace, RefinedExtremum,
    RefinementOutcome, gf3258_c7310_gradient_source, gf3258_gradient_planes,
    gf3258_primary_descriptor, gf3258_primary_orientation,
};

// FUN_001c2d40 GF3258 (sensor type 0x18) detector-source producer.
// a4840 mode 6 record at DAT_00273d80: tap_count=3, coefficients 0x5555 each.
// The coefficient sum is intentionally 65535, not 65536.
pub const GF3258_C2D40_MODE6_KERNEL: [i32; 3] = [21_845, 21_845, 21_845];
pub const GF3258_C2D40_INPUTS_REVISION: &str = "gf3258-c2d40-inputs-v1";

// -----------------------------------------------------------------------------
// FUN_001c2d40 GF3258 single-source -> c0910 two-image input producer
// -----------------------------------------------------------------------------

/// Exact GF3258 local_2b8 -> local_2b0 detector-source producer.
///
/// For sensor type 0x18, c2d40 first uses local_2b8 as the source bytes,
/// converts each byte to u16 Q8 with `byte << 8`, runs a4840 mode 6, then
/// stores the high byte of each filtered u16 into local_2b0. a4840 performs
/// Q16 truncation after each separable 1-D pass, exactly as the already-proven
/// modes 0/1 implementation used by `separable_q16_reflect101`.
pub fn gf3258_c2d40_detector_source(source_u8: &[u8]) -> Result<Vec<u8>, FeatureError> {
    if source_u8.len() != GF3258_PIXELS {
        return Err(FeatureError::UnexpectedPixelCount {
            expected: GF3258_PIXELS,
            actual: source_u8.len(),
        });
    }

    let source_q8: Vec<u16> = source_u8
        .iter()
        .map(|&value| u16::from(value) << 8)
        .collect();
    let filtered = separable_q16_reflect101(&source_q8, &GF3258_C2D40_MODE6_KERNEL);

    Ok(filtered
        .into_iter()
        .map(|value| (value >> 8) as u8)
        .collect())
}

/// Both c0910 image inputs produced from the single normal-GF3258 c2d40
/// source image (local_2b8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gf3258PreparedC0910Inputs {
    /// local_290 / c0910 param_1, produced by c6d90+c7310.
    pub gradient_source_u8: Vec<u8>,
    /// local_2b0 / c0910 param_2, produced by a4840 mode 6.
    pub detector_source_u8: Vec<u8>,
}

/// Produce both exact c0910 input images from the one normal GF3258 c2d40
/// source image. For sensor type 0x18, local_2b8 is a byte-for-byte copy of
/// c2d40 param_2 before these two branches are derived.
pub fn gf3258_prepare_c0910_inputs_from_c2d40_source(
    source_u8: &[u8],
) -> Result<Gf3258PreparedC0910Inputs, FeatureError> {
    // Validate once up front so both branches have the same explicit boundary.
    if source_u8.len() != GF3258_PIXELS {
        return Err(FeatureError::UnexpectedPixelCount {
            expected: GF3258_PIXELS,
            actual: source_u8.len(),
        });
    }

    Ok(Gf3258PreparedC0910Inputs {
        gradient_source_u8: gf3258_c7310_gradient_source(source_u8)?,
        detector_source_u8: gf3258_c2d40_detector_source(source_u8)?,
    })
}

// -----------------------------------------------------------------------------
// GF3258 c0910 two-image primary feature extraction
// -----------------------------------------------------------------------------

/// Revision marker for the production-facing two-image c0910 feature path.
pub const GF3258_PRIMARY_EXTRACTION_REVISION: &str = "gf3258-primary-extraction-v7";

/// Exact image roles at the FUN_001c0910 boundary for GF3258.
///
/// c2d40 calls:
///   FUN_001c0910(local_290, local_2b0, ...)
///
/// The first image (`param_1` / RDI / local_290) feeds the mode-0/mode-1
/// derivative producer. The second image (`param_2` / RSI / local_2b0) feeds
/// the Gaussian scale-space detector. They are deliberately represented as
/// separate inputs so callers cannot accidentally reuse the detector image as
/// the gradient source.
#[derive(Debug, Clone, Copy)]
pub struct Gf3258C0910Inputs<'a> {
    /// c0910 param_1 / RDI: source used to build magnitude + angle planes.
    pub gradient_source_u8: &'a [u8],
    /// c0910 param_2 / RSI: source used to build the detector scale space.
    pub detector_source_u8: &'a [u8],
}

/// Inputs at the c2d40 boundary immediately before c7310/c0910.
///
/// `c7310_source_u8` is local_2b8, from which c7310 builds c0910 param_1.
/// `detector_source_u8` is local_2b0, passed directly as c0910 param_2.
#[derive(Debug, Clone, Copy)]
pub struct Gf3258C2d40FeatureInputs<'a> {
    pub c7310_source_u8: &'a [u8],
    pub detector_source_u8: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gf3258ExtractedPrimaryPoint {
    /// Refined/deduplicated c0910 detector candidate.
    pub candidate: RefinedExtremum,
    /// Exact final FeaturePoint60 geometry/orientation/ranking fields after
    /// C0910's post-BF830 coordinate/orientation quantization.
    pub core: Gf3258FeaturePointCore,
    /// Full be0b0 orientation result retained for diagnostics/parity.
    pub orientation: Gf3258OrientationResult,
    /// Full bf830 -> bdee0 -> compact descriptor result.
    pub descriptor: Gf3258DescriptorResult,
}

impl Gf3258ExtractedPrimaryPoint {
    /// Compact FeaturePoint60 +0x10..+0x2f representation used downstream by
    /// registration/enrollment.
    #[inline]
    pub fn compact_descriptor(&self) -> &Gf3258CompactDescriptor {
        &self.descriptor.compact
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf3258PrimaryExtractionDiagnostics {
    /// Number of raw thresholded 3x3x3 extrema. Every raw extremum produces
    /// exactly one RefinementOutcome, so this equals refinement_outcomes.len().
    pub raw_extrema_count: usize,
    pub refined_accepted_count: usize,
    pub refinement_fallback_count: usize,
    /// Accepted candidates after the refined-pixel used-map de-duplication.
    pub primary_point_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gf3258PrimaryFeatureExtraction {
    /// Internally generated live derivative planes. These are exposed only for
    /// diagnostics/parity; callers do not supply them to the production API.
    pub gradient_planes: Gf3258GradientPlanes,
    /// One outcome per raw detector extremum, retained for diagnostics.
    pub refinement_outcomes: Vec<RefinementOutcome>,
    /// Final primary points with internally generated orientation/descriptor.
    pub points: Vec<Gf3258ExtractedPrimaryPoint>,
}

impl Gf3258PrimaryFeatureExtraction {
    pub fn diagnostics(&self) -> Gf3258PrimaryExtractionDiagnostics {
        let refined_accepted_count = self
            .refinement_outcomes
            .iter()
            .filter(|outcome| matches!(outcome, RefinementOutcome::Accepted(_)))
            .count();
        let refinement_fallback_count = self.refinement_outcomes.len() - refined_accepted_count;

        Gf3258PrimaryExtractionDiagnostics {
            raw_extrema_count: self.refinement_outcomes.len(),
            refined_accepted_count,
            refinement_fallback_count,
            primary_point_count: self.points.len(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gf3258PrimaryExtractionError {
    C7310Source(FeatureError),
    GradientSource(FeatureError),
    DetectorSource(FeatureError),
    InvalidDescriptorScale(i32),
    Orientation {
        point_index: usize,
        source: Gf3258OrientationError,
    },
    Descriptor {
        point_index: usize,
        source: Gf3258DescriptorError,
    },
}

impl fmt::Display for Gf3258PrimaryExtractionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::C7310Source(error) => {
                write!(f, "GF3258 c7310/local_2b8 source input: {error}")
            }
            Self::GradientSource(error) => {
                write!(f, "GF3258 c0910 gradient-source input: {error}")
            }
            Self::DetectorSource(error) => {
                write!(f, "GF3258 c0910 detector-source input: {error}")
            }
            Self::InvalidDescriptorScale(scale) => write!(
                f,
                "GF3258 c0910 descriptor/profile scale must be positive; got {scale}"
            ),
            Self::Orientation {
                point_index,
                source,
            } => write!(
                f,
                "GF3258 c0910 primary point {point_index} orientation failed: {source}"
            ),
            Self::Descriptor {
                point_index,
                source,
            } => write!(
                f,
                "GF3258 c0910 primary point {point_index} descriptor failed: {source}"
            ),
        }
    }
}

impl Error for Gf3258PrimaryExtractionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::C7310Source(error)
            | Self::GradientSource(error)
            | Self::DetectorSource(error) => Some(error),
            Self::Orientation { source, .. } => Some(source),
            Self::Descriptor { source, .. } => Some(source),
            Self::InvalidDescriptorScale(_) => None,
        }
    }
}

/// Production GF3258 primary-feature extraction from the single normal
/// c2d40 source image. This is the fixture-free feature boundary for sensor
/// type 0x18: Rust derives both local_290/c0910-param1 and local_2b0/c0910-param2
/// internally before entering the already-proven c0910 feature stack.
pub fn gf3258_extract_primary_features_from_c2d40_source(
    source_u8: &[u8],
) -> Result<Gf3258PrimaryFeatureExtraction, Gf3258PrimaryExtractionError> {
    let gradient_source = gf3258_c7310_gradient_source(source_u8)
        .map_err(Gf3258PrimaryExtractionError::C7310Source)?;
    let detector_source = gf3258_c2d40_detector_source(source_u8)
        .map_err(Gf3258PrimaryExtractionError::DetectorSource)?;

    gf3258_extract_primary_features(Gf3258C0910Inputs {
        gradient_source_u8: &gradient_source,
        detector_source_u8: &detector_source,
    })
}

/// Regression/research boundary retaining c2d40's two post-preprocessing roles.
/// Production GF3258 callers should prefer
/// `gf3258_extract_primary_features_from_c2d40_source`, which derives both
/// roles from the single local_2b8 source.
pub fn gf3258_extract_primary_features_from_c2d40(
    inputs: Gf3258C2d40FeatureInputs<'_>,
) -> Result<Gf3258PrimaryFeatureExtraction, Gf3258PrimaryExtractionError> {
    let gradient_source = gf3258_c7310_gradient_source(inputs.c7310_source_u8)
        .map_err(Gf3258PrimaryExtractionError::C7310Source)?;

    gf3258_extract_primary_features(Gf3258C0910Inputs {
        gradient_source_u8: &gradient_source,
        detector_source_u8: inputs.detector_source_u8,
    })
}

/// Production GF3258 primary-feature extraction from the exact two c0910 image
/// roles. Magnitude/angle planes are generated internally from param_1; callers
/// cannot inject precomputed be0b0 fixtures through this API.
pub fn gf3258_extract_primary_features(
    inputs: Gf3258C0910Inputs<'_>,
) -> Result<Gf3258PrimaryFeatureExtraction, Gf3258PrimaryExtractionError> {
    gf3258_extract_primary_features_with_descriptor_scale(
        inputs,
        GF3258_DESCRIPTOR_PROFILE_SCALE_Q16,
    )
}

/// Same orchestration with an explicit descriptor/profile scale. This exists
/// for deterministic parity/research of c0910 profiles; normal GF3258 callers
/// should use `gf3258_extract_primary_features`, which fixes the recovered
/// profile scale at 98862 Q16.
pub fn gf3258_extract_primary_features_with_descriptor_scale(
    inputs: Gf3258C0910Inputs<'_>,
    descriptor_scale_q16: i32,
) -> Result<Gf3258PrimaryFeatureExtraction, Gf3258PrimaryExtractionError> {
    if descriptor_scale_q16 <= 0 {
        return Err(Gf3258PrimaryExtractionError::InvalidDescriptorScale(
            descriptor_scale_q16,
        ));
    }

    // Keep the two source roles visibly separate. This is not redundant: the
    // same-run 10240/10240 parity check proved that substituting param_2 for
    // param_1 changes every one of the 78x62 interior derivative samples.
    let gradient_planes = gf3258_gradient_planes(inputs.gradient_source_u8)
        .map_err(Gf3258PrimaryExtractionError::GradientSource)?;
    let scale_space = Gf3258ScaleSpace::build(inputs.detector_source_u8)
        .map_err(Gf3258PrimaryExtractionError::DetectorSource)?;

    let refinement_outcomes = scale_space.refinement_outcomes();
    let candidates = scale_space.primary_candidates(&refinement_outcomes);
    let mut points = Vec::with_capacity(candidates.len());

    for (point_index, candidate) in candidates.into_iter().enumerate() {
        let orientation = gf3258_primary_orientation(
            &candidate,
            &gradient_planes.magnitude_map_i32,
            &gradient_planes.angle_map_u16,
        )
        .map_err(|source| Gf3258PrimaryExtractionError::Orientation {
            point_index,
            source,
        })?;

        let core = Gf3258FeaturePointCore::from_candidate(&candidate, &orientation);

        let descriptor = gf3258_primary_descriptor(
            &candidate,
            orientation.orientation_q12,
            descriptor_scale_q16,
            &gradient_planes.magnitude_map_i32,
            &gradient_planes.angle_map_u16,
        )
        .map_err(|source| Gf3258PrimaryExtractionError::Descriptor {
            point_index,
            source,
        })?;

        points.push(Gf3258ExtractedPrimaryPoint {
            candidate,
            core,
            orientation,
            descriptor,
        });
    }

    Ok(Gf3258PrimaryFeatureExtraction {
        gradient_planes,
        refinement_outcomes,
        points,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c2d40_mode6_record_is_exact() {
        assert_eq!(GF3258_C2D40_MODE6_KERNEL, [21_845, 21_845, 21_845]);
        assert_eq!(GF3258_C2D40_MODE6_KERNEL.iter().sum::<i32>(), 65_535);
    }

    #[test]
    fn c2d40_mode6_preserves_vendor_two_pass_truncation() {
        let source = vec![127u8; GF3258_PIXELS];
        let detector = gf3258_c2d40_detector_source(&source).unwrap();

        // 127<<8 = 32512. Because the mode-6 coefficients sum to 65535,
        // each Q16 1-D pass truncates one unit: 32512 -> 32511 -> 32510.
        // The final high byte is therefore 126, not 127.
        assert!(detector.iter().all(|&value| value == 126));
    }

    #[test]
    fn c2d40_single_source_prepares_both_c0910_roles() {
        let source = synthetic_c0910_image(0x55aa_1234);
        let prepared = gf3258_prepare_c0910_inputs_from_c2d40_source(&source).unwrap();

        assert_eq!(
            prepared.gradient_source_u8,
            gf3258_c7310_gradient_source(&source).unwrap()
        );
        assert_eq!(
            prepared.detector_source_u8,
            gf3258_c2d40_detector_source(&source).unwrap()
        );
    }

    fn synthetic_c0910_image(mut state: u32) -> Vec<u8> {
        let mut image = Vec::with_capacity(GF3258_PIXELS);
        for _ in 0..GF3258_PIXELS {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            image.push((state >> 24) as u8);
        }
        image
    }

    #[test]
    fn c2d40_single_source_extraction_matches_manual_preparation() {
        let source = synthetic_c0910_image(0xdec0_de01);

        let automatic = gf3258_extract_primary_features_from_c2d40_source(&source).unwrap();
        let prepared = gf3258_prepare_c0910_inputs_from_c2d40_source(&source).unwrap();
        let manual = gf3258_extract_primary_features(Gf3258C0910Inputs {
            gradient_source_u8: &prepared.gradient_source_u8,
            detector_source_u8: &prepared.detector_source_u8,
        })
        .unwrap();

        assert_eq!(automatic, manual);
    }

    #[test]
    fn c2d40_extraction_api_matches_manual_c7310_then_c0910() {
        let c7310_source = synthetic_c0910_image(0x0bad_f00d);
        let detector_source = synthetic_c0910_image(0x1020_3040);

        let automatic = gf3258_extract_primary_features_from_c2d40(Gf3258C2d40FeatureInputs {
            c7310_source_u8: &c7310_source,
            detector_source_u8: &detector_source,
        })
        .unwrap();

        let gradient_source = gf3258_c7310_gradient_source(&c7310_source).unwrap();
        let manual = gf3258_extract_primary_features(Gf3258C0910Inputs {
            gradient_source_u8: &gradient_source,
            detector_source_u8: &detector_source,
        })
        .unwrap();

        assert_eq!(automatic, manual);
    }

    #[test]
    fn primary_extraction_applies_c0910_final_point_quantization() {
        let gradient_source = synthetic_c0910_image(0x1357_9bdf);
        let detector_source = synthetic_c0910_image(0x2468_ace0);
        let result = gf3258_extract_primary_features(Gf3258C0910Inputs {
            gradient_source_u8: &gradient_source,
            detector_source_u8: &detector_source,
        })
        .unwrap();

        assert!(!result.points.is_empty());
        for point in &result.points {
            assert_eq!(point.core.x_q8 & 0x000f, 0);
            assert_eq!(point.core.y_q8 & 0x000f, 0);
            assert_eq!(point.core.orientation_q12 & 0x00ff, 0);
        }
    }

    #[test]
    fn primary_extraction_keeps_c0910_image_roles_separate() {
        let gradient_source = vec![17u8; GF3258_PIXELS];
        let detector_source = vec![23u8; GF3258_PIXELS];
        let result = gf3258_extract_primary_features(Gf3258C0910Inputs {
            gradient_source_u8: &gradient_source,
            detector_source_u8: &detector_source,
        })
        .unwrap();

        let expected_planes = gf3258_gradient_planes(&gradient_source).unwrap();
        assert_eq!(result.gradient_planes, expected_planes);
        assert_eq!(
            result.diagnostics().primary_point_count,
            result.points.len()
        );
    }

    #[test]
    fn primary_extraction_matches_manual_component_orchestration() {
        let gradient_source = synthetic_c0910_image(0x1357_9bdf);
        let detector_source = synthetic_c0910_image(0x2468_ace0);

        let result = gf3258_extract_primary_features(Gf3258C0910Inputs {
            gradient_source_u8: &gradient_source,
            detector_source_u8: &detector_source,
        })
        .unwrap();

        let planes = gf3258_gradient_planes(&gradient_source).unwrap();
        assert_eq!(result.gradient_planes, planes);

        let scale_space = Gf3258ScaleSpace::build(&detector_source).unwrap();
        let outcomes = scale_space.refinement_outcomes();
        let candidates = scale_space.primary_candidates(&outcomes);

        assert_eq!(result.refinement_outcomes, outcomes);
        assert_eq!(result.points.len(), candidates.len());

        for (index, candidate) in candidates.iter().enumerate() {
            let orientation = gf3258_primary_orientation(
                candidate,
                &planes.magnitude_map_i32,
                &planes.angle_map_u16,
            )
            .unwrap();
            let core = Gf3258FeaturePointCore::from_candidate(candidate, &orientation);
            let descriptor = gf3258_primary_descriptor(
                candidate,
                orientation.orientation_q12,
                GF3258_DESCRIPTOR_PROFILE_SCALE_Q16,
                &planes.magnitude_map_i32,
                &planes.angle_map_u16,
            )
            .unwrap();

            assert_eq!(result.points[index].candidate, *candidate);
            assert_eq!(result.points[index].orientation, orientation);
            assert_eq!(result.points[index].core, core);
            assert_eq!(result.points[index].descriptor, descriptor);
        }

        let diagnostics = result.diagnostics();
        assert_eq!(diagnostics.raw_extrema_count, outcomes.len());
        assert_eq!(
            diagnostics.refined_accepted_count + diagnostics.refinement_fallback_count,
            diagnostics.raw_extrema_count
        );
        assert_eq!(diagnostics.primary_point_count, candidates.len());
    }

    #[test]
    fn primary_extraction_rejects_bad_source_lengths_by_role() {
        let good = vec![0u8; GF3258_PIXELS];
        let short = vec![0u8; GF3258_PIXELS - 1];

        assert!(matches!(
            gf3258_extract_primary_features(Gf3258C0910Inputs {
                gradient_source_u8: &short,
                detector_source_u8: &good,
            }),
            Err(Gf3258PrimaryExtractionError::GradientSource(_))
        ));

        assert!(matches!(
            gf3258_extract_primary_features(Gf3258C0910Inputs {
                gradient_source_u8: &good,
                detector_source_u8: &short,
            }),
            Err(Gf3258PrimaryExtractionError::DetectorSource(_))
        ));
    }
}
