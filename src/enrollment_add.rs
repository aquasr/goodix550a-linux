//! GF3258 WN2 ba520-style add-sample coordinator.
//!
//! This module sits above `registration.rs` and `enrollment_graph.rs`.
//! It owns the retained per-sample registration points, runs the closed
//! descriptor/geometric registration path against every previous sample,
//! applies the exact ba520 final A/B acceptance table, stores accepted direct
//! PairRelation records, and then invokes the incremental enrollment graph
//! integration layer.
//!
//! FUN_001a9a50/FUN_001a9580/FUN_001a8ae0 are now wired directly for GF3258.
//! ba520 consumes primary-map metric A/B, while b9340 consumes the distinct
//! a9a50 return score.  No caller-supplied scoring callback remains on the
//! production add-sample API.

use crate::enrollment_graph::{
    Gf3258EnrollmentGraph, Gf3258EnrollmentGraphError, Gf3258EnrollmentIntegrationResult,
    Gf3258EnrollmentSample, gf3258_integrate_enrollment_graph,
};
use crate::feature::{Gf3258CompactDescriptor, Gf3258FeaturePointCore};
use crate::registration::{
    Gf3258AffineQ8, Gf3258RegistrationDecision, Gf3258RegistrationMapScores,
    Gf3258RegistrationPoint, gf3258_register_point_sets, gf3258_registration_accepts,
    gf3258_registration_map_scores,
};

/// Full source point retained for persistence while registration continues to
/// consume its reduced 192-bit projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gf3258EnrollmentFeaturePoint {
    pub core: Gf3258FeaturePointCore,
    pub compact: Gf3258CompactDescriptor,
}

impl Gf3258EnrollmentFeaturePoint {
    #[inline]
    pub fn registration_point(&self) -> Gf3258RegistrationPoint {
        Gf3258RegistrationPoint::from_feature_components(&self.core, &self.compact)
    }
}

/// Source-copied scalar state whose provenance is closed but whose human-readable
/// semantics are intentionally not invented.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Gf3258PersistentSourceScalars {
    pub scalar_108: i32,
    pub c2d40_param3: i32,
    pub c2d40_param4: i32,
    pub scalar_13c: i32,
    pub embedded_state_140: i32,
}

/// Persistence-capable logical equivalent of the vendor's retained Feature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gf3258PersistentSampleState {
    pub points: Vec<Gf3258EnrollmentFeaturePoint>,
    pub primary_registration_map: [u8; crate::registration::GF3258_REGISTRATION_PACKED_BYTES],
    pub secondary_registration_map:
        Option<[u8; crate::registration::GF3258_REGISTRATION_PACKED_BYTES]>,
    pub low_threshold_registration_map: [u8; crate::registration::GF3258_REGISTRATION_PACKED_BYTES],
    pub quarter_validity_packed: [u8; 40],
    pub active_validity_packed: [u8; crate::registration::GF3258_REGISTRATION_PACKED_BYTES],
    pub canonical_member: bool,
    pub relation_checkpoint: i32,
    pub sample_index: i32,
    pub scalar_108: i32,
    pub c2d40_param3: i32,
    pub c2d40_param4: i32,
    pub scalar_13c: i32,
    pub embedded_state_140: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gf3258PreviousRegistrationReject {
    FewerThanFiveDescriptorCorrespondences,
    FewerThanFiveGeometricInliers,
    FinalMetricGate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gf3258PreviousRegistrationAttempt {
    pub previous_index: usize,
    pub correspondence_count: usize,
    pub geometric_inliers: usize,
    pub transform_current_to_previous: Option<Gf3258AffineQ8>,
    pub map_scores: Option<Gf3258RegistrationMapScores>,
    pub accepted: bool,
    pub reject_reason: Option<Gf3258PreviousRegistrationReject>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gf3258EnrollmentAddKind {
    /// Vendor's first-sample path does not run pair registration/b9340.
    FirstSample,
    /// Current sample was retained, but no previous sample passed ba520's
    /// registration acceptance path, so b9340 is not invoked.
    NoSuccessfulPrevious,
    /// At least one previous sample passed and the graph layer was invoked.
    Integrated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gf3258EnrollmentAddResult {
    pub kind: Gf3258EnrollmentAddKind,
    pub current_index: usize,
    pub successful_previous: Vec<usize>,
    pub attempts: Vec<Gf3258PreviousRegistrationAttempt>,
    pub graph_integration: Option<Gf3258EnrollmentIntegrationResult>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gf3258EnrollmentAddError {
    CapacityReached { capacity: usize },
    Graph(Gf3258EnrollmentGraphError),
}

impl From<Gf3258EnrollmentGraphError> for Gf3258EnrollmentAddError {
    fn from(value: Gf3258EnrollmentGraphError) -> Self {
        Self::Graph(value)
    }
}

/// Enrollment template core with both the proven registration/graph state and
/// the full per-sample state required by the raw-template serializer.
///
/// `persistent_samples` is optional per entry only to preserve the legacy
/// registration-focused add API used by older tests/tools. Production feature
/// enrollment uses `add_persistent_sample`; the serializer rejects any legacy
/// incomplete entry rather than fabricating bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gf3258EnrollmentTemplateCore {
    /// Physical number of preallocated sample slots in the recovered newTemp layout.
    storage_capacity: usize,
    /// Runtime enrollment bound stored at vendor template+0x28 and serialized as tag 0x97.
    configured_max_samples: usize,
    pub graph: Gf3258EnrollmentGraph,
    point_sets: Vec<Vec<Gf3258RegistrationPoint>>,
    persistent_samples: Vec<Option<Gf3258PersistentSampleState>>,
}

impl Gf3258EnrollmentTemplateCore {
    /// Legacy constructor: storage and configured bounds are identical.
    #[cfg(test)]
    pub fn new(capacity: usize) -> Self {
        Self::new_with_configured_max_samples(capacity, capacity)
    }

    /// Exact split needed by the GF3258 vendor runtime: newTemp physically owns
    /// 50 sample slots, while the live enrollment template carries +0x28 == 40.
    pub fn new_with_configured_max_samples(
        storage_capacity: usize,
        configured_max_samples: usize,
    ) -> Self {
        assert!(configured_max_samples <= storage_capacity);
        Self {
            storage_capacity,
            configured_max_samples,
            graph: Gf3258EnrollmentGraph::new(storage_capacity),
            point_sets: Vec::with_capacity(storage_capacity),
            persistent_samples: Vec::with_capacity(storage_capacity),
        }
    }

    /// Physical/preallocated slot capacity (50 for the GF3258 newTemp profile).
    #[inline]
    #[cfg(test)]
    pub fn capacity(&self) -> usize {
        self.storage_capacity
    }

    /// Runtime enrollment bound at template+0x28, serialized as top-level tag 0x97.
    #[inline]
    pub fn configured_max_samples(&self) -> usize {
        self.configured_max_samples
    }

    #[inline]
    pub fn sample_count(&self) -> usize {
        self.point_sets.len()
    }

    #[inline]
    pub fn persistent_sample(&self, index: usize) -> Option<&Gf3258PersistentSampleState> {
        self.persistent_samples.get(index).and_then(Option::as_ref)
    }

    /// Number of currently populated/non-negative triangular relation records.
    /// This is graph state only; it is NOT vendor template+0x2c / tag 0x92.
    #[cfg(test)]
    pub fn relation_count(&self) -> usize {
        let mut count = 0usize;
        for high in 1..self.sample_count() {
            for low in 0..high {
                if self
                    .graph
                    .relations
                    .canonical_record(high, low)
                    .is_some_and(|record| record.relation_value >= 0)
                {
                    count += 1;
                }
            }
        }
        count
    }

    /// Vendor triangular relation-table cursor for `sample_count` retained samples.
    ///
    /// Live 12-touch fixture and the ba520 write path prove the sequence:
    /// 0,1,2,4,7,11,16,22,29,37,46,56,67.
    /// The +1 is the recovered extra/sentinel record after the first sample exists.
    #[inline]
    pub fn relation_table_cursor_for_sample_count(sample_count: usize) -> usize {
        if sample_count == 0 {
            0
        } else {
            1 + sample_count * (sample_count - 1) / 2
        }
    }

    /// Current vendor template+0x2c value / serialized tag 0x92.
    #[inline]
    pub fn relation_table_cursor(&self) -> usize {
        Self::relation_table_cursor_for_sample_count(self.sample_count())
    }

    fn sync_persistent_canonical_flags(&mut self) {
        for (index, entry) in self.persistent_samples.iter_mut().enumerate() {
            if let Some(sample) = entry.as_mut() {
                sample.canonical_member = self
                    .graph
                    .samples
                    .get(index)
                    .is_some_and(|graph_sample| graph_sample.canonical_member);
            }
        }
    }

    /// Legacy registration-only add API. It preserves existing tools/tests but
    /// deliberately records no persistence payload.
    pub fn add_sample(
        &mut self,
        points: Vec<Gf3258RegistrationPoint>,
        graph_sample: Gf3258EnrollmentSample,
        graph_score_threshold: i32,
    ) -> Result<Gf3258EnrollmentAddResult, Gf3258EnrollmentAddError> {
        self.add_sample_with_optional_persistence(
            points,
            graph_sample,
            None,
            graph_score_threshold,
            |samples, source, target, transform| {
                let source_sample = &samples[source];
                let target_sample = &samples[target];
                gf3258_registration_map_scores(
                    &source_sample.primary_registration_map,
                    &target_sample.primary_registration_map,
                    &source_sample.packed_validity,
                    &target_sample.packed_validity,
                    source_sample.secondary_registration_map.as_ref(),
                    target_sample.secondary_registration_map.as_ref(),
                    transform,
                )
            },
        )
    }

    /// Persistence-capable production add. The persistent sample is retained
    /// before pair registration just as b9180 copies the Feature before ba520
    /// appends the current sample's pair relations.
    pub fn add_persistent_sample(
        &mut self,
        points: Vec<Gf3258RegistrationPoint>,
        graph_sample: Gf3258EnrollmentSample,
        persistent_sample: Gf3258PersistentSampleState,
        graph_score_threshold: i32,
    ) -> Result<Gf3258EnrollmentAddResult, Gf3258EnrollmentAddError> {
        self.add_sample_with_optional_persistence(
            points,
            graph_sample,
            Some(persistent_sample),
            graph_score_threshold,
            |samples, source, target, transform| {
                let source_sample = &samples[source];
                let target_sample = &samples[target];
                gf3258_registration_map_scores(
                    &source_sample.primary_registration_map,
                    &target_sample.primary_registration_map,
                    &source_sample.packed_validity,
                    &target_sample.packed_validity,
                    source_sample.secondary_registration_map.as_ref(),
                    target_sample.secondary_registration_map.as_ref(),
                    transform,
                )
            },
        )
    }

    /// Private scoring seam retained only so integer threshold/state-machine
    /// tests can inject exact synthetic a9a50 outputs.  Production callers use
    /// `add_sample` above.
    #[cfg(test)]
    fn add_sample_with_scorer<F>(
        &mut self,
        points: Vec<Gf3258RegistrationPoint>,
        graph_sample: Gf3258EnrollmentSample,
        graph_score_threshold: i32,
        score_pair: F,
    ) -> Result<Gf3258EnrollmentAddResult, Gf3258EnrollmentAddError>
    where
        F: FnMut(
            &[Gf3258EnrollmentSample],
            usize,
            usize,
            Gf3258AffineQ8,
        ) -> Gf3258RegistrationMapScores,
    {
        self.add_sample_with_optional_persistence(
            points,
            graph_sample,
            None,
            graph_score_threshold,
            score_pair,
        )
    }

    fn add_sample_with_optional_persistence<F>(
        &mut self,
        points: Vec<Gf3258RegistrationPoint>,
        graph_sample: Gf3258EnrollmentSample,
        mut persistent_sample: Option<Gf3258PersistentSampleState>,
        graph_score_threshold: i32,
        mut score_pair: F,
    ) -> Result<Gf3258EnrollmentAddResult, Gf3258EnrollmentAddError>
    where
        F: FnMut(
            &[Gf3258EnrollmentSample],
            usize,
            usize,
            Gf3258AffineQ8,
        ) -> Gf3258RegistrationMapScores,
    {
        if self.sample_count() >= self.configured_max_samples {
            return Err(Gf3258EnrollmentAddError::CapacityReached {
                capacity: self.configured_max_samples,
            });
        }

        let current = self.point_sets.len();
        let relation_checkpoint = self.relation_table_cursor() as i32;
        if let Some(sample) = persistent_sample.as_mut() {
            sample.relation_checkpoint = relation_checkpoint;
            sample.sample_index = current as i32;
            sample.canonical_member = false;
        }

        self.point_sets.push(points);
        self.persistent_samples.push(persistent_sample);
        let graph_index = self.graph.push_sample(graph_sample);
        debug_assert_eq!(graph_index, current);

        if current == 0 {
            self.sync_persistent_canonical_flags();
            return Ok(Gf3258EnrollmentAddResult {
                kind: Gf3258EnrollmentAddKind::FirstSample,
                current_index: current,
                successful_previous: Vec::new(),
                attempts: Vec::new(),
                graph_integration: None,
            });
        }

        let mut successful_previous = Vec::new();
        let mut attempts = Vec::with_capacity(current);

        for previous in 0..current {
            let registration =
                gf3258_register_point_sets(&self.point_sets[previous], &self.point_sets[current]);

            let Some(registration) = registration else {
                attempts.push(Gf3258PreviousRegistrationAttempt {
                    previous_index: previous,
                    correspondence_count: 0,
                    geometric_inliers: 0,
                    transform_current_to_previous: None,
                    map_scores: None,
                    accepted: false,
                    reject_reason: Some(
                        Gf3258PreviousRegistrationReject::FewerThanFiveDescriptorCorrespondences,
                    ),
                });
                continue;
            };

            let correspondence_count = registration.correspondences.len();
            let geometric_inliers = registration.geometry.inlier_count;
            let current_to_previous = registration.geometry.transform;

            // ba520 enters a9a50 only after geometric inlier count > 4.
            if geometric_inliers <= 4 {
                attempts.push(Gf3258PreviousRegistrationAttempt {
                    previous_index: previous,
                    correspondence_count,
                    geometric_inliers,
                    transform_current_to_previous: Some(current_to_previous),
                    map_scores: None,
                    accepted: false,
                    reject_reason: Some(
                        Gf3258PreviousRegistrationReject::FewerThanFiveGeometricInliers,
                    ),
                });
                continue;
            }

            let scores = score_pair(&self.graph.samples, current, previous, current_to_previous);
            let decision =
                gf3258_registration_accepts(geometric_inliers, scores.metric_a, scores.metric_b);
            let accepted = decision == Gf3258RegistrationDecision::Accept;

            attempts.push(Gf3258PreviousRegistrationAttempt {
                previous_index: previous,
                correspondence_count,
                geometric_inliers,
                transform_current_to_previous: Some(current_to_previous),
                map_scores: Some(scores),
                accepted,
                reject_reason: (!accepted)
                    .then_some(Gf3258PreviousRegistrationReject::FinalMetricGate),
            });

            if !accepted {
                continue;
            }

            // Incremental ba520 pair records carry the direct geometric support
            // value; b9340 treats >5 as a strong direct relation.
            self.graph.set_relation_source_to_target(
                current,
                previous,
                geometric_inliers as i32,
                current_to_previous,
            );
            successful_previous.push(previous);
        }

        if successful_previous.is_empty() {
            self.sync_persistent_canonical_flags();
            return Ok(Gf3258EnrollmentAddResult {
                kind: Gf3258EnrollmentAddKind::NoSuccessfulPrevious,
                current_index: current,
                successful_previous,
                attempts,
                graph_integration: None,
            });
        }

        // b9340 uses FUN_001a9a50's return score, not ba520 metric A.
        // Clone only the small persistent map records so the scoring closure is
        // independent of the mutable graph borrow during integration.
        let score_samples = self.graph.samples.clone();
        let graph_integration = gf3258_integrate_enrollment_graph(
            &mut self.graph,
            current,
            &successful_previous,
            graph_score_threshold,
            |source, target, transform| score_pair(&score_samples, source, target, transform).score,
        )?;
        self.sync_persistent_canonical_flags();

        Ok(Gf3258EnrollmentAddResult {
            kind: Gf3258EnrollmentAddKind::Integrated,
            current_index: current,
            successful_previous,
            attempts,
            graph_integration: Some(graph_integration),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registration::GF3258_REGISTRATION_PACKED_BYTES;

    fn descriptor_for(id: usize) -> [u8; 24] {
        let mut d = [0u8; 24];
        // Distinct exact descriptors give best=0.  Repeating a sparse pattern
        // makes every nonmatching descriptor nonzero in Hamming distance.
        d[id % 24] = 1u8 << (id % 8);
        d[(id * 7 + 3) % 24] ^= 0x80;
        d
    }

    fn base_points(count: usize) -> Vec<Gf3258RegistrationPoint> {
        const XY: &[(u16, u16)] = &[
            (10, 10),
            (20, 10),
            (30, 10),
            (10, 20),
            (20, 20),
            (30, 20),
            (40, 10),
            (40, 20),
            (10, 30),
            (20, 30),
            (30, 30),
            (40, 30),
        ];
        assert!(count <= XY.len());
        XY[..count]
            .iter()
            .enumerate()
            .map(|(id, &(x, y))| Gf3258RegistrationPoint {
                x_q8: x << 8,
                y_q8: y << 8,
                descriptor_192: descriptor_for(id),
            })
            .collect()
    }

    fn translated_points(
        points: &[Gf3258RegistrationPoint],
        dx_pixels: i32,
        dy_pixels: i32,
    ) -> Vec<Gf3258RegistrationPoint> {
        points
            .iter()
            .map(|point| Gf3258RegistrationPoint {
                x_q8: (i32::from(point.x_q8) + dx_pixels * 256) as u16,
                y_q8: (i32::from(point.y_q8) + dy_pixels * 256) as u16,
                descriptor_192: point.descriptor_192,
            })
            .collect()
    }

    fn sample() -> Gf3258EnrollmentSample {
        Gf3258EnrollmentSample {
            canonical_member: false,
            status: 0,
            primary_registration_map: [0u8; GF3258_REGISTRATION_PACKED_BYTES],
            secondary_registration_map: None,
            packed_validity: [0xff; GF3258_REGISTRATION_PACKED_BYTES],
        }
    }

    fn synthetic_scores(score: i32, metric_a: i32, metric_b: i32) -> Gf3258RegistrationMapScores {
        use crate::registration::{Gf3258BinaryJointCounts, Gf3258RegistrationMapPass};
        let primary = Gf3258RegistrationMapPass {
            counts: Gf3258BinaryJointCounts::default(),
            participating_count: 0,
            score,
            metric_a,
            metric_b,
        };
        Gf3258RegistrationMapScores {
            score,
            metric_a,
            metric_b,
            primary,
            secondary: None,
        }
    }

    #[test]
    fn first_sample_skips_registration_and_graph_integration() {
        let mut template = Gf3258EnrollmentTemplateCore::new(50);
        let result = template
            .add_sample_with_scorer(base_points(6), sample(), 208, |_, _, _, _| {
                panic!("first sample must not call map scoring")
            })
            .unwrap();
        assert_eq!(result.kind, Gf3258EnrollmentAddKind::FirstSample);
        assert_eq!(template.sample_count(), 1);
        assert!(result.attempts.is_empty());
        assert!(result.graph_integration.is_none());
    }

    #[test]
    fn six_inliers_require_metric_a_216() {
        let previous = base_points(6);

        let mut reject_template = Gf3258EnrollmentTemplateCore::new(50);
        reject_template
            .add_sample_with_scorer(previous.clone(), sample(), 208, |_, _, _, _| unreachable!())
            .unwrap();
        let reject = reject_template
            .add_sample_with_scorer(previous.clone(), sample(), 208, |_, _, _, _| {
                synthetic_scores(255, 215, 255)
            })
            .unwrap();
        assert_eq!(reject.kind, Gf3258EnrollmentAddKind::NoSuccessfulPrevious);
        assert_eq!(reject.attempts[0].geometric_inliers, 6);
        assert_eq!(
            reject.attempts[0].reject_reason,
            Some(Gf3258PreviousRegistrationReject::FinalMetricGate)
        );

        let mut accept_template = Gf3258EnrollmentTemplateCore::new(50);
        accept_template
            .add_sample_with_scorer(previous.clone(), sample(), 208, |_, _, _, _| unreachable!())
            .unwrap();
        let accept = accept_template
            .add_sample_with_scorer(previous, sample(), 208, |_, _, _, _| {
                synthetic_scores(255, 216, 0)
            })
            .unwrap();
        assert_eq!(accept.kind, Gf3258EnrollmentAddKind::Integrated);
        assert_eq!(accept.successful_previous, vec![0]);
        let (value, transform) = accept_template
            .graph
            .relation_source_to_target(1, 0)
            .unwrap();
        assert_eq!(value, 6);
        assert_eq!(transform, Gf3258AffineQ8::IDENTITY);
    }

    #[test]
    fn seven_to_ten_inliers_accept_weak_a_only_with_b_65() {
        let previous = base_points(7);

        let mut template = Gf3258EnrollmentTemplateCore::new(50);
        template
            .add_sample_with_scorer(previous.clone(), sample(), 208, |_, _, _, _| unreachable!())
            .unwrap();
        let result = template
            .add_sample_with_scorer(previous, sample(), 208, |_, _, _, _| {
                synthetic_scores(255, 209, 65)
            })
            .unwrap();
        assert_eq!(result.kind, Gf3258EnrollmentAddKind::Integrated);
        assert_eq!(result.attempts[0].geometric_inliers, 7);
        assert!(result.attempts[0].accepted);
    }

    #[test]
    fn eleven_inliers_accept_independent_of_map_metrics() {
        let previous = base_points(11);
        let mut template = Gf3258EnrollmentTemplateCore::new(50);
        template
            .add_sample_with_scorer(previous.clone(), sample(), 208, |_, _, _, _| unreachable!())
            .unwrap();
        let result = template
            .add_sample_with_scorer(previous, sample(), 208, |_, _, _, _| {
                synthetic_scores(255, -100, 0)
            })
            .unwrap();
        assert_eq!(result.kind, Gf3258EnrollmentAddKind::Integrated);
        assert_eq!(result.attempts[0].geometric_inliers, 11);
        assert!(result.attempts[0].accepted);
    }

    #[test]
    fn accepted_relation_stores_current_to_previous_direction() {
        let previous = base_points(7);
        let current = translated_points(&previous, 2, 1);
        let mut template = Gf3258EnrollmentTemplateCore::new(50);
        template
            .add_sample_with_scorer(previous, sample(), 208, |_, _, _, _| unreachable!())
            .unwrap();
        let result = template
            .add_sample_with_scorer(current, sample(), 208, |_, _, _, _| {
                synthetic_scores(255, 216, 255)
            })
            .unwrap();
        assert_eq!(result.kind, Gf3258EnrollmentAddKind::Integrated);
        let (_, transform) = template.graph.relation_source_to_target(1, 0).unwrap();
        assert_eq!(transform.a, 0x100);
        assert_eq!(transform.b, 0);
        assert_eq!(transform.c, 0);
        assert_eq!(transform.d, 0x100);
        assert_eq!(transform.tx, -0x200);
        assert_eq!(transform.ty, -0x100);
    }

    #[test]
    fn graph_uses_a9a50_return_score_not_ba520_metric_a() {
        let previous = base_points(6);
        let mut template = Gf3258EnrollmentTemplateCore::new(50);
        template
            .add_sample_with_scorer(previous.clone(), sample(), 208, |_, _, _, _| unreachable!())
            .unwrap();
        let result = template
            .add_sample_with_scorer(previous, sample(), 208, |_, _, _, _| {
                // ba520 accepts A=216, but b9340's strict >208 test must see
                // the distinct a9a50 return score of 208 and stay unanchored.
                synthetic_scores(208, 216, 255)
            })
            .unwrap();
        assert_eq!(result.kind, Gf3258EnrollmentAddKind::Integrated);
        assert_eq!(result.successful_previous, vec![0]);
        assert_eq!(result.graph_integration.unwrap().canonical_anchor, None);
    }

    #[test]
    fn production_add_sample_uses_real_map_scorer() {
        let previous = base_points(6);
        let mut template = Gf3258EnrollmentTemplateCore::new(50);
        template
            .add_sample(previous.clone(), sample(), 208)
            .unwrap();
        let result = template.add_sample(previous, sample(), 208).unwrap();

        // Two identical zero primary maps with full validity produce the
        // recovered border-4 identity counts C00=825, A=246, B=165.  ba520
        // therefore accepts the six-inlier relation.  The distinct graph score
        // is 128, so no canonical component is established yet.
        assert_eq!(result.kind, Gf3258EnrollmentAddKind::Integrated);
        let scores = result.attempts[0].map_scores.unwrap();
        assert_eq!(scores.primary.counts.c00, 825);
        assert_eq!(scores.metric_a, 246);
        assert_eq!(scores.metric_b, 165);
        assert_eq!(scores.score, 128);
        assert_eq!(result.graph_integration.unwrap().canonical_anchor, None);
    }

    #[test]
    fn capacity_limit_is_enforced_before_mutation() {
        let mut template = Gf3258EnrollmentTemplateCore::new(1);
        template
            .add_sample_with_scorer(base_points(6), sample(), 208, |_, _, _, _| unreachable!())
            .unwrap();
        let error = template
            .add_sample_with_scorer(base_points(6), sample(), 208, |_, _, _, _| unreachable!())
            .unwrap_err();
        assert_eq!(
            error,
            Gf3258EnrollmentAddError::CapacityReached { capacity: 1 }
        );
        assert_eq!(template.sample_count(), 1);
        assert_eq!(template.graph.samples.len(), 1);
    }

    #[test]
    fn vendor_relation_table_cursor_sequence_is_exact() {
        let expected = [0usize, 1, 2, 4, 7, 11, 16, 22, 29, 37, 46, 56, 67];
        for (sample_count, &cursor) in expected.iter().enumerate() {
            assert_eq!(
                Gf3258EnrollmentTemplateCore::relation_table_cursor_for_sample_count(sample_count),
                cursor
            );
        }
    }

    #[test]
    fn storage_capacity_and_configured_bound_are_distinct() {
        let template = Gf3258EnrollmentTemplateCore::new_with_configured_max_samples(50, 40);
        assert_eq!(template.capacity(), 50);
        assert_eq!(template.configured_max_samples(), 40);
        assert_eq!(template.relation_table_cursor(), 0);
    }

    #[test]
    fn logical_relation_count_includes_nonnegative_graph_records() {
        let previous = base_points(6);
        let mut template = Gf3258EnrollmentTemplateCore::new(50);
        template
            .add_sample_with_scorer(previous.clone(), sample(), 208, |_, _, _, _| unreachable!())
            .unwrap();
        assert_eq!(template.relation_count(), 0);
        template
            .add_sample_with_scorer(previous, sample(), 208, |_, _, _, _| {
                synthetic_scores(255, 216, 0)
            })
            .unwrap();
        assert!(template.relation_count() >= 1);
    }
}
