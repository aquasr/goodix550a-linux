//! GF3258 WN2 incremental enrollment graph integration.
//!
//! This module sits above `registration.rs`.  It implements the enrollment
//! graph state that FUN_001b9340 maintains for the GF3258 path: canonical
//! anchor establishment, current-sample attachment, promotion of successful
//! non-canonical samples, graph closure through already-known pair relations,
//! and the final d0b0-style novelty metric.
//!
//! The score callback is the recovered FUN_001a9a50 registration-map score.
//! Keeping it injected here makes the graph state machine independently
//! testable and avoids coupling graph bookkeeping to image/map ownership.

use crate::registration::{
    GF3258_REGISTRATION_PACKED_BYTES, GF3258_REGISTRATION_SCORE_WEAK, Gf3258AffineQ8,
    Gf3258PairRelation, Gf3258PairRelationTable, gf3258_novel_coverage_metric,
};

/// Relevant persistent per-sample state from the vendor Feature object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gf3258EnrollmentSample {
    /// Feature +0x100.
    pub canonical_member: bool,
    /// Feature +0x114. Value 5 is excluded by b9340/d0b0 diagnostics/coverage.
    pub status: i32,
    /// Feature +0x08, GF3258 40x32 primary registration classification map,
    /// packed row-major LSB-first.
    pub primary_registration_map: [u8; GF3258_REGISTRATION_PACKED_BYTES],
    /// Feature +0x10 optional secondary registration map in the same packed
    /// representation.  a9a50 may use this only to improve its return score;
    /// GF3258 ba520 A/B remain the primary-map outputs.
    pub secondary_registration_map: Option<[u8; GF3258_REGISTRATION_PACKED_BYTES]>,
    /// Feature +0x130, GF3258 active-resolution packed validity mask.  This is
    /// exactly a8660(+0x28, 1) followed by a7f90, so unpacking it recreates the
    /// byte validity map consumed by a9a50/a9580.
    pub packed_validity: [u8; GF3258_REGISTRATION_PACKED_BYTES],
}

impl Default for Gf3258EnrollmentSample {
    fn default() -> Self {
        Self {
            canonical_member: false,
            status: 0,
            primary_registration_map: [0u8; GF3258_REGISTRATION_PACKED_BYTES],
            secondary_registration_map: None,
            packed_validity: [0u8; GF3258_REGISTRATION_PACKED_BYTES],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gf3258EnrollmentGraph {
    pub samples: Vec<Gf3258EnrollmentSample>,
    pub relations: Gf3258PairRelationTable,
    /// template +0x87e0 when `canonical_established` is true.
    pub canonical_anchor: usize,
    /// template +0x87ec.
    pub canonical_established: bool,
}

impl Gf3258EnrollmentGraph {
    pub fn new(sample_capacity: usize) -> Self {
        Self {
            samples: Vec::with_capacity(sample_capacity),
            relations: Gf3258PairRelationTable::new(sample_capacity),
            canonical_anchor: 0,
            canonical_established: false,
        }
    }

    pub fn push_sample(&mut self, sample: Gf3258EnrollmentSample) -> usize {
        let index = self.samples.len();
        self.samples.push(sample);
        index
    }

    /// Store a transform with normalized source->target semantics while honoring
    /// the vendor triangular storage direction (higher index -> lower index).
    pub fn set_relation_source_to_target(
        &mut self,
        source: usize,
        target: usize,
        relation_value: i32,
        source_to_target: Gf3258AffineQ8,
    ) -> bool {
        if source == target {
            return false;
        }
        let canonical = if source > target {
            source_to_target
        } else {
            source_to_target.inverse()
        };
        self.relations.set_canonical_record(
            source,
            target,
            Gf3258PairRelation {
                relation_value,
                transform_higher_to_lower: canonical,
            },
        )
    }

    /// Return source->target if the pair record exists.  Relation value -1 is
    /// deliberately returned: callers decide whether an absent edge is usable.
    pub fn relation_source_to_target(
        &self,
        source: usize,
        target: usize,
    ) -> Option<(i32, Gf3258AffineQ8)> {
        self.relations.relation_source_to_target(target, source)
    }

    fn sample_to_anchor(&self, sample: usize) -> Option<Gf3258AffineQ8> {
        if !self.canonical_established || sample >= self.samples.len() {
            return None;
        }
        if sample == self.canonical_anchor {
            return Some(Gf3258AffineQ8::IDENTITY);
        }
        if !self.samples[sample].canonical_member {
            return None;
        }
        let (value, transform) = self.relation_source_to_target(sample, self.canonical_anchor)?;
        (value >= 0).then_some(transform)
    }

    fn store_current_to_anchor(&mut self, sample: usize, sample_to_anchor: Gf3258AffineQ8) {
        debug_assert!(self.canonical_established);
        let anchor = self.canonical_anchor;
        self.samples[sample].canonical_member = true;
        if sample != anchor {
            // b9340 preserves an already-existing current<->anchor direct relation
            // value, but initializes an absent canonical link to 0.
            let existing = self
                .relations
                .canonical_record(sample, anchor)
                .map(|r| r.relation_value)
                .unwrap_or(-1);
            let value = if existing < 0 { 0 } else { existing };
            self.set_relation_source_to_target(sample, anchor, value, sample_to_anchor);
        }
    }

    fn store_promoted_to_anchor(&mut self, sample: usize, sample_to_anchor: Gf3258AffineQ8) {
        debug_assert!(self.canonical_established);
        let anchor = self.canonical_anchor;
        self.samples[sample].canonical_member = true;
        if sample != anchor {
            // Promotion paths in b9340 explicitly write relation_value = 0 even
            // if this triangular slot previously held a nonnegative relation.
            self.set_relation_source_to_target(sample, anchor, 0, sample_to_anchor);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gf3258EnrollmentGraphError {
    CurrentIsNotNewest { current: usize, sample_count: usize },
    PreviousIndexOutOfRange { index: usize, current: usize },
    MissingDirectRelation { current: usize, previous: usize },
    MissingCanonicalTransform { sample: usize, anchor: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gf3258EnrollmentIntegrationResult {
    pub current_index: usize,
    pub canonical_anchor: Option<usize>,
    pub current_is_canonical: bool,
    /// Samples newly promoted to Feature+0x100 == 1 by this call, excluding the
    /// current sample itself.
    pub promoted_samples: Vec<usize>,
    /// d0b0 result after GF3258's half-resolution x4 conversion.
    pub novel_coverage: i32,
}

/// Integrate the already-stored newest sample into the recovered b9340
/// canonical graph.
///
/// `successful_previous` is ba520's list of previous sample indices that passed
/// descriptor correspondence, geometric verification and final A/B acceptance.
/// Direct current->previous PairRelation records must already have been stored.
///
/// `score(source, target, source_to_target)` supplies FUN_001a9a50's *return*
/// score (not a9580 metric A).  b9340 uses a strict `> score_threshold` gate for
/// anchor establishment / transitive graph promotion, and a hard `>= 209` gate
/// when promoting a successful non-canonical sample directly through current.
pub fn gf3258_integrate_enrollment_graph<F>(
    graph: &mut Gf3258EnrollmentGraph,
    current: usize,
    successful_previous: &[usize],
    score_threshold: i32,
    mut score: F,
) -> Result<Gf3258EnrollmentIntegrationResult, Gf3258EnrollmentGraphError>
where
    F: FnMut(usize, usize, Gf3258AffineQ8) -> i32,
{
    let sample_count = graph.samples.len();
    if current + 1 != sample_count {
        return Err(Gf3258EnrollmentGraphError::CurrentIsNotNewest {
            current,
            sample_count,
        });
    }
    for &previous in successful_previous {
        if previous >= current {
            return Err(Gf3258EnrollmentGraphError::PreviousIndexOutOfRange {
                index: previous,
                current,
            });
        }
        if graph.relation_source_to_target(current, previous).is_none() {
            return Err(Gf3258EnrollmentGraphError::MissingDirectRelation { current, previous });
        }
    }

    // ---------------------------------------------------------------------
    // 1. If a canonical component already exists, attach current through the
    //    strongest successful previous sample that is already canonical.
    // ---------------------------------------------------------------------
    if graph.canonical_established {
        let strongest_canonical = successful_previous
            .iter()
            .copied()
            .filter(|&index| graph.samples[index].canonical_member)
            .filter_map(|index| {
                graph.relation_source_to_target(current, index).map(
                    |(relation_value, current_to_index)| (index, relation_value, current_to_index),
                )
            })
            .max_by_key(|&(_, relation_value, _)| relation_value);

        if let Some((through, _, current_to_through)) = strongest_canonical {
            let through_to_anchor = graph.sample_to_anchor(through).ok_or(
                Gf3258EnrollmentGraphError::MissingCanonicalTransform {
                    sample: through,
                    anchor: graph.canonical_anchor,
                },
            )?;
            let current_to_anchor = through_to_anchor.compose_and_normalize(current_to_through);
            graph.store_current_to_anchor(current, current_to_anchor);
        }
    }

    // ---------------------------------------------------------------------
    // 2. No component yet: choose the strongest successful direct relation.
    //    Vendor requires relation_value > 5 and a9a50 score > threshold.
    // ---------------------------------------------------------------------
    if !graph.canonical_established && !successful_previous.is_empty() {
        let strongest = successful_previous
            .iter()
            .copied()
            .filter_map(|previous| {
                graph
                    .relation_source_to_target(current, previous)
                    .map(|(relation_value, transform)| (previous, relation_value, transform))
            })
            .max_by_key(|&(_, relation_value, _)| relation_value);

        if let Some((anchor, relation_value, current_to_anchor)) = strongest {
            if relation_value > 5 && score(current, anchor, current_to_anchor) > score_threshold {
                graph.canonical_anchor = anchor;
                graph.canonical_established = true;
                graph.samples[anchor].canonical_member = true;
                graph.samples[current].canonical_member = true;
                // This is still the original direct relation, so preserve its
                // direct geometric relation value rather than replacing it by 0.
                graph.set_relation_source_to_target(
                    current,
                    anchor,
                    relation_value,
                    current_to_anchor,
                );
            }
        }
    }

    let mut promoted_samples = Vec::new();

    // ---------------------------------------------------------------------
    // 3. Once current is canonical, every successful previous sample that is
    //    still outside the component is eligible for direct promotion.
    //    b9340's hard gate here is score >= 209.
    // ---------------------------------------------------------------------
    if graph.canonical_established && graph.samples[current].canonical_member {
        let current_to_anchor = graph.sample_to_anchor(current).ok_or(
            Gf3258EnrollmentGraphError::MissingCanonicalTransform {
                sample: current,
                anchor: graph.canonical_anchor,
            },
        )?;

        let mut closure_seeds = Vec::new();
        for &previous in successful_previous {
            if graph.samples[previous].canonical_member {
                continue;
            }
            let Some((relation_value, current_to_previous)) =
                graph.relation_source_to_target(current, previous)
            else {
                continue;
            };
            if relation_value < 0 {
                continue;
            }
            if score(current, previous, current_to_previous) < GF3258_REGISTRATION_SCORE_WEAK {
                continue;
            }

            // previous->anchor = current->anchor o previous->current.
            let previous_to_current = current_to_previous.inverse();
            let previous_to_anchor = current_to_anchor.compose_and_normalize(previous_to_current);
            graph.store_promoted_to_anchor(previous, previous_to_anchor);
            promoted_samples.push(previous);
            closure_seeds.push(previous);
        }

        // -----------------------------------------------------------------
        // 4. Incremental graph closure.  The vendor walks older/later indices
        //    around each newly promoted sample.  Semantically it promotes an
        //    unintegrated node when a stored edge exists and a9a50 on that edge
        //    is strictly above the configured threshold, composing the path to
        //    the anchor.  We retain deterministic ascending-index traversal.
        // -----------------------------------------------------------------
        let mut queue_index = 0usize;
        while queue_index < closure_seeds.len() {
            let through = closure_seeds[queue_index];
            queue_index += 1;
            let through_to_anchor = graph.sample_to_anchor(through).ok_or(
                Gf3258EnrollmentGraphError::MissingCanonicalTransform {
                    sample: through,
                    anchor: graph.canonical_anchor,
                },
            )?;

            for candidate in 0..current {
                if candidate == through || graph.samples[candidate].canonical_member {
                    continue;
                }
                let Some((relation_value, candidate_to_through)) =
                    graph.relation_source_to_target(candidate, through)
                else {
                    continue;
                };
                if relation_value < 0 {
                    continue;
                }
                if score(candidate, through, candidate_to_through) <= score_threshold {
                    continue;
                }

                let candidate_to_anchor =
                    through_to_anchor.compose_and_normalize(candidate_to_through);
                graph.store_promoted_to_anchor(candidate, candidate_to_anchor);
                promoted_samples.push(candidate);
                closure_seeds.push(candidate);
            }
        }
    }

    // ---------------------------------------------------------------------
    // 5. d0b0 novelty: only if a canonical component exists and current is in
    //    it.  Derive current->other through the canonical anchor exactly as the
    //    recovered function does, then let registration.rs apply active-half
    //    translation scaling, frame subtraction, popcount, minimum-20 and x4.
    // ---------------------------------------------------------------------
    let novel_coverage = if graph.canonical_established && graph.samples[current].canonical_member {
        let current_to_anchor = graph.sample_to_anchor(current).ok_or(
            Gf3258EnrollmentGraphError::MissingCanonicalTransform {
                sample: current,
                anchor: graph.canonical_anchor,
            },
        )?;
        let mut current_to_other = Vec::new();
        for other in 0..current {
            if !graph.samples[other].canonical_member || graph.samples[other].status == 5 {
                continue;
            }
            let transform = if other == graph.canonical_anchor {
                current_to_anchor
            } else {
                let other_to_anchor = graph.sample_to_anchor(other).ok_or(
                    Gf3258EnrollmentGraphError::MissingCanonicalTransform {
                        sample: other,
                        anchor: graph.canonical_anchor,
                    },
                )?;
                let anchor_to_other = other_to_anchor.inverse();
                anchor_to_other.compose_and_normalize(current_to_anchor)
            };
            current_to_other.push(transform);
        }
        gf3258_novel_coverage_metric(&graph.samples[current].packed_validity, &current_to_other)
    } else {
        0
    };

    Ok(Gf3258EnrollmentIntegrationResult {
        current_index: current,
        canonical_anchor: graph
            .canonical_established
            .then_some(graph.canonical_anchor),
        current_is_canonical: graph.samples[current].canonical_member,
        promoted_samples,
        novel_coverage,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_validity() -> [u8; GF3258_REGISTRATION_PACKED_BYTES] {
        [0xff; GF3258_REGISTRATION_PACKED_BYTES]
    }

    fn sample() -> Gf3258EnrollmentSample {
        Gf3258EnrollmentSample {
            canonical_member: false,
            status: 0,
            primary_registration_map: [0u8; GF3258_REGISTRATION_PACKED_BYTES],
            secondary_registration_map: None,
            packed_validity: full_validity(),
        }
    }

    fn identity_relation(value: i32) -> Gf3258PairRelation {
        Gf3258PairRelation {
            relation_value: value,
            transform_higher_to_lower: Gf3258AffineQ8::IDENTITY,
        }
    }

    #[test]
    fn first_component_requires_relation_gt_5_and_strict_score_threshold() {
        let mut graph = Gf3258EnrollmentGraph::new(8);
        graph.push_sample(sample());
        graph.push_sample(sample());
        graph
            .relations
            .set_canonical_record(1, 0, identity_relation(6));

        let result =
            gf3258_integrate_enrollment_graph(&mut graph, 1, &[0], 208, |_, _, _| 209).unwrap();
        assert_eq!(result.canonical_anchor, Some(0));
        assert!(graph.samples[0].canonical_member);
        assert!(graph.samples[1].canonical_member);

        let mut equal_score = Gf3258EnrollmentGraph::new(8);
        equal_score.push_sample(sample());
        equal_score.push_sample(sample());
        equal_score
            .relations
            .set_canonical_record(1, 0, identity_relation(6));
        let result =
            gf3258_integrate_enrollment_graph(&mut equal_score, 1, &[0], 209, |_, _, _| 209)
                .unwrap();
        assert_eq!(result.canonical_anchor, None);

        let mut relation_five = Gf3258EnrollmentGraph::new(8);
        relation_five.push_sample(sample());
        relation_five.push_sample(sample());
        relation_five
            .relations
            .set_canonical_record(1, 0, identity_relation(5));
        let result =
            gf3258_integrate_enrollment_graph(&mut relation_five, 1, &[0], 208, |_, _, _| 255)
                .unwrap();
        assert_eq!(result.canonical_anchor, None);
    }

    #[test]
    fn current_attaches_through_strongest_successful_canonical_sample() {
        let mut graph = Gf3258EnrollmentGraph::new(8);
        graph.push_sample(sample());
        graph.push_sample(sample());
        graph.push_sample(sample());
        graph.canonical_anchor = 0;
        graph.canonical_established = true;
        graph.samples[0].canonical_member = true;
        graph.samples[1].canonical_member = true;
        graph
            .relations
            .set_canonical_record(1, 0, identity_relation(0));
        graph
            .relations
            .set_canonical_record(2, 0, identity_relation(7));
        graph
            .relations
            .set_canonical_record(2, 1, identity_relation(9));

        let result =
            gf3258_integrate_enrollment_graph(&mut graph, 2, &[0, 1], 208, |_, _, _| 255).unwrap();

        assert!(result.current_is_canonical);
        assert!(graph.samples[2].canonical_member);
        let (value, transform) = graph.relation_source_to_target(2, 0).unwrap();
        assert!(value >= 0);
        assert_eq!(transform, Gf3258AffineQ8::IDENTITY);
        assert_eq!(result.novel_coverage, 0);
    }

    #[test]
    fn successful_noncanonical_sample_promotes_at_score_209() {
        let mut graph = Gf3258EnrollmentGraph::new(8);
        graph.push_sample(sample()); // anchor 0
        graph.push_sample(sample()); // noncanonical 1
        graph.push_sample(sample()); // current 2
        graph.canonical_anchor = 0;
        graph.canonical_established = true;
        graph.samples[0].canonical_member = true;
        graph
            .relations
            .set_canonical_record(2, 0, identity_relation(9));
        graph
            .relations
            .set_canonical_record(2, 1, identity_relation(8));

        let result =
            gf3258_integrate_enrollment_graph(&mut graph, 2, &[0, 1], 208, |source, target, _| {
                if source == 2 && target == 1 { 209 } else { 255 }
            })
            .unwrap();

        assert!(graph.samples[2].canonical_member);
        assert!(graph.samples[1].canonical_member);
        assert!(result.promoted_samples.contains(&1));
        assert_eq!(
            graph.relation_source_to_target(1, 0).unwrap().1,
            Gf3258AffineQ8::IDENTITY
        );
    }

    #[test]
    fn transitive_closure_promotes_connected_noncanonical_sample() {
        let mut graph = Gf3258EnrollmentGraph::new(8);
        graph.push_sample(sample()); // anchor 0
        graph.push_sample(sample()); // candidate 1
        graph.push_sample(sample()); // successful seed 2
        graph.push_sample(sample()); // current 3
        graph.canonical_anchor = 0;
        graph.canonical_established = true;
        graph.samples[0].canonical_member = true;
        graph
            .relations
            .set_canonical_record(3, 0, identity_relation(10));
        graph
            .relations
            .set_canonical_record(3, 2, identity_relation(9));
        graph
            .relations
            .set_canonical_record(2, 1, identity_relation(7));

        let result =
            gf3258_integrate_enrollment_graph(&mut graph, 3, &[0, 2], 208, |_, _, _| 255).unwrap();

        assert!(graph.samples[3].canonical_member);
        assert!(graph.samples[2].canonical_member);
        assert!(graph.samples[1].canonical_member);
        assert!(result.promoted_samples.contains(&2));
        assert!(result.promoted_samples.contains(&1));
    }

    #[test]
    fn status_five_sample_is_excluded_from_novel_coverage_subtraction() {
        let mut graph = Gf3258EnrollmentGraph::new(8);
        graph.push_sample(sample()); // anchor 0
        let mut skipped = sample();
        skipped.status = 5;
        skipped.canonical_member = true;
        graph.push_sample(skipped); // 1
        graph.push_sample(sample()); // current 2
        graph.canonical_anchor = 0;
        graph.canonical_established = true;
        graph.samples[0].canonical_member = true;
        graph
            .relations
            .set_canonical_record(1, 0, identity_relation(0));
        graph
            .relations
            .set_canonical_record(2, 0, identity_relation(8));

        let result =
            gf3258_integrate_enrollment_graph(&mut graph, 2, &[0], 208, |_, _, _| 255).unwrap();

        // Anchor 0 alone overlaps the entire current frame, so novelty remains 0;
        // this test primarily verifies that status==5 does not require/use its edge.
        assert_eq!(result.novel_coverage, 0);
    }
}
