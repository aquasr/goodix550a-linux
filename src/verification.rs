//! Fresh-process GF3258 verification bridge.
//!
//! Persisted descriptor/hash material feeds the recovered candidate matcher
//! (`b0e90 -> afda0 -> ae220`). DecodeFingerTemplate now also proves the exact
//! quantized enrolled x/y/orientation reconstruction, allowing the resulting
//! pair slots to continue through `704f0 -> aef60` matcher geometry. The
//! GF3258 primary path also reproduces the optional `b1410 -> 704f0` refinement.

use crate::feature::{
    GF3258_HEIGHT, GF3258_MATCH_MAX_CANDIDATE_PAIRS, GF3258_MATCH_SCORE_MATRIX_STRIDE,
    GF3258_MATCH_SCORE_SENTINEL, GF3258_TAU_Q12, GF3258_WIDTH, Gf3258CandidateGeneration,
    Gf3258CandidateMatchError, Gf3258CandidateMatcherConfig, Gf3258EnrolledCandidateFeatureSet,
    Gf3258EnrolledCandidatePoint, Gf3258MatcherFeatureSet, Gf3258MatcherPoint,
    Gf3258OwnedVerificationMatcherFeature, Gf3258RecoveryEnrolledPoint,
    gf3258_cordic_atan2_magnitude_q12, gf3258_generate_enrolled_match_candidates,
    gf3258_generate_recovery_pair_slots_from_score_matrix,
    gf3258_select_correspondences_from_top_two,
};
pub(crate) use crate::registration::{Gf3258MatcherGeometryError, Gf3258MatcherGeometryResult};

use crate::registration::{
    GF3258_MAX_INITIAL_CORRESPONDENCES, GF3258_QUARTER_VALIDITY_CELLS, GF3258_REGISTRATION_HEIGHT,
    GF3258_REGISTRATION_PACKED_BYTES, GF3258_REGISTRATION_PIXELS, GF3258_REGISTRATION_WIDTH,
    Gf3258AffineQ8, Gf3258BinaryJointCounts, gf3258_affine_for_registration_scoring,
    gf3258_expand_quarter_validity, gf3258_joint_binary_counts_for_roi,
    gf3258_matcher_geometry_from_pair_slots, gf3258_registration_map_scores,
    gf3258_scanline_overlap, gf3258_unpack_quarter_validity, gf3258_unpack_registration_bits,
    gf3258_warp_u8_to_canvas_roi,
};
use crate::template_decode::Gf3258PersistedSample;

#[path = "verification_flag_policy_program.rs"]
mod flag_policy_program;
#[path = "verification_late_policy_program.rs"]
mod late_policy_program;
#[path = "verification_post_survival_policy_program.rs"]
mod post_survival_policy_program;
#[path = "verification_pre_tail_policy_program.rs"]
mod pre_tail_policy_program;
#[path = "verification_rescue_geometry.rs"]
mod rescue_geometry;
pub(crate) use rescue_geometry::*;
#[path = "verification_live.rs"]
mod live;
pub use live::*;

/// GF3258 caps `FUN_001704f0` correspondence geometry at 31 pairs and uses the
/// same value as the per-sample normalization divisor in `FUN_001900b0`.
pub(crate) const GF3258_VERIFICATION_METRIC_DIVISOR: i32 = 0x1f;

/// Finalize the GF3258 geometry-derived work metric immediately after
/// `FUN_00172700 -> FUN_00170a80` and the top-level merge in `FUN_001900b0`.
///
/// Recovered field mapping for the 0x150-byte work record:
/// - `+0x04`: primary selected `FUN_001704f0` count from `FUN_00172700`;
/// - `+0x08`: admitted secondary/rescue `FUN_001704f0` count from
///   `FUN_00170a80`;
/// - `+0x28`: quality field gating the one-count bonus;
/// - `+0x134`: secondary bonus gate.
///
/// `FUN_00170a80` applies the same bonus/cap operation to both `+0x00` and
/// `+0x04`; this helper intentionally finalizes only the `+0x04` branch used by
/// the caller's verification metric. `FUN_001900b0` subsequently stores
/// `max(+0x04, +0x08)` back to `+0x04`.
#[inline]
pub(crate) fn gf3258_finalize_geometry_work_metric(
    primary_704f0_count: i32,
    rescue_704f0_count: i32,
    quality_28: i32,
    quality_134: i32,
) -> i32 {
    let mut primary = primary_704f0_count;

    if quality_28 > 0x1e {
        if quality_134 < 10 {
            primary = primary.wrapping_add(1);
        }
        if primary > GF3258_VERIFICATION_METRIC_DIVISOR {
            primary = GF3258_VERIFICATION_METRIC_DIVISOR;
        }
    }

    if primary >= rescue_704f0_count {
        primary
    } else {
        rescue_704f0_count
    }
}

/// Exact GF3258 per-sample contribution used by `FUN_001900b0`.
///
/// Vendor arithmetic:
/// `contribution_q8 = (metric * 0x100 + (31 >> 1)) / 31`.
/// The result is Q8 and is accumulated only for samples that survive the late
/// verification policy path.
#[inline]
pub(crate) fn gf3258_verification_metric_contribution_q8(metric: i32) -> i32 {
    metric
        .wrapping_mul(0x100)
        .wrapping_add(GF3258_VERIFICATION_METRIC_DIVISOR >> 1)
        / GF3258_VERIFICATION_METRIC_DIVISOR
}

/// Exact score accumulator corresponding to the `iStack_18180` /
/// `iStack_181d4` pair in `FUN_001900b0`.
///
/// This type intentionally does not decide whether a sample survives the late
/// policy. The caller adds the already-finalized geometry-derived metric only
/// after that decision has been made.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Gf3258VerificationScoreAccumulator {
    sum_q8: i32,
    accepted_samples: i32,
}

impl Gf3258VerificationScoreAccumulator {
    #[inline]
    pub const fn new() -> Self {
        Self {
            sum_q8: 0,
            accepted_samples: 0,
        }
    }

    /// Add one finalized vendor geometry work metric after the sample survives policy.
    #[cfg(test)]
    #[inline]
    pub fn push_accepted_metric(&mut self, metric: i32) {
        self.push_contribution_q8(gf3258_verification_metric_contribution_q8(metric));
    }

    #[inline]
    fn push_contribution_q8(&mut self, contribution_q8: i32) {
        self.sum_q8 = self.sum_q8.wrapping_add(contribution_q8);
        self.accepted_samples = self.accepted_samples.wrapping_add(1);
    }

    #[cfg(test)]
    #[inline]
    pub const fn sum_q8(self) -> i32 {
        self.sum_q8
    }

    #[inline]
    pub const fn accepted_samples(self) -> i32 {
        self.accepted_samples
    }

    /// Exact final percentage expression used by `FUN_001900b0`.
    ///
    /// Returns `None` for an empty accumulator because the vendor evaluates the
    /// division only on paths with at least one accepted sample.
    #[inline]
    pub fn percent(self) -> Option<i32> {
        if self.accepted_samples == 0 {
            return None;
        }
        Some((self.sum_q8.wrapping_mul(100) / self.accepted_samples) >> 8)
    }
}

/// Return whether a complete vendor-equivalent signed verification score is a match.
///
/// Static recovery of two downstream GF3258 identify/feature-recognition consumers
/// proves the decision boundary is strictly positive: `score > 0`. Zero and negative
/// values remain non-match/policy-reject outcomes at those consumers.
///
/// This helper is intentionally defined over the **complete signed vendor score**.
/// `Gf3258VerificationScoreAccumulator::percent()` alone is not such a score: the
/// recovered `FUN_001900b0` late policy can suppress a candidate or emit zero/negative
/// policy results. Do not pass the isolated normalized percentage here until that late
/// policy has been reproduced.
#[inline]
pub(crate) const fn gf3258_vendor_verification_score_is_match(score: i32) -> bool {
    score > 0
}

/// GF3258 specialization of the 0x150-byte score-policy record consumed by
/// `FUN_00169290`.
///
/// Field names retain their recovered work-record offsets where the upstream
/// semantic name is not yet proven. Known origins include:
/// - `+0x00`: selected `FUN_001704f0` geometry count;
/// - `+0x04`: finalized geometry metric normalized by 31;
/// - `+0x30/+0x34/+0x38`: late-policy penalty indicators;
/// - `+0x54/+0x5c`: live/enrolled feature scalars copied into the work record.
///
/// The remaining scalar origins are recovered well enough to reproduce the
/// vendor policy exactly, but are intentionally not given stronger biometric
/// names until their producer helpers are fully closed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Gf3258VerificationPolicyRecord {
    pub geometry_count_00: i32,
    pub metric_04: i32,
    pub field_10: i32,
    pub field_14: i32,
    pub field_20: i32,
    pub field_24: i32,
    pub field_2c: i32,
    pub penalty_30: i32,
    pub penalty_34: i32,
    pub penalty_38: i32,
    pub live_scalar_54: i32,
    pub enrolled_scalar_5c: i32,
}

/// Exact GF3258 (`type == 0x18`, config `+0x44 == 0`) specialization of
/// `FUN_00169290`.
///
/// The generic vendor helper contains many sensor-family branches. For GF3258,
/// the policy reduces to two global gates followed by three alternative
/// admission routes. All three successful routes return the same normalized
/// `+0x04 / 31` percentage; otherwise the helper returns zero.
///
/// This function uses wrapping arithmetic where the vendor uses 32-bit integer
/// instructions. It has been parity-checked directly against raw vendor
/// `0x69290` over threshold cases and randomized signed work records.
#[inline]
pub(crate) fn gf3258_verification_policy_score(record: Gf3258VerificationPolicyRecord) -> i32 {
    let penalty_terms = record
        .penalty_30
        .wrapping_add(record.penalty_34)
        .wrapping_add(record.penalty_38)
        .wrapping_add(if record.geometry_count_00 <= 4 { 1 } else { 0 });
    let penalty = penalty_terms.wrapping_mul(3);
    let combined_evidence = record
        .field_14
        .wrapping_sub(penalty)
        .wrapping_add(record.field_20.wrapping_sub(penalty));

    if record
        .live_scalar_54
        .wrapping_add(record.enrolled_scalar_5c)
        > 0xaa
        || record.field_2c <= 9
    {
        return 0;
    }

    let route_a = record.geometry_count_00 > 4
        && record.metric_04 > 7
        && combined_evidence > 0x1a8
        && record.field_2c > 0x29;

    let route_b = record.geometry_count_00 > 2
        && record.field_10 > 0xea
        && record.field_24 > 0x77
        && combined_evidence > 0x18f;

    let route_c = record.field_24 > 0x3e
        && record.geometry_count_00 > 5
        && combined_evidence > 0x19e
        && record.field_2c > 0x28;

    if !(route_a || route_b || route_c) {
        return 0;
    }

    gf3258_verification_metric_contribution_q8(record.metric_04).wrapping_mul(100) >> 8
}

/// Exact scalar work-record projection consumed by the GF3258 (`type == 0x18`)
/// body of `FUN_0016bb90`.
///
/// Static access auditing proves that raw `0x6bb90` reads only these thirteen
/// 32-bit fields from its 0x150-byte work record and never writes that record.
/// Offset-derived names are intentionally retained until each upstream producer
/// is assigned a stronger semantic name.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Gf3258LatePolicyRecord {
    pub geometry_count_00: i32,
    pub metric_04: i32,
    pub field_10: i32,
    pub field_14: i32,
    pub field_20: i32,
    pub field_24: i32,
    pub field_28: i32,
    pub field_2c: i32,
    pub field_34: i32,
    pub field_38: i32,
    pub live_scalar_54: i32,
    pub enrolled_scalar_5c: i32,
    pub field_64: i32,
}

/// Non-record scalar inputs passed by `FUN_001900b0` to the GF3258 late
/// sample-policy body through `FUN_0018e790`.
///
/// `history_low` and `history_high` are the low/high dwords of the packed
/// seventh ABI argument. `profile_state` is the following integer argument.
/// `current_reject_count` is the incoming value behind the mutable reject-count
/// pointer; raw `0x6bb90` reads it at several rule nodes before conditionally
/// incrementing it at the common epilogue.
///
/// The mutable policy-flag pointer is not an input to the rule tree: the vendor
/// only writes zero through it on one outcome family.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Gf3258LatePolicyContext {
    pub live_quality: i32,
    pub history_low: i32,
    pub history_high: i32,
    pub profile_state: i32,
    pub current_reject_count: i32,
}

impl Gf3258LatePolicyContext {
    /// Exact signed `cmovge` reduction at raw `0x6bbef..0x6bc37`.
    #[inline]
    pub const fn profile_max(self) -> i32 {
        if self.history_low >= self.profile_state {
            self.history_low
        } else {
            self.profile_state
        }
    }
}

/// Geometry front-end produced before the scalar GF3258 rule tree in
/// `FUN_0016bb90`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Gf3258LatePolicyOverlap {
    /// `max(aafe0(T), aafe0(inverse(T)))`.
    pub count: i32,
    /// Vendor representation used by the policy comparisons: `count * 100`.
    pub count_times_100: i32,
}

/// Reproduce the exact bidirectional overlap reduction at the front of the
/// GF3258 `FUN_0016bb90` path.
///
/// The vendor evaluates `FUN_001aafe0` for the supplied affine, inverts the
/// affine with `FUN_001c60c0`, evaluates overlap again, keeps the larger count,
/// and later scales it by 100 for percentage-style rule-tree comparisons.
#[inline]
pub(crate) fn gf3258_late_policy_bidirectional_overlap(
    transform: Gf3258AffineQ8,
) -> Gf3258LatePolicyOverlap {
    let height = GF3258_HEIGHT as i32;
    let width = GF3258_WIDTH as i32;
    let forward = gf3258_scanline_overlap(height, width, height, width, transform).count;
    let inverse = gf3258_scanline_overlap(height, width, height, width, transform.inverse()).count;
    let count = if inverse >= forward { inverse } else { forward };

    Gf3258LatePolicyOverlap {
        count,
        count_times_100: count.wrapping_mul(100),
    }
}

/// Externally visible result contract of GF3258 raw `0x6bb90`.
///
/// The large internal rule tree returns only 0/1 in the recovered GF3258 call
/// domain. A return of 1 rejects the current sample and increments the caller's
/// reject counter. Independently, a small subset of paths clears the mutable
/// primary policy flag. The work record and affine transform are read-only.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Gf3258LatePolicyOutcome {
    pub reject: bool,
    pub clear_primary_flag: bool,
}

impl Gf3258LatePolicyOutcome {
    /// Apply only the two side effects proven for the GF3258 caller contract.
    #[inline]
    pub fn apply(self, reject_count: &mut i32, primary_flag: &mut i32) {
        if self.reject {
            *reject_count = (*reject_count).wrapping_add(1);
        }
        if self.clear_primary_flag {
            *primary_flag = 0;
        }
    }
}

/// Execute the exact recovered GF3258 scalar decision DAG from raw `0x6bb90`
/// after its bidirectional-overlap front end has already been evaluated.
///
/// The embedded program is a portable transcription of the call-free integer
/// CFG at raw `0x6bc88..0x704ef`. It consumes only the typed record/context
/// projection below and returns the two externally visible
/// policy outcomes: sample rejection and primary-flag clearing.
#[inline]
pub(crate) fn gf3258_late_policy_outcome_from_overlap(
    record: Gf3258LatePolicyRecord,
    context: Gf3258LatePolicyContext,
    overlap: Gf3258LatePolicyOverlap,
) -> Gf3258LatePolicyOutcome {
    late_policy_program::classify(record, context, overlap.count)
}

/// Execute the complete recovered GF3258 raw `0x6bb90` late-policy stage.
///
/// This first reproduces the exact forward/inverse full-frame overlap maximum
/// and then evaluates the transcribed scalar decision DAG. It does not apply the
/// returned side effects; callers may use [`Gf3258LatePolicyOutcome::apply`]
/// once they are reproducing the vendor caller order.
#[inline]
pub(crate) fn gf3258_late_policy_outcome(
    record: Gf3258LatePolicyRecord,
    context: Gf3258LatePolicyContext,
    transform: Gf3258AffineQ8,
) -> Gf3258LatePolicyOutcome {
    let overlap = gf3258_late_policy_bidirectional_overlap(transform);
    gf3258_late_policy_outcome_from_overlap(record, context, overlap)
}

/// Exact scalar work-record projection consumed by the GF3258 (`type == 0x18`)
/// body of raw `FUN_001663f0`.
///
/// This stage runs only after the current sample survives raw `0x6bb90`. Static
/// access auditing proves that `0x663f0` reads these fifteen 32-bit fields and
/// does not mutate the work record. Offset-derived names remain where upstream
/// producer semantics have not yet been assigned.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Gf3258PostSurvivalPolicyRecord {
    pub geometry_count_00: i32,
    pub metric_04: i32,
    pub field_10: i32,
    pub field_14: i32,
    pub field_1c: i32,
    pub field_20: i32,
    pub field_24: i32,
    pub field_28: i32,
    pub field_2c: i32,
    pub field_30: i32,
    pub field_34: i32,
    pub field_38: i32,
    pub live_scalar_54: i32,
    pub enrolled_scalar_5c: i32,
    pub field_64: i32,
}

/// Non-record scalar inputs consumed by the GF3258 raw `0x663f0` veto stage.
///
/// The field names preserve the exact `FUN_001900b0` caller provenance:
/// `scalar_43` is live `Feature+0x10c`, `scalar_56` is live `Feature+0x158`,
/// `candidate_state` is the evolving caller mapped mode, and `mode_value` is
/// verification-profile byte zero. `ratio_q8` is derived from the optional
/// profile self-agreement buckets immediately before the call.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Gf3258PostSurvivalPolicyContext {
    pub scalar_43: i32,
    pub scalar_56: i32,
    pub candidate_state: i32,
    pub mode_value: i32,
    pub ratio_q8: i32,
}

/// The two mutable policy words passed to raw `0x663f0`.
///
/// `score_gate` is vendor local `iStack_18130` (ABI argument 7) and is the
/// binary word tested immediately after `0x663f0` to enter the score-producing
/// path. `policy_class` is `aiStack_18140[3]` (ABI argument 8), whose recovered
/// upstream domain includes 0, 1 and 2. Raw `0x663f0` is veto-only: it may
/// clear either word but never creates a nonzero value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Gf3258PostSurvivalPolicyFlags {
    pub score_gate: i32,
    pub policy_class: i32,
}

/// Execute the exact recovered GF3258 (`type == 0x18`) post-survival veto at
/// raw `0x663f0`.
///
/// The embedded implementation is a safe Rust transcription of the complete
/// call-free integer CFG at raw `0x6640e..0x67616`. The vendor stage reads the
/// incoming `score_gate`, never reads `policy_class` as a decision input, and
/// can only clear outputs. In the recovered GF3258 domain, clearing
/// `score_gate` also clears `policy_class`; `policy_class` can be cleared on its
/// own while `score_gate` survives.
#[inline]
pub(crate) fn gf3258_post_survival_policy_flags(
    record: Gf3258PostSurvivalPolicyRecord,
    context: Gf3258PostSurvivalPolicyContext,
    flags: Gf3258PostSurvivalPolicyFlags,
) -> Gf3258PostSurvivalPolicyFlags {
    post_survival_policy_program::apply(record, context, flags)
}

/// Exact work-record projection consumed by the GF3258 type-0x18 body of raw
/// `FUN_00169740` immediately before the normal caller tail.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Gf3258PreTailPolicyRecord {
    pub geometry_count: i32,
    pub verification_metric: i32,
    pub map_score: i32,
    pub evidence: i32,
    /// Real `FUN_001900b0` keeps `work+0x20` zero at this stage. The field is
    /// retained here so direct machine-code parity can exercise the helper's
    /// complete GF3258 input domain.
    pub field_20: i32,
    pub scaled_coverage_q8: i32,
    pub matched_percent: i32,
    pub geometry_percent: i32,
    pub orthogonality_penalty: i32,
    pub severe_orthogonality: i32,
    pub live_quality: i32,
    pub enrolled_quality: i32,
}

/// Caller/profile state consumed by raw `FUN_00169740`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Gf3258PreTailPolicyContext {
    pub mapped_mode: i32,
    pub profile_mode: i32,
    /// Verification-profile byte three, passed as the seventh raw argument.
    pub auxiliary_mode: i32,
    pub agreement: Gf3258ProfileAgreementCounts,
}

/// Execute the exact recovered GF3258 pre-tail rejection policy at raw
/// `FUN_00169740`.
#[inline]
pub(crate) fn gf3258_pre_tail_policy_rejects(
    record: Gf3258PreTailPolicyRecord,
    context: Gf3258PreTailPolicyContext,
) -> bool {
    pre_tail_policy_program::rejects(record, context)
}

/// Work values consumed by the GF3258 preparation-strength helper at raw
/// `FUN_00165bb0`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Gf3258PolicyPreparationRecord {
    pub geometry_count: i32,
    pub verification_metric: i32,
    pub evidence: i32,
    pub scaled_coverage_q8: i32,
    pub matched_percent: i32,
    pub geometry_percent: i32,
    pub scale_penalty: i32,
    pub orthogonality_penalty: i32,
    pub severe_orthogonality: i32,
}

/// Live/configuration values passed to raw `FUN_00165bb0`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Gf3258PolicyPreparationContext {
    pub live_quality: i32,
    pub live_coverage: i32,
    pub config_00: i32,
    pub config_04: i32,
    pub config_3c: i32,
}

/// `FUN_00165bb0` is a preparation-strength classifier, not an accept/reject
/// policy. A zero tier or zero gate selects the caller's optional `0xaabd0`
/// fallback-preparation route before normal policy evaluation continues.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Gf3258PolicyPreparation {
    pub tier: i32,
    pub gate: i32,
}

const GF3258_POLICY_PREPARATION_EVIDENCE_A: [i32; 22] = [
    0x0fff_ffff,
    0x0fff_ffff,
    0x0fff_ffff,
    226,
    224,
    224,
    221,
    215,
    212,
    208,
    204,
    200,
    195,
    190,
    190,
    190,
    180,
    180,
    180,
    180,
    180,
    180,
];
const GF3258_POLICY_PREPARATION_EVIDENCE_B: [i32; 22] = [
    0x0fff_ffff,
    0x0fff_ffff,
    0x0fff_ffff,
    0x0fff_ffff,
    0x0fff_ffff,
    226,
    222,
    215,
    213,
    210,
    205,
    203,
    200,
    198,
    197,
    195,
    193,
    191,
    184,
    182,
    182,
    181,
];

/// Execute the exact GF3258 type-0x18 specialization of raw `FUN_00165bb0`.
#[inline]
pub(crate) fn gf3258_policy_preparation(
    record: Gf3258PolicyPreparationRecord,
    context: Gf3258PolicyPreparationContext,
) -> Gf3258PolicyPreparation {
    let mut geometry_margin = record.geometry_count.wrapping_sub(context.config_04);
    let mut metric_margin = record.verification_metric.wrapping_sub(context.config_04);
    let evidence = record.evidence.wrapping_sub(context.config_00);

    if record.scaled_coverage_q8 > 79 && record.matched_percent > 69 && geometry_margin > 4 {
        let bonus = record.matched_percent.wrapping_sub(70) / 5 + 1;
        geometry_margin = geometry_margin.wrapping_add(bonus);
        metric_margin = metric_margin.wrapping_add(bonus);
    }

    let mut adjusted_evidence = evidence;
    if metric_margin <= 11 {
        let penalty = record
            .scale_penalty
            .wrapping_add(record.orthogonality_penalty)
            .wrapping_add(record.severe_orthogonality)
            .wrapping_mul(4);
        adjusted_evidence = adjusted_evidence.wrapping_sub(penalty);
    }

    let coverage_base = if matches!(context.config_3c, 11 | 21) {
        80
    } else {
        100
    };
    if record.scaled_coverage_q8 > coverage_base {
        adjusted_evidence = adjusted_evidence
            .wrapping_add((record.scaled_coverage_q8.wrapping_sub(coverage_base) / 30) * 2)
            .wrapping_add(2);
    } else if record.scaled_coverage_q8 <= 24 {
        return Gf3258PolicyPreparation::default();
    }

    let geometry_index = geometry_margin.clamp(0, 21) as usize;
    let metric_index = metric_margin.clamp(0, 21) as usize;
    let gate = GF3258_POLICY_PREPARATION_EVIDENCE_A[geometry_index] < adjusted_evidence
        || GF3258_POLICY_PREPARATION_EVIDENCE_A[metric_index].wrapping_add(10) < adjusted_evidence
        || geometry_margin > 13;
    if !gate {
        return Gf3258PolicyPreparation::default();
    }

    if context.live_quality <= 15 || context.live_coverage <= 64 || record.scaled_coverage_q8 <= 39
    {
        return Gf3258PolicyPreparation { tier: 0, gate: 1 };
    }

    let strong = evidence > GF3258_POLICY_PREPARATION_EVIDENCE_B[geometry_index]
        || evidence > GF3258_POLICY_PREPARATION_EVIDENCE_B[metric_index].wrapping_add(10);
    if !strong {
        return Gf3258PolicyPreparation { tier: 0, gate: 1 };
    }

    let tier = if record.geometry_count > 7
        && record.verification_metric > 11
        && record.geometry_percent > 37
        && record.scaled_coverage_q8 > 95
    {
        2
    } else {
        1
    };
    Gf3258PolicyPreparation { tier, gate: 1 }
}

/// Exact scalar work-record projection consumed by the GF3258 verification
/// flag prepass/refinement helpers at raw `0x65700`, `0x72ea0`, `0x73c30`,
/// and `0x7a240`.
///
/// This is intentionally distinct from [`Gf3258PostSurvivalPolicyRecord`]. The
/// vendor caller can run raw `0xaa350` between the `0x65700` prepass and the
/// later `0x8df60` refinement, so the two stages do not necessarily observe the
/// same record snapshot. Offset-derived names remain until their upstream
/// producer semantics are proven.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Gf3258VerificationFlagPolicyRecord {
    pub geometry_count_00: i32,
    pub metric_04: i32,
    pub field_10: i32,
    pub field_14: i32,
    pub field_20: i32,
    pub field_24: i32,
    pub field_28: i32,
    pub field_2c: i32,
    pub field_30: i32,
    pub field_34: i32,
    pub field_38: i32,
    pub live_scalar_54: i32,
    pub field_58: i32,
    pub enrolled_scalar_5c: i32,
}

/// Scalar/config inputs shared by the GF3258 raw `0x65700` prepass and
/// `0x8df60` refinement chain.
///
/// `scalar_43` and `scalar_44` are the two caller scalars forwarded directly
/// from `FUN_001900b0`. `config_00`, `config_04`, and `config_48` remain
/// explicit because they are runtime/config values; the fixed GF3258 config
/// fields are supplied internally as type `0x18`, `+0x40 = 1`, `+0x44 = 0`,
/// and `+0x4c = 1`. `candidate_state` participates only in the caller-level
/// bypass predicate between the prepass and refinement.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Gf3258VerificationFlagPolicyContext {
    pub scalar_43: i32,
    pub scalar_44: i32,
    pub candidate_state: i32,
    pub config_00: i32,
    pub config_04: i32,
    pub config_48: i32,
}

/// Result of the GF3258 raw `0x65700` caller prepass.
///
/// The two policy words feed the later `0x8df60 -> 0x663f0` chain. The
/// auxiliary flag is the third mutable output passed by `FUN_001900b0`; it is
/// retained instead of being discarded even though its later consumer has not
/// yet been promoted to a standalone semantic API.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Gf3258VerificationFlagPrepass {
    pub flags: Gf3258PostSurvivalPolicyFlags,
    pub auxiliary_flag: i32,
    pub bypass_refinement: bool,
}

/// Exact GF3258 caller predicate that skips raw `0xaa350` and `0x8df60` after
/// the initial `0x65700` prepass.
///
/// Raw `FUN_001900b0` bypasses refinement iff:
/// - `policy_class == 2`;
/// - `candidate_state <= 1`;
/// - `field_14 > 204` or `scalar_43 <= 90`; and
/// - `field_24 > 104`.
#[inline]
pub(crate) const fn gf3258_verification_flag_refinement_is_bypassed(
    record: Gf3258VerificationFlagPolicyRecord,
    context: Gf3258VerificationFlagPolicyContext,
    flags: Gf3258PostSurvivalPolicyFlags,
) -> bool {
    flags.policy_class == 2
        && context.candidate_state <= 1
        && (record.field_14 > 0xcc || context.scalar_43 <= 0x5a)
        && record.field_24 > 0x68
}

/// Execute the exact GF3258 raw `0x65700` prepass used by `FUN_001900b0`
/// before its optional `0xaa350 -> 0x8df60` refinement path.
///
/// `record` must be the **pre-`0xaa350`** work-record snapshot. The embedded
/// implementation reproduces the raw helper with mode argument 1 and zeroed
/// incoming outputs, including the third auxiliary output. It also evaluates
/// the exact caller-level bypass predicate for the returned policy class.
#[inline]
pub(crate) fn gf3258_verification_flag_prepass(
    record: Gf3258VerificationFlagPolicyRecord,
    context: Gf3258VerificationFlagPolicyContext,
) -> Gf3258VerificationFlagPrepass {
    let (flags, auxiliary_flag) = flag_policy_program::prepass(record, context);
    let bypass_refinement = gf3258_verification_flag_refinement_is_bypassed(record, context, flags);
    Gf3258VerificationFlagPrepass {
        flags,
        auxiliary_flag,
        bypass_refinement,
    }
}

/// Execute the exact GF3258 (`type == 0x18`) refinement performed by raw
/// `FUN_0018df60`.
///
/// On the real non-bypass caller path, raw `FUN_001900b0` invokes `0xaa350`
/// **before** `0x8df60`. Therefore `record` here must be the **post-`0xaa350`**
/// snapshot. This function intentionally does not invoke or model `0xaa350`;
/// preserving that boundary prevents an unproven assumption that the prepass
/// and refinement observe identical record contents.
///
/// The specialized vendor chain is exactly:
/// `0x65700(mode=0)` as needed, optional `0x72ea0`, optional `0x73c30`, then
/// optional `0x7a240`, with the same OR/refinement semantics as raw `0x8df60`.
#[inline]
pub(crate) fn gf3258_refine_verification_flags(
    record: Gf3258VerificationFlagPolicyRecord,
    context: Gf3258VerificationFlagPolicyContext,
    flags: Gf3258PostSurvivalPolicyFlags,
) -> Gf3258PostSurvivalPolicyFlags {
    flag_policy_program::refine(record, context, flags)
}

/// Raw `FUN_001aa350` configuration mode that expands the 20x16 packed
/// quarter-validity mask to the 40x32 registration-map domain.
///
/// `FUN_001900b0` supplies this mode dynamically from template/group `+0x14`;
/// This implementation does not assume that runtime field is always one.
#[cfg(test)]
pub(crate) const GF3258_VERIFICATION_MAP_MODE_HALF_RESOLUTION: i32 = 1;

/// Raw `FUN_001900b0` always sets the `FUN_001aa350` warp border to zero.
pub(crate) const GF3258_VERIFICATION_MAP_WARP_BORDER: usize = 0;

/// Raw `FUN_001aa350` / `FUN_001aa110` map-agreement outputs written to the
/// verification work record.
///
/// For the four jointly-valid binary buckets `(c00, c10, c01, c11)`:
/// - `field_18 = round_q8((c00 + c11) / total)`;
/// - `field_1c = round_q8(c00 / (c00 + c10 + c01))`;
/// - `field_20 = round_q8(c11 / (c11 + c10 + c01))`.
///
/// The corresponding field is zero when its denominator is non-positive.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Gf3258VerificationMapEvidence {
    pub counts: Gf3258BinaryJointCounts,
    pub field_18: i32,
    pub field_1c: i32,
    pub field_20: i32,
}

impl Gf3258VerificationMapEvidence {
    /// Apply the only `0xaa350` output consumed by the `0x8df60` flag-policy
    /// projection.
    #[inline]
    pub fn apply_to_flag_policy_record(self, record: &mut Gf3258VerificationFlagPolicyRecord) {
        record.field_20 = self.field_20;
    }

    /// Apply the `0xaa350` output consumed by the already-recovered `0x6bb90`
    /// late-policy projection.
    #[cfg(test)]
    #[inline]
    pub fn apply_to_late_policy_record(self, record: &mut Gf3258LatePolicyRecord) {
        record.field_20 = self.field_20;
    }

    /// Apply the two `0xaa350` outputs consumed by the already-recovered
    /// `0x663f0` post-survival projection.
    #[cfg(test)]
    #[inline]
    pub fn apply_to_post_survival_policy_record(self, record: &mut Gf3258PostSurvivalPolicyRecord) {
        record.field_1c = self.field_1c;
        record.field_20 = self.field_20;
    }

    /// Apply the `0xaa350` output consumed by the recovered `0x69290` score
    /// policy projection.
    #[cfg(test)]
    #[inline]
    pub fn apply_to_score_policy_record(self, record: &mut Gf3258VerificationPolicyRecord) {
        record.field_20 = self.field_20;
    }
}

#[inline]
fn gf3258_aa110_rounded_q8(numerator: i32, denominator: i32) -> i32 {
    if denominator <= 0 {
        0
    } else {
        numerator.wrapping_shl(8).wrapping_add(denominator >> 1) / denominator
    }
}

/// Reproduce raw `FUN_001aa350 -> FUN_001aa110` for the GF3258
/// half-resolution (`map_mode == 1`) verification-map path.
///
/// This is the exact path compatible with the persisted 40x32 `Feature+0x18`
/// low-threshold registration map and the 20x16 packed `Feature+0x28` validity
/// mask. The caller's raw border is zero, unlike registration graph scoring
/// (`0xa9a50`), which uses border four. This API is exact for the normal
/// non-singular matcher-affine domain produced by the recovered geometry path.
/// Synthetic singular-affine behavior inside raw `0xa8ae0/0xc5b30` remains
/// outside this helper and is intentionally not generalized here.
///
/// `None` means the recovered affine ROI warp did not produce both map and
/// validity ROIs. Raw `0xaa350` returns zero in that case and leaves existing
/// work-record `+0x18/+0x1c/+0x20` values unchanged; callers must therefore
/// treat `None` as "preserve previous values", not as three zeros.
pub(crate) fn gf3258_verification_map_evidence_half_resolution(
    source_low_threshold_map: &[u8; GF3258_REGISTRATION_PACKED_BYTES],
    target_low_threshold_map: &[u8; GF3258_REGISTRATION_PACKED_BYTES],
    source_quarter_validity_packed: &[u8; GF3258_QUARTER_VALIDITY_CELLS / 8],
    target_quarter_validity_packed: &[u8; GF3258_QUARTER_VALIDITY_CELLS / 8],
    source_to_target_full_resolution: Gf3258AffineQ8,
) -> Option<Gf3258VerificationMapEvidence> {
    let source = gf3258_unpack_registration_bits(source_low_threshold_map);
    let target = gf3258_unpack_registration_bits(target_low_threshold_map);

    let source_quarter = gf3258_unpack_quarter_validity(source_quarter_validity_packed);
    let target_quarter = gf3258_unpack_quarter_validity(target_quarter_validity_packed);
    let source_validity = gf3258_expand_quarter_validity(&source_quarter);
    let target_validity = gf3258_expand_quarter_validity(&target_quarter);

    let active_transform = gf3258_affine_for_registration_scoring(source_to_target_full_resolution);
    let warped = gf3258_warp_u8_to_canvas_roi(
        &source,
        GF3258_REGISTRATION_WIDTH,
        GF3258_REGISTRATION_HEIGHT,
        GF3258_REGISTRATION_WIDTH,
        GF3258_REGISTRATION_HEIGHT,
        active_transform,
        GF3258_VERIFICATION_MAP_WARP_BORDER,
        0xff,
    )?;
    let warped_validity = gf3258_warp_u8_to_canvas_roi(
        &source_validity,
        GF3258_REGISTRATION_WIDTH,
        GF3258_REGISTRATION_HEIGHT,
        GF3258_REGISTRATION_WIDTH,
        GF3258_REGISTRATION_HEIGHT,
        active_transform,
        GF3258_VERIFICATION_MAP_WARP_BORDER,
        0xff,
    )?;

    debug_assert_eq!(warped.x, warped_validity.x);
    debug_assert_eq!(warped.y, warped_validity.y);
    debug_assert_eq!(warped.width, warped_validity.width);
    debug_assert_eq!(warped.height, warped_validity.height);

    let counts = gf3258_joint_binary_counts_for_roi(
        &warped,
        &target,
        GF3258_REGISTRATION_WIDTH,
        GF3258_REGISTRATION_HEIGHT,
        Some(&warped_validity.data),
        Some(&target_validity),
    );
    let total = counts
        .c00
        .wrapping_add(counts.c10)
        .wrapping_add(counts.c01)
        .wrapping_add(counts.c11);
    let non_one = counts.c00.wrapping_add(counts.c10).wrapping_add(counts.c01);
    let non_zero = counts.c11.wrapping_add(counts.c10).wrapping_add(counts.c01);

    Some(Gf3258VerificationMapEvidence {
        counts,
        field_18: gf3258_aa110_rounded_q8(counts.c00.wrapping_add(counts.c11), total),
        field_1c: gf3258_aa110_rounded_q8(counts.c00, non_one),
        field_20: gf3258_aa110_rounded_q8(counts.c11, non_zero),
    })
}

/// Result of composing the exact GF3258 `0x65700` prepass with the caller's
/// bypass or the supported half-resolution `0xaa350 -> 0x8df60` refinement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Gf3258VerificationFlagPolicyHalfResolutionResult {
    pub flags: Gf3258PostSurvivalPolicyFlags,
    pub auxiliary_flag: i32,
    pub bypassed_refinement: bool,
    /// Present only when `0xaa350` successfully produced a warped ROI. Raw
    /// `0xaa350` failure is represented by `None`; refinement still runs using
    /// the unchanged pre-`aa350` `field_20`, matching the vendor caller.
    pub map_evidence: Option<Gf3258VerificationMapEvidence>,
    pub post_refinement_record: Gf3258VerificationFlagPolicyRecord,
}

/// Exact caller-level GF3258 flag-policy composition for `map_mode == 1`
/// within the normal non-singular matcher-affine domain.
///
/// Order:
/// `0x65700(mode=1) -> bypass OR 0xaa350(border=0) -> 0x8df60`.
/// Raw `0xaa350`'s return value is ignored by `FUN_001900b0`; on warp failure
/// this helper leaves `field_20` unchanged and still executes `0x8df60`.
pub(crate) fn gf3258_verification_flag_policy_half_resolution(
    pre_aa350_record: Gf3258VerificationFlagPolicyRecord,
    context: Gf3258VerificationFlagPolicyContext,
    source_low_threshold_map: &[u8; GF3258_REGISTRATION_PACKED_BYTES],
    target_low_threshold_map: &[u8; GF3258_REGISTRATION_PACKED_BYTES],
    source_quarter_validity_packed: &[u8; GF3258_QUARTER_VALIDITY_CELLS / 8],
    target_quarter_validity_packed: &[u8; GF3258_QUARTER_VALIDITY_CELLS / 8],
    source_to_target_full_resolution: Gf3258AffineQ8,
) -> Gf3258VerificationFlagPolicyHalfResolutionResult {
    let prepass = gf3258_verification_flag_prepass(pre_aa350_record, context);
    if prepass.bypass_refinement {
        return Gf3258VerificationFlagPolicyHalfResolutionResult {
            flags: prepass.flags,
            auxiliary_flag: prepass.auxiliary_flag,
            bypassed_refinement: true,
            map_evidence: None,
            post_refinement_record: pre_aa350_record,
        };
    }

    let map_evidence = gf3258_verification_map_evidence_half_resolution(
        source_low_threshold_map,
        target_low_threshold_map,
        source_quarter_validity_packed,
        target_quarter_validity_packed,
        source_to_target_full_resolution,
    );
    let mut post_aa350_record = pre_aa350_record;
    if let Some(evidence) = map_evidence {
        evidence.apply_to_flag_policy_record(&mut post_aa350_record);
    }
    let flags = gf3258_refine_verification_flags(post_aa350_record, context, prepass.flags);

    Gf3258VerificationFlagPolicyHalfResolutionResult {
        flags,
        auxiliary_flag: prepass.auxiliary_flag,
        bypassed_refinement: false,
        map_evidence,
        post_refinement_record: post_aa350_record,
    }
}

/// Apply the exact GF3258 caller gate at raw `0x91161..0x9248b` after
/// `0x8df60` refinement.
///
/// This gate exists only on the non-bypass refinement path. When the retained
/// `0x65700` auxiliary output is nonzero and post-`0xaa350` `field_20 <= 0xae`,
/// `FUN_001900b0` clears both policy words before continuing to `0x6bb90`.
#[inline]
pub(crate) const fn gf3258_apply_post_refinement_auxiliary_gate(
    field_20: i32,
    auxiliary_flag: i32,
    flags: Gf3258PostSurvivalPolicyFlags,
) -> Gf3258PostSurvivalPolicyFlags {
    if auxiliary_flag != 0 && field_20 <= 0xae {
        Gf3258PostSurvivalPolicyFlags {
            score_gate: 0,
            policy_class: 0,
        }
    } else {
        flags
    }
}

/// Exact Q8 ratio formed by `FUN_001900b0` immediately before raw `0x663f0`.
///
/// The three inputs retain their caller stack-slot identities because their
/// upstream producer semantics are not yet fully named:
///
/// `((slot_224 + slot_22c) << 8) / (slot_224 + slot_228 + slot_22c + 1)`.
///
/// The real matcher supplies a positive denominator. `None` represents an
/// out-of-domain zero denominator instead of manufacturing a policy value.
#[inline]
pub(crate) fn gf3258_post_survival_ratio_q8(
    slot_224: i32,
    slot_228: i32,
    slot_22c: i32,
) -> Option<i32> {
    let numerator = slot_224.wrapping_add(slot_22c).wrapping_shl(8);
    let denominator = slot_224
        .wrapping_add(slot_228)
        .wrapping_add(slot_22c)
        .wrapping_add(1);
    if denominator == 0 {
        None
    } else {
        Some(numerator / denominator)
    }
}

/// Exact caller decision after raw `0x663f0` that determines whether the
/// current sample proceeds toward the final per-sample veto/score accumulator.
///
/// A surviving `score_gate == 1` proceeds directly. When that gate is not one,
/// GF3258 has one caller-level rescue route: `rescue_floor < field_10` and
/// `field_14 > 0xc3`. Boundary comparisons are signed and strict exactly as in
/// raw `0x91294..0x912d4`.
#[inline]
pub(crate) const fn gf3258_post_survival_reaches_score_path(
    record: Gf3258PostSurvivalPolicyRecord,
    flags: Gf3258PostSurvivalPolicyFlags,
    rescue_floor: i32,
) -> bool {
    flags.score_gate == 1 || (rescue_floor < record.field_10 && record.field_14 > 0xc3)
}

/// Exact GF3258 work-record projection consumed by raw `0x67620`.
///
/// Static type-`0x18` reachability proves that only these seven dwords are read
/// before the function either returns zero or reaches its common veto epilogue.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Gf3258FinalSampleVetoRecord {
    pub geometry_count_00: i32,
    pub metric_04: i32,
    pub field_14: i32,
    pub field_20: i32,
    pub field_24: i32,
    pub field_28: i32,
    pub field_2c: i32,
}

/// GF3258 scalar inputs that remain live at raw `0x67620`.
///
/// The vendor function also receives enrolled `+0x10c`, but the type-`0x18`
/// path never reads that argument. `enrolled_status_114` participates only as
/// a zero/nonzero predicate; the other two values are the live feature scalars
/// forwarded from `FUN_001900b0`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Gf3258FinalSampleVetoContext {
    pub enrolled_status_114: i32,
    pub live_scalar_43: i32,
    pub live_scalar_56: i32,
}

/// Result contract of the GF3258 raw `0x67620` final per-sample veto.
///
/// On veto the vendor returns one and clears both mutable policy words. On
/// survival it returns zero and leaves both words unchanged.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Gf3258FinalSampleVetoOutcome {
    pub reject: bool,
    pub flags: Gf3258PostSurvivalPolicyFlags,
}

/// Execute the exact GF3258 (`type == 0x18`) specialization of raw `0x67620`.
///
/// The generic helper is large, but the GF3258 dispatch reaches only three
/// signed integer veto predicates. Direct execution against the bundled vendor
/// `.so` matched this specialization over 100,000 randomized records with zero
/// mismatches, including return value and both output-word side effects.
#[inline]
pub(crate) fn gf3258_final_sample_veto(
    record: Gf3258FinalSampleVetoRecord,
    context: Gf3258FinalSampleVetoContext,
    flags: Gf3258PostSurvivalPolicyFlags,
) -> Gf3258FinalSampleVetoOutcome {
    let status_nonzero = context.enrolled_status_114 != 0;
    let combined_14_20 = record.field_14.wrapping_add(record.field_20);

    let veto_a = context.live_scalar_56 > 0x4a
        && status_nonzero
        && record.geometry_count_00 <= 0x0c
        && record.metric_04 <= 0x0c
        && combined_14_20 <= 0x19f
        && context.live_scalar_43 <= 0x20
        && record.field_2c <= 0x3c
        && record.field_28 <= 0x41
        && record.field_24 <= 0x32;

    let veto_b = context.live_scalar_56 > 0x1c
        && status_nonzero
        && record.geometry_count_00 <= 0x0f
        && record.metric_04 <= 0x10
        && combined_14_20 <= 0x178
        && context.live_scalar_43 <= 0x39
        && record.field_2c <= 0x1b
        && record.field_28 <= 0x2a
        && record.field_24 <= 0x68;

    let veto_c = context.live_scalar_56 > 0x27
        && status_nonzero
        && record.geometry_count_00 <= 0x11
        && record.metric_04 <= 0x11
        && combined_14_20 <= 0x166
        && context.live_scalar_43 <= 0x32
        && record.field_2c <= 0x21
        && record.field_28 <= 0x32
        && record.field_24 <= 0x6a;

    let reject = veto_a || veto_b || veto_c;
    Gf3258FinalSampleVetoOutcome {
        reject,
        flags: if reject {
            Gf3258PostSurvivalPolicyFlags {
                score_gate: 0,
                policy_class: 0,
            }
        } else {
            flags
        },
    }
}

/// Binary self-agreement buckets produced by the optional GF3258 verification
/// profile path in raw `FUN_001a9a50`.
///
/// The vendor normalizes the 40x32 profile mask to binary, warps that mask and
/// the live feature's expanded quarter-validity mask under the final policy
/// affine with border zero, and compares the warped profile against the original
/// profile. The enrolled feature's validity does not participate in these counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Gf3258ProfileAgreementCounts {
    pub both_zero: i32,
    pub mixed: i32,
    pub both_one: i32,
}

impl Gf3258ProfileAgreementCounts {
    #[cfg(test)]
    #[inline]
    pub fn ratio_q8(self) -> Option<i32> {
        gf3258_post_survival_ratio_q8(self.both_zero, self.mixed, self.both_one)
    }
}

/// Reproduce the optional-profile agreement counters written by raw
/// `FUN_001a9a50` for GF3258.
///
/// `profile_mask` is the caller's 40x32 profile raster. Any nonzero input byte
/// becomes one before warping. `live_quarter_validity_packed` is the first
/// `a9a50` feature argument's 20x16 validity mask; the normal caller supplies
/// the live feature in that position. The mask is expanded to 40x32 and both
/// it and the profile are self-warped under the final policy affine.
pub(crate) fn gf3258_profile_agreement_counts(
    profile_mask: &[u8; GF3258_REGISTRATION_PIXELS],
    live_quarter_validity_packed: &[u8; GF3258_QUARTER_VALIDITY_CELLS / 8],
    transform_source_to_canvas: Gf3258AffineQ8,
) -> Gf3258ProfileAgreementCounts {
    let mut profile = [0u8; GF3258_REGISTRATION_PIXELS];
    for (output, input) in profile.iter_mut().zip(profile_mask.iter().copied()) {
        *output = u8::from(input != 0);
    }

    let live_quarter_validity = gf3258_unpack_quarter_validity(live_quarter_validity_packed);
    let live_validity = gf3258_expand_quarter_validity(&live_quarter_validity);
    let transform = gf3258_affine_for_registration_scoring(transform_source_to_canvas);

    let Some(warped_profile) = gf3258_warp_u8_to_canvas_roi(
        &profile,
        GF3258_REGISTRATION_WIDTH,
        GF3258_REGISTRATION_HEIGHT,
        GF3258_REGISTRATION_WIDTH,
        GF3258_REGISTRATION_HEIGHT,
        transform,
        0,
        0xff,
    ) else {
        return Gf3258ProfileAgreementCounts::default();
    };
    let Some(warped_validity) = gf3258_warp_u8_to_canvas_roi(
        &live_validity,
        GF3258_REGISTRATION_WIDTH,
        GF3258_REGISTRATION_HEIGHT,
        GF3258_REGISTRATION_WIDTH,
        GF3258_REGISTRATION_HEIGHT,
        transform,
        0,
        0xff,
    ) else {
        return Gf3258ProfileAgreementCounts::default();
    };

    debug_assert_eq!(warped_profile.x, warped_validity.x);
    debug_assert_eq!(warped_profile.y, warped_validity.y);
    debug_assert_eq!(warped_profile.width, warped_validity.width);
    debug_assert_eq!(warped_profile.height, warped_validity.height);

    let counts = gf3258_joint_binary_counts_for_roi(
        &warped_profile,
        &profile,
        GF3258_REGISTRATION_WIDTH,
        GF3258_REGISTRATION_HEIGHT,
        Some(&warped_validity.data),
        Some(&live_validity),
    );
    Gf3258ProfileAgreementCounts {
        both_zero: counts.c00,
        mixed: counts.c10.wrapping_add(counts.c01),
        both_one: counts.c11,
    }
}

/// Low-level projection of the three optional-profile agreement counters used
/// to construct the Q8 input to `0x663f0`. Production composition derives these
/// from [`Gf3258ProfileAgreementCounts`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Gf3258PostSurvivalRatioInputs {
    pub slot_224: i32,
    pub slot_228: i32,
    pub slot_22c: i32,
}

/// Caller-tail disposition from the exact GF3258 stages after flag refinement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Gf3258VerificationCallerTailDisposition {
    /// Raw `0x6bb90` rejected the sample and incremented the reject counter.
    LatePolicyRejected,
    /// Raw `0x663f0` plus the caller rescue predicate did not select this
    /// sample for the score path.
    PostSurvivalNotSelected,
    /// Raw `0x67620` rejected the otherwise-selected sample.
    FinalVetoRejected,
    /// The sample reaches the vendor Q8 metric accumulator.
    Accepted,
    /// The recovered Q8 ratio denominator was zero. Real GF3258 caller counts
    /// have not been observed in this out-of-domain state.
    OutOfDomainRatio,
}

/// Exact externally relevant state after composing the recovered GF3258 caller
/// tail from post-`0x8df60` flags through accumulator entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Gf3258VerificationCallerTailResult {
    pub disposition: Gf3258VerificationCallerTailDisposition,
    pub flags: Gf3258PostSurvivalPolicyFlags,
    pub reject_count: i32,
    /// Q8 contribution added by `FUN_001900b0` only for `Accepted`.
    pub contribution_q8: Option<i32>,
}

/// Compose the GF3258 caller tail after flag-policy refinement:
///
/// `auxiliary gate -> 0x6bb90 -> ratio -> 0x663f0 -> caller rescue -> 0x67620`.
///
/// The low-level API retains explicit final-veto arguments for direct helper
/// parity. Static auditing of raw `0x71a40` proved that its optional side work
/// only reads `work+0x14/+0x20`; it does not mutate the work record. The
/// production composer therefore projects the final veto from the same mutable
/// policy-work snapshot used after flag refinement.
#[allow(clippy::too_many_arguments)]
pub(crate) fn gf3258_verification_caller_tail(
    refinement_was_bypassed: bool,
    auxiliary_flag: i32,
    post_refinement_field_20: i32,
    mut flags: Gf3258PostSurvivalPolicyFlags,
    late_record: Gf3258LatePolicyRecord,
    late_context: Gf3258LatePolicyContext,
    transform: Gf3258AffineQ8,
    ratio_inputs: Gf3258PostSurvivalRatioInputs,
    post_survival_record: Gf3258PostSurvivalPolicyRecord,
    mut post_survival_context: Gf3258PostSurvivalPolicyContext,
    rescue_floor: i32,
    final_veto_record: Gf3258FinalSampleVetoRecord,
    final_veto_context: Gf3258FinalSampleVetoContext,
) -> Gf3258VerificationCallerTailResult {
    if !refinement_was_bypassed {
        flags = gf3258_apply_post_refinement_auxiliary_gate(
            post_refinement_field_20,
            auxiliary_flag,
            flags,
        );
    }

    let late_outcome = gf3258_late_policy_outcome(late_record, late_context, transform);
    let mut reject_count = late_context.current_reject_count;
    late_outcome.apply(&mut reject_count, &mut flags.policy_class);
    if late_outcome.reject {
        return Gf3258VerificationCallerTailResult {
            disposition: Gf3258VerificationCallerTailDisposition::LatePolicyRejected,
            flags,
            reject_count,
            contribution_q8: None,
        };
    }

    let Some(ratio_q8) = gf3258_post_survival_ratio_q8(
        ratio_inputs.slot_224,
        ratio_inputs.slot_228,
        ratio_inputs.slot_22c,
    ) else {
        return Gf3258VerificationCallerTailResult {
            disposition: Gf3258VerificationCallerTailDisposition::OutOfDomainRatio,
            flags,
            reject_count,
            contribution_q8: None,
        };
    };
    post_survival_context.ratio_q8 = ratio_q8;
    flags = gf3258_post_survival_policy_flags(post_survival_record, post_survival_context, flags);

    if !gf3258_post_survival_reaches_score_path(post_survival_record, flags, rescue_floor) {
        return Gf3258VerificationCallerTailResult {
            disposition: Gf3258VerificationCallerTailDisposition::PostSurvivalNotSelected,
            flags,
            reject_count,
            contribution_q8: None,
        };
    }

    let final_outcome = gf3258_final_sample_veto(final_veto_record, final_veto_context, flags);
    if final_outcome.reject {
        return Gf3258VerificationCallerTailResult {
            disposition: Gf3258VerificationCallerTailDisposition::FinalVetoRejected,
            flags: final_outcome.flags,
            reject_count,
            contribution_q8: None,
        };
    }

    Gf3258VerificationCallerTailResult {
        disposition: Gf3258VerificationCallerTailDisposition::Accepted,
        flags: final_outcome.flags,
        reject_count,
        contribution_q8: Some(gf3258_verification_metric_contribution_q8(
            final_veto_record.metric_04,
        )),
    }
}

/// Terminal fallback reason bit: fewer than six accumulated recovery
/// correspondences were available.
pub(crate) const GF3258_FALLBACK_REASON_LOW_GEOMETRY: i32 = 0x04;
/// Terminal fallback reason bit: a candidate existed but its best evidence was
/// below `0xd0`.
pub(crate) const GF3258_FALLBACK_REASON_LOW_EVIDENCE: i32 = 0x02;
/// Terminal fallback reason bit: a candidate existed but its best quality was
/// below `0x80`.
pub(crate) const GF3258_FALLBACK_REASON_LOW_QUALITY: i32 = 0x01;

/// Encode the non-positive terminal fallback result emitted by
/// `FUN_001900b0` when `FUN_00169290` does not produce a positive score.
///
/// The vendor forms a three-bit reason mask and negates it. Therefore this
/// helper can return `0` as well as `-1..=-7`; zero means none of these three
/// terminal reason bits was set.
#[inline]
pub(crate) const fn gf3258_encode_vendor_fallback_nonpositive_score(
    accumulated_geometry_count: i32,
    had_candidate: bool,
    best_evidence: i32,
    best_quality: i32,
) -> i32 {
    let mut reason = 0;

    if accumulated_geometry_count < 6 {
        reason |= GF3258_FALLBACK_REASON_LOW_GEOMETRY;
    }
    if had_candidate && best_evidence < 0xd0 {
        reason |= GF3258_FALLBACK_REASON_LOW_EVIDENCE;
    }
    if had_candidate && best_quality < 0x80 {
        reason |= GF3258_FALLBACK_REASON_LOW_QUALITY;
    }

    -reason
}

/// Finalize the terminal recovery branch of `FUN_001900b0` once its
/// `FUN_00169290` policy score and recovery statistics are already known.
///
/// A positive policy score is capped at 100. A zero/non-positive policy score
/// is replaced by the vendor's negated three-bit fallback reason mask.
#[inline]
pub(crate) const fn gf3258_finalize_vendor_fallback_score(
    policy_score: i32,
    accumulated_geometry_count: i32,
    had_candidate: bool,
    best_evidence: i32,
    best_quality: i32,
) -> i32 {
    if policy_score > 0 {
        if policy_score < 0x65 {
            policy_score
        } else {
            100
        }
    } else {
        gf3258_encode_vendor_fallback_nonpositive_score(
            accumulated_geometry_count,
            had_candidate,
            best_evidence,
            best_quality,
        )
    }
}

/// Score emitted by raw `0x8e810` when the optional vendor cache-rescue search
/// finds a match. The same function clears the output score to zero before it
/// searches, so a cache miss produces zero.
pub(crate) const GF3258_CACHE_RESCUE_MATCH_SCORE: i32 = 10_000;

/// Recovery statistics consumed by the terminal fallback encoder after the
/// full recovery scan in `FUN_001900b0`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Gf3258TerminalRecoverySummary {
    pub policy_score: i32,
    pub accumulated_geometry_count: i32,
    pub had_candidate: bool,
    pub best_evidence: i32,
    pub best_quality: i32,
}

/// One GF3258 full-recovery candidate after the vendor has already:
///
/// 1. produced more than four `0x704f0` geometric inliers;
/// 2. passed the optional `0x6ad30` near-identity exclusion; and
/// 3. executed `0xa9a50` plus `0xaa480`.
///
/// The neutral field names deliberately mirror the values consumed by the
/// recovery aggregate in `FUN_001900b0`. `coverage_q8` is the fourth output of
/// raw `0xa9a50`; `affine_scale_q8` and `affine_orthogonality_q16` are raw
/// `0xaa480` outputs 0 and 2 respectively.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Gf3258TerminalRecoveryObservation {
    pub geometry_count: i32,
    pub map_score: i32,
    pub evidence: i32,
    pub coverage_q8: i32,
    pub affine_scale_q8: i32,
    pub affine_orthogonality_q16: i32,
}

/// Caller configuration used by the GF3258 full-recovery aggregate.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Gf3258TerminalRecoveryConfig {
    /// `param_4[0]`; admitted candidates require
    /// `map_score > map_score_base + 0xcf` with wrapping i32 addition.
    pub map_score_base: i32,
    /// `param_4[0xc]`; multiplied by `coverage_q8`, then arithmetic-shifted by 8.
    pub quality_scale_q8: i32,
    /// `param_4[0x10] != 0`; enables the two four-point affine penalties.
    pub apply_affine_penalty: bool,
}

/// Exact recovery-aggregate state retained in addition to the terminal summary.
/// The selected index is useful for parity diagnostics and corresponds to the
/// sample whose transform/work record the vendor retains after lexicographic
/// evidence/geometry/quality selection.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Gf3258TerminalRecoveryAggregation {
    pub summary: Gf3258TerminalRecoverySummary,
    pub admitted_candidates: i32,
    pub selected_observation_index: Option<usize>,
}

/// Return the exact number of four-point penalties raw `FUN_001900b0` applies
/// to a recovery candidate's evidence after `0xaa480`.
///
/// The scale predicate is intentionally unsigned and wrapping:
/// `(u32(scale_q8) - 0xea) > 0x2f`. Therefore the no-penalty scale interval is
/// exactly `0xea..=0x119` (234..=281), not merely an upper-bound check.
#[inline]
pub(crate) const fn gf3258_terminal_recovery_affine_penalty_count(
    affine_scale_q8: i32,
    affine_orthogonality_q16: i32,
) -> i32 {
    let scale_penalty = ((affine_scale_q8 as u32).wrapping_sub(0xea) > 0x2f) as i32;
    let orthogonality_penalty = (affine_orthogonality_q16 > 0x147a) as i32;
    scale_penalty + orthogonality_penalty
}

/// Reproduce the GF3258 full-recovery aggregate in `FUN_001900b0` once each
/// candidate has reached the post-`0xa9a50` observation point.
///
/// Admission is strictly:
///
/// ```text
/// map_score > wrapping(map_score_base + 0xcf)
/// evidence  > 0xc3
/// ```
///
/// Admitted geometry counts are summed with i32 wrapping. `best_evidence` is
/// the maximum adjusted evidence, while `best_quality` belongs to the vendor's
/// selected candidate under the exact lexicographic order:
///
/// ```text
/// adjusted evidence -> geometry count -> scaled quality
/// ```
///
/// A candidate that reaches this observation point sets `had_candidate` even
/// if it fails the admission thresholds.
///
/// Crucially, the recovery work record is zero-filled before this scan, its
/// `+0x2c` field is never written, and raw `0x69290` has the already-proven
/// GF3258 global gate `field_2c <= 9 -> score 0`. Therefore the exact full
/// recovery `policy_score` is always zero for type `0x18`.
pub(crate) fn gf3258_terminal_recovery_aggregate(
    config: Gf3258TerminalRecoveryConfig,
    observations: &[Gf3258TerminalRecoveryObservation],
) -> Gf3258TerminalRecoveryAggregation {
    let mut accumulated_geometry_count = 0i32;
    let mut best_evidence = 0i32;
    let mut selected_evidence = 0i32;
    let mut selected_geometry = 0i32;
    let mut selected_quality = 0i32;
    let mut admitted_candidates = 0i32;
    let mut selected_observation_index = None;

    for (index, observation) in observations.iter().copied().enumerate() {
        let scaled_quality = config
            .quality_scale_q8
            .wrapping_mul(observation.coverage_q8)
            >> 8;

        if observation.map_score <= config.map_score_base.wrapping_add(0xcf)
            || observation.evidence <= 0xc3
        {
            continue;
        }

        let mut adjusted_evidence = observation.evidence;
        if config.apply_affine_penalty {
            adjusted_evidence = adjusted_evidence.wrapping_sub(4i32.wrapping_mul(
                gf3258_terminal_recovery_affine_penalty_count(
                    observation.affine_scale_q8,
                    observation.affine_orthogonality_q16,
                ),
            ));
        }

        accumulated_geometry_count =
            accumulated_geometry_count.wrapping_add(observation.geometry_count);
        if best_evidence < adjusted_evidence {
            best_evidence = adjusted_evidence;
        }

        if selected_evidence < adjusted_evidence
            || (selected_evidence == adjusted_evidence
                && (selected_geometry < observation.geometry_count
                    || (selected_geometry == observation.geometry_count
                        && selected_quality < scaled_quality)))
        {
            selected_evidence = adjusted_evidence;
            selected_geometry = observation.geometry_count;
            selected_quality = scaled_quality;
            selected_observation_index = Some(index);
        }

        admitted_candidates = admitted_candidates.wrapping_add(1);
    }

    Gf3258TerminalRecoveryAggregation {
        summary: Gf3258TerminalRecoverySummary {
            policy_score: 0,
            accumulated_geometry_count,
            had_candidate: !observations.is_empty(),
            best_evidence,
            best_quality: selected_quality,
        },
        admitted_candidates,
        selected_observation_index,
    }
}

/// Inputs to the GF3258 (`type == 0x18`) terminal score arbitration in
/// `FUN_001900b0`.
///
/// At the real GF3258 caller, `history_count` is verification-profile byte
/// zero (or zero when no profile is present), `matcher_state_688` is the final
/// normal-loop state word at `param_5 + 0x688`, and `auxiliary_class` is the
/// evolving mapped candidate mode at loop exit. `config_48` is
/// `param_4[0x12]` (byte offset `0x48`). The low-level names are retained so
/// direct terminal-policy fixtures can still exercise arbitrary values.
///
/// `cache_rescue_enabled` corresponds to template/group `+0x8e10 == 1`.
/// When it is enabled, `cache_rescue_hit` is the already-determined result of
/// raw `0x8e810`. The cache search itself is intentionally outside this helper;
/// this helper reproduces its exact score effect (miss => 0, hit => 10000).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Gf3258TerminalArbitrationInput {
    /// Score already present in `*param_1` when the terminal block begins.
    pub current_score: i32,
    /// Normal Q8-accumulator percentage, used by the accepted-current-policy path.
    pub normal_percent: i32,
    pub history_count: i32,
    pub matcher_state_688: i32,
    pub auxiliary_class: i32,
    pub accepted_samples: i32,
    pub config_48: i32,
    /// Current-work raw `0x69290` result. For GF3258 this is zero or positive.
    pub current_policy_score: i32,
    pub recovery: Gf3258TerminalRecoverySummary,
    pub cache_rescue_enabled: bool,
    pub cache_rescue_hit: bool,
}

/// GF3258 terminal-arbitration inputs excluding the full-recovery summary.
/// Use `gf3258_terminal_arbitrate_score_from_recovery_observations` when the
/// caller has exact post-geometry recovery observations and should not supply
/// or synthesize a `Gf3258TerminalRecoverySummary` itself.
#[cfg(test)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Gf3258TerminalArbitrationCoreInput {
    pub current_score: i32,
    pub normal_percent: i32,
    pub history_count: i32,
    pub matcher_state_688: i32,
    pub auxiliary_class: i32,
    pub accepted_samples: i32,
    pub config_48: i32,
    pub current_policy_score: i32,
    pub cache_rescue_enabled: bool,
    pub cache_rescue_hit: bool,
}

/// Which exact GF3258 terminal family produced the returned signed score.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Gf3258TerminalScoreDisposition {
    /// A non-zero score already existed and the terminal retention gate kept it.
    RetainedCurrentScore,
    /// Terminal gates returned the current score (which can have been suppressed to zero).
    TerminalGateExit,
    /// Accepted samples plus a positive current-work `0x69290` result restored
    /// the normal accumulator percentage.
    RestoredNormalPercent,
    /// Full recovery produced a positive policy score, capped at 100.
    RecoveryPositive,
    /// Full recovery produced the exact zero/negative reason-mask result.
    RecoveryNonPositive,
    /// Optional raw `0x8e810` ran and did not find a cache-rescue match.
    CacheRescueMiss,
    /// Optional raw `0x8e810` found a cache-rescue match and emitted 10000.
    CacheRescueMatch,
}

/// Exact externally relevant result of GF3258 terminal score arbitration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Gf3258TerminalArbitrationResult {
    pub score: i32,
    pub disposition: Gf3258TerminalScoreDisposition,
    /// Raw `FUN_001900b0` sets matcher-state `+0x684 = 1` only when the full
    /// recovery path itself yields a positive policy score.
    pub mark_recovery_success: bool,
}

/// Reproduce the GF3258 terminal score arbitration in `FUN_001900b0` once the
/// normal accumulator percentage and full-recovery summary are already known.
///
/// For type `0x18`, the generic `-0x20` terminal family is unreachable: the
/// vendor type gate always selects the normal/recovery family before that
/// write. Therefore this function's core signed domain is the retained/restored
/// normal percentage, recovery `1..=100`, or fallback `0/-1..=-7`. If the
/// optional cache-rescue feature is enabled, raw `0x8e810` replaces a
/// non-positive fallback with exactly `0` (miss) or `10000` (hit).
#[inline]
pub(crate) const fn gf3258_terminal_arbitrate_score(
    input: Gf3258TerminalArbitrationInput,
) -> Gf3258TerminalArbitrationResult {
    let mut score = input.current_score;

    if input.history_count < 6 || input.matcher_state_688 != 0 {
        if score != 0 {
            return Gf3258TerminalArbitrationResult {
                score,
                disposition: Gf3258TerminalScoreDisposition::RetainedCurrentScore,
                mark_recovery_success: false,
            };
        }
    } else {
        score = 0;
    }

    // GF3258 config +0x34 / param_4[0xd] is proven to be 1. The generic
    // template-type subgate is also always true for type 0x18, so only these
    // two caller-local thresholds remain before recovery arbitration.
    if input.auxiliary_class >= 4 || input.history_count >= 2 {
        return Gf3258TerminalArbitrationResult {
            score,
            disposition: Gf3258TerminalScoreDisposition::TerminalGateExit,
            mark_recovery_success: false,
        };
    }

    if input.accepted_samples > 0 && input.config_48 == 0 && input.current_policy_score != 0 {
        return Gf3258TerminalArbitrationResult {
            score: input.normal_percent,
            disposition: Gf3258TerminalScoreDisposition::RestoredNormalPercent,
            mark_recovery_success: false,
        };
    }

    score = gf3258_finalize_vendor_fallback_score(
        input.recovery.policy_score,
        input.recovery.accumulated_geometry_count,
        input.recovery.had_candidate,
        input.recovery.best_evidence,
        input.recovery.best_quality,
    );

    if score > 0 {
        return Gf3258TerminalArbitrationResult {
            score,
            disposition: Gf3258TerminalScoreDisposition::RecoveryPositive,
            mark_recovery_success: true,
        };
    }

    if input.cache_rescue_enabled {
        if input.cache_rescue_hit {
            return Gf3258TerminalArbitrationResult {
                score: GF3258_CACHE_RESCUE_MATCH_SCORE,
                disposition: Gf3258TerminalScoreDisposition::CacheRescueMatch,
                mark_recovery_success: false,
            };
        }
        return Gf3258TerminalArbitrationResult {
            score: 0,
            disposition: Gf3258TerminalScoreDisposition::CacheRescueMiss,
            mark_recovery_success: false,
        };
    }

    Gf3258TerminalArbitrationResult {
        score,
        disposition: Gf3258TerminalScoreDisposition::RecoveryNonPositive,
        mark_recovery_success: false,
    }
}

/// Run exact GF3258 terminal arbitration with the recovery summary generated
/// internally from post-geometry recovery observations.
///
/// The recovery summary is generated from post-geometry observations before
/// terminal arbitration. The optional `0xb16e0` matcher-geometry refit is
/// handled by the recovery observation producer.
#[cfg(test)]
pub(crate) fn gf3258_terminal_arbitrate_score_from_recovery_observations(
    input: Gf3258TerminalArbitrationCoreInput,
    recovery_config: Gf3258TerminalRecoveryConfig,
    observations: &[Gf3258TerminalRecoveryObservation],
) -> Gf3258TerminalArbitrationResult {
    let recovery = gf3258_terminal_recovery_aggregate(recovery_config, observations).summary;
    gf3258_terminal_arbitrate_score(Gf3258TerminalArbitrationInput {
        current_score: input.current_score,
        normal_percent: input.normal_percent,
        history_count: input.history_count,
        matcher_state_688: input.matcher_state_688,
        auxiliary_class: input.auxiliary_class,
        accepted_samples: input.accepted_samples,
        config_48: input.config_48,
        current_policy_score: input.current_policy_score,
        recovery,
        cache_rescue_enabled: input.cache_rescue_enabled,
        cache_rescue_hit: input.cache_rescue_hit,
    })
}

/// Exact outputs of raw `FUN_001ab920` for the mode word stored at matcher
/// configuration `+0x48`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Gf3258RawModeFields {
    pub low: i32,
    pub high: i32,
}

/// Raw `FUN_001ab920`: preserve the low two bits and decode bits 8..10 into
/// the caller's sparse high-mode domain (`0` or `5..=11`).
#[inline]
pub(crate) const fn gf3258_raw_mode_fields(config_48: i32) -> Gf3258RawModeFields {
    let low = (config_48 as u32 & 3) as i32;
    let high_bits = (config_48 >> 8) & 7;
    let high = if high_bits == 0 { 0 } else { high_bits + 4 };
    Gf3258RawModeFields { low, high }
}

#[inline]
const fn gf3258_ab860_table_mode(value: i32) -> i32 {
    match value {
        1 | 2 => 2,
        3 => 3,
        4 => 0,
        5 => 1,
        6 => 2,
        7 => 4,
        8 | 9 => 5,
        _ => 0,
    }
}

/// Exact outputs of raw `FUN_001ab860`: apply the recovered nine-entry mode
/// table to both `FUN_001ab920` outputs.
#[inline]
pub(crate) const fn gf3258_mapped_mode_fields(config_48: i32) -> Gf3258RawModeFields {
    let raw = gf3258_raw_mode_fields(config_48);
    Gf3258RawModeFields {
        low: gf3258_ab860_table_mode(raw.low),
        high: gf3258_ab860_table_mode(raw.high),
    }
}

/// Recovery-loop `0x6ad30` mode. Raw `FUN_001900b0` calls `0xab860` again at
/// `0x93043` and stores `max(mapped_low, mapped_high)` before scanning the
/// recovery-eligible samples. It is not an independent caller input.
#[inline]
pub(crate) const fn gf3258_terminal_recovery_exclusion_mode_from_config_48(config_48: i32) -> i32 {
    let modes = gf3258_mapped_mode_fields(config_48);
    if modes.low >= modes.high {
        modes.low
    } else {
        modes.high
    }
}

/// Exact type-0x18 model of raw `FUN_00173880`, which initializes matcher state
/// `+0x68c` when live `Feature+0x13c` is nonzero.
///
/// The caller itself supplies `1` when the live scalar is zero; use
/// [`gf3258_normal_loop_initial_state_68c`] for the complete caller behavior.
pub(crate) fn gf3258_state_68c_from_scalar_13c(
    live_scalar_13c: i32,
    enrolled_samples: &[Gf3258PersistedSample],
) -> i32 {
    let original_bit0 = (live_scalar_13c as u32) & 1;
    let mut value = live_scalar_13c;
    let mut threshold = 0x1000i32;

    if (value as u32 & 0x8000) != 0 {
        value = value.wrapping_sub(0x8000);
        threshold = 0x09c4;
    }
    if value < 0 {
        return 0;
    }

    if original_bit0 == 0 {
        let mut high = value >> 16;
        let low = ((value as u32 & 0xffff) >> 1) as i32;
        let combined = if (value as u32 & 0x2000_0000) != 0 {
            high = high.wrapping_sub(0x2000);
            low.wrapping_sub(high)
        } else {
            low.wrapping_add(high)
        };
        return if combined >= 0x191 { 3 } else { 0 };
    }

    let live_value = value >> 1;
    let base: i32 = if live_value > 0x190 { 2 } else { 0 };
    let mut count = 0i32;
    let mut sum = 0i32;
    for sample in enrolled_samples {
        let raw = sample.scalar_13c as u32;
        let sample_value = ((raw & 0x7fff) >> 1) as i32;
        if sample_value != 0 && (raw & 1) != 0 {
            sum = sum.wrapping_add(sample_value);
            count = count.wrapping_add(1);
        }
    }

    if !enrolled_samples.is_empty()
        && (count.wrapping_mul(2) as u32) > enrolled_samples.len() as u32
    {
        let average = sum.wrapping_add(count >> 1) / count;
        let difference = average.wrapping_sub(live_value);
        let window = difference.wrapping_add(0x190) as u32;
        return base.wrapping_add((window < 0x321) as i32);
    }

    if live_value >= threshold {
        base
    } else {
        base.wrapping_add((live_value > 0x190) as i32)
    }
}

/// Complete caller initialization of matcher state `+0x68c`.
#[inline]
pub(crate) fn gf3258_normal_loop_initial_state_68c(
    live_scalar_13c: i32,
    enrolled_samples: &[Gf3258PersistedSample],
) -> i32 {
    if live_scalar_13c == 0 {
        1
    } else {
        gf3258_state_68c_from_scalar_13c(live_scalar_13c, enrolled_samples)
    }
}

/// Exact configuration fields consumed by the type-0x18 normal-loop
/// recovery/state producer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Gf3258NormalLoopRecoveryConfig {
    /// Matcher configuration `+0x10`; nonzero participates in the retained
    /// multi-sample continuation mode (`bVar60`).
    pub config_10: i32,
    /// Matcher configuration `+0x34` / `param_4[0x0d]`. Recovery eligibility
    /// requires equality to exactly `1`.
    pub config_34: i32,
    /// Packed mode word at matcher configuration `+0x48`.
    pub config_48: i32,
}

/// Configuration required to reproduce the normal caller's sample-loop gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Gf3258NormalLoopConfig {
    pub recovery: Gf3258NormalLoopRecoveryConfig,
    /// Matcher configuration `+0x38`, used as the selected sample index when
    /// `config_34` is zero.
    pub config_38: i32,
    /// Persisted template `+0x28`.
    pub configured_max_samples: usize,
}

/// Optional 40x32 verification-profile raster used by `FUN_001900b0`.
///
/// Raw `FUN_001ab8c0` interprets the first six bytes as six scalar controls.
/// When byte zero is greater than two, raw `FUN_001a9a50` also consumes the
/// same 40x32 byte buffer as the optional profile-agreement raster.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Gf3258VerificationProfile<'a> {
    pub raster: &'a [u8; GF3258_REGISTRATION_PIXELS],
}

impl Gf3258VerificationProfile<'_> {
    #[inline]
    pub fn value(self, index: usize) -> i32 {
        i32::from(self.raster[index])
    }

    #[inline]
    pub fn mode(self) -> i32 {
        self.value(0)
    }

    #[inline]
    pub fn auxiliary_mode(self) -> i32 {
        self.value(3)
    }
}

/// Live feature scalars that remain outside the matcher-point projection but
/// are consumed by the normal GF3258 policy chain.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Gf3258NormalPolicyLiveInput<'a> {
    /// Live `Feature+0x18`, used by `FUN_001aa350`.
    pub low_threshold_registration_map: &'a [u8; GF3258_REGISTRATION_PACKED_BYTES],
    /// Live `Feature+0x10c`.
    pub quality: i32,
    /// Live `Feature+0x110`.
    pub coverage: i32,
    /// Live `Feature+0x158` from the already-prepared verification feature.
    /// `FUN_001900b0` reads this field directly; it does not derive or mutate
    /// it from verification-profile byte one.
    pub scalar_158: i32,
}

/// Runtime matcher configuration consumed by the normal-policy path.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Gf3258NormalPolicyConfig {
    pub config_00: i32,
    pub config_04: i32,
    pub config_3c: i32,
    pub config_48: i32,
    /// Raw `config+0x50`. Values one and two suppress `FUN_001aabd0`.
    pub config_50: i32,
}

/// Caller comparison floor constructed once by `FUN_001900b0`. The same
/// `config+0x00 + 0xcf` value controls optional fallback preparation and the
/// later post-survival score-path rescue predicate.
#[inline]
pub(crate) const fn gf3258_normal_policy_rescue_floor(config_00: i32) -> i32 {
    config_00.wrapping_add(0xcf)
}

/// Genuine evolving caller-loop state needed to compose one sample's policy.
/// The gallery loop owns mutation of these values; they are not properties of
/// a persisted sample or of the live feature alone.
#[cfg(test)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Gf3258NormalPolicyLoopState {
    pub mapped_candidate_mode: i32,
    pub reject_count: i32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Gf3258SamplePolicyLoopState {
    mapped_candidate_mode: i32,
    profile_state: i32,
    reject_count: i32,
}

#[cfg(test)]
impl Gf3258NormalPolicyLoopState {
    /// Apply the per-sample `+0x140 -> ab860` mode contribution used by the
    /// GF3258 caller before the scalar policy helpers. This lower-level
    /// projection does not own the caller's reject-count promotion; the
    /// stateful evaluator resolves that earlier transition separately.
    fn for_sample(self, sample: &Gf3258PersistedSample) -> Gf3258SamplePolicyLoopState {
        let embedded = gf3258_mapped_mode_fields(sample.embedded_state_140.unwrap_or(0)).high;
        let profile_state = self.mapped_candidate_mode.wrapping_add(embedded).min(5);
        let mapped_candidate_mode = if embedded > 3 && embedded > self.mapped_candidate_mode {
            embedded
        } else {
            self.mapped_candidate_mode
        };
        Gf3258SamplePolicyLoopState {
            mapped_candidate_mode,
            profile_state,
            reject_count: self.reject_count,
        }
    }
}

/// Policy-facing mutable work state. Geometry decisions were already made in
/// [`Gf3258PersistedVerificationWork`]; this snapshot may later be refreshed by
/// `FUN_001aabd0` without retroactively changing those earlier decisions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Gf3258NormalPolicyWorkSnapshot {
    pub record: Gf3258VerificationWorkRecord,
    pub map_field_1c: i32,
    pub map_field_20: i32,
    pub live_quality: i32,
    pub live_coverage: i32,
    pub enrolled_quality: i32,
    pub axis_deviation_degrees: i32,
}

impl Gf3258NormalPolicyWorkSnapshot {
    fn pre_tail_record(self) -> Gf3258PreTailPolicyRecord {
        Gf3258PreTailPolicyRecord {
            geometry_count: self.record.geometry_count,
            verification_metric: self.record.verification_metric,
            map_score: self.record.map_score,
            evidence: self.record.evidence,
            field_20: 0,
            scaled_coverage_q8: self.record.scaled_coverage_q8,
            matched_percent: self.record.matched_percent,
            geometry_percent: self.record.geometry_percent,
            orthogonality_penalty: self.record.orthogonality_penalty,
            severe_orthogonality: self.record.severe_orthogonality,
            live_quality: self.live_quality,
            enrolled_quality: self.enrolled_quality,
        }
    }

    fn preparation_record(self) -> Gf3258PolicyPreparationRecord {
        Gf3258PolicyPreparationRecord {
            geometry_count: self.record.geometry_count,
            verification_metric: self.record.verification_metric,
            evidence: self.record.evidence,
            scaled_coverage_q8: self.record.scaled_coverage_q8,
            matched_percent: self.record.matched_percent,
            geometry_percent: self.record.geometry_percent,
            scale_penalty: self.record.scale_penalty,
            orthogonality_penalty: self.record.orthogonality_penalty,
            severe_orthogonality: self.record.severe_orthogonality,
        }
    }

    fn flag_record(self) -> Gf3258VerificationFlagPolicyRecord {
        Gf3258VerificationFlagPolicyRecord {
            geometry_count_00: self.record.geometry_count,
            metric_04: self.record.verification_metric,
            field_10: self.record.map_score,
            field_14: self.record.evidence,
            field_20: self.map_field_20,
            field_24: self.record.scaled_coverage_q8,
            field_28: self.record.matched_percent,
            field_2c: self.record.geometry_percent,
            field_30: self.record.scale_penalty,
            field_34: self.record.orthogonality_penalty,
            field_38: self.record.severe_orthogonality,
            live_scalar_54: self.live_quality,
            field_58: self.live_coverage,
            enrolled_scalar_5c: self.enrolled_quality,
        }
    }

    fn late_record(self) -> Gf3258LatePolicyRecord {
        Gf3258LatePolicyRecord {
            geometry_count_00: self.record.geometry_count,
            metric_04: self.record.verification_metric,
            field_10: self.record.map_score,
            field_14: self.record.evidence,
            field_20: self.map_field_20,
            field_24: self.record.scaled_coverage_q8,
            field_28: self.record.matched_percent,
            field_2c: self.record.geometry_percent,
            field_34: self.record.orthogonality_penalty,
            field_38: self.record.severe_orthogonality,
            live_scalar_54: self.live_quality,
            enrolled_scalar_5c: self.enrolled_quality,
            field_64: self.axis_deviation_degrees,
        }
    }

    fn post_survival_record(self) -> Gf3258PostSurvivalPolicyRecord {
        Gf3258PostSurvivalPolicyRecord {
            geometry_count_00: self.record.geometry_count,
            metric_04: self.record.verification_metric,
            field_10: self.record.map_score,
            field_14: self.record.evidence,
            field_1c: self.map_field_1c,
            field_20: self.map_field_20,
            field_24: self.record.scaled_coverage_q8,
            field_28: self.record.matched_percent,
            field_2c: self.record.geometry_percent,
            field_30: self.record.scale_penalty,
            field_34: self.record.orthogonality_penalty,
            field_38: self.record.severe_orthogonality,
            live_scalar_54: self.live_quality,
            enrolled_scalar_5c: self.enrolled_quality,
            field_64: self.axis_deviation_degrees,
        }
    }

    fn final_veto_record(self) -> Gf3258FinalSampleVetoRecord {
        Gf3258FinalSampleVetoRecord {
            geometry_count_00: self.record.geometry_count,
            metric_04: self.record.verification_metric,
            field_14: self.record.evidence,
            field_20: self.map_field_20,
            field_24: self.record.scaled_coverage_q8,
            field_28: self.record.matched_percent,
            field_2c: self.record.geometry_percent,
        }
    }

    fn score_policy_record(self) -> Gf3258VerificationPolicyRecord {
        Gf3258VerificationPolicyRecord {
            geometry_count_00: self.record.geometry_count,
            metric_04: self.record.verification_metric,
            field_10: self.record.map_score,
            field_14: self.record.evidence,
            field_20: self.map_field_20,
            field_24: self.record.scaled_coverage_q8,
            field_2c: self.record.geometry_percent,
            penalty_30: self.record.scale_penalty,
            penalty_34: self.record.orthogonality_penalty,
            penalty_38: self.record.severe_orthogonality,
            live_scalar_54: self.live_quality,
            enrolled_scalar_5c: self.enrolled_quality,
        }
    }
}

/// Diagnostics retained by the complete per-sample policy composer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Gf3258PersistedSampleNormalPolicyResult {
    pub sample_input: Gf3258NormalLoopSampleInput,
    pub policy_work: Gf3258NormalPolicyWorkSnapshot,
    pub profile_agreement: Gf3258ProfileAgreementCounts,
    pub preparation: Option<Gf3258PolicyPreparation>,
    /// Affine produced by `FUN_001aa830` when `FUN_001aabd0` actually replaced
    /// the mutable work evidence/quality snapshot. The caller policy affine is
    /// unchanged regardless of whether this field is present.
    pub fallback_refresh_affine: Option<Gf3258AffineQ8>,
    pub map_evidence: Option<Gf3258VerificationMapEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Gf3258PersistedSampleNormalPolicyError {
    VerificationWork(Gf3258PersistedVerificationWorkError),
    /// Current persisted GF3258 templates carry `Feature+0x18`. Older decoded
    /// samples may omit it; that is only an error when `0x65700` does not
    /// bypass the `0xaa350` refinement that consumes the map.
    MissingLowThresholdRegistrationMap,
}

impl std::fmt::Display for Gf3258PersistedSampleNormalPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VerificationWork(error) => std::fmt::Display::fmt(error, f),
            Self::MissingLowThresholdRegistrationMap => f.write_str(
                "GF3258 verification sample is missing its low-threshold registration map",
            ),
        }
    }
}

impl std::error::Error for Gf3258PersistedSampleNormalPolicyError {}

impl From<Gf3258PersistedVerificationWorkError> for Gf3258PersistedSampleNormalPolicyError {
    fn from(value: Gf3258PersistedVerificationWorkError) -> Self {
        Self::VerificationWork(value)
    }
}

#[derive(Debug, Clone, Copy)]
struct Gf3258ResolvedPersistedSampleNormalPolicyInput<'a> {
    registration: Gf3258VerificationRegistrationInput<'a>,
    sample_config: Gf3258VerificationSampleConfig,
    live_policy: Gf3258NormalPolicyLiveInput<'a>,
    profile: Option<Gf3258VerificationProfile<'a>>,
    loop_state: Gf3258SamplePolicyLoopState,
    config: Gf3258NormalPolicyConfig,
}

#[allow(clippy::too_many_lines)]
fn gf3258_persisted_sample_normal_policy_from_work(
    sample: &Gf3258PersistedSample,
    live: &Gf3258OwnedVerificationMatcherFeature,
    input: Gf3258ResolvedPersistedSampleNormalPolicyInput<'_>,
    work: &Gf3258PersistedVerificationWork,
) -> Result<Gf3258PersistedSampleNormalPolicyResult, Gf3258PersistedSampleNormalPolicyError> {
    let policy_transform = work.policy_transform_live_to_enrolled;

    // FUN_001900b0 recomputes the policy-facing a9a50/aa480 snapshot after
    // 0x72700/0x70a80. Do not reuse the intermediate registration bundle from
    // the geometry producer here.
    let final_registration = gf3258_verification_registration_evidence(
        sample,
        input.registration,
        policy_transform,
        input.sample_config.quality_scale_q8,
    );
    let mut policy_work = Gf3258NormalPolicyWorkSnapshot {
        record: work.record,
        map_field_1c: 0,
        map_field_20: 0,
        live_quality: input.live_policy.quality,
        live_coverage: input.live_policy.coverage,
        enrolled_quality: sample.c2d40_param3,
        axis_deviation_degrees: gf3258_affine_axis_deviation_degrees(policy_transform),
    };
    policy_work.record.map_score = final_registration.map_score;
    policy_work.record.evidence = final_registration.evidence;
    policy_work.record.scaled_coverage_q8 = final_registration.scaled_coverage_q8;
    policy_work.record.scale_penalty = final_registration.scale_penalty();
    policy_work.record.orthogonality_penalty = final_registration.orthogonality_penalty();
    policy_work.record.severe_orthogonality = final_registration.severe_orthogonality();

    let profile_mode = input.profile.map_or(0, Gf3258VerificationProfile::mode);
    let profile_auxiliary_mode = input
        .profile
        .map_or(0, Gf3258VerificationProfile::auxiliary_mode);
    let profile_agreement = match input.profile {
        Some(profile) if profile_mode > 2 => gf3258_profile_agreement_counts(
            profile.raster,
            input.registration.quarter_validity_packed,
            policy_transform,
        ),
        _ => Gf3258ProfileAgreementCounts::default(),
    };
    let loop_state = input.loop_state;

    if gf3258_pre_tail_policy_rejects(
        policy_work.pre_tail_record(),
        Gf3258PreTailPolicyContext {
            mapped_mode: loop_state.mapped_candidate_mode,
            profile_mode,
            auxiliary_mode: profile_auxiliary_mode,
            agreement: profile_agreement,
        },
    ) {
        return Ok(Gf3258PersistedSampleNormalPolicyResult {
            sample_input: work.normal_loop_sample_input(
                Gf3258NormalLoopPostGeometryDisposition::RejectedBeforeCallerTail,
            ),
            policy_work,
            profile_agreement,
            preparation: None,
            fallback_refresh_affine: None,
            map_evidence: None,
        });
    }

    let preparation = gf3258_policy_preparation(
        policy_work.preparation_record(),
        Gf3258PolicyPreparationContext {
            live_quality: input.live_policy.quality,
            live_coverage: input.live_policy.coverage,
            config_00: input.config.config_00,
            config_04: input.config.config_04,
            config_3c: input.config.config_3c,
        },
    );

    // The caller forms this once as config+0x00 + 0xcf and reuses it for
    // both fallback preparation and the post-survival rescue predicate.
    let rescue_floor = gf3258_normal_policy_rescue_floor(input.config.config_00);
    let fallback_requested = preparation.tier == 0
        || preparation.gate == 0
        || policy_work.record.map_score < rescue_floor;
    let fallback_refresh_affine = if fallback_requested && !matches!(input.config.config_50, 1 | 2)
    {
        rescue_geometry::gf3258_refresh_fallback_policy_work(
            &mut policy_work.record,
            sample,
            live,
            input.registration,
            input.sample_config.quality_scale_q8,
            policy_transform,
        )
    } else {
        None
    };

    let flag_context = Gf3258VerificationFlagPolicyContext {
        scalar_43: input.live_policy.quality,
        scalar_44: input.live_policy.coverage,
        candidate_state: loop_state.mapped_candidate_mode,
        config_00: input.config.config_00,
        config_04: input.config.config_04,
        config_48: input.config.config_48,
    };
    let pre_flag_record = policy_work.flag_record();
    let prepass = gf3258_verification_flag_prepass(pre_flag_record, flag_context);
    let flag_result = if prepass.bypass_refinement {
        Gf3258VerificationFlagPolicyHalfResolutionResult {
            flags: prepass.flags,
            auxiliary_flag: prepass.auxiliary_flag,
            bypassed_refinement: true,
            map_evidence: None,
            post_refinement_record: pre_flag_record,
        }
    } else {
        let enrolled_low_threshold = sample
            .low_threshold_registration_map
            .as_ref()
            .ok_or(Gf3258PersistedSampleNormalPolicyError::MissingLowThresholdRegistrationMap)?;
        gf3258_verification_flag_policy_half_resolution(
            pre_flag_record,
            flag_context,
            input.live_policy.low_threshold_registration_map,
            enrolled_low_threshold,
            input.registration.quarter_validity_packed,
            &sample.quarter_validity_packed,
            policy_transform,
        )
    };
    if let Some(evidence) = flag_result.map_evidence {
        policy_work.map_field_1c = evidence.field_1c;
        policy_work.map_field_20 = evidence.field_20;
    }

    let ratio_inputs = Gf3258PostSurvivalRatioInputs {
        slot_224: profile_agreement.both_zero,
        slot_228: profile_agreement.mixed,
        slot_22c: profile_agreement.both_one,
    };
    let tail = gf3258_verification_caller_tail(
        flag_result.bypassed_refinement,
        flag_result.auxiliary_flag,
        policy_work.map_field_20,
        flag_result.flags,
        policy_work.late_record(),
        Gf3258LatePolicyContext {
            live_quality: input.live_policy.quality,
            history_low: loop_state.mapped_candidate_mode,
            history_high: profile_mode,
            profile_state: loop_state.profile_state,
            current_reject_count: loop_state.reject_count,
        },
        policy_transform,
        ratio_inputs,
        policy_work.post_survival_record(),
        Gf3258PostSurvivalPolicyContext {
            scalar_43: input.live_policy.quality,
            scalar_56: input.live_policy.scalar_158,
            candidate_state: loop_state.mapped_candidate_mode,
            mode_value: profile_mode,
            ratio_q8: 0,
        },
        rescue_floor,
        policy_work.final_veto_record(),
        Gf3258FinalSampleVetoContext {
            enrolled_status_114: sample.status_114,
            live_scalar_43: input.live_policy.quality,
            live_scalar_56: input.live_policy.scalar_158,
        },
    );

    Ok(Gf3258PersistedSampleNormalPolicyResult {
        sample_input: work
            .normal_loop_sample_input(Gf3258NormalLoopPostGeometryDisposition::CallerTail(tail)),
        policy_work,
        profile_agreement,
        preparation: Some(preparation),
        fallback_refresh_affine,
        map_evidence: flag_result.map_evidence,
    })
}

/// Branch after a sample has passed the early geometry/quality gates and the
/// normal-loop `0x6ad30` exclusion. `RejectedBeforeCallerTail` covers raw
/// branches such as nonzero `0x69740` that jump directly to the next sample;
/// those branches are state-equivalent for `+0x684/+0x688` and recovery
/// eligibility. `CallerTail` carries the already-composed caller-tail result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Gf3258NormalLoopPostGeometryDisposition {
    RejectedBeforeCallerTail,
    CallerTail(Gf3258VerificationCallerTailResult),
}

/// One sample in the normal-loop order seen by `FUN_001900b0`.
///
/// `caller_processes_sample=false` represents the earlier caller skip gates
/// (selected-slot filtering and the `+0x644/+0x100/+0x688` skip family). Those
/// gates are not recovery-specific; explicitly carrying the branch prevents
/// this producer from silently assuming every persisted sample is processed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Gf3258NormalLoopRecoverySampleInput {
    pub caller_processes_sample: bool,
    pub primary_704f0_count: i32,
    pub rescue_704f0_count: i32,
    pub quality_28: i32,
    pub quality_134: i32,
    pub transform_live_to_enrolled: Gf3258AffineQ8,
    pub post_geometry: Gf3258NormalLoopPostGeometryDisposition,
}

impl Default for Gf3258NormalLoopRecoverySampleInput {
    fn default() -> Self {
        Self {
            caller_processes_sample: true,
            primary_704f0_count: 0,
            rescue_704f0_count: 0,
            quality_28: 0,
            quality_134: 0,
            transform_live_to_enrolled: Gf3258AffineQ8::IDENTITY,
            post_geometry: Gf3258NormalLoopPostGeometryDisposition::RejectedBeforeCallerTail,
        }
    }
}

/// One processed-candidate observation in persisted-sample order. Caller skip
/// decisions are derived internally by [`gf3258_normal_loop_state`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Gf3258NormalLoopSampleInput {
    pub primary_704f0_count: i32,
    pub rescue_704f0_count: i32,
    pub quality_28: i32,
    pub quality_134: i32,
    pub transform_live_to_enrolled: Gf3258AffineQ8,
    pub post_geometry: Gf3258NormalLoopPostGeometryDisposition,
}

impl Default for Gf3258NormalLoopSampleInput {
    fn default() -> Self {
        Self {
            primary_704f0_count: 0,
            rescue_704f0_count: 0,
            quality_28: 0,
            quality_134: 0,
            transform_live_to_enrolled: Gf3258AffineQ8::IDENTITY,
            post_geometry: Gf3258NormalLoopPostGeometryDisposition::RejectedBeforeCallerTail,
        }
    }
}

impl From<Gf3258NormalLoopSampleInput> for Gf3258NormalLoopRecoverySampleInput {
    fn from(value: Gf3258NormalLoopSampleInput) -> Self {
        Self {
            caller_processes_sample: true,
            primary_704f0_count: value.primary_704f0_count,
            rescue_704f0_count: value.rescue_704f0_count,
            quality_28: value.quality_28,
            quality_134: value.quality_134,
            transform_live_to_enrolled: value.transform_live_to_enrolled,
            post_geometry: value.post_geometry,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Gf3258NormalLoopStopReason {
    /// The pre-sample reject-counter gate exits when the count is greater than
    /// ten after the candidate-state/bVar59 condition has become active.
    RejectCountLimit,
    /// A nonzero score gate terminates the normal sample loop unless retained
    /// multi-sample continuation mode (`bVar60`) is active.
    ScoreGate,
}

/// Exact recovery-relevant state produced by the GF3258 normal sample loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Gf3258NormalLoopRecoveryState {
    pub eligible_samples: Vec<bool>,
    /// `+0x644` immediately after the normal sample loop.
    pub post_normal_loop_state_644: i32,
    /// Exact Q8 score accumulator and accepted-sample count at loop exit.
    pub score: Gf3258VerificationScoreAccumulator,
    /// Current value of the caller-provided signed score slot at normal-loop exit.
    /// Raw `FUN_001900b0` writes the running normal percentage to this slot
    /// whenever the score gate is active; the wrapper's initial zero is not
    /// necessarily the value seen by terminal arbitration.
    pub current_score: i32,
    /// `+0x684` immediately after the normal sample loop. Later terminal
    /// policy code can modify this field again; this is deliberately not named
    /// as final matcher state.
    pub post_normal_loop_state_684: i32,
    /// `+0x688` immediately after the normal sample loop, including the exact
    /// `!bVar60 -> 0` clear. Later terminal policy can clear it again.
    pub post_normal_loop_state_688: i32,
    pub matcher_state_68c: i32,
    pub reject_count: i32,
    pub candidate_state: i32,
    pub continuation_mode: bool,
    pub processed_samples: usize,
    pub stop_before_sample: Option<usize>,
    pub stop_reason: Option<Gf3258NormalLoopStopReason>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Gf3258NormalLoopRecoveryStateError {
    #[cfg(test)]
    ObservationLengthMismatch {
        samples: usize,
        observations: usize,
    },
    InvalidConfiguredSampleLimit {
        samples: usize,
        configured_max_samples: usize,
    },
    MissingAcceptedContribution {
        sample_index: usize,
    },
    RejectCountMismatch {
        sample_index: usize,
        expected: i32,
        actual: i32,
    },
    OutOfDomainRatio {
        sample_index: usize,
    },
}

impl std::fmt::Display for Gf3258NormalLoopRecoveryStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(test)]
            Self::ObservationLengthMismatch {
                samples,
                observations,
            } => write!(
                f,
                "GF3258 normal loop has {samples} samples but {observations} sample observations"
            ),
            Self::InvalidConfiguredSampleLimit {
                samples,
                configured_max_samples,
            } => write!(
                f,
                "GF3258 normal loop has {samples} samples but configured maximum is {configured_max_samples}"
            ),
            Self::MissingAcceptedContribution { sample_index } => write!(
                f,
                "GF3258 normal-loop sample {sample_index} is accepted without a Q8 score contribution"
            ),
            Self::RejectCountMismatch {
                sample_index,
                expected,
                actual,
            } => write!(
                f,
                "GF3258 normal-loop sample {sample_index} has reject count {actual}, expected {expected}"
            ),
            Self::OutOfDomainRatio { sample_index } => write!(
                f,
                "GF3258 normal-loop sample {sample_index} reached the synthetic zero-denominator ratio state"
            ),
        }
    }
}

impl std::error::Error for Gf3258NormalLoopRecoveryStateError {}

/// Observable state surrounding one persisted-sample transition in the
/// normal GF3258 caller loop.
///
/// Unlike [`Gf3258NormalLoopRecoveryState`], this is an in-loop snapshot: it
/// does not apply the caller's post-loop `!continuation_mode -> state_688 = 0`
/// normalization. That distinction lets the per-template evaluator expose the
/// state that actually feeds the next sample.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Gf3258NormalLoopSampleState {
    pub matcher_state_644: i32,
    pub matcher_state_684: i32,
    pub matcher_state_688: i32,
    pub matcher_state_68c: i32,
    pub reject_count: i32,
    pub candidate_state: i32,
    pub candidate_bump_active: bool,
    pub continuation_mode: bool,
    pub score: Gf3258VerificationScoreAccumulator,
    pub processed_samples: usize,
    pub stop_before_sample: Option<usize>,
    pub stop_reason: Option<Gf3258NormalLoopStopReason>,
}

/// Policy configuration that is genuinely independent of the normal-loop
/// state machine for one persisted-sample evaluation.
///
/// Matcher `config+0x48` is intentionally absent: the caller uses the same
/// packed mode word for both normal-loop state and scalar policy, so the
/// stateful evaluator derives it from [`Gf3258NormalLoopConfig`] rather than
/// allowing two caller-supplied values to diverge.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Gf3258PersistedSampleEvaluationPolicyConfig {
    pub config_00: i32,
    pub config_04: i32,
    pub config_3c: i32,
    pub config_50: i32,
}

impl Gf3258PersistedSampleEvaluationPolicyConfig {
    #[inline]
    const fn normal_policy(self, config_48: i32) -> Gf3258NormalPolicyConfig {
        Gf3258NormalPolicyConfig {
            config_00: self.config_00,
            config_04: self.config_04,
            config_3c: self.config_3c,
            config_48,
            config_50: self.config_50,
        }
    }
}

/// Per-template inputs that do not belong to the evolving caller loop.
///
/// The stateful evaluator supplies the live loop state and packed mode word
/// itself. Callers no longer construct [`Gf3258NormalLoopSampleInput`] or
/// recovery observations at this boundary.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Gf3258PersistedSampleEvaluationInput<'a> {
    pub registration: Gf3258VerificationRegistrationInput<'a>,
    pub sample_config: Gf3258VerificationSampleConfig,
    pub live_policy: Gf3258NormalPolicyLiveInput<'a>,
    pub profile: Option<Gf3258VerificationProfile<'a>>,
    pub policy_config: Gf3258PersistedSampleEvaluationPolicyConfig,
}

/// Complete result of evaluating one persisted sample in caller order.
///
/// `verification_work` is present once matcher geometry ran. `normal_policy`
/// is present only when the resulting geometry/quality and normal 6ad30 gates
/// allow the sample to reach scalar policy. `recovery_eligible` is the exact
/// normal-loop bit produced for this sample;
/// when set, `recovery_observation` is the later recovery-scan result
/// precomputed from the same persisted/live pair. `None` there retains the
/// vendor's `had_candidate == 0` outcome after recovery geometry/6ad30 gates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Gf3258PersistedSampleEvaluationResult {
    pub sample_index: usize,
    pub disposition: Gf3258PersistedSampleEvaluationDisposition,
    pub verification_work: Option<Gf3258PersistedVerificationWork>,
    pub normal_policy: Option<Gf3258PersistedSampleNormalPolicyResult>,
    pub recovery_eligible: bool,
    pub recovery_observation: Option<Gf3258TerminalRecoveryProducedObservation>,
    pub state_before: Gf3258NormalLoopSampleState,
    pub state_after: Gf3258NormalLoopSampleState,
    pub loop_stopped: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Gf3258PersistedSampleEvaluationDisposition {
    /// Selected-slot / canonical caller gating skipped this sample before any
    /// per-sample mode or matcher state changed.
    SkippedByCaller,
    /// The reject-counter gate terminated the normal loop after per-sample
    /// mode promotion but before geometry/policy evaluation.
    StoppedBeforeEvaluation,
    /// Matcher geometry was evaluated. `normal_policy` records whether the
    /// sample also reached the scalar policy chain.
    Evaluated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Gf3258PersistedSampleEvaluationError {
    NormalLoop(Gf3258NormalLoopRecoveryStateError),
    VerificationWork(Gf3258PersistedVerificationWorkError),
    NormalPolicy(Gf3258PersistedSampleNormalPolicyError),
    Recovery(Gf3258TerminalRecoveryScanError),
    LoopAlreadyStopped {
        reason: Gf3258NormalLoopStopReason,
    },
    NoRemainingSamples {
        expected_samples: usize,
    },
    IncompleteLoop {
        evaluated_samples: usize,
        expected_samples: usize,
    },
}

impl std::fmt::Display for Gf3258PersistedSampleEvaluationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NormalLoop(error) => write!(f, "GF3258 normal-loop state error: {error}"),
            Self::VerificationWork(error) => {
                write!(f, "GF3258 verification-work error: {error}")
            }
            Self::NormalPolicy(error) => write!(f, "GF3258 normal-policy error: {error}"),
            Self::Recovery(error) => write!(f, "GF3258 recovery error: {error}"),
            Self::LoopAlreadyStopped { reason } => {
                write!(f, "GF3258 normal loop already stopped: {reason:?}")
            }
            Self::NoRemainingSamples { expected_samples } => write!(
                f,
                "GF3258 normal loop already evaluated all {expected_samples} persisted samples"
            ),
            Self::IncompleteLoop {
                evaluated_samples,
                expected_samples,
            } => write!(
                f,
                "GF3258 normal loop evaluated {evaluated_samples} of {expected_samples} persisted samples"
            ),
        }
    }
}

impl std::error::Error for Gf3258PersistedSampleEvaluationError {}

impl From<Gf3258NormalLoopRecoveryStateError> for Gf3258PersistedSampleEvaluationError {
    fn from(value: Gf3258NormalLoopRecoveryStateError) -> Self {
        Self::NormalLoop(value)
    }
}

impl From<Gf3258PersistedVerificationWorkError> for Gf3258PersistedSampleEvaluationError {
    fn from(value: Gf3258PersistedVerificationWorkError) -> Self {
        Self::VerificationWork(value)
    }
}

impl From<Gf3258PersistedSampleNormalPolicyError> for Gf3258PersistedSampleEvaluationError {
    fn from(value: Gf3258PersistedSampleNormalPolicyError) -> Self {
        Self::NormalPolicy(value)
    }
}

impl From<Gf3258TerminalRecoveryScanError> for Gf3258PersistedSampleEvaluationError {
    fn from(value: Gf3258TerminalRecoveryScanError) -> Self {
        Self::Recovery(value)
    }
}

#[inline]
fn gf3258_mark_normal_loop_recovery_eligibility(
    eligible_samples: &mut [bool],
    sample_index: usize,
    matcher_state_684: i32,
    recovery_config_34: i32,
    geometry_metric: i32,
) {
    if matcher_state_684 == 0 && recovery_config_34 == 1 && geometry_metric > 2 {
        eligible_samples[sample_index] = true;
    }
}

/// Internal state machine shared by the explicit-observation and caller-gated
/// normal-loop entry points.
#[derive(Debug, Clone)]
struct Gf3258NormalLoopMachine {
    config: Gf3258NormalLoopRecoveryConfig,
    normal_near_identity_mode: i32,
    eligible_samples: Vec<bool>,
    matcher_state_644: i32,
    matcher_state_684: i32,
    matcher_state_688: i32,
    matcher_state_68c: i32,
    reject_count: i32,
    candidate_state: i32,
    candidate_bump_active: bool,
    continuation_mode: bool,
    score: Gf3258VerificationScoreAccumulator,
    current_score: i32,
    processed_samples: usize,
    stop_before_sample: Option<usize>,
    stop_reason: Option<Gf3258NormalLoopStopReason>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Gf3258NormalLoopSamplePreparation {
    Ready(Gf3258SamplePolicyLoopState),
    StopBeforeEvaluation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Gf3258NormalLoopGeometryPrefix {
    Complete,
    NeedsPolicy { geometry_metric: i32 },
}

impl Gf3258NormalLoopMachine {
    fn new(
        enrolled_samples: &[Gf3258PersistedSample],
        live_scalar_13c: i32,
        config: Gf3258NormalLoopRecoveryConfig,
    ) -> Self {
        let matcher_state_68c =
            gf3258_normal_loop_initial_state_68c(live_scalar_13c, enrolled_samples);
        let raw_modes = gf3258_raw_mode_fields(config.config_48);
        let mapped_modes = gf3258_mapped_mode_fields(config.config_48);

        Self {
            config,
            normal_near_identity_mode: mapped_modes.low,
            eligible_samples: vec![false; enrolled_samples.len()],
            matcher_state_644: 0,
            matcher_state_684: 0,
            matcher_state_688: 0,
            matcher_state_68c,
            reject_count: 0,
            candidate_state: mapped_modes.high,
            candidate_bump_active: false,
            continuation_mode: config.config_10 != 0
                && matcher_state_68c != 0
                && raw_modes.high < 7,
            score: Gf3258VerificationScoreAccumulator::new(),
            current_score: 0,
            processed_samples: 0,
            stop_before_sample: None,
            stop_reason: None,
        }
    }

    #[inline]
    fn sample_state(&self) -> Gf3258NormalLoopSampleState {
        Gf3258NormalLoopSampleState {
            matcher_state_644: self.matcher_state_644,
            matcher_state_684: self.matcher_state_684,
            matcher_state_688: self.matcher_state_688,
            matcher_state_68c: self.matcher_state_68c,
            reject_count: self.reject_count,
            candidate_state: self.candidate_state,
            candidate_bump_active: self.candidate_bump_active,
            continuation_mode: self.continuation_mode,
            score: self.score,
            processed_samples: self.processed_samples,
            stop_before_sample: self.stop_before_sample,
            stop_reason: self.stop_reason,
        }
    }

    fn prepare_sample(
        &mut self,
        sample_index: usize,
        sample: &Gf3258PersistedSample,
    ) -> Gf3258NormalLoopSamplePreparation {
        let embedded_modes = gf3258_mapped_mode_fields(sample.embedded_state_140.unwrap_or(0));

        // GF3258/type 0x18 follows the raw stack-mode == 2 branch: the
        // per-sample late-policy tier is formed before embedded-state
        // promotion, while later policy sees the promoted/bumped candidate
        // mode.
        let profile_state = self
            .candidate_state
            .wrapping_add(embedded_modes.high)
            .min(5);
        if embedded_modes.high > 3 && embedded_modes.high > self.candidate_state {
            self.candidate_state = embedded_modes.high;
        }

        if self.reject_count > 5 {
            if self.candidate_state > 4 || self.candidate_bump_active {
                if self.reject_count > 10 {
                    self.stop_before_sample = Some(sample_index);
                    self.stop_reason = Some(Gf3258NormalLoopStopReason::RejectCountLimit);
                    return Gf3258NormalLoopSamplePreparation::StopBeforeEvaluation;
                }
            } else {
                self.candidate_state = self.candidate_state.wrapping_add(1);
                self.candidate_bump_active = true;
                self.continuation_mode = false;
            }
        }

        Gf3258NormalLoopSamplePreparation::Ready(Gf3258SamplePolicyLoopState {
            mapped_candidate_mode: self.candidate_state,
            profile_state,
            reject_count: self.reject_count,
        })
    }

    fn process_geometry_prefix(
        &mut self,
        sample_index: usize,
        input: Gf3258NormalLoopRecoverySampleInput,
    ) -> Gf3258NormalLoopGeometryPrefix {
        self.processed_samples += 1;
        let geometry_metric = gf3258_finalize_geometry_work_metric(
            input.primary_704f0_count,
            input.rescue_704f0_count,
            input.quality_28,
            input.quality_134,
        );

        if geometry_metric <= 4 || input.quality_28 < 30 {
            gf3258_mark_normal_loop_recovery_eligibility(
                &mut self.eligible_samples,
                sample_index,
                self.matcher_state_684,
                self.config.config_34,
                geometry_metric,
            );
            return Gf3258NormalLoopGeometryPrefix::Complete;
        }

        if gf3258_terminal_recovery_near_identity_excluded(
            input.transform_live_to_enrolled,
            self.normal_near_identity_mode,
        ) {
            return Gf3258NormalLoopGeometryPrefix::Complete;
        }

        Gf3258NormalLoopGeometryPrefix::NeedsPolicy { geometry_metric }
    }

    fn process_policy_tail(
        &mut self,
        sample_index: usize,
        sample: &Gf3258PersistedSample,
        geometry_metric: i32,
        input: Gf3258NormalLoopRecoverySampleInput,
    ) -> Result<bool, Gf3258NormalLoopRecoveryStateError> {
        let tail = match input.post_geometry {
            Gf3258NormalLoopPostGeometryDisposition::RejectedBeforeCallerTail => return Ok(false),
            Gf3258NormalLoopPostGeometryDisposition::CallerTail(tail) => tail,
        };

        let expected_reject_count = match tail.disposition {
            Gf3258VerificationCallerTailDisposition::LatePolicyRejected => {
                self.reject_count.wrapping_add(1)
            }
            _ => self.reject_count,
        };
        if tail.reject_count != expected_reject_count {
            return Err(Gf3258NormalLoopRecoveryStateError::RejectCountMismatch {
                sample_index,
                expected: expected_reject_count,
                actual: tail.reject_count,
            });
        }
        self.reject_count = tail.reject_count;

        match tail.disposition {
            Gf3258VerificationCallerTailDisposition::LatePolicyRejected
            | Gf3258VerificationCallerTailDisposition::FinalVetoRejected => return Ok(false),
            Gf3258VerificationCallerTailDisposition::OutOfDomainRatio => {
                return Err(Gf3258NormalLoopRecoveryStateError::OutOfDomainRatio { sample_index });
            }
            Gf3258VerificationCallerTailDisposition::PostSurvivalNotSelected => {}
            Gf3258VerificationCallerTailDisposition::Accepted => {
                let contribution_q8 = tail.contribution_q8.ok_or(
                    Gf3258NormalLoopRecoveryStateError::MissingAcceptedContribution {
                        sample_index,
                    },
                )?;
                self.score.push_contribution_q8(contribution_q8);
            }
        }

        let score_gate = tail.flags.score_gate;
        let policy_class = tail.flags.policy_class;

        // Raw 0x90bee..0x90c05 writes the running normal percentage into
        // the caller-provided score slot whenever the score gate is active.
        // The current accepted contribution has already been accumulated.
        if score_gate != 0 {
            self.current_score = self.score.percent().unwrap_or(0);
        }

        self.matcher_state_684 = if self.matcher_state_684 != 0 {
            1
        } else {
            (score_gate != 0) as i32
        };
        self.matcher_state_688 = if self.matcher_state_688 != 0 {
            1
        } else {
            (policy_class != 0) as i32
        };

        gf3258_mark_normal_loop_recovery_eligibility(
            &mut self.eligible_samples,
            sample_index,
            self.matcher_state_684,
            self.config.config_34,
            geometry_metric,
        );

        if score_gate != 0 {
            self.matcher_state_644 = if self.matcher_state_644 != 0 {
                1
            } else {
                sample.canonical_member as i32
            };

            if !self.continuation_mode {
                self.stop_before_sample = sample_index.checked_add(1);
                self.stop_reason = Some(Gf3258NormalLoopStopReason::ScoreGate);
                return Ok(true);
            }
        }

        Ok(false)
    }

    #[cfg(test)]
    fn process_prepared_sample(
        &mut self,
        sample_index: usize,
        sample: &Gf3258PersistedSample,
        input: Gf3258NormalLoopRecoverySampleInput,
    ) -> Result<bool, Gf3258NormalLoopRecoveryStateError> {
        match self.process_geometry_prefix(sample_index, input) {
            Gf3258NormalLoopGeometryPrefix::Complete => Ok(false),
            Gf3258NormalLoopGeometryPrefix::NeedsPolicy { geometry_metric } => {
                self.process_policy_tail(sample_index, sample, geometry_metric, input)
            }
        }
    }

    #[cfg(test)]
    fn process_sample(
        &mut self,
        sample_index: usize,
        sample: &Gf3258PersistedSample,
        input: Gf3258NormalLoopRecoverySampleInput,
    ) -> Result<bool, Gf3258NormalLoopRecoveryStateError> {
        match self.prepare_sample(sample_index, sample) {
            Gf3258NormalLoopSamplePreparation::Ready(_) => {
                self.process_prepared_sample(sample_index, sample, input)
            }
            Gf3258NormalLoopSamplePreparation::StopBeforeEvaluation => Ok(true),
        }
    }

    fn finish(mut self) -> Gf3258NormalLoopRecoveryState {
        if !self.continuation_mode {
            self.matcher_state_688 = 0;
        }

        Gf3258NormalLoopRecoveryState {
            eligible_samples: self.eligible_samples,
            post_normal_loop_state_644: self.matcher_state_644,
            score: self.score,
            current_score: self.current_score,
            post_normal_loop_state_684: self.matcher_state_684,
            post_normal_loop_state_688: self.matcher_state_688,
            matcher_state_68c: self.matcher_state_68c,
            reject_count: self.reject_count,
            candidate_state: self.candidate_state,
            continuation_mode: self.continuation_mode,
            processed_samples: self.processed_samples,
            stop_before_sample: self.stop_before_sample,
            stop_reason: self.stop_reason,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Gf3258PersistedSampleEvaluator<'a> {
    samples: &'a [Gf3258PersistedSample],
    machine: Gf3258NormalLoopMachine,
    sample_count: usize,
    configured_max_samples: usize,
    selected_sample_index: i32,
    next_sample_index: usize,
}

impl<'a> Gf3258PersistedSampleEvaluator<'a> {
    /// Initialize the exact normal-loop caller state for a persisted gallery.
    pub fn new(
        enrolled_samples: &'a [Gf3258PersistedSample],
        live_scalar_13c: i32,
        config: Gf3258NormalLoopConfig,
    ) -> Result<Self, Gf3258PersistedSampleEvaluationError> {
        if enrolled_samples.len() > config.configured_max_samples {
            return Err(
                Gf3258NormalLoopRecoveryStateError::InvalidConfiguredSampleLimit {
                    samples: enrolled_samples.len(),
                    configured_max_samples: config.configured_max_samples,
                }
                .into(),
            );
        }

        Ok(Self {
            samples: enrolled_samples,
            machine: Gf3258NormalLoopMachine::new(
                enrolled_samples,
                live_scalar_13c,
                config.recovery,
            ),
            sample_count: enrolled_samples.len(),
            configured_max_samples: config.configured_max_samples,
            selected_sample_index: config.config_38,
            next_sample_index: 0,
        })
    }

    /// Index in persisted-sample iteration order expected by the next call to
    /// [`Self::evaluate_next`].
    #[inline]
    pub const fn next_sample_index(&self) -> usize {
        self.next_sample_index
    }

    /// Evaluate the next persisted sample and commit its caller transition.
    ///
    /// Evaluation is transactional: matcher/policy/recovery errors leave the
    /// evaluator unchanged so the caller can diagnose or retry without a
    /// partially advanced loop state.
    #[allow(clippy::too_many_lines)]
    pub fn evaluate_next(
        &mut self,
        live: &Gf3258OwnedVerificationMatcherFeature,
        input: Gf3258PersistedSampleEvaluationInput<'_>,
    ) -> Result<Gf3258PersistedSampleEvaluationResult, Gf3258PersistedSampleEvaluationError> {
        if let Some(reason) = self.machine.stop_reason {
            return Err(Gf3258PersistedSampleEvaluationError::LoopAlreadyStopped { reason });
        }
        if self.next_sample_index >= self.sample_count {
            return Err(Gf3258PersistedSampleEvaluationError::NoRemainingSamples {
                expected_samples: self.sample_count,
            });
        }

        let sample_index = self.next_sample_index;
        let sample = &self.samples[sample_index];
        let state_before = self.machine.sample_state();
        let caller_processed = gf3258_normal_loop_caller_processes_sample(
            self.sample_count,
            self.configured_max_samples,
            self.machine.config.config_34,
            self.selected_sample_index,
            sample,
            self.machine.matcher_state_644,
            self.machine.matcher_state_688,
        );

        if !caller_processed {
            self.next_sample_index += 1;
            return Ok(Gf3258PersistedSampleEvaluationResult {
                sample_index,
                disposition: Gf3258PersistedSampleEvaluationDisposition::SkippedByCaller,
                verification_work: None,
                normal_policy: None,
                recovery_eligible: false,
                recovery_observation: None,
                state_before,
                state_after: state_before,
                loop_stopped: false,
            });
        }

        let mut next_machine = self.machine.clone();
        let sample_loop_state = match next_machine.prepare_sample(sample_index, sample) {
            Gf3258NormalLoopSamplePreparation::Ready(state) => state,
            Gf3258NormalLoopSamplePreparation::StopBeforeEvaluation => {
                let state_after = next_machine.sample_state();
                self.machine = next_machine;
                self.next_sample_index += 1;
                return Ok(Gf3258PersistedSampleEvaluationResult {
                    sample_index,
                    disposition:
                        Gf3258PersistedSampleEvaluationDisposition::StoppedBeforeEvaluation,
                    verification_work: None,
                    normal_policy: None,
                    recovery_eligible: false,
                    recovery_observation: None,
                    state_before,
                    state_after,
                    loop_stopped: true,
                });
            }
        };
        let verification_work = gf3258_persisted_sample_verification_work(
            sample,
            live,
            input.registration,
            input.sample_config,
        )?;
        let geometry_input = verification_work.normal_loop_sample_input(
            Gf3258NormalLoopPostGeometryDisposition::RejectedBeforeCallerTail,
        );
        let (normal_policy, loop_stopped) =
            match next_machine.process_geometry_prefix(sample_index, geometry_input.into()) {
                Gf3258NormalLoopGeometryPrefix::Complete => (None, false),
                Gf3258NormalLoopGeometryPrefix::NeedsPolicy { geometry_metric } => {
                    let normal_policy = gf3258_persisted_sample_normal_policy_from_work(
                        sample,
                        live,
                        Gf3258ResolvedPersistedSampleNormalPolicyInput {
                            registration: input.registration,
                            sample_config: input.sample_config,
                            live_policy: input.live_policy,
                            profile: input.profile,
                            loop_state: sample_loop_state,
                            config: input
                                .policy_config
                                .normal_policy(next_machine.config.config_48),
                        },
                        &verification_work,
                    )?;
                    let loop_stopped = next_machine.process_policy_tail(
                        sample_index,
                        sample,
                        geometry_metric,
                        normal_policy.sample_input.into(),
                    )?;
                    (Some(normal_policy), loop_stopped)
                }
            };
        let recovery_eligible = next_machine.eligible_samples[sample_index];
        let recovery_observation = if recovery_eligible {
            gf3258_persisted_sample_terminal_recovery_observation(
                sample_index,
                sample,
                Gf3258TerminalRecoveryLiveFeature {
                    matcher: live.as_feature_set(),
                    primary_registration_map: input.registration.primary_registration_map,
                    secondary_registration_map: input.registration.secondary_registration_map,
                    quarter_validity_packed: input.registration.quarter_validity_packed,
                    active_validity_packed: input.registration.active_validity_packed,
                },
                input.sample_config.candidate_matcher,
                gf3258_terminal_recovery_exclusion_mode_from_config_48(
                    next_machine.config.config_48,
                ),
            )?
        } else {
            None
        };
        let state_after = next_machine.sample_state();

        self.machine = next_machine;
        self.next_sample_index += 1;

        Ok(Gf3258PersistedSampleEvaluationResult {
            sample_index,
            disposition: Gf3258PersistedSampleEvaluationDisposition::Evaluated,
            verification_work: Some(verification_work),
            normal_policy,
            recovery_eligible,
            recovery_observation,
            state_before,
            state_after,
            loop_stopped,
        })
    }

    /// Finalize the normal-loop state after every sample was visited or a
    /// vendor stop gate terminated the loop.
    pub fn finish(
        self,
    ) -> Result<Gf3258NormalLoopRecoveryState, Gf3258PersistedSampleEvaluationError> {
        if self.next_sample_index < self.sample_count && self.machine.stop_reason.is_none() {
            return Err(Gf3258PersistedSampleEvaluationError::IncompleteLoop {
                evaluated_samples: self.next_sample_index,
                expected_samples: self.sample_count,
            });
        }
        Ok(self.machine.finish())
    }
}

/// Revision of the complete persisted-gallery verification composition.
pub(crate) const GF3258_PERSISTED_GALLERY_VERIFICATION_REVISION: &str =
    "gf3258-persisted-gallery-verification-v1";

/// Inputs for one complete cache-disabled GF3258 persisted-gallery scan.
///
/// Raw identify/feature-recognition consumers initialize the score passed to
/// `FUN_001900b0` to zero. Optional `0x8e810` cache rescue is not part of the
/// standalone persisted-gallery biometric path and remains outside this API.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Gf3258PersistedGalleryVerificationInput<'a> {
    /// Live `Feature+0x13c`, used only to initialize matcher state `+0x68c`.
    pub live_scalar_13c: i32,
    pub normal_loop: Gf3258NormalLoopConfig,
    /// Shared live/config inputs used while the evaluator supplies each persisted sample.
    pub evaluation: Gf3258PersistedSampleEvaluationInput<'a>,
}

/// Final binary interpretation of the complete signed vendor verification score.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gf3258GalleryVerificationDecision {
    Match,
    NoMatch,
}

impl Gf3258GalleryVerificationDecision {
    #[inline]
    pub(crate) const fn from_score(score: i32) -> Self {
        if gf3258_vendor_verification_score_is_match(score) {
            Self::Match
        } else {
            Self::NoMatch
        }
    }
}

/// The per-sample policy work record retained by `FUN_001900b0` for terminal
/// `0x69290` scoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Gf3258SelectedTerminalPolicyWork {
    pub sample_index: usize,
    pub policy_work: Gf3258NormalPolicyWorkSnapshot,
    pub policy_score: i32,
}

/// Complete cache-disabled persisted-gallery verification result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Gf3258PersistedGalleryVerificationResult {
    pub decision: Gf3258GalleryVerificationDecision,
    pub arbitration: Gf3258TerminalArbitrationResult,
    pub normal_loop: Gf3258NormalLoopRecoveryState,
    pub recovery: Gf3258TerminalRecoveryAggregation,
    pub selected_terminal_work: Option<Gf3258SelectedTerminalPolicyWork>,
    pub sample_evaluations: Vec<Gf3258PersistedSampleEvaluationResult>,
}

#[inline]
fn gf3258_terminal_policy_work_key(work: Gf3258NormalPolicyWorkSnapshot) -> (i32, i32, i32) {
    (
        work.record.evidence,
        work.record.verification_metric,
        work.record.scaled_coverage_q8,
    )
}

#[inline]
fn gf3258_terminal_policy_key_is_better(
    current: Gf3258NormalPolicyWorkSnapshot,
    selected: Option<Gf3258NormalPolicyWorkSnapshot>,
) -> bool {
    let current = gf3258_terminal_policy_work_key(current);
    let selected = selected
        .map(gf3258_terminal_policy_work_key)
        .unwrap_or((0, 0, 0));
    current > selected
}

/// Exact accepted-sample selector for the dedicated terminal 0x150-byte work
/// record in `FUN_001900b0`.
///
/// Raw `+0x1b4` is the final policy-class flag that subsequently latches
/// matcher `+0x688`; raw `+0x1b8` is the final score-gate flag that latches
/// matcher `+0x684`. Selection happens before those latches are updated, so
/// `state_before` supplies the previous `+0x684/+0x688` values.
#[inline]
fn gf3258_should_replace_terminal_policy_work(
    state_before: Gf3258NormalLoopSampleState,
    flags: Gf3258PostSurvivalPolicyFlags,
    current: Gf3258NormalPolicyWorkSnapshot,
    selected: Option<Gf3258NormalPolicyWorkSnapshot>,
) -> bool {
    let better = gf3258_terminal_policy_key_is_better(current, selected);

    if state_before.matcher_state_688 != 0 {
        return flags.policy_class != 0 && better;
    }

    if state_before.matcher_state_684 != 0 {
        if flags.policy_class != 0 {
            return true;
        }
        return flags.score_gate != 0 && better;
    }

    flags.policy_class != 0 || flags.score_gate != 0 || better
}

fn gf3258_accepted_policy_tail(
    result: &Gf3258PersistedSampleEvaluationResult,
) -> Option<(
    Gf3258PostSurvivalPolicyFlags,
    Gf3258NormalPolicyWorkSnapshot,
)> {
    let policy = result.normal_policy?;
    let Gf3258NormalLoopPostGeometryDisposition::CallerTail(tail) =
        policy.sample_input.post_geometry
    else {
        return None;
    };
    if tail.disposition != Gf3258VerificationCallerTailDisposition::Accepted {
        return None;
    }
    Some((tail.flags, policy.policy_work))
}

/// Verify one live GF3258 feature against an entire persisted gallery and
/// return the complete signed vendor score plus its binary MATCH/NO MATCH
/// interpretation.
///
/// This composes the per-template evaluator, exact terminal-work
/// selection, recovery aggregation, and terminal arbitration. The terminal
/// history count is verification-profile byte zero; the auxiliary terminal
/// class is the final evolving candidate state. Both values are derived inside
/// the scan rather than supplied as caller policy observations.
pub(crate) fn gf3258_verify_persisted_gallery(
    samples: &[Gf3258PersistedSample],
    live: &Gf3258OwnedVerificationMatcherFeature,
    input: Gf3258PersistedGalleryVerificationInput<'_>,
) -> Result<Gf3258PersistedGalleryVerificationResult, Gf3258PersistedSampleEvaluationError> {
    let mut evaluator =
        Gf3258PersistedSampleEvaluator::new(samples, input.live_scalar_13c, input.normal_loop)?;
    let mut sample_evaluations = Vec::new();
    let mut recovery_observations = Vec::new();
    let mut selected_terminal_work: Option<Gf3258SelectedTerminalPolicyWork> = None;

    while evaluator.next_sample_index() < samples.len() {
        let result = evaluator.evaluate_next(live, input.evaluation)?;

        if let Some((flags, policy_work)) = gf3258_accepted_policy_tail(&result) {
            let selected_work = selected_terminal_work.map(|selected| selected.policy_work);
            if gf3258_should_replace_terminal_policy_work(
                result.state_before,
                flags,
                policy_work,
                selected_work,
            ) {
                selected_terminal_work = Some(Gf3258SelectedTerminalPolicyWork {
                    sample_index: result.sample_index,
                    policy_work,
                    policy_score: gf3258_verification_policy_score(
                        policy_work.score_policy_record(),
                    ),
                });
            }
        }

        if let Some(observation) = result.recovery_observation {
            recovery_observations.push(observation.observation);
        }

        let loop_stopped = result.loop_stopped;
        sample_evaluations.push(result);
        if loop_stopped {
            break;
        }
    }

    let normal_loop = evaluator.finish()?;
    let recovery = gf3258_terminal_recovery_aggregate(
        Gf3258TerminalRecoveryConfig {
            map_score_base: input.evaluation.policy_config.config_00,
            quality_scale_q8: input.evaluation.sample_config.quality_scale_q8,
            // Type 0x18 matcher configuration is built with config+0x40 = 1.
            apply_affine_penalty: true,
        },
        &recovery_observations,
    );
    let normal_percent = normal_loop.score.percent().unwrap_or(0);
    let history_count = input
        .evaluation
        .profile
        .map_or(0, Gf3258VerificationProfile::mode);
    let current_policy_score = selected_terminal_work.map_or(0, |selected| selected.policy_score);
    let arbitration = gf3258_terminal_arbitrate_score(Gf3258TerminalArbitrationInput {
        current_score: normal_loop.current_score,
        normal_percent,
        history_count,
        matcher_state_688: normal_loop.post_normal_loop_state_688,
        auxiliary_class: normal_loop.candidate_state,
        accepted_samples: normal_loop.score.accepted_samples(),
        config_48: input.normal_loop.recovery.config_48,
        current_policy_score,
        recovery: recovery.summary,
        cache_rescue_enabled: false,
        cache_rescue_hit: false,
    });

    Ok(Gf3258PersistedGalleryVerificationResult {
        decision: Gf3258GalleryVerificationDecision::from_score(arbitration.score),
        arbitration,
        normal_loop,
        recovery,
        selected_terminal_work,
        sample_evaluations,
    })
}

/// Reproduce the recovery-relevant normal-loop state from explicit caller
/// branch observations. `caller_processes_sample` remains available here for
/// diagnostics and parity fixtures that begin after the caller's skip gates.
#[cfg(test)]
pub(crate) fn gf3258_normal_loop_recovery_state(
    enrolled_samples: &[Gf3258PersistedSample],
    live_scalar_13c: i32,
    config: Gf3258NormalLoopRecoveryConfig,
    sample_inputs: &[Gf3258NormalLoopRecoverySampleInput],
) -> Result<Gf3258NormalLoopRecoveryState, Gf3258NormalLoopRecoveryStateError> {
    if enrolled_samples.len() != sample_inputs.len() {
        return Err(
            Gf3258NormalLoopRecoveryStateError::ObservationLengthMismatch {
                samples: enrolled_samples.len(),
                observations: sample_inputs.len(),
            },
        );
    }

    let mut machine = Gf3258NormalLoopMachine::new(enrolled_samples, live_scalar_13c, config);
    for (sample_index, (sample, input)) in enrolled_samples
        .iter()
        .zip(sample_inputs.iter().copied())
        .enumerate()
    {
        if !input.caller_processes_sample {
            continue;
        }
        if machine.process_sample(sample_index, sample, input)? {
            break;
        }
    }
    Ok(machine.finish())
}

#[inline]
fn gf3258_normal_loop_caller_processes_sample(
    sample_count: usize,
    configured_max_samples: usize,
    config_34: i32,
    config_38: i32,
    sample: &Gf3258PersistedSample,
    matcher_state_644: i32,
    matcher_state_688: i32,
) -> bool {
    if config_34 == 0 && config_38 != sample.sample_index {
        return false;
    }

    let canonical_gate = sample_count == configured_max_samples || matcher_state_688 == 1;
    !(canonical_gate && matcher_state_644 == 1 && sample.canonical_member)
}

/// Reproduce the normal caller loop while deriving its per-sample skip gates
/// from persisted sample state and the loop's sticky latches.
#[cfg(test)]
pub(crate) fn gf3258_normal_loop_state(
    enrolled_samples: &[Gf3258PersistedSample],
    live_scalar_13c: i32,
    config: Gf3258NormalLoopConfig,
    sample_inputs: &[Gf3258NormalLoopSampleInput],
) -> Result<Gf3258NormalLoopRecoveryState, Gf3258NormalLoopRecoveryStateError> {
    if enrolled_samples.len() != sample_inputs.len() {
        return Err(
            Gf3258NormalLoopRecoveryStateError::ObservationLengthMismatch {
                samples: enrolled_samples.len(),
                observations: sample_inputs.len(),
            },
        );
    }
    if enrolled_samples.len() > config.configured_max_samples {
        return Err(
            Gf3258NormalLoopRecoveryStateError::InvalidConfiguredSampleLimit {
                samples: enrolled_samples.len(),
                configured_max_samples: config.configured_max_samples,
            },
        );
    }

    let sample_count = enrolled_samples.len();
    let mut machine =
        Gf3258NormalLoopMachine::new(enrolled_samples, live_scalar_13c, config.recovery);

    for (sample_index, (sample, input)) in enrolled_samples
        .iter()
        .zip(sample_inputs.iter().copied())
        .enumerate()
    {
        if !gf3258_normal_loop_caller_processes_sample(
            sample_count,
            config.configured_max_samples,
            config.recovery.config_34,
            config.config_38,
            sample,
            machine.matcher_state_644,
            machine.matcher_state_688,
        ) {
            continue;
        }

        if machine.process_sample(sample_index, sample, input.into())? {
            break;
        }
    }

    Ok(machine.finish())
}

/// Recovery scanning configuration for already-composed normal-loop outcomes.
/// The eligibility vector and recovery `0x6ad30` mode are derived internally.
#[cfg(test)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct Gf3258TerminalRecoveryScanFromNormalLoopConfig<'a> {
    pub candidate_matcher: Gf3258CandidateMatcherConfig,
    pub aggregate: Gf3258TerminalRecoveryConfig,
    pub map_mode: i32,
    pub normal_loop: Gf3258NormalLoopRecoveryConfig,
    pub sample_inputs: &'a [Gf3258NormalLoopRecoverySampleInput],
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Gf3258TerminalRecoveryScanFromNormalLoopResult {
    pub normal_loop: Gf3258NormalLoopRecoveryState,
    pub scan: Gf3258TerminalRecoveryScanResult,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Gf3258TerminalRecoveryScanFromNormalLoopError {
    NormalLoop(Gf3258NormalLoopRecoveryStateError),
    RecoveryScan(Gf3258TerminalRecoveryScanError),
}

#[cfg(test)]
impl std::fmt::Display for Gf3258TerminalRecoveryScanFromNormalLoopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NormalLoop(error) => write!(f, "GF3258 normal-loop state error: {error}"),
            Self::RecoveryScan(error) => write!(f, "GF3258 recovery scan error: {error}"),
        }
    }
}

#[cfg(test)]
impl std::error::Error for Gf3258TerminalRecoveryScanFromNormalLoopError {}

#[cfg(test)]
impl From<Gf3258NormalLoopRecoveryStateError> for Gf3258TerminalRecoveryScanFromNormalLoopError {
    fn from(value: Gf3258NormalLoopRecoveryStateError) -> Self {
        Self::NormalLoop(value)
    }
}

#[cfg(test)]
impl From<Gf3258TerminalRecoveryScanError> for Gf3258TerminalRecoveryScanFromNormalLoopError {
    fn from(value: Gf3258TerminalRecoveryScanError) -> Self {
        Self::RecoveryScan(value)
    }
}

/// Produce recovery eligibility from normal-loop branch results and feed it
/// directly into the persisted-sample recovery scan.
#[cfg(test)]
pub(crate) fn gf3258_terminal_recovery_scan_from_normal_loop(
    samples: &[Gf3258PersistedSample],
    live_scalar_13c: i32,
    live: Gf3258TerminalRecoveryLiveFeature<'_>,
    config: Gf3258TerminalRecoveryScanFromNormalLoopConfig<'_>,
) -> Result<
    Gf3258TerminalRecoveryScanFromNormalLoopResult,
    Gf3258TerminalRecoveryScanFromNormalLoopError,
> {
    let normal_loop = gf3258_normal_loop_recovery_state(
        samples,
        live_scalar_13c,
        config.normal_loop,
        config.sample_inputs,
    )?;
    let recovery_exclusion_mode =
        gf3258_terminal_recovery_exclusion_mode_from_config_48(config.normal_loop.config_48);
    let scan = gf3258_terminal_recovery_scan_persisted_samples(
        samples,
        live,
        Gf3258TerminalRecoveryScanConfig {
            candidate_matcher: config.candidate_matcher,
            aggregate: config.aggregate,
            near_identity_exclusion_mode: recovery_exclusion_mode,
            map_mode: config.map_mode,
            eligible_samples: &normal_loop.eligible_samples,
        },
    )?;
    Ok(Gf3258TerminalRecoveryScanFromNormalLoopResult { normal_loop, scan })
}

/// Recovery scanning configuration for the caller-gated normal loop.
#[cfg(test)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct Gf3258TerminalRecoveryScanFromCallerLoopConfig<'a> {
    pub candidate_matcher: Gf3258CandidateMatcherConfig,
    pub aggregate: Gf3258TerminalRecoveryConfig,
    pub map_mode: i32,
    pub normal_loop: Gf3258NormalLoopConfig,
    pub sample_inputs: &'a [Gf3258NormalLoopSampleInput],
}

/// Derive caller skip state and recovery eligibility before scanning persisted
/// samples. No caller-supplied eligibility or per-sample process flag is used.
#[cfg(test)]
pub(crate) fn gf3258_terminal_recovery_scan_from_caller_loop(
    samples: &[Gf3258PersistedSample],
    live_scalar_13c: i32,
    live: Gf3258TerminalRecoveryLiveFeature<'_>,
    config: Gf3258TerminalRecoveryScanFromCallerLoopConfig<'_>,
) -> Result<
    Gf3258TerminalRecoveryScanFromNormalLoopResult,
    Gf3258TerminalRecoveryScanFromNormalLoopError,
> {
    let normal_loop = gf3258_normal_loop_state(
        samples,
        live_scalar_13c,
        config.normal_loop,
        config.sample_inputs,
    )?;
    let recovery_exclusion_mode = gf3258_terminal_recovery_exclusion_mode_from_config_48(
        config.normal_loop.recovery.config_48,
    );
    let scan = gf3258_terminal_recovery_scan_persisted_samples(
        samples,
        live,
        Gf3258TerminalRecoveryScanConfig {
            candidate_matcher: config.candidate_matcher,
            aggregate: config.aggregate,
            near_identity_exclusion_mode: recovery_exclusion_mode,
            map_mode: config.map_mode,
            eligible_samples: &normal_loop.eligible_samples,
        },
    )?;

    Ok(Gf3258TerminalRecoveryScanFromNormalLoopResult { normal_loop, scan })
}

/// Live Feature state consumed by the GF3258 terminal recovery scan.
///
/// Recovery `a9a50` consumes both validity representations for different
/// outputs. The registration score/evidence composition uses the expanded
/// 40x32 mask, while the fourth recovery output is derived from the original
/// 20x16 quarter-validity mask expanded and warped with border/fill zero.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Gf3258TerminalRecoveryLiveFeature<'a> {
    pub matcher: Gf3258MatcherFeatureSet<'a>,
    pub primary_registration_map: &'a [u8; GF3258_REGISTRATION_PACKED_BYTES],
    pub secondary_registration_map: Option<&'a [u8; GF3258_REGISTRATION_PACKED_BYTES]>,
    pub quarter_validity_packed: &'a [u8; GF3258_QUARTER_VALIDITY_CELLS / 8],
    pub active_validity_packed: &'a [u8; GF3258_REGISTRATION_PACKED_BYTES],
}

/// Caller state required to reproduce the recovery scan's pre-existing
/// eligibility and near-identity exclusion policy.
///
/// `eligible_samples` is the vendor `aiStack_17f78[]` state produced during the
/// preceding normal-sample loop. The recovery scan closes everything after that bit is
/// set, but deliberately does not infer it from persisted data alone.
#[cfg(test)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct Gf3258TerminalRecoveryScanConfig<'a> {
    pub candidate_matcher: Gf3258CandidateMatcherConfig,
    pub aggregate: Gf3258TerminalRecoveryConfig,
    /// `iStack_18130` at the recovery scan. Raw `0x6ad30` is called only for
    /// values 1..=5; all other values skip the near-identity exclusion.
    pub near_identity_exclusion_mode: i32,
    /// Runtime template/group map mode. The persisted GF3258 path currently has
    /// exact `0xa9a50` parity for mode 1 (40x32).
    pub map_mode: i32,
    pub eligible_samples: &'a [bool],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Gf3258TerminalRecoveryScanError {
    #[cfg(test)]
    EligibilityLengthMismatch {
        samples: usize,
        eligibility: usize,
    },
    #[cfg(test)]
    UnsupportedMapMode {
        mode: i32,
    },
    Candidate(Gf3258CandidateMatchError),
    Geometry(Gf3258MatcherGeometryError),
}

impl std::fmt::Display for Gf3258TerminalRecoveryScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(test)]
            Self::EligibilityLengthMismatch {
                samples,
                eligibility,
            } => write!(
                f,
                "GF3258 recovery scan has {samples} samples but {eligibility} eligibility bits"
            ),
            #[cfg(test)]
            Self::UnsupportedMapMode { mode } => write!(
                f,
                "GF3258 recovery scan currently proves only map mode 1; got {mode}"
            ),
            Self::Candidate(error) => write!(f, "GF3258 recovery candidate error: {error}"),
            Self::Geometry(error) => write!(f, "GF3258 recovery geometry error: {error:?}"),
        }
    }
}

impl std::error::Error for Gf3258TerminalRecoveryScanError {}

impl From<Gf3258CandidateMatchError> for Gf3258TerminalRecoveryScanError {
    fn from(value: Gf3258CandidateMatchError) -> Self {
        Self::Candidate(value)
    }
}

impl From<Gf3258MatcherGeometryError> for Gf3258TerminalRecoveryScanError {
    fn from(value: Gf3258MatcherGeometryError) -> Self {
        Self::Geometry(value)
    }
}

/// Diagnostic result for one sample that reached the post-geometry recovery
/// observation point. Samples rejected by geometry or `0x6ad30` are absent,
/// exactly matching the vendor's `uStack_182a8` / `had_candidate` semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Gf3258TerminalRecoveryProducedObservation {
    pub sample_index: usize,
    pub transform_live_to_enrolled: Gf3258AffineQ8,
    pub observation: Gf3258TerminalRecoveryObservation,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Gf3258TerminalRecoveryScanResult {
    pub observations: Vec<Gf3258TerminalRecoveryProducedObservation>,
    pub aggregation: Gf3258TerminalRecoveryAggregation,
}

#[inline]
const fn gf3258_wrapping_abs_i32(value: i32) -> i32 {
    let sign = value >> 31;
    (value ^ sign).wrapping_sub(sign)
}

/// Exact GF3258 type-0x18 specialization of raw `FUN_0016ad30`.
///
/// Return `true` means the affine is too close to identity for the supplied
/// recovery mode and the vendor skips the candidate. Modes outside 1..=5 do
/// not call `0x6ad30` in `FUN_001900b0` and therefore return false here.
pub(crate) fn gf3258_terminal_recovery_near_identity_excluded(
    transform: Gf3258AffineQ8,
    mode: i32,
) -> bool {
    let limits = match mode {
        1 => [15, 11, 0x400, 11, 15, 0x400],
        2 | 3 => [30, 22, 0x800, 22, 30, 0x800],
        4 => [38, 38, 0xc00, 38, 38, 0xc00],
        5 => [45, 40, 0xf00, 40, 45, 0xf00],
        _ => return false,
    };
    let identity = [0x100, 0, 0, 0, 0x100, 0];
    let values = transform.as_array();
    let mut index = 0usize;
    while index < 6 {
        if gf3258_wrapping_abs_i32(values[index].wrapping_sub(identity[index])) > limits[index] {
            return false;
        }
        index += 1;
    }
    true
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Gf3258TerminalRecoveryAffineMetrics {
    pub scale_q8: i32,
    pub orthogonality_q16: i32,
}

fn gf3258_integer_sqrt_u128(value: u128) -> u128 {
    if value < 2 {
        return value;
    }
    let bits = 128u32 - value.leading_zeros();
    let mut x = 1u128 << bits.div_ceil(2);
    loop {
        let next = (x + value / x) >> 1;
        if next >= x {
            return x;
        }
        x = next;
    }
}

/// Exact second scalar output of raw `FUN_001aa480`: deviation of the
/// affine's first axis from the nearest 180-degree-equivalent axis, in whole
/// degrees. The result lies in 0..=90 for the normal GF3258 domain.
pub(crate) fn gf3258_affine_axis_deviation_degrees(transform: Gf3258AffineQ8) -> i32 {
    let norm_squared = transform
        .a
        .wrapping_mul(transform.a)
        .wrapping_add(transform.c.wrapping_mul(transform.c));
    let norm = gf3258_integer_sqrt_u128(u128::from(norm_squared as u32)) as i32;
    if norm == 0 {
        return 0;
    }

    let normalized_a = transform.a.wrapping_shl(8) / norm;
    let normalized_c = transform.c.wrapping_shl(8) / norm;
    let (angle_bits, _) = gf3258_cordic_atan2_magnitude_q12(normalized_c, normalized_a);
    let mut angle_q12 = i32::from(angle_bits as i16);
    if angle_q12 < 0 {
        angle_q12 = angle_q12.wrapping_add(GF3258_TAU_Q12);
    }
    let mut degrees = (i64::from(angle_q12).wrapping_mul(0x395) >> 16) as i32;
    if degrees >= 180 {
        degrees = degrees.wrapping_sub(180);
    }
    degrees.min(180i32.wrapping_sub(degrees))
}

/// Exact normal-GF3258-domain outputs 0 and 2 of raw `FUN_001aa480`.
pub(crate) fn gf3258_terminal_recovery_affine_metrics(
    transform: Gf3258AffineQ8,
) -> Gf3258TerminalRecoveryAffineMetrics {
    let a = i128::from(transform.a);
    let b = i128::from(transform.b);
    let c = i128::from(transform.c);
    let d = i128::from(transform.d);
    let n0 = (a * a + c * c) as u128;
    let n1 = (b * b + d * d) as u128;
    let s0 = gf3258_integer_sqrt_u128(n0);
    let s1 = gf3258_integer_sqrt_u128(n1);
    let scale_q8 = ((s0 + s1) >> 1) as i32;

    let denominator = gf3258_integer_sqrt_u128(n0.saturating_mul(n1));
    let dot = a * b + c * d;
    let orthogonality_q16 = if denominator == 0 {
        0
    } else {
        let quotient = (dot << 16) / denominator as i128;
        quotient.unsigned_abs() as i32
    };

    Gf3258TerminalRecoveryAffineMetrics {
        scale_q8,
        orthogonality_q16,
    }
}

/// Exact fourth scalar output of raw `FUN_001a9a50` for the proven GF3258
/// `map_mode == 1` path. Unlike enrollment registration metric B, this quantity
/// is computed from the 20x16 quarter-validity masks, expanded to 40x32, with
/// the source warped using border zero and fill zero. Both the normal 0x72700
/// refinement gate and the terminal recovery scan consume this value.
fn gf3258_a9a50_coverage_q8_half_resolution(
    source_quarter_validity_packed: &[u8; GF3258_QUARTER_VALIDITY_CELLS / 8],
    target_quarter_validity_packed: &[u8; GF3258_QUARTER_VALIDITY_CELLS / 8],
    source_to_target_full_resolution: Gf3258AffineQ8,
) -> i32 {
    let source_quarter = gf3258_unpack_quarter_validity(source_quarter_validity_packed);
    let target_quarter = gf3258_unpack_quarter_validity(target_quarter_validity_packed);
    let source_validity = gf3258_expand_quarter_validity(&source_quarter);
    let target_validity = gf3258_expand_quarter_validity(&target_quarter);
    let active_transform = gf3258_affine_for_registration_scoring(source_to_target_full_resolution);
    let Some(warped) = gf3258_warp_u8_to_canvas_roi(
        &source_validity,
        GF3258_REGISTRATION_WIDTH,
        GF3258_REGISTRATION_HEIGHT,
        GF3258_REGISTRATION_WIDTH,
        GF3258_REGISTRATION_HEIGHT,
        active_transform,
        0,
        0,
    ) else {
        return 0;
    };

    let mut jointly_valid = 0i32;
    for ry in 0..warped.height {
        let target_y = warped.y + ry as i32;
        if target_y < 0 || target_y >= GF3258_REGISTRATION_HEIGHT as i32 {
            continue;
        }
        for rx in 0..warped.width {
            let target_x = warped.x + rx as i32;
            if target_x < 0 || target_x >= GF3258_REGISTRATION_WIDTH as i32 {
                continue;
            }
            let source_index = ry * warped.width + rx;
            let target_index = target_y as usize * GF3258_REGISTRATION_WIDTH + target_x as usize;
            if warped.data[source_index] != 0 && target_validity[target_index] != 0 {
                jointly_valid = jointly_valid.wrapping_add(1);
            }
        }
    }

    let canvas_cells = (GF3258_REGISTRATION_WIDTH * GF3258_REGISTRATION_HEIGHT) as i32;
    jointly_valid
        .wrapping_mul(0x100)
        .wrapping_add(canvas_cells >> 1)
        / canvas_cells
}

fn gf3258_persisted_recovery_points(
    sample: &Gf3258PersistedSample,
) -> Vec<Gf3258RecoveryEnrolledPoint> {
    sample
        .points
        .iter()
        .map(|point| {
            let geometry = point.matcher_geometry();
            Gf3258RecoveryEnrolledPoint {
                x_q8: geometry.x_q8,
                y_q8: geometry.y_q8,
            }
        })
        .collect()
}

/// Reproduce the recovery `b1310` pair slots for one persisted sample.
///
/// `0x72700` clears the 180x180 score table, runs `0xb0e90` for the current
/// sample, and invokes `0xb1310` immediately when that same sample becomes
/// recovery-eligible. Recomputing the exact `b0e90` matrix here therefore
/// reproduces the table consumed by the vendor's inverse selector.
pub(crate) fn gf3258_generate_persisted_sample_recovery_pair_slots(
    sample: &Gf3258PersistedSample,
    live: Gf3258MatcherFeatureSet<'_>,
    config: Gf3258CandidateMatcherConfig,
) -> Result<[[i32; 2]; GF3258_MAX_INITIAL_CORRESPONDENCES], Gf3258CandidateMatchError> {
    let normal = gf3258_generate_persisted_sample_candidates(sample, live, config)?;
    let enrolled = gf3258_persisted_recovery_points(sample);
    gf3258_generate_recovery_pair_slots_from_score_matrix(
        &enrolled,
        sample.matcher_polarity_split(),
        live,
        config,
        &normal.pair_score_matrix,
    )
}

/// Produce one exact post-geometry recovery observation from a persisted sample
/// that the preceding normal loop marked recovery-eligible.
///
/// `Ok(None)` means the vendor would not set the recovery `had_candidate` bit:
/// either `0x704f0 <= 4` or the optional `0x6ad30` near-identity exclusion
/// rejected the transform. Once those gates pass, an observation is returned
/// even when `0xa9a50` yields zero/failed map evidence, matching the caller.
pub(crate) fn gf3258_persisted_sample_terminal_recovery_observation(
    sample_index: usize,
    sample: &Gf3258PersistedSample,
    live: Gf3258TerminalRecoveryLiveFeature<'_>,
    candidate_config: Gf3258CandidateMatcherConfig,
    near_identity_exclusion_mode: i32,
) -> Result<Option<Gf3258TerminalRecoveryProducedObservation>, Gf3258TerminalRecoveryScanError> {
    let pair_slots = gf3258_generate_persisted_sample_recovery_pair_slots(
        sample,
        live.matcher,
        candidate_config,
    )?;
    let geometry =
        gf3258_persisted_sample_geometry_from_pair_slots(sample, live.matcher.points, &pair_slots)?;
    if geometry.final_inlier_count <= 4 {
        return Ok(None);
    }

    let transform = geometry.transform_live_to_enrolled;
    if gf3258_terminal_recovery_near_identity_excluded(transform, near_identity_exclusion_mode) {
        return Ok(None);
    }

    let map_scores = gf3258_registration_map_scores(
        live.primary_registration_map,
        &sample.primary_registration_map,
        live.active_validity_packed,
        &sample.active_validity_packed,
        live.secondary_registration_map,
        sample.secondary_registration_map.as_ref(),
        transform,
    );
    let coverage_q8 = gf3258_a9a50_coverage_q8_half_resolution(
        live.quarter_validity_packed,
        &sample.quarter_validity_packed,
        transform,
    );
    let affine = gf3258_terminal_recovery_affine_metrics(transform);

    Ok(Some(Gf3258TerminalRecoveryProducedObservation {
        sample_index,
        transform_live_to_enrolled: transform,
        observation: Gf3258TerminalRecoveryObservation {
            geometry_count: geometry.final_inlier_count as i32,
            map_score: map_scores.score,
            evidence: map_scores.metric_a,
            coverage_q8,
            affine_scale_q8: affine.scale_q8,
            affine_orthogonality_q16: affine.orthogonality_q16,
        },
    }))
}

/// Compose the GF3258 persisted-template terminal recovery scan from the
/// vendor's normal-loop eligibility bits through the recovery aggregate.
///
/// This removes caller-supplied recovery observations. The only retained
/// caller boundary is `eligible_samples`, because those bits depend on earlier
/// normal-path matcher state and are not a property of persisted samples alone.
#[cfg(test)]
pub(crate) fn gf3258_terminal_recovery_scan_persisted_samples(
    samples: &[Gf3258PersistedSample],
    live: Gf3258TerminalRecoveryLiveFeature<'_>,
    config: Gf3258TerminalRecoveryScanConfig<'_>,
) -> Result<Gf3258TerminalRecoveryScanResult, Gf3258TerminalRecoveryScanError> {
    if config.eligible_samples.len() != samples.len() {
        return Err(Gf3258TerminalRecoveryScanError::EligibilityLengthMismatch {
            samples: samples.len(),
            eligibility: config.eligible_samples.len(),
        });
    }
    if config.map_mode != GF3258_VERIFICATION_MAP_MODE_HALF_RESOLUTION {
        return Err(Gf3258TerminalRecoveryScanError::UnsupportedMapMode {
            mode: config.map_mode,
        });
    }

    let mut produced = Vec::new();
    for (sample_index, (sample, eligible)) in samples
        .iter()
        .zip(config.eligible_samples.iter().copied())
        .enumerate()
    {
        if !eligible {
            continue;
        }
        if let Some(observation) = gf3258_persisted_sample_terminal_recovery_observation(
            sample_index,
            sample,
            live,
            config.candidate_matcher,
            config.near_identity_exclusion_mode,
        )? {
            produced.push(observation);
        }
    }

    let observations = produced
        .iter()
        .map(|item| item.observation)
        .collect::<Vec<_>>();
    let aggregation = gf3258_terminal_recovery_aggregate(config.aggregate, &observations);
    Ok(Gf3258TerminalRecoveryScanResult {
        observations: produced,
        aggregation,
    })
}

/// Terminal result plus the exact persisted-sample recovery diagnostics that
/// produced its recovery summary.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Gf3258TerminalRecoveryArbitratedScanResult {
    pub scan: Gf3258TerminalRecoveryScanResult,
    pub arbitration: Gf3258TerminalArbitrationResult,
}

/// Run the exact persisted-sample recovery observation scan and immediately
/// feed its internally constructed summary into terminal arbitration.
///
/// This removes `Gf3258TerminalRecoveryObservation` and
/// `Gf3258TerminalRecoverySummary` from the external caller surface for the
/// cache-disabled core path. The still-explicit `eligible_samples` vector is
/// the prior normal-loop state boundary supplied by the caller.
#[cfg(test)]
pub(crate) fn gf3258_terminal_arbitrate_score_from_persisted_recovery_scan(
    terminal: Gf3258TerminalArbitrationCoreInput,
    samples: &[Gf3258PersistedSample],
    live: Gf3258TerminalRecoveryLiveFeature<'_>,
    scan_config: Gf3258TerminalRecoveryScanConfig<'_>,
) -> Result<Gf3258TerminalRecoveryArbitratedScanResult, Gf3258TerminalRecoveryScanError> {
    let scan = gf3258_terminal_recovery_scan_persisted_samples(samples, live, scan_config)?;
    let recovery = scan.aggregation.summary;
    let arbitration = gf3258_terminal_arbitrate_score(Gf3258TerminalArbitrationInput {
        current_score: terminal.current_score,
        normal_percent: terminal.normal_percent,
        history_count: terminal.history_count,
        matcher_state_688: terminal.matcher_state_688,
        auxiliary_class: terminal.auxiliary_class,
        accepted_samples: terminal.accepted_samples,
        config_48: terminal.config_48,
        current_policy_score: terminal.current_policy_score,
        recovery,
        cache_rescue_enabled: terminal.cache_rescue_enabled,
        cache_rescue_hit: terminal.cache_rescue_hit,
    });
    Ok(Gf3258TerminalRecoveryArbitratedScanResult { scan, arbitration })
}

/// Project one decoded persisted sample into the enrolled representation
/// consumed by the candidate matcher front half.
fn gf3258_persisted_candidate_points(
    sample: &Gf3258PersistedSample,
) -> Vec<Gf3258EnrolledCandidatePoint> {
    sample
        .points
        .iter()
        .map(|point| Gf3258EnrolledCandidatePoint {
            descriptor_10_1f: point.descriptor_10_1f,
            hash20: point.hash20,
            hash28: point.hash28,
        })
        .collect()
}

/// Run one decoded persisted sample through the exact recovered descriptor/hash
/// candidate stage against a fresh live matcher feature.
///
/// DecodeFingerTemplate's post-load split clamp is applied before candidate
/// generation, matching the point partition seen by the vendor matcher.
pub(crate) fn gf3258_generate_persisted_sample_candidates(
    sample: &Gf3258PersistedSample,
    live: Gf3258MatcherFeatureSet<'_>,
    config: Gf3258CandidateMatcherConfig,
) -> Result<Gf3258CandidateGeneration, Gf3258CandidateMatchError> {
    let enrolled_points = gf3258_persisted_candidate_points(sample);
    let polarity_split = sample.matcher_polarity_split();

    gf3258_generate_enrolled_match_candidates(
        Gf3258EnrolledCandidateFeatureSet {
            points: &enrolled_points,
            polarity_split,
        },
        live,
        config,
    )
}

/// Build the subset of loaded FeaturePoint60 state consumed by 704f0/aef60.
///
/// `hash24` and `hash30` are zero because matcher geometry never reads them.
/// The enrolled candidate path also reads only descriptor/hash20/hash28.
fn gf3258_persisted_geometry_points(sample: &Gf3258PersistedSample) -> Vec<Gf3258MatcherPoint> {
    let polarity_split = sample.matcher_polarity_split();
    sample
        .points
        .iter()
        .enumerate()
        .map(|(index, point)| {
            let geometry = point.matcher_geometry();
            Gf3258MatcherPoint {
                polarity: u16::from(index >= polarity_split),
                x_q8: geometry.x_q8,
                y_q8: geometry.y_q8,
                orientation_q12: geometry.orientation_q12,
                descriptor_10_1f: point.descriptor_10_1f,
                hash20: point.hash20,
                hash24: 0,
                hash28: point.hash28,
                hash30: 0,
            }
        })
        .collect()
}

const GF3258_REFINED_MATCH_AMBIGUITY_BEST_MULTIPLIER: i32 = 0x28;
const GF3258_REFINED_MATCH_AMBIGUITY_SECOND_MULTIPLIER: i32 = 0x26;
const GF3258_REFINED_MATCH_MAX_DELTA_Q8: i32 = 0x1500;
const GF3258_REFINEMENT_MIN_INITIAL_INLIERS: usize = 3;
const GF3258_REFINEMENT_MAX_INITIAL_INLIERS: usize = 15;
const GF3258_REFINEMENT_MIN_EVIDENCE: i32 = 0xb4;
const GF3258_REGISTRATION_REPLACEMENT_MIN_SCORE: i32 = 0x80;
const GF3258_REGISTRATION_SCALE_MIN_Q8: i32 = 0xea;
const GF3258_REGISTRATION_SCALE_SPAN_Q8: u32 = 0x2f;
const GF3258_REGISTRATION_ORTHOGONALITY_PENALTY_Q16: i32 = 0x147a;
const GF3258_REGISTRATION_ORTHOGONALITY_SEVERE_Q16: i32 = 0x28f5;

#[inline]
fn gf3258_primary_geometry_needs_refinement(initial_inliers: usize, evidence: i32) -> bool {
    (GF3258_REFINEMENT_MIN_INITIAL_INLIERS..=GF3258_REFINEMENT_MAX_INITIAL_INLIERS)
        .contains(&initial_inliers)
        && evidence > GF3258_REFINEMENT_MIN_EVIDENCE
}

/// Live registration state consumed by the GF3258 type-0x18 normal verifier.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Gf3258VerificationRegistrationInput<'a> {
    pub primary_registration_map: &'a [u8; GF3258_REGISTRATION_PACKED_BYTES],
    pub secondary_registration_map: Option<&'a [u8; GF3258_REGISTRATION_PACKED_BYTES]>,
    pub quarter_validity_packed: &'a [u8; GF3258_QUARTER_VALIDITY_CELLS / 8],
    pub active_validity_packed: &'a [u8; GF3258_REGISTRATION_PACKED_BYTES],
}

/// Registration evidence retained in the 0x150-byte per-sample work record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Gf3258VerificationRegistrationEvidence {
    pub map_score: i32,
    pub evidence: i32,
    pub coverage_q8: i32,
    pub scaled_coverage_q8: i32,
    pub affine_scale_q8: i32,
    pub affine_orthogonality_q16: i32,
    pub transform_live_to_enrolled: Gf3258AffineQ8,
}

impl Gf3258VerificationRegistrationEvidence {
    #[inline]
    pub fn scale_penalty(self) -> i32 {
        ((self.affine_scale_q8 as u32).wrapping_sub(GF3258_REGISTRATION_SCALE_MIN_Q8 as u32)
            > GF3258_REGISTRATION_SCALE_SPAN_Q8) as i32
    }

    #[inline]
    pub fn orthogonality_penalty(self) -> i32 {
        (self.affine_orthogonality_q16 > GF3258_REGISTRATION_ORTHOGONALITY_PENALTY_Q16) as i32
    }

    #[inline]
    pub fn severe_orthogonality(self) -> i32 {
        (self.affine_orthogonality_q16 > GF3258_REGISTRATION_ORTHOGONALITY_SEVERE_Q16) as i32
    }

    #[inline]
    pub fn adjusted_evidence(self) -> i32 {
        self.evidence
            .wrapping_sub(self.scale_penalty().wrapping_mul(4))
            .wrapping_sub(self.orthogonality_penalty().wrapping_mul(4))
    }
}

#[inline]
fn gf3258_registration_evidence_replaces(
    current: Option<Gf3258VerificationRegistrationEvidence>,
    candidate: Gf3258VerificationRegistrationEvidence,
) -> bool {
    if candidate.map_score <= GF3258_REGISTRATION_REPLACEMENT_MIN_SCORE {
        return false;
    }
    let current_adjusted =
        current.map_or(0, Gf3258VerificationRegistrationEvidence::adjusted_evidence);
    candidate.adjusted_evidence() > current_adjusted
}

fn gf3258_verification_registration_evidence(
    sample: &Gf3258PersistedSample,
    live: Gf3258VerificationRegistrationInput<'_>,
    transform_live_to_enrolled: Gf3258AffineQ8,
    quality_scale_q8: i32,
) -> Gf3258VerificationRegistrationEvidence {
    let map_scores = gf3258_registration_map_scores(
        live.primary_registration_map,
        &sample.primary_registration_map,
        live.active_validity_packed,
        &sample.active_validity_packed,
        live.secondary_registration_map,
        sample.secondary_registration_map.as_ref(),
        transform_live_to_enrolled,
    );
    let coverage_q8 = gf3258_a9a50_coverage_q8_half_resolution(
        live.quarter_validity_packed,
        &sample.quarter_validity_packed,
        transform_live_to_enrolled,
    );
    let affine = gf3258_terminal_recovery_affine_metrics(transform_live_to_enrolled);

    Gf3258VerificationRegistrationEvidence {
        map_score: map_scores.score,
        evidence: map_scores.metric_a,
        coverage_q8,
        scaled_coverage_q8: quality_scale_q8.wrapping_mul(coverage_q8) >> 8,
        affine_scale_q8: affine.scale_q8,
        affine_orthogonality_q16: affine.orthogonality_q16,
        transform_live_to_enrolled,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Gf3258PrimaryWorkStage {
    pub initial: Gf3258MatcherGeometryResult,
    pub selected_by_count: Gf3258MatcherGeometryResult,
    pub refined: Option<Gf3258MatcherGeometryResult>,
    pub registration: Option<Gf3258VerificationRegistrationEvidence>,
    pub policy_transform_live_to_enrolled: Gf3258AffineQ8,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Gf3258PersistedPrimaryGeometryError {
    Candidate(Gf3258CandidateMatchError),
    Geometry(Gf3258MatcherGeometryError),
}

#[cfg(test)]
impl std::fmt::Display for Gf3258PersistedPrimaryGeometryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Candidate(error) => write!(f, "GF3258 primary candidate error: {error}"),
            Self::Geometry(error) => write!(f, "GF3258 primary geometry error: {error:?}"),
        }
    }
}

#[cfg(test)]
impl std::error::Error for Gf3258PersistedPrimaryGeometryError {}

#[cfg(test)]
impl From<Gf3258CandidateMatchError> for Gf3258PersistedPrimaryGeometryError {
    fn from(value: Gf3258CandidateMatchError) -> Self {
        Self::Candidate(value)
    }
}

#[cfg(test)]
impl From<Gf3258MatcherGeometryError> for Gf3258PersistedPrimaryGeometryError {
    fn from(value: Gf3258MatcherGeometryError) -> Self {
        Self::Geometry(value)
    }
}

#[inline]
fn gf3258_affine_q16_raw(transform: Gf3258AffineQ8, x_q8: u16, y_q8: u16) -> (i32, i32) {
    let x = i32::from(x_q8);
    let y = i32::from(y_q8);
    let transformed_x = transform
        .a
        .wrapping_mul(x)
        .wrapping_add(transform.b.wrapping_mul(y))
        .wrapping_add(transform.tx.wrapping_shl(8));
    let transformed_y = transform
        .c
        .wrapping_mul(x)
        .wrapping_add(transform.d.wrapping_mul(y))
        .wrapping_add(transform.ty.wrapping_shl(8));
    (transformed_x, transformed_y)
}

#[inline]
fn gf3258_round_q16_coordinate_to_pixel(value: i32) -> i32 {
    (value.wrapping_add(0x80) >> 8).wrapping_add(0x80) >> 8
}

#[inline]
fn gf3258_update_refined_top_two(
    scores: &mut [i32; 2],
    indices: &mut [i32; 2],
    score: i32,
    live_index: i32,
) {
    if score < scores[0] {
        scores[1] = scores[0];
        indices[1] = indices[0];
        scores[0] = score;
        indices[0] = live_index;
    } else if score < scores[1] {
        scores[1] = score;
        indices[1] = live_index;
    }
}

// Preserve the recovered partition inputs and mutable top-two outputs explicitly.
#[allow(clippy::too_many_arguments)]
fn gf3258_process_refined_candidate_partition(
    enrolled: &[Gf3258MatcherPoint],
    live: &[Gf3258MatcherPoint],
    score_matrix: &[u8],
    transform_live_to_enrolled: Gf3258AffineQ8,
    enrolled_range: std::ops::Range<usize>,
    live_range: std::ops::Range<usize>,
    best_scores: &mut [[i32; 2]],
    best_live_indices: &mut [[i32; 2]],
) {
    let inverse = transform_live_to_enrolled.inverse();
    let enrolled_x_limit = GF3258_WIDTH as i32 - 5;
    let enrolled_y_limit = GF3258_HEIGHT as i32 - 5;
    let live_x_limit = GF3258_WIDTH as i32 - 4;
    let live_y_limit = GF3258_HEIGHT as i32 - 4;

    for enrolled_index in enrolled_range {
        let enrolled_point = &enrolled[enrolled_index];
        let (inverse_x, inverse_y) =
            gf3258_affine_q16_raw(inverse, enrolled_point.x_q8, enrolled_point.y_q8);
        let inverse_x = gf3258_round_q16_coordinate_to_pixel(inverse_x);
        let inverse_y = gf3258_round_q16_coordinate_to_pixel(inverse_y);
        if inverse_x >= enrolled_x_limit
            || inverse_y >= enrolled_y_limit
            || inverse_x <= 5
            || inverse_y <= 5
        {
            continue;
        }

        for live_index in live_range.clone() {
            let score =
                score_matrix[enrolled_index * GF3258_MATCH_SCORE_MATRIX_STRIDE + live_index];
            if score == 0xff {
                continue;
            }

            let live_point = &live[live_index];
            let (transformed_x, transformed_y) =
                gf3258_affine_q16_raw(transform_live_to_enrolled, live_point.x_q8, live_point.y_q8);
            let transformed_x_q8 = transformed_x >> 8;
            let transformed_y_q8 = transformed_y >> 8;
            if gf3258_wrapping_abs_i32(
                transformed_x_q8.wrapping_sub(i32::from(enrolled_point.x_q8)),
            ) > GF3258_REFINED_MATCH_MAX_DELTA_Q8
                || gf3258_wrapping_abs_i32(
                    transformed_y_q8.wrapping_sub(i32::from(enrolled_point.y_q8)),
                ) > GF3258_REFINED_MATCH_MAX_DELTA_Q8
            {
                continue;
            }

            let transformed_x = gf3258_round_q16_coordinate_to_pixel(transformed_x);
            let transformed_y = gf3258_round_q16_coordinate_to_pixel(transformed_y);
            if transformed_x >= live_x_limit
                || transformed_y >= live_y_limit
                || transformed_x <= 5
                || transformed_y <= 5
            {
                continue;
            }

            gf3258_update_refined_top_two(
                &mut best_scores[enrolled_index],
                &mut best_live_indices[enrolled_index],
                i32::from(score),
                live_index as i32,
            );
        }
    }
}

fn gf3258_refined_pair_slots_from_score_matrix(
    enrolled: &[Gf3258MatcherPoint],
    enrolled_polarity_split: usize,
    live: Gf3258MatcherFeatureSet<'_>,
    score_matrix: &[u8],
    transform_live_to_enrolled: Gf3258AffineQ8,
) -> [[i32; 2]; GF3258_MATCH_MAX_CANDIDATE_PAIRS] {
    debug_assert!(enrolled_polarity_split <= enrolled.len());
    debug_assert!(live.polarity_split <= live.points.len());
    debug_assert!(score_matrix.len() >= enrolled.len() * GF3258_MATCH_SCORE_MATRIX_STRIDE);

    let mut best_scores = vec![[GF3258_MATCH_SCORE_SENTINEL; 2]; enrolled.len()];
    let mut best_live_indices = vec![[-1; 2]; enrolled.len()];

    gf3258_process_refined_candidate_partition(
        enrolled,
        live.points,
        score_matrix,
        transform_live_to_enrolled,
        0..enrolled_polarity_split,
        0..live.polarity_split,
        &mut best_scores,
        &mut best_live_indices,
    );
    gf3258_process_refined_candidate_partition(
        enrolled,
        live.points,
        score_matrix,
        transform_live_to_enrolled,
        enrolled_polarity_split..enrolled.len(),
        live.polarity_split..live.points.len(),
        &mut best_scores,
        &mut best_live_indices,
    );

    let selected = gf3258_select_correspondences_from_top_two(
        live.points,
        &best_scores,
        &best_live_indices,
        GF3258_REFINED_MATCH_AMBIGUITY_BEST_MULTIPLIER,
        GF3258_REFINED_MATCH_AMBIGUITY_SECOND_MULTIPLIER,
    );
    let mut pair_slots = [[-1; 2]; GF3258_MATCH_MAX_CANDIDATE_PAIRS];
    for (slot, candidate) in selected.iter().enumerate() {
        pair_slots[slot] = [candidate.enrolled_index, candidate.live_index];
    }
    pair_slots
}

/// Reproduce the type-0x18 primary stage of raw `FUN_00172700`.
///
/// The vendor maintains two independent selections after refinement: the
/// larger inlier count becomes `work+0x04`, while the caller-visible affine and
/// registration evidence change only when the refined candidate has
/// `map_score > 128` and strictly better penalized evidence. Keeping those
/// selections separate is required by the later `FUN_00170a80` rescue path.
pub(super) fn gf3258_primary_work_stage_from_candidates(
    sample: &Gf3258PersistedSample,
    enrolled_points: &[Gf3258MatcherPoint],
    live: Gf3258MatcherFeatureSet<'_>,
    registration: Gf3258VerificationRegistrationInput<'_>,
    quality_scale_q8: i32,
    candidates: &Gf3258CandidateGeneration,
) -> Result<Gf3258PrimaryWorkStage, Gf3258MatcherGeometryError> {
    let initial = gf3258_matcher_geometry_from_pair_slots(
        enrolled_points,
        live.points,
        &candidates.pair_slots,
    )?;
    let mut selected_by_count = initial.clone();
    let mut selected_registration = None;
    let mut policy_transform_live_to_enrolled = initial.transform_live_to_enrolled;

    if initial.final_inlier_count > 2 {
        selected_registration = Some(gf3258_verification_registration_evidence(
            sample,
            registration,
            initial.transform_live_to_enrolled,
            quality_scale_q8,
        ));
    }

    let should_refine = match selected_registration {
        Some(evidence) => {
            gf3258_primary_geometry_needs_refinement(initial.final_inlier_count, evidence.evidence)
        }
        None => false,
    };
    if !should_refine {
        return Ok(Gf3258PrimaryWorkStage {
            initial,
            selected_by_count,
            refined: None,
            registration: selected_registration,
            policy_transform_live_to_enrolled,
        });
    }

    let refined_pair_slots = gf3258_refined_pair_slots_from_score_matrix(
        enrolled_points,
        sample.matcher_polarity_split(),
        live,
        &candidates.pair_score_matrix,
        initial.transform_live_to_enrolled,
    );
    let refined =
        gf3258_matcher_geometry_from_pair_slots(enrolled_points, live.points, &refined_pair_slots)?;
    let refined_registration = gf3258_verification_registration_evidence(
        sample,
        registration,
        refined.transform_live_to_enrolled,
        quality_scale_q8,
    );

    if refined.final_inlier_count > initial.final_inlier_count {
        selected_by_count = refined.clone();
    }
    if gf3258_registration_evidence_replaces(selected_registration, refined_registration) {
        selected_registration = Some(refined_registration);
        policy_transform_live_to_enrolled = refined.transform_live_to_enrolled;
    }

    Ok(Gf3258PrimaryWorkStage {
        initial,
        selected_by_count,
        refined: Some(refined),
        registration: selected_registration,
        policy_transform_live_to_enrolled,
    })
}

/// Return the count-selected primary geometry produced by GF3258
/// `FUN_00172700` before rescue.
///
/// This is deliberately the `work+0x04` selection, not necessarily the affine
/// retained for policy scoring. Use [`gf3258_persisted_sample_verification_work`]
/// when the complete geometry/evidence work state is required.
#[cfg(test)]
pub(crate) fn gf3258_persisted_sample_primary_geometry(
    sample: &Gf3258PersistedSample,
    live: Gf3258MatcherFeatureSet<'_>,
    registration: Gf3258VerificationRegistrationInput<'_>,
    candidate_config: Gf3258CandidateMatcherConfig,
) -> Result<Gf3258MatcherGeometryResult, Gf3258PersistedPrimaryGeometryError> {
    let candidates = gf3258_generate_persisted_sample_candidates(sample, live, candidate_config)?;
    let enrolled_points = gf3258_persisted_geometry_points(sample);
    let stage = gf3258_primary_work_stage_from_candidates(
        sample,
        &enrolled_points,
        live,
        registration,
        0x100,
        &candidates,
    )?;
    Ok(stage.selected_by_count)
}

/// Continue already-generated persisted-sample pair slots through the recovered
/// `FUN_001704f0 -> FUN_001aef60` geometry stage.
///
/// Pair slots remain `[enrolled_index, live_index]`; the fitted affine maps the
/// fresh live point coordinates into the vendor-imported persisted coordinates.
pub(crate) fn gf3258_persisted_sample_geometry_from_pair_slots(
    sample: &Gf3258PersistedSample,
    live_points: &[Gf3258MatcherPoint],
    pair_slots: &[[i32; 2]; GF3258_MAX_INITIAL_CORRESPONDENCES],
) -> Result<Gf3258MatcherGeometryResult, Gf3258MatcherGeometryError> {
    let enrolled_points = gf3258_persisted_geometry_points(sample);
    gf3258_matcher_geometry_from_pair_slots(&enrolled_points, live_points, pair_slots)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::{
        GF3258_PIXELS, Gf3258MatcherFeatureSet, Gf3258MatcherPoint,
        gf3258_extract_primary_features_from_c2d40_source,
    };
    use crate::registration::GF3258_REGISTRATION_PACKED_BYTES;
    use crate::template_decode::Gf3258PersistedPoint;

    fn persisted_sample(points: Vec<Gf3258PersistedPoint>, split: i32) -> Gf3258PersistedSample {
        Gf3258PersistedSample {
            primary_registration_map: [0; GF3258_REGISTRATION_PACKED_BYTES],
            secondary_registration_map: None,
            low_threshold_registration_map: None,
            quarter_validity_packed: [0; 40],
            active_validity_packed: [0; GF3258_REGISTRATION_PACKED_BYTES],
            points,
            canonical_member: false,
            relation_checkpoint: 0,
            scalar_108: split,
            c2d40_param3: 0,
            c2d40_param4: 0,
            status_114: 0,
            scalar_118: 0,
            sample_index: 0,
            scalar_120: 0,
            scalar_124: 0,
            scalar_13c: 0,
            embedded_state_140: None,
        }
    }

    fn live_point(descriptor: [u8; 16], x_q8: u16) -> Gf3258MatcherPoint {
        Gf3258MatcherPoint {
            polarity: 0,
            x_q8,
            y_q8: 0,
            orientation_q12: 0,
            descriptor_10_1f: descriptor,
            hash20: 0,
            hash24: 0,
            hash28: 0,
            hash30: 0,
        }
    }

    #[test]
    fn persisted_sample_reaches_candidate_pair_slots_without_geometry() {
        let sample = persisted_sample(
            vec![Gf3258PersistedPoint {
                geometry_word: 0xdead_beef,
                descriptor_10_1f: [0; 16],
                hash20: 0,
                hash28: 0,
                hash2c: 0x1234_5678,
            }],
            0,
        );
        let live = [live_point([0; 16], 0x1200), live_point([0xff; 16], 0x3400)];
        let config = Gf3258CandidateMatcherConfig {
            first_half_hamming_max: 64,
            descriptor_mode_hamming_max: 128,
            ambiguity_best_multiplier: 40,
            ambiguity_second_multiplier: 38,
        };

        let result = gf3258_generate_persisted_sample_candidates(
            &sample,
            Gf3258MatcherFeatureSet {
                points: &live,
                polarity_split: 0,
            },
            config,
        )
        .unwrap();

        assert_eq!(result.selected.len(), 1);
        assert_eq!(result.pair_slots[0], [0, 0]);
        assert_eq!(result.best_scores[0][0], 0);
    }

    #[test]
    fn persisted_candidate_projection_ignores_geometry_and_unneeded_hash2c() {
        let a = persisted_sample(
            vec![Gf3258PersistedPoint {
                geometry_word: 0x0102_0304,
                descriptor_10_1f: [0x5a; 16],
                hash20: 0x1122_3344,
                hash28: 0x5566_7788,
                hash2c: 0xaaaa_aaaa,
            }],
            0,
        );
        let b = persisted_sample(
            vec![Gf3258PersistedPoint {
                geometry_word: 0xfedc_ba98,
                descriptor_10_1f: [0x5a; 16],
                hash20: 0x1122_3344,
                hash28: 0x5566_7788,
                hash2c: 0xbbbb_bbbb,
            }],
            0,
        );

        assert_eq!(
            gf3258_persisted_candidate_points(&a),
            gf3258_persisted_candidate_points(&b)
        );
    }

    #[test]
    fn persisted_pair_slots_continue_through_vendor_imported_geometry() {
        fn point(x_q8: u16, y_q8: u16) -> Gf3258PersistedPoint {
            Gf3258PersistedPoint {
                geometry_word: (u32::from(y_q8) << 4) | (u32::from(x_q8) << 16),
                descriptor_10_1f: [0; 16],
                hash20: 0,
                hash28: 0,
                hash2c: 0,
            }
        }

        let sample = persisted_sample(
            vec![
                point(0x1000, 0x1000),
                point(0x3000, 0x1000),
                point(0x1000, 0x3000),
            ],
            1,
        );
        let live = [
            Gf3258MatcherPoint {
                y_q8: 0x1000,
                ..live_point([0; 16], 0x1000)
            },
            Gf3258MatcherPoint {
                y_q8: 0x1000,
                ..live_point([0; 16], 0x3000)
            },
            Gf3258MatcherPoint {
                y_q8: 0x3000,
                ..live_point([0; 16], 0x1000)
            },
        ];
        let mut pair_slots = [[-1, -1]; GF3258_MAX_INITIAL_CORRESPONDENCES];
        pair_slots[0] = [0, 0];
        pair_slots[1] = [1, 1];
        pair_slots[2] = [2, 2];

        let result =
            gf3258_persisted_sample_geometry_from_pair_slots(&sample, &live, &pair_slots).unwrap();

        assert_eq!(result.spatial_inlier_count, 3);
        assert_eq!(result.final_inlier_count, 3);
        assert_eq!(result.spatial_mse_q16, 0);
        assert_eq!(result.transform_live_to_enrolled.a, 0x100);
        assert_eq!(result.transform_live_to_enrolled.b, 0);
        assert_eq!(result.transform_live_to_enrolled.tx, 0);
        assert_eq!(result.transform_live_to_enrolled.c, 0);
        assert_eq!(result.transform_live_to_enrolled.d, 0x100);
        assert_eq!(result.transform_live_to_enrolled.ty, 0);
    }

    #[test]
    fn gf3258_metric_contribution_uses_exact_divisor_and_rounding() {
        assert_eq!(GF3258_VERIFICATION_METRIC_DIVISOR, 31);
        assert_eq!(gf3258_verification_metric_contribution_q8(0), 0);
        assert_eq!(gf3258_verification_metric_contribution_q8(1), 8);
        assert_eq!(gf3258_verification_metric_contribution_q8(5), 41);
        assert_eq!(gf3258_verification_metric_contribution_q8(15), 124);
        assert_eq!(gf3258_verification_metric_contribution_q8(16), 132);
        assert_eq!(gf3258_verification_metric_contribution_q8(31), 256);
    }

    #[test]
    fn gf3258_score_accumulator_matches_vendor_final_percent_ordering() {
        let mut score = Gf3258VerificationScoreAccumulator::new();
        assert_eq!(score.percent(), None);

        score.push_accepted_metric(31);
        assert_eq!(score.sum_q8(), 256);
        assert_eq!(score.accepted_samples(), 1);
        assert_eq!(score.percent(), Some(100));

        score.push_accepted_metric(16);
        assert_eq!(score.sum_q8(), 388);
        assert_eq!(score.accepted_samples(), 2);
        // Vendor order is ((sum_q8 * 100) / count) >> 8.
        assert_eq!(score.percent(), Some(75));
    }

    #[test]
    fn score_accumulator_does_not_apply_an_unproven_match_threshold() {
        let mut score = Gf3258VerificationScoreAccumulator::new();
        score.push_accepted_metric(5);
        assert_eq!(score.percent(), Some(16));
        score.push_accepted_metric(30);
        assert_eq!(score.percent(), Some(56));
    }

    #[test]
    fn complete_vendor_score_match_boundary_is_strictly_positive() {
        assert!(!gf3258_vendor_verification_score_is_match(i32::MIN));
        assert!(!gf3258_vendor_verification_score_is_match(-1));
        assert!(!gf3258_vendor_verification_score_is_match(0));
        assert!(gf3258_vendor_verification_score_is_match(1));
        assert!(gf3258_vendor_verification_score_is_match(100));
    }

    #[test]
    fn gf3258_policy_score_accepts_route_a_with_exact_metric_normalization() {
        let record = Gf3258VerificationPolicyRecord {
            geometry_count_00: 5,
            metric_04: 8,
            field_14: 220,
            field_20: 220,
            field_2c: 42,
            ..Default::default()
        };

        assert_eq!(gf3258_verification_policy_score(record), 25);
    }

    #[test]
    fn gf3258_policy_score_route_b_uses_strict_boundary_after_penalty() {
        let accepted = Gf3258VerificationPolicyRecord {
            geometry_count_00: 3,
            metric_04: 7,
            field_10: 235,
            field_14: 206,
            field_20: 200,
            field_24: 120,
            field_2c: 10,
            ..Default::default()
        };
        let boundary = Gf3258VerificationPolicyRecord {
            field_14: 205,
            ..accepted
        };

        // geometry_count <= 4 contributes one three-point penalty to each
        // evidence field: 206 + 200 - 6 == 400, which is strictly > 399.
        assert_eq!(gf3258_verification_policy_score(accepted), 22);
        assert_eq!(gf3258_verification_policy_score(boundary), 0);
    }

    #[test]
    fn gf3258_policy_score_accepts_route_c_at_its_strict_thresholds() {
        let accepted = Gf3258VerificationPolicyRecord {
            geometry_count_00: 6,
            metric_04: 15,
            field_14: 210,
            field_20: 210,
            field_24: 63,
            field_2c: 41,
            ..Default::default()
        };
        let low_field_24 = Gf3258VerificationPolicyRecord {
            field_24: 62,
            ..accepted
        };

        assert_eq!(gf3258_verification_policy_score(accepted), 48);
        assert_eq!(gf3258_verification_policy_score(low_field_24), 0);
    }

    #[test]
    fn gf3258_policy_score_applies_global_scalar_and_field_2c_gates() {
        let base = Gf3258VerificationPolicyRecord {
            geometry_count_00: 5,
            metric_04: 31,
            field_14: 220,
            field_20: 220,
            field_2c: 42,
            ..Default::default()
        };
        let high_scalar_sum = Gf3258VerificationPolicyRecord {
            live_scalar_54: 100,
            enrolled_scalar_5c: 71,
            ..base
        };
        let low_field_2c = Gf3258VerificationPolicyRecord {
            field_2c: 9,
            ..base
        };

        assert_eq!(gf3258_verification_policy_score(base), 100);
        assert_eq!(gf3258_verification_policy_score(high_scalar_sum), 0);
        assert_eq!(gf3258_verification_policy_score(low_field_2c), 0);
    }

    #[test]
    fn gf3258_policy_penalty_indicators_can_suppress_route_b() {
        let base = Gf3258VerificationPolicyRecord {
            geometry_count_00: 3,
            metric_04: 8,
            field_10: 235,
            field_14: 206,
            field_20: 200,
            field_24: 120,
            field_2c: 10,
            ..Default::default()
        };
        let penalized = Gf3258VerificationPolicyRecord {
            penalty_30: 1,
            ..base
        };

        assert_eq!(gf3258_verification_policy_score(base), 25);
        assert_eq!(gf3258_verification_policy_score(penalized), 0);
    }

    #[test]
    fn vendor_fallback_nonpositive_score_encodes_exact_reason_bits() {
        assert_eq!(
            gf3258_encode_vendor_fallback_nonpositive_score(0, false, 0, 0),
            -GF3258_FALLBACK_REASON_LOW_GEOMETRY
        );
        assert_eq!(
            gf3258_encode_vendor_fallback_nonpositive_score(5, true, 0xcf, 0x7f),
            -(GF3258_FALLBACK_REASON_LOW_GEOMETRY
                | GF3258_FALLBACK_REASON_LOW_EVIDENCE
                | GF3258_FALLBACK_REASON_LOW_QUALITY)
        );
        assert_eq!(
            gf3258_encode_vendor_fallback_nonpositive_score(6, true, 0xd0, 0x80),
            0
        );
    }

    #[test]
    fn vendor_fallback_finalizer_caps_positive_score_and_preserves_failure_encoding() {
        assert_eq!(
            gf3258_finalize_vendor_fallback_score(25, 0, false, 0, 0),
            25
        );
        assert_eq!(
            gf3258_finalize_vendor_fallback_score(101, 0, false, 0, 0),
            100
        );
        assert_eq!(
            gf3258_finalize_vendor_fallback_score(0, 5, true, 0xcf, 0x7f),
            -7
        );
    }

    fn terminal_input() -> Gf3258TerminalArbitrationInput {
        Gf3258TerminalArbitrationInput {
            current_score: 0,
            normal_percent: 42,
            history_count: 0,
            matcher_state_688: 0,
            auxiliary_class: 0,
            accepted_samples: 0,
            config_48: 0,
            current_policy_score: 0,
            recovery: Gf3258TerminalRecoverySummary {
                policy_score: 0,
                accumulated_geometry_count: 6,
                had_candidate: true,
                best_evidence: 0xd0,
                best_quality: 0x80,
            },
            cache_rescue_enabled: false,
            cache_rescue_hit: false,
        }
    }

    #[test]
    fn terminal_recovery_aggregate_empty_scan_is_exact_zero_state() {
        let result =
            gf3258_terminal_recovery_aggregate(Gf3258TerminalRecoveryConfig::default(), &[]);
        assert_eq!(result.summary, Gf3258TerminalRecoverySummary::default());
        assert_eq!(result.admitted_candidates, 0);
        assert_eq!(result.selected_observation_index, None);
    }

    #[test]
    fn terminal_recovery_candidate_presence_precedes_admission() {
        let observation = Gf3258TerminalRecoveryObservation {
            geometry_count: 9,
            map_score: 207,
            evidence: 195,
            coverage_q8: 256,
            affine_scale_q8: 256,
            affine_orthogonality_q16: 0,
        };
        let result = gf3258_terminal_recovery_aggregate(
            Gf3258TerminalRecoveryConfig {
                map_score_base: 0,
                quality_scale_q8: 256,
                apply_affine_penalty: false,
            },
            &[observation],
        );
        assert!(result.summary.had_candidate);
        assert_eq!(result.summary.accumulated_geometry_count, 0);
        assert_eq!(result.summary.best_evidence, 0);
        assert_eq!(result.summary.best_quality, 0);
        assert_eq!(result.admitted_candidates, 0);
    }

    #[test]
    fn terminal_recovery_admission_thresholds_are_strict() {
        let base = Gf3258TerminalRecoveryConfig {
            map_score_base: 1,
            quality_scale_q8: 128,
            apply_affine_penalty: false,
        };
        let observations = [
            Gf3258TerminalRecoveryObservation {
                geometry_count: 7,
                map_score: 208,
                evidence: 196,
                coverage_q8: 128,
                affine_scale_q8: 256,
                affine_orthogonality_q16: 0,
            },
            Gf3258TerminalRecoveryObservation {
                geometry_count: 9,
                map_score: 209,
                evidence: 197,
                coverage_q8: 128,
                affine_scale_q8: 256,
                affine_orthogonality_q16: 0,
            },
        ];
        let result = gf3258_terminal_recovery_aggregate(base, &observations);
        assert_eq!(result.summary.accumulated_geometry_count, 9);
        assert_eq!(result.summary.best_evidence, 197);
        assert_eq!(result.summary.best_quality, 64);
        assert_eq!(result.admitted_candidates, 1);
        assert_eq!(result.selected_observation_index, Some(1));
    }

    #[test]
    fn terminal_recovery_affine_penalty_uses_unsigned_scale_window() {
        assert_eq!(gf3258_terminal_recovery_affine_penalty_count(233, 0), 1);
        assert_eq!(gf3258_terminal_recovery_affine_penalty_count(234, 0), 0);
        assert_eq!(gf3258_terminal_recovery_affine_penalty_count(281, 0), 0);
        assert_eq!(gf3258_terminal_recovery_affine_penalty_count(282, 0), 1);
        assert_eq!(
            gf3258_terminal_recovery_affine_penalty_count(256, 0x147a),
            0
        );
        assert_eq!(
            gf3258_terminal_recovery_affine_penalty_count(256, 0x147b),
            1
        );
        assert_eq!(
            gf3258_terminal_recovery_affine_penalty_count(233, 0x147b),
            2
        );
    }

    #[test]
    fn terminal_recovery_selection_is_evidence_then_geometry_then_quality() {
        let observations = [
            Gf3258TerminalRecoveryObservation {
                geometry_count: 5,
                map_score: 208,
                evidence: 196,
                coverage_q8: 128,
                affine_scale_q8: 256,
                affine_orthogonality_q16: 0,
            },
            Gf3258TerminalRecoveryObservation {
                geometry_count: 10,
                map_score: 208,
                evidence: 220,
                coverage_q8: 100,
                affine_scale_q8: 233,
                affine_orthogonality_q16: 0,
            },
            Gf3258TerminalRecoveryObservation {
                geometry_count: 8,
                map_score: 300,
                evidence: 220,
                coverage_q8: 200,
                affine_scale_q8: 256,
                affine_orthogonality_q16: 0x147b,
            },
            Gf3258TerminalRecoveryObservation {
                geometry_count: 12,
                map_score: 300,
                evidence: 220,
                coverage_q8: 180,
                affine_scale_q8: 256,
                affine_orthogonality_q16: 0,
            },
            Gf3258TerminalRecoveryObservation {
                geometry_count: 12,
                map_score: 300,
                evidence: 220,
                coverage_q8: 220,
                affine_scale_q8: 256,
                affine_orthogonality_q16: 0,
            },
        ];
        let result = gf3258_terminal_recovery_aggregate(
            Gf3258TerminalRecoveryConfig {
                map_score_base: 0,
                quality_scale_q8: 256,
                apply_affine_penalty: true,
            },
            &observations,
        );
        assert_eq!(result.summary.accumulated_geometry_count, 47);
        assert_eq!(result.summary.best_evidence, 220);
        assert_eq!(result.summary.best_quality, 220);
        assert_eq!(result.admitted_candidates, 5);
        assert_eq!(result.selected_observation_index, Some(4));
    }

    #[test]
    fn terminal_recovery_exact_producer_cannot_emit_positive_policy_score() {
        let observation = Gf3258TerminalRecoveryObservation {
            geometry_count: 31,
            map_score: i32::MAX,
            evidence: i32::MAX,
            coverage_q8: 256,
            affine_scale_q8: 256,
            affine_orthogonality_q16: 0,
        };
        let result = gf3258_terminal_recovery_aggregate(
            Gf3258TerminalRecoveryConfig {
                map_score_base: i32::MIN,
                quality_scale_q8: 256,
                apply_affine_penalty: false,
            },
            &[observation],
        );
        assert_eq!(result.summary.policy_score, 0);
    }

    #[test]
    fn terminal_recovery_wrapper_builds_exact_nonpositive_reason_mask() {
        let observations = [Gf3258TerminalRecoveryObservation {
            geometry_count: 5,
            map_score: 300,
            evidence: 207,
            coverage_q8: 127,
            affine_scale_q8: 256,
            affine_orthogonality_q16: 0,
        }];
        let result = gf3258_terminal_arbitrate_score_from_recovery_observations(
            Gf3258TerminalArbitrationCoreInput::default(),
            Gf3258TerminalRecoveryConfig {
                map_score_base: 0,
                quality_scale_q8: 256,
                apply_affine_penalty: false,
            },
            &observations,
        );
        assert_eq!(result.score, -7);
        assert_eq!(
            result.disposition,
            Gf3258TerminalScoreDisposition::RecoveryNonPositive
        );
        assert!(!result.mark_recovery_success);
    }

    #[test]
    fn terminal_recovery_wrapper_cannot_take_recovery_positive_branch() {
        let observations = [Gf3258TerminalRecoveryObservation {
            geometry_count: 31,
            map_score: 1000,
            evidence: 1000,
            coverage_q8: 256,
            affine_scale_q8: 256,
            affine_orthogonality_q16: 0,
        }];
        let result = gf3258_terminal_arbitrate_score_from_recovery_observations(
            Gf3258TerminalArbitrationCoreInput::default(),
            Gf3258TerminalRecoveryConfig {
                map_score_base: 0,
                quality_scale_q8: 256,
                apply_affine_penalty: false,
            },
            &observations,
        );
        assert_eq!(result.score, 0);
        assert_eq!(
            result.disposition,
            Gf3258TerminalScoreDisposition::RecoveryNonPositive
        );
        assert!(!result.mark_recovery_success);
    }

    #[test]
    fn terminal_arbitration_retains_existing_nonzero_score_before_fallback() {
        let result = gf3258_terminal_arbitrate_score(Gf3258TerminalArbitrationInput {
            current_score: 37,
            history_count: 5,
            ..terminal_input()
        });
        assert_eq!(result.score, 37);
        assert_eq!(
            result.disposition,
            Gf3258TerminalScoreDisposition::RetainedCurrentScore
        );
        assert!(!result.mark_recovery_success);
    }

    #[test]
    fn terminal_arbitration_suppresses_score_when_history_gate_forces_zero() {
        let result = gf3258_terminal_arbitrate_score(Gf3258TerminalArbitrationInput {
            current_score: 37,
            history_count: 6,
            matcher_state_688: 0,
            ..terminal_input()
        });
        assert_eq!(result.score, 0);
        assert_eq!(
            result.disposition,
            Gf3258TerminalScoreDisposition::TerminalGateExit
        );
    }

    #[test]
    fn terminal_arbitration_auxiliary_class_can_exit_with_zero() {
        let result = gf3258_terminal_arbitrate_score(Gf3258TerminalArbitrationInput {
            auxiliary_class: 4,
            ..terminal_input()
        });
        assert_eq!(result.score, 0);
        assert_eq!(
            result.disposition,
            Gf3258TerminalScoreDisposition::TerminalGateExit
        );
    }

    #[test]
    fn terminal_arbitration_restores_normal_percent_for_current_policy_admission() {
        let result = gf3258_terminal_arbitrate_score(Gf3258TerminalArbitrationInput {
            normal_percent: 61,
            accepted_samples: 3,
            config_48: 0,
            current_policy_score: 1,
            ..terminal_input()
        });
        assert_eq!(result.score, 61);
        assert_eq!(
            result.disposition,
            Gf3258TerminalScoreDisposition::RestoredNormalPercent
        );
    }

    #[test]
    fn terminal_arbitration_caps_positive_recovery_and_marks_success() {
        let result = gf3258_terminal_arbitrate_score(Gf3258TerminalArbitrationInput {
            recovery: Gf3258TerminalRecoverySummary {
                policy_score: 101,
                ..terminal_input().recovery
            },
            ..terminal_input()
        });
        assert_eq!(result.score, 100);
        assert_eq!(
            result.disposition,
            Gf3258TerminalScoreDisposition::RecoveryPositive
        );
        assert!(result.mark_recovery_success);
    }

    #[test]
    fn terminal_arbitration_preserves_exact_nonpositive_recovery_mask_without_cache() {
        let result = gf3258_terminal_arbitrate_score(Gf3258TerminalArbitrationInput {
            recovery: Gf3258TerminalRecoverySummary {
                policy_score: 0,
                accumulated_geometry_count: 5,
                had_candidate: true,
                best_evidence: 0xcf,
                best_quality: 0x7f,
            },
            ..terminal_input()
        });
        assert_eq!(result.score, -7);
        assert_eq!(
            result.disposition,
            Gf3258TerminalScoreDisposition::RecoveryNonPositive
        );
        assert!(!result.mark_recovery_success);
    }

    #[test]
    fn terminal_arbitration_cache_miss_replaces_negative_fallback_with_zero() {
        let result = gf3258_terminal_arbitrate_score(Gf3258TerminalArbitrationInput {
            cache_rescue_enabled: true,
            cache_rescue_hit: false,
            recovery: Gf3258TerminalRecoverySummary {
                accumulated_geometry_count: 5,
                ..terminal_input().recovery
            },
            ..terminal_input()
        });
        assert_eq!(result.score, 0);
        assert_eq!(
            result.disposition,
            Gf3258TerminalScoreDisposition::CacheRescueMiss
        );
    }

    #[test]
    fn terminal_arbitration_cache_hit_emits_vendor_10000_sentinel() {
        let result = gf3258_terminal_arbitrate_score(Gf3258TerminalArbitrationInput {
            cache_rescue_enabled: true,
            cache_rescue_hit: true,
            recovery: Gf3258TerminalRecoverySummary {
                accumulated_geometry_count: 5,
                ..terminal_input().recovery
            },
            ..terminal_input()
        });
        assert_eq!(result.score, GF3258_CACHE_RESCUE_MATCH_SCORE);
        assert_eq!(result.score, 10_000);
        assert_eq!(
            result.disposition,
            Gf3258TerminalScoreDisposition::CacheRescueMatch
        );
        assert!(gf3258_vendor_verification_score_is_match(result.score));
    }

    #[test]
    fn geometry_work_metric_bonus_uses_exact_70a80_gates_and_cap() {
        assert_eq!(gf3258_finalize_geometry_work_metric(30, 0, 30, 9), 30);
        assert_eq!(gf3258_finalize_geometry_work_metric(30, 0, 31, 10), 30);
        assert_eq!(gf3258_finalize_geometry_work_metric(30, 0, 31, 9), 31);
        assert_eq!(gf3258_finalize_geometry_work_metric(31, 0, 31, 9), 31);
    }

    #[test]
    fn geometry_work_metric_merges_rescue_after_primary_bonus() {
        assert_eq!(gf3258_finalize_geometry_work_metric(15, 20, 31, 9), 20);
        assert_eq!(gf3258_finalize_geometry_work_metric(20, 15, 31, 9), 21);
        assert_eq!(gf3258_finalize_geometry_work_metric(31, 31, 31, 9), 31);
    }

    #[test]
    fn geometry_work_metric_is_entirely_704f0_derived_when_no_bonus_applies() {
        assert_eq!(gf3258_finalize_geometry_work_metric(12, 0, 0, -1), 12);
        assert_eq!(gf3258_finalize_geometry_work_metric(12, 18, 0, -1), 18);
    }

    #[test]
    fn late_policy_context_uses_signed_max_of_history_and_profile_state() {
        let context = Gf3258LatePolicyContext {
            history_low: 3,
            profile_state: 5,
            ..Default::default()
        };
        assert_eq!(context.profile_max(), 5);

        let context = Gf3258LatePolicyContext {
            history_low: 7,
            profile_state: 5,
            ..Default::default()
        };
        assert_eq!(context.profile_max(), 7);

        let context = Gf3258LatePolicyContext {
            history_low: -2,
            profile_state: -5,
            ..Default::default()
        };
        assert_eq!(context.profile_max(), -2);
    }

    #[test]
    fn late_policy_bidirectional_overlap_identity_is_full_gf3258_frame() {
        let overlap = gf3258_late_policy_bidirectional_overlap(Gf3258AffineQ8::IDENTITY);
        assert_eq!(overlap.count, 80 * 64);
        assert_eq!(overlap.count_times_100, 80 * 64 * 100);
    }

    #[test]
    fn late_policy_bidirectional_overlap_keeps_larger_direction() {
        let transform = Gf3258AffineQ8 {
            tx: 3 * 256,
            ty: -2 * 256,
            ..Gf3258AffineQ8::IDENTITY
        };
        let forward = gf3258_scanline_overlap(64, 80, 64, 80, transform).count;
        let inverse = gf3258_scanline_overlap(64, 80, 64, 80, transform.inverse()).count;
        let overlap = gf3258_late_policy_bidirectional_overlap(transform);

        assert_eq!(overlap.count, forward.max(inverse));
        assert_eq!(overlap.count_times_100, overlap.count * 100);
    }

    #[test]
    fn late_policy_reject_outcome_increments_only_the_reject_counter() {
        let mut reject_count = 9;
        let mut primary_flag = 3;
        Gf3258LatePolicyOutcome {
            reject: true,
            clear_primary_flag: false,
        }
        .apply(&mut reject_count, &mut primary_flag);

        assert_eq!(reject_count, 10);
        assert_eq!(primary_flag, 3);
    }

    #[test]
    fn late_policy_survive_outcome_preserves_reject_counter() {
        let mut reject_count = -4;
        let mut primary_flag = 2;
        Gf3258LatePolicyOutcome {
            reject: false,
            clear_primary_flag: false,
        }
        .apply(&mut reject_count, &mut primary_flag);

        assert_eq!(reject_count, -4);
        assert_eq!(primary_flag, 2);
    }

    #[test]
    fn late_policy_flag_clear_is_independent_of_reject_decision() {
        for reject in [false, true] {
            let mut reject_count = 0;
            let mut primary_flag = 7;
            Gf3258LatePolicyOutcome {
                reject,
                clear_primary_flag: true,
            }
            .apply(&mut reject_count, &mut primary_flag);

            assert_eq!(reject_count, if reject { 1 } else { 0 });
            assert_eq!(primary_flag, 0);
        }
    }

    #[test]
    fn late_policy_reject_counter_uses_vendor_wrapping_i32_increment() {
        let mut reject_count = i32::MAX;
        let mut primary_flag = 1;
        Gf3258LatePolicyOutcome {
            reject: true,
            clear_primary_flag: false,
        }
        .apply(&mut reject_count, &mut primary_flag);

        assert_eq!(reject_count, i32::MIN);
        assert_eq!(primary_flag, 1);
    }

    fn late_policy_vendor_vector_record(values: [i32; 13]) -> Gf3258LatePolicyRecord {
        Gf3258LatePolicyRecord {
            geometry_count_00: values[0],
            metric_04: values[1],
            field_10: values[2],
            field_14: values[3],
            field_20: values[4],
            field_24: values[5],
            field_28: values[6],
            field_2c: values[7],
            field_34: values[8],
            field_38: values[9],
            live_scalar_54: values[10],
            enrolled_scalar_5c: values[11],
            field_64: values[12],
        }
    }

    fn translated_identity(tx_pixels: i32, ty_pixels: i32) -> Gf3258AffineQ8 {
        Gf3258AffineQ8 {
            tx: tx_pixels * 256,
            ty: ty_pixels * 256,
            ..Gf3258AffineQ8::IDENTITY
        }
    }

    #[test]
    fn late_policy_vendor_vector_survives_without_flag_clear() {
        let record =
            late_policy_vendor_vector_record([17, 29, 133, 195, 141, 66, 53, 45, 1, 3, 70, 44, 14]);
        let context = Gf3258LatePolicyContext {
            live_quality: 38,
            history_low: 7,
            history_high: 0,
            profile_state: 5,
            current_reject_count: 4,
        };

        assert_eq!(
            gf3258_late_policy_outcome(record, context, translated_identity(11, 6)),
            Gf3258LatePolicyOutcome {
                reject: false,
                clear_primary_flag: false,
            }
        );
    }

    #[test]
    fn late_policy_vendor_vector_rejects_without_flag_clear() {
        let record =
            late_policy_vendor_vector_record([8, 23, 155, 172, 298, 179, 38, 92, 2, 2, 26, 31, 24]);
        let context = Gf3258LatePolicyContext {
            live_quality: 87,
            history_low: 3,
            history_high: 5,
            profile_state: 2,
            current_reject_count: 9,
        };

        assert_eq!(
            gf3258_late_policy_outcome(record, context, translated_identity(-5, 1)),
            Gf3258LatePolicyOutcome {
                reject: true,
                clear_primary_flag: false,
            }
        );
    }

    #[test]
    fn late_policy_vendor_vector_survives_and_clears_flag() {
        let record =
            late_policy_vendor_vector_record([9, 2, 184, 138, 271, 57, 42, 20, 3, 1, 95, 45, 4]);
        let context = Gf3258LatePolicyContext {
            live_quality: 25,
            history_low: 3,
            history_high: 1,
            profile_state: 2,
            current_reject_count: 4,
        };

        assert_eq!(
            gf3258_late_policy_outcome(record, context, translated_identity(1, -2)),
            Gf3258LatePolicyOutcome {
                reject: false,
                clear_primary_flag: true,
            }
        );
    }

    #[test]
    fn late_policy_vendor_vector_rejects_and_clears_flag() {
        let record =
            late_policy_vendor_vector_record([16, 14, 223, 108, 106, 24, 87, 23, 1, 1, 120, 71, 6]);
        let context = Gf3258LatePolicyContext {
            live_quality: 88,
            history_low: 7,
            history_high: 6,
            profile_state: 1,
            current_reject_count: 10,
        };

        assert_eq!(
            gf3258_late_policy_outcome(record, context, translated_identity(0, 5)),
            Gf3258LatePolicyOutcome {
                reject: true,
                clear_primary_flag: true,
            }
        );
    }

    fn post_survival_vendor_vector_record(values: [i32; 15]) -> Gf3258PostSurvivalPolicyRecord {
        Gf3258PostSurvivalPolicyRecord {
            geometry_count_00: values[0],
            metric_04: values[1],
            field_10: values[2],
            field_14: values[3],
            field_1c: values[4],
            field_20: values[5],
            field_24: values[6],
            field_28: values[7],
            field_2c: values[8],
            field_30: values[9],
            field_34: values[10],
            field_38: values[11],
            live_scalar_54: values[12],
            enrolled_scalar_5c: values[13],
            field_64: values[14],
        }
    }

    #[test]
    fn post_survival_vendor_vector_preserves_both_flags() {
        let record = post_survival_vendor_vector_record([
            122, 292, 27, 139, 232, 234, -91, -62, 73, 103, 317, -57, 213, 219, 91,
        ]);
        let context = Gf3258PostSurvivalPolicyContext {
            scalar_43: 276,
            scalar_56: 294,
            candidate_state: -1,
            mode_value: 7,
            ratio_q8: 171,
        };

        assert_eq!(
            gf3258_post_survival_policy_flags(
                record,
                context,
                Gf3258PostSurvivalPolicyFlags {
                    score_gate: 1,
                    policy_class: 2,
                },
            ),
            Gf3258PostSurvivalPolicyFlags {
                score_gate: 1,
                policy_class: 2,
            }
        );
    }

    #[test]
    fn post_survival_vendor_vector_clears_policy_class_only() {
        let record = post_survival_vendor_vector_record([
            36, -21, 41, 94, 219, 115, -56, -28, 310, -49, 133, -54, 146, 2, 33,
        ]);
        let context = Gf3258PostSurvivalPolicyContext {
            scalar_43: -68,
            scalar_56: 266,
            candidate_state: 3,
            mode_value: 5,
            ratio_q8: 186,
        };

        assert_eq!(
            gf3258_post_survival_policy_flags(
                record,
                context,
                Gf3258PostSurvivalPolicyFlags {
                    score_gate: 1,
                    policy_class: 2,
                },
            ),
            Gf3258PostSurvivalPolicyFlags {
                score_gate: 1,
                policy_class: 0,
            }
        );
    }

    #[test]
    fn post_survival_vendor_vector_clears_both_flags() {
        let record = post_survival_vendor_vector_record([
            10, 122, 134, 339, -64, 102, 240, 133, -12, -82, 121, 10, 316, 96, -5,
        ]);
        let context = Gf3258PostSurvivalPolicyContext {
            scalar_43: 221,
            scalar_56: 311,
            candidate_state: 12,
            mode_value: 7,
            ratio_q8: 258,
        };

        assert_eq!(
            gf3258_post_survival_policy_flags(
                record,
                context,
                Gf3258PostSurvivalPolicyFlags {
                    score_gate: 1,
                    policy_class: 2,
                },
            ),
            Gf3258PostSurvivalPolicyFlags {
                score_gate: 0,
                policy_class: 0,
            }
        );
    }

    #[test]
    fn post_survival_zero_score_gate_is_never_raised() {
        let record = post_survival_vendor_vector_record([
            122, 292, 27, 139, 232, 234, -91, -62, 73, 103, 317, -57, 213, 219, 91,
        ]);
        let context = Gf3258PostSurvivalPolicyContext {
            scalar_43: 276,
            scalar_56: 294,
            candidate_state: -1,
            mode_value: 7,
            ratio_q8: 171,
        };

        assert_eq!(
            gf3258_post_survival_policy_flags(
                record,
                context,
                Gf3258PostSurvivalPolicyFlags {
                    score_gate: 0,
                    policy_class: 2,
                },
            ),
            Gf3258PostSurvivalPolicyFlags {
                score_gate: 0,
                policy_class: 2,
            }
        );
    }

    fn flag_policy_vendor_vector_record(values: [i32; 14]) -> Gf3258VerificationFlagPolicyRecord {
        Gf3258VerificationFlagPolicyRecord {
            geometry_count_00: values[0],
            metric_04: values[1],
            field_10: values[2],
            field_14: values[3],
            field_20: values[4],
            field_24: values[5],
            field_28: values[6],
            field_2c: values[7],
            field_30: values[8],
            field_34: values[9],
            field_38: values[10],
            live_scalar_54: values[11],
            field_58: values[12],
            enrolled_scalar_5c: values[13],
        }
    }

    fn flag_policy_context(
        scalar_43: i32,
        scalar_44: i32,
        config_00: i32,
        config_04: i32,
        config_48: i32,
    ) -> Gf3258VerificationFlagPolicyContext {
        Gf3258VerificationFlagPolicyContext {
            scalar_43,
            scalar_44,
            candidate_state: 2,
            config_00,
            config_04,
            config_48,
        }
    }

    #[test]
    fn verification_flag_prepass_vendor_vector_zero_outputs() {
        let record = flag_policy_vendor_vector_record([
            -5, 13, -29, 220, 70, -6, 312, 97, -5, -58, 73, 322, 205, 344,
        ]);
        let context = flag_policy_context(10, -4, -10, -1, 325);
        assert_eq!(
            gf3258_verification_flag_prepass(record, context),
            Gf3258VerificationFlagPrepass {
                flags: Gf3258PostSurvivalPolicyFlags {
                    score_gate: 0,
                    policy_class: 0,
                },
                auxiliary_flag: 0,
                bypass_refinement: false,
            }
        );
    }

    #[test]
    fn verification_flag_prepass_vendor_vector_policy_two_score_one() {
        let record = flag_policy_vendor_vector_record([
            334, 331, 67, 262, 306, 164, 349, 57, 99, 303, 14, 59, 201, 208,
        ]);
        let mut context = flag_policy_context(77, 230, 1, 11, 357);
        context.candidate_state = 1;
        assert_eq!(
            gf3258_verification_flag_prepass(record, context),
            Gf3258VerificationFlagPrepass {
                flags: Gf3258PostSurvivalPolicyFlags {
                    score_gate: 1,
                    policy_class: 2,
                },
                auxiliary_flag: 0,
                bypass_refinement: true,
            }
        );
    }

    #[test]
    fn verification_flag_prepass_preserves_auxiliary_output() {
        let record = flag_policy_vendor_vector_record([
            -64, 18, 343, 160, 332, 262, -95, -47, 25, 195, -34, 95, -65, -49,
        ]);
        let context = flag_policy_context(350, 229, 17, 14, 135);
        assert_eq!(
            gf3258_verification_flag_prepass(record, context).auxiliary_flag,
            1
        );
    }

    #[test]
    fn verification_flag_bypass_uses_exact_strict_boundaries() {
        let mut record = Gf3258VerificationFlagPolicyRecord {
            field_14: 205,
            field_24: 105,
            ..Gf3258VerificationFlagPolicyRecord::default()
        };
        let mut context = Gf3258VerificationFlagPolicyContext {
            scalar_43: 91,
            candidate_state: 1,
            ..Gf3258VerificationFlagPolicyContext::default()
        };
        let flags = Gf3258PostSurvivalPolicyFlags {
            score_gate: 1,
            policy_class: 2,
        };
        assert!(gf3258_verification_flag_refinement_is_bypassed(
            record, context, flags
        ));

        record.field_14 = 204;
        assert!(!gf3258_verification_flag_refinement_is_bypassed(
            record, context, flags
        ));
        context.scalar_43 = 90;
        assert!(gf3258_verification_flag_refinement_is_bypassed(
            record, context, flags
        ));
        record.field_24 = 104;
        assert!(!gf3258_verification_flag_refinement_is_bypassed(
            record, context, flags
        ));
        record.field_24 = 105;
        context.candidate_state = 2;
        assert!(!gf3258_verification_flag_refinement_is_bypassed(
            record, context, flags
        ));
    }

    #[test]
    fn verification_map_evidence_identity_zero_maps_matches_vendor_vector() {
        let map = [0u8; GF3258_REGISTRATION_PACKED_BYTES];
        let validity = [0xffu8; GF3258_QUARTER_VALIDITY_CELLS / 8];
        let evidence = gf3258_verification_map_evidence_half_resolution(
            &map,
            &map,
            &validity,
            &validity,
            Gf3258AffineQ8::IDENTITY,
        )
        .unwrap();

        assert_eq!(evidence.counts.c00, 1280);
        assert_eq!(evidence.counts.c10, 0);
        assert_eq!(evidence.counts.c01, 0);
        assert_eq!(evidence.counts.c11, 0);
        assert_eq!(
            (evidence.field_18, evidence.field_1c, evidence.field_20),
            (256, 256, 0)
        );
    }

    #[test]
    fn verification_map_evidence_identity_one_maps_matches_vendor_vector() {
        let map = [0xffu8; GF3258_REGISTRATION_PACKED_BYTES];
        let validity = [0xffu8; GF3258_QUARTER_VALIDITY_CELLS / 8];
        let evidence = gf3258_verification_map_evidence_half_resolution(
            &map,
            &map,
            &validity,
            &validity,
            Gf3258AffineQ8::IDENTITY,
        )
        .unwrap();

        assert_eq!(evidence.counts.c00, 0);
        assert_eq!(evidence.counts.c10, 0);
        assert_eq!(evidence.counts.c01, 0);
        assert_eq!(evidence.counts.c11, 1280);
        assert_eq!(
            (evidence.field_18, evidence.field_1c, evidence.field_20),
            (256, 0, 256)
        );
    }

    #[test]
    fn verification_map_evidence_no_validity_matches_vendor_zero_vector() {
        let map = [0u8; GF3258_REGISTRATION_PACKED_BYTES];
        let validity = [0u8; GF3258_QUARTER_VALIDITY_CELLS / 8];
        let evidence = gf3258_verification_map_evidence_half_resolution(
            &map,
            &map,
            &validity,
            &validity,
            Gf3258AffineQ8::IDENTITY,
        )
        .unwrap();

        assert_eq!(evidence.counts, Gf3258BinaryJointCounts::default());
        assert_eq!(
            (evidence.field_18, evidence.field_1c, evidence.field_20),
            (0, 0, 0)
        );
    }

    #[test]
    fn verification_map_evidence_applies_only_vendor_written_projection_fields() {
        let evidence = Gf3258VerificationMapEvidence {
            counts: Gf3258BinaryJointCounts::default(),
            field_18: 11,
            field_1c: 22,
            field_20: 33,
        };

        let mut flag = Gf3258VerificationFlagPolicyRecord {
            field_14: 77,
            field_20: -1,
            ..Default::default()
        };
        evidence.apply_to_flag_policy_record(&mut flag);
        assert_eq!((flag.field_14, flag.field_20), (77, 33));

        let mut late = Gf3258LatePolicyRecord {
            field_14: 78,
            field_20: -2,
            ..Default::default()
        };
        evidence.apply_to_late_policy_record(&mut late);
        assert_eq!((late.field_14, late.field_20), (78, 33));

        let mut post = Gf3258PostSurvivalPolicyRecord {
            field_14: 79,
            field_1c: -3,
            field_20: -4,
            ..Default::default()
        };
        evidence.apply_to_post_survival_policy_record(&mut post);
        assert_eq!((post.field_14, post.field_1c, post.field_20), (79, 22, 33));

        let mut score = Gf3258VerificationPolicyRecord {
            field_14: 80,
            field_20: -5,
            ..Default::default()
        };
        evidence.apply_to_score_policy_record(&mut score);
        assert_eq!((score.field_14, score.field_20), (80, 33));
    }

    #[test]
    fn verification_flag_policy_half_resolution_bypass_skips_map_update() {
        let record = flag_policy_vendor_vector_record([
            334, 331, 67, 262, 306, 164, 349, 57, 99, 303, 14, 59, 201, 208,
        ]);
        let mut context = flag_policy_context(77, 230, 1, 11, 357);
        context.candidate_state = 1;
        let map = [0u8; GF3258_REGISTRATION_PACKED_BYTES];
        let validity = [0xffu8; GF3258_QUARTER_VALIDITY_CELLS / 8];

        let result = gf3258_verification_flag_policy_half_resolution(
            record,
            context,
            &map,
            &map,
            &validity,
            &validity,
            Gf3258AffineQ8::IDENTITY,
        );

        assert!(result.bypassed_refinement);
        assert_eq!(result.map_evidence, None);
        assert_eq!(result.post_refinement_record, record);
        assert_eq!(
            result.flags,
            Gf3258PostSurvivalPolicyFlags {
                score_gate: 1,
                policy_class: 2,
            }
        );
    }

    #[test]
    fn verification_flag_policy_half_resolution_failed_warp_preserves_field_20() {
        let record = flag_policy_vendor_vector_record([
            -5, 13, -29, 220, 70, -6, 312, 97, -5, -58, 73, 322, 205, 344,
        ]);
        let context = flag_policy_context(10, -4, -10, -1, 325);
        let prepass = gf3258_verification_flag_prepass(record, context);
        assert!(!prepass.bypass_refinement);
        let map = [0u8; GF3258_REGISTRATION_PACKED_BYTES];
        let validity = [0xffu8; GF3258_QUARTER_VALIDITY_CELLS / 8];
        let far_disjoint = Gf3258AffineQ8 {
            tx: 2000 * 256,
            ..Gf3258AffineQ8::IDENTITY
        };

        let result = gf3258_verification_flag_policy_half_resolution(
            record,
            context,
            &map,
            &map,
            &validity,
            &validity,
            far_disjoint,
        );

        assert!(!result.bypassed_refinement);
        assert_eq!(result.map_evidence, None);
        assert_eq!(result.post_refinement_record.field_20, record.field_20);
        assert_eq!(
            result.flags,
            gf3258_refine_verification_flags(record, context, prepass.flags)
        );
    }

    #[test]
    fn verification_flag_refinement_vendor_vector_preserves_both() {
        let record = flag_policy_vendor_vector_record([
            209, -17, 164, 41, 315, 215, 88, 166, 19, -56, -56, 217, 132, 102,
        ]);
        let context = flag_policy_context(281, 68, -8, -1, 70);
        assert_eq!(
            gf3258_refine_verification_flags(
                record,
                context,
                Gf3258PostSurvivalPolicyFlags {
                    score_gate: 1,
                    policy_class: 1,
                },
            ),
            Gf3258PostSurvivalPolicyFlags {
                score_gate: 1,
                policy_class: 1,
            }
        );
    }

    #[test]
    fn verification_flag_refinement_vendor_vector_clears_both() {
        let record = flag_policy_vendor_vector_record([
            -91, 199, -98, 287, -32, 231, 175, 332, -13, 293, 111, -70, -90, 55,
        ]);
        let context = flag_policy_context(37, 5, -9, 20, -36);
        assert_eq!(
            gf3258_refine_verification_flags(
                record,
                context,
                Gf3258PostSurvivalPolicyFlags {
                    score_gate: 1,
                    policy_class: 1,
                },
            ),
            Gf3258PostSurvivalPolicyFlags {
                score_gate: 0,
                policy_class: 0,
            }
        );
    }

    #[test]
    fn verification_flag_refinement_vendor_vector_clears_policy_only() {
        let record = flag_policy_vendor_vector_record([
            325, 26, 266, -42, 75, 129, -67, 157, -86, 190, 99, -4, 310, 175,
        ]);
        let context = flag_policy_context(267, 195, -2, 3, 20);
        assert_eq!(
            gf3258_refine_verification_flags(
                record,
                context,
                Gf3258PostSurvivalPolicyFlags {
                    score_gate: 1,
                    policy_class: 2,
                },
            ),
            Gf3258PostSurvivalPolicyFlags {
                score_gate: 1,
                policy_class: 0,
            }
        );
    }

    #[test]
    fn verification_flag_refinement_direct_domain_can_produce_class_three() {
        let record = flag_policy_vendor_vector_record([
            85, 246, 315, 265, -54, 49, 236, 284, -81, 96, -87, 330, 25, 52,
        ]);
        let context = flag_policy_context(264, 211, 12, -10, 171);
        assert_eq!(
            gf3258_refine_verification_flags(
                record,
                context,
                Gf3258PostSurvivalPolicyFlags {
                    score_gate: 0,
                    policy_class: 1,
                },
            ),
            Gf3258PostSurvivalPolicyFlags {
                score_gate: 1,
                policy_class: 3,
            }
        );
    }

    #[test]
    fn post_refinement_auxiliary_gate_clears_both_words_at_vendor_boundary() {
        let flags = Gf3258PostSurvivalPolicyFlags {
            score_gate: 1,
            policy_class: 2,
        };
        assert_eq!(
            gf3258_apply_post_refinement_auxiliary_gate(0xae, 1, flags),
            Gf3258PostSurvivalPolicyFlags::default()
        );
        assert_eq!(
            gf3258_apply_post_refinement_auxiliary_gate(0xaf, 1, flags),
            flags
        );
        assert_eq!(
            gf3258_apply_post_refinement_auxiliary_gate(0, 0, flags),
            flags
        );
    }

    #[test]
    fn post_survival_ratio_q8_matches_exact_caller_expression() {
        assert_eq!(gf3258_post_survival_ratio_q8(3, 4, 5), Some(157));
        assert_eq!(gf3258_post_survival_ratio_q8(0, 0, 0), Some(0));
        assert_eq!(gf3258_post_survival_ratio_q8(-1, 0, 0), None);
    }

    #[test]
    fn post_survival_score_path_has_exact_rescue_boundaries() {
        let mut record = Gf3258PostSurvivalPolicyRecord {
            field_10: 101,
            field_14: 0xc4,
            ..Default::default()
        };
        let zero = Gf3258PostSurvivalPolicyFlags::default();
        assert!(gf3258_post_survival_reaches_score_path(record, zero, 100));
        assert!(!gf3258_post_survival_reaches_score_path(record, zero, 101));
        record.field_14 = 0xc3;
        assert!(!gf3258_post_survival_reaches_score_path(record, zero, 100));
        assert!(gf3258_post_survival_reaches_score_path(
            record,
            Gf3258PostSurvivalPolicyFlags {
                score_gate: 1,
                policy_class: 0,
            },
            i32::MAX
        ));
    }

    fn final_veto_record(
        geometry_count_00: i32,
        metric_04: i32,
        field_14: i32,
        field_20: i32,
        field_24: i32,
        field_28: i32,
        field_2c: i32,
    ) -> Gf3258FinalSampleVetoRecord {
        Gf3258FinalSampleVetoRecord {
            geometry_count_00,
            metric_04,
            field_14,
            field_20,
            field_24,
            field_28,
            field_2c,
        }
    }

    #[test]
    fn final_sample_veto_vendor_rule_a_clears_both_words() {
        let flags = Gf3258PostSurvivalPolicyFlags {
            score_gate: 7,
            policy_class: 9,
        };
        let outcome = gf3258_final_sample_veto(
            final_veto_record(12, 12, 200, 200, 50, 65, 60),
            Gf3258FinalSampleVetoContext {
                enrolled_status_114: 1,
                live_scalar_43: 32,
                live_scalar_56: 75,
            },
            flags,
        );
        assert!(outcome.reject);
        assert_eq!(outcome.flags, Gf3258PostSurvivalPolicyFlags::default());
    }

    #[test]
    fn final_sample_veto_rule_a_uses_strict_live_quality_threshold() {
        let flags = Gf3258PostSurvivalPolicyFlags {
            score_gate: 1,
            policy_class: 2,
        };
        let outcome = gf3258_final_sample_veto(
            final_veto_record(12, 12, 200, 200, 50, 65, 60),
            Gf3258FinalSampleVetoContext {
                enrolled_status_114: 1,
                live_scalar_43: 32,
                live_scalar_56: 0x4a,
            },
            flags,
        );
        assert!(!outcome.reject);
        assert_eq!(outcome.flags, flags);
    }

    #[test]
    fn final_sample_veto_vendor_rule_b_boundary_matches() {
        let outcome = gf3258_final_sample_veto(
            final_veto_record(15, 16, 188, 188, 104, 42, 27),
            Gf3258FinalSampleVetoContext {
                enrolled_status_114: -1,
                live_scalar_43: 57,
                live_scalar_56: 29,
            },
            Gf3258PostSurvivalPolicyFlags {
                score_gate: 5,
                policy_class: 6,
            },
        );
        assert!(outcome.reject);
        assert_eq!(outcome.flags, Gf3258PostSurvivalPolicyFlags::default());
    }

    #[test]
    fn final_sample_veto_vendor_rule_c_boundary_matches() {
        let outcome = gf3258_final_sample_veto(
            final_veto_record(17, 17, 179, 179, 106, 50, 33),
            Gf3258FinalSampleVetoContext {
                enrolled_status_114: 1,
                live_scalar_43: 50,
                live_scalar_56: 40,
            },
            Gf3258PostSurvivalPolicyFlags {
                score_gate: 1,
                policy_class: 2,
            },
        );
        assert!(outcome.reject);
    }

    #[test]
    fn final_sample_veto_requires_nonzero_enrolled_status() {
        let flags = Gf3258PostSurvivalPolicyFlags {
            score_gate: 1,
            policy_class: 3,
        };
        let outcome = gf3258_final_sample_veto(
            final_veto_record(0, 0, 0, 0, 0, 0, 0),
            Gf3258FinalSampleVetoContext {
                enrolled_status_114: 0,
                live_scalar_43: -100,
                live_scalar_56: 500,
            },
            flags,
        );
        assert!(!outcome.reject);
        assert_eq!(outcome.flags, flags);
    }

    #[test]
    fn caller_tail_surviving_vendor_vectors_reach_accumulator() {
        let late_record =
            late_policy_vendor_vector_record([17, 29, 133, 195, 141, 66, 53, 45, 1, 3, 70, 44, 14]);
        let late_context = Gf3258LatePolicyContext {
            live_quality: 38,
            history_low: 7,
            history_high: 0,
            profile_state: 5,
            current_reject_count: 4,
        };
        let post_record = post_survival_vendor_vector_record([
            122, 292, 27, 139, 232, 234, -91, -62, 73, 103, 317, -57, 213, 219, 91,
        ]);
        let result = gf3258_verification_caller_tail(
            true,
            0,
            234,
            Gf3258PostSurvivalPolicyFlags {
                score_gate: 1,
                policy_class: 2,
            },
            late_record,
            late_context,
            translated_identity(11, 6),
            Gf3258PostSurvivalRatioInputs {
                slot_224: 0,
                slot_228: 21,
                slot_22c: 45,
            },
            post_record,
            Gf3258PostSurvivalPolicyContext {
                scalar_43: 276,
                scalar_56: 294,
                candidate_state: -1,
                mode_value: 7,
                ratio_q8: 0,
            },
            i32::MAX,
            final_veto_record(122, 292, 139, 234, -91, -62, 73),
            Gf3258FinalSampleVetoContext {
                enrolled_status_114: 0,
                live_scalar_43: 276,
                live_scalar_56: 294,
            },
        );
        assert_eq!(
            result.disposition,
            Gf3258VerificationCallerTailDisposition::Accepted
        );
        assert_eq!(result.reject_count, 4);
        assert_eq!(
            result.contribution_q8,
            Some(gf3258_verification_metric_contribution_q8(292))
        );
    }

    #[test]
    fn caller_tail_late_reject_increments_counter_before_exit() {
        let late_record =
            late_policy_vendor_vector_record([8, 23, 155, 172, 298, 179, 38, 92, 2, 2, 26, 31, 24]);
        let late_context = Gf3258LatePolicyContext {
            live_quality: 87,
            history_low: 3,
            history_high: 5,
            profile_state: 2,
            current_reject_count: 9,
        };
        let result = gf3258_verification_caller_tail(
            true,
            0,
            0,
            Gf3258PostSurvivalPolicyFlags {
                score_gate: 1,
                policy_class: 1,
            },
            late_record,
            late_context,
            translated_identity(-5, 1),
            Gf3258PostSurvivalRatioInputs::default(),
            Gf3258PostSurvivalPolicyRecord::default(),
            Gf3258PostSurvivalPolicyContext::default(),
            0,
            Gf3258FinalSampleVetoRecord::default(),
            Gf3258FinalSampleVetoContext::default(),
        );
        assert_eq!(
            result.disposition,
            Gf3258VerificationCallerTailDisposition::LatePolicyRejected
        );
        assert_eq!(result.reject_count, 10);
        assert_eq!(result.contribution_q8, None);
    }

    fn normal_loop_tail(
        disposition: Gf3258VerificationCallerTailDisposition,
        score_gate: i32,
        policy_class: i32,
        reject_count: i32,
    ) -> Gf3258VerificationCallerTailResult {
        Gf3258VerificationCallerTailResult {
            disposition,
            flags: Gf3258PostSurvivalPolicyFlags {
                score_gate,
                policy_class,
            },
            reject_count,
            contribution_q8: (disposition == Gf3258VerificationCallerTailDisposition::Accepted)
                .then_some(0),
        }
    }

    fn normal_loop_input(
        primary_704f0_count: i32,
        quality_28: i32,
        post_geometry: Gf3258NormalLoopPostGeometryDisposition,
    ) -> Gf3258NormalLoopRecoverySampleInput {
        Gf3258NormalLoopRecoverySampleInput {
            caller_processes_sample: true,
            primary_704f0_count,
            rescue_704f0_count: 0,
            quality_28,
            quality_134: 10,
            transform_live_to_enrolled: Gf3258AffineQ8::IDENTITY,
            post_geometry,
        }
    }

    fn caller_loop_input(
        primary_704f0_count: i32,
        quality_28: i32,
        post_geometry: Gf3258NormalLoopPostGeometryDisposition,
    ) -> Gf3258NormalLoopSampleInput {
        Gf3258NormalLoopSampleInput {
            primary_704f0_count,
            rescue_704f0_count: 0,
            quality_28,
            quality_134: 10,
            transform_live_to_enrolled: Gf3258AffineQ8::IDENTITY,
            post_geometry,
        }
    }

    #[test]
    fn normal_loop_mode_helpers_match_raw_fixed_domains() {
        assert_eq!(
            gf3258_raw_mode_fields(0),
            Gf3258RawModeFields { low: 0, high: 0 }
        );
        assert_eq!(
            gf3258_raw_mode_fields(0x0302),
            Gf3258RawModeFields { low: 2, high: 7 }
        );
        assert_eq!(
            gf3258_mapped_mode_fields(0x0103),
            Gf3258RawModeFields { low: 3, high: 1 }
        );
        assert_eq!(gf3258_terminal_recovery_exclusion_mode_from_config_48(0), 0);
        assert_eq!(
            gf3258_terminal_recovery_exclusion_mode_from_config_48(0x0103),
            3
        );
    }

    #[test]
    fn normal_loop_state_68c_matches_recovered_scalar_boundaries() {
        let samples = [persisted_sample(Vec::new(), 0)];
        assert_eq!(gf3258_normal_loop_initial_state_68c(0, &samples), 1);
        assert_eq!(gf3258_state_68c_from_scalar_13c(0x0320, &samples), 0);
        assert_eq!(gf3258_state_68c_from_scalar_13c(0x0322, &samples), 3);
        assert_eq!(gf3258_state_68c_from_scalar_13c(0x0323, &samples), 3);
        assert_eq!(gf3258_state_68c_from_scalar_13c(i32::MIN, &samples), 0);
    }

    #[test]
    fn normal_loop_prepares_profile_state_before_candidate_bump() {
        let mut sample = persisted_sample(Vec::new(), 0);
        // Raw +0x140 high mode maps to four for this fixed vector.
        sample.embedded_state_140 = Some(0x300);
        let samples = [sample.clone()];
        let mut machine = Gf3258NormalLoopMachine::new(
            &samples,
            0,
            Gf3258NormalLoopRecoveryConfig {
                config_10: 1,
                config_34: 1,
                config_48: 0,
            },
        );
        machine.candidate_state = 0;
        machine.reject_count = 6;
        machine.continuation_mode = true;

        let prepared = machine.prepare_sample(0, &sample);
        assert_eq!(
            prepared,
            Gf3258NormalLoopSamplePreparation::Ready(Gf3258SamplePolicyLoopState {
                mapped_candidate_mode: 5,
                profile_state: 4,
                reject_count: 6,
            })
        );
        assert_eq!(machine.candidate_state, 5);
        assert!(machine.candidate_bump_active);
        assert!(!machine.continuation_mode);
        assert_eq!(machine.processed_samples, 0);
    }

    #[test]
    fn normal_loop_deep_reject_stops_before_geometry_evaluation() {
        let sample = persisted_sample(Vec::new(), 0);
        let samples = [sample.clone()];
        let mut machine = Gf3258NormalLoopMachine::new(
            &samples,
            0,
            Gf3258NormalLoopRecoveryConfig {
                config_10: 0,
                config_34: 1,
                config_48: 0,
            },
        );
        machine.candidate_state = 5;
        machine.reject_count = 11;

        assert_eq!(
            machine.prepare_sample(0, &sample),
            Gf3258NormalLoopSamplePreparation::StopBeforeEvaluation
        );
        assert_eq!(machine.processed_samples, 0);
        assert_eq!(machine.stop_before_sample, Some(0));
        assert_eq!(
            machine.stop_reason,
            Some(Gf3258NormalLoopStopReason::RejectCountLimit)
        );
    }

    #[test]
    fn persisted_sample_evaluator_skips_before_matcher_work() {
        let sample = persisted_sample(Vec::new(), 0);
        let samples = [sample.clone()];
        let image = vec![127u8; GF3258_PIXELS];
        let extraction = gf3258_extract_primary_features_from_c2d40_source(&image).unwrap();
        let live = Gf3258OwnedVerificationMatcherFeature::from_primary_extraction(&extraction);
        let primary = [0u8; GF3258_REGISTRATION_PACKED_BYTES];
        let quarter = [0u8; GF3258_QUARTER_VALIDITY_CELLS / 8];
        let active = [0u8; GF3258_REGISTRATION_PACKED_BYTES];
        let low_threshold = [0u8; GF3258_REGISTRATION_PACKED_BYTES];
        let mut evaluator = Gf3258PersistedSampleEvaluator::new(
            &samples,
            0,
            Gf3258NormalLoopConfig {
                recovery: Gf3258NormalLoopRecoveryConfig {
                    config_10: 0,
                    config_34: 0,
                    config_48: 0,
                },
                config_38: 1,
                configured_max_samples: 1,
            },
        )
        .unwrap();

        let result = evaluator
            .evaluate_next(
                &live,
                Gf3258PersistedSampleEvaluationInput {
                    registration: Gf3258VerificationRegistrationInput {
                        primary_registration_map: &primary,
                        secondary_registration_map: None,
                        quarter_validity_packed: &quarter,
                        active_validity_packed: &active,
                    },
                    sample_config: Gf3258VerificationSampleConfig {
                        // Deliberately invalid: caller skip selection must occur
                        // before matcher configuration is consumed.
                        candidate_matcher: Gf3258CandidateMatcherConfig {
                            first_half_hamming_max: -1,
                            descriptor_mode_hamming_max: 47,
                            ambiguity_best_multiplier: 40,
                            ambiguity_second_multiplier: 38,
                        },
                        quality_scale_q8: 0x100,
                    },
                    live_policy: Gf3258NormalPolicyLiveInput {
                        low_threshold_registration_map: &low_threshold,
                        quality: 0,
                        coverage: 0,
                        scalar_158: 0,
                    },
                    profile: None,
                    policy_config: Gf3258PersistedSampleEvaluationPolicyConfig::default(),
                },
            )
            .unwrap();

        assert_eq!(
            result.disposition,
            Gf3258PersistedSampleEvaluationDisposition::SkippedByCaller
        );
        assert!(result.verification_work.is_none());
        assert!(result.normal_policy.is_none());
        assert_eq!(result.state_before, result.state_after);
        assert_eq!(evaluator.next_sample_index(), 1);
        assert_eq!(evaluator.finish().unwrap().processed_samples, 0);
    }

    #[test]
    fn persisted_sample_evaluator_applies_geometry_gate_before_scalar_policy() {
        let sample = persisted_sample(Vec::new(), 0);
        let samples = [sample.clone()];
        let image = vec![127u8; GF3258_PIXELS];
        let extraction = gf3258_extract_primary_features_from_c2d40_source(&image).unwrap();
        let live = Gf3258OwnedVerificationMatcherFeature::from_primary_extraction(&extraction);
        let primary = [0u8; GF3258_REGISTRATION_PACKED_BYTES];
        let quarter = [0u8; GF3258_QUARTER_VALIDITY_CELLS / 8];
        let active = [0u8; GF3258_REGISTRATION_PACKED_BYTES];
        let low_threshold = [0u8; GF3258_REGISTRATION_PACKED_BYTES];
        let loop_config = Gf3258NormalLoopConfig {
            recovery: Gf3258NormalLoopRecoveryConfig {
                config_10: 0,
                config_34: 1,
                config_48: 0,
            },
            config_38: 0,
            configured_max_samples: 1,
        };
        let mut evaluator = Gf3258PersistedSampleEvaluator::new(&samples, 0, loop_config).unwrap();

        let result = evaluator
            .evaluate_next(
                &live,
                Gf3258PersistedSampleEvaluationInput {
                    registration: Gf3258VerificationRegistrationInput {
                        primary_registration_map: &primary,
                        secondary_registration_map: None,
                        quarter_validity_packed: &quarter,
                        active_validity_packed: &active,
                    },
                    sample_config: Gf3258VerificationSampleConfig {
                        candidate_matcher: Gf3258CandidateMatcherConfig {
                            first_half_hamming_max: 23,
                            descriptor_mode_hamming_max: 47,
                            ambiguity_best_multiplier: 40,
                            ambiguity_second_multiplier: 38,
                        },
                        quality_scale_q8: 0x100,
                    },
                    live_policy: Gf3258NormalPolicyLiveInput {
                        low_threshold_registration_map: &low_threshold,
                        quality: 0,
                        coverage: 0,
                        scalar_158: 0,
                    },
                    profile: None,
                    policy_config: Gf3258PersistedSampleEvaluationPolicyConfig::default(),
                },
            )
            .unwrap();

        assert_eq!(
            result.disposition,
            Gf3258PersistedSampleEvaluationDisposition::Evaluated
        );
        assert_eq!(
            result
                .verification_work
                .as_ref()
                .unwrap()
                .record
                .verification_metric,
            0
        );
        assert!(result.normal_policy.is_none());
        assert!(!result.recovery_eligible);
        assert!(result.recovery_observation.is_none());
        assert_eq!(result.state_after.processed_samples, 1);
        let high_level_state = evaluator.finish().unwrap();
        let low_level_state = gf3258_normal_loop_state(
            &samples,
            0,
            loop_config,
            &[Gf3258NormalLoopSampleInput::default()],
        )
        .unwrap();
        assert_eq!(high_level_state, low_level_state);
    }

    fn terminal_policy_work(
        evidence: i32,
        verification_metric: i32,
        scaled_coverage_q8: i32,
    ) -> Gf3258NormalPolicyWorkSnapshot {
        Gf3258NormalPolicyWorkSnapshot {
            record: Gf3258VerificationWorkRecord {
                evidence,
                verification_metric,
                scaled_coverage_q8,
                ..Gf3258VerificationWorkRecord::default()
            },
            ..Gf3258NormalPolicyWorkSnapshot::default()
        }
    }

    #[test]
    fn terminal_policy_score_projection_uses_final_policy_work_fields() {
        let work = Gf3258NormalPolicyWorkSnapshot {
            record: Gf3258VerificationWorkRecord {
                geometry_count: 6,
                verification_metric: 12,
                rescue_count: 9,
                map_score: 240,
                evidence: 211,
                scaled_coverage_q8: 130,
                matched_percent: 71,
                geometry_percent: 44,
                scale_penalty: 1,
                orthogonality_penalty: 2,
                severe_orthogonality: 3,
                average_hash_hamming: 8,
            },
            map_field_1c: 17,
            map_field_20: 205,
            live_quality: 31,
            live_coverage: 77,
            enrolled_quality: 29,
            axis_deviation_degrees: 4,
        };

        assert_eq!(
            work.score_policy_record(),
            Gf3258VerificationPolicyRecord {
                geometry_count_00: 6,
                metric_04: 12,
                field_10: 240,
                field_14: 211,
                field_20: 205,
                field_24: 130,
                field_2c: 44,
                penalty_30: 1,
                penalty_34: 2,
                penalty_38: 3,
                live_scalar_54: 31,
                enrolled_scalar_5c: 29,
            }
        );
    }

    #[test]
    fn terminal_policy_work_selector_matches_raw_latch_and_lexicographic_order() {
        let selected = terminal_policy_work(100, 12, 90);
        let better = terminal_policy_work(101, 1, 1);
        let metric_better = terminal_policy_work(100, 13, 1);
        let coverage_better = terminal_policy_work(100, 12, 91);
        let worse = terminal_policy_work(99, 31, 255);
        let equal = selected;
        let mut state = Gf3258NormalLoopSampleState {
            matcher_state_688: 1,
            ..Gf3258NormalLoopSampleState::default()
        };
        assert!(!gf3258_should_replace_terminal_policy_work(
            state,
            Gf3258PostSurvivalPolicyFlags {
                policy_class: 0,
                score_gate: 1,
            },
            better,
            Some(selected),
        ));
        assert!(gf3258_should_replace_terminal_policy_work(
            state,
            Gf3258PostSurvivalPolicyFlags {
                policy_class: 1,
                score_gate: 0,
            },
            better,
            Some(selected),
        ));
        assert!(gf3258_should_replace_terminal_policy_work(
            state,
            Gf3258PostSurvivalPolicyFlags {
                policy_class: 1,
                score_gate: 0,
            },
            metric_better,
            Some(selected),
        ));
        assert!(gf3258_should_replace_terminal_policy_work(
            state,
            Gf3258PostSurvivalPolicyFlags {
                policy_class: 1,
                score_gate: 0,
            },
            coverage_better,
            Some(selected),
        ));
        assert!(!gf3258_should_replace_terminal_policy_work(
            state,
            Gf3258PostSurvivalPolicyFlags {
                policy_class: 1,
                score_gate: 0,
            },
            equal,
            Some(selected),
        ));

        state.matcher_state_688 = 0;
        state.matcher_state_684 = 1;
        assert!(gf3258_should_replace_terminal_policy_work(
            state,
            Gf3258PostSurvivalPolicyFlags {
                policy_class: 1,
                score_gate: 0,
            },
            worse,
            Some(selected),
        ));
        assert!(!gf3258_should_replace_terminal_policy_work(
            state,
            Gf3258PostSurvivalPolicyFlags {
                policy_class: 0,
                score_gate: 0,
            },
            better,
            Some(selected),
        ));
        assert!(gf3258_should_replace_terminal_policy_work(
            state,
            Gf3258PostSurvivalPolicyFlags {
                policy_class: 0,
                score_gate: 1,
            },
            better,
            Some(selected),
        ));

        state.matcher_state_684 = 0;
        assert!(gf3258_should_replace_terminal_policy_work(
            state,
            Gf3258PostSurvivalPolicyFlags {
                policy_class: 0,
                score_gate: 1,
            },
            worse,
            Some(selected),
        ));
        assert!(gf3258_should_replace_terminal_policy_work(
            state,
            Gf3258PostSurvivalPolicyFlags {
                policy_class: 1,
                score_gate: 0,
            },
            worse,
            Some(selected),
        ));
        assert!(gf3258_should_replace_terminal_policy_work(
            state,
            Gf3258PostSurvivalPolicyFlags {
                policy_class: 0,
                score_gate: 0,
            },
            better,
            Some(selected),
        ));
        assert!(!gf3258_should_replace_terminal_policy_work(
            state,
            Gf3258PostSurvivalPolicyFlags {
                policy_class: 0,
                score_gate: 0,
            },
            equal,
            Some(selected),
        ));
    }

    #[test]
    fn persisted_gallery_verification_composes_weak_sample_to_terminal_no_match() {
        let sample = persisted_sample(Vec::new(), 0);
        let samples = [sample];
        let image = vec![127u8; GF3258_PIXELS];
        let extraction = gf3258_extract_primary_features_from_c2d40_source(&image).unwrap();
        let live = Gf3258OwnedVerificationMatcherFeature::from_primary_extraction(&extraction);
        let primary = [0u8; GF3258_REGISTRATION_PACKED_BYTES];
        let quarter = [0u8; GF3258_QUARTER_VALIDITY_CELLS / 8];
        let active = [0u8; GF3258_REGISTRATION_PACKED_BYTES];
        let low_threshold = [0u8; GF3258_REGISTRATION_PACKED_BYTES];

        let result = gf3258_verify_persisted_gallery(
            &samples,
            &live,
            Gf3258PersistedGalleryVerificationInput {
                live_scalar_13c: 0,
                normal_loop: Gf3258NormalLoopConfig {
                    recovery: Gf3258NormalLoopRecoveryConfig {
                        config_10: 0,
                        config_34: 1,
                        config_48: 0,
                    },
                    config_38: 0,
                    configured_max_samples: 1,
                },
                evaluation: Gf3258PersistedSampleEvaluationInput {
                    registration: Gf3258VerificationRegistrationInput {
                        primary_registration_map: &primary,
                        secondary_registration_map: None,
                        quarter_validity_packed: &quarter,
                        active_validity_packed: &active,
                    },
                    sample_config: Gf3258VerificationSampleConfig {
                        candidate_matcher: Gf3258CandidateMatcherConfig {
                            first_half_hamming_max: 23,
                            descriptor_mode_hamming_max: 47,
                            ambiguity_best_multiplier: 40,
                            ambiguity_second_multiplier: 38,
                        },
                        quality_scale_q8: 0x100,
                    },
                    live_policy: Gf3258NormalPolicyLiveInput {
                        low_threshold_registration_map: &low_threshold,
                        quality: 0,
                        coverage: 0,
                        scalar_158: 0,
                    },
                    profile: None,
                    policy_config: Gf3258PersistedSampleEvaluationPolicyConfig::default(),
                },
            },
        )
        .unwrap();

        assert_eq!(result.decision, Gf3258GalleryVerificationDecision::NoMatch);
        assert_eq!(
            result.arbitration.score,
            -GF3258_FALLBACK_REASON_LOW_GEOMETRY
        );
        assert_eq!(
            result.arbitration.disposition,
            Gf3258TerminalScoreDisposition::RecoveryNonPositive
        );
        assert_eq!(result.normal_loop.processed_samples, 1);
        assert_eq!(result.normal_loop.score.accepted_samples(), 0);
        assert!(result.selected_terminal_work.is_none());
        assert!(result.recovery.selected_observation_index.is_none());
        assert_eq!(result.sample_evaluations.len(), 1);
    }

    #[test]
    fn normal_loop_early_geometry_branch_marks_recovery_without_latching_state() {
        let samples = [persisted_sample(Vec::new(), 0)];
        let inputs = [normal_loop_input(
            3,
            0,
            Gf3258NormalLoopPostGeometryDisposition::RejectedBeforeCallerTail,
        )];
        let result = gf3258_normal_loop_recovery_state(
            &samples,
            0,
            Gf3258NormalLoopRecoveryConfig {
                config_10: 0,
                config_34: 1,
                config_48: 0,
            },
            &inputs,
        )
        .unwrap();
        assert_eq!(result.eligible_samples, vec![true]);
        assert_eq!(result.post_normal_loop_state_684, 0);
        assert_eq!(result.post_normal_loop_state_688, 0);
        assert_eq!(result.processed_samples, 1);
    }

    #[test]
    fn normal_loop_reject_branches_do_not_mutate_latches_or_mark_full_path_candidate() {
        let samples = [
            persisted_sample(Vec::new(), 0),
            persisted_sample(Vec::new(), 0),
            persisted_sample(Vec::new(), 0),
        ];
        let inputs = [
            normal_loop_input(
                6,
                30,
                Gf3258NormalLoopPostGeometryDisposition::RejectedBeforeCallerTail,
            ),
            normal_loop_input(
                6,
                30,
                Gf3258NormalLoopPostGeometryDisposition::CallerTail(normal_loop_tail(
                    Gf3258VerificationCallerTailDisposition::LatePolicyRejected,
                    1,
                    1,
                    1,
                )),
            ),
            normal_loop_input(
                6,
                30,
                Gf3258NormalLoopPostGeometryDisposition::CallerTail(normal_loop_tail(
                    Gf3258VerificationCallerTailDisposition::FinalVetoRejected,
                    0,
                    0,
                    1,
                )),
            ),
        ];
        let result = gf3258_normal_loop_recovery_state(
            &samples,
            0,
            Gf3258NormalLoopRecoveryConfig {
                config_10: 0,
                config_34: 1,
                config_48: 0,
            },
            &inputs,
        )
        .unwrap();
        assert_eq!(result.eligible_samples, vec![false, false, false]);
        assert_eq!(result.post_normal_loop_state_684, 0);
        assert_eq!(result.post_normal_loop_state_688, 0);
        assert_eq!(result.reject_count, 1);
    }

    #[test]
    fn normal_loop_score_gate_zero_tail_can_mark_recovery_even_when_accepted() {
        let samples = [
            persisted_sample(Vec::new(), 0),
            persisted_sample(Vec::new(), 0),
        ];
        let inputs = [
            normal_loop_input(
                6,
                30,
                Gf3258NormalLoopPostGeometryDisposition::CallerTail(normal_loop_tail(
                    Gf3258VerificationCallerTailDisposition::PostSurvivalNotSelected,
                    0,
                    2,
                    0,
                )),
            ),
            normal_loop_input(
                6,
                30,
                Gf3258NormalLoopPostGeometryDisposition::CallerTail(normal_loop_tail(
                    Gf3258VerificationCallerTailDisposition::Accepted,
                    0,
                    0,
                    0,
                )),
            ),
        ];
        let result = gf3258_normal_loop_recovery_state(
            &samples,
            0,
            Gf3258NormalLoopRecoveryConfig {
                config_10: 0,
                config_34: 1,
                config_48: 0,
            },
            &inputs,
        )
        .unwrap();
        assert_eq!(result.eligible_samples, vec![true, true]);
        assert_eq!(result.post_normal_loop_state_684, 0);
        // policy_class latched in-loop, then exact !bVar60 post-loop clear.
        assert_eq!(result.post_normal_loop_state_688, 0);
    }

    #[test]
    fn accepted_score_gate_zero_sample_does_not_authenticate() {
        let samples = [persisted_sample(Vec::new(), 0)];
        let tail = Gf3258VerificationCallerTailResult {
            disposition: Gf3258VerificationCallerTailDisposition::Accepted,
            flags: Gf3258PostSurvivalPolicyFlags {
                score_gate: 0,
                policy_class: 0,
            },
            reject_count: 0,
            contribution_q8: Some(41),
        };
        let inputs = [normal_loop_input(
            5,
            36,
            Gf3258NormalLoopPostGeometryDisposition::CallerTail(tail),
        )];

        let normal = gf3258_normal_loop_recovery_state(
            &samples,
            0,
            Gf3258NormalLoopRecoveryConfig {
                config_10: 0,
                config_34: 1,
                config_48: 0,
            },
            &inputs,
        )
        .unwrap();

        assert_eq!(normal.score.accepted_samples(), 1);
        assert_eq!(normal.score.percent(), Some(16));
        assert_eq!(normal.current_score, 0);

        let terminal = gf3258_terminal_arbitrate_score(Gf3258TerminalArbitrationInput {
            current_score: normal.current_score,
            normal_percent: normal.score.percent().unwrap_or(0),
            accepted_samples: normal.score.accepted_samples(),
            recovery: Gf3258TerminalRecoverySummary::default(),
            ..Gf3258TerminalArbitrationInput::default()
        });

        assert_eq!(terminal.score, -GF3258_FALLBACK_REASON_LOW_GEOMETRY);
        assert_eq!(
            terminal.disposition,
            Gf3258TerminalScoreDisposition::RecoveryNonPositive
        );
        assert_eq!(
            Gf3258GalleryVerificationDecision::from_score(terminal.score),
            Gf3258GalleryVerificationDecision::NoMatch
        );
    }

    #[test]
    fn normal_loop_nonzero_score_gate_latches_684_and_stops_without_continuation_mode() {
        let samples = [
            persisted_sample(Vec::new(), 0),
            persisted_sample(Vec::new(), 0),
        ];
        let inputs = [
            normal_loop_input(
                6,
                30,
                Gf3258NormalLoopPostGeometryDisposition::CallerTail(normal_loop_tail(
                    Gf3258VerificationCallerTailDisposition::Accepted,
                    1,
                    3,
                    0,
                )),
            ),
            normal_loop_input(
                3,
                0,
                Gf3258NormalLoopPostGeometryDisposition::RejectedBeforeCallerTail,
            ),
        ];
        let result = gf3258_normal_loop_recovery_state(
            &samples,
            0,
            Gf3258NormalLoopRecoveryConfig {
                config_10: 0,
                config_34: 1,
                config_48: 0,
            },
            &inputs,
        )
        .unwrap();
        assert_eq!(result.eligible_samples, vec![false, false]);
        assert_eq!(result.post_normal_loop_state_684, 1);
        assert_eq!(result.post_normal_loop_state_688, 0);
        assert_eq!(result.processed_samples, 1);
        assert_eq!(result.stop_before_sample, Some(1));
        assert_eq!(
            result.stop_reason,
            Some(Gf3258NormalLoopStopReason::ScoreGate)
        );
    }

    #[test]
    fn normal_loop_score_gate_persists_running_score_for_terminal_arbitration() {
        let samples = [persisted_sample(Vec::new(), 0)];
        let tail = Gf3258VerificationCallerTailResult {
            disposition: Gf3258VerificationCallerTailDisposition::Accepted,
            flags: Gf3258PostSurvivalPolicyFlags {
                score_gate: 1,
                policy_class: 2,
            },
            reject_count: 0,
            contribution_q8: Some(239),
        };
        let inputs = [normal_loop_input(
            29,
            80,
            Gf3258NormalLoopPostGeometryDisposition::CallerTail(tail),
        )];

        let result = gf3258_normal_loop_recovery_state(
            &samples,
            0,
            Gf3258NormalLoopRecoveryConfig {
                config_10: 0,
                config_34: 1,
                config_48: 0,
            },
            &inputs,
        )
        .unwrap();

        assert_eq!(result.score.percent(), Some(93));
        assert_eq!(result.current_score, 93);
        assert_eq!(
            result.stop_reason,
            Some(Gf3258NormalLoopStopReason::ScoreGate)
        );

        let terminal = gf3258_terminal_arbitrate_score(Gf3258TerminalArbitrationInput {
            current_score: result.current_score,
            normal_percent: result.score.percent().unwrap(),
            history_count: 0,
            matcher_state_688: result.post_normal_loop_state_688,
            auxiliary_class: result.candidate_state,
            accepted_samples: result.score.accepted_samples(),
            config_48: 0,
            current_policy_score: 0,
            recovery: Gf3258TerminalRecoverySummary::default(),
            cache_rescue_enabled: false,
            cache_rescue_hit: false,
        });
        assert_eq!(terminal.score, 93);
        assert_eq!(
            terminal.disposition,
            Gf3258TerminalScoreDisposition::RetainedCurrentScore
        );
    }

    #[test]
    fn normal_loop_retained_continuation_preserves_688_and_processes_after_score_gate() {
        let samples = [
            persisted_sample(Vec::new(), 0),
            persisted_sample(Vec::new(), 0),
        ];
        let inputs = [
            normal_loop_input(
                6,
                30,
                Gf3258NormalLoopPostGeometryDisposition::CallerTail(normal_loop_tail(
                    Gf3258VerificationCallerTailDisposition::Accepted,
                    1,
                    2,
                    0,
                )),
            ),
            normal_loop_input(
                3,
                0,
                Gf3258NormalLoopPostGeometryDisposition::RejectedBeforeCallerTail,
            ),
        ];
        let result = gf3258_normal_loop_recovery_state(
            &samples,
            0,
            Gf3258NormalLoopRecoveryConfig {
                config_10: 1,
                config_34: 1,
                // raw high mode zero => <7, so bVar60 remains enabled.
                config_48: 0,
            },
            &inputs,
        )
        .unwrap();
        assert!(result.continuation_mode);
        assert_eq!(result.post_normal_loop_state_684, 1);
        assert_eq!(result.post_normal_loop_state_688, 1);
        assert_eq!(result.processed_samples, 2);
        assert_eq!(result.stop_reason, None);
        assert_eq!(result.eligible_samples, vec![false, false]);
    }

    #[test]
    fn normal_loop_reject_counter_precheck_disables_continuation_then_stops_above_ten() {
        let mut samples = Vec::new();
        let mut inputs = Vec::new();
        for index in 0..12 {
            samples.push(persisted_sample(Vec::new(), 0));
            inputs.push(normal_loop_input(
                6,
                30,
                Gf3258NormalLoopPostGeometryDisposition::CallerTail(normal_loop_tail(
                    Gf3258VerificationCallerTailDisposition::LatePolicyRejected,
                    0,
                    0,
                    index + 1,
                )),
            ));
        }
        let result = gf3258_normal_loop_recovery_state(
            &samples,
            0,
            Gf3258NormalLoopRecoveryConfig {
                config_10: 1,
                config_34: 1,
                config_48: 0,
            },
            &inputs,
        )
        .unwrap();
        assert!(!result.continuation_mode);
        assert_eq!(result.reject_count, 11);
        assert_eq!(result.processed_samples, 11);
        assert_eq!(result.stop_before_sample, Some(11));
        assert_eq!(
            result.stop_reason,
            Some(Gf3258NormalLoopStopReason::RejectCountLimit)
        );
    }

    #[test]
    fn normal_loop_recovery_enable_requires_exact_one() {
        let samples = [persisted_sample(Vec::new(), 0)];
        let inputs = [normal_loop_input(
            3,
            0,
            Gf3258NormalLoopPostGeometryDisposition::RejectedBeforeCallerTail,
        )];
        for disabled in [0, 2, -1] {
            let result = gf3258_normal_loop_recovery_state(
                &samples,
                0,
                Gf3258NormalLoopRecoveryConfig {
                    config_10: 0,
                    config_34: disabled,
                    config_48: 0,
                },
                &inputs,
            )
            .unwrap();
            assert_eq!(result.eligible_samples, vec![false]);
        }
    }

    #[test]
    fn normal_loop_explicit_caller_skip_has_no_state_or_recovery_effect() {
        let samples = [persisted_sample(Vec::new(), 0)];
        let inputs =
            [Gf3258NormalLoopRecoverySampleInput {
                caller_processes_sample: false,
                primary_704f0_count: 31,
                rescue_704f0_count: 31,
                quality_28: 31,
                quality_134: 0,
                transform_live_to_enrolled: Gf3258AffineQ8::IDENTITY,
                post_geometry: Gf3258NormalLoopPostGeometryDisposition::CallerTail(
                    normal_loop_tail(Gf3258VerificationCallerTailDisposition::Accepted, 1, 1, 0),
                ),
            }];
        let result = gf3258_normal_loop_recovery_state(
            &samples,
            0,
            Gf3258NormalLoopRecoveryConfig {
                config_10: 1,
                config_34: 1,
                config_48: 0,
            },
            &inputs,
        )
        .unwrap();
        assert_eq!(result.eligible_samples, vec![false]);
        assert_eq!(result.post_normal_loop_state_684, 0);
        assert_eq!(result.post_normal_loop_state_688, 0);
        assert_eq!(result.processed_samples, 0);
    }

    #[test]
    fn normal_loop_near_identity_rejection_skips_latch_and_eligibility() {
        let samples = [persisted_sample(Vec::new(), 0)];
        let inputs = [normal_loop_input(
            6,
            30,
            Gf3258NormalLoopPostGeometryDisposition::CallerTail(normal_loop_tail(
                Gf3258VerificationCallerTailDisposition::Accepted,
                0,
                0,
                0,
            )),
        )];
        let result = gf3258_normal_loop_recovery_state(
            &samples,
            0,
            Gf3258NormalLoopRecoveryConfig {
                config_10: 0,
                config_34: 1,
                // mapped-low mode 2; identity is inside the exact exclusion window.
                config_48: 1,
            },
            &inputs,
        )
        .unwrap();
        assert_eq!(result.eligible_samples, vec![false]);
        assert_eq!(result.post_normal_loop_state_684, 0);
        assert_eq!(result.post_normal_loop_state_688, 0);
    }

    #[test]
    fn normal_loop_reject_count_mismatch_and_out_of_domain_ratio_are_explicit_errors() {
        let samples = [persisted_sample(Vec::new(), 0)];
        let mismatch = [normal_loop_input(
            6,
            30,
            Gf3258NormalLoopPostGeometryDisposition::CallerTail(normal_loop_tail(
                Gf3258VerificationCallerTailDisposition::LatePolicyRejected,
                0,
                0,
                9,
            )),
        )];
        assert_eq!(
            gf3258_normal_loop_recovery_state(
                &samples,
                0,
                Gf3258NormalLoopRecoveryConfig {
                    config_10: 0,
                    config_34: 1,
                    config_48: 0,
                },
                &mismatch,
            )
            .unwrap_err(),
            Gf3258NormalLoopRecoveryStateError::RejectCountMismatch {
                sample_index: 0,
                expected: 1,
                actual: 9,
            }
        );

        let out_of_domain = [normal_loop_input(
            6,
            30,
            Gf3258NormalLoopPostGeometryDisposition::CallerTail(normal_loop_tail(
                Gf3258VerificationCallerTailDisposition::OutOfDomainRatio,
                0,
                0,
                0,
            )),
        )];
        assert_eq!(
            gf3258_normal_loop_recovery_state(
                &samples,
                0,
                Gf3258NormalLoopRecoveryConfig {
                    config_10: 0,
                    config_34: 1,
                    config_48: 0,
                },
                &out_of_domain,
            )
            .unwrap_err(),
            Gf3258NormalLoopRecoveryStateError::OutOfDomainRatio { sample_index: 0 }
        );
    }

    #[test]
    fn caller_loop_selected_sample_filter_uses_persisted_sample_index() {
        let mut samples = [
            persisted_sample(Vec::new(), 0),
            persisted_sample(Vec::new(), 0),
        ];
        samples[0].sample_index = 0;
        samples[1].sample_index = 1;
        let inputs = [
            caller_loop_input(
                3,
                0,
                Gf3258NormalLoopPostGeometryDisposition::RejectedBeforeCallerTail,
            ),
            caller_loop_input(
                3,
                0,
                Gf3258NormalLoopPostGeometryDisposition::RejectedBeforeCallerTail,
            ),
        ];

        let result = gf3258_normal_loop_state(
            &samples,
            0,
            Gf3258NormalLoopConfig {
                recovery: Gf3258NormalLoopRecoveryConfig {
                    config_10: 0,
                    config_34: 0,
                    config_48: 0,
                },
                config_38: 1,
                configured_max_samples: 40,
            },
            &inputs,
        )
        .unwrap();

        assert_eq!(result.processed_samples, 1);
        assert_eq!(result.eligible_samples, vec![false, false]);
    }

    #[test]
    fn caller_loop_full_template_skips_later_canonical_sample_after_644_latches() {
        let mut samples = [
            persisted_sample(Vec::new(), 0),
            persisted_sample(Vec::new(), 0),
        ];
        samples[0].canonical_member = true;
        samples[1].canonical_member = true;
        samples[1].sample_index = 1;
        let inputs = [
            caller_loop_input(
                6,
                30,
                Gf3258NormalLoopPostGeometryDisposition::CallerTail(
                    Gf3258VerificationCallerTailResult {
                        disposition: Gf3258VerificationCallerTailDisposition::Accepted,
                        flags: Gf3258PostSurvivalPolicyFlags {
                            score_gate: 1,
                            policy_class: 0,
                        },
                        reject_count: 0,
                        contribution_q8: Some(256),
                    },
                ),
            ),
            caller_loop_input(
                3,
                0,
                Gf3258NormalLoopPostGeometryDisposition::RejectedBeforeCallerTail,
            ),
        ];

        let result = gf3258_normal_loop_state(
            &samples,
            0,
            Gf3258NormalLoopConfig {
                recovery: Gf3258NormalLoopRecoveryConfig {
                    config_10: 1,
                    config_34: 1,
                    config_48: 0,
                },
                config_38: 0,
                configured_max_samples: 2,
            },
            &inputs,
        )
        .unwrap();

        assert!(result.continuation_mode);
        assert_eq!(result.processed_samples, 1);
        assert_eq!(result.post_normal_loop_state_644, 1);
        assert_eq!(result.score.accepted_samples(), 1);
        assert_eq!(result.score.sum_q8(), 256);
        assert_eq!(result.score.percent(), Some(100));
    }

    #[test]
    fn caller_loop_688_gate_skips_canonical_sample_before_capacity_is_full() {
        let mut samples = [
            persisted_sample(Vec::new(), 0),
            persisted_sample(Vec::new(), 0),
        ];
        samples[0].canonical_member = true;
        samples[1].canonical_member = true;
        samples[1].sample_index = 1;
        let inputs = [
            caller_loop_input(
                6,
                30,
                Gf3258NormalLoopPostGeometryDisposition::CallerTail(
                    Gf3258VerificationCallerTailResult {
                        disposition: Gf3258VerificationCallerTailDisposition::Accepted,
                        flags: Gf3258PostSurvivalPolicyFlags {
                            score_gate: 1,
                            policy_class: 1,
                        },
                        reject_count: 0,
                        contribution_q8: Some(128),
                    },
                ),
            ),
            caller_loop_input(
                3,
                0,
                Gf3258NormalLoopPostGeometryDisposition::RejectedBeforeCallerTail,
            ),
        ];

        let result = gf3258_normal_loop_state(
            &samples,
            0,
            Gf3258NormalLoopConfig {
                recovery: Gf3258NormalLoopRecoveryConfig {
                    config_10: 1,
                    config_34: 1,
                    config_48: 0,
                },
                config_38: 0,
                configured_max_samples: 40,
            },
            &inputs,
        )
        .unwrap();

        assert_eq!(result.processed_samples, 1);
        assert_eq!(result.post_normal_loop_state_644, 1);
        assert_eq!(result.post_normal_loop_state_688, 1);
    }

    #[test]
    fn caller_loop_noncanonical_sample_is_not_suppressed_by_canonical_gate() {
        let mut samples = [
            persisted_sample(Vec::new(), 0),
            persisted_sample(Vec::new(), 0),
        ];
        samples[0].canonical_member = true;
        samples[1].sample_index = 1;
        let inputs = [
            caller_loop_input(
                6,
                30,
                Gf3258NormalLoopPostGeometryDisposition::CallerTail(
                    Gf3258VerificationCallerTailResult {
                        disposition: Gf3258VerificationCallerTailDisposition::Accepted,
                        flags: Gf3258PostSurvivalPolicyFlags {
                            score_gate: 1,
                            policy_class: 1,
                        },
                        reject_count: 0,
                        contribution_q8: Some(128),
                    },
                ),
            ),
            caller_loop_input(
                3,
                0,
                Gf3258NormalLoopPostGeometryDisposition::RejectedBeforeCallerTail,
            ),
        ];

        let result = gf3258_normal_loop_state(
            &samples,
            0,
            Gf3258NormalLoopConfig {
                recovery: Gf3258NormalLoopRecoveryConfig {
                    config_10: 1,
                    config_34: 1,
                    config_48: 0,
                },
                config_38: 0,
                configured_max_samples: 40,
            },
            &inputs,
        )
        .unwrap();

        assert_eq!(result.processed_samples, 2);
    }

    #[test]
    fn caller_loop_accumulator_counts_only_samples_that_reach_accumulator() {
        let samples = [
            persisted_sample(Vec::new(), 0),
            persisted_sample(Vec::new(), 0),
            persisted_sample(Vec::new(), 0),
        ];
        let inputs = [
            caller_loop_input(
                6,
                30,
                Gf3258NormalLoopPostGeometryDisposition::CallerTail(
                    Gf3258VerificationCallerTailResult {
                        disposition: Gf3258VerificationCallerTailDisposition::Accepted,
                        flags: Gf3258PostSurvivalPolicyFlags::default(),
                        reject_count: 0,
                        contribution_q8: Some(256),
                    },
                ),
            ),
            caller_loop_input(
                6,
                30,
                Gf3258NormalLoopPostGeometryDisposition::CallerTail(normal_loop_tail(
                    Gf3258VerificationCallerTailDisposition::PostSurvivalNotSelected,
                    0,
                    0,
                    0,
                )),
            ),
            caller_loop_input(
                6,
                30,
                Gf3258NormalLoopPostGeometryDisposition::CallerTail(
                    Gf3258VerificationCallerTailResult {
                        disposition: Gf3258VerificationCallerTailDisposition::Accepted,
                        flags: Gf3258PostSurvivalPolicyFlags::default(),
                        reject_count: 0,
                        contribution_q8: Some(128),
                    },
                ),
            ),
        ];

        let result = gf3258_normal_loop_state(
            &samples,
            0,
            Gf3258NormalLoopConfig {
                recovery: Gf3258NormalLoopRecoveryConfig {
                    config_10: 0,
                    config_34: 1,
                    config_48: 0,
                },
                config_38: 0,
                configured_max_samples: 40,
            },
            &inputs,
        )
        .unwrap();

        assert_eq!(result.score.accepted_samples(), 2);
        assert_eq!(result.score.sum_q8(), 384);
        assert_eq!(result.score.percent(), Some(75));
    }

    #[test]
    fn caller_loop_rejects_accepted_tail_without_score_contribution() {
        let samples = [persisted_sample(Vec::new(), 0)];
        let inputs = [caller_loop_input(
            6,
            30,
            Gf3258NormalLoopPostGeometryDisposition::CallerTail(
                Gf3258VerificationCallerTailResult {
                    disposition: Gf3258VerificationCallerTailDisposition::Accepted,
                    flags: Gf3258PostSurvivalPolicyFlags::default(),
                    reject_count: 0,
                    contribution_q8: None,
                },
            ),
        )];

        assert_eq!(
            gf3258_normal_loop_state(
                &samples,
                0,
                Gf3258NormalLoopConfig {
                    recovery: Gf3258NormalLoopRecoveryConfig {
                        config_10: 0,
                        config_34: 1,
                        config_48: 0,
                    },
                    config_38: 0,
                    configured_max_samples: 40,
                },
                &inputs,
            )
            .unwrap_err(),
            Gf3258NormalLoopRecoveryStateError::MissingAcceptedContribution { sample_index: 0 }
        );
    }

    #[test]
    fn caller_loop_rejects_sample_count_above_configured_capacity() {
        let samples = [persisted_sample(Vec::new(), 0)];
        let inputs = [Gf3258NormalLoopSampleInput::default()];

        assert_eq!(
            gf3258_normal_loop_state(
                &samples,
                0,
                Gf3258NormalLoopConfig {
                    recovery: Gf3258NormalLoopRecoveryConfig::default(),
                    config_38: 0,
                    configured_max_samples: 0,
                },
                &inputs,
            )
            .unwrap_err(),
            Gf3258NormalLoopRecoveryStateError::InvalidConfiguredSampleLimit {
                samples: 1,
                configured_max_samples: 0,
            }
        );
    }

    #[test]
    fn recovery_scan_from_caller_loop_derives_process_flags_and_eligibility() {
        let (mut sample, live, primary, quarter_validity, active_validity, candidate_matcher) =
            terminal_recovery_identity_fixture();
        sample.sample_index = 0;
        let samples = [sample];
        let normal_inputs = [caller_loop_input(
            3,
            0,
            Gf3258NormalLoopPostGeometryDisposition::RejectedBeforeCallerTail,
        )];
        let result = gf3258_terminal_recovery_scan_from_caller_loop(
            &samples,
            0,
            Gf3258TerminalRecoveryLiveFeature {
                matcher: Gf3258MatcherFeatureSet {
                    points: &live,
                    polarity_split: 5,
                },
                primary_registration_map: &primary,
                secondary_registration_map: None,
                quarter_validity_packed: &quarter_validity,
                active_validity_packed: &active_validity,
            },
            Gf3258TerminalRecoveryScanFromCallerLoopConfig {
                candidate_matcher,
                aggregate: Gf3258TerminalRecoveryConfig {
                    map_score_base: -100,
                    quality_scale_q8: 256,
                    apply_affine_penalty: false,
                },
                map_mode: 1,
                normal_loop: Gf3258NormalLoopConfig {
                    recovery: Gf3258NormalLoopRecoveryConfig {
                        config_10: 0,
                        config_34: 1,
                        config_48: 0,
                    },
                    config_38: 0,
                    configured_max_samples: 40,
                },
                sample_inputs: &normal_inputs,
            },
        )
        .unwrap();

        assert_eq!(result.normal_loop.eligible_samples, vec![true]);
        assert_eq!(result.normal_loop.processed_samples, 1);
        assert_eq!(result.scan.observations.len(), 1);
    }

    #[test]
    fn recovery_scan_from_normal_loop_closes_eligibility_and_exclusion_mode_inputs() {
        let (sample, live, primary, quarter_validity, active_validity, candidate_matcher) =
            terminal_recovery_identity_fixture();
        let samples = [sample];
        let normal_inputs = [normal_loop_input(
            3,
            0,
            Gf3258NormalLoopPostGeometryDisposition::RejectedBeforeCallerTail,
        )];
        let result = gf3258_terminal_recovery_scan_from_normal_loop(
            &samples,
            0,
            Gf3258TerminalRecoveryLiveFeature {
                matcher: Gf3258MatcherFeatureSet {
                    points: &live,
                    polarity_split: 5,
                },
                primary_registration_map: &primary,
                secondary_registration_map: None,
                quarter_validity_packed: &quarter_validity,
                active_validity_packed: &active_validity,
            },
            Gf3258TerminalRecoveryScanFromNormalLoopConfig {
                candidate_matcher,
                aggregate: Gf3258TerminalRecoveryConfig {
                    map_score_base: -100,
                    quality_scale_q8: 256,
                    apply_affine_penalty: false,
                },
                map_mode: 1,
                normal_loop: Gf3258NormalLoopRecoveryConfig {
                    config_10: 0,
                    config_34: 1,
                    config_48: 0,
                },
                sample_inputs: &normal_inputs,
            },
        )
        .unwrap();
        assert_eq!(result.normal_loop.eligible_samples, vec![true]);
        assert_eq!(result.scan.observations.len(), 1);
        assert_eq!(result.scan.observations[0].observation.coverage_q8, 256);
        assert_eq!(result.scan.aggregation.summary.best_quality, 256);
    }

    fn terminal_recovery_identity_fixture() -> (
        Gf3258PersistedSample,
        Vec<Gf3258MatcherPoint>,
        [u8; GF3258_REGISTRATION_PACKED_BYTES],
        [u8; GF3258_QUARTER_VALIDITY_CELLS / 8],
        [u8; GF3258_REGISTRATION_PACKED_BYTES],
        Gf3258CandidateMatcherConfig,
    ) {
        fn persisted_point(x_q8: u16, y_q8: u16, descriptor_byte: u8) -> Gf3258PersistedPoint {
            Gf3258PersistedPoint {
                geometry_word: (u32::from(y_q8) << 4) | (u32::from(x_q8) << 16),
                descriptor_10_1f: [descriptor_byte; 16],
                hash20: 0,
                hash28: 0,
                hash2c: 0,
            }
        }
        let coordinates = [
            (0x0800, 0x0800),
            (0x1800, 0x0800),
            (0x2800, 0x0800),
            (0x0800, 0x1800),
            (0x1800, 0x1800),
            (0x2800, 0x1800),
        ];
        let mut sample = persisted_sample(
            coordinates
                .iter()
                .enumerate()
                .map(|(index, &(x, y))| persisted_point(x, y, (index + 1) as u8))
                .collect(),
            coordinates.len() as i32,
        );
        sample.quarter_validity_packed = [0xff; GF3258_QUARTER_VALIDITY_CELLS / 8];
        sample.active_validity_packed = [0xff; GF3258_REGISTRATION_PACKED_BYTES];

        let live = coordinates
            .iter()
            .enumerate()
            .map(|(index, &(x_q8, y_q8))| Gf3258MatcherPoint {
                polarity: 0,
                x_q8,
                y_q8,
                orientation_q12: 0,
                descriptor_10_1f: [(index + 1) as u8; 16],
                hash20: 0,
                hash24: 0,
                hash28: 0,
                hash30: 0,
            })
            .collect::<Vec<_>>();
        let primary = [0u8; GF3258_REGISTRATION_PACKED_BYTES];
        let quarter_validity = [0xffu8; GF3258_QUARTER_VALIDITY_CELLS / 8];
        let active_validity = [0xffu8; GF3258_REGISTRATION_PACKED_BYTES];
        let config = Gf3258CandidateMatcherConfig {
            first_half_hamming_max: 0,
            descriptor_mode_hamming_max: 0,
            ambiguity_best_multiplier: 1,
            ambiguity_second_multiplier: 1,
        };
        (
            sample,
            live,
            primary,
            quarter_validity,
            active_validity,
            config,
        )
    }

    #[test]
    fn terminal_recovery_near_identity_uses_exact_mode_windows() {
        assert!(gf3258_terminal_recovery_near_identity_excluded(
            Gf3258AffineQ8::IDENTITY,
            1
        ));
        assert!(gf3258_terminal_recovery_near_identity_excluded(
            Gf3258AffineQ8 {
                a: 271,
                ..Gf3258AffineQ8::IDENTITY
            },
            1
        ));
        assert!(!gf3258_terminal_recovery_near_identity_excluded(
            Gf3258AffineQ8 {
                a: 272,
                ..Gf3258AffineQ8::IDENTITY
            },
            1
        ));
        assert!(!gf3258_terminal_recovery_near_identity_excluded(
            Gf3258AffineQ8::IDENTITY,
            0
        ));
    }

    #[test]
    fn terminal_recovery_affine_metrics_identity_matches_vendor() {
        assert_eq!(
            gf3258_terminal_recovery_affine_metrics(Gf3258AffineQ8::IDENTITY),
            Gf3258TerminalRecoveryAffineMetrics {
                scale_q8: 256,
                orthogonality_q16: 0,
            }
        );
    }

    #[test]
    fn primary_refinement_gate_matches_gf3258_72700_boundaries() {
        assert!(!gf3258_primary_geometry_needs_refinement(2, 246));
        assert!(!gf3258_primary_geometry_needs_refinement(3, 180));
        assert!(gf3258_primary_geometry_needs_refinement(3, 181));
        assert!(gf3258_primary_geometry_needs_refinement(15, 246));
        assert!(!gf3258_primary_geometry_needs_refinement(16, 246));
    }

    #[test]
    fn primary_refinement_gate_uses_a9a50_evidence_not_coverage() {
        // The all-valid identity fixed vector has evidence 246 and coverage
        // 256. The raw 0x72700 gate consumes the former.
        assert!(gf3258_primary_geometry_needs_refinement(3, 246));
        assert!(!gf3258_primary_geometry_needs_refinement(3, 180));
    }

    #[test]
    fn refined_pair_selector_uses_transform_filter_and_polarity_partitions() {
        let matcher_point = |x: u16, y: u16, polarity: u16| Gf3258MatcherPoint {
            polarity,
            x_q8: x,
            y_q8: y,
            orientation_q12: 0,
            descriptor_10_1f: [0; 16],
            hash20: 0,
            hash24: 0,
            hash28: 0,
            hash30: 0,
        };
        let enrolled = [
            matcher_point(20 << 8, 20 << 8, 0),
            matcher_point(50 << 8, 40 << 8, 1),
        ];
        let live = [
            matcher_point(20 << 8, 20 << 8, 0),
            matcher_point(50 << 8, 40 << 8, 1),
        ];
        let mut score_matrix = vec![0xff; enrolled.len() * GF3258_MATCH_SCORE_MATRIX_STRIDE];
        score_matrix[0] = 10;
        score_matrix[1] = 0;
        score_matrix[GF3258_MATCH_SCORE_MATRIX_STRIDE] = 0;
        score_matrix[GF3258_MATCH_SCORE_MATRIX_STRIDE + 1] = 12;

        let slots = gf3258_refined_pair_slots_from_score_matrix(
            &enrolled,
            1,
            Gf3258MatcherFeatureSet {
                points: &live,
                polarity_split: 1,
            },
            &score_matrix,
            Gf3258AffineQ8::IDENTITY,
        );

        assert_eq!(slots[0], [0, 0]);
        assert_eq!(slots[1], [1, 1]);
        assert!(slots[2..].iter().all(|slot| *slot == [-1, -1]));
    }

    #[test]
    fn primary_geometry_api_preserves_initial_result_when_refinement_is_ineligible() {
        let sample = persisted_sample(
            vec![Gf3258PersistedPoint {
                geometry_word: 0xffff_ffff,
                descriptor_10_1f: [0; 16],
                hash20: 0,
                hash28: 0,
                hash2c: 0,
            }],
            1,
        );
        let live = [Gf3258MatcherPoint {
            polarity: 0,
            x_q8: 0x1000,
            y_q8: 0x1000,
            orientation_q12: 0,
            descriptor_10_1f: [0; 16],
            hash20: 0,
            hash24: 0,
            hash28: 0,
            hash30: 0,
        }];
        let config = Gf3258CandidateMatcherConfig {
            first_half_hamming_max: 64,
            descriptor_mode_hamming_max: 128,
            ambiguity_best_multiplier: 40,
            ambiguity_second_multiplier: 38,
        };
        let live_feature = Gf3258MatcherFeatureSet {
            points: &live,
            polarity_split: 1,
        };
        let candidates =
            gf3258_generate_persisted_sample_candidates(&sample, live_feature, config).unwrap();
        let initial = gf3258_persisted_sample_geometry_from_pair_slots(
            &sample,
            &live,
            &candidates.pair_slots,
        )
        .unwrap();
        let live_primary = [0u8; GF3258_REGISTRATION_PACKED_BYTES];
        let live_quarter = [0xffu8; GF3258_QUARTER_VALIDITY_CELLS / 8];
        let live_active = [0xffu8; GF3258_REGISTRATION_PACKED_BYTES];
        let selected = gf3258_persisted_sample_primary_geometry(
            &sample,
            live_feature,
            Gf3258VerificationRegistrationInput {
                primary_registration_map: &live_primary,
                secondary_registration_map: None,
                quarter_validity_packed: &live_quarter,
                active_validity_packed: &live_active,
            },
            config,
        )
        .unwrap();

        assert_eq!(initial, selected);
        assert!(selected.final_inlier_count < GF3258_REFINEMENT_MIN_INITIAL_INLIERS);
    }

    #[test]
    fn normal_registration_identity_keeps_evidence_and_coverage_distinct() {
        let mut sample = persisted_sample(Vec::new(), 0);
        sample.quarter_validity_packed = [0xff; GF3258_QUARTER_VALIDITY_CELLS / 8];
        sample.active_validity_packed = [0xff; GF3258_REGISTRATION_PACKED_BYTES];
        let primary = [0u8; GF3258_REGISTRATION_PACKED_BYTES];
        let quarter = [0xffu8; GF3258_QUARTER_VALIDITY_CELLS / 8];
        let active = [0xffu8; GF3258_REGISTRATION_PACKED_BYTES];
        let evidence = gf3258_verification_registration_evidence(
            &sample,
            Gf3258VerificationRegistrationInput {
                primary_registration_map: &primary,
                secondary_registration_map: None,
                quarter_validity_packed: &quarter,
                active_validity_packed: &active,
            },
            Gf3258AffineQ8::IDENTITY,
            0x100,
        );

        assert_eq!(evidence.map_score, 128);
        assert_eq!(evidence.evidence, 246);
        assert_eq!(evidence.coverage_q8, 256);
        assert_eq!(evidence.scaled_coverage_q8, 256);
    }

    #[test]
    fn registration_evidence_replacement_is_score_gated_and_strict() {
        let base = Gf3258VerificationRegistrationEvidence {
            map_score: 200,
            evidence: 200,
            coverage_q8: 200,
            scaled_coverage_q8: 200,
            affine_scale_q8: 256,
            affine_orthogonality_q16: 0,
            transform_live_to_enrolled: Gf3258AffineQ8::IDENTITY,
        };
        assert!(!gf3258_registration_evidence_replaces(
            Some(base),
            Gf3258VerificationRegistrationEvidence {
                map_score: 128,
                evidence: 255,
                ..base
            },
        ));
        assert!(!gf3258_registration_evidence_replaces(
            Some(base),
            Gf3258VerificationRegistrationEvidence {
                map_score: 129,
                ..base
            },
        ));
        assert!(gf3258_registration_evidence_replaces(
            Some(base),
            Gf3258VerificationRegistrationEvidence {
                map_score: 129,
                evidence: 201,
                ..base
            },
        ));
    }

    #[test]
    fn terminal_recovery_coverage_is_not_registration_metric_b() {
        let full = [0xffu8; GF3258_QUARTER_VALIDITY_CELLS / 8];
        let empty = [0u8; GF3258_QUARTER_VALIDITY_CELLS / 8];
        let alternating = [0x55u8; GF3258_QUARTER_VALIDITY_CELLS / 8];

        assert_eq!(
            gf3258_a9a50_coverage_q8_half_resolution(&full, &full, Gf3258AffineQ8::IDENTITY),
            256
        );
        assert_eq!(
            gf3258_a9a50_coverage_q8_half_resolution(&empty, &full, Gf3258AffineQ8::IDENTITY),
            0
        );
        assert_eq!(
            gf3258_a9a50_coverage_q8_half_resolution(
                &alternating,
                &alternating,
                Gf3258AffineQ8::IDENTITY,
            ),
            126
        );

        // The older registration scorer intentionally sees only 825 jointly
        // valid cells under its border-four warp for the all-valid identity
        // fixture, producing 165. Recovery a9a50's fourth output is a distinct
        // border-zero quarter-validity quantity and must remain 256.
        assert_eq!(
            crate::registration::gf3258_registration_metric_b(
                825,
                GF3258_REGISTRATION_WIDTH as i32,
                GF3258_REGISTRATION_HEIGHT as i32,
            ),
            165
        );
    }

    #[test]
    fn persisted_recovery_pair_slots_use_inverse_b1310_selection() {
        let (sample, live, _, _, _, config) = terminal_recovery_identity_fixture();
        let slots = gf3258_generate_persisted_sample_recovery_pair_slots(
            &sample,
            Gf3258MatcherFeatureSet {
                points: &live,
                polarity_split: 5,
            },
            config,
        )
        .unwrap();

        for (index, slot) in slots.iter().enumerate().take(live.len()) {
            assert_eq!(*slot, [index as i32, index as i32]);
        }
        assert_eq!(slots[live.len()], [-1, -1]);
    }

    #[test]
    fn persisted_recovery_observation_composes_geometry_maps_and_affine_metrics() {
        let (sample, live, primary, quarter_validity, active_validity, config) =
            terminal_recovery_identity_fixture();
        let result = gf3258_persisted_sample_terminal_recovery_observation(
            0,
            &sample,
            Gf3258TerminalRecoveryLiveFeature {
                matcher: Gf3258MatcherFeatureSet {
                    points: &live,
                    polarity_split: 5,
                },
                primary_registration_map: &primary,
                secondary_registration_map: None,
                quarter_validity_packed: &quarter_validity,
                active_validity_packed: &active_validity,
            },
            config,
            0,
        )
        .unwrap()
        .unwrap();

        assert_eq!(result.sample_index, 0);
        assert_eq!(result.transform_live_to_enrolled, Gf3258AffineQ8::IDENTITY);
        assert_eq!(result.observation.geometry_count, 6);
        assert_eq!(result.observation.map_score, 128);
        assert_eq!(result.observation.evidence, 246);
        assert_eq!(result.observation.coverage_q8, 256);
        assert_eq!(result.observation.affine_scale_q8, 256);
        assert_eq!(result.observation.affine_orthogonality_q16, 0);
    }

    #[test]
    fn persisted_recovery_scan_builds_and_aggregates_observations_internally() {
        let (sample, live, primary, quarter_validity, active_validity, candidate_matcher) =
            terminal_recovery_identity_fixture();
        let samples = [sample];
        let eligibility = [true];
        let result = gf3258_terminal_recovery_scan_persisted_samples(
            &samples,
            Gf3258TerminalRecoveryLiveFeature {
                matcher: Gf3258MatcherFeatureSet {
                    points: &live,
                    polarity_split: 5,
                },
                primary_registration_map: &primary,
                secondary_registration_map: None,
                quarter_validity_packed: &quarter_validity,
                active_validity_packed: &active_validity,
            },
            Gf3258TerminalRecoveryScanConfig {
                candidate_matcher,
                aggregate: Gf3258TerminalRecoveryConfig {
                    map_score_base: -100,
                    quality_scale_q8: 256,
                    apply_affine_penalty: false,
                },
                near_identity_exclusion_mode: 0,
                map_mode: 1,
                eligible_samples: &eligibility,
            },
        )
        .unwrap();

        assert_eq!(result.observations.len(), 1);
        assert_eq!(result.aggregation.admitted_candidates, 1);
        assert_eq!(result.aggregation.summary.accumulated_geometry_count, 6);
        assert_eq!(result.aggregation.summary.best_evidence, 246);
        assert_eq!(result.aggregation.summary.best_quality, 256);
        assert!(result.aggregation.summary.had_candidate);
    }

    #[test]
    fn persisted_recovery_scan_keeps_vendor_eligibility_as_explicit_boundary() {
        let (sample, live, primary, quarter_validity, active_validity, candidate_matcher) =
            terminal_recovery_identity_fixture();
        let samples = [sample];
        let eligibility = [false];
        let result = gf3258_terminal_recovery_scan_persisted_samples(
            &samples,
            Gf3258TerminalRecoveryLiveFeature {
                matcher: Gf3258MatcherFeatureSet {
                    points: &live,
                    polarity_split: 5,
                },
                primary_registration_map: &primary,
                secondary_registration_map: None,
                quarter_validity_packed: &quarter_validity,
                active_validity_packed: &active_validity,
            },
            Gf3258TerminalRecoveryScanConfig {
                candidate_matcher,
                aggregate: Gf3258TerminalRecoveryConfig::default(),
                near_identity_exclusion_mode: 0,
                map_mode: 1,
                eligible_samples: &eligibility,
            },
        )
        .unwrap();

        assert!(result.observations.is_empty());
        assert!(!result.aggregation.summary.had_candidate);
    }

    #[test]
    fn persisted_recovery_scan_rejects_unproven_runtime_map_mode() {
        let (sample, live, primary, quarter_validity, active_validity, candidate_matcher) =
            terminal_recovery_identity_fixture();
        let samples = [sample];
        let eligibility = [true];
        let error = gf3258_terminal_recovery_scan_persisted_samples(
            &samples,
            Gf3258TerminalRecoveryLiveFeature {
                matcher: Gf3258MatcherFeatureSet {
                    points: &live,
                    polarity_split: 5,
                },
                primary_registration_map: &primary,
                secondary_registration_map: None,
                quarter_validity_packed: &quarter_validity,
                active_validity_packed: &active_validity,
            },
            Gf3258TerminalRecoveryScanConfig {
                candidate_matcher,
                aggregate: Gf3258TerminalRecoveryConfig::default(),
                near_identity_exclusion_mode: 0,
                map_mode: 2,
                eligible_samples: &eligibility,
            },
        )
        .unwrap_err();

        assert_eq!(
            error,
            Gf3258TerminalRecoveryScanError::UnsupportedMapMode { mode: 2 }
        );
    }

    #[test]
    fn persisted_recovery_scan_feeds_terminal_arbiter_without_external_summary() {
        let (sample, live, primary, quarter_validity, active_validity, candidate_matcher) =
            terminal_recovery_identity_fixture();
        let samples = [sample];
        let eligibility = [true];
        let result = gf3258_terminal_arbitrate_score_from_persisted_recovery_scan(
            Gf3258TerminalArbitrationCoreInput {
                current_score: 0,
                normal_percent: 0,
                history_count: 0,
                matcher_state_688: 0,
                auxiliary_class: 0,
                accepted_samples: 0,
                config_48: 0,
                current_policy_score: 0,
                cache_rescue_enabled: false,
                cache_rescue_hit: false,
            },
            &samples,
            Gf3258TerminalRecoveryLiveFeature {
                matcher: Gf3258MatcherFeatureSet {
                    points: &live,
                    polarity_split: 5,
                },
                primary_registration_map: &primary,
                secondary_registration_map: None,
                quarter_validity_packed: &quarter_validity,
                active_validity_packed: &active_validity,
            },
            Gf3258TerminalRecoveryScanConfig {
                candidate_matcher,
                aggregate: Gf3258TerminalRecoveryConfig {
                    map_score_base: -100,
                    quality_scale_q8: 256,
                    apply_affine_penalty: false,
                },
                near_identity_exclusion_mode: 0,
                map_mode: 1,
                eligible_samples: &eligibility,
            },
        )
        .unwrap();

        assert_eq!(result.scan.observations.len(), 1);
        assert_eq!(
            result.scan.aggregation.summary.accumulated_geometry_count,
            6
        );
        assert_eq!(result.arbitration.score, 0);
        assert_eq!(
            result.arbitration.disposition,
            Gf3258TerminalScoreDisposition::RecoveryNonPositive
        );
    }

    #[test]
    fn profile_agreement_identity_full_validity_has_exact_constant_buckets() {
        let full_validity = [0xff; GF3258_QUARTER_VALIDITY_CELLS / 8];
        let zeros = [0u8; GF3258_REGISTRATION_PIXELS];
        let ones = [1u8; GF3258_REGISTRATION_PIXELS];

        assert_eq!(
            gf3258_profile_agreement_counts(&zeros, &full_validity, Gf3258AffineQ8::IDENTITY,),
            Gf3258ProfileAgreementCounts {
                both_zero: GF3258_REGISTRATION_PIXELS as i32,
                mixed: 0,
                both_one: 0,
            }
        );
        assert_eq!(
            gf3258_profile_agreement_counts(&ones, &full_validity, Gf3258AffineQ8::IDENTITY,),
            Gf3258ProfileAgreementCounts {
                both_zero: 0,
                mixed: 0,
                both_one: GF3258_REGISTRATION_PIXELS as i32,
            }
        );
    }

    #[test]
    fn profile_agreement_ratio_keeps_vendor_plus_one_denominator() {
        let counts = Gf3258ProfileAgreementCounts {
            both_zero: GF3258_REGISTRATION_PIXELS as i32,
            mixed: 0,
            both_one: 0,
        };
        assert_eq!(counts.ratio_q8(), Some(255));
    }

    #[test]
    fn policy_loop_profile_state_precedes_embedded_mode_promotion() {
        let mut sample = persisted_sample(Vec::new(), 0);
        // raw high bits 3 -> ab920 high 7 -> ab860 mapped high 4
        sample.embedded_state_140 = Some(0x300);
        let state = Gf3258NormalPolicyLoopState {
            mapped_candidate_mode: 2,
            reject_count: 2,
        }
        .for_sample(&sample);

        assert_eq!(state.profile_state, 5);
        assert_eq!(state.mapped_candidate_mode, 4);
        assert_eq!(state.reject_count, 2);
    }

    #[test]
    fn normal_policy_rescue_floor_is_derived_from_config_zero() {
        assert_eq!(gf3258_normal_policy_rescue_floor(0), 0xcf);
        assert_eq!(gf3258_normal_policy_rescue_floor(17), 0xe0);
        assert_eq!(
            gf3258_normal_policy_rescue_floor(i32::MAX),
            i32::MIN.wrapping_add(0xce),
        );
    }

    #[test]
    fn affine_axis_deviation_uses_undirected_nearest_axis() {
        assert_eq!(
            gf3258_affine_axis_deviation_degrees(Gf3258AffineQ8::IDENTITY),
            0
        );
        assert_eq!(
            gf3258_affine_axis_deviation_degrees(Gf3258AffineQ8 {
                a: 0,
                b: -256,
                tx: 0,
                c: 256,
                d: 0,
                ty: 0,
            }),
            90
        );
        assert_eq!(
            gf3258_affine_axis_deviation_degrees(Gf3258AffineQ8 {
                a: -256,
                b: 0,
                tx: 0,
                c: 0,
                d: -256,
                ty: 0,
            }),
            0
        );
    }

    #[test]
    fn pre_tail_policy_uses_complete_gf3258_entry_state() {
        assert!(!gf3258_pre_tail_policy_rejects(
            Gf3258PreTailPolicyRecord::default(),
            Gf3258PreTailPolicyContext::default(),
        ));

        let reject = gf3258_pre_tail_policy_rejects(
            Gf3258PreTailPolicyRecord {
                geometry_count: 27,
                verification_metric: 8,
                map_score: 69,
                evidence: 88,
                field_20: 0,
                scaled_coverage_q8: 149,
                matched_percent: 9,
                geometry_percent: 30,
                orthogonality_penalty: 2,
                severe_orthogonality: 0,
                live_quality: 71,
                enrolled_quality: 60,
            },
            Gf3258PreTailPolicyContext {
                mapped_mode: 4,
                profile_mode: 3,
                auxiliary_mode: 4,
                agreement: Gf3258ProfileAgreementCounts {
                    both_zero: 838,
                    mixed: 136,
                    both_one: 83,
                },
            },
        );
        assert!(reject);
    }

    #[test]
    fn policy_preparation_keeps_classifier_outputs_distinct() {
        assert_eq!(
            gf3258_policy_preparation(
                Gf3258PolicyPreparationRecord::default(),
                Gf3258PolicyPreparationContext::default(),
            ),
            Gf3258PolicyPreparation { tier: 0, gate: 0 }
        );

        let strong = gf3258_policy_preparation(
            Gf3258PolicyPreparationRecord {
                geometry_count: 20,
                verification_metric: 20,
                evidence: 300,
                scaled_coverage_q8: 120,
                matched_percent: 80,
                geometry_percent: 80,
                ..Gf3258PolicyPreparationRecord::default()
            },
            Gf3258PolicyPreparationContext {
                live_quality: 100,
                live_coverage: 100,
                ..Gf3258PolicyPreparationContext::default()
            },
        );
        assert_eq!(strong, Gf3258PolicyPreparation { tier: 2, gate: 1 });
    }
}
