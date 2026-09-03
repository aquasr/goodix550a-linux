//! GF3258 verification matcher geometry.
//!
//! Recovered from `FUN_001704f0 -> FUN_001aef60`. Pair slots are
//! `[enrolled_index, live_index]`, and the fitted affine maps live feature
//! coordinates into enrolled feature coordinates.

use crate::feature::{
    GF3258_PI_Q12, GF3258_TAU_Q12, Gf3258MatcherPoint, gf3258_cordic_atan2_magnitude_q12,
};

use super::affine::{integer_sqrt_u64, wrapping_abs_i32};
use super::{
    GF3258_GEOMETRY_AXIS_LIMIT_Q8, GF3258_GEOMETRY_INITIAL_COST, GF3258_GEOMETRY_RADIUS_SQ_Q16,
    GF3258_MAX_INITIAL_CORRESPONDENCES, Gf3258AffineQ8, Gf3258PointQ8,
    gf3258_affine_from_three_points, gf3258_affine_linear_part_is_valid,
};

pub const GF3258_MATCHER_HYPOTHESIS_CAP: usize = 0x3b2;
pub const GF3258_MATCHER_EARLY_EXIT_INLIERS: usize = 0x14;
pub const GF3258_MATCHER_TRIANGLE_MIN_QUARTER_SQ_Q16: i32 = 0x2ffff;
pub const GF3258_MATCHER_ORIENTATION_TRIPLE_TOLERANCE_Q12: i32 = 0x400;
pub const GF3258_MATCHER_ORIENTATION_INLIER_TOLERANCE_Q12: i32 = 0x506;
pub const GF3258_MATCHER_NEAR_SIMILARITY_DELTA_Q8: i32 = 0x31;
pub const GF3258_MATCHER_LINEAR_COEFFICIENT_LIMIT_Q8: i32 = 0x12b;
pub const GF3258_MATCHER_MIN_HYPOTHESIS_INLIERS: usize = 2;
pub const GF3258_MATCHER_REFIT_MIN_FINAL_INLIERS: usize = 4;
pub const GF3258_MATCHER_REFIT_MSE_THRESHOLD_Q16: i32 = 0x4000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gf3258MatcherGeometryError {
    PairIndexOutOfRange {
        slot: usize,
        side: &'static str,
        index: i32,
        point_count: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gf3258MatcherGeometryResult {
    /// Best FUN_001aef60 affine, mapping live Feature coordinates to enrolled
    /// Feature coordinates in Q8.
    pub transform_live_to_enrolled: Gf3258AffineQ8,
    /// Best aef60 spatial inlier mask, indexed by the 31 incoming pair slots.
    pub spatial_inlier_mask: [u8; GF3258_MAX_INITIAL_CORRESPONDENCES],
    pub spatial_inlier_count: usize,
    /// Rounded mean squared spatial residual returned through aef60 param_8.
    pub spatial_mse_q16: i32,
    /// FUN_001704f0 post-aef60 orientation-filtered mask, also indexed by the
    /// original 31 incoming pair slots.
    pub final_inlier_mask: [u8; GF3258_MAX_INITIAL_CORRESPONDENCES],
    /// FUN_001704f0 return value before the optional FUN_001b16e0 refit.
    pub final_inlier_count: usize,
    /// Number of ordered triple hypotheses admitted by the triangle and
    /// orientation-coherence prefilters. aef60 checks the 0x3b2 bound when
    /// advancing the outer-most triple index; the currently active outer
    /// iteration can therefore finish after the counter reaches 946.
    pub hypotheses_tested: usize,
    /// Exact vendor trigger for the reproduced FUN_001b16e0 refit.
    pub vendor_refit_triggered: bool,
}

impl Gf3258MatcherGeometryResult {
    fn empty() -> Self {
        Self {
            transform_live_to_enrolled: Gf3258AffineQ8 {
                a: 0,
                b: 0,
                tx: 0,
                c: 0,
                d: 0,
                ty: 0,
            },
            spatial_inlier_mask: [0; GF3258_MAX_INITIAL_CORRESPONDENCES],
            spatial_inlier_count: 0,
            spatial_mse_q16: GF3258_GEOMETRY_INITIAL_COST,
            final_inlier_mask: [0; GF3258_MAX_INITIAL_CORRESPONDENCES],
            final_inlier_count: 0,
            hypotheses_tested: 0,
            vendor_refit_triggered: false,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Gf3258MatcherPairGeometry {
    slot: usize,
    live: Gf3258PointQ8,
    enrolled: Gf3258PointQ8,
    live_orientation_q12: i32,
    enrolled_orientation_q12: i32,
}

#[inline]
fn gf3258_fold_ridge_delta_q12(mut delta: i32) -> i32 {
    let half_pi = GF3258_PI_Q12 / 2;
    if half_pi < delta {
        delta = delta.wrapping_sub(GF3258_PI_Q12);
    }
    if delta < -half_pi {
        delta = delta.wrapping_add(GF3258_PI_Q12);
    }
    delta
}

#[inline]
fn gf3258_triangle_quarter_distance_sq_q16(a: Gf3258PointQ8, b: Gf3258PointQ8) -> i32 {
    let dx = a.x.wrapping_sub(b.x);
    let dy = a.y.wrapping_sub(b.y);
    dx.wrapping_mul(dx)
        .wrapping_shr(2)
        .wrapping_add(dy.wrapping_mul(dy).wrapping_shr(2))
}

#[inline]
fn gf3258_matcher_triangle_edge_is_compatible(
    live_a: Gf3258PointQ8,
    live_b: Gf3258PointQ8,
    enrolled_a: Gf3258PointQ8,
    enrolled_b: Gf3258PointQ8,
) -> bool {
    let live_d2 = gf3258_triangle_quarter_distance_sq_q16(live_a, live_b);
    let enrolled_d2 = gf3258_triangle_quarter_distance_sq_q16(enrolled_a, enrolled_b);

    GF3258_MATCHER_TRIANGLE_MIN_QUARTER_SQ_Q16 < live_d2
        && GF3258_MATCHER_TRIANGLE_MIN_QUARTER_SQ_Q16 < enrolled_d2
        && live_d2.wrapping_mul(5) <= enrolled_d2.wrapping_mul(6)
        && enrolled_d2.wrapping_mul(5) <= live_d2.wrapping_mul(6)
}

fn gf3258_matcher_orientation_triple_is_coherent(
    pairs: &[Gf3258MatcherPairGeometry],
    i: usize,
    j: usize,
    k: usize,
) -> bool {
    let mut deltas = [
        gf3258_fold_ridge_delta_q12(
            pairs[i]
                .enrolled_orientation_q12
                .wrapping_sub(pairs[i].live_orientation_q12),
        ),
        gf3258_fold_ridge_delta_q12(
            pairs[j]
                .enrolled_orientation_q12
                .wrapping_sub(pairs[j].live_orientation_q12),
        ),
        gf3258_fold_ridge_delta_q12(
            pairs[k]
                .enrolled_orientation_q12
                .wrapping_sub(pairs[k].live_orientation_q12),
        ),
    ];

    let coherent = |values: [i32; 3]| {
        let mean = values[0].wrapping_add(values[1]).wrapping_add(values[2]) / 3;
        values.iter().all(|&value| {
            let residual = value.wrapping_sub(mean);
            (-GF3258_MATCHER_ORIENTATION_TRIPLE_TOLERANCE_Q12
                ..=GF3258_MATCHER_ORIENTATION_TRIPLE_TOLERANCE_Q12)
                .contains(&residual)
        })
    };

    if coherent(deltas) {
        return true;
    }

    // aef60 param_10 == 1 on GF3258. Its alternate wrap trial adds pi/2 to
    // each already-folded ridge delta and folds through the same pi period.
    let half_pi = GF3258_PI_Q12 / 2;
    for delta in &mut deltas {
        *delta = gf3258_fold_ridge_delta_q12(delta.wrapping_add(half_pi));
    }
    coherent(deltas)
}

#[inline]
fn gf3258_matcher_near_similarity_is_valid(transform: Gf3258AffineQ8) -> bool {
    let ad = transform.a.wrapping_sub(transform.d);
    let cb = transform.c.wrapping_add(transform.b);
    if wrapping_abs_i32(ad) > GF3258_MATCHER_NEAR_SIMILARITY_DELTA_Q8
        || wrapping_abs_i32(cb) > GF3258_MATCHER_NEAR_SIMILARITY_DELTA_Q8
    {
        return false;
    }

    [transform.a, transform.b, transform.c, transform.d]
        .into_iter()
        .all(|value| {
            (-GF3258_MATCHER_LINEAR_COEFFICIENT_LIMIT_Q8
                ..=GF3258_MATCHER_LINEAR_COEFFICIENT_LIMIT_Q8)
                .contains(&value)
        })
}

#[inline]
fn gf3258_matcher_transform_q8_rounded(
    transform: Gf3258AffineQ8,
    point: Gf3258PointQ8,
) -> Gf3258PointQ8 {
    let x = i64::from(transform.a)
        .wrapping_mul(i64::from(point.x))
        .wrapping_add(0x80)
        .wrapping_add(i64::from(transform.b).wrapping_mul(i64::from(point.y)));
    let y = i64::from(transform.c)
        .wrapping_mul(i64::from(point.x))
        .wrapping_add(0x80)
        .wrapping_add(i64::from(transform.d).wrapping_mul(i64::from(point.y)));

    Gf3258PointQ8 {
        x: ((x >> 8) as i32).wrapping_add(transform.tx),
        y: ((y >> 8) as i32).wrapping_add(transform.ty),
    }
}

fn gf3258_matcher_transform_rotation_q12(transform: Gf3258AffineQ8) -> Option<i32> {
    // Raw 704f0 normalizes the two column norms before calling b8b90. The
    // normalization is observable because the integer CORDIC angle can differ
    // slightly when fed an algebraically equivalent vector at another scale.
    let first_norm = integer_sqrt_u64(
        i64::from(transform.a)
            .wrapping_mul(i64::from(transform.a))
            .wrapping_add(i64::from(transform.c).wrapping_mul(i64::from(transform.c)))
            as u64,
    ) as i32;
    let second_norm = integer_sqrt_u64(
        i64::from(transform.b)
            .wrapping_mul(i64::from(transform.b))
            .wrapping_add(i64::from(transform.d).wrapping_mul(i64::from(transform.d)))
            as u64,
    ) as i32;
    let mean_norm = first_norm.wrapping_add(second_norm) / 2;
    if mean_norm == 0 {
        return None;
    }

    let half_sum = transform.a.wrapping_add(transform.d) / 2;
    let half_cross = transform.c.wrapping_sub(transform.b) / 2;
    let normalized_cos = half_sum.wrapping_mul(0x100) / mean_norm;
    let normalized_sin = half_cross.wrapping_mul(0x100) / mean_norm;
    let (angle_bits, _) = gf3258_cordic_atan2_magnitude_q12(normalized_sin, normalized_cos);
    Some(i32::from(angle_bits as i16))
}

#[inline]
fn gf3258_matcher_orientation_distance_q12(delta: i32) -> i32 {
    let normalize_once = |mut value: i32| {
        if value < 0 {
            value = value.wrapping_add(GF3258_TAU_Q12);
        }
        if GF3258_TAU_Q12 < value {
            value = value.wrapping_sub(GF3258_TAU_Q12);
        }
        value
    };

    let base = normalize_once(delta);
    let shifted = normalize_once(delta.wrapping_add(GF3258_PI_Q12));
    base.min(GF3258_TAU_Q12.wrapping_sub(base))
        .min(shifted)
        .min(GF3258_TAU_Q12.wrapping_sub(shifted))
}

#[inline]
fn gf3258_b16e0_dot_q8(left: &[i64], right: &[i64]) -> i64 {
    debug_assert_eq!(left.len(), right.len());
    let sum = left
        .iter()
        .zip(right)
        .fold(0i64, |sum, (&a, &b)| sum.wrapping_add(a.wrapping_mul(b)));
    sum.wrapping_add(0x80) >> 8
}

#[inline]
fn gf3258_b16e0_minor(a: i64, b: i64, c: i64, d: i64) -> i64 {
    a.wrapping_mul(b).wrapping_sub(c.wrapping_mul(d))
}

/// Exact integer affine refit used by raw FUN_001b16e0.
///
/// `live` and `enrolled` are the compact correspondence arrays constructed by
/// FUN_001704f0. `inlier_mask` is its post-orientation-filter mask. The least
/// squares system is fit only to non-zero mask entries, but the candidate is
/// then checked against every correspondence. The vendor writes the candidate
/// transform only when:
///
/// - the candidate's rounded mean residual is strictly below `previous_mse_q16`;
/// - the number of all-pair residuals within `0x63fff` is at least the masked
///   inlier count.
///
/// Returns true only when the vendor would overwrite the transform.
fn gf3258_matcher_refit_affine_b16e0(
    live: &[Gf3258PointQ8],
    enrolled: &[Gf3258PointQ8],
    inlier_mask: &[u8],
    previous_mse_q16: i32,
    transform: &mut Gf3258AffineQ8,
) -> bool {
    debug_assert_eq!(live.len(), enrolled.len());
    debug_assert_eq!(live.len(), inlier_mask.len());

    let selected: Vec<usize> = inlier_mask
        .iter()
        .enumerate()
        .filter_map(|(index, &enabled)| (enabled != 0).then_some(index))
        .collect();
    let selected_count = selected.len();

    let mut columns = [
        Vec::with_capacity(selected_count),
        Vec::with_capacity(selected_count),
        Vec::with_capacity(selected_count),
    ];
    let mut targets = [
        Vec::with_capacity(selected_count),
        Vec::with_capacity(selected_count),
    ];
    for &index in &selected {
        columns[0].push(i64::from(live[index].x));
        columns[1].push(i64::from(live[index].y));
        columns[2].push(0x100);
        targets[0].push(i64::from(enrolled[index].x));
        targets[1].push(i64::from(enrolled[index].y));
    }

    let mut gram = [[0i64; 3]; 3];
    for row in 0..3 {
        for column in 0..3 {
            gram[row][column] = gf3258_b16e0_dot_q8(&columns[row], &columns[column]);
        }
    }

    let mut rhs = [[0i64; 2]; 3];
    for row in 0..3 {
        for target in 0..2 {
            rhs[row][target] = gf3258_b16e0_dot_q8(&columns[row], &targets[target]);
        }
    }

    // Adjugate of the rounded Q8 Gram matrix. All operations are wrapping i64
    // operations, matching the raw IMUL/ADD/SUB sequence.
    let g = gram;
    let adj = [
        [
            gf3258_b16e0_minor(g[1][1], g[2][2], g[1][2], g[2][1]),
            gf3258_b16e0_minor(g[0][2], g[2][1], g[0][1], g[2][2]),
            gf3258_b16e0_minor(g[0][1], g[1][2], g[0][2], g[1][1]),
        ],
        [
            gf3258_b16e0_minor(g[1][2], g[2][0], g[1][0], g[2][2]),
            gf3258_b16e0_minor(g[0][0], g[2][2], g[0][2], g[2][0]),
            gf3258_b16e0_minor(g[0][2], g[1][0], g[0][0], g[1][2]),
        ],
        [
            gf3258_b16e0_minor(g[1][0], g[2][1], g[1][1], g[2][0]),
            gf3258_b16e0_minor(g[0][1], g[2][0], g[0][0], g[2][1]),
            gf3258_b16e0_minor(g[0][0], g[1][1], g[0][1], g[1][0]),
        ],
    ];

    let determinant_with_rounding = 0x80i64
        .wrapping_add(g[0][0].wrapping_mul(adj[0][0]))
        .wrapping_add(g[0][1].wrapping_mul(adj[1][0]))
        .wrapping_add(g[0][2].wrapping_mul(adj[2][0]));
    let denominator = determinant_with_rounding >> 8;
    if denominator == 0 {
        return false;
    }
    let half_denominator = determinant_with_rounding >> 9;

    let mut coefficients = [[0i32; 2]; 3];
    for row in 0..3 {
        for target in 0..2 {
            let mut numerator = 0i64;
            for column in 0..3 {
                numerator =
                    numerator.wrapping_add(adj[row][column].wrapping_mul(rhs[column][target]));
            }
            numerator = if numerator < 0 {
                numerator.wrapping_sub(half_denominator)
            } else {
                numerator.wrapping_add(half_denominator)
            };

            // In the real GF3258 coordinate domain this IDIV cannot overflow;
            // the vendor would fault on the pathological i64::MIN / -1 case.
            coefficients[row][target] = (numerator / denominator) as i32;
        }
    }

    let candidate = Gf3258AffineQ8 {
        a: coefficients[0][0],
        b: coefficients[1][0],
        tx: coefficients[2][0],
        c: coefficients[0][1],
        d: coefficients[1][1],
        ty: coefficients[2][1],
    };

    let mut retained_count = 0usize;
    let mut squared_error_sum = 0i64;
    for (&live_point, &enrolled_point) in live.iter().zip(enrolled) {
        let predicted = gf3258_matcher_transform_q8_rounded(candidate, live_point);
        let dx = predicted.x.wrapping_sub(enrolled_point.x);
        let dy = predicted.y.wrapping_sub(enrolled_point.y);
        let distance_sq = i64::from(dx)
            .wrapping_mul(i64::from(dx))
            .wrapping_add(i64::from(dy).wrapping_mul(i64::from(dy)));
        if (distance_sq as u64) <= 0x63fff {
            retained_count += 1;
            squared_error_sum = squared_error_sum.wrapping_add(distance_sq);
        }
    }

    let mean_error = if retained_count == 0 {
        0x190000u64
    } else {
        (squared_error_sum as u64).wrapping_add((retained_count >> 1) as u64)
            / retained_count as u64
    };
    let previous_mse_unsigned = i64::from(previous_mse_q16) as u64;

    if mean_error < previous_mse_unsigned && selected_count <= retained_count {
        *transform = candidate;
        true
    } else {
        false
    }
}

/// Matcher-specific geometric hypothesis stage recovered from
/// FUN_001704f0 -> FUN_001aef60 for GF3258.
///
/// Pair slots are `[enrolled_index, live_index]`. The fitted affine therefore
/// maps LIVE -> ENROLLED. This deliberately does not call
/// `gf3258_verify_geometry`: enrollment's aea40 path lacks aef60's triangle and
/// orientation-triple gates and uses different point-evaluation rounding.
///
/// The optional FUN_001b16e0 transform refit is reproduced exactly.
/// `vendor_refit_triggered` reports whether the caller entered that refit path;
/// the refit itself only overwrites `transform_live_to_enrolled` when its
/// all-pair residual check strictly improves on the pre-refit spatial MSE and
/// retains at least as many close correspondences as the orientation-filtered
/// inlier set.
pub fn gf3258_matcher_geometry_from_pair_slots(
    enrolled: &[Gf3258MatcherPoint],
    live: &[Gf3258MatcherPoint],
    pair_slots: &[[i32; 2]; GF3258_MAX_INITIAL_CORRESPONDENCES],
) -> Result<Gf3258MatcherGeometryResult, Gf3258MatcherGeometryError> {
    let mut pairs = Vec::with_capacity(GF3258_MAX_INITIAL_CORRESPONDENCES);
    for (slot, &[enrolled_index, live_index]) in pair_slots.iter().enumerate() {
        if enrolled_index < 0 || live_index < 0 {
            continue;
        }
        let enrolled_index_usize = enrolled_index as usize;
        if enrolled_index_usize >= enrolled.len() {
            return Err(Gf3258MatcherGeometryError::PairIndexOutOfRange {
                slot,
                side: "enrolled",
                index: enrolled_index,
                point_count: enrolled.len(),
            });
        }
        let live_index_usize = live_index as usize;
        if live_index_usize >= live.len() {
            return Err(Gf3258MatcherGeometryError::PairIndexOutOfRange {
                slot,
                side: "live",
                index: live_index,
                point_count: live.len(),
            });
        }

        let enrolled_point = enrolled[enrolled_index_usize];
        let live_point = live[live_index_usize];
        pairs.push(Gf3258MatcherPairGeometry {
            slot,
            live: Gf3258PointQ8 {
                x: i32::from(live_point.x_q8),
                y: i32::from(live_point.y_q8),
            },
            enrolled: Gf3258PointQ8 {
                x: i32::from(enrolled_point.x_q8),
                y: i32::from(enrolled_point.y_q8),
            },
            live_orientation_q12: i32::from(live_point.orientation_q12),
            enrolled_orientation_q12: i32::from(enrolled_point.orientation_q12),
        });
    }

    let mut best = Gf3258MatcherGeometryResult::empty();
    if pairs.len() < 3 {
        return Ok(best);
    }

    'triples: for i in 0..pairs.len() - 2 {
        // aef60's `while (local_1bc < 0x3b2)` surrounds the outer-most
        // index only. Do not turn this into an inner hard cap: the vendor
        // completes the current i-iteration once admitted.
        if best.hypotheses_tested >= GF3258_MATCHER_HYPOTHESIS_CAP {
            break;
        }
        for j in i + 1..pairs.len() - 1 {
            if !gf3258_matcher_triangle_edge_is_compatible(
                pairs[i].live,
                pairs[j].live,
                pairs[i].enrolled,
                pairs[j].enrolled,
            ) {
                continue;
            }

            for k in j + 1..pairs.len() {
                if !gf3258_matcher_orientation_triple_is_coherent(&pairs, i, j, k)
                    || !gf3258_matcher_triangle_edge_is_compatible(
                        pairs[i].live,
                        pairs[k].live,
                        pairs[i].enrolled,
                        pairs[k].enrolled,
                    )
                    || !gf3258_matcher_triangle_edge_is_compatible(
                        pairs[j].live,
                        pairs[k].live,
                        pairs[j].enrolled,
                        pairs[k].enrolled,
                    )
                {
                    continue;
                }

                best.hypotheses_tested += 1;
                let transform = gf3258_affine_from_three_points(
                    [pairs[i].live, pairs[j].live, pairs[k].live],
                    [pairs[i].enrolled, pairs[j].enrolled, pairs[k].enrolled],
                );
                if !gf3258_matcher_near_similarity_is_valid(transform) {
                    continue;
                }

                let mut compact_mask = vec![0u8; pairs.len()];
                let mut inlier_count = 0usize;
                let mut squared_error_sum = 0i32;
                for (pair_index, pair) in pairs.iter().enumerate() {
                    let predicted = gf3258_matcher_transform_q8_rounded(transform, pair.live);
                    let dx = predicted.x.wrapping_sub(pair.enrolled.x);
                    let dy = predicted.y.wrapping_sub(pair.enrolled.y);
                    if wrapping_abs_i32(dx) >= GF3258_GEOMETRY_AXIS_LIMIT_Q8
                        || wrapping_abs_i32(dy) >= GF3258_GEOMETRY_AXIS_LIMIT_Q8
                    {
                        continue;
                    }
                    let radius_sq = dx.wrapping_mul(dx).wrapping_add(dy.wrapping_mul(dy));
                    if radius_sq >= GF3258_GEOMETRY_RADIUS_SQ_Q16 {
                        continue;
                    }
                    compact_mask[pair_index] = 1;
                    inlier_count += 1;
                    squared_error_sum = squared_error_sum.wrapping_add(radius_sq);
                }

                if inlier_count < GF3258_MATCHER_MIN_HYPOTHESIS_INLIERS {
                    continue;
                }

                let mse = squared_error_sum.wrapping_add((inlier_count >> 1) as i32)
                    / inlier_count as i32;
                let better = inlier_count > best.spatial_inlier_count
                    || (inlier_count == best.spatial_inlier_count && mse < best.spatial_mse_q16);
                if !better || !gf3258_affine_linear_part_is_valid(transform) {
                    continue;
                }

                best.transform_live_to_enrolled = transform;
                best.spatial_inlier_mask = [0; GF3258_MAX_INITIAL_CORRESPONDENCES];
                for (pair_index, &is_inlier) in compact_mask.iter().enumerate() {
                    best.spatial_inlier_mask[pairs[pair_index].slot] = is_inlier;
                }
                best.spatial_inlier_count = inlier_count;
                best.spatial_mse_q16 = mse;

                if GF3258_MATCHER_EARLY_EXIT_INLIERS < best.spatial_inlier_count {
                    break 'triples;
                }
            }
        }
    }

    if best.spatial_inlier_count == 0 {
        return Ok(best);
    }

    best.final_inlier_mask = best.spatial_inlier_mask;
    best.final_inlier_count = 0;
    let Some(rotation_q12) = gf3258_matcher_transform_rotation_q12(best.transform_live_to_enrolled)
    else {
        best.final_inlier_count = best.spatial_inlier_count;
        return Ok(best);
    };
    for pair in &pairs {
        if best.spatial_inlier_mask[pair.slot] == 0 {
            continue;
        }
        let orientation_distance = gf3258_matcher_orientation_distance_q12(
            rotation_q12
                .wrapping_add(pair.enrolled_orientation_q12)
                .wrapping_sub(pair.live_orientation_q12),
        );
        if orientation_distance <= GF3258_MATCHER_ORIENTATION_INLIER_TOLERANCE_Q12 {
            best.final_inlier_count += 1;
        } else {
            best.final_inlier_mask[pair.slot] = 0;
        }
    }

    best.vendor_refit_triggered = GF3258_MATCHER_REFIT_MIN_FINAL_INLIERS <= best.final_inlier_count
        && GF3258_MATCHER_REFIT_MSE_THRESHOLD_Q16 < best.spatial_mse_q16;
    if best.vendor_refit_triggered {
        let compact_live: Vec<Gf3258PointQ8> = pairs.iter().map(|pair| pair.live).collect();
        let compact_enrolled: Vec<Gf3258PointQ8> = pairs.iter().map(|pair| pair.enrolled).collect();
        let compact_final_mask: Vec<u8> = pairs
            .iter()
            .map(|pair| best.final_inlier_mask[pair.slot])
            .collect();
        gf3258_matcher_refit_affine_b16e0(
            &compact_live,
            &compact_enrolled,
            &compact_final_mask,
            best.spatial_mse_q16,
            &mut best.transform_live_to_enrolled,
        );
    }

    Ok(best)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matcher_point(x_q8: u16, y_q8: u16, orientation_q12: u16) -> Gf3258MatcherPoint {
        Gf3258MatcherPoint {
            polarity: 0,
            x_q8,
            y_q8,
            orientation_q12,
            descriptor_10_1f: [0; 16],
            hash20: 0,
            hash24: 0,
            hash28: 0,
            hash30: 0,
        }
    }

    #[test]
    fn matcher_geometry_identity_keeps_all_spatial_and_orientation_inliers() {
        let enrolled = vec![
            matcher_point(10 << 8, 10 << 8, 0),
            matcher_point(20 << 8, 10 << 8, 0),
            matcher_point(10 << 8, 20 << 8, 0),
            matcher_point(20 << 8, 20 << 8, 0),
            matcher_point(15 << 8, 25 << 8, 0),
            matcher_point(25 << 8, 15 << 8, 0),
        ];
        let live = enrolled.clone();
        let mut slots = [[-1i32, -1i32]; GF3258_MAX_INITIAL_CORRESPONDENCES];
        for (i, slot) in slots.iter_mut().enumerate().take(enrolled.len()) {
            *slot = [i as i32, i as i32];
        }

        let result = gf3258_matcher_geometry_from_pair_slots(&enrolled, &live, &slots).unwrap();
        assert_eq!(result.transform_live_to_enrolled, Gf3258AffineQ8::IDENTITY);
        assert_eq!(result.spatial_inlier_count, enrolled.len());
        assert_eq!(result.final_inlier_count, enrolled.len());
        assert_eq!(result.spatial_mse_q16, 0);
        assert!(!result.vendor_refit_triggered);
    }

    #[test]
    fn matcher_geometry_orientation_filter_uses_vendor_rotation_sign() {
        let enrolled = vec![
            matcher_point(20 << 8, 20 << 8, 0),
            matcher_point(40 << 8, 20 << 8, 0),
            matcher_point(20 << 8, 40 << 8, 0),
            matcher_point(40 << 8, 40 << 8, 0),
            matcher_point(30 << 8, 50 << 8, 0),
            matcher_point(50 << 8, 30 << 8, 0),
        ];
        let live = vec![
            matcher_point(4688, 5607, 1750),
            matcher_point(9771, 4994, 1750),
            matcher_point(5301, 10690, 1750),
            matcher_point(10384, 10078, 1750),
            matcher_point(8149, 12926, 1750),
            matcher_point(12619, 7230, 1750),
        ];
        let mut slots = [[-1i32, -1i32]; GF3258_MAX_INITIAL_CORRESPONDENCES];
        for (index, slot) in slots.iter_mut().enumerate().take(enrolled.len()) {
            *slot = [index as i32, index as i32];
        }

        let result = gf3258_matcher_geometry_from_pair_slots(&enrolled, &live, &slots).unwrap();
        assert_eq!(result.spatial_inlier_count, enrolled.len());
        assert_eq!(result.final_inlier_count, enrolled.len());
        assert_eq!(
            result.transform_live_to_enrolled,
            Gf3258AffineQ8 {
                a: 254,
                b: -31,
                tx: 1140,
                c: 30,
                d: 254,
                ty: -996,
            }
        );
    }

    #[test]
    fn matcher_geometry_post_filter_rejects_orientation_outlier() {
        let mut enrolled = vec![
            matcher_point(10 << 8, 10 << 8, 0),
            matcher_point(20 << 8, 10 << 8, 0),
            matcher_point(10 << 8, 20 << 8, 0),
            matcher_point(20 << 8, 20 << 8, 0),
            matcher_point(15 << 8, 25 << 8, 0),
            matcher_point(25 << 8, 15 << 8, 0),
        ];
        let live = enrolled.clone();
        enrolled[5].orientation_q12 = 0x700;
        let mut slots = [[-1i32, -1i32]; GF3258_MAX_INITIAL_CORRESPONDENCES];
        for (i, slot) in slots.iter_mut().enumerate().take(enrolled.len()) {
            *slot = [i as i32, i as i32];
        }

        let result = gf3258_matcher_geometry_from_pair_slots(&enrolled, &live, &slots).unwrap();
        assert_eq!(result.spatial_inlier_count, enrolled.len());
        assert_eq!(result.final_inlier_count, enrolled.len() - 1);
        assert_eq!(result.final_inlier_mask[5], 0);
    }

    #[test]
    fn matcher_geometry_reports_bad_pair_index() {
        let enrolled = vec![matcher_point(10 << 8, 10 << 8, 0)];
        let live = enrolled.clone();
        let mut slots = [[-1i32, -1i32]; GF3258_MAX_INITIAL_CORRESPONDENCES];
        slots[0] = [1, 0];
        assert!(matches!(
            gf3258_matcher_geometry_from_pair_slots(&enrolled, &live, &slots),
            Err(Gf3258MatcherGeometryError::PairIndexOutOfRange {
                side: "enrolled",
                ..
            })
        ));
    }
    #[test]
    fn b16e0_identity_refit_matches_vendor_vector() {
        let live = [
            Gf3258PointQ8 {
                x: 10 << 8,
                y: 10 << 8,
            },
            Gf3258PointQ8 {
                x: 20 << 8,
                y: 10 << 8,
            },
            Gf3258PointQ8 {
                x: 10 << 8,
                y: 20 << 8,
            },
            Gf3258PointQ8 {
                x: 20 << 8,
                y: 20 << 8,
            },
            Gf3258PointQ8 {
                x: 15 << 8,
                y: 25 << 8,
            },
            Gf3258PointQ8 {
                x: 25 << 8,
                y: 15 << 8,
            },
        ];
        let mut transform = Gf3258AffineQ8 {
            a: 1,
            b: 2,
            tx: 3,
            c: 4,
            d: 5,
            ty: 6,
        };
        assert!(gf3258_matcher_refit_affine_b16e0(
            &live,
            &live,
            &[1; 6],
            0x10000,
            &mut transform,
        ));
        assert_eq!(transform, Gf3258AffineQ8::IDENTITY);
    }

    #[test]
    fn b16e0_translation_refit_matches_vendor_vector() {
        let live = [
            Gf3258PointQ8 {
                x: 10 << 8,
                y: 10 << 8,
            },
            Gf3258PointQ8 {
                x: 20 << 8,
                y: 10 << 8,
            },
            Gf3258PointQ8 {
                x: 10 << 8,
                y: 20 << 8,
            },
            Gf3258PointQ8 {
                x: 20 << 8,
                y: 20 << 8,
            },
            Gf3258PointQ8 {
                x: 15 << 8,
                y: 25 << 8,
            },
            Gf3258PointQ8 {
                x: 25 << 8,
                y: 15 << 8,
            },
        ];
        let enrolled = live.map(|point| Gf3258PointQ8 {
            x: point.x + (2 << 8),
            y: point.y - (3 << 8),
        });
        let mut transform = Gf3258AffineQ8::IDENTITY;
        assert!(gf3258_matcher_refit_affine_b16e0(
            &live,
            &enrolled,
            &[1; 6],
            0x10000,
            &mut transform,
        ));
        assert_eq!(
            transform,
            Gf3258AffineQ8 {
                a: 256,
                b: 0,
                tx: 512,
                c: 0,
                d: 256,
                ty: -768,
            }
        );
    }

    #[test]
    fn b16e0_requires_strict_mse_improvement() {
        let live = [
            Gf3258PointQ8 {
                x: 10 << 8,
                y: 10 << 8,
            },
            Gf3258PointQ8 {
                x: 20 << 8,
                y: 10 << 8,
            },
            Gf3258PointQ8 {
                x: 10 << 8,
                y: 20 << 8,
            },
            Gf3258PointQ8 {
                x: 20 << 8,
                y: 20 << 8,
            },
        ];
        let enrolled = live.map(|point| Gf3258PointQ8 {
            x: point.x + 512,
            y: point.y - 768,
        });
        let original = Gf3258AffineQ8 {
            a: 1,
            b: 2,
            tx: 3,
            c: 4,
            d: 5,
            ty: 6,
        };
        let mut transform = original;
        assert!(!gf3258_matcher_refit_affine_b16e0(
            &live,
            &enrolled,
            &[1; 4],
            0,
            &mut transform,
        ));
        assert_eq!(transform, original);
    }

    #[test]
    fn b16e0_masked_noisy_fit_matches_vendor_vector() {
        let live = [
            Gf3258PointQ8 {
                x: 10 << 8,
                y: 10 << 8,
            },
            Gf3258PointQ8 {
                x: 20 << 8,
                y: 10 << 8,
            },
            Gf3258PointQ8 {
                x: 10 << 8,
                y: 20 << 8,
            },
            Gf3258PointQ8 {
                x: 20 << 8,
                y: 20 << 8,
            },
            Gf3258PointQ8 {
                x: 15 << 8,
                y: 25 << 8,
            },
            Gf3258PointQ8 {
                x: 25 << 8,
                y: 15 << 8,
            },
        ];
        let noise = [
            (0, 0),
            (50, -30),
            (-100, 60),
            (20, 80),
            (300, -200),
            (-250, 150),
        ];
        let enrolled: [Gf3258PointQ8; 6] = core::array::from_fn(|index| Gf3258PointQ8 {
            x: live[index].x + 512 + noise[index].0,
            y: live[index].y - 768 + noise[index].1,
        });
        let mut transform = Gf3258AffineQ8::IDENTITY;
        assert!(gf3258_matcher_refit_affine_b16e0(
            &live,
            &enrolled,
            &[1, 1, 1, 1, 0, 0],
            0x10000,
            &mut transform,
        ));
        assert_eq!(
            transform,
            Gf3258AffineQ8 {
                a: 265,
                b: -7,
                tx: 475,
                c: -1,
                d: 265,
                ty: -861,
            }
        );
    }

    #[test]
    fn b16e0_rejects_candidate_that_retains_fewer_than_masked_inliers() {
        let live = [
            Gf3258PointQ8 { x: 7523, y: 2829 },
            Gf3258PointQ8 { x: 18901, y: 1536 },
            Gf3258PointQ8 { x: 8321, y: 3062 },
            Gf3258PointQ8 { x: 380, y: 5527 },
            Gf3258PointQ8 { x: 4676, y: 9011 },
            Gf3258PointQ8 { x: 6903, y: 11015 },
            Gf3258PointQ8 { x: 9368, y: 12012 },
            Gf3258PointQ8 { x: 15911, y: 14347 },
            Gf3258PointQ8 { x: 8251, y: 5979 },
        ];
        let enrolled = [
            Gf3258PointQ8 { x: 10433, y: 3511 },
            Gf3258PointQ8 { x: 23062, y: 5015 },
            Gf3258PointQ8 { x: 11035, y: 2476 },
            Gf3258PointQ8 { x: 850, y: 3190 },
            Gf3258PointQ8 { x: 8623, y: 8198 },
            Gf3258PointQ8 { x: 9942, y: 9908 },
            Gf3258PointQ8 { x: 13512, y: 10187 },
            Gf3258PointQ8 { x: 22881, y: 14046 },
            Gf3258PointQ8 { x: 11128, y: 6902 },
        ];
        let original = Gf3258AffineQ8 {
            a: 1,
            b: 2,
            tx: 3,
            c: 4,
            d: 5,
            ty: 6,
        };
        let mut transform = original;
        assert!(!gf3258_matcher_refit_affine_b16e0(
            &live,
            &enrolled,
            &[1, 1, 1, 1, 0, 1, 1, 1, 1],
            0x200000,
            &mut transform,
        ));
        assert_eq!(transform, original);
    }

    #[test]
    fn b16e0_rank_deficient_fit_preserves_transform() {
        let live = [
            Gf3258PointQ8 {
                x: 1 << 8,
                y: 1 << 8,
            },
            Gf3258PointQ8 {
                x: 2 << 8,
                y: 2 << 8,
            },
            Gf3258PointQ8 {
                x: 3 << 8,
                y: 3 << 8,
            },
            Gf3258PointQ8 {
                x: 4 << 8,
                y: 4 << 8,
            },
        ];
        let enrolled = live;
        let original = Gf3258AffineQ8 {
            a: 200,
            b: 1,
            tx: 2,
            c: 3,
            d: 201,
            ty: 4,
        };
        let mut transform = original;
        assert!(!gf3258_matcher_refit_affine_b16e0(
            &live,
            &enrolled,
            &[1; 4],
            0x10000,
            &mut transform,
        ));
        assert_eq!(transform, original);
    }
}
