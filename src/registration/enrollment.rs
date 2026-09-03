//! GF3258 enrollment descriptor correspondence and geometric registration.
//!
//! This module owns the recovered enrollment-side path from FeaturePoint60
//! registration records through initial descriptor correspondences and
//! `FUN_001aea40` geometric verification. The fitted affine maps the current
//! touch into the previously stored touch. Map scoring lives in
//! `registration::map`; final acceptance policy remains in the parent layer.

use crate::feature::{Gf3258CompactDescriptor, Gf3258FeaturePointCore};

use super::affine::wrapping_abs_i32;
use super::{
    GF3258_GEOMETRY_AXIS_LIMIT_Q8, GF3258_GEOMETRY_INITIAL_COST, GF3258_GEOMETRY_RADIUS_SQ_Q16,
    GF3258_MAX_INITIAL_CORRESPONDENCES, Gf3258AffineQ8, Gf3258PointQ8,
    gf3258_affine_from_three_points, gf3258_affine_linear_part_is_valid,
};

pub const GF3258_GEOMETRY_MASK_CAPACITY: usize = 42;
pub const GF3258_DESCRIPTOR_BITS: i32 = 192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf3258RegistrationPoint {
    pub x_q8: u16,
    pub y_q8: u16,
    /// Exact FeaturePoint60 bytes +0x10..+0x27 used by FUN_001b0cb0.
    pub descriptor_192: [u8; 24],
}

impl Gf3258RegistrationPoint {
    pub fn from_feature_components(
        core: &Gf3258FeaturePointCore,
        compact: &Gf3258CompactDescriptor,
    ) -> Self {
        let bytes = compact.feature_point_bytes_10_2f();
        let mut descriptor_192 = [0u8; 24];
        descriptor_192.copy_from_slice(&bytes[..24]);
        Self {
            x_q8: core.x_q8,
            y_q8: core.y_q8,
            descriptor_192,
        }
    }

    /// Parse the fields consumed by registration directly from one raw
    /// 60-byte vendor FeaturePoint record. This is retained under tests until
    /// semantic template reload makes raw FeaturePoint decoding production-reachable.
    #[cfg(test)]
    pub fn from_feature_point60_bytes(raw: &[u8]) -> Option<Self> {
        if raw.len() != 0x3c {
            return None;
        }
        let mut descriptor_192 = [0u8; 24];
        descriptor_192.copy_from_slice(&raw[0x10..0x28]);
        Some(Self {
            x_q8: u16::from_le_bytes([raw[0x02], raw[0x03]]),
            y_q8: u16::from_le_bytes([raw[0x04], raw[0x05]]),
            descriptor_192,
        })
    }

    #[inline]
    pub fn coordinate_q8(self) -> Gf3258PointQ8 {
        Gf3258PointQ8 {
            x: i32::from(self.x_q8),
            y: i32::from(self.y_q8),
        }
    }
}

#[cfg(test)]
pub fn gf3258_registration_points_from_feature_point60_records(
    raw: &[u8],
) -> Option<Vec<Gf3258RegistrationPoint>> {
    if raw.len() % 0x3c != 0 {
        return None;
    }
    raw.chunks_exact(0x3c)
        .map(Gf3258RegistrationPoint::from_feature_point60_bytes)
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf3258Correspondence {
    pub source_index: usize,
    pub destination_index: usize,
    pub best_score: i32,
    pub second_score: i32,
}

/// Exact byte-popcount/Hamming primitive used by FUN_001af9c0.
#[inline]
pub fn gf3258_hamming_distance(a: &[u8], b: &[u8]) -> i32 {
    assert_eq!(a.len(), b.len());
    a.iter()
        .zip(b)
        .map(|(&x, &y)| (x ^ y).count_ones() as i32)
        .sum()
}

/// GF3258 FUN_001b0cb0 + FUN_001ae220 correspondence selection.
///
/// Each source point chooses its best and second-best destination descriptor.
/// The vendor keeps only pairs satisfying the strict 0.95 ratio test,
/// suppresses destination coordinates within <= 0xffff Q8 squared distance,
/// and caps the result at 31 pairs by retaining lower Hamming scores.
pub fn gf3258_initial_correspondences(
    source: &[Gf3258RegistrationPoint],
    destination: &[Gf3258RegistrationPoint],
) -> Vec<Gf3258Correspondence> {
    let mut accepted: Vec<Gf3258Correspondence> = Vec::new();

    for (source_index, source_point) in source.iter().enumerate() {
        let mut best_score = GF3258_DESCRIPTOR_BITS;
        let mut second_score = GF3258_DESCRIPTOR_BITS;
        let mut best_index: Option<usize> = None;

        for (destination_index, destination_point) in destination.iter().enumerate() {
            let score = gf3258_hamming_distance(
                &source_point.descriptor_192,
                &destination_point.descriptor_192,
            );

            if score < best_score {
                second_score = best_score;
                best_score = score;
                best_index = Some(destination_index);
            } else if score < second_score {
                second_score = score;
            }
        }

        let Some(destination_index) = best_index else {
            continue;
        };

        // Vendor: 40*best < 38*second. Strict.
        if best_score.wrapping_mul(40) >= second_score.wrapping_mul(38) {
            continue;
        }

        let new_pair = Gf3258Correspondence {
            source_index,
            destination_index,
            best_score,
            second_score,
        };
        let new_destination = destination[destination_index];

        // Collision suppression is based only on destination x/y Q8.
        let collision = accepted.iter().position(|existing| {
            let old_destination = destination[existing.destination_index];
            let dx = i32::from(new_destination.x_q8) - i32::from(old_destination.x_q8);
            let dy = i32::from(new_destination.y_q8) - i32::from(old_destination.y_q8);
            dx.wrapping_mul(dx).wrapping_add(dy.wrapping_mul(dy)) <= 0xffff
        });

        if let Some(slot) = collision {
            if best_score < accepted[slot].best_score {
                accepted[slot] = new_pair;
            }
            continue;
        }

        if accepted.len() < GF3258_MAX_INITIAL_CORRESPONDENCES {
            accepted.push(new_pair);
            continue;
        }

        let (worst_slot, worst_score) = accepted
            .iter()
            .enumerate()
            .max_by_key(|(_, pair)| pair.best_score)
            .map(|(index, pair)| (index, pair.best_score))
            .expect("31-element correspondence list is nonempty");

        if best_score < worst_score {
            accepted[worst_slot] = new_pair;
        }
    }

    accepted
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gf3258GeometryVerification {
    pub transform: Gf3258AffineQ8,
    pub inlier_mask: Vec<u8>,
    pub inlier_count: usize,
    pub cost: i32,
}

/// FUN_001aea40 geometric verification.
pub fn gf3258_verify_geometry(
    source: &[Gf3258PointQ8],
    destination: &[Gf3258PointQ8],
) -> Gf3258GeometryVerification {
    assert_eq!(source.len(), destination.len());
    assert!(source.len() <= GF3258_GEOMETRY_MASK_CAPACITY);

    let count = source.len();
    let mut best = Gf3258GeometryVerification {
        transform: Gf3258AffineQ8::IDENTITY,
        inlier_mask: vec![0u8; count],
        inlier_count: 0,
        cost: GF3258_GEOMETRY_INITIAL_COST,
    };

    if count < 3 {
        return best;
    }

    'triples: for i in 0..count - 2 {
        for j in i + 1..count - 1 {
            for k in j + 1..count {
                let transform = gf3258_affine_from_three_points(
                    [source[i], source[j], source[k]],
                    [destination[i], destination[j], destination[k]],
                );
                if !gf3258_affine_linear_part_is_valid(transform) {
                    continue;
                }

                let mut mask = vec![0u8; count];
                let mut inliers = 0usize;
                let mut squared_error_sum = 0i32;

                for index in 0..count {
                    let predicted = transform.transform_q8(source[index]);
                    let dx = predicted.x.wrapping_sub(destination[index].x);
                    let dy = predicted.y.wrapping_sub(destination[index].y);
                    let abs_dx = wrapping_abs_i32(dx);
                    let abs_dy = wrapping_abs_i32(dy);
                    if abs_dx >= GF3258_GEOMETRY_AXIS_LIMIT_Q8
                        || abs_dy >= GF3258_GEOMETRY_AXIS_LIMIT_Q8
                    {
                        continue;
                    }
                    let radius_sq = dx.wrapping_mul(dx).wrapping_add(dy.wrapping_mul(dy));
                    if radius_sq >= GF3258_GEOMETRY_RADIUS_SQ_Q16 {
                        continue;
                    }
                    mask[index] = 1;
                    inliers += 1;
                    squared_error_sum = squared_error_sum.wrapping_add(radius_sq);
                }

                if inliers == 0 {
                    continue;
                }
                let cost = (squared_error_sum.wrapping_add((inliers >> 1) as i32)) / inliers as i32;

                if inliers > best.inlier_count || (inliers == best.inlier_count && cost < best.cost)
                {
                    best = Gf3258GeometryVerification {
                        transform,
                        inlier_mask: mask,
                        inlier_count: inliers,
                        cost,
                    };
                    if best.inlier_count > 20 {
                        break 'triples;
                    }
                }
            }
        }
    }

    best
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gf3258PointSetRegistration {
    pub correspondences: Vec<Gf3258Correspondence>,
    pub geometry: Gf3258GeometryVerification,
}

/// Descriptor correspondence + geometric verification portion of ba520.
///
/// The argument order is intentionally `previous, current` because it mirrors
/// the vendor call to FUN_001b0cb0: descriptor nearest-neighbor matching runs
/// from the stored/previous Feature to the current Feature and therefore emits
/// pairs `[previous_index, current_index]`.  ba520 then reverses the coordinate
/// sides when calling FUN_001aea40, estimating the affine `current -> previous`.
///
/// A caller still needs the a9a50 map metrics before applying the final
/// acceptance thresholds for 6..10 geometric inliers.
pub fn gf3258_register_point_sets(
    previous: &[Gf3258RegistrationPoint],
    current: &[Gf3258RegistrationPoint],
) -> Option<Gf3258PointSetRegistration> {
    // FUN_001b0cb0(previous, current): correspondence indices are
    // [previous_index, current_index].
    let correspondences = gf3258_initial_correspondences(previous, current);
    if correspondences.len() < 5 {
        return None;
    }

    // ba520 deliberately builds the geometry arrays in the opposite order:
    // source = current coordinates, destination = previous coordinates.
    // Therefore FUN_001aea40 returns current -> previous.
    let current_coordinates: Vec<_> = correspondences
        .iter()
        .map(|pair| current[pair.destination_index].coordinate_q8())
        .collect();
    let previous_coordinates: Vec<_> = correspondences
        .iter()
        .map(|pair| previous[pair.source_index].coordinate_q8())
        .collect();
    let geometry = gf3258_verify_geometry(&current_coordinates, &previous_coordinates);
    Some(Gf3258PointSetRegistration {
        correspondences,
        geometry,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn point(x: i32, y: i32) -> Gf3258PointQ8 {
        Gf3258PointQ8 { x, y }
    }

    #[test]
    fn feature_point60_parser_preserves_registration_prefix() {
        let mut raw = [0u8; 0x3c];
        raw[0x02..0x04].copy_from_slice(&0x1234u16.to_le_bytes());
        raw[0x04..0x06].copy_from_slice(&0x5678u16.to_le_bytes());
        for (index, byte) in raw[0x10..0x28].iter_mut().enumerate() {
            *byte = index as u8;
        }

        let parsed = gf3258_registration_points_from_feature_point60_records(&raw).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].x_q8, 0x1234);
        assert_eq!(parsed[0].y_q8, 0x5678);
        assert_eq!(&parsed[0].descriptor_192[..], &raw[0x10..0x28]);
    }

    #[test]
    fn hamming_is_exact_popcount() {
        assert_eq!(gf3258_hamming_distance(&[0x00, 0xff], &[0xff, 0x0f]), 12);
    }

    #[test]
    fn geometry_identity_finds_all_inliers() {
        let src = vec![
            point(0x100, 0x100),
            point(0x500, 0x100),
            point(0x100, 0x500),
            point(0x500, 0x500),
            point(0x300, 0x200),
            point(0x200, 0x300),
        ];
        let result = gf3258_verify_geometry(&src, &src);
        assert_eq!(result.inlier_count, src.len());
        assert_eq!(result.cost, 0);
        assert_eq!(result.transform, Gf3258AffineQ8::IDENTITY);
    }

    #[test]
    fn point_set_registration_matches_previous_to_current_but_estimates_current_to_previous() {
        fn registration_point(index: usize, x_q8: u16, y_q8: u16) -> Gf3258RegistrationPoint {
            let mut descriptor = [0u8; 24];
            if index != 0 {
                descriptor[index - 1] = 0xff;
            }
            Gf3258RegistrationPoint {
                x_q8,
                y_q8,
                descriptor_192: descriptor,
            }
        }

        let previous = vec![
            registration_point(0, 10 << 8, 10 << 8),
            registration_point(1, 20 << 8, 10 << 8),
            registration_point(2, 10 << 8, 20 << 8),
            registration_point(3, 20 << 8, 20 << 8),
            registration_point(4, 15 << 8, 25 << 8),
        ];
        let current: Vec<_> = previous
            .iter()
            .enumerate()
            .map(|(index, p)| {
                registration_point(
                    index,
                    p.x_q8.wrapping_add(2 << 8),
                    p.y_q8.wrapping_add(1 << 8),
                )
            })
            .collect();

        let registration = gf3258_register_point_sets(&previous, &current).unwrap();
        assert_eq!(registration.correspondences.len(), 5);
        for (index, pair) in registration.correspondences.iter().enumerate() {
            assert_eq!(pair.source_index, index);
            assert_eq!(pair.destination_index, index);
        }
        assert_eq!(registration.geometry.inlier_count, 5);
        assert_eq!(
            registration.geometry.transform,
            Gf3258AffineQ8 {
                a: 0x100,
                b: 0,
                tx: -(2 << 8),
                c: 0,
                d: 0x100,
                ty: -(1 << 8),
            }
        );
    }
}
