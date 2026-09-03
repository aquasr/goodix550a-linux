//! GF3258 point-neighborhood support and status rehabilitation.
//!
//! This module preserves the recovered `FUN_001bdd40` support calculation and
//! the strict post-support status rehabilitation gate from the GF3258 feature
//! pipeline. Arithmetic and threshold semantics intentionally match the vendor
//! implementation.

use std::{error::Error, fmt};

/// Revision marker for the exact GF3258 FUN_001bdd40 implementation.
pub const GF3258_POINT_SUPPORT_REVISION: &str = "gf3258-bdd40-v1";

/// FeaturePoint60 stride used by the vendor point array.
pub const GF3258_FEATURE_POINT_STRIDE: usize = 0x3c;

/// Squared-distance limit used by FUN_001bdd40. A candidate neighbor is used
/// only when 1 <= dx^2 + dy^2 <= 255.
pub const GF3258_SUPPORT_MAX_DISTANCE_SQ: i32 = 0xff;

/// The quality threshold for the 1.5x proximity-weight boost.
pub const GF3258_SUPPORT_QUALITY_BOOST_THRESHOLD: i8 = 0x32;

/// Final support byte is floor(weight_sum / 8), saturated to 100.
pub const GF3258_SUPPORT_MAX: u8 = 100;

/// Exact 256-entry dword table copied by FUN_001bdd40 from DAT_00239de0.
///
/// It is indexed by `255 - distance_squared`, so closer points receive larger
/// weights. The recovered vendor values fit in u8, but the original code loads
/// them as signed/unsigned 32-bit integers from this dword table.
pub const GF3258_SUPPORT_PROXIMITY_TABLE: [i32; 256] = [
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6,
    6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 8, 8, 8, 8, 8, 8, 8, 9, 9, 9, 9, 9, 9, 10, 10, 10, 10,
    10, 10, 11, 11, 11, 11, 11, 12, 12, 12, 12, 12, 12, 13, 13, 13, 13, 13, 14, 14, 14, 14, 14, 15,
    15, 15, 15, 16, 16, 16, 16, 16, 17, 17, 17, 17, 18, 18, 18, 18, 18, 19, 19, 19, 19, 20, 20, 20,
    20, 21, 21, 21, 21, 22, 22, 22, 22, 22, 23, 23, 23, 23, 24, 24, 24, 24, 25, 25, 25, 25, 26, 26,
    26, 26, 27, 27, 27, 27, 28, 28, 28, 28, 28, 29, 29, 29, 29, 30, 30, 30, 30, 31, 31, 31, 31, 31,
    32, 32, 32, 32, 32, 33, 33, 33, 33, 33, 34, 34, 34, 34, 34, 35, 35, 35, 35, 35, 35, 36, 36, 36,
    36, 36, 36, 36, 37, 37, 37, 37, 37, 37, 37, 38, 38, 38, 38, 38, 38, 38, 38, 38, 38, 39, 39, 39,
    39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf3258SupportPoint {
    /// Vendor FeaturePoint60 +0x02, Q8 little-endian coordinate.
    pub x_q8: u16,
    /// Vendor FeaturePoint60 +0x04, Q8 little-endian coordinate.
    pub y_q8: u16,
}

impl Gf3258SupportPoint {
    #[inline]
    pub fn x_integer(self) -> u8 {
        (self.x_q8 >> 8) as u8
    }

    #[inline]
    pub fn y_integer(self) -> u8 {
        (self.y_q8 >> 8) as u8
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gf3258PointSupportResult {
    /// Exact bytes written to FeaturePoint60 +0x39.
    pub neighborhood_support: Vec<u8>,
    /// Exact bytes written through FUN_001bdd40's third argument.
    /// Values are stored as raw bytes because the vendor writes AL directly;
    /// callers later interpret them as signed `char` values.
    pub neighborhood_average: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gf3258PointSupportError {
    CountMismatch {
        what: &'static str,
        expected: usize,
        actual: usize,
    },
}

impl fmt::Display for Gf3258PointSupportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CountMismatch {
                what,
                expected,
                actual,
            } => write!(
                f,
                "GF3258 point-support {what} has {actual} entries; expected {expected}"
            ),
        }
    }
}

impl Error for Gf3258PointSupportError {}

/// Exact GF3258 FUN_001bdd40 point-neighborhood computation.
///
/// `quality_164` corresponds to the signed bytes at `feature + 0x164`.
/// `source_quality` corresponds to the signed bytes passed as bdd40 argument 2
/// (the caller's `local_208`). When `enabled` is false (feature +0x15c == 0),
/// the vendor only clears point +0x39; its third output array is left untouched.
/// This pure result API therefore returns a zeroed average array for disabled
/// mode, matching the actual c2d40 caller which zeroes that array beforehand.
pub fn gf3258_point_support(
    points: &[Gf3258SupportPoint],
    quality_164: &[i8],
    source_quality: &[i8],
    enabled: bool,
) -> Result<Gf3258PointSupportResult, Gf3258PointSupportError> {
    let count = points.len();
    if quality_164.len() != count {
        return Err(Gf3258PointSupportError::CountMismatch {
            what: "feature+0x164 quality",
            expected: count,
            actual: quality_164.len(),
        });
    }
    if source_quality.len() != count {
        return Err(Gf3258PointSupportError::CountMismatch {
            what: "source quality",
            expected: count,
            actual: source_quality.len(),
        });
    }

    let mut support = vec![0u8; count];
    let mut average = vec![0u8; count];

    if !enabled {
        return Ok(Gf3258PointSupportResult {
            neighborhood_support: support,
            neighborhood_average: average,
        });
    }

    for i in 0..count {
        let xi = i32::from(points[i].x_integer());
        let yi = i32::from(points[i].y_integer());

        // Vendor initializes EDX=1 and adds 100 for every accepted neighbor.
        // This intentionally makes the third output slightly smaller than a
        // conventional arithmetic mean.
        let mut denominator: i32 = 1;
        let mut quality_sum: i32 = 0;
        let mut support_sum: i32 = 0;

        for j in 0..count {
            if j == i {
                continue;
            }

            let xj = i32::from(points[j].x_integer());
            let yj = i32::from(points[j].y_integer());
            let dx = xj - xi;
            let dy = yi - yj;
            let distance_sq = dx * dx + dy * dy;

            if distance_sq == 0 || distance_sq > GF3258_SUPPORT_MAX_DISTANCE_SQ {
                continue;
            }

            let proximity_index = (GF3258_SUPPORT_MAX_DISTANCE_SQ - distance_sq) as usize;
            let mut weight = GF3258_SUPPORT_PROXIMITY_TABLE[proximity_index];

            // Assembly computes ((weight * 3) << 2) >> 3. Values are positive,
            // but retain the staged integer operations to preserve truncation.
            if quality_164[j] > GF3258_SUPPORT_QUALITY_BOOST_THRESHOLD {
                weight = (weight.wrapping_mul(3).wrapping_shl(2)) >> 3;
            }

            support_sum = support_sum.wrapping_add(weight);
            quality_sum = quality_sum.wrapping_add(i32::from(source_quality[j]));
            denominator = denominator.wrapping_add(100);
        }

        // The vendor performs signed IDIV after multiplying the sum by 100,
        // then stores AL without saturation.
        let averaged = quality_sum.wrapping_mul(100) / denominator;
        average[i] = averaged as u8;

        let scaled_support = support_sum >> 3;
        support[i] = scaled_support.min(i32::from(GF3258_SUPPORT_MAX)) as u8;
    }

    Ok(Gf3258PointSupportResult {
        neighborhood_support: support,
        neighborhood_average: average,
    })
}

/// Exact c2d40 status-rehabilitation gate immediately following FUN_001bdd40
/// for the feature+0x15c == 1 path.
///
/// Only a nonzero status can be changed, and it becomes zero only when every
/// strict signed-byte threshold is satisfied.
pub fn gf3258_rehabilitate_point_status(
    status: u8,
    quality_164: i8,
    neighborhood_average: i8,
    source_quality: i8,
    neighborhood_support: u8,
) -> u8 {
    if status != 0
        && quality_164 > 30
        && neighborhood_average > 65
        && source_quality > 65
        && neighborhood_support > 35
    {
        0
    } else {
        status
    }
}

/// Apply the c2d40 rehabilitation gate across one point set.
pub fn gf3258_rehabilitate_point_statuses(
    statuses: &[u8],
    quality_164: &[i8],
    neighborhood_average: &[u8],
    source_quality: &[i8],
    neighborhood_support: &[u8],
) -> Result<Vec<u8>, Gf3258PointSupportError> {
    let count = statuses.len();
    for (what, actual) in [
        ("feature+0x164 quality", quality_164.len()),
        ("neighborhood average", neighborhood_average.len()),
        ("source quality", source_quality.len()),
        ("neighborhood support", neighborhood_support.len()),
    ] {
        if actual != count {
            return Err(Gf3258PointSupportError::CountMismatch {
                what,
                expected: count,
                actual,
            });
        }
    }

    Ok((0..count)
        .map(|i| {
            gf3258_rehabilitate_point_status(
                statuses[i],
                quality_164[i],
                neighborhood_average[i] as i8,
                source_quality[i],
                neighborhood_support[i],
            )
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proximity_table_matches_recovered_anchors() {
        assert_eq!(GF3258_SUPPORT_PROXIMITY_TABLE.len(), 256);
        assert_eq!(GF3258_SUPPORT_PROXIMITY_TABLE[0], 1);
        assert_eq!(GF3258_SUPPORT_PROXIMITY_TABLE[12], 2);
        assert_eq!(GF3258_SUPPORT_PROXIMITY_TABLE[128], 17);
        assert_eq!(GF3258_SUPPORT_PROXIMITY_TABLE[254], 39);
        assert_eq!(GF3258_SUPPORT_PROXIMITY_TABLE[255], 39);
    }

    #[test]
    fn support_uses_integer_coordinates_and_biased_average() {
        let points = [
            Gf3258SupportPoint {
                x_q8: 10 << 8,
                y_q8: 10 << 8,
            },
            Gf3258SupportPoint {
                x_q8: 11 << 8,
                y_q8: 10 << 8,
            },
            // Same integer coordinate as point 0: explicitly ignored.
            Gf3258SupportPoint {
                x_q8: (10 << 8) | 0xff,
                y_q8: (10 << 8) | 1,
            },
        ];
        let q164 = [0i8, 51i8, 100i8];
        let source = [100i8, 100i8, 100i8];
        let r = gf3258_point_support(&points, &q164, &source, true).unwrap();

        // point0 sees only point1 at d^2=1: table[254]=39, boosted to 58.
        assert_eq!(r.neighborhood_support[0], 58 >> 3);
        // 100*100/(1+100) = 99, not 100.
        assert_eq!(r.neighborhood_average[0], 99);
    }

    #[test]
    fn status_rehabilitation_uses_strict_thresholds() {
        assert_eq!(gf3258_rehabilitate_point_status(2, 31, 66, 66, 36), 0);
        assert_eq!(gf3258_rehabilitate_point_status(2, 30, 66, 66, 36), 2);
        assert_eq!(gf3258_rehabilitate_point_status(2, 31, 65, 66, 36), 2);
        assert_eq!(gf3258_rehabilitate_point_status(2, 31, 66, 65, 36), 2);
        assert_eq!(gf3258_rehabilitate_point_status(2, 31, 66, 66, 35), 2);
        assert_eq!(gf3258_rehabilitate_point_status(0, 100, 100, 100, 100), 0);
    }
}
