//! GF3258 registration-map generation, warping, and evidence scoring.
//!
//! This module owns the recovered 40x32 map mechanics used by enrollment
//! registration. Final acceptance policy, overlap/novel-coverage policy, and
//! pair-relation state remain outside this module.

use crate::feature::{GF3258_HEIGHT, GF3258_WIDTH};

use super::affine::Gf3258AffineQ8;
use super::{
    GF3258_QUARTER_VALIDITY_CELLS, GF3258_QUARTER_VALIDITY_HEIGHT, GF3258_QUARTER_VALIDITY_WIDTH,
    GF3258_REGISTRATION_HEIGHT, GF3258_REGISTRATION_PACKED_BYTES, GF3258_REGISTRATION_PIXELS,
    GF3258_REGISTRATION_WIDTH,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Gf3258BinaryJointCounts {
    pub c00: i32,
    pub c10: i32,
    pub c01: i32,
    pub c11: i32,
}

impl Gf3258BinaryJointCounts {
    #[inline]
    pub fn jointly_valid(self) -> i32 {
        self.c00 + self.c10 + self.c01 + self.c11
    }
}

/// First registration metric returned by FUN_001a9580.
pub fn gf3258_registration_metric_a(counts: Gf3258BinaryJointCounts) -> i32 {
    let s = counts.c00 + counts.c10 + counts.c01;
    let total = s + counts.c11;
    let base = if s > 0 {
        ((s >> 1) + counts.c00 * 256) / (s + 1)
    } else {
        0
    };
    let q11 = ((total >> 1) + counts.c11 * 256) / (total + 1);
    if q11 < 15 {
        base - ((15 - q11) >> 1) - 3
    } else {
        base
    }
}

/// Second registration metric returned by FUN_001a9580.
pub fn gf3258_registration_metric_b(k: i32, width: i32, height: i32) -> i32 {
    let n = width * height;
    assert!(n > 0);
    (k * 256 + (n >> 1)) / n
}

pub const GF3258_REGISTRATION_WARP_BORDER: usize = 4;
pub const GF3258_REGISTRATION_WARP_FILL: u8 = 0xff;

/// Unpack a76d0/a7f90 row-major LSB-first bits into the byte-per-cell form
/// consumed by a8110/a8ae0/a92f0.
pub fn gf3258_unpack_registration_bits(
    packed: &[u8; GF3258_REGISTRATION_PACKED_BYTES],
) -> [u8; GF3258_REGISTRATION_PIXELS] {
    let mut out = [0u8; GF3258_REGISTRATION_PIXELS];
    for index in 0..GF3258_REGISTRATION_PIXELS {
        out[index] = (packed[index >> 3] >> (index & 7)) & 1;
    }
    out
}

/// a9a50's GF3258 half-resolution transform conversion.  The linear Q8 part
/// is preserved; only Q8 translations use C signed `(t + 1) / 2` semantics.
pub fn gf3258_affine_for_registration_scoring(full_resolution: Gf3258AffineQ8) -> Gf3258AffineQ8 {
    Gf3258AffineQ8 {
        tx: full_resolution.tx.wrapping_add(1) / 2,
        ty: full_resolution.ty.wrapping_add(1) / 2,
        ..full_resolution
    }
}

/// FUN_001a9580 return-score formula for GF3258's param_2 == 0 path.
/// Score constants are [3, 2, 3], installed by FUN_001a9a50 when half-
/// resolution registration is active.
pub fn gf3258_registration_graph_score(counts: Gf3258BinaryJointCounts) -> i32 {
    let total = counts.jointly_valid();
    if total == 0 {
        return 0x80;
    }

    let half_canvas = (GF3258_REGISTRATION_PIXELS as i32) >> 1;
    let numerator = (total >> 1).wrapping_add(counts.c00.wrapping_mul(0x100));
    let score = if half_canvas < total {
        numerator / total + 0x26 + 3
    } else {
        numerator / (total + 1) + 0x13 + (total * 0x13) / half_canvas + 2
    };

    let q11 = ((total >> 1).wrapping_add(counts.c11.wrapping_mul(0x100))) / total + 3;
    if q11 > 0x17 || (score > 0xe6 && q11 > 0x10) {
        score
    } else {
        0x80
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf3258RegistrationMapPass {
    pub counts: Gf3258BinaryJointCounts,
    /// a92f0 participating cells.  On the recovered binary GF3258 path this is
    /// the sum of the four C00/C10/C01/C11 counters.
    pub participating_count: i32,
    /// FUN_001a9580's score output (param_3), consumed as a9a50's return score.
    pub score: i32,
    /// FUN_001a9580 param_5, ba520 metric A.
    pub metric_a: i32,
    /// FUN_001a9580 param_4, ba520 metric B.
    pub metric_b: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf3258RegistrationMapScores {
    /// Final FUN_001a9a50 return score.  The optional +0x10 secondary pass may
    /// replace only this field when secondary A > 195 and its score is larger.
    pub score: i32,
    /// Primary +0x08-map metric A; GF3258 param_2 == 0 prevents replacement by
    /// the optional secondary map pass.
    pub metric_a: i32,
    /// Primary +0x08-map metric B.
    pub metric_b: i32,
    pub primary: Gf3258RegistrationMapPass,
    pub secondary: Option<Gf3258RegistrationMapPass>,
}

impl Gf3258RegistrationMapScores {
    pub const FAILURE: Self = Self {
        score: 0,
        metric_a: 0,
        metric_b: 0,
        primary: Gf3258RegistrationMapPass {
            counts: Gf3258BinaryJointCounts {
                c00: 0,
                c10: 0,
                c01: 0,
                c11: 0,
            },
            participating_count: 0,
            score: 0,
            metric_a: 0,
            metric_b: 0,
        },
        secondary: None,
    };
}

/// Exact GF3258 a9580 map pass after a9a50 has selected one source/target map
/// pair.  a8ae0 uses the full 40x32 source rectangle for ROI construction,
/// initializes warped rasters to 0xff, and passes border=4 only to c5b30.
fn gf3258_score_registration_map_pass(
    source_packed: &[u8; GF3258_REGISTRATION_PACKED_BYTES],
    target_packed: &[u8; GF3258_REGISTRATION_PACKED_BYTES],
    source_packed_validity: &[u8; GF3258_REGISTRATION_PACKED_BYTES],
    target_packed_validity: &[u8; GF3258_REGISTRATION_PACKED_BYTES],
    active_transform_source_to_target: Gf3258AffineQ8,
) -> Option<Gf3258RegistrationMapPass> {
    let source = gf3258_unpack_registration_bits(source_packed);
    let target = gf3258_unpack_registration_bits(target_packed);
    let source_validity = gf3258_unpack_registration_bits(source_packed_validity);
    let target_validity = gf3258_unpack_registration_bits(target_packed_validity);

    let warped = gf3258_warp_u8_to_canvas_roi(
        &source,
        GF3258_REGISTRATION_WIDTH,
        GF3258_REGISTRATION_HEIGHT,
        GF3258_REGISTRATION_WIDTH,
        GF3258_REGISTRATION_HEIGHT,
        active_transform_source_to_target,
        GF3258_REGISTRATION_WARP_BORDER,
        GF3258_REGISTRATION_WARP_FILL,
    )?;
    let warped_validity = gf3258_warp_u8_to_canvas_roi(
        &source_validity,
        GF3258_REGISTRATION_WIDTH,
        GF3258_REGISTRATION_HEIGHT,
        GF3258_REGISTRATION_WIDTH,
        GF3258_REGISTRATION_HEIGHT,
        active_transform_source_to_target,
        GF3258_REGISTRATION_WARP_BORDER,
        GF3258_REGISTRATION_WARP_FILL,
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
    let participating_count = counts.jointly_valid();
    Some(Gf3258RegistrationMapPass {
        counts,
        participating_count,
        score: gf3258_registration_graph_score(counts),
        metric_a: gf3258_registration_metric_a(counts),
        metric_b: gf3258_registration_metric_b(
            participating_count,
            GF3258_REGISTRATION_WIDTH as i32,
            GF3258_REGISTRATION_HEIGHT as i32,
        ),
    })
}

/// GF3258 FUN_001a9a50 scoring path used by ba520 and b9340.
///
/// `source_to_target_full_resolution` is the Feature-point affine (for ba520,
/// current -> previous).  a9a50 converts its translations to the active 40x32
/// coordinate system before either a9580 pass.
pub fn gf3258_registration_map_scores(
    source_primary: &[u8; GF3258_REGISTRATION_PACKED_BYTES],
    target_primary: &[u8; GF3258_REGISTRATION_PACKED_BYTES],
    source_validity: &[u8; GF3258_REGISTRATION_PACKED_BYTES],
    target_validity: &[u8; GF3258_REGISTRATION_PACKED_BYTES],
    source_secondary: Option<&[u8; GF3258_REGISTRATION_PACKED_BYTES]>,
    target_secondary: Option<&[u8; GF3258_REGISTRATION_PACKED_BYTES]>,
    source_to_target_full_resolution: Gf3258AffineQ8,
) -> Gf3258RegistrationMapScores {
    let active_transform = gf3258_affine_for_registration_scoring(source_to_target_full_resolution);
    let Some(primary) = gf3258_score_registration_map_pass(
        source_primary,
        target_primary,
        source_validity,
        target_validity,
        active_transform,
    ) else {
        // a9a50 clears its primary score and does not enter the secondary pass
        // when the first a9580 fails to produce a warped ROI.
        return Gf3258RegistrationMapScores::FAILURE;
    };

    let secondary = match (source_secondary, target_secondary) {
        (Some(source), Some(target)) => gf3258_score_registration_map_pass(
            source,
            target,
            source_validity,
            target_validity,
            active_transform,
        ),
        _ => None,
    };

    let mut score = primary.score;
    if let Some(secondary_pass) = secondary {
        if score < secondary_pass.score && secondary_pass.metric_a > 0xc3 {
            score = secondary_pass.score;
        }
    }

    Gf3258RegistrationMapScores {
        score,
        metric_a: primary.metric_a,
        metric_b: primary.metric_b,
        primary,
        secondary,
    }
}

pub const GF3258_REGISTRATION_PRIMARY_THRESHOLD: u8 = 200;
pub const GF3258_REGISTRATION_LOW_THRESHOLD: u8 = 55;
pub const GF3258_A6C30_MODE0_COEFFICIENT: u32 = 0xcd;

/// GF3258 fixed-threshold registration map from FUN_001a7a60/FUN_001a76d0.
/// The 80x64 source is even/even decimated to 40x32 and the predicate is
/// strictly `pixel > threshold`.
pub fn gf3258_fixed_threshold_registration_map(
    image: &[u8],
    threshold: u8,
) -> [u8; GF3258_REGISTRATION_PACKED_BYTES] {
    assert_eq!(image.len(), GF3258_WIDTH * GF3258_HEIGHT);
    let mut packed = [0u8; GF3258_REGISTRATION_PACKED_BYTES];
    let mut out_index = 0usize;
    for y in 0..GF3258_REGISTRATION_HEIGHT {
        for x in 0..GF3258_REGISTRATION_WIDTH {
            let pixel = image[(y * 2) * GF3258_WIDTH + x * 2];
            if pixel > threshold {
                packed[out_index >> 3] |= 1u8 << (out_index & 7);
            }
            out_index += 1;
        }
    }
    packed
}

/// Feature+0x08 / tag 0xb2: local_2b0 even/even, strict >200.
pub fn gf3258_primary_registration_map(image: &[u8]) -> [u8; GF3258_REGISTRATION_PACKED_BYTES] {
    gf3258_fixed_threshold_registration_map(image, GF3258_REGISTRATION_PRIMARY_THRESHOLD)
}

/// Feature+0x18 / tag 0xcd: local_2b0 even/even, strict >55.
pub fn gf3258_low_threshold_registration_map(
    image: &[u8],
) -> [u8; GF3258_REGISTRATION_PACKED_BYTES] {
    gf3258_fixed_threshold_registration_map(image, GF3258_REGISTRATION_LOW_THRESHOLD)
}

/// Exact GF3258 FUN_001a6c30 mode-0 histogram quantile used for Feature+0x10.
/// `source` is local_290 and `support` is bd720 local_298, both 80x64. Only
/// even/even support-selected pixels participate in the histogram.
// Histogram bins are the recovered intensity domain; keep the explicit 0..255 scan.
#[allow(clippy::needless_range_loop)]
pub fn gf3258_a6c30_mode0_threshold(source: &[u8], support: &[u8]) -> u8 {
    assert_eq!(source.len(), GF3258_WIDTH * GF3258_HEIGHT);
    assert_eq!(support.len(), GF3258_WIDTH * GF3258_HEIGHT);

    let mut histogram = [0u32; 256];
    let mut valid_count = 0u32;
    for y in 0..GF3258_REGISTRATION_HEIGHT {
        for x in 0..GF3258_REGISTRATION_WIDTH {
            let index = (y * 2) * GF3258_WIDTH + x * 2;
            if support[index] != 0 {
                histogram[source[index] as usize] += 1;
                valid_count += 1;
            }
        }
    }

    // The normal GF3258 enrollment path has foreground support. Keep the empty
    // case deterministic without inventing a nonzero threshold.
    if valid_count == 0 {
        return 0;
    }

    let target = (GF3258_A6C30_MODE0_COEFFICIENT * valid_count + 128) >> 8;
    let mut cumulative = 0u32;
    for intensity in 0..256usize {
        let before = cumulative;
        cumulative += histogram[intensity];
        if cumulative >= target {
            if intensity == 0 {
                return 0;
            }

            // a6c30 chooses the nearer cumulative boundary around the target.
            // Exact ties select the upper intensity.
            let distance_to_lower = target.saturating_sub(before);
            let distance_to_upper = cumulative.saturating_sub(target);
            return if distance_to_lower < distance_to_upper {
                (intensity - 1) as u8
            } else {
                intensity as u8
            };
        }
    }

    255
}

/// Feature+0x10 / tag 0xcf for the normal GF3258 path.
/// Source is local_290, support is bd720 local_298, and the final predicate is
/// strict `source > dynamic_threshold` on the even/even 40x32 grid.
pub fn gf3258_secondary_registration_map(
    gradient_source: &[u8],
    bd720_support: &[u8],
) -> [u8; GF3258_REGISTRATION_PACKED_BYTES] {
    let threshold = gf3258_a6c30_mode0_threshold(gradient_source, bd720_support);
    gf3258_fixed_threshold_registration_map(gradient_source, threshold)
}

/// FUN_001a7eb0: pack the logical 20x16 Feature+0x28 validity cells as one
/// flat row-major bitstream, LSB-first, with no per-row byte padding.
pub fn gf3258_pack_quarter_validity(
    quarter: &[u8; GF3258_QUARTER_VALIDITY_CELLS],
) -> [u8; GF3258_QUARTER_VALIDITY_CELLS / 8] {
    let mut out = [0u8; GF3258_QUARTER_VALIDITY_CELLS / 8];
    for (index, &value) in quarter.iter().enumerate() {
        out[index >> 3] |= (value & 1) << (index & 7);
    }
    out
}

/// Inverse of [`gf3258_pack_quarter_validity`], matching the LSB-first
/// `Feature+0x28` bitstream consumed by raw `FUN_001a8660`.
pub fn gf3258_unpack_quarter_validity(
    packed: &[u8; GF3258_QUARTER_VALIDITY_CELLS / 8],
) -> [u8; GF3258_QUARTER_VALIDITY_CELLS] {
    let mut out = [0u8; GF3258_QUARTER_VALIDITY_CELLS];
    for index in 0..GF3258_QUARTER_VALIDITY_CELLS {
        out[index] = (packed[index >> 3] >> (index & 7)) & 1;
    }
    out
}

/// Expand an unpacked 20x16 quarter-resolution validity grid to the GF3258
/// 40x32 active-resolution byte grid.  This is the proven a8660(param2=1)
/// geometry and deliberately avoids assuming the still-unneeded +0x28 source
/// serialization order.
pub fn gf3258_expand_quarter_validity(
    quarter: &[u8; GF3258_QUARTER_VALIDITY_CELLS],
) -> [u8; GF3258_REGISTRATION_PIXELS] {
    let mut out = [0u8; GF3258_REGISTRATION_PIXELS];
    for qy in 0..GF3258_QUARTER_VALIDITY_HEIGHT {
        for qx in 0..GF3258_QUARTER_VALIDITY_WIDTH {
            let value = quarter[qy * GF3258_QUARTER_VALIDITY_WIDTH + qx];
            let x = qx * 2;
            let y = qy * 2;
            out[y * GF3258_REGISTRATION_WIDTH + x] = value;
            out[y * GF3258_REGISTRATION_WIDTH + x + 1] = value;
            out[(y + 1) * GF3258_REGISTRATION_WIDTH + x] = value;
            out[(y + 1) * GF3258_REGISTRATION_WIDTH + x + 1] = value;
        }
    }
    out
}

/// FUN_001a7f90 on the GF3258 40x32 binary validity map.
pub fn gf3258_pack_active_validity(
    active: &[u8; GF3258_REGISTRATION_PIXELS],
) -> [u8; GF3258_REGISTRATION_PACKED_BYTES] {
    let mut out = [0u8; GF3258_REGISTRATION_PACKED_BYTES];
    for y in 0..GF3258_REGISTRATION_HEIGHT {
        for byte_x in 0..(GF3258_REGISTRATION_WIDTH / 8) {
            let base = y * GF3258_REGISTRATION_WIDTH + byte_x * 8;
            let mut byte = 0u8;
            for bit in 0..8 {
                byte |= active[base + bit] << bit;
            }
            out[y * (GF3258_REGISTRATION_WIDTH / 8) + byte_x] = byte;
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gf3258WarpedRoi {
    pub x: i32,
    pub y: i32,
    pub width: usize,
    pub height: usize,
    pub data: Vec<u8>,
}

/// FUN_001c5b30 relevant path: inverse affine raster warp.
/// Returns None for the singular case, which is unreachable after b3d50.
// Keep dimensions, transform, border, and fill explicit to match the recovered warp contract.
#[allow(clippy::too_many_arguments)]
pub fn gf3258_inverse_affine_warp_u8(
    source: &[u8],
    source_width: usize,
    source_height: usize,
    destination_width: usize,
    destination_height: usize,
    transform_source_to_destination: Gf3258AffineQ8,
    border: usize,
    fill: u8,
) -> Option<Vec<u8>> {
    assert_eq!(source.len(), source_width * source_height);

    let t = transform_source_to_destination;
    let determinant = t.a.wrapping_mul(t.d).wrapping_sub(t.b.wrapping_mul(t.c));
    if determinant == 0 {
        return None;
    }
    let det64 = i64::from(determinant);

    let inv00 = (i64::from(t.d) << 18) / det64;
    let inv01 = (-i64::from(t.b) * 0x40000) / det64;
    let inv10 = (-i64::from(t.c) * 0x40000) / det64;
    let inv11 = (i64::from(t.a) << 18) / det64;
    let inv_tx =
        ((i64::from(t.b) * i64::from(t.ty) - i64::from(t.d) * i64::from(t.tx)) * 0x400) / det64;
    let inv_ty =
        ((i64::from(t.c) * i64::from(t.tx) - i64::from(t.a) * i64::from(t.ty)) * 0x400) / det64;

    let min_x = border as i32;
    let min_y = border as i32;
    let max_x = source_width as i32 - border as i32 - 1;
    let max_y = source_height as i32 - border as i32 - 1;

    let mut out = vec![fill; destination_width * destination_height];
    for y in 0..destination_height {
        let y64 = y as i64;
        for x in 0..destination_width {
            let x64 = x as i64;
            let sx = inv00 * x64 + inv01 * y64 + inv_tx;
            let sy = inv10 * x64 + inv11 * y64 + inv_ty;
            let x0 = (sx >> 10) as i32;
            let y0 = (sy >> 10) as i32;
            let x1 = x0 + 1;
            let y1 = y0 + 1;
            let fx = sx & 0x3ff;
            let fy = sy & 0x3ff;

            let candidates = [(x0, y0), (x1, y0), (x0, y1), (x1, y1)];
            let mut values = [0u8; 4];
            let mut valid = [false; 4];
            let mut valid_count = 0usize;
            for (index, &(px, py)) in candidates.iter().enumerate() {
                if px >= min_x && px <= max_x && py >= min_y && py <= max_y {
                    values[index] = source[py as usize * source_width + px as usize];
                    valid[index] = true;
                    valid_count += 1;
                }
            }

            let value = match valid_count {
                0 => fill,
                4 => {
                    let wx0 = 1024 - fx;
                    let wy0 = 1024 - fy;
                    let acc = i64::from(values[0]) * wx0 * wy0
                        + i64::from(values[1]) * fx * wy0
                        + i64::from(values[2]) * wx0 * fy
                        + i64::from(values[3]) * fx * fy;
                    ((acc + (1 << 19)) >> 20) as u8
                }
                _ => {
                    let sum: i32 = values
                        .iter()
                        .zip(valid)
                        .filter_map(|(&value, is_valid)| is_valid.then_some(i32::from(value)))
                        .sum();
                    (sum / valid_count as i32) as u8
                }
            };
            out[y * destination_width + x] = value;
        }
    }

    Some(out)
}

/// FUN_001a8ae0 relevant ROI builder around c5b30.
// Keep the recovered source/canvas geometry explicit at this low-level boundary.
#[allow(clippy::too_many_arguments)]
pub fn gf3258_warp_u8_to_canvas_roi(
    source: &[u8],
    source_width: usize,
    source_height: usize,
    canvas_width: usize,
    canvas_height: usize,
    transform_source_to_canvas: Gf3258AffineQ8,
    border: usize,
    fill: u8,
) -> Option<Gf3258WarpedRoi> {
    assert_eq!(source.len(), source_width * source_height);
    if source_width <= border * 2 || source_height <= border * 2 {
        return None;
    }

    // FUN_001a8ae0 computes the destination ROI from the *full* source
    // rectangle.  Its border argument is not applied to these corners; border
    // is passed only to FUN_001c5b30 when sampling the source raster.
    let left = 0i32;
    let right = source_width as i32 - 1;
    let top = 0i32;
    let bottom = source_height as i32 - 1;
    let corners = [(left, top), (right, top), (left, bottom), (right, bottom)];

    let mut xmin = i32::MAX;
    let mut xmax = i32::MIN;
    let mut ymin = i32::MAX;
    let mut ymax = i32::MIN;
    for (x, y) in corners {
        let (tx, ty) = transform_source_to_canvas.transform_integer_pixel(x, y);
        xmin = xmin.min(tx);
        xmax = xmax.max(tx);
        ymin = ymin.min(ty);
        ymax = ymax.max(ty);
    }

    xmin = xmin.max(0);
    ymin = ymin.max(0);
    xmax = xmax.min(canvas_width as i32 - 1);
    ymax = ymax.min(canvas_height as i32 - 1);
    if xmin > xmax || ymin > ymax {
        return None;
    }

    let width = (xmax - xmin + 1) as usize;
    let height = (ymax - ymin + 1) as usize;
    let mut local_transform = transform_source_to_canvas;
    local_transform.tx = local_transform.tx.wrapping_sub(xmin.wrapping_mul(256));
    local_transform.ty = local_transform.ty.wrapping_sub(ymin.wrapping_mul(256));
    let data = gf3258_inverse_affine_warp_u8(
        source,
        source_width,
        source_height,
        width,
        height,
        local_transform,
        border,
        fill,
    )?;

    Some(Gf3258WarpedRoi {
        x: xmin,
        y: ymin,
        width,
        height,
        data,
    })
}

/// Exact a92f0 counter semantics applied to a warped ROI and a full target map.
pub fn gf3258_joint_binary_counts_for_roi(
    warped: &Gf3258WarpedRoi,
    target: &[u8],
    target_width: usize,
    target_height: usize,
    warped_validity: Option<&[u8]>,
    target_validity: Option<&[u8]>,
) -> Gf3258BinaryJointCounts {
    assert_eq!(warped.data.len(), warped.width * warped.height);
    assert_eq!(target.len(), target_width * target_height);
    if let Some(validity) = warped_validity {
        assert_eq!(validity.len(), warped.data.len());
    }
    if let Some(validity) = target_validity {
        assert_eq!(validity.len(), target.len());
    }

    let mut counts = Gf3258BinaryJointCounts::default();
    for ry in 0..warped.height {
        let ty = warped.y + ry as i32;
        if ty < 0 || ty >= target_height as i32 {
            continue;
        }
        for rx in 0..warped.width {
            let tx = warped.x + rx as i32;
            if tx < 0 || tx >= target_width as i32 {
                continue;
            }
            let ri = ry * warped.width + rx;
            let ti = ty as usize * target_width + tx as usize;
            let a = warped.data[ri];
            let b = target[ti];
            if a >= 2 || b >= 2 {
                continue;
            }
            if warped_validity.is_some_and(|v| v[ri] == 0)
                || target_validity.is_some_and(|v| v[ti] == 0)
            {
                continue;
            }
            match (a, b) {
                (0, 0) => counts.c00 += 1,
                (1, 0) => counts.c10 += 1,
                (0, 1) => counts.c01 += 1,
                (1, 1) => counts.c11 += 1,
                _ => unreachable!(),
            }
        }
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_metrics_match_closed_integer_formulas() {
        let counts = Gf3258BinaryJointCounts {
            c00: 900,
            c10: 50,
            c01: 30,
            c11: 100,
        };
        let a = gf3258_registration_metric_a(counts);
        let b = gf3258_registration_metric_b(counts.jointly_valid(), 40, 32);
        assert_eq!(a, ((980 >> 1) + 900 * 256) / 981);
        assert_eq!(b, (1080 * 256 + 640) / 1280);
    }

    #[test]
    fn primary_map_uses_even_coordinates_and_strict_200() {
        let mut image = vec![0u8; GF3258_WIDTH * GF3258_HEIGHT];
        image[0] = 200;
        image[2] = 201;
        image[2 * GF3258_WIDTH] = 255;
        let map = gf3258_primary_registration_map(&image);
        assert_eq!(map[0] & 0b0000_0001, 0);
        assert_ne!(map[0] & 0b0000_0010, 0);
        assert_ne!(map[5] & 0b0000_0001, 0);
    }

    #[test]
    fn active_validity_packing_is_lsb_first() {
        let mut active = [0u8; GF3258_REGISTRATION_PIXELS];
        active[0] = 1;
        active[7] = 1;
        active[8] = 1;
        let packed = gf3258_pack_active_validity(&active);
        assert_eq!(packed[0], 0x81);
        assert_eq!(packed[1], 0x01);
    }

    #[test]
    fn registration_bit_unpack_is_lsb_first() {
        let mut packed = [0u8; GF3258_REGISTRATION_PACKED_BYTES];
        packed[0] = 0x81;
        packed[1] = 0x01;
        let unpacked = gf3258_unpack_registration_bits(&packed);
        assert_eq!(unpacked[0], 1);
        assert_eq!(unpacked[7], 1);
        assert_eq!(unpacked[8], 1);
        assert_eq!(unpacked[1], 0);
    }

    #[test]
    fn half_resolution_scoring_translation_uses_plus_one_signed_division() {
        let positive = gf3258_affine_for_registration_scoring(Gf3258AffineQ8 {
            tx: 0x200,
            ty: 0x100,
            ..Gf3258AffineQ8::IDENTITY
        });
        assert_eq!(positive.tx, 0x100);
        assert_eq!(positive.ty, 0x80);

        let negative = gf3258_affine_for_registration_scoring(Gf3258AffineQ8 {
            tx: -0x200,
            ty: -0x100,
            ..Gf3258AffineQ8::IDENTITY
        });
        // C/Rust signed division truncates toward zero after the vendor's +1.
        assert_eq!(negative.tx, -0xff);
        assert_eq!(negative.ty, -0x7f);
    }

    #[test]
    fn a8ae0_roi_uses_full_rectangle_while_c5b30_uses_border_four() {
        let source = vec![0u8; GF3258_REGISTRATION_PIXELS];
        let warped = gf3258_warp_u8_to_canvas_roi(
            &source,
            GF3258_REGISTRATION_WIDTH,
            GF3258_REGISTRATION_HEIGHT,
            GF3258_REGISTRATION_WIDTH,
            GF3258_REGISTRATION_HEIGHT,
            Gf3258AffineQ8::IDENTITY,
            GF3258_REGISTRATION_WARP_BORDER,
            GF3258_REGISTRATION_WARP_FILL,
        )
        .unwrap();
        assert_eq!((warped.x, warped.y), (0, 0));
        assert_eq!(warped.width, GF3258_REGISTRATION_WIDTH);
        assert_eq!(warped.height, GF3258_REGISTRATION_HEIGHT);
        assert_eq!(warped.data[0], 0xff);
        assert_eq!(warped.data[4 * GF3258_REGISTRATION_WIDTH + 4], 0);
    }

    #[test]
    fn a9580_graph_score_uses_recovered_3_2_3_constants() {
        let counts = Gf3258BinaryJointCounts {
            c00: 505,
            c10: 0,
            c01: 0,
            c11: 263,
        };
        assert_eq!(gf3258_registration_graph_score(counts), 209);
    }

    #[test]
    fn real_map_scorer_identity_zero_maps_produces_primary_a_b_and_score() {
        let map = [0u8; GF3258_REGISTRATION_PACKED_BYTES];
        let validity = [0xffu8; GF3258_REGISTRATION_PACKED_BYTES];
        let scores = gf3258_registration_map_scores(
            &map,
            &map,
            &validity,
            &validity,
            None,
            None,
            Gf3258AffineQ8::IDENTITY,
        );
        assert_eq!(scores.primary.counts.c00, 825);
        assert_eq!(scores.primary.counts.c10, 0);
        assert_eq!(scores.primary.counts.c01, 0);
        assert_eq!(scores.primary.counts.c11, 0);
        assert_eq!(scores.metric_a, 246);
        assert_eq!(scores.metric_b, 165);
        assert_eq!(scores.score, 128);
    }

    #[test]
    fn inverse_warp_identity_matches_vendor_partial_edge_rule() {
        let source: Vec<u8> = (0..16).map(|i| (i & 1) as u8).collect();
        let warped =
            gf3258_inverse_affine_warp_u8(&source, 4, 4, 4, 4, Gf3258AffineQ8::IDENTITY, 0, 0xff)
                .unwrap();

        // c5b30 uses bilinear interpolation only when all four neighbors are
        // inside the source core.  For a partial neighborhood it ignores the
        // fractional weights and returns the plain arithmetic mean of the
        // available neighbors.  Therefore an identity transform is exact in
        // the interior, but the final source row can change when x+1 exists.
        let expected = vec![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1];
        assert_eq!(warped, expected);
    }

    #[test]
    fn persistence_quarter_packing_is_flat_lsb_first_across_rows() {
        let mut quarter = [0u8; GF3258_QUARTER_VALIDITY_CELLS];
        quarter[0] = 1;
        quarter[7] = 1;
        quarter[8] = 1;
        quarter[19] = 1;
        quarter[20] = 1;
        let packed = gf3258_pack_quarter_validity(&quarter);
        assert_eq!(packed[0], 0x81);
        assert_eq!(packed[1] & 0x01, 0x01);
        assert_ne!(packed[19 >> 3] & (1 << (19 & 7)), 0);
        assert_ne!(packed[20 >> 3] & (1 << (20 & 7)), 0);
    }

    #[test]
    fn persistence_quarter_unpack_round_trips_flat_lsb_first_bits() {
        let mut quarter = [0u8; GF3258_QUARTER_VALIDITY_CELLS];
        for (index, value) in quarter.iter_mut().enumerate() {
            *value = ((index * 5 + 3) & 1) as u8;
        }
        let packed = gf3258_pack_quarter_validity(&quarter);
        assert_eq!(gf3258_unpack_quarter_validity(&packed), quarter);
    }

    #[test]
    fn fixed_threshold_maps_use_strict_greater_than() {
        let mut image = vec![0u8; GF3258_WIDTH * GF3258_HEIGHT];
        image[0] = 55;
        image[2] = 56;
        image[4] = 200;
        image[6] = 201;
        let low = gf3258_low_threshold_registration_map(&image);
        let primary = gf3258_primary_registration_map(&image);
        assert_eq!(low[0] & 0x0f, 0b1110);
        assert_eq!(primary[0] & 0x0f, 0b1000);
    }

    #[test]
    fn a6c30_mode0_uses_supported_even_even_histogram_and_upper_tie() {
        let mut source = vec![0u8; GF3258_WIDTH * GF3258_HEIGHT];
        let mut support = vec![0u8; GF3258_WIDTH * GF3258_HEIGHT];
        for x in 0..10usize {
            let index = x * 2;
            source[index] = if x < 6 { 10 } else { 20 };
            support[index] = 1;
        }
        // target=(205*10+128)>>8=8. At bin 20 the lower/upper cumulative
        // distances are both 2, so the recovered exact-tie rule selects upper 20.
        assert_eq!(gf3258_a6c30_mode0_threshold(&source, &support), 20);
    }
}
