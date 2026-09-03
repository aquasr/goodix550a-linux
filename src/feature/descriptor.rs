//! GF3258 oriented local descriptor extraction and compact descriptor encoding.
//!
//! This module contains the recovered `FUN_001bf830` descriptor builder and
//! the GF3258 `FUN_001bdee0` compact descriptor/hash pipeline.

use std::{error::Error, fmt};

use super::orientation::{
    GF3258_PI_Q12, GF3258_TAU_Q12, gaussian_spatial_weight_table, gf3258_cordic_sin_cos_q14,
};
use super::{GF3258_HEIGHT, GF3258_PIXELS, GF3258_WIDTH, RefinedExtremum};

// -----------------------------------------------------------------------------
// GF3258 oriented local descriptor extraction and compact descriptor encoding.
//
// FUN_001bf830 builds the raw 4x4x8 descriptor. The GF3258 path then runs
// FUN_001bdee0 twice:
//   - 128 raw bins -> sqrt/clipped normalization -> c7b80 + c8040
//   - central 32 bins -> independent normalization -> c7f40 + c8040
//
// The resulting 32 bytes correspond exactly to FeaturePoint60 +0x10..+0x2f:
// 16-byte Hadamard sign descriptor, 32-bit median hash, zero reserved dword,
// 32-bit central Hadamard hash, and 32-bit central median hash.
// -----------------------------------------------------------------------------

pub const GF3258_DESCRIPTOR_SPATIAL_CELLS: usize = 4;
pub const GF3258_DESCRIPTOR_ORIENTATION_BINS: usize = 8;
pub const GF3258_DESCRIPTOR_LEN: usize = GF3258_DESCRIPTOR_SPATIAL_CELLS
    * GF3258_DESCRIPTOR_SPATIAL_CELLS
    * GF3258_DESCRIPTOR_ORIENTATION_BINS;
pub const GF3258_DESCRIPTOR_PADDED_CELLS: usize = 6;
pub const GF3258_DESCRIPTOR_PADDED_LEN: usize = GF3258_DESCRIPTOR_PADDED_CELLS
    * GF3258_DESCRIPTOR_PADDED_CELLS
    * GF3258_DESCRIPTOR_ORIENTATION_BINS;
pub const GF3258_DESCRIPTOR_CENTRAL_LEN: usize = 32;
pub const GF3258_DESCRIPTOR_COMPACT_LEN: usize = 32;
pub const GF3258_COMPACT_DESCRIPTOR_REVISION: &str = "gf3258-compact-v1";

// Exact type-0x18 profile values consumed by bf830/bdee0.
// c2d40 initializes param_5[5] to 0x1822e and keeps the generic descriptor
// packing defaults {groups=32,stride=4} for the 128-vector and
// {groups=32,stride=1} for the central 32-vector.
pub const GF3258_DESCRIPTOR_PROFILE_SCALE_Q16: i32 = 0x1822e;
pub const GF3258_DESCRIPTOR_HASH_BITS: usize = 32;
pub const GF3258_DESCRIPTOR_FULL_HASH_STRIDE: usize = 4;
pub const GF3258_DESCRIPTOR_CENTRAL_HASH_STRIDE: usize = 1;

pub const GF3258_DESCRIPTOR_RADIUS_MAX: i32 = 32;
pub const GF3258_DESCRIPTOR_COORD_LIMIT_Q9: i32 = 0x4ff;
pub const GF3258_DESCRIPTOR_COORD_BIAS_Q9: i32 = 0x300;

const GF3258_DESCRIPTOR_RADIUS_MAGIC: i64 = 0x38916;
const GF3258_DESCRIPTOR_ANGLE_MAGIC: i32 = 0x145f3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gf3258DescriptorError {
    UnexpectedMapCount {
        map: &'static str,
        expected: usize,
        actual: usize,
    },
    InvalidScale(i32),
    InvalidOrientation(u16),
}

impl fmt::Display for Gf3258DescriptorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedMapCount {
                map,
                expected,
                actual,
            } => write!(
                f,
                "GF3258 descriptor {map} map has {actual} pixels; expected {expected} (80x64)"
            ),
            Self::InvalidScale(scale) => write!(
                f,
                "GF3258 descriptor requires a positive Q16 scale; got {scale}"
            ),
            Self::InvalidOrientation(angle) => {
                write!(f, "GF3258 ridge orientation {angle} is outside [0, pi) Q12")
            }
        }
    }
}

impl Error for Gf3258DescriptorError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf3258DescriptorWindow {
    pub x_min_offset: i32,
    pub x_max_offset: i32,
    pub y_min_offset: i32,
    pub y_max_offset: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gf3258CompactDescriptor {
    // FUN_001bdee0 normalization state for the full 128-vector.
    pub norm_128: u32,
    pub clip_128: u32,
    pub normalized_128: [u16; GF3258_DESCRIPTOR_LEN],

    // FUN_001c7b80 and the first FUN_001c8040 output.
    // Words are the little-endian dwords stored at FeaturePoint +0x10..+0x1f.
    pub hadamard_128_words: [u32; 4],
    pub median_hash_128: u32,

    // FUN_001bdee0 performs a completely independent normalization for the
    // central 32-vector.
    pub norm_32: u32,
    pub clip_32: u32,
    pub normalized_32: [u16; GF3258_DESCRIPTOR_CENTRAL_LEN],

    // FUN_001c7f40 and the second FUN_001c8040 output.
    pub hadamard_hash_32: u32,
    pub median_hash_32: u32,
}

impl Gf3258CompactDescriptor {
    /// Exact FeaturePoint60 bytes +0x10..+0x2f.
    ///
    /// c7b80 clears +0x10..+0x27 before writing the 128-bit Hadamard result.
    /// c7f40 clears +0x28..+0x37 before writing the 32-bit central result.
    /// Consequently +0x24..+0x27 is zero on the GF3258 path.
    pub fn feature_point_bytes_10_2f(&self) -> [u8; GF3258_DESCRIPTOR_COMPACT_LEN] {
        let mut out = [0u8; GF3258_DESCRIPTOR_COMPACT_LEN];

        for (i, word) in self.hadamard_128_words.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        out[0x10..0x14].copy_from_slice(&self.median_hash_128.to_le_bytes());
        // out[0x14..0x18] is the vendor-cleared reserved dword at point +0x24.
        out[0x18..0x1c].copy_from_slice(&self.hadamard_hash_32.to_le_bytes());
        out[0x1c..0x20].copy_from_slice(&self.median_hash_32.to_le_bytes());

        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gf3258DescriptorResult {
    pub radius: i32,
    pub gaussian_arg: i32,
    pub window: Gf3258DescriptorWindow,

    // FUN_001b8db0 outputs, Q14 where 0x4000 == 1.0.
    pub sin_q14: i32,
    pub cos_q14: i32,

    // bf830's scale-normalized rotation coefficients. A one-pixel x step adds
    // (cos_step_q9, sin_step_q9) to the rotated Q9 sampling coordinate.
    pub cos_step_q9: i32,
    pub sin_step_q9: i32,

    // Exact 6x6x8 padded accumulator and the copied 4x4x8 descriptor.
    pub padded_histogram: [u32; GF3258_DESCRIPTOR_PADDED_LEN],
    pub descriptor_128: [u32; GF3258_DESCRIPTOR_LEN],

    // GF3258's second bdee0 input: central cells (1,1), (1,2), (2,1), (2,2).
    pub central_descriptor_32: [u32; GF3258_DESCRIPTOR_CENTRAL_LEN],

    // Complete GF3258 bdee0 -> c7b80/c7f40/c8040 compact representation.
    pub compact: Gf3258CompactDescriptor,
}

/// Exact GF3258 bf830 raw descriptor construction.
///
/// The caller supplies the already-refined primary candidate, its parity-
/// proven ridge orientation, and the descriptor/profile scale passed by c0910
/// as param_5[5] (uVar6). This scale is distinct from candidate.scale_q16,
/// which is used by the earlier orientation stage. `magnitude_map_i32` and
/// `angle_map_u16` are the same 80x64 derivative planes used by FUN_001be0b0.
pub fn gf3258_primary_descriptor(
    candidate: &RefinedExtremum,
    orientation_q12: u16,
    descriptor_scale_q16: i32,
    magnitude_map_i32: &[i32],
    angle_map_u16: &[u16],
) -> Result<Gf3258DescriptorResult, Gf3258DescriptorError> {
    if magnitude_map_i32.len() != GF3258_PIXELS {
        return Err(Gf3258DescriptorError::UnexpectedMapCount {
            map: "i32 magnitude",
            expected: GF3258_PIXELS,
            actual: magnitude_map_i32.len(),
        });
    }
    if angle_map_u16.len() != GF3258_PIXELS {
        return Err(Gf3258DescriptorError::UnexpectedMapCount {
            map: "u16 angle",
            expected: GF3258_PIXELS,
            actual: angle_map_u16.len(),
        });
    }
    if descriptor_scale_q16 <= 0 {
        return Err(Gf3258DescriptorError::InvalidScale(descriptor_scale_q16));
    }
    if i32::from(orientation_q12) >= GF3258_PI_Q12 {
        return Err(Gf3258DescriptorError::InvalidOrientation(orientation_q12));
    }

    let center_x = candidate.x as i32;
    let center_y = candidate.y as i32;

    // bf830 does NOT consume the per-candidate detector scale. The caller
    // passes param_5[5] (uVar6), a descriptor/profile scale shared by the
    // points in this GF3258 getFeature invocation. bf830 first forms
    // q = 3*descriptor_scale_q16. Radius uses a signed 64-bit multiply by
    // 0x38916 and rounds the Q32 result using bit 31 before capping at 32.
    let scale3_q16 = descriptor_scale_q16.wrapping_mul(3);
    let radius_product = i64::from(scale3_q16) * GF3258_DESCRIPTOR_RADIUS_MAGIC;
    let mut radius =
        ((radius_product >> 32) as i32).wrapping_add(((radius_product >> 31) & 1) as i32);
    radius = radius.min(GF3258_DESCRIPTOR_RADIUS_MAX);

    // b8db0: orientation -> Q14 sine/cosine using the exact 13-step CORDIC.
    let (sin_q14, cos_q14) = gf3258_cordic_sin_cos_q14(orientation_q12);

    // bf830 spatial Gaussian argument: floor(2^45 / (3*scale)^2).
    let scale3_sq = i64::from(scale3_q16) * i64::from(scale3_q16);
    let gaussian_arg = (0x2000_0000_0000i64 / scale3_sq) as i32;

    // Scale-normalized rotation coefficients:
    //   factor = floor(2^36 / (3*scale_q16))
    //   component = (Q14_component * factor) >> 25
    let inverse_scale = (0x10_0000_0000i64 / i64::from(scale3_q16)) as i32;
    let cos_step_q9 = ((i64::from(cos_q14) * i64::from(inverse_scale)) >> 25) as i32;
    let sin_step_q9 = ((i64::from(sin_q14) * i64::from(inverse_scale)) >> 25) as i32;

    let window = Gf3258DescriptorWindow {
        x_min_offset: (-radius).max(1 - center_x),
        x_max_offset: radius.min(GF3258_WIDTH as i32 - center_x - 2),
        y_min_offset: (-radius).max(1 - center_y),
        y_max_offset: radius.min(GF3258_HEIGHT as i32 - center_y - 2),
    };

    let weights = gaussian_spatial_weight_table(radius as usize, gaussian_arg as u32);
    let weight_stride = radius as usize + 1;
    let mut padded_histogram = [0u32; GF3258_DESCRIPTOR_PADDED_LEN];

    if window.x_min_offset <= window.x_max_offset && window.y_min_offset <= window.y_max_offset {
        for dy in window.y_min_offset..=window.y_max_offset {
            let abs_y = dy.unsigned_abs() as usize;

            for dx in window.x_min_offset..=window.x_max_offset {
                // Rotated, scale-normalized local coordinate, Q9.
                let rotated_x_q9 = cos_step_q9
                    .wrapping_mul(dx)
                    .wrapping_sub(sin_step_q9.wrapping_mul(dy));
                let rotated_y_q9 = sin_step_q9
                    .wrapping_mul(dx)
                    .wrapping_add(cos_step_q9.wrapping_mul(dy));

                if wrapping_abs_i32(rotated_x_q9) > GF3258_DESCRIPTOR_COORD_LIMIT_Q9
                    || wrapping_abs_i32(rotated_y_q9) > GF3258_DESCRIPTOR_COORD_LIMIT_Q9
                {
                    continue;
                }

                let px = (center_x + dx) as usize;
                let py = (center_y + dy) as usize;
                let pixel = py * GF3258_WIDTH + px;

                let weight = weights[abs_y * weight_stride + dx.unsigned_abs() as usize];

                // bf830: signed low-32-bit multiply followed by arithmetic >>9.
                // The following interpolation shifts are logical, so retain the
                // resulting i32 bit pattern as u32.
                let weighted_magnitude =
                    (weight as i32).wrapping_mul(magnitude_map_i32[pixel]) >> 9;
                let magnitude = weighted_magnitude as u32;

                // Relative directed gradient angle, normalized to [0, 2*pi).
                let sample_angle_q12 = angle_map_u16[pixel] as i16 as i32;
                let mut relative_q12 = GF3258_PI_Q12
                    .wrapping_sub(sample_angle_q12)
                    .wrapping_sub(i32::from(orientation_q12));
                while relative_q12 < 0 {
                    relative_q12 = relative_q12.wrapping_add(GF3258_TAU_Q12);
                }
                while relative_q12 > GF3258_TAU_Q12 - 1 {
                    relative_q12 = relative_q12.wrapping_sub(GF3258_TAU_Q12);
                }

                // Spatial location in a padded 6x6 grid. The +0x300 Q9 bias is
                // 1.5 cells; accepted coordinates produce base cells -1..3,
                // with interpolation reaching the neighboring padded cell.
                let spatial_x_q9 = rotated_x_q9.wrapping_add(GF3258_DESCRIPTOR_COORD_BIAS_Q9);
                let spatial_y_q9 = rotated_y_q9.wrapping_add(GF3258_DESCRIPTOR_COORD_BIAS_Q9);
                let cell_x = spatial_x_q9 >> 9;
                let cell_y = spatial_y_q9 >> 9;
                let frac_x = (spatial_x_q9 as u32) & 0x1ff;
                let frac_y = (spatial_y_q9 as u32) & 0x1ff;

                let base_cell =
                    ((cell_y + 1) * GF3258_DESCRIPTOR_PADDED_CELLS as i32 + (cell_x + 1)) as usize;
                debug_assert!(
                    base_cell < GF3258_DESCRIPTOR_PADDED_CELLS * GF3258_DESCRIPTOR_PADDED_CELLS
                );

                // Full-circle 8-bin orientation coordinate. The largest legal
                // relative angle keeps this signed product below INT32_MAX.
                let angle_scaled = relative_q12.wrapping_mul(GF3258_DESCRIPTOR_ANGLE_MAGIC);
                let orientation_bin = angle_scaled >> 28;
                let orientation_frac_q12 =
                    (angle_scaled >> 16).wrapping_sub(orientation_bin << 12) as u32;
                let bin0 = (orientation_bin as usize) & 7;
                let bin1 = (bin0 + 1) & 7;

                // Vendor spatial interpolation order, preserving every logical
                // shift/truncation point from bfbc4..bfc29.
                let y1 = magnitude.wrapping_mul(frac_y) >> 9;
                let y0 = magnitude.wrapping_sub(y1);

                let y1_x1 = y1.wrapping_mul(frac_x) >> 9;
                let y1_x0 = y1.wrapping_sub(y1_x1);
                let y0_x1 = y0.wrapping_mul(frac_x) >> 9;
                let y0_x0 = y0.wrapping_sub(y0_x1);

                add_descriptor_vote(
                    &mut padded_histogram,
                    base_cell,
                    bin0,
                    bin1,
                    y0_x0,
                    orientation_frac_q12,
                );
                add_descriptor_vote(
                    &mut padded_histogram,
                    base_cell + 1,
                    bin0,
                    bin1,
                    y0_x1,
                    orientation_frac_q12,
                );
                add_descriptor_vote(
                    &mut padded_histogram,
                    base_cell + GF3258_DESCRIPTOR_PADDED_CELLS,
                    bin0,
                    bin1,
                    y1_x0,
                    orientation_frac_q12,
                );
                add_descriptor_vote(
                    &mut padded_histogram,
                    base_cell + GF3258_DESCRIPTOR_PADDED_CELLS + 1,
                    bin0,
                    bin1,
                    y1_x1,
                    orientation_frac_q12,
                );
            }
        }
    }

    // bf830 copies four 128-byte runs from the padded rows, selecting columns
    // 1..4 and rows 1..4. Result order is 4 rows x 4 cells x 8 bins.
    let mut descriptor_128 = [0u32; GF3258_DESCRIPTOR_LEN];
    let mut out = 0usize;
    for row in 1..=4usize {
        for col in 1..=4usize {
            let cell = row * GF3258_DESCRIPTOR_PADDED_CELLS + col;
            let src = cell * GF3258_DESCRIPTOR_ORIENTATION_BINS;
            descriptor_128[out..out + GF3258_DESCRIPTOR_ORIENTATION_BINS]
                .copy_from_slice(&padded_histogram[src..src + GF3258_DESCRIPTOR_ORIENTATION_BINS]);
            out += GF3258_DESCRIPTOR_ORIENTATION_BINS;
        }
    }
    debug_assert_eq!(out, GF3258_DESCRIPTOR_LEN);

    // GF3258 later gathers the central 2x2 cells for the second bdee0 call.
    let mut central_descriptor_32 = [0u32; GF3258_DESCRIPTOR_CENTRAL_LEN];
    let central_cells = [5usize, 6, 9, 10];
    let mut central_out = 0usize;
    for cell in central_cells {
        let src = cell * GF3258_DESCRIPTOR_ORIENTATION_BINS;
        central_descriptor_32[central_out..central_out + GF3258_DESCRIPTOR_ORIENTATION_BINS]
            .copy_from_slice(&descriptor_128[src..src + GF3258_DESCRIPTOR_ORIENTATION_BINS]);
        central_out += GF3258_DESCRIPTOR_ORIENTATION_BINS;
    }

    let compact = gf3258_compact_descriptor(&descriptor_128, &central_descriptor_32);

    Ok(Gf3258DescriptorResult {
        radius,
        gaussian_arg,
        window,
        sin_q14,
        cos_q14,
        cos_step_q9,
        sin_step_q9,
        padded_histogram,
        descriptor_128,
        central_descriptor_32,
        compact,
    })
}

/// Reproduce the complete GF3258 compact descriptor post-processing performed
/// by the two FUN_001bdee0 calls made by FUN_001bf830.
///
/// This is intentionally GF3258-specific. The type-9/0x12 alternate c7860
/// branch is not part of the 27c6:550a path.
pub fn gf3258_compact_descriptor(
    descriptor_128: &[u32; GF3258_DESCRIPTOR_LEN],
    central_descriptor_32: &[u32; GF3258_DESCRIPTOR_CENTRAL_LEN],
) -> Gf3258CompactDescriptor {
    let (normalized_128, norm_128, clip_128) = bdee0_normalize(descriptor_128);
    let hadamard_128_words = c7b80_hadamard_128(&normalized_128);
    let median_hash_128 = c8040_median_hash_128(&normalized_128);

    let (normalized_32, norm_32, clip_32) = bdee0_normalize(central_descriptor_32);
    let hadamard_hash_32 = c7f40_hadamard_32(&normalized_32);
    let median_hash_32 = c8040_median_hash_32(&normalized_32);

    Gf3258CompactDescriptor {
        norm_128,
        clip_128,
        normalized_128,
        hadamard_128_words,
        median_hash_128,
        norm_32,
        clip_32,
        normalized_32,
        hadamard_hash_32,
        median_hash_32,
    }
}

/// Exact GF3258 FUN_001bdee0 normalization.
///
/// sum_sq is accumulated from unsigned u32 raw bins in 64 bits. b8b40 returns
/// floor(sqrt(sum_sq)). The clipping threshold is then:
///
///     clip = (norm * 0x3333) >> 16
///
/// Every output is floor(sqrt(raw[i])) unless raw[i] >= clip (unsigned), in
/// which case the precomputed floor(sqrt(clip)) is stored. The two bf830 calls
/// invoke this independently for 128 and 32 elements.
fn bdee0_normalize<const N: usize>(raw: &[u32; N]) -> ([u16; N], u32, u32) {
    let mut sum_sq = 0u64;
    for &value in raw {
        let value64 = u64::from(value);
        sum_sq = sum_sq.wrapping_add(value64.wrapping_mul(value64));
    }

    let norm = integer_sqrt_u64(sum_sq);
    let clip = ((u64::from(norm) * 0x3333u64) >> 16) as u32;
    let clipped_sqrt = integer_sqrt_u32(clip) as u16;

    let mut normalized = [0u16; N];
    for (out, &value) in normalized.iter_mut().zip(raw.iter()) {
        *out = if value >= clip {
            clipped_sqrt
        } else {
            integer_sqrt_u32(value) as u16
        };
    }

    (normalized, norm, clip)
}

/// FUN_001b8b40 / FUN_001b8b00 integer-square-root result: floor(sqrt(x)).
///
/// The restoring form avoids floating point and therefore preserves the exact
/// integer boundary behavior used by bdee0.
fn integer_sqrt_u64(mut value: u64) -> u32 {
    let mut result = 0u64;
    let mut bit = 1u64 << 62; // highest power of four representable in u64

    while bit > value {
        bit >>= 2;
    }

    while bit != 0 {
        if value >= result.wrapping_add(bit) {
            value = value.wrapping_sub(result.wrapping_add(bit));
            result = (result >> 1).wrapping_add(bit);
        } else {
            result >>= 1;
        }
        bit >>= 2;
    }

    result as u32
}

fn integer_sqrt_u32(value: u32) -> u32 {
    integer_sqrt_u64(u64::from(value))
}

/// H128 generated by c0910 is the six-times-doubled Sylvester matrix seeded by
/// [[+1,+1],[+1,-1]]. Hence H[row,col] = (-1)^popcount(row & col).
#[inline]
fn sylvester_hadamard_negative(row: usize, col: usize) -> bool {
    ((row & col).count_ones() & 1) != 0
}

/// c7b80 multiplies as 16-bit words, accumulates each 32-element quarter, then
/// sign-extends only the low 16 bits of that quarter before combining quarters.
/// Preserve that intermediate wrap rather than replacing it with a full i32
/// dot product.
// The explicit column index selects the recovered Hadamard sign while preserving quarter order.
#[allow(clippy::needless_range_loop)]
fn c7b80_quarter_sum_i16(
    row: usize,
    start_col: usize,
    values: &[u16; GF3258_DESCRIPTOR_LEN],
) -> i32 {
    let mut sum = 0u32;

    for col in start_col..start_col + 32 {
        let value = values[col];
        let product_low16 = if sylvester_hadamard_negative(row, col) {
            0u16.wrapping_sub(value)
        } else {
            value
        };
        sum = sum.wrapping_add(u32::from(product_low16));
    }

    i32::from(sum as u16 as i16)
}

/// FUN_001c7b80: 128 sign bits from the exact H128 transform layout.
///
/// The outer vendor loop computes four 32-element quarter sums from H row c,
/// c=0..31. Four fixed +/- quarter combinations then correspond to H rows
/// c, c+32, c+64, and c+96. Bit c is set only when the signed result is > 0.
fn c7b80_hadamard_128(values: &[u16; GF3258_DESCRIPTOR_LEN]) -> [u32; 4] {
    const QUARTER_SIGNS: [[i32; 4]; 4] =
        [[1, 1, 1, 1], [1, -1, 1, -1], [1, 1, -1, -1], [1, -1, -1, 1]];

    let mut words = [0u32; 4];

    for bit in 0..32usize {
        let quarters = [
            c7b80_quarter_sum_i16(bit, 0, values),
            c7b80_quarter_sum_i16(bit, 32, values),
            c7b80_quarter_sum_i16(bit, 64, values),
            c7b80_quarter_sum_i16(bit, 96, values),
        ];

        for word_index in 0..4usize {
            let mut total = 0i32;
            for quarter in 0..4usize {
                total = total.wrapping_add(
                    quarters[quarter].wrapping_mul(QUARTER_SIGNS[word_index][quarter]),
                );
            }

            if total > 0 {
                words[word_index] |= 1u32 << bit;
            }
        }
    }

    words
}

/// FUN_001c7f40: central 32-vector sign(H32 * vector).
///
/// Unlike c7b80, this helper sign-extends both the Hadamard coefficient and
/// every normalized word before each 32-bit multiply.
// The explicit column index is part of the recovered Hadamard coefficient lookup.
#[allow(clippy::needless_range_loop)]
fn c7f40_hadamard_32(values: &[u16; GF3258_DESCRIPTOR_CENTRAL_LEN]) -> u32 {
    let mut word = 0u32;

    for row in 0..32usize {
        let mut sum = 0i32;

        for col in 0..32usize {
            let coefficient = if sylvester_hadamard_negative(row, col) {
                -1i32
            } else {
                1i32
            };
            let value = i32::from(values[col] as i16);
            sum = sum.wrapping_add(coefficient.wrapping_mul(value));
        }

        if sum > 0 {
            word |= 1u32 << row;
        }
    }

    word
}

/// c8040 selects sorted[(len-1)>>1], i.e. the lower median for even lengths.
/// Its comparisons are signed 16-bit comparisons, so keep that behavior even
/// though observed GF3258 normalized values are positive and below 0x8000.
fn c8040_lower_median_signed<const N: usize>(values: &[u16; N]) -> u16 {
    let mut sorted = *values;
    sorted.sort_unstable_by_key(|&value| value as i16);
    sorted[(N - 1) >> 1]
}

fn c8040_median_hash_128(values: &[u16; GF3258_DESCRIPTOR_LEN]) -> u32 {
    let median = c8040_lower_median_signed(values);
    let median_signed = median as i16;
    let mut word = 0u32;

    // GF3258 mode0 config: groups=32, stride=4.
    // c8040 uses element 1 + i*stride when stride != 1.
    for bit in 0..GF3258_DESCRIPTOR_HASH_BITS {
        let sample = values[1 + bit * GF3258_DESCRIPTOR_FULL_HASH_STRIDE] as i16;
        if sample > median_signed {
            word |= 1u32 << bit;
        }
    }

    word
}

fn c8040_median_hash_32(values: &[u16; GF3258_DESCRIPTOR_CENTRAL_LEN]) -> u32 {
    let median = c8040_lower_median_signed(values);
    let median_signed = median as i16;
    let mut word = 0u32;

    // GF3258 mode1 config: groups=32, stride=1.
    for bit in 0..GF3258_DESCRIPTOR_HASH_BITS {
        let sample = values[bit * GF3258_DESCRIPTOR_CENTRAL_HASH_STRIDE] as i16;
        if sample > median_signed {
            word |= 1u32 << bit;
        }
    }

    word
}

fn add_descriptor_vote(
    histogram: &mut [u32; GF3258_DESCRIPTOR_PADDED_LEN],
    cell: usize,
    bin0: usize,
    bin1: usize,
    spatial_value: u32,
    orientation_frac_q12: u32,
) {
    debug_assert!(cell < GF3258_DESCRIPTOR_PADDED_CELLS * GF3258_DESCRIPTOR_PADDED_CELLS);
    debug_assert!(bin0 < GF3258_DESCRIPTOR_ORIENTATION_BINS);
    debug_assert!(bin1 < GF3258_DESCRIPTOR_ORIENTATION_BINS);

    let product = spatial_value.wrapping_mul(orientation_frac_q12);
    let bin1_q12 = product >> 12;

    // bf830 intentionally does not collapse these into one rational formula:
    // bin0 is formed after a >>12 truncation and then >>5, while bin1 uses the
    // original low-32-bit product >>17.
    let contribution0 = spatial_value.wrapping_sub(bin1_q12) >> 5;
    let contribution1 = product >> 17;

    let base = cell * GF3258_DESCRIPTOR_ORIENTATION_BINS;
    histogram[base + bin0] = histogram[base + bin0].wrapping_add(contribution0);
    histogram[base + bin1] = histogram[base + bin1].wrapping_add(contribution1);
}

fn wrapping_abs_i32(value: i32) -> i32 {
    let sign = value >> 31;
    (value ^ sign).wrapping_sub(sign)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_sqrt_helpers_are_floor_exact_at_boundaries() {
        assert_eq!(integer_sqrt_u32(0), 0);
        assert_eq!(integer_sqrt_u32(1), 1);
        assert_eq!(integer_sqrt_u32(2), 1);
        assert_eq!(integer_sqrt_u32(15), 3);
        assert_eq!(integer_sqrt_u32(16), 4);
        assert_eq!(integer_sqrt_u32(17), 4);
        assert_eq!(integer_sqrt_u32(u32::MAX), 65_535);
        assert_eq!(integer_sqrt_u64(1u64 << 32), 65_536);
    }

    #[test]
    fn sylvester_seed_and_hadamard_bit_order_are_exact() {
        assert!(!sylvester_hadamard_negative(0, 0));
        assert!(!sylvester_hadamard_negative(0, 1));
        assert!(!sylvester_hadamard_negative(1, 0));
        assert!(sylvester_hadamard_negative(1, 1));

        let full = [1u16; GF3258_DESCRIPTOR_LEN];
        assert_eq!(c7b80_hadamard_128(&full), [1, 0, 0, 0]);

        let central = [1u16; GF3258_DESCRIPTOR_CENTRAL_LEN];
        assert_eq!(c7f40_hadamard_32(&central), 1);
    }

    #[test]
    fn c8040_lower_median_and_gf3258_sampling_are_exact() {
        let mut full = [0u16; GF3258_DESCRIPTOR_LEN];
        for (i, value) in full.iter_mut().enumerate() {
            *value = i as u16;
        }
        assert_eq!(c8040_lower_median_signed(&full), 63);
        assert_eq!(c8040_median_hash_128(&full), 0xffff_0000);

        let mut central = [0u16; GF3258_DESCRIPTOR_CENTRAL_LEN];
        for (i, value) in central.iter_mut().enumerate() {
            *value = i as u16;
        }
        assert_eq!(c8040_lower_median_signed(&central), 15);
        assert_eq!(c8040_median_hash_32(&central), 0xffff_0000);
    }

    #[test]
    fn compact_bytes_follow_feature_point_offsets() {
        let compact = Gf3258CompactDescriptor {
            norm_128: 0,
            clip_128: 0,
            normalized_128: [0; GF3258_DESCRIPTOR_LEN],
            hadamard_128_words: [0x0302_0100, 0x0706_0504, 0x0b0a_0908, 0x0f0e_0d0c],
            median_hash_128: 0x1312_1110,
            norm_32: 0,
            clip_32: 0,
            normalized_32: [0; GF3258_DESCRIPTOR_CENTRAL_LEN],
            hadamard_hash_32: 0x1b1a_1918,
            median_hash_32: 0x1f1e_1d1c,
        };

        assert_eq!(
            compact.feature_point_bytes_10_2f(),
            [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x00, 0x00, 0x00, 0x00, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f,
            ]
        );
    }

    #[test]
    fn descriptor_central_2x2_layout_is_cell_5_6_9_10() {
        let mut descriptor = [0u32; GF3258_DESCRIPTOR_LEN];
        for (i, value) in descriptor.iter_mut().enumerate() {
            *value = i as u32;
        }

        let cells = [5usize, 6, 9, 10];
        let mut central = [0u32; GF3258_DESCRIPTOR_CENTRAL_LEN];
        let mut out = 0usize;
        for cell in cells {
            let src = cell * GF3258_DESCRIPTOR_ORIENTATION_BINS;
            central[out..out + 8].copy_from_slice(&descriptor[src..src + 8]);
            out += 8;
        }

        assert_eq!(central[0], 40);
        assert_eq!(central[7], 47);
        assert_eq!(central[8], 48);
        assert_eq!(central[15], 55);
        assert_eq!(central[16], 72);
        assert_eq!(central[23], 79);
        assert_eq!(central[24], 80);
        assert_eq!(central[31], 87);
    }
}
