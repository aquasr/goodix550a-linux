//! GF3258 orientation estimation and orientation-dependent gradient preparation.
//!
//! This module contains the recovered integer paths that produce gradient
//! angle/magnitude planes, ridge-direction smoothing, candidate ridge
//! orientation, and the Q12/Q14 CORDIC primitives shared with descriptor and
//! matcher geometry code. Vendor arithmetic and strict comparisons are kept
//! intentionally literal where parity depends on them.

use std::{error::Error, fmt};

use super::filter::separable_q16_reflect101;
use super::{FeatureError, GF3258_HEIGHT, GF3258_PIXELS, GF3258_WIDTH, RefinedExtremum};

// Exact Q16 filter records selected by FUN_001a4840 modes 0 and 1 in
// FUN_001c0910 before the gradient/CORDIC plane producer. Mode 1 is
// applied to the already-filtered mode-0 image, matching the vendor call order.
pub const GF3258_GRADIENT_GAUSS_0: [i32; 9] = [84, 957, 5433, 15399, 21790, 15399, 5433, 957, 84];
pub const GF3258_GRADIENT_GAUSS_1: [i32; 7] = [139, 2672, 15742, 28430, 15742, 2672, 139];

// FUN_001b8b90 lookup tables recovered from DAT_00239b80 / DAT_00239bc0.
// The first table is cumulative inverse CORDIC gain in Q16. The second is
// atan(2^-i) in signed Q12 radians for iterations i=0..12.
pub const GF3258_CORDIC_GAIN_INV_Q16: [i32; 13] = [
    0xb505, 0xa1e9, 0x9d13, 0x9bdd, 0x9b8f, 0x9b7b, 0x9b77, 0x9b75, 0x9b75, 0x9b75, 0x9b75, 0x9b75,
    0x9b75,
];
pub const GF3258_VECTOR_CORDIC_ATAN_Q12: [i16; 13] = [
    0x0c91, 0x076b, 0x03eb, 0x01fd, 0x0100, 0x0080, 0x0040, 0x0020, 0x0010, 0x0008, 0x0004, 0x0002,
    0x0001,
];
pub const GF3258_GRADIENT_MAGNITUDE_MAX: i32 = 0x3ffff;
pub const GF3258_GRADIENT_PLANES_REVISION: &str = "gf3258-gradient-planes-v1";

// -----------------------------------------------------------------------------
// FUN_001c6d90 + FUN_001c7310: c2d40 local_2b8 -> c0910 param_1 producer
// -----------------------------------------------------------------------------

/// Static-recovery revision for the GF3258 local_2b8 -> local_290 path.
pub const GF3258_C7310_REVISION: &str = "gf3258-c7310-v1";

/// c7310's exact seven-tap line weights.
pub const GF3258_C7310_WEIGHTS: [i32; 7] = [1, 2, 4, 8, 4, 2, 1];

/// Exact 12 x 7 integer line offsets from DAT_002742e0.
///
/// Each class is one seven-sample line centered at (0,0). c7310 selects a
/// class from the c6d90 byte field and then averages the in-bounds source
/// samples with GF3258_C7310_WEIGHTS. Out-of-bounds samples are omitted and
/// the surviving weights are renormalized; there is no reflection/clamping.
pub const GF3258_C7310_DIRECTION_OFFSETS: [[(i32, i32); 7]; 12] = [
    [(-3, 0), (-2, 0), (-1, 0), (0, 0), (1, 0), (2, 0), (3, 0)],
    [(-3, -1), (-2, -1), (-1, 0), (0, 0), (1, 0), (2, 1), (3, 1)],
    [(-3, -2), (-2, -1), (-1, -1), (0, 0), (1, 1), (2, 1), (3, 2)],
    [(-3, -3), (-2, -2), (-1, -1), (0, 0), (1, 1), (2, 2), (3, 3)],
    [(-2, -3), (-1, -2), (-1, -1), (0, 0), (1, 1), (1, 2), (2, 3)],
    [(-1, -3), (-1, -2), (0, -1), (0, 0), (0, 1), (1, 2), (1, 3)],
    [(0, -3), (0, -2), (0, -1), (0, 0), (0, 1), (0, 2), (0, 3)],
    [(-1, 3), (-1, 2), (0, 1), (0, 0), (0, -1), (1, -2), (1, -3)],
    [(-2, 3), (-1, 2), (-1, 1), (0, 0), (1, -1), (1, -2), (2, -3)],
    [(-3, 3), (-2, 2), (-1, 1), (0, 0), (1, -1), (2, -2), (3, -3)],
    [(-3, 2), (-2, 1), (-1, 1), (0, 0), (1, -1), (2, -1), (3, -2)],
    [(-3, 1), (-2, 1), (-1, 0), (0, 0), (1, 0), (2, -1), (3, -1)],
];

/// c6d90 uses a clipped 13x13 tensor-integration window (radius six).
pub const GF3258_C6D90_TENSOR_RADIUS: i32 = 6;

/// Integer factor used by c6d90 to convert the normalized b8b90 Q12 angle
/// into half-angle degrees: (angle * 0x1ca6) >> 20.
pub const GF3258_C6D90_HALF_DEGREE_FACTOR: i32 = 0x1ca6;

// -----------------------------------------------------------------------------
// GF3258 live orientation-plane producer
// FUN_001c0910 modes 0/1 + central differences + FUN_001b8b90.
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gf3258GradientPlanes {
    /// 80x64 magnitude plane consumed by FUN_001be0b0 / bf830.
    pub magnitude_map_i32: Vec<i32>,
    /// 80x64 signed-Q12 atan2(dy, dx) values stored in the vendor's u16 plane.
    pub angle_map_u16: Vec<u16>,
}

/// Exact signed-Q12 saturation used by FUN_001c0910 before FUN_001b8b90.
///
/// The source central difference is allowed through in [-0x80000, 0x7ffff]
/// and multiplied by 0x1000. Values outside that interval saturate to the
/// corresponding signed-i32 Q12 endpoint.
#[inline]
pub fn gf3258_gradient_difference_to_q12(diff: i32) -> i32 {
    if diff >= 0x80000 {
        0x7fff_f000
    } else if diff < -0x80000 {
        i32::MIN
    } else {
        diff.wrapping_mul(0x1000)
    }
}

/// Exact FUN_001b8b90 vectoring CORDIC.
///
/// Inputs are signed Q12 gradient components. The returned u16 contains the
/// vendor's signed-i16 Q12 angle bit pattern (atan2(dy, dx)); the second value
/// is the gain-corrected magnitude in the same Q12 scale.
// The numeric iteration index selects both the shift amount and the recovered CORDIC table entry.
#[allow(clippy::needless_range_loop)]
pub fn gf3258_cordic_atan2_magnitude_q12(dy_q12: i32, dx_q12: i32) -> (u16, i32) {
    let original_dy = dy_q12;
    let original_dx = dx_q12;

    // The vendor computes abs with the sign/xor/sub idiom. wrapping_abs keeps
    // its INT_MIN behavior exact.
    let mut y = dy_q12.wrapping_abs();
    let mut x = dx_q12.wrapping_abs();

    // Axis fast paths occur before the CORDIC loop. Note the exact < 1 test:
    // (dy, dx) == (0, 0) returns +pi, not zero.
    if y == 0 {
        let angle = if original_dx < 1 {
            GF3258_PI_Q12 as u16
        } else {
            0
        };
        return (angle, x);
    }
    if x == 0 {
        let half_pi = 0x1922i16;
        let angle = if original_dy < 1 {
            half_pi.wrapping_neg() as u16
        } else {
            half_pi as u16
        };
        return (angle, y);
    }

    let mut theta: i16 = 0;
    let mut last_iteration = 12usize;

    for i in 0..13usize {
        let y_shift = y >> i;
        let x_shift = x >> i;

        let step = if y < 1 {
            // y' = y + (x >> i), x' = x - (y >> i)
            y = y.wrapping_add(x_shift);
            x = x.wrapping_sub(y_shift);
            GF3258_VECTOR_CORDIC_ATAN_Q12[i].wrapping_neg()
        } else {
            // y' = y - (x >> i), x' = x + (y >> i)
            y = y.wrapping_sub(x_shift);
            x = x.wrapping_add(y_shift);
            GF3258_VECTOR_CORDIC_ATAN_Q12[i]
        };

        // Ghidra's uVar2/uVar7 pair truncates to 16 bits after every step.
        theta = theta.wrapping_add(step);

        if y == 0 {
            last_iteration = i;
            break;
        }
    }

    let pi = GF3258_PI_Q12 as i16;
    let final_angle = if original_dx < 1 {
        if original_dy < 1 {
            theta.wrapping_sub(pi)
        } else {
            pi.wrapping_sub(theta)
        }
    } else if original_dy < 0 {
        theta.wrapping_neg()
    } else {
        theta
    };

    let product = i64::from(GF3258_CORDIC_GAIN_INV_Q16[last_iteration]) * i64::from(x) + 0x8000;
    let magnitude_q12 = (product >> 16) as i32;

    (final_angle as u16, magnitude_q12)
}

/// Build the exact 80x64 magnitude/angle planes used by the GF3258 primary
/// orientation and descriptor path from a fresh algorithm-ready u8 image.
///
/// Vendor order in FUN_001c0910:
///   source = image << 8
///   mode0  = filter(source, mode 0)
///   mode1  = filter(mode0, mode 1)
///   work   = mode1 + (mode0 - mode1) * 10
///          = 10*mode0 - 9*mode1
///   dx/dy  = central differences over work
///   angle/magnitude = FUN_001b8b90(dy, dx)
///
/// Both output planes are zero-initialized; only the 1-pixel interior is
/// written, matching the vendor loops.
pub fn gf3258_gradient_planes(image: &[u8]) -> Result<Gf3258GradientPlanes, FeatureError> {
    if image.len() != GF3258_PIXELS {
        return Err(FeatureError::UnexpectedPixelCount {
            expected: GF3258_PIXELS,
            actual: image.len(),
        });
    }

    let source: Vec<u16> = image.iter().map(|&v| u16::from(v) << 8).collect();

    // The second call consumes the first call's output. Do not run both
    // filters independently from `source`.
    let mode0 = separable_q16_reflect101(&source, &GF3258_GRADIENT_GAUSS_0);
    let mode1 = separable_q16_reflect101(&mode0, &GF3258_GRADIENT_GAUSS_1);

    let mut work = vec![0i32; GF3258_PIXELS];
    for i in 0..GF3258_PIXELS {
        work[i] = i32::from(mode1[i]).wrapping_add(
            i32::from(mode0[i])
                .wrapping_sub(i32::from(mode1[i]))
                .wrapping_mul(10),
        );
    }

    let mut magnitude_map_i32 = vec![0i32; GF3258_PIXELS];
    let mut angle_map_u16 = vec![0u16; GF3258_PIXELS];

    for y in 1..(GF3258_HEIGHT - 1) {
        for x in 1..(GF3258_WIDTH - 1) {
            let idx = y * GF3258_WIDTH + x;

            let dx = work[idx + 1].wrapping_sub(work[idx - 1]);
            let dy = work[idx + GF3258_WIDTH].wrapping_sub(work[idx - GF3258_WIDTH]);

            let dx_q12 = gf3258_gradient_difference_to_q12(dx);
            let dy_q12 = gf3258_gradient_difference_to_q12(dy);
            let (angle, magnitude_q12) = gf3258_cordic_atan2_magnitude_q12(dy_q12, dx_q12);

            angle_map_u16[idx] = angle;

            let mut magnitude = magnitude_q12 >> 12;
            if magnitude > GF3258_GRADIENT_MAGNITUDE_MAX {
                magnitude = GF3258_GRADIENT_MAGNITUDE_MAX;
            }
            magnitude_map_i32[idx] = magnitude;
        }
    }

    Ok(Gf3258GradientPlanes {
        magnitude_map_i32,
        angle_map_u16,
    })
}

/// Exact Sobel/tensor byte field produced by FUN_001c6d90 for GF3258.
///
/// The vendor:
///   1. computes 3x3 Sobel gx/gy on the one-pixel interior,
///   2. forms tensor terms 2*gx*gy and gx^2-gy^2,
///   3. builds wrapping i32 integral images of both terms,
///   4. integrates a clipped 13x13 neighborhood around every output pixel,
///   5. calls FUN_001b8b90(diff, cross),
///   6. converts that doubled-angle result to a 0..179 ridge-direction byte.
///
/// The unusual `b8b90(diff, cross)` argument order is intentional. Combined
/// with the vendor's half-angle and rotation below it yields ridge direction
/// (gradient direction + 90 degrees), which is then quantized by c7310.
pub fn gf3258_c6d90_direction_map(image: &[u8]) -> Result<Vec<u8>, FeatureError> {
    if image.len() != GF3258_PIXELS {
        return Err(FeatureError::UnexpectedPixelCount {
            expected: GF3258_PIXELS,
            actual: image.len(),
        });
    }

    let mut gx = vec![0i32; GF3258_PIXELS];
    let mut gy = vec![0i32; GF3258_PIXELS];

    // FUN_001c6d90 leaves the one-pixel border at zero and writes Sobel
    // derivatives only for x=1..w-2, y=1..h-2.
    for y in 1..(GF3258_HEIGHT - 1) {
        for x in 1..(GF3258_WIDTH - 1) {
            let tl = i32::from(image[(y - 1) * GF3258_WIDTH + (x - 1)]);
            let tc = i32::from(image[(y - 1) * GF3258_WIDTH + x]);
            let tr = i32::from(image[(y - 1) * GF3258_WIDTH + (x + 1)]);
            let ml = i32::from(image[y * GF3258_WIDTH + (x - 1)]);
            let mr = i32::from(image[y * GF3258_WIDTH + (x + 1)]);
            let bl = i32::from(image[(y + 1) * GF3258_WIDTH + (x - 1)]);
            let bc = i32::from(image[(y + 1) * GF3258_WIDTH + x]);
            let br = i32::from(image[(y + 1) * GF3258_WIDTH + (x + 1)]);

            let idx = y * GF3258_WIDTH + x;

            // Preserve the vendor's 32-bit arithmetic bit-for-bit.
            gx[idx] = tr
                .wrapping_add(mr.wrapping_mul(2))
                .wrapping_add(br)
                .wrapping_sub(tl)
                .wrapping_sub(ml.wrapping_mul(2))
                .wrapping_sub(bl);

            gy[idx] = bl
                .wrapping_add(bc.wrapping_mul(2))
                .wrapping_add(br)
                .wrapping_sub(tl)
                .wrapping_sub(tc.wrapping_mul(2))
                .wrapping_sub(tr);
        }
    }

    let mut cross = vec![0i32; GF3258_PIXELS];
    let mut diff = vec![0i32; GF3258_PIXELS];
    for i in 0..GF3258_PIXELS {
        cross[i] = gx[i].wrapping_mul(gy[i]).wrapping_mul(2);
        diff[i] = gx[i]
            .wrapping_mul(gx[i])
            .wrapping_sub(gy[i].wrapping_mul(gy[i]));
    }

    // c6d90 constructs integral images with row 0 and column 0 left at zero.
    // All additions/subtractions are 32-bit wrapping operations.
    fn integral_image(source: &[i32]) -> Vec<i32> {
        let mut integral = vec![0i32; GF3258_PIXELS];

        for y in 1..GF3258_HEIGHT {
            for x in 1..GF3258_WIDTH {
                let idx = y * GF3258_WIDTH + x;
                integral[idx] = integral[(y - 1) * GF3258_WIDTH + x]
                    .wrapping_add(integral[y * GF3258_WIDTH + (x - 1)])
                    .wrapping_sub(integral[(y - 1) * GF3258_WIDTH + (x - 1)])
                    .wrapping_add(source[idx]);
            }
        }

        integral
    }

    let cross_integral = integral_image(&cross);
    let diff_integral = integral_image(&diff);

    #[inline]
    fn rectangle_sum(integral: &[i32], x0: usize, y0: usize, x1: usize, y1: usize) -> i32 {
        // c6d90's bounds always satisfy x0,y0 >= 1 for GF3258.
        integral[y1 * GF3258_WIDTH + x1]
            .wrapping_add(integral[(y0 - 1) * GF3258_WIDTH + (x0 - 1)])
            .wrapping_sub(integral[y1 * GF3258_WIDTH + (x0 - 1)])
            .wrapping_sub(integral[(y0 - 1) * GF3258_WIDTH + x1])
    }

    let mut direction = vec![0u8; GF3258_PIXELS];

    for y in 0..GF3258_HEIGHT {
        let y0 = (y as i32 - GF3258_C6D90_TENSOR_RADIUS).max(1) as usize;
        let y1 = (y as i32 + GF3258_C6D90_TENSOR_RADIUS).min(GF3258_HEIGHT as i32 - 1) as usize;

        for x in 0..GF3258_WIDTH {
            let x0 = (x as i32 - GF3258_C6D90_TENSOR_RADIUS).max(1) as usize;
            let x1 = (x as i32 + GF3258_C6D90_TENSOR_RADIUS).min(GF3258_WIDTH as i32 - 1) as usize;

            let local_diff = rectangle_sum(&diff_integral, x0, y0, x1, y1);
            let local_cross = rectangle_sum(&cross_integral, x0, y0, x1, y1);

            // FUN_001b8b90 receives pointers to (diff, cross), i.e. the first
            // value occupies the routine's atan2 "y" role and the second the
            // "x" role. Its magnitude output is irrelevant here.
            let (angle_bits, _) = gf3258_cordic_atan2_magnitude_q12(local_diff, local_cross);

            let mut angle_q12 = i32::from(angle_bits as i16);
            if angle_q12 < 0 {
                angle_q12 = angle_q12.wrapping_add(GF3258_TAU_Q12);
            }

            // Exact c6d90 conversion:
            //   half_degrees = angle_q12 * 0x1ca6 >> 20
            let half_degrees = angle_q12.wrapping_mul(GF3258_C6D90_HALF_DEGREE_FACTOR) >> 20;

            // Exact branch and signed-char narrowing from the vendor.
            let rotated = if half_degrees.wrapping_sub(0x87) < 1 {
                half_degrees.wrapping_add(0x2d)
            } else {
                half_degrees.wrapping_sub(0x87)
            };
            let selector_i8 = (-0x4ci8).wrapping_sub(rotated as i8);

            direction[y * GF3258_WIDTH + x] = selector_i8 as u8;
        }
    }

    Ok(direction)
}

/// Exact FUN_001c7310 GF3258 producer for c0910 param_1/local_290.
///
/// `source_u8` is c2d40's local_2b8 backing image. The returned 80x64 u8
/// buffer is the image descriptor backing store that c2d40 passes as c0910
/// param_1. The output is an orientation-adaptive seven-tap line average.
pub fn gf3258_c7310_gradient_source(source_u8: &[u8]) -> Result<Vec<u8>, FeatureError> {
    if source_u8.len() != GF3258_PIXELS {
        return Err(FeatureError::UnexpectedPixelCount {
            expected: GF3258_PIXELS,
            actual: source_u8.len(),
        });
    }

    let direction = gf3258_c6d90_direction_map(source_u8)?;
    let mut output = vec![0u8; GF3258_PIXELS];

    for y in 0..GF3258_HEIGHT {
        for x in 0..GF3258_WIDTH {
            let idx = y * GF3258_WIDTH + x;
            let delta = direction[idx].wrapping_sub(8);
            let class = if delta < 0xa5 {
                usize::from(delta / 15) + 1
            } else {
                0
            };

            let mut weighted_sum = 0i32;
            let mut weight_sum = 0i32;

            for (tap, &(dx, dy)) in GF3258_C7310_DIRECTION_OFFSETS[class].iter().enumerate() {
                let sx = x as i32 + dx;
                let sy = y as i32 + dy;

                if sx >= 0 && sx < GF3258_WIDTH as i32 && sy >= 0 && sy < GF3258_HEIGHT as i32 {
                    let weight = GF3258_C7310_WEIGHTS[tap];
                    weighted_sum = weighted_sum.wrapping_add(
                        i32::from(source_u8[sy as usize * GF3258_WIDTH + sx as usize])
                            .wrapping_mul(weight),
                    );
                    weight_sum = weight_sum.wrapping_add(weight);
                }
            }

            output[idx] = if weight_sum == 0 {
                0xff
            } else {
                (weighted_sum / weight_sum) as u8
            };
        }
    }

    Ok(output)
}

// -----------------------------------------------------------------------------
// GF3258 candidate -> ridge-orientation extraction
// FUN_001be0b0 + the single-orientation post-processing path in FUN_001be410.
// -----------------------------------------------------------------------------

pub const GF3258_ORIENTATION_BINS: usize = 36;
pub const GF3258_ORIENTATION_HALF_BINS: usize = 18;
pub const GF3258_ORIENTATION_RADIUS_MAX: i32 = 32;
pub const GF3258_PI_Q12: i32 = 0x3244;
pub const GF3258_TAU_Q12: i32 = 0x6488;
pub const GF3258_ORIENTATION_BIN_Q9: i32 = 0x200;
pub const GF3258_ORIENTATION_TURN_Q9: i32 =
    GF3258_ORIENTATION_BINS as i32 * GF3258_ORIENTATION_BIN_Q9;

const GF3258_GAUSS_ZERO_CUTOFF: u32 = 0x0006_ee75;
const GF3258_GAUSS_MAGIC_THIRDS: u32 = 0xaaaa_aaab;
const GF3258_GAUSS_MAGIC_FIFTHS: u32 = 0xcccc_cccd;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gf3258OrientationError {
    UnexpectedMapCount {
        map: &'static str,
        expected: usize,
        actual: usize,
    },
    InvalidScale(i32),
}

impl fmt::Display for Gf3258OrientationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedMapCount {
                map,
                expected,
                actual,
            } => write!(
                f,
                "GF3258 orientation {map} map has {actual} pixels; expected {expected} (80x64)"
            ),
            Self::InvalidScale(scale) => write!(
                f,
                "GF3258 primary orientation requires a positive Q16 scale; got {scale}"
            ),
        }
    }
}

impl Error for Gf3258OrientationError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf3258OrientationWindow {
    pub x_min_offset: i32,
    pub x_max_offset: i32,
    pub y_min_offset: i32,
    pub y_max_offset: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gf3258OrientationResult {
    pub radius: i32,
    pub sigma_q16: i32,
    pub gaussian_arg: i32,
    pub window: Gf3258OrientationWindow,

    // Histogram before and after FUN_001be0b0's circular [1,4,6,4,1]/16 pass.
    pub raw_histogram: [u32; GF3258_ORIENTATION_BINS],
    pub histogram: [u32; GF3258_ORIENTATION_BINS],

    // The smoothed scan finds the earliest maximum. With GF3258's duplicated
    // pi-periodic histogram, FUN_001be0b0 adds 18 before returning the bin.
    pub earliest_max_bin: usize,
    pub returned_max_bin: usize,
    pub max_value: u32,

    // FUN_001be410 single-orientation path.
    pub interpolated_peak_q9: i32,
    pub full_angle_q12: i32,
    pub orientation_q12: u16,
}

/// Reproduce the GF3258 primary candidate's ridge-orientation path.
///
/// `magnitude_map_i32` is the 80x64 4-byte plane passed as stack arg7 to
/// FUN_001be0b0. `angle_map_u16` is the 80x64 2-byte plane passed in RCX;
/// each element is consumed by the vendor as a signed i16 fixed-point angle.
///
/// The GF3258 primary path uses the pi-periodic duplicated histogram mode
/// (FUN_001be0b0 arg10 == 1) and FUN_001be410's single-orientation mode.
pub fn gf3258_primary_orientation(
    candidate: &RefinedExtremum,
    magnitude_map_i32: &[i32],
    angle_map_u16: &[u16],
) -> Result<Gf3258OrientationResult, Gf3258OrientationError> {
    if magnitude_map_i32.len() != GF3258_PIXELS {
        return Err(Gf3258OrientationError::UnexpectedMapCount {
            map: "i32 magnitude",
            expected: GF3258_PIXELS,
            actual: magnitude_map_i32.len(),
        });
    }
    if angle_map_u16.len() != GF3258_PIXELS {
        return Err(Gf3258OrientationError::UnexpectedMapCount {
            map: "u16 angle",
            expected: GF3258_PIXELS,
            actual: angle_map_u16.len(),
        });
    }
    if candidate.scale_q16 <= 0 {
        return Err(Gf3258OrientationError::InvalidScale(candidate.scale_q16));
    }

    let x = candidate.x as i32;
    let y = candidate.y as i32;

    // FUN_001be0b0:
    //
    //   t = 18 * scale_q16
    //   radius = round(t / 2^18), capped at 32
    //
    // For the positive GF3258 scale domain the assembly implements the round
    // bit explicitly from ((t >> 2) & 0x8000).
    let t = candidate.scale_q16.wrapping_mul(18);
    let mut radius = (t >> 18) + if ((t >> 2) & 0x8000) != 0 { 1 } else { 0 };
    radius = radius.min(GF3258_ORIENTATION_RADIUS_MAX);

    // sigma_q16 = (6 * scale_q16) >> 2 == 1.5 * scale.
    let sigma_q16 = candidate.scale_q16.wrapping_mul(6) >> 2;
    let sigma_sq = i64::from(sigma_q16) * i64::from(sigma_q16);
    let gaussian_arg = (0x8000_0000_0000i64 / sigma_sq) as i32;

    // Keep the sampled neighborhood inside the one-pixel derivative border.
    let window = Gf3258OrientationWindow {
        x_min_offset: (-radius).max(1 - x),
        x_max_offset: radius.min(GF3258_WIDTH as i32 - x - 2),
        y_min_offset: (-radius).max(1 - y),
        y_max_offset: radius.min(GF3258_HEIGHT as i32 - y - 2),
    };

    let weights = gaussian_spatial_weight_table(radius as usize, gaussian_arg as u32);

    let mut raw_histogram = [0u32; GF3258_ORIENTATION_BINS];
    let n = radius as usize + 1;

    if window.x_min_offset <= window.x_max_offset && window.y_min_offset <= window.y_max_offset {
        for dy in window.y_min_offset..=window.y_max_offset {
            let ay = dy.unsigned_abs() as usize;
            for dx in window.x_min_offset..=window.x_max_offset {
                let ax = dx.unsigned_abs() as usize;

                let px = (x + dx) as usize;
                let py = (y + dy) as usize;
                let pixel = py * GF3258_WIDTH + px;

                let weight = weights[ay * n + ax];
                let magnitude = magnitude_map_i32[pixel] as u32;

                // be257..be260: low-32-bit multiply followed by logical >> 8.
                let contribution = weight.wrapping_mul(magnitude) >> 8;

                let signed_angle = angle_map_u16[pixel] as i16 as i32;
                let bin = orientation_bin_from_signed_q12(signed_angle);

                raw_histogram[bin] = raw_histogram[bin].wrapping_add(contribution);

                // GF3258 call uses duplicate_pi=true (arg10 == 1).
                let mirror = (bin + GF3258_ORIENTATION_HALF_BINS) % GF3258_ORIENTATION_BINS;
                raw_histogram[mirror] = raw_histogram[mirror].wrapping_add(contribution);
            }
        }
    }

    let histogram = smooth_orientation_histogram(&raw_histogram);

    // FUN_001be0b0 scans with unsigned ">" and keeps the earliest maximum.
    let mut earliest_max_bin = 0usize;
    let mut max_value = histogram[0];
    for (bin, &value) in histogram.iter().enumerate().skip(1) {
        if value > max_value {
            earliest_max_bin = bin;
            max_value = value;
        }
    }

    // In duplicated pi-periodic mode the first maximum is in 0..17 and the
    // vendor adds 18 before writing the returned max-bin index.
    let returned_max_bin = earliest_max_bin + GF3258_ORIENTATION_HALF_BINS;
    debug_assert!(returned_max_bin < GF3258_ORIENTATION_BINS);

    let interpolated_peak_q9 = interpolate_orientation_peak_q9(&histogram, returned_max_bin);

    // be5b7..be5e6:
    //   product = peak_q9 * 0x6488
    //   quotient = product / 36        (signed truncation toward zero)
    //   full_angle_q12 = quotient >> 9
    //
    // Preserve the intermediate division instead of algebraically combining it.
    let angle_product = interpolated_peak_q9.wrapping_mul(GF3258_TAU_Q12);
    let full_angle_q12 = (angle_product / GF3258_ORIENTATION_BINS as i32) >> 9;

    // Primary/single-orientation be410 mode folds the directed 2*pi result to
    // the undirected fingerprint-ridge interval [0, pi).
    let shifted = full_angle_q12 - GF3258_PI_Q12;
    let orientation_q12 = if shifted < 0 { full_angle_q12 } else { shifted } as u16;

    Ok(Gf3258OrientationResult {
        radius,
        sigma_q16,
        gaussian_arg,
        window,
        raw_histogram,
        histogram,
        earliest_max_bin,
        returned_max_bin,
        max_value,
        interpolated_peak_q9,
        full_angle_q12,
        orientation_q12,
    })
}

/// FUN_001bdc20, reconstructed literally from its integer assembly.
///
/// It fills an (radius+1)x(radius+1) symmetric spatial table. The vendor writes
/// only one triangle plus its transpose; computing every entry directly gives
/// the same table because the scalar approximation depends only on x^2+y^2.
pub(super) fn gaussian_spatial_weight_table(radius: usize, gaussian_arg: u32) -> Vec<u32> {
    let n = radius + 1;
    let mut out = vec![0u32; n * n];

    for y in 0..n {
        for x in 0..n {
            let distance_sq = (x * x + y * y) as u32;
            let z = distance_sq.wrapping_mul(gaussian_arg);
            out[y * n + x] = gaussian_weight_from_scaled_radius(z);
        }
    }

    out
}

/// Scalar core of FUN_001bdc20.
///
/// This is an integer rational approximation used by the vendor's Gaussian
/// spatial weighting code. Keep the exact unsigned 32-bit operations and
/// high-half multiplies; replacing it with floating-point exp() loses parity.
fn gaussian_weight_from_scaled_radius(z: u32) -> u32 {
    if z > GF3258_GAUSS_ZERO_CUTOFF {
        return 0;
    }

    let high_thirds = ((u64::from(z) * u64::from(GF3258_GAUSS_MAGIC_THIRDS)) >> 32) as u32;

    let z_div_256 = z >> 8;
    let z_div_128 = z >> 7;

    let square_8 = z_div_256.wrapping_mul(z_div_256);

    let mut a = high_thirds >> 2;
    a = a.wrapping_add(0x8000);
    a >>= 8;
    a = a.wrapping_mul(square_8);
    a >>= 15;

    let mut b = square_8 >> 8;
    b = b.wrapping_mul(b);
    b >>= 8;

    let mut denom_base = z_div_128.wrapping_add(a).wrapping_add(0x200);

    let high_fifths = ((u64::from(GF3258_GAUSS_MAGIC_FIFTHS) * u64::from(z)) >> 32) as u32;
    let mut c = high_fifths >> 2;
    c = c.wrapping_add(0x1_0000);
    c >>= 8;

    b = b.wrapping_mul(c);
    b >>= 7;

    let high_b_thirds = ((u64::from(b) * u64::from(GF3258_GAUSS_MAGIC_THIRDS)) >> 32) as u32;
    denom_base = denom_base.wrapping_add(high_b_thirds >> 4);

    // Final vendor DIV:
    //   ((denom / 2) + 0x40000) / denom
    ((denom_base >> 1).wrapping_add(0x4_0000)) / denom_base
}

fn orientation_bin_from_signed_q12(angle_q12: i32) -> usize {
    // be2b1..be2d0:
    //
    // tmp = 0x3244 + 36 * (0x3244 - angle)
    // bin = signed_divide(tmp, 0x6488)
    //
    // The vendor uses the magic 0xa2f96525 sequence instead of IDIV.
    let delta = GF3258_PI_Q12.wrapping_sub(angle_q12);
    let tmp = GF3258_PI_Q12.wrapping_add(delta.wrapping_mul(36));

    let magic = 0xa2f9_6525u32 as i32;
    let high = signed_mul_high_i32(tmp, magic);
    let mut bin = high.wrapping_add(tmp) >> 14;
    bin = bin.wrapping_sub(tmp >> 31);

    if bin > 35 {
        0
    } else {
        debug_assert!(bin >= 0, "valid GF3258 angle map produced a negative bin");
        bin as usize
    }
}

fn signed_mul_high_i32(a: i32, b: i32) -> i32 {
    ((i64::from(a) * i64::from(b)) >> 32) as i32
}

fn smooth_orientation_histogram(
    raw: &[u32; GF3258_ORIENTATION_BINS],
) -> [u32; GF3258_ORIENTATION_BINS] {
    let mut out = [0u32; GF3258_ORIENTATION_BINS];

    for i in 0..GF3258_ORIENTATION_BINS {
        let m2 = raw[(i + GF3258_ORIENTATION_BINS - 2) % GF3258_ORIENTATION_BINS];
        let m1 = raw[(i + GF3258_ORIENTATION_BINS - 1) % GF3258_ORIENTATION_BINS];
        let c = raw[i];
        let p1 = raw[(i + 1) % GF3258_ORIENTATION_BINS];
        let p2 = raw[(i + 2) % GF3258_ORIENTATION_BINS];

        // Assembly uses 32-bit LEA/ADD and logical SHR; preserve wrapping.
        let sum = m2
            .wrapping_add(m1.wrapping_mul(4))
            .wrapping_add(c.wrapping_mul(6))
            .wrapping_add(p1.wrapping_mul(4))
            .wrapping_add(p2);

        out[i] = sum >> 4;
    }

    out
}

fn interpolate_orientation_peak_q9(histogram: &[u32; GF3258_ORIENTATION_BINS], bin: usize) -> i32 {
    debug_assert!(bin < GF3258_ORIENTATION_BINS);

    let prev = i64::from(histogram[(bin + GF3258_ORIENTATION_BINS - 1) % GF3258_ORIENTATION_BINS]);
    let current = i64::from(histogram[bin]);
    let next = i64::from(histogram[(bin + 1) % GF3258_ORIENTATION_BINS]);

    // be53b..be568. The vendor intentionally keeps this integer quantization:
    //
    //   curvature = prev - 2*current + next
    //   numerator = ((prev-next) << 9) - curvature
    //   denominator = 2*curvature
    //   delta = numerator / denominator       (signed, truncation toward zero)
    //
    // The strict local-maximum test guarantees a nonzero negative curvature for
    // the selected primary peak.
    let curvature = prev - 2 * current + next;
    let numerator = ((prev - next) << 9) - curvature;
    let denominator = 2 * curvature;
    debug_assert_ne!(denominator, 0);

    let delta = numerator / denominator;
    let mut peak_q9 = (bin as i32)
        .wrapping_mul(GF3258_ORIENTATION_BIN_Q9)
        .wrapping_add(delta as i32);

    // be56b..be57c wraps the signed 16-bit result into one 36-bin turn.
    if peak_q9 < 0 {
        peak_q9 = peak_q9.wrapping_add(GF3258_ORIENTATION_TURN_Q9);
    } else if peak_q9 >= GF3258_ORIENTATION_TURN_Q9 {
        peak_q9 = peak_q9.wrapping_sub(GF3258_ORIENTATION_TURN_Q9);
    }

    peak_q9
}

// FUN_001b8db0 trigonometric CORDIC constants used by descriptor rotation.
const GF3258_CORDIC_GAIN_Q16: i32 = 0x9b75;
const GF3258_CORDIC_ATAN_Q12: [i32; 13] = [3217, 1899, 1003, 509, 256, 128, 64, 32, 16, 8, 4, 2, 1];

/// FUN_001b8db0 restricted to the proven GF3258 ridge-orientation domain
/// [0, pi). Returns (sin, cos) in Q14.
pub fn gf3258_cordic_sin_cos_q14(angle_q12: u16) -> (i32, i32) {
    let angle = i32::from(angle_q12);
    debug_assert!((0..GF3258_PI_Q12).contains(&angle));

    let (reduced, negate_cos) = if angle <= GF3258_PI_Q12 / 2 {
        (angle, false)
    } else {
        (GF3258_PI_Q12 - angle, true)
    };

    let (sin_q14, mut cos_q14) = if reduced == 0 {
        (0, 0x4000)
    } else if reduced == GF3258_PI_Q12 / 2 {
        (0x4000, 0)
    } else {
        let mut x = 0x4000i32;
        let mut y = 0i32;
        let mut accumulated_angle = 0i32;

        for (shift, &atan_q12) in GF3258_CORDIC_ATAN_Q12.iter().enumerate() {
            // Every vendor iteration reloads x/y through MOVSX word, so the
            // state is effectively quantized to signed i16 before shifting.
            let x16 = x as i16 as i32;
            let y16 = y as i16 as i32;

            if reduced >= accumulated_angle {
                accumulated_angle = accumulated_angle.wrapping_add(atan_q12);
                y = y.wrapping_add(x16 >> shift);
                x = x.wrapping_sub(y16 >> shift);
            } else {
                accumulated_angle = accumulated_angle.wrapping_sub(atan_q12);
                y = y.wrapping_sub(x16 >> shift);
                x = x.wrapping_add(y16 >> shift);
            }
        }

        let x16 = x as i16 as i32;
        let y16 = y as i16 as i32;

        let cos = x16
            .wrapping_mul(GF3258_CORDIC_GAIN_Q16)
            .wrapping_add(0x8000)
            >> 16;
        let sin = y16
            .wrapping_mul(GF3258_CORDIC_GAIN_Q16)
            .wrapping_add(0x8000)
            >> 16;
        (sin, cos)
    };

    if negate_cos {
        cos_q14 = cos_q14.wrapping_neg();
    }

    (sin_q14, cos_q14)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cordic_table_and_axis_anchors_are_exact() {
        assert_eq!(
            GF3258_CORDIC_ATAN_Q12,
            [3217, 1899, 1003, 509, 256, 128, 64, 32, 16, 8, 4, 2, 1,]
        );
        assert_eq!(gf3258_cordic_sin_cos_q14(0), (0, 0x4000));
        assert_eq!(
            gf3258_cordic_sin_cos_q14((GF3258_PI_Q12 / 2) as u16),
            (0x4000, 0)
        );
    }

    #[test]
    fn cordic_candidate0_orientation_has_stable_integer_anchor() {
        // Predicted directly from the recovered b8db0 assembly/table. The live
        // bf830 parity capture validates this boundary against the vendor.
        assert_eq!(gf3258_cordic_sin_cos_q14(12_185), (2_720, -16_157));
    }

    #[test]
    fn bdc20_scalar_anchors_match_recovered_integer_code() {
        assert_eq!(gaussian_weight_from_scaled_radius(0), 512);
        assert_eq!(gaussian_weight_from_scaled_radius(1801), 498);
        assert_eq!(
            gaussian_weight_from_scaled_radius(GF3258_GAUSS_ZERO_CUTOFF),
            2
        );
        assert_eq!(
            gaussian_weight_from_scaled_radius(GF3258_GAUSS_ZERO_CUTOFF + 1),
            0
        );
    }

    #[test]
    fn observed_histogram_postprocessing_is_exact() {
        let histogram: [u32; 36] = [
            2_483_809, 1_435_489, 593_162, 159_745, 33_459, 12_932, 4_957, 3_689, 6_176, 7_965,
            6_738, 6_047, 10_042, 19_844, 219_779, 1_057_402, 2_369_961, 3_024_969, 2_483_809,
            1_435_489, 593_162, 159_745, 33_459, 12_932, 4_957, 3_689, 6_176, 7_965, 6_738, 6_047,
            10_042, 19_844, 219_779, 1_057_402, 2_369_961, 3_024_969,
        ];

        let peak = interpolate_orientation_peak_q9(&histogram, 35);
        assert_eq!(peak, 17_943);

        let full = (peak * GF3258_TAU_Q12 / 36) >> 9;
        assert_eq!(full, 25_053);

        let folded = if full - GF3258_PI_Q12 < 0 {
            full
        } else {
            full - GF3258_PI_Q12
        };
        assert_eq!(folded, 12_185);
    }

    #[test]
    fn gradient_filter_records_are_exact_normalized_q16() {
        assert_eq!(GF3258_GRADIENT_GAUSS_0.len(), 9);
        assert_eq!(GF3258_GRADIENT_GAUSS_1.len(), 7);
        assert_eq!(GF3258_GRADIENT_GAUSS_0.iter().sum::<i32>(), 65_536);
        assert_eq!(GF3258_GRADIENT_GAUSS_1.iter().sum::<i32>(), 65_536);
        assert_eq!(GF3258_GRADIENT_GAUSS_0[4], 21_790);
        assert_eq!(GF3258_GRADIENT_GAUSS_1[3], 28_430);
    }

    #[test]
    fn gradient_q12_saturation_matches_c0910_boundaries() {
        assert_eq!(gf3258_gradient_difference_to_q12(0x7ffff), 0x7fff_f000);
        assert_eq!(gf3258_gradient_difference_to_q12(0x80000), 0x7fff_f000);
        assert_eq!(gf3258_gradient_difference_to_q12(-0x80000), i32::MIN);
        assert_eq!(gf3258_gradient_difference_to_q12(-0x80001), i32::MIN);
        assert_eq!(gf3258_gradient_difference_to_q12(1), 0x1000);
        assert_eq!(gf3258_gradient_difference_to_q12(-1), -0x1000);
    }

    #[test]
    fn b8b90_axis_and_diagonal_anchors_are_exact() {
        assert_eq!(gf3258_cordic_atan2_magnitude_q12(0, 0), (0x3244, 0));
        assert_eq!(gf3258_cordic_atan2_magnitude_q12(0, 4096), (0, 4096));
        assert_eq!(gf3258_cordic_atan2_magnitude_q12(0, -4096), (0x3244, 4096));
        assert_eq!(gf3258_cordic_atan2_magnitude_q12(4096, 0), (0x1922, 4096));
        assert_eq!(
            gf3258_cordic_atan2_magnitude_q12(-4096, 0),
            ((-0x1922i16) as u16, 4096),
        );
        assert_eq!(
            gf3258_cordic_atan2_magnitude_q12(4096, 4096),
            (0x0c91, 5793),
        );
        assert_eq!(
            gf3258_cordic_atan2_magnitude_q12(-4096, 4096),
            ((-0x0c91i16) as u16, 5793),
        );
    }

    #[test]
    fn constant_image_gradient_planes_match_vendor_zero_gradient_convention() {
        let planes = gf3258_gradient_planes(&vec![127u8; GF3258_PIXELS]).unwrap();

        for x in 0..GF3258_WIDTH {
            assert_eq!(planes.magnitude_map_i32[x], 0);
            assert_eq!(planes.angle_map_u16[x], 0);
            let bottom = (GF3258_HEIGHT - 1) * GF3258_WIDTH + x;
            assert_eq!(planes.magnitude_map_i32[bottom], 0);
            assert_eq!(planes.angle_map_u16[bottom], 0);
        }

        for y in 0..GF3258_HEIGHT {
            let left = y * GF3258_WIDTH;
            let right = left + GF3258_WIDTH - 1;
            assert_eq!(planes.magnitude_map_i32[left], 0);
            assert_eq!(planes.angle_map_u16[left], 0);
            assert_eq!(planes.magnitude_map_i32[right], 0);
            assert_eq!(planes.angle_map_u16[right], 0);
        }

        let center = (GF3258_HEIGHT / 2) * GF3258_WIDTH + GF3258_WIDTH / 2;
        assert_eq!(planes.magnitude_map_i32[center], 0);
        assert_eq!(planes.angle_map_u16[center], GF3258_PI_Q12 as u16);
    }

    #[test]
    fn c7310_static_line_table_matches_recovered_shape() {
        assert_eq!(GF3258_C7310_WEIGHTS, [1, 2, 4, 8, 4, 2, 1]);
        assert_eq!(GF3258_C7310_WEIGHTS.iter().sum::<i32>(), 22);

        for class in GF3258_C7310_DIRECTION_OFFSETS {
            assert_eq!(class[3], (0, 0));
        }

        assert_eq!(
            GF3258_C7310_DIRECTION_OFFSETS[0],
            [(-3, 0), (-2, 0), (-1, 0), (0, 0), (1, 0), (2, 0), (3, 0)]
        );
        assert_eq!(
            GF3258_C7310_DIRECTION_OFFSETS[3],
            [(-3, -3), (-2, -2), (-1, -1), (0, 0), (1, 1), (2, 2), (3, 3)]
        );
        assert_eq!(
            GF3258_C7310_DIRECTION_OFFSETS[6],
            [(0, -3), (0, -2), (0, -1), (0, 0), (0, 1), (0, 2), (0, 3)]
        );
        assert_eq!(
            GF3258_C7310_DIRECTION_OFFSETS[9],
            [(-3, 3), (-2, 2), (-1, 1), (0, 0), (1, -1), (2, -2), (3, -3)]
        );
    }

    #[test]
    fn c6d90_constant_image_uses_vendor_zero_tensor_direction() {
        let image = vec![127u8; GF3258_PIXELS];
        let direction = gf3258_c6d90_direction_map(&image).unwrap();

        // Zero tensor -> b8b90(0,0)=+pi -> half_degrees=90 ->
        // c6d90's rotation/narrowing emits byte 45 everywhere.
        assert!(direction.iter().all(|&v| v == 45));

        let filtered = gf3258_c7310_gradient_source(&image).unwrap();
        assert_eq!(filtered, image);
    }

    #[test]
    fn c6d90_ramp_directions_match_ridge_orientation() {
        let horizontal_ramp: Vec<u8> = (0..GF3258_HEIGHT)
            .flat_map(|_| (0..GF3258_WIDTH).map(|x| x as u8))
            .collect();
        let vertical_ramp: Vec<u8> = (0..GF3258_HEIGHT)
            .flat_map(|y| (0..GF3258_WIDTH).map(move |_| y as u8))
            .collect();
        let diagonal_ramp: Vec<u8> = (0..GF3258_HEIGHT)
            .flat_map(|y| (0..GF3258_WIDTH).map(move |x| (x + y) as u8))
            .collect();

        let center = (GF3258_HEIGHT / 2) * GF3258_WIDTH + GF3258_WIDTH / 2;

        // Horizontal intensity gradient -> vertical ridge direction.
        assert_eq!(
            gf3258_c6d90_direction_map(&horizontal_ramp).unwrap()[center],
            90
        );
        // Vertical intensity gradient -> horizontal ridge direction.
        assert_eq!(
            gf3258_c6d90_direction_map(&vertical_ramp).unwrap()[center],
            0
        );
        // gx == gy -> ridge line has slope -1, represented as 135 degrees.
        assert_eq!(
            gf3258_c6d90_direction_map(&diagonal_ramp).unwrap()[center],
            135
        );

        // Smoothing along a ridge leaves these ideal ramps unchanged away
        // from border renormalization effects.
        let horizontal_filtered = gf3258_c7310_gradient_source(&horizontal_ramp).unwrap();
        let vertical_filtered = gf3258_c7310_gradient_source(&vertical_ramp).unwrap();
        let diagonal_filtered = gf3258_c7310_gradient_source(&diagonal_ramp).unwrap();

        assert_eq!(horizontal_filtered[center], horizontal_ramp[center]);
        assert_eq!(vertical_filtered[center], vertical_ramp[center]);
        assert_eq!(diagonal_filtered[center], diagonal_ramp[center]);
    }

    #[test]
    fn c7310_selector_quantization_matches_vendor_boundaries() {
        fn class(selector: u8) -> usize {
            let delta = selector.wrapping_sub(8);
            if delta < 0xa5 {
                usize::from(delta / 15) + 1
            } else {
                0
            }
        }

        assert_eq!(class(0), 0);
        assert_eq!(class(7), 0);
        assert_eq!(class(8), 1);
        assert_eq!(class(22), 1);
        assert_eq!(class(23), 2);
        assert_eq!(class(172), 11);
        assert_eq!(class(173), 0);
        assert_eq!(class(179), 0);
        assert_eq!(class(255), 0);
    }
}
