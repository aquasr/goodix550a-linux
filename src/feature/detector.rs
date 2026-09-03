//! GF3258 DoG scale-space detection and fixed-point extremum refinement.
//!
//! This module contains the recovered detector/refinement portion of
//! `FUN_001c0910`, including the exact Gaussian records, 3x3x3 extrema scan,
//! guarded Q12 Hessian solve, relocation policy, contrast gate, and scale
//! conversion.

use super::filter::separable_q16_reflect101;
use super::{FeatureError, GF3258_HEIGHT, GF3258_PIXELS, GF3258_WIDTH};

pub const GF3258_PYRAMID_LEVELS: usize = 9;
pub const GF3258_DOG_LEVELS: usize = GF3258_PYRAMID_LEVELS - 1;

// FUN_001c0910 rejects |DoG| <= 0x148 before the 3x3x3 extrema test.
pub const GF3258_DOG_CONTRAST_THRESHOLD: i32 = 0x148;

// FUN_001c0910 scans x/y from 6 through dimension-7 inclusive.
pub const GF3258_EXTREMA_BORDER: usize = 6;

// GF3258 (sensor type 0x18) refines over DoG levels 1..=6.
pub const GF3258_MIN_REFINED_LEVEL: i32 = 1;
pub const GF3258_MAX_REFINED_LEVEL: i32 = 6;

// The vendor runs at most five quadratic solves/relocations for one raw extremum.
pub const GF3258_MAX_REFINEMENT_ITERS: usize = 5;

// Q12 offsets in [-0x7ff, +0x7ff] are considered settled.
// Exactly +/-0x800 (half a sample) triggers integer relocation.
pub const GF3258_SETTLED_Q12: i32 = 0x7ff;

// GF3258 requires abs(interpolated fixed-point response) >= 0x1478000.
pub const GF3258_INTERPOLATED_CONTRAST_MIN: i64 = 0x0147_8000;

// Invalid fixed-point displacement written by the vendor when the numerator is
// too much wider than the Hessian determinant for its guarded Q12 division.
pub const GF3258_INVALID_OFFSET_Q12: i32 = 0x00ff_ffff;

// Exact Q16 filter records selected by FUN_001a4840 modes 300..308.
// Keep the literal vendor constants: modes 304 and 307 intentionally do not
// sum to 65536.
pub const GAUSS_300: [i32; 7] = [291, 3539, 15862, 26152, 15862, 3539, 291];
pub const GAUSS_301: [i32; 9] = [77, 913, 5345, 15439, 21988, 15439, 5345, 913, 77];
pub const GAUSS_302: [i32; 7] = [16, 1124, 14549, 34158, 14549, 1124, 16];
pub const GAUSS_303: [i32; 7] = [126, 2569, 15710, 28726, 15710, 2569, 126];
pub const GAUSS_304: [i32; 9] = [26, 519, 4382, 15764, 24155, 15764, 4382, 519, 26];
pub const GAUSS_305: [i32; 9] = [163, 1344, 6077, 15025, 20318, 15025, 6077, 1344, 163];
pub const GAUSS_306: [i32; 11] = [
    82, 562, 2503, 7276, 13802, 17086, 13802, 7276, 2503, 562, 82,
];
pub const GAUSS_307: [i32; 13] = [
    63, 331, 1285, 3695, 7857, 12355, 14367, 12355, 7857, 3695, 1285, 331, 63,
];
pub const GAUSS_308: [i32; 15] = [
    65, 259, 839, 2192, 4625, 7886, 10860, 12084, 10860, 7886, 4625, 2192, 839, 259, 65,
];

// FUN_001b8f80's exact greedy log2(1 + 2^-k) Q16 thresholds, k=1..16.
const EXP2_LOG_STEPS_Q16: [i32; 16] = [
    0x95c0, 0x526a, 0x2b80, 0x1664, 0x0b5d, 0x05ba, 0x02e0, 0x0171, 0x00b8, 0x005c, 0x002e, 0x0017,
    0x000c, 0x0006, 0x0003, 0x0001,
];

#[derive(Debug, Clone)]
pub struct Gf3258ScaleSpace {
    levels: Vec<Vec<u16>>,
    dogs: Vec<Vec<i32>>,
}

impl Gf3258ScaleSpace {
    pub fn build(image: &[u8]) -> Result<Self, FeatureError> {
        if image.len() != GF3258_PIXELS {
            return Err(FeatureError::UnexpectedPixelCount {
                expected: GF3258_PIXELS,
                actual: image.len(),
            });
        }

        // FUN_001c0910 converts the algorithm u8 image to u16 by byte << 8.
        let source: Vec<u16> = image.iter().map(|&v| u16::from(v) << 8).collect();

        let mut levels = Vec::with_capacity(GF3258_PYRAMID_LEVELS);

        // Modes 300 and 301 both start from the same original source.
        levels.push(separable_q16_reflect101(&source, &GAUSS_300));
        levels.push(separable_q16_reflect101(&source, &GAUSS_301));

        // Modes 302..308 are incremental Gaussian blurs chained from the
        // preceding level. This yields nine levels total (0..8).
        for kernel in [
            GAUSS_302.as_slice(),
            GAUSS_303.as_slice(),
            GAUSS_304.as_slice(),
            GAUSS_305.as_slice(),
            GAUSS_306.as_slice(),
            GAUSS_307.as_slice(),
            GAUSS_308.as_slice(),
        ] {
            let next = separable_q16_reflect101(levels.last().unwrap(), kernel);
            levels.push(next);
        }

        debug_assert_eq!(levels.len(), GF3258_PYRAMID_LEVELS);

        // Detector response at scale k is L[k+1] - L[k].
        let mut dogs = Vec::with_capacity(GF3258_DOG_LEVELS);
        for k in 0..GF3258_DOG_LEVELS {
            dogs.push(
                levels[k + 1]
                    .iter()
                    .zip(&levels[k])
                    .map(|(&hi, &lo)| i32::from(hi) - i32::from(lo))
                    .collect(),
            );
        }

        Ok(Self { levels, dogs })
    }

    pub fn levels(&self) -> &[Vec<u16>] {
        &self.levels
    }

    pub fn dogs(&self) -> &[Vec<i32>] {
        &self.dogs
    }

    /// Parity-proven GF3258 prefix of FUN_001c0910:
    /// thresholded 3x3x3 extrema across DoG levels 6 -> 1.
    pub fn raw_extrema(&self) -> Vec<RawExtremum> {
        let mut out = Vec::new();

        for dog_level in (1usize..=6).rev() {
            let prev = &self.dogs[dog_level - 1];
            let cur = &self.dogs[dog_level];
            let next = &self.dogs[dog_level + 1];

            for y in GF3258_EXTREMA_BORDER..(GF3258_HEIGHT - GF3258_EXTREMA_BORDER) {
                for x in GF3258_EXTREMA_BORDER..(GF3258_WIDTH - GF3258_EXTREMA_BORDER) {
                    let i = y * GF3258_WIDTH + x;

                    // The vendor exposes the center DoG through a signed short
                    // for this first threshold/comparison stage.
                    let response = cur[i] as i16 as i32;
                    if response.abs() <= GF3258_DOG_CONTRAST_THRESHOLD {
                        continue;
                    }

                    let is_extremum = if response < 0 {
                        all_neighbors_at_least(response, prev, cur, next, x, y)
                    } else {
                        all_neighbors_at_most(response, prev, cur, next, x, y)
                    };

                    if is_extremum {
                        out.push(RawExtremum {
                            dog_level: dog_level as u8,
                            x: x as u16,
                            y: y as u16,
                            response,
                        });
                    }
                }
            }
        }

        out
    }

    /// Run the complete GF3258 quadratic-refinement/acceptance block that
    /// follows LAB_001c1ab9. Every raw extremum becomes either:
    ///
    /// - Accepted: passed fixed-point 3-D refinement, interpolated contrast,
    ///   and GF3258's positive spatial-Hessian-determinant gate.
    /// - Fallback: vendor would place the original raw extremum into its later
    ///   fallback/recovery pool.
    ///
    /// This intentionally stops before FUN_001be410.
    pub fn refinement_outcomes(&self) -> Vec<RefinementOutcome> {
        let raw = self.raw_extrema();
        raw.iter()
            .copied()
            .enumerate()
            .map(|(ordinal, point)| match self.refine_one(ordinal, point) {
                Ok(refined) => RefinementOutcome::Accepted(refined),
                Err(failure) => RefinementOutcome::Fallback(FallbackExtremum {
                    ordinal,
                    raw: point,
                    failure,
                    x_q8: point.x << 8,
                    y_q8: point.y << 8,
                    scale_q16: fallback_scale_q16(point.dog_level),
                }),
            })
            .collect()
    }

    /// Apply the vendor's refined-pixel used-map check that occurs immediately
    /// before FUN_001be410. Later fallback recovery is deliberately not mixed
    /// into this result.
    pub fn primary_candidates(&self, outcomes: &[RefinementOutcome]) -> Vec<RefinedExtremum> {
        let mut used = vec![false; GF3258_PIXELS];
        let mut out = Vec::new();

        for outcome in outcomes {
            let RefinementOutcome::Accepted(point) = outcome else {
                continue;
            };

            let i = point.y * GF3258_WIDTH + point.x;
            if !used[i] {
                used[i] = true;
                out.push(*point);
            }
        }

        out
    }

    fn refine_one(
        &self,
        ordinal: usize,
        raw: RawExtremum,
    ) -> Result<RefinedExtremum, RefinementFailure> {
        let mut x = i32::from(raw.x);
        let mut y = i32::from(raw.y);
        let mut level = i32::from(raw.dog_level);

        for iteration in 1..=GF3258_MAX_REFINEMENT_ITERS {
            let d = self.derivatives(level, x, y)?;

            let offsets = solve_q12_offsets(&d);

            let settled = q12_is_settled(offsets.dx)
                && q12_is_settled(offsets.dy)
                && q12_is_settled(offsets.ds);

            if !settled {
                x += q12_round_sample(offsets.dx);
                y += q12_round_sample(offsets.dy);
                level += q12_round_sample(offsets.ds);

                if !(GF3258_MIN_REFINED_LEVEL..=GF3258_MAX_REFINED_LEVEL).contains(&level)
                    || x < 1
                    || x >= (GF3258_WIDTH as i32 - 1)
                    || y < 1
                    || y >= (GF3258_HEIGHT as i32 - 1)
                {
                    return Err(RefinementFailure::RelocationOutOfBounds);
                }

                // Vendor decrements its five-try counter after relocation and
                // exits when it reaches zero, without performing a sixth solve.
                if iteration == GF3258_MAX_REFINEMENT_ITERS {
                    return Err(RefinementFailure::IterationLimit);
                }

                continue;
            }

            // GF3258 is in the special branch selected by uVar20 < 4:
            // center contribution is (2*DoG_center) << 13.
            let interpolated = i64::from(d.gs) * i64::from(offsets.ds)
                + (i64::from(d.center_twice) << 13)
                + i64::from(d.gx) * i64::from(offsets.dx)
                + i64::from(d.gy) * i64::from(offsets.dy);

            let response_abs = abs_i64(interpolated);
            if response_abs < GF3258_INTERPOLATED_CONTRAST_MIN as u64 {
                return Err(RefinementFailure::InterpolatedContrast);
            }

            // GF3258 takes the special acceptance branch and skips the generic
            // trace^2/determinant edge-ratio test. It requires only a positive
            // spatial 2-D Hessian determinant.
            if d.spatial_det <= 0 {
                return Err(RefinementFailure::SpatialHessian);
            }

            let x_q8_i32 = ((x << 12) + offsets.dx) >> 4;
            let y_q8_i32 = ((y << 12) + offsets.dy) >> 4;

            let scale_fixed = ((level << 12) + offsets.ds) << 4;
            // local_3978 == 4 for sensor type 0x18.
            let scale_exponent_q16 = scale_fixed / 4;
            let scale_q16 = exp2_q16(scale_exponent_q16);

            return Ok(RefinedExtremum {
                ordinal,
                raw,
                x: x as usize,
                y: y as usize,
                dog_level: level as u8,
                dx_q12: offsets.dx,
                dy_q12: offsets.dy,
                ds_q12: offsets.ds,
                x_q8: x_q8_i32 as u16,
                y_q8: y_q8_i32 as u16,
                response: (response_abs >> 12) as i32,
                spatial_det: d.spatial_det,
                scale_q16,
                iterations: iteration as u8,
            });
        }

        unreachable!("GF3258 refinement loop always returns within five iterations")
    }

    fn derivatives(
        &self,
        level: i32,
        x: i32,
        y: i32,
    ) -> Result<DerivativeBlock, RefinementFailure> {
        debug_assert!((1..=6).contains(&level));
        debug_assert!(x > 0 && x < GF3258_WIDTH as i32 - 1);
        debug_assert!(y > 0 && y < GF3258_HEIGHT as i32 - 1);

        let s = level as usize;
        let x = x as usize;
        let y = y as usize;

        let center = self.dog_at(s, x, y);

        let left = self.dog_at(s, x - 1, y);
        let right = self.dog_at(s, x + 1, y);
        let up = self.dog_at(s, x, y - 1);
        let down = self.dog_at(s, x, y + 1);
        let prev = self.dog_at(s - 1, x, y);
        let next = self.dog_at(s + 1, x, y);

        // The vendor stores 2*center back through a signed 16-bit temporary.
        let center_twice = center.wrapping_mul(2) as i16 as i32;

        // First derivatives are 4x the conventional central derivatives.
        let gx = 2i64 * i64::from(right - left);
        let gy = 2i64 * i64::from(down - up);
        let gs = 2i64 * i64::from(next - prev);

        for value in [gx, gy, gs] {
            if abs_i64(value) > 0x7fff {
                return Err(RefinementFailure::FirstDerivativeOverflow);
            }
        }

        // Diagonal Hessian entries are 4x conventional second derivatives.
        let hxx = 4i64 * (i64::from(right) + i64::from(left) - i64::from(center_twice));
        let hyy = 4i64 * (i64::from(down) + i64::from(up) - i64::from(center_twice));
        let hss = 4i64 * (i64::from(next) + i64::from(prev) - i64::from(center_twice));

        for value in [hxx, hyy, hss] {
            if abs_i64(value) > 0x7fff {
                return Err(RefinementFailure::SecondDerivativeOverflow);
            }
        }

        // Mixed derivatives are already the four-sample numerator, i.e. 4x
        // the conventional central mixed derivative.
        let hxy = i64::from(self.dog_at(s, x + 1, y + 1))
            - i64::from(self.dog_at(s, x - 1, y + 1))
            - i64::from(self.dog_at(s, x + 1, y - 1))
            + i64::from(self.dog_at(s, x - 1, y - 1));

        let hxs = i64::from(self.dog_at(s + 1, x + 1, y))
            - i64::from(self.dog_at(s + 1, x - 1, y))
            - i64::from(self.dog_at(s - 1, x + 1, y))
            + i64::from(self.dog_at(s - 1, x - 1, y));

        let hys = i64::from(self.dog_at(s + 1, x, y + 1))
            - i64::from(self.dog_at(s + 1, x, y - 1))
            - i64::from(self.dog_at(s - 1, x, y + 1))
            + i64::from(self.dog_at(s - 1, x, y - 1));

        for value in [hxy, hxs, hys] {
            if abs_i64(value) > 0x1fff {
                return Err(RefinementFailure::MixedDerivativeOverflow);
            }
        }

        let gx = gx as i32;
        let gy = gy as i32;
        let gs = gs as i32;
        let hxx = hxx as i32;
        let hyy = hyy as i32;
        let hss = hss as i32;
        let hxy = hxy as i32;
        let hxs = hxs as i32;
        let hys = hys as i32;

        let spatial_det = i64::from(hyy) * i64::from(hxx) - i64::from(hxy) * i64::from(hxy);

        Ok(DerivativeBlock {
            center_twice,
            gx,
            gy,
            gs,
            hxx,
            hyy,
            hss,
            hxy,
            hxs,
            hys,
            spatial_det,
        })
    }

    fn dog_at(&self, level: usize, x: usize, y: usize) -> i32 {
        let i = y * GF3258_WIDTH + x;
        i32::from(self.levels[level + 1][i]) - i32::from(self.levels[level][i])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawExtremum {
    pub dog_level: u8,
    pub x: u16,
    pub y: u16,
    pub response: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefinedExtremum {
    pub ordinal: usize,
    pub raw: RawExtremum,

    // Integer sample selected after zero to four relocations.
    pub x: usize,
    pub y: usize,
    pub dog_level: u8,

    // Final settled sub-sample offsets.
    pub dx_q12: i32,
    pub dy_q12: i32,
    pub ds_q12: i32,

    // Candidate fields passed onward toward FUN_001be410.
    pub x_q8: u16,
    pub y_q8: u16,
    pub response: i32,
    pub spatial_det: i64,
    pub scale_q16: i32,

    pub iterations: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FallbackExtremum {
    pub ordinal: usize,
    pub raw: RawExtremum,
    pub failure: RefinementFailure,

    // Original, unrefined fallback record fields used by the later vendor
    // recovery pool. The recovery itself is downstream of this phase.
    pub x_q8: u16,
    pub y_q8: u16,
    pub scale_q16: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefinementOutcome {
    Accepted(RefinedExtremum),
    Fallback(FallbackExtremum),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RefinementFailure {
    FirstDerivativeOverflow,
    SecondDerivativeOverflow,
    MixedDerivativeOverflow,
    RelocationOutOfBounds,
    IterationLimit,
    InterpolatedContrast,
    SpatialHessian,
}

impl RefinementFailure {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FirstDerivativeOverflow => "first_derivative_overflow",
            Self::SecondDerivativeOverflow => "second_derivative_overflow",
            Self::MixedDerivativeOverflow => "mixed_derivative_overflow",
            Self::RelocationOutOfBounds => "relocation_out_of_bounds",
            Self::IterationLimit => "iteration_limit",
            Self::InterpolatedContrast => "interpolated_contrast",
            Self::SpatialHessian => "spatial_hessian",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct DerivativeBlock {
    center_twice: i32,
    gx: i32,
    gy: i32,
    gs: i32,
    hxx: i32,
    hyy: i32,
    hss: i32,
    hxy: i32,
    hxs: i32,
    hys: i32,
    spatial_det: i64,
}

#[derive(Debug, Clone, Copy)]
struct Q12Offsets {
    dx: i32,
    dy: i32,
    ds: i32,
}

fn solve_q12_offsets(d: &DerivativeBlock) -> Q12Offsets {
    let hxx = i64::from(d.hxx);
    let hyy = i64::from(d.hyy);
    let hss = i64::from(d.hss);
    let hxy = i64::from(d.hxy);
    let hxs = i64::from(d.hxs);
    let hys = i64::from(d.hys);

    // Cofactors used verbatim by the vendor integer solve.
    let c00 = hyy * hss - hys * hys;
    let c01 = hys * hxs - hss * hxy;
    let c02 = hys * hxy - hyy * hxs;
    let c12 = hxs * hxy - hxx * hys;
    let spatial_det = hyy * hxx - hxy * hxy;

    let det = hxs * c02 + hxy * c01 + hxx * c00;

    if det == 0 {
        // Exact vendor behavior: a singular 3-D Hessian produces zero
        // displacement and proceeds to contrast/spatial-Hessian tests.
        return Q12Offsets {
            dx: 0,
            dy: 0,
            ds: 0,
        };
    }

    let gx = i64::from(d.gx);
    let gy = i64::from(d.gy);
    let gs = i64::from(d.gs);

    // -adj(H) * g
    let nx = -c00 * gx - c01 * gy - c02 * gs;
    let ny = -c01 * gx - (hxx * hss - hxs * hxs) * gy - c12 * gs;
    let ns = -c02 * gx - c12 * gy - spatial_det * gs;

    Q12Offsets {
        dx: guarded_q12_div(nx, det),
        dy: guarded_q12_div(ny, det),
        ds: guarded_q12_div(ns, det),
    }
}

/// Reproduce the vendor's overflow-guarded signed Q12 division.
///
/// It compares numerator/determinant bit lengths, right-shifts both operands
/// when necessary to keep the subsequent <<12 signed division safe, and uses
/// signed integer division (truncation toward zero).
fn guarded_q12_div(numerator: i64, determinant: i64) -> i32 {
    debug_assert_ne!(determinant, 0);

    let det_bits = bit_length_plus_one(determinant);
    let num_bits = bit_length_plus_one(numerator);

    if num_bits - det_bits > 8 {
        return GF3258_INVALID_OFFSET_Q12;
    }

    let mut n = numerator;
    let mut d = determinant;

    if num_bits > 32 && num_bits >= det_bits {
        let shift = (num_bits - 32) as u32;
        n >>= shift;
        d >>= shift;
    } else if num_bits < det_bits && det_bits > 32 {
        let shift = (det_bits - 32) as u32;
        n >>= shift;
        d >>= shift;
    }

    ((n << 12) / d) as i32
}

/// Vendor bit-count loop starts at one, then increments once per nonzero bit.
/// Therefore this is conventional bit_length(abs(value)) + 1.
fn bit_length_plus_one(value: i64) -> i32 {
    let mut magnitude = abs_i64(value);
    let mut count = 1i32;
    while magnitude != 0 {
        count += 1;
        magnitude >>= 1;
    }
    count
}

fn q12_is_settled(value: i32) -> bool {
    (-GF3258_SETTLED_Q12..=GF3258_SETTLED_Q12).contains(&value)
}

/// Q12 -> integer relocation used by FUN_001c0910:
/// nearest integer, exact half away from zero.
fn q12_round_sample(value: i32) -> i32 {
    if value < 0 {
        let magnitude = value.wrapping_neg();
        -((magnitude >> 12) + if (magnitude & 0x800) != 0 { 1 } else { 0 })
    } else {
        (value >> 12) + if (value & 0x800) != 0 { 1 } else { 0 }
    }
}

/// FUN_001b8f80: signed Q16 2^x approximation used by GF3258 scale conversion.
///
/// The fractional part is synthesized greedily as products of
/// (1 + 2^-k), using the exact recovered Q16 log2 thresholds.
pub fn exp2_q16(x_q16: i32) -> i32 {
    // FUN_001b8f80 first works on |x|. For the GF3258 detector scale
    // domain this magnitude is small and non-negative after wrapping_abs().
    let magnitude = x_q16.wrapping_abs();
    let integer = magnitude >> 16;
    let mut fraction = magnitude & 0xffff;

    // Important vendor ordering: apply the integer power-of-two scaling
    // BEFORE the fractional greedy products. Moving this shift after the loop
    // changes low bits because every `value >> k` truncates independently.
    let mut value = 1i64 << 16;
    if integer > 0 {
        value <<= integer as u32;
    }

    for (index, &threshold) in EXP2_LOG_STEPS_Q16.iter().enumerate() {
        if fraction >= threshold {
            fraction -= threshold;
            value += value >> (index + 1);
        }
    }

    if x_q16 > 0 {
        value as i32
    } else {
        // Zero and negative inputs take the reciprocal path. The assembly
        // performs unsigned DIV of 0x1_0000_0000 by the positive Q16 value.
        ((1u64 << 32) / (value as u64)) as i32
    }
}

fn fallback_scale_q16(level: u8) -> i32 {
    // GF3258 fallback record:
    // FUN_001b8f80((level << 16) / 6), then *0x13333 >>16.
    let exponent = ((i32::from(level)) << 16) / 6;
    let base = exp2_q16(exponent);
    (((base as u32 as u64) * 0x13333u64) >> 16) as i32
}

fn abs_i64(value: i64) -> u64 {
    if value < 0 {
        value.wrapping_neg() as u64
    } else {
        value as u64
    }
}

fn all_neighbors_at_least(
    center: i32,
    prev: &[i32],
    cur: &[i32],
    next: &[i32],
    x: usize,
    y: usize,
) -> bool {
    for yy in (y - 1)..=(y + 1) {
        for xx in (x - 1)..=(x + 1) {
            let i = yy * GF3258_WIDTH + xx;
            if prev[i] < center || next[i] < center {
                return false;
            }
            if (xx != x || yy != y) && cur[i] < center {
                return false;
            }
        }
    }
    true
}

fn all_neighbors_at_most(
    center: i32,
    prev: &[i32],
    cur: &[i32],
    next: &[i32],
    x: usize,
    y: usize,
) -> bool {
    for yy in (y - 1)..=(y + 1) {
        for xx in (x - 1)..=(x + 1) {
            let i = yy * GF3258_WIDTH + xx;
            if prev[i] > center || next[i] > center {
                return false;
            }
            if (xx != x || yy != y) && cur[i] > center {
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovered_kernel_records_are_exact() {
        assert_eq!(GAUSS_300.iter().sum::<i32>(), 65536);
        assert_eq!(GAUSS_301.iter().sum::<i32>(), 65536);
        assert_eq!(GAUSS_302.iter().sum::<i32>(), 65536);
        assert_eq!(GAUSS_303.iter().sum::<i32>(), 65536);
        assert_eq!(GAUSS_304.iter().sum::<i32>(), 65537);
        assert_eq!(GAUSS_305.iter().sum::<i32>(), 65536);
        assert_eq!(GAUSS_306.iter().sum::<i32>(), 65536);
        assert_eq!(GAUSS_307.iter().sum::<i32>(), 65539);
        assert_eq!(GAUSS_308.iter().sum::<i32>(), 65536);
    }

    #[test]
    fn scale_space_has_nine_levels_and_eight_dogs() {
        let image = vec![127u8; GF3258_PIXELS];
        let scale = Gf3258ScaleSpace::build(&image).unwrap();
        assert_eq!(scale.levels().len(), 9);
        assert_eq!(scale.dogs().len(), 8);
    }

    #[test]
    fn constant_image_has_no_raw_extrema() {
        let image = vec![127u8; GF3258_PIXELS];
        let scale = Gf3258ScaleSpace::build(&image).unwrap();
        assert!(scale.raw_extrema().is_empty());
    }

    #[test]
    fn q12_relocation_rounds_half_away_from_zero() {
        assert_eq!(q12_round_sample(0x7ff), 0);
        assert_eq!(q12_round_sample(0x800), 1);
        assert_eq!(q12_round_sample(0x1800), 2);
        assert_eq!(q12_round_sample(-0x7ff), 0);
        assert_eq!(q12_round_sample(-0x800), -1);
        assert_eq!(q12_round_sample(-0x1800), -2);
    }

    #[test]
    fn exp2_q16_has_exact_integer_anchor_points() {
        assert_eq!(exp2_q16(0), 0x10000);
        assert_eq!(exp2_q16(0x10000), 0x20000);
        assert_eq!(exp2_q16(-0x10000), 0x8000);
    }

    #[test]
    fn exp2_q16_matches_observed_vendor_refinement_scales() {
        // First accepted candidate: level 6, ds_q12 = 126.
        assert_eq!(exp2_q16(98_808), 186_353);

        // Second accepted candidate: level 5, ds_q12 = -1551.
        assert_eq!(exp2_q16(75_716), 145_972);
    }
}
