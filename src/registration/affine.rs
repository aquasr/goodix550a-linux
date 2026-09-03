//! GF3258 fixed-point affine geometry primitives.
//!
//! This module owns the Q8 point/affine representation and the recovered
//! low-level transform arithmetic shared by enrollment registration and the
//! verification matcher. It intentionally contains no acceptance policy.

pub const GF3258_AFFINE_MIN_SCALE_SQUARED_Q16: i64 = 163i64 << 8;
pub const GF3258_AFFINE_MAX_SCALE_SQUARED_Q16: i64 = 401i64 << 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf3258PointQ8 {
    pub x: i32,
    pub y: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf3258AffineQ8 {
    pub a: i32,
    pub b: i32,
    pub tx: i32,
    pub c: i32,
    pub d: i32,
    pub ty: i32,
}

impl Gf3258AffineQ8 {
    pub const IDENTITY: Self = Self {
        a: 0x100,
        b: 0,
        tx: 0,
        c: 0,
        d: 0x100,
        ty: 0,
    };

    #[inline]
    pub fn as_array(self) -> [i32; 6] {
        [self.a, self.b, self.tx, self.c, self.d, self.ty]
    }

    /// FUN_001aea40 point evaluation: Q8 input -> Q8 output, no +0x80 rounding.
    #[inline]
    pub fn transform_q8(self, point: Gf3258PointQ8) -> Gf3258PointQ8 {
        let x = self
            .a
            .wrapping_mul(point.x)
            .wrapping_add(self.b.wrapping_mul(point.y));
        let y = self
            .c
            .wrapping_mul(point.x)
            .wrapping_add(self.d.wrapping_mul(point.y));
        Gf3258PointQ8 {
            x: (x >> 8).wrapping_add(self.tx),
            y: (y >> 8).wrapping_add(self.ty),
        }
    }

    /// FUN_001b3d10: integer-pixel input -> integer-pixel output with +0x80.
    #[inline]
    pub fn transform_integer_pixel(self, x: i32, y: i32) -> (i32, i32) {
        let out_x = self
            .a
            .wrapping_mul(x)
            .wrapping_add(self.b.wrapping_mul(y))
            .wrapping_add(self.tx)
            .wrapping_add(0x80)
            >> 8;
        let out_y = self
            .c
            .wrapping_mul(x)
            .wrapping_add(self.d.wrapping_mul(y))
            .wrapping_add(self.ty)
            .wrapping_add(0x80)
            >> 8;
        (out_x, out_y)
    }

    /// FUN_001c60c0. Singular transforms are copied unchanged by the vendor.
    pub fn inverse(self) -> Self {
        let det = self
            .a
            .wrapping_mul(self.d)
            .wrapping_sub(self.c.wrapping_mul(self.b));
        if det == 0 {
            return self;
        }

        let det64 = i64::from(det);
        let a = (i64::from(self.d) * 65_536 / det64) as i32;
        let b = (-i64::from(self.b) * 65_536 / det64) as i32;
        let c = (-i64::from(self.c) * 65_536 / det64) as i32;
        let d = (i64::from(self.a) * 65_536 / det64) as i32;
        let tx_num =
            (i64::from(self.b) * i64::from(self.ty) - i64::from(self.d) * i64::from(self.tx)) * 256;
        let ty_num =
            (i64::from(self.tx) * i64::from(self.c) - i64::from(self.a) * i64::from(self.ty)) * 256;

        Self {
            a,
            b,
            tx: (tx_num / det64) as i32,
            c,
            d,
            ty: (ty_num / det64) as i32,
        }
    }

    /// FUN_001c5960: self ∘ rhs, then FUN_001c58d0 rigid normalization.
    pub fn compose_and_normalize(self, rhs: Self) -> Self {
        let mut out = Self {
            a: self
                .a
                .wrapping_mul(rhs.a)
                .wrapping_add(self.b.wrapping_mul(rhs.c))
                >> 8,
            b: self
                .a
                .wrapping_mul(rhs.b)
                .wrapping_add(self.b.wrapping_mul(rhs.d))
                >> 8,
            tx: self.tx.wrapping_add(
                self.a
                    .wrapping_mul(rhs.tx)
                    .wrapping_add(self.b.wrapping_mul(rhs.ty))
                    >> 8,
            ),
            c: self
                .c
                .wrapping_mul(rhs.a)
                .wrapping_add(self.d.wrapping_mul(rhs.c))
                >> 8,
            d: self
                .c
                .wrapping_mul(rhs.b)
                .wrapping_add(self.d.wrapping_mul(rhs.d))
                >> 8,
            ty: self.ty.wrapping_add(
                self.c
                    .wrapping_mul(rhs.tx)
                    .wrapping_add(self.d.wrapping_mul(rhs.ty))
                    >> 8,
            ),
        };
        out.normalize_linear_to_rotation();
        out
    }

    /// FUN_001c58d0. Translation is intentionally preserved.
    pub fn normalize_linear_to_rotation(&mut self) {
        let m = self.a.wrapping_add(self.d) >> 1;
        let n = self.c.wrapping_sub(self.b) >> 1;
        let radius_sq = i64::from(m) * i64::from(m) + i64::from(n) * i64::from(n);
        let radius = integer_sqrt_u64(radius_sq as u64) as i32;

        if radius == 0 {
            self.a = 0x100;
            self.b = 0;
            self.c = 0;
            self.d = 0x100;
            return;
        }

        // C signed division truncates toward zero.  The +r/2 term is deliberately
        // asymmetric for negative m/n and must not be replaced by symmetric round().
        let qcos = m.wrapping_mul(256).wrapping_add(radius >> 1) / radius;
        let qneg_sin = (radius >> 1).wrapping_sub(n.wrapping_mul(256)) / radius;
        self.a = qcos;
        self.b = qneg_sin;
        self.c = qneg_sin.wrapping_neg();
        self.d = qcos;
    }
}

#[inline]
pub(super) fn wrapping_abs_i32(value: i32) -> i32 {
    let sign = value >> 31;
    (value ^ sign).wrapping_sub(sign)
}

pub(super) fn integer_sqrt_u64(value: u64) -> u64 {
    if value < 2 {
        return value;
    }
    let mut bit = 1u64 << 62;
    while bit > value {
        bit >>= 2;
    }
    let mut remainder = value;
    let mut result = 0u64;
    while bit != 0 {
        if remainder >= result + bit {
            remainder -= result + bit;
            result = (result >> 1) + bit;
        } else {
            result >>= 1;
        }
        bit >>= 2;
    }
    result
}

fn integer_sqrt_u128(value: u128) -> u128 {
    if value < 2 {
        return value;
    }
    let mut x = 1u128 << 126;
    while x > value {
        x >>= 2;
    }
    let mut remainder = value;
    let mut result = 0u128;
    while x != 0 {
        if remainder >= result + x {
            remainder -= result + x;
            result = (result >> 1) + x;
        } else {
            result >>= 1;
        }
        x >>= 2;
    }
    result
}

/// FUN_001c55f0: full affine estimate from three Q8 point pairs.
///
/// Linear coefficients are solved in Q10, then arithmetic-shifted to Q8.
/// Translation is computed from the *unquantized Q10* coefficients and only
/// then shifted back to Q8 spatial units.
pub fn gf3258_affine_from_three_points(
    source: [Gf3258PointQ8; 3],
    destination: [Gf3258PointQ8; 3],
) -> Gf3258AffineQ8 {
    let [p0, p1, p2] = source;
    let [q0, q1, q2] = destination;

    let x0 = i64::from(p0.x);
    let y0 = i64::from(p0.y);
    let x1 = i64::from(p1.x);
    let y1 = i64::from(p1.y);
    let x2 = i64::from(p2.x);
    let y2 = i64::from(p2.y);

    let determinant = x0 * (y1 - y2) + x1 * (y2 - y0) + x2 * (y0 - y1);

    let solve = |z0: i32, z1: i32, z2: i32, anchor: usize| -> (i64, i64, i32) {
        let source_x = [x0, x1, x2];
        let source_y = [y0, y1, y2];
        let target_q10 = [
            i64::from(z0) << 10,
            i64::from(z1) << 10,
            i64::from(z2) << 10,
        ];

        if determinant == 0 {
            let sentinel_q10 = i64::from(i32::MAX);
            let translation = (target_q10[anchor]
                - sentinel_q10 * source_x[anchor]
                - sentinel_q10 * source_y[anchor])
                >> 10;
            return (sentinel_q10, sentinel_q10, translation as i32);
        }

        let alpha =
            (target_q10[0] * (y1 - y2) + target_q10[1] * (y2 - y0) + target_q10[2] * (y0 - y1))
                / determinant;
        let beta =
            (target_q10[0] * (x2 - x1) + target_q10[1] * (x0 - x2) + target_q10[2] * (x1 - x0))
                / determinant;
        let translation =
            (target_q10[anchor] - alpha * source_x[anchor] - beta * source_y[anchor]) >> 10;
        (alpha, beta, translation as i32)
    };

    // Raw c55f0 anchors X translation at correspondence 0 and Y translation
    // at correspondence 2 after the Q10 coefficient divisions. The asymmetric
    // anchors are observable because the coefficients are integer-quantized.
    let (a_q10, b_q10, tx_q8) = solve(q0.x, q1.x, q2.x, 0);
    let (c_q10, d_q10, ty_q8) = solve(q0.y, q1.y, q2.y, 2);

    Gf3258AffineQ8 {
        a: (a_q10 >> 2) as i32,
        b: (b_q10 >> 2) as i32,
        tx: tx_q8,
        c: (c_q10 >> 2) as i32,
        d: (d_q10 >> 2) as i32,
        ty: ty_q8,
    }
}

/// FUN_001b3d50 with the GF3258 call thresholds (401, 163).
pub fn gf3258_affine_linear_part_is_valid(transform: Gf3258AffineQ8) -> bool {
    let a = i64::from(transform.a);
    let b = i64::from(transform.b);
    let c = i64::from(transform.c);
    let d = i64::from(transform.d);

    let n0 = a * a + b * b;
    let n1 = c * c + d * d;
    let dot = a * c + b * d;
    let sum = n0 + n1;
    if sum < 0 {
        return false;
    }

    let diff = i128::from(n0 - n1);
    let dot128 = i128::from(dot);
    let delta = (diff * diff + 4 * dot128 * dot128) as u128;
    let root = integer_sqrt_u128(delta) as i64;

    let lambda_min = (sum - root) >> 1;
    let lambda_max = (sum + root) >> 1;

    lambda_min > GF3258_AFFINE_MIN_SCALE_SQUARED_Q16
        && lambda_max < GF3258_AFFINE_MAX_SCALE_SQUARED_Q16
}

#[cfg(test)]
mod tests {
    use super::*;

    fn point(x: i32, y: i32) -> Gf3258PointQ8 {
        Gf3258PointQ8 { x, y }
    }

    #[test]
    fn three_point_affine_identity_is_exact() {
        let src = [
            point(0x100, 0x200),
            point(0x500, 0x200),
            point(0x100, 0x700),
        ];
        assert_eq!(
            gf3258_affine_from_three_points(src, src),
            Gf3258AffineQ8::IDENTITY
        );
    }

    #[test]
    fn three_point_affine_matches_vendor_asymmetric_translation_anchor() {
        let src = [point(8041, 6054), point(2881, 3250), point(6553, 11093)];
        let dst = [point(11844, 8238), point(19078, 11274), point(20181, 11971)];

        assert_eq!(
            gf3258_affine_from_three_points(src, dst),
            Gf3258AffineQ8 {
                a: -508,
                b: 273,
                tx: 21316,
                c: -219,
                d: 125,
                ty: 12147,
            }
        );
    }

    #[test]
    fn three_point_affine_translation_uses_q8_spatial_units() {
        let src = [
            point(0x100, 0x200),
            point(0x500, 0x200),
            point(0x100, 0x700),
        ];
        let dst = src.map(|p| point(p.x + 0x180, p.y - 0x80));
        let t = gf3258_affine_from_three_points(src, dst);
        assert_eq!(t.a, 0x100);
        assert_eq!(t.b, 0);
        assert_eq!(t.c, 0);
        assert_eq!(t.d, 0x100);
        assert_eq!(t.tx, 0x180);
        assert_eq!(t.ty, -0x80);
    }

    #[test]
    fn affine_validity_accepts_identity_and_rejects_large_scale() {
        assert!(gf3258_affine_linear_part_is_valid(Gf3258AffineQ8::IDENTITY));
        let too_large = Gf3258AffineQ8 {
            a: 0x180,
            d: 0x180,
            ..Gf3258AffineQ8::IDENTITY
        };
        assert!(!gf3258_affine_linear_part_is_valid(too_large));
    }

    #[test]
    fn transform_inverse_round_trip_is_identity_for_translation() {
        let t = Gf3258AffineQ8 {
            tx: 0x180,
            ty: -0x80,
            ..Gf3258AffineQ8::IDENTITY
        };
        let inv = t.inverse();
        let composed = t.compose_and_normalize(inv);
        assert_eq!(composed, Gf3258AffineQ8::IDENTITY);
    }
}
