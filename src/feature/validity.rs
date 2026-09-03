//! Enrollment-validity generation for GF3258.
//!
//! This module preserves the recovered `FUN_001bd720` 80x64 validity-mask
//! producer and the `FUN_001a8200` 20x16 logical reduction used by the
//! enrollment pipeline. Arithmetic, thresholds, reflection behavior, and
//! strict comparisons intentionally mirror the vendor implementation.

use super::filter::{reflect101, separable_q16_reflect101};
use super::{FeatureError, GF3258_HEIGHT, GF3258_PIXELS, GF3258_WIDTH};

// FUN_001bd720 validity-mask producer used by c2d40 before enrollment packing.
// a4840 mode 7 record at DAT_00273dc0: five taps summing exactly to Q16 unity.
pub const GF3258_BD720_MODE7_KERNEL: [i32; 5] = [3_571, 16_004, 26_386, 16_004, 3_571];
pub const GF3258_BD720_BOX_RADIUS: usize = 7;
pub const GF3258_BD720_BOX_RECIP_Q16: i32 = 291; // floor(65536 / (15*15))
pub const GF3258_BD720_THRESHOLD: u16 = 0x6e;
pub const GF3258_BD720_REVISION: &str = "gf3258-bd720-v1";

// FUN_001a8200 GF3258 path: reduce the 80x64 bd720 mask to the logical
// 20x16 validity grid that exists before FUN_001a7eb0 serializes Feature+0x28.
pub const GF3258_A8200_BLOCK: usize = 4;
pub const GF3258_A8200_WIDTH: usize = GF3258_WIDTH / GF3258_A8200_BLOCK;
pub const GF3258_A8200_HEIGHT: usize = GF3258_HEIGHT / GF3258_A8200_BLOCK;
pub const GF3258_A8200_CELLS: usize = GF3258_A8200_WIDTH * GF3258_A8200_HEIGHT;
pub const GF3258_A8200_REVISION: &str = "gf3258-a8200-logical-v1";

// -----------------------------------------------------------------------------
// FUN_001bd720: c2d40 local_2b8 -> 80x64 binary enrollment-validity source
// -----------------------------------------------------------------------------

/// Exact GF3258 result for FUN_001bd720(local_2b8, local_298, 1, 0x6e, 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gf3258Bd720Validity {
    /// local_298: one byte per 80x64 source pixel, exactly 0 or 1.
    pub mask_u8: Vec<u8>,
    /// Number of pixels for which the post-smoothed strength is strictly > 110.
    pub selected_pixels: usize,
    /// Vendor fixed-point selected-area fraction: floor((selected << 16) / 5120).
    pub coverage_q16: u32,
}

/// FUN_001bd720's Sobel pair after mode-7 prefiltering.
///
/// Gx uses the centered horizontal derivative and vertical [1,2,1] smoothing.
/// The left/right output columns are forced to zero; top/bottom sampling uses
/// reflect101, matching bd720's two padded derivative rows.
///
/// Gy uses the centered vertical derivative and horizontal [1,2,1] smoothing.
/// The top/bottom output rows are forced to zero; left/right sampling uses
/// reflect101, matching FUN_001bd5c0's two padded derivative columns.
fn gf3258_bd720_sobel(filtered_u8: &[u8]) -> (Vec<i16>, Vec<i16>) {
    debug_assert_eq!(filtered_u8.len(), GF3258_PIXELS);

    let mut gx = vec![0i16; GF3258_PIXELS];
    let mut gy = vec![0i16; GF3258_PIXELS];

    // Horizontal derivative, then vertical [1,2,1]. x=0 and x=w-1 stay zero.
    for y in 0..GF3258_HEIGHT {
        let ym1 = reflect101(y as isize - 1, GF3258_HEIGHT);
        let yp1 = reflect101(y as isize + 1, GF3258_HEIGHT);
        for x in 1..(GF3258_WIDTH - 1) {
            let dx_m1 = i16::from(filtered_u8[ym1 * GF3258_WIDTH + (x + 1)])
                - i16::from(filtered_u8[ym1 * GF3258_WIDTH + (x - 1)]);
            let dx_0 = i16::from(filtered_u8[y * GF3258_WIDTH + (x + 1)])
                - i16::from(filtered_u8[y * GF3258_WIDTH + (x - 1)]);
            let dx_p1 = i16::from(filtered_u8[yp1 * GF3258_WIDTH + (x + 1)])
                - i16::from(filtered_u8[yp1 * GF3258_WIDTH + (x - 1)]);

            gx[y * GF3258_WIDTH + x] = dx_m1 + dx_0 * 2 + dx_p1;
        }
    }

    // Vertical derivative, then horizontal [1,2,1]. y=0 and y=h-1 stay zero.
    for y in 1..(GF3258_HEIGHT - 1) {
        for x in 0..GF3258_WIDTH {
            let xm1 = reflect101(x as isize - 1, GF3258_WIDTH);
            let xp1 = reflect101(x as isize + 1, GF3258_WIDTH);

            let dy_m1 = i16::from(filtered_u8[(y + 1) * GF3258_WIDTH + xm1])
                - i16::from(filtered_u8[(y - 1) * GF3258_WIDTH + xm1]);
            let dy_0 = i16::from(filtered_u8[(y + 1) * GF3258_WIDTH + x])
                - i16::from(filtered_u8[(y - 1) * GF3258_WIDTH + x]);
            let dy_p1 = i16::from(filtered_u8[(y + 1) * GF3258_WIDTH + xp1])
                - i16::from(filtered_u8[(y - 1) * GF3258_WIDTH + xp1]);

            gy[y * GF3258_WIDTH + x] = dy_m1 + dy_0 * 2 + dy_p1;
        }
    }

    (gx, gy)
}

/// Exact FUN_001a61a0(..., 7, 7) operation for bd720's nonnegative strength map.
///
/// The vendor constructs reflect101 padding and an i32 integral image. For the
/// fixed GF3258 7/7 radii this is exactly a 15x15 reflected window sum followed
/// by multiplication by floor(65536/225)=291 and a Q16 truncating shift.
fn gf3258_bd720_box15_q16(strength: &[u16]) -> Vec<u16> {
    debug_assert_eq!(strength.len(), GF3258_PIXELS);

    let radius = GF3258_BD720_BOX_RADIUS as isize;
    let mut out = vec![0u16; GF3258_PIXELS];

    for y in 0..GF3258_HEIGHT {
        for x in 0..GF3258_WIDTH {
            let mut sum = 0i32;
            for dy in -radius..=radius {
                let sy = reflect101(y as isize + dy, GF3258_HEIGHT);
                for dx in -radius..=radius {
                    let sx = reflect101(x as isize + dx, GF3258_WIDTH);
                    sum += i32::from(strength[sy * GF3258_WIDTH + sx]);
                }
            }

            out[y * GF3258_WIDTH + x] = ((sum * GF3258_BD720_BOX_RECIP_Q16) >> 16) as u16;
        }
    }

    out
}

/// Exact normal-GF3258 validity-source producer used by c2d40:
///
///   local_2b8 u8
///     -> bf3f0: u16 = u8 << 8
///     -> a4840 mode 7, reflect101, Q16 truncation after each 1-D pass
///     -> bf3b0: u8 = high byte
///     -> Sobel Gx/Gy
///     -> abs(Gx)/2 + abs(Gy)/2 (two independent integer divisions)
///     -> a61a0 radii 7,7 == 15x15 reflect101 box, *291 >> 16
///     -> local_298[i] = 1 iff value > 0x6e, otherwise 0.
fn gf3258_bd720_smoothed_strength(source_u8: &[u8]) -> Result<Vec<u16>, FeatureError> {
    if source_u8.len() != GF3258_PIXELS {
        return Err(FeatureError::UnexpectedPixelCount {
            expected: GF3258_PIXELS,
            actual: source_u8.len(),
        });
    }

    // bf3f0: exact unsigned-byte to Q8-u16 conversion.
    let source_q8: Vec<u16> = source_u8
        .iter()
        .map(|&value| u16::from(value) << 8)
        .collect();

    // a4840 mode 7 + bf3b0 high-byte conversion.
    let filtered_q8 = separable_q16_reflect101(&source_q8, &GF3258_BD720_MODE7_KERNEL);
    let filtered_u8: Vec<u8> = filtered_q8
        .into_iter()
        .map(|value| (value >> 8) as u8)
        .collect();

    let (gx, gy) = gf3258_bd720_sobel(&filtered_u8);

    let mut strength = vec![0u16; GF3258_PIXELS];
    for i in 0..GF3258_PIXELS {
        let ax = i32::from(gx[i]).abs();
        let ay = i32::from(gy[i]).abs();
        // Preserve bd720's two independent signed-C divisions by 2.
        strength[i] = (ax / 2 + ay / 2) as u16;
    }

    Ok(gf3258_bd720_box15_q16(&strength))
}

/// Return bd720's selected-area fraction for an explicit strict threshold.
///
/// This is shared by the enrollment-validity path (threshold 110) and the
/// capture-quality path (threshold 120). The filtering and strength pipeline
/// is identical; only the final strict comparison differs.
pub(super) fn gf3258_bd720_coverage_q16_with_threshold(
    source_u8: &[u8],
    threshold: u16,
) -> Result<i32, FeatureError> {
    let smoothed = gf3258_bd720_smoothed_strength(source_u8)?;
    let selected = smoothed.iter().filter(|&&value| value > threshold).count() as i32;

    Ok((selected * 65_536) / GF3258_PIXELS as i32)
}

pub fn gf3258_bd720_validity(source_u8: &[u8]) -> Result<Gf3258Bd720Validity, FeatureError> {
    let smoothed = gf3258_bd720_smoothed_strength(source_u8)?;
    let mut mask_u8 = vec![0u8; GF3258_PIXELS];
    let mut selected_pixels = 0usize;

    for (dst, &value) in mask_u8.iter_mut().zip(smoothed.iter()) {
        if value > GF3258_BD720_THRESHOLD {
            *dst = 1;
            selected_pixels += 1;
        }
    }

    let coverage_q16 = (((selected_pixels as u64) << 16) / GF3258_PIXELS as u64) as u32;

    Ok(Gf3258Bd720Validity {
        mask_u8,
        selected_pixels,
        coverage_q16,
    })
}

// -----------------------------------------------------------------------------
// FUN_001a8200: local_298 80x64 -> logical Feature+0x28 validity 20x16
// -----------------------------------------------------------------------------

/// GF3258-relevant logical output of FUN_001a8200 before FUN_001a7eb0
/// serializes it into the vendor Feature+0x28 storage representation.
///
/// GF3258 dimensions are exactly divisible by four, so none of a8200's
/// right/bottom partial-block branches are reachable for this sensor.
pub fn gf3258_a8200_quarter_validity(
    local_298: &[u8],
) -> Result<[u8; GF3258_A8200_CELLS], FeatureError> {
    if local_298.len() != GF3258_PIXELS {
        return Err(FeatureError::UnexpectedPixelCount {
            expected: GF3258_PIXELS,
            actual: local_298.len(),
        });
    }

    let mut out = [0u8; GF3258_A8200_CELLS];

    for qy in 0..GF3258_A8200_HEIGHT {
        for qx in 0..GF3258_A8200_WIDTH {
            let x0 = qx * GF3258_A8200_BLOCK;
            let y0 = qy * GF3258_A8200_BLOCK;
            let mut sum = 0u32;

            for dy in 0..GF3258_A8200_BLOCK {
                let row = (y0 + dy) * GF3258_WIDTH + x0;
                for dx in 0..GF3258_A8200_BLOCK {
                    // Preserve a8200 literally: it sums byte values.  On the
                    // c2d40 path bd720 has already proven these are binary 0/1.
                    sum = sum.wrapping_add(u32::from(local_298[row + dx]));
                }
            }

            // Vendor predicate: 0x0f < sum * 2.  For the proven binary bd720
            // input this is exactly "at least 8 of the 16 source pixels".
            if 0x0f < sum.wrapping_mul(2) {
                out[qy * GF3258_A8200_WIDTH + qx] = 1;
            }
        }
    }

    Ok(out)
}

/// Complete GF3258 c2d40 validity source used by standalone enrollment:
/// local_2b8 -> bd720 local_298 -> a8200 logical 20x16 quarter validity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gf3258EnrollmentValidity {
    pub bd720: Gf3258Bd720Validity,
    pub quarter_validity: [u8; GF3258_A8200_CELLS],
    pub quarter_selected_cells: usize,
}

pub fn gf3258_enrollment_validity_from_c2d40_source(
    source_u8: &[u8],
) -> Result<Gf3258EnrollmentValidity, FeatureError> {
    let bd720 = gf3258_bd720_validity(source_u8)?;
    let quarter_validity = gf3258_a8200_quarter_validity(&bd720.mask_u8)?;
    let quarter_selected_cells = quarter_validity.iter().filter(|&&value| value != 0).count();

    Ok(Gf3258EnrollmentValidity {
        bd720,
        quarter_validity,
        quarter_selected_cells,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bd720_static_constants_match_vendor_records() {
        assert_eq!(
            GF3258_BD720_MODE7_KERNEL,
            [3_571, 16_004, 26_386, 16_004, 3_571]
        );
        assert_eq!(GF3258_BD720_MODE7_KERNEL.iter().sum::<i32>(), 65_536);
        assert_eq!(GF3258_BD720_BOX_RADIUS, 7);
        assert_eq!(GF3258_BD720_BOX_RECIP_Q16, 291);
        assert_eq!(GF3258_BD720_THRESHOLD, 110);
    }

    #[test]
    fn bd720_constant_image_has_zero_validity() {
        let image = vec![127u8; GF3258_PIXELS];
        let result = gf3258_bd720_validity(&image).unwrap();
        assert!(result.mask_u8.iter().all(|&value| value == 0));
        assert_eq!(result.selected_pixels, 0);
        assert_eq!(result.coverage_q16, 0);
    }

    #[test]
    fn bd720_box_filter_preserves_vendor_q16_reciprocal_truncation() {
        let strength = vec![225u16; GF3258_PIXELS];
        let filtered = gf3258_bd720_box15_q16(&strength);

        // Vendor uses (sum * floor(65536/225)) >> 16, not sum/225.
        // 15*15*225 = 50625; (50625*291)>>16 = 224.
        assert!(filtered.iter().all(|&value| value == 224));
    }

    #[test]
    fn bd720_rejects_bad_source_length() {
        let short = vec![0u8; GF3258_PIXELS - 1];
        assert!(matches!(
            gf3258_bd720_validity(&short),
            Err(FeatureError::UnexpectedPixelCount { .. })
        ));
    }

    #[test]
    fn a8200_all_zero_and_all_one_masks_are_exact() {
        let zeros = vec![0u8; GF3258_PIXELS];
        let zero_q = gf3258_a8200_quarter_validity(&zeros).unwrap();
        assert!(zero_q.iter().all(|&v| v == 0));

        let ones = vec![1u8; GF3258_PIXELS];
        let one_q = gf3258_a8200_quarter_validity(&ones).unwrap();
        assert!(one_q.iter().all(|&v| v == 1));
    }

    #[test]
    fn a8200_binary_threshold_accepts_exactly_eight_of_sixteen() {
        let mut seven = vec![0u8; GF3258_PIXELS];
        for i in 0..7 {
            let y = i / 4;
            let x = i % 4;
            seven[y * GF3258_WIDTH + x] = 1;
        }
        assert_eq!(gf3258_a8200_quarter_validity(&seven).unwrap()[0], 0);

        seven[GF3258_WIDTH + 3] = 1;
        assert_eq!(gf3258_a8200_quarter_validity(&seven).unwrap()[0], 1);
    }

    #[test]
    fn a8200_output_geometry_is_20_by_16() {
        assert_eq!(GF3258_A8200_WIDTH, 20);
        assert_eq!(GF3258_A8200_HEIGHT, 16);
        assert_eq!(GF3258_A8200_CELLS, 320);
    }
}
