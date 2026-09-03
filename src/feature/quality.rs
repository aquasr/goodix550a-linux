//! Capture-quality computation for GF3258.
//!
//! This module is the single implementation of the recovered quality path used
//! to materialize Feature+0x10c / persisted b8 and Feature+0x110 / persisted b9.
//! It preserves the integer arithmetic and strict comparisons recovered from
//! bcac0, bbab0, bbd00, bc7c0, bc890, bcbc0, and the threshold-120 bd720 path.

use super::validity::gf3258_bd720_coverage_q16_with_threshold;
use super::{FeatureError, GF3258_HEIGHT, GF3258_PIXELS, GF3258_WIDTH};

const GF3258_CAPTURE_COVERAGE_THRESHOLD: u16 = 120;
const GF3258_QUALITY_WINDOW_RADIUS: usize = 9;
const GF3258_QUALITY_WINDOW_STEP: usize = 6;
const GF3258_QUALITY_MIN_MASK_PIXELS: i32 = 180;
const GF3258_QUALITY_MIN_TENSOR_PIXELS: i32 = 60;
const GF3258_QUALITY_STRENGTH_THRESHOLD: i32 = 25;
const GF3258_RAW_QUALITY_CLASSIFIER_THRESHOLD: i32 = 70;
const GF3258_RAW_QUALITY_ACCEPT_THRESHOLD: i32 = 45;
const GF3258_CLASS4_REFERENCE_PERCENT: i32 = 35;
const GF3258_MASK_COVERAGE_LOSS_Q16: i32 = 0x3333;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Gf3258CaptureQuality {
    pub raw_quality: i32,
    pub quality: i32,
    pub coverage: i32,
    pub mask_coverage_q16: i32,
    pub coverage_q16: i32,
    pub class4_percent: Option<i32>,
}

impl Gf3258CaptureQuality {
    #[inline]
    pub(crate) fn accepted_for_enrollment(self) -> bool {
        self.raw_quality >= GF3258_RAW_QUALITY_ACCEPT_THRESHOLD
    }

    #[inline]
    pub(crate) fn raw_quality_rejected(self) -> bool {
        !self.accepted_for_enrollment()
    }
}

fn gf3258_quality_mask(source_u8: &[u8]) -> Vec<u8> {
    debug_assert_eq!(source_u8.len(), GF3258_PIXELS);

    let initial: Vec<u8> = source_u8
        .iter()
        .map(|&value| if value == 0xff { 0x00 } else { 0xff })
        .collect();

    const OFFSETS: [(isize, isize); 9] = [
        (0, 0),
        (-1, 0),
        (1, 0),
        (-2, 0),
        (2, 0),
        (0, -1),
        (0, 1),
        (0, -2),
        (0, 2),
    ];

    let mut output = vec![0u8; GF3258_PIXELS];

    for y in 0..GF3258_HEIGHT {
        for x in 0..GF3258_WIDTH {
            let mut active = false;

            for &(dx, dy) in &OFFSETS {
                let nx = x as isize + dx;

                let ny = y as isize + dy;

                if nx < 0 || nx >= GF3258_WIDTH as isize || ny < 0 || ny >= GF3258_HEIGHT as isize {
                    continue;
                }

                let index = ny as usize * GF3258_WIDTH + nx as usize;

                if initial[index] != 0 {
                    active = true;
                    break;
                }
            }

            if active {
                output[y * GF3258_WIDTH + x] = 0xff;
            }
        }
    }

    output
}

fn gf3258_quality_planes(source_u8: &[u8], mask: &[u8]) -> (Vec<i32>, Vec<i32>, Vec<i32>) {
    debug_assert_eq!(source_u8.len(), GF3258_PIXELS);
    debug_assert_eq!(mask.len(), GF3258_PIXELS);

    let mut dx_plane = vec![0i32; GF3258_PIXELS];

    let mut dy_plane = vec![0i32; GF3258_PIXELS];

    let mut strength = vec![0i32; GF3258_PIXELS];

    for y in 1..(GF3258_HEIGHT - 1) {
        for x in 1..(GF3258_WIDTH - 1) {
            let mut all_nonzero = true;

            'mask_scan: for dy in -1isize..=1 {
                for dx in -1isize..=1 {
                    let nx = (x as isize + dx) as usize;

                    let ny = (y as isize + dy) as usize;

                    if mask[ny * GF3258_WIDTH + nx] == 0 {
                        all_nonzero = false;
                        break 'mask_scan;
                    }
                }
            }

            if !all_nonzero {
                continue;
            }

            let index = y * GF3258_WIDTH + x;

            let dx = i32::from(source_u8[index + 1]) - i32::from(source_u8[index - 1]);

            let dy = i32::from(source_u8[(y + 1) * GF3258_WIDTH + x])
                - i32::from(source_u8[(y - 1) * GF3258_WIDTH + x]);

            dx_plane[index] = dx;
            dy_plane[index] = dy;
            strength[index] = dx * dx + dy * dy;
        }
    }

    (dx_plane, dy_plane, strength)
}

// The vendor histogram cutoff scans exact integer score order from 0 through 100.
#[allow(clippy::needless_range_loop)]
fn gf3258_raw_quality(source_u8: &[u8], mask: &mut [u8]) -> i32 {
    debug_assert_eq!(source_u8.len(), GF3258_PIXELS);
    debug_assert_eq!(mask.len(), GF3258_PIXELS);

    let (dx_plane, dy_plane, strength) = gf3258_quality_planes(source_u8, mask);

    // center index + score.
    // score == -1 means the mask-support gate failed.
    let mut blocks: Vec<(usize, i32)> = Vec::with_capacity(88);

    let mut histogram = [0i32; 101];

    let mut sum_quality_q16 = 0i32;

    let mut valid_blocks = 0i32;

    let radius = GF3258_QUALITY_WINDOW_RADIUS;

    let mut center_y = radius;

    while center_y < GF3258_HEIGHT - radius {
        let mut center_x = radius;

        while center_x < GF3258_WIDTH - radius {
            let center = center_y * GF3258_WIDTH + center_x;

            if mask[center] != 0 {
                let mut mask_count = 0i32;

                for y in (center_y - radius)..=(center_y + radius) {
                    for x in (center_x - radius)..=(center_x + radius) {
                        if mask[y * GF3258_WIDTH + x] != 0 {
                            mask_count += 1;
                        }
                    }
                }

                if mask_count < GF3258_QUALITY_MIN_MASK_PIXELS {
                    blocks.push((center, -1));
                } else {
                    let mut count = 0i32;

                    let mut sum_xx = 0i32;

                    let mut sum_yy = 0i32;

                    let mut sum_xy = 0i32;

                    for y in (center_y - radius)..=(center_y + radius) {
                        for x in (center_x - radius)..=(center_x + radius) {
                            let index = y * GF3258_WIDTH + x;

                            if strength[index] >= GF3258_QUALITY_STRENGTH_THRESHOLD {
                                let dx = dx_plane[index];

                                let dy = dy_plane[index];

                                count += 1;
                                sum_xx += dx * dx;
                                sum_yy += dy * dy;
                                sum_xy += dy * dx;
                            }
                        }
                    }

                    let (quality_q16, score) = if count < GF3258_QUALITY_MIN_TENSOR_PIXELS {
                        (0i32, 0i32)
                    } else {
                        let half = count >> 1;

                        let a = i64::from((sum_xx + half) / count);

                        let b = i64::from((sum_yy + half) / count);

                        let c = i64::from((sum_xy + half) / count);

                        let mean = (a + b) / 2;

                        let determinant = a * b - c * c;

                        let mut determinant_q16 =
                            ((determinant * 65_536i64) / (mean * mean + 1)) as i32;

                        if determinant_q16 < 0 {
                            determinant_q16 = 0;
                        }

                        let mut q16 = 65_536i32 - determinant_q16;

                        if q16 < 0 {
                            q16 = 0;
                        }

                        let score = (q16 * 100) >> 16;

                        (q16, score)
                    };

                    debug_assert!((0..=100).contains(&score));

                    sum_quality_q16 += quality_q16;

                    valid_blocks += 1;

                    histogram[score as usize] += 1;

                    blocks.push((center, score));
                }
            }

            center_x += GF3258_QUALITY_WINDOW_STEP;
        }

        center_y += GF3258_QUALITY_WINDOW_STEP;
    }

    let raw_quality = if valid_blocks == 0 {
        0
    } else {
        let average_q16 = (sum_quality_q16 + (valid_blocks >> 1)) / valid_blocks;

        (average_q16 * 100) >> 16
    };

    // param_3 == 1 side effect:
    //
    // target = valid_blocks >> 1
    // cutoff = first score whose cumulative histogram >= target.
    let target = valid_blocks >> 1;

    let mut cumulative = 0i32;

    let mut cutoff = 0i32;

    for score in 0..=100usize {
        cumulative += histogram[score];
        cutoff = score as i32;

        if cumulative >= target {
            break;
        }
    }

    // Every selected block marks an 18x18 rectangle:
    //
    // x/y offsets -9 .. +8.
    //
    // The write is unconditional within the rectangle.
    for &(center, score) in &blocks {
        if score < 0 || score > cutoff {
            continue;
        }

        let center_y = center / GF3258_WIDTH;

        let center_x = center % GF3258_WIDTH;

        for dy in -9isize..9isize {
            for dx in -9isize..9isize {
                let x = (center_x as isize + dx) as usize;

                let y = (center_y as isize + dy) as usize;

                mask[y * GF3258_WIDTH + x] = 0x20;
            }
        }
    }

    // Final vendor rewrite.
    for value in mask.iter_mut() {
        *value = if *value == 0x20 { 0xff } else { 0x00 };
    }

    raw_quality
}

fn gf3258_class4_percent(source_u8: &[u8], mask: &[u8]) -> i32 {
    debug_assert_eq!(source_u8.len(), GF3258_PIXELS);
    debug_assert_eq!(mask.len(), GF3258_PIXELS);

    let mut labels = vec![9u8; GF3258_PIXELS];

    for y in 1..(GF3258_HEIGHT - 1) {
        for x in 1..(GF3258_WIDTH - 1) {
            let index = y * GF3258_WIDTH + x;

            if mask[index] == 0 {
                continue;
            }

            let center = i32::from(source_u8[index]);

            let neighbors = [
                (y - 1) * GF3258_WIDTH + (x - 1), // NW
                (y - 1) * GF3258_WIDTH + x,       // N
                (y - 1) * GF3258_WIDTH + (x + 1), // NE
                y * GF3258_WIDTH + (x + 1),       // E
                (y + 1) * GF3258_WIDTH + (x + 1), // SE
                (y + 1) * GF3258_WIDTH + x,       // S
                (y + 1) * GF3258_WIDTH + (x - 1), // SW
                y * GF3258_WIDTH + (x - 1),       // W
            ];

            let mut bits = [0i32; 8];

            for (bit, &neighbor_index) in bits.iter_mut().zip(neighbors.iter()) {
                let difference = i32::from(source_u8[neighbor_index]) - center;

                *bit = if difference > 4 { 1 } else { 0 };
            }

            let mut transitions = 0i32;

            for bit_index in 0..8usize {
                let previous = if bit_index == 0 { 7 } else { bit_index - 1 };

                transitions += (bits[bit_index] - bits[previous]).abs();
            }

            if transitions < 3 {
                let label: i32 = bits.iter().sum();

                labels[index] = label as u8;
            }
        }
    }

    // Exact bc760 call:
    //
    //     ECX = 10
    //
    // Therefore the sentinel label 9 has a valid histogram slot.
    let mut histogram = [0i32; 10];

    for index in 0..GF3258_PIXELS {
        if mask[index] != 0 {
            let label = usize::from(labels[index]);

            histogram[label] += 1;
        }
    }

    // Exact bc7c0 loop:
    // sum only bins 0..8.
    let total: i32 = histogram[..9].iter().sum();

    if total == 0 {
        0
    } else {
        (histogram[4] * 100) / total
    }
}

pub(crate) fn gf3258_capture_quality(
    source_u8: &[u8],
) -> Result<Gf3258CaptureQuality, FeatureError> {
    if source_u8.len() != GF3258_PIXELS {
        return Err(FeatureError::UnexpectedPixelCount {
            expected: GF3258_PIXELS,
            actual: source_u8.len(),
        });
    }

    // bcac0 + a6e70 result.
    let mut quality_mask = gf3258_quality_mask(source_u8);

    // bc890 computes this before bbd00 mutates its private mask copy.
    let mask_nonzero = quality_mask.iter().filter(|&&value| value != 0).count() as i32;

    let mask_coverage_q16 = (mask_nonzero * 65_536) / GF3258_PIXELS as i32;

    // bbd00 mutates quality_mask as a required side effect.
    let raw_quality = gf3258_raw_quality(source_u8, &mut quality_mask);

    let mut quality = raw_quality;

    let mut class4_percent = None;

    // bc890:
    // raw quality below 70 enters bc7c0.
    if raw_quality < GF3258_RAW_QUALITY_CLASSIFIER_THRESHOLD {
        let percent = gf3258_class4_percent(source_u8, &quality_mask);

        class4_percent = Some(percent);

        if percent < GF3258_CLASS4_REFERENCE_PERCENT {
            let scale_q8 = (percent << 8) / GF3258_CLASS4_REFERENCE_PERCENT;

            // Preserve both independent Q8 truncations.
            quality = (quality * scale_q8) >> 8;

            quality = (quality * scale_q8) >> 8;
        }

        // GF3258 param_10 == 0, so the separate >=25 additive branch
        // has no numeric effect.
    }

    // Independent bd720 coverage with strict threshold 120.
    let coverage_q16 =
        gf3258_bd720_coverage_q16_with_threshold(source_u8, GF3258_CAPTURE_COVERAGE_THRESHOLD)?;

    // bc890 coverage-loss correction.
    if mask_coverage_q16 - coverage_q16 > GF3258_MASK_COVERAGE_LOSS_Q16 {
        // Preserve both independent integer divisions.
        quality = (quality * coverage_q16) / mask_coverage_q16;

        quality = (quality * coverage_q16) / mask_coverage_q16;
    }

    // Preserve Q16->percent as a separate truncation stage.
    let mut coverage = (coverage_q16 * 100) >> 16;

    // bcbc0 GF3258 / type 0x18.
    if quality > 0 {
        quality += 7;
    }

    if coverage < 50 {
        quality = (coverage * quality * coverage) / 2500;
    }

    quality = quality.clamp(0, 100);

    coverage = coverage.clamp(0, 100);

    // FUN_00163780 final rule.
    if coverage < 6 {
        quality = 0;
    }

    Ok(Gf3258CaptureQuality {
        raw_quality,
        quality,
        coverage,
        mask_coverage_q16,
        coverage_q16,
        class4_percent,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::gf3258_bd720_validity;

    #[test]
    fn threshold_110_duplicate_matches_existing_bd720() {
        let mut source = vec![0u8; GF3258_PIXELS];
        for y in 0..GF3258_HEIGHT {
            for x in 0..GF3258_WIDTH {
                source[y * GF3258_WIDTH + x] = ((x * 17 + y * 31) & 0xff) as u8;
            }
        }

        let canonical = gf3258_bd720_validity(&source).unwrap();
        let coverage = gf3258_bd720_coverage_q16_with_threshold(&source, 110).unwrap();
        assert_eq!(coverage, canonical.coverage_q16 as i32);
    }

    #[test]
    fn class4_is_four_contiguous_high_neighbors() {
        let mut source = vec![0u8; GF3258_PIXELS];
        let mut mask = vec![0u8; GF3258_PIXELS];
        let x = 20usize;
        let y = 20usize;
        let index = y * GF3258_WIDTH + x;
        mask[index] = 0xff;
        source[index] = 100;

        for (nx, ny) in [(x - 1, y - 1), (x, y - 1), (x + 1, y - 1), (x + 1, y)] {
            source[ny * GF3258_WIDTH + nx] = 110;
        }

        assert_eq!(gf3258_class4_percent(&source, &mask), 100);
    }

    #[test]
    fn all_white_image_has_zero_quality_and_coverage() {
        let source = vec![0xffu8; GF3258_PIXELS];
        let quality = gf3258_capture_quality(&source).unwrap();
        assert_eq!(quality.raw_quality, 0);
        assert_eq!(quality.quality, 0);
        assert_eq!(quality.coverage, 0);
        assert_eq!(quality.mask_coverage_q16, 0);
        assert_eq!(quality.coverage_q16, 0);
        assert_eq!(quality.class4_percent, Some(0));
        assert!(quality.raw_quality_rejected());
        assert!(!quality.accepted_for_enrollment());
    }
}
