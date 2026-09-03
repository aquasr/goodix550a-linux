use std::{error::Error, fmt};

use crate::image::{IMAGE_HEIGHT, IMAGE_WIDTH};

const PIXEL_COUNT: usize = IMAGE_WIDTH * IMAGE_HEIGHT;
const Q13_ONE: u16 = 0x2000;
const RAW_MAX: u16 = 0x0fff;

const VALID_LOW_EXCLUSIVE: u16 = 50;
const VALID_HIGH_EXCLUSIVE: u16 = 4050;
const VALID_BORDER: usize = 2;

const MASK_BASE_THRESHOLD: u16 = 120;
const MASK_SPARSE_LIMIT: usize = IMAGE_WIDTH * 10;

const ACTIVE_DIFFERENCE_THRESHOLD: u16 = 100;
const ACTIVE_REQUIRED_STRICT: usize = (PIXEL_COUNT * 205) >> 8; // 4100; vendor uses >.
const GF3258_MEDIAN_DEVIATION: u16 = 800;

const LOCAL_BACKGROUND_RADIUS: usize = 5;
const LOCAL_BACKGROUND_CENTER: i32 = 3000;
const LOCAL_EXTREMA_RADIUS: usize = 5;
const LOW_DYNAMIC_RANGE_THRESHOLD: u16 = 50;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreprocessError {
    UnexpectedPixelCount {
        expected: usize,
        actual: usize,
    },
    InvalidRawFrame {
        good_pixels: usize,
        tested_pixels: usize,
    },
}

impl fmt::Display for PreprocessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedPixelCount { expected, actual } => write!(
                f,
                "unexpected GF3258 pixel count: expected {expected}, received {actual}",
            ),
            Self::InvalidRawFrame {
                good_pixels,
                tested_pixels,
            } => write!(
                f,
                "GF3258 raw-frame validation failed: {good_pixels}/{tested_pixels} central pixels satisfy 50 < v < 4050; vendor requires strictly more than 50%",
            ),
        }
    }
}

impl Error for PreprocessError {}

#[derive(Debug, Clone)]
pub(crate) struct PreprocessedImage {
    pixels: Vec<u8>,
    mask_threshold: u16,
    foreground_count: usize,
    coverage_percent: u16,
    valid_central_pixels: usize,
    tested_central_pixels: usize,
    active_difference_count: usize,
    gain_correction_active: bool,
    low_dynamic_range_count: usize,
    pathological_edge_samples: usize,
}

impl PreprocessedImage {
    pub fn pixels(&self) -> &[u8] {
        &self.pixels
    }

    pub(crate) fn mask_threshold(&self) -> u16 {
        self.mask_threshold
    }

    pub(crate) fn foreground_count(&self) -> usize {
        self.foreground_count
    }

    pub(crate) fn coverage_percent(&self) -> u16 {
        self.coverage_percent
    }

    pub(crate) fn valid_central_pixels(&self) -> usize {
        self.valid_central_pixels
    }

    pub(crate) fn tested_central_pixels(&self) -> usize {
        self.tested_central_pixels
    }

    pub(crate) fn active_difference_count(&self) -> usize {
        self.active_difference_count
    }

    pub(crate) fn gain_correction_active(&self) -> bool {
        self.gain_correction_active
    }

    pub fn low_dynamic_range_count(&self) -> usize {
        self.low_dynamic_range_count
    }

    pub(crate) fn pathological_edge_samples(&self) -> usize {
        self.pathological_edge_samples
    }
}

/// GF3258 WN2 preprocessing state.
///
/// The proprietary preprocessor has a persisted calibration loader and an
/// explicit default-calibration path.  The default path initializes the
/// primary 80x64 u16 plane to Q13 unity (0x2000) and the second plane to zero.
/// This implementation intentionally starts from that vendor-supported state;
/// it does not depend on a proprietary calibration file.
///
/// The vendor also maintains slower adaptive maps across frames.  Their
/// storage, fixed-point learner and shared history counter have been recovered,
/// but their periodic update gate is separate from the immediate first-frame
/// pixel path.  Keep this object stateful so those updates can be added without
/// changing the public preprocessing boundary when enrollment becomes
/// multi-frame.
#[derive(Debug, Clone)]
pub(crate) struct Gf3258Preprocessor {
    calibration: Vec<u16>,
    secondary_calibration: Vec<u16>,
}

impl Default for Gf3258Preprocessor {
    fn default() -> Self {
        Self {
            calibration: vec![Q13_ONE; PIXEL_COUNT],
            secondary_calibration: vec![0; PIXEL_COUNT],
        }
    }
}

#[derive(Debug, Clone)]
pub struct FinalStageImage {
    pixels: Vec<u8>,
    low_dynamic_range_count: usize,
}

impl FinalStageImage {
    pub fn pixels(&self) -> &[u8] {
        &self.pixels
    }

    pub fn low_dynamic_range_count(&self) -> usize {
        self.low_dynamic_range_count
    }
}

/// Reproduce only FUN_00160590 from its already-corrected u16 input and
/// 5120-byte foreground mask.  This is intentionally exposed for vendor
/// parity validation so upstream calibration/gain state cannot affect the
/// comparison.
pub fn process_final_stage_from_corrected(
    corrected: &[u16],
    mask: &[u8],
) -> Result<FinalStageImage, PreprocessError> {
    if corrected.len() != PIXEL_COUNT {
        return Err(PreprocessError::UnexpectedPixelCount {
            expected: PIXEL_COUNT,
            actual: corrected.len(),
        });
    }

    if mask.len() != PIXEL_COUNT {
        return Err(PreprocessError::UnexpectedPixelCount {
            expected: PIXEL_COUNT,
            actual: mask.len(),
        });
    }

    let locally_centered = local_background_correction(corrected, mask);
    let smoothed = binomial_smooth_3x3(&locally_centered);

    let (horizontal_min, horizontal_max) = horizontal_extrema(&smoothed);
    let (vertical_min, vertical_max) = vertical_extrema(&smoothed);

    let mut pre_upper = vec![0_u16; PIXEL_COUNT];
    let mut pre_lower = vec![0_u16; PIXEL_COUNT];
    for i in 0..PIXEL_COUNT {
        pre_upper[i] = horizontal_max[i].max(vertical_max[i]);
        pre_lower[i] = horizontal_min[i].min(vertical_min[i]);
    }

    let (upper, lower) = refine_diagonal_bounds(&pre_upper, &pre_lower);
    let (pixels, low_dynamic_range_count) =
        normalize_algorithm_image(&smoothed, mask, &upper, &lower);

    Ok(FinalStageImage {
        pixels,
        low_dynamic_range_count,
    })
}

impl Gf3258Preprocessor {
    pub(crate) fn process(&mut self, raw: &[u16]) -> Result<PreprocessedImage, PreprocessError> {
        if raw.len() != PIXEL_COUNT {
            return Err(PreprocessError::UnexpectedPixelCount {
                expected: PIXEL_COUNT,
                actual: raw.len(),
            });
        }

        let (raw_work, pathological_edge_samples) = sanitize_raw(raw);
        let (good_pixels, tested_pixels) = validate_raw(&raw_work);

        // Vendor predicate is: good * 100 > total * 50.
        if good_pixels * 100 <= tested_pixels * 50 {
            return Err(PreprocessError::InvalidRawFrame {
                good_pixels,
                tested_pixels,
            });
        }

        let mask_threshold = mask_threshold(&self.calibration, &raw_work);
        let mask = make_mask(&self.calibration, &raw_work, mask_threshold);
        let foreground_count = mask.iter().filter(|&&v| v != 0).count();
        let coverage_percent = ((foreground_count * 100) / PIXEL_COUNT) as u16;

        let difference: Vec<u16> = self
            .calibration
            .iter()
            .zip(&raw_work)
            .map(|(&calibration, &pixel)| calibration.saturating_sub(pixel))
            .collect();

        let active_difference_count = difference
            .iter()
            .filter(|&&value| value > ACTIVE_DIFFERENCE_THRESHOLD)
            .count();
        let gain_correction_active = active_difference_count > ACTIVE_REQUIRED_STRICT;

        // FUN_001b6300's normal GF3258 per-frame gain map starts at Q13 unity.
        let mut scale = vec![Q13_ONE; PIXEL_COUNT];

        if gain_correction_active {
            update_spatial_scale(&difference, &mut scale);
        }

        // The default primary calibration plane is nonzero everywhere, so the
        // normal default path always takes the Q13 correction branch.  Keep the
        // zero test anyway because it is part of the recovered implementation.
        let corrected = final_q13_correction(&raw_work, &self.calibration, &scale);

        let final_stage = process_final_stage_from_corrected(&corrected, &mask)?;
        let pixels = final_stage.pixels;
        let low_dynamic_range_count = final_stage.low_dynamic_range_count;

        // Keep the second vendor-default plane alive in the state model even
        // though it does not change the first/default frame's final pixel path.
        debug_assert_eq!(self.secondary_calibration.len(), PIXEL_COUNT);

        // The sanitization stage guarantees the work image stays 12-bit.
        debug_assert!(raw_work.iter().all(|&v| v <= RAW_MAX));

        Ok(PreprocessedImage {
            pixels,
            mask_threshold,
            foreground_count,
            coverage_percent,
            valid_central_pixels: good_pixels,
            tested_central_pixels: tested_pixels,
            active_difference_count,
            gain_correction_active,
            low_dynamic_range_count,
            pathological_edge_samples,
        })
    }
}

fn sanitize_raw(raw: &[u16]) -> (Vec<u16>, usize) {
    let output: Vec<u16> = raw.iter().map(|&v| v.min(RAW_MAX)).collect();

    // Proven GF3258 behavior includes a special repair for pathological 0/4095
    // values on the top/bottom edge rows.  The exact neighbor-selection rule
    // was not preserved in the recovered material used for this implementation.
    // Do not invent it: preserve those already-clamped samples and report how
    // many were encountered.  Ordinary frames are unaffected; a parity test
    // containing one of these samples must be treated as non-bit-exact until
    // that small repair branch is recovered.
    let mut pathological = 0_usize;
    for y in [0, 1, IMAGE_HEIGHT - 2, IMAGE_HEIGHT - 1] {
        let row = &output[y * IMAGE_WIDTH..(y + 1) * IMAGE_WIDTH];
        pathological += row
            .iter()
            .filter(|&&value| value == 0 || value == RAW_MAX)
            .count();
    }

    (output, pathological)
}

fn validate_raw(raw: &[u16]) -> (usize, usize) {
    let mut good = 0_usize;
    let mut total = 0_usize;

    for y in VALID_BORDER..(IMAGE_HEIGHT - VALID_BORDER) {
        for x in VALID_BORDER..(IMAGE_WIDTH - VALID_BORDER) {
            let value = raw[y * IMAGE_WIDTH + x];
            total += 1;
            if value > VALID_LOW_EXCLUSIVE && value < VALID_HIGH_EXCLUSIVE {
                good += 1;
            }
        }
    }

    debug_assert_eq!(total, 76 * 60);
    (good, total)
}

fn mask_threshold(calibration: &[u16], raw: &[u16]) -> u16 {
    let mut count = 0_usize;
    let mut sum = 0_u64;

    for (&calibration, &pixel) in calibration.iter().zip(raw) {
        let difference = calibration.saturating_sub(pixel);
        if difference > MASK_BASE_THRESHOLD {
            count += 1;
            sum += u64::from(difference);
        }
    }

    if count == 0 {
        return MASK_BASE_THRESHOLD;
    }

    // Preserve the vendor's two sequential integer divisions rather than
    // algebraically collapsing them.
    let mean = sum / count as u64;
    let mut threshold = (mean / 5) as u16;

    if count <= MASK_SPARSE_LIMIT {
        threshold = threshold.max(MASK_BASE_THRESHOLD);
    }

    threshold
}

fn make_mask(calibration: &[u16], raw: &[u16], threshold: u16) -> Vec<u8> {
    calibration
        .iter()
        .zip(raw)
        .map(|(&calibration, &pixel)| {
            let difference = calibration.saturating_sub(pixel);
            if difference >= threshold && pixel != RAW_MAX {
                0xff
            } else {
                0
            }
        })
        .collect()
}

fn update_spatial_scale(difference: &[u16], scale: &mut [u16]) {
    let ratio: Vec<u16> = difference
        .iter()
        .zip(scale.iter())
        .map(|(&difference, &scale)| {
            if scale == 0 {
                ((u32::from(difference) << 13) & 0xffff) as u16
            } else {
                let numerator = (u32::from(difference) << 13) + u32::from(scale) / 2;
                (numerator / u32::from(scale)) as u16
            }
        })
        .collect();

    let median = separable_median3(&ratio);

    for i in 0..PIXEL_COUNT {
        let ratio_value = ratio[i];
        let median_value = median[i];

        if ratio_value == 0 || median_value == 0 {
            continue;
        }

        if ratio_value.abs_diff(median_value) <= GF3258_MEDIAN_DEVIATION {
            continue;
        }

        let numerator = u32::from(ratio_value) * u32::from(scale[i]) + u32::from(median_value) / 2;
        let candidate = numerator / u32::from(median_value);

        // Processing type 0x18 stores the low u16 directly; it skips the
        // generic 0x7fff clamp used by other profiles.
        scale[i] = candidate as u16;
    }
}

fn separable_median3(source: &[u16]) -> Vec<u16> {
    let mut horizontal = source.to_vec();

    for y in 0..IMAGE_HEIGHT {
        for x in 1..IMAGE_WIDTH - 1 {
            let i = y * IMAGE_WIDTH + x;
            horizontal[i] = median3(source[i - 1], source[i], source[i + 1]);
        }
    }

    let mut vertical = horizontal.clone();
    for y in 1..IMAGE_HEIGHT - 1 {
        for x in 0..IMAGE_WIDTH {
            let i = y * IMAGE_WIDTH + x;
            vertical[i] = median3(
                horizontal[i - IMAGE_WIDTH],
                horizontal[i],
                horizontal[i + IMAGE_WIDTH],
            );
        }
    }

    vertical
}

fn median3(a: u16, b: u16, c: u16) -> u16 {
    if a > b {
        if b > c {
            b
        } else if a > c {
            c
        } else {
            a
        }
    } else if a > c {
        a
    } else if b > c {
        c
    } else {
        b
    }
}

fn final_q13_correction(raw: &[u16], gate: &[u16], scale: &[u16]) -> Vec<u16> {
    raw.iter()
        .zip(gate)
        .zip(scale)
        .map(|((&pixel, &gate), &scale)| {
            if gate == 0 {
                pixel
            } else if scale == 0 {
                ((u32::from(pixel) << 13) & 0xffff) as u16
            } else {
                let numerator = (u32::from(pixel) << 13) + u32::from(scale) / 2;
                (numerator / u32::from(scale)) as u16
            }
        })
        .collect()
}

fn local_background_correction(raw: &[u16], mask: &[u8]) -> Vec<u16> {
    let mut output = vec![LOCAL_BACKGROUND_CENTER as u16; PIXEL_COUNT];

    for y in 0..IMAGE_HEIGHT {
        let y0 = y.saturating_sub(LOCAL_BACKGROUND_RADIUS);
        let y1 = (y + LOCAL_BACKGROUND_RADIUS).min(IMAGE_HEIGHT - 1);

        for x in 0..IMAGE_WIDTH {
            let i = y * IMAGE_WIDTH + x;
            if mask[i] == 0 {
                continue;
            }

            let x0 = x.saturating_sub(LOCAL_BACKGROUND_RADIUS);
            let x1 = (x + LOCAL_BACKGROUND_RADIUS).min(IMAGE_WIDTH - 1);

            let mut sum = 0_u64;
            let mut count = 0_u32;

            for yy in y0..=y1 {
                for xx in x0..=x1 {
                    let j = yy * IMAGE_WIDTH + xx;
                    if mask[j] != 0 {
                        sum += u64::from(raw[j]);
                        count += 1;
                    }
                }
            }

            if count == 0 {
                continue;
            }

            let mean = ((sum + u64::from(count) / 2) / u64::from(count)) as i32;
            let value = i32::from(raw[i]) + LOCAL_BACKGROUND_CENTER - mean;
            output[i] = value.max(0) as u16;
        }
    }

    output
}

fn binomial_smooth_3x3(source: &[u16]) -> Vec<u16> {
    let mut output = source.to_vec();

    for y in 1..IMAGE_HEIGHT - 1 {
        for x in 1..IMAGE_WIDTH - 1 {
            let i = y * IMAGE_WIDTH + x;
            let nw = u32::from(source[i - IMAGE_WIDTH - 1]);
            let n = u32::from(source[i - IMAGE_WIDTH]);
            let ne = u32::from(source[i - IMAGE_WIDTH + 1]);
            let w = u32::from(source[i - 1]);
            let c = u32::from(source[i]);
            let e = u32::from(source[i + 1]);
            let sw = u32::from(source[i + IMAGE_WIDTH - 1]);
            let s = u32::from(source[i + IMAGE_WIDTH]);
            let se = u32::from(source[i + IMAGE_WIDTH + 1]);

            let sum = nw + 2 * n + ne + 2 * w + 4 * c + 2 * e + sw + 2 * s + se;
            output[i] = ((sum + 8) >> 4) as u16;
        }
    }

    output
}

fn horizontal_extrema(source: &[u16]) -> (Vec<u16>, Vec<u16>) {
    let mut minimum = vec![0_u16; PIXEL_COUNT];
    let mut maximum = vec![0_u16; PIXEL_COUNT];

    for y in 0..IMAGE_HEIGHT {
        for x in 0..IMAGE_WIDTH {
            let x0 = x.saturating_sub(LOCAL_EXTREMA_RADIUS);
            let x1 = (x + LOCAL_EXTREMA_RADIUS).min(IMAGE_WIDTH - 1);
            let mut lo = u16::MAX;
            let mut hi = u16::MIN;

            for xx in x0..=x1 {
                let value = source[y * IMAGE_WIDTH + xx];
                lo = lo.min(value);
                hi = hi.max(value);
            }

            let i = y * IMAGE_WIDTH + x;
            minimum[i] = lo;
            maximum[i] = hi;
        }
    }

    (minimum, maximum)
}

fn vertical_extrema(source: &[u16]) -> (Vec<u16>, Vec<u16>) {
    let mut minimum = vec![0_u16; PIXEL_COUNT];
    let mut maximum = vec![0_u16; PIXEL_COUNT];

    for y in 0..IMAGE_HEIGHT {
        let y0 = y.saturating_sub(LOCAL_EXTREMA_RADIUS);
        let y1 = (y + LOCAL_EXTREMA_RADIUS).min(IMAGE_HEIGHT - 1);

        for x in 0..IMAGE_WIDTH {
            let mut lo = u16::MAX;
            let mut hi = u16::MIN;

            for yy in y0..=y1 {
                let value = source[yy * IMAGE_WIDTH + x];
                lo = lo.min(value);
                hi = hi.max(value);
            }

            let i = y * IMAGE_WIDTH + x;
            minimum[i] = lo;
            maximum[i] = hi;
        }
    }

    (minimum, maximum)
}

fn refine_diagonal_bounds(pre_upper: &[u16], pre_lower: &[u16]) -> (Vec<u16>, Vec<u16>) {
    let mut upper = vec![0_u16; PIXEL_COUNT];
    let mut lower = vec![0_u16; PIXEL_COUNT];

    // Exact 80x64 GF3258 FUN_0015f280 layout.  The vendor function handles
    // the top row, middle rows, and bottom row separately instead of using a
    // generic border mode.  Preserve that structure here for parity work.
    //
    // For param_1 / pre_upper it selects the minimum of the center and the
    // diagonals that physically exist.  For param_2 / pre_lower it selects
    // the corresponding maximum.

    let w = IMAGE_WIDTH;
    let h = IMAGE_HEIGHT;
    debug_assert!(w >= 2 && h >= 2);

    // ---- Top row ---------------------------------------------------------
    // Top-left: center + SE.
    upper[0] = pre_upper[0].min(pre_upper[w + 1]);
    lower[0] = pre_lower[0].max(pre_lower[w + 1]);

    // Top edge interior: center + SW + SE.
    for x in 1..w - 1 {
        let i = x;
        upper[i] = pre_upper[i]
            .min(pre_upper[w + x - 1])
            .min(pre_upper[w + x + 1]);
        lower[i] = pre_lower[i]
            .max(pre_lower[w + x - 1])
            .max(pre_lower[w + x + 1]);
    }

    // Top-right: center + SW.
    let i = w - 1;
    upper[i] = pre_upper[i].min(pre_upper[w + w - 2]);
    lower[i] = pre_lower[i].max(pre_lower[w + w - 2]);

    // ---- Middle rows ----------------------------------------------------
    for y in 1..h - 1 {
        let row = y * w;
        let prev = (y - 1) * w;
        let next = (y + 1) * w;

        // Left edge: center + NE + SE.
        let i = row;
        upper[i] = pre_upper[i]
            .min(pre_upper[prev + 1])
            .min(pre_upper[next + 1]);
        lower[i] = pre_lower[i]
            .max(pre_lower[prev + 1])
            .max(pre_lower[next + 1]);

        // Interior: center + NW + NE + SW + SE.
        for x in 1..w - 1 {
            let i = row + x;
            upper[i] = pre_upper[i]
                .min(pre_upper[prev + x - 1])
                .min(pre_upper[prev + x + 1])
                .min(pre_upper[next + x - 1])
                .min(pre_upper[next + x + 1]);
            lower[i] = pre_lower[i]
                .max(pre_lower[prev + x - 1])
                .max(pre_lower[prev + x + 1])
                .max(pre_lower[next + x - 1])
                .max(pre_lower[next + x + 1]);
        }

        // Right edge: center + NW + SW.
        let i = row + w - 1;
        upper[i] = pre_upper[i]
            .min(pre_upper[prev + w - 2])
            .min(pre_upper[next + w - 2]);
        lower[i] = pre_lower[i]
            .max(pre_lower[prev + w - 2])
            .max(pre_lower[next + w - 2]);
    }

    // ---- Bottom row -----------------------------------------------------
    let row = (h - 1) * w;
    let prev = (h - 2) * w;

    // Bottom-left: center + NE.
    upper[row] = pre_upper[row].min(pre_upper[prev + 1]);
    lower[row] = pre_lower[row].max(pre_lower[prev + 1]);

    // Bottom edge interior: center + NW + NE.
    for x in 1..w - 1 {
        let i = row + x;
        upper[i] = pre_upper[i]
            .min(pre_upper[prev + x - 1])
            .min(pre_upper[prev + x + 1]);
        lower[i] = pre_lower[i]
            .max(pre_lower[prev + x - 1])
            .max(pre_lower[prev + x + 1]);
    }

    // Bottom-right: center + NW.
    let i = row + w - 1;
    upper[i] = pre_upper[i].min(pre_upper[prev + w - 2]);
    lower[i] = pre_lower[i].max(pre_lower[prev + w - 2]);

    (upper, lower)
}

fn normalize_algorithm_image(
    processed: &[u16],
    mask: &[u8],
    upper: &[u16],
    lower: &[u16],
) -> (Vec<u8>, usize) {
    let mut output = vec![0xff_u8; PIXEL_COUNT];
    let mut low_dynamic_range_count = 0_usize;

    for i in 0..PIXEL_COUNT {
        if mask[i] == 0 {
            continue;
        }

        let upper_value = upper[i];
        let lower_value = lower[i];
        let range = upper_value.saturating_sub(lower_value);

        // This threshold is diagnostic only in FUN_00160590.  It does not
        // select a different pixel formula.
        if range < LOW_DYNAMIC_RANGE_THRESHOLD {
            low_dynamic_range_count += 1;
        }

        let q = if upper_value == lower_value {
            255_i32
        } else {
            let numerator = (i32::from(processed[i]) - i32::from(lower_value)) * 255;
            let denominator = i32::from(upper_value) - i32::from(lower_value);
            numerator / denominator // x86 IDIV and Rust both truncate toward zero.
        };

        output[i] = if q < 0 {
            255
        } else {
            255_u8 - (q.min(255) as u8)
        };
    }

    (output, low_dynamic_range_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_state_matches_vendor_fallback_planes() {
        let preprocessor = Gf3258Preprocessor::default();
        assert!(preprocessor.calibration.iter().all(|&v| v == 0x2000));
        assert!(preprocessor.secondary_calibration.iter().all(|&v| v == 0));
    }

    #[test]
    fn raw_validator_uses_strict_bounds_and_strict_majority() {
        let mut raw = vec![0_u16; PIXEL_COUNT];
        let mut filled = 0_usize;
        for y in VALID_BORDER..IMAGE_HEIGHT - VALID_BORDER {
            for x in VALID_BORDER..IMAGE_WIDTH - VALID_BORDER {
                if filled < 2280 {
                    raw[y * IMAGE_WIDTH + x] = 1000;
                }
                filled += 1;
            }
        }
        let (good, total) = validate_raw(&raw);
        assert_eq!((good, total), (2280, 4560));
        assert!(good * 100 <= total * 50);

        // Make one more central pixel valid: 2281/4560 is the first success.
        'outer: for y in VALID_BORDER..IMAGE_HEIGHT - VALID_BORDER {
            for x in VALID_BORDER..IMAGE_WIDTH - VALID_BORDER {
                let i = y * IMAGE_WIDTH + x;
                if raw[i] == 0 {
                    raw[i] = 1000;
                    break 'outer;
                }
            }
        }
        let (good, total) = validate_raw(&raw);
        assert_eq!((good, total), (2281, 4560));
        assert!(good * 100 > total * 50);
    }

    #[test]
    fn raw_validator_bounds_are_exclusive() {
        let mut raw = vec![1000_u16; PIXEL_COUNT];
        let i = 2 * IMAGE_WIDTH + 2;
        raw[i] = 50;
        let (good_low, _) = validate_raw(&raw);
        raw[i] = 4050;
        let (good_high, _) = validate_raw(&raw);
        raw[i] = 51;
        let (good_51, _) = validate_raw(&raw);
        assert_eq!(good_51, good_low + 1);
        assert_eq!(good_51, good_high + 1);
    }

    #[test]
    fn mask_threshold_uses_sequential_integer_division() {
        let calibration = vec![1000_u16; PIXEL_COUNT];
        let mut raw = vec![1000_u16; PIXEL_COUNT];
        for value in raw.iter_mut().take(801) {
            *value = 379; // difference 621; mean=621; /5=124.
        }
        assert_eq!(mask_threshold(&calibration, &raw), 124);
    }

    #[test]
    fn sparse_mask_threshold_has_120_floor() {
        let calibration = vec![1000_u16; PIXEL_COUNT];
        let mut raw = vec![1000_u16; PIXEL_COUNT];
        for value in raw.iter_mut().take(800) {
            *value = 399; // difference 601; /5=120.
        }
        assert_eq!(mask_threshold(&calibration, &raw), 120);
    }

    #[test]
    fn median_filter_is_separable_and_preserves_one_pixel_border() {
        let mut source = vec![10_u16; PIXEL_COUNT];
        source[0] = 999;
        source[2 * IMAGE_WIDTH + 2] = 100;
        source[2 * IMAGE_WIDTH + 3] = 200;
        source[2 * IMAGE_WIDTH + 4] = 300;
        let output = separable_median3(&source);
        assert_eq!(output[0], 999);
        assert_eq!(output[2 * IMAGE_WIDTH + 3], 10);
    }

    #[test]
    fn binomial_smoothing_preserves_border_and_uses_full_interior_neighborhood() {
        let mut source = vec![0_u16; PIXEL_COUNT];
        source[0] = 777;
        source[IMAGE_WIDTH + 1] = 160;

        let output = binomial_smooth_3x3(&source);

        // The one-pixel border is copied unchanged.
        assert_eq!(output[0], 777);

        // (1,1) is an interior pixel, so its 3x3 neighborhood includes (0,0):
        //
        //   (1 * 777 + 4 * 160 + 8) >> 4 = 89
        //
        // All other samples in this synthetic neighborhood are zero.
        assert_eq!(output[IMAGE_WIDTH + 1], 89);
    }

    #[test]
    fn normalization_background_is_white() {
        let processed = vec![3000_u16; PIXEL_COUNT];
        let mask = vec![0_u8; PIXEL_COUNT];
        let upper = vec![3100_u16; PIXEL_COUNT];
        let lower = vec![2900_u16; PIXEL_COUNT];
        let (pixels, low) = normalize_algorithm_image(&processed, &mask, &upper, &lower);
        assert!(pixels.iter().all(|&v| v == 255));
        assert_eq!(low, 0);
    }

    #[test]
    fn normalization_matches_signed_idiv_clamps() {
        let mut processed = vec![3000_u16; PIXEL_COUNT];
        let mut mask = vec![0_u8; PIXEL_COUNT];
        let mut upper = vec![3100_u16; PIXEL_COUNT];
        let mut lower = vec![2900_u16; PIXEL_COUNT];
        mask[0] = 0xff;

        processed[0] = 3000;
        let (pixels, _) = normalize_algorithm_image(&processed, &mask, &upper, &lower);
        assert_eq!(pixels[0], 128); // q=127 due integer truncation.

        processed[0] = 2800;
        let (pixels, _) = normalize_algorithm_image(&processed, &mask, &upper, &lower);
        assert_eq!(pixels[0], 255); // negative q -> white.

        processed[0] = 3200;
        let (pixels, _) = normalize_algorithm_image(&processed, &mask, &upper, &lower);
        assert_eq!(pixels[0], 0); // q >255 clamps to255 then invert.

        upper[0] = 3000;
        lower[0] = 3000;
        let (pixels, low) = normalize_algorithm_image(&processed, &mask, &upper, &lower);
        assert_eq!(pixels[0], 0);
        assert_eq!(low, 1);
    }

    #[test]
    fn default_uniform_valid_frame_runs_end_to_end() {
        let raw = vec![1000_u16; PIXEL_COUNT];
        let mut preprocessor = Gf3258Preprocessor::default();
        let image = preprocessor.process(&raw).unwrap();
        assert_eq!(image.pixels().len(), PIXEL_COUNT);
        assert!(image.pixels().iter().all(|&v| v == 0));
        assert_eq!(image.valid_central_pixels(), 4560);
        assert_eq!(image.foreground_count(), PIXEL_COUNT);
        assert!(image.gain_correction_active());
        assert_eq!(image.pathological_edge_samples(), 0);
    }

    #[test]
    fn pathological_edge_detection_does_not_modify_sample() {
        let mut raw = vec![1000_u16; PIXEL_COUNT];
        raw[0] = 0;
        raw[IMAGE_WIDTH] = RAW_MAX;
        raw[(IMAGE_HEIGHT - 1) * IMAGE_WIDTH] = 5000;
        let (sanitized, count) = sanitize_raw(&raw);
        assert_eq!(sanitized[0], 0);
        assert_eq!(sanitized[IMAGE_WIDTH], RAW_MAX);
        assert_eq!(sanitized[(IMAGE_HEIGHT - 1) * IMAGE_WIDTH], RAW_MAX);
        assert_eq!(count, 3);
    }

    #[test]
    fn diagonal_refinement_matches_vendor_border_cases() {
        let mut upper_src = vec![1000_u16; PIXEL_COUNT];
        let mut lower_src = vec![100_u16; PIXEL_COUNT];

        // Top-left -> only SE participates.
        upper_src[IMAGE_WIDTH + 1] = 700;
        lower_src[IMAGE_WIDTH + 1] = 300;

        // Top edge x=2 -> SW and SE participate.
        upper_src[IMAGE_WIDTH + 1] = 650;
        upper_src[IMAGE_WIDTH + 3] = 600;
        lower_src[IMAGE_WIDTH + 1] = 325;
        lower_src[IMAGE_WIDTH + 3] = 350;

        // Left edge y=2 -> NE and SE participate.
        upper_src[IMAGE_WIDTH + 1] = 650;
        upper_src[3 * IMAGE_WIDTH + 1] = 550;
        lower_src[IMAGE_WIDTH + 1] = 325;
        lower_src[3 * IMAGE_WIDTH + 1] = 375;

        // Bottom-right -> only NW participates.
        let br = PIXEL_COUNT - 1;
        let nw = (IMAGE_HEIGHT - 2) * IMAGE_WIDTH + (IMAGE_WIDTH - 2);
        upper_src[nw] = 500;
        lower_src[nw] = 400;

        let (upper, lower) = refine_diagonal_bounds(&upper_src, &lower_src);

        assert_eq!(upper[0], 650);
        assert_eq!(lower[0], 325);

        assert_eq!(upper[2], 600);
        assert_eq!(lower[2], 350);

        assert_eq!(upper[2 * IMAGE_WIDTH], 550);
        assert_eq!(lower[2 * IMAGE_WIDTH], 375);

        assert_eq!(upper[br], 500);
        assert_eq!(lower[br], 400);
    }
}
