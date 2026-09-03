//! Registration overlap and novel-coverage mechanics.

use super::{
    GF3258_REGISTRATION_HEIGHT, GF3258_REGISTRATION_PACKED_BYTES, GF3258_REGISTRATION_WIDTH,
    Gf3258AffineQ8,
};

pub const GF3258_NOVEL_COVERAGE_MIN_CELLS: i32 = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gf3258ScanlineOverlap {
    pub first_y: i32,
    pub last_y: i32,
    pub left: Vec<i32>,
    pub right: Vec<i32>,
    pub count: i32,
}

/// FUN_001aaed0. Returns the vendor's inclusive integer-x interval before the
/// caller intersects it with [0, src_len-1].
pub fn gf3258_axis_valid_interval_q8(
    base_q8: i32,
    slope_q8: i32,
    limit: i32,
    src_len: i32,
) -> (i32, i32) {
    let max_q8 = limit.wrapping_sub(1).wrapping_mul(0x100);

    if slope_q8 == 0 {
        if base_q8 >= 0 && base_q8 <= max_q8 {
            return (0, src_len - 1);
        }
        return (0x0fff_ffff, 0xf000_0001u32 as i32);
    }

    if slope_q8 > 0 {
        let mut left = ((-i64::from(base_q8)) / i64::from(slope_q8)) as i32;
        let mut left_coord = base_q8.wrapping_add(slope_q8.wrapping_mul(left));
        while left_coord < 0 && left < src_len {
            left = left.wrapping_add(1);
            left_coord = left_coord.wrapping_add(slope_q8);
        }

        let mut right = (i64::from(max_q8.wrapping_sub(base_q8)) / i64::from(slope_q8)) as i32;
        let mut right_coord = base_q8.wrapping_add(slope_q8.wrapping_mul(right));
        while right_coord > max_q8 && right >= 0 {
            right = right.wrapping_sub(1);
            right_coord = right_coord.wrapping_sub(slope_q8);
        }
        (left, right)
    } else {
        let mut left = (i64::from(max_q8.wrapping_sub(base_q8)) / i64::from(slope_q8)) as i32;
        let mut left_coord = base_q8.wrapping_add(slope_q8.wrapping_mul(left));
        while left_coord > max_q8 && left < src_len {
            left = left.wrapping_add(1);
            left_coord = left_coord.wrapping_add(slope_q8);
        }

        let mut right = ((-i64::from(base_q8)) / i64::from(slope_q8)) as i32;
        let mut right_coord = base_q8.wrapping_add(slope_q8.wrapping_mul(right));
        while right_coord < 0 && right >= 0 {
            right = right.wrapping_sub(1);
            right_coord = right_coord.wrapping_sub(slope_q8);
        }
        (left, right)
    }
}

/// FUN_001aafe0: count source integer pixels whose Q8-transformed coordinates
/// fall inside the inclusive destination pixel-center rectangle.
pub fn gf3258_scanline_overlap(
    source_height: i32,
    source_width: i32,
    destination_height: i32,
    destination_width: i32,
    transform: Gf3258AffineQ8,
) -> Gf3258ScanlineOverlap {
    assert!(source_height >= 0 && source_width >= 0);
    let mut left = vec![0i32; source_height as usize];
    let mut right = vec![0i32; source_height as usize];
    let mut first_y = source_height;
    let mut last_y = 0i32;
    let mut count = 0i32;

    let mut base_x = transform.tx;
    let mut base_y = transform.ty;
    for y in 0..source_height {
        let (x_left, x_right) =
            gf3258_axis_valid_interval_q8(base_x, transform.a, destination_width, source_width);
        let (y_left, y_right) =
            gf3258_axis_valid_interval_q8(base_y, transform.c, destination_height, source_width);

        let row_left = x_left.max(y_left).max(0);
        let row_right = x_right.min(y_right).min(source_width - 1);
        if row_left <= row_right {
            if y < first_y {
                first_y = y;
            }
            if y > last_y {
                last_y = y;
            }
            left[y as usize] = row_left;
            right[y as usize] = row_right;
            count = count.wrapping_add(row_right - row_left + 1);
        }

        base_x = base_x.wrapping_add(transform.b);
        base_y = base_y.wrapping_add(transform.d);
    }

    Gf3258ScanlineOverlap {
        first_y,
        last_y,
        left,
        right,
        count,
    }
}

/// FUN_001ab1a0 semantic equivalent for a row-major LSB-first packed mask.
pub fn gf3258_clear_overlap_from_packed_mask(
    packed: &mut [u8],
    width: usize,
    height: usize,
    overlap: &Gf3258ScanlineOverlap,
) {
    assert_eq!(packed.len(), width.div_ceil(8) * height);
    if overlap.first_y > overlap.last_y || overlap.first_y < 0 {
        return;
    }
    let bytes_per_row = width.div_ceil(8);
    for y in overlap.first_y..=overlap.last_y {
        if y < 0 || y >= height as i32 {
            continue;
        }
        let left = overlap.left[y as usize].max(0) as usize;
        let right = overlap.right[y as usize].min(width as i32 - 1);
        if right < left as i32 {
            continue;
        }
        for x in left..=right as usize {
            packed[y as usize * bytes_per_row + (x >> 3)] &= !(1u8 << (x & 7));
        }
    }
}

/// Core of FUN_0015d0b0 after the caller has selected the applicable canonical
/// samples and supplied current->other transforms.
pub fn gf3258_novel_coverage_metric(
    current_packed_validity: &[u8; GF3258_REGISTRATION_PACKED_BYTES],
    current_to_other_full_resolution: &[Gf3258AffineQ8],
) -> i32 {
    let mut remaining = *current_packed_validity;
    for &full_transform in current_to_other_full_resolution {
        let mut active_transform = full_transform;
        active_transform.tx >>= 1;
        active_transform.ty >>= 1;
        let overlap = gf3258_scanline_overlap(
            GF3258_REGISTRATION_HEIGHT as i32,
            GF3258_REGISTRATION_WIDTH as i32,
            GF3258_REGISTRATION_HEIGHT as i32,
            GF3258_REGISTRATION_WIDTH as i32,
            active_transform,
        );
        gf3258_clear_overlap_from_packed_mask(
            &mut remaining,
            GF3258_REGISTRATION_WIDTH,
            GF3258_REGISTRATION_HEIGHT,
            &overlap,
        );
    }

    let cells: i32 = remaining.iter().map(|b| b.count_ones() as i32).sum();
    if cells < GF3258_NOVEL_COVERAGE_MIN_CELLS {
        0
    } else {
        cells << 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn axis_interval_identity_is_full_axis() {
        assert_eq!(gf3258_axis_valid_interval_q8(0, 0x100, 80, 80), (0, 79));
        assert_eq!(
            gf3258_axis_valid_interval_q8(79 * 256, -0x100, 80, 80),
            (0, 79)
        );
    }

    #[test]
    fn scanline_overlap_identity_is_5120() {
        let overlap = gf3258_scanline_overlap(64, 80, 64, 80, Gf3258AffineQ8::IDENTITY);
        assert_eq!(overlap.count, 5120);
        assert_eq!(overlap.first_y, 0);
        assert_eq!(overlap.last_y, 63);
        assert_eq!(overlap.left[0], 0);
        assert_eq!(overlap.right[63], 79);
    }

    #[test]
    fn clear_overlap_uses_lsb_first_inclusive_span() {
        let mut packed = [0xffu8; 2];
        let overlap = Gf3258ScanlineOverlap {
            first_y: 0,
            last_y: 0,
            left: vec![2],
            right: vec![5],
            count: 4,
        };
        gf3258_clear_overlap_from_packed_mask(&mut packed, 16, 1, &overlap);
        assert_eq!(packed[0], 0b1100_0011);
        assert_eq!(packed[1], 0xff);
    }

    #[test]
    fn novel_coverage_identity_against_one_old_sample_is_zero() {
        let current = [0xffu8; GF3258_REGISTRATION_PACKED_BYTES];
        assert_eq!(
            gf3258_novel_coverage_metric(&current, &[Gf3258AffineQ8::IDENTITY]),
            0
        );
    }
}
