//! Shared fixed-point image filtering primitives for GF3258 feature processing.
//!
//! These helpers reproduce the vendor REFLECT_101 border handling and Q16
//! truncation after each separable pass. They are intentionally private to the
//! feature subsystem.

use super::{GF3258_HEIGHT, GF3258_PIXELS, GF3258_WIDTH};

pub(super) fn separable_q16_reflect101(source: &[u16], kernel: &[i32]) -> Vec<u16> {
    debug_assert_eq!(source.len(), GF3258_PIXELS);
    debug_assert!(kernel.len() % 2 == 1);

    let radius = (kernel.len() / 2) as isize;
    let mut horizontal = vec![0u16; GF3258_PIXELS];

    for y in 0..GF3258_HEIGHT {
        for x in 0..GF3258_WIDTH {
            let mut acc = 0i64;
            for (tap, &coeff) in kernel.iter().enumerate() {
                let sx = reflect101(x as isize + tap as isize - radius, GF3258_WIDTH);
                acc += i64::from(source[y * GF3258_WIDTH + sx]) * i64::from(coeff);
            }

            // FUN_001a4840 performs Q16 truncation after each 1-D pass.
            horizontal[y * GF3258_WIDTH + x] = (acc >> 16) as u16;
        }
    }

    let mut vertical = vec![0u16; GF3258_PIXELS];
    for y in 0..GF3258_HEIGHT {
        for x in 0..GF3258_WIDTH {
            let mut acc = 0i64;
            for (tap, &coeff) in kernel.iter().enumerate() {
                let sy = reflect101(y as isize + tap as isize - radius, GF3258_HEIGHT);
                acc += i64::from(horizontal[sy * GF3258_WIDTH + x]) * i64::from(coeff);
            }
            vertical[y * GF3258_WIDTH + x] = (acc >> 16) as u16;
        }
    }

    vertical
}

/// FUN_001a4670(..., mode=4) == BORDER_REFLECT_101.
pub(super) fn reflect101(mut p: isize, len: usize) -> usize {
    debug_assert!(len > 0);
    if len == 1 {
        return 0;
    }

    let n = len as isize;
    while p < 0 || p >= n {
        if p < 0 {
            p = -p;
        } else {
            p = 2 * n - p - 2;
        }
    }
    p as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reflect101_matches_vendor_helper() {
        assert_eq!(reflect101(-1, 5), 1);
        assert_eq!(reflect101(-2, 5), 2);
        assert_eq!(reflect101(5, 5), 3);
        assert_eq!(reflect101(6, 5), 2);
        assert_eq!(reflect101(9, 5), 1);
    }
}
