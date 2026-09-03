//! Compatibility helpers for capture-derived persistence metadata.
//!
//! The quality algorithm itself lives in `feature::quality`. This module keeps
//! the older persistence-facing shape used by validation code and preserves the
//! recovered b3970 point-ordering helper until persistence is reorganized.

use crate::feature::{FeatureError, GF3258_PIXELS, gf3258_capture_quality};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf3258PersistenceCaptureScalars {
    pub raw_quality: i32,
    pub quality: i32,
    pub coverage: i32,
    pub mask_coverage_q16: i32,
    pub coverage_q16: i32,
    pub class4_percent: Option<i32>,
    pub raw_quality_reject: bool,
}

#[inline]
pub fn gf3258_polarity_from_raw_response(raw_response: i32) -> u16 {
    u16::from(raw_response < 0)
}

fn gf3258_b3970_partition_by<T, F>(points: &mut [T], polarity: F) -> i32
where
    F: Fn(&T) -> u16,
{
    if points.is_empty() {
        return 0;
    }

    let mut front = 0usize;
    let mut back = points.len() - 1;

    loop {
        while front < back && (polarity(&points[front]) & 3) == 0 {
            front += 1;
        }

        while front < back && (polarity(&points[back]) & 3) == 1 {
            back -= 1;
        }

        if front < back {
            points.swap(front, back);
            continue;
        }

        if front == back && (polarity(&points[front]) & 3) == 0 {
            front += 1;
        }

        return front as i32;
    }
}

pub fn gf3258_preprocessor_persistence_scalars(
    source_u8: &[u8],
) -> Result<Gf3258PersistenceCaptureScalars, FeatureError> {
    let quality = gf3258_capture_quality(source_u8)?;

    Ok(Gf3258PersistenceCaptureScalars {
        raw_quality: quality.raw_quality,
        quality: quality.quality,
        coverage: quality.coverage,
        mask_coverage_q16: quality.mask_coverage_q16,
        coverage_q16: quality.coverage_q16,
        class4_percent: quality.class4_percent,
        raw_quality_reject: quality.raw_quality_rejected(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn polarity_is_strict_signed_negative() {
        assert_eq!(gf3258_polarity_from_raw_response(i32::MIN), 1);
        assert_eq!(gf3258_polarity_from_raw_response(-1), 1);
        assert_eq!(gf3258_polarity_from_raw_response(0), 0);
        assert_eq!(gf3258_polarity_from_raw_response(1), 0);
        assert_eq!(gf3258_polarity_from_raw_response(i32::MAX), 0);
    }

    #[test]
    fn b3970_partition_preserves_vendor_unstable_swap_shape() {
        let mut points = vec![
            (0usize, 0u16),
            (1usize, 1u16),
            (2usize, 0u16),
            (3usize, 1u16),
            (4usize, 0u16),
        ];

        let boundary = gf3258_b3970_partition_by(&mut points, |point| point.1);
        assert_eq!(boundary, 3);

        let ids: Vec<usize> = points.iter().map(|point| point.0).collect();
        assert_eq!(ids, vec![0, 4, 2, 3, 1]);
        assert!(points[..boundary as usize].iter().all(|point| point.1 == 0));
        assert!(points[boundary as usize..].iter().all(|point| point.1 == 1));
    }

    #[test]
    fn b3970_edge_cases_match_vendor() {
        let mut empty: Vec<u16> = Vec::new();
        assert_eq!(gf3258_b3970_partition_by(&mut empty, |value| *value), 0);

        let mut one_zero = vec![0u16];
        assert_eq!(gf3258_b3970_partition_by(&mut one_zero, |value| *value), 1);

        let mut one_one = vec![1u16];
        assert_eq!(gf3258_b3970_partition_by(&mut one_one, |value| *value), 0);
    }

    #[test]
    fn all_white_algorithm_image_has_zero_capture_scores() {
        let image = vec![0xffu8; GF3258_PIXELS];
        let result = gf3258_preprocessor_persistence_scalars(&image).unwrap();

        assert_eq!(result.raw_quality, 0);
        assert_eq!(result.quality, 0);
        assert_eq!(result.coverage, 0);
        assert_eq!(result.mask_coverage_q16, 0);
        assert_eq!(result.coverage_q16, 0);
        assert_eq!(result.class4_percent, Some(0));
        assert!(result.raw_quality_reject);
    }
}
