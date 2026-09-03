use std::{error::Error, fmt};

pub const GF3258_WIDTH: usize = 80;
pub const GF3258_HEIGHT: usize = 64;
pub const GF3258_PIXELS: usize = GF3258_WIDTH * GF3258_HEIGHT;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeatureError {
    UnexpectedPixelCount { expected: usize, actual: usize },
}

impl fmt::Display for FeatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedPixelCount { expected, actual } => write!(
                f,
                "GF3258 algorithm image has {actual} pixels; expected {expected} (80x64)"
            ),
        }
    }
}

impl Error for FeatureError {}

mod filter;

mod detector;
pub use detector::*;

mod orientation;
pub use orientation::*;

mod descriptor;
pub use descriptor::*;

mod extraction;
pub use extraction::*;

mod support;
pub use support::*;

mod validity;
pub use validity::*;

mod quality;
pub(crate) use quality::gf3258_capture_quality;

pub(crate) mod matching;
pub use matching::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf3258FeaturePointCore {
    pub x_q8: u16,
    pub y_q8: u16,
    pub orientation_q12: u16,
    pub ranking_score: i32,
}

#[inline]
fn gf3258_c0910_round_coordinate_q8(value: u16) -> u16 {
    value.wrapping_add(8) & 0xfff0
}

#[inline]
fn gf3258_c0910_round_orientation_q12(value: u16) -> u16 {
    let signed = value as i16;
    if signed < 0 {
        let magnitude = i32::from(signed).wrapping_neg();
        ((magnitude.wrapping_add(0x80) & !0xff) as i16).wrapping_neg() as u16
    } else {
        value.wrapping_add(0x80) & 0xff00
    }
}

impl Gf3258FeaturePointCore {
    pub fn from_candidate(
        candidate: &detector::RefinedExtremum,
        orientation: &orientation::Gf3258OrientationResult,
    ) -> Self {
        Self {
            // C0910 rounds the BF830 output geometry before publishing the
            // FeaturePoint60. Persistence relies on the resulting low-nibble
            // zeros because its x/y/orientation bit fields intentionally overlap.
            x_q8: gf3258_c0910_round_coordinate_q8(candidate.x_q8),
            y_q8: gf3258_c0910_round_coordinate_q8(candidate.y_q8),
            orientation_q12: gf3258_c0910_round_orientation_q12(orientation.orientation_q12),
            // Primary candidates already carry abs(response); be410 stores
            // its negative as the ranking/sort score.
            ranking_score: candidate.response.wrapping_neg(),
        }
    }
}

#[cfg(test)]
mod point_core_tests {
    use super::{gf3258_c0910_round_coordinate_q8, gf3258_c0910_round_orientation_q12};

    #[test]
    fn c0910_coordinate_rounding_matches_final_feature_point_store() {
        assert_eq!(gf3258_c0910_round_coordinate_q8(0x1230), 0x1230);
        assert_eq!(gf3258_c0910_round_coordinate_q8(0x1237), 0x1230);
        assert_eq!(gf3258_c0910_round_coordinate_q8(0x1238), 0x1240);
        assert_eq!(gf3258_c0910_round_coordinate_q8(0x123f), 0x1240);
    }

    #[test]
    fn c0910_orientation_rounding_is_signed_and_symmetric() {
        assert_eq!(gf3258_c0910_round_orientation_q12(0x007f), 0x0000);
        assert_eq!(gf3258_c0910_round_orientation_q12(0x0080), 0x0100);
        assert_eq!(
            gf3258_c0910_round_orientation_q12((-0x007f_i16) as u16),
            0x0000
        );
        assert_eq!(
            gf3258_c0910_round_orientation_q12((-0x0080_i16) as u16),
            0xff00
        );
        assert_eq!(
            gf3258_c0910_round_orientation_q12((-0x0180_i16) as u16),
            0xfe00
        );
    }
}
