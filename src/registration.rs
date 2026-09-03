//! GF3258 WN2 registration primitives, scoring, and enrollment policy.
//!
//! This module is intentionally GF3258-specific. It exposes the recovered
//! registration building blocks through one stable API while keeping affine
//! math, enrollment correspondence, verification geometry, map evidence,
//! coverage, acceptance policy, and relation storage in separate modules.

use crate::feature::{GF3258_HEIGHT, GF3258_WIDTH};

mod affine;
pub use affine::*;

mod coverage;
pub use coverage::*;

mod enrollment;
pub use enrollment::*;

mod map;
pub use map::*;

mod matcher_geometry;
pub use matcher_geometry::*;

mod policy;
pub use policy::*;

mod relations;
pub use relations::*;

pub const GF3258_REGISTRATION_WIDTH: usize = GF3258_WIDTH / 2;
pub const GF3258_REGISTRATION_HEIGHT: usize = GF3258_HEIGHT / 2;
pub const GF3258_REGISTRATION_PIXELS: usize =
    GF3258_REGISTRATION_WIDTH * GF3258_REGISTRATION_HEIGHT;
pub const GF3258_REGISTRATION_PACKED_BYTES: usize = GF3258_REGISTRATION_PIXELS / 8;

pub const GF3258_QUARTER_VALIDITY_WIDTH: usize = GF3258_WIDTH.div_ceil(4);
pub const GF3258_QUARTER_VALIDITY_HEIGHT: usize = GF3258_HEIGHT.div_ceil(4);
pub const GF3258_QUARTER_VALIDITY_CELLS: usize =
    GF3258_QUARTER_VALIDITY_WIDTH * GF3258_QUARTER_VALIDITY_HEIGHT;

pub const GF3258_MAX_INITIAL_CORRESPONDENCES: usize = 31;
pub const GF3258_GEOMETRY_AXIS_LIMIT_Q8: i32 = 0x281; // strict abs < 641
pub const GF3258_GEOMETRY_RADIUS_SQ_Q16: i32 = 0x64000; // strict < 640^2
pub const GF3258_GEOMETRY_INITIAL_COST: i32 = 0x190000;
