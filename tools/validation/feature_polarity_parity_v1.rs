use std::{env, error::Error, fs};

use goodix_info::feature::{GF3258_PIXELS, Gf3258ScaleSpace};
use goodix_info::validation_support::validation_root;

const EXPECTED_POINTS: usize = 97;
const FEATURE_POINT_STRIDE: usize = 0x3c;

fn main() -> Result<(), Box<dyn Error>> {
    let root = validation_root(env::args_os().nth(1));

    let image_path = root.join("first_algorithm_u8_live.bin");
    let vendor_path = root.join("feature_orientation/vendor_primary_points.bin");

    let image = fs::read(&image_path)?;
    if image.len() != GF3258_PIXELS {
        return Err(format!(
            "{}: expected {} bytes, found {}",
            image_path.display(),
            GF3258_PIXELS,
            image.len()
        )
        .into());
    }

    let vendor = fs::read(&vendor_path)?;
    let expected_vendor_bytes = EXPECTED_POINTS * FEATURE_POINT_STRIDE;

    if vendor.len() != expected_vendor_bytes {
        return Err(format!(
            "{}: expected {} bytes, found {}",
            vendor_path.display(),
            expected_vendor_bytes,
            vendor.len()
        )
        .into());
    }

    let scale = Gf3258ScaleSpace::build(&image)?;
    let outcomes = scale.refinement_outcomes();
    let primary = scale.primary_candidates(&outcomes);

    if primary.len() != EXPECTED_POINTS {
        return Err(format!(
            "expected {} primary candidates, found {}",
            EXPECTED_POINTS,
            primary.len()
        )
        .into());
    }

    let mut vendor_zero = 0usize;
    let mut vendor_one = 0usize;

    let mut raw_negative = 0usize;
    let mut raw_nonnegative = 0usize;

    let mut negative_is_one_mismatches = 0usize;
    let mut negative_is_zero_mismatches = 0usize;

    for (index, point) in primary.iter().enumerate() {
        let offset = index * FEATURE_POINT_STRIDE;

        let vendor_polarity = u16::from_le_bytes([vendor[offset], vendor[offset + 1]]);

        match vendor_polarity {
            0 => vendor_zero += 1,
            1 => vendor_one += 1,
            other => {
                return Err(
                    format!("vendor polarity[{index}]={other}; expected binary 0/1").into(),
                );
            }
        }

        if point.raw.response < 0 {
            raw_negative += 1;
        } else {
            raw_nonnegative += 1;
        }

        let negative_is_one = u16::from(point.raw.response < 0);

        let negative_is_zero = u16::from(point.raw.response >= 0);

        if negative_is_one != vendor_polarity {
            negative_is_one_mismatches += 1;
        }

        if negative_is_zero != vendor_polarity {
            negative_is_zero_mismatches += 1;
        }
    }

    println!("vendor: polarity0={} polarity1={}", vendor_zero, vendor_one);

    println!(
        "rust raw sign: negative={} nonnegative={}",
        raw_negative, raw_nonnegative
    );

    println!(
        "mapping raw<0 => polarity1 mismatches={}",
        negative_is_one_mismatches
    );

    println!(
        "mapping raw<0 => polarity0 mismatches={}",
        negative_is_zero_mismatches
    );

    if negative_is_one_mismatches == 0 {
        println!(
            "PROVEN FIXTURE MAPPING: \
             polarity = (raw_response < 0) as u16"
        );
    } else if negative_is_zero_mismatches == 0 {
        println!(
            "PROVEN FIXTURE MAPPING: \
             polarity = (raw_response >= 0) as u16"
        );
    } else {
        return Err("vendor polarity is not a direct raw-DoG-sign mapping".into());
    }

    Ok(())
}
