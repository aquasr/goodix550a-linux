use std::{env, error::Error, path::PathBuf};

use goodix_info::{
    feature::{GF3258_PIXELS, gf3258_c6d90_direction_map, gf3258_c7310_gradient_source},
    validation_support::{read_exact, validation_root},
};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = env::args_os().collect();
    let root = validation_root(None);
    let source = args
        .get(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("feature_orientation/c7310_source_local2b8_u8.bin"));
    let vendor = args
        .get(2)
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("feature_orientation/c7310_output_local290_u8.bin"));

    println!("GF3258 c7310 local_2b8 -> c0910 param_1 parity");
    println!("source={}", source.display());
    println!("vendor_output={}", vendor.display());

    let source_bytes = read_exact(&source, GF3258_PIXELS)?;
    let vendor_bytes = read_exact(&vendor, GF3258_PIXELS)?;
    if source_bytes.len() != GF3258_PIXELS {
        return Err(format!("source length {} != {}", source_bytes.len(), GF3258_PIXELS).into());
    }
    if vendor_bytes.len() != GF3258_PIXELS {
        return Err(format!("vendor length {} != {}", vendor_bytes.len(), GF3258_PIXELS).into());
    }

    let direction = gf3258_c6d90_direction_map(&source_bytes)?;
    let rust = gf3258_c7310_gradient_source(&source_bytes)?;

    let mut mismatches = 0usize;
    let mut examples = Vec::new();
    for i in 0..GF3258_PIXELS {
        if rust[i] != vendor_bytes[i] {
            mismatches += 1;
            if examples.len() < 24 {
                examples.push((i, i % 80, i / 80, direction[i], rust[i], vendor_bytes[i]));
            }
        }
    }

    println!("comparisons={} mismatches={}", GF3258_PIXELS, mismatches);
    for (i, x, y, selector, actual, expected) in examples {
        println!(
            "  output[{i}] (x={x}, y={y}) selector={selector} rust={actual} vendor={expected}"
        );
    }

    if mismatches != 0 {
        return Err(format!("c7310 parity failed: {mismatches} mismatches").into());
    }

    println!("PARITY: EXACT {}/{} values", GF3258_PIXELS, GF3258_PIXELS);
    Ok(())
}
