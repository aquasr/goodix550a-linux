use std::{env, error::Error, path::PathBuf};

use goodix_info::{
    feature::{GF3258_PIXELS, GF3258_WIDTH, gf3258_gradient_planes},
    validation_support::{read_exact, read_i32_le, read_u16_le, validation_root},
};

fn resolve_paths() -> Result<(PathBuf, PathBuf, PathBuf), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    match args.len() {
        1 => {
            let base = validation_root(None);
            Ok((
                base.join("first_algorithm_u8_live.bin"),
                base.join("be0b0_map_i32.bin"),
                base.join("be0b0_map_u16.bin"),
            ))
        }
        4 => Ok((
            PathBuf::from(&args[1]),
            PathBuf::from(&args[2]),
            PathBuf::from(&args[3]),
        )),
        _ => Err(format!(
            "usage: {} [algorithm_u8.bin vendor_magnitude_i32.bin vendor_angle_u16.bin]",
            args[0]
        )
        .into()),
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let (algorithm_path, magnitude_path, angle_path) = resolve_paths()?;

    println!("GF3258 live gradient-plane parity");
    println!("algorithm={}", algorithm_path.display());
    println!("vendor_magnitude={}", magnitude_path.display());
    println!("vendor_angle={}", angle_path.display());

    let algorithm = read_exact(&algorithm_path, GF3258_PIXELS)?;
    let vendor_magnitude = read_i32_le(&magnitude_path, GF3258_PIXELS)?;
    let vendor_angle = read_u16_le(&angle_path, GF3258_PIXELS)?;

    let rust = gf3258_gradient_planes(&algorithm)?;

    let mut magnitude_mismatches = Vec::new();
    let mut angle_mismatches = Vec::new();

    for i in 0..GF3258_PIXELS {
        if rust.magnitude_map_i32[i] != vendor_magnitude[i] {
            magnitude_mismatches.push((i, rust.magnitude_map_i32[i], vendor_magnitude[i]));
        }
        if rust.angle_map_u16[i] != vendor_angle[i] {
            angle_mismatches.push((i, rust.angle_map_u16[i], vendor_angle[i]));
        }
    }

    println!(
        "magnitude comparisons={} mismatches={}",
        GF3258_PIXELS,
        magnitude_mismatches.len()
    );
    for &(i, actual, expected) in magnitude_mismatches.iter().take(20) {
        let x = i % GF3258_WIDTH;
        let y = i / GF3258_WIDTH;
        println!("  magnitude[{i}] (x={x}, y={y}) rust={actual} vendor={expected}");
    }

    println!(
        "angle comparisons={} mismatches={}",
        GF3258_PIXELS,
        angle_mismatches.len()
    );
    for &(i, actual, expected) in angle_mismatches.iter().take(20) {
        let x = i % GF3258_WIDTH;
        let y = i / GF3258_WIDTH;
        println!("  angle[{i}] (x={x}, y={y}) rust=0x{actual:04x} vendor=0x{expected:04x}");
    }

    if magnitude_mismatches.is_empty() && angle_mismatches.is_empty() {
        println!("PARITY: EXACT 10240/10240 values");
        Ok(())
    } else {
        Err(format!(
            "gradient-plane parity failed: {} magnitude mismatches, {} angle mismatches",
            magnitude_mismatches.len(),
            angle_mismatches.len()
        )
        .into())
    }
}
