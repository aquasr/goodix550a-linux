use std::{env, error::Error, fs, path::Path};

use goodix_info::image::{IMAGE_HEIGHT, IMAGE_WIDTH};
use goodix_info::preprocess::process_final_stage_from_corrected;
use goodix_info::validation_support::{read_u16_le, validation_root};

const PIXEL_COUNT: usize = IMAGE_WIDTH * IMAGE_HEIGHT;
const MASK_HEADER_LEN: usize = 16;

fn read_mask(path: &Path) -> Result<Vec<u8>, Box<dyn Error>> {
    let bytes = fs::read(path)?;
    if bytes.len() != MASK_HEADER_LEN + PIXEL_COUNT {
        return Err(format!(
            "{}: expected {} bytes, found {}",
            path.display(),
            MASK_HEADER_LEN + PIXEL_COUNT,
            bytes.len()
        )
        .into());
    }

    let foreground = u32::from_le_bytes(bytes[0..4].try_into()?);
    let height = u32::from_le_bytes(bytes[4..8].try_into()?);
    let width = u32::from_le_bytes(bytes[8..12].try_into()?);
    let threshold = u16::from_le_bytes(bytes[12..14].try_into()?);
    let coverage = u16::from_le_bytes(bytes[14..16].try_into()?);

    println!(
        "Vendor mask: foreground={foreground}/{} width={width} height={height} threshold={threshold} coverage={coverage}%",
        PIXEL_COUNT
    );

    if width as usize != IMAGE_WIDTH || height as usize != IMAGE_HEIGHT {
        return Err(format!(
            "vendor mask geometry is {width}x{height}, expected {}x{}",
            IMAGE_WIDTH, IMAGE_HEIGHT
        )
        .into());
    }

    Ok(bytes[MASK_HEADER_LEN..].to_vec())
}

fn main() -> Result<(), Box<dyn Error>> {
    let root = validation_root(env::args_os().nth(1));

    let corrected_path = root.join("first_pre60590_corrected_u16.bin");
    let mask_path = root.join("vendor_mask_result.bin");
    let vendor_path = root.join("first_algorithm_u8_live.bin");
    let rust_path = root.join("rust_from_vendor_pre60590_u8.bin");

    println!("Validation directory: {}", root.display());
    println!("Corrected input:      {}", corrected_path.display());
    println!("Mask result:          {}", mask_path.display());
    println!("Vendor output:        {}", vendor_path.display());

    let corrected = read_u16_le(&corrected_path, PIXEL_COUNT)?;
    let mask = read_mask(&mask_path)?;
    let vendor = fs::read(&vendor_path)?;

    if vendor.len() != PIXEL_COUNT {
        return Err(format!(
            "{}: expected {} bytes, found {}",
            vendor_path.display(),
            PIXEL_COUNT,
            vendor.len()
        )
        .into());
    }

    let result = process_final_stage_from_corrected(&corrected, &mask)?;
    let rust = result.pixels();
    fs::write(&rust_path, rust)?;

    let mut differing = 0usize;
    let mut border_differing = 0usize;
    let mut interior_differing = 0usize;
    let mut max_abs_diff = 0u8;
    let mut sum_abs_diff = 0u64;
    let mut examples = Vec::new();

    for (i, (&actual, &expected)) in rust.iter().zip(&vendor).enumerate() {
        if actual == expected {
            continue;
        }

        differing += 1;
        let x = i % IMAGE_WIDTH;
        let y = i / IMAGE_WIDTH;
        let border = x == 0 || y == 0 || x + 1 == IMAGE_WIDTH || y + 1 == IMAGE_HEIGHT;
        if border {
            border_differing += 1;
        } else {
            interior_differing += 1;
        }

        let abs_diff = actual.abs_diff(expected);
        max_abs_diff = max_abs_diff.max(abs_diff);
        sum_abs_diff += u64::from(abs_diff);

        if examples.len() < 32 {
            examples.push((
                i,
                x,
                y,
                expected,
                actual,
                i16::from(actual) - i16::from(expected),
            ));
        }
    }

    println!("Rust output:           {}", rust_path.display());
    println!(
        "Low dynamic range:     {} foreground pixels",
        result.low_dynamic_range_count()
    );
    println!("Differing pixels:      {differing}/{PIXEL_COUNT}");
    println!("  border:              {border_differing}");
    println!("  interior:            {interior_differing}");
    println!("Maximum abs diff:      {max_abs_diff}");
    println!("Sum abs diff:          {sum_abs_diff}");

    if differing == 0 {
        println!(
            "RESULT: EXACT MATCH — recovered FUN_00160590 pixel path is byte-identical for this vendor frame."
        );
    } else {
        let mean = sum_abs_diff as f64 / differing as f64;
        println!("Mean abs diff (diffs): {mean:.4}");
        println!("RESULT: MISMATCH");
        println!("First {} mismatches:", examples.len());
        println!("index\tx\ty\tvendor\trust\tdelta");
        for (i, x, y, expected, actual, delta) in examples {
            println!("{i}\t{x}\t{y}\t{expected}\t{actual}\t{delta}");
        }
    }

    Ok(())
}
