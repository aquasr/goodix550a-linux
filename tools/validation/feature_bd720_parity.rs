use std::{env, error::Error, path::PathBuf};

use goodix_info::{
    feature::{GF3258_BD720_REVISION, GF3258_PIXELS, gf3258_bd720_validity},
    validation_support::{read_exact, validation_root},
};

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args_os().skip(1);
    let root = validation_root(None);
    let source = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("feature_orientation/bd720_source_local2b8_u8.bin"));
    let vendor_mask = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("feature_orientation/bd720_output_local298_u8.bin"));

    if args.next().is_some() {
        return Err("usage: feature_bd720_parity [source_local2b8.bin vendor_local298.bin]".into());
    }

    let source_bytes = read_exact(&source, GF3258_PIXELS)?;
    let vendor = read_exact(&vendor_mask, GF3258_PIXELS)?;
    let rust = gf3258_bd720_validity(&source_bytes)?;

    let mut mismatches = 0usize;
    let mut shown = 0usize;
    for (i, &vendor_value) in vendor.iter().enumerate().take(GF3258_PIXELS) {
        if rust.mask_u8[i] != vendor_value {
            mismatches += 1;
            if shown < 20 {
                let x = i % 80;
                let y = i / 80;
                eprintln!(
                    "mismatch[{i}] x={x} y={y}: rust={} vendor={}",
                    rust.mask_u8[i], vendor_value
                );
                shown += 1;
            }
        }
    }

    let vendor_selected = vendor.iter().filter(|&&value| value != 0).count();
    let vendor_nonbinary = vendor.iter().filter(|&&value| value > 1).count();

    println!("GF3258 bd720 local_2b8 -> local_298 validity parity");
    println!("revision={GF3258_BD720_REVISION}");
    println!("source_local2b8={}", source.display());
    println!("vendor_local298={}", vendor_mask.display());
    println!("rust_selected_pixels={}", rust.selected_pixels);
    println!("rust_coverage_q16={}", rust.coverage_q16);
    println!("vendor_selected_pixels={vendor_selected}");
    println!("vendor_nonbinary_values={vendor_nonbinary}");
    println!("comparisons={GF3258_PIXELS} mismatches={mismatches}");

    if mismatches == 0 && vendor_nonbinary == 0 {
        println!("PARITY: EXACT {GF3258_PIXELS}/{GF3258_PIXELS} values");
        Ok(())
    } else {
        Err(format!(
            "bd720 parity failed: {mismatches} mismatches, {vendor_nonbinary} nonbinary vendor bytes"
        )
        .into())
    }
}
