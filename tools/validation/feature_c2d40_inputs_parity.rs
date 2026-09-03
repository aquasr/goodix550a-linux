use std::{env, error::Error, path::PathBuf};

use goodix_info::{
    feature::{
        GF3258_C2D40_INPUTS_REVISION, GF3258_PIXELS, gf3258_c2d40_detector_source,
        gf3258_c7310_gradient_source,
    },
    validation_support::{read_exact, validation_root},
};

fn compare(label: &str, actual: &[u8], expected: &[u8]) -> usize {
    let mut mismatches = 0usize;
    let mut shown = 0usize;
    for i in 0..GF3258_PIXELS {
        if actual[i] != expected[i] {
            mismatches += 1;
            if shown < 24 {
                println!(
                    "  {label}[{i}] (x={}, y={}) rust={} vendor={}",
                    i % 80,
                    i / 80,
                    actual[i],
                    expected[i]
                );
                shown += 1;
            }
        }
    }
    println!(
        "{label} comparisons={} mismatches={}",
        GF3258_PIXELS, mismatches
    );
    mismatches
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    let (source_path, vendor_param1_path, vendor_param2_path) = match args.as_slice() {
        [] => {
            let root = validation_root(None);
            (
                root.join("feature_orientation/c7310_source_local2b8_u8.bin"),
                root.join("feature_orientation/c7310_output_local290_u8.bin"),
                root.join("feature_orientation/c2d40_output_local2b0_u8.bin"),
            )
        }
        [source, param1, param2] => (
            PathBuf::from(source),
            PathBuf::from(param1),
            PathBuf::from(param2),
        ),
        _ => {
            return Err(
                "usage: feature_c2d40_inputs_parity [local2b8_u8.bin local290_u8.bin local2b0_u8.bin]"
                    .into(),
            );
        }
    };

    println!("GF3258 c2d40 single-source -> c0910 input parity");
    println!("revision={GF3258_C2D40_INPUTS_REVISION}");
    println!("source_local2b8={}", source_path.display());
    println!("vendor_param1_local290={}", vendor_param1_path.display());
    println!("vendor_param2_local2b0={}", vendor_param2_path.display());

    let source = read_exact(&source_path, GF3258_PIXELS)?;
    let vendor_param1 = read_exact(&vendor_param1_path, GF3258_PIXELS)?;
    let vendor_param2 = read_exact(&vendor_param2_path, GF3258_PIXELS)?;

    let rust_param1 = gf3258_c7310_gradient_source(&source)?;
    let rust_param2 = gf3258_c2d40_detector_source(&source)?;

    let param1_mismatches = compare("param1_local290", &rust_param1, &vendor_param1);
    let param2_mismatches = compare("param2_local2b0", &rust_param2, &vendor_param2);

    if param1_mismatches != 0 || param2_mismatches != 0 {
        return Err(format!(
            "c2d40 input parity failed: param1={} param2={} mismatches",
            param1_mismatches, param2_mismatches
        )
        .into());
    }

    println!(
        "PARITY: EXACT {}/{} values",
        GF3258_PIXELS * 2,
        GF3258_PIXELS * 2
    );
    Ok(())
}
