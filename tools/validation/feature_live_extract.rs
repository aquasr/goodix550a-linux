use std::{env, error::Error, fmt::Write as _, path::PathBuf};

use goodix_info::{
    feature::{
        GF3258_C2D40_INPUTS_REVISION, GF3258_C7310_REVISION, GF3258_PIXELS,
        GF3258_PRIMARY_EXTRACTION_REVISION, gf3258_extract_primary_features_from_c2d40_source,
    },
    validation_support::{read_exact, validation_root},
};

fn compact_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut out, "{byte:02x}").expect("String writes cannot fail");
    }
    out
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    let source_path = match args.as_slice() {
        [] => validation_root(None).join("feature_orientation/c7310_source_local2b8_u8.bin"),
        [source] => PathBuf::from(source),
        _ => return Err("usage: feature_live_extract [c2d40_local2b8_u8.bin]".into()),
    };

    println!("GF3258 single-source primary feature extraction");
    println!("feature_revision={GF3258_PRIMARY_EXTRACTION_REVISION}");
    println!("c2d40_inputs_revision={GF3258_C2D40_INPUTS_REVISION}");
    println!("c7310_revision={GF3258_C7310_REVISION}");
    println!("source_local2b8={}", source_path.display());

    let source = read_exact(&source_path, GF3258_PIXELS)?;
    let extraction = gf3258_extract_primary_features_from_c2d40_source(&source)?;

    let d = extraction.diagnostics();
    println!("raw_extrema={}", d.raw_extrema_count);
    println!("refined_accepted={}", d.refined_accepted_count);
    println!("refinement_fallback={}", d.refinement_fallback_count);
    println!("primary_points={}", d.primary_point_count);

    if let Some(point) = extraction.points.first() {
        println!("point0:");
        println!("  detector_x={}", point.candidate.x);
        println!("  detector_y={}", point.candidate.y);
        println!("  dog_level={}", point.candidate.dog_level);
        println!("  response={}", point.candidate.response);
        println!("  x_q8={}", point.core.x_q8);
        println!("  y_q8={}", point.core.y_q8);
        println!("  detector_scale_q16={}", point.candidate.scale_q16);
        println!("  orientation_q12={}", point.core.orientation_q12);
        println!("  ranking_score={}", point.core.ranking_score);
        println!("  descriptor_radius={}", point.descriptor.radius);
        println!(
            "  descriptor_gaussian_arg={}",
            point.descriptor.gaussian_arg
        );
        println!("  descriptor_sin_q14={}", point.descriptor.sin_q14);
        println!("  descriptor_cos_q14={}", point.descriptor.cos_q14);
        println!("  descriptor_cos_step_q9={}", point.descriptor.cos_step_q9);
        println!("  descriptor_sin_step_q9={}", point.descriptor.sin_step_q9);
        println!(
            "  compact_10_2f={}",
            compact_hex(&point.descriptor.compact.feature_point_bytes_10_2f())
        );
    }

    println!("SINGLE-SOURCE PRIMARY EXTRACTION: OK");
    Ok(())
}
