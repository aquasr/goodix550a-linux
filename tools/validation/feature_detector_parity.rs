use std::{collections::BTreeMap, env, error::Error, fmt::Write as _, fs, path::Path};

use goodix_info::feature::{
    FallbackExtremum, GF3258_DOG_LEVELS, GF3258_PIXELS, GF3258_PYRAMID_LEVELS, Gf3258ScaleSpace,
    RawExtremum, RefinedExtremum, RefinementOutcome,
};
use goodix_info::validation_support::{validation_root, write_i32_le, write_u16_le};

fn write_raw_extrema(path: &Path, extrema: &[RawExtremum]) -> Result<(), Box<dyn Error>> {
    let mut text = String::from("ordinal\tdog_level\tx\ty\tresponse\n");
    for (ordinal, point) in extrema.iter().enumerate() {
        writeln!(
            &mut text,
            "{}\t{}\t{}\t{}\t{}",
            ordinal, point.dog_level, point.x, point.y, point.response
        )?;
    }
    fs::write(path, text)?;
    Ok(())
}

fn write_refined(path: &Path, points: &[RefinedExtremum]) -> Result<(), Box<dyn Error>> {
    let mut text = String::from(
        "ordinal\traw_level\traw_x\traw_y\traw_response\trefined_level\trefined_x\trefined_y\t\
         dx_q12\tdy_q12\tds_q12\tx_q8\ty_q8\tresponse\tspatial_det\tscale_q16\titerations\n",
    );

    for p in points {
        writeln!(
            &mut text,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            p.ordinal,
            p.raw.dog_level,
            p.raw.x,
            p.raw.y,
            p.raw.response,
            p.dog_level,
            p.x,
            p.y,
            p.dx_q12,
            p.dy_q12,
            p.ds_q12,
            p.x_q8,
            p.y_q8,
            p.response,
            p.spatial_det,
            p.scale_q16,
            p.iterations,
        )?;
    }

    fs::write(path, text)?;
    Ok(())
}

fn write_fallback(path: &Path, points: &[FallbackExtremum]) -> Result<(), Box<dyn Error>> {
    let mut text = String::from(
        "ordinal\traw_level\traw_x\traw_y\traw_response\tfailure\tx_q8\ty_q8\tfallback_scale_q16\n",
    );

    for p in points {
        writeln!(
            &mut text,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            p.ordinal,
            p.raw.dog_level,
            p.raw.x,
            p.raw.y,
            p.raw.response,
            p.failure.as_str(),
            p.x_q8,
            p.y_q8,
            p.scale_q16,
        )?;
    }

    fs::write(path, text)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let root = validation_root(env::args_os().nth(1));

    let input_path = root.join("first_algorithm_u8_live.bin");
    let output_dir = root.join("feature_detector");

    let image = fs::read(&input_path)?;
    if image.len() != GF3258_PIXELS {
        return Err(format!(
            "{}: expected {} bytes, found {}",
            input_path.display(),
            GF3258_PIXELS,
            image.len()
        )
        .into());
    }

    fs::create_dir_all(&output_dir)?;
    let scale = Gf3258ScaleSpace::build(&image)?;

    for (level, pixels) in scale.levels().iter().enumerate() {
        let path = output_dir.join(format!("pyramid_{level:02}_u16_le.bin"));
        write_u16_le(&path, pixels)?;
    }

    for (level, response) in scale.dogs().iter().enumerate() {
        let path = output_dir.join(format!("dog_{level:02}_i32_le.bin"));
        write_i32_le(&path, response)?;
    }

    let raw = scale.raw_extrema();
    write_raw_extrema(&output_dir.join("raw_extrema.tsv"), &raw)?;

    let outcomes = scale.refinement_outcomes();

    let mut refined = Vec::new();
    let mut fallback = Vec::new();
    let mut failure_counts: BTreeMap<&'static str, usize> = BTreeMap::new();

    for outcome in &outcomes {
        match outcome {
            RefinementOutcome::Accepted(point) => refined.push(*point),
            RefinementOutcome::Fallback(point) => {
                *failure_counts.entry(point.failure.as_str()).or_default() += 1;
                fallback.push(*point);
            }
        }
    }

    let primary = scale.primary_candidates(&outcomes);

    write_refined(&output_dir.join("refined_extrema.tsv"), &refined)?;
    write_refined(&output_dir.join("primary_candidates.tsv"), &primary)?;
    write_fallback(&output_dir.join("fallback_extrema.tsv"), &fallback)?;

    let mut raw_counts = [0usize; GF3258_DOG_LEVELS];
    for point in &raw {
        raw_counts[point.dog_level as usize] += 1;
    }

    let mut refined_counts = [0usize; GF3258_DOG_LEVELS];
    for point in &refined {
        refined_counts[point.raw.dog_level as usize] += 1;
    }

    let mut summary = String::new();
    writeln!(
        &mut summary,
        "GF3258 FUN_001c0910 detector/refinement parity"
    )?;
    writeln!(&mut summary, "input={}", input_path.display())?;
    writeln!(&mut summary, "pyramid_levels={GF3258_PYRAMID_LEVELS}")?;
    writeln!(&mut summary, "dog_levels={GF3258_DOG_LEVELS}")?;
    writeln!(&mut summary, "raw_extrema={}", raw.len())?;
    writeln!(&mut summary, "refined_accepted={}", refined.len())?;
    writeln!(
        &mut summary,
        "primary_unique_after_pixel_dedup={}",
        primary.len()
    )?;
    writeln!(&mut summary, "fallback_extrema={}", fallback.len())?;

    for level in (1usize..=6).rev() {
        writeln!(
            &mut summary,
            "dog_{level}: raw={} refined={}",
            raw_counts[level], refined_counts[level]
        )?;
    }

    if !failure_counts.is_empty() {
        writeln!(&mut summary, "failure_breakdown:")?;
        for (reason, count) in failure_counts {
            writeln!(&mut summary, "  {reason}={count}")?;
        }
    }

    writeln!(&mut summary)?;
    writeln!(
        &mut summary,
        "NOTE: raw prefix is vendor-parity-proven at 138 extrema for the saved fixture."
    )?;
    writeln!(
        &mut summary,
        "NOTE: refinement now implements the GF3258 integer quadratic solve, relocation, contrast, positive-spatial-Hessian gate, scale conversion, and refined-pixel dedup."
    )?;
    writeln!(
        &mut summary,
        "NOTE: fallback_extrema.tsv is the later recovery pool input; fallback recovery and FUN_001be410 remain downstream."
    )?;

    fs::write(output_dir.join("summary.txt"), &summary)?;

    print!("{summary}");
    println!("Output directory:    {}", output_dir.display());
    println!(
        "Raw extrema:         {}",
        output_dir.join("raw_extrema.tsv").display()
    );
    println!(
        "Refined extrema:     {}",
        output_dir.join("refined_extrema.tsv").display()
    );
    println!(
        "Primary candidates:  {}",
        output_dir.join("primary_candidates.tsv").display()
    );
    println!(
        "Fallback extrema:    {}",
        output_dir.join("fallback_extrema.tsv").display()
    );

    Ok(())
}
