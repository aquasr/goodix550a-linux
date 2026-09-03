use std::{env, error::Error, fmt::Write as _, fs, path::Path};

use goodix_info::feature::{
    GF3258_FEATURE_POINT_STRIDE, GF3258_POINT_SUPPORT_REVISION, Gf3258SupportPoint,
    gf3258_point_support, gf3258_rehabilitate_point_statuses,
};
use goodix_info::validation_support::{byte_mismatches, validation_root};

fn read_exact(path: &Path) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(fs::read(path)?)
}

fn require_len(path: &Path, bytes: &[u8], expected: usize) -> Result<(), Box<dyn Error>> {
    if bytes.len() != expected {
        return Err(format!(
            "{}: expected {} bytes, found {}",
            path.display(),
            expected,
            bytes.len()
        )
        .into());
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    assert_eq!(GF3258_POINT_SUPPORT_REVISION, "gf3258-bdd40-v1");

    let root = validation_root(env::args_os().nth(1));
    let dir = root.join("feature_point_support");

    let input_points_path = dir.join("vendor_bdd40_input_points.bin");
    let output_points_path = dir.join("vendor_bdd40_output_points.bin");
    let quality164_path = dir.join("vendor_quality164_i8.bin");
    let source_path = dir.join("vendor_local208_i8.bin");
    let average_path = dir.join("vendor_local358_i8.bin");

    let input_points = read_exact(&input_points_path)?;
    if input_points.is_empty() || input_points.len() % GF3258_FEATURE_POINT_STRIDE != 0 {
        return Err(format!(
            "{}: size {} is not a nonzero multiple of FeaturePoint60 stride {}",
            input_points_path.display(),
            input_points.len(),
            GF3258_FEATURE_POINT_STRIDE
        )
        .into());
    }
    let count = input_points.len() / GF3258_FEATURE_POINT_STRIDE;

    let output_points = read_exact(&output_points_path)?;
    require_len(&output_points_path, &output_points, input_points.len())?;

    let quality164_raw = read_exact(&quality164_path)?;
    require_len(&quality164_path, &quality164_raw, count)?;
    let source_raw = read_exact(&source_path)?;
    require_len(&source_path, &source_raw, count)?;
    let vendor_average = read_exact(&average_path)?;
    require_len(&average_path, &vendor_average, count)?;

    let quality164: Vec<i8> = quality164_raw.iter().map(|&v| v as i8).collect();
    let source_quality: Vec<i8> = source_raw.iter().map(|&v| v as i8).collect();

    let points: Vec<Gf3258SupportPoint> = input_points
        .chunks_exact(GF3258_FEATURE_POINT_STRIDE)
        .map(|p| Gf3258SupportPoint {
            x_q8: u16::from_le_bytes([p[0x02], p[0x03]]),
            y_q8: u16::from_le_bytes([p[0x04], p[0x05]]),
        })
        .collect();

    let rust = gf3258_point_support(&points, &quality164, &source_quality, true)?;
    let vendor_support: Vec<u8> = output_points
        .chunks_exact(GF3258_FEATURE_POINT_STRIDE)
        .map(|p| p[0x39])
        .collect();

    fs::create_dir_all(&dir)?;
    fs::write(dir.join("rust_support_39.bin"), &rust.neighborhood_support)?;
    fs::write(dir.join("rust_local358_i8.bin"), &rust.neighborhood_average)?;

    let support_mismatches = byte_mismatches(&rust.neighborhood_support, &vendor_support);
    let average_mismatches = byte_mismatches(&rust.neighborhood_average, &vendor_average);

    // bdd40 is only allowed to mutate FeaturePoint60 +0x39.
    let mut unexpected_point_mutations = Vec::new();
    for point_index in 0..count {
        let base = point_index * GF3258_FEATURE_POINT_STRIDE;
        for field_offset in 0..GF3258_FEATURE_POINT_STRIDE {
            if field_offset == 0x39 {
                continue;
            }
            let before = input_points[base + field_offset];
            let after = output_points[base + field_offset];
            if before != after {
                unexpected_point_mutations.push((point_index, field_offset, before, after));
            }
        }
    }

    let input_statuses: Vec<u8> = input_points
        .chunks_exact(GF3258_FEATURE_POINT_STRIDE)
        .map(|p| p[0x38])
        .collect();
    let rehabilitated = gf3258_rehabilitate_point_statuses(
        &input_statuses,
        &quality164,
        &rust.neighborhood_average,
        &source_quality,
        &rust.neighborhood_support,
    )?;
    fs::write(dir.join("rust_rehabilitated_status38.bin"), &rehabilitated)?;

    let final_status_path = dir.join("vendor_after_support_gate_status38.bin");
    let mut status_exact = None;
    let mut status_mismatches = Vec::new();
    if final_status_path.exists() {
        let vendor_status = read_exact(&final_status_path)?;
        require_len(&final_status_path, &vendor_status, count)?;
        status_mismatches = byte_mismatches(&rehabilitated, &vendor_status);
        status_exact = Some(status_mismatches.is_empty());
    }

    let mut summary = String::new();
    writeln!(&mut summary, "GF3258 bdd40 point-support parity")?;
    writeln!(&mut summary, "points={count}")?;
    writeln!(
        &mut summary,
        "support comparisons={} mismatches={}",
        count,
        support_mismatches.len()
    )?;
    for (i, rust_v, vendor_v) in support_mismatches.iter().take(20) {
        writeln!(
            &mut summary,
            "  support[{i}] rust={rust_v} vendor={vendor_v}"
        )?;
    }
    writeln!(
        &mut summary,
        "local358 comparisons={} mismatches={}",
        count,
        average_mismatches.len()
    )?;
    for (i, rust_v, vendor_v) in average_mismatches.iter().take(20) {
        writeln!(
            &mut summary,
            "  local358[{i}] rust={rust_v} vendor={vendor_v}"
        )?;
    }
    writeln!(
        &mut summary,
        "unexpected_non_39_point_mutations={}",
        unexpected_point_mutations.len()
    )?;
    for (point, off, before, after) in unexpected_point_mutations.iter().take(20) {
        writeln!(
            &mut summary,
            "  point[{point}] +0x{off:02x}: before={before:02x} after={after:02x}"
        )?;
    }

    match status_exact {
        Some(exact) => {
            writeln!(
                &mut summary,
                "status_gate comparisons={} mismatches={}",
                count,
                status_mismatches.len()
            )?;
            for (i, rust_v, vendor_v) in status_mismatches.iter().take(20) {
                writeln!(
                    &mut summary,
                    "  status[{i}] rust={rust_v} vendor={vendor_v}"
                )?;
            }
            writeln!(&mut summary, "status_gate_exact={exact}")?;
        }
        None => {
            writeln!(
                &mut summary,
                "status_gate_vendor_fixture=missing (optional: {})",
                final_status_path.display()
            )?;
        }
    }

    let exact = support_mismatches.is_empty()
        && average_mismatches.is_empty()
        && unexpected_point_mutations.is_empty();
    writeln!(&mut summary, "bdd40_exact_match={exact}")?;
    if exact {
        writeln!(
            &mut summary,
            "EXACT MATCH: all GF3258 bdd40 +0x39 support and local358 outputs"
        )?;
    }

    fs::write(dir.join("point_support_summary.txt"), &summary)?;
    print!("{summary}");

    if !exact || status_exact == Some(false) {
        std::process::exit(1);
    }
    Ok(())
}
