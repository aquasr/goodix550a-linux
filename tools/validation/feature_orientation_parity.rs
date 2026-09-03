use std::{env, error::Error, fmt::Write as _, fs, path::Path};

use goodix_info::feature::{
    GF3258_ORIENTATION_BINS, GF3258_PIXELS, Gf3258FeaturePointCore, Gf3258ScaleSpace,
    gf3258_primary_orientation,
};
use goodix_info::validation_support::{read_i32_le, read_u16_le, validation_root, write_u32_le};

const EXPECTED_PRIMARY_POINTS: usize = 97;
const VENDOR_POINT_STRIDE: usize = 0x3c;

const EXPECTED_HISTOGRAM: [u32; GF3258_ORIENTATION_BINS] = [
    2_483_809, 1_435_489, 593_162, 159_745, 33_459, 12_932, 4_957, 3_689, 6_176, 7_965, 6_738,
    6_047, 10_042, 19_844, 219_779, 1_057_402, 2_369_961, 3_024_969, 2_483_809, 1_435_489, 593_162,
    159_745, 33_459, 12_932, 4_957, 3_689, 6_176, 7_965, 6_738, 6_047, 10_042, 19_844, 219_779,
    1_057_402, 2_369_961, 3_024_969,
];

#[derive(Debug, Clone, Copy)]
struct VendorPointCore {
    polarity: u16,
    x_q8: u16,
    y_q8: u16,
    orientation_q12: u16,
    ranking_score: i32,
}

#[derive(Debug, Clone, Copy)]
struct FieldMismatch {
    index: usize,
    field: &'static str,
    rust: i64,
    vendor: i64,
}

fn read_vendor_point0(path: &Path) -> Result<Option<VendorPointCore>, Box<dyn Error>> {
    if !path.exists() {
        return Ok(None);
    }

    let bytes = fs::read(path)?;
    if bytes.len() < 12 {
        return Err(format!("{}: expected at least 12 bytes", path.display()).into());
    }

    Ok(Some(parse_vendor_core(&bytes[..12])))
}

fn read_vendor_primary_points(path: &Path) -> Result<Vec<VendorPointCore>, Box<dyn Error>> {
    let bytes = fs::read(path)?;

    if bytes.len() % VENDOR_POINT_STRIDE != 0 {
        return Err(format!(
            "{}: size {} is not divisible by FeaturePoint60 stride 0x{:x}",
            path.display(),
            bytes.len(),
            VENDOR_POINT_STRIDE
        )
        .into());
    }

    let count = bytes.len() / VENDOR_POINT_STRIDE;
    if count != EXPECTED_PRIMARY_POINTS {
        return Err(format!(
            "{}: expected {} vendor FeaturePoint60 records ({} bytes), found {} records ({} bytes)",
            path.display(),
            EXPECTED_PRIMARY_POINTS,
            EXPECTED_PRIMARY_POINTS * VENDOR_POINT_STRIDE,
            count,
            bytes.len()
        )
        .into());
    }

    Ok(bytes
        .chunks_exact(VENDOR_POINT_STRIDE)
        .map(|record| parse_vendor_core(&record[..12]))
        .collect())
}

fn parse_vendor_core(bytes: &[u8]) -> VendorPointCore {
    VendorPointCore {
        polarity: u16::from_le_bytes([bytes[0], bytes[1]]),
        x_q8: u16::from_le_bytes([bytes[2], bytes[3]]),
        y_q8: u16::from_le_bytes([bytes[4], bytes[5]]),
        orientation_q12: u16::from_le_bytes([bytes[6], bytes[7]]),
        ranking_score: i32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
    }
}

fn compare_core(
    index: usize,
    rust: &Gf3258FeaturePointCore,
    vendor: &VendorPointCore,
    mismatches: &mut Vec<FieldMismatch>,
) {
    let fields = [
        ("x_q8", i64::from(rust.x_q8), i64::from(vendor.x_q8)),
        ("y_q8", i64::from(rust.y_q8), i64::from(vendor.y_q8)),
        (
            "orientation_q12",
            i64::from(rust.orientation_q12),
            i64::from(vendor.orientation_q12),
        ),
        (
            "ranking",
            i64::from(rust.ranking_score),
            i64::from(vendor.ranking_score),
        ),
    ];

    for (field, rust_value, vendor_value) in fields {
        if rust_value != vendor_value {
            mismatches.push(FieldMismatch {
                index,
                field,
                rust: rust_value,
                vendor: vendor_value,
            });
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let root = validation_root(env::args_os().nth(1));

    let image_path = root.join("first_algorithm_u8_live.bin");
    let orientation_dir = root.join("feature_orientation");
    let map_i32_path = orientation_dir.join("be0b0_map_i32.bin");
    let map_u16_path = orientation_dir.join("be0b0_map_u16.bin");
    let vendor_point0_path = orientation_dir.join("vendor_point0.bin");
    let vendor_primary_path = orientation_dir.join("vendor_primary_points.bin");

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

    let magnitude = read_i32_le(&map_i32_path, GF3258_PIXELS)?;
    let angles = read_u16_le(&map_u16_path, GF3258_PIXELS)?;
    let vendor_primary = read_vendor_primary_points(&vendor_primary_path)?;

    let scale = Gf3258ScaleSpace::build(&image)?;
    let outcomes = scale.refinement_outcomes();
    let primary = scale.primary_candidates(&outcomes);

    if primary.len() != EXPECTED_PRIMARY_POINTS {
        return Err(format!(
            "Rust detector boundary changed: expected {} primary candidates, found {}",
            EXPECTED_PRIMARY_POINTS,
            primary.len()
        )
        .into());
    }

    let candidate = primary.first().ok_or("no primary candidate 0")?;

    // The detector boundary was already closed at all 97 candidate records.
    // Keep the first record as an explicit guard for the deep orientation fixture.
    let candidate0_ok = candidate.x == 71
        && candidate.y == 9
        && candidate.dog_level == 6
        && candidate.response == 12_796
        && candidate.x_q8 == 18_086
        && candidate.y_q8 == 2_316
        && candidate.scale_q16 == 186_353;

    if !candidate0_ok {
        return Err(format!(
            "candidate 0 changed: x={} y={} level={} response={} x_q8={} y_q8={} scale_q16={}",
            candidate.x,
            candidate.y,
            candidate.dog_level,
            candidate.response,
            candidate.x_q8,
            candidate.y_q8,
            candidate.scale_q16
        )
        .into());
    }

    // Deep candidate-0 parity: compare every observed internal boundary.
    let orientation0 = gf3258_primary_orientation(candidate, &magnitude, &angles)?;
    let core0 = Gf3258FeaturePointCore::from_candidate(candidate, &orientation0);

    let histogram_mismatches: Vec<_> = orientation0
        .histogram
        .iter()
        .zip(EXPECTED_HISTOGRAM.iter())
        .enumerate()
        .filter_map(|(i, (&actual, &expected))| {
            (actual != expected).then_some((i, actual, expected))
        })
        .collect();

    let candidate0_scalar_ok = orientation0.radius == 13
        && orientation0.sigma_q16 == 279_529
        && orientation0.gaussian_arg == 1_801
        && orientation0.window.x_min_offset == -13
        && orientation0.window.x_max_offset == 7
        && orientation0.window.y_min_offset == -8
        && orientation0.window.y_max_offset == 13
        && orientation0.max_value == 3_024_969
        && orientation0.earliest_max_bin == 17
        && orientation0.returned_max_bin == 35
        && orientation0.interpolated_peak_q9 == 17_943
        && orientation0.full_angle_q12 == 25_053
        && orientation0.orientation_q12 == 12_185
        && core0.x_q8 == 18_086
        && core0.y_q8 == 2_316
        && core0.orientation_q12 == 12_185
        && core0.ranking_score == -12_796;

    let mut point0_file_ok = true;
    let mut point0_polarity = None;
    if let Some(vendor0) = read_vendor_point0(&vendor_point0_path)? {
        point0_polarity = Some(vendor0.polarity);
        point0_file_ok = vendor0.x_q8 == core0.x_q8
            && vendor0.y_q8 == core0.y_q8
            && vendor0.orientation_q12 == core0.orientation_q12
            && vendor0.ranking_score == core0.ranking_score;
    }

    write_u32_le(
        &orientation_dir.join("rust_histogram36_u32.bin"),
        &orientation0.histogram,
    )?;

    // Broad deterministic parity: all 97 primary candidates, using the exact
    // same captured magnitude/angle maps as the vendor run.
    let mut rust_cores = Vec::with_capacity(primary.len());
    let mut field_mismatches = Vec::new();

    for (index, candidate) in primary.iter().enumerate() {
        let orientation = gf3258_primary_orientation(candidate, &magnitude, &angles)?;
        let core = Gf3258FeaturePointCore::from_candidate(candidate, &orientation);
        compare_core(index, &core, &vendor_primary[index], &mut field_mismatches);
        rust_cores.push(core);
    }

    let mut rust_tsv = String::from("index\tx_q8\ty_q8\torientation_q12\tranking\n");
    for (index, core) in rust_cores.iter().enumerate() {
        writeln!(
            &mut rust_tsv,
            "{}\t{}\t{}\t{}\t{}",
            index, core.x_q8, core.y_q8, core.orientation_q12, core.ranking_score
        )?;
    }
    fs::write(
        orientation_dir.join("rust_primary_orientation_points.tsv"),
        rust_tsv,
    )?;

    let field_comparisons = EXPECTED_PRIMARY_POINTS * 4;
    let deep_exact = histogram_mismatches.is_empty() && candidate0_scalar_ok && point0_file_ok;
    let all97_exact = field_mismatches.is_empty();
    let exact = deep_exact && all97_exact;

    let mut summary = String::new();
    writeln!(&mut summary, "GF3258 candidate -> ridge orientation parity")?;
    writeln!(&mut summary)?;
    writeln!(&mut summary, "candidate0 deep parity:")?;
    writeln!(
        &mut summary,
        "  candidate x={} y={} level={} response={} x_q8={} y_q8={} scale_q16={}",
        candidate.x,
        candidate.y,
        candidate.dog_level,
        candidate.response,
        candidate.x_q8,
        candidate.y_q8,
        candidate.scale_q16
    )?;
    writeln!(
        &mut summary,
        "  radius={} sigma_q16={} gaussian_arg={}",
        orientation0.radius, orientation0.sigma_q16, orientation0.gaussian_arg
    )?;
    writeln!(
        &mut summary,
        "  window x=[{}..{}] y=[{}..{}]",
        orientation0.window.x_min_offset,
        orientation0.window.x_max_offset,
        orientation0.window.y_min_offset,
        orientation0.window.y_max_offset
    )?;
    writeln!(
        &mut summary,
        "  histogram_mismatches={}",
        histogram_mismatches.len()
    )?;
    for (bin, actual, expected) in histogram_mismatches.iter().take(10) {
        writeln!(
            &mut summary,
            "    bin[{bin}] rust={actual} vendor={expected}"
        )?;
    }
    writeln!(
        &mut summary,
        "  max={} earliest_max_bin={} returned_max_bin={}",
        orientation0.max_value, orientation0.earliest_max_bin, orientation0.returned_max_bin
    )?;
    writeln!(
        &mut summary,
        "  interpolated_peak_q9={}",
        orientation0.interpolated_peak_q9
    )?;
    writeln!(
        &mut summary,
        "  full_angle_q12={}",
        orientation0.full_angle_q12
    )?;
    writeln!(
        &mut summary,
        "  orientation_q12={}",
        orientation0.orientation_q12
    )?;
    writeln!(
        &mut summary,
        "  point_core x_q8={} y_q8={} orientation={} ranking={}",
        core0.x_q8, core0.y_q8, core0.orientation_q12, core0.ranking_score
    )?;
    if let Some(polarity) = point0_polarity {
        writeln!(
            &mut summary,
            "  vendor_point0 polarity={} (observed only; polarity is outside this feature)",
            polarity
        )?;
        writeln!(&mut summary, "  vendor_point_core_match={point0_file_ok}")?;
    } else {
        writeln!(
            &mut summary,
            "  vendor_point0.bin not present; skipped redundant point0 file comparison"
        )?;
    }
    writeln!(&mut summary, "  deep_exact={deep_exact}")?;

    writeln!(&mut summary)?;
    writeln!(&mut summary, "all-primary orientation parity:")?;
    writeln!(&mut summary, "  vendor_records={}", vendor_primary.len())?;
    writeln!(&mut summary, "  rust_records={}", rust_cores.len())?;
    writeln!(&mut summary, "  field_comparisons={field_comparisons}")?;
    writeln!(&mut summary, "  mismatches={}", field_mismatches.len())?;

    for mismatch in field_mismatches.iter().take(20) {
        writeln!(
            &mut summary,
            "    point[{}].{} rust={} vendor={}",
            mismatch.index, mismatch.field, mismatch.rust, mismatch.vendor
        )?;
    }
    if field_mismatches.len() > 20 {
        writeln!(
            &mut summary,
            "    ... {} additional mismatches omitted",
            field_mismatches.len() - 20
        )?;
    }

    // Polarity is intentionally not part of the 388 orientation-owned field
    // comparisons, but report its distribution for fixture sanity.
    let polarity_zero = vendor_primary.iter().filter(|p| p.polarity == 0).count();
    let polarity_one = vendor_primary.iter().filter(|p| p.polarity == 1).count();
    let polarity_other = vendor_primary.len() - polarity_zero - polarity_one;
    writeln!(
        &mut summary,
        "  vendor_polarity_distribution: 0={} 1={} other={} (not compared)",
        polarity_zero, polarity_one, polarity_other
    )?;
    writeln!(&mut summary, "  all97_exact={all97_exact}")?;
    writeln!(&mut summary)?;
    writeln!(&mut summary, "exact_match={exact}")?;

    fs::write(orientation_dir.join("orientation_summary.txt"), &summary)?;
    print!("{summary}");

    if !exact {
        return Err("GF3258 orientation parity mismatch".into());
    }

    println!(
        "EXACT MATCH: candidate0 internal anchors + all 97 primary records, 388/388 orientation-owned fields"
    );

    Ok(())
}
