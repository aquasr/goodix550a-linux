use std::{env, error::Error, fmt::Write as _, fs};

use goodix_info::feature::{
    GF3258_DESCRIPTOR_CENTRAL_LEN, GF3258_DESCRIPTOR_COMPACT_LEN, GF3258_DESCRIPTOR_LEN,
    GF3258_DESCRIPTOR_PADDED_LEN, GF3258_DESCRIPTOR_PROFILE_SCALE_Q16, GF3258_PIXELS,
    Gf3258ScaleSpace, gf3258_primary_descriptor, gf3258_primary_orientation,
};
use goodix_info::validation_support::{
    byte_mismatches, read_i32_le, read_u16_le, read_u32_le, u32_mismatches, validation_root,
    write_u16_le, write_u32_le,
};

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02x}").expect("writing to String cannot fail");
    }
    out
}

fn main() -> Result<(), Box<dyn Error>> {
    let root = validation_root(env::args_os().nth(1));

    let image_path = root.join("first_algorithm_u8_live.bin");
    let orientation_dir = root.join("feature_orientation");
    let descriptor_dir = root.join("feature_descriptor");
    fs::create_dir_all(&descriptor_dir)?;

    let map_i32_path = orientation_dir.join("be0b0_map_i32.bin");
    let map_u16_path = orientation_dir.join("be0b0_map_u16.bin");

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

    let scale = Gf3258ScaleSpace::build(&image)?;
    let outcomes = scale.refinement_outcomes();
    let primary = scale.primary_candidates(&outcomes);
    let candidate = primary.first().ok_or("no primary candidate 0")?;

    let candidate_ok = candidate.x == 71
        && candidate.y == 9
        && candidate.dog_level == 6
        && candidate.response == 12_796
        && candidate.x_q8 == 18_086
        && candidate.y_q8 == 2_316
        && candidate.scale_q16 == 186_353;

    if !candidate_ok {
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

    let orientation = gf3258_primary_orientation(candidate, &magnitude, &angles)?;
    if orientation.orientation_q12 != 12_185 {
        return Err(format!(
            "candidate0 orientation changed: expected 12185, found {}",
            orientation.orientation_q12
        )
        .into());
    }

    let descriptor = gf3258_primary_descriptor(
        candidate,
        orientation.orientation_q12,
        GF3258_DESCRIPTOR_PROFILE_SCALE_Q16,
        &magnitude,
        &angles,
    )?;

    write_u32_le(
        &descriptor_dir.join("rust_padded_6x6x8_u32.bin"),
        &descriptor.padded_histogram,
    )?;
    write_u32_le(
        &descriptor_dir.join("rust_descriptor128_u32.bin"),
        &descriptor.descriptor_128,
    )?;
    write_u32_le(
        &descriptor_dir.join("rust_central32_u32.bin"),
        &descriptor.central_descriptor_32,
    )?;
    write_u16_le(
        &descriptor_dir.join("rust_normalized128_u16.bin"),
        &descriptor.compact.normalized_128,
    )?;
    write_u16_le(
        &descriptor_dir.join("rust_normalized32_u16.bin"),
        &descriptor.compact.normalized_32,
    )?;

    let compact_bytes = descriptor.compact.feature_point_bytes_10_2f();
    fs::write(descriptor_dir.join("rust_compact_10_2f.bin"), compact_bytes)?;

    let geometry_ok = descriptor.radius == 16
        && descriptor.gaussian_arg == 399
        && descriptor.window.x_min_offset == -16
        && descriptor.window.x_max_offset == 7
        && descriptor.window.y_min_offset == -8
        && descriptor.window.y_max_offset == 16
        && descriptor.sin_q14 == 2_720
        && descriptor.cos_q14 == -16_157
        && descriptor.cos_step_q9 == -112
        && descriptor.sin_step_q9 == 18;

    let vendor128_path = descriptor_dir.join("vendor_descriptor128.bin");
    let vendor32_path = descriptor_dir.join("vendor_central32.bin");
    let vendor_padded_path = descriptor_dir.join("vendor_padded_6x6x8.bin");
    let vendor_compact_path = descriptor_dir.join("vendor_compact_10_2f.bin");
    let vendor_point_path = descriptor_dir.join("vendor_point0_after_bf830.bin");

    let mut summary = String::new();
    writeln!(&mut summary, "GF3258 bf830 raw descriptor parity")?;
    writeln!(
        &mut summary,
        "candidate x={} y={} level={} response={} candidate_scale_q16={} descriptor_scale_q16={} orientation_q12={}",
        candidate.x,
        candidate.y,
        candidate.dog_level,
        candidate.response,
        candidate.scale_q16,
        GF3258_DESCRIPTOR_PROFILE_SCALE_Q16,
        orientation.orientation_q12
    )?;
    writeln!(
        &mut summary,
        "radius={} gaussian_arg={} window x=[{}..{}] y=[{}..{}]",
        descriptor.radius,
        descriptor.gaussian_arg,
        descriptor.window.x_min_offset,
        descriptor.window.x_max_offset,
        descriptor.window.y_min_offset,
        descriptor.window.y_max_offset
    )?;
    writeln!(
        &mut summary,
        "cordic sin_q14={} cos_q14={} rotation cos_step_q9={} sin_step_q9={}",
        descriptor.sin_q14, descriptor.cos_q14, descriptor.cos_step_q9, descriptor.sin_step_q9
    )?;
    writeln!(&mut summary, "geometry_anchors_match={geometry_ok}")?;

    let nonzero_padded = descriptor
        .padded_histogram
        .iter()
        .filter(|&&v| v != 0)
        .count();
    let nonzero_128 = descriptor
        .descriptor_128
        .iter()
        .filter(|&&v| v != 0)
        .count();
    let nonzero_32 = descriptor
        .central_descriptor_32
        .iter()
        .filter(|&&v| v != 0)
        .count();
    writeln!(
        &mut summary,
        "nonzero padded={}/{} descriptor128={}/{} central32={}/{}",
        nonzero_padded,
        GF3258_DESCRIPTOR_PADDED_LEN,
        nonzero_128,
        GF3258_DESCRIPTOR_LEN,
        nonzero_32,
        GF3258_DESCRIPTOR_CENTRAL_LEN
    )?;
    writeln!(
        &mut summary,
        "bdee0_128 norm={} clip={} normalized_nonzero={}/{}",
        descriptor.compact.norm_128,
        descriptor.compact.clip_128,
        descriptor
            .compact
            .normalized_128
            .iter()
            .filter(|&&v| v != 0)
            .count(),
        GF3258_DESCRIPTOR_LEN
    )?;
    writeln!(
        &mut summary,
        "compact128 hadamard_words={:08x} {:08x} {:08x} {:08x} median_hash={:08x}",
        descriptor.compact.hadamard_128_words[0],
        descriptor.compact.hadamard_128_words[1],
        descriptor.compact.hadamard_128_words[2],
        descriptor.compact.hadamard_128_words[3],
        descriptor.compact.median_hash_128
    )?;
    writeln!(
        &mut summary,
        "bdee0_32 norm={} clip={} normalized_nonzero={}/{}",
        descriptor.compact.norm_32,
        descriptor.compact.clip_32,
        descriptor
            .compact
            .normalized_32
            .iter()
            .filter(|&&v| v != 0)
            .count(),
        GF3258_DESCRIPTOR_CENTRAL_LEN
    )?;
    writeln!(
        &mut summary,
        "compact32 hadamard_hash={:08x} median_hash={:08x}",
        descriptor.compact.hadamard_hash_32, descriptor.compact.median_hash_32
    )?;
    writeln!(
        &mut summary,
        "rust_compact_10_2f={}",
        hex_bytes(&compact_bytes)
    )?;

    let mut all_exact = geometry_ok;
    let mut compact_exact = None;
    let mut compared_any_vendor = false;

    if vendor128_path.exists() {
        compared_any_vendor = true;
        let vendor = read_u32_le(&vendor128_path, GF3258_DESCRIPTOR_LEN)?;
        let mismatches = u32_mismatches(&descriptor.descriptor_128, &vendor);
        writeln!(
            &mut summary,
            "vendor_descriptor128 comparisons={} mismatches={}",
            GF3258_DESCRIPTOR_LEN,
            mismatches.len()
        )?;
        for (index, actual, expected) in mismatches.iter().take(20) {
            writeln!(
                &mut summary,
                "  d128[{index}] rust={actual} vendor={expected}"
            )?;
        }
        all_exact &= mismatches.is_empty();
    } else {
        writeln!(
            &mut summary,
            "vendor_descriptor128=missing ({})",
            vendor128_path.display()
        )?;
    }

    if vendor32_path.exists() {
        compared_any_vendor = true;
        let vendor = read_u32_le(&vendor32_path, GF3258_DESCRIPTOR_CENTRAL_LEN)?;
        let mismatches = u32_mismatches(&descriptor.central_descriptor_32, &vendor);
        writeln!(
            &mut summary,
            "vendor_central32 comparisons={} mismatches={}",
            GF3258_DESCRIPTOR_CENTRAL_LEN,
            mismatches.len()
        )?;
        for (index, actual, expected) in mismatches.iter().take(20) {
            writeln!(
                &mut summary,
                "  d32[{index}] rust={actual} vendor={expected}"
            )?;
        }
        all_exact &= mismatches.is_empty();
    }

    if vendor_padded_path.exists() {
        compared_any_vendor = true;
        let vendor = read_u32_le(&vendor_padded_path, GF3258_DESCRIPTOR_PADDED_LEN)?;
        let mismatches = u32_mismatches(&descriptor.padded_histogram, &vendor);
        writeln!(
            &mut summary,
            "vendor_padded comparisons={} mismatches={}",
            GF3258_DESCRIPTOR_PADDED_LEN,
            mismatches.len()
        )?;
        for (index, actual, expected) in mismatches.iter().take(20) {
            writeln!(
                &mut summary,
                "  padded[{index}] rust={actual} vendor={expected}"
            )?;
        }
        all_exact &= mismatches.is_empty();
    }

    let vendor_compact = if vendor_compact_path.exists() {
        Some(fs::read(&vendor_compact_path)?)
    } else if vendor_point_path.exists() {
        let point = fs::read(&vendor_point_path)?;
        if point.len() != 0x3c {
            return Err(format!(
                "{}: expected 60-byte FeaturePoint, found {} bytes",
                vendor_point_path.display(),
                point.len()
            )
            .into());
        }
        Some(point[0x10..0x30].to_vec())
    } else {
        None
    };

    if let Some(vendor) = vendor_compact {
        compared_any_vendor = true;
        if vendor.len() != GF3258_DESCRIPTOR_COMPACT_LEN {
            return Err(format!(
                "vendor compact descriptor: expected {} bytes, found {}",
                GF3258_DESCRIPTOR_COMPACT_LEN,
                vendor.len()
            )
            .into());
        }

        let mismatches = byte_mismatches(&compact_bytes, &vendor);
        writeln!(
            &mut summary,
            "vendor_compact comparisons={} mismatches={}",
            GF3258_DESCRIPTOR_COMPACT_LEN,
            mismatches.len()
        )?;
        for (index, actual, expected) in mismatches.iter().take(32) {
            writeln!(
                &mut summary,
                "  compact[0x{index:02x}] rust=0x{actual:02x} vendor=0x{expected:02x}"
            )?;
        }
        let exact = mismatches.is_empty();
        compact_exact = Some(exact);
        all_exact &= exact;
    } else {
        writeln!(
            &mut summary,
            "vendor_compact=missing (supply {} or {})",
            vendor_compact_path.display(),
            vendor_point_path.display()
        )?;
    }

    if compared_any_vendor {
        writeln!(&mut summary, "all_supplied_boundaries_exact={all_exact}")?;
    }

    match compact_exact {
        Some(exact) => {
            writeln!(&mut summary, "compact_exact_match={exact}")?;
            if exact && all_exact {
                writeln!(
                    &mut summary,
                    "EXACT MATCH: bf830 raw descriptor plus bdee0/c7b80/c7f40/c8040 compact GF3258 representation"
                )?;
            }
        }
        None => {
            writeln!(
                &mut summary,
                "compact_exact_match=pending vendor +0x10..+0x2f dump"
            )?;
        }
    }

    print!("{summary}");
    fs::write(descriptor_dir.join("descriptor_summary.txt"), summary)?;

    Ok(())
}
