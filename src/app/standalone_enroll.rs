//! Standalone GF3258 WN2 enrollment runner.
//!
//! No proprietary Goodix host .so is used by this executable.
//!
//! The runner uses the recovered Rust USB/session/image path, persistent
//! preprocessing state, feature extraction, registration, enrollment graph,
//! raw-template serialization, and fresh TGLA persistence.
//!
//! Enrollment completion follows the recovered GF3258 vendor policy:
//!
//! - GeneralSamples = 12.
//! - Each successfully retained sample increments the accepted-sample count.
//! - Progress is floor(accepted_samples * 100 / 12), clamped to 100.
//! - Rejected captures do not advance progress.
//!
//! On successful enrollment the runner writes:
//!
//! - the raw algorithm template;
//! - the recovered fresh TGLA wrapper.
//!
//! `--load-template` performs a load-only persistence validation in a fresh
//! process without opening the USB sensor.

use super::{
    error::{AppResult, invalid_data, invalid_input},
    require_unprivileged_hardware_access,
};
use std::{env, error::Error, fs, path::PathBuf};

use crate::driver::{Gf3258DeviceSession, Gf3258EnrollmentTransaction};
use crate::enrollment::{
    GF3258_ENROLLMENT_TARGET_SAMPLES, GF3258_TEMPLATE_PERSISTENCE_REVISION,
    GF3258_TEMPLATE_STORAGE_REVISION, Gf3258EnrollmentAddKind, Gf3258EnrollmentGraphDiagnostics,
    Gf3258EnrollmentPreparation, Gf3258EnrollmentRejection, Gf3258PreprocessDiagnostics,
    gf3258_validate_fresh_tgla,
};
use crate::feature::{
    GF3258_A8200_REVISION, GF3258_BD720_REVISION, GF3258_MATCH_SCORE_MATRIX_STRIDE,
    Gf3258CandidateMatcherConfig, Gf3258OwnedMatcherFeature, gf3258_generate_match_candidates,
};
use crate::registration::gf3258_matcher_geometry_from_pair_slots;
use crate::trace::TraceLogger;

/// Operational safety bound only.
///
/// Rejected captures do not consume enrollment progress.
const DEFAULT_MAX_ATTEMPTS: usize = 36;

/// Recovered GF3258 initial matcher vector prefix used by
/// b0e90 -> afda0 -> ae220. The later refinement path may change 38 -> 36,
/// but the first-pass candidate generation uses the values below.
const GF3258_MATCHER_DIAGNOSTIC_CONFIG: Gf3258CandidateMatcherConfig =
    Gf3258CandidateMatcherConfig {
        first_half_hamming_max: 23,
        descriptor_mode_hamming_max: 47,
        ambiguity_best_multiplier: 40,
        ambiguity_second_multiplier: 38,
    };

#[derive(Debug)]
struct Options {
    max_attempts: usize,
    trace_path: Option<PathBuf>,
    firmware_path: Option<PathBuf>,
    raw_template_path: PathBuf,
    tgla_template_path: PathBuf,
    load_template_path: Option<PathBuf>,
}

pub fn run() -> AppResult<()> {
    let options = parse_arguments()?;

    // Load-only mode intentionally returns before any USB device is opened.
    if let Some(path) = options.load_template_path.as_deref() {
        let bytes = fs::read(path)?;
        let validated = gf3258_validate_fresh_tgla(&bytes)?;
        let diagnostics = validated.diagnostics();

        println!("GF3258 persistent template reload: OK");
        println!("file: {}", path.display());
        println!("TGLA total size: {}", diagnostics.total_size);
        println!("raw template size: {}", diagnostics.raw_length);
        println!("raw CRC32/MPEG-2: 0x{:08x}", diagnostics.raw_crc);

        println!("config prefix zero: {}", diagnostics.config_prefix_zero);

        println!("commit metadata zero: {}", diagnostics.commit_metadata_zero);

        println!("trailing calloc bytes: {}", diagnostics.trailing_zero_bytes);

        let raw = validated.raw_template();

        if raw.len() >= 6 {
            println!(
                "raw envelope: magic=0x{:02x} crc_le={:02x?} payload_tag=0x{:02x}",
                raw[0],
                &raw[1..5],
                raw[5],
            );
        }

        println!("MILESTONE: persistent TGLA survived process restart and validated successfully.");

        return Ok(());
    }

    require_unprivileged_hardware_access()?;

    println!("GF3258 standalone enrollment");
    println!("target: Goodix 27c6:550a / GM168SEC / GF3258 WN2");
    println!("vendor GeneralSamples target: {GF3258_ENROLLMENT_TARGET_SAMPLES}");
    println!("operational max attempts: {}", options.max_attempts);
    println!("bd720 revision: {GF3258_BD720_REVISION}");
    println!("a8200 revision: {GF3258_A8200_REVISION}");
    println!("template persistence revision: {GF3258_TEMPLATE_PERSISTENCE_REVISION}");
    println!("template storage revision: {GF3258_TEMPLATE_STORAGE_REVISION}");
    println!(
        "raw template output: {}",
        options.raw_template_path.display()
    );
    println!(
        "TGLA template output: {}",
        options.tgla_template_path.display()
    );
    println!();

    println!("IMPORTANT: stop fprintd before running this executable.");
    println!("No proprietary Goodix host .so is loaded or called by this program.");
    println!(
        "Vendor GdxEnc sealing is intentionally not used; standalone persistence stores the recovered TGLA representation directly."
    );
    println!(
        "Multi-frame adaptive preprocessing state beyond the recovered immediate path remains partial."
    );
    println!("Captures with unresolved pathological top/bottom edge samples are rejected.");
    println!();

    let trace = TraceLogger::new(options.trace_path.as_deref())?;
    let firmware = options.firmware_path.as_deref().map(fs::read).transpose()?;
    let mut session = match firmware.as_deref() {
        Some(bytes) => Gf3258DeviceSession::open_with_firmware_and_trace(bytes, trace)?,
        None => Gf3258DeviceSession::open_with_trace(trace)?,
    };
    let layout = session.usb_layout();

    println!("USB interface claimed: {}", layout.interface());
    println!(
        "bulk OUT=0x{:02x} IN=0x{:02x}",
        layout.bulk_out(),
        layout.bulk_in()
    );
    println!("firmware: {}", session.firmware_version());
    println!(
        "MCU volatile-state lost: {}",
        session.mcu_power_lost_on_open()
    );
    println!("session startup: {}", session.startup());

    // One driver transaction owns the stateful preprocessor and retained
    // enrollment/template state while the reusable device session owns USB.
    // Diagnostic policy remains application-only.
    let mut enrollment = Gf3258EnrollmentTransaction::new();

    // Keep matcher-ready copies in the same order as retained enrollment
    // samples. The current touch is compared against this cache *before* it is
    // inserted, preventing an accidental self-match diagnostic.
    let mut matcher_reference_samples: Vec<Gf3258OwnedMatcherFeature> = Vec::new();

    let mut accepted_live_relations = 0usize;
    let mut rejected_pathological = 0usize;
    let mut rejected_oversized_points = 0usize;

    // FUN_00144c20 EnrollStart copies AlgoConfig.GeneralSamples into the
    // enrollment target. The driver transaction owns the retained-sample count
    // and exact vendor progress arithmetic.
    let mut attempted_touches = 0usize;

    while !enrollment.is_complete() && attempted_touches < options.max_attempts {
        attempted_touches += 1;
        let attempt_number = attempted_touches;

        println!();
        println!("================================================================");
        println!("TOUCH ATTEMPT #{attempt_number}");
        println!("================================================================");

        println!("waiting for finger...");
        let detailed = enrollment.capture_next_prepared(&mut session)?;
        let capture = detailed.capture_diagnostics();

        println!(
            "capture: OK protected={}B crc=0x{:08x} raw_pixels={}",
            capture.protected_bytes(),
            capture.stored_crc(),
            crate::image::IMAGE_WIDTH * crate::image::IMAGE_HEIGHT
        );

        let (_, preparation) = detailed.into_parts();
        let prepared = match preparation {
            Gf3258EnrollmentPreparation::Rejected(Gf3258EnrollmentRejection::Preprocess(error)) => {
                println!("preprocess: REJECT ({error})");
                continue;
            }

            Gf3258EnrollmentPreparation::Rejected(Gf3258EnrollmentRejection::TooManyPoints {
                actual,
                capacity,
            }) => {
                rejected_oversized_points += 1;
                println!(
                    "features: REJECT point_count={actual} exceeds recovered capacity {capacity}"
                );
                continue;
            }

            Gf3258EnrollmentPreparation::Rejected(
                Gf3258EnrollmentRejection::PathologicalEdge { diagnostics },
            ) => {
                print_preprocess_diagnostics(diagnostics);
                rejected_pathological += 1;

                println!(
                    "sample: REJECT unresolved pathological-edge branch encountered ({} samples)",
                    diagnostics.pathological_edge_samples
                );

                continue;
            }

            Gf3258EnrollmentPreparation::Prepared(prepared) => prepared,
        };

        print_preprocess_diagnostics(prepared.preprocess_diagnostics());

        let feature_diag = prepared.extraction().diagnostics();

        println!(
            "features: raw_extrema={} refined={} fallback={} primary={}",
            feature_diag.raw_extrema_count,
            feature_diag.refined_accepted_count,
            feature_diag.refinement_fallback_count,
            feature_diag.primary_point_count,
        );

        let validity = prepared.validity_diagnostics();

        println!(
            "validity: bd720_selected={}/5120 coverage_q16={} quarter_valid={}/320",
            validity.bd720_selected_pixels,
            validity.bd720_coverage_q16,
            validity.quarter_selected_cells,
        );

        // Diagnostic only: exercise the recovered verify front half on a real
        // touch before enrollment mutates the template. This result does not
        // affect enrollment acceptance, progress, graph state, or persistence.
        let current_matcher_feature =
            Gf3258OwnedMatcherFeature::from_primary_extraction(prepared.extraction());

        print_matcher_diagnostics(&matcher_reference_samples, &current_matcher_feature)?;

        let committed = enrollment.commit_prepared(prepared)?;
        let accepted_samples = committed.sample_count;
        let progress = committed.progress_percent;
        let step = committed.step;

        // A successful return means this enrollment sample was retained. Keep
        // its matcher-facing copy only now, after the production enrollment
        // path has accepted the sample.
        matcher_reference_samples.push(current_matcher_feature);

        println!(
            "feature object: points={} primary_map_foreground={} active_valid_cells={} status={}",
            step.feature.point_count,
            step.feature.primary_foreground_cells,
            step.feature.valid_cells,
            step.feature.status,
        );

        println!(
            "enrollment add: kind={:?} sample_index={} successful_previous={:?}",
            step.enrollment.kind,
            step.enrollment.current_index,
            step.enrollment.successful_previous,
        );

        if step.enrollment.attempts.is_empty() {
            println!("registration: first stored sample; no previous sample to compare");
        } else {
            for attempt in &step.enrollment.attempts {
                match attempt.map_scores {
                    Some(scores) => println!(
                        "registration prev={} pairs={} inliers={} metricA={} metricB={} graphScore={} accepted={} reject={:?}",
                        attempt.previous_index,
                        attempt.correspondence_count,
                        attempt.geometric_inliers,
                        scores.metric_a,
                        scores.metric_b,
                        scores.score,
                        attempt.accepted,
                        attempt.reject_reason,
                    ),

                    None => println!(
                        "registration prev={} pairs={} inliers={} metricA=n/a metricB=n/a graphScore=n/a accepted={} reject={:?}",
                        attempt.previous_index,
                        attempt.correspondence_count,
                        attempt.geometric_inliers,
                        attempt.accepted,
                        attempt.reject_reason,
                    ),
                }
            }
        }

        if step.enrollment.kind == Gf3258EnrollmentAddKind::Integrated {
            let newly_accepted = step.enrollment.successful_previous.len();

            accepted_live_relations += newly_accepted;

            println!(
                "LIVE CROSS-TOUCH REGISTRATION: ACCEPTED against {} previous sample(s)",
                newly_accepted
            );
        }

        if let Some(graph) = &step.enrollment.graph_integration {
            println!(
                "graph integration: anchor={:?} current_canonical={} promoted={:?} novel_coverage={}",
                graph.canonical_anchor,
                graph.current_is_canonical,
                graph.promoted_samples,
                graph.novel_coverage,
            );
        }

        print_graph_summary(enrollment.graph_diagnostics());

        println!(
            "enrollment progress: accepted_samples={}/{} progress={}%%",
            accepted_samples, GF3258_ENROLLMENT_TARGET_SAMPLES, progress
        );

        if progress == 100 {
            println!("ENROLLMENT COMPLETE: recovered GF3258 GeneralSamples target reached");
            break;
        }
    }

    let accepted_samples = enrollment.sample_count();
    let final_progress = enrollment.progress_percent();

    println!();
    println!("================================================================");
    println!("LIVE ENROLLMENT RUN SUMMARY");
    println!("================================================================");

    println!("touch attempts performed: {attempted_touches}");

    println!(
        "accepted/retained enrollment samples: {accepted_samples}/{GF3258_ENROLLMENT_TARGET_SAMPLES}"
    );

    println!("vendor-style progress: {final_progress}%%");

    println!("pathological-edge captures rejected: {rejected_pathological}");

    println!("oversized-point captures rejected: {rejected_oversized_points}");

    println!("accepted direct cross-touch relations: {accepted_live_relations}");

    print_graph_summary(enrollment.graph_diagnostics());

    if final_progress == 100 {
        println!(
            "MILESTONE: standalone enrollment reached the recovered vendor completion target (12 retained samples)."
        );
    } else {
        println!(
            "ENROLLMENT INCOMPLETE: safety limit reached at {accepted_samples}/{GF3258_ENROLLMENT_TARGET_SAMPLES} retained samples ({final_progress}%%)."
        );

        println!(
            "Increase --max-attempts if needed; rejected captures do not advance vendor progress."
        );
    }

    if accepted_live_relations > 0 {
        println!("Cross-touch registration + enrollment graph growth were also observed.");
    } else {
        println!(
            "No direct cross-touch relation passed during this run; inspect per-pair diagnostics."
        );
    }

    if final_progress == 100 {
        let artifacts = enrollment.finish()?;
        let raw_template = artifacts.raw_template();
        let tgla = artifacts.tgla_template();
        let tgla_diagnostics = artifacts.tgla_diagnostics();

        fs::write(&options.raw_template_path, raw_template)?;

        println!(
            "raw algorithm template: wrote {} bytes to {}",
            raw_template.len(),
            options.raw_template_path.display()
        );

        println!(
            "raw envelope: magic=0x{:02x} crc_le={:02x?} payload_tag=0x{:02x}",
            raw_template[0],
            &raw_template[1..5],
            raw_template[5],
        );

        fs::write(&options.tgla_template_path, tgla)?;

        println!(
            "TGLA persistent template: wrote {} bytes to {}",
            tgla.len(),
            options.tgla_template_path.display()
        );

        println!(
            "TGLA: raw={}B total={}B raw_crc_mpeg2=0x{:08x}",
            tgla_diagnostics.raw_length, tgla_diagnostics.total_size, tgla_diagnostics.raw_crc,
        );

        println!(
            "TGLA fixed fields: config_prefix_zero={} commit_metadata_zero={} trailing_zero_bytes={}",
            tgla_diagnostics.config_prefix_zero,
            tgla_diagnostics.commit_metadata_zero,
            tgla_diagnostics.trailing_zero_bytes,
        );

        // Re-read the actual file rather than validating only the in-memory
        // Vec. Filesystem I/O stays in the application; byte validation stays
        // in the reusable enrollment transaction/workflow.
        let reloaded_bytes = fs::read(&options.tgla_template_path)?;

        let reloaded = artifacts.validate_tgla_bytes(&reloaded_bytes)?;

        println!(
            "persistent reload validation: PASS raw={}B total={}B",
            reloaded.raw_length, reloaded.total_size,
        );

        println!(
            "Reload check: run standalone_enroll --load-template {} in a new process.",
            options.tgla_template_path.display()
        );
    } else {
        println!(
            "persistent template not written because enrollment did not reach 12/12 retained samples."
        );
    }

    Ok(())
}

fn print_matcher_diagnostics(
    enrolled_samples: &[Gf3258OwnedMatcherFeature],
    live: &Gf3258OwnedMatcherFeature,
) -> Result<(), Box<dyn Error>> {
    println!(
        "matcher diagnostic: live_points={} polarity_split={} prior_retained_samples={}",
        live.points.len(),
        live.polarity_split,
        enrolled_samples.len(),
    );

    if enrolled_samples.is_empty() {
        println!("matcher diagnostic: first retained candidate; no prior sample to compare");
        return Ok(());
    }

    for (sample_index, enrolled) in enrolled_samples.iter().enumerate() {
        let candidates = gf3258_generate_match_candidates(
            enrolled.as_feature_set(),
            live.as_feature_set(),
            GF3258_MATCHER_DIAGNOSTIC_CONFIG,
        )?;

        let geometry = gf3258_matcher_geometry_from_pair_slots(
            &enrolled.points,
            &live.points,
            &candidates.pair_slots,
        )
        .map_err(|error| {
            invalid_data(format!(
                "matcher geometry failed for retained sample {sample_index}: {error:?}"
            ))
        })?;

        let normal_mode_selected = candidates
            .selected
            .iter()
            .filter(|pair| {
                let enrolled_index = pair.enrolled_index as usize;
                let live_index = pair.live_index as usize;
                candidates.pair_normal_mode_matrix
                    [enrolled_index * GF3258_MATCH_SCORE_MATRIX_STRIDE + live_index]
            })
            .count();
        let alternate_mode_selected = candidates.selected.len() - normal_mode_selected;

        let transform = geometry.transform_live_to_enrolled;
        println!(
            "matcher sample {}: enrolled_points={} enrolled_split={} candidate_pairs={} normal_mode={} alternate_mode={} spatial_inliers={} final_inliers={} mse_q16={} hypotheses={} affine_live_to_enrolled=[{}, {}, {}, {}, {}, {}] refit_triggered={}",
            sample_index,
            enrolled.points.len(),
            enrolled.polarity_split,
            candidates.selected.len(),
            normal_mode_selected,
            alternate_mode_selected,
            geometry.spatial_inlier_count,
            geometry.final_inlier_count,
            geometry.spatial_mse_q16,
            geometry.hypotheses_tested,
            transform.a,
            transform.b,
            transform.tx,
            transform.c,
            transform.d,
            transform.ty,
            geometry.vendor_refit_triggered,
        );
    }

    Ok(())
}

fn print_preprocess_diagnostics(diagnostics: Gf3258PreprocessDiagnostics) {
    println!(
        "preprocess: OK central_valid={}/{} foreground={} coverage={}%% active_diff={} gain_correction={} low_dynamic={} pathological_edge={}",
        diagnostics.valid_central_pixels,
        diagnostics.tested_central_pixels,
        diagnostics.foreground_count,
        diagnostics.coverage_percent,
        diagnostics.active_difference_count,
        diagnostics.gain_correction_active,
        diagnostics.low_dynamic_range_count,
        diagnostics.pathological_edge_samples,
    );
}

fn print_graph_summary(diagnostics: Gf3258EnrollmentGraphDiagnostics) {
    println!(
        "graph: nodes={} relations={} canonical_nodes={} anchor={:?}",
        diagnostics.nodes,
        diagnostics.nonnegative_relations,
        diagnostics.canonical_nodes,
        diagnostics.canonical_anchor,
    );
}

fn parse_arguments() -> Result<Options, Box<dyn Error>> {
    let mut max_attempts = DEFAULT_MAX_ATTEMPTS;

    let mut trace_path = None;

    let mut firmware_path = None;

    let mut raw_template_path = PathBuf::from("gf3258-enrollment.raw");

    let mut tgla_template_path = PathBuf::from("gf3258-enrollment.tgla");

    let mut load_template_path = None;

    let mut args = env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--max-attempts" | "--touches" => {
                let option_name = arg;

                let value = args.next().ok_or_else(|| {
                    invalid_input(format!("{option_name} requires a positive integer"))
                })?;

                max_attempts = value
                    .parse::<usize>()
                    .map_err(|_| invalid_input(format!("invalid {option_name} value: {value}")))?;

                if max_attempts == 0 {
                    return Err(
                        invalid_input(format!("{option_name} must be greater than zero")).into(),
                    );
                }
            }

            "--trace" => {
                let value = args
                    .next()
                    .ok_or_else(|| invalid_input("--trace requires a filename"))?;

                trace_path = Some(PathBuf::from(value));
            }

            "--firmware" => {
                let value = args
                    .next()
                    .ok_or_else(|| invalid_input("--firmware requires a filename"))?;

                firmware_path = Some(PathBuf::from(value));
            }

            "--raw-template" => {
                let value = args
                    .next()
                    .ok_or_else(|| invalid_input("--raw-template requires a filename"))?;

                raw_template_path = PathBuf::from(value);
            }

            "--tgla-template" | "--template" => {
                let value = args
                    .next()
                    .ok_or_else(|| invalid_input("--tgla-template requires a filename"))?;

                tgla_template_path = PathBuf::from(value);
            }

            "--load-template" => {
                let value = args
                    .next()
                    .ok_or_else(|| invalid_input("--load-template requires a filename"))?;

                load_template_path = Some(PathBuf::from(value));
            }

            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }

            _ => {
                return Err(invalid_input(format!("unknown argument: {arg}")).into());
            }
        }
    }

    if load_template_path.is_none() && max_attempts < GF3258_ENROLLMENT_TARGET_SAMPLES {
        eprintln!(
            "warning: max attempts ({max_attempts}) is below the recovered {}-sample completion target; completion is impossible if every attempt succeeds",
            GF3258_ENROLLMENT_TARGET_SAMPLES
        );
    }

    Ok(Options {
        max_attempts,
        trace_path,
        firmware_path,
        raw_template_path,
        tgla_template_path,
        load_template_path,
    })
}

fn print_usage() {
    println!(
        r#"Usage:

Enrollment:
  cargo run --release --bin standalone_enroll -- \
    [--max-attempts N] \
    [--trace FILE] \
    [--firmware FILE] \
    [--raw-template FILE] \
    [--tgla-template FILE]

Reload-only validation:
  cargo run --release --bin standalone_enroll -- \
    --load-template FILE

Enrollment captures fresh physical touches until the recovered GF3258
vendor target is reached: GeneralSamples=12 retained samples.
Rejected captures do not advance progress. --firmware supplies exact
APP15045 bytes when automatic IAP recovery is required; an already-running
APP device is never rewritten.

On successful enrollment:
  raw algorithm template -> gf3258-enrollment.raw
  fresh TGLA template     -> gf3258-enrollment.tgla

--load-template validates an already-written TGLA without opening USB."#
    );
}
