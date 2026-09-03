//! Standalone GF3258 WN2 verification runner.
//!
//! The executable loads a persisted TGLA template, captures a fresh protected
//! sensor frame, runs the open Rust image/feature pipeline, scans the persisted
//! gallery and prints the complete signed vendor-equivalent core score. No
//! proprietary Goodix host library is loaded or called.

use std::{env, fs, path::PathBuf};

use crate::driver::{Gf3258DeviceSession, Gf3258VerificationTransaction};
use crate::trace::TraceLogger;
use crate::verification::{
    GF3258_LIVE_VERIFICATION_FEATURE_REVISION, GF3258_PERSISTED_GALLERY_VERIFICATION_REVISION,
    GF3258_RECOGNITION_QUALITY_SCALE_Q8, Gf3258DetailedRawFrameVerificationOutcome,
    Gf3258GalleryVerificationDecision, Gf3258LiveVerificationRejection,
};

use super::{
    error::{AppResult, invalid_data, invalid_input},
    require_unprivileged_hardware_access,
};

const DEFAULT_ATTEMPTS: usize = 1;

#[derive(Debug)]
struct Options {
    template_path: PathBuf,
    attempts: usize,
    trace_path: Option<PathBuf>,
    firmware_path: Option<PathBuf>,
    label: Option<String>,
}

pub fn run() -> AppResult<()> {
    let options = parse_arguments()?;

    let template_bytes = fs::read(&options.template_path)?;
    let mut verification = Gf3258VerificationTransaction::from_tgla(&template_bytes)
        .map_err(|error| invalid_data(error.to_string()))?;

    require_unprivileged_hardware_access()?;

    println!("GF3258 standalone verification");
    println!("target: Goodix 27c6:550a / GM168SEC / GF3258 WN2");
    println!("template: {}", options.template_path.display());
    println!("enrolled samples: {}", verification.sample_count());
    println!(
        "configured max samples: {}",
        verification.configured_max_samples()
    );
    println!("live feature revision: {GF3258_LIVE_VERIFICATION_FEATURE_REVISION}");
    println!("gallery revision: {GF3258_PERSISTED_GALLERY_VERIFICATION_REVISION}");
    println!("recognition coverage scale Q8: {GF3258_RECOGNITION_QUALITY_SCALE_Q8}");
    if let Some(label) = options.label.as_deref() {
        println!("operator label: {label}");
    }
    println!();
    println!("IMPORTANT: stop fprintd before running this executable.");
    println!("No proprietary Goodix host .so is loaded or called by this program.");
    println!("Fresh optional verification-profile/cache state remains disabled.");
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

    let mut completed = 0usize;
    let mut rejected = 0usize;

    for attempt in 1..=options.attempts {
        println!();
        println!("================================================================");
        println!("VERIFY TOUCH #{attempt}");
        println!("================================================================");

        println!("waiting for finger...");
        let touch = verification.capture_next_detailed(&mut session)?;
        let capture = touch.capture_diagnostics();
        println!(
            "capture: OK protected={}B crc=0x{:08x} raw_pixels={}",
            capture.protected_bytes(),
            capture.stored_crc(),
            touch.pixel_count(),
        );

        match touch.into_outcome() {
            Gf3258DetailedRawFrameVerificationOutcome::Rejected(reason) => {
                rejected += 1;
                print_rejection(reason);
            }
            Gf3258DetailedRawFrameVerificationOutcome::Verified {
                decision,
                diagnostics,
                result,
            } => {
                completed += 1;
                let normal_percent = result.normal_loop.score.percent().unwrap_or(0);
                println!(
                    "live: points={} quality={} raw_quality={} raw_quality_rejected={} coverage={}%% quarter_valid={} preprocess_coverage={}%% class4={:?}",
                    diagnostics.point_count,
                    diagnostics.quality,
                    diagnostics.raw_quality,
                    diagnostics.raw_quality_rejected,
                    diagnostics.coverage,
                    diagnostics.quarter_selected_cells,
                    diagnostics.preprocess_coverage_percent,
                    diagnostics.class4_percent,
                );
                println!(
                    "normal: processed={} accepted={} percent={} current_score={} reject_count={} candidate={} stop={:?}",
                    result.normal_loop.processed_samples,
                    result.normal_loop.score.accepted_samples(),
                    normal_percent,
                    result.normal_loop.current_score,
                    result.normal_loop.reject_count,
                    result.normal_loop.candidate_state,
                    result.normal_loop.stop_reason,
                );
                println!(
                    "recovery: admitted={} selected={:?} policy_score={} geometry={} evidence={} quality={}",
                    result.recovery.admitted_candidates,
                    result.recovery.selected_observation_index,
                    result.recovery.summary.policy_score,
                    result.recovery.summary.accumulated_geometry_count,
                    result.recovery.summary.best_evidence,
                    result.recovery.summary.best_quality,
                );
                if let Some(selected) = result.selected_terminal_work {
                    println!(
                        "terminal-work: sample={} evidence={} metric={} scaled_coverage={} policy_score={}",
                        selected.sample_index,
                        selected.policy_work.record.evidence,
                        selected.policy_work.record.verification_metric,
                        selected.policy_work.record.scaled_coverage_q8,
                        selected.policy_score,
                    );
                } else {
                    println!("terminal-work: none");
                }
                println!(
                    "terminal score: {} disposition={:?}",
                    result.arbitration.score, result.arbitration.disposition
                );
                println!("decision: {}", decision_name(decision));
                println!(
                    "VERIFY_RESULT attempt={} label={} decision={} score={} quality={} coverage={} points={} normal_percent={} accepted={} recovery_candidates={}",
                    attempt,
                    options.label.as_deref().unwrap_or("unlabeled"),
                    decision_name(decision),
                    result.arbitration.score,
                    diagnostics.quality,
                    diagnostics.coverage,
                    diagnostics.point_count,
                    normal_percent,
                    result.normal_loop.score.accepted_samples(),
                    result.recovery.admitted_candidates,
                );
            }
        }
    }

    println!();
    println!("verification run complete: completed={completed} rejected={rejected}");
    Ok(())
}

fn decision_name(decision: Gf3258GalleryVerificationDecision) -> &'static str {
    match decision {
        Gf3258GalleryVerificationDecision::Match => "MATCH",
        Gf3258GalleryVerificationDecision::NoMatch => "NO_MATCH",
    }
}

fn print_rejection(reason: Gf3258LiveVerificationRejection) {
    match reason {
        Gf3258LiveVerificationRejection::Preprocess(error) => {
            println!("verification capture rejected during preprocessing: {error}");
        }
        Gf3258LiveVerificationRejection::PathologicalEdge {
            pathological_edge_samples,
        } => {
            println!(
                "verification capture rejected: pathological edge samples={pathological_edge_samples}"
            );
        }
    }
}

fn parse_arguments() -> AppResult<Options> {
    let mut template_path = None;
    let mut attempts = DEFAULT_ATTEMPTS;
    let mut trace_path = None;
    let mut firmware_path = None;
    let mut label = None;

    let mut args = env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--template" => {
                let value = args
                    .next()
                    .ok_or_else(|| invalid_input("--template requires a filename"))?;
                template_path = Some(PathBuf::from(value));
            }
            "--attempts" => {
                let value = args
                    .next()
                    .ok_or_else(|| invalid_input("--attempts requires a positive integer"))?;
                attempts = value
                    .parse::<usize>()
                    .map_err(|_| invalid_input("--attempts must be a positive integer"))?;
                if attempts == 0 {
                    return Err(invalid_input("--attempts must be greater than zero").into());
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
            "--label" => {
                label = Some(
                    args.next()
                        .ok_or_else(|| invalid_input("--label requires a value"))?,
                );
            }
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            _ => {
                return Err(invalid_input(format!("unknown option: {argument}")).into());
            }
        }
    }

    let template_path =
        template_path.ok_or_else(|| invalid_input("--template FILE is required"))?;
    Ok(Options {
        template_path,
        attempts,
        trace_path,
        firmware_path,
        label,
    })
}

fn print_usage() {
    println!(
        r#"Usage: standalone_verify --template FILE [--attempts N] [--trace FILE] [--firmware FILE] [--label TEXT]

Captures fresh GF3258 touches and verifies them against one persisted
TGLA gallery using only the open Rust pipeline. --firmware supplies
exact APP15045 bytes when automatic IAP recovery is required. An
already-running APP device is never rewritten. --label is diagnostic
metadata and never changes biometric policy."#
    );
}
