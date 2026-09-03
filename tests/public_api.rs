use goodix_info::{
    driver::{
        Gf3258CapturedFrame, Gf3258DeviceSession, Gf3258EnrollmentTouchResult,
        Gf3258EnrollmentTransaction, Gf3258EnrollmentTransactionError, Gf3258SessionError,
        Gf3258SessionStartup, Gf3258VerificationTouchResult, Gf3258VerificationTransaction,
        Gf3258VerificationTransactionError,
    },
    enrollment::{
        GF3258_ENROLLMENT_POINT_CAPACITY, Gf3258EnrollmentFrameOutcome, Gf3258EnrollmentWorkflow,
        gf3258_decode_fresh_tgla, gf3258_validate_fresh_tgla,
    },
    feature::{GF3258_PIXELS, gf3258_extract_primary_features_from_c2d40_source},
    image::{IMAGE_HEIGHT, IMAGE_WIDTH},
    preprocess::process_final_stage_from_corrected,
    verification::{
        Gf3258GalleryVerificationDecision, Gf3258RawFrameVerificationOutcome,
        Gf3258VerificationTemplate, Gf3258VerificationTemplateError, Gf3258VerificationWorkflow,
    },
};

#[test]
fn public_feature_pipeline_handles_constant_sensor_image() {
    let image = vec![127_u8; GF3258_PIXELS];
    let extraction = gf3258_extract_primary_features_from_c2d40_source(&image).unwrap();
    let diagnostics = extraction.diagnostics();

    assert_eq!(diagnostics.raw_extrema_count, 0);
    assert_eq!(diagnostics.refined_accepted_count, 0);
    assert_eq!(diagnostics.refinement_fallback_count, 0);
    assert_eq!(diagnostics.primary_point_count, 0);
    assert!(extraction.points.is_empty());
    assert_eq!(
        extraction.gradient_planes.magnitude_map_i32.len(),
        GF3258_PIXELS
    );
    assert_eq!(
        extraction.gradient_planes.angle_map_u16.len(),
        GF3258_PIXELS
    );
}

#[test]
fn public_preprocess_output_flows_into_feature_extraction() {
    let pixel_count = IMAGE_WIDTH * IMAGE_HEIGHT;
    assert_eq!(pixel_count, GF3258_PIXELS);

    let corrected = vec![0x4000_u16; pixel_count];
    let foreground_mask = vec![1_u8; pixel_count];

    let final_stage = process_final_stage_from_corrected(&corrected, &foreground_mask).unwrap();
    assert_eq!(final_stage.pixels().len(), pixel_count);

    let extraction =
        gf3258_extract_primary_features_from_c2d40_source(final_stage.pixels()).unwrap();
    assert_eq!(
        extraction.gradient_planes.magnitude_map_i32.len(),
        pixel_count
    );
    assert_eq!(extraction.gradient_planes.angle_map_u16.len(), pixel_count);
}

#[test]
fn public_enrollment_capacity_matches_persistent_type_18_limit() {
    assert_eq!(GF3258_ENROLLMENT_POINT_CAPACITY, 120);
}

#[test]
fn public_enrollment_workflow_reaches_persistent_bytes_without_app_or_usb() {
    let raw = vec![1000_u16; IMAGE_WIDTH * IMAGE_HEIGHT];
    let mut workflow = Gf3258EnrollmentWorkflow::new();

    let committed = match workflow.process_raw_frame(&raw).unwrap() {
        Gf3258EnrollmentFrameOutcome::Accepted(committed) => committed,
        rejection => panic!("uniform valid frame was unexpectedly rejected: {rejection:?}"),
    };
    assert_eq!(committed.sample_count, 1);
    assert_eq!(committed.progress_percent, 8);
    assert_eq!(workflow.sample_count(), 1);

    let artifacts = workflow.encode_artifacts().unwrap();
    let validated = gf3258_validate_fresh_tgla(artifacts.tgla_template()).unwrap();
    assert_eq!(validated.raw_template(), artifacts.raw_template());
    assert_eq!(
        validated.diagnostics().raw_length,
        artifacts.raw_template().len()
    );
}

#[test]
fn public_persisted_template_decode_survives_tgla_boundary() {
    let raw = vec![1000_u16; IMAGE_WIDTH * IMAGE_HEIGHT];
    let mut workflow = Gf3258EnrollmentWorkflow::new();
    assert!(matches!(
        workflow.process_raw_frame(&raw).unwrap(),
        Gf3258EnrollmentFrameOutcome::Accepted(_)
    ));

    let artifacts = workflow.encode_artifacts().unwrap();
    let decoded = gf3258_decode_fresh_tgla(artifacts.tgla_template()).unwrap();

    assert_eq!(decoded.header.sample_count, 1);
    assert_eq!(decoded.samples.len(), 1);
    assert_eq!(decoded.samples[0].sample_index, 0);
    assert_eq!(decoded.storage.active_slots[0], 0);
    assert!(
        decoded.storage.active_slots[1..]
            .iter()
            .all(|&slot| slot == -1)
    );
}

#[test]
fn public_raw_frame_verification_uses_opaque_validated_gallery() {
    let raw = vec![1000_u16; IMAGE_WIDTH * IMAGE_HEIGHT];
    let mut enrollment = Gf3258EnrollmentWorkflow::new();
    assert!(matches!(
        enrollment.process_raw_frame(&raw).unwrap(),
        Gf3258EnrollmentFrameOutcome::Accepted(_)
    ));

    let artifacts = enrollment.encode_artifacts().unwrap();
    let template = Gf3258VerificationTemplate::from_tgla(artifacts.tgla_template()).unwrap();
    assert_eq!(template.sample_count(), 1);

    let mut verification = Gf3258VerificationWorkflow::new();
    match verification.verify_raw_frame(&template, &raw).unwrap() {
        Gf3258RawFrameVerificationOutcome::Rejected(reason) => {
            panic!("uniform valid frame was unexpectedly rejected during verification: {reason:?}");
        }
        Gf3258RawFrameVerificationOutcome::Verified(result) => {
            assert_eq!(result.diagnostics().point_count, 0);
            assert_eq!(
                result.decision(),
                Gf3258GalleryVerificationDecision::NoMatch
            );
            assert!(result.score() <= 0);
        }
    }
}

#[test]
fn public_verification_template_rejects_empty_gallery() {
    let enrollment = Gf3258EnrollmentWorkflow::new();
    let artifacts = enrollment.encode_artifacts().unwrap();

    let error = Gf3258VerificationTemplate::from_tgla(artifacts.tgla_template()).unwrap_err();
    assert_eq!(error, Gf3258VerificationTemplateError::EmptyGallery);
    assert_eq!(
        error.to_string(),
        "verification template contains no enrolled samples"
    );
}

#[test]
fn public_verification_transaction_owns_validated_gallery_without_device_access() {
    let raw = vec![1000_u16; IMAGE_WIDTH * IMAGE_HEIGHT];
    let mut enrollment = Gf3258EnrollmentWorkflow::new();
    assert!(matches!(
        enrollment.process_raw_frame(&raw).unwrap(),
        Gf3258EnrollmentFrameOutcome::Accepted(_)
    ));

    let artifacts = enrollment.encode_artifacts().unwrap();
    let transaction = Gf3258VerificationTransaction::from_tgla(artifacts.tgla_template()).unwrap();
    assert_eq!(transaction.sample_count(), 1);
}

#[test]
fn public_driver_session_exposes_hardware_free_transaction_signatures() {
    let _open: fn() -> Result<Gf3258DeviceSession, Gf3258SessionError> = Gf3258DeviceSession::open;
    let _open_with_firmware: fn(&[u8]) -> Result<Gf3258DeviceSession, Gf3258SessionError> =
        Gf3258DeviceSession::open_with_firmware;
    let _startup: fn(&Gf3258DeviceSession) -> Gf3258SessionStartup = Gf3258DeviceSession::startup;
    let _capture: fn(&mut Gf3258DeviceSession) -> Result<Gf3258CapturedFrame, Gf3258SessionError> =
        Gf3258DeviceSession::capture_frame;
    let _new_enrollment: fn() -> Gf3258EnrollmentTransaction = Gf3258EnrollmentTransaction::new;
    let _enroll_touch: fn(
        &mut Gf3258EnrollmentTransaction,
        &mut Gf3258DeviceSession,
    )
        -> Result<Gf3258EnrollmentTouchResult, Gf3258EnrollmentTransactionError> =
        Gf3258EnrollmentTransaction::capture_next;
    let _finish: fn(
        Gf3258EnrollmentTransaction,
    ) -> Result<
        goodix_info::enrollment::Gf3258EnrollmentArtifacts,
        Gf3258EnrollmentTransactionError,
    > = Gf3258EnrollmentTransaction::finish;
    let _new_verification: fn(Gf3258VerificationTemplate) -> Gf3258VerificationTransaction =
        Gf3258VerificationTransaction::new;
    let _verification_from_tgla: fn(
        &[u8],
    ) -> Result<
        Gf3258VerificationTransaction,
        Gf3258VerificationTemplateError,
    > = Gf3258VerificationTransaction::from_tgla;
    let _verify_touch: fn(
        &mut Gf3258VerificationTransaction,
        &mut Gf3258DeviceSession,
    ) -> Result<
        Gf3258VerificationTouchResult,
        Gf3258VerificationTransactionError,
    > = Gf3258VerificationTransaction::capture_next;
}
