use goodix_info::libfprint_wire::{
    GF3258_LIBFPRINT_USB_OUT_BLOCK_SIZE, Gf3258LibfprintFirmwareIdentity,
    gf3258_libfprint_build_get_version_request, gf3258_libfprint_parse_get_version_ack,
    gf3258_libfprint_parse_get_version_response,
};

#[test]
fn public_wire_request_matches_captured_a8_prefix() {
    let request = gf3258_libfprint_build_get_version_request().unwrap();
    assert_eq!(request.len(), GF3258_LIBFPRINT_USB_OUT_BLOCK_SIZE);
    assert_eq!(
        &request[..10],
        &[0xa0, 0x06, 0x00, 0xa6, 0xa8, 0x03, 0x00, 0x00, 0x00, 0xff]
    );
}

#[test]
fn public_wire_ack_exposes_power_lost_without_rejecting_ack() {
    let ack = gf3258_libfprint_parse_get_version_ack(&[
        0xa0, 0x06, 0x00, 0xa6, 0xb0, 0x03, 0x00, 0xa8, 0x03, 0x4c,
    ])
    .unwrap();
    assert_eq!(ack.flags(), 0x03);
    assert!(ack.mcu_power_lost());
}

#[test]
fn public_wire_response_classifies_app15045() {
    let response = [
        0xa0, 0x1d, 0x00, 0xbd, 0xa8, 0x1a, 0x00, 0x47, 0x46, 0x55, 0x53, 0x42, 0x5f, 0x47, 0x4d,
        0x31, 0x36, 0x38, 0x53, 0x45, 0x43, 0x5f, 0x41, 0x50, 0x50, 0x5f, 0x31, 0x35, 0x30, 0x34,
        0x35, 0x00, 0x66,
    ];
    assert_eq!(
        gf3258_libfprint_parse_get_version_response(&response).unwrap(),
        Gf3258LibfprintFirmwareIdentity::App15045
    );
}

#[test]
fn public_recovery_engine_starts_with_exact_a6_get_otp_transfer() {
    use goodix_info::libfprint_wire::{
        Gf3258LibfprintRecoveryEngine, Gf3258LibfprintRecoveryStage,
        Gf3258LibfprintTransferDirection,
    };

    let engine = Gf3258LibfprintRecoveryEngine::new();
    let mut output = [0u8; 264];
    let action = engine.next_action(&mut output).unwrap();

    assert_eq!(action.stage(), Gf3258LibfprintRecoveryStage::ReadOtpWrite);
    assert_eq!(action.direction(), Gf3258LibfprintTransferDirection::Out);
    assert_eq!(action.endpoint(), 0x01);
    assert_eq!(action.transfer_length(), 64);
    assert_eq!(
        &output[..10],
        &[0xa0, 0x06, 0x00, 0xa6, 0xa6, 0x03, 0x00, 0x40, 0x00, 0xc1]
    );
}
