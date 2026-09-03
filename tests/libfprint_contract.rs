use goodix_info::libfprint::{
    GF3258_LIBFPRINT_DRIVER_ID, GF3258_LIBFPRINT_ENROLL_STAGES, GF3258_LIBFPRINT_FULL_NAME,
    GF3258_LIBFPRINT_USB_PID, GF3258_LIBFPRINT_USB_VID, Gf3258LibfprintAdapter,
    Gf3258LibfprintError, Gf3258LibfprintOperationId, Gf3258LibfprintPrint, Gf3258LibfprintState,
};

#[test]
fn public_libfprint_identity_is_stable() {
    assert_eq!(GF3258_LIBFPRINT_DRIVER_ID, "goodix550a");
    assert_eq!(
        GF3258_LIBFPRINT_FULL_NAME,
        "Goodix GF3258 WN2 Fingerprint Sensor"
    );
    assert_eq!(GF3258_LIBFPRINT_USB_VID, 0x27c6);
    assert_eq!(GF3258_LIBFPRINT_USB_PID, 0x550a);
    assert_eq!(GF3258_LIBFPRINT_ENROLL_STAGES, 12);
}

#[test]
fn public_adapter_starts_closed() {
    assert_eq!(
        Gf3258LibfprintAdapter::default().state(),
        Gf3258LibfprintState::Closed
    );
}

#[test]
fn public_closed_adapter_rejects_close_and_enroll() {
    let mut adapter = Gf3258LibfprintAdapter::new();
    assert!(matches!(
        adapter.close(),
        Err(Gf3258LibfprintError::NotOpen)
    ));
    assert!(matches!(
        adapter.start_enrollment(),
        Err(Gf3258LibfprintError::NotOpen)
    ));
}

#[test]
fn public_cancellation_handle_is_cloneable() {
    let adapter = Gf3258LibfprintAdapter::new();
    let _clone = adapter.cancellation().clone();

    // The constructor is intentionally opaque; this test proves the public
    // operation-id accessor/type remains usable without exposing mutation.
    let id_size = std::mem::size_of::<Gf3258LibfprintOperationId>();
    assert_eq!(id_size, std::mem::size_of::<u64>());
}

#[test]
fn public_print_rejects_non_tgla_bytes_before_hardware() {
    let error = Gf3258LibfprintPrint::from_tgla(b"not-a-gf3258-template").unwrap_err();
    assert!(error.to_string().contains("template"));
}
