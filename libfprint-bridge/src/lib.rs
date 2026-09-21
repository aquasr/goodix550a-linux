use std::{
    ffi::{CString, c_char},
    ptr, slice,
    time::{Duration, Instant},
};

use goodix_info::libfprint_wire::{
    GF3258_LIBFPRINT_POSTBOOT_RESET_DELAY_MS, GF3258_LIBFPRINT_USB_OUT_BLOCK_SIZE,
    Gf3258LibfprintBootstrapEngine, Gf3258LibfprintBootstrapProgress, Gf3258LibfprintCaptureEngine,
    Gf3258LibfprintCaptureProgress, Gf3258LibfprintEnrollmentEngine,
    Gf3258LibfprintFirmwareIdentity, Gf3258LibfprintIdentificationDisposition,
    Gf3258LibfprintIdentificationEngine, Gf3258LibfprintRecoveryEngine,
    Gf3258LibfprintTransferDirection, Gf3258LibfprintVerificationEngine,
    gf3258_libfprint_build_bootstrap_reset_request, gf3258_libfprint_build_chip_id_request,
    gf3258_libfprint_build_get_version_request, gf3258_libfprint_build_postboot_reset_request,
    gf3258_libfprint_parse_bootstrap_reset_ack, gf3258_libfprint_parse_chip_id_ack,
    gf3258_libfprint_parse_get_version_ack, gf3258_libfprint_parse_get_version_response,
    gf3258_libfprint_parse_postboot_reset_ack, gf3258_libfprint_parse_postboot_reset_response,
    gf3258_libfprint_validate_chip_id_response,
};

const STATUS_OK: i32 = 0;
const STATUS_INVALID_ARGUMENT: i32 = -1;
const STATUS_BUFFER_TOO_SMALL: i32 = -2;
const STATUS_PROTOCOL_ERROR: i32 = -3;

static STATUS_OK_TEXT: &[u8] = b"ok\0";
static STATUS_INVALID_ARGUMENT_TEXT: &[u8] = b"invalid bridge argument\0";
static STATUS_BUFFER_TOO_SMALL_TEXT: &[u8] = b"bridge output buffer is too small\0";
static STATUS_PROTOCOL_ERROR_TEXT: &[u8] = b"Goodix Rust wire parser rejected the packet\0";
static STATUS_UNKNOWN_TEXT: &[u8] = b"unknown bridge status\0";
static APP_VERSION_TEXT: &[u8] = b"GFUSB_GM168SEC_APP_15045\0";
static IAP_VERSION_TEXT: &[u8] = b"MILAN_GM168SEC_IAP_10007\0";
static UNKNOWN_VERSION_TEXT: &[u8] = b"unknown\0";

#[derive(Debug, Clone, Copy)]
struct InTransferDeadlineState {
    stage: u32,
    deadline: Instant,
    budget_ms: u32,
}

#[derive(Debug, Default)]
struct InTransferDeadline {
    state: Option<InTransferDeadlineState>,
}

impl InTransferDeadline {
    fn timeout_for_action(
        &mut self,
        direction: Gf3258LibfprintTransferDirection,
        stage: u32,
        timeout_ms: u32,
    ) -> Result<u32, String> {
        self.timeout_for_action_at(direction, stage, timeout_ms, Instant::now())
    }

    fn timeout_for_action_at(
        &mut self,
        direction: Gf3258LibfprintTransferDirection,
        stage: u32,
        timeout_ms: u32,
        now: Instant,
    ) -> Result<u32, String> {
        if direction != Gf3258LibfprintTransferDirection::In {
            self.state = None;
            return Ok(timeout_ms);
        }

        if timeout_ms == 0 {
            self.state = None;
            return Err(format!(
                "libfprint IN stage {stage} requested an unbounded zero-millisecond timeout"
            ));
        }

        match self.state {
            None => {
                let budget = Duration::from_millis(u64::from(timeout_ms));
                let deadline = now.checked_add(budget).ok_or_else(|| {
                    format!(
                        "libfprint IN stage {stage} deadline overflow for {timeout_ms} ms budget"
                    )
                })?;

                self.state = Some(InTransferDeadlineState {
                    stage,
                    deadline,
                    budget_ms: timeout_ms,
                });

                Ok(timeout_ms)
            }
            Some(state) if state.stage != stage => {
                let budget = Duration::from_millis(u64::from(timeout_ms));
                let deadline = now.checked_add(budget).ok_or_else(|| {
                    format!(
                        "libfprint IN stage {stage} deadline overflow for {timeout_ms} ms budget"
                    )
                })?;

                self.state = Some(InTransferDeadlineState {
                    stage,
                    deadline,
                    budget_ms: timeout_ms,
                });

                Ok(timeout_ms)
            }
            Some(state) => {
                if now >= state.deadline {
                    return Err(format!(
                        "libfprint IN stage {} exceeded its absolute {} ms wait budget",
                        state.stage, state.budget_ms
                    ));
                }

                let remaining = state.deadline.duration_since(now);

                // libusb interprets a zero timeout as an unbounded wait. Round a
                // positive sub-millisecond remainder up to one millisecond.
                let remaining_ms = remaining.as_millis().clamp(1, u128::from(u32::MAX)) as u32;

                // A repeated request for the same logical IN stage may tighten
                // its per-transfer timeout, but it must never extend the
                // original absolute deadline.
                Ok(remaining_ms.min(timeout_ms))
            }
        }
    }
}

struct BridgeWorkflowState {
    in_deadline: InTransferDeadline,
    last_error: CString,
}

impl Default for BridgeWorkflowState {
    fn default() -> Self {
        Self {
            in_deadline: InTransferDeadline::default(),
            last_error: cstring("ok"),
        }
    }
}

impl BridgeWorkflowState {
    fn timeout_for_action(
        &mut self,
        direction: Gf3258LibfprintTransferDirection,
        stage: u32,
        timeout_ms: u32,
    ) -> Result<u32, String> {
        self.in_deadline
            .timeout_for_action(direction, stage, timeout_ms)
    }

    fn record_error(&mut self, error: impl ToString) -> i32 {
        self.last_error = cstring(&error.to_string());
        STATUS_PROTOCOL_ERROR
    }

    fn last_error_ptr(&self) -> *const c_char {
        self.last_error.as_ptr()
    }
}

#[repr(C)]
pub struct Goodix550aBridgeAck {
    flags: u8,
    mcu_power_lost: u8,
}

#[repr(C)]
pub struct Goodix550aBridgeBootstrapAction {
    direction: u32,
    stage: u32,
    transfer_length: usize,
    timeout_ms: u32,
    endpoint: u8,
    short_is_error: u8,
    reserved: u16,
}

#[repr(C)]
pub struct Goodix550aBridgeBootstrapInfo {
    f0_chunks_sent: usize,
    firmware_check_result: u32,
}

pub struct Goodix550aBridgeBootstrap {
    engine: Gf3258LibfprintBootstrapEngine,
    state: BridgeWorkflowState,
}

impl Goodix550aBridgeBootstrap {
    fn new(firmware: &[u8]) -> Result<Self, String> {
        let engine =
            Gf3258LibfprintBootstrapEngine::new(firmware).map_err(|error| error.to_string())?;
        Ok(Self {
            engine,
            state: BridgeWorkflowState::default(),
        })
    }
}

#[repr(C)]
pub struct Goodix550aBridgeRecoveryAction {
    direction: u32,
    stage: u32,
    transfer_length: usize,
    timeout_ms: u32,
    endpoint: u8,
    short_is_error: u8,
    reserved: u16,
}

#[repr(C)]
pub struct Goodix550aBridgeRecoveryInfo {
    tcode: u16,
    diff: u16,
    fdt_offset: u8,
    reserved: u8,
    checksum: u16,
}

pub struct Goodix550aBridgeRecovery {
    engine: Gf3258LibfprintRecoveryEngine,
    state: BridgeWorkflowState,
}

impl Goodix550aBridgeRecovery {
    fn new() -> Self {
        Self {
            engine: Gf3258LibfprintRecoveryEngine::new(),
            state: BridgeWorkflowState::default(),
        }
    }
}

#[repr(C)]
pub struct Goodix550aBridgeCaptureAction {
    direction: u32,
    stage: u32,
    transfer_length: usize,
    timeout_ms: u32,
    endpoint: u8,
    short_is_error: u8,
    reserved: u16,
}

#[repr(C)]
pub struct Goodix550aBridgeCaptureInfo {
    protected_bytes: usize,
    pixel_count: usize,
    stored_crc: u32,
}

pub struct Goodix550aBridgeCapture {
    engine: Gf3258LibfprintCaptureEngine,
    state: BridgeWorkflowState,
}

impl Goodix550aBridgeCapture {
    fn new() -> Result<Self, String> {
        let engine = Gf3258LibfprintCaptureEngine::new().map_err(|error| error.to_string())?;
        Ok(Self {
            engine,
            state: BridgeWorkflowState::default(),
        })
    }
}

#[repr(C)]
pub struct Goodix550aBridgeEnrollmentAction {
    direction: u32,
    stage: u32,
    transfer_length: usize,
    timeout_ms: u32,
    endpoint: u8,
    short_is_error: u8,
    reserved: u16,
}

#[repr(C)]
pub struct Goodix550aBridgeEnrollmentInfo {
    disposition: u32,
    sample_count: usize,
    progress_percent: usize,
    protected_bytes: usize,
    pixel_count: usize,
    stored_crc: u32,
    tgla_bytes: usize,
}

pub struct Goodix550aBridgeEnrollment {
    engine: Gf3258LibfprintEnrollmentEngine,
    state: BridgeWorkflowState,
}

impl Goodix550aBridgeEnrollment {
    fn new() -> Result<Self, String> {
        let engine = Gf3258LibfprintEnrollmentEngine::new().map_err(|error| error.to_string())?;
        Ok(Self {
            engine,
            state: BridgeWorkflowState::default(),
        })
    }
}

#[repr(C)]
pub struct Goodix550aBridgeVerificationAction {
    direction: u32,
    stage: u32,
    transfer_length: usize,
    timeout_ms: u32,
    endpoint: u8,
    short_is_error: u8,
    reserved: u16,
}

#[repr(C)]
pub struct Goodix550aBridgeVerificationInfo {
    disposition: u32,
    score: i32,
    protected_bytes: usize,
    pixel_count: usize,
    stored_crc: u32,
}

pub struct Goodix550aBridgeVerification {
    engine: Gf3258LibfprintVerificationEngine,
    state: BridgeWorkflowState,
}

impl Goodix550aBridgeVerification {
    fn new(tgla: &[u8]) -> Result<Self, String> {
        let engine =
            Gf3258LibfprintVerificationEngine::new(tgla).map_err(|error| error.to_string())?;
        Ok(Self {
            engine,
            state: BridgeWorkflowState::default(),
        })
    }
}

#[repr(C)]
pub struct Goodix550aBridgeIdentificationAction {
    direction: u32,
    stage: u32,
    transfer_length: usize,
    timeout_ms: u32,
    endpoint: u8,
    short_is_error: u8,
    reserved: u16,
}

#[repr(C)]
pub struct Goodix550aBridgeIdentificationInfo {
    disposition: u32,
    score: i32,
    match_index: usize,
    protected_bytes: usize,
    pixel_count: usize,
    stored_crc: u32,
    scanned_tgla_bytes: usize,
}

pub struct Goodix550aBridgeIdentification {
    engine: Gf3258LibfprintIdentificationEngine,
    state: BridgeWorkflowState,
}

impl Goodix550aBridgeIdentification {
    fn new(tgla: &[u8]) -> Result<Self, String> {
        let engine =
            Gf3258LibfprintIdentificationEngine::new(tgla).map_err(|error| error.to_string())?;

        Ok(Self {
            engine,
            state: BridgeWorkflowState::default(),
        })
    }
}

fn c_text(bytes: &'static [u8]) -> *const c_char {
    bytes.as_ptr().cast()
}

fn cstring(text: &str) -> CString {
    CString::new(text).unwrap_or_else(|_| {
        CString::new("bridge error contained NUL").expect("static bridge error has no NUL")
    })
}

#[unsafe(no_mangle)]
/// # Safety
///
/// Every non-null raw pointer supplied by the caller must be valid for
/// the access and length described by the corresponding arguments for
/// the duration of this call. Opaque bridge handles must originate from
/// this library and remain live for the duration of the operation.
pub unsafe extern "C" fn goodix550a_bridge_build_postboot_reset_request(
    output: *mut u8,
    output_length: usize,
) -> i32 {
    if output.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }
    if output_length < GF3258_LIBFPRINT_USB_OUT_BLOCK_SIZE {
        return STATUS_BUFFER_TOO_SMALL;
    }

    let request = match gf3258_libfprint_build_postboot_reset_request() {
        Ok(request) => request,
        Err(_) => return STATUS_PROTOCOL_ERROR,
    };

    // SAFETY: `output` was checked for null and the caller supplied capacity for
    // the exact 64-byte request. Source and destination do not overlap.
    unsafe {
        ptr::copy_nonoverlapping(request.as_ptr(), output, request.len());
    }

    STATUS_OK
}

#[unsafe(no_mangle)]
/// # Safety
///
/// Every non-null raw pointer supplied by the caller must be valid for
/// the access and length described by the corresponding arguments for
/// the duration of this call. Opaque bridge handles must originate from
/// this library and remain live for the duration of the operation.
pub unsafe extern "C" fn goodix550a_bridge_parse_postboot_reset_ack(
    input: *const u8,
    input_length: usize,
    ack: *mut Goodix550aBridgeAck,
) -> i32 {
    if input.is_null() || ack.is_null() || input_length == 0 {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the C caller guarantees `input_length` readable bytes for this
    // synchronous call. The slice does not escape.
    let bytes = unsafe { slice::from_raw_parts(input, input_length) };
    let parsed = match gf3258_libfprint_parse_postboot_reset_ack(bytes) {
        Ok(parsed) => parsed,
        Err(_) => return STATUS_PROTOCOL_ERROR,
    };

    let value = Goodix550aBridgeAck {
        flags: parsed.flags(),
        mcu_power_lost: u8::from(parsed.mcu_power_lost()),
    };

    // SAFETY: `ack` points to writable caller-owned storage for one POD value.
    unsafe {
        ptr::write(ack, value);
    }

    STATUS_OK
}

#[unsafe(no_mangle)]
/// # Safety
///
/// Every non-null raw pointer supplied by the caller must be valid for
/// the access and length described by the corresponding arguments for
/// the duration of this call. Opaque bridge handles must originate from
/// this library and remain live for the duration of the operation.
pub unsafe extern "C" fn goodix550a_bridge_parse_postboot_reset_response(
    input: *const u8,
    input_length: usize,
) -> i32 {
    if input.is_null() || input_length == 0 {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the C caller guarantees `input_length` readable bytes for this
    // synchronous call. The slice does not escape.
    let bytes = unsafe { slice::from_raw_parts(input, input_length) };
    match gf3258_libfprint_parse_postboot_reset_response(bytes) {
        Ok(()) => STATUS_OK,
        Err(_) => STATUS_PROTOCOL_ERROR,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn goodix550a_bridge_postboot_reset_delay_ms() -> u32 {
    GF3258_LIBFPRINT_POSTBOOT_RESET_DELAY_MS
}

#[unsafe(no_mangle)]
/// # Safety
///
/// Every non-null raw pointer supplied by the caller must be valid for
/// the access and length described by the corresponding arguments for
/// the duration of this call. Opaque bridge handles must originate from
/// this library and remain live for the duration of the operation.
pub unsafe extern "C" fn goodix550a_bridge_build_chip_id_request(
    output: *mut u8,
    output_length: usize,
) -> i32 {
    if output.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }
    if output_length < GF3258_LIBFPRINT_USB_OUT_BLOCK_SIZE {
        return STATUS_BUFFER_TOO_SMALL;
    }

    let request = match gf3258_libfprint_build_chip_id_request() {
        Ok(request) => request,
        Err(_) => return STATUS_PROTOCOL_ERROR,
    };

    // SAFETY: `output` was checked for null and the caller supplied capacity for
    // the exact 64-byte request. Source and destination do not overlap.
    unsafe {
        ptr::copy_nonoverlapping(request.as_ptr(), output, request.len());
    }

    STATUS_OK
}

#[unsafe(no_mangle)]
/// # Safety
///
/// Every non-null raw pointer supplied by the caller must be valid for
/// the access and length described by the corresponding arguments for
/// the duration of this call. Opaque bridge handles must originate from
/// this library and remain live for the duration of the operation.
pub unsafe extern "C" fn goodix550a_bridge_parse_chip_id_ack(
    input: *const u8,
    input_length: usize,
    ack: *mut Goodix550aBridgeAck,
) -> i32 {
    if input.is_null() || ack.is_null() || input_length == 0 {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the C caller guarantees `input_length` readable bytes for this
    // synchronous call. The slice does not escape.
    let bytes = unsafe { slice::from_raw_parts(input, input_length) };
    let parsed = match gf3258_libfprint_parse_chip_id_ack(bytes) {
        Ok(parsed) => parsed,
        Err(_) => return STATUS_PROTOCOL_ERROR,
    };

    let value = Goodix550aBridgeAck {
        flags: parsed.flags(),
        mcu_power_lost: u8::from(parsed.mcu_power_lost()),
    };

    // SAFETY: `ack` points to writable caller-owned storage for one POD value.
    unsafe {
        ptr::write(ack, value);
    }

    STATUS_OK
}

#[unsafe(no_mangle)]
/// # Safety
///
/// Every non-null raw pointer supplied by the caller must be valid for
/// the access and length described by the corresponding arguments for
/// the duration of this call. Opaque bridge handles must originate from
/// this library and remain live for the duration of the operation.
pub unsafe extern "C" fn goodix550a_bridge_validate_chip_id_response(
    input: *const u8,
    input_length: usize,
    chip_id: *mut u32,
) -> i32 {
    if input.is_null() || chip_id.is_null() || input_length == 0 {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the C caller guarantees `input_length` readable bytes for this
    // synchronous call. The slice does not escape.
    let bytes = unsafe { slice::from_raw_parts(input, input_length) };
    let parsed = match gf3258_libfprint_validate_chip_id_response(bytes) {
        Ok(parsed) => parsed,
        Err(_) => return STATUS_PROTOCOL_ERROR,
    };

    // SAFETY: `chip_id` points to writable caller-owned storage for one u32.
    unsafe {
        ptr::write(chip_id, parsed);
    }

    STATUS_OK
}

#[unsafe(no_mangle)]
/// # Safety
///
/// Every non-null raw pointer supplied by the caller must be valid for
/// the access and length described by the corresponding arguments for
/// the duration of this call. Opaque bridge handles must originate from
/// this library and remain live for the duration of the operation.
pub unsafe extern "C" fn goodix550a_bridge_build_bootstrap_reset_request(
    output: *mut u8,
    output_length: usize,
) -> i32 {
    if output.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }
    if output_length < GF3258_LIBFPRINT_USB_OUT_BLOCK_SIZE {
        return STATUS_BUFFER_TOO_SMALL;
    }

    let request = match gf3258_libfprint_build_bootstrap_reset_request() {
        Ok(request) => request,
        Err(_) => return STATUS_PROTOCOL_ERROR,
    };

    // SAFETY: `output` was checked for null and the caller supplied capacity for
    // the exact 64-byte request. Source and destination do not overlap.
    unsafe {
        ptr::copy_nonoverlapping(request.as_ptr(), output, request.len());
    }

    STATUS_OK
}

#[unsafe(no_mangle)]
/// # Safety
///
/// Every non-null raw pointer supplied by the caller must be valid for
/// the access and length described by the corresponding arguments for
/// the duration of this call. Opaque bridge handles must originate from
/// this library and remain live for the duration of the operation.
pub unsafe extern "C" fn goodix550a_bridge_parse_bootstrap_reset_ack(
    input: *const u8,
    input_length: usize,
    ack: *mut Goodix550aBridgeAck,
) -> i32 {
    if input.is_null() || ack.is_null() || input_length == 0 {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the C caller guarantees `input_length` readable bytes for this
    // synchronous call. The slice does not escape.
    let bytes = unsafe { slice::from_raw_parts(input, input_length) };
    let parsed = match gf3258_libfprint_parse_bootstrap_reset_ack(bytes) {
        Ok(parsed) => parsed,
        Err(_) => return STATUS_PROTOCOL_ERROR,
    };

    let value = Goodix550aBridgeAck {
        flags: parsed.flags(),
        mcu_power_lost: u8::from(parsed.mcu_power_lost()),
    };

    // SAFETY: `ack` points to writable caller-owned storage for one POD value.
    unsafe {
        ptr::write(ack, value);
    }

    STATUS_OK
}

#[unsafe(no_mangle)]
/// # Safety
///
/// Every non-null raw pointer supplied by the caller must be valid for
/// the access and length described by the corresponding arguments for
/// the duration of this call. Opaque bridge handles must originate from
/// this library and remain live for the duration of the operation.
pub unsafe extern "C" fn goodix550a_bridge_build_get_version_request(
    output: *mut u8,
    output_length: usize,
) -> i32 {
    if output.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }
    if output_length < GF3258_LIBFPRINT_USB_OUT_BLOCK_SIZE {
        return STATUS_BUFFER_TOO_SMALL;
    }

    let request = match gf3258_libfprint_build_get_version_request() {
        Ok(request) => request,
        Err(_) => return STATUS_PROTOCOL_ERROR,
    };

    // SAFETY: `output` was checked for null and the caller supplied a capacity
    // of at least the exact 64-byte request length. The regions do not overlap.
    unsafe {
        ptr::copy_nonoverlapping(request.as_ptr(), output, request.len());
    }

    STATUS_OK
}

#[unsafe(no_mangle)]
/// # Safety
///
/// Every non-null raw pointer supplied by the caller must be valid for
/// the access and length described by the corresponding arguments for
/// the duration of this call. Opaque bridge handles must originate from
/// this library and remain live for the duration of the operation.
pub unsafe extern "C" fn goodix550a_bridge_parse_get_version_ack(
    input: *const u8,
    input_length: usize,
    ack: *mut Goodix550aBridgeAck,
) -> i32 {
    if input.is_null() || ack.is_null() || input_length == 0 {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the C caller guarantees that `input` references `input_length`
    // readable bytes for the duration of this call. The slice does not escape.
    let bytes = unsafe { slice::from_raw_parts(input, input_length) };
    let parsed = match gf3258_libfprint_parse_get_version_ack(bytes) {
        Ok(parsed) => parsed,
        Err(_) => return STATUS_PROTOCOL_ERROR,
    };

    let value = Goodix550aBridgeAck {
        flags: parsed.flags(),
        mcu_power_lost: u8::from(parsed.mcu_power_lost()),
    };

    // SAFETY: `ack` was checked for null and points to writable storage owned
    // by the C caller for the duration of this call.
    unsafe {
        ptr::write(ack, value);
    }

    STATUS_OK
}

#[unsafe(no_mangle)]
/// # Safety
///
/// Every non-null raw pointer supplied by the caller must be valid for
/// the access and length described by the corresponding arguments for
/// the duration of this call. Opaque bridge handles must originate from
/// this library and remain live for the duration of the operation.
pub unsafe extern "C" fn goodix550a_bridge_parse_get_version_response(
    input: *const u8,
    input_length: usize,
    firmware: *mut u32,
) -> i32 {
    if input.is_null() || firmware.is_null() || input_length == 0 {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the C caller guarantees that `input` references `input_length`
    // readable bytes for the duration of this call. The slice does not escape.
    let bytes = unsafe { slice::from_raw_parts(input, input_length) };
    let parsed = match gf3258_libfprint_parse_get_version_response(bytes) {
        Ok(parsed) => parsed,
        Err(_) => return STATUS_PROTOCOL_ERROR,
    };

    let value = parsed as u32;

    // SAFETY: `firmware` was checked for null and points to writable storage
    // owned by the C caller for the duration of this call.
    unsafe {
        ptr::write(firmware, value);
    }

    STATUS_OK
}

#[unsafe(no_mangle)]
/// # Safety
///
/// Every non-null raw pointer supplied by the caller must be valid for
/// the access and length described by the corresponding arguments for
/// the duration of this call. Opaque bridge handles must originate from
/// this library and remain live for the duration of the operation.
pub unsafe extern "C" fn goodix550a_bridge_bootstrap_new(
    firmware: *const u8,
    firmware_length: usize,
    bootstrap: *mut *mut Goodix550aBridgeBootstrap,
) -> i32 {
    if firmware.is_null() || firmware_length == 0 || bootstrap.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the C caller guarantees `firmware_length` readable bytes for
    // the duration of this call. The firmware slice is consumed synchronously.
    let firmware = unsafe { slice::from_raw_parts(firmware, firmware_length) };
    let value = match Goodix550aBridgeBootstrap::new(firmware) {
        Ok(value) => value,
        Err(_) => return STATUS_PROTOCOL_ERROR,
    };
    let raw = Box::into_raw(Box::new(value));

    // SAFETY: `bootstrap` points to writable caller storage for one opaque pointer.
    unsafe {
        ptr::write(bootstrap, raw);
    }
    STATUS_OK
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `handle` must either be null or be a live handle returned by the
/// corresponding constructor in this bridge. A non-null handle must
/// not have been freed previously and must not be used after this call.
pub unsafe extern "C" fn goodix550a_bridge_bootstrap_free(
    bootstrap: *mut Goodix550aBridgeBootstrap,
) {
    if bootstrap.is_null() {
        return;
    }

    // SAFETY: pointer originates from bootstrap_new and is returned exactly once.
    unsafe {
        drop(Box::from_raw(bootstrap));
    }
}

#[unsafe(no_mangle)]
/// # Safety
///
/// Every non-null raw pointer supplied by the caller must be valid for
/// the access and length described by the corresponding arguments for
/// the duration of this call. Opaque bridge handles must originate from
/// this library and remain live for the duration of the operation.
pub unsafe extern "C" fn goodix550a_bridge_bootstrap_next_action(
    bootstrap: *mut Goodix550aBridgeBootstrap,
    action: *mut Goodix550aBridgeBootstrapAction,
    output: *mut u8,
    output_length: usize,
) -> i32 {
    if bootstrap.is_null() || action.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: opaque pointer is bridge-owned and valid until bootstrap_free.
    let bootstrap = unsafe { &mut *bootstrap };
    let mut empty = [];
    let output = if output_length == 0 {
        &mut empty[..]
    } else {
        if output.is_null() {
            return STATUS_INVALID_ARGUMENT;
        }
        // SAFETY: caller provides output_length writable bytes for this call.
        unsafe { slice::from_raw_parts_mut(output, output_length) }
    };

    let next = match bootstrap.engine.next_action(output) {
        Ok(next) => next,
        Err(error) => return bootstrap.state.record_error(error),
    };
    let timeout_ms = match bootstrap.state.timeout_for_action(
        next.direction(),
        next.stage() as u32,
        next.timeout_ms(),
    ) {
        Ok(timeout_ms) => timeout_ms,
        Err(error) => return bootstrap.state.record_error(error),
    };

    let value = Goodix550aBridgeBootstrapAction {
        direction: next.direction() as u32,
        stage: next.stage() as u32,
        transfer_length: next.transfer_length(),
        timeout_ms,
        endpoint: next.endpoint(),
        short_is_error: u8::from(next.short_is_error()),
        reserved: 0,
    };

    // SAFETY: action points to writable caller storage for one POD descriptor.
    unsafe {
        ptr::write(action, value);
    }
    STATUS_OK
}

#[unsafe(no_mangle)]
/// # Safety
///
/// Every non-null raw pointer supplied by the caller must be valid for
/// the access and length described by the corresponding arguments for
/// the duration of this call. Opaque bridge handles must originate from
/// this library and remain live for the duration of the operation.
pub unsafe extern "C" fn goodix550a_bridge_bootstrap_complete_transfer(
    bootstrap: *mut Goodix550aBridgeBootstrap,
    input: *const u8,
    input_length: usize,
    advanced: *mut u8,
) -> i32 {
    if bootstrap.is_null() || advanced.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: opaque pointer is bridge-owned and valid until bootstrap_free.
    let bootstrap = unsafe { &mut *bootstrap };
    let bytes = if input_length == 0 {
        &[][..]
    } else {
        if input.is_null() {
            return STATUS_INVALID_ARGUMENT;
        }
        // SAFETY: caller provides input_length readable bytes for this call.
        unsafe { slice::from_raw_parts(input, input_length) }
    };

    let progress = match bootstrap.engine.complete_transfer(bytes) {
        Ok(progress) => progress,
        Err(error) => return bootstrap.state.record_error(error),
    };
    let value = u8::from(matches!(
        progress,
        Gf3258LibfprintBootstrapProgress::Advanced
    ));

    // SAFETY: advanced points to one writable byte.
    unsafe {
        ptr::write(advanced, value);
    }
    STATUS_OK
}

#[unsafe(no_mangle)]
/// # Safety
///
/// Every non-null raw pointer supplied by the caller must be valid for
/// the access and length described by the corresponding arguments for
/// the duration of this call. Opaque bridge handles must originate from
/// this library and remain live for the duration of the operation.
pub unsafe extern "C" fn goodix550a_bridge_bootstrap_result(
    bootstrap: *mut Goodix550aBridgeBootstrap,
    info: *mut Goodix550aBridgeBootstrapInfo,
) -> i32 {
    if bootstrap.is_null() || info.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: opaque pointer is bridge-owned and valid until bootstrap_free.
    let bootstrap = unsafe { &mut *bootstrap };
    let result = match bootstrap.engine.result() {
        Ok(result) => result,
        Err(error) => return bootstrap.state.record_error(error),
    };
    let value = Goodix550aBridgeBootstrapInfo {
        f0_chunks_sent: result.f0_chunks_sent(),
        firmware_check_result: u32::from(result.firmware_check_result()),
    };

    // SAFETY: info points to writable caller storage for one POD structure.
    unsafe {
        ptr::write(info, value);
    }
    STATUS_OK
}

#[unsafe(no_mangle)]
/// # Safety
///
/// Every non-null raw pointer supplied by the caller must be valid for
/// the access and length described by the corresponding arguments for
/// the duration of this call. Opaque bridge handles must originate from
/// this library and remain live for the duration of the operation.
pub unsafe extern "C" fn goodix550a_bridge_bootstrap_last_error(
    bootstrap: *const Goodix550aBridgeBootstrap,
) -> *const c_char {
    if bootstrap.is_null() {
        return c_text(STATUS_INVALID_ARGUMENT_TEXT);
    }

    // SAFETY: pointer is valid until bootstrap_free; CString storage is owned by it.
    let bootstrap = unsafe { &*bootstrap };
    bootstrap.state.last_error_ptr()
}

#[unsafe(no_mangle)]
/// # Safety
///
/// Every non-null raw pointer supplied by the caller must be valid for
/// the access and length described by the corresponding arguments for
/// the duration of this call. Opaque bridge handles must originate from
/// this library and remain live for the duration of the operation.
pub unsafe extern "C" fn goodix550a_bridge_recovery_new(
    recovery: *mut *mut Goodix550aBridgeRecovery,
) -> i32 {
    if recovery.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }
    let raw = Box::into_raw(Box::new(Goodix550aBridgeRecovery::new()));
    // SAFETY: `recovery` points to writable caller storage for one opaque pointer.
    unsafe {
        ptr::write(recovery, raw);
    }
    STATUS_OK
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `handle` must either be null or be a live handle returned by the
/// corresponding constructor in this bridge. A non-null handle must
/// not have been freed previously and must not be used after this call.
pub unsafe extern "C" fn goodix550a_bridge_recovery_free(recovery: *mut Goodix550aBridgeRecovery) {
    if recovery.is_null() {
        return;
    }
    // SAFETY: pointer originates from recovery_new and is returned exactly once.
    unsafe {
        drop(Box::from_raw(recovery));
    }
}

#[unsafe(no_mangle)]
/// # Safety
///
/// Every non-null raw pointer supplied by the caller must be valid for
/// the access and length described by the corresponding arguments for
/// the duration of this call. Opaque bridge handles must originate from
/// this library and remain live for the duration of the operation.
pub unsafe extern "C" fn goodix550a_bridge_recovery_next_action(
    recovery: *mut Goodix550aBridgeRecovery,
    action: *mut Goodix550aBridgeRecoveryAction,
    output: *mut u8,
    output_length: usize,
) -> i32 {
    if recovery.is_null() || action.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }
    // SAFETY: opaque pointer is bridge-owned and valid until recovery_free.
    let recovery = unsafe { &mut *recovery };
    let mut empty = [];
    let output = if output_length == 0 {
        &mut empty[..]
    } else {
        if output.is_null() {
            return STATUS_INVALID_ARGUMENT;
        }
        // SAFETY: caller provides output_length writable bytes for this call.
        unsafe { slice::from_raw_parts_mut(output, output_length) }
    };
    let next = match recovery.engine.next_action(output) {
        Ok(next) => next,
        Err(error) => return recovery.state.record_error(error),
    };
    let timeout_ms = match recovery.state.timeout_for_action(
        next.direction(),
        next.stage() as u32,
        next.timeout_ms(),
    ) {
        Ok(timeout_ms) => timeout_ms,
        Err(error) => return recovery.state.record_error(error),
    };

    let value = Goodix550aBridgeRecoveryAction {
        direction: next.direction() as u32,
        stage: next.stage() as u32,
        transfer_length: next.transfer_length(),
        timeout_ms,
        endpoint: next.endpoint(),
        short_is_error: u8::from(next.short_is_error()),
        reserved: 0,
    };
    // SAFETY: action points to writable caller storage for one POD descriptor.
    unsafe {
        ptr::write(action, value);
    }
    STATUS_OK
}

#[unsafe(no_mangle)]
/// # Safety
///
/// Every non-null raw pointer supplied by the caller must be valid for
/// the access and length described by the corresponding arguments for
/// the duration of this call. Opaque bridge handles must originate from
/// this library and remain live for the duration of the operation.
pub unsafe extern "C" fn goodix550a_bridge_recovery_complete_transfer(
    recovery: *mut Goodix550aBridgeRecovery,
    input: *const u8,
    input_length: usize,
    advanced: *mut u8,
) -> i32 {
    if recovery.is_null() || advanced.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }
    // SAFETY: opaque pointer is bridge-owned and valid until recovery_free.
    let recovery = unsafe { &mut *recovery };
    let bytes = if input_length == 0 {
        &[][..]
    } else {
        if input.is_null() {
            return STATUS_INVALID_ARGUMENT;
        }
        // SAFETY: caller provides input_length readable bytes for this call.
        unsafe { slice::from_raw_parts(input, input_length) }
    };
    let progress = match recovery.engine.complete_transfer(bytes) {
        Ok(progress) => progress,
        Err(error) => return recovery.state.record_error(error),
    };
    let value = u8::from(matches!(progress, Gf3258LibfprintCaptureProgress::Advanced));
    // SAFETY: advanced points to one writable byte.
    unsafe {
        ptr::write(advanced, value);
    }
    STATUS_OK
}

#[unsafe(no_mangle)]
/// # Safety
///
/// Every non-null raw pointer supplied by the caller must be valid for
/// the access and length described by the corresponding arguments for
/// the duration of this call. Opaque bridge handles must originate from
/// this library and remain live for the duration of the operation.
pub unsafe extern "C" fn goodix550a_bridge_recovery_result(
    recovery: *mut Goodix550aBridgeRecovery,
    info: *mut Goodix550aBridgeRecoveryInfo,
) -> i32 {
    if recovery.is_null() || info.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }
    // SAFETY: opaque pointer is bridge-owned and valid until recovery_free.
    let recovery = unsafe { &mut *recovery };
    let result = match recovery.engine.result() {
        Ok(result) => result,
        Err(error) => return recovery.state.record_error(error),
    };
    let value = Goodix550aBridgeRecoveryInfo {
        tcode: result.tcode(),
        diff: result.diff(),
        fdt_offset: result.fdt_offset(),
        reserved: 0,
        checksum: result.checksum(),
    };
    // SAFETY: info points to writable caller storage for one POD structure.
    unsafe {
        ptr::write(info, value);
    }
    STATUS_OK
}

#[unsafe(no_mangle)]
/// # Safety
///
/// Every non-null raw pointer supplied by the caller must be valid for
/// the access and length described by the corresponding arguments for
/// the duration of this call. Opaque bridge handles must originate from
/// this library and remain live for the duration of the operation.
pub unsafe extern "C" fn goodix550a_bridge_recovery_last_error(
    recovery: *const Goodix550aBridgeRecovery,
) -> *const c_char {
    if recovery.is_null() {
        return c_text(STATUS_INVALID_ARGUMENT_TEXT);
    }
    // SAFETY: pointer is valid until recovery_free; CString storage is owned by it.
    let recovery = unsafe { &*recovery };
    recovery.state.last_error_ptr()
}

#[unsafe(no_mangle)]
/// # Safety
///
/// Every non-null raw pointer supplied by the caller must be valid for
/// the access and length described by the corresponding arguments for
/// the duration of this call. Opaque bridge handles must originate from
/// this library and remain live for the duration of the operation.
pub unsafe extern "C" fn goodix550a_bridge_capture_new(
    capture: *mut *mut Goodix550aBridgeCapture,
) -> i32 {
    if capture.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    let value = match Goodix550aBridgeCapture::new() {
        Ok(value) => value,
        Err(_) => return STATUS_PROTOCOL_ERROR,
    };
    let raw = Box::into_raw(Box::new(value));

    // SAFETY: `capture` was checked for null and points to writable caller
    // storage for one opaque bridge pointer.
    unsafe {
        ptr::write(capture, raw);
    }

    STATUS_OK
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `handle` must either be null or be a live handle returned by the
/// corresponding constructor in this bridge. A non-null handle must
/// not have been freed previously and must not be used after this call.
pub unsafe extern "C" fn goodix550a_bridge_capture_free(capture: *mut Goodix550aBridgeCapture) {
    if capture.is_null() {
        return;
    }

    // SAFETY: the pointer originates from `Box::into_raw` in
    // `goodix550a_bridge_capture_new` and ownership is returned exactly once.
    unsafe {
        drop(Box::from_raw(capture));
    }
}

#[unsafe(no_mangle)]
/// # Safety
///
/// Every non-null raw pointer supplied by the caller must be valid for
/// the access and length described by the corresponding arguments for
/// the duration of this call. Opaque bridge handles must originate from
/// this library and remain live for the duration of the operation.
pub unsafe extern "C" fn goodix550a_bridge_capture_next_action(
    capture: *mut Goodix550aBridgeCapture,
    action: *mut Goodix550aBridgeCaptureAction,
    output: *mut u8,
    output_length: usize,
) -> i32 {
    if capture.is_null() || action.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: `capture` is an opaque pointer created by this bridge and remains
    // exclusively owned by the C driver until capture_free.
    let capture = unsafe { &mut *capture };
    let mut empty = [];
    let output = if output_length == 0 {
        &mut empty[..]
    } else {
        if output.is_null() {
            return STATUS_INVALID_ARGUMENT;
        }
        // SAFETY: the caller guarantees `output_length` writable bytes for the
        // duration of this call. The slice does not escape.
        unsafe { slice::from_raw_parts_mut(output, output_length) }
    };

    let next = match capture.engine.next_action(output) {
        Ok(next) => next,
        Err(error) => return capture.state.record_error(error),
    };
    let timeout_ms = match capture.state.timeout_for_action(
        next.direction(),
        next.stage() as u32,
        next.timeout_ms(),
    ) {
        Ok(timeout_ms) => timeout_ms,
        Err(error) => return capture.state.record_error(error),
    };

    let value = Goodix550aBridgeCaptureAction {
        direction: next.direction() as u32,
        stage: next.stage() as u32,
        transfer_length: next.transfer_length(),
        timeout_ms,
        endpoint: next.endpoint(),
        short_is_error: u8::from(next.short_is_error()),
        reserved: 0,
    };

    // SAFETY: `action` was checked for null and points to writable caller
    // storage for one POD action descriptor.
    unsafe {
        ptr::write(action, value);
    }

    STATUS_OK
}

#[unsafe(no_mangle)]
/// # Safety
///
/// Every non-null raw pointer supplied by the caller must be valid for
/// the access and length described by the corresponding arguments for
/// the duration of this call. Opaque bridge handles must originate from
/// this library and remain live for the duration of the operation.
pub unsafe extern "C" fn goodix550a_bridge_capture_complete_transfer(
    capture: *mut Goodix550aBridgeCapture,
    input: *const u8,
    input_length: usize,
    advanced: *mut u8,
) -> i32 {
    if capture.is_null() || advanced.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: `capture` is an opaque pointer created by this bridge and remains
    // exclusively owned by the C driver until capture_free.
    let capture = unsafe { &mut *capture };
    let bytes = if input_length == 0 {
        &[][..]
    } else {
        if input.is_null() {
            return STATUS_INVALID_ARGUMENT;
        }
        // SAFETY: the C caller guarantees `input_length` readable bytes for the
        // duration of this call. The slice does not escape.
        unsafe { slice::from_raw_parts(input, input_length) }
    };

    let progress = match capture.engine.complete_transfer(bytes) {
        Ok(progress) => progress,
        Err(error) => return capture.state.record_error(error),
    };
    let value = u8::from(matches!(progress, Gf3258LibfprintCaptureProgress::Advanced));

    // SAFETY: `advanced` was checked for null and points to one writable byte.
    unsafe {
        ptr::write(advanced, value);
    }

    STATUS_OK
}

#[unsafe(no_mangle)]
/// # Safety
///
/// Every non-null raw pointer supplied by the caller must be valid for
/// the access and length described by the corresponding arguments for
/// the duration of this call. Opaque bridge handles must originate from
/// this library and remain live for the duration of the operation.
pub unsafe extern "C" fn goodix550a_bridge_capture_copy_image_u8(
    capture: *mut Goodix550aBridgeCapture,
    output: *mut u8,
    output_length: usize,
    info: *mut Goodix550aBridgeCaptureInfo,
) -> i32 {
    if capture.is_null() || output.is_null() || info.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: `capture` is an opaque pointer created by this bridge and remains
    // exclusively owned by the C driver until capture_free.
    let capture = unsafe { &mut *capture };
    let result = match capture.engine.result() {
        Ok(result) => result,
        Err(error) => return capture.state.record_error(error),
    };
    if output_length < result.pixel_count() {
        return STATUS_BUFFER_TOO_SMALL;
    }

    // SAFETY: `output` was checked for null and the caller supplied enough
    // writable bytes for the complete normalized image. The regions do not overlap.
    unsafe {
        ptr::copy_nonoverlapping(
            result.normalized_u8().as_ptr(),
            output,
            result.pixel_count(),
        );
    }
    let value = Goodix550aBridgeCaptureInfo {
        protected_bytes: result.protected_bytes(),
        pixel_count: result.pixel_count(),
        stored_crc: result.stored_crc(),
    };

    // SAFETY: `info` was checked for null and points to writable caller storage
    // for one POD capture-info structure.
    unsafe {
        ptr::write(info, value);
    }

    STATUS_OK
}

#[unsafe(no_mangle)]
/// # Safety
///
/// Every non-null raw pointer supplied by the caller must be valid for
/// the access and length described by the corresponding arguments for
/// the duration of this call. Opaque bridge handles must originate from
/// this library and remain live for the duration of the operation.
pub unsafe extern "C" fn goodix550a_bridge_capture_last_error(
    capture: *const Goodix550aBridgeCapture,
) -> *const c_char {
    if capture.is_null() {
        return c_text(STATUS_INVALID_ARGUMENT_TEXT);
    }

    // SAFETY: `capture` is an opaque pointer created by this bridge and remains
    // valid until capture_free. The returned CString storage is owned by it.
    let capture = unsafe { &*capture };
    capture.state.last_error_ptr()
}

#[unsafe(no_mangle)]
/// # Safety
///
/// Every non-null raw pointer supplied by the caller must be valid for
/// the access and length described by the corresponding arguments for
/// the duration of this call. Opaque bridge handles must originate from
/// this library and remain live for the duration of the operation.
pub unsafe extern "C" fn goodix550a_bridge_enrollment_new(
    enrollment: *mut *mut Goodix550aBridgeEnrollment,
) -> i32 {
    if enrollment.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    let value = match Goodix550aBridgeEnrollment::new() {
        Ok(value) => value,
        Err(_) => return STATUS_PROTOCOL_ERROR,
    };
    let raw = Box::into_raw(Box::new(value));

    // SAFETY: `enrollment` points to writable caller storage for one opaque pointer.
    unsafe {
        ptr::write(enrollment, raw);
    }

    STATUS_OK
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `handle` must either be null or be a live handle returned by the
/// corresponding constructor in this bridge. A non-null handle must
/// not have been freed previously and must not be used after this call.
pub unsafe extern "C" fn goodix550a_bridge_enrollment_free(
    enrollment: *mut Goodix550aBridgeEnrollment,
) {
    if enrollment.is_null() {
        return;
    }

    // SAFETY: pointer originates from enrollment_new and ownership is returned once.
    unsafe {
        drop(Box::from_raw(enrollment));
    }
}

#[unsafe(no_mangle)]
/// # Safety
///
/// Every non-null raw pointer supplied by the caller must be valid for
/// the access and length described by the corresponding arguments for
/// the duration of this call. Opaque bridge handles must originate from
/// this library and remain live for the duration of the operation.
pub unsafe extern "C" fn goodix550a_bridge_enrollment_next_action(
    enrollment: *mut Goodix550aBridgeEnrollment,
    action: *mut Goodix550aBridgeEnrollmentAction,
    output: *mut u8,
    output_length: usize,
) -> i32 {
    if enrollment.is_null() || action.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: opaque pointer is bridge-owned and valid until enrollment_free.
    let enrollment = unsafe { &mut *enrollment };
    let mut empty = [];
    let output = if output_length == 0 {
        &mut empty[..]
    } else {
        if output.is_null() {
            return STATUS_INVALID_ARGUMENT;
        }
        // SAFETY: caller provides output_length writable bytes for this call.
        unsafe { slice::from_raw_parts_mut(output, output_length) }
    };

    let next = match enrollment.engine.next_action(output) {
        Ok(next) => next,
        Err(error) => return enrollment.state.record_error(error),
    };
    let timeout_ms = match enrollment.state.timeout_for_action(
        next.direction(),
        next.stage() as u32,
        next.timeout_ms(),
    ) {
        Ok(timeout_ms) => timeout_ms,
        Err(error) => return enrollment.state.record_error(error),
    };

    let value = Goodix550aBridgeEnrollmentAction {
        direction: next.direction() as u32,
        stage: next.stage() as u32,
        transfer_length: next.transfer_length(),
        timeout_ms,
        endpoint: next.endpoint(),
        short_is_error: u8::from(next.short_is_error()),
        reserved: 0,
    };

    // SAFETY: action points to writable caller storage for one POD descriptor.
    unsafe {
        ptr::write(action, value);
    }

    STATUS_OK
}

#[unsafe(no_mangle)]
/// # Safety
///
/// Every non-null raw pointer supplied by the caller must be valid for
/// the access and length described by the corresponding arguments for
/// the duration of this call. Opaque bridge handles must originate from
/// this library and remain live for the duration of the operation.
pub unsafe extern "C" fn goodix550a_bridge_enrollment_complete_transfer(
    enrollment: *mut Goodix550aBridgeEnrollment,
    input: *const u8,
    input_length: usize,
    advanced: *mut u8,
) -> i32 {
    if enrollment.is_null() || advanced.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: opaque pointer is bridge-owned and valid until enrollment_free.
    let enrollment = unsafe { &mut *enrollment };
    let bytes = if input_length == 0 {
        &[][..]
    } else {
        if input.is_null() {
            return STATUS_INVALID_ARGUMENT;
        }
        // SAFETY: caller provides input_length readable bytes for this call.
        unsafe { slice::from_raw_parts(input, input_length) }
    };

    let progress = match enrollment.engine.complete_transfer(bytes) {
        Ok(progress) => progress,
        Err(error) => return enrollment.state.record_error(error),
    };
    let value = u8::from(matches!(progress, Gf3258LibfprintCaptureProgress::Advanced));

    // SAFETY: advanced points to one writable byte.
    unsafe {
        ptr::write(advanced, value);
    }

    STATUS_OK
}

#[unsafe(no_mangle)]
/// # Safety
///
/// Every non-null raw pointer supplied by the caller must be valid for
/// the access and length described by the corresponding arguments for
/// the duration of this call. Opaque bridge handles must originate from
/// this library and remain live for the duration of the operation.
pub unsafe extern "C" fn goodix550a_bridge_enrollment_result(
    enrollment: *mut Goodix550aBridgeEnrollment,
    info: *mut Goodix550aBridgeEnrollmentInfo,
) -> i32 {
    if enrollment.is_null() || info.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: opaque pointer is bridge-owned and valid until enrollment_free.
    let enrollment = unsafe { &mut *enrollment };
    let result = match enrollment.engine.result() {
        Ok(result) => result,
        Err(error) => return enrollment.state.record_error(error),
    };
    let disposition = result.disposition() as u32;
    let value = Goodix550aBridgeEnrollmentInfo {
        disposition,
        sample_count: result.sample_count(),
        progress_percent: result.progress_percent(),
        protected_bytes: result.protected_bytes(),
        pixel_count: result.pixel_count(),
        stored_crc: result.stored_crc(),
        tgla_bytes: result.tgla_bytes(),
    };

    // SAFETY: info points to writable caller storage for one POD structure.
    unsafe {
        ptr::write(info, value);
    }

    STATUS_OK
}

#[unsafe(no_mangle)]
/// # Safety
///
/// Every non-null raw pointer supplied by the caller must be valid for
/// the access and length described by the corresponding arguments for
/// the duration of this call. Opaque bridge handles must originate from
/// this library and remain live for the duration of the operation.
pub unsafe extern "C" fn goodix550a_bridge_enrollment_start_next_touch(
    enrollment: *mut Goodix550aBridgeEnrollment,
) -> i32 {
    if enrollment.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: opaque pointer is bridge-owned and valid until enrollment_free.
    let enrollment = unsafe { &mut *enrollment };
    match enrollment.engine.start_next_touch() {
        Ok(()) => STATUS_OK,
        Err(error) => enrollment.state.record_error(error),
    }
}

#[unsafe(no_mangle)]
/// # Safety
///
/// Every non-null raw pointer supplied by the caller must be valid for
/// the access and length described by the corresponding arguments for
/// the duration of this call. Opaque bridge handles must originate from
/// this library and remain live for the duration of the operation.
pub unsafe extern "C" fn goodix550a_bridge_enrollment_copy_tgla(
    enrollment: *mut Goodix550aBridgeEnrollment,
    output: *mut u8,
    output_length: usize,
    written: *mut usize,
) -> i32 {
    if enrollment.is_null() || output.is_null() || written.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: opaque pointer is bridge-owned and valid until enrollment_free.
    let enrollment = unsafe { &mut *enrollment };
    let tgla = match enrollment.engine.tgla() {
        Ok(tgla) => tgla,
        Err(error) => return enrollment.state.record_error(error),
    };
    if output_length < tgla.len() {
        return STATUS_BUFFER_TOO_SMALL;
    }

    // SAFETY: caller supplied at least tgla.len() writable bytes; regions do not overlap.
    unsafe {
        ptr::copy_nonoverlapping(tgla.as_ptr(), output, tgla.len());
        ptr::write(written, tgla.len());
    }

    STATUS_OK
}

#[unsafe(no_mangle)]
/// # Safety
///
/// Every non-null raw pointer supplied by the caller must be valid for
/// the access and length described by the corresponding arguments for
/// the duration of this call. Opaque bridge handles must originate from
/// this library and remain live for the duration of the operation.
pub unsafe extern "C" fn goodix550a_bridge_enrollment_last_error(
    enrollment: *const Goodix550aBridgeEnrollment,
) -> *const c_char {
    if enrollment.is_null() {
        return c_text(STATUS_INVALID_ARGUMENT_TEXT);
    }

    // SAFETY: pointer is valid until enrollment_free; CString storage is owned by it.
    let enrollment = unsafe { &*enrollment };
    enrollment.state.last_error_ptr()
}

#[unsafe(no_mangle)]
/// # Safety
///
/// Every non-null raw pointer supplied by the caller must be valid for
/// the access and length described by the corresponding arguments for
/// the duration of this call. Opaque bridge handles must originate from
/// this library and remain live for the duration of the operation.
pub unsafe extern "C" fn goodix550a_bridge_verification_new(
    tgla: *const u8,
    tgla_length: usize,
    verification: *mut *mut Goodix550aBridgeVerification,
) -> i32 {
    if tgla.is_null() || tgla_length == 0 || verification.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the C caller guarantees `tgla_length` readable bytes for this
    // call. The Rust engine fully decodes/owns its template before returning.
    let tgla = unsafe { slice::from_raw_parts(tgla, tgla_length) };
    let value = match Goodix550aBridgeVerification::new(tgla) {
        Ok(value) => value,
        Err(_) => return STATUS_PROTOCOL_ERROR,
    };
    let raw = Box::into_raw(Box::new(value));

    // SAFETY: `verification` points to writable caller storage for one opaque
    // bridge pointer.
    unsafe {
        ptr::write(verification, raw);
    }

    STATUS_OK
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `handle` must either be null or be a live handle returned by the
/// corresponding constructor in this bridge. A non-null handle must
/// not have been freed previously and must not be used after this call.
pub unsafe extern "C" fn goodix550a_bridge_verification_free(
    verification: *mut Goodix550aBridgeVerification,
) {
    if verification.is_null() {
        return;
    }

    // SAFETY: pointer originates from verification_new and ownership is
    // returned exactly once.
    unsafe {
        drop(Box::from_raw(verification));
    }
}

#[unsafe(no_mangle)]
/// # Safety
///
/// Every non-null raw pointer supplied by the caller must be valid for
/// the access and length described by the corresponding arguments for
/// the duration of this call. Opaque bridge handles must originate from
/// this library and remain live for the duration of the operation.
pub unsafe extern "C" fn goodix550a_bridge_verification_next_action(
    verification: *mut Goodix550aBridgeVerification,
    action: *mut Goodix550aBridgeVerificationAction,
    output: *mut u8,
    output_length: usize,
) -> i32 {
    if verification.is_null() || action.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: opaque pointer is bridge-owned and valid until verification_free.
    let verification = unsafe { &mut *verification };
    let mut empty = [];
    let output = if output_length == 0 {
        &mut empty[..]
    } else {
        if output.is_null() {
            return STATUS_INVALID_ARGUMENT;
        }
        // SAFETY: caller provides output_length writable bytes for this call.
        unsafe { slice::from_raw_parts_mut(output, output_length) }
    };

    let next = match verification.engine.next_action(output) {
        Ok(next) => next,
        Err(error) => return verification.state.record_error(error),
    };
    let timeout_ms = match verification.state.timeout_for_action(
        next.direction(),
        next.stage() as u32,
        next.timeout_ms(),
    ) {
        Ok(timeout_ms) => timeout_ms,
        Err(error) => return verification.state.record_error(error),
    };

    let value = Goodix550aBridgeVerificationAction {
        direction: next.direction() as u32,
        stage: next.stage() as u32,
        transfer_length: next.transfer_length(),
        timeout_ms,
        endpoint: next.endpoint(),
        short_is_error: u8::from(next.short_is_error()),
        reserved: 0,
    };

    // SAFETY: `action` points to writable caller storage for one POD action.
    unsafe {
        ptr::write(action, value);
    }

    STATUS_OK
}

#[unsafe(no_mangle)]
/// # Safety
///
/// Every non-null raw pointer supplied by the caller must be valid for
/// the access and length described by the corresponding arguments for
/// the duration of this call. Opaque bridge handles must originate from
/// this library and remain live for the duration of the operation.
pub unsafe extern "C" fn goodix550a_bridge_verification_complete_transfer(
    verification: *mut Goodix550aBridgeVerification,
    input: *const u8,
    input_length: usize,
    advanced: *mut u8,
) -> i32 {
    if verification.is_null() || advanced.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: opaque pointer is bridge-owned and valid until verification_free.
    let verification = unsafe { &mut *verification };
    let bytes = if input_length == 0 {
        &[][..]
    } else {
        if input.is_null() {
            return STATUS_INVALID_ARGUMENT;
        }
        // SAFETY: caller provides input_length readable bytes for this call.
        unsafe { slice::from_raw_parts(input, input_length) }
    };

    let progress = match verification.engine.complete_transfer(bytes) {
        Ok(progress) => progress,
        Err(error) => return verification.state.record_error(error),
    };
    let value = u8::from(matches!(progress, Gf3258LibfprintCaptureProgress::Advanced));

    // SAFETY: `advanced` points to one writable byte.
    unsafe {
        ptr::write(advanced, value);
    }

    STATUS_OK
}

#[unsafe(no_mangle)]
/// # Safety
///
/// Every non-null raw pointer supplied by the caller must be valid for
/// the access and length described by the corresponding arguments for
/// the duration of this call. Opaque bridge handles must originate from
/// this library and remain live for the duration of the operation.
pub unsafe extern "C" fn goodix550a_bridge_verification_result(
    verification: *mut Goodix550aBridgeVerification,
    info: *mut Goodix550aBridgeVerificationInfo,
) -> i32 {
    if verification.is_null() || info.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: opaque pointer is bridge-owned and valid until verification_free.
    let verification = unsafe { &mut *verification };
    let result = match verification.engine.result() {
        Ok(result) => result,
        Err(error) => return verification.state.record_error(error),
    };
    let disposition = result.disposition() as u32;
    let value = Goodix550aBridgeVerificationInfo {
        disposition,
        score: result.score(),
        protected_bytes: result.protected_bytes(),
        pixel_count: result.pixel_count(),
        stored_crc: result.stored_crc(),
    };

    // SAFETY: `info` points to writable caller storage for one POD result.
    unsafe {
        ptr::write(info, value);
    }

    STATUS_OK
}

#[unsafe(no_mangle)]
/// # Safety
///
/// Every non-null raw pointer supplied by the caller must be valid for
/// the access and length described by the corresponding arguments for
/// the duration of this call. Opaque bridge handles must originate from
/// this library and remain live for the duration of the operation.
pub unsafe extern "C" fn goodix550a_bridge_verification_last_error(
    verification: *const Goodix550aBridgeVerification,
) -> *const c_char {
    if verification.is_null() {
        return c_text(STATUS_INVALID_ARGUMENT_TEXT);
    }

    // SAFETY: pointer is valid until verification_free; CString storage is
    // owned by the opaque bridge object.
    let verification = unsafe { &*verification };
    verification.state.last_error_ptr()
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `tgla` must point to `tgla_length` readable bytes. `identification` must
/// point to writable storage for one opaque bridge pointer.
pub unsafe extern "C" fn goodix550a_bridge_identification_new(
    tgla: *const u8,
    tgla_length: usize,
    identification: *mut *mut Goodix550aBridgeIdentification,
) -> i32 {
    if identification.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    /*
     * A failed constructor must never leave a stale caller value looking like
     * a live bridge handle.
     */
    // SAFETY: identification points to writable caller storage for one pointer.
    unsafe {
        ptr::write(identification, ptr::null_mut());
    }

    if tgla.is_null() || tgla_length == 0 {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: caller guarantees tgla_length readable bytes for this call.
    let tgla = unsafe { slice::from_raw_parts(tgla, tgla_length) };

    let value = match Goodix550aBridgeIdentification::new(tgla) {
        Ok(value) => value,
        Err(_) => return STATUS_PROTOCOL_ERROR,
    };

    let raw = Box::into_raw(Box::new(value));

    // SAFETY: identification points to writable caller storage for one pointer.
    unsafe {
        ptr::write(identification, raw);
    }

    STATUS_OK
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `identification` must be a live bridge handle and `tgla` must point to
/// `tgla_length` readable bytes.
pub unsafe extern "C" fn goodix550a_bridge_identification_add_template(
    identification: *mut Goodix550aBridgeIdentification,
    tgla: *const u8,
    tgla_length: usize,
) -> i32 {
    if identification.is_null() || tgla.is_null() || tgla_length == 0 {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: handle and input storage are valid for this call.
    let identification = unsafe { &mut *identification };
    let tgla = unsafe { slice::from_raw_parts(tgla, tgla_length) };

    match identification.engine.add_template(tgla) {
        Ok(()) => STATUS_OK,
        Err(error) => identification.state.record_error(error),
    }
}

#[unsafe(no_mangle)]
/// # Safety
///
/// A non-null handle must have been returned by identification_new exactly
/// once and must not be used after this call.
pub unsafe extern "C" fn goodix550a_bridge_identification_free(
    identification: *mut Goodix550aBridgeIdentification,
) {
    if identification.is_null() {
        return;
    }

    // SAFETY: ownership originated from Box::into_raw in identification_new.
    unsafe {
        drop(Box::from_raw(identification));
    }
}

#[unsafe(no_mangle)]
/// # Safety
///
/// All non-null pointers must be valid for the supplied lengths for the
/// duration of this call.
pub unsafe extern "C" fn goodix550a_bridge_identification_next_action(
    identification: *mut Goodix550aBridgeIdentification,
    action: *mut Goodix550aBridgeIdentificationAction,
    output: *mut u8,
    output_length: usize,
) -> i32 {
    if identification.is_null() || action.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: handle remains bridge-owned until identification_free.
    let identification = unsafe { &mut *identification };

    let mut empty = [];
    let output = if output_length == 0 {
        &mut empty[..]
    } else {
        if output.is_null() {
            return STATUS_INVALID_ARGUMENT;
        }

        // SAFETY: caller supplied output_length writable bytes.
        unsafe { slice::from_raw_parts_mut(output, output_length) }
    };

    let next = match identification.engine.next_action(output) {
        Ok(next) => next,
        Err(error) => return identification.state.record_error(error),
    };

    /*
     * Identification deliberately receives the same absolute-IN-stage
     * deadline protection as verify/enroll/capture. An ignored packet may
     * resubmit an IN transfer, but may not purchase a fresh timeout budget.
     */
    let timeout_ms = match identification.state.timeout_for_action(
        next.direction(),
        next.stage() as u32,
        next.timeout_ms(),
    ) {
        Ok(timeout_ms) => timeout_ms,
        Err(error) => return identification.state.record_error(error),
    };

    let value = Goodix550aBridgeIdentificationAction {
        direction: next.direction() as u32,
        stage: next.stage() as u32,
        transfer_length: next.transfer_length(),
        timeout_ms,
        endpoint: next.endpoint(),
        short_is_error: u8::from(next.short_is_error()),
        reserved: 0,
    };

    // SAFETY: action points to writable storage for one POD action.
    unsafe {
        ptr::write(action, value);
    }

    STATUS_OK
}

#[unsafe(no_mangle)]
/// # Safety
///
/// Input must contain `input_length` readable bytes when non-empty and
/// `advanced` must point to one writable byte.
pub unsafe extern "C" fn goodix550a_bridge_identification_complete_transfer(
    identification: *mut Goodix550aBridgeIdentification,
    input: *const u8,
    input_length: usize,
    advanced: *mut u8,
) -> i32 {
    if identification.is_null() || advanced.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: handle remains valid until identification_free.
    let identification = unsafe { &mut *identification };

    let bytes = if input_length == 0 {
        &[][..]
    } else {
        if input.is_null() {
            return STATUS_INVALID_ARGUMENT;
        }

        // SAFETY: caller supplied input_length readable bytes.
        unsafe { slice::from_raw_parts(input, input_length) }
    };

    let progress = match identification.engine.complete_transfer(bytes) {
        Ok(progress) => progress,
        Err(error) => return identification.state.record_error(error),
    };

    let value = u8::from(matches!(progress, Gf3258LibfprintCaptureProgress::Advanced));

    // SAFETY: advanced points to one writable byte.
    unsafe {
        ptr::write(advanced, value);
    }

    STATUS_OK
}

#[unsafe(no_mangle)]
/// # Safety
///
/// Both pointers must refer to live/writable storage for this call.
pub unsafe extern "C" fn goodix550a_bridge_identification_result(
    identification: *mut Goodix550aBridgeIdentification,
    info: *mut Goodix550aBridgeIdentificationInfo,
) -> i32 {
    if identification.is_null() || info.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: handle remains valid until identification_free.
    let identification = unsafe { &mut *identification };

    let result = match identification.engine.result() {
        Ok(result) => result,
        Err(error) => return identification.state.record_error(error),
    };

    let result_disposition = result.disposition();
    let disposition = result_disposition as u32;

    /*
     * SIZE_MAX is only a transport sentinel. C must inspect disposition before
     * using match_index. A Match is required to have a real gallery index.
     */
    let match_index = match result.match_index() {
        Some(index) => index,
        None => usize::MAX,
    };

    if result_disposition == Gf3258LibfprintIdentificationDisposition::Match
        && result.match_index().is_none()
    {
        return identification
            .state
            .record_error("identification Match result did not contain a gallery index");
    }

    if result_disposition != Gf3258LibfprintIdentificationDisposition::Match
        && result.match_index().is_some()
    {
        return identification.state.record_error(
            "non-Match identification result unexpectedly contained a gallery index",
        );
    }

    let value = Goodix550aBridgeIdentificationInfo {
        disposition,
        score: result.score(),
        match_index,
        protected_bytes: result.protected_bytes(),
        pixel_count: result.pixel_count(),
        stored_crc: result.stored_crc(),
        scanned_tgla_bytes: result.scanned_tgla_bytes(),
    };

    // SAFETY: info points to writable caller storage for one POD result.
    unsafe {
        ptr::write(info, value);
    }

    STATUS_OK
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `output` must have at least `output_length` writable bytes and `written`
/// must point to one writable size_t.
pub unsafe extern "C" fn goodix550a_bridge_identification_copy_scanned_tgla(
    identification: *mut Goodix550aBridgeIdentification,
    output: *mut u8,
    output_length: usize,
    written: *mut usize,
) -> i32 {
    if identification.is_null() || written.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: handle remains valid until identification_free.
    let identification = unsafe { &mut *identification };

    let tgla = match identification.engine.scanned_tgla() {
        Ok(tgla) => tgla,
        Err(error) => return identification.state.record_error(error),
    };

    if output_length < tgla.len() {
        return STATUS_BUFFER_TOO_SMALL;
    }

    if !tgla.is_empty() {
        if output.is_null() {
            return STATUS_INVALID_ARGUMENT;
        }

        // SAFETY: output has tgla.len() writable bytes and the regions do not overlap.
        unsafe {
            ptr::copy_nonoverlapping(tgla.as_ptr(), output, tgla.len());
        }
    }

    // SAFETY: written points to one writable size_t.
    unsafe {
        ptr::write(written, tgla.len());
    }

    STATUS_OK
}

#[unsafe(no_mangle)]
/// # Safety
///
/// The pointer must be null or a live identification bridge handle.
pub unsafe extern "C" fn goodix550a_bridge_identification_last_error(
    identification: *const Goodix550aBridgeIdentification,
) -> *const c_char {
    if identification.is_null() {
        return c_text(STATUS_INVALID_ARGUMENT_TEXT);
    }

    // SAFETY: CString storage is owned by the live opaque handle.
    let identification = unsafe { &*identification };
    identification.state.last_error_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn goodix550a_bridge_firmware_name(firmware: u32) -> *const c_char {
    if firmware == Gf3258LibfprintFirmwareIdentity::App15045 as u32 {
        c_text(APP_VERSION_TEXT)
    } else if firmware == Gf3258LibfprintFirmwareIdentity::Iap10007 as u32 {
        c_text(IAP_VERSION_TEXT)
    } else {
        c_text(UNKNOWN_VERSION_TEXT)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn goodix550a_bridge_status_message(status: i32) -> *const c_char {
    match status {
        STATUS_OK => c_text(STATUS_OK_TEXT),
        STATUS_INVALID_ARGUMENT => c_text(STATUS_INVALID_ARGUMENT_TEXT),
        STATUS_BUFFER_TOO_SMALL => c_text(STATUS_BUFFER_TOO_SMALL_TEXT),
        STATUS_PROTOCOL_ERROR => c_text(STATUS_PROTOCOL_ERROR_TEXT),
        _ => c_text(STATUS_UNKNOWN_TEXT),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_in_stage_consumes_one_absolute_budget() {
        let mut deadline = InTransferDeadline::default();
        let start = Instant::now();

        assert_eq!(
            deadline
                .timeout_for_action_at(Gf3258LibfprintTransferDirection::In, 7, 30_000, start,)
                .unwrap(),
            30_000
        );

        assert_eq!(
            deadline
                .timeout_for_action_at(
                    Gf3258LibfprintTransferDirection::In,
                    7,
                    30_000,
                    start + Duration::from_secs(10),
                )
                .unwrap(),
            20_000
        );

        assert_eq!(
            deadline
                .timeout_for_action_at(
                    Gf3258LibfprintTransferDirection::In,
                    7,
                    30_000,
                    start + Duration::from_millis(29_999),
                )
                .unwrap(),
            1
        );

        let error = deadline
            .timeout_for_action_at(
                Gf3258LibfprintTransferDirection::In,
                7,
                30_000,
                start + Duration::from_secs(30),
            )
            .unwrap_err();

        assert!(error.contains("absolute 30000 ms wait budget"));
    }

    #[test]
    fn advancing_to_another_in_stage_gets_a_fresh_budget() {
        let mut deadline = InTransferDeadline::default();
        let start = Instant::now();

        assert_eq!(
            deadline
                .timeout_for_action_at(Gf3258LibfprintTransferDirection::In, 7, 30_000, start,)
                .unwrap(),
            30_000
        );

        assert_eq!(
            deadline
                .timeout_for_action_at(
                    Gf3258LibfprintTransferDirection::In,
                    8,
                    3_000,
                    start + Duration::from_secs(20),
                )
                .unwrap(),
            3_000
        );
    }

    #[test]
    fn out_action_clears_the_prior_in_deadline() {
        let mut deadline = InTransferDeadline::default();
        let start = Instant::now();

        assert_eq!(
            deadline
                .timeout_for_action_at(Gf3258LibfprintTransferDirection::In, 7, 30_000, start,)
                .unwrap(),
            30_000
        );

        assert_eq!(
            deadline
                .timeout_for_action_at(
                    Gf3258LibfprintTransferDirection::Out,
                    8,
                    1_000,
                    start + Duration::from_secs(10),
                )
                .unwrap(),
            1_000
        );

        // Returning to the same numeric IN stage after an OUT action represents
        // a new logical wait and therefore receives a fresh budget.
        assert_eq!(
            deadline
                .timeout_for_action_at(
                    Gf3258LibfprintTransferDirection::In,
                    7,
                    30_000,
                    start + Duration::from_secs(20),
                )
                .unwrap(),
            30_000
        );
    }

    #[test]
    fn changing_timeout_does_not_reset_same_stage_deadline() {
        let mut deadline = InTransferDeadline::default();
        let start = Instant::now();

        assert_eq!(
            deadline
                .timeout_for_action_at(Gf3258LibfprintTransferDirection::In, 7, 30_000, start,)
                .unwrap(),
            30_000
        );

        // Tightening the individual transfer timeout is allowed, but the
        // original 30-second absolute deadline remains authoritative.
        assert_eq!(
            deadline
                .timeout_for_action_at(
                    Gf3258LibfprintTransferDirection::In,
                    7,
                    5_000,
                    start + Duration::from_secs(10),
                )
                .unwrap(),
            5_000
        );

        // Increasing it again cannot buy another 30 seconds.
        assert_eq!(
            deadline
                .timeout_for_action_at(
                    Gf3258LibfprintTransferDirection::In,
                    7,
                    30_000,
                    start + Duration::from_secs(29),
                )
                .unwrap(),
            1_000
        );

        assert!(
            deadline
                .timeout_for_action_at(
                    Gf3258LibfprintTransferDirection::In,
                    7,
                    30_000,
                    start + Duration::from_secs(30),
                )
                .is_err()
        );
    }

    #[test]
    fn zero_timeout_is_rejected_for_in_transfer() {
        let mut deadline = InTransferDeadline::default();

        let error = deadline
            .timeout_for_action_at(Gf3258LibfprintTransferDirection::In, 3, 0, Instant::now())
            .unwrap_err();

        assert!(error.contains("unbounded zero-millisecond timeout"));
    }

    #[test]
    fn sub_millisecond_remaining_never_becomes_infinite_usb_timeout() {
        let mut deadline = InTransferDeadline::default();
        let start = Instant::now();

        deadline
            .timeout_for_action_at(Gf3258LibfprintTransferDirection::In, 3, 1_000, start)
            .unwrap();

        let timeout_ms = deadline
            .timeout_for_action_at(
                Gf3258LibfprintTransferDirection::In,
                3,
                1_000,
                start + Duration::from_micros(999_500),
            )
            .unwrap();

        assert_eq!(timeout_ms, 1);
    }

    fn synthetic_identification_tgla() -> Vec<u8> {
        use goodix_info::enrollment::{Gf3258EnrollmentFrameOutcome, Gf3258EnrollmentWorkflow};
        use goodix_info::libfprint_wire::GF3258_LIBFPRINT_CAPTURE_PIXEL_COUNT;

        let raw = vec![1000u16; GF3258_LIBFPRINT_CAPTURE_PIXEL_COUNT];
        let mut enrollment = Gf3258EnrollmentWorkflow::new();

        assert!(matches!(
            enrollment.process_raw_frame(&raw).unwrap(),
            Gf3258EnrollmentFrameOutcome::Accepted(_)
        ));

        enrollment
            .encode_artifacts()
            .unwrap()
            .tgla_template()
            .to_vec()
    }

    #[test]
    fn identification_abi_constructor_nulls_failed_output() {
        let malformed = b"not-a-template";
        let mut identification =
            std::ptr::NonNull::<Goodix550aBridgeIdentification>::dangling().as_ptr();

        let status = unsafe {
            goodix550a_bridge_identification_new(
                malformed.as_ptr(),
                malformed.len(),
                &mut identification,
            )
        };

        assert_eq!(status, STATUS_PROTOCOL_ERROR);
        assert!(identification.is_null());

        let tgla = synthetic_identification_tgla();
        let status = unsafe {
            goodix550a_bridge_identification_new(tgla.as_ptr(), tgla.len(), std::ptr::null_mut())
        };
        assert_eq!(status, STATUS_INVALID_ARGUMENT);

        // Freeing NULL is intentionally a no-op at the C ABI boundary.
        unsafe {
            goodix550a_bridge_identification_free(std::ptr::null_mut());
        }
    }

    #[test]
    fn identification_abi_accepts_gallery_before_capture() {
        let tgla = synthetic_identification_tgla();
        let mut identification = std::ptr::null_mut();

        assert_eq!(
            unsafe {
                goodix550a_bridge_identification_new(tgla.as_ptr(), tgla.len(), &mut identification)
            },
            STATUS_OK
        );
        assert!(!identification.is_null());

        assert_eq!(
            unsafe {
                goodix550a_bridge_identification_add_template(
                    identification,
                    tgla.as_ptr(),
                    tgla.len(),
                )
            },
            STATUS_OK
        );

        let malformed = b"bad-template";
        assert_eq!(
            unsafe {
                goodix550a_bridge_identification_add_template(
                    identification,
                    malformed.as_ptr(),
                    malformed.len(),
                )
            },
            STATUS_PROTOCOL_ERROR
        );

        let error = unsafe {
            std::ffi::CStr::from_ptr(goodix550a_bridge_identification_last_error(identification))
        }
        .to_string_lossy();

        assert_ne!(error, "ok");

        unsafe {
            goodix550a_bridge_identification_free(identification);
        }
    }

    #[test]
    fn identification_abi_freezes_gallery_after_first_action() {
        let tgla = synthetic_identification_tgla();
        let mut identification = std::ptr::null_mut();

        assert_eq!(
            unsafe {
                goodix550a_bridge_identification_new(tgla.as_ptr(), tgla.len(), &mut identification)
            },
            STATUS_OK
        );

        let mut action = std::mem::MaybeUninit::<Goodix550aBridgeIdentificationAction>::uninit();
        let mut output = [0u8; 64];

        assert_eq!(
            unsafe {
                goodix550a_bridge_identification_next_action(
                    identification,
                    action.as_mut_ptr(),
                    output.as_mut_ptr(),
                    output.len(),
                )
            },
            STATUS_OK
        );

        assert_eq!(
            unsafe {
                goodix550a_bridge_identification_add_template(
                    identification,
                    tgla.as_ptr(),
                    tgla.len(),
                )
            },
            STATUS_PROTOCOL_ERROR
        );

        let error = unsafe {
            std::ffi::CStr::from_ptr(goodix550a_bridge_identification_last_error(identification))
        }
        .to_string_lossy();

        assert_ne!(error, "ok");

        unsafe {
            goodix550a_bridge_identification_free(identification);
        }
    }

    #[test]
    fn identification_abi_result_and_scanned_tgla_require_completion() {
        let tgla = synthetic_identification_tgla();
        let mut identification = std::ptr::null_mut();

        assert_eq!(
            unsafe {
                goodix550a_bridge_identification_new(tgla.as_ptr(), tgla.len(), &mut identification)
            },
            STATUS_OK
        );

        let mut info = std::mem::MaybeUninit::<Goodix550aBridgeIdentificationInfo>::uninit();

        assert_eq!(
            unsafe { goodix550a_bridge_identification_result(identification, info.as_mut_ptr(),) },
            STATUS_PROTOCOL_ERROR
        );

        let mut written = usize::MAX;

        assert_eq!(
            unsafe {
                goodix550a_bridge_identification_copy_scanned_tgla(
                    identification,
                    std::ptr::null_mut(),
                    0,
                    &mut written,
                )
            },
            STATUS_PROTOCOL_ERROR
        );

        assert_eq!(written, usize::MAX);

        unsafe {
            goodix550a_bridge_identification_free(identification);
        }
    }
}
