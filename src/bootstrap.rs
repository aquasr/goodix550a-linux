use std::{error::Error, io, str, time::Duration};

use crate::{
    device::{GoodixDevice, GoodixUsbIo, ReenumerationError},
    firmware::{AppTransferPackage, FirmwareBlob},
    firmware_auth::{firmware_f4_tag, unseal_psk, verify_psk_hash},
    trace::TraceLogger,
    transport::GoodixTransport,
};

/// Exact IAP build on the target GM168SEC / 27c6:550a.
pub(crate) const EXPECTED_IAP_VERSION: &str = "MILAN_GM168SEC_IAP_10007";

/// Exact APP build carried by the recovered firmware resource.
pub(crate) const EXPECTED_APP_VERSION: &str = "GFUSB_GM168SEC_APP_15045";

const EXPECTED_FIRMWARE_BLOB_LEN: usize = 0x611d;
const EXPECTED_APP_LEN: usize = 0x6100;
const EXPECTED_BLOB_CRC: u32 = 0x4bd5_12b0;
const EXPECTED_PACKAGE_APP_CRC: u32 = 0x4d44_46c1;
const EXPECTED_PACKAGE_HEADER_CRC: u32 = 0xa2b6_9ee2;
const EXPECTED_PACKAGE_LEN: usize = 0x610c;
const EXPECTED_F0_CHUNK_COUNT: usize = 98;

/// Vendor WriteApp waits at most 10 seconds for detach -> attach.
pub(crate) const REENUMERATION_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeouts whose exact vendor values are not yet being claimed here.
///
/// The re-enumeration bound is intentionally not configurable because the
/// 10-second value is recovered directly from WriteApp. The remaining
/// command-level timeout values are supplied by the caller so this module
/// does not invent vendor constants we have not proven.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BootstrapTimeouts {
    pub(crate) version: Duration,
    pub(crate) psk_read: Duration,
    pub(crate) f0: Duration,
    pub(crate) f4: Duration,
    pub(crate) reset_mcu_ack: Duration,
    pub(crate) reset_fingerprint: Duration,
    pub(crate) chip_id: Duration,
}

/// Typestate token produced only after the pre-detach portion of the cold
/// bootstrap has completed successfully.
///
/// Possessing this value means:
///
/// ```text
/// IAP version verified
/// -> persisted PSK read + authenticated + hash verified
/// -> APP package built
/// -> F4 tag derived from that live PSK and exact package
/// -> every F0 transaction succeeded
/// -> F4 result byte was non-zero
/// -> A2 02 32 received its matching successful B0 ACK
/// ```
///
/// It does NOT mean the new APP instance has re-enumerated yet.
#[derive(Debug)]
pub(crate) struct PendingColdBootstrap {
    expected_app_version: String,
    f0_chunks_sent: usize,
    firmware_check_result: u8,
}

/// Final result after the fresh, re-enumerated USB instance has passed both
/// APP-version and loader chip-ID validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ColdBootstrapResult {
    pub(crate) app_version: String,
    pub(crate) chip_id: u32,
    pub(crate) f0_chunks_sent: usize,
    pub(crate) firmware_check_result: u8,
}

/// Successful cold-bootstrap handoff.
///
/// The caller receives the exact re-enumerated APP device plus the SAME
/// TraceLogger session that recorded the IAP side of the transition. This
/// allows subsequent APP initialization/capture to continue without reopening
/// or truncating the trace file.
pub(crate) struct ColdBootstrapSession {
    pub(crate) result: ColdBootstrapResult,
    pub(crate) device: GoodixDevice,
    pub(crate) trace: TraceLogger,
}

/// Validate the exact redistributable-external APP15045 resource before any
/// persistent firmware write is possible.
///
/// This preserves the live-bootstrap hard preflight in the reusable driver
/// path. The project does not redistribute the firmware blob; callers supply
/// the bytes explicitly when cold IAP recovery is required.
pub(crate) fn validate_cold_bootstrap_firmware(firmware_blob: &[u8]) -> Result<(), Box<dyn Error>> {
    let blob = FirmwareBlob::parse(firmware_blob)?;
    let metadata = firmware_metadata_version(&blob)?;

    if metadata != EXPECTED_APP_VERSION {
        return Err(invalid_data(format!(
            "unexpected APP firmware metadata: expected {EXPECTED_APP_VERSION}, found {metadata}"
        ))
        .into());
    }

    let package = AppTransferPackage::build(&blob)?;
    let exact_target = firmware_blob.len() == EXPECTED_FIRMWARE_BLOB_LEN
        && blob.app().len() == EXPECTED_APP_LEN
        && blob.stored_crc() == EXPECTED_BLOB_CRC
        && package.app_crc() == EXPECTED_PACKAGE_APP_CRC
        && package.header_crc() == EXPECTED_PACKAGE_HEADER_CRC
        && package.len() == EXPECTED_PACKAGE_LEN
        && package.f0_chunk_count() == EXPECTED_F0_CHUNK_COUNT;

    if !exact_target {
        return Err(invalid_data(
            "firmware resource failed exact GM168SEC APP15045 bootstrap regression",
        )
        .into());
    }

    Ok(())
}

/// Execute the complete ownership-safe cold IAP -> APP bootstrap.
///
/// This is the first function that assembles all already-proven internal
/// primitives into the actual live transition, but it remains unreachable
/// from CLI argument parsing.
///
/// Exact high-level sequence:
///
/// ```text
/// old 27c6:550a device
/// -> GoodixTransport(old, trace clone)
/// -> begin_cold_bootstrap()
///      IAP version
///      E4 PSK verify
///      F0 x N
///      F4 non-zero
///      A2 02 32 ACK
/// -> old transport destroyed
/// -> old USB device explicitly dropped
/// -> wait absent -> present, <= 10 s
/// -> reopen / claim new 27c6:550a
/// -> GoodixTransport(new, SAME trace session)
/// -> finish_cold_bootstrap()
///      APP version
///      A2 05 14
///      10 ms
///      chip ID 0x002503a8
/// -> return fresh APP device + continuous trace
/// ```
///
/// No proprietary host driver or Goodix shared object participates in this
/// function.
#[allow(dead_code)]
pub(crate) fn cold_bootstrap(
    old_device: GoodixDevice,
    trace: TraceLogger,
    firmware_blob: &[u8],
    timeouts: BootstrapTimeouts,
) -> Result<ColdBootstrapSession, Box<dyn Error>> {
    validate_cold_bootstrap_firmware(firmware_blob)?;
    trace.event("cold bootstrap: exact APP firmware preflight passed")?;
    trace.event("cold bootstrap: begin on IAP device")?;

    let trace_for_begin = trace.clone();
    let trace_for_wait = trace.clone();
    let trace_for_finish = trace.clone();

    /*
     * Keep the original TraceLogger outside the ownership orchestration.
     * The transports receive clones that share the same already-open writer
     * and start timestamp.
     */
    let (result, new_device) = orchestrate_reenumeration(
        old_device,
        |device| {
            let mut transport = GoodixTransport::new(device, trace_for_begin.clone());

            let pending = begin_cold_bootstrap(&mut transport, firmware_blob, timeouts)?;

            trace_for_begin.event("cold bootstrap: F4 accepted; McuResetMcu ACK received")?;

            /*
             * `transport` is destroyed at callback return. The generic
             * orchestrator then explicitly drops `device` before it calls
             * the wait closure.
             */
            Ok::<_, Box<dyn Error>>(pending)
        },
        || {
            trace_for_wait
                .event("cold bootstrap: old USB handle dropped; waiting for detach -> attach")?;

            let device = wait_for_reenumerated_device()?;

            trace_for_wait.event("cold bootstrap: 27c6:550a reattached, reopened and claimed")?;

            Ok::<_, Box<dyn Error>>(device)
        },
        |pending, device| {
            let mut transport = GoodixTransport::new(device, trace_for_finish.clone());

            let result = finish_cold_bootstrap(pending, &mut transport, timeouts)?;

            trace_for_finish.event("cold bootstrap: APP version and chip ID validation passed")?;

            Ok::<_, Box<dyn Error>>(result)
        },
    )?;

    Ok(ColdBootstrapSession {
        result,
        device: new_device,
        trace,
    })
}

/// Orchestrate the ownership boundary around a reset-induced USB
/// detach -> attach transition.
///
/// This helper is intentionally generic and performs no USB I/O itself.
/// The generic shape makes the most important lifetime rule testable without
/// hardware:
///
/// ```text
/// old device
///   -> begin(&old_device)
///      (a borrowed transport may exist only inside this callback)
///   -> begin returns Pending
///   -> DROP old device
///   -> wait_for_new_device()
///   -> finish(Pending, &new_device)
///   -> return (result, new_device)
/// ```
///
/// The old device is therefore guaranteed to be dropped before the
/// re-enumeration wait begins. A transport borrowing that device cannot
/// escape the `begin` callback because only `Pending` is returned.
///
/// The reopened device is returned alongside the final result so normal APP
/// initialization can continue on that exact fresh device instance.
#[allow(dead_code)]
pub(crate) fn orchestrate_reenumeration<
    OldDevice,
    Pending,
    NewDevice,
    Output,
    E,
    Begin,
    Wait,
    Finish,
>(
    old_device: OldDevice,
    begin: Begin,
    wait_for_new_device: Wait,
    finish: Finish,
) -> Result<(Output, NewDevice), E>
where
    Begin: FnOnce(&OldDevice) -> Result<Pending, E>,
    Wait: FnOnce() -> Result<NewDevice, E>,
    Finish: FnOnce(Pending, &NewDevice) -> Result<Output, E>,
{
    let pending = begin(&old_device)?;

    /*
     * This explicit drop is the central ownership guarantee.
     *
     * For the live Goodix path the begin callback creates a
     * GoodixTransport<'_> borrowing old_device. That transport is destroyed
     * when the callback returns. Only then do we drop old_device itself.
     */
    drop(old_device);

    let new_device = wait_for_new_device()?;
    let output = finish(pending, &new_device)?;

    Ok((output, new_device))
}

/// Execute the pre-detach half of the proven 550a cold bootstrap.
///
/// This is intentionally NOT exposed by any CLI action.
///
/// Sequence:
///
/// ```text
/// require MILAN_GM168SEC_IAP_10007
/// -> E4 read sealed PSK 0xbb010002
/// -> authenticate + unseal
/// -> E4 read SHA-256 object 0xbb020001
/// -> verify plaintext PSK hash
/// -> parse + CRC-check local APP firmware blob
/// -> require metadata GFUSB_GM168SEC_APP_15045
/// -> build exact WriteApp package
/// -> derive F4 = HMAC chain from live PSK + exact package
/// -> 98 x F0 for the known APP image
/// -> F4, require one non-zero result byte
/// -> A2 02 32, require matching B0 ACK
/// -> return PendingColdBootstrap
/// ```
///
/// IMPORTANT OWNERSHIP BOUNDARY:
///
/// After this function returns successfully, the caller must immediately
/// drop the old `GoodixTransport` and old `GoodixDevice` before calling
/// `wait_for_reenumerated_device()`.
#[allow(dead_code)]
pub(crate) fn begin_cold_bootstrap<D: GoodixUsbIo + ?Sized>(
    transport: &mut GoodixTransport<'_, D>,
    firmware_blob: &[u8],
    timeouts: BootstrapTimeouts,
) -> Result<PendingColdBootstrap, Box<dyn Error>> {
    let current_version = transport.get_version(timeouts.version)?;

    if current_version != EXPECTED_IAP_VERSION {
        return Err(invalid_data(format!(
            "cold bootstrap requires IAP {EXPECTED_IAP_VERSION}, \
             device reported {current_version}"
        ))
        .into());
    }

    /*
     * PresetPskIsVaildG:
     *
     *   read bb010002
     *   -> GfUnsealData
     *   -> SHA256(plaintext PSK)
     *   -> compare bb020001
     *
     * This path only reads persisted objects. It does not provision or write
     * a PSK.
     */
    let sealed_psk = transport.read_sealed_psk(timeouts.psk_read)?;
    let psk = unseal_psk(&sealed_psk)?;

    let stored_psk_hash = transport.read_psk_hash(timeouts.psk_read)?;

    if !verify_psk_hash(&psk, &stored_psk_hash) {
        return Err(invalid_data("persisted Goodix PSK failed SHA-256 verification").into());
    }

    /*
     * Parse the exact local resource before any firmware command is sent.
     * FirmwareBlob::parse validates the resource's outer CRC.
     */
    let blob = FirmwareBlob::parse(firmware_blob)?;
    let expected_app_version = firmware_metadata_version(&blob)?;

    if expected_app_version != EXPECTED_APP_VERSION {
        return Err(invalid_data(format!(
            "firmware resource metadata mismatch: expected \
             {EXPECTED_APP_VERSION}, found {expected_app_version}"
        ))
        .into());
    }

    let package = AppTransferPackage::build(&blob)?;

    /*
     * Recovered WriteApp authentication:
     *
     *   GetPmkHmac(runtime PSK)
     *   -> HMAC-SHA256(full transfer package)
     *
     * firmware_f4_tag() implements that complete chain.
     */
    let f4_tag = firmware_f4_tag(&psk, package.bytes());

    /*
     * This is the first persistent firmware-write operation in the state
     * machine. The lower layer reproduces:
     *
     *   all F0 chunks
     *   -> F4
     *   -> reject result 0
     */
    let transfer = transport.write_app_transfer(&package, &f4_tag, timeouts.f0, timeouts.f4)?;

    /*
     * WriteApp immediately follows successful F4 verification with
     * McuResetMcu. This is ACK-only because the USB instance disappears
     * instead of returning a normal A2 completion.
     */
    transport.reset_mcu(timeouts.reset_mcu_ack)?;

    Ok(PendingColdBootstrap {
        expected_app_version,
        f0_chunks_sent: transfer.f0_chunks_sent,
        firmware_check_result: transfer.firmware_check_result,
    })
}

/// Wait for the exact reset-induced 27c6:550a detach -> attach transition,
/// then reopen and claim the fresh USB instance.
///
/// Call this only AFTER dropping both the pre-reset transport and device.
///
/// The 10-second deadline is the exact upper bound recovered from Geneva
/// WriteApp's hotplug-event wait.
#[allow(dead_code)]
pub(crate) fn wait_for_reenumerated_device() -> Result<GoodixDevice, ReenumerationError> {
    GoodixDevice::wait_for_reenumeration(REENUMERATION_TIMEOUT)
}

/// Consume a successful pre-detach bootstrap token on a transport bound to
/// the freshly re-enumerated device.
///
/// This deliberately performs a stronger post-write check than merely
/// observing USB reappearance:
///
/// ```text
/// GetVersion
/// -> require GFUSB_GM168SEC_APP_15045
/// -> A2 05 14  (McuResetFingerPrint)
/// -> sleep 10 ms
/// -> 82 addr=0 len=4  (McuGetChipId)
/// -> require 0x002503a8
/// ```
///
/// The A2/reset-fingerprint + chip-ID sequence is the normal loader
/// initialization path after UpdateFirmware succeeds.
#[allow(dead_code)]
pub(crate) fn finish_cold_bootstrap<D: GoodixUsbIo + ?Sized>(
    pending: PendingColdBootstrap,
    transport: &mut GoodixTransport<'_, D>,
    timeouts: BootstrapTimeouts,
) -> Result<ColdBootstrapResult, Box<dyn Error>> {
    let app_version = transport.get_version(timeouts.version)?;

    if app_version != pending.expected_app_version {
        return Err(invalid_data(format!(
            "post-bootstrap APP version mismatch: expected {}, found {}",
            pending.expected_app_version, app_version
        ))
        .into());
    }

    let chip_id =
        transport.validate_post_reenumeration(timeouts.reset_fingerprint, timeouts.chip_id)?;

    Ok(ColdBootstrapResult {
        app_version,
        chip_id,
        f0_chunks_sent: pending.f0_chunks_sent,
        firmware_check_result: pending.firmware_check_result,
    })
}

/// Extract the exact APP-version string from the firmware resource metadata.
///
/// The known GM168SEC blob stores:
///
/// ```text
/// blob[0] = 24
/// metadata = "GFUSB_GM168SEC_APP_15045"
/// ```
///
/// Accept a trailing NUL defensively because the binary-side resource APIs
/// often deal with C strings, but do not otherwise normalize the metadata.
fn firmware_metadata_version(blob: &FirmwareBlob<'_>) -> Result<String, Box<dyn Error>> {
    let metadata = str::from_utf8(blob.metadata())?;
    Ok(metadata.trim_end_matches('\0').to_owned())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firmware::crc32_mpeg2;
    use std::{cell::Cell, rc::Rc};

    fn synthetic_blob(metadata: &[u8], app: &[u8]) -> Vec<u8> {
        assert!(metadata.len() <= u8::MAX as usize);

        let mut blob = Vec::new();
        blob.push(metadata.len() as u8);
        blob.extend_from_slice(metadata);
        blob.extend_from_slice(app);

        let crc = crc32_mpeg2(&blob);
        blob.extend_from_slice(&crc.to_le_bytes());
        blob
    }

    #[test]
    fn target_versions_are_exact() {
        assert_eq!(EXPECTED_IAP_VERSION, "MILAN_GM168SEC_IAP_10007");
        assert_eq!(EXPECTED_APP_VERSION, "GFUSB_GM168SEC_APP_15045");
    }

    #[test]
    fn vendor_reenumeration_bound_is_ten_seconds() {
        assert_eq!(REENUMERATION_TIMEOUT, Duration::from_secs(10));
    }

    #[test]
    fn extracts_exact_app_version_from_metadata() {
        let raw = synthetic_blob(b"GFUSB_GM168SEC_APP_15045", &[0x11, 0x22, 0x33, 0x44]);

        let blob = FirmwareBlob::parse(&raw).unwrap();

        assert_eq!(
            firmware_metadata_version(&blob).unwrap(),
            EXPECTED_APP_VERSION
        );
    }

    #[test]
    fn accepts_only_trailing_nul_as_metadata_padding() {
        let raw = synthetic_blob(b"GFUSB_GM168SEC_APP_15045\0", &[0x11, 0x22, 0x33, 0x44]);

        let blob = FirmwareBlob::parse(&raw).unwrap();

        assert_eq!(
            firmware_metadata_version(&blob).unwrap(),
            EXPECTED_APP_VERSION
        );
    }

    #[test]
    fn exact_bootstrap_preflight_rejects_synthetic_same_version_blob() {
        let raw = synthetic_blob(b"GFUSB_GM168SEC_APP_15045", &[0x11, 0x22, 0x33, 0x44]);
        let error = validate_cold_bootstrap_firmware(&raw).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("exact GM168SEC APP15045 bootstrap regression")
        );
    }

    #[test]
    fn pending_token_fields_flow_into_final_result_shape() {
        let pending = PendingColdBootstrap {
            expected_app_version: EXPECTED_APP_VERSION.to_owned(),
            f0_chunks_sent: 98,
            firmware_check_result: 0x01,
        };

        assert_eq!(pending.expected_app_version, EXPECTED_APP_VERSION);
        assert_eq!(pending.f0_chunks_sent, 98);
        assert_ne!(pending.firmware_check_result, 0);
    }

    #[derive(Debug)]
    struct DropProbe {
        dropped: Rc<Cell<bool>>,
    }

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.dropped.set(true);
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct FreshDevice(u32);

    #[test]
    fn orchestration_drops_old_device_before_waiting_for_new_device() {
        let old_dropped = Rc::new(Cell::new(false));

        let old_device = DropProbe {
            dropped: Rc::clone(&old_dropped),
        };

        let (output, new_device) = orchestrate_reenumeration(
            old_device,
            |old| {
                assert!(!old.dropped.get());
                Ok::<_, &'static str>("pending")
            },
            || {
                /*
                 * This assertion proves the exact boundary we care about:
                 * wait/reopen cannot start while the old device remains
                 * owned by the orchestration layer.
                 */
                assert!(old_dropped.get());
                Ok::<_, &'static str>(FreshDevice(0x550a))
            },
            |pending, new_device| {
                assert_eq!(pending, "pending");
                assert_eq!(new_device, &FreshDevice(0x550a));
                Ok::<_, &'static str>("complete")
            },
        )
        .unwrap();

        assert_eq!(output, "complete");
        assert_eq!(new_device, FreshDevice(0x550a));
    }

    #[test]
    fn begin_failure_never_waits_or_finishes() {
        let old_dropped = Rc::new(Cell::new(false));
        let waited = Cell::new(false);
        let finished = Cell::new(false);

        let old_device = DropProbe {
            dropped: Rc::clone(&old_dropped),
        };

        let result = orchestrate_reenumeration(
            old_device,
            |_old| Err::<(), _>("begin failed"),
            || {
                waited.set(true);
                Ok::<_, &'static str>(FreshDevice(0x550a))
            },
            |_pending, _new_device| {
                finished.set(true);
                Ok::<_, &'static str>(())
            },
        );

        assert_eq!(result.unwrap_err(), "begin failed");
        assert!(old_dropped.get());
        assert!(!waited.get());
        assert!(!finished.get());
    }

    #[test]
    fn wait_failure_happens_after_old_device_drop_and_never_finishes() {
        let old_dropped = Rc::new(Cell::new(false));
        let finished = Cell::new(false);

        let old_device = DropProbe {
            dropped: Rc::clone(&old_dropped),
        };

        let result = orchestrate_reenumeration(
            old_device,
            |_old| Ok::<_, &'static str>("pending"),
            || {
                assert!(old_dropped.get());
                Err::<FreshDevice, _>("wait failed")
            },
            |_pending, _new_device| {
                finished.set(true);
                Ok::<_, &'static str>(())
            },
        );

        assert_eq!(result.unwrap_err(), "wait failed");
        assert!(old_dropped.get());
        assert!(!finished.get());
    }

    #[test]
    fn finish_failure_does_not_lose_phase_ordering() {
        let old_dropped = Rc::new(Cell::new(false));

        let old_device = DropProbe {
            dropped: Rc::clone(&old_dropped),
        };

        let result = orchestrate_reenumeration(
            old_device,
            |_old| Ok::<_, &'static str>("pending"),
            || {
                assert!(old_dropped.get());
                Ok::<_, &'static str>(FreshDevice(0x550a))
            },
            |pending, new_device| {
                assert_eq!(pending, "pending");
                assert_eq!(new_device, &FreshDevice(0x550a));
                Err::<(), _>("finish failed")
            },
        );

        assert_eq!(result.unwrap_err(), "finish failed");
        assert!(old_dropped.get());
    }

    #[test]
    fn orchestration_can_keep_state_outside_the_device_lifetime() {
        let old_dropped = Rc::new(Cell::new(false));
        let session_state = Rc::new(Cell::new(0u8));

        let old_device = DropProbe {
            dropped: Rc::clone(&old_dropped),
        };

        let state_for_begin = Rc::clone(&session_state);
        let state_for_wait = Rc::clone(&session_state);
        let state_for_finish = Rc::clone(&session_state);

        let (result, new_device) = orchestrate_reenumeration(
            old_device,
            |_old| {
                state_for_begin.set(1);
                Ok::<_, &'static str>("pending")
            },
            || {
                assert!(old_dropped.get());
                assert_eq!(state_for_wait.get(), 1);

                state_for_wait.set(2);

                Ok::<_, &'static str>(FreshDevice(0x550a))
            },
            |pending, new_device| {
                assert_eq!(pending, "pending");
                assert_eq!(new_device, &FreshDevice(0x550a));
                assert_eq!(state_for_finish.get(), 2);

                state_for_finish.set(3);

                Ok::<_, &'static str>("complete")
            },
        )
        .unwrap();

        assert_eq!(result, "complete");
        assert_eq!(new_device, FreshDevice(0x550a));
        assert_eq!(session_state.get(), 3);
    }
}
