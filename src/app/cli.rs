use super::{
    error::{AppResult, invalid_data, invalid_input},
    require_unprivileged_hardware_access,
};
use crate::chicago_h;
use std::{
    env,
    error::Error,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use crate::bootstrap::{
    BootstrapTimeouts, EXPECTED_APP_VERSION, EXPECTED_IAP_VERSION, cold_bootstrap,
    validate_cold_bootstrap_firmware,
};
use crate::crypto::{ImageSession, decrypt_image};
use crate::device::GoodixDevice;
use crate::fdt::{FDT_DOWN_PAYLOAD, FDT_UP_PAYLOAD, GET_IMAGE_PAYLOAD};
use crate::firmware::{APP_FIRMWARE_TYPE, AppTransferPackage, FirmwareBlob};
use crate::firmware_auth::{
    EXPECTED_VENDOR_F4, firmware_f4_tag, get_pmk_hmac_from_psk, psk_sha256, unseal_psk,
    verify_psk_hash,
};
use crate::image::{
    IMAGE_HEIGHT, IMAGE_WIDTH, ProtectedImage, normalize_12bit_to_u8, restructure_gf3258_wn2,
};
use crate::preprocess::Gf3258Preprocessor;
use crate::protocol::{Command, McuPacket};
use crate::trace::TraceLogger;
use crate::transport::GoodixTransport;

const VERSION_TIMEOUT: Duration = Duration::from_secs(3);

/// Per-command timeout used by the GF3258 WN2 / ChicagoH volatile
/// cold-initialization sequence:
///
///     A6 GetOtp
///     -> validate/generate configuration locally
///     -> 0x90 DownloadConfig
///
/// `chicago_h::initialize()` applies this timeout independently to A6 and
/// 0x90. It performs no firmware or persistent-state writes.
const CHICAGO_H_INIT_TIMEOUT: Duration = Duration::from_secs(3);

const IMAGE_SESSION_TIMEOUT: Duration = Duration::from_secs(3);

const FDT_TIMEOUT: Duration = Duration::from_secs(30);

const IMAGE_TIMEOUT: Duration = Duration::from_secs(5);

const PSK_READ_TIMEOUT: Duration = Duration::from_secs(5);

const IMAGE_PREVIEW_LEN: usize = 32;

#[derive(Debug)]
enum Action {
    Info,

    Monitor,

    Capture {
        output: PathBuf,
    },

    /// Read and validate the persisted PSK using only E4 reads.
    Psk,

    /// Build the complete APP bootstrap transfer using the live PSK,
    /// but do not transmit F0/F4.
    BootstrapCheck {
        firmware: PathBuf,
    },

    /// Perform the real cold IAP -> APP transition.
    ///
    /// This is the ONLY CLI action permitted to transmit F0/F4.
    BootstrapLive {
        firmware: PathBuf,
    },

    Visualize {
        input: PathBuf,
        output: PathBuf,
    },
}

#[derive(Debug)]
struct Options {
    action: Action,
    trace_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FirmwareMode {
    App,
    Iap,
    Unknown,
}

struct RuntimePsk {
    sealed: Vec<u8>,
    plaintext: Vec<u8>,
    stored_hash: [u8; 32],
    calculated_hash: [u8; 32],
}

pub fn run() -> AppResult<()> {
    let options = parse_arguments()?;

    if let Action::Visualize { input, output } = &options.action {
        return run_visualize(input, output);
    }

    require_unprivileged_hardware_access()?;

    let device = open_device()?;

    if let Some(path) = options.trace_path.as_ref() {
        println!("Trace file: {}", path.display());

        println!();
    }

    let trace = TraceLogger::new(options.trace_path.as_deref())?;

    /*
     * Keep the original trace session owned by main. The transport gets a
     * clone that shares the same writer/start timestamp. bootstrap-live must
     * later destroy this transport and move the original trace across USB
     * re-enumeration.
     */
    let mut transport = GoodixTransport::new(&device, trace.clone());

    println!("Reading firmware version...");

    let (version, version_ack) = transport.get_version_with_ack(VERSION_TIMEOUT)?;

    println!("Firmware: {version}");
    println!("MCU volatile-state lost: {}", version_ack.mcu_power_lost);

    println!();

    let mode = firmware_mode(&version);

    match mode {
        FirmwareMode::App => {}

        FirmwareMode::Iap => {
            println!("Device is in IAP mode.");

            match &options.action {
                Action::Psk | Action::BootstrapCheck { .. } => {
                    println!(
                        "Continuing with read-only \
                         diagnostic."
                    );
                    println!();
                }

                Action::BootstrapLive { .. } => {
                    println!("Live cold bootstrap requested.");
                    println!(
                        "This action WILL transmit F0/F4 firmware data and \
                         reset the MCU."
                    );
                    println!();
                }

                _ => {
                    println!(
                        "No firmware upload or reset \
                         will be attempted."
                    );

                    return Ok(());
                }
            }
        }

        FirmwareMode::Unknown => {
            return Err(invalid_data(format!(
                "unrecognized firmware \
                         version: {version}"
            ))
            .into());
        }
    }

    match options.action {
        Action::Info => {
            println!("Firmware mode: {}", firmware_mode_name(mode));
        }

        Action::Monitor => {
            run_monitor(&mut transport, version_ack.mcu_power_lost)?;
        }

        Action::Capture { output } => {
            run_capture(&mut transport, &output, version_ack.mcu_power_lost)?;
        }

        Action::Psk => {
            run_psk_diagnostic(&mut transport, mode)?;
        }

        Action::BootstrapCheck { firmware } => {
            run_bootstrap_check(&mut transport, mode, &version, &firmware)?;
        }

        Action::BootstrapLive { firmware } => {
            /*
             * GoodixTransport borrows `device`. Destroy that borrow before
             * moving ownership of the old USB device into cold_bootstrap().
             */
            drop(transport);

            run_bootstrap_live(device, trace, mode, &version, &firmware)?;
        }

        Action::Visualize { .. } => {
            unreachable!(
                "visualize is handled before \
                 opening the USB device"
            );
        }
    }

    Ok(())
}

fn open_device() -> Result<GoodixDevice, Box<dyn Error>> {
    println!("Opening Goodix 27c6:550a...");

    println!();

    let device = GoodixDevice::open()?;

    let layout = device.layout();

    println!("Device opened and interface claimed.");

    println!("Interface: {}", layout.interface);

    println!("Bulk IN:   0x{:02x}", layout.bulk_in);

    println!("Bulk OUT:  0x{:02x}", layout.bulk_out);

    println!("Max packet size: {}", layout.max_packet_size);

    println!();

    Ok(device)
}

/// Read, authenticate and verify the persisted runtime PSK.
///
/// Device operations performed:
///
///     E4 read 0xbb010002
///     E4 read 0xbb020001
///
/// No persistent state is modified.
fn read_verified_runtime_psk(
    transport: &mut GoodixTransport<'_>,
) -> Result<RuntimePsk, Box<dyn Error>> {
    let sealed = transport.read_sealed_psk(PSK_READ_TIMEOUT)?;

    let plaintext = unseal_psk(&sealed)?;

    let stored_hash = transport.read_psk_hash(PSK_READ_TIMEOUT)?;

    let calculated_hash = psk_sha256(&plaintext);

    if !verify_psk_hash(&plaintext, &stored_hash) {
        return Err(invalid_data(
            "persisted PSK failed \
                 SHA-256 verification",
        )
        .into());
    }

    Ok(RuntimePsk {
        sealed,
        plaintext,
        stored_hash,
        calculated_hash,
    })
}

/// Real proprietary-driver-free cold IAP -> APP bootstrap.
///
/// This is intentionally strict. Before any F0 transmission it requires:
///
/// - exact current IAP version;
/// - exact local APP resource metadata;
/// - exact known APP/package size and CRC regression.
///
/// `cold_bootstrap()` then independently revalidates the firmware resource,
/// reads/authenticates the live persisted PSK, derives F4, performs F0/F4,
/// resets the MCU, requires detach -> attach, reopens the device and validates
/// APP version + chip ID.
fn run_bootstrap_live(
    device: GoodixDevice,
    trace: TraceLogger,
    mode: FirmwareMode,
    device_version: &str,
    firmware_path: &Path,
) -> Result<(), Box<dyn Error>> {
    println!("LIVE COLD BOOTSTRAP");
    println!("Device mode: {}", firmware_mode_name(mode));
    println!("Device firmware: {device_version}");
    println!("Firmware file: {}", firmware_path.display());
    println!();

    if mode != FirmwareMode::Iap {
        return Err(invalid_data(
            "bootstrap-live is permitted only while the device is in IAP mode",
        )
        .into());
    }

    if device_version != EXPECTED_IAP_VERSION {
        return Err(invalid_data(format!(
            "bootstrap-live requires exact IAP {EXPECTED_IAP_VERSION}, \
             device reported {device_version}"
        ))
        .into());
    }

    /*
     * Hard preflight the exact recovered APP resource before the first
     * persistent firmware command is possible.
     */
    println!("Preflighting firmware resource...");

    let raw = fs::read(firmware_path)?;
    validate_cold_bootstrap_firmware(&raw)?;

    let blob = FirmwareBlob::parse(&raw)?;
    let package = AppTransferPackage::build(&blob)?;

    println!("Firmware preflight: PASS");
    println!("APP: {EXPECTED_APP_VERSION}");
    println!("APP bytes: 0x{:x}", blob.app().len());
    println!("Package bytes: 0x{:x}", package.len());
    println!("F0 chunks: {}", package.f0_chunk_count());
    println!();

    println!("Starting real IAP -> APP transition...");
    println!("From this point F0/F4 firmware data may be transmitted.");
    println!();

    let session = cold_bootstrap(device, trace, &raw, live_bootstrap_timeouts())?;

    println!();
    println!("COLD BOOTSTRAP: PASS");
    println!("APP firmware: {}", session.result.app_version);
    println!("Chip ID:      0x{:08x}", session.result.chip_id);
    println!("F0 chunks:    {}", session.result.f0_chunks_sent);
    println!(
        "F4 result:    0x{:02x}",
        session.result.firmware_check_result
    );
    println!();
    println!(
        "The re-enumerated APP device remains open and claimed by the \
         standalone Rust process."
    );
    println!(
        "No proprietary Goodix host driver or shared object was used by \
         this bootstrap path."
    );

    /*
     * Keep the successfully reopened objects alive through the end of this
     * function. Future APP initialization will consume this session directly.
     */
    let _device = session.device;
    let _trace = session.trace;

    Ok(())
}

/// Local command timeout policy for the first controlled live bootstrap.
///
/// Only the 10-second detach -> attach bound inside bootstrap.rs is claimed
/// to be vendor-exact. These command-level values are conservative host-side
/// policy until their exact vendor timeout constants are recovered.
fn live_bootstrap_timeouts() -> BootstrapTimeouts {
    BootstrapTimeouts {
        version: VERSION_TIMEOUT,
        psk_read: PSK_READ_TIMEOUT,
        f0: Duration::from_secs(5),
        f4: Duration::from_secs(5),
        reset_mcu_ack: Duration::from_secs(3),
        reset_fingerprint: Duration::from_secs(3),
        chip_id: Duration::from_secs(3),
    }
}

/// Live bootstrap dry-run.
///
/// Device side:
///
///     E4 read sealed PSK
///     E4 read PSK hash
///
/// Local/offline side:
///
///     parse firmware blob
///     build WriteApp package
///     construct all F0 payloads
///     derive GetPmkHmac
///     calculate F4
///
/// Deliberately NOT performed:
///
///     E0
///     F0 transmission
///     F4 transmission
///     erase
///     reset
///     firmware update
fn run_bootstrap_check(
    transport: &mut GoodixTransport<'_>,
    mode: FirmwareMode,
    device_version: &str,
    firmware_path: &Path,
) -> Result<(), Box<dyn Error>> {
    println!("Live bootstrap dry-run");

    println!("Device mode: {}", firmware_mode_name(mode));

    println!("Device firmware: {device_version}");

    println!("Firmware file: {}", firmware_path.display());

    println!("Device operations: read-only E4");

    println!();

    /*
     * ------------------------------------------------------------
     * Local firmware resource
     * ------------------------------------------------------------
     */

    println!("Reading firmware blob...");

    let raw = fs::read(firmware_path)?;

    println!("Blob size: {} / 0x{:x}", raw.len(), raw.len());

    let blob = FirmwareBlob::parse(&raw)?;

    println!("Firmware blob CRC valid.");

    match std::str::from_utf8(blob.metadata()) {
        Ok(metadata) => {
            println!("Firmware metadata: {metadata}");
        }

        Err(_) => {
            println!("Firmware metadata: {:02x?}", blob.metadata());
        }
    }

    println!("APP size: {} / 0x{:x}", blob.app().len(), blob.app().len());

    println!("Outer CRC: 0x{:08x}", blob.stored_crc());

    println!();

    /*
     * ------------------------------------------------------------
     * Live persisted PSK
     * ------------------------------------------------------------
     */

    println!("Reading live persisted PSK...");

    let runtime_psk = read_verified_runtime_psk(transport)?;

    println!("Sealed PSK object: {} bytes", runtime_psk.sealed.len());

    println!("Recovered PSK: {} bytes", runtime_psk.plaintext.len());

    println!(
        "Stored SHA-256:     {}",
        encode_hex(&runtime_psk.stored_hash)
    );

    println!(
        "Calculated SHA-256: {}",
        encode_hex(&runtime_psk.calculated_hash)
    );

    println!("Live PSK verified: true");

    println!();

    /*
     * ------------------------------------------------------------
     * WriteApp package
     * ------------------------------------------------------------
     */

    println!("Building WriteApp package...");

    let package = AppTransferPackage::build(&blob)?;

    println!("APP length:      0x{:x}", package.app_len());

    println!("APP CRC:         0x{:08x}", package.app_crc());

    println!("Header CRC:      0x{:08x}", package.header_crc());

    println!("Package length:  0x{:x}", package.len());

    println!("Package header:  {}", encode_hex(&package.bytes()[..12]));

    println!();

    /*
     * ------------------------------------------------------------
     * F0 construction
     * ------------------------------------------------------------
     *
     * The payloads are built in memory only.
     */

    let chunks: Vec<_> = package.chunks().collect();

    let f0_payloads: Vec<_> = package.f0_payloads().collect();

    println!("Constructing F0 transfer plan...");

    println!("Firmware type:   {}", APP_FIRMWARE_TYPE);

    println!("F0 chunks:       {}", chunks.len());

    println!("F0 payloads:     {}", f0_payloads.len());

    if let (Some(first), Some(first_payload)) = (chunks.first(), f0_payloads.first()) {
        println!("First offset:    0x{:08x}", first.offset());

        println!("First length:    0x{:x}", first.length());

        println!("First F0 header: {}", encode_hex(&first_payload[..12]));
    }

    if let (Some(last), Some(last_payload)) = (chunks.last(), f0_payloads.last()) {
        println!("Last offset:     0x{:08x}", last.offset());

        println!("Last length:     0x{:x}", last.length());

        println!("Last F0 header:  {}", encode_hex(&last_payload[..12]));
    }

    println!();

    /*
     * ------------------------------------------------------------
     * F4 authentication
     * ------------------------------------------------------------
     */

    println!("Calculating firmware authentication...");

    let pmk_hmac = get_pmk_hmac_from_psk(&runtime_psk.plaintext);

    let f4_tag = firmware_f4_tag(&runtime_psk.plaintext, package.bytes());

    println!("GetPmkHmac:      {}", encode_hex(&pmk_hmac));

    println!("Calculated F4:   {}", encode_hex(&f4_tag));

    println!("Captured F4:     {}", encode_hex(&EXPECTED_VENDOR_F4));

    let captured_f4_match = f4_tag == EXPECTED_VENDOR_F4;

    println!("Captured F4 match: {}", captured_f4_match);

    println!();

    /*
     * ------------------------------------------------------------
     * Known GM168SEC package regression
     * ------------------------------------------------------------
     */

    let package_regression = package.app_len() == 0x6100
        && package.app_crc() == 0x4d44_46c1
        && package.header_crc() == 0xa2b6_9ee2
        && package.len() == 0x610c
        && chunks.len() == 98
        && f0_payloads.len() == 98;

    println!("Package regression: {}", package_regression);

    /*
     * This exact F4 comparison is a regression against the captured
     * provisioning state.
     *
     * A legitimately re-provisioned device could contain a different
     * PSK and therefore produce a different F4 while still being
     * internally valid. The critical live validity test is the PSK
     * hash verification above.
     */
    println!("Captured authentication regression: {}", captured_f4_match);

    println!();

    if package_regression {
        println!("LIVE BOOTSTRAP DRY-RUN: PASS");
    } else {
        return Err(invalid_data(
            "live bootstrap package \
                 regression failed",
        )
        .into());
    }

    println!();

    println!("No firmware data was transmitted.");

    println!(
        "No F0, F4, E0, erase, reset, or \
         provisioning command was sent."
    );

    Ok(())
}

/// Read and validate the persisted Goodix PSK without modifying the
/// fingerprint device.
fn run_psk_diagnostic(
    transport: &mut GoodixTransport<'_>,
    mode: FirmwareMode,
) -> Result<(), Box<dyn Error>> {
    println!("Persisted PSK diagnostic");

    println!("Mode: {}", firmware_mode_name(mode));

    println!("Operation: read-only E4");

    println!();

    println!(
        "Reading sealed PSK object \
         0xbb010002..."
    );

    let runtime_psk = read_verified_runtime_psk(transport)?;

    println!("Sealed PSK object: {} bytes", runtime_psk.sealed.len());

    println!("Sealed PSK: {}", encode_hex(&runtime_psk.sealed));

    println!();

    println!("Recovered PSK: {} bytes", runtime_psk.plaintext.len());

    println!("PSK: {}", encode_hex(&runtime_psk.plaintext));

    println!(
        "PSK all-zero: {}",
        runtime_psk.plaintext.iter().all(|&byte| byte == 0)
    );

    println!();

    println!(
        "Stored SHA-256:     {}",
        encode_hex(&runtime_psk.stored_hash)
    );

    println!(
        "Calculated SHA-256: {}",
        encode_hex(&runtime_psk.calculated_hash)
    );

    println!("PSK hash valid: true");

    println!();

    println!("Deriving GetPmkHmac...");

    let pmk_hmac = get_pmk_hmac_from_psk(&runtime_psk.plaintext);

    println!("GetPmkHmac: {}", encode_hex(&pmk_hmac));

    println!();

    println!("PSK diagnostic complete.");

    println!(
        "No persistent device state \
         was modified."
    );

    Ok(())
}

/// Ensure the GF3258 WN2 volatile sensor state is usable before any
/// operation that depends on FDT/image configuration.
///
/// The initial A8 ACK obtained in `main()` is the state probe:
///
/// - power_lost = true:
///   restore the ChicagoH volatile configuration using A6 -> 0x90;
/// - power_lost = false:
///   preserve the already-live state and do not resend A6/0x90.
///
/// Recovery policy stays here, above the transport. `GoodixTransport` only
/// reports the B0 state; `chicago_h` only knows how to perform the restore.
fn ensure_sensor_ready(
    transport: &mut GoodixTransport<'_>,
    mcu_power_lost: bool,
) -> Result<(), Box<dyn Error>> {
    if mcu_power_lost {
        println!("MCU reported volatile-state loss; restoring GF3258 WN2 configuration...");

        let chip_config = chicago_h::initialize(transport, CHICAGO_H_INIT_TIMEOUT)?;

        println!("ChicagoH initialization complete.");
        println!(
            "Calibration: T-code=0x{:04x}, diff=0x{:04x}, FDT offset={}",
            chip_config.calibration.tcode,
            chip_config.calibration.diff,
            chip_config.calibration.fdt_offset
        );
        println!("Config checksum: 0x{:04x}", chip_config.checksum);
    } else {
        println!("MCU volatile state is intact; skipping A6/0x90 configuration restore.");
    }

    println!();

    Ok(())
}

fn run_monitor(
    transport: &mut GoodixTransport<'_>,
    mcu_power_lost: bool,
) -> Result<(), Box<dyn Error>> {
    println!("FDT monitor");

    println!();

    ensure_sensor_ready(transport, mcu_power_lost)?;

    loop {
        let down = wait_for_finger_down(transport)?;

        print_fdt_event("FINGER DOWN", &down);

        let up = wait_for_finger_up(transport)?;

        print_fdt_event("FINGER UP", &up);
    }
}

fn run_capture(
    transport: &mut GoodixTransport<'_>,
    output_path: &Path,
    mcu_power_lost: bool,
) -> Result<(), Box<dyn Error>> {
    println!("Fingerprint image capture");

    println!("Output: {}", output_path.display());

    println!();

    /*
     * ------------------------------------------------------------
     * GF3258 WN2 / ChicagoH volatile cold initialization
     * ------------------------------------------------------------
     *
     * A true MCU power loss clears the sensor's volatile chip
     * configuration. The vendor recovery path is:
     *
     *     A6 GetOtp
     *       -> validate ChicagoH CP / FT / MT CRCs
     *       -> derive OTP calibration
     *       -> generate exact 0x100-byte chip configuration
     *       -> 0x90 DownloadConfig
     *       -> require completion [01 00]
     *
     * Our live cold-start experiment proved that FDT does not produce
     * finger events before this configuration is restored, and that it
     * works normally immediately afterward.
     *
     * The initial A8 B0 ACK now determines whether recovery is needed.
     * If bit 0x02 is set, run the recovered ChicagoH restore exactly once
     * before D2. If it is clear, preserve the already-live volatile state
     * and skip A6/0x90 entirely.
     */
    ensure_sensor_ready(transport, mcu_power_lost)?;

    /*
     * The host generates 32 random bytes and installs them
     * using command D2.
     *
     * The second 16 bytes become the AES-128 image key.
     */
    println!("Initializing image session...");

    let session = ImageSession::generate()?;

    let d2_response = transport.install_image_session(&session, IMAGE_SESSION_TIMEOUT)?;

    println!("Image session installed.");

    println!("D2 response payload: {}", encode_hex(&d2_response.payload));

    println!();

    let down = wait_for_finger_down(transport)?;

    print_fdt_event("FINGER DOWN", &down);

    println!("Requesting image...");

    let image_packet = transport.transact(Command::GetImage, &GET_IMAGE_PAYLOAD, IMAGE_TIMEOUT)?;

    println!(
        "Protected image payload: {} bytes",
        image_packet.payload.len()
    );

    let preview_len = image_packet.payload.len().min(IMAGE_PREVIEW_LEN);

    println!(
        "Payload prefix: {}",
        encode_hex(&image_packet.payload[..preview_len],)
    );

    let protected = ProtectedImage::parse(&image_packet.payload)?;

    println!("Image header: {}", encode_hex(protected.header()));

    println!("Encrypted image: {} bytes", protected.ciphertext().len());

    println!("Image CRC bytes: {}", encode_hex(protected.crc()));

    println!("Stored image CRC: 0x{:08x}", protected.stored_crc());

    if protected.is_boot_image() {
        return Err(invalid_data(
            "received boot image instead \
                 of normal fingerprint image",
        )
        .into());
    }

    println!();

    println!("Decrypting image...");

    let image_key = session.image_key();

    let decrypted = decrypt_image(protected.ciphertext(), &image_key)?;

    println!("Decrypted image: {} bytes", decrypted.len());

    println!("Validating image CRC...");

    protected.validate_crc(&decrypted)?;

    println!("Image CRC valid: 0x{:08x}", protected.stored_crc());

    println!();

    println!("Restructuring GF3258 WN2 image...");

    let pixels_12bit = restructure_gf3258_wn2(&decrypted)?;

    let minimum = pixels_12bit.iter().copied().min().unwrap_or(0);

    let maximum = pixels_12bit.iter().copied().max().unwrap_or(0);

    println!("Reconstructed image: {}x{}", IMAGE_WIDTH, IMAGE_HEIGHT);

    println!("Pixels: {}", pixels_12bit.len());

    println!("12-bit range: {minimum}..{maximum}");

    println!();
    println!("Preprocessing GF3258 WN2 frame...");

    let mut preprocessor = Gf3258Preprocessor::default();
    let algorithm_image = preprocessor.process(&pixels_12bit)?;

    println!(
        "Raw validation: {}/{} central pixels valid",
        algorithm_image.valid_central_pixels(),
        algorithm_image.tested_central_pixels(),
    );
    println!("Mask threshold: {}", algorithm_image.mask_threshold());
    println!(
        "Foreground: {} / {} ({}%)",
        algorithm_image.foreground_count(),
        IMAGE_WIDTH * IMAGE_HEIGHT,
        algorithm_image.coverage_percent(),
    );
    println!(
        "Gain correction: {} ({} pixels with difference > 100)",
        if algorithm_image.gain_correction_active() {
            "active"
        } else {
            "inactive"
        },
        algorithm_image.active_difference_count(),
    );
    println!(
        "Low dynamic range (<50): {} foreground pixels",
        algorithm_image.low_dynamic_range_count(),
    );

    if algorithm_image.pathological_edge_samples() != 0 {
        println!(
            "WARNING: {} top/bottom-edge samples are 0/4095 after clamping; \
             the vendor GF3258 pathological-edge repair rule is not yet reproduced, \
             so this frame is not eligible for a bit-exact parity claim.",
            algorithm_image.pathological_edge_samples(),
        );
    }

    write_pgm(output_path, algorithm_image.pixels())?;

    println!();

    println!(
        "Saved GF3258 algorithm-ready fingerprint: {}",
        output_path.display()
    );

    println!();

    let up = wait_for_finger_up(transport)?;

    print_fdt_event("FINGER UP", &up);

    println!("Capture complete.");

    Ok(())
}

fn run_visualize(input_path: &Path, output_path: &Path) -> Result<(), Box<dyn Error>> {
    println!("GF3258 WN2 image visualization");

    println!("Input:  {}", input_path.display());

    println!("Output: {}", output_path.display());

    println!();

    let decrypted = fs::read(input_path)?;

    println!("Decrypted input: {} bytes", decrypted.len());

    let pixels_12bit = restructure_gf3258_wn2(&decrypted)?;

    let minimum = pixels_12bit.iter().copied().min().unwrap_or(0);

    let maximum = pixels_12bit.iter().copied().max().unwrap_or(0);

    println!("Reconstructed image: {}x{}", IMAGE_WIDTH, IMAGE_HEIGHT);

    println!("Pixels: {}", pixels_12bit.len());

    println!("12-bit range: {minimum}..{maximum}");

    let pixels_8bit = normalize_12bit_to_u8(&pixels_12bit);

    write_pgm(output_path, &pixels_8bit)?;

    println!();

    println!("Saved grayscale image: {}", output_path.display());

    Ok(())
}

fn write_pgm(path: &Path, pixels: &[u8]) -> Result<(), Box<dyn Error>> {
    let expected = IMAGE_WIDTH * IMAGE_HEIGHT;

    if pixels.len() != expected {
        return Err(invalid_data(format!(
            "unexpected image pixel count: \
                     expected {expected}, received {}",
            pixels.len()
        ))
        .into());
    }

    let header = format!("P5\n{} {}\n255\n", IMAGE_WIDTH, IMAGE_HEIGHT);

    let mut pgm = Vec::with_capacity(header.len() + pixels.len());

    pgm.extend_from_slice(header.as_bytes());

    pgm.extend_from_slice(pixels);

    fs::write(path, pgm)?;

    Ok(())
}

fn wait_for_finger_down(transport: &mut GoodixTransport<'_>) -> Result<McuPacket, Box<dyn Error>> {
    println!("Waiting for finger...");

    Ok(transport.transact(Command::FdtDown, &FDT_DOWN_PAYLOAD, FDT_TIMEOUT)?)
}

fn wait_for_finger_up(transport: &mut GoodixTransport<'_>) -> Result<McuPacket, Box<dyn Error>> {
    println!("Waiting for finger removal...");

    Ok(transport.transact(Command::FdtUp, &FDT_UP_PAYLOAD, FDT_TIMEOUT)?)
}

fn print_fdt_event(name: &str, packet: &McuPacket) {
    println!("{name}");

    println!("FDT payload: {}", encode_hex(&packet.payload));

    println!();
}

fn firmware_mode(version: &str) -> FirmwareMode {
    if version.contains("_APP_") {
        FirmwareMode::App
    } else if version.contains("_IAP_") {
        FirmwareMode::Iap
    } else {
        FirmwareMode::Unknown
    }
}

fn firmware_mode_name(mode: FirmwareMode) -> &'static str {
    match mode {
        FirmwareMode::App => "APP",
        FirmwareMode::Iap => "IAP",
        FirmwareMode::Unknown => "UNKNOWN",
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);

    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect(
            "formatting into a String \
             cannot fail",
        );
    }

    output
}

fn parse_arguments() -> Result<Options, Box<dyn Error>> {
    let mut args = env::args().skip(1);

    let mut action = None;
    let mut trace_path = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "info" => {
                set_action(&mut action, Action::Info)?;
            }

            "monitor" => {
                set_action(&mut action, Action::Monitor)?;
            }

            "capture" => {
                let output = args.next().ok_or_else(|| {
                    invalid_input(
                        "capture requires an \
                                     output PGM filename",
                    )
                })?;

                set_action(
                    &mut action,
                    Action::Capture {
                        output: PathBuf::from(output),
                    },
                )?;
            }

            "psk" => {
                set_action(&mut action, Action::Psk)?;
            }

            "bootstrap-check" => {
                let firmware = args.next().ok_or_else(|| {
                    invalid_input(
                        "bootstrap-check requires \
                                     a firmware blob filename",
                    )
                })?;

                set_action(
                    &mut action,
                    Action::BootstrapCheck {
                        firmware: PathBuf::from(firmware),
                    },
                )?;
            }

            "bootstrap-live" => {
                let firmware = args.next().ok_or_else(|| {
                    invalid_input(
                        "bootstrap-live requires \
                                     a firmware blob filename",
                    )
                })?;

                set_action(
                    &mut action,
                    Action::BootstrapLive {
                        firmware: PathBuf::from(firmware),
                    },
                )?;
            }

            "visualize" => {
                let input = args.next().ok_or_else(|| {
                    invalid_input(
                        "visualize requires \
                                     a decrypted input filename",
                    )
                })?;

                let output = args.next().ok_or_else(|| {
                    invalid_input(
                        "visualize requires \
                                     an output PGM filename",
                    )
                })?;

                set_action(
                    &mut action,
                    Action::Visualize {
                        input: PathBuf::from(input),

                        output: PathBuf::from(output),
                    },
                )?;
            }

            "--trace" => {
                let path = args.next().ok_or_else(|| {
                    invalid_input(
                        "--trace requires \
                                     a filename",
                    )
                })?;

                if trace_path.is_some() {
                    return Err(invalid_input(
                        "--trace may only be \
                             specified once",
                    )
                    .into());
                }

                trace_path = Some(PathBuf::from(path));
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

    Ok(Options {
        action: action.unwrap_or(Action::Info),

        trace_path,
    })
}

fn set_action(slot: &mut Option<Action>, action: Action) -> Result<(), Box<dyn Error>> {
    if slot.is_some() {
        return Err(invalid_input(
            "only one command may \
                 be specified",
        )
        .into());
    }

    *slot = Some(action);

    Ok(())
}

fn print_usage() {
    println!(
        "\
Usage:
  goodix-info [info] [--trace FILE]
  goodix-info monitor [--trace FILE]
  goodix-info capture OUTPUT.pgm [--trace FILE]
  goodix-info psk [--trace FILE]
  goodix-info bootstrap-check FIRMWARE.bin [--trace FILE]
  goodix-info bootstrap-live FIRMWARE.bin [--trace FILE]
  goodix-info visualize DECRYPTED OUTPUT.pgm

Commands:
  info
      Show device and firmware information

  monitor
      Ensure GF3258 WN2 volatile sensor state is ready, then
      monitor finger-down and finger-up events

  capture OUTPUT.pgm
      Initialize a fresh D2 image session, capture one
      fingerprint, decrypt it, validate its CRC, restructure
      the GF3258 frame, run the recovered GF3258 preprocessing
      pipeline, and save the 80x64 algorithm-ready PGM

  psk
      Read object 0xbb010002 using E4, authenticate and
      unseal the persisted PSK, read object 0xbb020001,
      verify the PSK SHA-256, and derive GetPmkHmac.
      This command is read-only and may run in APP or IAP.

  bootstrap-check FIRMWARE.bin
      Read and verify the live persisted PSK, parse the local
      APP firmware, construct the WriteApp package and all F0
      payloads, and calculate the F4 authentication tag.
      F0/F4 are NOT transmitted.
      This command may run in APP or IAP.

  bootstrap-live FIRMWARE.bin
      Perform the real cold IAP -> APP bootstrap using the
      standalone Rust implementation. Requires exact IAP10007
      and exact APP15045 firmware. Transmits F0/F4, resets the
      MCU, waits for USB detach/attach, reopens the device, and
      validates APP15045 plus chip ID 0x002503a8.
      This is the only CLI command that transmits firmware.

  visualize DECRYPTED OUTPUT.pgm
      Restructure an already-decrypted GF3258 WN2 image
      and normalize it to 8-bit grayscale

Options:
  --trace FILE
      Record USB traffic to FILE

  -h, --help
      Show this help"
    );
}
