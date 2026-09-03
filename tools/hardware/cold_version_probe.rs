use std::{
    error::Error,
    fmt::Write as _,
    thread,
    time::{Duration, Instant},
};

use rusb::{DeviceHandle, GlobalContext};

const VID: u16 = 0x27c6;
const PID: u16 = 0x550a;
const INTERFACE: u8 = 0;
const BULK_OUT: u8 = 0x01;
const BULK_IN: u8 = 0x83;
const USB_PACKET_SIZE: usize = 64;

const GET_VERSION_FRAME: [u8; 10] = [0xA0, 0x06, 0x00, 0xA6, 0xA8, 0x03, 0x00, 0x00, 0x00, 0xFF];

fn main() -> Result<(), Box<dyn Error>> {
    goodix_info::app::require_unprivileged_hardware_access()?;

    println!("Goodix 27c6:550a cold GetVersion probe");
    println!("READ-ONLY diagnostic: only A8 GetVersion is transmitted.");
    println!();

    let handle = rusb::open_device_with_vid_pid(VID, PID).ok_or("Goodix 27c6:550a not found")?;

    prepare_handle(&handle)?;

    println!("Device opened and interface {INTERFACE} claimed.");
    println!();

    /*
     * Previous strict `info` attempts may have exited immediately after
     * seeing B0/A8/03, leaving the following A8 version response queued.
     *
     * Drain everything already pending BEFORE sending the one diagnostic
     * request. This prevents stale traffic from being mistaken for the new
     * request's response.
     */
    println!("Draining stale IN packets...");
    drain_stale_input(&handle)?;
    println!("Drain complete.");
    println!();

    let mut out = [0u8; USB_PACKET_SIZE];
    out[..GET_VERSION_FRAME.len()].copy_from_slice(&GET_VERSION_FRAME);

    println!("TX A8: {}", hex(&out));

    let written = handle.write_bulk(BULK_OUT, &out, Duration::from_secs(1))?;

    if written != USB_PACKET_SIZE {
        return Err(format!("short USB write: expected {USB_PACKET_SIZE}, wrote {written}").into());
    }

    println!();
    println!("Collecting all IN packets for 1 second...");
    println!();

    let deadline = Instant::now() + Duration::from_secs(1);
    let mut buffer = vec![0u8; 32768];
    let mut packet_index = 0usize;

    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let timeout = remaining.min(Duration::from_millis(100));

        match handle.read_bulk(BULK_IN, &mut buffer, timeout) {
            Ok(0) => {}
            Ok(length) => {
                packet_index += 1;
                let packet = &buffer[..length];

                println!("RX #{packet_index}: len={length} data={}", hex(packet));

                describe_packet(packet);
                println!();
            }
            Err(rusb::Error::Timeout) => {}
            Err(error) => {
                return Err(format!("USB read failed: {error}").into());
            }
        }
    }

    println!("Probe complete.");
    println!("Packets received after the single new A8 request: {packet_index}");

    if packet_index == 0 {
        println!("No response packets were received.");
    }

    Ok(())
}

fn prepare_handle(handle: &DeviceHandle<GlobalContext>) -> Result<(), Box<dyn Error>> {
    /*
     * Match the normal driver behavior without depending on the Goodix
     * userspace stack.
     */
    match handle.set_auto_detach_kernel_driver(true) {
        Ok(()) => {}
        Err(rusb::Error::NotSupported) => {}
        Err(error) => return Err(error.into()),
    }

    handle.claim_interface(INTERFACE)?;

    Ok(())
}

fn drain_stale_input(handle: &DeviceHandle<GlobalContext>) -> Result<(), Box<dyn Error>> {
    let mut buffer = vec![0u8; 32768];

    /*
     * Require a quiet interval of 100 ms. Every packet resets the quiet
     * interval, with a hard 1-second ceiling so this diagnostic cannot hang
     * on unsolicited traffic.
     */
    let hard_deadline = Instant::now() + Duration::from_secs(1);
    let mut quiet_since = Instant::now();

    loop {
        let now = Instant::now();

        if now >= hard_deadline {
            println!("Drain reached 1-second ceiling.");
            return Ok(());
        }

        if now.duration_since(quiet_since) >= Duration::from_millis(100) {
            return Ok(());
        }

        match handle.read_bulk(BULK_IN, &mut buffer, Duration::from_millis(20)) {
            Ok(0) => {}
            Ok(length) => {
                let packet = &buffer[..length];

                println!("  stale RX: len={length} data={}", hex(packet));

                describe_packet(packet);
                quiet_since = Instant::now();
            }
            Err(rusb::Error::Timeout) => {
                thread::yield_now();
            }
            Err(error) => {
                return Err(format!("USB read failed while draining stale input: {error}").into());
            }
        }
    }
}

fn describe_packet(packet: &[u8]) {
    if packet.len() < 7 || packet[0] != 0xA0 {
        println!("  decoded: not a complete recognizable A0 packet");
        return;
    }

    let inner_len = u16::from_le_bytes([packet[1], packet[2]]) as usize;

    println!("  decoded: outer inner-length={inner_len}");

    let command = packet[4];

    match command {
        0xB0 => {
            /*
             * Ordinary B0 packet:
             *   B0 03 00 <original command> <message byte> <trailer>
             */
            if packet.len() >= 10 {
                println!(
                    "  decoded: B0 message for command=0x{:02x}, byte=0x{:02x}",
                    packet[7], packet[8],
                );
            } else {
                println!("  decoded: truncated B0 message");
            }
        }

        0xA8 => {
            /*
             * A8 response:
             *   A8 <len> <NUL-terminated ASCII version> <checksum>
             */
            if packet.len() >= 8 {
                let encoded_len = u16::from_le_bytes([packet[5], packet[6]]) as usize;

                /*
                 * encoded_len includes the final trailer byte.
                 */
                let payload_len = encoded_len.saturating_sub(1);
                let payload_start = 7usize;
                let payload_end = payload_start.saturating_add(payload_len).min(packet.len());

                let payload = &packet[payload_start..payload_end];
                let payload = payload.strip_suffix(&[0]).unwrap_or(payload);

                match std::str::from_utf8(payload) {
                    Ok(version) => {
                        println!("  decoded: A8 version response = {version:?}");
                    }
                    Err(_) => {
                        println!("  decoded: A8 payload (non-UTF8) = {}", hex(payload));
                    }
                }
            }
        }

        other => {
            println!("  decoded: command=0x{other:02x}");
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);

    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("formatting into String cannot fail");
    }

    output
}
