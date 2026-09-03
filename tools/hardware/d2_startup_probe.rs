use std::{
    error::Error,
    fmt::Write as _,
    time::{Duration, Instant},
};

use getrandom::fill as getrandom_fill;
use rusb::{DeviceHandle, GlobalContext};

const VID: u16 = 0x27c6;
const PID: u16 = 0x550a;
const INTERFACE: u8 = 0;
const BULK_OUT: u8 = 0x01;
const BULK_IN: u8 = 0x83;
const USB_PACKET_SIZE: usize = 64;

fn main() -> Result<(), Box<dyn Error>> {
    goodix_info::app::require_unprivileged_hardware_access()?;

    println!("Goodix 27c6:550a D2 startup probe");
    println!("Safe diagnostic: A8 GetVersion + ephemeral D2 image-session install only.");
    println!();

    let handle = rusb::open_device_with_vid_pid(VID, PID).ok_or("Goodix 27c6:550a not found")?;

    prepare_handle(&handle)?;

    println!("Device opened and interface {INTERFACE} claimed.");
    println!();

    drain_stale_input(&handle)?;

    println!("=== A8 GetVersion ===");
    let a8 = encode_single(0xA8, &[0x00, 0x00])?;
    send_block(&handle, &a8)?;
    collect_for(&handle, Duration::from_millis(250))?;

    println!();
    println!("=== D2 ephemeral image-session install ===");

    let mut d2_payload = [0u8; 32];
    getrandom_fill(&mut d2_payload)?;

    println!("D2 payload: {}", hex(&d2_payload));

    let d2 = encode_single(0xD2, &d2_payload)?;
    send_block(&handle, &d2)?;
    collect_for(&handle, Duration::from_millis(500))?;

    println!();
    println!("Probe complete.");
    Ok(())
}

fn prepare_handle(handle: &DeviceHandle<GlobalContext>) -> Result<(), Box<dyn Error>> {
    match handle.set_auto_detach_kernel_driver(true) {
        Ok(()) | Err(rusb::Error::NotSupported) => {}
        Err(error) => return Err(error.into()),
    }

    handle.claim_interface(INTERFACE)?;
    Ok(())
}

fn drain_stale_input(handle: &DeviceHandle<GlobalContext>) -> Result<(), Box<dyn Error>> {
    println!("Draining stale IN packets...");

    let mut buffer = vec![0u8; 32768];
    let hard_deadline = Instant::now() + Duration::from_secs(1);
    let mut last_packet = Instant::now();

    loop {
        if Instant::now() >= hard_deadline {
            break;
        }

        if last_packet.elapsed() >= Duration::from_millis(100) {
            break;
        }

        match handle.read_bulk(BULK_IN, &mut buffer, Duration::from_millis(20)) {
            Ok(0) => {}
            Ok(length) => {
                println!("stale RX len={length} data={}", hex(&buffer[..length]));
                last_packet = Instant::now();
            }
            Err(rusb::Error::Timeout) => {}
            Err(error) => return Err(error.into()),
        }
    }

    println!("Drain complete.");
    println!();
    Ok(())
}

fn collect_for(
    handle: &DeviceHandle<GlobalContext>,
    duration: Duration,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + duration;
    let mut buffer = vec![0u8; 32768];
    let mut index = 0usize;

    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());

        // Never pass a sub-millisecond timeout to libusb: 0 ms means infinite.
        let timeout = remaining
            .min(Duration::from_millis(50))
            .max(Duration::from_millis(1));

        match handle.read_bulk(BULK_IN, &mut buffer, timeout) {
            Ok(0) => {}
            Ok(length) => {
                index += 1;
                let packet = &buffer[..length];
                println!("RX #{index}: len={length} data={}", hex(packet));
                describe(packet);
            }
            Err(rusb::Error::Timeout) => {}
            Err(error) => return Err(error.into()),
        }
    }

    if index == 0 {
        println!("No response packets.");
    }

    Ok(())
}

fn describe(packet: &[u8]) {
    if packet.len() < 7 || packet[0] != 0xA0 {
        println!("  decoded: unrecognized");
        return;
    }

    let command = packet[4];

    match command {
        0xB0 if packet.len() >= 10 => {
            println!(
                "  decoded: B0 for command=0x{:02x}, byte=0x{:02x}",
                packet[7], packet[8]
            );
        }
        0xA8 => {
            let encoded_len = u16::from_le_bytes([packet[5], packet[6]]) as usize;
            let payload_len = encoded_len.saturating_sub(1);
            let start = 7;
            let end = (start + payload_len).min(packet.len());
            let payload = &packet[start..end];
            let payload = payload.strip_suffix(&[0]).unwrap_or(payload);
            match std::str::from_utf8(payload) {
                Ok(v) => println!("  decoded: A8 version={v:?}"),
                Err(_) => println!("  decoded: A8 payload={}", hex(payload)),
            }
        }
        0xD2 => {
            println!(
                "  decoded: D2 completion payload={}",
                decode_payload_hex(packet)
            );
        }
        _ => {
            println!("  decoded: command=0x{command:02x}");
        }
    }
}

fn decode_payload_hex(packet: &[u8]) -> String {
    if packet.len() < 8 {
        return "<truncated>".into();
    }

    let encoded_len = u16::from_le_bytes([packet[5], packet[6]]) as usize;
    let payload_len = encoded_len.saturating_sub(1);
    let start = 7usize;
    let end = (start + payload_len).min(packet.len());
    hex(&packet[start..end])
}

fn encode_single(command: u8, payload: &[u8]) -> Result<[u8; 64], Box<dyn Error>> {
    let encoded_len = payload
        .len()
        .checked_add(1)
        .ok_or("payload length overflow")?;

    if encoded_len > u16::MAX as usize {
        return Err("payload too large".into());
    }

    let encoded_len_u16 = encoded_len as u16;
    let [len_lo, len_hi] = encoded_len_u16.to_le_bytes();

    let checksum_sum = command
        .wrapping_add(len_lo)
        .wrapping_add(len_hi)
        .wrapping_add(payload.iter().fold(0u8, |acc, &b| acc.wrapping_add(b)));

    let checksum = 0xAAu8.wrapping_sub(checksum_sum);

    let inner_len = 1 + 2 + payload.len() + 1;
    let [outer_lo, outer_hi] = (inner_len as u16).to_le_bytes();
    let outer_checksum = 0xA0u8.wrapping_add(outer_lo).wrapping_add(outer_hi);

    let logical_len = 4 + inner_len;
    if logical_len > USB_PACKET_SIZE {
        return Err(format!("logical packet is {logical_len} bytes, exceeds 64").into());
    }

    let mut out = [0u8; USB_PACKET_SIZE];
    out[0] = 0xA0;
    out[1] = outer_lo;
    out[2] = outer_hi;
    out[3] = outer_checksum;
    out[4] = command;
    out[5] = len_lo;
    out[6] = len_hi;
    out[7..7 + payload.len()].copy_from_slice(payload);
    out[7 + payload.len()] = checksum;

    Ok(out)
}

fn send_block(
    handle: &DeviceHandle<GlobalContext>,
    block: &[u8; 64],
) -> Result<(), Box<dyn Error>> {
    println!("TX: {}", hex(block));

    let actual = handle.write_bulk(BULK_OUT, block, Duration::from_secs(1))?;

    if actual != block.len() {
        return Err(format!("short write: expected {}, got {}", block.len(), actual).into());
    }

    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);

    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("formatting into String cannot fail");
    }

    output
}
