use rusb::{Context, DeviceHandle, UsbContext};
use std::error::Error;
use std::io;
use std::time::Duration;

const VID: u16 = 0x27c6;
const PID: u16 = 0x550a;

const INTERFACE: u8 = 0;
const EP_OUT: u8 = 0x01;
const EP_IN: u8 = 0x83;

const TIMEOUT: Duration = Duration::from_secs(1);

const CMD_GET_OTP: u8 = 0xA6;
const CMD_ACK: u8 = 0xB0;

/// ChicagoH requests exactly 64 bytes of OTP data.
///
/// Wire packet:
///
///   A0 06 00 A6 A6 03 00 40 00 C1
///
/// Inner packet:
///
///   command       = A6
///   encoded_len   = 0003
///   payload       = 40 00
///   checksum      = C1
///
const GET_OTP_REQUEST: [u8; 10] = [0xA0, 0x06, 0x00, 0xA6, 0xA6, 0x03, 0x00, 0x40, 0x00, 0xC1];

fn invalid_data(message: impl Into<String>) -> Box<dyn Error> {
    io::Error::new(io::ErrorKind::InvalidData, message.into()).into()
}

fn write_packet(handle: &mut DeviceHandle<Context>, packet: &[u8]) -> Result<(), Box<dyn Error>> {
    if packet.len() > 64 {
        return Err(invalid_data(format!(
            "packet too large for current 64-byte write helper: {} bytes",
            packet.len()
        )));
    }

    let mut out = [0u8; 64];
    out[..packet.len()].copy_from_slice(packet);

    let written = handle.write_bulk(EP_OUT, &out, TIMEOUT)?;

    if written != out.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            format!("short USB write: {written}/{}", out.len()),
        )
        .into());
    }

    println!(
        "OUT (logical {} bytes, USB transfer {} bytes):",
        packet.len(),
        out.len()
    );
    print_hex(packet);

    Ok(())
}

fn read_packet(handle: &mut DeviceHandle<Context>) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut input = vec![0u8; 32768];

    let n = handle.read_bulk(EP_IN, &mut input, TIMEOUT)?;
    input.truncate(n);

    println!("IN ({n} bytes):");
    print_hex(&input);

    Ok(input)
}

fn print_hex(data: &[u8]) {
    for (row, chunk) in data.chunks(16).enumerate() {
        print!("{:04x}: ", row * 16);

        for byte in chunk {
            print!("{byte:02x} ");
        }

        println!();
    }
}

/// Validate the four-byte Goodix outer header.
///
/// Layout:
///
///   +0  A0
///   +1  inner length low
///   +2  inner length high
///   +3  A0 + length-low + length-high
///
/// Returns the inner packet length.
fn validate_outer(packet: &[u8]) -> Result<usize, Box<dyn Error>> {
    if packet.len() < 4 {
        return Err(invalid_data(format!(
            "packet too short for outer header: {} bytes",
            packet.len()
        )));
    }

    if packet[0] != 0xA0 {
        return Err(invalid_data(format!(
            "unexpected outer marker: 0x{:02x}",
            packet[0]
        )));
    }

    let inner_len = u16::from_le_bytes([packet[1], packet[2]]) as usize;

    let expected_outer_checksum = 0xA0u8.wrapping_add(packet[1]).wrapping_add(packet[2]);

    if packet[3] != expected_outer_checksum {
        return Err(invalid_data(format!(
            "bad outer checksum: got 0x{:02x}, expected 0x{:02x}",
            packet[3], expected_outer_checksum
        )));
    }

    let expected_total = 4 + inner_len;

    if packet.len() != expected_total {
        return Err(invalid_data(format!(
            "outer length mismatch: packet has {} bytes, header describes {}",
            packet.len(),
            expected_total
        )));
    }

    Ok(inner_len)
}

/// Goodix ordinary inner checksum.
///
/// checksum = 0xAA -
///            (command + len_lo + len_hi + sum(payload))
///
/// All arithmetic is modulo 256.
fn ordinary_checksum(command: u8, encoded_len: u16, payload: &[u8]) -> u8 {
    let [len_lo, len_hi] = encoded_len.to_le_bytes();

    let mut sum = command.wrapping_add(len_lo).wrapping_add(len_hi);

    for &byte in payload {
        sum = sum.wrapping_add(byte);
    }

    0xAAu8.wrapping_sub(sum)
}

/// Parse an ordinary Goodix inner packet.
///
/// Returns:
///
///   (command, payload)
fn parse_inner(packet: &[u8]) -> Result<(u8, &[u8]), Box<dyn Error>> {
    let inner_len = validate_outer(packet)?;

    if inner_len < 4 {
        return Err(invalid_data(format!("inner packet too short: {inner_len}")));
    }

    let command = packet[4];

    let encoded_len = u16::from_le_bytes([packet[5], packet[6]]);

    if encoded_len == 0 {
        return Err(invalid_data("encoded inner length cannot be zero"));
    }

    let expected_inner_len = 3 + encoded_len as usize;

    if inner_len != expected_inner_len {
        return Err(invalid_data(format!(
            "inner length mismatch: outer says {inner_len}, \
             encoded inner packet requires {expected_inner_len}"
        )));
    }

    // encoded_len = payload + one-byte trailer/checksum.
    let payload_len = encoded_len as usize - 1;

    let payload_start = 7;
    let payload_end = payload_start + payload_len;

    if payload_end >= packet.len() {
        return Err(invalid_data("inner payload extends beyond received packet"));
    }

    let payload = &packet[payload_start..payload_end];
    let trailer = packet[payload_end];

    let expected_trailer = ordinary_checksum(command, encoded_len, payload);

    if trailer != expected_trailer {
        return Err(invalid_data(format!(
            "bad inner checksum for command 0x{command:02x}: \
             got 0x{trailer:02x}, expected 0x{expected_trailer:02x}"
        )));
    }

    Ok((command, payload))
}

fn parse_a6_ack(packet: &[u8]) -> Result<u8, Box<dyn Error>> {
    let (command, payload) = parse_inner(packet)?;

    if command != CMD_ACK {
        return Err(invalid_data(format!(
            "expected B0 ACK packet, received command 0x{command:02x}"
        )));
    }

    if payload.len() != 2 {
        return Err(invalid_data(format!(
            "B0 ACK payload should contain exactly 2 bytes, got {}",
            payload.len()
        )));
    }

    let acknowledged_command = payload[0];
    let flags = payload[1];

    if acknowledged_command != CMD_GET_OTP {
        return Err(invalid_data(format!(
            "B0 ACK is for command 0x{acknowledged_command:02x}, \
             expected A6"
        )));
    }

    Ok(flags)
}

fn parse_a6_response(packet: &[u8]) -> Result<[u8; 64], Box<dyn Error>> {
    let (command, payload) = parse_inner(packet)?;

    if command != CMD_GET_OTP {
        return Err(invalid_data(format!(
            "expected A6 OTP response, received command 0x{command:02x}"
        )));
    }

    if payload.len() != 0x40 {
        return Err(invalid_data(format!(
            "expected exactly 64 OTP bytes, received {}",
            payload.len()
        )));
    }

    let mut otp = [0u8; 64];
    otp.copy_from_slice(payload);

    Ok(otp)
}

/// FUN_0010f950
///
/// Table recovered from DAT_00202780 corresponds to:
///
///   width   = 8
///   poly    = 0x07
///   init    = 0x00
///   refin   = false
///   refout  = false
///   xorout  = 0xFF
///
fn goodix_crc8(data: &[u8]) -> u8 {
    let mut crc = 0u8;

    for &byte in data {
        crc ^= byte;

        for _ in 0..8 {
            crc = if crc & 0x80 != 0 {
                (crc << 1) ^ 0x07
            } else {
                crc << 1
            };
        }
    }

    !crc
}

fn validate_chicago_h_otp(otp: &[u8; 64]) -> bool {
    //
    // CP checksum
    //
    // OTP:
    //   00..0A
    //   24..27
    //
    // stored checksum:
    //   3C
    //
    let mut cp = Vec::with_capacity(15);

    cp.extend_from_slice(&otp[0x00..0x0B]);
    cp.extend_from_slice(&otp[0x24..0x28]);

    assert_eq!(cp.len(), 15);

    let cp_calculated = goodix_crc8(&cp);
    let cp_stored = otp[0x3C];

    //
    // FT checksum
    //
    // OTP:
    //   0B..13
    //   1C
    //   32..35
    //   38..3B
    //   3E
    //
    // stored checksum:
    //   3D
    //
    let mut ft = Vec::with_capacity(19);

    ft.extend_from_slice(&otp[0x0B..0x14]);
    ft.push(otp[0x1C]);
    ft.extend_from_slice(&otp[0x32..0x36]);
    ft.extend_from_slice(&otp[0x38..0x3C]);
    ft.push(otp[0x3E]);

    assert_eq!(ft.len(), 19);

    let ft_calculated = goodix_crc8(&ft);
    let ft_stored = otp[0x3D];

    //
    // MT checksum
    //
    // OTP:
    //   14..1B
    //   1D..23
    //   28..31
    //   36..37
    //
    // stored checksum:
    //   3F
    //
    let mut mt = Vec::with_capacity(27);

    mt.extend_from_slice(&otp[0x14..0x1C]);
    mt.extend_from_slice(&otp[0x1D..0x24]);
    mt.extend_from_slice(&otp[0x28..0x32]);
    mt.extend_from_slice(&otp[0x36..0x38]);

    assert_eq!(mt.len(), 27);

    let mt_calculated = goodix_crc8(&mt);
    let mt_stored = otp[0x3F];

    println!();
    println!("--- ChicagoH OTP integrity ---");

    println!(
        "CP: calculated=0x{cp_calculated:02x} \
         stored=0x{cp_stored:02x}  {}",
        if cp_calculated == cp_stored {
            "PASS"
        } else {
            "FAIL"
        }
    );

    println!(
        "FT: calculated=0x{ft_calculated:02x} \
         stored=0x{ft_stored:02x}  {}",
        if ft_calculated == ft_stored {
            "PASS"
        } else {
            "FAIL"
        }
    );

    println!(
        "MT: calculated=0x{mt_calculated:02x} \
         stored=0x{mt_stored:02x}  {}",
        if mt_calculated == mt_stored {
            "PASS"
        } else {
            "FAIL"
        }
    );

    cp_calculated == cp_stored && ft_calculated == ft_stored && mt_calculated == mt_stored
}

/// Recovered _MilanFSerGetFdtOffsetFromOtp behavior.
///
/// OTP[0x1B] stores three redundant representations of the
/// same two-bit FDT-offset value.
fn decode_fdt_offset(encoded: u8) -> Option<u8> {
    let a = encoded & 0x03;
    let b = (!(encoded >> 2)) & 0x03;
    let c = (encoded >> 4) & 0x03;

    if a == c || a == b {
        Some(a)
    } else if b == c {
        Some(c)
    } else {
        None
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    goodix_info::app::require_unprivileged_hardware_access()?;

    //
    // Sanity-check our recovered CRC parameters before touching USB.
    //
    if goodix_crc8(b"123456789") != 0x0B {
        return Err(invalid_data("internal CRC-8 self-test failed"));
    }

    println!("Opening Goodix 27c6:550a...");

    let context = Context::new()?;

    let mut handle = context
        .open_device_with_vid_pid(VID, PID)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "27c6:550a not found"))?;

    if handle.kernel_driver_active(INTERFACE).unwrap_or(false) {
        println!("Detaching kernel driver from interface {INTERFACE}...");
        handle.detach_kernel_driver(INTERFACE)?;
    }

    handle.claim_interface(INTERFACE)?;

    println!("Interface {INTERFACE} claimed.");

    println!();
    println!("--- ChicagoHGetOtp ---");
    println!("Requesting 0x40 bytes with command A6...");

    write_packet(&mut handle, &GET_OTP_REQUEST)?;

    //
    // Vendor behavior:
    //
    //   IN B0 [A6, flags]
    //   IN A6 <64-byte OTP>
    //
    let ack_packet = read_packet(&mut handle)?;
    let flags = parse_a6_ack(&ack_packet)?;

    println!();
    println!("A6 ACK accepted.");
    println!("ACK flags: 0x{flags:02x}");

    let mcu_power_lost = flags & 0x02 != 0;

    println!("MCU power-lost flag: {mcu_power_lost}");

    //
    // A power-loss indication is NOT an ACK failure.
    //
    // We intentionally do not perform recovery here because this
    // diagnostic exists only to read and validate OTP.
    //
    let response_packet = read_packet(&mut handle)?;
    let otp = parse_a6_response(&response_packet)?;

    println!();
    println!("--- Raw 64-byte OTP ---");
    print_hex(&otp);

    println!();
    println!("OTP as one hex string:");
    for byte in otp {
        print!("{byte:02x}");
    }
    println!();

    let valid = validate_chicago_h_otp(&otp);

    println!();
    println!("--- Recovered calibration fields ---");

    println!("OTP[0x1b] FDT encoding: 0x{:02x}", otp[0x1B]);

    match decode_fdt_offset(otp[0x1B]) {
        Some(offset) => {
            println!("decoded FDT offset: {offset}");

            if offset == 0 {
                println!("config behavior: leave the default FDT-offset field unchanged");
            } else {
                println!("config low-byte override: 0x{:02x}", offset + 8);
            }
        }
        None => {
            println!("decoded FDT offset: INVALID");
        }
    }

    println!("OTP[0x2a] T-code/diff source: 0x{:02x}", otp[0x2A]);

    println!("OTP[0x2d] redundant copy:     0x{:02x}", otp[0x2D]);

    println!();

    if !valid {
        return Err(invalid_data(
            "ChicagoH OTP validation FAILED; do not use this OTP to generate chip configuration",
        ));
    }

    println!("ChicagoH OTP validation PASSED.");
    println!("OTP is safe to use for further reverse-engineering.");

    Ok(())
}
