use rusb::{Context, DeviceHandle, UsbContext};
use std::error::Error;
use std::io;
use std::time::Duration;

const VID: u16 = 0x27c6;
const PID: u16 = 0x550a;

const INTERFACE: u8 = 0;
const EP_OUT: u8 = 0x01;
const EP_IN: u8 = 0x83;

const TIMEOUT: Duration = Duration::from_secs(2);

const CMD_ACK: u8 = 0xb0;
const CMD_GET_OTP: u8 = 0xa6;
const CMD_CHIP_CONFIG: u8 = 0x90;

const CONFIG_SUM_TARGET: u16 = 0x5a5b;

// First-live-test safety gate.
//
// This is the exact 64-byte OTP read from this sensor and independently
// validated against ChicagoH CheckOtp:
//
//   CP = 0x16 PASS
//   FT = 0x5f PASS
//   MT = 0xff PASS
//
// The live A6 response must match this exactly before this probe is
// permitted to send command 0x90.
const EXPECTED_OTP: [u8; 64] = [
    0x57, 0x43, 0x47, 0x34, 0x33, 0x38, 0x2e, 0x00, 0xc0, 0x74, 0x8b, 0xab, 0x42, 0xeb, 0x16, 0x0a,
    0x01, 0x05, 0x03, 0x06, 0x00, 0x00, 0x79, 0x00, 0x00, 0x00, 0x00, 0x0c, 0xf1, 0x73, 0x8c, 0x0c,
    0x07, 0x00, 0x00, 0x00, 0xe5, 0x73, 0xdf, 0xfc, 0x08, 0x76, 0xad, 0x52, 0x06, 0xad, 0xae, 0xaf,
    0xad, 0xae, 0xae, 0xaf, 0xad, 0xae, 0x00, 0x00, 0xe5, 0x1a, 0xdf, 0x20, 0x16, 0x5f, 0x79, 0xff,
];

// Exact 0x100-byte base constructed by ChicagoH GetChipConfig.
//
// Stored here in the same 32 little-endian qwords seen in the vendor
// implementation.
const CHICAGO_H_BASE_QWORDS: [u64; 32] = [
    0xc92c9d2c716011b0,
    0xfd00fd00fd18e51c,
    0x0400ca800100ba03,
    0x000086b315008400,
    0x00008aba000088c4,
    0x00008eaa00008cb2,
    0xb10092bbbb0090c1,
    0x000096a8000094b1,
    0x00009a00000098b6,
    0x0000d4000000d200,
    0x0000d8000000d600,
    0x0000d00501005000,
    0x7800720000007000,
    0x1000201234007456,
    0x0100220402012a40,
    0x0100800032002420,
    0x2400560080005c00,
    0x0c00320203005820,
    0x00007c0003006602,
    0x82012a1580008258,
    0x1400242001002203,
    0x00005c0001008000,
    0x0300582004005601,
    0x030066020c003202,
    0x8000825800007c00,
    0x80005c0008012a15,
    0x0400620110005400,
    0x0300660019006403,
    0x08012a5801007c00,
    0x0800520100005c00,
    0x0300660100005400,
    0xffbc005801007c00,
];

fn invalid_data(message: impl Into<String>) -> Box<dyn Error> {
    io::Error::new(io::ErrorKind::InvalidData, message.into()).into()
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

// Ordinary Goodix inner checksum:
//
//   checksum = 0xAA -
//              (cmd + len_lo + len_hi + sum(payload))
//
// modulo 256.
fn ordinary_checksum(command: u8, encoded_len: u16, payload: &[u8]) -> u8 {
    let [len_lo, len_hi] = encoded_len.to_le_bytes();

    let mut sum = command.wrapping_add(len_lo).wrapping_add(len_hi);

    for &byte in payload {
        sum = sum.wrapping_add(byte);
    }

    0xaau8.wrapping_sub(sum)
}

// Construct an ordinary Goodix command:
//
// Outer:
//   A0
//   u16 LE inner length
//   outer checksum
//
// Inner:
//   command
//   u16 LE encoded length
//   payload
//   ordinary checksum
//
// encoded length = payload length + 1 checksum byte.
fn build_command(command: u8, payload: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let encoded_len_usize = payload
        .len()
        .checked_add(1)
        .ok_or_else(|| invalid_data("encoded length overflow"))?;

    let encoded_len =
        u16::try_from(encoded_len_usize).map_err(|_| invalid_data("payload too large"))?;

    let inner_len_usize = 1usize
        .checked_add(2)
        .and_then(|x| x.checked_add(encoded_len_usize))
        .ok_or_else(|| invalid_data("inner length overflow"))?;

    let inner_len =
        u16::try_from(inner_len_usize).map_err(|_| invalid_data("inner packet too large"))?;

    let [inner_lo, inner_hi] = inner_len.to_le_bytes();

    let outer_checksum = 0xa0u8.wrapping_add(inner_lo).wrapping_add(inner_hi);

    let [encoded_lo, encoded_hi] = encoded_len.to_le_bytes();

    let trailer = ordinary_checksum(command, encoded_len, payload);

    let mut packet = Vec::with_capacity(4 + inner_len_usize);

    packet.push(0xa0);
    packet.push(inner_lo);
    packet.push(inner_hi);
    packet.push(outer_checksum);

    packet.push(command);
    packet.push(encoded_lo);
    packet.push(encoded_hi);

    packet.extend_from_slice(payload);
    packet.push(trailer);

    Ok(packet)
}

// Preserve the already-proven behavior used by otp_dump for short commands:
//
// a logical command shorter than one endpoint packet is placed in a
// zero-filled 64-byte USB OUT transfer.
fn write_short_packet(
    handle: &mut DeviceHandle<Context>,
    packet: &[u8],
) -> Result<(), Box<dyn Error>> {
    if packet.len() > 64 {
        return Err(invalid_data(format!(
            "short-packet helper received {} bytes",
            packet.len()
        )));
    }

    let mut out = [0u8; 64];
    out[..packet.len()].copy_from_slice(packet);

    println!("OUT logical={} USB=64:", packet.len());
    print_hex(packet);

    let written = handle.write_bulk(EP_OUT, &out, TIMEOUT)?;

    if written != out.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            format!("short USB write: {written}/{}", out.len()),
        )
        .into());
    }

    Ok(())
}

// The 0x90 packet is 264 bytes.
//
// Send the exact logical transfer length. libusb/USB will split this
// naturally across the endpoint's 64-byte max-packet size:
//
//   64 + 64 + 64 + 64 + 8
//
// We deliberately do NOT append zero padding after the 264-byte command.
fn write_exact_packet(
    handle: &mut DeviceHandle<Context>,
    packet: &[u8],
) -> Result<(), Box<dyn Error>> {
    println!("OUT exact USB transfer={} bytes:", packet.len());
    print_hex(packet);

    let written = handle.write_bulk(EP_OUT, packet, TIMEOUT)?;

    if written != packet.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            format!("short USB write: {written}/{}", packet.len()),
        )
        .into());
    }

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

fn validate_outer(packet: &[u8]) -> Result<usize, Box<dyn Error>> {
    if packet.len() < 4 {
        return Err(invalid_data(format!("packet too short: {}", packet.len())));
    }

    if packet[0] != 0xa0 {
        return Err(invalid_data(format!(
            "unexpected outer marker 0x{:02x}",
            packet[0]
        )));
    }

    let inner_len = u16::from_le_bytes([packet[1], packet[2]]) as usize;

    let expected_outer_checksum = 0xa0u8.wrapping_add(packet[1]).wrapping_add(packet[2]);

    if packet[3] != expected_outer_checksum {
        return Err(invalid_data(format!(
            "bad outer checksum: got 0x{:02x}, expected 0x{:02x}",
            packet[3], expected_outer_checksum
        )));
    }

    let expected_total = 4 + inner_len;

    if packet.len() != expected_total {
        return Err(invalid_data(format!(
            "packet length mismatch: got {}, expected {}",
            packet.len(),
            expected_total
        )));
    }

    Ok(inner_len)
}

fn parse_inner(packet: &[u8]) -> Result<(u8, &[u8]), Box<dyn Error>> {
    let inner_len = validate_outer(packet)?;

    if inner_len < 4 {
        return Err(invalid_data(format!("inner packet too short: {inner_len}")));
    }

    let command = packet[4];

    let encoded_len = u16::from_le_bytes([packet[5], packet[6]]);

    if encoded_len == 0 {
        return Err(invalid_data("encoded inner length is zero"));
    }

    let expected_inner_len = 3 + encoded_len as usize;

    if inner_len != expected_inner_len {
        return Err(invalid_data(format!(
            "inner length mismatch: outer={inner_len}, encoded={expected_inner_len}"
        )));
    }

    let payload_len = encoded_len as usize - 1;

    let payload_start = 7;
    let payload_end = payload_start + payload_len;

    if payload_end >= packet.len() {
        return Err(invalid_data("payload extends beyond packet"));
    }

    let payload = &packet[payload_start..payload_end];

    let trailer = packet[payload_end];

    let expected_trailer = ordinary_checksum(command, encoded_len, payload);

    if trailer != expected_trailer {
        return Err(invalid_data(format!(
            "bad command 0x{command:02x} checksum: got 0x{trailer:02x}, expected 0x{expected_trailer:02x}"
        )));
    }

    Ok((command, payload))
}

fn parse_ack(packet: &[u8], expected_command: u8) -> Result<u8, Box<dyn Error>> {
    let (command, payload) = parse_inner(packet)?;

    if command != CMD_ACK {
        return Err(invalid_data(format!(
            "expected B0 ACK, received command 0x{command:02x}"
        )));
    }

    if payload.len() != 2 {
        return Err(invalid_data(format!(
            "expected 2-byte B0 payload, got {}",
            payload.len()
        )));
    }

    if payload[0] != expected_command {
        return Err(invalid_data(format!(
            "ACK is for command 0x{:02x}, expected 0x{expected_command:02x}",
            payload[0]
        )));
    }

    // McuParseMsg semantics:
    //
    // payload[0] = acknowledged command
    // payload[1] = flags
    //
    // bit 1 = MCU power lost.
    //
    // 0x01 and 0x03 are both ACKs.
    Ok(payload[1])
}

fn parse_otp_response(packet: &[u8]) -> Result<[u8; 64], Box<dyn Error>> {
    let (command, payload) = parse_inner(packet)?;

    if command != CMD_GET_OTP {
        return Err(invalid_data(format!(
            "expected A6 response, received 0x{command:02x}"
        )));
    }

    if payload.len() != 64 {
        return Err(invalid_data(format!(
            "A6 returned {} bytes, expected 64",
            payload.len()
        )));
    }

    let mut otp = [0u8; 64];
    otp.copy_from_slice(payload);

    Ok(otp)
}

// FUN_0010f950:
//
// CRC-8
// poly    0x07
// init    0x00
// refin   false
// refout  false
// xorout  0xff
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
    let mut cp = Vec::with_capacity(15);

    cp.extend_from_slice(&otp[0x00..0x0b]);
    cp.extend_from_slice(&otp[0x24..0x28]);

    let cp_calculated = goodix_crc8(&cp);
    let cp_stored = otp[0x3c];

    let mut ft = Vec::with_capacity(19);

    ft.extend_from_slice(&otp[0x0b..0x14]);
    ft.push(otp[0x1c]);
    ft.extend_from_slice(&otp[0x32..0x36]);
    ft.extend_from_slice(&otp[0x38..0x3c]);
    ft.push(otp[0x3e]);

    let ft_calculated = goodix_crc8(&ft);
    let ft_stored = otp[0x3d];

    let mut mt = Vec::with_capacity(27);

    mt.extend_from_slice(&otp[0x14..0x1c]);
    mt.extend_from_slice(&otp[0x1d..0x24]);
    mt.extend_from_slice(&otp[0x28..0x32]);
    mt.extend_from_slice(&otp[0x36..0x38]);

    let mt_calculated = goodix_crc8(&mt);
    let mt_stored = otp[0x3f];

    println!(
        "CP: calculated=0x{cp_calculated:02x} stored=0x{cp_stored:02x} {}",
        if cp_calculated == cp_stored {
            "PASS"
        } else {
            "FAIL"
        }
    );

    println!(
        "FT: calculated=0x{ft_calculated:02x} stored=0x{ft_stored:02x} {}",
        if ft_calculated == ft_stored {
            "PASS"
        } else {
            "FAIL"
        }
    );

    println!(
        "MT: calculated=0x{mt_calculated:02x} stored=0x{mt_stored:02x} {}",
        if mt_calculated == mt_stored {
            "PASS"
        } else {
            "FAIL"
        }
    );

    cp_calculated == cp_stored && ft_calculated == ft_stored && mt_calculated == mt_stored
}

// ChicagoH GetTcodeAndDiffFromOtp.
fn decode_tcode_diff(otp: &[u8; 64]) -> Option<(u16, u16)> {
    let source = otp[0x2a];
    let redundant = otp[0x2d];

    if source == 0 || source != redundant {
        return None;
    }

    let high = i32::from(source >> 4);

    let low = i32::from(source & 0x0f);

    // FUN_00201cf0(high, 5)
    let tcode_base = high.checked_add(5)?;

    let tcode_i32 = tcode_base.checked_mul(16)?;

    let tcode = u16::try_from(tcode_i32).ok()?;

    // FUN_00201cf0(low, 2)
    let diff_base = low.checked_add(2)?;

    // FUN_00201dc0(..., 100)
    let scaled = diff_base.checked_mul(100)?;

    let numerator = scaled.checked_mul(256)?;

    let divided = numerator / i32::from(tcode);

    let diff = (((divided as u32) & 0xffff) / 0x30) as u16;

    Some((tcode, diff))
}

// _MilanFSerGetFdtOffsetFromOtp.
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

fn base_config() -> [u8; 256] {
    let mut config = [0u8; 256];

    for (index, qword) in CHICAGO_H_BASE_QWORDS.iter().enumerate() {
        let offset = index * 8;

        config[offset..offset + 8].copy_from_slice(&qword.to_le_bytes());
    }

    config
}

// Vendor invariant:
//
// sum(all 128 LE u16 words) mod 65536 == 0x5a5b
//
// Final word at 0xfe is regenerated whenever a field changes.
fn recompute_config_checksum(config: &mut [u8; 256]) -> u16 {
    let mut sum = 0u16;

    for chunk in config[..0xfe].chunks_exact(2) {
        let word = u16::from_le_bytes([chunk[0], chunk[1]]);

        sum = sum.wrapping_add(word);
    }

    let checksum = CONFIG_SUM_TARGET.wrapping_sub(sum);

    config[0xfe..0x100].copy_from_slice(&checksum.to_le_bytes());

    checksum
}

fn config_word_sum(config: &[u8; 256]) -> u16 {
    let mut sum = 0u16;

    for chunk in config.chunks_exact(2) {
        let word = u16::from_le_bytes([chunk[0], chunk[1]]);

        sum = sum.wrapping_add(word);
    }

    sum
}

fn section_bounds(config: &[u8; 256], start_field: usize, length_field: usize) -> (usize, usize) {
    let start = usize::from(config[start_field]);

    let length = usize::from(config[length_field]);

    (start, start + length)
}

fn find_config_value(config: &[u8; 256], start: usize, end: usize, key: u16) -> Option<u16> {
    let mut offset = start;

    while offset + 4 <= end {
        let record_key = u16::from_le_bytes([config[offset], config[offset + 1]]);

        if record_key == key {
            return Some(u16::from_le_bytes([config[offset + 2], config[offset + 3]]));
        }

        offset += 4;
    }

    None
}

// FUN_0012e210:
//
// Locate:
//   u16 key
//   u16 value
//
// Replace value and regenerate the trailing config checksum.
fn replace_config_value(
    config: &mut [u8; 256],
    start: usize,
    end: usize,
    key: u16,
    new_value: u16,
) -> Result<u16, Box<dyn Error>> {
    let mut offset = start;

    while offset + 4 <= end {
        let record_key = u16::from_le_bytes([config[offset], config[offset + 1]]);

        if record_key == key {
            let old_value = u16::from_le_bytes([config[offset + 2], config[offset + 3]]);

            config[offset + 2..offset + 4].copy_from_slice(&new_value.to_le_bytes());

            recompute_config_checksum(config);

            return Ok(old_value);
        }

        offset += 4;
    }

    Err(invalid_data(format!(
        "key 0x{key:04x} not found in section 0x{start:02x}..0x{end:02x}"
    )))
}

fn generate_chicago_h_config(otp: &[u8; 64]) -> Result<[u8; 256], Box<dyn Error>> {
    let mut config = base_config();

    // Vendor computes the initial checksum before applying
    // OTP-specific modifications.
    let base_checksum = recompute_config_checksum(&mut config);

    println!("base config checksum: 0x{base_checksum:04x}");

    if base_checksum != 0x0e53 {
        return Err(invalid_data(format!(
            "unexpected base checksum 0x{base_checksum:04x}; expected 0x0e53"
        )));
    }

    let (fdt_start, fdt_end) = section_bounds(&config, 5, 6);

    let (image_start, image_end) = section_bounds(&config, 9, 10);

    println!("FDT section:   0x{fdt_start:02x}..0x{fdt_end:02x}");

    println!("image section: 0x{image_start:02x}..0x{image_end:02x}");

    let (tcode, diff) =
        decode_tcode_diff(otp).ok_or_else(|| invalid_data("T-code/diff OTP copies are invalid"))?;

    println!("OTP-derived T-code: 0x{tcode:04x}");

    println!("OTP-derived diff:   0x{diff:04x}");

    // First-live-test safety gate.
    if tcode != 0x00f0 || diff != 0x0021 {
        return Err(invalid_data(format!(
            "unexpected calibration: tcode=0x{tcode:04x}, diff=0x{diff:04x}; refusing 0x90"
        )));
    }

    // _MilanFSerModifyImageTcode
    let old_tcode = replace_config_value(&mut config, image_start, image_end, 0x005c, tcode)?;

    println!("image key 0x005c: 0x{old_tcode:04x} -> 0x{tcode:04x}");

    // _MilanFSerModifyFdtDelta
    let fdt_delta = (diff << 8) | 0x0080;

    let old_delta = replace_config_value(&mut config, fdt_start, fdt_end, 0x0082, fdt_delta)?;

    println!("FDT key 0x0082:   0x{old_delta:04x} -> 0x{fdt_delta:04x}");

    // _MilanFSerModifyFdtOffset
    let decoded_fdt_offset = decode_fdt_offset(otp[0x1b])
        .ok_or_else(|| invalid_data("FDT offset redundant encoding invalid"))?;

    println!("decoded FDT offset: {decoded_fdt_offset}");

    // First-live-test safety gate.
    if decoded_fdt_offset != 0 {
        return Err(invalid_data(format!(
            "expected this unit's FDT offset to decode as 0, got {decoded_fdt_offset}; refusing 0x90"
        )));
    }

    // Zero means ChicagoH_GetChipConfig does not invoke
    // _MilanFSerModifyFdtOffset. Leave key 0x0056 unchanged.

    let image_tcode = find_config_value(&config, image_start, image_end, 0x005c)
        .ok_or_else(|| invalid_data("image key 0x005c missing"))?;

    let final_delta = find_config_value(&config, fdt_start, fdt_end, 0x0082)
        .ok_or_else(|| invalid_data("FDT key 0x0082 missing"))?;

    let final_offset = find_config_value(&config, fdt_start, fdt_end, 0x0056)
        .ok_or_else(|| invalid_data("FDT key 0x0056 missing"))?;

    let checksum = u16::from_le_bytes([config[0xfe], config[0xff]]);

    let word_sum = config_word_sum(&config);

    println!();
    println!("Generated config verification:");
    println!("  image 0x005c = 0x{image_tcode:04x}");
    println!("  FDT   0x0082 = 0x{final_delta:04x}");
    println!("  FDT   0x0056 = 0x{final_offset:04x}");
    println!("  checksum      = 0x{checksum:04x}");
    println!("  u16 word sum  = 0x{word_sum:04x}");

    if image_tcode != 0x00f0 {
        return Err(invalid_data("generated image T-code mismatch"));
    }

    if final_delta != 0x2180 {
        return Err(invalid_data("generated FDT delta mismatch"));
    }

    if final_offset != 0x2004 {
        return Err(invalid_data("generated FDT offset mismatch"));
    }

    if checksum != 0x1e48 {
        return Err(invalid_data(format!(
            "generated config checksum is 0x{checksum:04x}, expected 0x1e48"
        )));
    }

    if word_sum != CONFIG_SUM_TARGET {
        return Err(invalid_data(format!(
            "config word sum is 0x{word_sum:04x}, expected 0x{CONFIG_SUM_TARGET:04x}"
        )));
    }

    Ok(config)
}

fn parse_chip_config_completion(packet: &[u8]) -> Result<(), Box<dyn Error>> {
    let (command, payload) = parse_inner(packet)?;

    if command != CMD_CHIP_CONFIG {
        return Err(invalid_data(format!(
            "expected 0x90 completion, received command 0x{command:02x}"
        )));
    }

    if payload != [0x01, 0x00] {
        return Err(invalid_data(format!(
            "0x90 completion payload was {:02x?}, expected [01, 00]",
            payload
        )));
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    goodix_info::app::require_unprivileged_hardware_access()?;

    // Local recovered-CRC sanity check.
    if goodix_crc8(b"123456789") != 0x0b {
        return Err(invalid_data("CRC-8 self-test failed"));
    }

    println!("--- GF3258 WN2 cold configuration probe ---");

    println!("Scope: A6 read -> OTP validation -> generated 0x90 -> STOP");

    println!();

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

    //
    // STEP 1: fresh live OTP.
    //
    println!();
    println!("=== STEP 1: ChicagoHGetOtp ===");

    let a6 = build_command(CMD_GET_OTP, &[0x40, 0x00])?;

    if a6 != [0xa0, 0x06, 0x00, 0xa6, 0xa6, 0x03, 0x00, 0x40, 0x00, 0xc1] {
        return Err(invalid_data(
            "internally generated A6 request does not match known wire packet",
        ));
    }

    write_short_packet(&mut handle, &a6)?;

    let a6_ack = read_packet(&mut handle)?;

    let a6_flags = parse_ack(&a6_ack, CMD_GET_OTP)?;

    println!("A6 ACK flags: 0x{a6_flags:02x}");

    println!("A6 MCU-power-lost: {}", a6_flags & 0x02 != 0);

    let a6_response = read_packet(&mut handle)?;

    let otp = parse_otp_response(&a6_response)?;

    println!();
    println!("Live 64-byte OTP:");
    print_hex(&otp);

    //
    // STEP 2: exact ChicagoH integrity validation.
    //
    println!();
    println!("=== STEP 2: OTP validation ===");

    if !validate_chicago_h_otp(&otp) {
        return Err(invalid_data(
            "ChicagoH OTP validation FAILED; refusing 0x90",
        ));
    }

    println!("All ChicagoH OTP CRCs PASS.");

    //
    // First-live-test unit identity gate.
    //
    if otp != EXPECTED_OTP {
        println!();
        println!("EXPECTED OTP:");
        print_hex(&EXPECTED_OTP);

        println!();
        println!("LIVE OTP:");
        print_hex(&otp);

        return Err(invalid_data(
            "live OTP differs from the previously validated OTP; refusing 0x90",
        ));
    }

    println!("Live OTP exactly matches the previously validated unit OTP.");

    //
    // STEP 3: generate the exact 256-byte ChicagoH chip config.
    //
    println!();
    println!("=== STEP 3: Generate chip configuration ===");

    let config = generate_chicago_h_config(&otp)?;

    println!();
    println!("Final generated 256-byte config:");
    print_hex(&config);

    //
    // STEP 4: construct 0x90 wire packet.
    //
    println!();
    println!("=== STEP 4: Construct 0x90 packet ===");

    let command_90 = build_command(CMD_CHIP_CONFIG, &config)?;

    println!("0x90 logical packet length: {} bytes", command_90.len());

    if command_90.len() != 264 {
        return Err(invalid_data(format!(
            "0x90 packet length is {}, expected 264",
            command_90.len()
        )));
    }

    // Exact known framing:
    //
    // A0 04 01 A5
    // 90 01 01
    // <256 config>
    // 6F
    if command_90[0..7] != [0xa0, 0x04, 0x01, 0xa5, 0x90, 0x01, 0x01] {
        return Err(invalid_data("0x90 packet header mismatch"));
    }

    let trailer = *command_90
        .last()
        .ok_or_else(|| invalid_data("empty 0x90 packet"))?;

    println!("0x90 ordinary command trailer: 0x{trailer:02x}");

    if trailer != 0x6f {
        return Err(invalid_data(format!(
            "0x90 trailer is 0x{trailer:02x}, expected 0x6f"
        )));
    }

    println!("All pre-send safety gates PASS.");

    //
    // STEP 5: the one live configuration write.
    //
    println!();
    println!("=== STEP 5: Send volatile chip config (0x90) ===");

    write_exact_packet(&mut handle, &command_90)?;

    //
    // First response: B0 ACK.
    //
    let ack_90 = read_packet(&mut handle)?;

    let flags_90 = parse_ack(&ack_90, CMD_CHIP_CONFIG)?;

    println!();
    println!("0x90 B0 ACK accepted.");
    println!("0x90 ACK flags: 0x{flags_90:02x}");

    println!("0x90 ACK MCU-power-lost flag: {}", flags_90 & 0x02 != 0);

    //
    // Second response: actual command execution completion.
    //
    let completion = read_packet(&mut handle)?;

    parse_chip_config_completion(&completion)?;

    println!();
    println!("0x90 completion payload: [01 00] PASS");

    println!();
    println!("SUCCESS: GF3258 WN2 volatile chip configuration was accepted.");

    println!("Probe stops here. No D2, FDT, image, firmware, PSK, or register writes performed.");

    Ok(())
}
