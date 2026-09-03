const LIVE_OTP: [u8; 64] = [
    0x57, 0x43, 0x47, 0x34, 0x33, 0x38, 0x2e, 0x00, 0xc0, 0x74, 0x8b, 0xab, 0x42, 0xeb, 0x16, 0x0a,
    0x01, 0x05, 0x03, 0x06, 0x00, 0x00, 0x79, 0x00, 0x00, 0x00, 0x00, 0x0c, 0xf1, 0x73, 0x8c, 0x0c,
    0x07, 0x00, 0x00, 0x00, 0xe5, 0x73, 0xdf, 0xfc, 0x08, 0x76, 0xad, 0x52, 0x06, 0xad, 0xae, 0xaf,
    0xad, 0xae, 0xae, 0xaf, 0xad, 0xae, 0x00, 0x00, 0xe5, 0x1a, 0xdf, 0x20, 0x16, 0x5f, 0x79, 0xff,
];

//
// Exact 32 qwords constructed by ChicagoH GetChipConfig.
//
// These are copied into the 0x100-byte buffer in little-endian order.
// The hard-coded final word initially contains 0xffbc, but the vendor
// immediately replaces config[0xfe..0xff] with the computed checksum.
//
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

const CONFIG_SUM_TARGET: u16 = 0x5a5b;

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

fn check_chicago_h_otp(otp: &[u8; 64]) -> bool {
    //
    // CP:
    //   OTP[00..0A] + OTP[24..27]
    // stored CRC = OTP[3C]
    //
    let mut cp = Vec::with_capacity(15);
    cp.extend_from_slice(&otp[0x00..0x0b]);
    cp.extend_from_slice(&otp[0x24..0x28]);

    //
    // FT:
    //   OTP[0B..13]
    //   OTP[1C]
    //   OTP[32..35]
    //   OTP[38..3B]
    //   OTP[3E]
    // stored CRC = OTP[3D]
    //
    let mut ft = Vec::with_capacity(19);
    ft.extend_from_slice(&otp[0x0b..0x14]);
    ft.push(otp[0x1c]);
    ft.extend_from_slice(&otp[0x32..0x36]);
    ft.extend_from_slice(&otp[0x38..0x3c]);
    ft.push(otp[0x3e]);

    //
    // MT:
    //   OTP[14..1B]
    //   OTP[1D..23]
    //   OTP[28..31]
    //   OTP[36..37]
    // stored CRC = OTP[3F]
    //
    let mut mt = Vec::with_capacity(27);
    mt.extend_from_slice(&otp[0x14..0x1c]);
    mt.extend_from_slice(&otp[0x1d..0x24]);
    mt.extend_from_slice(&otp[0x28..0x32]);
    mt.extend_from_slice(&otp[0x36..0x38]);

    let cp_calc = goodix_crc8(&cp);
    let ft_calc = goodix_crc8(&ft);
    let mt_calc = goodix_crc8(&mt);

    let cp_ok = cp_calc == otp[0x3c];
    let ft_ok = ft_calc == otp[0x3d];
    let mt_ok = mt_calc == otp[0x3f];

    println!(
        "CP: calculated=0x{cp_calc:02x} stored=0x{:02x} {}",
        otp[0x3c],
        if cp_ok { "PASS" } else { "FAIL" }
    );

    println!(
        "FT: calculated=0x{ft_calc:02x} stored=0x{:02x} {}",
        otp[0x3d],
        if ft_ok { "PASS" } else { "FAIL" }
    );

    println!(
        "MT: calculated=0x{mt_calc:02x} stored=0x{:02x} {}",
        otp[0x3f],
        if mt_ok { "PASS" } else { "FAIL" }
    );

    cp_ok && ft_ok && mt_ok
}

//
// Recovered ChicagoH GetTcodeAndDiffFromOtp behavior.
//
fn decode_tcode_diff(otp: &[u8; 64]) -> Option<(u16, u16)> {
    let source = otp[0x2a];
    let redundant = otp[0x2d];

    //
    // Vendor falls back to static defaults if source is zero
    // or the redundant copy does not match.
    //
    if source == 0 || source != redundant {
        return None;
    }

    let high = i32::from(source >> 4);
    let low = i32::from(source & 0x0f);

    //
    // FUN_00201cf0(high, 5)
    //
    let tcode_base = high.checked_add(5)?;

    //
    // local_b6 = result << 4
    //
    let tcode_i32 = tcode_base.checked_mul(16)?;
    let tcode = u16::try_from(tcode_i32).ok()?;

    //
    // FUN_00201cf0(low, 2)
    //
    let diff_base = low.checked_add(2)?;

    //
    // FUN_00201dc0(diff_base, 100)
    //
    let scaled = diff_base.checked_mul(100)?;

    //
    // ((scaled << 8) / tcode & 0xffff) / 0x30
    //
    let numerator = scaled.checked_mul(256)?;
    let divided = numerator / i32::from(tcode);

    let diff = (((divided as u32) & 0xffff) / 0x30) as u16;

    Some((tcode, diff))
}

//
// Recovered _MilanFSerGetFdtOffsetFromOtp.
//
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

//
// Vendor checksum invariant:
//
//     sum(all 128 little-endian u16 words) == 0x5a5b mod 65536
//
// config[0xfe..0xff] is the checksum word.
//
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

//
// Recovered FUN_0012e210 behavior.
//
// Search 4-byte records:
//
//     u16 key
//     u16 value
//
// Replace the matching value and immediately recompute
// the configuration checksum.
//
fn replace_config_value(
    config: &mut [u8; 256],
    start: usize,
    end: usize,
    key: u16,
    new_value: u16,
) -> Result<u16, String> {
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

    Err(format!(
        "key 0x{key:04x} not found in section \
         0x{start:02x}..0x{end:02x}"
    ))
}

fn generate_chicago_h_config(otp: &[u8; 64]) -> Result<[u8; 256], String> {
    if !check_chicago_h_otp(otp) {
        return Err("ChicagoH OTP validation failed".to_string());
    }

    let mut config = base_config();

    //
    // ChicagoH_GetChipConfig:
    //
    // FUN_0012e1d0(config, 0x7f)
    // config[0x7f] = checksum
    //
    let base_checksum = recompute_config_checksum(&mut config);

    println!(
        "base checksum after vendor-style recompute: \
         0x{base_checksum:04x}"
    );

    //
    // FDT section:
    //   start  = config[5] = 0x9d
    //   length = config[6] = 0x2c
    //   end    = 0xc9
    //
    let (fdt_start, fdt_end) = section_bounds(&config, 5, 6);

    //
    // Image section:
    //   start  = config[9]  = 0xe5
    //   length = config[10] = 0x18
    //   end    = 0xfd
    //
    let (image_start, image_end) = section_bounds(&config, 9, 10);

    //
    // T-code + diff.
    //
    if let Some((tcode, diff)) = decode_tcode_diff(otp) {
        println!("OTP-derived T-code: 0x{tcode:04x}");

        println!("OTP-derived diff:   0x{diff:04x}");

        //
        // _MilanFSerModifyImageTcode
        //
        let old_tcode = replace_config_value(&mut config, image_start, image_end, 0x005c, tcode)?;

        println!(
            "image key 0x005c: 0x{old_tcode:04x} \
             -> 0x{tcode:04x}"
        );

        //
        // _MilanFSerModifyFdtDelta
        //
        let fdt_delta = (diff << 8) | 0x0080;

        let old_delta = replace_config_value(&mut config, fdt_start, fdt_end, 0x0082, fdt_delta)?;

        println!(
            "FDT key 0x0082:   0x{old_delta:04x} \
             -> 0x{fdt_delta:04x}"
        );
    } else {
        println!(
            "T-code/diff OTP invalid; \
             leaving static defaults"
        );
    }

    //
    // _MilanFSerModifyFdtOffset
    //
    match decode_fdt_offset(otp[0x1b]) {
        Some(0) => {
            //
            // This is exactly what your sensor does.
            //
            // ChicagoH_GetChipConfig only calls the
            // modifier when the decoded value != 0.
            //
            println!(
                "decoded FDT offset = 0; \
                 leaving key 0x0056 unchanged"
            );
        }

        Some(offset) => {
            let old_value = find_config_value(&config, fdt_start, fdt_end, 0x0056)
                .ok_or_else(|| "FDT key 0x0056 not found".to_string())?;

            //
            // Preserve upper byte and replace lower byte
            // with decoded OTP offset + 8.
            //
            let new_value = (old_value & 0xff00) | u16::from(offset + 8);

            replace_config_value(&mut config, fdt_start, fdt_end, 0x0056, new_value)?;

            println!(
                "FDT key 0x0056:   0x{old_value:04x} \
                 -> 0x{new_value:04x}"
            );
        }

        None => {
            println!(
                "FDT offset OTP invalid; \
                 leaving static default"
            );
        }
    }

    Ok(config)
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

fn main() -> Result<(), String> {
    //
    // Recovered CRC-8 test vector.
    //
    assert_eq!(goodix_crc8(b"123456789"), 0x0b);

    println!("--- ChicagoH GF3258 WN2 offline config generator ---");
    println!();

    let config = generate_chicago_h_config(&LIVE_OTP)?;

    let (fdt_start, fdt_end) = section_bounds(&config, 5, 6);

    let (image_start, image_end) = section_bounds(&config, 9, 10);

    let image_tcode = find_config_value(&config, image_start, image_end, 0x005c)
        .ok_or_else(|| "image key 0x005c missing".to_string())?;

    let fdt_delta = find_config_value(&config, fdt_start, fdt_end, 0x0082)
        .ok_or_else(|| "FDT key 0x0082 missing".to_string())?;

    let fdt_offset = find_config_value(&config, fdt_start, fdt_end, 0x0056)
        .ok_or_else(|| "FDT key 0x0056 missing".to_string())?;

    let checksum = u16::from_le_bytes([config[0xfe], config[0xff]]);

    let word_sum = config_word_sum(&config);

    println!();
    println!("--- Final verification ---");

    println!("image 0x005c = 0x{image_tcode:04x}");

    println!("FDT   0x0082 = 0x{fdt_delta:04x}");

    println!("FDT   0x0056 = 0x{fdt_offset:04x}");

    println!("checksum      = 0x{checksum:04x}");

    println!("u16 word sum  = 0x{word_sum:04x}");

    //
    // Expected values for your validated live OTP.
    //
    assert_eq!(image_tcode, 0x00f0);
    assert_eq!(fdt_delta, 0x2180);
    assert_eq!(fdt_offset, 0x2004);
    assert_eq!(checksum, 0x1e48);
    assert_eq!(word_sum, CONFIG_SUM_TARGET);

    println!();
    println!("All expected values match.");

    println!();
    println!(
        "--- Generated 0x90 payload \
         (256 bytes; NOT sent) ---"
    );

    print_hex(&config);

    println!();
    println!("One-line hex:");

    for byte in config {
        print!("{byte:02x}");
    }

    println!();

    Ok(())
}
