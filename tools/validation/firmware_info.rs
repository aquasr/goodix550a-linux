use goodix_info::firmware::{APP_FIRMWARE_TYPE, AppTransferPackage, FirmwareBlob};
use goodix_info::firmware_auth::{
    EXPECTED_CAPTURED_PMK_HMAC, EXPECTED_VENDOR_F4, firmware_f4_tag, get_pmk_hmac_from_psk,
};

use std::env;
use std::error::Error;
use std::fs;
use std::path::Path;

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let path = env::args()
        .nth(1)
        .ok_or("usage: firmware_info <goodix-app.bin>")?;

    let path = Path::new(&path);

    let raw = fs::read(path)?;

    println!("Goodix bootstrap preparation");

    println!("Mode: offline / no USB writes");

    println!();

    println!("Firmware file: {}", path.display());

    println!("Blob size:     {} / 0x{:x}", raw.len(), raw.len());

    println!();

    /*
     * ------------------------------------------------------------
     * Firmware resource
     * ------------------------------------------------------------
     */

    let blob = FirmwareBlob::parse(&raw)?;

    println!("Firmware blob valid.");

    println!();

    println!("Metadata length: {}", blob.metadata_length());

    println!(
        "Prefix size:     {} / 0x{:x}",
        blob.prefix_size(),
        blob.prefix_size()
    );

    match std::str::from_utf8(blob.metadata()) {
        Ok(metadata) => {
            println!("Metadata:        {metadata}");
        }

        Err(_) => {
            println!("Metadata:        {:02x?}", blob.metadata());
        }
    }

    println!();

    println!(
        "APP size:        {} / 0x{:x}",
        blob.app().len(),
        blob.app().len()
    );

    println!("Outer CRC:       0x{:08x}", blob.stored_crc());

    println!("Computed CRC:    0x{:08x}", blob.computed_crc());

    println!();

    /*
     * ------------------------------------------------------------
     * WriteApp transfer package
     * ------------------------------------------------------------
     */

    let package = AppTransferPackage::build(&blob)?;

    println!("WriteApp transfer package:");

    println!("  Package size:  {} / 0x{:x}", package.len(), package.len());

    println!(
        "  APP length:    {} / 0x{:x}",
        package.app_len(),
        package.app_len()
    );

    println!("  APP CRC:       0x{:08x}", package.app_crc());

    println!("  Header CRC:    0x{:08x}", package.header_crc());

    println!();

    print!("  Header bytes:  ");

    print_hex(&package.bytes()[..12]);

    println!();

    /*
     * ------------------------------------------------------------
     * F0 preparation
     * ------------------------------------------------------------
     *
     * This constructs the exact payloads that would be passed to
     * command F0.
     *
     * Nothing is sent.
     */

    let chunks: Vec<_> = package.chunks().collect();

    let f0_payloads: Vec<_> = package.f0_payloads().collect();

    println!("F0 transfer plan:");

    println!("  Firmware type: {}", APP_FIRMWARE_TYPE);

    println!("  Chunk count:   {}", chunks.len());

    println!("  Payload count: {}", f0_payloads.len());

    if let Some(first) = chunks.first() {
        println!();

        println!("  First chunk:");

        println!("    Offset:       0x{:08x}", first.offset());

        println!("    Data length:  0x{:x}", first.length());

        println!("    Type:         {}", first.firmware_type());

        let payload = &f0_payloads[0];

        println!("    F0 payload:   {} bytes", payload.len());

        print!("    F0 header:    ");

        print_hex(&payload[..12]);
    }

    if let Some(last) = chunks.last() {
        println!();

        println!("  Last chunk:");

        println!("    Offset:       0x{:08x}", last.offset());

        println!("    Data length:  0x{:x}", last.length());

        println!("    Type:         {}", last.firmware_type());

        let payload = f0_payloads
            .last()
            .expect("F0 payload exists for last chunk");

        println!("    F0 payload:   {} bytes", payload.len());

        print!("    F0 header:    ");

        print_hex(&payload[..12]);
    }

    println!();

    /*
     * ------------------------------------------------------------
     * Firmware authentication
     * ------------------------------------------------------------
     *
     * This PSK is a regression fixture recovered from the captured
     * provisioning state:
     *
     *     0xbb010002
     *       -> authenticated
     *       -> AES-CBC unsealed
     *       -> 32 zero bytes
     *
     * It must NOT be treated as a universal device PSK.
     *
     * The live bootstrap path will instead obtain the PSK through:
     *
     *     E4
     *       -> unseal_psk()
     *       -> verify against 0xbb020001
     */

    let captured_psk = [0u8; 32];

    let pmk_hmac = get_pmk_hmac_from_psk(&captured_psk);

    let f4_tag = firmware_f4_tag(&captured_psk, package.bytes());

    println!("Firmware authentication:");

    println!();

    print!("  Captured PSK:  ");

    print_hex(&captured_psk);

    print!("  GetPmkHmac:    ");

    print_hex(&pmk_hmac);

    print!("  Expected PMK:  ");

    print_hex(&EXPECTED_CAPTURED_PMK_HMAC);

    println!(
        "  PMK match:     {}",
        pmk_hmac == EXPECTED_CAPTURED_PMK_HMAC
    );

    println!();

    print!("  Calculated F4: ");

    print_hex(&f4_tag);

    print!("  Vendor F4:     ");

    print_hex(&EXPECTED_VENDOR_F4);

    let f4_match = f4_tag == EXPECTED_VENDOR_F4;

    println!("  F4 match:      {}", f4_match);

    println!();

    /*
     * ------------------------------------------------------------
     * Known GM168SEC regression values
     * ------------------------------------------------------------
     */

    println!("Known GM168SEC APP regression:");

    println!("  APP length expected:     0x6100");

    println!("  APP length actual:       0x{:x}", package.app_len());

    println!("  APP CRC expected:        0x4d4446c1");

    println!("  APP CRC actual:          0x{:08x}", package.app_crc());

    println!("  Header CRC expected:     0xa2b69ee2");

    println!("  Header CRC actual:       0x{:08x}", package.header_crc());

    println!("  Package length expected: 0x610c");

    println!("  Package length actual:   0x{:x}", package.len());

    println!("  F0 count expected:       98");

    println!("  F0 count actual:         {}", chunks.len());

    println!();

    let package_matches = package.app_len() == 0x6100
        && package.app_crc() == 0x4d44_46c1
        && package.header_crc() == 0xa2b6_9ee2
        && package.len() == 0x610c
        && chunks.len() == 98;

    println!("Package regression match: {}", package_matches);

    println!("Authentication match:     {}", f4_match);

    println!();

    if package_matches && f4_match {
        println!("BOOTSTRAP PREPARATION: PASS");
    } else {
        println!("BOOTSTRAP PREPARATION: MISMATCH");
    }

    println!();

    println!(
        "No F0, F4, E0, erase, reset, or \
         other persistent command was sent."
    );

    Ok(())
}

fn print_hex(data: &[u8]) {
    for (index, byte) in data.iter().enumerate() {
        if index != 0 {
            print!(" ");
        }

        print!("{byte:02x}");
    }

    println!();
}
