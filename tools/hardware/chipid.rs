use rusb::{Context, DeviceHandle, UsbContext};
use std::error::Error;
use std::io;
use std::thread;
use std::time::Duration;

const VID: u16 = 0x27c6;
const PID: u16 = 0x550a;

const INTERFACE: u8 = 0;
const EP_OUT: u8 = 0x01;
const EP_IN: u8 = 0x83;
const TIMEOUT: Duration = Duration::from_secs(1);

fn write_packet(handle: &mut DeviceHandle<Context>, packet: &[u8]) -> Result<(), Box<dyn Error>> {
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

    println!("OUT: {:02x?}", packet);

    Ok(())
}

fn read_packet(handle: &mut DeviceHandle<Context>) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut input = vec![0u8; 32768];
    let n = handle.read_bulk(EP_IN, &mut input, TIMEOUT)?;
    input.truncate(n);

    println!("IN ({n}): {:02x?}", input);

    Ok(input)
}

fn main() -> Result<(), Box<dyn Error>> {
    goodix_info::app::require_unprivileged_hardware_access()?;

    let context = Context::new()?;

    let mut handle = context
        .open_device_with_vid_pid(VID, PID)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "27c6:550a not found"))?;

    if handle.kernel_driver_active(INTERFACE).unwrap_or(false) {
        handle.detach_kernel_driver(INTERFACE)?;
    }

    handle.claim_interface(INTERFACE)?;

    //
    // McuResetFingerPrint
    //
    // command: A2
    // payload: 05 14
    //
    // This is the exact request observed from the proprietary driver.
    //
    let reset = [0xA0, 0x06, 0x00, 0xA6, 0xA2, 0x03, 0x00, 0x05, 0x14, 0xEC];

    println!("--- McuResetFingerPrint ---");
    write_packet(&mut handle, &reset)?;

    // Vendor capture showed:
    //   10-byte ACK
    //   11-byte A2 response
    let reset_ack = read_packet(&mut handle)?;
    let reset_response = read_packet(&mut handle)?;

    println!("reset ACK length: {}", reset_ack.len());
    println!("reset response length: {}", reset_response.len());

    //
    // Exact delay used by McuDevLoader.c.
    //
    thread::sleep(Duration::from_millis(10));

    //
    // McuGetChipId
    //
    // _McuReadRegister:
    //   address = 0x0000
    //   length  = 4
    //
    let get_chip_id = [
        0xA0, 0x09, 0x00, 0xA9, 0x82, 0x06, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x1E,
    ];

    println!();
    println!("--- McuGetChipId ---");
    write_packet(&mut handle, &get_chip_id)?;

    // Vendor capture showed:
    //   10-byte ACK
    //   12-byte 0x82 response
    let _ack = read_packet(&mut handle)?;
    let response = read_packet(&mut handle)?;

    if response.len() < 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("chip ID response too short: {}", response.len()),
        )
        .into());
    }

    if response[0] != 0xA0 || response[4] != 0x82 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected response: {:02x?}", response),
        )
        .into());
    }

    let encoded_len = u16::from_le_bytes([response[5], response[6]]);

    if encoded_len != 5 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected encoded length: {encoded_len}"),
        )
        .into());
    }

    let wire = [response[7], response[8], response[9], response[10]];

    println!();
    println!("register bytes on wire: {:02x?}", wire);

    //
    // FUN_0010fd10:
    // swap the byte order of each 16-bit word.
    //
    let converted = [wire[1], wire[0], wire[3], wire[2]];

    let chip_id = u32::from_le_bytes(converted);
    let selector = chip_id >> 8;

    println!("after u16 byte swaps: {:02x?}", converted);
    println!("chip_id:  0x{chip_id:08x}");
    println!("selector: 0x{selector:04x}");

    Ok(())
}
