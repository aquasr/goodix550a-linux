use std::{
    error::Error,
    fmt, thread,
    time::{Duration, Instant},
};

use rusb::{Device, DeviceHandle, Direction, GlobalContext, TransferType};

pub(crate) const GOODIX_VID: u16 = 0x27c6;
pub(crate) const GOODIX_550A_PID: u16 = 0x550a;

/// Poll interval used while waiting for the reset-induced USB
/// detach -> attach transition.
///
/// The vendor implementation waits on a hotplug event. Our standalone
/// implementation currently uses libusb enumeration instead, so keep
/// the polling interval short without busy-spinning.
const REENUMERATION_POLL_INTERVAL: Duration = Duration::from_millis(25);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UsbLayout {
    pub(crate) interface: u8,
    pub(crate) bulk_in: u8,
    pub(crate) bulk_out: u8,
    pub(crate) max_packet_size: u16,
}

/// Backend-neutral USB failure classification used by the recovered Goodix
/// protocol transport.
///
/// The standalone backend currently maps libusb/rusb errors into this type. A
/// libfprint backend can map GUsb/FpiUsbTransfer failures into the same small
/// set without leaking either USB library into protocol code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GoodixUsbErrorKind {
    Timeout,
    NoDevice,
    NotFound,
    Busy,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GoodixUsbError {
    kind: GoodixUsbErrorKind,
    message: String,
}

impl GoodixUsbError {
    pub(crate) fn new(kind: GoodixUsbErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub(crate) const fn kind(&self) -> GoodixUsbErrorKind {
        self.kind
    }
}

impl fmt::Display for GoodixUsbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for GoodixUsbError {}

impl From<rusb::Error> for GoodixUsbError {
    fn from(error: rusb::Error) -> Self {
        let message = error.to_string();
        let kind = match error {
            rusb::Error::Timeout => GoodixUsbErrorKind::Timeout,
            rusb::Error::NoDevice => GoodixUsbErrorKind::NoDevice,
            rusb::Error::NotFound => GoodixUsbErrorKind::NotFound,
            rusb::Error::Busy => GoodixUsbErrorKind::Busy,
            _ => GoodixUsbErrorKind::Other,
        };

        Self::new(kind, message)
    }
}

/// Minimal physical USB contract required by `GoodixTransport`.
///
/// Interface discovery, ownership, opening/closing, hotplug/re-enumeration,
/// and cancellation remain responsibilities of the backend owner. The
/// recovered protocol layer only needs endpoint metadata plus bulk IN/OUT.
pub(crate) trait GoodixUsbIo {
    fn layout(&self) -> UsbLayout;

    fn write_bulk(&self, data: &[u8], timeout: Duration) -> Result<usize, GoodixUsbError>;

    fn read_bulk(&self, buffer: &mut [u8], timeout: Duration) -> Result<usize, GoodixUsbError>;
}

#[derive(Debug)]
pub(crate) enum ReenumerationError {
    Usb(rusb::Error),

    /// The device never disappeared after McuResetMcu.
    DetachTimedOut {
        timeout: Duration,
    },

    /// The device disappeared, but no usable 27c6:550a instance
    /// reappeared before the same overall deadline expired.
    AttachTimedOut {
        timeout: Duration,
    },
}

impl fmt::Display for ReenumerationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usb(error) => {
                write!(
                    f,
                    "USB error while waiting for Goodix re-enumeration: {error}"
                )
            }

            Self::DetachTimedOut { timeout } => {
                write!(
                    f,
                    "Goodix 27c6:550a did not detach within the \
                     {timeout:?} re-enumeration deadline"
                )
            }

            Self::AttachTimedOut { timeout } => {
                write!(
                    f,
                    "Goodix 27c6:550a detached but did not reattach \
                     and reopen within the {timeout:?} re-enumeration deadline"
                )
            }
        }
    }
}

impl Error for ReenumerationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Usb(error) => Some(error),
            Self::DetachTimedOut { .. } | Self::AttachTimedOut { .. } => None,
        }
    }
}

impl From<rusb::Error> for ReenumerationError {
    fn from(error: rusb::Error) -> Self {
        Self::Usb(error)
    }
}

pub(crate) struct GoodixDevice {
    handle: DeviceHandle<GlobalContext>,
    layout: UsbLayout,
}

impl GoodixDevice {
    pub(crate) fn open() -> rusb::Result<Self> {
        for device in rusb::devices()?.iter() {
            let Ok(descriptor) = device.device_descriptor() else {
                continue;
            };

            if descriptor.vendor_id() != GOODIX_VID || descriptor.product_id() != GOODIX_550A_PID {
                continue;
            }

            return Self::open_device(&device);
        }

        Err(rusb::Error::NoDevice)
    }

    fn open_device(device: &Device<GlobalContext>) -> rusb::Result<Self> {
        let layout = discover_layout(device)?;
        let handle = device.open()?;

        if handle.kernel_driver_active(layout.interface)? {
            return Err(rusb::Error::Busy);
        }

        handle.claim_interface(layout.interface)?;

        Ok(Self { handle, layout })
    }

    pub(crate) fn layout(&self) -> UsbLayout {
        self.layout
    }

    pub(crate) fn write_bulk(&self, data: &[u8], timeout: Duration) -> rusb::Result<usize> {
        self.handle.write_bulk(self.layout.bulk_out, data, timeout)
    }

    pub(crate) fn read_bulk(&self, buffer: &mut [u8], timeout: Duration) -> rusb::Result<usize> {
        self.handle.read_bulk(self.layout.bulk_in, buffer, timeout)
    }

    /// Wait for the reset-induced USB detach -> attach transition and
    /// return a newly opened / claimed Goodix device.
    ///
    /// Precondition:
    ///
    /// - the caller successfully sent `McuResetMcu` (`A2 02 32`);
    /// - the old `GoodixTransport` and `GoodixDevice` have been dropped.
    ///
    /// The caller's possession of the old open device proves the initial
    /// "present" state. This function then proves the remaining:
    ///
    /// ```text
    /// present before reset
    ///     -> absent
    ///     -> present again
    ///     -> open + claim interface
    /// ```
    ///
    /// The single `timeout` is an overall deadline covering both the
    /// detach and attach phases. Geneva WriteApp uses a 10-second upper
    /// bound for this transition.
    ///
    /// This helper performs no MCU command and cannot initiate a reset by
    /// itself.
    #[allow(dead_code)]
    pub(crate) fn wait_for_reenumeration(timeout: Duration) -> Result<Self, ReenumerationError> {
        let deadline = Instant::now() + timeout;

        /*
         * Phase 1: require the old USB instance to disappear.
         *
         * If the detach happened between the reset ACK and entering this
         * function, the very first enumeration already reports "absent";
         * that still satisfies the detach phase because the caller had an
         * open 27c6:550a immediately before McuResetMcu.
         */
        loop {
            if !goodix_550a_present()? {
                break;
            }

            if Instant::now() >= deadline {
                return Err(ReenumerationError::DetachTimedOut { timeout });
            }

            sleep_until_next_poll(deadline);
        }

        /*
         * Phase 2: wait for a new 27c6:550a to appear and successfully
         * reopen/reclaim it.
         *
         * A NoDevice/NotFound result can occur during the small race
         * between enumeration and opening while the USB core is still
         * publishing the new instance, so retry those until the deadline.
         * Other errors (for example permissions or a genuinely busy
         * interface) are actionable and are returned immediately.
         */
        loop {
            if Instant::now() >= deadline {
                return Err(ReenumerationError::AttachTimedOut { timeout });
            }

            match Self::open() {
                Ok(device) => {
                    return Ok(device);
                }

                Err(rusb::Error::NoDevice | rusb::Error::NotFound) => {}

                Err(error) => {
                    return Err(ReenumerationError::Usb(error));
                }
            }

            sleep_until_next_poll(deadline);
        }
    }
}

impl GoodixUsbIo for GoodixDevice {
    fn layout(&self) -> UsbLayout {
        GoodixDevice::layout(self)
    }

    fn write_bulk(&self, data: &[u8], timeout: Duration) -> Result<usize, GoodixUsbError> {
        GoodixDevice::write_bulk(self, data, timeout).map_err(Into::into)
    }

    fn read_bulk(&self, buffer: &mut [u8], timeout: Duration) -> Result<usize, GoodixUsbError> {
        GoodixDevice::read_bulk(self, buffer, timeout).map_err(Into::into)
    }
}

impl Drop for GoodixDevice {
    fn drop(&mut self) {
        if let Err(error) = self.handle.release_interface(self.layout.interface) {
            /*
             * NoDevice is expected when the MCU reset has already detached
             * the old USB instance. Do not turn that normal reset path into
             * a warning.
             */
            if error != rusb::Error::NoDevice {
                eprintln!(
                    "warning: failed to release USB interface {}: {error}",
                    self.layout.interface
                );
            }
        }
    }
}

/// Return true when a 27c6:550a is currently visible to libusb.
///
/// Descriptor failures caused by a device disappearing mid-enumeration are
/// ignored; a later poll will observe the stable state.
fn goodix_550a_present() -> rusb::Result<bool> {
    for device in rusb::devices()?.iter() {
        let Ok(descriptor) = device.device_descriptor() else {
            continue;
        };

        if descriptor.vendor_id() == GOODIX_VID && descriptor.product_id() == GOODIX_550A_PID {
            return Ok(true);
        }
    }

    Ok(false)
}

fn sleep_until_next_poll(deadline: Instant) {
    let now = Instant::now();

    if now >= deadline {
        return;
    }

    thread::sleep(REENUMERATION_POLL_INTERVAL.min(deadline - now));
}

fn discover_layout(device: &Device<GlobalContext>) -> rusb::Result<UsbLayout> {
    let device_descriptor = device.device_descriptor()?;

    for config_index in 0..device_descriptor.num_configurations() {
        let config = device.config_descriptor(config_index)?;

        for interface in config.interfaces() {
            for descriptor in interface.descriptors() {
                if let Some(layout) = layout_from_interface(&descriptor) {
                    return Ok(layout);
                }
            }
        }
    }

    Err(rusb::Error::NotFound)
}

fn layout_from_interface(descriptor: &rusb::InterfaceDescriptor<'_>) -> Option<UsbLayout> {
    let mut bulk_in = None;
    let mut bulk_out = None;
    let mut max_packet_size = 0;

    for endpoint in descriptor.endpoint_descriptors() {
        if endpoint.transfer_type() != TransferType::Bulk {
            continue;
        }

        max_packet_size = max_packet_size.max(endpoint.max_packet_size());

        match endpoint.direction() {
            Direction::In => {
                bulk_in = Some(endpoint.address());
            }
            Direction::Out => {
                bulk_out = Some(endpoint.address());
            }
        }
    }

    Some(UsbLayout {
        interface: descriptor.interface_number(),
        bulk_in: bulk_in?,
        bulk_out: bulk_out?,
        max_packet_size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_ids_match_goodix_550a() {
        assert_eq!(GOODIX_VID, 0x27c6);
        assert_eq!(GOODIX_550A_PID, 0x550a);
    }

    #[test]
    fn reenumeration_poll_interval_is_shorter_than_vendor_bound() {
        assert!(REENUMERATION_POLL_INTERVAL < Duration::from_secs(10));
    }

    #[test]
    fn rusb_timeout_maps_to_backend_neutral_timeout() {
        let error = GoodixUsbError::from(rusb::Error::Timeout);

        assert_eq!(error.kind(), GoodixUsbErrorKind::Timeout);
        assert_eq!(error.to_string(), rusb::Error::Timeout.to_string());
    }

    #[test]
    fn rusb_ownership_errors_keep_actionable_classification() {
        assert_eq!(
            GoodixUsbError::from(rusb::Error::Busy).kind(),
            GoodixUsbErrorKind::Busy
        );
        assert_eq!(
            GoodixUsbError::from(rusb::Error::NoDevice).kind(),
            GoodixUsbErrorKind::NoDevice
        );
        assert_eq!(
            GoodixUsbError::from(rusb::Error::NotFound).kind(),
            GoodixUsbErrorKind::NotFound
        );
    }
}
