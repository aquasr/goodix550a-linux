use std::error::Error;
use std::fmt;
use std::time::Duration;

/// Bytes prepended by WriteApp before the actual APP firmware.
pub const TRANSFER_HEADER_LEN: usize = 12;

/// Final CRC stored in the proprietary embedded firmware blob.
pub const BLOB_CRC_LEN: usize = 4;

/// Firmware type passed by WriteApp to _WriteFw for APP firmware.
pub const APP_FIRMWARE_TYPE: u32 = 2;

/// Header placed in front of each chunk by `_WriteFw`.
///
/// Exact F0 command payload:
///
/// ```text
/// +0x00  u32 LE package_offset
/// +0x04  u32 LE chunk_length
/// +0x08  u32 LE firmware_type
/// +0x0c  chunk bytes
/// ```
pub const F0_PAYLOAD_HEADER_LEN: usize = 12;

/// Maximum firmware-package data bytes carried by one F0 command.
///
/// `_WriteFw` sends:
///
/// ```text
/// u32 offset
/// u32 chunk_length
/// u32 firmware_type
/// data[chunk_length]
/// ```
///
/// with chunk_length <= 0x100.
pub const F0_MAX_CHUNK_DATA: usize = 0x100;

/// HMAC-SHA256 tag length sent by WriteApp with command F4.
pub const F4_TAG_LEN: usize = 0x20;

/// Firmware commands issued by the WriteApp transfer stage.
///
/// This deliberately models only the two commands used after the APP
/// transfer package has already been built:
///
/// - F0 writes one package chunk.
/// - F4 verifies/authenticates the complete package.
///
/// Mapping these values to the protocol-level `Command` enum belongs to
/// the live transport caller, not to this offline firmware module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirmwareTransferCommand {
    F0Write,
    F4Check,
}

/// Successful result of the F0 -> F4 portion of vendor WriteApp.
///
/// This stage intentionally stops before McuResetMcu / USB re-enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteAppTransferResult {
    pub f0_chunks_sent: usize,
    pub firmware_check_result: u8,
}

/// Error returned by the F0 -> F4 WriteApp transfer stage.
///
/// `E` is the caller's transport error type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteAppTransferError<E> {
    Transport(E),

    /// The recovered GM168SEC F4 completion contains exactly one result byte.
    MalformedFirmwareCheckResponse {
        payload_len: usize,
    },

    /// Vendor WriteApp treats result byte 0 as firmware-check failure.
    FirmwareCheckRejected {
        result: u8,
    },
}

impl<E: fmt::Display> fmt::Display for WriteAppTransferError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => {
                write!(f, "firmware transport error: {error}")
            }

            Self::MalformedFirmwareCheckResponse { payload_len } => {
                write!(
                    f,
                    "malformed F4 completion: expected exactly one result byte, \
                     received {payload_len}"
                )
            }

            Self::FirmwareCheckRejected { result } => {
                write!(
                    f,
                    "firmware F4 check rejected the APP package with result \
                     0x{result:02x}"
                )
            }
        }
    }
}

impl<E> Error for WriteAppTransferError<E>
where
    E: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirmwareError {
    BlobTooShort {
        size: usize,
    },

    PrefixOutOfBounds {
        prefix_size: usize,
        blob_size: usize,
    },

    EmptyApp,

    BlobCrcMismatch {
        expected: u32,
        computed: u32,
    },

    AppTooLarge {
        size: usize,
    },

    PackageTooLarge {
        size: usize,
    },
}

impl fmt::Display for FirmwareError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BlobTooShort { size } => {
                write!(f, "firmware blob is too short: {size} bytes")
            }

            Self::PrefixOutOfBounds {
                prefix_size,
                blob_size,
            } => {
                write!(
                    f,
                    "firmware metadata prefix extends past blob: \
                     prefix size {prefix_size}, blob size {blob_size}"
                )
            }

            Self::EmptyApp => {
                write!(f, "firmware blob contains no APP payload")
            }

            Self::BlobCrcMismatch { expected, computed } => {
                write!(
                    f,
                    "firmware blob CRC mismatch: \
                     stored 0x{expected:08x}, \
                     computed 0x{computed:08x}"
                )
            }

            Self::AppTooLarge { size } => {
                write!(
                    f,
                    "APP firmware is too large for the vendor \
                     u32 format: {size} bytes"
                )
            }

            Self::PackageTooLarge { size } => {
                write!(
                    f,
                    "APP transfer package is too large for \
                     32-bit firmware offsets: {size} bytes"
                )
            }
        }
    }
}

impl Error for FirmwareError {}

/// Parsed proprietary Goodix APP firmware resource.
///
/// Vendor blob:
///
/// ```text
/// +0x00       u8 metadata_len
/// +0x01       metadata[metadata_len]
///             APP firmware bytes
/// last 4      LE32(CRC32_MPEG2(all previous blob bytes))
/// ```
///
/// WriteApp computes:
///
/// ```text
/// prefix_size = blob[0] + 1
/// app = blob[prefix_size .. blob.len() - 4]
/// ```
#[derive(Debug, Clone, Copy)]
pub struct FirmwareBlob<'a> {
    raw: &'a [u8],
    prefix_size: usize,
    app: &'a [u8],
    stored_crc: u32,
}

impl<'a> FirmwareBlob<'a> {
    /// Parse and CRC-validate a proprietary Goodix APP blob.
    pub fn parse(raw: &'a [u8]) -> Result<Self, FirmwareError> {
        if raw.len() < 1 + BLOB_CRC_LEN {
            return Err(FirmwareError::BlobTooShort { size: raw.len() });
        }

        /*
         * WriteApp:
         *
         *     MOVZX EDI, byte ptr [R14]
         *     MOV   ESI, 1
         *     CALL  checked_add
         *
         * Therefore blob[0] is unsigned.
         */
        let prefix_size = usize::from(raw[0]) + 1;

        let crc_offset = raw.len() - BLOB_CRC_LEN;

        if prefix_size > crc_offset {
            return Err(FirmwareError::PrefixOutOfBounds {
                prefix_size,
                blob_size: raw.len(),
            });
        }

        let stored_crc = u32::from_le_bytes(
            raw[crc_offset..]
                .try_into()
                .expect("CRC slice is exactly four bytes"),
        );

        let computed_crc = crc32_mpeg2(&raw[..crc_offset]);

        if stored_crc != computed_crc {
            return Err(FirmwareError::BlobCrcMismatch {
                expected: stored_crc,
                computed: computed_crc,
            });
        }

        let app = &raw[prefix_size..crc_offset];

        if app.is_empty() {
            return Err(FirmwareError::EmptyApp);
        }

        Ok(Self {
            raw,
            prefix_size,
            app,
            stored_crc,
        })
    }

    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }

    pub fn metadata_length(&self) -> usize {
        self.prefix_size - 1
    }

    pub fn prefix_size(&self) -> usize {
        self.prefix_size
    }

    pub fn prefix(&self) -> &'a [u8] {
        &self.raw[..self.prefix_size]
    }

    pub fn metadata(&self) -> &'a [u8] {
        &self.raw[1..self.prefix_size]
    }

    pub fn app(&self) -> &'a [u8] {
        self.app
    }

    pub fn stored_crc(&self) -> u32 {
        self.stored_crc
    }

    pub fn computed_crc(&self) -> u32 {
        crc32_mpeg2(&self.raw[..self.raw.len() - BLOB_CRC_LEN])
    }
}

/// Package constructed by vendor WriteApp before `_WriteFw` divides
/// it into F0 transfers.
///
/// Exact layout:
///
/// ```text
/// +0x00  u32 LE header_crc
/// +0x04  u32 LE app_len
/// +0x08  u32 LE app_crc
/// +0x0c  APP firmware bytes
/// ```
///
/// where:
///
/// ```text
/// app_crc = CRC32_MPEG2(app)
///
/// header_crc = CRC32_MPEG2(
///     LE32(app_len) || LE32(app_crc)
/// )
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppTransferPackage {
    bytes: Vec<u8>,
    app_len: u32,
    app_crc: u32,
    header_crc: u32,
}

impl AppTransferPackage {
    pub fn build(blob: &FirmwareBlob<'_>) -> Result<Self, FirmwareError> {
        Self::from_app(blob.app())
    }

    pub fn from_app(app: &[u8]) -> Result<Self, FirmwareError> {
        if app.is_empty() {
            return Err(FirmwareError::EmptyApp);
        }

        let app_len =
            u32::try_from(app.len()).map_err(|_| FirmwareError::AppTooLarge { size: app.len() })?;

        let package_len = TRANSFER_HEADER_LEN
            .checked_add(app.len())
            .ok_or(FirmwareError::PackageTooLarge { size: usize::MAX })?;

        /*
         * `_WriteFw` uses 32-bit package offsets.
         *
         * The real GM168SEC package is tiny compared with this
         * boundary, but keep the representation faithful.
         */
        if package_len > u32::MAX as usize {
            return Err(FirmwareError::PackageTooLarge { size: package_len });
        }

        let app_crc = crc32_mpeg2(app);

        let mut crc_header = [0u8; 8];

        crc_header[0..4].copy_from_slice(&app_len.to_le_bytes());

        crc_header[4..8].copy_from_slice(&app_crc.to_le_bytes());

        let header_crc = crc32_mpeg2(&crc_header);

        let mut bytes = Vec::with_capacity(package_len);

        bytes.extend_from_slice(&header_crc.to_le_bytes());

        bytes.extend_from_slice(&app_len.to_le_bytes());

        bytes.extend_from_slice(&app_crc.to_le_bytes());

        bytes.extend_from_slice(app);

        debug_assert_eq!(bytes.len(), TRANSFER_HEADER_LEN + app.len());

        Ok(Self {
            bytes,
            app_len,
            app_crc,
            header_crc,
        })
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn app_len(&self) -> u32 {
        self.app_len
    }

    pub fn app_crc(&self) -> u32 {
        self.app_crc
    }

    pub fn header_crc(&self) -> u32 {
        self.header_crc
    }

    pub fn app(&self) -> &[u8] {
        &self.bytes[TRANSFER_HEADER_LEN..]
    }

    /// Number of F0 commands `_WriteFw` must issue for this package.
    pub fn f0_chunk_count(&self) -> usize {
        self.bytes.len().div_ceil(F0_MAX_CHUNK_DATA)
    }

    /// Divide the package exactly as `_WriteFw` does.
    ///
    /// This is offline only. No USB operation occurs.
    pub fn chunks(&self) -> impl Iterator<Item = FirmwareChunk<'_>> {
        self.bytes
            .chunks(F0_MAX_CHUNK_DATA)
            .enumerate()
            .map(|(index, data)| FirmwareChunk {
                offset: (index * F0_MAX_CHUNK_DATA) as u32,

                firmware_type: APP_FIRMWARE_TYPE,

                data,
            })
    }

    /// Produce every exact F0 payload that `_WriteFw` would pass to
    /// IoHubMcuSendCmd2.
    ///
    /// These are command PAYLOADS only:
    ///
    /// ```text
    /// offset || length || firmware_type || chunk
    /// ```
    ///
    /// They are NOT A0-framed and they are NOT transmitted.
    pub fn f0_payloads(&self) -> impl Iterator<Item = Vec<u8>> + '_ {
        self.chunks().map(|chunk| chunk.f0_payload())
    }
}

/// Execute only the F0 -> F4 transfer/check portion of Geneva WriteApp.
///
/// The caller supplies the already-derived 32-byte F4 HMAC tag and a
/// transaction callback. This keeps firmware package construction and
/// WriteApp sequencing independent from any particular USB implementation.
///
/// Proven vendor semantics reproduced here:
///
/// 1. Send every package chunk with F0 in order.
/// 2. A successful F0 transaction is enough; the F0 completion payload is
///    deliberately ignored.
/// 3. After every F0 succeeds, send the 32-byte tag with F4.
/// 4. For GM168SEC APP 15045 the F4 completion payload is one result byte.
/// 5. Result 0 means failure; any non-zero result means success.
///
/// This function does NOT:
///
/// - derive the F4 tag;
/// - read or provision a PSK;
/// - send A2 / McuResetMcu;
/// - wait for USB detach/attach;
/// - reopen the USB device;
/// - verify the post-reset APP version or chip ID.
///
/// Those operations belong to the higher-level cold-bootstrap state machine.
#[allow(dead_code)]
pub fn write_app_transfer<E, F>(
    package: &AppTransferPackage,
    f4_tag: &[u8; F4_TAG_LEN],
    f0_timeout: Duration,
    f4_timeout: Duration,
    mut transact: F,
) -> Result<WriteAppTransferResult, WriteAppTransferError<E>>
where
    F: FnMut(FirmwareTransferCommand, &[u8], Duration) -> Result<Vec<u8>, E>,
{
    let mut f0_chunks_sent = 0usize;

    for chunk in package.chunks() {
        let payload = chunk.f0_payload();

        /*
         * Vendor _WriteFw only checks IoHubMcuSendCmd2's success/failure.
         * It supplies no output buffer, so the parsed F0 completion byte is
         * discarded. Do the same here: require a successful transaction but
         * do not inspect the completion payload.
         */
        let _completion = transact(FirmwareTransferCommand::F0Write, &payload, f0_timeout)
            .map_err(WriteAppTransferError::Transport)?;

        f0_chunks_sent += 1;
    }

    debug_assert_eq!(f0_chunks_sent, package.f0_chunk_count());

    let f4_completion = transact(FirmwareTransferCommand::F4Check, f4_tag, f4_timeout)
        .map_err(WriteAppTransferError::Transport)?;

    let [result] = f4_completion.as_slice() else {
        return Err(WriteAppTransferError::MalformedFirmwareCheckResponse {
            payload_len: f4_completion.len(),
        });
    };

    if *result == 0 {
        return Err(WriteAppTransferError::FirmwareCheckRejected { result: *result });
    }

    Ok(WriteAppTransferResult {
        f0_chunks_sent,
        firmware_check_result: *result,
    })
}

/// One package-data chunk consumed by `_WriteFw`.
///
/// Eventual F0 payload:
///
/// ```text
/// +0x00 u32 LE package_offset
/// +0x04 u32 LE chunk_length
/// +0x08 u32 LE firmware_type = 2
/// +0x0c chunk bytes
/// ```
///
/// This structure cannot perform USB I/O.
#[derive(Debug, Clone, Copy)]
pub struct FirmwareChunk<'a> {
    offset: u32,
    firmware_type: u32,
    data: &'a [u8],
}

impl<'a> FirmwareChunk<'a> {
    pub fn offset(&self) -> u32 {
        self.offset
    }

    pub fn length(&self) -> u32 {
        self.data.len() as u32
    }

    pub fn firmware_type(&self) -> u32 {
        self.firmware_type
    }

    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    /// Total size of the command payload after adding the `_WriteFw`
    /// 12-byte per-chunk header.
    pub fn f0_payload_len(&self) -> usize {
        F0_PAYLOAD_HEADER_LEN + self.data.len()
    }

    /// Construct the exact payload passed to command F0.
    ///
    /// No A0 framing and no USB operation are performed.
    pub fn f0_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(self.f0_payload_len());

        payload.extend_from_slice(&self.offset.to_le_bytes());

        payload.extend_from_slice(&self.length().to_le_bytes());

        payload.extend_from_slice(&self.firmware_type.to_le_bytes());

        payload.extend_from_slice(self.data);

        debug_assert_eq!(payload.len(), self.f0_payload_len());

        payload
    }
}

/// Goodix CRC used by CheckFirmware and WriteApp.
///
/// Parameters:
///
/// ```text
/// width   = 32
/// poly    = 0x04C11DB7
/// init    = 0xFFFFFFFF
/// refin   = false
/// refout  = false
/// xorout  = 0
/// ```
///
/// This is CRC-32/MPEG-2.
pub fn crc32_mpeg2(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;

    for &byte in data {
        crc ^= u32::from(byte) << 24;

        for _ in 0..8 {
            crc = if (crc & 0x8000_0000) != 0 {
                (crc << 1) ^ 0x04c1_1db7
            } else {
                crc << 1
            };
        }
    }

    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_mpeg2_known_vector() {
        assert_eq!(crc32_mpeg2(b"123456789"), 0x0376_e6e7);
    }

    #[test]
    fn parses_valid_blob() {
        let metadata = [0xaa, 0xbb, 0xcc];

        let app = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];

        let mut blob = Vec::new();

        blob.push(metadata.len() as u8);

        blob.extend_from_slice(&metadata);

        blob.extend_from_slice(&app);

        let crc = crc32_mpeg2(&blob);

        blob.extend_from_slice(&crc.to_le_bytes());

        let parsed = FirmwareBlob::parse(&blob).unwrap();

        assert_eq!(parsed.metadata_length(), 3);

        assert_eq!(parsed.prefix_size(), 4);

        assert_eq!(parsed.metadata(), metadata);

        assert_eq!(parsed.app(), app);

        assert_eq!(parsed.stored_crc(), crc);

        assert_eq!(parsed.computed_crc(), crc);
    }

    #[test]
    fn rejects_bad_outer_crc() {
        let mut blob = vec![0x01, 0xaa, 0x10, 0x20, 0x30, 0x40];

        let crc = crc32_mpeg2(&blob);

        blob.extend_from_slice(&crc.to_le_bytes());

        blob[3] ^= 0xff;

        let err = FirmwareBlob::parse(&blob).unwrap_err();

        assert!(matches!(err, FirmwareError::BlobCrcMismatch { .. }));
    }

    #[test]
    fn rejects_prefix_past_payload() {
        let mut blob = vec![0xff, 0x01, 0x02];

        let crc = crc32_mpeg2(&blob);

        blob.extend_from_slice(&crc.to_le_bytes());

        let err = FirmwareBlob::parse(&blob).unwrap_err();

        assert!(matches!(err, FirmwareError::PrefixOutOfBounds { .. }));
    }

    #[test]
    fn builds_exact_transfer_header() {
        let app = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        let package = AppTransferPackage::from_app(&app).unwrap();

        let app_crc = crc32_mpeg2(&app);

        let mut expected_header_input = [0u8; 8];

        expected_header_input[0..4].copy_from_slice(&(app.len() as u32).to_le_bytes());

        expected_header_input[4..8].copy_from_slice(&app_crc.to_le_bytes());

        let header_crc = crc32_mpeg2(&expected_header_input);

        assert_eq!(&package.bytes()[0..4], &header_crc.to_le_bytes());

        assert_eq!(&package.bytes()[4..8], &(app.len() as u32).to_le_bytes());

        assert_eq!(&package.bytes()[8..12], &app_crc.to_le_bytes());

        assert_eq!(&package.bytes()[12..], &app);

        assert_eq!(package.header_crc(), header_crc);

        assert_eq!(package.app_crc(), app_crc);

        assert_eq!(package.app_len(), app.len() as u32);
    }

    #[test]
    fn chunks_match_writefw_boundaries() {
        let app = vec![0x5a; 600];

        let package = AppTransferPackage::from_app(&app).unwrap();

        let chunks: Vec<_> = package.chunks().collect();

        assert_eq!(chunks.len(), 3);

        assert_eq!(chunks[0].offset(), 0x000);

        assert_eq!(chunks[0].length(), 0x100);

        assert_eq!(chunks[0].firmware_type(), 2);

        assert_eq!(chunks[1].offset(), 0x100);

        assert_eq!(chunks[1].length(), 0x100);

        assert_eq!(chunks[1].firmware_type(), 2);

        assert_eq!(chunks[2].offset(), 0x200);

        assert_eq!(chunks[2].length(), (package.len() - 0x200) as u32);

        assert_eq!(chunks[2].firmware_type(), 2);

        let reconstructed: Vec<u8> = chunks
            .iter()
            .flat_map(|chunk| chunk.data().iter().copied())
            .collect();

        assert_eq!(reconstructed, package.bytes());
    }

    #[test]
    fn f0_payload_matches_writefw_layout() {
        let app = vec![0x5a; 300];

        let package = AppTransferPackage::from_app(&app).unwrap();

        let first = package.chunks().next().unwrap();

        let payload = first.f0_payload();

        assert_eq!(payload.len(), 12 + 0x100);

        assert_eq!(&payload[0..4], &0u32.to_le_bytes());

        assert_eq!(&payload[4..8], &0x100u32.to_le_bytes());

        assert_eq!(&payload[8..12], &APP_FIRMWARE_TYPE.to_le_bytes());

        assert_eq!(&payload[12..], first.data());
    }

    #[test]
    fn gm168sec_package_has_98_f0_chunks() {
        /*
         * Real GFUSB_GM168SEC_APP_15045:
         *
         * APP     = 0x6100 bytes
         * package = 0x610c bytes
         *
         * Therefore:
         *
         * 97 complete 0x100-byte chunks
         * + one final 0x0c-byte chunk
         * = 98 F0 transfers.
         *
         * The contents here are synthetic; this test validates only
         * the already-recovered transfer boundaries.
         */
        let app = vec![0u8; 0x6100];

        let package = AppTransferPackage::from_app(&app).unwrap();

        assert_eq!(package.len(), 0x610c);

        assert_eq!(package.f0_chunk_count(), 98);

        let chunks: Vec<_> = package.chunks().collect();

        let first = chunks.first().unwrap();

        let last = chunks.last().unwrap();

        assert_eq!(first.offset(), 0x0000);

        assert_eq!(first.length(), 0x100);

        assert_eq!(last.offset(), 0x6100);

        assert_eq!(last.length(), 0x0c);

        assert_eq!(last.firmware_type(), 2);
    }

    #[test]
    fn final_gm168sec_f0_header_is_exact() {
        let app = vec![0u8; 0x6100];

        let package = AppTransferPackage::from_app(&app).unwrap();

        let last = package.chunks().last().unwrap();

        let payload = last.f0_payload();

        assert_eq!(
            &payload[..12],
            &[
                // package offset = 0x6100
                0x00, 0x61, 0x00, 0x00, // final length = 0x0c
                0x0c, 0x00, 0x00, 0x00, // firmware type = APP = 2
                0x02, 0x00, 0x00, 0x00,
            ]
        );

        assert_eq!(payload.len(), 12 + 0x0c);
    }

    #[test]
    fn f0_payload_iterator_reconstructs_all_chunks() {
        let app = vec![0x42; 900];

        let package = AppTransferPackage::from_app(&app).unwrap();

        let payloads: Vec<_> = package.f0_payloads().collect();

        assert_eq!(payloads.len(), package.f0_chunk_count());

        for (chunk, payload) in package.chunks().zip(payloads.iter()) {
            assert_eq!(payload.len(), F0_PAYLOAD_HEADER_LEN + chunk.data().len());

            assert_eq!(&payload[0..4], &chunk.offset().to_le_bytes());

            assert_eq!(&payload[4..8], &chunk.length().to_le_bytes());

            assert_eq!(&payload[8..12], &chunk.firmware_type().to_le_bytes());

            assert_eq!(&payload[12..], chunk.data());
        }
    }

    #[test]
    fn write_app_transfer_sends_98_f0_then_f4() {
        use std::convert::Infallible;

        let app = vec![0u8; 0x6100];
        let package = AppTransferPackage::from_app(&app).unwrap();
        let f4_tag = [0x5au8; F4_TAG_LEN];

        let f0_timeout = Duration::from_millis(111);
        let f4_timeout = Duration::from_millis(222);

        let mut calls: Vec<(FirmwareTransferCommand, Vec<u8>, Duration)> = Vec::new();

        let result = write_app_transfer(
            &package,
            &f4_tag,
            f0_timeout,
            f4_timeout,
            |command, payload, timeout| -> Result<Vec<u8>, Infallible> {
                calls.push((command, payload.to_vec(), timeout));

                Ok(match command {
                    // Deliberately return zero for F0. WriteApp ignores it.
                    FirmwareTransferCommand::F0Write => vec![0x00],
                    FirmwareTransferCommand::F4Check => vec![0x01],
                })
            },
        )
        .unwrap();

        assert_eq!(result.f0_chunks_sent, 98);
        assert_eq!(result.firmware_check_result, 0x01);

        assert_eq!(calls.len(), 99);

        for (index, (command, payload, timeout)) in calls[..98].iter().enumerate() {
            assert_eq!(*command, FirmwareTransferCommand::F0Write);
            assert_eq!(*timeout, f0_timeout);

            let expected_offset = (index * F0_MAX_CHUNK_DATA) as u32;
            assert_eq!(&payload[0..4], &expected_offset.to_le_bytes());
            assert_eq!(&payload[8..12], &APP_FIRMWARE_TYPE.to_le_bytes());
        }

        let first = &calls[0].1;
        assert_eq!(&first[0..4], &0u32.to_le_bytes());
        assert_eq!(&first[4..8], &0x100u32.to_le_bytes());

        let last = &calls[97].1;
        assert_eq!(&last[0..4], &0x6100u32.to_le_bytes());
        assert_eq!(&last[4..8], &0x0cu32.to_le_bytes());
        assert_eq!(last.len(), F0_PAYLOAD_HEADER_LEN + 0x0c);

        let (command, payload, timeout) = &calls[98];
        assert_eq!(*command, FirmwareTransferCommand::F4Check);
        assert_eq!(*timeout, f4_timeout);
        assert_eq!(payload.as_slice(), &f4_tag[..]);
    }

    #[test]
    fn write_app_transfer_accepts_any_nonzero_f4_result() {
        use std::convert::Infallible;

        let package = AppTransferPackage::from_app(&[0x11]).unwrap();
        let f4_tag = [0u8; F4_TAG_LEN];

        let result = write_app_transfer(
            &package,
            &f4_tag,
            Duration::from_secs(1),
            Duration::from_secs(1),
            |command, _payload, _timeout| -> Result<Vec<u8>, Infallible> {
                Ok(match command {
                    FirmwareTransferCommand::F0Write => vec![],
                    FirmwareTransferCommand::F4Check => vec![0x7f],
                })
            },
        )
        .unwrap();

        assert_eq!(result.firmware_check_result, 0x7f);
    }

    #[test]
    fn write_app_transfer_rejects_zero_f4_result() {
        use std::convert::Infallible;

        let package = AppTransferPackage::from_app(&[0x11]).unwrap();
        let f4_tag = [0u8; F4_TAG_LEN];

        let error = write_app_transfer(
            &package,
            &f4_tag,
            Duration::from_secs(1),
            Duration::from_secs(1),
            |command, _payload, _timeout| -> Result<Vec<u8>, Infallible> {
                Ok(match command {
                    FirmwareTransferCommand::F0Write => vec![0xaa],
                    FirmwareTransferCommand::F4Check => vec![0x00],
                })
            },
        )
        .unwrap_err();

        assert!(matches!(
            error,
            WriteAppTransferError::FirmwareCheckRejected { result: 0x00 }
        ));
    }

    #[test]
    fn write_app_transfer_rejects_malformed_f4_completion() {
        use std::convert::Infallible;

        let package = AppTransferPackage::from_app(&[0x11]).unwrap();
        let f4_tag = [0u8; F4_TAG_LEN];

        for malformed in [Vec::new(), vec![0x01, 0x02]] {
            let error = write_app_transfer(
                &package,
                &f4_tag,
                Duration::from_secs(1),
                Duration::from_secs(1),
                |command, _payload, _timeout| -> Result<Vec<u8>, Infallible> {
                    Ok(match command {
                        FirmwareTransferCommand::F0Write => vec![0x00],
                        FirmwareTransferCommand::F4Check => malformed.clone(),
                    })
                },
            )
            .unwrap_err();

            assert!(matches!(
                error,
                WriteAppTransferError::MalformedFirmwareCheckResponse { .. }
            ));
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct MockTransportError;

    impl fmt::Display for MockTransportError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("mock transport failure")
        }
    }

    impl Error for MockTransportError {}

    #[test]
    fn write_app_transfer_stops_on_first_f0_transport_error() {
        let app = vec![0x42; 600];
        let package = AppTransferPackage::from_app(&app).unwrap();
        let f4_tag = [0u8; F4_TAG_LEN];

        let mut f0_calls = 0usize;
        let mut f4_called = false;

        let error = write_app_transfer(
            &package,
            &f4_tag,
            Duration::from_secs(1),
            Duration::from_secs(1),
            |command, _payload, _timeout| match command {
                FirmwareTransferCommand::F0Write => {
                    f0_calls += 1;

                    if f0_calls == 2 {
                        return Err(MockTransportError);
                    }

                    Ok(vec![0xff])
                }

                FirmwareTransferCommand::F4Check => {
                    f4_called = true;
                    Ok(vec![0x01])
                }
            },
        )
        .unwrap_err();

        assert!(matches!(
            error,
            WriteAppTransferError::Transport(MockTransportError)
        ));
        assert_eq!(f0_calls, 2);
        assert!(!f4_called);
    }
}
