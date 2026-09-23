use crate::private_file::open_private_file;

use std::{
    cell::RefCell,
    fmt::{self, Write as _},
    fs::File,
    io::{self, BufWriter, Write},
    path::Path,
    rc::Rc,
    time::Instant,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Direction {
    In,
    Out,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::In => f.write_str("IN"),
            Self::Out => f.write_str("OUT"),
        }
    }
}

struct TraceState {
    start: Instant,
    writer: Option<BufWriter<File>>,
}

/// One trace session that can survive destruction/recreation of a transport.
///
/// Cloning `TraceLogger` does NOT reopen the trace path. Every clone shares:
///
/// - the same start timestamp;
/// - the same already-open file;
/// - the same append position.
///
/// This is important for Goodix firmware bootstrap because `McuResetMcu`
/// destroys the old USB device/transport. A clone retained by the bootstrap
/// orchestrator can then be moved into the transport for the re-enumerated
/// APP device without reopening the trace path and truncating the IAP
/// portion of the trace.
///
/// The driver is currently single-threaded, so `Rc<RefCell<_>>` is sufficient
/// and avoids pretending this logger is a cross-thread synchronization
/// primitive.
#[derive(Clone)]
pub(crate) struct TraceLogger {
    state: Rc<RefCell<TraceState>>,
}

impl TraceLogger {
    /// Start a new trace session.
    ///
    /// If `path` is present this intentionally truncates/creates it exactly
    /// once, at the beginning of the session. Cloning this logger never
    /// touches the path again.
    pub(crate) fn new(path: Option<&Path>) -> io::Result<Self> {
        let writer = path.map(open_private_file).transpose()?.map(BufWriter::new);

        Ok(Self {
            state: Rc::new(RefCell::new(TraceState {
                start: Instant::now(),
                writer,
            })),
        })
    }

    /// Create a trace sink that performs no file output.
    ///
    /// Production driver sessions use this mode so protocol tracing never
    /// becomes an observable side effect of enrollment or verification.
    pub(crate) fn quiet() -> Self {
        Self {
            state: Rc::new(RefCell::new(TraceState {
                start: Instant::now(),
                writer: None,
            })),
        }
    }

    pub(crate) fn transfer(
        &self,
        direction: Direction,
        endpoint: u8,
        data: &[u8],
    ) -> io::Result<()> {
        let elapsed = self.elapsed_seconds();

        if self.has_writer() {
            let line = format!(
                "[{elapsed:10.6}] {direction:<3} \
                 ep=0x{endpoint:02x} len={} data={}",
                data.len(),
                encode_hex(data),
            );

            self.write_line(&line)?;
        }

        Ok(())
    }

    pub(crate) fn timeout(&self, endpoint: u8) -> io::Result<()> {
        if !self.has_writer() {
            return Ok(());
        }

        let elapsed = self.elapsed_seconds();

        let line = format!("[{elapsed:10.6}] IN  ep=0x{endpoint:02x} timeout");

        self.write_line(&line)
    }

    pub(crate) fn usb_error(&self, operation: &str, error: &dyn fmt::Display) -> io::Result<()> {
        let elapsed = self.elapsed_seconds();

        let line = format!("[{elapsed:10.6}] ERROR {operation}: {error}");

        if self.has_writer() {
            self.write_line(&line)?;
        }

        Ok(())
    }

    /// Add a non-transfer event to the same continuous trace timeline.
    ///
    /// This is useful around USB reset/re-enumeration where no bulk endpoint
    /// transfer exists to represent events such as "old device dropped" or
    /// "new APP device reopened".
    pub(crate) fn event(&self, message: &str) -> io::Result<()> {
        let elapsed = self.elapsed_seconds();

        let line = format!("[{elapsed:10.6}] EVENT {message}");

        if self.has_writer() {
            self.write_line(&line)?;
        }

        Ok(())
    }

    fn elapsed_seconds(&self) -> f64 {
        self.state.borrow().start.elapsed().as_secs_f64()
    }

    fn has_writer(&self) -> bool {
        self.state.borrow().writer.is_some()
    }

    fn write_line(&self, line: &str) -> io::Result<()> {
        let mut state = self.state.borrow_mut();

        let Some(writer) = state.writer.as_mut() else {
            return Ok(());
        };

        writeln!(writer, "{line}")?;
        writer.flush()
    }
}

fn encode_hex(data: &[u8]) -> String {
    let mut output = String::with_capacity(data.len() * 2);

    for byte in data {
        write!(&mut output, "{byte:02x}").expect("formatting into a String cannot fail");
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn hex_encoding_is_lowercase_and_contiguous() {
        assert_eq!(encode_hex(&[0x00, 0x01, 0xA0, 0xFF]), "0001a0ff");
    }

    #[test]
    fn cloned_loggers_share_one_file_without_truncation() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        let path = std::env::temp_dir().join(format!(
            "goodix-trace-clone-{}-{unique}.log",
            std::process::id()
        ));

        let first = TraceLogger::new(Some(&path)).unwrap();
        let second = first.clone();

        first.event("IAP before reset").unwrap();
        second.event("APP after re-enumeration").unwrap();

        drop(first);
        drop(second);

        let trace = fs::read_to_string(&path).unwrap();

        assert!(trace.contains("EVENT IAP before reset"));
        assert!(trace.contains("EVENT APP after re-enumeration"));

        fs::remove_file(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn trace_file_is_created_with_private_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        let path = std::env::temp_dir().join(format!(
            "goodix-private-trace-{}-{unique}.log",
            std::process::id()
        ));

        let trace = TraceLogger::new(Some(&path)).unwrap();
        trace.event("private trace").unwrap();
        drop(trace);

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;

        assert_eq!(mode, 0o600);

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn quiet_logger_has_no_file_sink() {
        let trace = TraceLogger::quiet();

        assert!(!trace.has_writer());
        trace.transfer(Direction::Out, 0x01, &[0xa0, 0x00]).unwrap();
        trace.event("quiet event").unwrap();
    }
}
