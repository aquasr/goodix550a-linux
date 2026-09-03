use std::{
    cell::RefCell,
    fmt::{self, Write as _},
    fs::File,
    io::{self, BufWriter, Write},
    path::Path,
    rc::Rc,
    time::Instant,
};

const CONSOLE_FULL_LIMIT: usize = 128;
const CONSOLE_PREVIEW_LEN: usize = 64;

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
    console: bool,
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
/// APP device without calling `File::create()` again and truncating the IAP
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
        let writer = path.map(File::create).transpose()?.map(BufWriter::new);

        Ok(Self {
            state: Rc::new(RefCell::new(TraceState {
                start: Instant::now(),
                writer,
                console: true,
            })),
        })
    }

    /// Create a trace sink that performs no console or file output.
    ///
    /// Production driver sessions use this mode so protocol tracing never
    /// becomes an observable side effect of enrollment or verification.
    pub(crate) fn quiet() -> Self {
        Self {
            state: Rc::new(RefCell::new(TraceState {
                start: Instant::now(),
                writer: None,
                console: false,
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

        if self.console_enabled() {
            print_transfer(elapsed, direction, endpoint, data);
        }

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

        if self.console_enabled() {
            eprintln!("{line}");
        }

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
    #[allow(dead_code)]
    pub(crate) fn event(&self, message: &str) -> io::Result<()> {
        let elapsed = self.elapsed_seconds();

        let line = format!("[{elapsed:10.6}] EVENT {message}");

        if self.console_enabled() {
            println!("{line}");
        }

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

    fn console_enabled(&self) -> bool {
        self.state.borrow().console
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

fn print_transfer(elapsed: f64, direction: Direction, endpoint: u8, data: &[u8]) {
    if data.len() <= CONSOLE_FULL_LIMIT {
        println!(
            "[{elapsed:10.6}] {direction:<3} \
             ep=0x{endpoint:02x} len={} data={}",
            data.len(),
            encode_hex(data),
        );

        return;
    }

    let preview = &data[..data.len().min(CONSOLE_PREVIEW_LEN)];

    println!(
        "[{elapsed:10.6}] {direction:<3} \
         ep=0x{endpoint:02x} len={} data={}...",
        data.len(),
        encode_hex(preview),
    );
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
    fn direction_display_matches_trace_format() {
        assert_eq!(Direction::In.to_string(), "IN");
        assert_eq!(Direction::Out.to_string(), "OUT");
    }

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

    #[test]
    fn cloned_loggers_share_the_same_start_timestamp() {
        let first = TraceLogger::new(None).unwrap();
        let second = first.clone();

        assert!(Rc::ptr_eq(&first.state, &second.state));
    }

    #[test]
    fn quiet_logger_has_no_console_or_file_sink() {
        let trace = TraceLogger::quiet();

        assert!(!trace.console_enabled());
        assert!(!trace.has_writer());
        trace.transfer(Direction::Out, 0x01, &[0xa0, 0x00]).unwrap();
        trace.event("quiet event").unwrap();
    }
}
