use std::{
    io::Write,
    sync::Once,
    time::{SystemTime, UNIX_EPOCH},
};

use backtrace::Backtrace;
use flux::utils::thread_boot;
use tracing::{error, level_filters::LevelFilter};
use tracing_appender::{non_blocking::WorkerGuard, rolling::Rotation};
use tracing_subscriber::{
    EnvFilter,
    fmt::{format::Writer, time, time::FormatTime},
};

pub const DEFAULT_TRACING_ENV_FILTERS: [&str; 6] = [
    "hyper::proto::h1=off",
    "trust_dns_proto=off",
    "trust_dns_resolver=off",
    "discv5=off",
    "hyper_util=off",
    "reqwest=info",
];

const TRACING_APPENDER_THREAD: &str = "tracing-appender";
const SECS_PER_DAY: u64 = 24 * 60 * 60;
const ANSI_DIM: &str = "\x1b[2m";
const ANSI_GREEN: &str = "\x1b[32m";
const ANSI_RESET: &str = "\x1b[0m";

struct PinnedAppenderWriter<W> {
    inner: W,
    log_core: Option<usize>,
    booted: bool,
    rotation_header: Option<String>,
    header_day: Option<u64>,
}

impl<W> PinnedAppenderWriter<W> {
    fn new(inner: W, log_core: Option<usize>, rotation_header: Option<&str>) -> Self {
        Self {
            inner,
            log_core,
            booted: false,
            rotation_header: rotation_header.map(str::to_owned),
            header_day: None,
        }
    }

    fn boot(&mut self) {
        if self.booted {
            return;
        }
        self.booted = true;
        thread_boot(self.log_core.as_slice(), None);
    }
}

impl<W: Write> PinnedAppenderWriter<W> {
    fn write_header_on_new_day(&mut self) -> std::io::Result<()> {
        let Some(message) = &self.rotation_header else { return Ok(()) };
        let day = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() /
            SECS_PER_DAY;
        if self.header_day == Some(day) {
            return Ok(());
        }
        self.header_day = Some(day);

        // Byte-for-byte the fmt layer's `Full` format with thread names and
        // ansi on, so the line reads like every other INFO line in the file.
        let mut timestamp = String::new();
        time::SystemTime.format_time(&mut Writer::new(&mut timestamp)).ok();
        let target = module_path!();
        let line = format!(
            "{ANSI_DIM}{timestamp}{ANSI_RESET} {ANSI_GREEN} INFO{ANSI_RESET} \
             {TRACING_APPENDER_THREAD} {ANSI_DIM}{target}{ANSI_RESET}{ANSI_DIM}:{ANSI_RESET} \
             {message}\n"
        );
        self.inner.write_all(line.as_bytes())
    }
}

impl<W: Write> Write for PinnedAppenderWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.boot();
        self.write_header_on_new_day()?;
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.boot();
        self.inner.flush()
    }
}

/// Initialises tracing logger that creates daily log files. `rotation_header`
/// is logged at INFO as the first line of every file, at boot and at each
/// rotation.
pub fn initialise_tracing_log(
    filename_prefix: &str,
    max_log_files: usize,
    env_filters: Option<Vec<&str>>,
    use_stdout: bool,
    rotation_header: Option<&str>,
) -> Option<WorkerGuard> {
    initialise_tracing_log_on_core(
        filename_prefix,
        max_log_files,
        env_filters,
        use_stdout,
        None,
        rotation_header,
    )
}

pub fn initialise_tracing_log_on_core(
    filename_prefix: &str,
    max_log_files: usize,
    env_filters: Option<Vec<&str>>,
    use_stdout: bool,
    log_core: Option<usize>,
    rotation_header: Option<&str>,
) -> Option<WorkerGuard> {
    log_panics();
    let use_stdout = use_stdout || std::env::var("LOG_STDOUT").map(|_| true).unwrap_or(false);

    if use_stdout {
        tracing_subscriber::fmt()
            .with_env_filter(build_env_filter(env_filters))
            .with_thread_names(true)
            .init();
        if let Some(message) = rotation_header {
            tracing::info!("{message}");
        }
        None
    } else {
        let log_path = std::env::var("LOG_PATH").unwrap_or("/tmp/logs".into());

        let file_appender = tracing_appender::rolling::Builder::new()
            .filename_prefix(filename_prefix)
            .max_log_files(max_log_files)
            .rotation(Rotation::DAILY)
            .build(&log_path)
            .unwrap_or_else(|_| panic!("failed to create log appender! path: {log_path}"));

        let file_appender = PinnedAppenderWriter::new(file_appender, log_core, rotation_header);
        let (non_blocking, guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
            .thread_name(TRACING_APPENDER_THREAD)
            .finish(file_appender);
        tracing_subscriber::fmt()
            .with_env_filter(build_env_filter(env_filters))
            .with_thread_names(true)
            .with_writer(non_blocking)
            .init();
        Some(guard)
    }
}

fn log_panics() {
    static INSTALLED: Once = Once::new();
    INSTALLED.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            error!("{info}\nFull backtrace:\n{:?}", Backtrace::new());
            previous(info);
        }));
    });
}

pub fn initialise_test_tracing_logger() {
    initialise_test_tracing_logger_with_level(LevelFilter::DEBUG);
}

pub fn initialise_test_tracing_logger_with_level(level: LevelFilter) {
    log_panics();

    // Use try_init() to avoid panicking if the subscriber is already set
    // This allows multiple tests to call this function without failing
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_max_level(level)
        .with_thread_names(true)
        .with_file(true) // Enable file display
        .with_line_number(true) // Enable line number display
        .try_init(); // just console
}

/// Builds an environment filter for logging. Uses a default set of filters plus
/// some optional extras.
pub fn build_env_filter(env_filters: Option<Vec<&str>>) -> EnvFilter {
    // Without a default an unset `RUST_LOG` enables nothing, so a panicking
    // process would leave no record of why it stopped.
    let mut env_filter =
        EnvFilter::builder().with_default_directive(LevelFilter::ERROR.into()).from_env_lossy();

    for directive in DEFAULT_TRACING_ENV_FILTERS {
        env_filter = env_filter.add_directive(directive.parse().unwrap());
    }

    if let Some(env_filters) = env_filters {
        for directive in env_filters {
            if !DEFAULT_TRACING_ENV_FILTERS.contains(&directive) {
                env_filter = env_filter.add_directive(directive.parse().unwrap());
            }
        }
    }

    env_filter
}
