use std::io::Write;

use backtrace::Backtrace;
use flux::utils::{ThreadPriority, thread_boot};
use tracing::{error, level_filters::LevelFilter};
use tracing_appender::{non_blocking::WorkerGuard, rolling::Rotation};
use tracing_subscriber::EnvFilter;

pub const DEFAULT_TRACING_ENV_FILTERS: [&str; 6] = [
    "hyper::proto::h1=off",
    "trust_dns_proto=off",
    "trust_dns_resolver=off",
    "discv5=off",
    "hyper_util=off",
    "reqwest=info",
];

const TRACING_APPENDER_THREAD: &str = "tracing-appender";

struct PinnedAppenderWriter<W> {
    inner: W,
    log_core: Option<usize>,
    booted: bool,
}

impl<W> PinnedAppenderWriter<W> {
    fn new(inner: W, log_core: Option<usize>) -> Self {
        Self { inner, log_core, booted: false }
    }

    fn boot(&mut self) {
        if self.booted {
            return;
        }
        self.booted = true;
        thread_boot(self.log_core, ThreadPriority::OSDefault);
    }
}

impl<W: Write> Write for PinnedAppenderWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.boot();
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.boot();
        self.inner.flush()
    }
}

/// Initialises tracing logger that creates daily log files.
pub fn initialise_tracing_log(
    filename_prefix: &str,
    max_log_files: usize,
    env_filters: Option<Vec<&str>>,
    use_stdout: bool,
) -> Option<WorkerGuard> {
    initialise_tracing_log_on_core(filename_prefix, max_log_files, env_filters, use_stdout, None)
}

pub fn initialise_tracing_log_on_core(
    filename_prefix: &str,
    max_log_files: usize,
    env_filters: Option<Vec<&str>>,
    use_stdout: bool,
    log_core: Option<usize>,
) -> Option<WorkerGuard> {
    let use_stdout = use_stdout || std::env::var("LOG_STDOUT").map(|_| true).unwrap_or(false);

    if use_stdout {
        tracing_subscriber::fmt()
            .with_env_filter(build_env_filter(env_filters))
            .with_thread_names(true)
            .init();
        None
    } else {
        let log_path = std::env::var("LOG_PATH").unwrap_or("/tmp/logs".into());

        let file_appender = tracing_appender::rolling::Builder::new()
            .filename_prefix(filename_prefix)
            .max_log_files(max_log_files)
            .rotation(Rotation::DAILY)
            .build(&log_path)
            .unwrap_or_else(|_| panic!("failed to create log appender! path: {log_path}"));

        let file_appender = PinnedAppenderWriter::new(file_appender, log_core);
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

pub fn initialise_test_tracing_logger() {
    initialise_test_tracing_logger_with_level(LevelFilter::DEBUG);
}

pub fn initialise_test_tracing_logger_with_level(level: LevelFilter) {
    std::panic::set_hook(Box::new(|info| {
        let backtrace = Backtrace::new();
        let crash_log = format!("Panic: {info}\nFull backtrace:\n{backtrace:?}\n");
        error!("{crash_log}");
    }));

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
    let mut env_filter = EnvFilter::builder().from_env_lossy();

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
