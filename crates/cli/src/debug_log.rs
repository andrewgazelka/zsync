//! Debug file logging for zsync
//!
//! Creates a trace log file at `/tmp/zsync-{session_id}.log` for debugging.
//! The session ID is a UUID generated at startup.

use std::path::PathBuf;

use tracing_subscriber::Layer as _;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

/// Debug log guard - keeps the file logger alive
pub struct DebugLogGuard {
    _guard: tracing_appender::non_blocking::WorkerGuard,
}

/// Session info returned after initializing debug logging
pub struct SessionInfo {
    pub log_path: PathBuf,
    pub guard: DebugLogGuard,
}

/// Initialize file-only logging for debugging.
///
/// Returns the session info including the log file path.
/// The guard must be kept alive for the duration of the program.
pub fn init() -> SessionInfo {
    let session_id = uuid::Uuid::new_v4();
    let log_filename = format!("zsync-{session_id}.log");
    let log_path = PathBuf::from("/tmp").join(&log_filename);

    // Create non-blocking file appender
    let file_appender = tracing_appender::rolling::never("/tmp", &log_filename);
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    // File layer: detailed debug output
    let file_layer = tracing_subscriber::fmt::layer()
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_target(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .with_span_events(FmtSpan::ENTER | FmtSpan::EXIT);

    // File filter: capture everything at debug level for zsync crates
    let file_filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::new(
            "warn,zsync=trace,zsync_core=trace,zsync_transport=trace",
        )
    });

    // Only file logging - no console output to avoid interfering with progress bars
    tracing_subscriber::registry()
        .with(file_layer.with_filter(file_filter))
        .init();

    SessionInfo {
        log_path,
        guard: DebugLogGuard { _guard: guard },
    }
}
