//! Debug file logging for zsync
//!
//! Creates a trace log file at `/tmp/zsync-{session_id}.log` for debugging.
//! The session ID is a UUID generated at startup.

use std::path::PathBuf;

use tracing_subscriber::Layer as _;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

use crate::progress;

/// Debug log guard - keeps the file logger alive
pub struct DebugLogGuard {
    _guard: tracing_appender::non_blocking::WorkerGuard,
}

/// Session info returned after initializing debug logging
pub struct SessionInfo {
    pub log_path: PathBuf,
    pub guard: DebugLogGuard,
}

/// Initialize combined logging: file (detailed) + console (through MultiProgress).
///
/// Returns the session info including the log file path.
/// The guard must be kept alive for the duration of the program.
pub fn init(verbose: bool) -> SessionInfo {
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

    // Console layer: goes through ProgressWriter to coordinate with indicatif
    let console_level = if verbose {
        tracing_subscriber::filter::LevelFilter::DEBUG
    } else {
        tracing_subscriber::filter::LevelFilter::INFO
    };
    let console_layer = tracing_subscriber::fmt::layer()
        .with_writer(progress::ProgressWriter)
        .with_target(false)
        .with_filter(console_level);

    // File filter: capture everything at debug level for zsync crates
    let file_filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::new(
            "warn,zsync=trace,zsync_core=trace,zsync_transport=trace",
        )
    });

    tracing_subscriber::registry()
        .with(file_filter)
        .with(file_layer)
        .with(console_layer)
        .init();

    SessionInfo {
        log_path,
        guard: DebugLogGuard { _guard: guard },
    }
}
