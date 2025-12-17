//! Cargo-style progress output for zsync
//!
//! Displays progress in the familiar cargo format:
//! ```text
//!    Checking 14808 unique chunks across 952 files...
//!   Uploading [=========>           ] 45% 30.2 MiB/67.4 MiB src/main.rs
//!     Syncing [===========>             ] 500/952 src/main.rs
//!      Synced 952 files in 3.2s
//! ```
//!
//! Uses `indicatif::MultiProgress` to coordinate all terminal output and prevent
//! display corruption from concurrent stderr writes.
//!
//! ## Ghostty Terminal Progress Protocol
//!
//! When running in Ghostty terminal (detected via `TERM_PROGRAM=ghostty` or
//! `GHOSTTY_RESOURCES_DIR` env var), zsync emits OSC 9;4 escape sequences to
//! show progress in the terminal tab/title bar.

use std::io::Write as _;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

/// Global MultiProgress instance for coordinating all terminal output.
/// All progress bars and status messages go through this to prevent display corruption.
static MULTI: OnceLock<indicatif::MultiProgress> = OnceLock::new();

/// Whether we're running in Ghostty terminal (supports OSC 9;4 progress protocol)
static IS_GHOSTTY: AtomicBool = AtomicBool::new(false);

/// Initialize Ghostty detection. Call once at startup.
pub fn init() {
    let is_ghostty = std::env::var("TERM_PROGRAM")
        .map(|v| v.eq_ignore_ascii_case("ghostty"))
        .unwrap_or(false)
        || std::env::var("GHOSTTY_RESOURCES_DIR").is_ok();

    IS_GHOSTTY.store(is_ghostty, Ordering::Relaxed);
}

/// Set Ghostty tab progress (0-100). Only emits if running in Ghostty.
fn set_ghostty_progress(percent: u8) {
    if IS_GHOSTTY.load(Ordering::Relaxed) {
        // OSC 9;4;1;{percent} ST - Set progress bar (1 = normal progress)
        let _ = write!(std::io::stderr(), "\x1b]9;4;1;{percent}\x1b\\");
        let _ = std::io::stderr().flush();
    }
}

/// Clear Ghostty tab progress. Only emits if running in Ghostty.
fn clear_ghostty_progress() {
    if IS_GHOSTTY.load(Ordering::Relaxed) {
        // OSC 9;4;0;0 ST - Clear progress bar (0 = remove)
        let _ = write!(std::io::stderr(), "\x1b]9;4;0;0\x1b\\");
        let _ = std::io::stderr().flush();
    }
}

fn multi() -> &'static indicatif::MultiProgress {
    MULTI.get_or_init(indicatif::MultiProgress::new)
}

/// A writer that coordinates with the global MultiProgress.
/// Use this with tracing-subscriber to ensure logs don't corrupt progress bar display.
#[derive(Clone)]
pub struct ProgressWriter;

impl std::io::Write for ProgressWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Convert to string and print through MultiProgress
        if let Ok(s) = std::str::from_utf8(buf) {
            // Strip trailing newline since println adds one
            let s = s.trim_end_matches('\n');
            if !s.is_empty() {
                multi().println(s).ok();
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::stderr().flush()
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for ProgressWriter {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Status verbs for cargo-style output (right-aligned to 12 chars)
struct Status;

impl Status {
    const CHECKING: &str = "Checking";
    const UPLOADING: &str = "Uploading";
    const SYNCED: &str = "Synced";
    const SKIPPED: &str = "Skipped";
}

/// Print a cargo-style status line, coordinated with any active progress bars
fn print_status(status: &str, message: &str) {
    let style = console::Style::new().green().bold();
    let line = format!("{:>12} {}", style.apply_to(status), message);
    multi().println(line).ok();
}

/// Progress bar for chunk uploads with byte-level tracking
pub struct UploadProgress {
    bar: indicatif::ProgressBar,
    total_bytes: u64,
}

impl UploadProgress {
    /// Set which file is currently being uploaded (shown as dim suffix)
    pub fn set_current_file(&self, file_name: &str) {
        self.bar.set_prefix(file_name.to_string());
    }

    /// Add bytes to the progress (call as chunks are uploaded)
    pub fn add_bytes(&self, bytes: u64) {
        self.bar.inc(bytes);

        // Update Ghostty progress
        let percent = (self.bar.position() * 100 / self.total_bytes.max(1)) as u8;
        set_ghostty_progress(percent.min(100));
    }

    /// Mark upload as complete
    pub fn finish(self) {
        self.bar.finish_and_clear();
        clear_ghostty_progress();
    }
}

/// Progress tracker for the sync operation
pub struct SyncProgress {
    start: Instant,
}

impl SyncProgress {
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    /// Show the initial "Checking X chunks across Y files" message
    pub fn checking(chunks: usize, files: usize) {
        print_status(
            Status::CHECKING,
            &format!("{chunks} unique chunks across {files} files..."),
        );
    }

    /// Create a progress bar for chunk uploads with byte tracking
    ///
    /// Returns an `UploadProgress` which tracks bytes uploaded and can display
    /// which file's chunks are currently being processed.
    pub fn upload_bar(total_bytes: u64) -> UploadProgress {
        let pb = multi().add(indicatif::ProgressBar::new(total_bytes));
        pb.set_style(
            indicatif::ProgressStyle::default_bar()
                // Format: "   Uploading [====>       ] 45% 30.2/67.4 MiB src/main.rs"
                .template(
                    "{msg:>12} [{bar:20.cyan/dim}] {percent:>3}% {binary_bytes}/{binary_total_bytes} {prefix:.dim}",
                )
                .expect("valid template")
                .progress_chars("=> "),
        );
        pb.set_message(Status::UPLOADING);
        pb.enable_steady_tick(std::time::Duration::from_millis(80));

        // Set initial Ghostty progress
        set_ghostty_progress(0);

        UploadProgress {
            bar: pb,
            total_bytes,
        }
    }

    /// Show "All chunks already on server" message
    pub fn chunks_deduped() {
        print_status(
            Status::SKIPPED,
            "all chunks already on server (deduplication win!)",
        );
    }

    /// Create a progress bar for file syncing
    pub fn file_sync_bar(total_files: u64) -> indicatif::ProgressBar {
        let pb = multi().add(indicatif::ProgressBar::new(total_files));
        pb.set_style(
            indicatif::ProgressStyle::default_bar()
                .template(
                    "{msg:>12} [{bar:25.cyan/dim}] {pos}/{len} {prefix:.dim} {spinner:.green}",
                )
                .expect("valid template")
                .progress_chars("=> "),
        );
        pb.set_message("Syncing");
        pb.enable_steady_tick(std::time::Duration::from_millis(100));
        pb
    }

    /// Show final summary
    pub fn finish(&self, success_count: u32, error_count: usize) {
        let elapsed = self.start.elapsed();
        let elapsed_str = if elapsed.as_secs() >= 1 {
            format!("{:.2}s", elapsed.as_secs_f64())
        } else {
            format!("{}ms", elapsed.as_millis())
        };

        if error_count == 0 {
            print_status(
                Status::SYNCED,
                &format!("{success_count} files in {elapsed_str}"),
            );
        } else {
            let style = console::Style::new().yellow().bold();
            let line = format!(
                "{:>12} {} successful, {} failed in {}",
                style.apply_to("Finished"),
                success_count,
                error_count,
                elapsed_str
            );
            multi().println(line).ok();
        }
    }
}

impl Default for SyncProgress {
    fn default() -> Self {
        Self::new()
    }
}
