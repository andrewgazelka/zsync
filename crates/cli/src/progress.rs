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

/// Get terminal width, defaulting to 80 if unavailable
fn terminal_width() -> usize {
    console::Term::stderr().size().1 as usize
}

/// Truncate text to fit within max_width, adding "..." if truncated.
/// Uses Unicode-aware width measurement.
fn truncate_to_width(text: &str, max_width: usize) -> std::borrow::Cow<'_, str> {
    let text_width = console::measure_text_width(text);
    if text_width <= max_width {
        return std::borrow::Cow::Borrowed(text);
    }

    // Leave room for "..."
    let target_width = max_width.saturating_sub(3);
    let truncated = console::truncate_str(text, target_width, "...");
    std::borrow::Cow::Owned(truncated.to_string())
}

/// Status verbs for cargo-style output (right-aligned to 12 chars)
mod status {
    pub const CONNECTING: &str = "Connecting";
    pub const CONNECTED: &str = "Connected";
    pub const SCANNING: &str = "Scanning";
    pub const CHECKING: &str = "Checking";
    pub const UPLOADING: &str = "Uploading";
    pub const SYNCING: &str = "Syncing";
    pub const DELETING: &str = "Deleting";
    pub const SYNCED: &str = "Synced";
    pub const IN_SYNC: &str = "In sync";
    pub const SKIPPED: &str = "Skipped";
    pub const WATCHING: &str = "Watching";
}

/// Width of status prefix: 12 chars for right-aligned status + 1 space separator
const STATUS_PREFIX_WIDTH: usize = 13;

/// Print a cargo-style status line, coordinated with any active progress bars.
/// Truncates message to fit terminal width, preventing line wrapping that causes
/// display corruption on terminal resize.
fn print_status(status: &str, message: &str) {
    let style = console::Style::new().green().bold();

    // Leave 1 char margin to avoid edge cases
    let available = terminal_width()
        .saturating_sub(STATUS_PREFIX_WIDTH)
        .saturating_sub(1);
    let truncated_message = truncate_to_width(message, available);

    let line = format!("{:>12} {}", style.apply_to(status), truncated_message);
    multi().println(line).ok();
}

// ========== Connection Status ==========

/// Show "Connecting to host:port..."
pub fn connecting(host: &str, port: u16) {
    print_status(status::CONNECTING, &format!("{host}:{port}..."));
}

/// Show "Connected via SSH agent" or similar auth method
pub fn connected(auth_method: &str) {
    print_status(status::CONNECTED, &format!("via {auth_method}"));
}

// ========== Scan Status ==========

/// Show "Scanning N local files..."
pub fn scanning_local(count: usize) {
    print_status(status::SCANNING, &format!("{count} local files..."));
}

/// Show "Checking N remote files..."
pub fn checking_remote(count: usize) {
    print_status(status::CHECKING, &format!("{count} remote files..."));
}

/// Show "In sync N files" when already synchronized
pub fn already_in_sync(count: usize) {
    print_status(status::IN_SYNC, &format!("{count} files"));
}

// ========== Watch Mode ==========

/// Show "Watching for changes..."
pub fn watching() {
    print_status(status::WATCHING, "for changes (Ctrl+C to stop)");
}

/// Direction of file sync
#[derive(Debug, Clone, Copy)]
pub enum SyncDirection {
    /// Local -> Remote (upload)
    Upload,
    /// Remote -> Local (download)
    Download,
}

/// Show "Syncing path/to/file.rs (2.3 KiB) ->" or "<-"
pub fn syncing_file(path: &std::path::Path, size: u64, direction: SyncDirection) {
    let size_str = humansize::format_size(size, humansize::BINARY);
    let arrow = match direction {
        SyncDirection::Upload => "->",
        SyncDirection::Download => "<-",
    };
    print_status(
        status::SYNCING,
        &format!("{} ({}) {}", path.display(), size_str, arrow),
    );
}

/// Show "Deleting path/to/file.rs"
pub fn deleting_file(path: &std::path::Path) {
    print_status(status::DELETING, &format!("{}", path.display()));
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
            status::CHECKING,
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
        pb.set_message(status::UPLOADING);
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
            status::SKIPPED,
            "all chunks already on server (deduplication win!)",
        );
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
                status::SYNCED,
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
