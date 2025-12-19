//! Modern progress UI for zsync
//!
//! Custom ANSI-based progress display with:
//! - Braille dot spinner for indeterminate operations
//! - Unicode block progress bar for uploads
//! - Semantic colors and left-aligned icons
//!
//! Example output:
//! ```text
//! ⠋ Connecting to host:22...
//! ✓ Connected via SSH
//! ⠋ Scanning 542 files...
//! ✓ Scanned 542 files
//! → [████████████░░░░░░░░] 45% 30.2/67.4 MiB main.rs
//! ✓ Synced 952 files in 3.2s
//! ```

use std::io::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

/// ANSI escape sequences for terminal control
mod ansi {
    pub const HIDE_CURSOR: &str = "\x1b[?25l";
    pub const SHOW_CURSOR: &str = "\x1b[?25h";
    pub const CLEAR_LINE: &str = "\x1b[2K\r";
    pub const RESET: &str = "\x1b[0m";
    pub const BOLD: &str = "\x1b[1m";
    pub const DIM: &str = "\x1b[2m";
    pub const RED: &str = "\x1b[31m";
    pub const GREEN: &str = "\x1b[32m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const BLUE: &str = "\x1b[34m";
    pub const MAGENTA: &str = "\x1b[35m";
    pub const CYAN: &str = "\x1b[36m";
}

/// Unicode icons for status messages
mod icon {
    pub const SUCCESS: &str = "✓";
    pub const ERROR: &str = "✗";
    pub const ARROW: &str = "→";
    pub const BULLET: &str = "●";
    pub const CIRCLE: &str = "○";
    pub const WARN: &str = "!";
}

/// Spinner animation frames (braille dots)
const SPINNER_FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// Progress bar characters
mod bar {
    pub const FILLED: char = '█';
    pub const EMPTY: char = '░';
    pub const WIDTH: usize = 20;
}

/// Whether we're running in Ghostty terminal (supports OSC 9;4 progress protocol)
static IS_GHOSTTY: AtomicBool = AtomicBool::new(false);

/// Initialize progress UI. Call once at startup.
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
        let _ = write!(std::io::stderr(), "\x1b]9;4;1;{percent}\x1b\\");
        let _ = std::io::stderr().flush();
    }
}

/// Clear Ghostty tab progress. Only emits if running in Ghostty.
fn clear_ghostty_progress() {
    if IS_GHOSTTY.load(Ordering::Relaxed) {
        let _ = write!(std::io::stderr(), "\x1b]9;4;0;0\x1b\\");
        let _ = std::io::stderr().flush();
    }
}

/// Get terminal width, defaulting to 80 if unavailable
fn terminal_width() -> usize {
    console::Term::stderr().size().1 as usize
}

/// Truncate text to fit within max_width, adding "..." if truncated
fn truncate_to_width(text: &str, max_width: usize) -> std::borrow::Cow<'_, str> {
    let text_width = console::measure_text_width(text);
    if text_width <= max_width {
        return std::borrow::Cow::Borrowed(text);
    }
    let target_width = max_width.saturating_sub(3);
    let truncated = console::truncate_str(text, target_width, "...");
    std::borrow::Cow::Owned(truncated.to_string())
}

// ============================================================================
// Status message functions (one-shot, newline-terminated)
// ============================================================================

/// Print success message: ✓ {msg} (green)
pub fn success(msg: &str) {
    let available = terminal_width().saturating_sub(3);
    let msg = truncate_to_width(msg, available);
    eprintln!(
        "{}{}{} {}{}",
        ansi::GREEN,
        ansi::BOLD,
        icon::SUCCESS,
        msg,
        ansi::RESET
    );
}

/// Print info message: → {msg} (cyan)
pub fn info(msg: &str) {
    let available = terminal_width().saturating_sub(3);
    let msg = truncate_to_width(msg, available);
    eprintln!("{}{} {}{}", ansi::CYAN, icon::ARROW, msg, ansi::RESET);
}

/// Print warning message: ! {msg} (yellow)
pub fn warn(msg: &str) {
    let available = terminal_width().saturating_sub(3);
    let msg = truncate_to_width(msg, available);
    eprintln!(
        "{}{}{} {}{}",
        ansi::YELLOW,
        ansi::BOLD,
        icon::WARN,
        msg,
        ansi::RESET
    );
}

/// Print error message: ✗ {msg} (red)
pub fn error(msg: &str) {
    let available = terminal_width().saturating_sub(3);
    let msg = truncate_to_width(msg, available);
    eprintln!(
        "{}{}{} {}{}",
        ansi::RED,
        ansi::BOLD,
        icon::ERROR,
        msg,
        ansi::RESET
    );
}

/// Print dim/skipped message: ○ {msg} (dim)
pub fn dim(msg: &str) {
    let available = terminal_width().saturating_sub(3);
    let msg = truncate_to_width(msg, available);
    eprintln!("{}{} {}{}", ansi::DIM, icon::CIRCLE, msg, ansi::RESET);
}

/// Print indented info message:   → {msg} (blue, for file lists)
pub fn file_sync(msg: &str) {
    let available = terminal_width().saturating_sub(5);
    let msg = truncate_to_width(msg, available);
    eprintln!("{}  {} {}{}", ansi::BLUE, icon::ARROW, msg, ansi::RESET);
}

/// Print indented delete message:   ✗ {msg} (red, for deletions)
pub fn file_delete(msg: &str) {
    let available = terminal_width().saturating_sub(5);
    let msg = truncate_to_width(msg, available);
    eprintln!("{}  {} {}{}", ansi::RED, icon::ERROR, msg, ansi::RESET);
}

/// Print watching message: ● {msg} (magenta)
pub fn watching(msg: &str) {
    let available = terminal_width().saturating_sub(3);
    let msg = truncate_to_width(msg, available);
    eprintln!(
        "{}{}{} {}{}",
        ansi::MAGENTA,
        ansi::BOLD,
        icon::BULLET,
        msg,
        ansi::RESET
    );
}

// ============================================================================
// Spinner - for indeterminate operations
// ============================================================================

/// Animated spinner for indeterminate operations.
///
/// The spinner runs in a background thread and updates every 80ms.
/// Call `finish_success()` or `finish_error()` to stop and show final status.
pub struct Spinner {
    /// Shared state for the spinner thread
    running: Arc<AtomicBool>,
    /// Current message (can be updated)
    message: Arc<std::sync::Mutex<String>>,
    /// Handle to the spinner thread
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Spinner {
    /// Create and start a new spinner with the given message.
    pub fn new(message: &str) -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let message = Arc::new(std::sync::Mutex::new(message.to_string()));

        let running_clone = Arc::clone(&running);
        let message_clone = Arc::clone(&message);

        // Hide cursor
        eprint!("{}", ansi::HIDE_CURSOR);
        let _ = std::io::stderr().flush();

        let handle = std::thread::spawn(move || {
            let mut frame = 0usize;
            while running_clone.load(Ordering::Relaxed) {
                let msg = message_clone.lock().unwrap().clone();
                let spinner_char = SPINNER_FRAMES[frame % SPINNER_FRAMES.len()];

                // Clear line and print spinner
                eprint!(
                    "{}{}{} {}{}",
                    ansi::CLEAR_LINE,
                    ansi::CYAN,
                    spinner_char,
                    msg,
                    ansi::RESET
                );
                let _ = std::io::stderr().flush();

                frame += 1;
                std::thread::sleep(std::time::Duration::from_millis(80));
            }
        });

        Self {
            running,
            message,
            handle: Some(handle),
        }
    }

    /// Update the spinner message without stopping it.
    pub fn set_message(&self, message: &str) {
        if let Ok(mut msg) = self.message.lock() {
            *msg = message.to_string();
        }
    }

    /// Stop the spinner and print a success message.
    pub fn finish_success(self, message: &str) {
        self.stop();
        // Clear line and print success
        eprint!("{}", ansi::CLEAR_LINE);
        success(message);
    }

    /// Stop the spinner and print an error message.
    pub fn finish_error(self, message: &str) {
        self.stop();
        // Clear line and print error
        eprint!("{}", ansi::CLEAR_LINE);
        error(message);
    }

    /// Stop the spinner without printing anything.
    pub fn finish_silent(self) {
        self.stop();
        eprint!("{}", ansi::CLEAR_LINE);
        let _ = std::io::stderr().flush();
    }

    fn stop(mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        // Show cursor
        eprint!("{}", ansi::SHOW_CURSOR);
        let _ = std::io::stderr().flush();
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        // Ensure we stop if dropped without calling finish
        if self.running.load(Ordering::Relaxed) {
            self.running.store(false, Ordering::Relaxed);
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
            eprint!("{}{}", ansi::CLEAR_LINE, ansi::SHOW_CURSOR);
            let _ = std::io::stderr().flush();
        }
    }
}

// ============================================================================
// ProgressBar - for uploads with byte tracking
// ============================================================================

/// Progress bar for determinate operations like uploads.
///
/// Updates in-place on a single line with byte progress and percentage.
pub struct ProgressBar {
    total: u64,
    current: Arc<AtomicU64>,
    message: Arc<std::sync::Mutex<String>>,
    running: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl ProgressBar {
    /// Create a new progress bar with the given total bytes.
    pub fn new(total: u64) -> Self {
        let current = Arc::new(AtomicU64::new(0));
        let message = Arc::new(std::sync::Mutex::new(String::new()));
        let running = Arc::new(AtomicBool::new(true));

        let current_clone = Arc::clone(&current);
        let message_clone = Arc::clone(&message);
        let running_clone = Arc::clone(&running);

        // Hide cursor and set initial Ghostty progress
        eprint!("{}", ansi::HIDE_CURSOR);
        let _ = std::io::stderr().flush();
        set_ghostty_progress(0);

        let handle = std::thread::spawn(move || {
            while running_clone.load(Ordering::Relaxed) {
                let cur = current_clone.load(Ordering::Relaxed);
                let msg = message_clone.lock().unwrap().clone();

                Self::render(cur, total, &msg);

                std::thread::sleep(std::time::Duration::from_millis(80));
            }
        });

        Self {
            total,
            current,
            message,
            running,
            handle: Some(handle),
        }
    }

    /// Set the current file being processed (shown at end of bar).
    pub fn set_message(&self, message: &str) {
        if let Ok(mut msg) = self.message.lock() {
            *msg = message.to_string();
        }
    }

    /// Add bytes to the progress.
    pub fn add(&self, bytes: u64) {
        let new_value = self.current.fetch_add(bytes, Ordering::Relaxed) + bytes;
        let percent = (new_value * 100 / self.total.max(1)) as u8;
        set_ghostty_progress(percent.min(100));
    }

    /// Finish the progress bar successfully.
    pub fn finish(mut self) {
        self.stop();
    }

    fn stop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        // Clear line and show cursor
        eprint!("{}{}", ansi::CLEAR_LINE, ansi::SHOW_CURSOR);
        let _ = std::io::stderr().flush();
        clear_ghostty_progress();
    }

    fn render(current: u64, total: u64, message: &str) {
        let percent = if total > 0 {
            (current * 100 / total) as usize
        } else {
            0
        };
        let filled = (percent * bar::WIDTH) / 100;
        let empty = bar::WIDTH - filled;

        let bar_str: String = std::iter::repeat_n(bar::FILLED, filled)
            .chain(std::iter::repeat_n(bar::EMPTY, empty))
            .collect();

        let current_str = humansize::format_size(current, humansize::BINARY);
        let total_str = humansize::format_size(total, humansize::BINARY);

        // Calculate available space for message
        // Format: "→ [████░░░░] 100% 999.9 MiB/999.9 MiB "
        // That's about 45-50 chars, leave room for message
        let term_width = terminal_width();
        let prefix_len = 50; // approximate
        let available = term_width.saturating_sub(prefix_len);
        let msg_display = if message.is_empty() {
            String::new()
        } else {
            truncate_to_width(message, available).to_string()
        };

        eprint!(
            "{}{}{} [{}{}{}{}{}] {:>3}% {}/{} {}{}{}",
            ansi::CLEAR_LINE,
            ansi::CYAN,
            icon::ARROW,
            ansi::CYAN,
            bar_str.chars().take(filled).collect::<String>(),
            ansi::DIM,
            bar_str.chars().skip(filled).collect::<String>(),
            ansi::RESET,
            percent,
            current_str,
            total_str,
            ansi::DIM,
            msg_display,
            ansi::RESET
        );
        let _ = std::io::stderr().flush();
    }
}

impl Drop for ProgressBar {
    fn drop(&mut self) {
        if self.running.load(Ordering::Relaxed) {
            self.stop();
        }
    }
}

// ============================================================================
// SyncProgress - high-level sync progress tracking
// ============================================================================

/// Direction of file sync
#[derive(Debug, Clone, Copy)]
pub enum SyncDirection {
    /// Local -> Remote (upload)
    Upload,
    /// Remote -> Local (download)
    Download,
}

/// High-level sync progress tracker.
pub struct SyncProgress {
    start: Instant,
}

impl SyncProgress {
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    /// Show final summary.
    pub fn finish(&self, success_count: u32, error_count: usize) {
        let elapsed = self.start.elapsed();
        let elapsed_str = if elapsed.as_secs() >= 1 {
            format!("{:.2}s", elapsed.as_secs_f64())
        } else {
            format!("{}ms", elapsed.as_millis())
        };

        if error_count == 0 {
            success(&format!("Synced {success_count} files in {elapsed_str}"));
        } else {
            warn(&format!(
                "{success_count} synced, {error_count} failed in {elapsed_str}"
            ));
        }
    }
}

impl Default for SyncProgress {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Convenience functions for common messages
// ============================================================================

/// Show "Scanned N local files"
pub fn scanning_local(count: usize) {
    info(&format!("Scanned {count} local files"));
}

/// Show "Checked N remote files"
pub fn checking_remote(count: usize) {
    info(&format!("Checked {count} remote files"));
}

/// Show "Already in sync (N files)"
pub fn already_in_sync(count: usize) {
    success(&format!("Already in sync ({count} files)"));
}

/// Show "Checking N chunks across M files"
pub fn checking_chunks(chunks: usize, files: usize) {
    info(&format!("Checking {chunks} chunks across {files} files"));
}

/// Show "All chunks deduplicated"
pub fn chunks_deduped() {
    dim("All chunks already on server");
}

/// Create upload progress bar
pub fn upload_bar(total_bytes: u64) -> ProgressBar {
    ProgressBar::new(total_bytes)
}

/// Show "Syncing path (size) →" or "←"
pub fn syncing_file(path: &std::path::Path, size: u64, direction: SyncDirection) {
    let size_str = humansize::format_size(size, humansize::BINARY);
    let arrow = match direction {
        SyncDirection::Upload => "→",
        SyncDirection::Download => "←",
    };
    file_sync(&format!("{} ({}) {}", path.display(), size_str, arrow));
}

/// Show "Deleting path"
pub fn deleting_file(path: &std::path::Path) {
    file_delete(&format!("{}", path.display()));
}

/// Show "Watching for changes..."
pub fn watch_mode() {
    watching("Watching for changes (Ctrl+C to stop)");
}

/// Show "Connecting to host:port..."
pub fn connecting(host: &str, port: u16) -> Spinner {
    Spinner::new(&format!("Connecting to {host}:{port}..."))
}

/// Finish connection spinner with success
pub fn connected(spinner: Spinner, auth_method: &str) {
    spinner.finish_success(&format!("Connected via {auth_method}"));
}
