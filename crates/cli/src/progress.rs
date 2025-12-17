//! Cargo-style progress output for zsync
//!
//! Displays progress in the familiar cargo format:
//! ```text
//!    Checking 14808 unique chunks across 952 files...
//!   Uploading [======>                  ] 67.44 MiB
//!     Syncing [===========>             ] 500/952 src/main.rs
//!      Synced 952 files in 3.2s
//! ```

use std::io::Write as _;
use std::time::Instant;

/// Status verbs for cargo-style output (right-aligned to 12 chars)
struct Status;

impl Status {
    const CHECKING: &str = "Checking";
    const UPLOADING: &str = "Uploading";
    const SYNCED: &str = "Synced";
    const SKIPPED: &str = "Skipped";
}

/// Print a cargo-style status line
fn print_status(status: &str, message: &str) {
    let mut term = console::Term::stderr();
    let style = console::Style::new().green().bold();
    let _ = writeln!(term, "{:>12} {}", style.apply_to(status), message);
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
    pub fn checking(&self, chunks: usize, files: usize) {
        print_status(
            Status::CHECKING,
            &format!("{chunks} unique chunks across {files} files..."),
        );
    }

    /// Create a spinner for chunk upload (can't track real progress)
    pub fn upload_spinner(&self, total_bytes: u64) -> indicatif::ProgressBar {
        let pb = indicatif::ProgressBar::new_spinner();
        let size_str = humansize::format_size(total_bytes, humansize::BINARY);
        pb.set_style(
            indicatif::ProgressStyle::default_spinner()
                .template("{spinner:.green} {msg:>12} {prefix}")
                .expect("valid template"),
        );
        pb.set_message(Status::UPLOADING);
        pb.set_prefix(format!("{size_str}..."));
        pb.enable_steady_tick(std::time::Duration::from_millis(80));
        pb
    }

    /// Show "All chunks already on server" message
    pub fn chunks_deduped(&self) {
        print_status(
            Status::SKIPPED,
            "all chunks already on server (deduplication win!)",
        );
    }

    /// Create a progress bar for file syncing
    pub fn file_sync_bar(&self, total_files: u64) -> indicatif::ProgressBar {
        let pb = indicatif::ProgressBar::new(total_files);
        pb.set_style(
            indicatif::ProgressStyle::default_bar()
                .template(
                    "{spinner:.green} {msg:>12} [{bar:25.cyan/dim}] {pos}/{len} {prefix:.dim}",
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
            let mut term = console::Term::stderr();
            let style = console::Style::new().yellow().bold();
            let _ = writeln!(
                term,
                "{:>12} {} successful, {} failed in {}",
                style.apply_to("Finished"),
                success_count,
                error_count,
                elapsed_str
            );
        }
    }
}

impl Default for SyncProgress {
    fn default() -> Self {
        Self::new()
    }
}
