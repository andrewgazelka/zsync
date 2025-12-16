//! zsync: Fast, modern file synchronization
//!
//! A modern alternative to mutagen/rsync with:
//! - Native .gitignore support
//! - BLAKE3 content-addressed hashing
//! - Binary protocol (no JSON overhead)
//! - Pure Rust SSH transport
//! - File watching with debouncing

mod embedded_agents;

use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

use clap::builder::styling::{AnsiColor, Effects};
use clap::{Parser, Subcommand, builder::Styles};
use color_eyre::Result;
use notify::RecursiveMode;
use notify_debouncer_full::{DebounceEventResult, new_debouncer};
use tracing::{error, info};

use zsync_core::{Scanner, Snapshot};
use zsync_transport::SshTransport;

const STYLES: Styles = Styles::styled()
    .header(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .usage(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .literal(AnsiColor::Cyan.on_default().effects(Effects::BOLD))
    .placeholder(AnsiColor::Cyan.on_default())
    .valid(AnsiColor::Green.on_default())
    .invalid(AnsiColor::Red.on_default());

#[derive(Parser)]
#[command(name = "zsync")]
#[command(version)]
#[command(styles = STYLES)]
#[command(about = "Fast file sync with native .gitignore support")]
#[command(long_about = r#"
zsync is a modern alternative to mutagen and rsync.

Features:
  • Native .gitignore - respects your existing ignore files
  • Delta sync       - only transfers what changed
  • Zero remote deps - agent binary auto-deploys via SSH
  • Fast             - BLAKE3 hashing, binary protocol
"#)]
struct Cli {
    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Sync local directory to remote
    Sync {
        /// Local directory path
        #[arg(default_value = ".")]
        local: PathBuf,

        /// Remote destination (user@host:/path)
        remote: String,

        /// SSH port
        #[arg(short, long, default_value = "22")]
        port: u16,

        /// Force-include files even if gitignored (e.g., .env)
        #[arg(short, long)]
        include: Vec<String>,
    },

    /// Watch and continuously sync changes
    Watch {
        /// Local directory path
        #[arg(default_value = ".")]
        local: PathBuf,

        /// Remote destination (user@host:/path)
        remote: String,

        /// SSH port
        #[arg(short, long, default_value = "22")]
        port: u16,

        /// Debounce delay in milliseconds
        #[arg(short, long, default_value = "100")]
        debounce: u64,

        /// Force-include files even if gitignored (e.g., .env)
        #[arg(long)]
        include: Vec<String>,
    },

    /// Scan local directory and print snapshot
    Scan {
        /// Directory to scan
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// Show version and build info
    Version,
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    let cli = Cli::parse();

    // Setup logging
    let filter = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    match cli.command {
        Commands::Version => {
            eprintln!("zsync {}", env!("CARGO_PKG_VERSION"));
        }
        Commands::Scan { path } => {
            scan_command(&path)?;
        }
        Commands::Sync {
            local,
            remote,
            port,
            include,
        } => {
            sync_command(&local, &remote, port, &include).await?;
        }
        Commands::Watch {
            local,
            remote,
            port,
            debounce,
            include,
        } => {
            watch_command(&local, &remote, port, debounce, &include).await?;
        }
    }

    Ok(())
}

fn scan_command(path: &PathBuf) -> Result<()> {
    info!("Scanning {}...", path.display());

    let scanner = Scanner::new(path);
    let entries = scanner.scan()?;
    let snapshot = Snapshot::from_entries(entries);

    eprintln!("Files: {}", snapshot.len());
    let total_size: u64 = snapshot.files.values().map(|f| f.size).sum();
    eprintln!("Total size: {} bytes", total_size);

    if snapshot.len() <= 20 {
        eprintln!("\nFiles:");
        for (path, entry) in &snapshot.files {
            eprintln!("  {} ({} bytes)", path.display(), entry.size);
        }
    }

    Ok(())
}

async fn sync_command(local: &PathBuf, remote: &str, port: u16, includes: &[String]) -> Result<()> {
    let (user, host, remote_path) = parse_remote(remote)?;

    info!(
        "Syncing {} -> {}@{}:{}",
        local.display(),
        user,
        host,
        remote_path
    );

    // Scan local
    info!("Scanning local directory...");
    let mut scanner = Scanner::new(local);
    for pattern in includes {
        scanner = scanner.include(pattern);
    }
    let entries = scanner.scan()?;
    let local_snapshot = Snapshot::from_entries(entries);
    info!("Found {} local files", local_snapshot.len());

    // Connect to remote
    let mut transport = SshTransport::connect(&host, port, &user).await?;

    // Deploy agent
    let bundle = embedded_agents::embedded_bundle();
    if bundle.platforms().is_empty() {
        return Err(color_eyre::eyre::eyre!(
            "No embedded agent binaries - cannot sync"
        ));
    }

    transport.ensure_agent(&bundle).await?;

    // Start agent
    info!("Starting remote agent...");
    let mut agent = transport.start_agent(&remote_path).await?;

    // Get remote snapshot
    info!("Getting remote snapshot...");
    let remote_snapshot = agent.snapshot().await?;
    info!("Found {} remote files", remote_snapshot.len());

    // Compute diff
    let diff = remote_snapshot.diff(&local_snapshot);

    if diff.is_empty() {
        info!("Already in sync!");
    } else {
        info!(
            "Changes: {} added, {} modified, {} deleted",
            diff.added.len(),
            diff.modified.len(),
            diff.removed.len()
        );

        // Transfer added and modified files
        let to_transfer: Vec<_> = diff.added.iter().chain(diff.modified.iter()).collect();

        for (i, path) in to_transfer.iter().enumerate() {
            let entry = local_snapshot
                .files
                .get(*path)
                .ok_or_else(|| color_eyre::eyre::eyre!("File not found: {}", path.display()))?;

            let full_path = local.join(path);
            let data = std::fs::read(&full_path)?;

            info!(
                "[{}/{}] Uploading {} ({} bytes)",
                i + 1,
                to_transfer.len(),
                path.display(),
                data.len()
            );

            agent.write_file(path, &data, entry.executable).await?;
        }

        // Delete removed files
        for (i, path) in diff.removed.iter().enumerate() {
            info!(
                "[{}/{}] Deleting {}",
                i + 1,
                diff.removed.len(),
                path.display()
            );
            agent.delete_file(path).await?;
        }
    }

    // Shutdown agent
    agent.shutdown().await?;

    info!("Sync complete!");
    Ok(())
}

async fn watch_command(
    local: &PathBuf,
    remote: &str,
    port: u16,
    debounce_ms: u64,
    includes: &[String],
) -> Result<()> {
    let (user, host, remote_path) = parse_remote(remote)?;

    info!(
        "Watching {} -> {}@{}:{}",
        local.display(),
        user,
        host,
        remote_path
    );

    // Initial sync
    sync_command(local, remote, port, includes).await?;

    // Setup file watcher
    let (tx, rx) = mpsc::channel();

    let mut debouncer = new_debouncer(
        Duration::from_millis(debounce_ms),
        None,
        move |result: DebounceEventResult| {
            if let Ok(events) = result {
                let _ = tx.send(events);
            }
        },
    )?;

    debouncer.watch(local, RecursiveMode::Recursive)?;

    info!("Watching for changes (Ctrl+C to stop)...");

    // Process file change events
    loop {
        match rx.recv() {
            Ok(events) => {
                let paths: Vec<_> = events.iter().flat_map(|e| e.paths.iter()).collect();

                if paths.is_empty() {
                    continue;
                }

                info!("Detected {} changed paths, syncing...", paths.len());

                // Re-sync
                if let Err(e) = sync_command(local, remote, port, includes).await {
                    error!("Sync failed: {e}");
                }
            }
            Err(e) => {
                error!("Watch error: {e}");
                break;
            }
        }
    }

    Ok(())
}

/// Parse remote string like "user@host:/path" into components
fn parse_remote(remote: &str) -> Result<(String, String, String)> {
    let at_pos = remote.find('@').ok_or_else(|| {
        color_eyre::eyre::eyre!("Invalid remote format, expected user@host:/path")
    })?;

    let user = remote[..at_pos].to_string();
    let rest = &remote[at_pos + 1..];

    let colon_pos = rest.find(':').ok_or_else(|| {
        color_eyre::eyre::eyre!("Invalid remote format, expected user@host:/path")
    })?;

    let host = rest[..colon_pos].to_string();
    let path = rest[colon_pos + 1..].to_string();

    Ok((user, host, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_remote() {
        let (user, host, path) = parse_remote("root@example.com:/home/user").unwrap();
        assert_eq!(user, "root");
        assert_eq!(host, "example.com");
        assert_eq!(path, "/home/user");
    }

    #[test]
    fn test_parse_remote_relative_path() {
        let (user, host, path) = parse_remote("user@host:workspace/project").unwrap();
        assert_eq!(user, "user");
        assert_eq!(host, "host");
        assert_eq!(path, "workspace/project");
    }
}
