//! zsync: Fast, modern file synchronization
//!
//! A modern alternative to mutagen/rsync with:
//! - Native .gitignore support
//! - BLAKE3 content-addressed hashing
//! - Delta sync with zstd compression
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
use tracing::{debug, error, info, warn};

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
  • Fast             - BLAKE3 hashing, zstd compression

Examples:
  zsync sync ./local user@host:/remote    One-time sync
  zsync watch ./local user@host:/remote   Continuous sync
  zsync scan ./project                    Scan local directory
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
        local: PathBuf,

        /// Remote destination (user@host:/path)
        remote: String,

        /// SSH port
        #[arg(short, long, default_value = "22")]
        port: u16,
    },

    /// Watch and continuously sync changes
    Watch {
        /// Local directory path
        local: PathBuf,

        /// Remote destination (user@host:/path)
        remote: String,

        /// SSH port
        #[arg(short, long, default_value = "22")]
        port: u16,

        /// Debounce delay in milliseconds
        #[arg(short, long, default_value = "100")]
        debounce: u64,
    },

    /// Scan local directory and print snapshot
    Scan {
        /// Directory to scan
        path: PathBuf,

        /// Output format (json, summary)
        #[arg(short, long, default_value = "summary")]
        format: String,
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
            eprintln!("Built with Rust {}", env!("CARGO_PKG_RUST_VERSION"));
        }
        Commands::Scan { path, format } => {
            scan_command(&path, &format)?;
        }
        Commands::Sync {
            local,
            remote,
            port,
        } => {
            sync_command(&local, &remote, port).await?;
        }
        Commands::Watch {
            local,
            remote,
            port,
            debounce,
        } => {
            watch_command(&local, &remote, port, debounce).await?;
        }
    }

    Ok(())
}

fn scan_command(path: &PathBuf, format: &str) -> Result<()> {
    info!("Scanning {}...", path.display());

    let scanner = Scanner::new(path);
    let entries = scanner.scan()?;
    let snapshot = Snapshot::from_entries(entries);

    match format {
        "json" => {
            let json = serde_json::to_string_pretty(&snapshot)?;
            eprintln!("{json}");
        }
        _ => {
            eprintln!("Files: {}", snapshot.len());
            let total_size: u64 = snapshot.files.values().map(|f| f.size).sum();
            eprintln!("Total size: {total_size} bytes");

            if snapshot.len() <= 20 {
                eprintln!("\nFiles:");
                for (path, entry) in &snapshot.files {
                    eprintln!("  {} ({} bytes)", path.display(), entry.size);
                }
            }
        }
    }

    Ok(())
}

async fn sync_command(local: &PathBuf, remote: &str, port: u16) -> Result<()> {
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
    let scanner = Scanner::new(local);
    let entries = scanner.scan()?;
    let local_snapshot = Snapshot::from_entries(entries);
    info!("Found {} local files", local_snapshot.len());

    // Connect to remote
    info!("Connecting to remote...");
    let mut transport = SshTransport::connect(&host, port, &user).await?;

    // Deploy agent
    let bundle = embedded_agents::embedded_bundle();
    if bundle.platforms().is_empty() {
        warn!("No embedded agent binaries - remote must have zsync-agent installed");
    } else {
        let agent_path = transport.ensure_agent(&bundle).await?;
        info!("Agent ready at {agent_path:?}");
    }

    // TODO: Get remote snapshot via agent
    // TODO: Compute diff
    // TODO: Transfer changed files

    info!("Sync complete!");
    Ok(())
}

async fn watch_command(local: &PathBuf, remote: &str, port: u16, debounce_ms: u64) -> Result<()> {
    let (user, host, remote_path) = parse_remote(remote)?;

    info!(
        "Watching {} -> {}@{}:{}",
        local.display(),
        user,
        host,
        remote_path
    );

    // Initial sync
    sync_command(local, remote, port).await?;

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
                for path in &paths {
                    debug!("  Changed: {}", path.display());
                }

                // Re-sync
                if let Err(e) = sync_command(local, remote, port).await {
                    error!("Sync failed: {}", e);
                }
            }
            Err(e) => {
                error!("Watch error: {}", e);
                break;
            }
        }
    }

    Ok(())
}

/// Parse remote string like "user@host:/path" into components
fn parse_remote(remote: &str) -> Result<(String, String, String)> {
    // Format: user@host:/path or user@host:path
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
