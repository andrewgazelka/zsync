//! zsync: Fast, modern file synchronization
//!
//! A modern alternative to mutagen/rsync with:
//! - Native .gitignore support
//! - BLAKE3 content-addressed hashing
//! - Binary protocol (no JSON overhead)
//! - Pure Rust SSH transport
//! - File watching with debouncing

mod embedded_agents;

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use clap::builder::styling::{AnsiColor, Effects};
use clap::{Parser, Subcommand, builder::Styles};
use color_eyre::Result;
use notify::RecursiveMode;
use notify_debouncer_full::{DebounceEventResult, new_debouncer};
use tracing::{debug, error, info, warn};

use zsync_core::{DeltaComputer, Scanner, Snapshot};
use zsync_transport::{AgentSession, SshTransport};

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
        /// Remote destination (user@host:/path)
        remote: String,

        /// Local directory path
        #[arg(default_value = ".")]
        local: PathBuf,

        /// SSH port
        #[arg(short, long, default_value = "22")]
        port: u16,

        /// Force-include files even if gitignored (e.g., .env)
        #[arg(short, long)]
        include: Vec<String>,

        /// Don't delete remote files that don't exist locally
        #[arg(long)]
        no_delete: bool,
    },

    /// Watch and continuously sync changes
    Watch {
        /// Remote destination (user@host:/path)
        remote: String,

        /// Local directory path
        #[arg(default_value = ".")]
        local: PathBuf,

        /// SSH port
        #[arg(short, long, default_value = "22")]
        port: u16,

        /// Debounce delay in milliseconds
        #[arg(short, long, default_value = "100")]
        debounce: u64,

        /// Force-include files even if gitignored (e.g., .env)
        #[arg(long)]
        include: Vec<String>,

        /// Don't delete remote files that don't exist locally
        #[arg(long)]
        no_delete: bool,
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
            no_delete,
        } => {
            sync_command(&local, &remote, port, &include, no_delete).await?;
        }
        Commands::Watch {
            local,
            remote,
            port,
            debounce,
            include,
            no_delete,
        } => {
            watch_command(&local, &remote, port, debounce, &include, no_delete).await?;
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
    eprintln!("Total size: {total_size} bytes");

    if snapshot.len() <= 20 {
        eprintln!("\nFiles:");
        for (path, entry) in &snapshot.files {
            eprintln!("  {} ({} bytes)", path.display(), entry.size);
        }
    }

    Ok(())
}

/// Threshold for using delta transfers (files larger than this use delta)
const DELTA_THRESHOLD: u64 = 32 * 1024; // 32KB

/// Prepare a file for transfer, using delta if beneficial
async fn prepare_transfer(
    local: &Path,
    path: &Path,
    remote_snapshot: &Snapshot,
    agent: &mut AgentSession,
    executable: bool,
) -> Result<TransferData> {
    let full_path = local.join(path);
    let local_data = std::fs::read(&full_path)?;

    // Check if file exists on remote and is large enough for delta
    if let Some(remote_entry) = remote_snapshot.files.get(path) {
        if remote_entry.size >= DELTA_THRESHOLD && local_data.len() as u64 >= DELTA_THRESHOLD {
            // Try delta transfer
            match agent.get_signature(path).await {
                Ok(sig_data) => {
                    let sig = DeltaComputer::decompress_signature(&sig_data)?;
                    let computer = DeltaComputer::new();
                    let delta = computer.delta(&local_data, &sig);
                    let compressed_delta = DeltaComputer::compress_delta(&delta)?;

                    // Only use delta if it's significantly smaller
                    if compressed_delta.len() < local_data.len() / 2 {
                        debug!(
                            "Using delta for {} ({} -> {} bytes, {:.1}% reduction)",
                            path.display(),
                            local_data.len(),
                            compressed_delta.len(),
                            (1.0 - compressed_delta.len() as f64 / local_data.len() as f64) * 100.0
                        );
                        return Ok(TransferData::Delta {
                            data: compressed_delta,
                            executable,
                        });
                    }
                }
                Err(e) => {
                    debug!(
                        "Delta transfer failed for {}, using full: {e}",
                        path.display()
                    );
                }
            }
        }
    }

    // Fall back to full file transfer with compression
    let compressed = zstd::encode_all(local_data.as_slice(), 3)?;
    if compressed.len() < local_data.len() {
        debug!(
            "Compressed {} ({} -> {} bytes)",
            path.display(),
            local_data.len(),
            compressed.len()
        );
        Ok(TransferData::CompressedFull {
            data: local_data,
            executable,
        })
    } else {
        Ok(TransferData::Full {
            data: local_data,
            executable,
        })
    }
}

enum TransferData {
    Full { data: Vec<u8>, executable: bool },
    CompressedFull { data: Vec<u8>, executable: bool },
    Delta { data: Vec<u8>, executable: bool },
}

/// Perform a single sync operation using an existing agent session.
/// Returns true if changes were synced, false if already in sync.
async fn sync_once(
    local: &Path,
    agent: &mut AgentSession,
    includes: &[String],
    no_delete: bool,
) -> Result<bool> {
    // Scan local
    debug!("Scanning local directory...");
    let mut scanner = Scanner::new(local);
    for pattern in includes {
        scanner = scanner.include(pattern);
    }
    let entries = scanner.scan()?;
    let local_snapshot = Snapshot::from_entries(entries);
    debug!("Found {} local files", local_snapshot.len());

    // Get remote snapshot
    debug!("Getting remote snapshot...");
    let remote_snapshot = agent.snapshot().await?;
    debug!("Found {} remote files", remote_snapshot.len());

    // Compute diff
    let diff = remote_snapshot.diff(&local_snapshot);

    let deletions = if no_delete { 0 } else { diff.removed.len() };

    if diff.is_empty() || (diff.added.is_empty() && diff.modified.is_empty() && no_delete) {
        return Ok(false);
    }

    info!(
        "Changes: {} added, {} modified, {} removed",
        diff.added.len(),
        diff.modified.len(),
        deletions
    );

    // Print individual file changes
    for path in &diff.added {
        info!("  + {}", path.display());
    }
    for path in &diff.modified {
        info!("  ~ {}", path.display());
    }
    if !no_delete {
        for path in &diff.removed {
            info!("  - {}", path.display());
        }
    }

    // Collect all files to transfer
    let added: Vec<_> = diff.added.iter().collect();
    let modified: Vec<_> = diff.modified.iter().collect();
    let to_delete: Vec<_> = if no_delete {
        vec![]
    } else {
        diff.removed.iter().collect()
    };

    let total_ops = added.len() + modified.len() + to_delete.len();

    if total_ops > 0 {
        // Prepare transfer data (delta for modified files where beneficial)
        let mut transfers: Vec<(&Path, TransferData)> = Vec::new();
        let mut total_bytes = 0u64;
        let mut delta_count = 0usize;

        // Added files - always full transfer
        for path in &added {
            let entry = local_snapshot
                .files
                .get(*path)
                .ok_or_else(|| color_eyre::eyre::eyre!("File not found: {}", path.display()))?;
            let full_path = local.join(path);
            let data = std::fs::read(&full_path)?;
            total_bytes += data.len() as u64;
            transfers.push((
                path,
                TransferData::Full {
                    data,
                    executable: entry.executable,
                },
            ));
        }

        // Modified files - try delta transfer
        for path in &modified {
            let entry = local_snapshot
                .files
                .get(*path)
                .ok_or_else(|| color_eyre::eyre::eyre!("File not found: {}", path.display()))?;
            let transfer =
                prepare_transfer(local, path, &remote_snapshot, agent, entry.executable).await?;
            match &transfer {
                TransferData::Delta { data, .. } => {
                    delta_count += 1;
                    total_bytes += data.len() as u64;
                }
                TransferData::Full { data, .. } | TransferData::CompressedFull { data, .. } => {
                    total_bytes += data.len() as u64;
                }
            }
            transfers.push((path, transfer));
        }

        if delta_count > 0 {
            info!("Using delta transfer for {delta_count} modified files");
        }

        // Start batch mode for pipelining
        info!(
            "Transferring {} in {} operations (pipelined)...",
            humansize::format_size(total_bytes, humansize::BINARY),
            total_ops
        );
        agent.start_batch(total_ops as u32).await?;

        // Queue all writes
        for (i, (path, transfer)) in transfers.iter().enumerate() {
            debug!(
                "[{}/{}] Queueing {}",
                i + 1,
                transfers.len(),
                path.display()
            );
            match transfer {
                TransferData::Full { data, executable }
                | TransferData::CompressedFull { data, executable } => {
                    agent.queue_write_file(path, data, *executable).await?;
                }
                TransferData::Delta { data, executable } => {
                    agent.queue_write_delta(path, data, *executable).await?;
                }
            }
        }

        // Queue all deletes
        for path in &to_delete {
            debug!("Queueing delete: {}", path.display());
            agent.queue_delete_file(path).await?;
        }

        // End batch and get results
        let result = agent.end_batch().await?;

        if result.errors.is_empty() {
            info!(
                "Batch complete: {} operations successful",
                result.success_count
            );
        } else {
            warn!(
                "Batch complete: {} successful, {} failed",
                result.success_count,
                result.errors.len()
            );
            for (idx, msg) in &result.errors {
                error!("  Operation {idx}: {msg}");
            }
        }
    }

    Ok(true)
}

/// Connect to remote and start agent session
async fn connect_and_start_agent(
    host: &str,
    port: u16,
    user: &str,
    remote_path: &str,
) -> Result<(SshTransport, AgentSession)> {
    let mut transport = SshTransport::connect(host, port, user).await?;

    let bundle = embedded_agents::embedded_bundle();
    if bundle.platforms().is_empty() {
        return Err(color_eyre::eyre::eyre!(
            "No embedded agent binaries - cannot sync"
        ));
    }

    transport.ensure_agent(&bundle).await?;

    debug!("Starting remote agent...");
    let agent = transport.start_agent(remote_path).await?;

    Ok((transport, agent))
}

async fn sync_command(
    local: &PathBuf,
    remote: &str,
    port: u16,
    includes: &[String],
    no_delete: bool,
) -> Result<()> {
    let (user, host, remote_path) = parse_remote(remote)?;

    info!(
        "Syncing {} -> {}@{}:{}",
        local.display(),
        user,
        host,
        remote_path
    );

    info!("Scanning local directory...");
    let mut scanner = Scanner::new(local);
    for pattern in includes {
        scanner = scanner.include(pattern);
    }
    let entries = scanner.scan()?;
    let local_snapshot = Snapshot::from_entries(entries);
    info!("Found {} local files", local_snapshot.len());

    let (_transport, mut agent) = connect_and_start_agent(&host, port, &user, &remote_path).await?;

    info!("Getting remote snapshot...");
    let remote_snapshot = agent.snapshot().await?;
    info!("Found {} remote files", remote_snapshot.len());

    // Use sync_once logic but with pre-fetched snapshots for initial sync
    let diff = remote_snapshot.diff(&local_snapshot);
    let deletions = if no_delete { 0 } else { diff.removed.len() };

    if diff.is_empty() || (diff.added.is_empty() && diff.modified.is_empty() && no_delete) {
        info!("Already in sync!");
    } else {
        info!(
            "Changes: {} added, {} modified, {} removed",
            diff.added.len(),
            diff.modified.len(),
            deletions
        );

        for path in &diff.added {
            info!("  + {}", path.display());
        }
        for path in &diff.modified {
            info!("  ~ {}", path.display());
        }
        if !no_delete {
            for path in &diff.removed {
                info!("  - {}", path.display());
            }
        }

        let added: Vec<_> = diff.added.iter().collect();
        let modified: Vec<_> = diff.modified.iter().collect();
        let to_delete: Vec<_> = if no_delete {
            vec![]
        } else {
            diff.removed.iter().collect()
        };

        let total_ops = added.len() + modified.len() + to_delete.len();

        if total_ops > 0 {
            let mut transfers: Vec<(&Path, TransferData)> = Vec::new();
            let mut total_bytes = 0u64;
            let mut delta_count = 0usize;

            for path in &added {
                let entry = local_snapshot
                    .files
                    .get(*path)
                    .ok_or_else(|| color_eyre::eyre::eyre!("File not found: {}", path.display()))?;
                let full_path = local.join(path);
                let data = std::fs::read(&full_path)?;
                total_bytes += data.len() as u64;
                transfers.push((
                    path,
                    TransferData::Full {
                        data,
                        executable: entry.executable,
                    },
                ));
            }

            for path in &modified {
                let entry = local_snapshot
                    .files
                    .get(*path)
                    .ok_or_else(|| color_eyre::eyre::eyre!("File not found: {}", path.display()))?;
                let transfer =
                    prepare_transfer(local, path, &remote_snapshot, &mut agent, entry.executable)
                        .await?;
                match &transfer {
                    TransferData::Delta { data, .. } => {
                        delta_count += 1;
                        total_bytes += data.len() as u64;
                    }
                    TransferData::Full { data, .. } | TransferData::CompressedFull { data, .. } => {
                        total_bytes += data.len() as u64;
                    }
                }
                transfers.push((path, transfer));
            }

            if delta_count > 0 {
                info!("Using delta transfer for {delta_count} modified files");
            }

            info!(
                "Transferring {} in {} operations (pipelined)...",
                humansize::format_size(total_bytes, humansize::BINARY),
                total_ops
            );
            agent.start_batch(total_ops as u32).await?;

            for (i, (path, transfer)) in transfers.iter().enumerate() {
                debug!(
                    "[{}/{}] Queueing {}",
                    i + 1,
                    transfers.len(),
                    path.display()
                );
                match transfer {
                    TransferData::Full { data, executable }
                    | TransferData::CompressedFull { data, executable } => {
                        agent.queue_write_file(path, data, *executable).await?;
                    }
                    TransferData::Delta { data, executable } => {
                        agent.queue_write_delta(path, data, *executable).await?;
                    }
                }
            }

            for path in &to_delete {
                debug!("Queueing delete: {}", path.display());
                agent.queue_delete_file(path).await?;
            }

            let result = agent.end_batch().await?;

            if result.errors.is_empty() {
                info!(
                    "Batch complete: {} operations successful",
                    result.success_count
                );
            } else {
                warn!(
                    "Batch complete: {} successful, {} failed",
                    result.success_count,
                    result.errors.len()
                );
                for (idx, msg) in &result.errors {
                    error!("  Operation {idx}: {msg}");
                }
            }
        }
    }

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
    no_delete: bool,
) -> Result<()> {
    let (user, host, remote_path) = parse_remote(remote)?;

    info!(
        "Watching {} -> {}@{}:{}",
        local.display(),
        user,
        host,
        remote_path
    );

    // Connect and keep connection alive
    let (mut transport, mut agent) =
        connect_and_start_agent(&host, port, &user, &remote_path).await?;

    // Initial sync
    info!("Initial sync...");
    match sync_once(local, &mut agent, includes, no_delete).await {
        Ok(true) => info!("Initial sync complete"),
        Ok(false) => info!("Already in sync!"),
        Err(e) => {
            return Err(e.wrap_err("initial sync failed"));
        }
    }

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

                debug!("Detected {} changed paths", paths.len());

                // Sync using existing connection
                match sync_once(local, &mut agent, includes, no_delete).await {
                    Ok(true) => {}  // Changes synced, already logged
                    Ok(false) => {} // No actual changes, stay quiet
                    Err(e) => {
                        warn!("Sync failed: {e}, reconnecting...");
                        // Try to reconnect
                        match connect_and_start_agent(&host, port, &user, &remote_path).await {
                            Ok((new_transport, new_agent)) => {
                                transport = new_transport;
                                agent = new_agent;
                                info!("Reconnected, retrying sync...");
                                if let Err(e) =
                                    sync_once(local, &mut agent, includes, no_delete).await
                                {
                                    error!("Sync failed after reconnect: {e}");
                                }
                            }
                            Err(e) => {
                                error!("Reconnection failed: {e}");
                            }
                        }
                    }
                }
            }
            Err(e) => {
                error!("Watch error: {e}");
                break;
            }
        }
    }

    drop(transport); // Explicit drop to silence unused warning
    agent.shutdown().await?;
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
