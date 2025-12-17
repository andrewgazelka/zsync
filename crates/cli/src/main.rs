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

use bytes::Bytes;

use zsync_core::{
    ChunkConfig, ContentHash, FileManifest, Scanner, Snapshot, ZsyncConfig, chunk_data,
};
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

        /// Show what would be synced without actually syncing
        #[arg(long)]
        dry_run: bool,
    },

    /// Show sync status without making changes (alias for sync --dry-run)
    Status {
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

        /// Don't consider remote-only files as "to be deleted"
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
            dry_run,
        } => {
            sync_command(&local, &remote, port, &include, no_delete, dry_run).await?;
        }
        Commands::Status {
            local,
            remote,
            port,
            include,
            no_delete,
        } => {
            // Status is just sync --dry-run
            sync_command(&local, &remote, port, &include, no_delete, true).await?;
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

/// File prepared for CAS transfer
struct FileTransfer {
    path: PathBuf,
    manifest: FileManifest,
    mode: u32,
    /// Chunks that need to be transferred (hash -> data)
    chunks: Vec<(ContentHash, Bytes)>,
}

/// Prepare files for CAS transfer - chunks files and creates manifests
fn prepare_cas_transfers(
    local: &Path,
    paths: &[&Path],
    snapshot: &Snapshot,
) -> Result<Vec<FileTransfer>> {
    let mut transfers = Vec::with_capacity(paths.len());

    for path in paths {
        let entry = snapshot
            .files
            .get(*path)
            .ok_or_else(|| color_eyre::eyre::eyre!("File not found: {}", path.display()))?;
        let full_path = local.join(path);
        let data = std::fs::read(&full_path)?;
        let file_hash = ContentHash::from_bytes(&data);

        // Chunk the file
        let config = ChunkConfig::default();
        let chunks: Vec<_> = chunk_data(&data, &config).collect();
        let chunk_hashes: Vec<ContentHash> = chunks.iter().map(|c| c.hash).collect();

        // Create chunks with data
        let mut file_chunks = Vec::with_capacity(chunks.len());
        for chunk in &chunks {
            let start = chunk.offset as usize;
            let end = start + chunk.length as usize;
            file_chunks.push((chunk.hash, Bytes::copy_from_slice(&data[start..end])));
        }

        transfers.push(FileTransfer {
            path: (*path).to_path_buf(),
            manifest: FileManifest {
                file_hash,
                size: data.len() as u64,
                chunks: chunk_hashes,
            },
            mode: entry.mode,
            chunks: file_chunks,
        });
    }

    Ok(transfers)
}

/// Transfer files using CAS - only sends chunks the server doesn't have
async fn transfer_files_cas(
    agent: &mut AgentSession,
    transfers: &[FileTransfer],
    to_delete: &[&Path],
) -> Result<()> {
    // Collect all unique chunks across all files
    let mut all_chunks: std::collections::HashMap<ContentHash, Bytes> =
        std::collections::HashMap::new();
    for transfer in transfers {
        for (hash, data) in &transfer.chunks {
            all_chunks.entry(*hash).or_insert_with(|| data.clone());
        }
    }

    let all_hashes: Vec<ContentHash> = all_chunks.keys().copied().collect();
    info!(
        "Checking {} unique chunks across {} files...",
        all_hashes.len(),
        transfers.len()
    );

    // Ask server which chunks are missing
    let missing_hashes = agent.check_chunks(&all_hashes).await?;
    let missing_set: std::collections::HashSet<_> = missing_hashes.iter().collect();

    // Prepare missing chunks for transfer
    let chunks_to_send: Vec<(ContentHash, Bytes)> = all_chunks
        .into_iter()
        .filter(|(h, _)| missing_set.contains(h))
        .collect();

    let total_chunk_bytes: usize = chunks_to_send.iter().map(|(_, d)| d.len()).sum();

    if chunks_to_send.is_empty() {
        info!("All chunks already on server (deduplication win!)");
    } else {
        info!(
            "Transferring {} missing chunks ({})...",
            chunks_to_send.len(),
            humansize::format_size(total_chunk_bytes, humansize::BINARY)
        );
        agent.store_chunks(&chunks_to_send).await?;
    }

    // Send file manifests and deletes in a batch
    let total_ops = transfers.len() + to_delete.len();
    agent.start_batch(total_ops as u32).await?;

    for transfer in transfers {
        debug!("Queueing manifest: {}", transfer.path.display());
        agent
            .queue_write_manifest(&transfer.path, &transfer.manifest, transfer.mode)
            .await?;
    }

    for path in to_delete {
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

    Ok(())
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

    // Warn if local directory appears empty
    if local_snapshot.is_empty() {
        warn!(
            "Local directory '{}' contains no files (after .gitignore filtering)",
            local.display()
        );
    }

    // Get remote snapshot
    debug!("Getting remote snapshot...");
    let remote_snapshot = agent.snapshot().await?;
    debug!("Found {} remote files", remote_snapshot.len());

    // Compute diff
    let diff = remote_snapshot.diff(&local_snapshot);

    let deletions = if no_delete { 0 } else { diff.removed.len() };

    if diff.is_empty() || (diff.added.is_empty() && diff.modified.is_empty() && no_delete) {
        debug!(
            "Already in sync ({} local, {} remote)",
            local_snapshot.len(),
            remote_snapshot.len()
        );
        return Ok(false);
    }

    // Count modification reasons
    let (hash_only, mode_only, both) = diff.modified.iter().fold((0, 0, 0), |(h, m, b), f| match f
        .reason
    {
        zsync_core::ModifyReason::HashChanged => (h + 1, m, b),
        zsync_core::ModifyReason::ModeChanged => (h, m + 1, b),
        zsync_core::ModifyReason::Both => (h, m, b + 1),
    });

    info!(
        "Changes: {} added, {} modified, {} removed",
        diff.added.len(),
        diff.modified.len(),
        deletions
    );

    // Show breakdown if there are mode-only changes (common cross-platform issue)
    if mode_only > 0 || both > 0 {
        info!(
            "  Modified breakdown: {} content, {} mode-only, {} both",
            hash_only, mode_only, both
        );
    }

    // Print individual file changes with sizes
    for path in &diff.added {
        let size = local_snapshot.files.get(path).map_or(0, |e| e.size);
        info!(
            "  + {} ({})",
            path.display(),
            humansize::format_size(size, humansize::BINARY)
        );
    }
    for m in &diff.modified {
        let size = local_snapshot.files.get(&m.path).map_or(0, |e| e.size);
        let reason = match m.reason {
            zsync_core::ModifyReason::HashChanged => "content".to_string(),
            zsync_core::ModifyReason::ModeChanged => {
                format!("mode {:o}->{:o}", m.old_mode, m.new_mode)
            }
            zsync_core::ModifyReason::Both => {
                format!("content+mode {:o}->{:o}", m.old_mode, m.new_mode)
            }
        };
        info!(
            "  ~ {} ({}, {})",
            m.path.display(),
            humansize::format_size(size, humansize::BINARY),
            reason
        );
    }
    if !no_delete {
        for path in &diff.removed {
            info!("  - {}", path.display());
        }
    }

    // Collect all files to transfer
    let mut all_paths: Vec<&Path> = Vec::new();
    all_paths.extend(diff.added.iter().map(std::path::PathBuf::as_path));
    all_paths.extend(diff.modified.iter().map(|m| m.path.as_path()));

    let to_delete: Vec<&Path> = if no_delete {
        vec![]
    } else {
        diff.removed
            .iter()
            .map(std::path::PathBuf::as_path)
            .collect()
    };

    if !all_paths.is_empty() || !to_delete.is_empty() {
        // Prepare CAS transfers (chunk files, create manifests)
        let transfers = prepare_cas_transfers(local, &all_paths, &local_snapshot)?;

        // Transfer using CAS (deduplicating chunks)
        transfer_files_cas(agent, &transfers, &to_delete).await?;
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

#[allow(clippy::too_many_lines)]
async fn sync_command(
    local: &PathBuf,
    remote: &str,
    port: u16,
    includes: &[String],
    no_delete: bool,
    dry_run: bool,
) -> Result<()> {
    let (user, host, remote_path) = parse_remote(remote)?;

    if dry_run {
        info!(
            "Checking {} -> {}@{}:{} (dry-run, no changes will be made)",
            local.display(),
            user,
            host,
            remote_path
        );
    } else {
        info!(
            "Syncing {} -> {}@{}:{}",
            local.display(),
            user,
            host,
            remote_path
        );
    }

    info!("Scanning local directory...");
    let mut scanner = Scanner::new(local);
    for pattern in includes {
        scanner = scanner.include(pattern);
    }
    let entries = scanner.scan()?;
    let local_snapshot = Snapshot::from_entries(entries);
    info!("Found {} local files", local_snapshot.len());

    // Warn if local directory appears empty - might indicate wrong path or overly aggressive gitignore
    if local_snapshot.is_empty() {
        warn!(
            "Local directory '{}' contains no files (after .gitignore filtering). \
             Check that this is the correct path and that your files aren't all gitignored.",
            local.display()
        );
    }

    let (_transport, mut agent) = connect_and_start_agent(&host, port, &user, &remote_path).await?;

    info!("Getting remote snapshot...");
    let remote_snapshot = agent.snapshot().await?;
    info!("Found {} remote files", remote_snapshot.len());

    // Use sync_once logic but with pre-fetched snapshots for initial sync
    let diff = remote_snapshot.diff(&local_snapshot);
    let deletions = if no_delete { 0 } else { diff.removed.len() };

    if diff.is_empty() || (diff.added.is_empty() && diff.modified.is_empty() && no_delete) {
        info!(
            "Already in sync! ({} local files, {} remote files)",
            local_snapshot.len(),
            remote_snapshot.len()
        );
        // Show sample matching files in debug mode
        if !local_snapshot.files.is_empty() {
            let sample: Vec<_> = local_snapshot.files.keys().take(3).collect();
            debug!("Sample matching files: {:?}", sample);
        }
    } else {
        // Count modification reasons
        let (hash_only, mode_only, both) =
            diff.modified
                .iter()
                .fold((0, 0, 0), |(h, m, b), f| match f.reason {
                    zsync_core::ModifyReason::HashChanged => (h + 1, m, b),
                    zsync_core::ModifyReason::ModeChanged => (h, m + 1, b),
                    zsync_core::ModifyReason::Both => (h, m, b + 1),
                });

        info!(
            "Changes: {} added, {} modified, {} removed",
            diff.added.len(),
            diff.modified.len(),
            deletions
        );

        // Show breakdown if there are mode-only changes (common cross-platform issue)
        if mode_only > 0 || both > 0 {
            info!(
                "  Modified breakdown: {} content, {} mode-only, {} both",
                hash_only, mode_only, both
            );
        }

        for path in &diff.added {
            let size = local_snapshot.files.get(path).map_or(0, |e| e.size);
            info!(
                "  + {} ({})",
                path.display(),
                humansize::format_size(size, humansize::BINARY)
            );
        }
        for m in &diff.modified {
            let size = local_snapshot.files.get(&m.path).map_or(0, |e| e.size);
            let reason = match m.reason {
                zsync_core::ModifyReason::HashChanged => "content".to_string(),
                zsync_core::ModifyReason::ModeChanged => {
                    format!("mode {:o}->{:o}", m.old_mode, m.new_mode)
                }
                zsync_core::ModifyReason::Both => {
                    format!("content+mode {:o}->{:o}", m.old_mode, m.new_mode)
                }
            };
            info!(
                "  ~ {} ({}, {})",
                m.path.display(),
                humansize::format_size(size, humansize::BINARY),
                reason
            );
        }
        if !no_delete {
            for path in &diff.removed {
                info!("  - {}", path.display());
            }
        }

        // In dry-run mode, just show what would be done and exit
        if dry_run {
            info!("Dry-run complete. Use 'zsync sync' without --dry-run to apply changes.");
            agent.shutdown().await?;
            return Ok(());
        }

        // Collect all files to transfer
        let mut all_paths: Vec<&Path> = Vec::new();
        all_paths.extend(diff.added.iter().map(std::path::PathBuf::as_path));
        all_paths.extend(diff.modified.iter().map(|m| m.path.as_path()));

        let to_delete: Vec<&Path> = if no_delete {
            vec![]
        } else {
            diff.removed
                .iter()
                .map(std::path::PathBuf::as_path)
                .collect()
        };

        if !all_paths.is_empty() || !to_delete.is_empty() {
            // Prepare CAS transfers (chunk files, create manifests)
            let transfers = prepare_cas_transfers(local, &all_paths, &local_snapshot)?;

            // Transfer using CAS (deduplicating chunks)
            transfer_files_cas(&mut agent, &transfers, &to_delete).await?;
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

    // Load .zsync.toml config
    let config = ZsyncConfig::load(local)?;

    // Merge includes from config and CLI args
    let mut all_includes: Vec<String> = config.include.clone();
    for inc in includes {
        if !all_includes.contains(inc) {
            all_includes.push(inc.clone());
        }
    }

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

    // Start port forwards from config
    let mut forward_handles = Vec::new();
    for fwd in &config.forward {
        info!(
            "Forwarding localhost:{} -> {}:{}",
            fwd.local, fwd.remote_host, fwd.remote
        );
        let handle = transport
            .forward_port(fwd.local, &fwd.remote_host, fwd.remote)
            .await?;
        forward_handles.push(handle);
    }

    // Initial sync
    info!("Initial sync...");
    match sync_once(local, &mut agent, &all_includes, no_delete).await {
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
                match sync_once(local, &mut agent, &all_includes, no_delete).await {
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
                                    sync_once(local, &mut agent, &all_includes, no_delete).await
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

    // Abort port forward tasks
    for handle in forward_handles {
        handle.abort();
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
