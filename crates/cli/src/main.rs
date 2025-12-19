//! zsync: Fast, modern file synchronization
//!
//! A modern alternative to mutagen/rsync with:
//! - Native .gitignore support
//! - BLAKE3 content-addressed hashing
//! - Binary protocol (no JSON overhead)
//! - Pure Rust SSH transport
//! - File watching with debouncing

mod debug_log;
mod embedded_agents;
mod progress;

use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::builder::styling::{AnsiColor, Effects};
use clap::{Parser, builder::Styles};
use color_eyre::Result;
use ignore::WalkBuilder;
use notify::RecursiveMode;
use notify_debouncer_full::{DebounceEventResult, new_debouncer};
use tracing::{debug, error, info, warn};

use bytes::Bytes;

use zsync_core::{
    ChunkConfig, ContentHash, FileManifest, Scanner, Snapshot, ZsyncConfig, chunk_data,
};
use zsync_transport::{AgentSession, SshTransport};

/// Checks if paths are ignored by gitignore rules.
/// Pre-builds an ignore matcher from the root directory for efficient repeated checks.
struct IgnoreChecker {
    /// Set of all non-ignored file paths (relative to root)
    included_paths: std::collections::HashSet<PathBuf>,
}

impl IgnoreChecker {
    /// Build an ignore checker by walking the directory once.
    fn new(root: &Path) -> Self {
        let mut builder = WalkBuilder::new(root);
        builder
            .hidden(false)
            .git_ignore(true)
            .git_global(true)
            .git_exclude(true)
            .require_git(false)
            .filter_entry(|e| e.file_name() != ".git");

        let included_paths: std::collections::HashSet<PathBuf> = builder
            .build()
            .flatten()
            .filter_map(|entry| {
                let path = entry.path();
                path.strip_prefix(root).ok().map(Path::to_path_buf)
            })
            .collect();

        Self { included_paths }
    }

    /// Check if a relative path is ignored
    fn is_ignored(&self, rel_path: &Path) -> bool {
        // Check if the path or any of its ancestors is in our included set
        // For a file like "target/debug/foo", we need to check if "target" would be walked
        // If "target" isn't in our set, then "target/debug/foo" is ignored
        let mut check_path = rel_path.to_path_buf();
        loop {
            if self.included_paths.contains(&check_path) {
                return false; // This path or ancestor is included
            }
            if !check_path.pop() {
                break;
            }
        }
        true // Neither the path nor any ancestor is in the included set
    }
}

/// Maximum bytes of chunk data per batch to avoid SSH flow control deadlock.
///
/// When uploading chunks, we send them in batches of approximately this size.
/// Each batch is a separate STORE_CHUNKS message that gets an OK response
/// before the next batch is sent. This prevents the SSH channel from filling
/// up and deadlocking when the agent can't process data fast enough.
///
/// The default SSH window size is typically 2MB (2097152 bytes), so 1MB per
/// batch provides good throughput while staying well under the limit.
const CHUNK_BATCH_BYTES: u64 = 1_000_000;

/// Maximum number of manifest operations per batch to avoid SSH flow control deadlock.
///
/// File manifest operations are smaller than chunk uploads, but sending hundreds
/// without waiting for acknowledgement can still fill the SSH window.
const MANIFEST_BATCH_SIZE: usize = 100;

/// A manifest operation to be batched.
enum ManifestOp<'a> {
    Write {
        path: &'a std::path::Path,
        manifest: &'a FileManifest,
        mode: u32,
    },
    Delete {
        path: &'a std::path::Path,
    },
}

/// Result of batched manifest operations.
struct ManifestBatchResult {
    success_count: u32,
    errors: Vec<(u32, String)>,
}

/// Execute manifest operations in batches to avoid SSH flow control deadlock.
async fn execute_manifest_batches(
    agent: &mut AgentSession,
    ops: &[ManifestOp<'_>],
) -> Result<ManifestBatchResult> {
    let mut total_success = 0u32;
    let mut all_errors: Vec<(u32, String)> = Vec::new();

    for batch in ops.chunks(MANIFEST_BATCH_SIZE) {
        agent.start_batch(batch.len() as u32).await?;

        for op in batch {
            match op {
                ManifestOp::Write {
                    path,
                    manifest,
                    mode,
                } => {
                    progress::syncing_file(path, manifest.size, progress::SyncDirection::Upload);
                    agent.queue_write_manifest(path, manifest, *mode).await?;
                }
                ManifestOp::Delete { path } => {
                    progress::deleting_file(path);
                    agent.queue_delete_file(path).await?;
                }
            }
        }

        let result = agent.end_batch().await?;
        total_success += result.success_count;
        all_errors.extend(result.errors);
    }

    Ok(ManifestBatchResult {
        success_count: total_success,
        errors: all_errors,
    })
}

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

Examples:
  zsync root@host                    # Sync to ~/zsync/<local_dir>
  zsync root@host -p 2222            # Custom SSH port
  zsync root@host:2222               # Port via colon (same as -p)
  zsync root@host:/workspace         # Explicit remote path
  zsync root@host --watch            # Continuous sync
  zsync root@host --delete           # Delete remote files not in local
"#)]
struct Cli {
    /// Remote destination (user@host, user@host:port, or user@host:/path)
    remote: String,

    /// Local directory path
    #[arg(default_value = ".")]
    local: PathBuf,

    /// SSH port (can also use user@host:port syntax)
    #[arg(short, long)]
    port: Option<u16>,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Watch for changes and sync continuously
    #[arg(short, long)]
    watch: bool,

    /// Delete remote files that don't exist locally (default: keep them)
    #[arg(long)]
    delete: bool,

    /// Force-include files even if gitignored (e.g., .env)
    #[arg(short, long)]
    include: Vec<String>,

    /// Debounce delay in milliseconds (for watch mode)
    #[arg(short, long, default_value = "100")]
    debounce: u64,

    /// Show what would be synced without making changes
    #[arg(long)]
    dry_run: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    let cli = Cli::parse();

    // Initialize progress UI (detects Ghostty terminal for OSC 9;4 progress protocol)
    progress::init();

    // Initialize combined logging: file (detailed trace) + console (through MultiProgress)
    // The guard must be kept alive for the log file to be written
    let session = debug_log::init();

    // Show log file path at startup (direct eprintln, not through tracing)
    eprintln!(
        "{}  Debug log: {}",
        console::style("Trace").cyan().bold(),
        session.log_path.display()
    );

    // Keep the guard alive
    let _log_guard = session.guard;

    // Canonicalize local path for consistent directory name extraction
    let local = cli
        .local
        .canonicalize()
        .unwrap_or_else(|_| cli.local.clone());

    // Parse remote destination (includes port if specified)
    let remote = parse_remote(&cli.remote, cli.port, &local);

    if cli.watch {
        watch_command(&cli.local, &remote, cli.debounce, &cli.include, cli.delete).await?;
    } else {
        sync_command(&cli.local, &remote, &cli.include, cli.delete, cli.dry_run).await?;
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
    let progress = progress::SyncProgress::new();

    // Collect all unique chunks across all files
    let mut all_chunks: std::collections::HashMap<ContentHash, Bytes> =
        std::collections::HashMap::new();
    for transfer in transfers {
        for (hash, data) in &transfer.chunks {
            all_chunks.entry(*hash).or_insert_with(|| data.clone());
        }
    }

    let all_hashes: Vec<ContentHash> = all_chunks.keys().copied().collect();
    progress::checking_chunks(all_hashes.len(), transfers.len());

    // Ask server which chunks are missing
    let missing_hashes = agent.check_chunks(&all_hashes).await?;
    let missing_set: std::collections::HashSet<_> = missing_hashes.iter().collect();

    // Prepare missing chunks for transfer
    let chunks_to_send: Vec<(ContentHash, Bytes)> = all_chunks
        .into_iter()
        .filter(|(h, _)| missing_set.contains(h))
        .collect();

    let total_chunk_bytes: u64 = chunks_to_send.iter().map(|(_, d)| d.len() as u64).sum();

    if chunks_to_send.is_empty() {
        progress::chunks_deduped();
    } else {
        // Calculate total bytes including protocol overhead (36 bytes header per chunk)
        let total_wire_bytes = total_chunk_bytes + (chunks_to_send.len() as u64 * 36);

        // Show progress bar for chunk upload with streaming progress
        let upload_bar = progress::upload_bar(total_wire_bytes);

        // Show summary of files being uploaded
        let file_summary = if transfers.len() == 1 {
            transfers[0]
                .path
                .file_name()
                .map_or_else(
                    || transfers[0].path.to_string_lossy(),
                    |n| n.to_string_lossy(),
                )
                .to_string()
        } else {
            format!("{} files", transfers.len())
        };
        upload_bar.set_message(&file_summary);

        // Split chunks into batches to avoid SSH flow control deadlock.
        // Each batch is sent as a separate STORE_CHUNKS message, and we wait
        // for the OK response before sending the next batch.
        let mut batch: Vec<(ContentHash, Bytes)> = Vec::new();
        let mut batch_bytes: u64 = 0;

        for (hash, data) in chunks_to_send {
            let chunk_wire_bytes = 36 + data.len() as u64; // header + data

            // If adding this chunk would exceed batch limit, flush the current batch first
            if !batch.is_empty() && batch_bytes + chunk_wire_bytes > CHUNK_BATCH_BYTES {
                tracing::debug!(
                    "Sending batch of {} chunks ({} bytes)",
                    batch.len(),
                    batch_bytes
                );
                agent
                    .store_chunks_with_progress(&batch, |bytes| {
                        upload_bar.add(bytes);
                    })
                    .await?;
                batch.clear();
                batch_bytes = 0;
            }

            batch.push((hash, data));
            batch_bytes += chunk_wire_bytes;
        }

        // Send any remaining chunks in the final batch
        if !batch.is_empty() {
            tracing::debug!(
                "Sending final batch of {} chunks ({} bytes)",
                batch.len(),
                batch_bytes
            );
            agent
                .store_chunks_with_progress(&batch, |bytes| {
                    upload_bar.add(bytes);
                })
                .await?;
        }

        upload_bar.finish();
    }

    // Collect all operations to batch them
    let mut all_ops: Vec<ManifestOp<'_>> = Vec::with_capacity(transfers.len() + to_delete.len());
    for transfer in transfers {
        all_ops.push(ManifestOp::Write {
            path: &transfer.path,
            manifest: &transfer.manifest,
            mode: transfer.mode,
        });
    }
    for path in to_delete {
        all_ops.push(ManifestOp::Delete { path });
    }

    // Send file manifests and deletes in batches
    let batch_result = execute_manifest_batches(agent, &all_ops).await?;

    progress.finish(batch_result.success_count, batch_result.errors.len());

    for (idx, msg) in &batch_result.errors {
        error!("  Operation {idx}: {msg}");
    }

    Ok(())
}

/// Perform a single sync operation using an existing agent session.
/// Returns true if changes were synced, false if already in sync.
async fn sync_once(
    local: &Path,
    agent: &mut AgentSession,
    includes: &[String],
    delete: bool,
) -> Result<bool> {
    // Scan local
    debug!("Scanning local directory...");
    let mut scanner = Scanner::new(local);
    for pattern in includes {
        scanner = scanner.include(pattern);
    }
    let entries = scanner.scan()?;
    let local_snapshot = Snapshot::from_entries(entries);
    progress::scanning_local(local_snapshot.len());

    // Warn if local directory appears empty
    if local_snapshot.is_empty() {
        warn!(
            "Local directory '{}' contains no files (after .gitignore filtering)",
            local.display()
        );
    }

    // Get remote snapshot
    let remote_snapshot = agent.snapshot().await?;
    progress::checking_remote(remote_snapshot.len());

    // Compute diff
    let diff = remote_snapshot.diff(&local_snapshot);

    let deletions = if delete { diff.removed.len() } else { 0 };

    if diff.is_empty() || (diff.added.is_empty() && diff.modified.is_empty() && !delete) {
        progress::already_in_sync(local_snapshot.len());
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
    if delete {
        for path in &diff.removed {
            info!("  - {}", path.display());
        }
    }

    // Collect all files to transfer
    let mut all_paths: Vec<&Path> = Vec::new();
    all_paths.extend(diff.added.iter().map(std::path::PathBuf::as_path));
    all_paths.extend(diff.modified.iter().map(|m| m.path.as_path()));

    let to_delete: Vec<&Path> = if delete {
        diff.removed
            .iter()
            .map(std::path::PathBuf::as_path)
            .collect()
    } else {
        vec![]
    };

    if !all_paths.is_empty() || !to_delete.is_empty() {
        // Prepare CAS transfers (chunk files, create manifests)
        let transfers = prepare_cas_transfers(local, &all_paths, &local_snapshot)?;

        // Transfer using CAS (deduplicating chunks)
        transfer_files_cas(agent, &transfers, &to_delete).await?;
    }

    Ok(true)
}

/// Sync only specific changed paths (incremental sync for watch mode).
///
/// This is much faster than `sync_once` because it only hashes changed files
/// instead of rescanning the entire directory.
async fn sync_changed_paths(
    local: &Path,
    agent: &mut AgentSession,
    changed_paths: &[&Path],
) -> Result<bool> {
    // Convert absolute paths to relative paths and categorize
    let mut relative_paths: Vec<&std::path::Path> = Vec::new();
    let mut to_delete: Vec<std::path::PathBuf> = Vec::new();

    for abs_path in changed_paths {
        // Skip paths outside our local directory
        let Ok(rel_path) = abs_path.strip_prefix(local) else {
            continue;
        };

        // Check if file exists (modified/added) or was deleted
        if abs_path.is_file() {
            relative_paths.push(rel_path);
        } else if !abs_path.exists() {
            // File was deleted
            to_delete.push(rel_path.to_path_buf());
        }
        // Skip directories
    }

    if relative_paths.is_empty() && to_delete.is_empty() {
        return Ok(false);
    }

    // Scan only the changed files (fast - no full directory walk)
    let scanner = Scanner::new(local);
    let rel_path_refs: Vec<&std::path::Path> = relative_paths.clone();
    let entries = scanner.scan_files(&rel_path_refs)?;

    if entries.is_empty() && to_delete.is_empty() {
        return Ok(false);
    }

    // Build partial snapshot from changed files
    let local_snapshot = Snapshot::from_entries(entries);

    // Log what we're syncing
    let sync_count = local_snapshot.len();
    let delete_count = to_delete.len();

    if sync_count > 0 {
        for (path, entry) in &local_snapshot.files {
            info!(
                "  ~ {} ({})",
                path.display(),
                humansize::format_size(entry.size, humansize::BINARY)
            );
        }
    }
    for path in &to_delete {
        info!("  - {}", path.display());
    }

    // Prepare CAS transfers for changed files
    let all_paths: Vec<&Path> = local_snapshot
        .files
        .keys()
        .map(std::path::PathBuf::as_path)
        .collect();

    if !all_paths.is_empty() || !to_delete.is_empty() {
        let transfers = prepare_cas_transfers(local, &all_paths, &local_snapshot)?;
        let delete_refs: Vec<&Path> = to_delete.iter().map(std::path::PathBuf::as_path).collect();
        transfer_files_cas(agent, &transfers, &delete_refs).await?;
    }

    info!(
        "Incremental sync: {} updated, {} deleted",
        sync_count, delete_count
    );

    Ok(true)
}

/// Connect to remote and start agent session
async fn connect_and_start_agent(
    host: &str,
    port: u16,
    user: &str,
    remote_path: &str,
) -> Result<(SshTransport, AgentSession)> {
    let spinner = progress::connecting(host, port);
    let mut transport = SshTransport::connect(host, port, user).await?;
    progress::connected(spinner, "SSH");

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
    remote: &RemoteSpec,
    includes: &[String],
    delete: bool,
    dry_run: bool,
) -> Result<()> {
    let RemoteSpec {
        user,
        host,
        port,
        path: remote_path,
    } = remote;

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

    let mut scanner = Scanner::new(local);
    for pattern in includes {
        scanner = scanner.include(pattern);
    }
    let entries = scanner.scan()?;
    let local_snapshot = Snapshot::from_entries(entries);
    progress::scanning_local(local_snapshot.len());

    // Warn if local directory appears empty - might indicate wrong path or overly aggressive gitignore
    if local_snapshot.is_empty() {
        warn!(
            "Local directory '{}' contains no files (after .gitignore filtering). \
             Check that this is the correct path and that your files aren't all gitignored.",
            local.display()
        );
    }

    let (_transport, mut agent) = connect_and_start_agent(host, *port, user, remote_path).await?;

    let remote_snapshot = agent.snapshot().await?;
    progress::checking_remote(remote_snapshot.len());

    // Use sync_once logic but with pre-fetched snapshots for initial sync
    let diff = remote_snapshot.diff(&local_snapshot);
    let deletions = if delete { diff.removed.len() } else { 0 };

    if diff.is_empty() || (diff.added.is_empty() && diff.modified.is_empty() && !delete) {
        progress::already_in_sync(local_snapshot.len());
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
        if delete {
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

        let to_delete: Vec<&Path> = if delete {
            diff.removed
                .iter()
                .map(std::path::PathBuf::as_path)
                .collect()
        } else {
            vec![]
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

#[allow(clippy::too_many_lines)]
async fn watch_command(
    local: &PathBuf,
    remote: &RemoteSpec,
    debounce_ms: u64,
    includes: &[String],
    delete: bool,
) -> Result<()> {
    let RemoteSpec {
        user,
        host,
        port,
        path: remote_path,
    } = remote;

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
        "Watching {} <-> {}@{}:{} (bidirectional)",
        local.display(),
        user,
        host,
        remote_path
    );

    // Connect with watch mode enabled for bidirectional sync
    let (mut transport, mut agent) =
        connect_and_start_agent_watch(host, *port, user, remote_path).await?;

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

    // Initial sync (progress output comes from sync_once/transfer_files_cas)
    sync_once(local, &mut agent, &all_includes, delete).await?;

    // Setup local file watcher with tokio channel for async compatibility
    let (tx, mut watch_rx) = tokio::sync::mpsc::channel(100);

    let mut debouncer = new_debouncer(
        Duration::from_millis(debounce_ms),
        None,
        move |result: DebounceEventResult| {
            if let Ok(events) = result {
                let _ = tx.blocking_send(events);
            }
        },
    )?;

    debouncer.watch(local, RecursiveMode::Recursive)?;

    // Build ignore checker once - walks directory to find all non-ignored paths
    let ignore_checker = IgnoreChecker::new(local);

    progress::watch_mode();

    // Bidirectional watch loop:
    // - Handle local file changes (sync local -> remote)
    // - Handle CHANGE_NOTIFY from agent (sync remote -> local)
    loop {
        // Use a short poll timeout to check for remote changes
        let poll_timeout = Duration::from_millis(100);

        tokio::select! {
            biased;

            // Check for local file changes
            Some(events) = watch_rx.recv() => {
                // Collect unique changed paths, filtering out gitignored files
                let paths: Vec<_> = events
                    .iter()
                    .flat_map(|e| e.paths.iter())
                    .filter(|path| {
                        // Get relative path for gitignore matching
                        let Ok(rel_path) = path.strip_prefix(local) else {
                            return false;
                        };
                        // Check against pre-built ignore set
                        !ignore_checker.is_ignored(rel_path)
                    })
                    .collect::<std::collections::HashSet<_>>()
                    .into_iter()
                    .collect();

                if paths.is_empty() {
                    continue;
                }

                debug!("Local changes: {} paths (after gitignore filter)", paths.len());

                // Incremental sync local -> remote
                let path_refs: Vec<&Path> = paths.iter().map(|p| p.as_path()).collect();
                if let Err(e) = sync_changed_paths(local, &mut agent, &path_refs).await {
                    warn!("Sync failed: {e}, will retry on next change");
                }
            }

            // Check for remote changes via CHANGE_NOTIFY
            remote_result = agent.try_read_message(poll_timeout) => {
                match remote_result {
                    Ok(Some(zsync_core::Message::ChangeNotify)) => {
                        info!("Remote files changed, syncing...");
                        // For now, do a full sync from remote
                        // TODO: implement proper remote -> local incremental sync
                        if let Err(e) = sync_once(local, &mut agent, &all_includes, delete).await {
                            warn!("Sync from remote failed: {e}");
                        }
                    }
                    Ok(Some(other)) => {
                        debug!("Unexpected message from agent: {:?}", other);
                    }
                    Ok(None) => {
                        // No message, that's fine
                    }
                    Err(e) => {
                        warn!("Error reading from agent: {e}, reconnecting...");
                        // Try to reconnect
                        match connect_and_start_agent_watch(host, *port, user, remote_path).await {
                            Ok((new_transport, new_agent)) => {
                                transport = new_transport;
                                agent = new_agent;
                                info!("Reconnected, doing full sync...");
                                if let Err(e) =
                                    sync_once(local, &mut agent, &all_includes, delete).await
                                {
                                    error!("Sync failed after reconnect: {e}");
                                }
                            }
                            Err(e) => {
                                error!("Reconnection failed: {e}");
                                break;
                            }
                        }
                    }
                }
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

/// Connect to remote and start agent session with watch mode for bidirectional sync
async fn connect_and_start_agent_watch(
    host: &str,
    port: u16,
    user: &str,
    remote_path: &str,
) -> Result<(SshTransport, AgentSession)> {
    let spinner = progress::connecting(host, port);
    let mut transport = SshTransport::connect(host, port, user).await?;
    progress::connected(spinner, "SSH");

    let bundle = embedded_agents::embedded_bundle();
    if bundle.platforms().is_empty() {
        return Err(color_eyre::eyre::eyre!(
            "No embedded agent binaries - cannot sync"
        ));
    }

    transport.ensure_agent(&bundle).await?;

    debug!("Starting remote agent with watch mode...");
    let agent = transport.start_agent_watch(remote_path).await?;

    Ok((transport, agent))
}

/// Parsed remote destination
struct RemoteSpec {
    user: String,
    host: String,
    port: u16,
    path: String,
}

/// Load SSH config from ~/.ssh/config
fn load_ssh_config() -> Option<ssh2_config::SshConfig> {
    let home = dirs::home_dir()?;
    let config_path = home.join(".ssh/config");
    let file = std::fs::File::open(&config_path).ok()?;
    let mut reader = std::io::BufReader::new(file);
    ssh2_config::SshConfig::default()
        .parse(&mut reader, ssh2_config::ParseRule::ALLOW_UNKNOWN_FIELDS)
        .ok()
}

/// Parse remote string into components.
///
/// Formats:
/// - `user@host` → port 22, path from local dir
/// - `user@host:2222` → port 2222, path from local dir
/// - `user@host:/path` → port 22, explicit path
/// - `user@host:2222:/path` → port 2222, explicit path
/// - `host:/path` → SSH config host with path (user/port from ~/.ssh/config)
/// - `host:path` → SSH config host with relative path
/// - `host` → SSH config host, default path
///
/// The `port_override` takes precedence over port in the remote string.
/// The `local_dir` is used to generate default path when none specified.
fn parse_remote(remote: &str, port_override: Option<u16>, local_dir: &Path) -> RemoteSpec {
    // Check if there's an @ symbol (explicit user@host format)
    let (user, host, parsed_port, parsed_path) = if let Some(at_pos) = remote.find('@') {
        // Explicit user@host format
        let user = remote[..at_pos].to_string();
        let rest = &remote[at_pos + 1..];

        // Find all colons
        let colon_positions: Vec<usize> = rest.match_indices(':').map(|(i, _)| i).collect();

        let (host, parsed_port, parsed_path) = if colon_positions.is_empty() {
            // Just user@host
            (rest.to_string(), 22, None)
        } else {
            let first_colon = colon_positions[0];
            let host = rest[..first_colon].to_string();
            let after_first_colon = &rest[first_colon + 1..];

            if colon_positions.len() >= 2 {
                // Could be host:port:/path - check if first segment is numeric
                let potential_port = &rest[first_colon + 1..colon_positions[1]];

                if let Ok(port_num) = potential_port.parse::<u16>() {
                    // It's host:port:/path
                    let path = rest[colon_positions[1] + 1..].to_string();
                    (host, port_num, Some(path))
                } else {
                    // Not a port number, treat as host:/path/with:colon
                    (host, 22, Some(after_first_colon.to_string()))
                }
            } else {
                // One colon: could be host:port or host:/path
                // If it parses as u16, it's a port; otherwise it's a path
                if let Ok(port_num) = after_first_colon.parse::<u16>() {
                    (host, port_num, None)
                } else {
                    (host, 22, Some(after_first_colon.to_string()))
                }
            }
        };

        (user, host, parsed_port, parsed_path)
    } else {
        // No @ symbol - treat as SSH config host
        // Format: host, host:/path, or host:path
        let colon_pos = remote.find(':');

        let (host_alias, parsed_path) = if let Some(pos) = colon_pos {
            let host = remote[..pos].to_string();
            let path = remote[pos + 1..].to_string();
            (host, Some(path))
        } else {
            (remote.to_string(), None)
        };

        // Look up host in SSH config
        let ssh_config = load_ssh_config();
        let params = ssh_config.as_ref().map(|cfg| cfg.query(&host_alias));

        // Extract user from SSH config, or default to current user
        let user = params
            .as_ref()
            .and_then(|p| p.user.clone())
            .unwrap_or_else(|| std::env::var("USER").unwrap_or_else(|_| "root".to_string()));

        // Extract hostname (may differ from alias) and port from SSH config
        let host = params
            .as_ref()
            .and_then(|p| p.host_name.clone())
            .unwrap_or_else(|| host_alias.clone());

        let parsed_port = params.as_ref().and_then(|p| p.port).unwrap_or(22);

        (user, host, parsed_port, parsed_path)
    };

    // Port override from -p flag takes precedence
    let port = port_override.unwrap_or(parsed_port);

    // Default path: ~/zsync/<local_dir_name>
    let path = parsed_path.unwrap_or_else(|| {
        let dir_name = local_dir
            .file_name()
            .map_or_else(|| "sync".to_string(), |n| n.to_string_lossy().to_string());
        format!("~/zsync/{dir_name}")
    });

    RemoteSpec {
        user,
        host,
        port,
        path,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_local() -> PathBuf {
        PathBuf::from("/test/myproject")
    }

    #[test]
    fn test_parse_remote() {
        let remote = parse_remote("root@example.com:/home/user", None, &test_local());
        assert_eq!(remote.user, "root");
        assert_eq!(remote.host, "example.com");
        assert_eq!(remote.port, 22);
        assert_eq!(remote.path, "/home/user");
    }

    #[test]
    fn test_parse_remote_with_port() {
        let remote = parse_remote("root@example.com:2222:/home/user", None, &test_local());
        assert_eq!(remote.user, "root");
        assert_eq!(remote.host, "example.com");
        assert_eq!(remote.port, 2222);
        assert_eq!(remote.path, "/home/user");
    }

    #[test]
    fn test_parse_remote_relative_path() {
        let remote = parse_remote("user@host:workspace/project", None, &test_local());
        assert_eq!(remote.user, "user");
        assert_eq!(remote.host, "host");
        assert_eq!(remote.port, 22);
        assert_eq!(remote.path, "workspace/project");
    }

    #[test]
    fn test_parse_remote_relative_path_with_port() {
        let remote = parse_remote("user@host:10249:workspace/project", None, &test_local());
        assert_eq!(remote.user, "user");
        assert_eq!(remote.host, "host");
        assert_eq!(remote.port, 10249);
        assert_eq!(remote.path, "workspace/project");
    }

    #[test]
    fn test_parse_remote_no_path() {
        let remote = parse_remote("root@example.com", None, &test_local());
        assert_eq!(remote.user, "root");
        assert_eq!(remote.host, "example.com");
        assert_eq!(remote.port, 22);
        assert_eq!(remote.path, "~/zsync/myproject");
    }

    #[test]
    fn test_parse_remote_port_only() {
        let remote = parse_remote("root@example.com:2222", None, &test_local());
        assert_eq!(remote.user, "root");
        assert_eq!(remote.host, "example.com");
        assert_eq!(remote.port, 2222);
        assert_eq!(remote.path, "~/zsync/myproject");
    }

    #[test]
    fn test_parse_remote_port_override() {
        // -p flag should override port in remote string
        let remote = parse_remote("root@example.com:2222", Some(3333), &test_local());
        assert_eq!(remote.port, 3333);
        assert_eq!(remote.path, "~/zsync/myproject");
    }

    #[test]
    fn test_parse_remote_ssh_config_host() {
        // SSH config host without @ - should use current user as fallback
        let remote = parse_remote("myserver:/workspace", None, &test_local());
        // User comes from $USER env or defaults to "root"
        assert!(!remote.user.is_empty());
        // Host falls back to alias if not in SSH config
        assert_eq!(remote.host, "myserver");
        assert_eq!(remote.port, 22);
        assert_eq!(remote.path, "/workspace");
    }

    #[test]
    fn test_parse_remote_ssh_config_host_no_path() {
        // SSH config host without path
        let remote = parse_remote("myserver", None, &test_local());
        assert!(!remote.user.is_empty());
        assert_eq!(remote.host, "myserver");
        assert_eq!(remote.path, "~/zsync/myproject");
    }
}
