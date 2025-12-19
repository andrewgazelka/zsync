//! zsync-agent: Remote agent for zsync
//!
//! Binary deployed to remote hosts, communicates over stdin/stdout
//! using a length-prefixed binary protocol.

use std::collections::HashMap;
use std::io::{BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::{Parser, Subcommand};
use color_eyre::Result;
use notify_debouncer_full::{DebouncedEvent, Debouncer, RecommendedCache, new_debouncer};
use tokio::sync::mpsc;

/// Tracks files written by the protocol to suppress self-triggered watch events.
/// Uses content hashes for reliable detection - if the file on disk matches
/// what we wrote, suppress the event.
struct RecentWrites {
    /// Map of absolute path -> hash we wrote
    writes: Mutex<HashMap<PathBuf, ContentHash>>,
}

impl RecentWrites {
    fn new() -> Self {
        Self {
            writes: Mutex::new(HashMap::new()),
        }
    }

    /// Record that a file was just written by the protocol with the given hash
    fn record(&self, path: PathBuf, hash: ContentHash) {
        let mut writes = self.writes.lock().unwrap();
        writes.insert(path, hash);
    }

    /// Check if a path should be suppressed.
    /// Returns true if the file's current hash matches what we wrote.
    fn should_suppress(&self, path: &PathBuf) -> bool {
        let writes = self.writes.lock().unwrap();
        let Some(expected_hash) = writes.get(path) else {
            return false;
        };

        // Hash the current file and compare
        match ContentHash::from_file(path) {
            Ok(current_hash) => current_hash == *expected_hash,
            Err(_) => false, // File gone or unreadable, don't suppress
        }
    }

    /// Clear the recorded hash for a path (called after we've processed/suppressed it)
    fn clear(&self, path: &PathBuf) {
        let mut writes = self.writes.lock().unwrap();
        writes.remove(path);
    }

    /// Filter events, removing any for files that still match what we wrote
    fn filter_events(&self, events: Vec<DebouncedEvent>) -> Vec<DebouncedEvent> {
        events
            .into_iter()
            .filter(|e| {
                // Check each path in the event
                !e.paths.iter().any(|p| {
                    if self.should_suppress(p) {
                        // Hash matched, suppress and clear
                        self.clear(p);
                        true
                    } else {
                        false
                    }
                })
            })
            .collect()
    }
}

use zsync_core::{
    ChunkCache, ChunkStore, ContentHash, DeltaComputer, Message, ProtocolReader, ProtocolWriter,
    Snapshot,
    protocol::{ChangeType, FileChange},
};

#[derive(Parser)]
#[command(name = "zsync-agent")]
#[command(about = "Remote agent for zsync file synchronization")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run in daemon mode, listening on stdin for commands
    Daemon {
        /// Root directory to sync
        #[arg(short, long)]
        root: PathBuf,
        /// Enable file watching for bidirectional sync
        #[arg(short, long)]
        watch: bool,
    },
    /// Print version and exit
    Version,
}

fn main() -> Result<()> {
    color_eyre::install()?;

    let cli = Cli::parse();

    match cli.command {
        Commands::Version => {
            eprintln!("zsync-agent {}", env!("CARGO_PKG_VERSION"));
        }
        Commands::Daemon { root, watch } => {
            if watch {
                // Run async with file watching
                let rt = tokio::runtime::Runtime::new()?;
                rt.block_on(run_daemon_watch(&root))?;
            } else {
                // Run sync (legacy mode)
                run_daemon(&root)?;
            }
        }
    }

    Ok(())
}

/// Run daemon with file watching for bidirectional sync
#[allow(clippy::too_many_lines)]
async fn run_daemon_watch(root: &PathBuf) -> Result<()> {
    eprintln!(
        "zsync-agent daemon starting (watch mode), root: {}",
        root.display()
    );

    // Ensure root directory exists
    std::fs::create_dir_all(root)?;

    // Initialize chunk cache and CAS
    let cache_path = root.join(".zsync").join("cache");
    let cache = ChunkCache::open(&cache_path)?;
    eprintln!("Chunk cache initialized at {}", cache_path.display());

    let cas_path = root.join(".zsync").join("cas");
    let cas = ChunkStore::open(&cas_path)?;
    eprintln!("CAS chunk store initialized at {}", cas_path.display());

    // Track recently-written files to suppress self-triggered watch events
    // Uses content hashes - if file matches what we wrote, suppress the event
    let recent_writes = Arc::new(RecentWrites::new());
    let recent_writes_for_watcher = Arc::clone(&recent_writes);

    // Set up file watcher
    let (watch_tx, mut watch_rx) = mpsc::channel::<Vec<DebouncedEvent>>(100);
    let root_clone = root.clone();

    let mut debouncer: Debouncer<notify::RecommendedWatcher, RecommendedCache> = new_debouncer(
        Duration::from_millis(200),
        None,
        move |result: Result<Vec<DebouncedEvent>, Vec<notify::Error>>| {
            if let Ok(events) = result {
                // Filter out .zsync directory changes
                let filtered: Vec<_> = events
                    .into_iter()
                    .filter(|e| {
                        !e.paths.iter().any(|p| {
                            p.strip_prefix(&root_clone)
                                .map(|rel| rel.starts_with(".zsync") || rel.starts_with(".git"))
                                .unwrap_or(false)
                        })
                    })
                    .collect();

                // Filter out files recently written by the protocol (self-triggered events)
                let filtered = recent_writes_for_watcher.filter_events(filtered);

                if !filtered.is_empty() {
                    let _ = watch_tx.blocking_send(filtered);
                }
            }
        },
    )?;

    // Start watching
    debouncer.watch(root.as_path(), notify::RecursiveMode::Recursive)?;
    eprintln!("File watcher started");

    // Channels for communication between threads
    let (msg_tx, mut msg_rx) = mpsc::channel::<Result<Message>>(100);
    let (write_tx, write_rx) = std::sync::mpsc::channel::<WriteCommand>();

    // Spawn blocking I/O thread that owns both stdin and stdout
    let root_for_io = root.clone();
    let cache_for_io = cache;
    let cas_for_io = cas;
    std::thread::spawn(move || {
        run_io_thread(
            root_for_io,
            msg_tx,
            write_rx,
            cache_for_io,
            cas_for_io,
            recent_writes,
        );
    });

    loop {
        tokio::select! {
            // Handle protocol messages
            Some(msg_result) = msg_rx.recv() => {
                match msg_result {
                    Ok(msg) => {
                        let should_shutdown = matches!(msg, Message::Shutdown);

                        // Send message to IO thread for handling
                        let cmd = WriteCommand::HandleMessage { msg };
                        if write_tx.send(cmd).is_err() {
                            break;
                        }

                        if should_shutdown {
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("Read error (likely EOF): {e}");
                        break;
                    }
                }
            }

            // Handle file change events
            Some(events) = watch_rx.recv() => {
                eprintln!("File changes detected: {} events", events.len());
                for event in &events {
                    eprintln!("  {:?}: {:?}", event.kind, event.paths);
                }

                // Build enriched file change list
                let changes: Vec<FileChange> = events
                    .iter()
                    .flat_map(|e| &e.paths)
                    .filter_map(|path| {
                        let rel_path = path.strip_prefix(root).ok()?.to_path_buf();
                        let (content_hash, change_type) = if path.exists() {
                            let hash = ContentHash::from_file(path).ok()?;
                            // We can't reliably distinguish created vs modified from notify events,
                            // so we use Modified for all existing files
                            (hash, ChangeType::Modified)
                        } else {
                            // File was deleted - use zeroed hash
                            (ContentHash::from_raw([0u8; 32]), ChangeType::Deleted)
                        };
                        Some(FileChange {
                            path: rel_path,
                            content_hash,
                            change_type,
                        })
                    })
                    .collect();

                if !changes.is_empty() {
                    // Send change notification to client
                    if write_tx.send(WriteCommand::ChangeNotify { changes }).is_err() {
                        break;
                    }
                }
            }
        }
    }

    eprintln!("zsync-agent daemon shutting down");
    Ok(())
}

/// Commands sent to the I/O thread
enum WriteCommand {
    HandleMessage { msg: Message },
    ChangeNotify { changes: Vec<FileChange> },
}

/// I/O thread that owns stdin/stdout and handles protocol messages
fn run_io_thread(
    root: PathBuf,
    msg_tx: mpsc::Sender<Result<Message>>,
    write_rx: std::sync::mpsc::Receiver<WriteCommand>,
    cache: ChunkCache,
    cas: ChunkStore,
    recent_writes: Arc<RecentWrites>,
) {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();

    // We need to handle stdin in a separate thread since it blocks
    // But stdout can be handled in this thread
    let mut writer = ProtocolWriter::new(BufWriter::new(stdout.lock()));

    let mut batch_mode = false;
    let mut batch_errors: Vec<(u32, String)> = Vec::new();
    let mut batch_index: u32 = 0;
    let mut batch_success: u32 = 0;

    // Spawn reader in a separate thread - it will send messages via channel
    std::thread::spawn(move || {
        let mut reader = ProtocolReader::new(BufReader::new(stdin.lock()));
        loop {
            let msg = reader.read_message();
            let is_err = msg.is_err();
            if msg_tx.blocking_send(msg).is_err() || is_err {
                break;
            }
        }
    });

    // Handle write commands
    while let Ok(cmd) = write_rx.recv() {
        match cmd {
            WriteCommand::HandleMessage { msg } => {
                let should_shutdown = matches!(msg, Message::Shutdown);

                match handle_message(
                    &root,
                    msg,
                    &mut writer,
                    &mut batch_mode,
                    &cache,
                    &cas,
                    &recent_writes,
                ) {
                    Ok(BatchResponse::Normal) => {}
                    Ok(BatchResponse::BatchStarted) => {
                        batch_errors.clear();
                        batch_index = 0;
                        batch_success = 0;
                    }
                    Ok(BatchResponse::BatchEnded) => {
                        if let Err(e) = writer.send_batch_result(batch_success, &batch_errors) {
                            eprintln!("Error sending batch result: {e}");
                        }
                        batch_mode = false;
                    }
                    Ok(BatchResponse::BatchOp) => {
                        batch_success += 1;
                        batch_index += 1;
                    }
                    Err(e) => {
                        eprintln!("Error handling message: {e}");
                        if batch_mode {
                            batch_errors.push((batch_index, e.to_string()));
                            batch_index += 1;
                        } else {
                            let _ = writer.send_error(&e.to_string());
                        }
                    }
                }

                if should_shutdown {
                    break;
                }
            }
            WriteCommand::ChangeNotify { changes } => {
                if let Err(e) = writer.send_change_notify(&changes) {
                    eprintln!("Error sending change notify: {e}");
                }
            }
        }
    }
}

/// Run daemon in legacy sync mode (no file watching)
fn run_daemon(root: &PathBuf) -> Result<()> {
    eprintln!("zsync-agent daemon starting, root: {}", root.display());

    // Ensure root directory exists
    std::fs::create_dir_all(root)?;

    // Initialize chunk cache at {root}/.zsync/cache (for legacy delta operations)
    let cache_path = root.join(".zsync").join("cache");
    let cache = ChunkCache::open(&cache_path)?;
    eprintln!("Chunk cache initialized at {}", cache_path.display());

    // Initialize CAS chunk store at {root}/.zsync/cas
    let cas_path = root.join(".zsync").join("cas");
    let cas = ChunkStore::open(&cas_path)?;
    eprintln!("CAS chunk store initialized at {}", cas_path.display());

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();

    let mut reader = ProtocolReader::new(BufReader::new(stdin.lock()));
    let mut writer = ProtocolWriter::new(BufWriter::new(stdout.lock()));
    let mut batch_mode = false;
    let mut batch_errors: Vec<(u32, String)> = Vec::new();
    let mut batch_index: u32 = 0;
    let mut batch_success: u32 = 0;

    // Legacy mode doesn't watch files, but handle_message still needs RecentWrites
    let recent_writes = RecentWrites::new();

    loop {
        match reader.read_message() {
            Ok(msg) => {
                let should_shutdown = matches!(msg, Message::Shutdown);

                match handle_message(
                    root,
                    msg,
                    &mut writer,
                    &mut batch_mode,
                    &cache,
                    &cas,
                    &recent_writes,
                ) {
                    Ok(BatchResponse::Normal) => {}
                    Ok(BatchResponse::BatchStarted) => {
                        batch_errors.clear();
                        batch_index = 0;
                        batch_success = 0;
                    }
                    Ok(BatchResponse::BatchEnded) => {
                        // Send batch result
                        if let Err(e) = writer.send_batch_result(batch_success, &batch_errors) {
                            eprintln!("Error sending batch result: {e}");
                        }
                        batch_mode = false;
                    }
                    Ok(BatchResponse::BatchOp) => {
                        batch_success += 1;
                        batch_index += 1;
                    }
                    Err(e) => {
                        eprintln!("Error handling message: {e}");
                        if batch_mode {
                            batch_errors.push((batch_index, e.to_string()));
                            batch_index += 1;
                        } else {
                            let _ = writer.send_error(&e.to_string());
                        }
                    }
                }

                if should_shutdown {
                    break;
                }
            }
            Err(e) => {
                // EOF or read error
                eprintln!("Read error (likely EOF): {e}");
                break;
            }
        }
    }

    eprintln!("zsync-agent daemon shutting down");
    Ok(())
}

enum BatchResponse {
    Normal,
    BatchStarted,
    BatchEnded,
    BatchOp,
}

#[allow(clippy::too_many_lines)]
fn handle_message<W: Write>(
    root: &PathBuf,
    msg: Message,
    writer: &mut ProtocolWriter<W>,
    batch_mode: &mut bool,
    cache: &ChunkCache,
    cas: &ChunkStore,
    recent_writes: &RecentWrites,
) -> Result<BatchResponse> {
    match msg {
        Message::SnapshotReq => {
            let entries = scan_directory(root)?;
            let snapshot = Snapshot::from_entries(entries);
            writer.send_snapshot_resp(&snapshot)?;
            Ok(BatchResponse::Normal)
        }

        Message::WriteFile { path, data, mode } => {
            let full_path = root.join(&path);
            let file_hash = ContentHash::from_bytes(&data);
            write_file(&full_path, &data, mode)?;

            // Record the write so we can suppress self-triggered watch events
            recent_writes.record(full_path, file_hash);

            if *batch_mode {
                Ok(BatchResponse::BatchOp)
            } else {
                writer.send_ok()?;
                Ok(BatchResponse::Normal)
            }
        }

        Message::DeleteFile { path } => {
            let full_path = root.join(&path);
            if let Err(e) = std::fs::remove_file(&full_path) {
                // Ignore "not found" errors
                if e.kind() != std::io::ErrorKind::NotFound {
                    return Err(e.into());
                }
            }
            if *batch_mode {
                Ok(BatchResponse::BatchOp)
            } else {
                writer.send_ok()?;
                Ok(BatchResponse::Normal)
            }
        }

        Message::Shutdown => {
            writer.send_ok()?;
            Ok(BatchResponse::Normal)
        }

        // Batch operations
        Message::BatchStart { count: _ } => {
            *batch_mode = true;
            Ok(BatchResponse::BatchStarted)
        }

        Message::BatchEnd => Ok(BatchResponse::BatchEnded),

        // Delta operations
        Message::SignatureReq { path } => {
            let full_path = root.join(&path);
            let data = std::fs::read(&full_path)?;
            let file_hash = ContentHash::from_bytes(&data);

            // Check cache first
            let chunks = if let Some(cached_chunks) = cache.get_signature(&file_hash) {
                eprintln!("Cache hit for signature: {}", path.display());
                cached_chunks
            } else {
                eprintln!("Cache miss for signature: {}", path.display());
                let computer = DeltaComputer::new();
                let sig = computer.signature(&data);
                // Cache the chunks for next time
                let chunks: Vec<_> = sig
                    .chunks
                    .iter()
                    .map(|c| zsync_core::Chunk {
                        offset: c.offset,
                        length: c.length,
                        hash: c.hash,
                    })
                    .collect();
                if let Err(e) = cache.put_signature(&file_hash, &chunks) {
                    eprintln!("Failed to cache signature: {e}");
                }
                chunks
            };

            // Convert chunks back to Signature for compression
            let sig = zsync_core::delta::Signature {
                chunks: chunks
                    .iter()
                    .map(|c| zsync_core::delta::ChunkSignature {
                        offset: c.offset,
                        length: c.length,
                        hash: c.hash,
                    })
                    .collect(),
                file_size: data.len() as u64,
            };
            let compressed = DeltaComputer::compress_signature(&sig)?;
            writer.send_signature_resp(&path, &compressed)?;
            Ok(BatchResponse::Normal)
        }

        Message::WriteDelta { path, delta, mode } => {
            let full_path = root.join(&path);

            // Read existing file (if any) to apply delta
            let old_data = std::fs::read(&full_path).unwrap_or_default();
            let delta = DeltaComputer::decompress_delta(&delta)?;
            let computer = DeltaComputer::new();
            let new_data = computer.apply(&old_data, &delta)?;
            let file_hash = ContentHash::from_bytes(&new_data);

            write_file(&full_path, &new_data, mode)?;

            // Record the write so we can suppress self-triggered watch events
            recent_writes.record(full_path, file_hash);

            if *batch_mode {
                Ok(BatchResponse::BatchOp)
            } else {
                writer.send_ok()?;
                Ok(BatchResponse::Normal)
            }
        }

        // CAS operations
        Message::CheckChunks { hashes } => {
            let missing = cas.find_missing(&hashes);
            eprintln!(
                "CheckChunks: {} requested, {} missing",
                hashes.len(),
                missing.len()
            );
            writer.send_missing_chunks(&missing)?;
            Ok(BatchResponse::Normal)
        }

        Message::StoreChunks { chunks } => {
            eprintln!("StoreChunks: storing {} chunks", chunks.len());
            let new_count = cas.put_many(&chunks)?;
            eprintln!("StoreChunks: {new_count} new chunks stored");
            writer.send_ok()?;
            Ok(BatchResponse::Normal)
        }

        Message::WriteManifest {
            path,
            manifest,
            mode,
        } => {
            let full_path = root.join(&path);
            eprintln!(
                "WriteManifest: {} ({} chunks, {} bytes)",
                path.display(),
                manifest.chunks.len(),
                manifest.size
            );

            // Assemble file from CAS chunks
            let data = cas.assemble(&manifest.chunks)?;

            // Verify hash
            let actual_hash = ContentHash::from_bytes(&data);
            color_eyre::eyre::ensure!(
                actual_hash == manifest.file_hash,
                "hash mismatch after assembly: expected {}, got {}",
                manifest.file_hash,
                actual_hash
            );

            write_file(&full_path, &data, mode)?;

            // Record the write so we can suppress self-triggered watch events
            recent_writes.record(full_path, manifest.file_hash);

            if *batch_mode {
                Ok(BatchResponse::BatchOp)
            } else {
                writer.send_ok()?;
                Ok(BatchResponse::Normal)
            }
        }

        // Bidirectional messages - agent shouldn't receive these
        Message::ChangeNotify { .. } => {
            writer.send_error("Agent received ChangeNotify (should only be sent by agent)")?;
            Ok(BatchResponse::Normal)
        }

        // These are responses, not requests - shouldn't receive them
        Message::SnapshotResp(_)
        | Message::Ok
        | Message::Error(_)
        | Message::BatchResult { .. }
        | Message::SignatureResp { .. }
        | Message::MissingChunks { .. } => {
            writer.send_error("Unexpected message type")?;
            Ok(BatchResponse::Normal)
        }
    }
}

/// Scan directory without gitignore filtering.
///
/// The server should see ALL files on disk, regardless of gitignore.
/// The client already did the filtering - we just need to know what exists.
fn scan_directory(root: &PathBuf) -> Result<Vec<zsync_core::FileEntry>> {
    use ignore::WalkBuilder;
    use rayon::prelude::*;

    let mut builder = WalkBuilder::new(root);
    builder
        .hidden(false) // Include hidden files
        .git_ignore(false) // CRITICAL: Don't respect gitignore
        .git_global(false)
        .git_exclude(false)
        .require_git(false)
        .filter_entry(|e| {
            let name = e.file_name();
            // Skip .git directory and .zsync directory (our internal storage)
            name != ".git" && name != ".zsync"
        });

    let paths: Vec<_> = builder
        .build()
        .filter_map(std::result::Result::ok)
        .filter_map(|entry| {
            let path = entry.into_path();
            if !path.is_file() {
                return None;
            }
            let relative_path = path.strip_prefix(root).ok()?.to_path_buf();
            Some((path, relative_path))
        })
        .collect();

    let entries: Vec<zsync_core::FileEntry> = paths
        .into_par_iter()
        .map(|(path, relative_path)| {
            let metadata = std::fs::metadata(&path)?;
            let hash = ContentHash::from_file(&path)?;

            #[cfg(unix)]
            let mode = {
                use std::os::unix::fs::PermissionsExt as _;
                metadata.permissions().mode() & 0o7777
            };
            #[cfg(not(unix))]
            let mode = 0o644;

            Ok(zsync_core::FileEntry {
                path: relative_path,
                size: metadata.len(),
                modified: metadata.modified()?,
                hash,
                mode,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(entries)
}

fn write_file(path: &PathBuf, data: &[u8], mode: u32) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(path, data)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let perms = std::fs::Permissions::from_mode(mode);
        // set_permissions may silently fail on some filesystems (overlay, network mounts)
        // We log a warning but don't fail the operation
        if let Err(e) = std::fs::set_permissions(path, perms) {
            eprintln!(
                "Warning: failed to set mode {:o} on {}: {}",
                mode,
                path.display(),
                e
            );
        }
    }

    #[cfg(not(unix))]
    let _ = mode;

    Ok(())
}
