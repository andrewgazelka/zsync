//! zsync-agent: Remote agent for zsync
//!
//! Binary deployed to remote hosts, communicates over stdin/stdout
//! using a length-prefixed binary protocol.

use std::io::{BufReader, BufWriter, Write};
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use color_eyre::Result;

use zsync_core::{
    ChunkCache, ChunkStore, ContentHash, DeltaComputer, Message, ProtocolReader, ProtocolWriter,
    Snapshot,
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
        Commands::Daemon { root } => {
            run_daemon(&root)?;
        }
    }

    Ok(())
}

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

    loop {
        match reader.read_message() {
            Ok(msg) => {
                let should_shutdown = matches!(msg, Message::Shutdown);

                match handle_message(root, msg, &mut writer, &mut batch_mode, &cache, &cas) {
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
            write_file(&full_path, &data, mode)?;
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

            write_file(&full_path, &new_data, mode)?;

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

            if *batch_mode {
                Ok(BatchResponse::BatchOp)
            } else {
                writer.send_ok()?;
                Ok(BatchResponse::Normal)
            }
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
        eprintln!("  Setting mode {:o} on {}", mode, path.display());
        let perms = std::fs::Permissions::from_mode(mode);
        std::fs::set_permissions(path, perms)?;

        // Verify it was set
        let actual = std::fs::metadata(path)?.permissions().mode() & 0o7777;
        if actual != mode {
            eprintln!(
                "  WARNING: mode mismatch! wanted {:o}, got {:o}",
                mode, actual
            );
        }
    }

    #[cfg(not(unix))]
    let _ = mode;

    Ok(())
}
