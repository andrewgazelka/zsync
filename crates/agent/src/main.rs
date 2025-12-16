//! zsync-agent: Remote agent for zsync
//!
//! Binary deployed to remote hosts, communicates over stdin/stdout
//! using a length-prefixed binary protocol.

use std::io::{BufReader, BufWriter, Write};
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use color_eyre::Result;

use zsync_core::{DeltaComputer, Message, ProtocolReader, ProtocolWriter, Scanner, Snapshot};

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

                match handle_message(root, msg, &mut writer, &mut batch_mode) {
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

fn handle_message<W: Write>(
    root: &PathBuf,
    msg: Message,
    writer: &mut ProtocolWriter<W>,
    batch_mode: &mut bool,
) -> Result<BatchResponse> {
    match msg {
        Message::SnapshotReq => {
            let snapshot = scan_directory(root)?;
            writer.send_snapshot_resp(&snapshot)?;
            Ok(BatchResponse::Normal)
        }

        Message::WriteFile {
            path,
            data,
            executable,
        } => {
            let full_path = root.join(&path);
            write_file(&full_path, &data, executable)?;
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
            let computer = DeltaComputer::new();
            let sig = computer.signature(&data);
            let compressed = DeltaComputer::compress_signature(&sig)?;
            writer.send_signature_resp(&path, &compressed)?;
            Ok(BatchResponse::Normal)
        }

        Message::WriteDelta {
            path,
            delta,
            executable,
        } => {
            let full_path = root.join(&path);

            // Read existing file (if any) to apply delta
            let old_data = std::fs::read(&full_path).unwrap_or_default();
            let delta = DeltaComputer::decompress_delta(&delta)?;
            let computer = DeltaComputer::new();
            let new_data = computer.apply(&old_data, &delta)?;

            write_file(&full_path, &new_data, executable)?;

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
        | Message::SignatureResp { .. } => {
            writer.send_error("Unexpected message type")?;
            Ok(BatchResponse::Normal)
        }
    }
}

fn scan_directory(root: &PathBuf) -> Result<Snapshot> {
    let scanner = Scanner::new(root);
    let entries = scanner.scan()?;
    Ok(Snapshot::from_entries(entries))
}

fn write_file(path: &PathBuf, data: &[u8], executable: bool) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(path, data)?;

    #[cfg(unix)]
    if executable {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(perms.mode() | 0o111);
        std::fs::set_permissions(path, perms)?;
    }

    #[cfg(not(unix))]
    let _ = executable;

    Ok(())
}
