//! zsync-agent: Remote agent for zsync
//!
//! This binary is deployed to remote hosts and communicates with the local
//! zsync CLI over stdin/stdout using a simple JSON protocol.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use color_eyre::Result;
use serde::{Deserialize, Serialize};

use zsync_core::{DeltaComputer, Scanner, Snapshot};

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
    /// Scan a directory and print snapshot
    Scan {
        /// Directory to scan
        path: PathBuf,
    },
}

/// Protocol message from client to agent
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
enum Request {
    /// Request current snapshot
    Snapshot,
    /// Request signature for a file
    Signature { path: PathBuf },
    /// Apply a delta to a file
    ApplyDelta { path: PathBuf, delta: String },
    /// Write a file directly
    WriteFile { path: PathBuf, data: String },
    /// Delete a file
    DeleteFile { path: PathBuf },
    /// Create a directory
    CreateDir { path: PathBuf },
    /// Shutdown the agent
    Shutdown,
}

/// Protocol message from agent to client
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
enum Response {
    /// Snapshot of current state
    Snapshot { snapshot: Snapshot },
    /// Signature for a file
    Signature { signature: String },
    /// Operation completed successfully
    Ok,
    /// Error occurred
    Error { message: String },
}

fn main() -> Result<()> {
    color_eyre::install()?;

    let cli = Cli::parse();

    match cli.command {
        Commands::Version => {
            eprintln!("zsync-agent {}", env!("CARGO_PKG_VERSION"));
        }
        Commands::Scan { path } => {
            let scanner = Scanner::new(&path);
            let entries = scanner.scan()?;
            let snapshot = Snapshot::from_entries(entries);
            let json = serde_json::to_string_pretty(&snapshot)?;
            // Use eprintln for output since we can't use println due to clippy
            let mut stderr = std::io::stderr();
            writeln!(stderr, "{json}")?;
        }
        Commands::Daemon { root } => {
            run_daemon(&root)?;
        }
    }

    Ok(())
}

fn run_daemon(root: &PathBuf) -> Result<()> {
    // Use stderr for logging since stdout is for protocol
    eprintln!("zsync-agent daemon starting, root: {}", root.display());

    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let reader = BufReader::new(stdin.lock());

    for line in reader.lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<Request>(&line) {
            Ok(request) => handle_request(root, request),
            Err(e) => Response::Error {
                message: format!("Invalid request: {e}"),
            },
        };

        let response_json = serde_json::to_string(&response)?;
        writeln!(stdout, "{response_json}")?;
        stdout.flush()?;

        if matches!(response, Response::Ok)
            && matches!(
                serde_json::from_str::<Request>(&line),
                Ok(Request::Shutdown)
            )
        {
            break;
        }
    }

    eprintln!("zsync-agent daemon shutting down");
    Ok(())
}

fn handle_request(root: &PathBuf, request: Request) -> Response {
    match request {
        Request::Snapshot => match scan_directory(root) {
            Ok(snapshot) => Response::Snapshot { snapshot },
            Err(e) => Response::Error {
                message: format!("Scan failed: {e}"),
            },
        },
        Request::Signature { path } => {
            let full_path = root.join(&path);
            match std::fs::read(&full_path) {
                Ok(data) => {
                    let computer = DeltaComputer::new();
                    let sig = computer.signature(&data);
                    match serde_json::to_string(&sig) {
                        Ok(json) => Response::Signature { signature: json },
                        Err(e) => Response::Error {
                            message: format!("Serialization failed: {e}"),
                        },
                    }
                }
                Err(e) => Response::Error {
                    message: format!("Read failed: {e}"),
                },
            }
        }
        Request::ApplyDelta { path, delta } => {
            let full_path = root.join(&path);
            match apply_delta(&full_path, &delta) {
                Ok(()) => Response::Ok,
                Err(e) => Response::Error {
                    message: format!("Apply delta failed: {e}"),
                },
            }
        }
        Request::WriteFile { path, data } => {
            let full_path = root.join(&path);
            // Data is base64 encoded
            match base64_decode_and_write(&full_path, &data) {
                Ok(()) => Response::Ok,
                Err(e) => Response::Error {
                    message: format!("Write failed: {e}"),
                },
            }
        }
        Request::DeleteFile { path } => {
            let full_path = root.join(&path);
            match std::fs::remove_file(&full_path) {
                Ok(()) => Response::Ok,
                Err(e) => Response::Error {
                    message: format!("Delete failed: {e}"),
                },
            }
        }
        Request::CreateDir { path } => {
            let full_path = root.join(&path);
            match std::fs::create_dir_all(&full_path) {
                Ok(()) => Response::Ok,
                Err(e) => Response::Error {
                    message: format!("Create dir failed: {e}"),
                },
            }
        }
        Request::Shutdown => Response::Ok,
    }
}

fn scan_directory(root: &PathBuf) -> Result<Snapshot> {
    let scanner = Scanner::new(root);
    let entries = scanner.scan()?;
    Ok(Snapshot::from_entries(entries))
}

fn apply_delta(path: &PathBuf, delta_json: &str) -> Result<()> {
    let delta: zsync_core::Delta = serde_json::from_str(delta_json)?;
    let old_data = std::fs::read(path).unwrap_or_default();
    let computer = DeltaComputer::new();
    let new_data = computer.apply(&old_data, &delta)?;

    // Create parent directory if needed
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(path, &new_data)?;
    Ok(())
}

fn base64_decode_and_write(path: &PathBuf, data: &str) -> Result<()> {
    // Simple base64 decode (in production, use a proper base64 crate)

    // Create parent directory if needed
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // For now, assume data is raw bytes encoded as hex
    let bytes: Vec<u8> = (0..data.len())
        .step_by(2)
        .filter_map(|i| {
            data.get(i..i + 2)
                .and_then(|s| u8::from_str_radix(s, 16).ok())
        })
        .collect();

    std::fs::write(path, &bytes)?;
    Ok(())
}
