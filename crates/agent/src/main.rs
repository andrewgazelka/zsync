//! zsync-agent: Remote agent for zsync
//!
//! Binary deployed to remote hosts, communicates over stdin/stdout
//! using a length-prefixed binary protocol.

use std::io::{BufReader, BufWriter, Write};
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use color_eyre::Result;

use zsync_core::{Message, ProtocolReader, ProtocolWriter, Scanner, Snapshot};

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

    loop {
        match reader.read_message() {
            Ok(msg) => {
                let should_shutdown = matches!(msg, Message::Shutdown);

                if let Err(e) = handle_message(root, msg, &mut writer) {
                    eprintln!("Error handling message: {e}");
                    let _ = writer.send_error(&e.to_string());
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

fn handle_message<W: Write>(
    root: &PathBuf,
    msg: Message,
    writer: &mut ProtocolWriter<W>,
) -> Result<()> {
    match msg {
        Message::SnapshotReq => {
            let snapshot = scan_directory(root)?;
            writer.send_snapshot_resp(&snapshot)?;
        }

        Message::WriteFile {
            path,
            data,
            executable,
        } => {
            let full_path = root.join(&path);
            write_file(&full_path, &data, executable)?;
            writer.send_ok()?;
        }

        Message::DeleteFile { path } => {
            let full_path = root.join(&path);
            match std::fs::remove_file(&full_path) {
                Ok(()) => writer.send_ok()?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => writer.send_ok()?,
                Err(e) => return Err(e.into()),
            }
        }

        Message::Shutdown => {
            writer.send_ok()?;
        }

        // These are responses, not requests - shouldn't receive them
        Message::SnapshotResp(_) | Message::Ok | Message::Error(_) => {
            writer.send_error("Unexpected message type")?;
        }
    }

    Ok(())
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
