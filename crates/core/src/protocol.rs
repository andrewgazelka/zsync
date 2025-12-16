//! Binary protocol for zsync agent communication
//!
//! Wire format (all integers are big-endian):
//!
//! Request/Response frame:
//! ```text
//! +--------+--------+------------------+
//! | type   | length | payload          |
//! | 1 byte | 4 bytes| variable         |
//! +--------+--------+------------------+
//! ```
//!
//! Message types:
//! - 0x01: Snapshot request (no payload)
//! - 0x02: Snapshot response (snapshot data)
//! - 0x03: WriteFile request (path_len:2, path, executable:1, data)
//! - 0x04: DeleteFile request (path_len:2, path)
//! - 0x05: Ok response (no payload)
//! - 0x06: Error response (message)
//! - 0x07: Shutdown request (no payload)

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use color_eyre::Result;

use crate::ContentHash;
use crate::scan::FileEntry;
use crate::snapshot::Snapshot;

/// Message type identifiers
pub mod msg {
    pub const SNAPSHOT_REQ: u8 = 0x01;
    pub const SNAPSHOT_RESP: u8 = 0x02;
    pub const WRITE_FILE: u8 = 0x03;
    pub const DELETE_FILE: u8 = 0x04;
    pub const OK: u8 = 0x05;
    pub const ERROR: u8 = 0x06;
    pub const SHUTDOWN: u8 = 0x07;
}

/// Write a frame header (type + length)
fn write_header<W: Write>(w: &mut W, msg_type: u8, len: u32) -> std::io::Result<()> {
    w.write_all(&[msg_type])?;
    w.write_all(&len.to_be_bytes())?;
    Ok(())
}

/// Read a frame header, returns (type, length)
fn read_header<R: Read>(r: &mut R) -> std::io::Result<(u8, u32)> {
    let mut type_buf = [0u8; 1];
    r.read_exact(&mut type_buf)?;

    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;

    Ok((type_buf[0], u32::from_be_bytes(len_buf)))
}

/// Encode a path as length-prefixed bytes
fn encode_path(path: &Path) -> Vec<u8> {
    let path_bytes = path.to_string_lossy().as_bytes().to_vec();
    let len = path_bytes.len() as u16;
    let mut buf = Vec::with_capacity(2 + path_bytes.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&path_bytes);
    buf
}

/// Decode a path from reader
fn decode_path<R: Read>(r: &mut R) -> std::io::Result<PathBuf> {
    let mut len_buf = [0u8; 2];
    r.read_exact(&mut len_buf)?;
    let len = u16::from_be_bytes(len_buf) as usize;

    let mut path_buf = vec![0u8; len];
    r.read_exact(&mut path_buf)?;

    Ok(PathBuf::from(
        String::from_utf8_lossy(&path_buf).to_string(),
    ))
}

/// Protocol writer for sending messages
pub struct ProtocolWriter<W> {
    inner: W,
}

impl<W: Write> ProtocolWriter<W> {
    pub fn new(inner: W) -> Self {
        Self { inner }
    }

    /// Send snapshot request
    pub fn send_snapshot_req(&mut self) -> Result<()> {
        write_header(&mut self.inner, msg::SNAPSHOT_REQ, 0)?;
        self.inner.flush()?;
        Ok(())
    }

    /// Send snapshot response
    pub fn send_snapshot_resp(&mut self, snapshot: &Snapshot) -> Result<()> {
        let payload = encode_snapshot(snapshot);
        write_header(&mut self.inner, msg::SNAPSHOT_RESP, payload.len() as u32)?;
        self.inner.write_all(&payload)?;
        self.inner.flush()?;
        Ok(())
    }

    /// Send write file request
    pub fn send_write_file(&mut self, path: &Path, data: &[u8], executable: bool) -> Result<()> {
        let path_encoded = encode_path(path);
        let payload_len = path_encoded.len() + 1 + data.len();

        write_header(&mut self.inner, msg::WRITE_FILE, payload_len as u32)?;
        self.inner.write_all(&path_encoded)?;
        self.inner.write_all(&[u8::from(executable)])?;
        self.inner.write_all(data)?;
        self.inner.flush()?;
        Ok(())
    }

    /// Send delete file request
    pub fn send_delete_file(&mut self, path: &Path) -> Result<()> {
        let path_encoded = encode_path(path);
        write_header(&mut self.inner, msg::DELETE_FILE, path_encoded.len() as u32)?;
        self.inner.write_all(&path_encoded)?;
        self.inner.flush()?;
        Ok(())
    }

    /// Send OK response
    pub fn send_ok(&mut self) -> Result<()> {
        write_header(&mut self.inner, msg::OK, 0)?;
        self.inner.flush()?;
        Ok(())
    }

    /// Send error response
    pub fn send_error(&mut self, message: &str) -> Result<()> {
        let payload = message.as_bytes();
        write_header(&mut self.inner, msg::ERROR, payload.len() as u32)?;
        self.inner.write_all(payload)?;
        self.inner.flush()?;
        Ok(())
    }

    /// Send shutdown request
    pub fn send_shutdown(&mut self) -> Result<()> {
        write_header(&mut self.inner, msg::SHUTDOWN, 0)?;
        self.inner.flush()?;
        Ok(())
    }

    /// Get inner writer
    pub fn into_inner(self) -> W {
        self.inner
    }
}

/// Message received from protocol
#[derive(Debug)]
pub enum Message {
    SnapshotReq,
    SnapshotResp(Snapshot),
    WriteFile {
        path: PathBuf,
        data: Vec<u8>,
        executable: bool,
    },
    DeleteFile {
        path: PathBuf,
    },
    Ok,
    Error(String),
    Shutdown,
}

/// Protocol reader for receiving messages
pub struct ProtocolReader<R> {
    inner: R,
}

impl<R: Read> ProtocolReader<R> {
    pub fn new(inner: R) -> Self {
        Self { inner }
    }

    /// Read next message
    pub fn read_message(&mut self) -> Result<Message> {
        let (msg_type, len) = read_header(&mut self.inner)?;

        match msg_type {
            msg::SNAPSHOT_REQ => Ok(Message::SnapshotReq),

            msg::SNAPSHOT_RESP => {
                let mut payload = vec![0u8; len as usize];
                self.inner.read_exact(&mut payload)?;
                let snapshot = decode_snapshot(&payload)?;
                Ok(Message::SnapshotResp(snapshot))
            }

            msg::WRITE_FILE => {
                let path = decode_path(&mut self.inner)?;
                let mut exec_buf = [0u8; 1];
                self.inner.read_exact(&mut exec_buf)?;
                let executable = exec_buf[0] != 0;

                // Remaining bytes are data
                let path_len = 2 + path.to_string_lossy().len();
                let data_len = len as usize - path_len - 1;
                let mut data = vec![0u8; data_len];
                self.inner.read_exact(&mut data)?;

                Ok(Message::WriteFile {
                    path,
                    data,
                    executable,
                })
            }

            msg::DELETE_FILE => {
                let path = decode_path(&mut self.inner)?;
                Ok(Message::DeleteFile { path })
            }

            msg::OK => Ok(Message::Ok),

            msg::ERROR => {
                let mut payload = vec![0u8; len as usize];
                self.inner.read_exact(&mut payload)?;
                Ok(Message::Error(
                    String::from_utf8_lossy(&payload).to_string(),
                ))
            }

            msg::SHUTDOWN => Ok(Message::Shutdown),

            _ => Err(color_eyre::eyre::eyre!("Unknown message type: {msg_type}")),
        }
    }

    /// Get inner reader
    pub fn into_inner(self) -> R {
        self.inner
    }
}

/// Encode snapshot to binary
///
/// Format:
/// ```text
/// file_count: u32
/// for each file:
///   path_len: u16
///   path: [u8; path_len]
///   size: u64
///   hash: [u8; 32]
///   executable: u8
/// ```
fn encode_snapshot(snapshot: &Snapshot) -> Vec<u8> {
    let mut buf = Vec::new();

    // File count
    buf.extend_from_slice(&(snapshot.files.len() as u32).to_be_bytes());

    for (path, entry) in &snapshot.files {
        // Path
        let path_bytes = path.to_string_lossy().as_bytes().to_vec();
        buf.extend_from_slice(&(path_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(&path_bytes);

        // Size
        buf.extend_from_slice(&entry.size.to_be_bytes());

        // Hash (32 bytes)
        buf.extend_from_slice(entry.hash.as_bytes());

        // Executable
        buf.push(u8::from(entry.executable));
    }

    buf
}

/// Decode snapshot from binary
fn decode_snapshot(data: &[u8]) -> Result<Snapshot> {
    use std::io::Cursor;
    let mut cursor = Cursor::new(data);

    // File count
    let mut count_buf = [0u8; 4];
    cursor.read_exact(&mut count_buf)?;
    let count = u32::from_be_bytes(count_buf) as usize;

    let mut entries = Vec::with_capacity(count);

    for _ in 0..count {
        // Path
        let mut path_len_buf = [0u8; 2];
        cursor.read_exact(&mut path_len_buf)?;
        let path_len = u16::from_be_bytes(path_len_buf) as usize;

        let mut path_buf = vec![0u8; path_len];
        cursor.read_exact(&mut path_buf)?;
        let path = PathBuf::from(String::from_utf8_lossy(&path_buf).to_string());

        // Size
        let mut size_buf = [0u8; 8];
        cursor.read_exact(&mut size_buf)?;
        let size = u64::from_be_bytes(size_buf);

        // Hash
        let mut hash_buf = [0u8; 32];
        cursor.read_exact(&mut hash_buf)?;
        let hash = ContentHash::from_raw(hash_buf);

        // Executable
        let mut exec_buf = [0u8; 1];
        cursor.read_exact(&mut exec_buf)?;
        let executable = exec_buf[0] != 0;

        entries.push(FileEntry {
            path,
            size,
            modified: std::time::SystemTime::UNIX_EPOCH, // Not transmitted
            hash,
            executable,
        });
    }

    Ok(Snapshot::from_entries(entries))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_snapshot_roundtrip() {
        let entries = vec![
            FileEntry {
                path: PathBuf::from("test.txt"),
                size: 100,
                modified: std::time::SystemTime::UNIX_EPOCH,
                hash: ContentHash::from_bytes(b"test"),
                executable: false,
            },
            FileEntry {
                path: PathBuf::from("src/main.rs"),
                size: 500,
                modified: std::time::SystemTime::UNIX_EPOCH,
                hash: ContentHash::from_bytes(b"main"),
                executable: true,
            },
        ];

        let snapshot = Snapshot::from_entries(entries);
        let encoded = encode_snapshot(&snapshot);
        let decoded = decode_snapshot(&encoded).unwrap();

        assert_eq!(snapshot.files.len(), decoded.files.len());
        for (path, entry) in &snapshot.files {
            let decoded_entry = decoded.files.get(path).unwrap();
            assert_eq!(entry.size, decoded_entry.size);
            assert_eq!(entry.hash, decoded_entry.hash);
            assert_eq!(entry.executable, decoded_entry.executable);
        }
    }

    #[test]
    fn test_write_file_roundtrip() {
        let mut buf = Vec::new();
        let mut writer = ProtocolWriter::new(&mut buf);

        let path = Path::new("test/file.txt");
        let data = b"hello world";
        writer.send_write_file(path, data, true).unwrap();

        let mut reader = ProtocolReader::new(Cursor::new(buf));
        match reader.read_message().unwrap() {
            Message::WriteFile {
                path: p,
                data: d,
                executable: e,
            } => {
                assert_eq!(p, path);
                assert_eq!(d, data);
                assert!(e);
            }
            _ => panic!("Wrong message type"),
        }
    }
}
