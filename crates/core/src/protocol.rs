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
//! - 0x30: CheckChunks (count:4, hashes:[32]*count)
//! - 0x31: MissingChunks (count:4, hashes:[32]*count)
//! - 0x32: StoreChunks (count:4, (hash:32, len:4, data)*count)
//! - 0x33: WriteManifest (path_len:2, path, executable:1, file_hash:32, size:8, chunk_count:4, hashes:[32]*count)

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use bytes::Bytes;
use color_eyre::Result;
use serde::{Deserialize, Serialize};

use crate::ContentHash;
use crate::scan::FileEntry;
use crate::snapshot::Snapshot;

/// A file represented as a list of content-addressed chunks.
///
/// To reconstruct the file: read each chunk from CAS in order, concatenate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileManifest {
    /// Content hash of the complete file
    pub file_hash: ContentHash,
    /// File size in bytes
    pub size: u64,
    /// Ordered list of chunk hashes
    pub chunks: Vec<ContentHash>,
}

/// Message type identifiers
pub mod msg {
    pub const SNAPSHOT_REQ: u8 = 0x01;
    pub const SNAPSHOT_RESP: u8 = 0x02;
    pub const WRITE_FILE: u8 = 0x03;
    pub const DELETE_FILE: u8 = 0x04;
    pub const OK: u8 = 0x05;
    pub const ERROR: u8 = 0x06;
    pub const SHUTDOWN: u8 = 0x07;
    // Pipelined batch operations
    pub const BATCH_START: u8 = 0x10;
    pub const BATCH_END: u8 = 0x11;
    pub const BATCH_RESULT: u8 = 0x12;
    // Legacy delta transfer operations (deprecated - use CAS instead)
    pub const SIGNATURE_REQ: u8 = 0x20;
    pub const SIGNATURE_RESP: u8 = 0x21;
    pub const WRITE_DELTA: u8 = 0x22;
    // CAS (Content-Addressable Storage) operations
    pub const CHECK_CHUNKS: u8 = 0x30;
    pub const MISSING_CHUNKS: u8 = 0x31;
    pub const STORE_CHUNKS: u8 = 0x32;
    pub const WRITE_MANIFEST: u8 = 0x33;
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

    /// Send batch start (pipelining)
    pub fn send_batch_start(&mut self, count: u32) -> Result<()> {
        write_header(&mut self.inner, msg::BATCH_START, 4)?;
        self.inner.write_all(&count.to_be_bytes())?;
        self.inner.flush()?;
        Ok(())
    }

    /// Send batch end
    pub fn send_batch_end(&mut self) -> Result<()> {
        write_header(&mut self.inner, msg::BATCH_END, 0)?;
        self.inner.flush()?;
        Ok(())
    }

    /// Send batch result
    pub fn send_batch_result(
        &mut self,
        success_count: u32,
        errors: &[(u32, String)],
    ) -> Result<()> {
        // Format: success_count(4) + error_count(4) + errors...
        let mut payload = Vec::new();
        payload.extend_from_slice(&success_count.to_be_bytes());
        payload.extend_from_slice(&(errors.len() as u32).to_be_bytes());
        for (idx, msg) in errors {
            payload.extend_from_slice(&idx.to_be_bytes());
            let msg_bytes = msg.as_bytes();
            payload.extend_from_slice(&(msg_bytes.len() as u16).to_be_bytes());
            payload.extend_from_slice(msg_bytes);
        }
        write_header(&mut self.inner, msg::BATCH_RESULT, payload.len() as u32)?;
        self.inner.write_all(&payload)?;
        self.inner.flush()?;
        Ok(())
    }

    /// Send signature request for delta transfer
    pub fn send_signature_req(&mut self, path: &Path) -> Result<()> {
        let path_encoded = encode_path(path);
        write_header(
            &mut self.inner,
            msg::SIGNATURE_REQ,
            path_encoded.len() as u32,
        )?;
        self.inner.write_all(&path_encoded)?;
        self.inner.flush()?;
        Ok(())
    }

    /// Send signature response
    pub fn send_signature_resp(&mut self, path: &Path, signature: &[u8]) -> Result<()> {
        let path_encoded = encode_path(path);
        let payload_len = path_encoded.len() + 4 + signature.len();
        write_header(&mut self.inner, msg::SIGNATURE_RESP, payload_len as u32)?;
        self.inner.write_all(&path_encoded)?;
        self.inner
            .write_all(&(signature.len() as u32).to_be_bytes())?;
        self.inner.write_all(signature)?;
        self.inner.flush()?;
        Ok(())
    }

    /// Send delta write (compressed delta data)
    pub fn send_write_delta(&mut self, path: &Path, delta: &[u8], executable: bool) -> Result<()> {
        let path_encoded = encode_path(path);
        let payload_len = path_encoded.len() + 1 + 4 + delta.len();
        write_header(&mut self.inner, msg::WRITE_DELTA, payload_len as u32)?;
        self.inner.write_all(&path_encoded)?;
        self.inner.write_all(&[u8::from(executable)])?;
        self.inner.write_all(&(delta.len() as u32).to_be_bytes())?;
        self.inner.write_all(delta)?;
        self.inner.flush()?;
        Ok(())
    }

    /// Send write file without flushing (for batch operations)
    pub fn send_write_file_no_flush(
        &mut self,
        path: &Path,
        data: &[u8],
        executable: bool,
    ) -> Result<()> {
        let path_encoded = encode_path(path);
        let payload_len = path_encoded.len() + 1 + data.len();

        write_header(&mut self.inner, msg::WRITE_FILE, payload_len as u32)?;
        self.inner.write_all(&path_encoded)?;
        self.inner.write_all(&[u8::from(executable)])?;
        self.inner.write_all(data)?;
        // No flush - caller will flush after batch
        Ok(())
    }

    /// Send delete file without flushing (for batch operations)
    pub fn send_delete_file_no_flush(&mut self, path: &Path) -> Result<()> {
        let path_encoded = encode_path(path);
        write_header(&mut self.inner, msg::DELETE_FILE, path_encoded.len() as u32)?;
        self.inner.write_all(&path_encoded)?;
        // No flush - caller will flush after batch
        Ok(())
    }

    /// Send write delta without flushing (for batch operations)
    pub fn send_write_delta_no_flush(
        &mut self,
        path: &Path,
        delta: &[u8],
        executable: bool,
    ) -> Result<()> {
        let path_encoded = encode_path(path);
        let payload_len = path_encoded.len() + 1 + 4 + delta.len();
        write_header(&mut self.inner, msg::WRITE_DELTA, payload_len as u32)?;
        self.inner.write_all(&path_encoded)?;
        self.inner.write_all(&[u8::from(executable)])?;
        self.inner.write_all(&(delta.len() as u32).to_be_bytes())?;
        self.inner.write_all(delta)?;
        // No flush
        Ok(())
    }

    // ========== CAS (Content-Addressable Storage) Operations ==========

    /// Send check chunks request - ask server which chunks are missing
    pub fn send_check_chunks(&mut self, hashes: &[ContentHash]) -> Result<()> {
        let payload_len = 4 + hashes.len() * 32;
        write_header(&mut self.inner, msg::CHECK_CHUNKS, payload_len as u32)?;
        self.inner.write_all(&(hashes.len() as u32).to_be_bytes())?;
        for hash in hashes {
            self.inner.write_all(hash.as_bytes())?;
        }
        self.inner.flush()?;
        Ok(())
    }

    /// Send missing chunks response - tells client which chunks to send
    pub fn send_missing_chunks(&mut self, hashes: &[ContentHash]) -> Result<()> {
        let payload_len = 4 + hashes.len() * 32;
        write_header(&mut self.inner, msg::MISSING_CHUNKS, payload_len as u32)?;
        self.inner.write_all(&(hashes.len() as u32).to_be_bytes())?;
        for hash in hashes {
            self.inner.write_all(hash.as_bytes())?;
        }
        self.inner.flush()?;
        Ok(())
    }

    /// Send store chunks - transfer chunk data to server
    pub fn send_store_chunks(&mut self, chunks: &[(ContentHash, Bytes)]) -> Result<()> {
        // Calculate payload size: count(4) + (hash(32) + len(4) + data)*count
        let payload_len: usize = 4 + chunks
            .iter()
            .map(|(_, data)| 32 + 4 + data.len())
            .sum::<usize>();
        write_header(&mut self.inner, msg::STORE_CHUNKS, payload_len as u32)?;
        self.inner.write_all(&(chunks.len() as u32).to_be_bytes())?;
        for (hash, data) in chunks {
            self.inner.write_all(hash.as_bytes())?;
            self.inner.write_all(&(data.len() as u32).to_be_bytes())?;
            self.inner.write_all(data)?;
        }
        self.inner.flush()?;
        Ok(())
    }

    /// Send write manifest - tell server to assemble file from chunks
    pub fn send_write_manifest(
        &mut self,
        path: &Path,
        manifest: &FileManifest,
        executable: bool,
    ) -> Result<()> {
        let path_encoded = encode_path(path);
        // path_len(2) + path + executable(1) + file_hash(32) + size(8) + chunk_count(4) + hashes
        let payload_len = path_encoded.len() + 1 + 32 + 8 + 4 + manifest.chunks.len() * 32;
        write_header(&mut self.inner, msg::WRITE_MANIFEST, payload_len as u32)?;
        self.inner.write_all(&path_encoded)?;
        self.inner.write_all(&[u8::from(executable)])?;
        self.inner.write_all(manifest.file_hash.as_bytes())?;
        self.inner.write_all(&manifest.size.to_be_bytes())?;
        self.inner
            .write_all(&(manifest.chunks.len() as u32).to_be_bytes())?;
        for hash in &manifest.chunks {
            self.inner.write_all(hash.as_bytes())?;
        }
        self.inner.flush()?;
        Ok(())
    }

    /// Send write manifest without flushing (for batch operations)
    pub fn send_write_manifest_no_flush(
        &mut self,
        path: &Path,
        manifest: &FileManifest,
        executable: bool,
    ) -> Result<()> {
        let path_encoded = encode_path(path);
        let payload_len = path_encoded.len() + 1 + 32 + 8 + 4 + manifest.chunks.len() * 32;
        write_header(&mut self.inner, msg::WRITE_MANIFEST, payload_len as u32)?;
        self.inner.write_all(&path_encoded)?;
        self.inner.write_all(&[u8::from(executable)])?;
        self.inner.write_all(manifest.file_hash.as_bytes())?;
        self.inner.write_all(&manifest.size.to_be_bytes())?;
        self.inner
            .write_all(&(manifest.chunks.len() as u32).to_be_bytes())?;
        for hash in &manifest.chunks {
            self.inner.write_all(hash.as_bytes())?;
        }
        Ok(())
    }

    /// Flush the underlying writer
    pub fn flush(&mut self) -> Result<()> {
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
    // Batch operations (pipelining)
    BatchStart {
        /// Number of operations in this batch
        count: u32,
    },
    BatchEnd,
    BatchResult {
        /// Number of successful operations
        success_count: u32,
        /// Errors (index, message) for failed operations
        errors: Vec<(u32, String)>,
    },
    // Legacy delta operations (deprecated - use CAS instead)
    SignatureReq {
        path: PathBuf,
    },
    SignatureResp {
        path: PathBuf,
        /// Compressed signature data
        signature: Vec<u8>,
    },
    WriteDelta {
        path: PathBuf,
        /// Compressed delta data
        delta: Vec<u8>,
        executable: bool,
    },
    // CAS (Content-Addressable Storage) operations
    /// Client asks server which chunks are missing
    CheckChunks {
        hashes: Vec<ContentHash>,
    },
    /// Server responds with missing chunk hashes
    MissingChunks {
        hashes: Vec<ContentHash>,
    },
    /// Client sends chunk data to server
    StoreChunks {
        chunks: Vec<(ContentHash, Bytes)>,
    },
    /// Client tells server to assemble file from chunks
    WriteManifest {
        path: PathBuf,
        manifest: FileManifest,
        executable: bool,
    },
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
    #[allow(clippy::too_many_lines)]
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

            msg::BATCH_START => {
                let mut count_buf = [0u8; 4];
                self.inner.read_exact(&mut count_buf)?;
                Ok(Message::BatchStart {
                    count: u32::from_be_bytes(count_buf),
                })
            }

            msg::BATCH_END => Ok(Message::BatchEnd),

            msg::BATCH_RESULT => {
                let mut success_buf = [0u8; 4];
                self.inner.read_exact(&mut success_buf)?;
                let success_count = u32::from_be_bytes(success_buf);

                let mut error_count_buf = [0u8; 4];
                self.inner.read_exact(&mut error_count_buf)?;
                let error_count = u32::from_be_bytes(error_count_buf) as usize;

                let mut errors = Vec::with_capacity(error_count);
                for _ in 0..error_count {
                    let mut idx_buf = [0u8; 4];
                    self.inner.read_exact(&mut idx_buf)?;
                    let idx = u32::from_be_bytes(idx_buf);

                    let mut msg_len_buf = [0u8; 2];
                    self.inner.read_exact(&mut msg_len_buf)?;
                    let msg_len = u16::from_be_bytes(msg_len_buf) as usize;

                    let mut msg_buf = vec![0u8; msg_len];
                    self.inner.read_exact(&mut msg_buf)?;
                    let msg = String::from_utf8_lossy(&msg_buf).to_string();

                    errors.push((idx, msg));
                }

                Ok(Message::BatchResult {
                    success_count,
                    errors,
                })
            }

            msg::SIGNATURE_REQ => {
                let path = decode_path(&mut self.inner)?;
                Ok(Message::SignatureReq { path })
            }

            msg::SIGNATURE_RESP => {
                let path = decode_path(&mut self.inner)?;
                let mut sig_len_buf = [0u8; 4];
                self.inner.read_exact(&mut sig_len_buf)?;
                let sig_len = u32::from_be_bytes(sig_len_buf) as usize;

                let mut signature = vec![0u8; sig_len];
                self.inner.read_exact(&mut signature)?;

                Ok(Message::SignatureResp { path, signature })
            }

            msg::WRITE_DELTA => {
                let path = decode_path(&mut self.inner)?;
                let mut exec_buf = [0u8; 1];
                self.inner.read_exact(&mut exec_buf)?;
                let executable = exec_buf[0] != 0;

                let mut delta_len_buf = [0u8; 4];
                self.inner.read_exact(&mut delta_len_buf)?;
                let delta_len = u32::from_be_bytes(delta_len_buf) as usize;

                let mut delta = vec![0u8; delta_len];
                self.inner.read_exact(&mut delta)?;

                Ok(Message::WriteDelta {
                    path,
                    delta,
                    executable,
                })
            }

            // CAS operations
            msg::CHECK_CHUNKS => {
                let mut count_buf = [0u8; 4];
                self.inner.read_exact(&mut count_buf)?;
                let count = u32::from_be_bytes(count_buf) as usize;

                let mut hashes = Vec::with_capacity(count);
                for _ in 0..count {
                    let mut hash_buf = [0u8; 32];
                    self.inner.read_exact(&mut hash_buf)?;
                    hashes.push(ContentHash::from_raw(hash_buf));
                }

                Ok(Message::CheckChunks { hashes })
            }

            msg::MISSING_CHUNKS => {
                let mut count_buf = [0u8; 4];
                self.inner.read_exact(&mut count_buf)?;
                let count = u32::from_be_bytes(count_buf) as usize;

                let mut hashes = Vec::with_capacity(count);
                for _ in 0..count {
                    let mut hash_buf = [0u8; 32];
                    self.inner.read_exact(&mut hash_buf)?;
                    hashes.push(ContentHash::from_raw(hash_buf));
                }

                Ok(Message::MissingChunks { hashes })
            }

            msg::STORE_CHUNKS => {
                let mut count_buf = [0u8; 4];
                self.inner.read_exact(&mut count_buf)?;
                let count = u32::from_be_bytes(count_buf) as usize;

                let mut chunks = Vec::with_capacity(count);
                for _ in 0..count {
                    let mut hash_buf = [0u8; 32];
                    self.inner.read_exact(&mut hash_buf)?;
                    let hash = ContentHash::from_raw(hash_buf);

                    let mut len_buf = [0u8; 4];
                    self.inner.read_exact(&mut len_buf)?;
                    let data_len = u32::from_be_bytes(len_buf) as usize;

                    let mut data = vec![0u8; data_len];
                    self.inner.read_exact(&mut data)?;

                    chunks.push((hash, Bytes::from(data)));
                }

                Ok(Message::StoreChunks { chunks })
            }

            msg::WRITE_MANIFEST => {
                let path = decode_path(&mut self.inner)?;

                let mut exec_buf = [0u8; 1];
                self.inner.read_exact(&mut exec_buf)?;
                let executable = exec_buf[0] != 0;

                let mut file_hash_buf = [0u8; 32];
                self.inner.read_exact(&mut file_hash_buf)?;
                let file_hash = ContentHash::from_raw(file_hash_buf);

                let mut size_buf = [0u8; 8];
                self.inner.read_exact(&mut size_buf)?;
                let size = u64::from_be_bytes(size_buf);

                let mut chunk_count_buf = [0u8; 4];
                self.inner.read_exact(&mut chunk_count_buf)?;
                let chunk_count = u32::from_be_bytes(chunk_count_buf) as usize;

                let mut chunks = Vec::with_capacity(chunk_count);
                for _ in 0..chunk_count {
                    let mut hash_buf = [0u8; 32];
                    self.inner.read_exact(&mut hash_buf)?;
                    chunks.push(ContentHash::from_raw(hash_buf));
                }

                Ok(Message::WriteManifest {
                    path,
                    manifest: FileManifest {
                        file_hash,
                        size,
                        chunks,
                    },
                    executable,
                })
            }

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
