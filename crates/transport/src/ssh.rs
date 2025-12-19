//! SSH transport implementation using russh (pure Rust)
//!
//! Uses russh for native Rust SSH with binary protocol support.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use color_eyre::Result;
use russh::keys::agent::client::AgentClient;
use russh::keys::key::PrivateKeyWithHashAlg;
use russh::keys::{PublicKey, load_secret_key};
use russh::{ChannelMsg, Disconnect};
use tracing::{debug, info};

use async_trait::async_trait;
use bytes::Bytes;

use crate::agent::AgentBundle;
use crate::{AgentSessionTrait, BatchOperationResult, Platform};
use zsync_core::protocol::{ChangeType, FileChange};
use zsync_core::{ContentHash, FileManifest, Message, Snapshot, protocol};

/// SSH transport for communicating with remote hosts
pub struct SshTransport {
    session: Arc<russh::client::Handle<ClientHandler>>,
    #[allow(dead_code)] // Kept for future diagnostics/debugging
    host: String,
    #[allow(dead_code)]
    port: u16,
    #[allow(dead_code)]
    user: String,
    platform: Platform,
    agent_path: Option<PathBuf>,
}

struct ClientHandler;

impl russh::client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        // TODO: Proper host key verification
        Ok(true)
    }
}

/// Active agent session for communicating with remote
pub struct AgentSession {
    channel: russh::Channel<russh::client::Msg>,
    root: PathBuf,
    buffer: Vec<u8>,
    /// Buffer ChangeNotify messages received during a request/response
    /// that should be returned on the next try_read_message call.
    pending_change_notify: Option<Vec<FileChange>>,
}

impl AgentSession {
    /// Read exact number of bytes from channel
    #[tracing::instrument(skip(self, buf), fields(want = buf.len()))]
    async fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        let mut offset = 0;

        // First, drain from buffer
        let drain_len = buf.len().min(self.buffer.len());
        if drain_len > 0 {
            buf[..drain_len].copy_from_slice(&self.buffer[..drain_len]);
            self.buffer.drain(..drain_len);
            offset = drain_len;
            tracing::trace!("drained {} bytes from buffer", drain_len);
        }

        // Then read from channel
        while offset < buf.len() {
            tracing::trace!(
                "waiting for channel data: need {} more bytes (have {}/{})",
                buf.len() - offset,
                offset,
                buf.len()
            );
            match self.channel.wait().await {
                Some(ChannelMsg::Data { data }) => {
                    let bytes = data.as_ref();
                    let to_copy = (buf.len() - offset).min(bytes.len());
                    buf[offset..offset + to_copy].copy_from_slice(&bytes[..to_copy]);
                    offset += to_copy;
                    tracing::trace!(
                        "received {} bytes from channel, copied {}, offset now {}",
                        bytes.len(),
                        to_copy,
                        offset
                    );

                    // Buffer any extra
                    if to_copy < bytes.len() {
                        self.buffer.extend_from_slice(&bytes[to_copy..]);
                        tracing::trace!("buffered {} extra bytes", bytes.len() - to_copy);
                    }
                }
                Some(ChannelMsg::Eof | ChannelMsg::Close) => {
                    tracing::warn!("channel closed unexpectedly while reading");
                    return Err(color_eyre::eyre::eyre!("Channel closed unexpectedly"));
                }
                Some(msg) => {
                    tracing::trace!(
                        "ignoring channel message: {:?}",
                        std::mem::discriminant(&msg)
                    );
                }
                None => {
                    tracing::warn!("channel returned None");
                    return Err(color_eyre::eyre::eyre!("Channel closed"));
                }
            }
        }

        tracing::trace!("read_exact complete: {} bytes", buf.len());
        Ok(())
    }

    /// Read a message from the agent
    #[tracing::instrument(skip(self))]
    async fn read_message(&mut self) -> Result<Message> {
        tracing::trace!("read_message: waiting for header");
        // Read header: type (1 byte) + length (4 bytes)
        let mut header = [0u8; 5];
        self.read_exact(&mut header).await?;

        let msg_type = header[0];
        let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
        tracing::trace!(
            "read_message: header received, type=0x{:02x}, payload_len={}",
            msg_type,
            len
        );

        // Read payload
        let mut payload = vec![0u8; len];
        if len > 0 {
            tracing::trace!("read_message: reading {} byte payload", len);
            self.read_exact(&mut payload).await?;
            tracing::trace!("read_message: payload received");
        }

        // Parse based on type
        match msg_type {
            protocol::msg::SNAPSHOT_RESP => {
                let snapshot = decode_snapshot(&payload)?;
                Ok(Message::SnapshotResp(snapshot))
            }
            protocol::msg::OK => Ok(Message::Ok),
            protocol::msg::ERROR => {
                let message = String::from_utf8_lossy(&payload).to_string();
                Ok(Message::Error(message))
            }
            protocol::msg::BATCH_RESULT => {
                let (success_count, errors) = decode_batch_result(&payload)?;
                Ok(Message::BatchResult {
                    success_count,
                    errors,
                })
            }
            protocol::msg::SIGNATURE_RESP => {
                let (path, signature) = decode_signature_resp(&payload)?;
                Ok(Message::SignatureResp { path, signature })
            }
            protocol::msg::MISSING_CHUNKS => {
                let hashes = decode_missing_chunks(&payload)?;
                Ok(Message::MissingChunks { hashes })
            }
            protocol::msg::CHANGE_NOTIFY => {
                let changes = decode_change_notify(&payload)?;
                Ok(Message::ChangeNotify { changes })
            }
            _ => Err(color_eyre::eyre::eyre!("Unknown message type: {msg_type}")),
        }
    }

    /// Read a response message, buffering any ChangeNotify messages for later.
    ///
    /// In watch mode, the server can send ChangeNotify at any time. When we're
    /// waiting for a specific response (like MissingChunks), we need to buffer
    /// the ChangeNotify and return it later via try_read_message.
    async fn read_response(&mut self) -> Result<Message> {
        loop {
            let msg = self.read_message().await?;
            match msg {
                Message::ChangeNotify { changes } => {
                    tracing::debug!("buffering ChangeNotify received during request/response");
                    self.pending_change_notify = Some(changes);
                    // Continue reading until we get the actual response
                }
                other => return Ok(other),
            }
        }
    }

    /// Try to read a message with a timeout.
    /// Returns None if no message is available within the timeout.
    /// This is used to poll for server-initiated messages like CHANGE_NOTIFY.
    pub async fn try_read_message(
        &mut self,
        timeout: std::time::Duration,
    ) -> Result<Option<Message>> {
        // First check for pending ChangeNotify from a previous request/response
        if let Some(changes) = self.pending_change_notify.take() {
            return Ok(Some(Message::ChangeNotify { changes }));
        }

        tokio::select! {
            biased;

            result = self.read_message() => {
                Ok(Some(result?))
            }
            () = tokio::time::sleep(timeout) => {
                Ok(None)
            }
        }
    }

    /// Wait for either a message from the agent or a timeout.
    /// Returns the message if one arrives, or None on timeout.
    ///
    /// This is the main method for bidirectional watch mode - it allows
    /// the CLI to wait for CHANGE_NOTIFY from the agent while also
    /// being able to handle local file changes via tokio::select!.
    pub async fn wait_for_message(&mut self) -> Result<Message> {
        self.read_message().await
    }

    /// Send raw bytes to agent
    #[tracing::instrument(skip(self, data), fields(len = data.len()))]
    async fn send(&self, data: &[u8]) -> Result<()> {
        tracing::trace!("sending {} bytes to agent", data.len());
        self.channel.data(data).await?;
        tracing::trace!("sent {} bytes successfully", data.len());
        Ok(())
    }

    /// Get snapshot from remote
    pub async fn snapshot(&mut self) -> Result<Snapshot> {
        // Send snapshot request: type=0x01, len=0
        self.send(&[protocol::msg::SNAPSHOT_REQ, 0, 0, 0, 0])
            .await?;

        match self.read_response().await? {
            Message::SnapshotResp(snapshot) => Ok(snapshot),
            Message::Error(msg) => Err(color_eyre::eyre::eyre!("Snapshot failed: {msg}")),
            other => Err(color_eyre::eyre::eyre!("Unexpected response: {other:?}")),
        }
    }

    /// Write a file to the remote
    pub async fn write_file(&mut self, path: &Path, data: &[u8], mode: u32) -> Result<()> {
        // Build payload: path_len(2) + path + mode(4) + data
        let path_bytes = path.to_string_lossy().as_bytes().to_vec();
        let payload_len = 2 + path_bytes.len() + 4 + data.len();

        // Header
        let mut msg = Vec::with_capacity(5 + payload_len);
        msg.push(protocol::msg::WRITE_FILE);
        msg.extend_from_slice(&(payload_len as u32).to_be_bytes());

        // Path
        msg.extend_from_slice(&(path_bytes.len() as u16).to_be_bytes());
        msg.extend_from_slice(&path_bytes);

        // Mode
        msg.extend_from_slice(&mode.to_be_bytes());

        // Data
        msg.extend_from_slice(data);

        self.send(&msg).await?;

        match self.read_response().await? {
            Message::Ok => Ok(()),
            Message::Error(msg) => Err(color_eyre::eyre::eyre!("Write failed: {msg}")),
            other => Err(color_eyre::eyre::eyre!("Unexpected response: {other:?}")),
        }
    }

    /// Delete a file on the remote
    pub async fn delete_file(&mut self, path: &Path) -> Result<()> {
        let path_bytes = path.to_string_lossy().as_bytes().to_vec();
        let payload_len = 2 + path_bytes.len();

        let mut msg = Vec::with_capacity(5 + payload_len);
        msg.push(protocol::msg::DELETE_FILE);
        msg.extend_from_slice(&(payload_len as u32).to_be_bytes());
        msg.extend_from_slice(&(path_bytes.len() as u16).to_be_bytes());
        msg.extend_from_slice(&path_bytes);

        self.send(&msg).await?;

        match self.read_response().await? {
            Message::Ok => Ok(()),
            Message::Error(msg) => Err(color_eyre::eyre::eyre!("Delete failed: {msg}")),
            other => Err(color_eyre::eyre::eyre!("Unexpected response: {other:?}")),
        }
    }

    /// Shutdown the agent
    pub async fn shutdown(&mut self) -> Result<()> {
        self.send(&[protocol::msg::SHUTDOWN, 0, 0, 0, 0]).await?;
        let _ = self.read_message().await;
        Ok(())
    }

    /// Get the remote root path
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    // ========== Batch Operations (Pipelining) ==========

    /// Start a batch of operations. Operations within a batch are pipelined
    /// (sent without waiting for individual ACKs). Call `end_batch` to get results.
    pub async fn start_batch(&mut self, count: u32) -> Result<()> {
        let mut msg = Vec::with_capacity(9);
        msg.push(protocol::msg::BATCH_START);
        msg.extend_from_slice(&4u32.to_be_bytes()); // payload len
        msg.extend_from_slice(&count.to_be_bytes());
        self.send(&msg).await
    }

    /// Queue a file write in batch mode (no ACK until end_batch)
    pub async fn queue_write_file(&mut self, path: &Path, data: &[u8], mode: u32) -> Result<()> {
        let path_bytes = path.to_string_lossy().as_bytes().to_vec();
        let payload_len = 2 + path_bytes.len() + 4 + data.len();

        let mut msg = Vec::with_capacity(5 + payload_len);
        msg.push(protocol::msg::WRITE_FILE);
        msg.extend_from_slice(&(payload_len as u32).to_be_bytes());
        msg.extend_from_slice(&(path_bytes.len() as u16).to_be_bytes());
        msg.extend_from_slice(&path_bytes);
        msg.extend_from_slice(&mode.to_be_bytes());
        msg.extend_from_slice(data);

        self.send(&msg).await
    }

    /// Queue a file deletion in batch mode (no ACK until end_batch)
    pub async fn queue_delete_file(&mut self, path: &Path) -> Result<()> {
        let path_bytes = path.to_string_lossy().as_bytes().to_vec();
        let payload_len = 2 + path_bytes.len();

        let mut msg = Vec::with_capacity(5 + payload_len);
        msg.push(protocol::msg::DELETE_FILE);
        msg.extend_from_slice(&(payload_len as u32).to_be_bytes());
        msg.extend_from_slice(&(path_bytes.len() as u16).to_be_bytes());
        msg.extend_from_slice(&path_bytes);

        self.send(&msg).await
    }

    /// Queue a delta write in batch mode (no ACK until end_batch)
    pub async fn queue_write_delta(&mut self, path: &Path, delta: &[u8], mode: u32) -> Result<()> {
        let path_bytes = path.to_string_lossy().as_bytes().to_vec();
        let payload_len = 2 + path_bytes.len() + 4 + 4 + delta.len();

        let mut msg = Vec::with_capacity(5 + payload_len);
        msg.push(protocol::msg::WRITE_DELTA);
        msg.extend_from_slice(&(payload_len as u32).to_be_bytes());
        msg.extend_from_slice(&(path_bytes.len() as u16).to_be_bytes());
        msg.extend_from_slice(&path_bytes);
        msg.extend_from_slice(&mode.to_be_bytes());
        msg.extend_from_slice(&(delta.len() as u32).to_be_bytes());
        msg.extend_from_slice(delta);

        self.send(&msg).await
    }

    /// End the batch and get results
    pub async fn end_batch(&mut self) -> Result<BatchOperationResult> {
        self.send(&[protocol::msg::BATCH_END, 0, 0, 0, 0]).await?;

        match self.read_response().await? {
            Message::BatchResult {
                success_count,
                errors,
            } => Ok(BatchOperationResult {
                success_count,
                errors,
            }),
            Message::Error(msg) => Err(color_eyre::eyre::eyre!("Batch failed: {msg}")),
            other => Err(color_eyre::eyre::eyre!("Unexpected response: {other:?}")),
        }
    }

    // ========== Delta Operations ==========

    /// Request signature for a file on the remote (for delta computation)
    pub async fn get_signature(&mut self, path: &Path) -> Result<Vec<u8>> {
        let path_bytes = path.to_string_lossy().as_bytes().to_vec();
        let payload_len = 2 + path_bytes.len();

        let mut msg = Vec::with_capacity(5 + payload_len);
        msg.push(protocol::msg::SIGNATURE_REQ);
        msg.extend_from_slice(&(payload_len as u32).to_be_bytes());
        msg.extend_from_slice(&(path_bytes.len() as u16).to_be_bytes());
        msg.extend_from_slice(&path_bytes);

        self.send(&msg).await?;

        match self.read_response().await? {
            Message::SignatureResp { signature, .. } => Ok(signature),
            Message::Error(msg) => Err(color_eyre::eyre::eyre!("Signature request failed: {msg}")),
            other => Err(color_eyre::eyre::eyre!("Unexpected response: {other:?}")),
        }
    }

    /// Write a file using delta transfer
    pub async fn write_delta(&mut self, path: &Path, delta: &[u8], mode: u32) -> Result<()> {
        let path_bytes = path.to_string_lossy().as_bytes().to_vec();
        let payload_len = 2 + path_bytes.len() + 4 + 4 + delta.len();

        let mut msg = Vec::with_capacity(5 + payload_len);
        msg.push(protocol::msg::WRITE_DELTA);
        msg.extend_from_slice(&(payload_len as u32).to_be_bytes());
        msg.extend_from_slice(&(path_bytes.len() as u16).to_be_bytes());
        msg.extend_from_slice(&path_bytes);
        msg.extend_from_slice(&mode.to_be_bytes());
        msg.extend_from_slice(&(delta.len() as u32).to_be_bytes());
        msg.extend_from_slice(delta);

        self.send(&msg).await?;

        match self.read_response().await? {
            Message::Ok => Ok(()),
            Message::Error(msg) => Err(color_eyre::eyre::eyre!("Delta write failed: {msg}")),
            other => Err(color_eyre::eyre::eyre!("Unexpected response: {other:?}")),
        }
    }

    // ========== CAS (Content-Addressable Storage) Operations ==========

    /// Check which chunks the server is missing
    pub async fn check_chunks(&mut self, hashes: &[ContentHash]) -> Result<Vec<ContentHash>> {
        // Build payload: count(4) + hashes(32*count)
        let payload_len = 4 + hashes.len() * 32;

        let mut msg = Vec::with_capacity(5 + payload_len);
        msg.push(protocol::msg::CHECK_CHUNKS);
        msg.extend_from_slice(&(payload_len as u32).to_be_bytes());
        msg.extend_from_slice(&(hashes.len() as u32).to_be_bytes());
        for hash in hashes {
            msg.extend_from_slice(hash.as_bytes());
        }

        self.send(&msg).await?;

        match self.read_response().await? {
            Message::MissingChunks { hashes } => Ok(hashes),
            Message::Error(msg) => Err(color_eyre::eyre::eyre!("Check chunks failed: {msg}")),
            other => Err(color_eyre::eyre::eyre!("Unexpected response: {other:?}")),
        }
    }

    /// Store chunks on the server
    pub async fn store_chunks(&mut self, chunks: &[(ContentHash, Bytes)]) -> Result<()> {
        self.store_chunks_with_progress(chunks, |_| {}).await
    }

    /// Store chunks on the server with progress callback.
    ///
    /// The callback is invoked after each chunk is sent with the number of bytes
    /// transferred in that chunk. This allows real-time progress tracking during upload.
    #[tracing::instrument(skip(self, chunks, on_progress), fields(chunk_count = chunks.len()))]
    pub async fn store_chunks_with_progress<F>(
        &mut self,
        chunks: &[(ContentHash, Bytes)],
        mut on_progress: F,
    ) -> Result<()>
    where
        F: FnMut(u64),
    {
        // Calculate total payload length: count(4) + (hash(32) + len(4) + data)*count
        let payload_len: usize = 4 + chunks
            .iter()
            .map(|(_, data)| 32 + 4 + data.len())
            .sum::<usize>();

        tracing::debug!(
            "store_chunks_with_progress: {} chunks, {} bytes total payload",
            chunks.len(),
            payload_len
        );

        // Send header: type(1) + length(4) + count(4)
        let mut header = Vec::with_capacity(9);
        header.push(protocol::msg::STORE_CHUNKS);
        header.extend_from_slice(&(payload_len as u32).to_be_bytes());
        header.extend_from_slice(&(chunks.len() as u32).to_be_bytes());
        tracing::trace!("sending STORE_CHUNKS header: 9 bytes");
        self.send(&header).await?;
        tracing::trace!("STORE_CHUNKS header sent");

        // Stream each chunk individually for progress tracking
        for (idx, (hash, data)) in chunks.iter().enumerate() {
            tracing::trace!(
                "sending chunk {}/{}: hash={}, {} bytes",
                idx + 1,
                chunks.len(),
                hash,
                data.len()
            );

            // Build chunk header: hash(32) + len(4)
            let mut chunk_header = Vec::with_capacity(36);
            chunk_header.extend_from_slice(hash.as_bytes());
            chunk_header.extend_from_slice(&(data.len() as u32).to_be_bytes());
            self.send(&chunk_header).await?;
            tracing::trace!("chunk {} header sent", idx + 1);

            // Send chunk data
            self.send(data).await?;
            tracing::trace!("chunk {} data sent", idx + 1);

            // Report progress: header (36 bytes) + data
            on_progress(36 + data.len() as u64);
        }

        tracing::debug!("all chunks sent, waiting for server response");
        match self.read_response().await? {
            Message::Ok => {
                tracing::debug!("store_chunks_with_progress: server acknowledged OK");
                Ok(())
            }
            Message::Error(msg) => Err(color_eyre::eyre::eyre!("Store chunks failed: {msg}")),
            other => Err(color_eyre::eyre::eyre!("Unexpected response: {other:?}")),
        }
    }

    /// Queue a manifest write in batch mode (no ACK until end_batch)
    pub async fn queue_write_manifest(
        &mut self,
        path: &Path,
        manifest: &FileManifest,
        mode: u32,
    ) -> Result<()> {
        let path_bytes = path.to_string_lossy().as_bytes().to_vec();
        // path_len(2) + path + mode(4) + file_hash(32) + size(8) + chunk_count(4) + hashes
        let payload_len = 2 + path_bytes.len() + 4 + 32 + 8 + 4 + manifest.chunks.len() * 32;

        let mut msg = Vec::with_capacity(5 + payload_len);
        msg.push(protocol::msg::WRITE_MANIFEST);
        msg.extend_from_slice(&(payload_len as u32).to_be_bytes());
        msg.extend_from_slice(&(path_bytes.len() as u16).to_be_bytes());
        msg.extend_from_slice(&path_bytes);
        msg.extend_from_slice(&mode.to_be_bytes());
        msg.extend_from_slice(manifest.file_hash.as_bytes());
        msg.extend_from_slice(&manifest.size.to_be_bytes());
        msg.extend_from_slice(&(manifest.chunks.len() as u32).to_be_bytes());
        for hash in &manifest.chunks {
            msg.extend_from_slice(hash.as_bytes());
        }

        self.send(&msg).await
    }
}

#[async_trait]
impl AgentSessionTrait for AgentSession {
    async fn snapshot(&mut self) -> Result<Snapshot> {
        Self::snapshot(self).await
    }

    async fn write_file(&mut self, path: &Path, data: &[u8], mode: u32) -> Result<()> {
        Self::write_file(self, path, data, mode).await
    }

    async fn delete_file(&mut self, path: &Path) -> Result<()> {
        Self::delete_file(self, path).await
    }

    async fn shutdown(&mut self) -> Result<()> {
        Self::shutdown(self).await
    }

    fn root(&self) -> &Path {
        Self::root(self)
    }

    async fn start_batch(&mut self, count: u32) -> Result<()> {
        Self::start_batch(self, count).await
    }

    async fn queue_write_file(&mut self, path: &Path, data: &[u8], mode: u32) -> Result<()> {
        Self::queue_write_file(self, path, data, mode).await
    }

    async fn queue_delete_file(&mut self, path: &Path) -> Result<()> {
        Self::queue_delete_file(self, path).await
    }

    async fn queue_write_manifest(
        &mut self,
        path: &Path,
        manifest: &FileManifest,
        mode: u32,
    ) -> Result<()> {
        Self::queue_write_manifest(self, path, manifest, mode).await
    }

    async fn end_batch(&mut self) -> Result<BatchOperationResult> {
        Self::end_batch(self).await
    }

    async fn check_chunks(&mut self, hashes: &[ContentHash]) -> Result<Vec<ContentHash>> {
        Self::check_chunks(self, hashes).await
    }

    async fn store_chunks(&mut self, chunks: &[(ContentHash, Bytes)]) -> Result<()> {
        Self::store_chunks(self, chunks).await
    }
}

/// Simple glob matching for SSH host patterns
/// Supports * as wildcard (matches any characters)
fn glob_match(pattern: &str, text: &str) -> bool {
    let mut pattern_chars = pattern.chars().peekable();
    let mut text_chars = text.chars();

    while let Some(p) = pattern_chars.next() {
        match p {
            '*' => {
                // If * is at end, match everything
                if pattern_chars.peek().is_none() {
                    return true;
                }
                // Try matching rest of pattern at each position
                let rest: String = pattern_chars.collect();
                let remaining: String = text_chars.collect();
                for i in 0..=remaining.len() {
                    if glob_match(&rest, &remaining[i..]) {
                        return true;
                    }
                }
                return false;
            }
            '?' => {
                // Match any single character
                if text_chars.next().is_none() {
                    return false;
                }
            }
            c => {
                if text_chars.next() != Some(c) {
                    return false;
                }
            }
        }
    }

    text_chars.next().is_none()
}

/// Decode snapshot from binary (same format as protocol.rs)
fn decode_snapshot(data: &[u8]) -> Result<Snapshot> {
    use std::io::{Cursor, Read};
    use std::time::{Duration, UNIX_EPOCH};
    use zsync_core::{ContentHash, FileEntry};

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

        // Mode
        let mut mode_buf = [0u8; 4];
        cursor.read_exact(&mut mode_buf)?;
        let mode = u32::from_be_bytes(mode_buf);

        // Modification time (seconds since UNIX epoch)
        let mut mtime_buf = [0u8; 8];
        cursor.read_exact(&mut mtime_buf)?;
        let mtime_secs = i64::from_be_bytes(mtime_buf);
        let modified = if mtime_secs >= 0 {
            UNIX_EPOCH + Duration::from_secs(mtime_secs as u64)
        } else {
            UNIX_EPOCH - Duration::from_secs((-mtime_secs) as u64)
        };

        entries.push(FileEntry {
            path,
            size,
            modified,
            hash,
            mode,
        });
    }

    Ok(Snapshot::from_entries(entries))
}

/// Decode batch result from binary
fn decode_batch_result(data: &[u8]) -> Result<(u32, Vec<(u32, String)>)> {
    use std::io::{Cursor, Read};

    let mut cursor = Cursor::new(data);

    // Success count
    let mut success_buf = [0u8; 4];
    cursor.read_exact(&mut success_buf)?;
    let success_count = u32::from_be_bytes(success_buf);

    // Error count
    let mut error_count_buf = [0u8; 4];
    cursor.read_exact(&mut error_count_buf)?;
    let error_count = u32::from_be_bytes(error_count_buf) as usize;

    let mut errors = Vec::with_capacity(error_count);
    for _ in 0..error_count {
        let mut idx_buf = [0u8; 4];
        cursor.read_exact(&mut idx_buf)?;
        let idx = u32::from_be_bytes(idx_buf);

        let mut msg_len_buf = [0u8; 2];
        cursor.read_exact(&mut msg_len_buf)?;
        let msg_len = u16::from_be_bytes(msg_len_buf) as usize;

        let mut msg_buf = vec![0u8; msg_len];
        cursor.read_exact(&mut msg_buf)?;
        let msg = String::from_utf8_lossy(&msg_buf).to_string();

        errors.push((idx, msg));
    }

    Ok((success_count, errors))
}

/// Decode signature response from binary
fn decode_signature_resp(data: &[u8]) -> Result<(PathBuf, Vec<u8>)> {
    use std::io::{Cursor, Read};

    let mut cursor = Cursor::new(data);

    // Path
    let mut path_len_buf = [0u8; 2];
    cursor.read_exact(&mut path_len_buf)?;
    let path_len = u16::from_be_bytes(path_len_buf) as usize;

    let mut path_buf = vec![0u8; path_len];
    cursor.read_exact(&mut path_buf)?;
    let path = PathBuf::from(String::from_utf8_lossy(&path_buf).to_string());

    // Signature length
    let mut sig_len_buf = [0u8; 4];
    cursor.read_exact(&mut sig_len_buf)?;
    let sig_len = u32::from_be_bytes(sig_len_buf) as usize;

    // Signature data
    let mut signature = vec![0u8; sig_len];
    cursor.read_exact(&mut signature)?;

    Ok((path, signature))
}

/// Decode missing chunks response from binary
fn decode_missing_chunks(data: &[u8]) -> Result<Vec<ContentHash>> {
    use std::io::{Cursor, Read};

    let mut cursor = Cursor::new(data);

    // Count
    let mut count_buf = [0u8; 4];
    cursor.read_exact(&mut count_buf)?;
    let count = u32::from_be_bytes(count_buf) as usize;

    let mut hashes = Vec::with_capacity(count);
    for _ in 0..count {
        let mut hash_buf = [0u8; 32];
        cursor.read_exact(&mut hash_buf)?;
        hashes.push(ContentHash::from_raw(hash_buf));
    }

    Ok(hashes)
}

/// Decode change notify message from binary
fn decode_change_notify(data: &[u8]) -> Result<Vec<FileChange>> {
    use std::io::{Cursor, Read as _};

    let mut cursor = Cursor::new(data);

    // Count
    let mut count_buf = [0u8; 4];
    cursor.read_exact(&mut count_buf)?;
    let count = u32::from_be_bytes(count_buf) as usize;

    let mut changes = Vec::with_capacity(count);
    for _ in 0..count {
        // Path length
        let mut path_len_buf = [0u8; 2];
        cursor.read_exact(&mut path_len_buf)?;
        let path_len = u16::from_be_bytes(path_len_buf) as usize;

        // Path bytes
        let mut path_buf = vec![0u8; path_len];
        cursor.read_exact(&mut path_buf)?;
        let path = PathBuf::from(String::from_utf8_lossy(&path_buf).to_string());

        // Content hash
        let mut hash_buf = [0u8; 32];
        cursor.read_exact(&mut hash_buf)?;
        let content_hash = ContentHash::from_raw(hash_buf);

        // Change type
        let mut type_buf = [0u8; 1];
        cursor.read_exact(&mut type_buf)?;
        let change_type = ChangeType::from_u8(type_buf[0])
            .ok_or_else(|| color_eyre::eyre::eyre!("invalid change type: {}", type_buf[0]))?;

        changes.push(FileChange {
            path,
            content_hash,
            change_type,
        });
    }

    Ok(changes)
}

/// Parsed SSH config for a specific host (naive parser)
struct SshHostConfig {
    identity_agent: Option<PathBuf>,
}

impl SshTransport {
    /// Connect to a remote host via SSH
    pub async fn connect(host: &str, port: u16, user: &str) -> Result<Self> {
        info!("Connecting to {user}@{host}:{port}");

        let config = Arc::new(russh::client::Config::default());
        let handler = ClientHandler;

        let mut session = russh::client::connect(config, (host, port), handler).await?;

        // Try to authenticate with SSH keys
        let authenticated = Self::authenticate(&mut session, user, host).await?;
        if !authenticated {
            return Err(color_eyre::eyre::eyre!(
                "SSH authentication failed for {user}@{host}"
            ));
        }

        // Detect remote platform
        let platform = Self::detect_platform(&session).await?;
        info!("Remote platform: {platform:?}");

        Ok(Self {
            session: Arc::new(session),
            host: host.to_string(),
            port,
            user: user.to_string(),
            platform,
            agent_path: None,
        })
    }

    /// Parse SSH config for IdentityAgent (naive line-by-line parser)
    ///
    /// This is a simple parser that looks for `IdentityAgent` in ~/.ssh/config.
    /// It handles:
    /// - Global settings (Host *)
    /// - Host-specific settings
    /// - Paths with spaces (common with 1Password)
    /// - Tilde expansion
    fn parse_ssh_config(host: &str) -> SshHostConfig {
        use std::io::BufRead;

        let Some(home) = dirs::home_dir() else {
            return SshHostConfig {
                identity_agent: None,
            };
        };

        let ssh_config_path = home.join(".ssh/config");
        let Ok(file) = std::fs::File::open(&ssh_config_path) else {
            return SshHostConfig {
                identity_agent: None,
            };
        };

        let reader = std::io::BufReader::new(file);
        let mut current_hosts: Vec<String> = vec!["*".to_string()]; // Start with global
        let mut global_identity_agent: Option<PathBuf> = None;
        let mut host_identity_agent: Option<PathBuf> = None;

        for line in reader.lines().map_while(Result::ok) {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Check for Host directive
            if let Some(hosts) = line
                .strip_prefix("Host ")
                .or_else(|| line.strip_prefix("Host\t"))
            {
                current_hosts = hosts.split_whitespace().map(String::from).collect();
                continue;
            }

            // Check for IdentityAgent directive
            if let Some(agent) = line
                .strip_prefix("IdentityAgent ")
                .or_else(|| line.strip_prefix("IdentityAgent\t"))
            {
                let agent = agent.trim().trim_matches('"').trim_matches('\'');
                let expanded = if let Some(stripped) = agent.strip_prefix("~/") {
                    home.join(stripped)
                } else {
                    PathBuf::from(agent)
                };

                if expanded.exists() {
                    // Check if this applies to our host
                    let matches_host = current_hosts.iter().any(|pattern| {
                        pattern == "*" || pattern == host || glob_match(pattern, host)
                    });

                    if matches_host {
                        if current_hosts.contains(&"*".to_string()) {
                            global_identity_agent = Some(expanded);
                        } else {
                            host_identity_agent = Some(expanded);
                        }
                    }
                } else {
                    debug!("IdentityAgent path does not exist: {}", expanded.display());
                }
            }
        }

        // Host-specific takes precedence over global
        let identity_agent = host_identity_agent.or(global_identity_agent);
        if let Some(ref path) = identity_agent {
            debug!("Found IdentityAgent for host {host}: {}", path.display());
        }

        SshHostConfig { identity_agent }
    }

    /// Get the SSH agent socket path from SSH config or environment
    fn get_agent_socket_path(host: &str) -> Option<PathBuf> {
        // First, try SSH config for this specific host
        let config = Self::parse_ssh_config(host);
        if let Some(agent_path) = config.identity_agent {
            return Some(agent_path);
        }

        // Fall back to SSH_AUTH_SOCK environment variable
        if let Ok(sock) = std::env::var("SSH_AUTH_SOCK") {
            let path = PathBuf::from(&sock);
            if path.exists() {
                debug!("Using SSH_AUTH_SOCK: {sock}");
                return Some(path);
            }
        }

        None
    }

    /// Authenticate using SSH keys
    async fn authenticate(
        session: &mut russh::client::Handle<ClientHandler>,
        user: &str,
        host: &str,
    ) -> Result<bool> {
        // Try SSH agent first (from config or environment)
        if let Some(agent_path) = Self::get_agent_socket_path(host) {
            match AgentClient::connect_uds(&agent_path).await {
                Ok(mut agent) => {
                    debug!("Connected to SSH agent at {}", agent_path.display());
                    match agent.request_identities().await {
                        Ok(identities) => {
                            debug!("SSH agent has {} identities", identities.len());
                            for identity in identities {
                                if let Ok(result) = session
                                    .authenticate_publickey_with(user, identity, None, &mut agent)
                                    .await
                                {
                                    if result.success() {
                                        info!("Authenticated via SSH agent");
                                        return Ok(true);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            debug!("Failed to get identities from agent: {e}");
                        }
                    }
                }
                Err(e) => {
                    debug!(
                        "Failed to connect to SSH agent at {}: {e}",
                        agent_path.display()
                    );
                }
            }
        }

        // Try default key paths
        let home = dirs::home_dir().ok_or_else(|| color_eyre::eyre::eyre!("No home directory"))?;
        let key_paths = [
            home.join(".ssh/id_ed25519"),
            home.join(".ssh/id_rsa"),
            home.join(".ssh/id_ecdsa"),
        ];

        for key_path in &key_paths {
            if key_path.exists() {
                match load_secret_key(key_path, None) {
                    Ok(key) => {
                        let key_with_hash = PrivateKeyWithHashAlg::new(Arc::new(key), None);
                        if let Ok(result) =
                            session.authenticate_publickey(user, key_with_hash).await
                        {
                            if result.success() {
                                info!("Authenticated with key: {}", key_path.display());
                                return Ok(true);
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Failed to load key {}: {e}", key_path.display());
                    }
                }
            }
        }

        Ok(false)
    }

    /// Detect remote platform via uname
    async fn detect_platform(session: &russh::client::Handle<ClientHandler>) -> Result<Platform> {
        let mut channel = session.channel_open_session().await?;
        channel.exec(true, "uname -s && uname -m").await?;

        let mut stdout = String::new();
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Data { data }) => {
                    stdout.push_str(&String::from_utf8_lossy(&data));
                }
                Some(ChannelMsg::Eof | ChannelMsg::Close) | None => break,
                Some(_) => {}
            }
        }

        let lines: Vec<&str> = stdout.lines().collect();
        if lines.len() < 2 {
            return Err(color_eyre::eyre::eyre!(
                "Failed to detect platform: unexpected uname output: {stdout}"
            ));
        }

        Platform::from_uname(lines[0], lines[1]).ok_or_else(|| {
            color_eyre::eyre::eyre!("Unsupported platform: {} {}", lines[0], lines[1])
        })
    }

    /// Get the remote platform
    #[must_use]
    pub fn platform(&self) -> Platform {
        self.platform
    }

    /// Execute a command on the remote host
    pub async fn execute(&self, command: &str) -> Result<(String, String, i32)> {
        let mut channel = self.session.channel_open_session().await?;
        channel.exec(true, command).await?;

        let mut stdout = String::new();
        let mut stderr = String::new();
        let mut exit_code = 0;

        loop {
            match channel.wait().await {
                Some(ChannelMsg::Data { data }) => {
                    stdout.push_str(&String::from_utf8_lossy(&data));
                }
                Some(ChannelMsg::ExtendedData { data, ext: 1 }) => {
                    stderr.push_str(&String::from_utf8_lossy(&data));
                }
                Some(ChannelMsg::ExitStatus { exit_status }) => {
                    exit_code = exit_status as i32;
                }
                Some(ChannelMsg::Eof | ChannelMsg::Close) | None => break,
                Some(_) => {}
            }
        }

        Ok((stdout, stderr, exit_code))
    }

    /// Ensure the agent is deployed to the remote host
    pub async fn ensure_agent(&mut self, bundle: &AgentBundle) -> Result<PathBuf> {
        if let Some(path) = &self.agent_path {
            return Ok(path.clone());
        }

        // Get agent binary for this platform
        let agent_data = bundle.get(self.platform).ok_or_else(|| {
            color_eyre::eyre::eyre!("No agent binary for platform {:?}", self.platform)
        })?;

        // Use content hash to ensure agent is re-deployed when code changes
        let agent_hash = zsync_core::ContentHash::from_bytes(agent_data);
        let hash_prefix = &agent_hash.to_hex()[..12];
        let remote_dir = format!(".zsync/agents/{hash_prefix}");
        let remote_path = format!("{remote_dir}/zsync-agent");

        info!("Agent hash: {hash_prefix} ({} bytes)", agent_data.len());

        // Check if this exact agent version already exists
        let (stdout, _, _) = self
            .execute(&format!("test -x ~/{remote_path} && echo exists"))
            .await?;

        if stdout.contains("exists") {
            info!("Agent {hash_prefix} already deployed, reusing");
            let (home, _, _) = self.execute("echo $HOME").await?;
            let home = home.trim();
            let path = PathBuf::from(format!("{home}/{remote_path}"));
            self.agent_path = Some(path.clone());
            return Ok(path);
        }

        info!("Deploying NEW agent {hash_prefix} to remote host...");

        // Create directory
        self.execute(&format!("mkdir -p ~/{remote_dir}")).await?;

        // Get remote home dir
        let (home, _, _) = self.execute("echo $HOME").await?;
        let home = home.trim();
        let full_path = format!("{home}/{remote_path}");

        // Upload via exec + stdin
        self.upload_bytes(agent_data, &full_path).await?;

        // Make executable
        self.execute(&format!("chmod +x {full_path}")).await?;

        info!("Agent deployed to {full_path}");
        self.agent_path = Some(PathBuf::from(&full_path));
        Ok(PathBuf::from(full_path))
    }

    /// Upload bytes to remote path via exec + stdin
    async fn upload_bytes(&self, data: &[u8], remote_path: &str) -> Result<()> {
        let mut channel = self.session.channel_open_session().await?;
        channel.exec(true, format!("cat > {remote_path}")).await?;

        channel.data(data).await?;
        channel.eof().await?;

        // Wait for completion
        loop {
            if let Some(ChannelMsg::Eof | ChannelMsg::Close) = channel.wait().await {
                break;
            }
        }

        Ok(())
    }

    /// Start the agent process on the remote host and return a session
    pub async fn start_agent(&self, root: &str) -> Result<AgentSession> {
        self.start_agent_internal(root, false).await
    }

    /// Start the agent process with file watching enabled for bidirectional sync
    pub async fn start_agent_watch(&self, root: &str) -> Result<AgentSession> {
        self.start_agent_internal(root, true).await
    }

    /// Internal method to start agent with or without watch mode
    async fn start_agent_internal(&self, root: &str, watch: bool) -> Result<AgentSession> {
        let agent_path = self.agent_path.as_ref().ok_or_else(|| {
            color_eyre::eyre::eyre!("Agent not deployed - call ensure_agent first")
        })?;

        let channel = self.session.channel_open_session().await?;
        let watch_flag = if watch { " --watch" } else { "" };
        channel
            .exec(
                true,
                format!("{} daemon --root {root}{watch_flag}", agent_path.display()),
            )
            .await?;

        Ok(AgentSession {
            channel,
            root: PathBuf::from(root),
            buffer: Vec::new(),
            pending_change_notify: None,
        })
    }

    /// Start port forwarding from local to remote.
    ///
    /// Returns a handle to the background task. The port forwarding runs until
    /// the task is dropped or the SSH session is closed.
    ///
    /// # Arguments
    /// * `local_port` - Local port to listen on (binds to 127.0.0.1)
    /// * `remote_host` - Remote host to connect to (usually "localhost")
    /// * `remote_port` - Remote port to connect to
    pub async fn forward_port(
        &self,
        local_port: u16,
        remote_host: &str,
        remote_port: u16,
    ) -> Result<tokio::task::JoinHandle<()>> {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", local_port)).await?;
        let session = Arc::clone(&self.session);
        let remote_host = remote_host.to_string();

        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((socket, addr)) => {
                        let session = Arc::clone(&session);
                        let remote_host = remote_host.clone();

                        tokio::spawn(async move {
                            if let Err(e) = handle_port_forward(
                                socket,
                                &session,
                                &remote_host,
                                remote_port,
                                addr,
                            )
                            .await
                            {
                                debug!("Port forward connection error: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        debug!("Port forward listener error: {e}");
                        break;
                    }
                }
            }
        });

        Ok(handle)
    }

    /// Disconnect from the remote host
    pub async fn disconnect(self) -> Result<()> {
        self.session
            .disconnect(Disconnect::ByApplication, "", "English")
            .await?;
        Ok(())
    }
}

/// Handle a single port-forwarded connection
async fn handle_port_forward(
    socket: tokio::net::TcpStream,
    session: &russh::client::Handle<ClientHandler>,
    remote_host: &str,
    remote_port: u16,
    local_addr: std::net::SocketAddr,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Open SSH direct-tcpip channel to remote
    let channel = session
        .channel_open_direct_tcpip(
            remote_host,
            u32::from(remote_port),
            local_addr.ip().to_string(),
            u32::from(local_addr.port()),
        )
        .await?;

    // Convert channel to stream that implements AsyncRead + AsyncWrite
    let channel_stream = channel.into_stream();
    let (mut channel_read, mut channel_write) = tokio::io::split(channel_stream);
    let (mut socket_read, mut socket_write) = socket.into_split();

    // Task: local socket -> SSH channel
    let write_task = tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        loop {
            match socket_read.read(&mut buf).await {
                Ok(0) => break, // EOF
                Ok(n) => {
                    if channel_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = channel_write.shutdown().await;
    });

    // Task: SSH channel -> local socket
    let read_task = tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        loop {
            match channel_read.read(&mut buf).await {
                Ok(0) => break, // EOF
                Ok(n) => {
                    if socket_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = socket_write.shutdown().await;
    });

    // Wait for both directions to complete
    let _ = tokio::join!(write_task, read_task);

    Ok(())
}
