//! zsync-transport: SSH transport layer
//!
//! Handles SSH connections, agent deployment, and remote communication.

use std::path::Path;

use async_trait::async_trait;
use bytes::Bytes;
use color_eyre::Result;
use zsync_core::{ContentHash, FileManifest, Snapshot};

pub mod agent;
pub mod local;
pub mod ssh;

pub use agent::AgentBundle;
pub use local::LocalTransport;
pub use ssh::{AgentSession, SshTransport};

/// Result of a batch operation
#[derive(Debug, Clone)]
pub struct BatchOperationResult {
    /// Number of successful operations
    pub success_count: u32,
    /// Errors (index, message) for failed operations
    pub errors: Vec<(u32, String)>,
}

/// Trait for agent session operations (abstraction for testing)
///
/// This trait allows swapping the real SSH transport with a local
/// in-process implementation for testing.
#[async_trait]
pub trait AgentSessionTrait: Send {
    /// Get snapshot from remote
    async fn snapshot(&mut self) -> Result<Snapshot>;

    /// Write a file to the remote
    async fn write_file(&mut self, path: &Path, data: &[u8], mode: u32) -> Result<()>;

    /// Delete a file on the remote
    async fn delete_file(&mut self, path: &Path) -> Result<()>;

    /// Shutdown the agent
    async fn shutdown(&mut self) -> Result<()>;

    /// Get the remote root path
    fn root(&self) -> &Path;

    // === Batch Operations ===

    /// Start a batch of operations
    async fn start_batch(&mut self, count: u32) -> Result<()>;

    /// Queue a file write in batch mode
    async fn queue_write_file(&mut self, path: &Path, data: &[u8], mode: u32) -> Result<()>;

    /// Queue a file deletion in batch mode
    async fn queue_delete_file(&mut self, path: &Path) -> Result<()>;

    /// Queue a manifest write in batch mode
    async fn queue_write_manifest(
        &mut self,
        path: &Path,
        manifest: &FileManifest,
        mode: u32,
    ) -> Result<()>;

    /// End the batch and get results
    async fn end_batch(&mut self) -> Result<BatchOperationResult>;

    // === CAS Operations ===

    /// Check which chunks the server is missing
    async fn check_chunks(&mut self, hashes: &[ContentHash]) -> Result<Vec<ContentHash>>;

    /// Store chunks on the server
    async fn store_chunks(&mut self, chunks: &[(ContentHash, Bytes)]) -> Result<()>;
}

/// Target platform for agent binaries
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Platform {
    LinuxX86_64,
    LinuxAarch64,
    DarwinX86_64,
    DarwinAarch64,
}

impl Platform {
    /// Detect platform from uname output
    #[must_use]
    pub fn from_uname(uname_s: &str, uname_m: &str) -> Option<Self> {
        let os = uname_s.trim().to_lowercase();
        let arch = uname_m.trim().to_lowercase();

        match (os.as_str(), arch.as_str()) {
            ("linux", "x86_64") => Some(Self::LinuxX86_64),
            ("linux", "aarch64" | "arm64") => Some(Self::LinuxAarch64),
            ("darwin", "x86_64") => Some(Self::DarwinX86_64),
            ("darwin", "arm64" | "aarch64") => Some(Self::DarwinAarch64),
            _ => None,
        }
    }

    /// Get the binary name suffix for this platform
    #[must_use]
    pub fn binary_suffix(&self) -> &'static str {
        match self {
            Self::LinuxX86_64 => "linux-x86_64",
            Self::LinuxAarch64 => "linux-aarch64",
            Self::DarwinX86_64 => "darwin-x86_64",
            Self::DarwinAarch64 => "darwin-aarch64",
        }
    }
}
