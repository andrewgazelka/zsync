//! Local in-process transport for testing
//!
//! This module provides a `LocalTransport` that simulates agent operations
//! directly in the local filesystem, without SSH. Useful for testing.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use bytes::Bytes;
use color_eyre::Result;

use zsync_core::{ChunkStore, ContentHash, FileManifest, Scanner, Snapshot};

use crate::{AgentSessionTrait, BatchOperationResult};

/// Local transport for testing (no SSH, operates on local filesystem)
pub struct LocalTransport {
    root: PathBuf,
}

impl LocalTransport {
    /// Create a new local transport with the given root directory
    pub fn new(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;
        std::fs::create_dir_all(root.join(".zsync/cas"))?;
        Ok(Self { root })
    }

    /// Start a local agent session
    pub fn start_session(&self) -> Result<LocalAgentSession> {
        let cas = ChunkStore::open(&self.root.join(".zsync/cas"))?;
        Ok(LocalAgentSession {
            root: self.root.clone(),
            cas,
            batch_mode: false,
            batch_errors: Vec::new(),
            batch_success: 0,
        })
    }
}

/// Local agent session for testing
pub struct LocalAgentSession {
    root: PathBuf,
    cas: ChunkStore,
    batch_mode: bool,
    batch_errors: Vec<(u32, String)>,
    batch_success: u32,
}

#[async_trait]
impl AgentSessionTrait for LocalAgentSession {
    async fn snapshot(&mut self) -> Result<Snapshot> {
        let scanner = Scanner::new(&self.root);
        let entries = scanner.scan()?;
        Ok(Snapshot::from_entries(entries))
    }

    async fn write_file(&mut self, path: &Path, data: &[u8], mode: u32) -> Result<()> {
        let full_path = self.root.join(path);

        // Create parent directories
        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(&full_path, data)?;

        // Set mode on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let perms = std::fs::Permissions::from_mode(mode);
            std::fs::set_permissions(&full_path, perms)?;
        }
        let _ = mode; // Suppress unused warning on non-Unix

        Ok(())
    }

    async fn delete_file(&mut self, path: &Path) -> Result<()> {
        let full_path = self.root.join(path);
        if full_path.exists() {
            std::fs::remove_file(&full_path)?;
        }
        Ok(())
    }

    async fn shutdown(&mut self) -> Result<()> {
        // Nothing to do for local transport
        Ok(())
    }

    fn root(&self) -> &Path {
        &self.root
    }

    async fn start_batch(&mut self, _count: u32) -> Result<()> {
        self.batch_mode = true;
        self.batch_errors.clear();
        self.batch_success = 0;
        Ok(())
    }

    async fn queue_write_file(&mut self, path: &Path, data: &[u8], mode: u32) -> Result<()> {
        if !self.batch_mode {
            color_eyre::eyre::bail!("Not in batch mode");
        }

        match self.write_file(path, data, mode).await {
            Ok(()) => self.batch_success += 1,
            Err(e) => {
                let idx = self.batch_success + self.batch_errors.len() as u32;
                self.batch_errors.push((idx, e.to_string()));
            }
        }
        Ok(())
    }

    async fn queue_delete_file(&mut self, path: &Path) -> Result<()> {
        if !self.batch_mode {
            color_eyre::eyre::bail!("Not in batch mode");
        }

        match self.delete_file(path).await {
            Ok(()) => self.batch_success += 1,
            Err(e) => {
                let idx = self.batch_success + self.batch_errors.len() as u32;
                self.batch_errors.push((idx, e.to_string()));
            }
        }
        Ok(())
    }

    async fn queue_write_manifest(
        &mut self,
        path: &Path,
        manifest: &FileManifest,
        mode: u32,
    ) -> Result<()> {
        if !self.batch_mode {
            color_eyre::eyre::bail!("Not in batch mode");
        }

        match self.write_manifest_internal(path, manifest, mode) {
            Ok(()) => self.batch_success += 1,
            Err(e) => {
                let idx = self.batch_success + self.batch_errors.len() as u32;
                self.batch_errors.push((idx, e.to_string()));
            }
        }
        Ok(())
    }

    async fn end_batch(&mut self) -> Result<BatchOperationResult> {
        self.batch_mode = false;
        Ok(BatchOperationResult {
            success_count: self.batch_success,
            errors: std::mem::take(&mut self.batch_errors),
        })
    }

    async fn check_chunks(&mut self, hashes: &[ContentHash]) -> Result<Vec<ContentHash>> {
        Ok(self.cas.find_missing(hashes))
    }

    async fn store_chunks(&mut self, chunks: &[(ContentHash, Bytes)]) -> Result<()> {
        for (hash, data) in chunks {
            self.cas.put(hash, data)?;
        }
        Ok(())
    }
}

impl LocalAgentSession {
    /// Write a file from manifest (assemble from chunks)
    fn write_manifest_internal(
        &self,
        path: &Path,
        manifest: &FileManifest,
        mode: u32,
    ) -> Result<()> {
        let full_path = self.root.join(path);

        // Create parent directories
        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Assemble file from chunks using CAS
        let data = self.cas.assemble(&manifest.chunks)?;

        // Verify hash
        let actual_hash = ContentHash::from_bytes(&data);
        if actual_hash != manifest.file_hash {
            color_eyre::eyre::bail!(
                "Hash mismatch: expected {}, got {actual_hash}",
                manifest.file_hash
            );
        }

        std::fs::write(&full_path, &data)?;

        // Set mode on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let perms = std::fs::Permissions::from_mode(mode);
            std::fs::set_permissions(&full_path, perms)?;
        }
        let _ = mode;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use zsync_core::{ChunkConfig, FileManifest, chunk_data};

    #[tokio::test]
    async fn test_local_transport_snapshot() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("test.txt"), "hello").unwrap();

        let transport = LocalTransport::new(dir.path()).unwrap();
        let mut session = transport.start_session().unwrap();

        let snapshot = session.snapshot().await.unwrap();
        assert!(snapshot.files.contains_key(&PathBuf::from("test.txt")));
    }

    #[tokio::test]
    async fn test_local_transport_write_delete() {
        let dir = TempDir::new().unwrap();

        let transport = LocalTransport::new(dir.path()).unwrap();
        let mut session = transport.start_session().unwrap();

        // Write a file
        session
            .write_file(Path::new("new.txt"), b"content", 0o644)
            .await
            .unwrap();
        assert!(dir.path().join("new.txt").exists());
        assert_eq!(
            std::fs::read_to_string(dir.path().join("new.txt")).unwrap(),
            "content"
        );

        // Delete the file
        session.delete_file(Path::new("new.txt")).await.unwrap();
        assert!(!dir.path().join("new.txt").exists());
    }

    #[tokio::test]
    async fn test_local_transport_chunks() {
        let dir = TempDir::new().unwrap();

        let transport = LocalTransport::new(dir.path()).unwrap();
        let mut session = transport.start_session().unwrap();

        let hash1 = ContentHash::from_bytes(b"chunk1");
        let hash2 = ContentHash::from_bytes(b"chunk2");

        // Initially all chunks are missing
        let missing = session.check_chunks(&[hash1, hash2]).await.unwrap();
        assert_eq!(missing.len(), 2);

        // Store one chunk
        session
            .store_chunks(&[(hash1, Bytes::from_static(b"chunk1"))])
            .await
            .unwrap();

        // Now only hash2 is missing
        let missing = session.check_chunks(&[hash1, hash2]).await.unwrap();
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0], hash2);
    }

    // ========== Integration Tests for Two-Way Sync ==========

    #[tokio::test]
    async fn test_batch_operations() {
        let dir = TempDir::new().unwrap();

        let transport = LocalTransport::new(dir.path()).unwrap();
        let mut session = transport.start_session().unwrap();

        // Start batch
        session.start_batch(3).await.unwrap();

        // Queue multiple writes
        session
            .queue_write_file(Path::new("file1.txt"), b"content1", 0o644)
            .await
            .unwrap();
        session
            .queue_write_file(Path::new("file2.txt"), b"content2", 0o644)
            .await
            .unwrap();
        session
            .queue_write_file(Path::new("subdir/file3.txt"), b"content3", 0o644)
            .await
            .unwrap();

        // End batch
        let result = session.end_batch().await.unwrap();
        assert_eq!(result.success_count, 3);
        assert!(result.errors.is_empty());

        // Verify files exist
        assert_eq!(
            std::fs::read_to_string(dir.path().join("file1.txt")).unwrap(),
            "content1"
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("file2.txt")).unwrap(),
            "content2"
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("subdir/file3.txt")).unwrap(),
            "content3"
        );
    }

    #[tokio::test]
    async fn test_batch_with_deletes() {
        let dir = TempDir::new().unwrap();

        // Create initial files
        std::fs::write(dir.path().join("delete_me.txt"), "will be deleted").unwrap();
        std::fs::write(dir.path().join("keep.txt"), "keep this").unwrap();

        let transport = LocalTransport::new(dir.path()).unwrap();
        let mut session = transport.start_session().unwrap();

        // Start batch with mixed operations
        session.start_batch(2).await.unwrap();
        session
            .queue_delete_file(Path::new("delete_me.txt"))
            .await
            .unwrap();
        session
            .queue_write_file(Path::new("new.txt"), b"new content", 0o644)
            .await
            .unwrap();

        let result = session.end_batch().await.unwrap();
        assert_eq!(result.success_count, 2);

        // Verify state
        assert!(!dir.path().join("delete_me.txt").exists());
        assert!(dir.path().join("keep.txt").exists());
        assert!(dir.path().join("new.txt").exists());
    }

    #[tokio::test]
    async fn test_manifest_write_with_chunks() {
        let dir = TempDir::new().unwrap();

        let transport = LocalTransport::new(dir.path()).unwrap();
        let mut session = transport.start_session().unwrap();

        // Create file content and chunk it
        let content = b"This is test content for chunking";
        let file_hash = ContentHash::from_bytes(content);
        let config = ChunkConfig::default();
        let chunks: Vec<_> = chunk_data(content, &config).collect();

        // Store chunks in CAS - extract actual bytes using offset and length
        let chunk_pairs: Vec<_> = chunks
            .iter()
            .map(|chunk| {
                let start = chunk.offset as usize;
                let end = start + chunk.length as usize;
                let chunk_bytes = &content[start..end];
                (chunk.hash, Bytes::copy_from_slice(chunk_bytes))
            })
            .collect();
        session.store_chunks(&chunk_pairs).await.unwrap();

        // Create manifest
        let manifest = FileManifest {
            file_hash,
            size: content.len() as u64,
            chunks: chunks.iter().map(|c| c.hash).collect(),
        };

        // Start batch and queue manifest write
        session.start_batch(1).await.unwrap();
        session
            .queue_write_manifest(Path::new("assembled.txt"), &manifest, 0o644)
            .await
            .unwrap();
        let result = session.end_batch().await.unwrap();
        assert_eq!(result.success_count, 1);

        // Verify file was assembled correctly
        let written = std::fs::read(dir.path().join("assembled.txt")).unwrap();
        assert_eq!(written, content);
    }

    #[tokio::test]
    async fn test_snapshot_mtime_preserved() {
        use std::time::{Duration, UNIX_EPOCH};

        let dir = TempDir::new().unwrap();

        // Create a file with a specific mtime
        let file_path = dir.path().join("test.txt");
        std::fs::write(&file_path, "hello").unwrap();

        // Set a specific mtime (Jan 1, 2024)
        let expected_mtime = UNIX_EPOCH + Duration::from_secs(1_704_067_200);
        filetime::set_file_mtime(
            &file_path,
            filetime::FileTime::from_system_time(expected_mtime),
        )
        .unwrap();

        let transport = LocalTransport::new(dir.path()).unwrap();
        let mut session = transport.start_session().unwrap();

        let snapshot = session.snapshot().await.unwrap();
        let entry = snapshot.files.get(&PathBuf::from("test.txt")).unwrap();

        // Verify mtime is preserved (within 1 second tolerance)
        let diff = if entry.modified > expected_mtime {
            entry.modified.duration_since(expected_mtime).unwrap()
        } else {
            expected_mtime.duration_since(entry.modified).unwrap()
        };
        assert!(
            diff < Duration::from_secs(1),
            "mtime not preserved: expected {:?}, got {:?}",
            expected_mtime,
            entry.modified
        );
    }

    #[tokio::test]
    async fn test_bidirectional_sync_scenario() {
        // Simulate two-way sync: local and remote directories
        let local_dir = TempDir::new().unwrap();
        let remote_dir = TempDir::new().unwrap();

        // Setup initial state: same file on both sides
        std::fs::write(local_dir.path().join("shared.txt"), "initial").unwrap();
        std::fs::write(remote_dir.path().join("shared.txt"), "initial").unwrap();

        // Local adds a new file
        std::fs::write(local_dir.path().join("local_new.txt"), "from local").unwrap();

        // Remote adds a different file
        std::fs::write(remote_dir.path().join("remote_new.txt"), "from remote").unwrap();

        // Create transports
        let local_transport = LocalTransport::new(local_dir.path()).unwrap();
        let remote_transport = LocalTransport::new(remote_dir.path()).unwrap();

        let mut local_session = local_transport.start_session().unwrap();
        let mut remote_session = remote_transport.start_session().unwrap();

        // Get snapshots from both sides
        let local_snapshot = local_session.snapshot().await.unwrap();
        let remote_snapshot = remote_session.snapshot().await.unwrap();

        // Verify initial snapshots
        assert!(
            local_snapshot
                .files
                .contains_key(&PathBuf::from("shared.txt"))
        );
        assert!(
            local_snapshot
                .files
                .contains_key(&PathBuf::from("local_new.txt"))
        );
        assert!(
            !local_snapshot
                .files
                .contains_key(&PathBuf::from("remote_new.txt"))
        );

        assert!(
            remote_snapshot
                .files
                .contains_key(&PathBuf::from("shared.txt"))
        );
        assert!(
            !remote_snapshot
                .files
                .contains_key(&PathBuf::from("local_new.txt"))
        );
        assert!(
            remote_snapshot
                .files
                .contains_key(&PathBuf::from("remote_new.txt"))
        );

        // Sync: push local_new.txt to remote
        let local_new_content = std::fs::read(local_dir.path().join("local_new.txt")).unwrap();
        remote_session
            .write_file(Path::new("local_new.txt"), &local_new_content, 0o644)
            .await
            .unwrap();

        // Sync: pull remote_new.txt to local
        let remote_new_content = std::fs::read(remote_dir.path().join("remote_new.txt")).unwrap();
        local_session
            .write_file(Path::new("remote_new.txt"), &remote_new_content, 0o644)
            .await
            .unwrap();

        // Verify both sides now have all files
        assert!(local_dir.path().join("local_new.txt").exists());
        assert!(local_dir.path().join("remote_new.txt").exists());
        assert!(remote_dir.path().join("local_new.txt").exists());
        assert!(remote_dir.path().join("remote_new.txt").exists());

        // Verify content
        assert_eq!(
            std::fs::read_to_string(local_dir.path().join("remote_new.txt")).unwrap(),
            "from remote"
        );
        assert_eq!(
            std::fs::read_to_string(remote_dir.path().join("local_new.txt")).unwrap(),
            "from local"
        );
    }

    #[tokio::test]
    async fn test_deletion_sync() {
        let local_dir = TempDir::new().unwrap();
        let remote_dir = TempDir::new().unwrap();

        // Create same files on both sides
        std::fs::write(
            local_dir.path().join("delete_local.txt"),
            "will delete locally",
        )
        .unwrap();
        std::fs::write(
            remote_dir.path().join("delete_local.txt"),
            "will delete locally",
        )
        .unwrap();
        std::fs::write(
            local_dir.path().join("delete_remote.txt"),
            "will delete remotely",
        )
        .unwrap();
        std::fs::write(
            remote_dir.path().join("delete_remote.txt"),
            "will delete remotely",
        )
        .unwrap();

        let local_transport = LocalTransport::new(local_dir.path()).unwrap();
        let remote_transport = LocalTransport::new(remote_dir.path()).unwrap();

        let mut local_session = local_transport.start_session().unwrap();
        let mut remote_session = remote_transport.start_session().unwrap();

        // Delete locally
        std::fs::remove_file(local_dir.path().join("delete_local.txt")).unwrap();

        // Delete remotely
        std::fs::remove_file(remote_dir.path().join("delete_remote.txt")).unwrap();

        // Sync deletions: propagate local deletion to remote
        remote_session
            .delete_file(Path::new("delete_local.txt"))
            .await
            .unwrap();

        // Sync deletions: propagate remote deletion to local
        local_session
            .delete_file(Path::new("delete_remote.txt"))
            .await
            .unwrap();

        // Verify deletions propagated
        assert!(!local_dir.path().join("delete_local.txt").exists());
        assert!(!local_dir.path().join("delete_remote.txt").exists());
        assert!(!remote_dir.path().join("delete_local.txt").exists());
        assert!(!remote_dir.path().join("delete_remote.txt").exists());
    }

    #[tokio::test]
    async fn test_nested_directory_sync() {
        let dir = TempDir::new().unwrap();

        let transport = LocalTransport::new(dir.path()).unwrap();
        let mut session = transport.start_session().unwrap();

        // Write files in nested directories
        session
            .write_file(Path::new("a/b/c/deep.txt"), b"deep content", 0o644)
            .await
            .unwrap();

        session
            .write_file(Path::new("x/y/z/another.txt"), b"another deep", 0o644)
            .await
            .unwrap();

        // Verify nested structure created
        assert!(dir.path().join("a/b/c/deep.txt").exists());
        assert!(dir.path().join("x/y/z/another.txt").exists());

        // Get snapshot and verify nested files included
        let snapshot = session.snapshot().await.unwrap();
        assert!(
            snapshot
                .files
                .contains_key(&PathBuf::from("a/b/c/deep.txt"))
        );
        assert!(
            snapshot
                .files
                .contains_key(&PathBuf::from("x/y/z/another.txt"))
        );
    }
}
