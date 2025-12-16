//! Content-Addressable Storage (CAS) for chunk deduplication
//!
//! Stores chunks by their BLAKE3 hash. Never stores the same content twice.
//! Enables cross-file deduplication - if two files share chunks, only stored once.

use std::path::Path;

use bytes::Bytes;
use heed::types::Bytes as HeedBytes;
use heed::{Database, Env, EnvOpenOptions};

use crate::hash::ContentHash;

/// Content-addressable chunk store using LMDB.
///
/// Key: ContentHash (32 bytes)
/// Value: raw chunk bytes
pub struct ChunkStore {
    env: Env,
    /// chunks database: hash -> data
    chunks: Database<HeedBytes, HeedBytes>,
}

impl ChunkStore {
    /// Open or create a chunk store at the given path.
    ///
    /// # Errors
    /// Returns an error if the database cannot be opened or created.
    pub fn open(path: &Path) -> color_eyre::Result<Self> {
        std::fs::create_dir_all(path)?;

        // SAFETY: Standard LMDB memory-mapped I/O
        let env = unsafe {
            EnvOpenOptions::new()
                .map_size(4 * 1024 * 1024 * 1024) // 4GB max - chunks can be large
                .max_dbs(1)
                .open(path)?
        };

        let mut wtxn = env.write_txn()?;
        let chunks: Database<HeedBytes, HeedBytes> = env
            .database_options()
            .types::<HeedBytes, HeedBytes>()
            .name("chunks")
            .create(&mut wtxn)?;
        wtxn.commit()?;

        Ok(Self { env, chunks })
    }

    /// Check if a chunk exists in the store.
    #[must_use]
    pub fn contains(&self, hash: &ContentHash) -> bool {
        let Ok(rtxn) = self.env.read_txn() else {
            return false;
        };
        self.chunks
            .get(&rtxn, hash.as_bytes())
            .ok()
            .flatten()
            .is_some()
    }

    /// Get a chunk by its hash.
    #[must_use]
    pub fn get(&self, hash: &ContentHash) -> Option<Bytes> {
        let rtxn = self.env.read_txn().ok()?;
        let data = self.chunks.get(&rtxn, hash.as_bytes()).ok()??;
        Some(Bytes::copy_from_slice(data))
    }

    /// Store a chunk. Returns true if newly stored, false if already existed.
    ///
    /// # Errors
    /// Returns an error if the write transaction fails.
    pub fn put(&self, hash: &ContentHash, data: &[u8]) -> color_eyre::Result<bool> {
        // Verify hash matches data (defensive)
        let computed = ContentHash::from_bytes(data);
        color_eyre::eyre::ensure!(
            computed == *hash,
            "hash mismatch: expected {hash}, got {computed}"
        );

        let mut wtxn = self.env.write_txn()?;

        // Check if already exists
        if self.chunks.get(&wtxn, hash.as_bytes())?.is_some() {
            return Ok(false);
        }

        self.chunks.put(&mut wtxn, hash.as_bytes(), data)?;
        wtxn.commit()?;
        Ok(true)
    }

    /// Store multiple chunks atomically.
    ///
    /// # Errors
    /// Returns an error if the write transaction fails.
    pub fn put_many(&self, chunks: &[(ContentHash, Bytes)]) -> color_eyre::Result<usize> {
        let mut wtxn = self.env.write_txn()?;
        let mut new_count = 0;

        for (hash, data) in chunks {
            // Verify hash
            let computed = ContentHash::from_bytes(data);
            color_eyre::eyre::ensure!(
                computed == *hash,
                "hash mismatch: expected {hash}, got {computed}"
            );

            // Skip if exists
            if self.chunks.get(&wtxn, hash.as_bytes())?.is_some() {
                continue;
            }

            self.chunks.put(&mut wtxn, hash.as_bytes(), data)?;
            new_count += 1;
        }

        wtxn.commit()?;
        Ok(new_count)
    }

    /// Check which hashes are missing from the store.
    #[must_use]
    pub fn find_missing(&self, hashes: &[ContentHash]) -> Vec<ContentHash> {
        let Ok(rtxn) = self.env.read_txn() else {
            return hashes.to_vec();
        };

        hashes
            .iter()
            .filter(|h| {
                self.chunks
                    .get(&rtxn, h.as_bytes())
                    .ok()
                    .flatten()
                    .is_none()
            })
            .copied()
            .collect()
    }

    /// Assemble a file from a list of chunk hashes.
    ///
    /// # Errors
    /// Returns an error if any chunk is missing.
    pub fn assemble(&self, chunk_hashes: &[ContentHash]) -> color_eyre::Result<Vec<u8>> {
        let rtxn = self.env.read_txn()?;
        let mut result = Vec::new();

        for (i, hash) in chunk_hashes.iter().enumerate() {
            let data = self
                .chunks
                .get(&rtxn, hash.as_bytes())?
                .ok_or_else(|| color_eyre::eyre::eyre!("missing chunk {i}: {hash}"))?;
            result.extend_from_slice(data);
        }

        Ok(result)
    }

    /// Get statistics about the store.
    #[must_use]
    pub fn stats(&self) -> Option<StoreStats> {
        let rtxn = self.env.read_txn().ok()?;
        let mut count = 0u64;
        let mut total_bytes = 0u64;

        let iter = self.chunks.iter(&rtxn).ok()?;
        for entry in iter {
            let (_, data) = entry.ok()?;
            count += 1;
            total_bytes += data.len() as u64;
        }

        Some(StoreStats { count, total_bytes })
    }

    /// Clear all chunks from the store.
    ///
    /// # Errors
    /// Returns an error if the clear operation fails.
    pub fn clear(&self) -> color_eyre::Result<()> {
        let mut wtxn = self.env.write_txn()?;
        self.chunks.clear(&mut wtxn)?;
        wtxn.commit()?;
        Ok(())
    }
}

/// Statistics about the chunk store
#[derive(Debug, Clone, Copy)]
pub struct StoreStats {
    /// Number of unique chunks stored
    pub count: u64,
    /// Total bytes stored
    pub total_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store_and_retrieve() {
        let dir = tempfile::tempdir().unwrap();
        let store = ChunkStore::open(dir.path()).unwrap();

        let data = b"hello world chunk data";
        let hash = ContentHash::from_bytes(data);

        // Initially missing
        assert!(!store.contains(&hash));
        assert!(store.get(&hash).is_none());

        // Store
        let was_new = store.put(&hash, data).unwrap();
        assert!(was_new);

        // Now exists
        assert!(store.contains(&hash));
        let retrieved = store.get(&hash).unwrap();
        assert_eq!(&retrieved[..], data);

        // Store again - should return false (already exists)
        let was_new = store.put(&hash, data).unwrap();
        assert!(!was_new);
    }

    #[test]
    fn test_find_missing() {
        let dir = tempfile::tempdir().unwrap();
        let store = ChunkStore::open(dir.path()).unwrap();

        let data1 = b"chunk one";
        let data2 = b"chunk two";
        let data3 = b"chunk three";

        let h1 = ContentHash::from_bytes(data1);
        let h2 = ContentHash::from_bytes(data2);
        let h3 = ContentHash::from_bytes(data3);

        // Store only h1
        store.put(&h1, data1).unwrap();

        // Check missing
        let missing = store.find_missing(&[h1, h2, h3]);
        assert_eq!(missing.len(), 2);
        assert!(missing.contains(&h2));
        assert!(missing.contains(&h3));
    }

    #[test]
    fn test_assemble() {
        let dir = tempfile::tempdir().unwrap();
        let store = ChunkStore::open(dir.path()).unwrap();

        let data1 = b"hello ";
        let data2 = b"world";
        let h1 = ContentHash::from_bytes(data1);
        let h2 = ContentHash::from_bytes(data2);

        store.put(&h1, data1).unwrap();
        store.put(&h2, data2).unwrap();

        let assembled = store.assemble(&[h1, h2]).unwrap();
        assert_eq!(&assembled[..], b"hello world");
    }

    #[test]
    fn test_assemble_missing_chunk() {
        let dir = tempfile::tempdir().unwrap();
        let store = ChunkStore::open(dir.path()).unwrap();

        let h1 = ContentHash::from_bytes(b"chunk");
        let result = store.assemble(&[h1]);
        assert!(result.is_err());
    }

    #[test]
    fn test_put_many() {
        let dir = tempfile::tempdir().unwrap();
        let store = ChunkStore::open(dir.path()).unwrap();

        let data1 = b"chunk one";
        let data2 = b"chunk two";
        let h1 = ContentHash::from_bytes(data1);
        let h2 = ContentHash::from_bytes(data2);

        // Store h1 first
        store.put(&h1, data1).unwrap();

        // put_many should only store h2
        let chunks = vec![
            (h1, Bytes::from_static(data1)),
            (h2, Bytes::from_static(data2)),
        ];
        let new_count = store.put_many(&chunks).unwrap();
        assert_eq!(new_count, 1); // Only h2 was new

        // Both should exist
        assert!(store.contains(&h1));
        assert!(store.contains(&h2));
    }

    #[test]
    fn test_hash_verification() {
        let dir = tempfile::tempdir().unwrap();
        let store = ChunkStore::open(dir.path()).unwrap();

        let data = b"real data";
        let wrong_hash = ContentHash::from_bytes(b"different data");

        // Should fail - hash doesn't match data
        let result = store.put(&wrong_hash, data);
        assert!(result.is_err());
    }
}
