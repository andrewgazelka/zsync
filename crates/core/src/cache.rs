//! Chunk signature cache using heed (LMDB) + rkyv (zero-copy serialization)

use std::path::Path;

use heed::types::Bytes;
use heed::{Database, Env, EnvOpenOptions};
use rkyv::rancor::Error as RkyvError;
use rkyv::{Archive, Deserialize, Serialize};

use crate::chunker::Chunk;
use crate::hash::ContentHash;

/// Archived chunk for zero-copy deserialization
#[derive(Archive, Serialize, Deserialize, Debug)]
#[rkyv(compare(PartialEq), derive(Debug))]
struct CachedChunks {
    chunks: Vec<CachedChunk>,
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone)]
#[rkyv(compare(PartialEq), derive(Debug))]
struct CachedChunk {
    offset: u64,
    length: u32,
    hash: [u8; 32],
}

impl From<&Chunk> for CachedChunk {
    fn from(chunk: &Chunk) -> Self {
        Self {
            offset: chunk.offset,
            length: chunk.length,
            hash: *chunk.hash.as_bytes(),
        }
    }
}

impl From<&CachedChunk> for Chunk {
    fn from(cached: &CachedChunk) -> Self {
        Self {
            offset: cached.offset,
            length: cached.length,
            hash: ContentHash::from_raw(cached.hash),
        }
    }
}

impl From<&ArchivedCachedChunk> for Chunk {
    fn from(archived: &ArchivedCachedChunk) -> Self {
        Self {
            offset: archived.offset.into(),
            length: archived.length.into(),
            hash: ContentHash::from_raw(archived.hash),
        }
    }
}

/// Cache for chunk signatures and file hashes.
///
/// Uses LMDB (via heed) for fast, memory-mapped lookups and
/// rkyv for zero-copy deserialization.
pub struct ChunkCache {
    env: Env,
    /// Maps file content hash -> chunk signatures (rkyv serialized)
    signatures: Database<Bytes, Bytes>,
    /// Maps (path_hash, size, mtime) -> file content hash
    file_hashes: Database<Bytes, Bytes>,
}

impl ChunkCache {
    /// Open or create a cache at the given path.
    ///
    /// # Errors
    /// Returns an error if the database cannot be opened or created.
    #[allow(unsafe_code)]
    pub fn open(path: &Path) -> color_eyre::Result<Self> {
        std::fs::create_dir_all(path)?;

        // SAFETY: We're opening the database with standard settings.
        // The unsafe is required by heed for memory-mapped I/O.
        // The only requirement is that the database file is not modified
        // externally while the Env is open.
        let env = unsafe {
            EnvOpenOptions::new()
                .map_size(256 * 1024 * 1024) // 256MB max
                .max_dbs(2)
                .open(path)?
        };

        let mut wtxn = env.write_txn()?;
        let signatures: Database<Bytes, Bytes> = env
            .database_options()
            .types::<Bytes, Bytes>()
            .name("signatures")
            .create(&mut wtxn)?;
        let file_hashes: Database<Bytes, Bytes> = env
            .database_options()
            .types::<Bytes, Bytes>()
            .name("file_hashes")
            .create(&mut wtxn)?;
        wtxn.commit()?;

        Ok(Self {
            env,
            signatures,
            file_hashes,
        })
    }

    /// Get cached chunk signatures for a file by its content hash.
    ///
    /// Uses zero-copy deserialization where possible.
    #[must_use]
    pub fn get_signature(&self, file_hash: &ContentHash) -> Option<Vec<Chunk>> {
        let rtxn = self.env.read_txn().ok()?;
        let data = self.signatures.get(&rtxn, file_hash.as_bytes()).ok()??;

        // Zero-copy access to archived data
        let archived = rkyv::access::<ArchivedCachedChunks, RkyvError>(data).ok()?;
        Some(archived.chunks.iter().map(Chunk::from).collect())
    }

    /// Store chunk signatures for a file.
    ///
    /// # Errors
    /// Returns an error if the write transaction fails.
    pub fn put_signature(
        &self,
        file_hash: &ContentHash,
        chunks: &[Chunk],
    ) -> color_eyre::Result<()> {
        let cached = CachedChunks {
            chunks: chunks.iter().map(CachedChunk::from).collect(),
        };

        let bytes = rkyv::to_bytes::<RkyvError>(&cached)
            .map_err(|e| color_eyre::eyre::eyre!("rkyv serialization failed: {e}"))?;

        let mut wtxn = self.env.write_txn()?;
        self.signatures
            .put(&mut wtxn, file_hash.as_bytes(), &bytes)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Get cached file hash by path metadata.
    ///
    /// Uses a hash of (path, size, mtime) as the key to detect changes.
    #[must_use]
    pub fn get_file_hash(&self, path: &str, size: u64, mtime_secs: u64) -> Option<ContentHash> {
        let key = Self::make_file_key(path, size, mtime_secs);
        let rtxn = self.env.read_txn().ok()?;
        let data = self.file_hashes.get(&rtxn, &key).ok()??;

        if data.len() == 32 {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(data);
            Some(ContentHash::from_raw(bytes))
        } else {
            None
        }
    }

    /// Store file hash by path metadata.
    ///
    /// # Errors
    /// Returns an error if the write transaction fails.
    pub fn put_file_hash(
        &self,
        path: &str,
        size: u64,
        mtime_secs: u64,
        hash: &ContentHash,
    ) -> color_eyre::Result<()> {
        let key = Self::make_file_key(path, size, mtime_secs);
        let mut wtxn = self.env.write_txn()?;
        self.file_hashes.put(&mut wtxn, &key, hash.as_bytes())?;
        wtxn.commit()?;
        Ok(())
    }

    /// Clear all cached data.
    ///
    /// # Errors
    /// Returns an error if the clear operation fails.
    pub fn clear(&self) -> color_eyre::Result<()> {
        let mut wtxn = self.env.write_txn()?;
        self.signatures.clear(&mut wtxn)?;
        self.file_hashes.clear(&mut wtxn)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Create a key for the file_hashes database from path metadata.
    fn make_file_key(path: &str, size: u64, mtime_secs: u64) -> Vec<u8> {
        // Hash the path to get a fixed-size key component
        let path_hash = ContentHash::from_bytes(path.as_bytes());
        let mut key = Vec::with_capacity(32 + 8 + 8);
        key.extend_from_slice(path_hash.as_bytes());
        key.extend_from_slice(&size.to_be_bytes());
        key.extend_from_slice(&mtime_secs.to_be_bytes());
        key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let cache = ChunkCache::open(dir.path()).unwrap();

        let file_hash = ContentHash::from_bytes(b"test file content");
        let chunks = vec![
            Chunk {
                offset: 0,
                length: 100,
                hash: ContentHash::from_bytes(b"chunk1"),
            },
            Chunk {
                offset: 100,
                length: 200,
                hash: ContentHash::from_bytes(b"chunk2"),
            },
        ];

        // Initially empty
        assert!(cache.get_signature(&file_hash).is_none());

        // Store and retrieve
        cache.put_signature(&file_hash, &chunks).unwrap();
        let retrieved = cache.get_signature(&file_hash).unwrap();

        assert_eq!(retrieved.len(), chunks.len());
        assert_eq!(retrieved[0].offset, chunks[0].offset);
        assert_eq!(retrieved[0].length, chunks[0].length);
        assert_eq!(retrieved[0].hash, chunks[0].hash);
    }

    #[test]
    fn test_file_hash_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let cache = ChunkCache::open(dir.path()).unwrap();

        let path = "/some/file/path.rs";
        let size = 12345u64;
        let mtime = 1_700_000_000_u64;
        let hash = ContentHash::from_bytes(b"file content hash");

        // Initially empty
        assert!(cache.get_file_hash(path, size, mtime).is_none());

        // Store and retrieve
        cache.put_file_hash(path, size, mtime, &hash).unwrap();
        let retrieved = cache.get_file_hash(path, size, mtime).unwrap();

        assert_eq!(retrieved, hash);

        // Different mtime should miss
        assert!(cache.get_file_hash(path, size, mtime + 1).is_none());

        // Different size should miss
        assert!(cache.get_file_hash(path, size + 1, mtime).is_none());
    }

    #[test]
    fn test_clear() {
        let dir = tempfile::tempdir().unwrap();
        let cache = ChunkCache::open(dir.path()).unwrap();

        let file_hash = ContentHash::from_bytes(b"test");
        let chunks = vec![Chunk {
            offset: 0,
            length: 10,
            hash: ContentHash::from_bytes(b"chunk"),
        }];

        cache.put_signature(&file_hash, &chunks).unwrap();
        assert!(cache.get_signature(&file_hash).is_some());

        cache.clear().unwrap();
        assert!(cache.get_signature(&file_hash).is_none());
    }
}
