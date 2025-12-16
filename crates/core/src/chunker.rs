//! Content-defined chunking using FastCDC

use crate::hash::ContentHash;

/// Configuration for content-defined chunking
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct ChunkConfig {
    /// Minimum chunk size in bytes
    pub min_size: u32,
    /// Average (expected) chunk size in bytes
    pub avg_size: u32,
    /// Maximum chunk size in bytes
    pub max_size: u32,
}

impl Default for ChunkConfig {
    fn default() -> Self {
        Self {
            min_size: 512,
            avg_size: 4096,
            max_size: 32768,
        }
    }
}

impl ChunkConfig {
    /// Create config optimized for source code files
    #[must_use]
    pub fn for_source_code() -> Self {
        Self::default()
    }

    /// Create config optimized for large binary files
    #[must_use]
    pub fn for_large_files() -> Self {
        Self {
            min_size: 4096,
            avg_size: 16384,
            max_size: 65536,
        }
    }
}

/// A content-defined chunk with its location and hash
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Chunk {
    /// Byte offset in the source data
    pub offset: u64,
    /// Length of this chunk in bytes
    pub length: u32,
    /// BLAKE3 hash of the chunk content
    pub hash: ContentHash,
}

/// Chunk data into content-defined pieces using FastCDC.
///
/// Returns an iterator over chunks, allowing lazy evaluation and chaining.
pub fn chunk_data<'a>(data: &'a [u8], config: &ChunkConfig) -> impl Iterator<Item = Chunk> + 'a {
    use fastcdc::v2020::{FastCDC, Normalization};

    FastCDC::with_level(
        data,
        config.min_size,
        config.avg_size,
        config.max_size,
        Normalization::Level1, // Good balance of speed and chunk distribution
    )
    .map(|entry| {
        let chunk_data = &data[entry.offset..entry.offset + entry.length];
        Chunk {
            offset: entry.offset as u64,
            length: entry.length as u32,
            hash: ContentHash::from_bytes(chunk_data),
        }
    })
}

/// Chunk data and collect into a Vec (convenience function)
#[must_use]
pub fn chunk_data_vec(data: &[u8], config: &ChunkConfig) -> Vec<Chunk> {
    chunk_data(data, config).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_deterministic() {
        let data = b"hello world this is some test data that should be chunked".repeat(100);
        let config = ChunkConfig::default();

        let chunks1: Vec<_> = chunk_data(&data, &config).collect();
        let chunks2: Vec<_> = chunk_data(&data, &config).collect();

        assert_eq!(chunks1.len(), chunks2.len());
        for (c1, c2) in chunks1.iter().zip(chunks2.iter()) {
            assert_eq!(c1.offset, c2.offset);
            assert_eq!(c1.length, c2.length);
            assert_eq!(c1.hash, c2.hash);
        }
    }

    #[test]
    fn test_chunk_covers_entire_file() {
        let data = b"some test data for chunking".repeat(50);
        let config = ChunkConfig::default();

        let chunks: Vec<_> = chunk_data(&data, &config).collect();

        // Verify chunks cover entire file without gaps
        let mut expected_offset = 0u64;
        for chunk in &chunks {
            assert_eq!(chunk.offset, expected_offset);
            expected_offset += u64::from(chunk.length);
        }
        assert_eq!(expected_offset, data.len() as u64);
    }

    #[test]
    fn test_insertion_preserves_chunks() {
        // FastCDC should preserve chunk boundaries after insertion
        // Use varied data (simulating source code) rather than repetitive data
        // Repetitive data like "AAAA" doesn't provide natural CDC boundaries
        let mut original = Vec::with_capacity(50_000);
        for i in 0..5000 {
            // Create varied content with natural boundaries
            original.extend_from_slice(format!("fn func_{i}() {{ let x = {i}; }}\n").as_bytes());
        }

        let mut modified = b"// New header comment\n".to_vec();
        modified.extend_from_slice(&original);

        let config = ChunkConfig::default();
        let original_chunks: Vec<_> = chunk_data(&original, &config).collect();
        let modified_chunks: Vec<_> = chunk_data(&modified, &config).collect();

        // After the insertion, some chunks should match (by hash)
        let original_hashes: std::collections::HashSet<_> =
            original_chunks.iter().map(|c| c.hash).collect();
        let modified_hashes: std::collections::HashSet<_> =
            modified_chunks.iter().map(|c| c.hash).collect();

        let common = original_hashes.intersection(&modified_hashes).count();
        // With CDC, we expect significant chunk reuse even after insertion
        // Note: CDC doesn't guarantee reuse but it should help for varied content
        assert!(
            common > 0 || original_chunks.len() <= 1,
            "Expected some common chunks after insertion (orig={}, mod={}, common={})",
            original_chunks.len(),
            modified_chunks.len(),
            common
        );
    }

    #[test]
    fn test_empty_data() {
        let data = b"";
        let config = ChunkConfig::default();
        assert!(chunk_data(data, &config).next().is_none());
    }

    #[test]
    fn test_small_data() {
        let data = b"small";
        let config = ChunkConfig::default();
        let chunks: Vec<_> = chunk_data(data, &config).collect();
        // Small data should produce exactly one chunk
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].offset, 0);
        assert_eq!(chunks[0].length, 5);
    }
}
