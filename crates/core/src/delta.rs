//! Delta computation using FastCDC content-defined chunking

use std::collections::HashMap;

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::chunker::{ChunkConfig, chunk_data};
use crate::hash::ContentHash;

/// Protocol version for signature/delta format
const PROTOCOL_VERSION: u8 = 2;

/// A signature for a file, used to compute deltas.
///
/// Uses content-defined chunks (FastCDC) for better deduplication
/// when content is inserted or deleted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    /// Chunk signatures
    pub chunks: Vec<ChunkSignature>,
    /// Original file size
    pub file_size: u64,
}

/// Signature for a single content-defined chunk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkSignature {
    /// Byte offset in original file
    pub offset: u64,
    /// Length of this chunk
    pub length: u32,
    /// BLAKE3 hash of chunk content
    pub hash: ContentHash,
}

/// An operation in a delta
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeltaOp {
    /// Copy a chunk from the original file at given offset/length
    CopyChunk {
        /// Byte offset in old file
        offset: u64,
        /// Number of bytes to copy
        length: u32,
    },
    /// Insert literal data
    Literal {
        /// Raw bytes to insert
        data: Bytes,
    },
}

/// A delta between two versions of a file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delta {
    /// Operations to reconstruct the new file from the old
    pub ops: Vec<DeltaOp>,
    /// Hash of the new file for verification
    pub new_hash: ContentHash,
    /// Size of the new file
    pub new_size: u64,
}

/// Computes deltas between files using FastCDC content-defined chunking
pub struct DeltaComputer {
    config: ChunkConfig,
}

impl Default for DeltaComputer {
    fn default() -> Self {
        Self::new()
    }
}

impl DeltaComputer {
    /// Create a new delta computer with default chunk config (optimized for source code)
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: ChunkConfig::default(),
        }
    }

    /// Create with custom chunk configuration
    #[must_use]
    pub fn with_config(config: ChunkConfig) -> Self {
        Self { config }
    }

    /// Compute signature for a file (run on the destination side).
    ///
    /// Uses FastCDC to split the file into content-defined chunks,
    /// which provides better deduplication than fixed-size blocks.
    #[must_use]
    pub fn signature(&self, data: &[u8]) -> Signature {
        let chunks = chunk_data(data, &self.config)
            .map(|chunk| ChunkSignature {
                offset: chunk.offset,
                length: chunk.length,
                hash: chunk.hash,
            })
            .collect();

        Signature {
            chunks,
            file_size: data.len() as u64,
        }
    }

    /// Compute delta from new data against old signature.
    ///
    /// Chunks the new file and matches against the old file's chunk hashes.
    /// Matching chunks emit `CopyChunk`, non-matching regions emit `Literal`.
    #[must_use]
    pub fn delta(&self, new_data: &[u8], old_sig: &Signature) -> Delta {
        // Build hash lookup: hash -> (offset, length) from old signature
        // First occurrence wins for duplicate hashes
        let mut hash_map: HashMap<ContentHash, (u64, u32)> = HashMap::new();
        for chunk in &old_sig.chunks {
            hash_map
                .entry(chunk.hash)
                .or_insert((chunk.offset, chunk.length));
        }

        // Chunk the new data
        let new_chunks: Vec<_> = chunk_data(new_data, &self.config).collect();

        let mut ops = Vec::new();
        let mut literal_start: Option<usize> = None;

        for chunk in &new_chunks {
            if let Some(&(old_offset, old_length)) = hash_map.get(&chunk.hash) {
                // Found a match! Flush any pending literal data first
                if let Some(start) = literal_start.take() {
                    let end = chunk.offset as usize;
                    if start < end {
                        ops.push(DeltaOp::Literal {
                            data: Bytes::copy_from_slice(&new_data[start..end]),
                        });
                    }
                }

                ops.push(DeltaOp::CopyChunk {
                    offset: old_offset,
                    length: old_length,
                });
            } else {
                // No match - start or continue literal section
                if literal_start.is_none() {
                    literal_start = Some(chunk.offset as usize);
                }
            }
        }

        // Flush final literal section
        if let Some(start) = literal_start {
            if start < new_data.len() {
                ops.push(DeltaOp::Literal {
                    data: Bytes::copy_from_slice(&new_data[start..]),
                });
            }
        }

        // Handle empty file case
        if new_chunks.is_empty() && !new_data.is_empty() {
            ops.push(DeltaOp::Literal {
                data: Bytes::copy_from_slice(new_data),
            });
        }

        // Merge adjacent literals for efficiency
        let ops = merge_literals(ops);

        Delta {
            ops,
            new_hash: ContentHash::from_bytes(new_data),
            new_size: new_data.len() as u64,
        }
    }

    /// Apply a delta to reconstruct the new file.
    ///
    /// # Errors
    /// Returns an error if:
    /// - A `CopyChunk` references data outside the old file bounds
    /// - The reconstructed file's hash doesn't match the expected hash
    pub fn apply(&self, old_data: &[u8], delta: &Delta) -> color_eyre::Result<Vec<u8>> {
        let mut result = Vec::with_capacity(delta.new_size as usize);

        for op in &delta.ops {
            match op {
                DeltaOp::CopyChunk { offset, length } => {
                    let start = *offset as usize;
                    let end = start + *length as usize;

                    color_eyre::eyre::ensure!(
                        end <= old_data.len(),
                        "CopyChunk out of bounds: offset={offset}, length={length}, old_len={}",
                        old_data.len()
                    );

                    result.extend_from_slice(&old_data[start..end]);
                }
                DeltaOp::Literal { data } => {
                    result.extend_from_slice(data);
                }
            }
        }

        // Verify hash
        let actual_hash = ContentHash::from_bytes(&result);
        color_eyre::eyre::ensure!(
            actual_hash == delta.new_hash,
            "Hash mismatch after applying delta: expected {}, got {}",
            delta.new_hash,
            actual_hash
        );

        Ok(result)
    }

    /// Compress delta data using zstd.
    ///
    /// Prepends a version byte for forward compatibility.
    ///
    /// # Errors
    /// Returns an error if compression fails.
    pub fn compress_delta(delta: &Delta) -> color_eyre::Result<Vec<u8>> {
        let json = serde_json::to_vec(delta)?;
        let compressed = zstd::encode_all(json.as_slice(), 3)?;

        // Prepend version byte
        let mut result = Vec::with_capacity(1 + compressed.len());
        result.push(PROTOCOL_VERSION);
        result.extend_from_slice(&compressed);
        Ok(result)
    }

    /// Decompress delta data.
    ///
    /// # Errors
    /// Returns an error if:
    /// - Data is empty
    /// - Protocol version is unsupported
    /// - Decompression or deserialization fails
    pub fn decompress_delta(data: &[u8]) -> color_eyre::Result<Delta> {
        color_eyre::eyre::ensure!(!data.is_empty(), "empty delta data");

        let version = data[0];
        let payload = &data[1..];

        match version {
            2 => {
                let decompressed = zstd::decode_all(payload)?;
                let delta: Delta = serde_json::from_slice(&decompressed)?;
                Ok(delta)
            }
            v => color_eyre::eyre::bail!("unsupported delta protocol version: {v}"),
        }
    }

    /// Compress signature data using zstd.
    ///
    /// Prepends a version byte for forward compatibility.
    ///
    /// # Errors
    /// Returns an error if compression fails.
    pub fn compress_signature(sig: &Signature) -> color_eyre::Result<Vec<u8>> {
        let json = serde_json::to_vec(sig)?;
        let compressed = zstd::encode_all(json.as_slice(), 3)?;

        // Prepend version byte
        let mut result = Vec::with_capacity(1 + compressed.len());
        result.push(PROTOCOL_VERSION);
        result.extend_from_slice(&compressed);
        Ok(result)
    }

    /// Decompress signature data.
    ///
    /// # Errors
    /// Returns an error if:
    /// - Data is empty
    /// - Protocol version is unsupported
    /// - Decompression or deserialization fails
    pub fn decompress_signature(data: &[u8]) -> color_eyre::Result<Signature> {
        color_eyre::eyre::ensure!(!data.is_empty(), "empty signature data");

        let version = data[0];
        let payload = &data[1..];

        match version {
            2 => {
                let decompressed = zstd::decode_all(payload)?;
                let sig: Signature = serde_json::from_slice(&decompressed)?;
                Ok(sig)
            }
            v => color_eyre::eyre::bail!("unsupported signature protocol version: {v}"),
        }
    }
}

/// Merge adjacent Literal operations for smaller delta representation
fn merge_literals(ops: Vec<DeltaOp>) -> Vec<DeltaOp> {
    let mut result = Vec::with_capacity(ops.len());
    let mut pending_literal: Option<Vec<u8>> = None;

    for op in ops {
        match op {
            DeltaOp::Literal { data } => {
                pending_literal
                    .get_or_insert_with(Vec::new)
                    .extend_from_slice(&data);
            }
            DeltaOp::CopyChunk { .. } => {
                if let Some(data) = pending_literal.take() {
                    result.push(DeltaOp::Literal {
                        data: Bytes::from(data),
                    });
                }
                result.push(op);
            }
        }
    }

    if let Some(data) = pending_literal {
        result.push(DeltaOp::Literal {
            data: Bytes::from(data),
        });
    }

    result
}

/// Calculate the size of a delta in bytes (uncompressed)
#[must_use]
pub fn delta_size(delta: &Delta) -> u64 {
    delta
        .ops
        .iter()
        .map(|op| match op {
            DeltaOp::CopyChunk { .. } => 12, // offset(8) + length(4)
            DeltaOp::Literal { data } => data.len() as u64,
        })
        .sum()
}

/// Calculate compression ratio for a delta
#[must_use]
pub fn compression_ratio(original_size: u64, delta: &Delta) -> f64 {
    if original_size == 0 {
        return 1.0;
    }

    delta_size(delta) as f64 / original_size as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identical_files() {
        let computer = DeltaComputer::new();
        let data = b"Hello, World! This is some test data that spans multiple chunks.";
        let data_vec = data.repeat(100); // Make it larger

        let sig = computer.signature(&data_vec);
        let delta = computer.delta(&data_vec, &sig);

        // Should be mostly CopyChunk operations
        let copy_count = delta
            .ops
            .iter()
            .filter(|op| matches!(op, DeltaOp::CopyChunk { .. }))
            .count();
        assert!(
            copy_count > 0,
            "Expected copy operations for identical data"
        );

        // Should be able to reconstruct
        let reconstructed = computer.apply(&data_vec, &delta).unwrap();
        assert_eq!(reconstructed, data_vec);
    }

    #[test]
    fn test_small_change() {
        let computer = DeltaComputer::new();
        let old_data = b"AAAA".repeat(1000);
        let mut new_data = old_data.clone();
        // Change one byte in the middle
        new_data[500] = b'B';

        let sig = computer.signature(&old_data);
        let delta = computer.delta(&new_data, &sig);

        let reconstructed = computer.apply(&old_data, &delta).unwrap();
        assert_eq!(reconstructed, new_data);
    }

    #[test]
    fn test_completely_different() {
        let computer = DeltaComputer::new();
        let old_data = b"AAAA".repeat(100);
        let new_data = b"BBBB".repeat(100);

        let sig = computer.signature(&old_data);
        let delta = computer.delta(&new_data, &sig);

        // Should be all literal
        let literal_count = delta
            .ops
            .iter()
            .filter(|op| matches!(op, DeltaOp::Literal { .. }))
            .count();
        assert!(literal_count > 0);

        let reconstructed = computer.apply(&old_data, &delta).unwrap();
        assert_eq!(reconstructed, new_data);
    }

    #[test]
    fn test_insertion_at_start() {
        // FastCDC should handle insertions better than fixed blocks
        // Use varied data (like source code) rather than repetitive data
        let computer = DeltaComputer::new();

        // Create realistic source-code-like content with natural variation
        let mut original = Vec::with_capacity(50_000);
        for i in 0..3000 {
            original.extend_from_slice(
                format!("fn process_{i}(x: i32) -> i32 {{ x * {i} }}\n").as_bytes(),
            );
        }

        let mut modified = b"// Copyright 2025\n// License: MIT\n\n".to_vec();
        modified.extend_from_slice(&original);

        let sig = computer.signature(&original);
        let delta = computer.delta(&modified, &sig);

        // With CDC, we expect chunk reuse even after prefix insertion
        // (unlike fixed blocks which would shift everything)
        let reconstructed = computer.apply(&original, &delta).unwrap();
        assert_eq!(reconstructed, modified);

        // Check that there are some copy operations (chunk reuse)
        let copy_count = delta
            .ops
            .iter()
            .filter(|op| matches!(op, DeltaOp::CopyChunk { .. }))
            .count();

        // Delta should be smaller than full file (due to chunk reuse)
        let delta_bytes = delta_size(&delta);
        assert!(
            delta_bytes < modified.len() as u64,
            "Delta ({delta_bytes}) should be smaller than modified file ({}) with {} copy ops",
            modified.len(),
            copy_count
        );
    }

    #[test]
    fn test_compression_roundtrip() {
        let computer = DeltaComputer::new();
        let data = b"Hello, World!".repeat(1000);
        let sig = computer.signature(&data);
        let delta = computer.delta(&data, &sig);

        // Test delta compression
        let compressed_delta = DeltaComputer::compress_delta(&delta).unwrap();
        let decompressed_delta = DeltaComputer::decompress_delta(&compressed_delta).unwrap();
        assert_eq!(delta.new_hash, decompressed_delta.new_hash);
        assert_eq!(delta.ops.len(), decompressed_delta.ops.len());

        // Test signature compression
        let compressed_sig = DeltaComputer::compress_signature(&sig).unwrap();
        let decompressed_sig = DeltaComputer::decompress_signature(&compressed_sig).unwrap();
        assert_eq!(sig.file_size, decompressed_sig.file_size);
        assert_eq!(sig.chunks.len(), decompressed_sig.chunks.len());
    }

    #[test]
    fn test_empty_file() {
        let computer = DeltaComputer::new();
        let old_data = b"some data";
        let new_data = b"";

        let sig = computer.signature(old_data);
        let delta = computer.delta(new_data, &sig);

        let reconstructed = computer.apply(old_data, &delta).unwrap();
        assert_eq!(reconstructed, new_data);
    }

    #[test]
    fn test_new_file() {
        let computer = DeltaComputer::new();
        let old_data = b"";
        let new_data = b"brand new content";

        let sig = computer.signature(old_data);
        let delta = computer.delta(new_data, &sig);

        // Should be all literal
        assert!(matches!(delta.ops.first(), Some(DeltaOp::Literal { .. })));

        let reconstructed = computer.apply(old_data, &delta).unwrap();
        assert_eq!(reconstructed, new_data);
    }

    #[test]
    fn test_version_byte() {
        let computer = DeltaComputer::new();
        let data = b"test data";
        let sig = computer.signature(data);
        let delta = computer.delta(data, &sig);

        let compressed_sig = DeltaComputer::compress_signature(&sig).unwrap();
        let compressed_delta = DeltaComputer::compress_delta(&delta).unwrap();

        // First byte should be version
        assert_eq!(compressed_sig[0], PROTOCOL_VERSION);
        assert_eq!(compressed_delta[0], PROTOCOL_VERSION);
    }
}
