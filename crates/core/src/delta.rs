//! Delta computation using rsync-style block matching

use std::collections::HashMap;

use bytes::Bytes;
use color_eyre::Result;
use serde::{Deserialize, Serialize};

use crate::hash::{ContentHash, RollingHash};

/// Block size for delta computation (4KB default)
pub const BLOCK_SIZE: usize = 4096;

/// A signature for a file, used to compute deltas
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    /// Block signatures: (weak_hash, strong_hash, block_index)
    pub blocks: Vec<BlockSignature>,
    /// Original file size
    pub file_size: u64,
}

/// Signature for a single block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockSignature {
    /// Rolling hash (CRC32) for fast comparison
    pub weak: u32,
    /// Strong hash (BLAKE3) for verification
    pub strong: ContentHash,
    /// Block index in original file
    pub index: usize,
}

/// An operation in a delta
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeltaOp {
    /// Copy a block from the original file
    Copy { index: usize },
    /// Insert literal data
    Literal { data: Bytes },
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

/// Computes deltas between files
pub struct DeltaComputer {
    block_size: usize,
}

impl Default for DeltaComputer {
    fn default() -> Self {
        Self::new()
    }
}

impl DeltaComputer {
    /// Create a new delta computer with default block size
    #[must_use]
    pub fn new() -> Self {
        Self {
            block_size: BLOCK_SIZE,
        }
    }

    /// Create with custom block size
    #[must_use]
    pub fn with_block_size(block_size: usize) -> Self {
        Self { block_size }
    }

    /// Compute signature for a file (run on the destination side)
    #[must_use]
    pub fn signature(&self, data: &[u8]) -> Signature {
        let mut blocks = Vec::new();

        for (i, chunk) in data.chunks(self.block_size).enumerate() {
            let weak = RollingHash::new(chunk).value();
            let strong = ContentHash::from_bytes(chunk);
            blocks.push(BlockSignature {
                weak,
                strong,
                index: i,
            });
        }

        Signature {
            blocks,
            file_size: data.len() as u64,
        }
    }

    /// Compute delta from new data against old signature
    #[must_use]
    pub fn delta(&self, new_data: &[u8], old_sig: &Signature) -> Delta {
        // Build lookup table: weak_hash -> [(strong_hash, index)]
        let mut lookup: HashMap<u32, Vec<(ContentHash, usize)>> = HashMap::new();
        for block in &old_sig.blocks {
            lookup
                .entry(block.weak)
                .or_default()
                .push((block.strong, block.index));
        }

        let mut ops = Vec::new();
        let mut pos = 0;
        let mut literal_start = 0;

        while pos + self.block_size <= new_data.len() {
            let block = &new_data[pos..pos + self.block_size];
            let weak = RollingHash::new(block).value();

            let mut matched = false;

            if let Some(candidates) = lookup.get(&weak) {
                let strong = ContentHash::from_bytes(block);
                for (candidate_strong, idx) in candidates {
                    if &strong == candidate_strong {
                        // Found a match! Flush any pending literal data first
                        if literal_start < pos {
                            ops.push(DeltaOp::Literal {
                                data: Bytes::copy_from_slice(&new_data[literal_start..pos]),
                            });
                        }
                        ops.push(DeltaOp::Copy { index: *idx });
                        pos += self.block_size;
                        literal_start = pos;
                        matched = true;
                        break;
                    }
                }
            }

            if !matched {
                pos += 1;
            }
        }

        // Flush remaining literal data
        if literal_start < new_data.len() {
            ops.push(DeltaOp::Literal {
                data: Bytes::copy_from_slice(&new_data[literal_start..]),
            });
        }

        Delta {
            ops,
            new_hash: ContentHash::from_bytes(new_data),
            new_size: new_data.len() as u64,
        }
    }

    /// Apply a delta to reconstruct the new file
    ///
    /// # Errors
    /// Returns an error if the reconstructed file doesn't match the expected hash
    pub fn apply(&self, old_data: &[u8], delta: &Delta) -> Result<Vec<u8>> {
        let mut result = Vec::with_capacity(delta.new_size as usize);

        for op in &delta.ops {
            match op {
                DeltaOp::Copy { index } => {
                    let start = index * self.block_size;
                    let end = (start + self.block_size).min(old_data.len());
                    result.extend_from_slice(old_data.get(start..end).unwrap_or(&[]));
                }
                DeltaOp::Literal { data } => {
                    result.extend_from_slice(data);
                }
            }
        }

        // Verify hash
        let actual_hash = ContentHash::from_bytes(&result);
        if actual_hash != delta.new_hash {
            return Err(color_eyre::eyre::eyre!(
                "Hash mismatch after applying delta: expected {}, got {}",
                delta.new_hash,
                actual_hash
            ));
        }

        Ok(result)
    }

    /// Compress delta data using zstd
    ///
    /// # Errors
    /// Returns an error if compression fails
    pub fn compress_delta(delta: &Delta) -> Result<Vec<u8>> {
        let json = serde_json::to_vec(delta)?;
        let compressed = zstd::encode_all(json.as_slice(), 3)?;
        Ok(compressed)
    }

    /// Decompress delta data
    ///
    /// # Errors
    /// Returns an error if decompression or deserialization fails
    pub fn decompress_delta(data: &[u8]) -> Result<Delta> {
        let decompressed = zstd::decode_all(data)?;
        let delta: Delta = serde_json::from_slice(&decompressed)?;
        Ok(delta)
    }

    /// Compress signature data using zstd
    ///
    /// # Errors
    /// Returns an error if compression fails
    pub fn compress_signature(sig: &Signature) -> Result<Vec<u8>> {
        let json = serde_json::to_vec(sig)?;
        let compressed = zstd::encode_all(json.as_slice(), 3)?;
        Ok(compressed)
    }

    /// Decompress signature data
    ///
    /// # Errors
    /// Returns an error if decompression or deserialization fails
    pub fn decompress_signature(data: &[u8]) -> Result<Signature> {
        let decompressed = zstd::decode_all(data)?;
        let sig: Signature = serde_json::from_slice(&decompressed)?;
        Ok(sig)
    }
}

/// Calculate compression ratio for a delta
#[must_use]
pub fn compression_ratio(original_size: u64, delta: &Delta) -> f64 {
    let delta_size: u64 = delta
        .ops
        .iter()
        .map(|op| match op {
            DeltaOp::Copy { .. } => 8, // Just storing index
            DeltaOp::Literal { data } => data.len() as u64,
        })
        .sum();

    if original_size == 0 {
        return 1.0;
    }

    delta_size as f64 / original_size as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identical_files() {
        let computer = DeltaComputer::new();
        let data = b"Hello, World! This is some test data that spans multiple blocks.";
        let data_vec = data.repeat(100); // Make it larger

        let sig = computer.signature(&data_vec);
        let delta = computer.delta(&data_vec, &sig);

        // Should be mostly Copy operations
        let copy_count = delta
            .ops
            .iter()
            .filter(|op| matches!(op, DeltaOp::Copy { .. }))
            .count();
        assert!(copy_count > 0);

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
    fn test_compression() {
        let computer = DeltaComputer::new();
        let data = b"Hello, World!".repeat(1000);
        let sig = computer.signature(&data);
        let delta = computer.delta(&data, &sig);

        let compressed = DeltaComputer::compress_delta(&delta).unwrap();
        let decompressed = DeltaComputer::decompress_delta(&compressed).unwrap();

        assert_eq!(delta.new_hash, decompressed.new_hash);
        assert_eq!(delta.ops.len(), decompressed.ops.len());
    }
}
