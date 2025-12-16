//! Content-addressed hashing using BLAKE3

use std::fmt;
use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// A content hash using BLAKE3 (256-bit)
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContentHash([u8; 32]);

impl ContentHash {
    /// Hash arbitrary bytes
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Self {
        Self(*blake3::hash(data).as_bytes())
    }

    /// Hash a file by path
    ///
    /// # Errors
    /// Returns an error if the file cannot be read
    pub fn from_file(path: &Path) -> color_eyre::Result<Self> {
        let mut file = std::fs::File::open(path)?;
        let mut hasher = blake3::Hasher::new();
        let mut buffer = [0u8; 64 * 1024]; // 64KB buffer

        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        Ok(Self(*hasher.finalize().as_bytes()))
    }

    /// Get raw bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to hex string
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = self.to_hex();
        write!(f, "ContentHash({})", hex.get(..16).unwrap_or(&hex))
    }
}

impl fmt::Display for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = self.to_hex();
        write!(f, "{}", hex.get(..16).unwrap_or(&hex))
    }
}

/// Rolling hash for rsync-style block matching (CRC32)
#[derive(Clone, Copy)]
pub struct RollingHash {
    hash: u32,
}

impl RollingHash {
    /// Create a new rolling hash from a block
    #[must_use]
    pub fn new(block: &[u8]) -> Self {
        Self {
            hash: crc32fast::hash(block),
        }
    }

    /// Get the current hash value
    #[must_use]
    pub fn value(&self) -> u32 {
        self.hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_hash_deterministic() {
        let data = b"hello world";
        let h1 = ContentHash::from_bytes(data);
        let h2 = ContentHash::from_bytes(data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_content_hash_different_data() {
        let h1 = ContentHash::from_bytes(b"hello");
        let h2 = ContentHash::from_bytes(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_rolling_hash() {
        let block = b"test block data";
        let rh = RollingHash::new(block);
        assert_ne!(rh.value(), 0);
    }
}
