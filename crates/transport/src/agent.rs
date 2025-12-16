//! Agent binary bundling and deployment

use std::collections::HashMap;

use color_eyre::Result;

use crate::Platform;

/// Bundle of agent binaries for different platforms
///
/// At build time, cross-compiled agent binaries are embedded into the CLI.
/// At runtime, the appropriate binary is extracted and deployed to the remote host.
pub struct AgentBundle {
    /// Compressed agent binaries by platform
    binaries: HashMap<Platform, Vec<u8>>,
}

impl AgentBundle {
    /// Create a new empty bundle
    #[must_use]
    pub fn new() -> Self {
        Self {
            binaries: HashMap::new(),
        }
    }

    /// Add a binary for a platform
    pub fn add(&mut self, platform: Platform, data: Vec<u8>) {
        self.binaries.insert(platform, data);
    }

    /// Get binary for a platform (decompressed)
    #[must_use]
    pub fn get(&self, platform: Platform) -> Option<&[u8]> {
        self.binaries.get(&platform).map(Vec::as_slice)
    }

    /// Check if a platform is available
    #[must_use]
    pub fn has(&self, platform: Platform) -> bool {
        self.binaries.contains_key(&platform)
    }

    /// List available platforms
    #[must_use]
    pub fn platforms(&self) -> Vec<Platform> {
        self.binaries.keys().copied().collect()
    }

    /// Load embedded agent binaries
    ///
    /// In a real build, this would use `include_bytes!` or `include_dir!`
    /// to embed cross-compiled binaries.
    #[must_use]
    pub fn embedded() -> Self {
        // In production, these would be embedded at compile time:
        // bundle.add(Platform::LinuxX86_64, include_bytes!("../agents/linux-x86_64.zst").to_vec());
        // bundle.add(Platform::LinuxAarch64, include_bytes!("../agents/linux-aarch64.zst").to_vec());
        // etc.

        // For now, return empty bundle (agent must be built separately)
        Self::new()
    }

    /// Load agent binaries from a directory (for development)
    ///
    /// # Errors
    /// Returns an error if reading files fails
    pub fn from_dir(dir: &std::path::Path) -> Result<Self> {
        let mut bundle = Self::new();

        let platforms = [
            (Platform::LinuxX86_64, "linux-x86_64"),
            (Platform::LinuxAarch64, "linux-aarch64"),
            (Platform::DarwinX86_64, "darwin-x86_64"),
            (Platform::DarwinAarch64, "darwin-aarch64"),
        ];

        for (platform, suffix) in platforms {
            let path = dir.join(format!("zsync-agent-{suffix}"));
            if path.exists() {
                let data = std::fs::read(&path)?;
                let len = data.len();
                bundle.add(platform, data);
                tracing::debug!("Loaded agent for {suffix} ({len} bytes)");
            }
        }

        Ok(bundle)
    }
}

impl Default for AgentBundle {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bundle_add_get() {
        let mut bundle = AgentBundle::new();
        bundle.add(Platform::LinuxX86_64, vec![1, 2, 3]);

        assert!(bundle.has(Platform::LinuxX86_64));
        assert!(!bundle.has(Platform::LinuxAarch64));
        assert_eq!(bundle.get(Platform::LinuxX86_64), Some(&[1u8, 2, 3][..]));
    }

    #[test]
    fn test_platform_from_uname() {
        assert_eq!(
            Platform::from_uname("Linux", "x86_64"),
            Some(Platform::LinuxX86_64)
        );
        assert_eq!(
            Platform::from_uname("Linux", "aarch64"),
            Some(Platform::LinuxAarch64)
        );
        assert_eq!(
            Platform::from_uname("Darwin", "arm64"),
            Some(Platform::DarwinAarch64)
        );
        assert_eq!(Platform::from_uname("Windows", "x86_64"), None);
    }
}
