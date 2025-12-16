//! Agent binary bundling and deployment

use std::collections::HashMap;

use color_eyre::Result;

use crate::Platform;

/// Bundle of agent binaries for different platforms
///
/// At build time, cross-compiled agent binaries are embedded into the CLI.
/// At runtime, the appropriate binary is extracted and deployed to the remote host.
pub struct AgentBundle {
    /// Agent binaries by platform
    binaries: HashMap<Platform, &'static [u8]>,
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
    pub fn add(&mut self, platform: Platform, data: &'static [u8]) {
        self.binaries.insert(platform, data);
    }

    /// Get binary for a platform
    #[must_use]
    pub fn get(&self, platform: Platform) -> Option<&[u8]> {
        self.binaries.get(&platform).copied()
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

    /// Load agent binaries from a directory (for development)
    ///
    /// # Errors
    /// Returns an error if reading files fails
    pub fn from_dir(dir: &std::path::Path) -> Result<Self> {
        let mut owned = OwnedAgentBundle::new();

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
                owned.add(platform, data);
                tracing::debug!("Loaded agent for {suffix} ({len} bytes)");
            }
        }

        Ok(owned.into_static())
    }
}

impl Default for AgentBundle {
    fn default() -> Self {
        Self::new()
    }
}

/// Owned version for loading from disk
struct OwnedAgentBundle {
    binaries: HashMap<Platform, Vec<u8>>,
}

impl OwnedAgentBundle {
    fn new() -> Self {
        Self {
            binaries: HashMap::new(),
        }
    }

    fn add(&mut self, platform: Platform, data: Vec<u8>) {
        self.binaries.insert(platform, data);
    }

    fn into_static(self) -> AgentBundle {
        let mut bundle = AgentBundle::new();
        for (platform, data) in self.binaries {
            // Leak the Vec to get a 'static slice - fine for CLI lifetime
            let static_data: &'static [u8] = Box::leak(data.into_boxed_slice());
            bundle.add(platform, static_data);
        }
        bundle
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bundle_add_get() {
        let mut bundle = AgentBundle::new();
        static TEST_DATA: &[u8] = &[1, 2, 3];
        bundle.add(Platform::LinuxX86_64, TEST_DATA);

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
