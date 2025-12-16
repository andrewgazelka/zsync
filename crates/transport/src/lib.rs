//! zsync-transport: SSH transport layer
//!
//! Handles SSH connections, agent deployment, and remote communication.

pub mod agent;
pub mod ssh;

pub use agent::AgentBundle;
pub use ssh::{AgentSession, BatchResult, SshTransport};

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
