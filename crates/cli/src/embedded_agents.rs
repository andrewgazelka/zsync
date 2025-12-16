//! Embedded agent binaries
//!
//! When built with Nix, agent binaries are embedded at compile time.
//! The build.rs sets cfg flags when ZSYNC_AGENT_* env vars are present.

use zsync_transport::AgentBundle;
#[cfg(any(zsync_embed_linux_x86_64, zsync_embed_linux_aarch64))]
use zsync_transport::Platform;

/// Create an agent bundle with embedded binaries (if available)
pub fn embedded_bundle() -> AgentBundle {
    #[allow(unused_mut)]
    let mut bundle = AgentBundle::new();

    #[cfg(zsync_embed_linux_x86_64)]
    bundle.add(
        Platform::LinuxX86_64,
        include_bytes!(env!("ZSYNC_AGENT_LINUX_X86_64")),
    );

    #[cfg(zsync_embed_linux_aarch64)]
    bundle.add(
        Platform::LinuxAarch64,
        include_bytes!(env!("ZSYNC_AGENT_LINUX_AARCH64")),
    );

    bundle
}
