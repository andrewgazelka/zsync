//! zsync-core: Core sync engine
//!
//! Provides file scanning, hashing, delta computation, and sync primitives.

pub mod cache;
pub mod chunker;
pub mod config;
pub mod delta;
pub mod hash;
pub mod protocol;
pub mod scan;
pub mod snapshot;

pub use cache::ChunkCache;
pub use chunker::{Chunk, ChunkConfig};
pub use config::{PortForward, ZsyncConfig};
pub use delta::{Delta, DeltaComputer};
pub use hash::ContentHash;
pub use protocol::{Message, ProtocolReader, ProtocolWriter};
pub use scan::{FileEntry, Scanner};
pub use snapshot::Snapshot;
