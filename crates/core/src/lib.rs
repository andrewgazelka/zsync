//! zsync-core: Core sync engine
//!
//! Provides file scanning, hashing, CAS storage, and sync primitives.

pub mod cache;
pub mod cas;
pub mod chunker;
pub mod config;
pub mod delta;
pub mod hash;
pub mod protocol;
pub mod scan;
pub mod snapshot;

pub use cache::ChunkCache;
pub use cas::ChunkStore;
pub use chunker::{Chunk, ChunkConfig, chunk_data};
pub use config::{PortForward, ZsyncConfig};
pub use delta::{Delta, DeltaComputer};
pub use hash::ContentHash;
pub use protocol::{FileManifest, Message, ProtocolReader, ProtocolWriter};
pub use scan::{FileEntry, Scanner};
pub use snapshot::Snapshot;
