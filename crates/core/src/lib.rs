//! zsync-core: Core sync engine
//!
//! Provides file scanning, hashing, CAS storage, and sync primitives.

pub mod cache;
pub mod cas;
pub mod chunker;
pub mod config;
pub mod conflict;
pub mod delta;
pub mod hash;
pub mod protocol;
pub mod scan;
pub mod snapshot;
pub mod sync_state;

pub use cache::ChunkCache;
pub use cas::ChunkStore;
pub use chunker::{Chunk, ChunkConfig, chunk_data};
pub use config::{PortForward, ZsyncConfig};
pub use conflict::{Conflict, Resolution, SyncPlan, plan_sync};
pub use delta::{Delta, DeltaComputer};
pub use hash::ContentHash;
pub use protocol::{FileManifest, Message, ProtocolReader, ProtocolWriter};
pub use scan::{FileEntry, Scanner};
pub use snapshot::{ModifiedFile, ModifyReason, Snapshot, SnapshotDiff};
pub use sync_state::{FileChange, SyncState, SyncedFileState, TombstoneEntry, detect_changes};
