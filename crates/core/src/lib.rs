//! zsync-core: Core sync engine
//!
//! Provides file scanning, hashing, delta computation, and sync primitives.

pub mod delta;
pub mod hash;
pub mod protocol;
pub mod scan;
pub mod snapshot;

pub use delta::{Delta, DeltaComputer};
pub use hash::ContentHash;
pub use protocol::{Message, ProtocolReader, ProtocolWriter};
pub use scan::{FileEntry, Scanner};
pub use snapshot::Snapshot;
