//! Sync state tracking for two-way sync
//!
//! Tracks the last-synced state of files on both local and remote sides.
//! Used to detect what changed since the last sync and resolve conflicts.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rkyv::rancor::Error as RkyvError;
use rkyv::{Archive, Deserialize, Serialize};

use crate::hash::ContentHash;
use crate::scan::FileEntry;
use crate::snapshot::Snapshot;

/// State of a file at last successful sync
#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[rkyv(derive(Debug))]
pub struct SyncedFileState {
    /// Content hash at last successful sync
    pub hash: [u8; 32],
    /// Modification time at last sync (seconds since UNIX epoch)
    pub mtime_secs: i64,
    /// Permission mode at last sync
    pub mode: u32,
    /// File size at last sync
    pub size: u64,
}

impl SyncedFileState {
    /// Create from a `FileEntry`
    #[must_use]
    pub fn from_entry(entry: &FileEntry) -> Self {
        let mtime_secs = entry
            .modified
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        Self {
            hash: *entry.hash.as_bytes(),
            mtime_secs,
            mode: entry.mode,
            size: entry.size,
        }
    }

    /// Get the content hash
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        ContentHash::from_raw(self.hash)
    }

    /// Get the modification time as SystemTime
    #[must_use]
    pub fn modified(&self) -> SystemTime {
        if self.mtime_secs >= 0 {
            UNIX_EPOCH + Duration::from_secs(self.mtime_secs as u64)
        } else {
            UNIX_EPOCH - Duration::from_secs((-self.mtime_secs) as u64)
        }
    }
}

/// Tombstone entry for tracking deleted files
#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[rkyv(derive(Debug))]
pub struct TombstoneEntry {
    /// When the file was deleted (seconds since UNIX epoch)
    pub deleted_at_secs: i64,
    /// Last known content hash before deletion
    pub last_hash: [u8; 32],
    /// Sync version when deletion was recorded
    pub sync_version: u64,
}

impl TombstoneEntry {
    /// Create a new tombstone
    #[must_use]
    pub fn new(last_hash: ContentHash, sync_version: u64) -> Self {
        let deleted_at_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        Self {
            deleted_at_secs,
            last_hash: *last_hash.as_bytes(),
            sync_version,
        }
    }

    /// Check if tombstone is older than the given duration
    #[must_use]
    pub fn is_expired(&self, max_age: Duration) -> bool {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let age_secs = now_secs - self.deleted_at_secs;
        age_secs > max_age.as_secs() as i64
    }
}

/// Full sync state for a directory
#[derive(Archive, Serialize, Deserialize, Debug, Clone, Default)]
#[rkyv(derive(Debug))]
pub struct SyncState {
    /// Map of relative path (as string) -> file state at last sync
    pub files: HashMap<String, SyncedFileState>,
    /// Monotonically increasing sync version
    pub version: u64,
    /// Deleted files since last sync (path -> tombstone)
    pub tombstones: HashMap<String, TombstoneEntry>,
}

impl SyncState {
    /// Create an empty sync state
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Load sync state from a file, or return empty state if not found
    ///
    /// # Errors
    /// Returns an error if the file exists but cannot be read or parsed.
    pub fn load(root: &Path) -> color_eyre::Result<Self> {
        let state_path = root.join(".zsync").join("sync_state.rkyv");

        if !state_path.exists() {
            return Ok(Self::new());
        }

        let bytes = std::fs::read(&state_path)?;
        let archived = rkyv::access::<ArchivedSyncState, RkyvError>(&bytes)
            .map_err(|e| color_eyre::eyre::eyre!("failed to access archived sync state: {e}"))?;

        // Deserialize from archived to owned
        let state: Self = rkyv::deserialize::<Self, RkyvError>(archived)
            .map_err(|e| color_eyre::eyre::eyre!("failed to deserialize sync state: {e}"))?;

        Ok(state)
    }

    /// Save sync state to a file
    ///
    /// # Errors
    /// Returns an error if the file cannot be written.
    pub fn save(&self, root: &Path) -> color_eyre::Result<()> {
        let zsync_dir = root.join(".zsync");
        std::fs::create_dir_all(&zsync_dir)?;

        let state_path = zsync_dir.join("sync_state.rkyv");
        let bytes = rkyv::to_bytes::<RkyvError>(self)
            .map_err(|e| color_eyre::eyre::eyre!("failed to serialize sync state: {e}"))?;

        std::fs::write(&state_path, &bytes)?;
        Ok(())
    }

    /// Update sync state from a snapshot after successful sync
    pub fn update_from_snapshot(&mut self, snapshot: &Snapshot) {
        self.version += 1;

        // Update file states
        self.files.clear();
        for (path, entry) in &snapshot.files {
            let path_str = path.to_string_lossy().to_string();
            self.files
                .insert(path_str, SyncedFileState::from_entry(entry));
        }
    }

    /// Record a file deletion
    pub fn record_deletion(&mut self, path: &Path, last_hash: ContentHash) {
        self.version += 1;
        let path_str = path.to_string_lossy().to_string();

        // Remove from files
        self.files.remove(&path_str);

        // Add tombstone
        self.tombstones
            .insert(path_str, TombstoneEntry::new(last_hash, self.version));
    }

    /// Remove tombstones older than max_age
    pub fn gc_tombstones(&mut self, max_age: Duration) {
        self.tombstones
            .retain(|_, entry| !entry.is_expired(max_age));
    }

    /// Get the synced state for a file
    #[must_use]
    pub fn get_file(&self, path: &Path) -> Option<&SyncedFileState> {
        let path_str = path.to_string_lossy().to_string();
        self.files.get(&path_str)
    }

    /// Check if a file was deleted (has tombstone)
    #[must_use]
    pub fn was_deleted(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy().to_string();
        self.tombstones.contains_key(&path_str)
    }
}

/// Type of change detected for a file
#[derive(Debug, Clone)]
pub enum FileChange {
    /// File is new (not in last sync state)
    Added { path: PathBuf, entry: FileEntry },
    /// File content or mode changed since last sync
    Modified {
        path: PathBuf,
        entry: FileEntry,
        last_synced: SyncedFileState,
    },
    /// File was deleted (exists in sync state but not on disk)
    Deleted {
        path: PathBuf,
        last_synced: SyncedFileState,
    },
}

impl FileChange {
    /// Get the path of the changed file
    #[must_use]
    pub fn path(&self) -> &Path {
        match self {
            Self::Added { path, .. } | Self::Modified { path, .. } | Self::Deleted { path, .. } => {
                path
            }
        }
    }

    /// Get the modification time (if available)
    #[must_use]
    pub fn mtime(&self) -> Option<SystemTime> {
        match self {
            Self::Added { entry, .. } | Self::Modified { entry, .. } => Some(entry.modified),
            Self::Deleted { .. } => None,
        }
    }

    /// Check if this is an unchanged file
    #[must_use]
    pub fn is_unchanged(&self) -> bool {
        false // FileChange only represents actual changes
    }
}

/// Detect changes between current snapshot and last sync state
#[must_use]
pub fn detect_changes(current: &Snapshot, sync_state: &SyncState) -> Vec<FileChange> {
    let mut changes = Vec::new();

    // Check each file in current snapshot
    for (path, entry) in &current.files {
        let path_str = path.to_string_lossy().to_string();

        match sync_state.files.get(&path_str) {
            None => {
                // Not in sync state - it's new (or was in tombstones and recreated)
                changes.push(FileChange::Added {
                    path: path.clone(),
                    entry: entry.clone(),
                });
            }
            Some(synced) => {
                // Check if content or mode changed
                if entry.hash.as_bytes() != &synced.hash || entry.mode != synced.mode {
                    changes.push(FileChange::Modified {
                        path: path.clone(),
                        entry: entry.clone(),
                        last_synced: synced.clone(),
                    });
                }
                // If unchanged, we don't add it to changes
            }
        }
    }

    // Check for deletions (in sync state but not in current snapshot)
    for (path_str, synced) in &sync_state.files {
        let path = PathBuf::from(path_str);
        if !current.files.contains_key(&path) {
            changes.push(FileChange::Deleted {
                path,
                last_synced: synced.clone(),
            });
        }
    }

    changes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(path: &str, content: &[u8], mtime_secs: u64) -> FileEntry {
        FileEntry {
            path: PathBuf::from(path),
            size: content.len() as u64,
            modified: UNIX_EPOCH + Duration::from_secs(mtime_secs),
            hash: ContentHash::from_bytes(content),
            mode: 0o644,
        }
    }

    #[test]
    fn test_sync_state_roundtrip() {
        let dir = tempfile::tempdir().unwrap();

        let mut state = SyncState::new();
        state.files.insert(
            "test.txt".to_string(),
            SyncedFileState {
                hash: [1u8; 32],
                mtime_secs: 1_700_000_000,
                mode: 0o644,
                size: 100,
            },
        );
        state.version = 5;

        state.save(dir.path()).unwrap();
        let loaded = SyncState::load(dir.path()).unwrap();

        assert_eq!(loaded.version, 5);
        assert_eq!(loaded.files.len(), 1);
        assert!(loaded.files.contains_key("test.txt"));
    }

    #[test]
    fn test_detect_changes_added() {
        let sync_state = SyncState::new();
        let snapshot = Snapshot::from_entries(vec![make_entry("new.txt", b"content", 1000)]);

        let changes = detect_changes(&snapshot, &sync_state);
        assert_eq!(changes.len(), 1);
        assert!(
            matches!(&changes[0], FileChange::Added { path, .. } if path == Path::new("new.txt"))
        );
    }

    #[test]
    fn test_detect_changes_modified() {
        let mut sync_state = SyncState::new();
        sync_state.files.insert(
            "file.txt".to_string(),
            SyncedFileState {
                hash: *ContentHash::from_bytes(b"old").as_bytes(),
                mtime_secs: 1000,
                mode: 0o644,
                size: 3,
            },
        );

        let snapshot = Snapshot::from_entries(vec![make_entry("file.txt", b"new content", 2000)]);

        let changes = detect_changes(&snapshot, &sync_state);
        assert_eq!(changes.len(), 1);
        assert!(
            matches!(&changes[0], FileChange::Modified { path, .. } if path == Path::new("file.txt"))
        );
    }

    #[test]
    fn test_detect_changes_deleted() {
        let mut sync_state = SyncState::new();
        sync_state.files.insert(
            "deleted.txt".to_string(),
            SyncedFileState {
                hash: [1u8; 32],
                mtime_secs: 1000,
                mode: 0o644,
                size: 10,
            },
        );

        let snapshot = Snapshot::from_entries(vec![]); // Empty snapshot

        let changes = detect_changes(&snapshot, &sync_state);
        assert_eq!(changes.len(), 1);
        assert!(
            matches!(&changes[0], FileChange::Deleted { path, .. } if path == Path::new("deleted.txt"))
        );
    }

    #[test]
    fn test_tombstone_expiry() {
        let entry = TombstoneEntry {
            deleted_at_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
                - 100, // 100 seconds ago
            last_hash: [0u8; 32],
            sync_version: 1,
        };

        // Not expired after 200 seconds
        assert!(!entry.is_expired(Duration::from_secs(200)));

        // Expired after 50 seconds
        assert!(entry.is_expired(Duration::from_secs(50)));
    }
}
