//! Snapshot: A point-in-time view of a directory tree

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::hash::ContentHash;
use crate::scan::FileEntry;

/// A snapshot of a directory tree at a point in time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    /// All files in the snapshot, keyed by relative path
    pub files: HashMap<PathBuf, FileEntry>,
}

impl Snapshot {
    /// Create a snapshot from scanned entries
    #[must_use]
    pub fn from_entries(entries: Vec<FileEntry>) -> Self {
        let files = entries.into_iter().map(|e| (e.path.clone(), e)).collect();
        Self { files }
    }

    /// Create an empty snapshot
    #[must_use]
    pub fn empty() -> Self {
        Self {
            files: HashMap::new(),
        }
    }

    /// Get the number of files
    #[must_use]
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Check if empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Get a file by path
    #[must_use]
    pub fn get(&self, path: &PathBuf) -> Option<&FileEntry> {
        self.files.get(path)
    }

    /// Compare two snapshots and return the differences
    #[must_use]
    pub fn diff(&self, other: &Self) -> SnapshotDiff {
        let mut added = Vec::new();
        let mut removed = Vec::new();
        let mut modified = Vec::new();

        // Find added and modified files
        for (path, new_entry) in &other.files {
            match self.files.get(path) {
                None => added.push(path.clone()),
                Some(old_entry) if old_entry.hash != new_entry.hash => {
                    modified.push(path.clone());
                }
                _ => {}
            }
        }

        // Find removed files
        for path in self.files.keys() {
            if !other.files.contains_key(path) {
                removed.push(path.clone());
            }
        }

        SnapshotDiff {
            added,
            removed,
            modified,
        }
    }

    /// Get all content hashes in this snapshot
    #[must_use]
    pub fn content_hashes(&self) -> Vec<ContentHash> {
        self.files.values().map(|e| e.hash).collect()
    }
}

/// Differences between two snapshots
#[derive(Debug, Clone)]
pub struct SnapshotDiff {
    /// Files that exist in new but not in old
    pub added: Vec<PathBuf>,
    /// Files that exist in old but not in new
    pub removed: Vec<PathBuf>,
    /// Files that exist in both but have different content
    pub modified: Vec<PathBuf>,
}

impl SnapshotDiff {
    /// Check if there are any changes
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.modified.is_empty()
    }

    /// Get total number of changes
    #[must_use]
    pub fn len(&self) -> usize {
        self.added.len() + self.removed.len() + self.modified.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    fn make_entry(path: &str, content: &[u8]) -> FileEntry {
        FileEntry {
            path: PathBuf::from(path),
            size: content.len() as u64,
            modified: SystemTime::now(),
            hash: ContentHash::from_bytes(content),
            executable: false,
        }
    }

    #[test]
    fn test_snapshot_diff_added() {
        let old = Snapshot::from_entries(vec![make_entry("a.txt", b"a")]);
        let new =
            Snapshot::from_entries(vec![make_entry("a.txt", b"a"), make_entry("b.txt", b"b")]);

        let diff = old.diff(&new);
        assert_eq!(diff.added, vec![PathBuf::from("b.txt")]);
        assert!(diff.removed.is_empty());
        assert!(diff.modified.is_empty());
    }

    #[test]
    fn test_snapshot_diff_removed() {
        let old =
            Snapshot::from_entries(vec![make_entry("a.txt", b"a"), make_entry("b.txt", b"b")]);
        let new = Snapshot::from_entries(vec![make_entry("a.txt", b"a")]);

        let diff = old.diff(&new);
        assert!(diff.added.is_empty());
        assert_eq!(diff.removed, vec![PathBuf::from("b.txt")]);
        assert!(diff.modified.is_empty());
    }

    #[test]
    fn test_snapshot_diff_modified() {
        let old = Snapshot::from_entries(vec![make_entry("a.txt", b"old content")]);
        let new = Snapshot::from_entries(vec![make_entry("a.txt", b"new content")]);

        let diff = old.diff(&new);
        assert!(diff.added.is_empty());
        assert!(diff.removed.is_empty());
        assert_eq!(diff.modified, vec![PathBuf::from("a.txt")]);
    }
}
