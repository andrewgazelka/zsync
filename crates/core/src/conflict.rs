//! Conflict resolution for two-way sync
//!
//! Implements last-write-wins conflict resolution based on mtime.

use std::path::PathBuf;
use std::time::SystemTime;

use crate::sync_state::FileChange;

/// Resolution for a conflict between local and remote changes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    /// Use local version (local mtime is newer or remote was deleted)
    UseLocal,
    /// Use remote version (remote mtime is newer or local was deleted)
    UseRemote,
    /// Both sides deleted the file - no action needed
    BothDeleted,
}

/// A conflict between local and remote changes to the same file
#[derive(Debug, Clone)]
pub struct Conflict {
    /// Path of the conflicting file
    pub path: PathBuf,
    /// Change on local side
    pub local_change: FileChange,
    /// Change on remote side
    pub remote_change: FileChange,
}

impl Conflict {
    /// Create a new conflict
    #[must_use]
    pub fn new(path: PathBuf, local_change: FileChange, remote_change: FileChange) -> Self {
        Self {
            path,
            local_change,
            remote_change,
        }
    }

    /// Resolve this conflict using last-write-wins (mtime comparison)
    ///
    /// Rules:
    /// - If both have mtime, newer wins
    /// - If one is deleted (no mtime), the non-deleted one wins
    /// - If both are deleted, return BothDeleted
    #[must_use]
    pub fn resolve(&self) -> Resolution {
        let local_mtime = self.local_change.mtime();
        let remote_mtime = self.remote_change.mtime();

        match (local_mtime, remote_mtime) {
            (Some(local), Some(remote)) => {
                if local >= remote {
                    Resolution::UseLocal
                } else {
                    Resolution::UseRemote
                }
            }
            // Local has file, remote deleted -> local wins
            (Some(_), None) => Resolution::UseLocal,
            // Remote has file, local deleted -> remote wins
            (None, Some(_)) => Resolution::UseRemote,
            // Both deleted -> no action needed
            (None, None) => Resolution::BothDeleted,
        }
    }
}

/// Result of analyzing changes from both sides
#[derive(Debug, Default)]
pub struct SyncPlan {
    /// Changes to push from local to remote (no conflict)
    pub push_to_remote: Vec<FileChange>,
    /// Changes to pull from remote to local (no conflict)
    pub pull_from_remote: Vec<FileChange>,
    /// Conflicts that were resolved
    pub resolved_conflicts: Vec<(Conflict, Resolution)>,
}

impl SyncPlan {
    /// Create an empty sync plan
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if there are any changes to sync
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.push_to_remote.is_empty()
            && self.pull_from_remote.is_empty()
            && self.resolved_conflicts.is_empty()
    }

    /// Total number of operations
    #[must_use]
    pub fn total_operations(&self) -> usize {
        self.push_to_remote.len() + self.pull_from_remote.len() + self.resolved_conflicts.len()
    }
}

/// Plan a bidirectional sync by analyzing local and remote changes
///
/// This function:
/// 1. Identifies conflicts (same file changed on both sides)
/// 2. Resolves conflicts using last-write-wins
/// 3. Separates non-conflicting changes into push/pull lists
#[must_use]
pub fn plan_sync(local_changes: Vec<FileChange>, remote_changes: Vec<FileChange>) -> SyncPlan {
    use std::collections::HashMap;

    let mut plan = SyncPlan::new();

    // Index remote changes by path for quick lookup
    let mut remote_by_path: HashMap<PathBuf, FileChange> = HashMap::new();
    for change in remote_changes {
        remote_by_path.insert(change.path().to_path_buf(), change);
    }

    // Process local changes
    for local_change in local_changes {
        let path = local_change.path().to_path_buf();

        if let Some(remote_change) = remote_by_path.remove(&path) {
            // Same file changed on both sides - conflict!
            let conflict = Conflict::new(path, local_change, remote_change);
            let resolution = conflict.resolve();

            match resolution {
                Resolution::UseLocal => {
                    plan.push_to_remote.push(conflict.local_change.clone());
                }
                Resolution::UseRemote => {
                    plan.pull_from_remote.push(conflict.remote_change.clone());
                }
                Resolution::BothDeleted => {
                    // Nothing to do
                }
            }

            plan.resolved_conflicts.push((conflict, resolution));
        } else {
            // Only changed locally - push to remote
            plan.push_to_remote.push(local_change);
        }
    }

    // Remaining remote changes (not in local) - pull from remote
    for (_, remote_change) in remote_by_path {
        plan.pull_from_remote.push(remote_change);
    }

    plan
}

/// Compare two modification times, returning which is newer
///
/// Returns positive if a is newer, negative if b is newer, 0 if equal.
#[must_use]
pub fn compare_mtime(a: SystemTime, b: SystemTime) -> std::cmp::Ordering {
    a.cmp(&b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::ContentHash;
    use crate::scan::FileEntry;
    use crate::sync_state::SyncedFileState;
    use std::time::{Duration, UNIX_EPOCH};

    fn make_entry(path: &str, content: &[u8], mtime_secs: u64) -> FileEntry {
        FileEntry {
            path: PathBuf::from(path),
            size: content.len() as u64,
            modified: UNIX_EPOCH + Duration::from_secs(mtime_secs),
            hash: ContentHash::from_bytes(content),
            mode: 0o644,
        }
    }

    fn make_synced_state(content: &[u8], mtime_secs: i64) -> SyncedFileState {
        SyncedFileState {
            hash: *ContentHash::from_bytes(content).as_bytes(),
            mtime_secs,
            mode: 0o644,
            size: content.len() as u64,
        }
    }

    #[test]
    fn test_conflict_resolution_local_newer() {
        let local_change = FileChange::Modified {
            path: PathBuf::from("file.txt"),
            entry: make_entry("file.txt", b"local", 2000),
            last_synced: make_synced_state(b"old", 1000),
        };

        let remote_change = FileChange::Modified {
            path: PathBuf::from("file.txt"),
            entry: make_entry("file.txt", b"remote", 1500),
            last_synced: make_synced_state(b"old", 1000),
        };

        let conflict = Conflict::new(PathBuf::from("file.txt"), local_change, remote_change);
        assert_eq!(conflict.resolve(), Resolution::UseLocal);
    }

    #[test]
    fn test_conflict_resolution_remote_newer() {
        let local_change = FileChange::Modified {
            path: PathBuf::from("file.txt"),
            entry: make_entry("file.txt", b"local", 1500),
            last_synced: make_synced_state(b"old", 1000),
        };

        let remote_change = FileChange::Modified {
            path: PathBuf::from("file.txt"),
            entry: make_entry("file.txt", b"remote", 2000),
            last_synced: make_synced_state(b"old", 1000),
        };

        let conflict = Conflict::new(PathBuf::from("file.txt"), local_change, remote_change);
        assert_eq!(conflict.resolve(), Resolution::UseRemote);
    }

    #[test]
    fn test_conflict_resolution_local_modified_remote_deleted() {
        let local_change = FileChange::Modified {
            path: PathBuf::from("file.txt"),
            entry: make_entry("file.txt", b"local", 2000),
            last_synced: make_synced_state(b"old", 1000),
        };

        let remote_change = FileChange::Deleted {
            path: PathBuf::from("file.txt"),
            last_synced: make_synced_state(b"old", 1000),
        };

        let conflict = Conflict::new(PathBuf::from("file.txt"), local_change, remote_change);
        // Modification wins over deletion
        assert_eq!(conflict.resolve(), Resolution::UseLocal);
    }

    #[test]
    fn test_conflict_resolution_local_deleted_remote_modified() {
        let local_change = FileChange::Deleted {
            path: PathBuf::from("file.txt"),
            last_synced: make_synced_state(b"old", 1000),
        };

        let remote_change = FileChange::Modified {
            path: PathBuf::from("file.txt"),
            entry: make_entry("file.txt", b"remote", 2000),
            last_synced: make_synced_state(b"old", 1000),
        };

        let conflict = Conflict::new(PathBuf::from("file.txt"), local_change, remote_change);
        // Modification wins over deletion
        assert_eq!(conflict.resolve(), Resolution::UseRemote);
    }

    #[test]
    fn test_conflict_resolution_both_deleted() {
        let local_change = FileChange::Deleted {
            path: PathBuf::from("file.txt"),
            last_synced: make_synced_state(b"old", 1000),
        };

        let remote_change = FileChange::Deleted {
            path: PathBuf::from("file.txt"),
            last_synced: make_synced_state(b"old", 1000),
        };

        let conflict = Conflict::new(PathBuf::from("file.txt"), local_change, remote_change);
        assert_eq!(conflict.resolve(), Resolution::BothDeleted);
    }

    #[test]
    fn test_plan_sync_no_conflicts() {
        let local_changes = vec![FileChange::Added {
            path: PathBuf::from("local_new.txt"),
            entry: make_entry("local_new.txt", b"local", 1000),
        }];

        let remote_changes = vec![FileChange::Added {
            path: PathBuf::from("remote_new.txt"),
            entry: make_entry("remote_new.txt", b"remote", 1000),
        }];

        let plan = plan_sync(local_changes, remote_changes);

        assert_eq!(plan.push_to_remote.len(), 1);
        assert_eq!(plan.pull_from_remote.len(), 1);
        assert!(plan.resolved_conflicts.is_empty());
    }

    #[test]
    fn test_plan_sync_with_conflict() {
        let local_changes = vec![FileChange::Modified {
            path: PathBuf::from("shared.txt"),
            entry: make_entry("shared.txt", b"local", 2000),
            last_synced: make_synced_state(b"old", 1000),
        }];

        let remote_changes = vec![FileChange::Modified {
            path: PathBuf::from("shared.txt"),
            entry: make_entry("shared.txt", b"remote", 1500),
            last_synced: make_synced_state(b"old", 1000),
        }];

        let plan = plan_sync(local_changes, remote_changes);

        // Local wins (newer), so push to remote
        assert_eq!(plan.push_to_remote.len(), 1);
        assert!(plan.pull_from_remote.is_empty());
        assert_eq!(plan.resolved_conflicts.len(), 1);
        assert_eq!(plan.resolved_conflicts[0].1, Resolution::UseLocal);
    }
}
