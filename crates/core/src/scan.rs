//! File scanning with gitignore support via the `ignore` crate

use std::path::PathBuf;
use std::time::SystemTime;

use color_eyre::Result;
use ignore::WalkBuilder;
use ignore::overrides::OverrideBuilder;
use serde::{Deserialize, Serialize};

use crate::hash::ContentHash;

/// Metadata for a single file entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    /// Relative path from scan root
    pub path: PathBuf,
    /// File size in bytes
    pub size: u64,
    /// Modification time
    pub modified: SystemTime,
    /// Content hash (BLAKE3)
    pub hash: ContentHash,
    /// Whether this is executable (Unix)
    pub executable: bool,
}

/// Scanner for directory trees with gitignore support
pub struct Scanner {
    root: PathBuf,
    /// Additional ignore patterns beyond .gitignore
    extra_ignores: Vec<String>,
    /// Patterns to force-include even if gitignored (e.g., ".env")
    includes: Vec<String>,
}

/// Filename for include patterns (like .gitignore but for force-including)
pub const ZSYNC_INCLUDE_FILE: &str = ".zsyncinclude";

impl Scanner {
    /// Create a new scanner for the given root directory
    ///
    /// Automatically loads patterns from `.zsyncinclude` if present.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let mut includes = Vec::new();

        // Load .zsyncinclude if it exists
        let include_path = root.join(ZSYNC_INCLUDE_FILE);
        if let Ok(contents) = std::fs::read_to_string(&include_path) {
            for line in contents.lines() {
                let line = line.trim();
                // Skip empty lines and comments
                if !line.is_empty() && !line.starts_with('#') {
                    includes.push(line.to_string());
                }
            }
        }

        Self {
            root,
            extra_ignores: Vec::new(),
            includes,
        }
    }

    /// Add an extra ignore pattern
    #[must_use]
    pub fn ignore(mut self, pattern: impl Into<String>) -> Self {
        self.extra_ignores.push(pattern.into());
        self
    }

    /// Force-include a pattern even if it matches .gitignore
    ///
    /// Useful for syncing files like `.env` that are normally gitignored.
    #[must_use]
    pub fn include(mut self, pattern: impl Into<String>) -> Self {
        self.includes.push(pattern.into());
        self
    }

    /// Create a configured walk builder
    fn walk_builder(&self) -> WalkBuilder {
        let mut builder = WalkBuilder::new(&self.root);
        builder
            .hidden(false) // Include hidden files (e.g., .env.example)
            .git_ignore(true) // Respect .gitignore
            .git_global(true) // Respect global gitignore
            .git_exclude(true) // Respect .git/info/exclude
            .require_git(false) // Work even without .git directory
            .filter_entry(|e| e.file_name() != ".git");

        for pattern in &self.extra_ignores {
            builder.add_ignore(pattern);
        }

        builder
    }

    /// Build an override matcher for force-included patterns
    fn include_matcher(&self) -> Result<Option<ignore::overrides::Override>> {
        if self.includes.is_empty() {
            return Ok(None);
        }

        let mut overrides = OverrideBuilder::new(&self.root);
        for pattern in &self.includes {
            overrides.add(pattern)?;
        }
        Ok(Some(overrides.build()?))
    }

    /// Scan for files matching include patterns (bypassing gitignore)
    fn scan_includes(&self) -> Result<Vec<FileEntry>> {
        if self.includes.is_empty() {
            return Ok(Vec::new());
        }

        let matcher = self.include_matcher()?.unwrap();
        let mut entries = Vec::new();

        // Walk without gitignore to find included files
        let mut builder = WalkBuilder::new(&self.root);
        builder
            .hidden(false)
            .git_ignore(false) // Bypass gitignore for includes
            .git_global(false)
            .git_exclude(false)
            .require_git(false)
            .filter_entry(|e| e.file_name() != ".git");

        for result in builder.build() {
            let entry = result?;
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            let relative_path = path.strip_prefix(&self.root)?.to_path_buf();

            // Only include files matching our include patterns
            if matcher.matched(&relative_path, false).is_whitelist() {
                let metadata = std::fs::metadata(path)?;
                let hash = ContentHash::from_file(path)?;

                #[cfg(unix)]
                let executable = {
                    use std::os::unix::fs::PermissionsExt;
                    metadata.permissions().mode() & 0o111 != 0
                };
                #[cfg(not(unix))]
                let executable = false;

                entries.push(FileEntry {
                    path: relative_path,
                    size: metadata.len(),
                    modified: metadata.modified()?,
                    hash,
                    executable,
                });
            }
        }

        Ok(entries)
    }

    /// Scan the directory and return all file entries
    ///
    /// # Errors
    /// Returns an error if directory traversal or file reading fails
    pub fn scan(&self) -> Result<Vec<FileEntry>> {
        use std::collections::HashSet;

        let mut entries = Vec::new();
        let mut seen_paths: HashSet<PathBuf> = HashSet::new();

        // First, scan normally (respecting gitignore)
        for result in self.walk_builder().build() {
            let entry = result?;
            let path = entry.path();

            // Skip directories, only process files
            if !path.is_file() {
                continue;
            }

            let metadata = std::fs::metadata(path)?;
            let relative_path = path.strip_prefix(&self.root)?.to_path_buf();

            let hash = ContentHash::from_file(path)?;

            #[cfg(unix)]
            let executable = {
                use std::os::unix::fs::PermissionsExt;
                metadata.permissions().mode() & 0o111 != 0
            };
            #[cfg(not(unix))]
            let executable = false;

            seen_paths.insert(relative_path.clone());
            entries.push(FileEntry {
                path: relative_path,
                size: metadata.len(),
                modified: metadata.modified()?,
                hash,
                executable,
            });
        }

        // Then, add any force-included files that weren't already found
        for included in self.scan_includes()? {
            if !seen_paths.contains(&included.path) {
                entries.push(included);
            }
        }

        // Sort for deterministic ordering
        entries.sort_by(|a, b| a.path.cmp(&b.path));

        Ok(entries)
    }

    /// Scan and return only paths (faster, no hashing)
    ///
    /// # Errors
    /// Returns an error if directory traversal fails
    pub fn scan_paths(&self) -> Result<Vec<PathBuf>> {
        let mut paths = Vec::new();

        for result in self.walk_builder().build() {
            let entry = result?;
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            let relative_path = path.strip_prefix(&self.root)?.to_path_buf();
            paths.push(relative_path);
        }

        paths.sort();
        Ok(paths)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;
    use tempfile::TempDir;

    #[test]
    fn test_scan_simple_directory() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("file1.txt"), "hello").unwrap();
        fs::write(dir.path().join("file2.txt"), "world").unwrap();

        let scanner = Scanner::new(dir.path());
        let entries = scanner.scan().unwrap();

        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|e| e.path == Path::new("file1.txt")));
        assert!(entries.iter().any(|e| e.path == Path::new("file2.txt")));
    }

    #[test]
    fn test_scan_respects_gitignore() {
        let dir = TempDir::new().unwrap();
        // Need .git directory for ignore crate to recognize as git repo
        fs::create_dir(dir.path().join(".git")).unwrap();
        fs::write(dir.path().join(".gitignore"), "*.log\n").unwrap();
        fs::write(dir.path().join("keep.txt"), "keep").unwrap();
        fs::write(dir.path().join("ignore.log"), "ignore").unwrap();

        let scanner = Scanner::new(dir.path());
        let entries = scanner.scan().unwrap();

        // Should have .gitignore and keep.txt, but not ignore.log
        let paths: Vec<_> = entries.iter().map(|e| e.path.clone()).collect();
        assert!(
            paths.contains(&PathBuf::from("keep.txt")),
            "paths: {paths:?}"
        );
        assert!(
            paths.contains(&PathBuf::from(".gitignore")),
            "paths: {paths:?}"
        );
        assert!(
            !paths.contains(&PathBuf::from("ignore.log")),
            "paths: {paths:?}"
        );
    }

    #[test]
    fn test_scan_nested_directories() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("sub/dir")).unwrap();
        fs::write(dir.path().join("root.txt"), "root").unwrap();
        fs::write(dir.path().join("sub/nested.txt"), "nested").unwrap();
        fs::write(dir.path().join("sub/dir/deep.txt"), "deep").unwrap();

        let scanner = Scanner::new(dir.path());
        let entries = scanner.scan().unwrap();

        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn test_include_overrides_gitignore() {
        let dir = TempDir::new().unwrap();
        fs::create_dir(dir.path().join(".git")).unwrap();
        fs::write(dir.path().join(".gitignore"), ".env\n").unwrap();
        fs::write(dir.path().join(".env"), "SECRET=123").unwrap();
        fs::write(dir.path().join("keep.txt"), "keep").unwrap();

        // Without include, .env should be ignored
        let scanner = Scanner::new(dir.path());
        let entries = scanner.scan().unwrap();
        let paths: Vec<_> = entries.iter().map(|e| e.path.clone()).collect();
        assert!(
            !paths.contains(&PathBuf::from(".env")),
            ".env should be ignored: {paths:?}"
        );

        // With include, .env should be present
        let scanner = Scanner::new(dir.path()).include(".env");
        let entries = scanner.scan().unwrap();
        let paths: Vec<_> = entries.iter().map(|e| e.path.clone()).collect();
        assert!(
            paths.contains(&PathBuf::from(".env")),
            ".env should be included: {paths:?}"
        );
        assert!(
            paths.contains(&PathBuf::from("keep.txt")),
            "keep.txt should still be present: {paths:?}"
        );
    }

    #[test]
    fn test_zsyncinclude_file() {
        let dir = TempDir::new().unwrap();
        fs::create_dir(dir.path().join(".git")).unwrap();
        fs::write(dir.path().join(".gitignore"), ".env\nsecrets/\n").unwrap();
        fs::write(dir.path().join(".env"), "SECRET=123").unwrap();
        fs::create_dir(dir.path().join("secrets")).unwrap();
        fs::write(dir.path().join("secrets/key.pem"), "private").unwrap();
        fs::write(dir.path().join("keep.txt"), "keep").unwrap();

        // Create .zsyncinclude file
        fs::write(
            dir.path().join(".zsyncinclude"),
            "# Force include these files\n.env\nsecrets/key.pem\n",
        )
        .unwrap();

        // Scanner should auto-load .zsyncinclude
        let scanner = Scanner::new(dir.path());
        let entries = scanner.scan().unwrap();
        let paths: Vec<_> = entries.iter().map(|e| e.path.clone()).collect();

        assert!(
            paths.contains(&PathBuf::from(".env")),
            ".env should be included via .zsyncinclude: {paths:?}"
        );
        assert!(
            paths.contains(&PathBuf::from("secrets/key.pem")),
            "secrets/key.pem should be included via .zsyncinclude: {paths:?}"
        );
        assert!(
            paths.contains(&PathBuf::from("keep.txt")),
            "keep.txt should still be present: {paths:?}"
        );
    }
}
