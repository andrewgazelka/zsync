//! File scanning with gitignore support via the `ignore` crate

use std::path::PathBuf;
use std::time::SystemTime;

use color_eyre::Result;
use color_eyre::eyre::WrapErr as _;
use ignore::WalkBuilder;
use ignore::overrides::OverrideBuilder;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::config::ZsyncConfig;
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
    /// Unix permission mode bits (e.g., 0o755, 0o644)
    pub mode: u32,
}

/// Scanner for directory trees with gitignore support
pub struct Scanner {
    root: PathBuf,
    /// Additional ignore patterns beyond .gitignore
    extra_ignores: Vec<String>,
    /// Patterns to force-include even if gitignored (e.g., ".env")
    includes: Vec<String>,
}

impl Scanner {
    /// Create a new scanner for the given root directory
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            extra_ignores: Vec::new(),
            includes: Vec::new(),
        }
    }

    /// Create a new scanner with includes from .zsync.toml config
    #[must_use]
    pub fn with_config(root: impl Into<PathBuf>, config: &ZsyncConfig) -> Self {
        Self {
            root: root.into(),
            extra_ignores: Vec::new(),
            includes: config.include.clone(),
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

        // Walk without gitignore to find included files
        let mut builder = WalkBuilder::new(&self.root);
        builder
            .hidden(false)
            .git_ignore(false) // Bypass gitignore for includes
            .git_global(false)
            .git_exclude(false)
            .require_git(false)
            .filter_entry(|e| e.file_name() != ".git");

        // Collect matching file paths first (cheap)
        let paths: Vec<_> = builder
            .build()
            .filter_map(std::result::Result::ok)
            .filter_map(|entry| {
                let path = entry.into_path();
                if !path.is_file() {
                    return None;
                }
                let relative_path = path.strip_prefix(&self.root).ok()?.to_path_buf();
                if matcher.matched(&relative_path, false).is_whitelist() {
                    Some((path, relative_path))
                } else {
                    None
                }
            })
            .collect();

        // Hash files in parallel
        paths
            .into_par_iter()
            .map(|(path, relative_path)| {
                let metadata = std::fs::metadata(&path)
                    .wrap_err_with(|| format!("failed to read metadata for {}", path.display()))?;
                let hash = ContentHash::from_file(&path)
                    .wrap_err_with(|| format!("failed to hash {}", path.display()))?;

                #[cfg(unix)]
                let mode = {
                    use std::os::unix::fs::PermissionsExt as _;
                    metadata.permissions().mode() & 0o7777
                };
                #[cfg(not(unix))]
                let mode = 0o644;

                Ok(FileEntry {
                    path: relative_path,
                    size: metadata.len(),
                    modified: metadata.modified()?,
                    hash,
                    mode,
                })
            })
            .collect()
    }

    /// Scan the directory and return all file entries
    ///
    /// # Errors
    /// Returns an error if directory traversal or file reading fails
    pub fn scan(&self) -> Result<Vec<FileEntry>> {
        use std::collections::HashSet;

        // Collect file paths first (cheap directory walk)
        let paths: Vec<_> = self
            .walk_builder()
            .build()
            .filter_map(std::result::Result::ok)
            .filter_map(|entry| {
                let path = entry.into_path();
                if !path.is_file() {
                    return None;
                }
                let relative_path = path.strip_prefix(&self.root).ok()?.to_path_buf();
                Some((path, relative_path))
            })
            .collect();

        // Hash files in parallel (expensive I/O + CPU)
        let mut entries: Vec<FileEntry> = paths
            .into_par_iter()
            .map(|(path, relative_path)| {
                let metadata = std::fs::metadata(&path)
                    .wrap_err_with(|| format!("failed to read metadata for {}", path.display()))?;
                let hash = ContentHash::from_file(&path)
                    .wrap_err_with(|| format!("failed to hash {}", path.display()))?;

                #[cfg(unix)]
                let mode = {
                    use std::os::unix::fs::PermissionsExt as _;
                    metadata.permissions().mode() & 0o7777
                };
                #[cfg(not(unix))]
                let mode = 0o644;

                Ok(FileEntry {
                    path: relative_path,
                    size: metadata.len(),
                    modified: metadata.modified()?,
                    hash,
                    mode,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        // Build set of seen paths for deduplication
        let seen_paths: HashSet<PathBuf> = entries.iter().map(|e| e.path.clone()).collect();

        // Add any force-included files that weren't already found
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

    /// Scan only specific files (by relative path).
    ///
    /// This is much faster than a full scan when only a few files changed.
    /// Files that don't exist are silently skipped.
    ///
    /// # Errors
    /// Returns an error if file reading or hashing fails
    pub fn scan_files(&self, relative_paths: &[&std::path::Path]) -> Result<Vec<FileEntry>> {
        let entries: Vec<FileEntry> = relative_paths
            .into_par_iter()
            .filter_map(|relative_path| {
                let absolute_path = self.root.join(relative_path);

                // Skip if file doesn't exist (was deleted)
                if !absolute_path.is_file() {
                    return None;
                }

                let Ok(metadata) = std::fs::metadata(&absolute_path) else {
                    return None;
                };

                let Ok(hash) = ContentHash::from_file(&absolute_path) else {
                    return None;
                };

                #[cfg(unix)]
                let mode = {
                    use std::os::unix::fs::PermissionsExt as _;
                    metadata.permissions().mode() & 0o7777
                };
                #[cfg(not(unix))]
                let mode = 0o644;

                Some(FileEntry {
                    path: relative_path.to_path_buf(),
                    size: metadata.len(),
                    modified: metadata.modified().ok()?,
                    hash,
                    mode,
                })
            })
            .collect();

        Ok(entries)
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
    fn test_zsync_toml_config() {
        let dir = TempDir::new().unwrap();
        fs::create_dir(dir.path().join(".git")).unwrap();
        fs::write(dir.path().join(".gitignore"), ".env\nsecrets/\n").unwrap();
        fs::write(dir.path().join(".env"), "SECRET=123").unwrap();
        fs::create_dir(dir.path().join("secrets")).unwrap();
        fs::write(dir.path().join("secrets/key.pem"), "private").unwrap();
        fs::write(dir.path().join("keep.txt"), "keep").unwrap();

        // Create .zsync.toml config file
        fs::write(
            dir.path().join(".zsync.toml"),
            r#"
include = [".env", "secrets/key.pem"]
"#,
        )
        .unwrap();

        // Load config and create scanner
        let config = ZsyncConfig::load(dir.path()).unwrap();
        let scanner = Scanner::with_config(dir.path(), &config);
        let entries = scanner.scan().unwrap();
        let paths: Vec<_> = entries.iter().map(|e| e.path.clone()).collect();

        assert!(
            paths.contains(&PathBuf::from(".env")),
            ".env should be included via .zsync.toml: {paths:?}"
        );
        assert!(
            paths.contains(&PathBuf::from("secrets/key.pem")),
            "secrets/key.pem should be included via .zsync.toml: {paths:?}"
        );
        assert!(
            paths.contains(&PathBuf::from("keep.txt")),
            "keep.txt should still be present: {paths:?}"
        );
    }

    #[test]
    fn test_scan_ignores_target_directory() {
        let dir = TempDir::new().unwrap();
        // Create .git to make ignore crate recognize this as a git repo
        fs::create_dir(dir.path().join(".git")).unwrap();
        // Create .gitignore with target
        fs::write(dir.path().join(".gitignore"), "target\n").unwrap();
        // Create target directory with nested files (like cargo does)
        fs::create_dir_all(dir.path().join("target/debug/build/foo")).unwrap();
        fs::write(
            dir.path().join("target/debug/build/foo/build-script"),
            "binary",
        )
        .unwrap();
        // Create a normal file
        fs::write(dir.path().join("src.rs"), "fn main() {}").unwrap();

        let scanner = Scanner::new(dir.path());
        let entries = scanner.scan().unwrap();
        let paths: Vec<_> = entries.iter().map(|e| e.path.clone()).collect();

        // src.rs and .gitignore should be present
        assert!(
            paths.contains(&PathBuf::from("src.rs")),
            "src.rs should be present: {paths:?}"
        );
        assert!(
            paths.contains(&PathBuf::from(".gitignore")),
            ".gitignore should be present: {paths:?}"
        );
        // target files should NOT be present
        assert!(
            !paths.iter().any(|p| p.starts_with("target")),
            "target/ files should be ignored: {paths:?}"
        );
    }

    #[test]
    fn test_gitignore_builder_matches_nested_paths() {
        use ignore::gitignore::GitignoreBuilder;

        let dir = TempDir::new().unwrap();
        fs::create_dir(dir.path().join(".git")).unwrap();
        fs::write(dir.path().join(".gitignore"), "target\n").unwrap();

        let mut builder = GitignoreBuilder::new(dir.path());
        builder.add(dir.path().join(".gitignore"));
        let gitignore = builder.build().unwrap();

        // Test direct match
        let target_match = gitignore.matched(Path::new("target"), true);
        assert!(target_match.is_ignore(), "target/ should be ignored");

        // Test nested path match
        let nested_match =
            gitignore.matched(Path::new("target/debug/build/foo/build-script"), false);
        assert!(
            nested_match.is_ignore(),
            "target/debug/build/foo/build-script should be ignored, got: {:?}",
            nested_match
        );
    }
}
