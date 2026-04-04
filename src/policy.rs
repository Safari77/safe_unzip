//! Security policies for archive extraction.
//!
//! Policies validate entries before they are extracted, providing
//! protection against various archive-based attacks.

use std::path::{Component, Path, PathBuf};

use crate::entry::{EntryInfo, EntryKind};
use crate::error::Error;

/// State tracked during extraction for cumulative limit checks.
#[derive(Debug, Clone, Default)]
pub struct ExtractionState {
    /// Number of files extracted so far.
    pub files_extracted: usize,
    /// Number of directories created.
    pub dirs_created: usize,
    /// Total bytes written so far.
    pub bytes_written: u64,
    /// Entries skipped (symlinks, filtered, etc.).
    pub entries_skipped: usize,
    /// Tracking renames with --overwrite rename-{base,ext}
    pub renames: Vec<(String, String)>,
}

/// A security policy that validates entries before extraction.
pub trait Policy: Send + Sync {
    /// Validate an entry against this policy.
    ///
    /// Returns `Ok(())` if the entry passes, or an error if it violates the policy.
    fn check(&self, entry: &EntryInfo, state: &ExtractionState) -> Result<(), Error>;
}

/// A chain of policies that all must pass.
pub struct PolicyChain {
    policies: Vec<Box<dyn Policy>>,
}

impl PolicyChain {
    /// Create a new empty policy chain.
    pub fn new() -> Self {
        Self { policies: Vec::new() }
    }

    /// Add a policy to the chain.
    pub fn with<P: Policy + 'static>(mut self, policy: P) -> Self {
        self.policies.push(Box::new(policy));
        self
    }

    /// Check all policies against an entry.
    pub fn check_all(&self, entry: &EntryInfo, state: &ExtractionState) -> Result<(), Error> {
        for policy in &self.policies {
            policy.check(entry, state)?;
        }
        Ok(())
    }
}

impl Default for PolicyChain {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Path Security Policy
// ============================================================================

/// Policy that prevents path traversal attacks (Zip Slip).
pub struct PathPolicy {
    junk_paths: bool,
    allow_windows_reserved: bool,
}

impl PathPolicy {
    pub fn new<P: AsRef<Path>>(
        _destination: P,
        junk_paths: bool,
        allow_windows_reserved: bool,
    ) -> Result<Self, Error> {
        Ok(Self { junk_paths, allow_windows_reserved })
    }

    /// Validate a filename for security issues.
    fn validate_filename(name: &str, allow_windows_reserved: bool) -> Result<(), &'static str> {
        // Reject empty names
        if name.is_empty() {
            return Err("empty filename");
        }

        // Reject control characters (includes null bytes)
        if name.chars().any(|c| c.is_control()) {
            return Err("contains control characters");
        }

        // Reject backslashes (Windows path separator could bypass Unix checks)
        if name.contains('\\') {
            return Err("contains backslash");
        }

        // Reject extremely long filenames
        if name.len() > 1024 {
            return Err("path too long (>1024 bytes)");
        }

        if name.split('/').any(|component| component.len() > 255) {
            return Err("path component too long (>255 bytes)");
        }

        // Possibly reject Windows reserved names
        if !allow_windows_reserved {
            for component in Path::new(name).components() {
                if let Component::Normal(s) = component
                    && let Some(s) = s.to_str()
                {
                    let s_upper = s.to_ascii_uppercase();
                    let file_stem = s_upper.split('.').next().unwrap_or(&s_upper);

                    match file_stem {
                        "CON" | "PRN" | "AUX" | "NUL" | "COM1" | "COM2" | "COM3" | "COM4"
                        | "COM5" | "COM6" | "COM7" | "COM8" | "COM9" | "LPT1" | "LPT2" | "LPT3"
                        | "LPT4" | "LPT5" | "LPT6" | "LPT7" | "LPT8" | "LPT9" => {
                            return Err("Windows reserved name");
                        }
                        _ => {}
                    }
                }
            }
        }

        Ok(())
    }
}

impl Policy for PathPolicy {
    fn check(&self, entry: &EntryInfo, _state: &ExtractionState) -> Result<(), Error> {
        if let Err(reason) = Self::validate_filename(&entry.name, self.allow_windows_reserved) {
            return Err(Error::InvalidFilename {
                entry: entry.name.clone(),
                reason: reason.to_string(),
            });
        }

        // 2. If junk_paths is enabled, all directories are stripped natively.
        // We can safely bypass the traversal checks because we only extract the filename.
        if self.junk_paths {
            return Ok(());
        }

        let path = Path::new(&entry.name);
        for comp in path.components() {
            match comp {
                Component::ParentDir => {
                    return Err(Error::PathEscape {
                        entry: entry.name.clone(),
                        detail: "Contains parent directory (..) component".to_string(),
                    });
                }
                Component::RootDir | Component::Prefix(_) => {
                    return Err(Error::PathEscape {
                        entry: entry.name.clone(),
                        detail: "Contains absolute path component".to_string(),
                    });
                }
                _ => {}
            }
        }
        Ok(())
    }
}

// ============================================================================
// Size Limits Policy
// ============================================================================

/// Policy that enforces size limits to prevent zip bombs.
pub struct SizePolicy {
    /// Maximum size of a single file.
    pub max_single_file: u64,
    /// Maximum total bytes across all files.
    pub max_total: u64,
}

impl SizePolicy {
    /// Create a new size policy with the given limits.
    pub fn new(max_single_file: u64, max_total: u64) -> Self {
        Self { max_single_file, max_total }
    }
}

impl Policy for SizePolicy {
    fn check(&self, entry: &EntryInfo, state: &ExtractionState) -> Result<(), Error> {
        // Check single file limit
        if entry.size > self.max_single_file {
            return Err(Error::FileTooLarge {
                entry: entry.name.clone(),
                limit: self.max_single_file,
                size: entry.size,
            });
        }

        // Check total size limit
        if state.bytes_written + entry.size > self.max_total {
            return Err(Error::TotalSizeExceeded {
                limit: self.max_total,
                would_be: state.bytes_written + entry.size,
            });
        }

        Ok(())
    }
}

// ============================================================================
// File Count Policy
// ============================================================================

/// Policy that enforces a maximum file count.
pub struct CountPolicy {
    /// Maximum number of files.
    pub max_files: usize,
}

impl CountPolicy {
    /// Create a new count policy.
    pub fn new(max_files: usize) -> Self {
        Self { max_files }
    }
}

impl Policy for CountPolicy {
    fn check(&self, _entry: &EntryInfo, state: &ExtractionState) -> Result<(), Error> {
        if state.files_extracted >= self.max_files {
            return Err(Error::FileCountExceeded {
                limit: self.max_files,
                attempted: state.files_extracted + 1,
            });
        }
        Ok(())
    }
}

// ============================================================================
// Path Depth Policy
// ============================================================================

/// Policy that enforces a maximum path depth.
pub struct DepthPolicy {
    /// Maximum directory depth.
    pub max_depth: usize,
}

impl DepthPolicy {
    /// Create a new depth policy.
    pub fn new(max_depth: usize) -> Self {
        Self { max_depth }
    }
}

impl Policy for DepthPolicy {
    fn check(&self, entry: &EntryInfo, _state: &ExtractionState) -> Result<(), Error> {
        let depth = Path::new(&entry.name).components().count();
        if depth > self.max_depth {
            return Err(Error::PathTooDeep {
                entry: entry.name.clone(),
                depth,
                limit: self.max_depth,
            });
        }
        Ok(())
    }
}

// ============================================================================
// Symlink Policy
// ============================================================================

/// What to do when encountering a symlink.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SymlinkBehavior {
    /// Skip symlinks silently.
    #[default]
    Skip,
    /// Return an error if a symlink is encountered.
    Error,
}

/// Policy that handles symlinks in archives.
pub struct SymlinkPolicy {
    /// What to do with symlinks.
    pub behavior: SymlinkBehavior,
}

impl SymlinkPolicy {
    /// Create a new symlink policy.
    pub fn new(behavior: SymlinkBehavior) -> Self {
        Self { behavior }
    }
}

impl Policy for SymlinkPolicy {
    fn check(&self, entry: &EntryInfo, _state: &ExtractionState) -> Result<(), Error> {
        if let EntryKind::Symlink { target } = &entry.kind {
            match self.behavior {
                SymlinkBehavior::Skip => {
                    // This will be handled by the extractor by skipping
                    // We don't error here, just let the extractor know to skip
                }
                SymlinkBehavior::Error => {
                    return Err(Error::SymlinkNotAllowed {
                        entry: entry.name.clone(),
                        target: target.clone(),
                    });
                }
            }
        }
        Ok(())
    }
}

// ============================================================================
// Default Policy Chain Builder
// ============================================================================

/// Configuration for building a default policy chain.
#[derive(Debug, Clone)]
pub struct PolicyConfig {
    pub destination: PathBuf,
    pub max_single_file: u64,
    pub max_total: u64,
    pub max_files: usize,
    pub max_depth: usize,
    pub symlink_behavior: SymlinkBehavior,
    pub allow_windows_reserved: bool,
}

impl PolicyConfig {
    /// Build a policy chain from this configuration.
    pub fn build(&self) -> Result<PolicyChain, Error> {
        Ok(PolicyChain::new()
            .with(PathPolicy::new(&self.destination, false, self.allow_windows_reserved)?)
            .with(SizePolicy::new(self.max_single_file, self.max_total))
            .with(CountPolicy::new(self.max_files))
            .with(DepthPolicy::new(self.max_depth))
            .with(SymlinkPolicy::new(self.symlink_behavior)))
    }
}
