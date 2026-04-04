//! Generic archive entry representation.
//!
//! This module defines the common `Entry` type that all archive adapters
//! produce, enabling format-agnostic security policies.

use std::io::Read;
use std::path::Path;

/// The type of entry in an archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryKind {
    /// A regular file.
    File,
    /// A directory.
    Directory,
    /// A symbolic link pointing to a target path.
    Symlink { target: String },
}

/// A single entry in an archive.
///
/// This is the format-agnostic representation that all adapters produce.
/// Security policies operate on this struct, not on format-specific types.
pub struct Entry<'a> {
    /// The path/name of the entry within the archive.
    pub name: String,
    /// The uncompressed size in bytes (may be declared, not actual).
    pub size: u64,
    /// The type of entry (file, directory, symlink).
    pub kind: EntryKind,
    /// Unix permissions (if available).
    pub mode: Option<u32>,
    /// Modification time
    pub mtime: Option<u64>,
    /// A reader to access the entry's content.
    pub reader: Box<dyn Read + 'a>,
}

impl<'a> Entry<'a> {
    /// Returns true if this entry is a regular file.
    pub fn is_file(&self) -> bool {
        matches!(self.kind, EntryKind::File)
    }

    /// Returns true if this entry is a directory.
    pub fn is_dir(&self) -> bool {
        matches!(self.kind, EntryKind::Directory)
    }

    /// Returns true if this entry is a symbolic link.
    pub fn is_symlink(&self) -> bool {
        matches!(self.kind, EntryKind::Symlink { .. })
    }

    /// Returns the symlink target if this is a symlink.
    pub fn symlink_target(&self) -> Option<&str> {
        match &self.kind {
            EntryKind::Symlink { target } => Some(target),
            _ => None,
        }
    }

    /// Returns the depth of the entry path (number of components).
    pub fn depth(&self) -> usize {
        Path::new(&self.name).components().count()
    }
}

/// Information about an entry for policy decisions (without the reader).
///
/// Used for validation passes where we don't need to read content.
#[derive(Debug, Clone)]
pub struct EntryInfo {
    /// The path/name of the entry within the archive.
    pub name: String,
    /// The uncompressed size in bytes.
    pub size: u64,
    /// The type of entry.
    pub kind: EntryKind,
    /// Unix permissions (if available).
    pub mode: Option<u32>,
    /// Restored file modification time
    pub mtime: Option<u64>,
}

impl<'a> From<&Entry<'a>> for EntryInfo {
    fn from(entry: &Entry<'a>) -> Self {
        Self {
            name: entry.name.clone(),
            size: entry.size,
            kind: entry.kind.clone(),
            mode: entry.mode,
            mtime: entry.mtime,
        }
    }
}

/// Securely applies the modified time to an open file descriptor,
/// preventing symlink TOC-TOU attacks.
pub(crate) fn restore_file_times(file: std::fs::File, mtime: Option<u64>, name: &str) {
    if let Some(m) = mtime {
        let st = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(m);
        if let Err(e) = file.set_modified(st) {
            eprintln!("Warning: Could not set timestamp for {}: {}", name, e);
        }
    } else {
        eprintln!("Warning: No valid timestamp found in archive for {}", name);
    }
    // `file` drops here, securely closing the file descriptor.
}

/// Securely creates a directory path using cap_std and applies dir_mode to each newly created component.
pub(crate) fn ensure_directory(
    dir: &cap_std::fs_utf8::Dir,
    path: &str,
    dir_mode: Option<u32>,
) -> Result<(), crate::error::Error> {
    let utf8_path = camino::Utf8Path::new(path);
    let mut current = camino::Utf8PathBuf::new();

    for component in utf8_path.components() {
        current.push(component);
        if current.as_str().is_empty() || current.as_str() == "/" {
            continue;
        }

        match dir.create_dir(&current) {
            Ok(()) => {
                #[cfg(unix)]
                if let Some(mode) = dir_mode {
                    // Scope cap_std's PermissionsExt trait locally
                    use cap_std::fs::PermissionsExt;
                    let safe_mode = mode & 0o0777;
                    // Ignore errors here, as cap-std will block unsafe traversal anyway
                    let _ = dir
                        .set_permissions(&current, cap_std::fs::Permissions::from_mode(safe_mode));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
