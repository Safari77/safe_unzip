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
}

impl<'a> From<&Entry<'a>> for EntryInfo {
    fn from(entry: &Entry<'a>) -> Self {
        Self {
            name: entry.name.clone(),
            size: entry.size,
            kind: entry.kind.clone(),
            mode: entry.mode,
        }
    }
}
