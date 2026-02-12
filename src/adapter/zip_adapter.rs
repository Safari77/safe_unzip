//! ZIP archive adapter.

use std::fs::File;
use std::io::{BufReader, Read, Seek, Write};
use std::path::Path;

use crate::entry::{EntryInfo, EntryKind};
use crate::error::Error;

/// Adapter for ZIP archives.
///
/// Wraps the `zip` crate and provides a format-agnostic interface for extraction.
pub struct ZipAdapter<R> {
    archive: zip::ZipArchive<R>,
    password: Option<Vec<u8>>,
}

impl<R: Read + Seek> ZipAdapter<R> {
    /// Create a new ZipAdapter from a reader.
    pub fn new(reader: R) -> Result<Self, Error> {
        let archive = zip::ZipArchive::new(reader)?;
        Ok(Self {
            archive,
            password: None,
        })
    }

    pub fn password<P: AsRef<[u8]>>(&mut self, password: Option<P>) {
        self.password = password.map(|p| p.as_ref().to_vec());
    }

    /// Returns the number of entries in the archive.
    pub fn len(&self) -> usize {
        self.archive.len()
    }

    /// Returns true if the archive is empty.
    pub fn is_empty(&self) -> bool {
        self.archive.is_empty()
    }

    /// Get all entry metadata without decompressing (for validation).
    ///
    /// Uses `by_index_raw()` to read only headers, not content.
    ///
    /// # Errors
    ///
    /// Returns `Error::EncryptedEntry` if any entry is encrypted.
    pub fn entries_metadata(&mut self) -> Result<Vec<EntryInfo>, Error> {
        let mut entries = Vec::with_capacity(self.archive.len());

        for i in 0..self.archive.len() {
            let entry = self.archive.by_index_raw(i)?;
            let name = entry.name().to_string();

            // Reject encrypted entries
            if entry.encrypted() {
                return Err(Error::EncryptedEntry { entry: name });
            }

            let kind = if entry.is_dir() {
                EntryKind::Directory
            } else if entry.is_symlink() {
                EntryKind::Symlink {
                    target: String::new(), // Can't read target without decompressing
                }
            } else {
                EntryKind::File
            };

            entries.push(EntryInfo {
                name,
                size: entry.size(),
                kind,
                mode: entry.unix_mode(),
            });
        }

        Ok(entries)
    }

    /// Process each entry with a callback.
    ///
    /// This design works around the zip crate's lifetime constraints by
    /// processing entries one at a time through a callback.
    ///
    /// The callback receives:
    /// - `info`: Entry metadata for policy decisions
    /// - `reader`: A reader to access the entry's content (only for files)
    ///
    /// Return `Ok(true)` to continue, `Ok(false)` to stop, or `Err` to abort.
    ///
    /// # Errors
    ///
    /// Returns `Error::EncryptedEntry` if any entry is encrypted.
    pub fn for_each<F>(&mut self, mut callback: F) -> Result<(), Error>
    where
        F: FnMut(EntryInfo, Option<&mut dyn Read>) -> Result<bool, Error>,
    {
        for i in 0..self.archive.len() {
            let mut entry = match &self.password {
                Some(pwd) => self.archive.by_index_decrypt(i, pwd)?,
                None => self.archive.by_index(i)?,
            };
            let name = entry.name().to_string();

            // Reject encrypted entries
            if entry.encrypted() {
                return Err(Error::EncryptedEntry { entry: name });
            }

            // Determine entry kind and read symlink target if applicable
            let kind = if entry.is_dir() {
                EntryKind::Directory
            } else if entry.is_symlink() {
                let mut target = String::new();
                entry.read_to_string(&mut target)?;
                EntryKind::Symlink { target }
            } else {
                EntryKind::File
            };

            let info = EntryInfo {
                name,
                size: entry.size(),
                kind: kind.clone(),
                mode: entry.unix_mode(),
            };

            // For files, provide the reader; for dirs/symlinks, no reader needed
            let continue_extraction = if matches!(kind, EntryKind::File) {
                callback(info, Some(&mut entry))?
            } else {
                callback(info, None)?
            };

            if !continue_extraction {
                break;
            }
        }

        Ok(())
    }

    /// Extract a single entry by index, writing to the provided writer.
    ///
    /// Returns the entry info and number of bytes written.
    ///
    /// # Errors
    ///
    /// Returns `Error::EncryptedEntry` if the entry is encrypted.
    pub fn extract_to<W: Write>(
        &mut self,
        index: usize,
        writer: &mut W,
        limit: u64,
    ) -> Result<(EntryInfo, u64), Error> {
        let mut entry = match &self.password {
            Some(pwd) => self.archive.by_index_decrypt(index, pwd)?,
            None => self.archive.by_index(index)?,
        };

        let name = entry.name().to_string();

        // Reject encrypted entries
        if entry.encrypted() && self.password.is_none() {
            return Err(Error::EncryptedEntry { entry: name });
        }

        let kind = if entry.is_dir() {
            EntryKind::Directory
        } else if entry.is_symlink() {
            let mut target = String::new();
            entry.read_to_string(&mut target)?;
            EntryKind::Symlink { target }
        } else {
            EntryKind::File
        };

        let info = EntryInfo {
            name,
            size: entry.size(),
            kind: kind.clone(),
            mode: entry.unix_mode(),
        };

        let bytes_written = if matches!(kind, EntryKind::File) {
            copy_limited(&mut entry, writer, limit)?
        } else {
            0
        };

        Ok((info, bytes_written))
    }

    /// Get entry info by index without reading content.
    ///
    /// # Errors
    ///
    /// Returns `Error::EncryptedEntry` if the entry is encrypted.
    pub fn entry_info(&mut self, index: usize) -> Result<EntryInfo, Error> {
        let entry = self.archive.by_index_raw(index)?;
        let name = entry.name().to_string();

        // Reject encrypted entries
        if entry.encrypted() {
            return Err(Error::EncryptedEntry { entry: name });
        }

        let kind = if entry.is_dir() {
            EntryKind::Directory
        } else if entry.is_symlink() {
            EntryKind::Symlink {
                target: String::new(),
            }
        } else {
            EntryKind::File
        };

        Ok(EntryInfo {
            name,
            size: entry.size(),
            kind,
            mode: entry.unix_mode(),
        })
    }
}

impl ZipAdapter<BufReader<File>> {
    /// Open a ZIP file from a path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        Self::new(reader)
    }
}

/// Copy with a byte limit, returning bytes written.
fn copy_limited<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    limit: u64,
) -> Result<u64, Error> {
    let mut total = 0u64;
    let mut buf = [0u8; 8192];

    loop {
        let remaining = limit.saturating_sub(total);
        if remaining == 0 {
            break;
        }

        let to_read = buf.len().min(remaining as usize);
        let n = reader.read(&mut buf[..to_read])?;
        if n == 0 {
            break;
        }

        writer.write_all(&buf[..n])?;
        total += n as u64;
    }

    Ok(total)
}
