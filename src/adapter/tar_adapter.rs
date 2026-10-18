//! TAR archive adapter.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use flate2::read::GzDecoder;

use crate::entry::{EntryInfo, EntryKind};
use crate::error::Error;

/// Adapter for TAR archives.
///
/// Supports both plain `.tar` and gzip-compressed `.tar.gz` / `.tgz` files.
///
/// Unlike ZIP, TAR is a sequential format without a central directory.
/// This means:
/// - Entries must be read in order
/// - `ValidateFirst` mode requires reading the entire archive twice
/// - Random access to entries is not supported
pub struct TarAdapter<R: Read> {
    archive: tar::Archive<R>,
    /// Cached entries for validation mode (read once, extract later)
    cached_entries: Option<Vec<CachedEntry>>,
}

/// Cached entry data for two-pass extraction.
struct CachedEntry {
    info: EntryInfo,
    data: Vec<u8>,
}

impl<R: Read> TarAdapter<R> {
    /// Create a new TarAdapter from a reader.
    ///
    /// For `.tar.gz` files, wrap the reader in `GzDecoder` first,
    /// or use `TarAdapter::open_gz()`.
    pub fn new(reader: R) -> Self {
        Self { archive: tar::Archive::new(reader), cached_entries: None }
    }

    /// Process each entry with a callback.
    ///
    /// TAR is sequential, so entries are processed in order.
    /// The callback receives entry info and a reader for the content.
    ///
    /// Return `Ok(true)` to continue, `Ok(false)` to stop, or `Err` to abort.
    pub fn for_each<F>(&mut self, mut callback: F) -> Result<(), Error>
    where
        F: FnMut(EntryInfo, Option<&mut dyn Read>) -> Result<bool, Error>,
    {
        let entries = self.archive.entries()?;

        for entry_result in entries {
            let mut entry = entry_result?;
            let header = entry.header();

            let name = entry.path()?.to_string_lossy().into_owned();

            let entry_type = header.entry_type();
            let kind = match entry_type {
                tar::EntryType::Regular | tar::EntryType::Continuous => EntryKind::File,
                tar::EntryType::Directory => EntryKind::Directory,
                tar::EntryType::Symlink => {
                    let target = entry
                        .link_name()?
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    EntryKind::Symlink { target }
                }
                tar::EntryType::Link => {
                    let target = entry
                        .link_name()?
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    EntryKind::Hardlink { target }
                }
                // Reject device files, fifos, etc. - these are security risks
                other => {
                    return Err(Error::UnsupportedEntryType {
                        entry: name,
                        entry_type: entry_type_name(other),
                    });
                }
            };

            let info = EntryInfo {
                name,
                size: header.size()?,
                kind: kind.clone(),
                mode: header.mode().ok(),
                mtime: header.mtime().ok(),
            };

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

    /// Read all entries into memory for validation.
    ///
    /// This is used by `ValidateFirst` mode to check all entries
    /// before extracting any. The data is cached for later extraction.
    ///
    /// Note that this buffers the whole archive in memory. Prefer
    /// [`Self::cache_all_limited`] so a malicious archive cannot exhaust RAM
    /// before the policy chain gets a chance to reject it.
    pub fn cache_all(&mut self) -> Result<Vec<EntryInfo>, Error> {
        self.cache_all_limited(u64::MAX, u64::MAX)
    }

    /// Read all entries into memory, refusing archives larger than the limits.
    ///
    /// `ValidateFirst` has to buffer content before it can validate it, so the
    /// size limits are enforced here as well as in the policy chain -- otherwise
    /// a tar bomb would OOM the process before any policy ran.
    pub fn cache_all_limited(
        &mut self,
        max_single_file: u64,
        max_total_bytes: u64,
    ) -> Result<Vec<EntryInfo>, Error> {
        let mut entries = Vec::new();
        let mut cached = Vec::new();
        let mut total_bytes: u64 = 0;

        let tar_entries = self.archive.entries()?;

        for entry_result in tar_entries {
            let mut entry = entry_result?;
            let header = entry.header();

            let name = entry.path()?.to_string_lossy().into_owned();

            let entry_type = header.entry_type();
            let kind = match entry_type {
                tar::EntryType::Regular | tar::EntryType::Continuous => EntryKind::File,
                tar::EntryType::Directory => EntryKind::Directory,
                tar::EntryType::Symlink => {
                    let target = entry
                        .link_name()?
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    EntryKind::Symlink { target }
                }
                tar::EntryType::Link => {
                    let target = entry
                        .link_name()?
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    EntryKind::Hardlink { target }
                }
                // Reject device files, fifos, etc. - these are security risks
                other => {
                    return Err(Error::UnsupportedEntryType {
                        entry: name,
                        entry_type: entry_type_name(other),
                    });
                }
            };

            let info = EntryInfo {
                name: name.clone(),
                size: header.size()?,
                kind: kind.clone(),
                mode: header.mode().ok(),
                mtime: header.mtime().ok(),
            };

            // Read file content into memory
            let mut data = Vec::new();
            if matches!(kind, EntryKind::File) {
                if info.size > max_single_file {
                    return Err(Error::FileTooLarge {
                        entry: name,
                        limit: max_single_file,
                        size: info.size,
                    });
                }

                let would_be = total_bytes.saturating_add(info.size);
                if would_be > max_total_bytes {
                    return Err(Error::TotalSizeExceeded { limit: max_total_bytes, would_be });
                }

                // Read at most the declared size: a header that understates the
                // real content must not be able to grow the buffer past the limit.
                let read = super::copy_limited(&mut entry, &mut data, info.size)?;
                if read < info.size {
                    return Err(Error::Io(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        format!(
                            "entry '{}' ended after {} of {} declared bytes",
                            name, read, info.size
                        ),
                    )));
                }

                if read == info.size && super::has_more_data(&mut entry)? {
                    return Err(Error::SizeMismatch {
                        entry: name,
                        declared: info.size,
                        actual: read.saturating_add(1),
                    });
                }
                total_bytes = total_bytes.saturating_add(read);
            }

            entries.push(info.clone());
            cached.push(CachedEntry { info, data });
        }

        self.cached_entries = Some(cached);
        Ok(entries)
    }

    /// Extract cached entries (after cache_all was called).
    pub fn extract_cached<F>(&mut self, mut callback: F) -> Result<(), Error>
    where
        F: FnMut(EntryInfo, Option<&[u8]>) -> Result<bool, Error>,
    {
        let cached = self.cached_entries.take().ok_or_else(|| {
            Error::Io(std::io::Error::other("no cached entries (call cache_all first)"))
        })?;

        for entry in cached {
            let data = if matches!(entry.info.kind, EntryKind::File) {
                Some(entry.data.as_slice())
            } else {
                None
            };

            if !callback(entry.info, data)? {
                break;
            }
        }

        Ok(())
    }
}

impl TarAdapter<BufReader<File>> {
    /// Open a plain TAR file from a path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        Ok(Self::new(reader))
    }
}

impl TarAdapter<GzDecoder<BufReader<File>>> {
    /// Open a gzip-compressed TAR file (.tar.gz, .tgz) from a path.
    pub fn open_gz<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let decoder = GzDecoder::new(reader);
        Ok(Self::new(decoder))
    }
}

/// Convert TAR entry type to a human-readable name.
fn entry_type_name(entry_type: tar::EntryType) -> String {
    match entry_type {
        tar::EntryType::Regular => "regular file".into(),
        tar::EntryType::Link => "hard link".into(),
        tar::EntryType::Symlink => "symbolic link".into(),
        tar::EntryType::Char => "character device".into(),
        tar::EntryType::Block => "block device".into(),
        tar::EntryType::Directory => "directory".into(),
        tar::EntryType::Fifo => "fifo (named pipe)".into(),
        tar::EntryType::Continuous => "continuous file".into(),
        tar::EntryType::GNULongName => "GNU long name".into(),
        tar::EntryType::GNULongLink => "GNU long link".into(),
        tar::EntryType::GNUSparse => "GNU sparse file".into(),
        _ => format!("unknown (0x{:02x})", entry_type.as_byte()),
    }
}
