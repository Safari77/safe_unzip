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
        Ok(Self { archive, password: None })
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
    /// Returns `Error::EncryptedEntry` if any entry is encrypted and no
    /// password was set via [`Self::password`].
    pub fn entries_metadata(&mut self) -> Result<Vec<EntryInfo>, Error> {
        let mut entries = Vec::with_capacity(self.archive.len());

        for i in 0..self.archive.len() {
            let entry = self.archive.by_index_raw(i)?;
            let name = entry.name()?.into_owned();

            // Reject encrypted entries we have no way of reading
            if entry.encrypted() && self.password.is_none() {
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
                mtime: zip_time_to_timestamp(entry.last_modified()),
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
    /// Returns `Error::EncryptedEntry` if any entry is encrypted and no
    /// password was set via [`Self::password`].
    pub fn for_each<F>(&mut self, mut callback: F) -> Result<(), Error>
    where
        F: FnMut(EntryInfo, Option<&mut dyn Read>) -> Result<bool, Error>,
    {
        for i in 0..self.archive.len() {
            // Check encryption status via raw metadata and drop borrow before decrypting
            let (is_encrypted, raw_name) = {
                let raw_entry = self.archive.by_index_raw(i)?;
                (raw_entry.encrypted(), raw_entry.name()?.to_string())
            };
            if is_encrypted && self.password.is_none() {
                return Err(Error::EncryptedEntry { entry: raw_name });
            }

            let mut entry = match &self.password {
                Some(pwd) => self.archive.by_index_decrypt(i, pwd)?,
                None => self.archive.by_index(i)?,
            };
            let name = entry.name()?.into_owned();

            // Determine entry kind and read symlink target if applicable
            let kind = if entry.is_dir() {
                EntryKind::Directory
            } else if entry.is_symlink() {
                let mut target_buf = [0u8; 4096];
                let mut total_read = 0;
                loop {
                    let n = entry.read(&mut target_buf[total_read..])?;
                    if n == 0 {
                        break;
                    }
                    total_read += n;
                    if total_read == target_buf.len() && crate::adapter::has_more_data(&mut entry)?
                    {
                        return Err(Error::InvalidFilename {
                            entry: name,
                            reason: "symlink target exceeds 4096 bytes".to_string(),
                        });
                    }
                }
                let target = String::from_utf8_lossy(&target_buf[..total_read]).into_owned();
                EntryKind::Symlink { target }
            } else {
                EntryKind::File
            };

            let info = EntryInfo {
                name,
                size: entry.size(),
                kind: kind.clone(),
                mode: entry.unix_mode(),
                mtime: zip_time_to_timestamp(entry.last_modified()),
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
        // Inspect raw metadata and drop borrow before opening entry
        let (is_encrypted, raw_name) = {
            let raw_entry = self.archive.by_index_raw(index)?;
            (raw_entry.encrypted(), raw_entry.name()?.to_string())
        };
        if is_encrypted && self.password.is_none() {
            return Err(Error::EncryptedEntry { entry: raw_name });
        }

        let mut entry = match &self.password {
            Some(pwd) => self.archive.by_index_decrypt(index, pwd)?,
            None => self.archive.by_index(index)?,
        };

        let name = entry.name()?.into_owned();

        let kind = if entry.is_dir() {
            EntryKind::Directory
        } else if entry.is_symlink() {
            let mut target_buf = [0u8; 4096];
            let mut total_read = 0;
            loop {
                let n = entry.read(&mut target_buf[total_read..])?;
                if n == 0 {
                    break;
                }
                total_read += n;
                if total_read == target_buf.len() && crate::adapter::has_more_data(&mut entry)? {
                    return Err(Error::InvalidFilename {
                        entry: name,
                        reason: "symlink target exceeds 4096 bytes".to_string(),
                    });
                }
            }
            let target = String::from_utf8_lossy(&target_buf[..total_read]).into_owned();
            EntryKind::Symlink { target }
        } else {
            EntryKind::File
        };

        let info = EntryInfo {
            name,
            size: entry.size(),
            kind: kind.clone(),
            mode: entry.unix_mode(),
            mtime: zip_time_to_timestamp(entry.last_modified()),
        };

        let bytes_written = if matches!(kind, EntryKind::File) {
            let written = crate::adapter::copy_limited(&mut entry, writer, limit)?;

            if written == limit && crate::adapter::has_more_data(&mut entry)? {
                if limit < info.size {
                    return Err(Error::TotalSizeExceeded {
                        limit,
                        would_be: limit.saturating_add(1),
                    });
                } else {
                    return Err(Error::SizeMismatch {
                        entry: info.name.clone(),
                        declared: info.size,
                        actual: written.saturating_add(1),
                    });
                }
            }

            if written < info.size && limit >= info.size {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    format!(
                        "entry '{}' ended after {} of {} declared bytes",
                        info.name, written, info.size
                    ),
                )));
            }

            written
        } else {
            0
        };

        Ok((info, bytes_written))
    }

    /// Get entry info by index without reading content.
    ///
    /// # Errors
    ///
    /// Returns `Error::EncryptedEntry` if the entry is encrypted and no
    /// password was set via [`Self::password`].
    pub fn entry_info(&mut self, index: usize) -> Result<EntryInfo, Error> {
        let entry = self.archive.by_index_raw(index)?;
        let name = entry.name()?.into_owned();

        // Reject encrypted entries we have no way of reading
        if entry.encrypted() && self.password.is_none() {
            return Err(Error::EncryptedEntry { entry: name });
        }

        let kind = if entry.is_dir() {
            EntryKind::Directory
        } else if entry.is_symlink() {
            EntryKind::Symlink { target: String::new() }
        } else {
            EntryKind::File
        };

        Ok(EntryInfo {
            name,
            size: entry.size(),
            kind,
            mode: entry.unix_mode(),
            mtime: zip_time_to_timestamp(entry.last_modified()),
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

/// Helper to safely convert zip::DateTime to a Unix timestamp.
/// MS-DOS times are often invalid (e.g. day 0, second 60). We clamp
/// and sanitize them to ensure `chrono` doesn't reject the date.
pub(crate) fn zip_time_to_timestamp(dt: Option<zip::DateTime>) -> Option<u64> {
    let dt = dt?;

    let year = dt.year() as i32;
    let month = (dt.month() as u32).clamp(1, 12);
    let day = (dt.day() as u32).clamp(1, 31);
    let hour = (dt.hour() as u32).min(23);
    let minute = (dt.minute() as u32).min(59);
    let second = (dt.second() as u32).min(59); // ZIP allows 60 for leap seconds, chrono rejects it

    // Attempt to parse the exact date. If it's an invalid combination (like Feb 30th),
    // fallback to the 1st of the month.
    let date = chrono::NaiveDate::from_ymd_opt(year, month, day)
        .or_else(|| chrono::NaiveDate::from_ymd_opt(year, month, 1))
        .unwrap_or_else(|| chrono::NaiveDate::from_ymd_opt(1980, 1, 1).unwrap());

    let time = chrono::NaiveTime::from_hms_opt(hour, minute, second).unwrap_or_default();

    // Dates before the Unix epoch give a negative timestamp; casting that to u64
    // wraps into the far future and blows up SystemTime arithmetic later.
    u64::try_from(chrono::NaiveDateTime::new(date, time).and_utc().timestamp()).ok()
}
