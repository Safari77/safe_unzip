//! 7z archive adapter.
//!
//! Provides read-only extraction of 7z archives with the same security
//! guarantees as ZIP and TAR.

use std::io::Write;
use std::path::Path;

use crate::entry::{EntryInfo, EntryKind};
use crate::error::Error;

/// Adapter for 7z archives.
///
/// Uses the `sevenz-rust` crate for decompression. Note that 7z archives
/// are fully decompressed into memory before extraction, so very large
/// archives may use significant RAM.
///
/// # Example
///
/// ```ignore
/// use safe_unzip::{Driver, SevenZAdapter};
///
/// let adapter = SevenZAdapter::open("archive.7z")?;
/// let report = Driver::new("/tmp/out")?.extract_7z(adapter)?;
/// ```
pub struct SevenZAdapter {
    /// Cached entries (7z requires full decompression)
    entries: Vec<SevenZEntry>,
}

struct SevenZEntry {
    info: EntryInfo,
    data: Vec<u8>,
}

impl SevenZAdapter {
    /// Open a 7z file from a path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        Self::open_with_password(path, None)
    }

    /// Open a 7z file from a path, decrypting with `password`.
    ///
    /// `None` opens the archive with an empty password, which only works for
    /// unencrypted archives. Both encrypted headers and encrypted content
    /// (7zAES) need the password supplied here.
    pub fn open_with_password<P: AsRef<Path>>(
        path: P,
        password: Option<&str>,
    ) -> Result<Self, Error> {
        Self::open_with_limits(path, password, &crate::limits::Limits::default())
    }

    /// Open a 7z file from a path, refusing to buffer more than
    /// `max_total_bytes` of decompressed content.
    ///
    /// 7z entries are decompressed up front, so without a cap a small archive
    /// can exhaust memory long before the policy chain ever sees it.
    pub fn open_with_limit<P: AsRef<Path>>(
        path: P,
        password: Option<&str>,
        max_total_bytes: u64,
    ) -> Result<Self, Error> {
        let limits = crate::limits::Limits {
            max_total_bytes,
            max_single_file: max_total_bytes,
            ..crate::limits::Limits::default()
        };
        Self::open_with_limits(path, password, &limits)
    }

    /// Open a 7z file from a path with full resource limits enforced during decompression.
    pub fn open_with_limits<P: AsRef<Path>>(
        path: P,
        password: Option<&str>,
        limits: &crate::limits::Limits,
    ) -> Result<Self, Error> {
        let path = path.as_ref();
        let entries = Self::decompress_all(path, password, limits)?;
        Ok(Self { entries })
    }

    /// Open a 7z file from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        Self::from_bytes_with_password(data, None)
    }

    /// Open a 7z file from bytes, decrypting with `password`.
    pub fn from_bytes_with_password(data: &[u8], password: Option<&str>) -> Result<Self, Error> {
        Self::from_bytes_with_limits(data, password, &crate::limits::Limits::default())
    }

    /// Open a 7z file from bytes with a cap on decompressed size.
    pub fn from_bytes_with_limit(
        data: &[u8],
        password: Option<&str>,
        max_total_bytes: u64,
    ) -> Result<Self, Error> {
        let limits = crate::limits::Limits {
            max_total_bytes,
            max_single_file: max_total_bytes,
            ..crate::limits::Limits::default()
        };
        Self::from_bytes_with_limits(data, password, &limits)
    }

    /// Open a 7z file from bytes with full resource limits enforced during decompression.
    pub fn from_bytes_with_limits(
        data: &[u8],
        password: Option<&str>,
        limits: &crate::limits::Limits,
    ) -> Result<Self, Error> {
        // sevenz-rust requires a file path, so we write to a temp file
        let mut temp = tempfile::NamedTempFile::new()?;
        temp.write_all(data)?;
        temp.flush()?;
        Self::open_with_limits(temp.path(), password, limits)
    }

    fn decompress_all(
        path: &Path,
        password: Option<&str>,
        limits: &crate::limits::Limits,
    ) -> Result<Vec<SevenZEntry>, Error> {
        let mut entries = Vec::new();
        let mut total_bytes: u64 = 0;
        let mut file_count: usize = 0;
        let mut dir_count: usize = 0;
        let mut abort_error: Option<Error> = None;

        // Password::from(&str) does the UTF-16LE encoding that 7zAES expects
        let password = match password {
            Some(p) => sevenz_rust2::Password::from(p),
            None => sevenz_rust2::Password::empty(),
        };

        // Use the lower-level API to iterate entries
        let mut archive = sevenz_rust2::ArchiveReader::open(path, password)
            .map_err(|e| map_7z_error("open", e))?;

        // Iterate through all entries
        archive
            .for_each_entries(|entry, reader| {
                let name = entry.name().to_string();

                // Detect Windows and POSIX symlinks stored in 7z attributes
                let is_symlink = entry.has_windows_attributes
                    && (((entry.windows_attributes >> 16) & 0o170000 == 0o120000)
                        || (entry.windows_attributes & 0x400 != 0));

                let mut data = Vec::new();

                let kind = if entry.is_directory() {
                    dir_count += 1;
                    if dir_count > limits.max_dir_count {
                        abort_error = Some(Error::DirCountExceeded {
                            limit: limits.max_dir_count,
                            attempted: dir_count,
                        });
                        return Ok(false);
                    }
                    EntryKind::Directory
                } else if is_symlink {
                    let mut buf = [0u8; 4096];
                    let mut total_read = 0;
                    loop {
                        let n = reader
                            .read(&mut buf[total_read..])
                            .map_err(sevenz_rust2::Error::from)?;
                        if n == 0 {
                            break;
                        }
                        total_read += n;
                        if total_read == buf.len() {
                            let mut probe = [0u8; 1];
                            let has_more =
                                reader.read(&mut probe).map_err(sevenz_rust2::Error::from)? > 0;
                            if has_more {
                                return Err(sevenz_rust2::Error::from(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    format!("symlink target in '{}' exceeds 4096 bytes", name),
                                )));
                            }
                        }
                    }
                    let target = String::from_utf8_lossy(&buf[..total_read]).into_owned();
                    EntryKind::Symlink { target }
                } else {
                    file_count += 1;
                    if file_count > limits.max_file_count {
                        abort_error = Some(Error::FileCountExceeded {
                            limit: limits.max_file_count,
                            attempted: file_count,
                        });
                        return Ok(false);
                    }
                    EntryKind::File
                };

                // Read content for files, stopping one byte past the remaining
                // budget so an over-sized archive is detected rather than buffered
                if matches!(kind, EntryKind::File) {
                    if entry.size() > limits.max_single_file {
                        abort_error = Some(Error::FileTooLarge {
                            entry: name,
                            limit: limits.max_single_file,
                            size: entry.size(),
                        });
                        return Ok(false);
                    }

                    let remaining_total = limits.max_total_bytes.saturating_sub(total_bytes);
                    let file_cap = limits.max_single_file.min(remaining_total);
                    let budget = file_cap.saturating_add(1);
                    let mut buf = [0u8; 8192];
                    while (data.len() as u64) < budget {
                        let want = (budget - data.len() as u64).min(buf.len() as u64) as usize;
                        let n = reader.read(&mut buf[..want])?;
                        if n == 0 {
                            break;
                        }
                        data.extend_from_slice(&buf[..n]);
                    }

                    let read_len = data.len() as u64;
                    if read_len > limits.max_single_file {
                        abort_error = Some(Error::FileTooLarge {
                            entry: name,
                            limit: limits.max_single_file,
                            size: read_len,
                        });
                        return Ok(false);
                    }

                    total_bytes = total_bytes.saturating_add(read_len);
                    if total_bytes > limits.max_total_bytes {
                        abort_error = Some(Error::TotalSizeExceeded {
                            limit: limits.max_total_bytes,
                            would_be: total_bytes,
                        });
                        return Ok(false);
                    }
                }

                // Restore mtime from Windows FILETIME (100-ns intervals since 1601-01-01)
                const FILETIME_TO_UNIX_OFFSET: u64 = 116_444_736_000_000_000;
                let mtime = if entry.has_last_modified_date {
                    let ft = u64::from(entry.last_modified_date);
                    if ft >= FILETIME_TO_UNIX_OFFSET {
                        Some((ft - FILETIME_TO_UNIX_OFFSET) / 10_000_000)
                    } else {
                        None
                    }
                } else {
                    None
                };

                let mode = if entry.has_windows_attributes && (entry.windows_attributes >> 16) != 0
                {
                    Some(entry.windows_attributes >> 16)
                } else {
                    None
                };

                let info = EntryInfo { name, size: data.len() as u64, kind, mode, mtime };

                entries.push(SevenZEntry { info, data });
                Ok(true)
            })
            .map_err(|e| map_7z_error("read", e))?;

        if let Some(err) = abort_error {
            return Err(err);
        }

        Ok(entries)
    }

    /// Get all entry metadata.
    pub fn entries_metadata(&self) -> Vec<EntryInfo> {
        self.entries.iter().map(|e| e.info.clone()).collect()
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the archive is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Process each entry with a callback.
    pub fn for_each<F>(&self, mut callback: F) -> Result<(), Error>
    where
        F: FnMut(&EntryInfo, Option<&[u8]>) -> Result<bool, Error>,
    {
        for entry in &self.entries {
            let data = if matches!(entry.info.kind, EntryKind::File) {
                Some(entry.data.as_slice())
            } else {
                None
            };

            if !callback(&entry.info, data)? {
                break;
            }
        }
        Ok(())
    }
}

/// Map a sevenz-rust2 error into our own error type.
///
/// The crate reports "no password given" and "wrong password" as ordinary
/// errors (`PasswordRequired`, `MaybeBadPassword`), which is confusing when it
/// surfaces as a bare I/O error, so those get a clearer message. Generic over
/// `Display` to avoid naming sevenz-rust2's error type here.
fn map_7z_error<E: std::fmt::Display>(stage: &str, e: E) -> Error {
    let text = e.to_string();
    if text.to_ascii_lowercase().contains("password") {
        Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("7z {} error: wrong or missing password ({})", stage, text),
        ))
    } else {
        Error::Io(std::io::Error::other(format!("7z {} error: {}", stage, text)))
    }
}
