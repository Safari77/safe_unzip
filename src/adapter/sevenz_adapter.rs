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
        let path = path.as_ref();
        let entries = Self::decompress_all(path, password)?;
        Ok(Self { entries })
    }

    /// Open a 7z file from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        Self::from_bytes_with_password(data, None)
    }

    /// Open a 7z file from bytes, decrypting with `password`.
    pub fn from_bytes_with_password(data: &[u8], password: Option<&str>) -> Result<Self, Error> {
        // sevenz-rust requires a file path, so we write to a temp file
        let mut temp = tempfile::NamedTempFile::new()?;
        temp.write_all(data)?;
        temp.flush()?;
        Self::open_with_password(temp.path(), password)
    }

    fn decompress_all(path: &Path, password: Option<&str>) -> Result<Vec<SevenZEntry>, Error> {
        let mut entries = Vec::new();

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

                // Determine entry kind
                let kind =
                    if entry.is_directory() { EntryKind::Directory } else { EntryKind::File };

                // Read content for files
                let mut data = Vec::new();
                if matches!(kind, EntryKind::File) {
                    reader.read_to_end(&mut data)?;
                }

                let info = EntryInfo {
                    name,
                    size: data.len() as u64,
                    kind,
                    mode: None, // 7z doesn't preserve Unix permissions
                    mtime: None,
                };

                entries.push(SevenZEntry { info, data });
                Ok(true)
            })
            .map_err(|e| map_7z_error("read", e))?;

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
