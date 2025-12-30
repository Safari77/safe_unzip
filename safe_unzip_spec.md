# safe_unzip Specification (v0.1)

Zip extraction that won't ruin your day.

## 1. Overview

`safe_unzip` is a secure zip extraction library that prevents:

- **Zip Slip**: Path traversal via `../../` in entry names
- **Zip Bombs**: Archives that expand to exhaust disk/memory
- **Symlink Attacks**: Symlinks pointing outside extraction directory

Built on `path_jail` for path validation.

## 2. Threat Model

| Threat | Attack Vector | Defense |
|--------|---------------|---------|
| Zip Slip | Entry named `../../etc/cron.d/pwned` | `path_jail` validates every path |
| Zip Bomb (size) | 42KB expands to 4PB | `max_total_bytes` limit |
| Zip Bomb (count) | 1 million empty files | `max_file_count` limit |
| Zip Bomb (ratio) | Single file with extreme compression | `max_single_file` limit |
| Symlink Escape | Symlink to `/etc/passwd` | Skip or error on symlinks |
| Path Depth | `a/b/c/d/.../` to 10000 levels | `max_path_depth` limit |
| Overwrite | Replace existing sensitive file | `OverwritePolicy::Error` default |

## 3. Scope

### v0.1 (This Spec)

- Zip format only
- Synchronous API
- File and directory extraction
- Configurable limits
- Filter callback

### v0.2 (Planned)

- Tar/tar.gz/tar.bz2 support
- Async API
- Atomic extraction (temp dir, move on success)
- Progress callback

### Non-Goals

- Creating archives (extraction only)
- Password-protected zips (use `zip` crate directly)
- Self-extracting archives

## 4. Dependencies

```toml
[dependencies]
path_jail = "0.1"
zip = "2.1"
```

Zero additional dependencies beyond these.

## 5. Rust API

### 5.1 Core Types

```rust
use std::io::{Read, Seek};
use std::path::Path;

/// Zip extractor with security constraints.
pub struct Extractor {
    jail: path_jail::Jail,
    limits: Limits,
    overwrite: OverwritePolicy,
    symlinks: SymlinkPolicy,
    mode: ExtractionMode,
    filter: Option<Box<dyn Fn(&EntryInfo) -> bool + Send + Sync>>,
}

/// Resource limits to prevent denial of service.
pub struct Limits {
    /// Maximum total bytes to extract. Default: 1 GB.
    pub max_total_bytes: u64,
    
    /// Maximum number of files to extract. Default: 10,000.
    pub max_file_count: usize,
    
    /// Maximum size of a single file. Default: 100 MB.
    pub max_single_file: u64,
    
    /// Maximum directory depth. Default: 50.
    pub max_path_depth: usize,
}

/// What to do when a file already exists.
#[derive(Debug, Clone, Copy, Default)]
pub enum OverwritePolicy {
    /// Fail extraction if file exists.
    #[default]
    Error,
    
    /// Skip files that already exist.
    Skip,
    
    /// Overwrite existing files.
    Overwrite,
}

/// What to do with symlinks in the archive.
#[derive(Debug, Clone, Copy, Default)]
pub enum SymlinkPolicy {
    /// Ignore symlinks silently.
    #[default]
    Skip,
    
    /// Fail extraction if archive contains symlinks.
    Error,
}

/// Extraction strategy.
#[derive(Debug, Clone, Copy, Default)]
pub enum ExtractionMode {
    /// Extract immediately. Partial state on failure.
    #[default]
    Streaming,
    
    /// Validate all entries first, then extract.
    /// Slower (2x iteration) but no partial state on validation failure.
    ValidateFirst,
}

/// Information about an archive entry (for filtering).
pub struct EntryInfo<'a> {
    /// Entry name as stored in archive.
    pub name: &'a str,
    
    /// Uncompressed size in bytes.
    pub size: u64,
    
    /// Compressed size in bytes.
    pub compressed_size: u64,
    
    /// True if entry is a directory.
    pub is_dir: bool,
    
    /// True if entry is a symlink.
    pub is_symlink: bool,
}

/// Extraction report.
#[derive(Debug, Clone)]
pub struct Report {
    /// Number of files successfully extracted.
    pub files_extracted: usize,
    
    /// Number of directories created.
    pub dirs_created: usize,
    
    /// Total bytes written.
    pub bytes_written: u64,
    
    /// Number of entries skipped (symlinks, filtered, existing).
    pub entries_skipped: usize,
}
```

### 5.2 Builder API

```rust
impl Extractor {
    /// Create extractor for the given destination directory.
    /// Directory must exist.
    pub fn new<P: AsRef<Path>>(destination: P) -> Result<Self, Error>;
    
    /// Set resource limits.
    pub fn limits(self, limits: Limits) -> Self;
    
    /// Set overwrite policy.
    pub fn overwrite(self, policy: OverwritePolicy) -> Self;
    
    /// Set symlink policy.
    pub fn symlinks(self, policy: SymlinkPolicy) -> Self;
    
    /// Set extraction mode.
    pub fn mode(self, mode: ExtractionMode) -> Self;
    
    /// Set filter function. Return `true` to extract, `false` to skip.
    pub fn filter<F>(self, f: F) -> Self
    where
        F: Fn(&EntryInfo) -> bool + Send + Sync + 'static;
    
    /// Extract from a reader.
    pub fn extract<R: Read + Seek>(self, reader: R) -> Result<Report, Error>;
    
    /// Extract from a file path.
    pub fn extract_file<P: AsRef<Path>>(self, path: P) -> Result<Report, Error>;
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_total_bytes: 1024 * 1024 * 1024,  // 1 GB
            max_file_count: 10_000,
            max_single_file: 100 * 1024 * 1024,   // 100 MB
            max_path_depth: 50,
        }
    }
}
```

### 5.3 Convenience Function

```rust
/// Extract a zip file with default settings.
pub fn extract<P, R>(destination: P, reader: R) -> Result<Report, Error>
where
    P: AsRef<Path>,
    R: Read + Seek,
{
    Extractor::new(destination)?.extract(reader)
}

/// Extract a zip file from a path with default settings.
pub fn extract_file<D, F>(destination: D, file: F) -> Result<Report, Error>
where
    D: AsRef<Path>,
    F: AsRef<Path>,
{
    Extractor::new(destination)?.extract_file(file)
}
```

### 5.4 Error Type

```rust
#[derive(Debug)]
pub enum Error {
    /// Path escapes destination directory.
    PathEscape {
        entry: String,
        detail: String,
    },
    
    /// Archive contains symlink and policy is Error.
    SymlinkNotAllowed {
        entry: String,
    },
    
    /// Exceeded maximum total bytes.
    TotalSizeExceeded {
        limit: u64,
        would_be: u64,
    },
    
    /// Exceeded maximum file count.
    FileCountExceeded {
        limit: usize,
    },
    
    /// Single file exceeds size limit.
    FileTooLarge {
        entry: String,
        limit: u64,
        size: u64,
    },
    
    /// Path exceeds depth limit.
    PathTooDeep {
        entry: String,
        depth: usize,
        limit: usize,
    },
    
    /// File already exists and policy is Error.
    AlreadyExists {
        path: String,
    },
    
    /// Invalid entry name.
    InvalidEntry {
        entry: String,
        reason: String,
    },
    
    /// Destination directory does not exist.
    DestinationNotFound {
        path: String,
    },
    
    /// Zip format error.
    Zip(zip::result::ZipError),
    
    /// IO error.
    Io(std::io::Error),
    
    /// Path jail error.
    Jail(path_jail::JailError),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PathEscape { entry, detail } => {
                write!(f, "path escape in '{}': {}", entry, detail)
            }
            Self::SymlinkNotAllowed { entry } => {
                write!(f, "symlink not allowed: '{}'", entry)
            }
            Self::TotalSizeExceeded { limit, would_be } => {
                write!(f, "total size {} exceeds limit {}", would_be, limit)
            }
            Self::FileCountExceeded { limit } => {
                write!(f, "file count exceeds limit {}", limit)
            }
            Self::FileTooLarge { entry, limit, size } => {
                write!(f, "'{}' size {} exceeds limit {}", entry, size, limit)
            }
            Self::PathTooDeep { entry, depth, limit } => {
                write!(f, "'{}' depth {} exceeds limit {}", entry, depth, limit)
            }
            Self::AlreadyExists { path } => {
                write!(f, "file already exists: '{}'", path)
            }
            Self::InvalidEntry { entry, reason } => {
                write!(f, "invalid entry '{}': {}", entry, reason)
            }
            Self::DestinationNotFound { path } => {
                write!(f, "destination not found: '{}'", path)
            }
            Self::Zip(e) => write!(f, "zip error: {}", e),
            Self::Io(e) => write!(f, "io error: {}", e),
            Self::Jail(e) => write!(f, "jail error: {}", e),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Zip(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::Jail(e) => Some(e),
            _ => None,
        }
    }
}
```

## 6. Implementation Notes

### 6.1 Two-Pass Extraction (ValidateFirst Mode)

When `ExtractionMode::ValidateFirst` is set, extraction happens in two phases:

```rust
pub fn extract<R: Read + Seek>(self, reader: R) -> Result<Report, Error> {
    let mut archive = zip::ZipArchive::new(reader)?;
    
    if matches!(self.mode, ExtractionMode::ValidateFirst) {
        // Pass 1: Validate all entries without extracting
        self.validate_all(&mut archive)?;
    }
    
    // Pass 2: Extract (or Pass 1 if Streaming mode)
    self.extract_all(&mut archive)
}

fn validate_all<R: Read + Seek>(&self, archive: &mut ZipArchive<R>) -> Result<(), Error> {
    let mut total_size: u64 = 0;
    let mut file_count: usize = 0;
    
    for i in 0..archive.len() {
        let entry = archive.by_index_raw(i)?;  // No decompression
        let name = entry.name().to_string();
        
        // Check symlink policy
        if entry.is_symlink() && matches!(self.symlinks, SymlinkPolicy::Error) {
            return Err(Error::SymlinkNotAllowed { entry: name });
        }
        
        // Check path depth
        let depth = name.matches('/').count();
        if depth > self.limits.max_path_depth {
            return Err(Error::PathTooDeep {
                entry: name,
                depth,
                limit: self.limits.max_path_depth,
            });
        }
        
        // Check single file size
        if !entry.is_dir() && entry.size() > self.limits.max_single_file {
            return Err(Error::FileTooLarge {
                entry: name,
                limit: self.limits.max_single_file,
                size: entry.size(),
            });
        }
        
        // Validate path with path_jail
        self.jail.join(&name).map_err(|e| Error::PathEscape {
            entry: name.clone(),
            detail: e.to_string(),
        })?;
        
        // Accumulate totals
        if !entry.is_dir() && !entry.is_symlink() {
            total_size += entry.size();
            file_count += 1;
        }
    }
    
    // Check totals
    if total_size > self.limits.max_total_bytes {
        return Err(Error::TotalSizeExceeded {
            limit: self.limits.max_total_bytes,
            would_be: total_size,
        });
    }
    
    if file_count > self.limits.max_file_count {
        return Err(Error::FileCountExceeded {
            limit: self.limits.max_file_count,
        });
    }
    
    Ok(())
}
```

The dry run uses `by_index_raw()` which reads metadata without decompressing, making it fast.

### 6.2 Extraction Loop

```rust
pub fn extract<R: Read + Seek>(self, reader: R) -> Result<Report, Error> {
    let mut archive = zip::ZipArchive::new(reader)?;
    let mut report = Report::default();
    let mut total_bytes: u64 = 0;
    
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let name = entry.name().to_string();
        
        // 1. Validate path with path_jail FIRST (even for symlinks)
        // This ensures we catch traversal attempts before deciding to skip
        self.jail.join(&name).map_err(|e| {
            Error::PathEscape {
                entry: name.clone(),
                detail: e.to_string(),
            }
        })?;
        
        // 2. Check symlink policy
        if entry.is_symlink() {
            match self.symlinks {
                SymlinkPolicy::Skip => {
                    report.entries_skipped += 1;
                    continue;
                }
                SymlinkPolicy::Error => {
                    return Err(Error::SymlinkNotAllowed { entry: name });
                }
            }
        }
        
        // 3. Build EntryInfo for filtering
        let info = EntryInfo {
            name: &name,
            size: entry.size(),
            compressed_size: entry.compressed_size(),
            is_dir: entry.is_dir(),
            is_symlink: entry.is_symlink(),
        };
        
        // 4. Apply filter
        if let Some(ref filter) = self.filter {
            if !filter(&info) {
                report.entries_skipped += 1;
                continue;
            }
        }
        
        // 5. Check path depth (count actual directory segments)
        let depth = std::path::Path::new(&name)
            .components()
            .filter(|c| matches!(c, std::path::Component::Normal(_)))
            .count();
        if depth > self.limits.max_path_depth {
            return Err(Error::PathTooDeep {
                entry: name,
                depth,
                limit: self.limits.max_path_depth,
            });
        }
        
        // 6. Check single file size
        if !entry.is_dir() && entry.size() > self.limits.max_single_file {
            return Err(Error::FileTooLarge {
                entry: name,
                limit: self.limits.max_single_file,
                size: entry.size(),
            });
        }
        
        // 7. Check file count
        if report.files_extracted >= self.limits.max_file_count {
            return Err(Error::FileCountExceeded {
                limit: self.limits.max_file_count,
            });
        }
        
        // 8. Check total size (before extraction)
        if total_bytes + entry.size() > self.limits.max_total_bytes {
            return Err(Error::TotalSizeExceeded {
                limit: self.limits.max_total_bytes,
                would_be: total_bytes + entry.size(),
            });
        }
        
        // 9. Build safe path for extraction (already validated above)
        let safe_path = self.jail.join(&name).unwrap();
        
        // 10. Check overwrite policy
        if safe_path.exists() {
            match self.overwrite {
                OverwritePolicy::Error => {
                    return Err(Error::AlreadyExists {
                        path: safe_path.display().to_string(),
                    });
                }
                OverwritePolicy::Skip => {
                    report.entries_skipped += 1;
                    continue;
                }
                OverwritePolicy::Overwrite => {}
            }
        }
        
        // 11. Extract
        if entry.is_dir() {
            std::fs::create_dir_all(&safe_path)?;
            report.dirs_created += 1;
        } else {
            // Ensure parent directory exists
            if let Some(parent) = safe_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            
            let mut outfile = std::fs::File::create(&safe_path)?;
            let written = std::io::copy(&mut entry, &mut outfile)?;
            
            total_bytes += written;
            report.bytes_written += written;
            report.files_extracted += 1;
            
            // Apply permissions (Unix only, strip dangerous bits)
            #[cfg(unix)]
            if let Some(mode) = entry.unix_mode() {
                use std::os::unix::fs::PermissionsExt;
                // Strip setuid, setgid, sticky bits
                let safe_mode = mode & 0o0777;
                std::fs::set_permissions(
                    &safe_path,
                    std::fs::Permissions::from_mode(safe_mode),
                )?;
            }
        }
    }
    
    Ok(report)
}
```

### 6.3 Filter Semantics

The filter callback is **advisory, not a security boundary**:

- Filter runs after path validation (traversal attempts still error)
- Filter runs before limit checks
- Limits are checked on entries that pass the filter

This means:
- A malicious entry with `../../etc/passwd` will error even if your filter would reject it
- An oversized file will error even if your filter would skip it

This ordering ensures security checks cannot be bypassed by filter logic.

### 6.4 Symlink Counting

When `SymlinkPolicy::Skip` is active:

- Symlinks count toward `entries_skipped`
- Symlinks do NOT count toward `files_extracted` or `file_count` limit
- Symlinks ARE validated for path traversal before skipping

This ensures traversal attempts via symlinks still error, even when skipping.

### 6.5 Streaming Limitation

The `zip` crate requires `Read + Seek` because zip files have a central directory at the end. True streaming extraction from stdin is not possible with the standard zip format.

**What works:**
- `std::fs::File`
- `std::io::Cursor<Vec<u8>>`
- `std::io::Cursor<&[u8]>`
- Flask `FileStorage` (seekable)
- Django `UploadedFile` (seekable)

**What does NOT work:**
- `request.stream` (not seekable)
- Piped stdin
- HTTP response bodies (without buffering)

For non-seekable streams, buffer to `Cursor` first:

```rust
let mut buf = Vec::new();
stream.read_to_end(&mut buf)?;
let cursor = std::io::Cursor::new(buf);
extract(dest, cursor)?;
```

Document this limitation. Users needing true streaming should use tar.gz (planned for v0.2).

### 6.6 Partial Extraction on Failure

**Streaming mode:** If extraction fails mid-way, already-extracted files remain on disk. This matches the behavior of standard tools like `unzip`.

**ValidateFirst mode:** Validation failures happen before any files are written. Extraction failures (e.g., disk full) can still leave partial state.

For fully atomic extraction (all-or-nothing), planned for v0.2:
1. Extract to temp directory
2. Move to destination on success
3. Clean up temp on failure

### 6.7 Permissions

**Unix:** Permissions from the archive are applied with dangerous bits stripped:

```rust
let safe_mode = mode & 0o0777;  // Remove setuid, setgid, sticky
```

This prevents archives from creating setuid executables.

**Windows:** Archive permissions are ignored. Windows does not use Unix-style permission bits.

## 7. Python API

### 7.1 Module Structure

```
python/
  safe_unzip/
    __init__.py
    __init__.pyi
    py.typed
```

### 7.2 API

```python
from safe_unzip import extract, extract_file, Extractor

# Simple extraction
report = extract("/var/uploads", file_object)
report = extract_file("/var/uploads", "archive.zip")

# With options
extractor = (
    Extractor("/var/uploads")
    .max_total_mb(500)
    .max_files(1000)
    .max_single_file_mb(50)
    .max_depth(20)
    .overwrite("skip")          # "error" | "skip" | "overwrite"
    .symlinks("error")          # "skip" | "error"
    .mode("validate_first")     # "streaming" | "validate_first"
    .filter(lambda e: e.name.endswith(".png"))
)
report = extractor.extract(file_object)
report = extractor.extract_file("archive.zip")

# Report
print(report.files_extracted)
print(report.dirs_created)
print(report.bytes_written)
print(report.entries_skipped)
```

### 7.3 Input Requirements

The source must be seekable. This works:

- `open("file.zip", "rb")`
- `io.BytesIO(data)`
- Flask `FileStorage`
- Django `UploadedFile`
- Django `InMemoryUploadedFile`

This does NOT work:

- `request.stream` (not seekable)
- Raw `wsgi.input`
- HTTP response bodies without buffering

For non-seekable streams, buffer first:

```python
import io
from safe_unzip import extract

# Buffer to BytesIO
data = request.stream.read()
extract("/var/uploads", io.BytesIO(data))
```

### 7.4 Type Stubs

```python
from os import PathLike
from pathlib import Path
from typing import Union, Callable, BinaryIO, Literal

_PathType = Union[str, PathLike[str]]
_OverwritePolicy = Literal["error", "skip", "overwrite"]
_SymlinkPolicy = Literal["skip", "error"]
_ExtractionMode = Literal["streaming", "validate_first"]

class EntryInfo:
    @property
    def name(self) -> str: ...
    @property
    def size(self) -> int: ...
    @property
    def compressed_size(self) -> int: ...
    @property
    def is_dir(self) -> bool: ...
    @property
    def is_symlink(self) -> bool: ...

class Report:
    @property
    def files_extracted(self) -> int: ...
    @property
    def dirs_created(self) -> int: ...
    @property
    def bytes_written(self) -> int: ...
    @property
    def entries_skipped(self) -> int: ...
    @property
    def destination(self) -> Path: ...  # Root where files were extracted

class Extractor:
    def __init__(self, destination: _PathType) -> None: ...
    @property
    def destination(self) -> Path: ...  # Returns pathlib.Path
    def max_total_mb(self, mb: int) -> "Extractor": ...
    def max_files(self, count: int) -> "Extractor": ...
    def max_single_file_mb(self, mb: int) -> "Extractor": ...
    def max_depth(self, depth: int) -> "Extractor": ...
    def overwrite(self, policy: _OverwritePolicy) -> "Extractor": ...
    def symlinks(self, policy: _SymlinkPolicy) -> "Extractor": ...
    def mode(self, mode: _ExtractionMode) -> "Extractor": ...
    def filter(self, f: Callable[[EntryInfo], bool]) -> "Extractor": ...
    def extract(self, source: BinaryIO) -> Report: ...
    def extract_file(self, path: _PathType) -> Report: ...

def extract(destination: _PathType, source: BinaryIO) -> Report: ...
def extract_file(destination: _PathType, path: _PathType) -> Report: ...
```

### 7.5 Error Handling

```python
from safe_unzip import extract_file, PathEscapeError, QuotaError

try:
    report = extract_file("/var/uploads", "untrusted.zip")
except PathEscapeError as e:
    print(f"Blocked traversal: {e.entry}")
except QuotaError as e:
    print(f"Resource limit exceeded: {e}")
except OSError as e:
    print(f"IO error: {e}")
```

Exception hierarchy (keep simple for v0.1):

```
Exception
  SafeUnzipError (base)
    PathEscapeError      # Traversal, symlink escape, broken symlink
    SymlinkNotAllowedError
    QuotaError           # All limit violations (size, count, depth)
    AlreadyExistsError
  OSError (for IO errors)
```

Note: Don't over-refine the exception hierarchy in v0.1. `QuotaError` covers all limit violations. Subclasses can be added later without breaking existing `except QuotaError` handlers.

## 8. Project Structure

### 8.1 Monorepo Layout

```
safe_unzip/
├── Cargo.toml                    # Workspace root
├── crates/
│   └── safe_unzip/               # Core Rust library
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           ├── extractor.rs
│           ├── limits.rs
│           └── error.rs
├── bindings/
│   └── python/                   # Python bindings
│       ├── Cargo.toml
│       ├── pyproject.toml
│       ├── src/
│       │   └── lib.rs
│       └── python/
│           └── safe_unzip/
│               ├── __init__.py
│               ├── __init__.pyi
│               └── py.typed
├── tests/
│   └── fixtures/                 # Shared test archives
│       ├── normal.zip
│       ├── traversal.zip
│       ├── symlink_escape.zip
│       ├── bomb_size.zip
│       ├── bomb_count.zip
│       ├── deep_path.zip
│       └── setuid.zip
├── README.md
├── LICENSE-MIT
└── LICENSE-APACHE
```

### 8.2 Workspace Configuration

```toml
# Root Cargo.toml
[workspace]
members = ["crates/*", "bindings/*"]
resolver = "2"

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "MIT OR Apache-2.0"
repository = "https://github.com/aimable100/safe_unzip"
```

```toml
# crates/safe_unzip/Cargo.toml
[package]
name = "safe_unzip"
version.workspace = true
edition.workspace = true
license.workspace = true
description = "Secure zip extraction. Prevents Zip Slip and Zip Bombs."
keywords = ["zip", "security", "archive", "extraction", "safe"]
categories = ["filesystem", "compression"]

[dependencies]
path_jail = "0.1"
zip = "2.1"

[dev-dependencies]
tempfile = "3"
```

```toml
# bindings/python/Cargo.toml
[package]
name = "safe_unzip_python"
version.workspace = true
edition.workspace = true
license.workspace = true

[lib]
name = "safe_unzip"
crate-type = ["cdylib"]

[dependencies]
safe_unzip = { path = "../../crates/safe_unzip" }
pyo3 = { version = "0.21", features = ["extension-module"] }
```

```toml
# bindings/python/pyproject.toml
[build-system]
requires = ["maturin>=1.0,<2.0"]
build-backend = "maturin"

[project]
name = "safe-unzip"
version = "0.1.0"
description = "Secure zip extraction. Prevents Zip Slip and Zip Bombs."
readme = "README.md"
license = {text = "MIT OR Apache-2.0"}
requires-python = ">=3.8"
classifiers = [
    "Programming Language :: Rust",
    "Programming Language :: Python :: Implementation :: CPython",
    "Topic :: Security",
    "Topic :: System :: Archiving :: Compression",
]

[tool.maturin]
python-source = "python"
module-name = "safe_unzip.safe_unzip"
```

## 9. Test Strategy

### 9.1 Test Fixtures

Create malicious zip files for testing:

```
tests/fixtures/
├── normal.zip              # Valid archive
├── traversal.zip           # Contains ../../etc/passwd
├── symlink_escape.zip      # Symlink to /etc
├── bomb_size.zip           # Expands to > limit
├── bomb_count.zip          # 100,000 empty files
├── deep_path.zip           # a/b/c/d/.../file (100 levels)
├── existing_file.zip       # File that will conflict
└── setuid.zip              # Contains setuid executable
```

### 9.2 Rust Tests

```rust
#[test]
fn blocks_traversal() {
    let dir = tempdir().unwrap();
    let result = extract_file(dir.path(), "tests/fixtures/traversal.zip");
    assert!(matches!(result, Err(Error::PathEscape { .. })));
}

#[test]
fn blocks_symlink_escape() {
    let dir = tempdir().unwrap();
    let result = Extractor::new(dir.path())
        .unwrap()
        .symlinks(SymlinkPolicy::Error)
        .extract_file("tests/fixtures/symlink_escape.zip");
    assert!(matches!(result, Err(Error::SymlinkNotAllowed { .. })));
}

#[test]
fn enforces_size_limit() {
    let dir = tempdir().unwrap();
    let result = Extractor::new(dir.path())
        .unwrap()
        .limits(Limits {
            max_total_bytes: 1024,
            ..Default::default()
        })
        .extract_file("tests/fixtures/bomb_size.zip");
    assert!(matches!(result, Err(Error::TotalSizeExceeded { .. })));
}

#[test]
fn skips_symlinks_by_default() {
    let dir = tempdir().unwrap();
    let report = extract_file(dir.path(), "tests/fixtures/symlink_escape.zip").unwrap();
    assert!(report.entries_skipped > 0);
}

#[test]
fn respects_overwrite_error() {
    let dir = tempdir().unwrap();
    // First extraction
    extract_file(dir.path(), "tests/fixtures/normal.zip").unwrap();
    // Second should fail
    let result = extract_file(dir.path(), "tests/fixtures/normal.zip");
    assert!(matches!(result, Err(Error::AlreadyExists { .. })));
}

#[test]
fn respects_overwrite_skip() {
    let dir = tempdir().unwrap();
    extract_file(dir.path(), "tests/fixtures/normal.zip").unwrap();
    let report = Extractor::new(dir.path())
        .unwrap()
        .overwrite(OverwritePolicy::Skip)
        .extract_file("tests/fixtures/normal.zip")
        .unwrap();
    assert!(report.entries_skipped > 0);
}

#[test]
fn filter_works() {
    let dir = tempdir().unwrap();
    let report = Extractor::new(dir.path())
        .unwrap()
        .filter(|e| e.name.ends_with(".txt"))
        .extract_file("tests/fixtures/normal.zip")
        .unwrap();
    // Only .txt files extracted
}

#[test]
fn validate_first_catches_traversal_before_extraction() {
    let dir = tempdir().unwrap();
    
    // With ValidateFirst, nothing should be written on failure
    let result = Extractor::new(dir.path())
        .unwrap()
        .mode(ExtractionMode::ValidateFirst)
        .extract_file("tests/fixtures/traversal.zip");
    
    assert!(matches!(result, Err(Error::PathEscape { .. })));
    // Directory should be empty (nothing extracted)
    assert!(dir.path().read_dir().unwrap().next().is_none());
}

#[cfg(unix)]
#[test]
fn strips_setuid() {
    let dir = tempdir().unwrap();
    extract_file(dir.path(), "tests/fixtures/setuid.zip").unwrap();
    let meta = std::fs::metadata(dir.path().join("setuid_binary")).unwrap();
    let mode = std::os::unix::fs::PermissionsExt::mode(&meta.permissions());
    assert_eq!(mode & 0o7000, 0);  // No setuid/setgid/sticky
}
```

### 9.3 Python Tests

```python
import pytest
from safe_unzip import extract_file, Extractor, PathEscapeError, QuotaError

def test_blocks_traversal(tmp_path):
    with pytest.raises(PathEscapeError):
        extract_file(tmp_path, "tests/fixtures/traversal.zip")

def test_enforces_size_limit(tmp_path):
    with pytest.raises(QuotaError):
        Extractor(tmp_path).max_total_mb(1).extract_file("tests/fixtures/bomb_size.zip")

def test_filter(tmp_path):
    report = (
        Extractor(tmp_path)
        .filter(lambda e: e.name.endswith(".txt"))
        .extract_file("tests/fixtures/normal.zip")
    )
    # Verify only .txt files exist

def test_validate_first_no_partial_state(tmp_path):
    with pytest.raises(PathEscapeError):
        (
            Extractor(tmp_path)
            .mode("validate_first")
            .extract_file("tests/fixtures/traversal.zip")
        )
    # Nothing should be extracted
    assert list(tmp_path.iterdir()) == []
```

## 10. README

```markdown
# safe_unzip

[![Crates.io](https://img.shields.io/crates/v/safe_unzip.svg)](https://crates.io/crates/safe_unzip)
[![PyPI](https://img.shields.io/pypi/v/safe-unzip.svg)](https://pypi.org/project/safe-unzip/)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)

Zip extraction that won't ruin your day.

## The Problem

Zip files can contain malicious paths:

```python
# Python's zipfile is vulnerable
import zipfile
zipfile.ZipFile("evil.zip").extractall("/var/uploads")
# Extracts ../../etc/cron.d/pwned -> /etc/cron.d/pwned
```

This is CVE-2018-1000001 (Zip Slip).

## The Solution

```python
from safe_unzip import extract_file

extract_file("/var/uploads", "evil.zip")
# Raises: PathEscapeError("../../etc/cron.d/pwned")
```

## Features

- **Path traversal protection** via path_jail
- **Zip bomb protection** with configurable limits
- **Symlink handling** (skip or error)
- **Filter callback** for selective extraction
- **Zero unsafe code**

## Installation

```bash
# Rust
cargo add safe_unzip

# Python
pip install safe-unzip
```

## Usage

### Rust

```rust
use safe_unzip::{extract_file, Extractor, Limits};

// Simple
let report = extract_file("/var/uploads", "archive.zip")?;

// With options
let report = Extractor::new("/var/uploads")?
    .limits(Limits {
        max_total_bytes: 500 * 1024 * 1024,  // 500 MB
        max_file_count: 1000,
        ..Default::default()
    })
    .filter(|e| e.name.ends_with(".png"))
    .extract_file("archive.zip")?;

println!("Extracted {} files", report.files_extracted);
```

### Python

```python
from safe_unzip import extract_file, Extractor

# Simple
report = extract_file("/var/uploads", "archive.zip")

# With options
report = (
    Extractor("/var/uploads")
    .max_total_mb(500)
    .max_files(1000)
    .filter(lambda e: e.name.endswith(".png"))
    .extract_file("archive.zip")
)

print(f"Extracted {report.files_extracted} files")
```

### Validate Before Extracting

Use `validate_first` mode to catch errors before writing any files:

```python
report = (
    Extractor("/var/uploads")
    .mode("validate_first")  # Dry run first, then extract
    .extract_file("untrusted.zip")
)
```

### Filter by Extension

Only extract specific file types:

```rust
// Rust: Only images
.filter(|e| {
    e.name.ends_with(".png") || 
    e.name.ends_with(".jpg")
})
```

```python
# Python: Only images
.filter(lambda e: e.name.endswith((".png", ".jpg")))
```

## Security

| Threat | Protection |
|--------|------------|
| Zip Slip (path traversal) | path_jail validates every entry |
| Zip Bomb (size) | Configurable total size limit |
| Zip Bomb (count) | Configurable file count limit |
| Symlink attacks | Skipped by default |
| Setuid binaries | Dangerous permission bits stripped |

## Limitations

- Zip format only (tar support planned for v0.2)
- Requires seekable input (no stdin streaming)
- Partial extraction on failure in streaming mode (use `validate_first` mode to avoid)

## License

MIT OR Apache-2.0
```

## 11. Checklist

- [ ] Core `Extractor` struct
- [ ] `path_jail` integration
- [ ] Limits enforcement
- [ ] Overwrite policies
- [ ] Symlink policies
- [ ] ExtractionMode (Streaming, ValidateFirst)
- [ ] Filter callback
- [ ] Unix permission handling
- [ ] Error types
- [ ] Unit tests
- [ ] Integration tests with malicious fixtures
- [ ] Python bindings
- [ ] Python tests
- [ ] README
- [ ] `cargo publish`
- [ ] `maturin publish`
