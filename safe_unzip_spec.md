# safe_unzip Specification (v0.4.0+)

Archive extraction that won't ruin your day.

> **Note:** This spec reflects v0.4.0 with Python TAR bindings added post-release.

## 1. Overview

`safe_unzip` is a secure archive extraction library that prevents:

- **Zip Slip**: Path traversal via `../../` in entry names
- **Zip Bombs**: Archives that expand to exhaust disk/memory
- **Symlink Attacks**: Symlinks pointing outside extraction directory

Built on cap-std for capability-based, sandboxed filesystem access, ensuring operations cannot escape the target directory.

## 2. Threat Model

| Threat | Attack Vector | Defense |
|--------|---------------|---------|
| Zip Slip | Entry named `../../etc/cron.d/pwned` | `path_jail` validates every path |
| Zip Bomb (size) | 42KB expands to 4PB | `max_total_bytes` limit |
| Zip Bomb (count) | 1 million empty files | `max_file_count` limit |
| Zip Bomb (ratio) | Single file with extreme compression | `max_single_file` limit |
| Zip Bomb (lying) | Declared 1KB, decompresses to 1GB | `LimitReader` enforces during read |
| Symlink Escape | Symlink to `/etc/passwd` | Skip or error on symlinks |
| Symlink Overwrite | Create symlink, then overwrite its target | Remove symlinks before overwrite |
| Path Depth | `a/b/c/d/.../` to 10000 levels | `max_path_depth` limit |
| Invalid Filename | Control chars, `CON`, `NUL`, backslashes | Filename sanitization |
| Overwrite | Replace existing sensitive file | `OverwritePolicy::Error` default |
| Setuid Escalation | Archive creates setuid binaries | Permission bits stripped |
| Device Files (TAR) | TAR contains block/char devices, FIFOs | `UnsupportedEntryType` error |
| TOCTOU Race | Check-then-create race condition | Atomic `create_new(true)` via openat2 |

## 3. Scope

### v0.4.0 (This Spec)

- **ZIP format** — Full support (deflate, deflate64, lzma, aes-crypto)
- **TAR format** — Plain `.tar` and gzip-compressed `.tar.gz`
- **7Z format** — Full support via sevenz-rust2
- Async API (via tokio)
- File and directory extraction
- Configurable limits
- Filter callback
- New adapter/policy/driver architecture for extensibility

### Non-Goals

- Creating archives (extraction only)
- Self-extracting archives

## 4. Dependencies

```toml
[dependencies]

cap-std = { version = "4", features = ["fs_utf8"] }
zip = "8"
tar = "0.4"
flate2 = "1"  # For .tar.gz support
tokio = { version = "1", features = ["rt", "fs", "sync"], optional = true }
sevenz-rust2 = "0"

[features]
default = []
async = ["tokio"]
```

## 6. Implementation Notes

### 6.1 Two-Pass Extraction (ValidateFirst Mode)

When `ExtractionMode::ValidateFirst` is set:

1. **Pass 1 (Validation):** Iterate all entries using `by_index_raw()` (no decompression) for ZIP or caching to memory for TAR.
  Check paths, limits, policies. Accumulate totals.
2. **Pass 2 (Extraction):** Only runs if validation passed. Extract files normally.

### 6.2 Secure Overwrite

Symlink attack: archive creates /uploads/log -> /etc/passwd, second extraction overwrites through symlink.
Defense: Use symlink_metadata() on the cap_std::fs_utf8::Dir file descriptor to detect symlinks and remove them before writing (don't follow).

### 6.4 Atomic File Creation (TOCTOU Mitigation)
For OverwriteMode::Error and OverwriteMode::Skip, use create_new(true) via cap-std which uses openat2 securely under the hood on Unix systems:
```
self.dir.open_with(
    &actual_path,
    OpenOptions::new().write(true).create_new(true)
)
```

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
from safe_unzip import (
    # ZIP functions
    extract_file, extract_bytes,
    # TAR functions
    extract_tar_file, extract_tar_gz_file, extract_tar_bytes,
    # Builder
    Extractor,
)

# Simple ZIP extraction
report = extract_file("/var/uploads", "archive.zip")
report = extract_bytes("/var/uploads", zip_data)

# Simple TAR extraction
report = extract_tar_file("/var/uploads", "archive.tar")
report = extract_tar_gz_file("/var/uploads", "archive.tar.gz")
report = extract_tar_bytes("/var/uploads", tar_data)

# With options (works for both ZIP and TAR)
extractor = (
    Extractor("/var/uploads")
    .max_total_mb(500)
    .max_files(1000)
    .max_single_file_mb(50)
    .max_depth(20)
    .overwrite("skip")          # "error" | "skip" | "overwrite"
    .symlinks("error")          # "skip" | "error"
    .mode("validate_first")     # "streaming" | "validate_first"
)

# ZIP via Extractor
report = extractor.extract_file("archive.zip")
report = extractor.extract_bytes(zip_data)

# TAR via Extractor
report = extractor.extract_tar_file("archive.tar")
report = extractor.extract_tar_gz_file("archive.tar.gz")
report = extractor.extract_tar_bytes(tar_data)
report = extractor.extract_tar_gz_bytes(tar_gz_data)

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

### 7.4 Error Handling

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

Exception hierarchy:

```
Exception
  SafeUnzipError (base)
    PathEscapeError           # Traversal, invalid filename
    SymlinkNotAllowedError    # Symlink with policy=error
    QuotaError                # All limit violations (size, count, depth)
    AlreadyExistsError        # File exists with policy=error
    EncryptedArchiveError     # Encrypted ZIP entries
    UnsupportedEntryTypeError # Device files, FIFOs in TAR
  OSError (for IO errors)
```

## 8. Project Structure

### 8.1 Flattened Layout

This is a small crate with one binding. We use a flat structure:

```
safe_unzip/
├── Cargo.toml                    # Workspace root + core library
├── src/
│   ├── lib.rs                    # Public API
│   ├── extractor.rs              # Legacy ZIP-only API
│   ├── driver.rs                 # New generic extraction driver
│   ├── limits.rs                 # Resource limits
│   ├── error.rs                  # Error types
│   ├── entry.rs                  # Generic entry types
│   ├── policy.rs                 # Security policies
│   └── adapter/
│       ├── mod.rs
│       ├── zip_adapter.rs        # ZIP format adapter
│       └── tar_adapter.rs        # TAR format adapter
├── python/                       # Python bindings
│   ├── Cargo.toml
│   ├── pyproject.toml
│   ├── src/
│   │   └── lib.rs                # PyO3 bindings
│   └── python/
│       └── safe_unzip/
│           ├── __init__.py
│           ├── __init__.pyi      # Type stubs
│           └── py.typed          # PEP 561 marker
├── fuzz/                         # Fuzzing targets
│   ├── Cargo.toml
│   └── fuzz_targets/
│       ├── fuzz_extract.rs
│       └── fuzz_zip_adapter.rs
├── tests/
│   ├── security_test.rs          # ZIP security tests
│   ├── driver_test.rs            # Driver API tests
│   └── tar_test.rs               # TAR tests
├── README.md
├── LICENSE-MIT
└── LICENSE-APACHE
```

### 8.2 Key Configuration

- **Root `Cargo.toml`**: Workspace with `members = [".", "python"]`
- **Dependencies**: `path_jail = "0.2"`, `zip = "2.1"`, `tar = "0.4"`, `flate2 = "1"`
- **Python bindings**: PyO3 0.28, maturin build system
- **Package name**: `safe-unzip` on PyPI, `safe_unzip` on crates.io
- **Fuzzing**: cargo-fuzz with libfuzzer

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

### 9.2 Required Test Coverage

**Rust tests must verify (ZIP):**
- Path traversal blocked (`PathEscape` error)
- Symlink escape blocked (skip or `SymlinkNotAllowed`)
- Size limits enforced (`TotalSizeExceeded`, `FileTooLarge`)
- File count limits enforced (`FileCountExceeded`)
- Path depth limits enforced (`PathTooDeep`)
- Overwrite policies work (Error, Skip, Overwrite)
- Filter callback works
- ValidateFirst prevents partial state
- Setuid bits stripped (Unix only)
- Size mismatch detected (`SizeMismatch`)
- Encrypted entries rejected (`EncryptedEntry`)
- Atomic file creation (TOCTOU)

**Rust tests must verify (TAR):**
- Basic extraction (.tar)
- Gzip extraction (.tar.gz)
- Path traversal blocked
- Absolute paths blocked/sanitized
- Symlink policies (skip, error)
- Hard links treated as symlinks
- Device files rejected (block, char, fifo)
- Setuid/setgid bits stripped
- Size/count/depth limits enforced
- ValidateFirst mode
- Filter callback works

**Python tests must verify:**
- Same security guarantees as Rust (ZIP and TAR)
- Exception hierarchy works (`PathEscapeError`, `QuotaError`, `EncryptedArchiveError`, `UnsupportedEntryTypeError`)
- Builder API works with string policies
- TAR extraction methods work
