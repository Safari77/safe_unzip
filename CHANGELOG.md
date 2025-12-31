# Changelog

All notable changes to this project will be documented in this file.

## [0.1.1] - 2025-12-31

### Changed

- Upgraded `path_jail` dependency from 0.1 to 0.2
- Added ARM64 CI builds (Linux arm64, Windows arm64)

### Fixed

- Fixed PyPI sdist build (README handling)

## [0.1.0] - 2025-12-31

### Initial Release 🎉

**safe_unzip** is a secure zip extraction library that prevents common archive-based attacks.

### Features

- **Zip Slip Prevention**: Blocks path traversal attacks (`../../etc/passwd`)
- **Zip Bomb Protection**: Limits on total size, file count, single file size, and path depth
- **Symlink Safety**: Configurable policies (skip or error)
- **Secure Overwrite**: Removes symlinks before overwriting to prevent TOCTOU attacks
- **Filename Sanitization**: Rejects control characters, backslashes, Windows reserved names
- **Strict Size Enforcement**: Catches zip bombs that lie about declared size
- **Two Extraction Modes**: 
  - `Streaming` (default): Fast, may leave partial state on error
  - `ValidateFirst`: Two-pass, atomic (all-or-nothing)

### Python Bindings

Full Python bindings with identical security guarantees:

```python
from safe_unzip import Extractor

Extractor("/path/to/dest").extract_file("archive.zip")
```

### Platforms

- Linux (x86_64)
- macOS (arm64, x86_64)
- Windows (x86_64)

### Links

- [crates.io](https://crates.io/crates/safe_unzip)
- [PyPI](https://pypi.org/project/safe-unzip/)
- [Documentation](https://github.com/tenuo-ai/safe_unzip)

