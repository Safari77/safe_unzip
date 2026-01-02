"""
safe_unzip - Secure archive extraction that prevents Zip Slip and Zip Bombs.

Example usage:
    from safe_unzip import extract_file, extract_tar_file
    
    # ZIP extraction
    report = extract_file("/var/uploads", "archive.zip")
    print(f"Extracted {report.files_extracted} files")
    
    # TAR extraction
    report = extract_tar_file("/var/uploads", "archive.tar")
    report = extract_tar_gz_file("/var/uploads", "archive.tar.gz")

With options:
    from safe_unzip import Extractor
    
    report = (
        Extractor("/var/uploads")
        .max_total_mb(500)
        .max_files(1000)
        .mode("validate_first")
        .extract_file("archive.zip")  # or .extract_tar_file("archive.tar")
    )

Async usage:
    from safe_unzip import async_extract_file, AsyncExtractor
    
    # Convenience function
    report = await async_extract_file("/var/uploads", "archive.zip")
    
    # With options
    report = await (
        AsyncExtractor("/var/uploads")
        .max_total_mb(500)
        .extract_file("archive.zip")
    )
"""

import asyncio
from os import PathLike
from pathlib import Path
from typing import Union, Literal, Optional, Callable

from safe_unzip._safe_unzip import (
    # Classes
    Extractor,
    Report,
    # Functions - ZIP
    extract_file,
    extract_bytes,
    # Functions - TAR
    extract_tar_file,
    extract_tar_gz_file,
    extract_tar_bytes,
    # Exceptions
    SafeUnzipError,
    PathEscapeError,
    SymlinkNotAllowedError,
    QuotaError,
    AlreadyExistsError,
    EncryptedArchiveError,
    UnsupportedEntryTypeError,
)

_PathType = Union[str, PathLike, Path]
_OverwritePolicy = Literal["error", "skip", "overwrite"]
_SymlinkPolicy = Literal["skip", "error"]
_ExtractionMode = Literal["streaming", "validate_first"]


# ============================================================================
# Async Convenience Functions
# ============================================================================

async def async_extract_file(destination: _PathType, path: _PathType) -> Report:
    """Extract a ZIP file asynchronously with default settings."""
    return await asyncio.to_thread(extract_file, destination, path)


async def async_extract_bytes(destination: _PathType, data: bytes) -> Report:
    """Extract ZIP from bytes asynchronously with default settings."""
    return await asyncio.to_thread(extract_bytes, destination, data)


async def async_extract_tar_file(destination: _PathType, path: _PathType) -> Report:
    """Extract a TAR file asynchronously with default settings."""
    return await asyncio.to_thread(extract_tar_file, destination, path)


async def async_extract_tar_gz_file(destination: _PathType, path: _PathType) -> Report:
    """Extract a gzip-compressed TAR file asynchronously with default settings."""
    return await asyncio.to_thread(extract_tar_gz_file, destination, path)


async def async_extract_tar_bytes(destination: _PathType, data: bytes) -> Report:
    """Extract TAR from bytes asynchronously with default settings."""
    return await asyncio.to_thread(extract_tar_bytes, destination, data)


# ============================================================================
# AsyncExtractor - Async wrapper for Extractor
# ============================================================================

class AsyncExtractor:
    """Async archive extractor with security constraints. Supports ZIP and TAR.
    
    Example:
        report = await (
            AsyncExtractor("/var/uploads")
            .max_total_mb(500)
            .max_files(1000)
            .extract_file("archive.zip")
        )
    """
    
    def __init__(self, destination: _PathType) -> None:
        """Create async extractor for the given destination directory."""
        self._extractor = Extractor(destination)
    
    def max_total_mb(self, mb: int) -> "AsyncExtractor":
        """Set maximum total bytes to extract (in megabytes)."""
        self._extractor.max_total_mb(mb)
        return self
    
    def max_files(self, count: int) -> "AsyncExtractor":
        """Set maximum number of files to extract."""
        self._extractor.max_files(count)
        return self
    
    def max_single_file_mb(self, mb: int) -> "AsyncExtractor":
        """Set maximum size of a single file (in megabytes)."""
        self._extractor.max_single_file_mb(mb)
        return self
    
    def max_depth(self, depth: int) -> "AsyncExtractor":
        """Set maximum directory depth."""
        self._extractor.max_depth(depth)
        return self
    
    def overwrite(self, policy: _OverwritePolicy) -> "AsyncExtractor":
        """Set overwrite policy: 'error', 'skip', or 'overwrite'."""
        self._extractor.overwrite(policy)
        return self
    
    def symlinks(self, policy: _SymlinkPolicy) -> "AsyncExtractor":
        """Set symlink policy: 'skip' or 'error'."""
        self._extractor.symlinks(policy)
        return self
    
    def mode(self, mode: _ExtractionMode) -> "AsyncExtractor":
        """Set extraction mode: 'streaming' or 'validate_first'."""
        self._extractor.mode(mode)
        return self
    
    # ZIP extraction
    async def extract_file(self, path: _PathType) -> Report:
        """Extract a ZIP file asynchronously."""
        return await asyncio.to_thread(self._extractor.extract_file, path)
    
    async def extract_bytes(self, data: bytes) -> Report:
        """Extract ZIP from bytes asynchronously."""
        return await asyncio.to_thread(self._extractor.extract_bytes, data)
    
    # TAR extraction
    async def extract_tar_file(self, path: _PathType) -> Report:
        """Extract a TAR file asynchronously."""
        return await asyncio.to_thread(self._extractor.extract_tar_file, path)
    
    async def extract_tar_gz_file(self, path: _PathType) -> Report:
        """Extract a gzip-compressed TAR file (.tar.gz, .tgz) asynchronously."""
        return await asyncio.to_thread(self._extractor.extract_tar_gz_file, path)
    
    async def extract_tar_bytes(self, data: bytes) -> Report:
        """Extract TAR from bytes asynchronously."""
        return await asyncio.to_thread(self._extractor.extract_tar_bytes, data)
    
    async def extract_tar_gz_bytes(self, data: bytes) -> Report:
        """Extract gzip-compressed TAR from bytes asynchronously."""
        return await asyncio.to_thread(self._extractor.extract_tar_gz_bytes, data)


__all__ = [
    # Classes
    "Extractor",
    "AsyncExtractor",
    "Report",
    # Sync Functions - ZIP
    "extract_file",
    "extract_bytes",
    # Sync Functions - TAR
    "extract_tar_file",
    "extract_tar_gz_file",
    "extract_tar_bytes",
    # Async Functions - ZIP
    "async_extract_file",
    "async_extract_bytes",
    # Async Functions - TAR
    "async_extract_tar_file",
    "async_extract_tar_gz_file",
    "async_extract_tar_bytes",
    # Exceptions
    "SafeUnzipError",
    "PathEscapeError",
    "SymlinkNotAllowedError",
    "QuotaError",
    "AlreadyExistsError",
    "EncryptedArchiveError",
    "UnsupportedEntryTypeError",
]

__version__ = "0.1.3"

