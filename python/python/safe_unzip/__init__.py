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
"""

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

__all__ = [
    # Classes
    "Extractor",
    "Report",
    # Functions - ZIP
    "extract_file",
    "extract_bytes",
    # Functions - TAR
    "extract_tar_file",
    "extract_tar_gz_file",
    "extract_tar_bytes",
    # Exceptions
    "SafeUnzipError",
    "PathEscapeError",
    "SymlinkNotAllowedError",
    "QuotaError",
    "AlreadyExistsError",
    "EncryptedArchiveError",
    "UnsupportedEntryTypeError",
]

__version__ = "0.1.2"

