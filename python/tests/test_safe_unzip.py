"""Tests for safe_unzip Python bindings.

These tests verify that the Python bindings have identical security
guarantees to the Rust implementation.
"""

import io
import os
import zipfile
from pathlib import Path

import pytest

from safe_unzip import (
    Extractor,
    extract_file,
    extract_bytes,
    PathEscapeError,
    QuotaError,
    AlreadyExistsError,
)


# ============================================================================
# Helper Functions
# ============================================================================

def create_simple_zip(filename: str, content: bytes) -> bytes:
    """Create a zip file with a single entry."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as zf:
        zf.writestr(filename, content)
    return buffer.getvalue()


def create_multi_file_zip(files: dict[str, bytes]) -> bytes:
    """Create a zip file with multiple entries."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buffer.getvalue()


# ============================================================================
# Basic Functionality Tests
# ============================================================================

def test_extract_simple_zip(tmp_path):
    """Test basic extraction works."""
    zip_data = create_simple_zip("hello.txt", b"Hello, World!")
    
    report = Extractor(tmp_path).extract_bytes(zip_data)
    
    assert report.files_extracted == 1
    assert report.bytes_written == 13
    assert (tmp_path / "hello.txt").read_text() == "Hello, World!"


def test_extract_multiple_files(tmp_path):
    """Test extracting multiple files."""
    zip_data = create_multi_file_zip({
        "a.txt": b"aaa",
        "b.txt": b"bbb",
        "subdir/c.txt": b"ccc",
    })
    
    report = Extractor(tmp_path).extract_bytes(zip_data)
    
    assert report.files_extracted == 3
    assert report.dirs_created >= 1  # subdir
    assert (tmp_path / "a.txt").exists()
    assert (tmp_path / "subdir" / "c.txt").exists()


def test_extract_creates_destination(tmp_path):
    """Test that extract_bytes creates destination if missing."""
    new_dest = tmp_path / "new_folder"
    zip_data = create_simple_zip("file.txt", b"data")
    
    # Extractor with non-existent path should work
    report = Extractor(new_dest).extract_bytes(zip_data)
    
    assert new_dest.exists()
    assert (new_dest / "file.txt").exists()


# ============================================================================
# Security Tests: Path Traversal (Zip Slip)
# ============================================================================

def test_blocks_path_traversal(tmp_path):
    """Test that path traversal attacks are blocked."""
    # Create malicious zip with traversal path
    zip_data = create_simple_zip("../../etc/passwd", b"evil")
    
    with pytest.raises(PathEscapeError):
        Extractor(tmp_path).extract_bytes(zip_data)
    
    # Ensure nothing was written outside
    assert not (tmp_path.parent.parent / "etc" / "passwd").exists()


def test_blocks_absolute_path(tmp_path):
    """Test that absolute paths are blocked or contained."""
    zip_data = create_simple_zip("/tmp/evil.txt", b"evil")
    
    # Should either raise PathEscapeError or safely contain it
    try:
        Extractor(tmp_path).extract_bytes(zip_data)
        # If it succeeded, verify it didn't write to actual /tmp
        assert not Path("/tmp/evil.txt").exists()
    except PathEscapeError:
        pass  # Expected behavior


def test_blocks_backslash_traversal(tmp_path):
    """Test that backslash paths are rejected."""
    zip_data = create_simple_zip("folder\\file.txt", b"data")
    
    with pytest.raises(PathEscapeError):
        Extractor(tmp_path).extract_bytes(zip_data)


@pytest.mark.skipif(os.name != 'nt', reason="Windows-only test")
def test_blocks_windows_drive_path(tmp_path):
    """Test that Windows drive paths are blocked."""
    zip_data = create_simple_zip("C:\\Windows\\evil.txt", b"evil")
    
    # Should either raise PathEscapeError or safely contain it
    try:
        Extractor(tmp_path).extract_bytes(zip_data)
        # If succeeded, ensure it didn't write to actual C:\Windows
        assert not Path("C:\\Windows\\evil.txt").exists()
    except PathEscapeError:
        pass  # Expected behavior


# ============================================================================
# Security Tests: Zip Bombs
# ============================================================================

def test_enforces_total_size_limit(tmp_path):
    """Test that total size limit is enforced."""
    # Create zip with content larger than limit
    zip_data = create_simple_zip("big.txt", b"x" * 1000)
    
    with pytest.raises(QuotaError):
        Extractor(tmp_path).max_total_mb(0).extract_bytes(zip_data)  # 0 MB limit


def test_enforces_file_count_limit(tmp_path):
    """Test that file count limit is enforced."""
    zip_data = create_multi_file_zip({
        "a.txt": b"a",
        "b.txt": b"b",
        "c.txt": b"c",
        "d.txt": b"d",
        "e.txt": b"e",
    })
    
    with pytest.raises(QuotaError):
        Extractor(tmp_path).max_files(3).extract_bytes(zip_data)


def test_enforces_single_file_limit(tmp_path):
    """Test that single file size limit is enforced."""
    zip_data = create_simple_zip("big.txt", b"x" * 10000)
    
    with pytest.raises(QuotaError):
        # 1 byte limit per file
        Extractor(tmp_path).max_single_file_mb(0).extract_bytes(zip_data)


def test_enforces_path_depth_limit(tmp_path):
    """Test that path depth limit is enforced."""
    deep_path = "/".join(["d"] * 100) + "/file.txt"
    zip_data = create_simple_zip(deep_path, b"deep")
    
    with pytest.raises(QuotaError):
        Extractor(tmp_path).max_depth(10).extract_bytes(zip_data)


# ============================================================================
# Security Tests: Overwrite Policies
# ============================================================================

def test_overwrite_policy_error(tmp_path):
    """Test that overwrite policy 'error' raises on existing files."""
    (tmp_path / "existing.txt").write_text("original")
    zip_data = create_simple_zip("existing.txt", b"new")
    
    with pytest.raises(AlreadyExistsError):
        Extractor(tmp_path).overwrite("error").extract_bytes(zip_data)
    
    # Original should be unchanged
    assert (tmp_path / "existing.txt").read_text() == "original"


def test_overwrite_policy_skip(tmp_path):
    """Test that overwrite policy 'skip' preserves existing files."""
    (tmp_path / "existing.txt").write_text("original")
    zip_data = create_simple_zip("existing.txt", b"new")
    
    report = Extractor(tmp_path).overwrite("skip").extract_bytes(zip_data)
    
    assert report.entries_skipped == 1
    assert (tmp_path / "existing.txt").read_text() == "original"


def test_overwrite_policy_overwrite(tmp_path):
    """Test that overwrite policy 'overwrite' replaces existing files."""
    (tmp_path / "existing.txt").write_text("original")
    zip_data = create_simple_zip("existing.txt", b"new")
    
    report = Extractor(tmp_path).overwrite("overwrite").extract_bytes(zip_data)
    
    assert report.files_extracted == 1
    assert (tmp_path / "existing.txt").read_bytes() == b"new"


# ============================================================================
# Security Tests: Symlinks (Unix only)
# ============================================================================

@pytest.mark.skipif(os.name != 'posix', reason="Unix-only test")
def test_symlink_overwrite_protection(tmp_path):
    """Test that symlinks are removed before overwriting, not followed."""
    # Create target and symlink
    target = tmp_path / "target.txt"
    target.write_text("sensitive")
    link = tmp_path / "link"
    link.symlink_to(target)
    
    # Create zip that writes to "link"
    zip_data = create_simple_zip("link", b"overwritten")
    
    # Extract with overwrite
    Extractor(tmp_path).overwrite("overwrite").extract_bytes(zip_data)
    
    # Link should now be a regular file
    assert not link.is_symlink()
    assert link.read_bytes() == b"overwritten"
    
    # Target should be unchanged (symlink was removed, not followed)
    assert target.read_text() == "sensitive"


# ============================================================================
# Extraction Mode Tests
# ============================================================================

def test_validate_first_prevents_partial_extraction(tmp_path):
    """Test that validate_first mode doesn't write if validation fails."""
    # Create zip with valid file first, then traversal attempt
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as zf:
        zf.writestr("good.txt", b"good")
        zf.writestr("../../evil.txt", b"evil")
    zip_data = buffer.getvalue()
    
    with pytest.raises(PathEscapeError):
        Extractor(tmp_path).mode("validate_first").extract_bytes(zip_data)
    
    # Nothing should be extracted (not even good.txt)
    assert not (tmp_path / "good.txt").exists()


def test_streaming_may_leave_partial_state(tmp_path):
    """Test that streaming mode may leave partial files on failure."""
    # Create zip with valid file first, then traversal attempt
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as zf:
        zf.writestr("good.txt", b"good")
        zf.writestr("../../evil.txt", b"evil")
    zip_data = buffer.getvalue()
    
    with pytest.raises(PathEscapeError):
        Extractor(tmp_path).mode("streaming").extract_bytes(zip_data)
    
    # In streaming mode, good.txt MAY have been extracted before failure
    # (This is expected behavior, not a bug)


# ============================================================================
# Invalid Filename Tests
# ============================================================================

def test_rejects_null_byte_in_filename(tmp_path):
    """Test that null bytes in filenames are rejected."""
    zip_data = create_simple_zip("file.txt\x00.exe", b"data")
    
    with pytest.raises(PathEscapeError):
        Extractor(tmp_path).extract_bytes(zip_data)


def test_rejects_empty_filename(tmp_path):
    """Test that empty filenames are rejected."""
    zip_data = create_simple_zip("", b"data")
    
    with pytest.raises(PathEscapeError):
        Extractor(tmp_path).extract_bytes(zip_data)

