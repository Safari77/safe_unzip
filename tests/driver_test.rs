//! Tests for the new Driver-based architecture.

use safe_unzip::{Driver, OverwriteMode, ValidationMode, ZipAdapter};
use std::io::Write;
use tempfile::tempdir;
use zip::write::FileOptions;

/// Helper to create a simple zip with one file.
fn create_simple_zip(name: &str, content: &[u8]) -> std::fs::File {
    let file = tempfile::tempfile().unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options: FileOptions<()> = FileOptions::default();
    zip.start_file(name, options).unwrap();
    zip.write_all(content).unwrap();
    zip.finish().unwrap()
}

/// Helper to create a zip with multiple files.
fn create_multi_file_zip(files: &[(&str, &[u8])]) -> std::fs::File {
    let file = tempfile::tempfile().unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options: FileOptions<()> = FileOptions::default();

    for (name, content) in files {
        zip.start_file(*name, options).unwrap();
        zip.write_all(content).unwrap();
    }

    zip.finish().unwrap()
}

#[test]
fn test_driver_basic_extraction() {
    let dest = tempdir().unwrap();
    let zip_file = create_simple_zip("hello.txt", b"Hello, World!");

    let adapter = ZipAdapter::new(zip_file).unwrap();
    let report = Driver::new(dest.path())
        .unwrap()
        .extract_zip(adapter)
        .unwrap();

    assert_eq!(report.files_extracted, 1);
    assert_eq!(report.bytes_written, 13);
    assert!(dest.path().join("hello.txt").exists());

    let content = std::fs::read_to_string(dest.path().join("hello.txt")).unwrap();
    assert_eq!(content, "Hello, World!");

    println!("✅ Driver basic extraction works");
}

#[test]
fn test_driver_multiple_files() {
    let dest = tempdir().unwrap();
    let zip_file = create_multi_file_zip(&[
        ("a.txt", b"aaa"),
        ("b.txt", b"bbb"),
        ("subdir/c.txt", b"ccc"),
    ]);

    let adapter = ZipAdapter::new(zip_file).unwrap();
    let report = Driver::new(dest.path())
        .unwrap()
        .extract_zip(adapter)
        .unwrap();

    assert_eq!(report.files_extracted, 3);
    assert!(dest.path().join("a.txt").exists());
    assert!(dest.path().join("subdir/c.txt").exists());

    println!("✅ Driver multiple files extraction works");
}

#[test]
fn test_driver_blocks_path_traversal() {
    let dest = tempdir().unwrap();
    let zip_file = create_simple_zip("../../etc/passwd", b"evil");

    let adapter = ZipAdapter::new(zip_file).unwrap();
    let result = Driver::new(dest.path()).unwrap().extract_zip(adapter);

    assert!(result.is_err());
    println!("✅ Driver blocks path traversal");
}

#[test]
fn test_driver_validate_first_mode() {
    let dest = tempdir().unwrap();

    // Create zip with valid file then traversal attempt
    let file = tempfile::tempfile().unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options: FileOptions<()> = FileOptions::default();

    zip.start_file("good.txt", options).unwrap();
    zip.write_all(b"This is fine").unwrap();

    zip.start_file("../../evil.txt", options).unwrap();
    zip.write_all(b"pwned").unwrap();

    let zip_file = zip.finish().unwrap();

    let adapter = ZipAdapter::new(zip_file).unwrap();
    let result = Driver::new(dest.path())
        .unwrap()
        .validation(ValidationMode::ValidateFirst)
        .extract_zip(adapter);

    // Should fail
    assert!(result.is_err());

    // Nothing should be written in ValidateFirst mode
    assert!(
        !dest.path().join("good.txt").exists(),
        "ValidateFirst should not write good.txt before failing"
    );

    println!("✅ Driver ValidateFirst mode works");
}

#[test]
fn test_driver_overwrite_error() {
    let dest = tempdir().unwrap();

    // First extraction
    let zip1 = create_simple_zip("test.txt", b"original");
    let adapter1 = ZipAdapter::new(zip1).unwrap();
    Driver::new(dest.path())
        .unwrap()
        .extract_zip(adapter1)
        .unwrap();

    // Second extraction should fail (default is Error)
    let zip2 = create_simple_zip("test.txt", b"modified");
    let adapter2 = ZipAdapter::new(zip2).unwrap();
    let result = Driver::new(dest.path())
        .unwrap()
        .overwrite(OverwriteMode::Error)
        .extract_zip(adapter2);

    assert!(result.is_err());

    // Content should be unchanged
    let content = std::fs::read_to_string(dest.path().join("test.txt")).unwrap();
    assert_eq!(content, "original");

    println!("✅ Driver OverwriteMode::Error works");
}

#[test]
fn test_driver_overwrite_skip() {
    let dest = tempdir().unwrap();

    // First extraction
    let zip1 = create_simple_zip("test.txt", b"original");
    let adapter1 = ZipAdapter::new(zip1).unwrap();
    Driver::new(dest.path())
        .unwrap()
        .extract_zip(adapter1)
        .unwrap();

    // Second extraction with Skip
    let zip2 = create_simple_zip("test.txt", b"modified");
    let adapter2 = ZipAdapter::new(zip2).unwrap();
    let report = Driver::new(dest.path())
        .unwrap()
        .overwrite(OverwriteMode::Skip)
        .extract_zip(adapter2)
        .unwrap();

    assert_eq!(report.entries_skipped, 1);

    // Content should be unchanged
    let content = std::fs::read_to_string(dest.path().join("test.txt")).unwrap();
    assert_eq!(content, "original");

    println!("✅ Driver OverwriteMode::Skip works");
}

#[test]
fn test_driver_overwrite_overwrite() {
    let dest = tempdir().unwrap();

    // First extraction
    let zip1 = create_simple_zip("test.txt", b"original");
    let adapter1 = ZipAdapter::new(zip1).unwrap();
    Driver::new(dest.path())
        .unwrap()
        .extract_zip(adapter1)
        .unwrap();

    // Second extraction with Overwrite
    let zip2 = create_simple_zip("test.txt", b"modified");
    let adapter2 = ZipAdapter::new(zip2).unwrap();
    let report = Driver::new(dest.path())
        .unwrap()
        .overwrite(OverwriteMode::Overwrite)
        .extract_zip(adapter2)
        .unwrap();

    assert_eq!(report.files_extracted, 1);

    // Content should be updated
    let content = std::fs::read_to_string(dest.path().join("test.txt")).unwrap();
    assert_eq!(content, "modified");

    println!("✅ Driver OverwriteMode::Overwrite works");
}

#[test]
fn test_driver_filter() {
    let dest = tempdir().unwrap();
    let zip_file = create_multi_file_zip(&[
        ("image.png", b"png data"),
        ("document.txt", b"text data"),
        ("photo.jpg", b"jpg data"),
    ]);

    let adapter = ZipAdapter::new(zip_file).unwrap();
    let report = Driver::new(dest.path())
        .unwrap()
        .filter(|info| info.name.ends_with(".txt"))
        .extract_zip(adapter)
        .unwrap();

    assert_eq!(report.files_extracted, 1);
    assert!(dest.path().join("document.txt").exists());
    assert!(!dest.path().join("image.png").exists());
    assert!(!dest.path().join("photo.jpg").exists());

    println!("✅ Driver filter works");
}

#[test]
fn test_driver_atomic_file_creation() {
    // Test that OverwriteMode::Error uses atomic creation
    // This is a basic test - race conditions are hard to test deterministically
    let dest = tempdir().unwrap();

    // Create a file first
    std::fs::write(dest.path().join("existing.txt"), "original").unwrap();

    // Create a zip that tries to extract to the same name
    let zip_file = create_simple_zip("existing.txt", b"new content");

    let adapter = ZipAdapter::new(zip_file).unwrap();
    let result = Driver::new(dest.path())
        .unwrap()
        .overwrite(OverwriteMode::Error)
        .extract_zip(adapter);

    // Should fail with AlreadyExists
    assert!(matches!(
        result,
        Err(safe_unzip::Error::AlreadyExists { .. })
    ));

    // Original content should be preserved
    let content = std::fs::read_to_string(dest.path().join("existing.txt")).unwrap();
    assert_eq!(content, "original");

    println!("✅ Driver atomic file creation works");
}
