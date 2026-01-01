//! Tests for TAR archive extraction.

use safe_unzip::{Driver, TarAdapter, ValidationMode};
use std::io::Write;
use tempfile::tempdir;

/// Create a simple tar archive with one file.
fn create_simple_tar(name: &str, content: &[u8]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());

    let mut header = tar::Header::new_gnu();
    header.set_path(name).unwrap();
    header.set_size(content.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();

    builder.append(&header, content).unwrap();
    builder.into_inner().unwrap()
}

/// Create a tar archive with multiple files.
fn create_multi_file_tar(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());

    for (name, content) in files {
        let mut header = tar::Header::new_gnu();
        header.set_path(*name).unwrap();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();

        builder.append(&header, *content).unwrap();
    }

    builder.into_inner().unwrap()
}

/// Create a tar archive with a directory.
fn create_tar_with_dir(dir_name: &str, file_name: &str, content: &[u8]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());

    // Add directory
    let mut header = tar::Header::new_gnu();
    header.set_path(dir_name).unwrap();
    header.set_size(0);
    header.set_mode(0o755);
    header.set_entry_type(tar::EntryType::Directory);
    header.set_cksum();
    builder.append(&header, &[][..]).unwrap();

    // Add file in directory
    let full_path = format!("{}/{}", dir_name.trim_end_matches('/'), file_name);
    let mut header = tar::Header::new_gnu();
    header.set_path(&full_path).unwrap();
    header.set_size(content.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append(&header, content).unwrap();

    builder.into_inner().unwrap()
}

#[test]
fn test_tar_basic_extraction() {
    let dest = tempdir().unwrap();
    let tar_data = create_simple_tar("hello.txt", b"Hello, TAR!");

    let adapter = TarAdapter::new(std::io::Cursor::new(tar_data));
    let report = Driver::new(dest.path())
        .unwrap()
        .extract_tar(adapter)
        .unwrap();

    assert_eq!(report.files_extracted, 1);
    assert_eq!(report.bytes_written, 11);
    assert!(dest.path().join("hello.txt").exists());

    let content = std::fs::read_to_string(dest.path().join("hello.txt")).unwrap();
    assert_eq!(content, "Hello, TAR!");

    println!("✅ TAR basic extraction works");
}

#[test]
fn test_tar_multiple_files() {
    let dest = tempdir().unwrap();
    let tar_data =
        create_multi_file_tar(&[("a.txt", b"aaa"), ("b.txt", b"bbb"), ("c.txt", b"ccc")]);

    let adapter = TarAdapter::new(std::io::Cursor::new(tar_data));
    let report = Driver::new(dest.path())
        .unwrap()
        .extract_tar(adapter)
        .unwrap();

    assert_eq!(report.files_extracted, 3);
    assert!(dest.path().join("a.txt").exists());
    assert!(dest.path().join("b.txt").exists());
    assert!(dest.path().join("c.txt").exists());

    println!("✅ TAR multiple files extraction works");
}

#[test]
fn test_tar_with_directory() {
    let dest = tempdir().unwrap();
    let tar_data = create_tar_with_dir("subdir/", "file.txt", b"in subdir");

    let adapter = TarAdapter::new(std::io::Cursor::new(tar_data));
    let report = Driver::new(dest.path())
        .unwrap()
        .extract_tar(adapter)
        .unwrap();

    assert_eq!(report.files_extracted, 1);
    assert_eq!(report.dirs_created, 1);
    assert!(dest.path().join("subdir/file.txt").exists());

    println!("✅ TAR with directory works");
}

#[test]
fn test_tar_blocks_path_traversal() {
    let dest = tempdir().unwrap();

    // Create a tar with path traversal attempt using raw bytes
    // The tar crate's set_path() blocks "..", so we manually construct the header
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();

    // Use a safe path first, then modify the raw bytes
    header.set_path("placeholder").unwrap();
    header.set_size(4);
    header.set_mode(0o644);

    // Manually set the path in the header bytes
    let evil_path = b"../../etc/passwd";
    header.as_mut_bytes()[..evil_path.len()].copy_from_slice(evil_path);
    header.as_mut_bytes()[evil_path.len()] = 0; // Null terminate

    header.set_cksum();
    builder.append(&header, &b"evil"[..]).unwrap();
    let tar_data = builder.into_inner().unwrap();

    let adapter = TarAdapter::new(std::io::Cursor::new(tar_data));
    let result = Driver::new(dest.path()).unwrap().extract_tar(adapter);

    assert!(result.is_err());
    println!("✅ TAR blocks path traversal");
}

#[test]
fn test_tar_validate_first_mode() {
    let dest = tempdir().unwrap();

    // Create tar with valid file then traversal attempt
    let mut builder = tar::Builder::new(Vec::new());

    // Good file
    let mut header = tar::Header::new_gnu();
    header.set_path("good.txt").unwrap();
    header.set_size(12);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append(&header, &b"This is fine"[..]).unwrap();

    // Bad file (path traversal) - manually set path to bypass tar crate's check
    let mut header = tar::Header::new_gnu();
    header.set_path("placeholder").unwrap();
    header.set_size(5);
    header.set_mode(0o644);

    let evil_path = b"../../evil.txt";
    header.as_mut_bytes()[..evil_path.len()].copy_from_slice(evil_path);
    header.as_mut_bytes()[evil_path.len()] = 0;

    header.set_cksum();
    builder.append(&header, &b"pwned"[..]).unwrap();

    let tar_data = builder.into_inner().unwrap();

    let adapter = TarAdapter::new(std::io::Cursor::new(tar_data));
    let result = Driver::new(dest.path())
        .unwrap()
        .validation(ValidationMode::ValidateFirst)
        .extract_tar(adapter);

    // Should fail
    assert!(result.is_err());

    // Nothing should be written in ValidateFirst mode
    assert!(
        !dest.path().join("good.txt").exists(),
        "ValidateFirst should not write good.txt before failing"
    );

    println!("✅ TAR ValidateFirst mode works");
}

#[test]
fn test_tar_filter() {
    let dest = tempdir().unwrap();
    let tar_data = create_multi_file_tar(&[
        ("image.png", b"png data"),
        ("document.txt", b"text data"),
        ("photo.jpg", b"jpg data"),
    ]);

    let adapter = TarAdapter::new(std::io::Cursor::new(tar_data));
    let report = Driver::new(dest.path())
        .unwrap()
        .filter(|info| info.name.ends_with(".txt"))
        .extract_tar(adapter)
        .unwrap();

    assert_eq!(report.files_extracted, 1);
    assert!(dest.path().join("document.txt").exists());
    assert!(!dest.path().join("image.png").exists());
    assert!(!dest.path().join("photo.jpg").exists());

    println!("✅ TAR filter works");
}

#[test]
fn test_tar_gz_extraction() {
    use flate2::write::GzEncoder;
    use flate2::Compression;

    let dest = tempdir().unwrap();

    // Create tar data
    let tar_data = create_simple_tar("compressed.txt", b"I was compressed!");

    // Compress with gzip
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tar_data).unwrap();
    let gz_data = encoder.finish().unwrap();

    // Extract using GzDecoder
    use flate2::read::GzDecoder;
    let decoder = GzDecoder::new(std::io::Cursor::new(gz_data));
    let adapter = TarAdapter::new(decoder);

    let report = Driver::new(dest.path())
        .unwrap()
        .extract_tar(adapter)
        .unwrap();

    assert_eq!(report.files_extracted, 1);
    assert!(dest.path().join("compressed.txt").exists());

    let content = std::fs::read_to_string(dest.path().join("compressed.txt")).unwrap();
    assert_eq!(content, "I was compressed!");

    println!("✅ TAR.GZ extraction works");
}
