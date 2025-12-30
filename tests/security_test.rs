use safe_unzip::{Extractor, Error};
use std::io::Write;
use tempfile::tempdir;
use zip::write::FileOptions;

fn create_malicious_zip() -> std::io::Result<std::fs::File> {
    let file = tempfile::tempfile()?;
    let mut zip = zip::ZipWriter::new(file);
    
    // Add a normal file (should be processed first if we order it so, 
    // or just checking if the whole thing fails)
    let options: FileOptions<()> = FileOptions::default()
        .compression_method(zip::CompressionMethod::Stored);
    zip.start_file("safe.txt", options.clone())?;
    zip.write_all(b"safe content")?;

    // Add the ATTACK file: tries to write to parent directory
    // We use a raw filename that includes traversal characters
    zip.start_file("../../evil.txt", options)?;
    zip.write_all(b"evil content")?;

    Ok(zip.finish()?)
}

#[test]
fn test_blocks_zip_slip() {
    // 1. Setup
    let root = tempdir().unwrap();
    let zip_file = create_malicious_zip().expect("failed to create fixture");
    
    // 2. Execution
    let result = Extractor::new(root.path())
        .expect("jail init failed")
        .extract(zip_file);

    // 3. Assertion
    match result {
        Err(Error::PathEscape { entry, .. }) => {
            println!("✅ Successfully blocked traversal: {}", entry);
            assert_eq!(entry, "../../evil.txt");
        }
        Ok(_) => panic!("❌ SECURITY FAIL: Malicious file was extracted!"),
        Err(e) => panic!("❌ Unexpected error type: {:?}", e),
    }

    // Double check: ensure 'evil.txt' does NOT exist outside the root
    let evil_path = root.path().join("../../evil.txt");
    if evil_path.exists() {
        // Cleanup if it actually leaked (should never happen)
        let _ = std::fs::remove_file(evil_path); 
        panic!("❌ SECURITY FAIL: File found on disk outside jail!");
    }
}

#[test]
fn test_limits_quota() {
    let root = tempdir().unwrap();
    let file = tempfile::tempfile().unwrap();
    let mut zip = zip::ZipWriter::new(file);
    
    // Create a 200 byte file
    let options: FileOptions<()> = FileOptions::default();
    zip.start_file("big.txt", options).unwrap();
    zip.write_all(&[0u8; 200]).unwrap();
    let zip_file = zip.finish().unwrap();

    // Set limit to 100 bytes (should fail)
    let result = Extractor::new(root.path())
        .unwrap()
        .limits(safe_unzip::Limits {
            max_total_bytes: 100,
            ..Default::default()
        })
        .extract(zip_file);

    match result {
        Err(Error::TotalSizeExceeded { limit, would_be }) => {
            println!("✅ Successfully enforced quota: {} > {}", would_be, limit);
        }
        _ => panic!("❌ Failed to enforce quota"),
    }
}