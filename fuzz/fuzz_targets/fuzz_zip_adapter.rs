//! Fuzz test for the ZipAdapter (new architecture).
//!
//! This target tests the adapter layer which parses ZIP headers and metadata,
//! catching panics in the parsing logic before extraction occurs.

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use tempfile::tempdir;

fuzz_target!(|data: &[u8]| {
    // Wrap the fuzz input as a seekable reader
    let reader = Cursor::new(data);
    
    // Try to create a ZipAdapter and read metadata
    if let Ok(mut adapter) = safe_unzip::ZipAdapter::new(reader) {
        // Try to read all entry metadata (no decompression)
        let _ = adapter.entries_metadata();
        
        // If that worked, try extraction with the Driver
        let reader2 = Cursor::new(data);
        if let Ok(adapter2) = safe_unzip::ZipAdapter::new(reader2) {
            if let Ok(dest) = tempdir() {
                let _ = safe_unzip::Driver::new(dest.path())
                    .map(|d| d.extract_zip(adapter2));
            }
        }
    }
});

