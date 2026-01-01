//! Fuzz test for the main extraction API.
//!
//! This target tests the complete extraction pipeline with arbitrary byte input,
//! catching panics in zip parsing, path handling, and file writing.

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use tempfile::tempdir;

fuzz_target!(|data: &[u8]| {
    // Create a temporary directory for extraction
    let Ok(dest) = tempdir() else { return };
    
    // Wrap the fuzz input as a seekable reader
    let reader = Cursor::new(data);
    
    // Try to extract using the main API
    // We don't care about the result - we're looking for panics
    let _ = safe_unzip::Extractor::new(dest.path())
        .map(|e| e.extract(reader));
});

