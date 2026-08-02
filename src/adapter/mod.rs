//! Archive format adapters.
//!
//! Adapters normalize different archive formats into a common interface
//! for the extraction engine.

use std::io::{Read, Write};

use crate::error::Error;

#[cfg(feature = "tar")]
mod tar_adapter;
pub mod zip_adapter;

#[cfg(feature = "sevenz")]
mod sevenz_adapter;

#[cfg(feature = "tar")]
pub use tar_adapter::TarAdapter;
pub use zip_adapter::ZipAdapter;

#[cfg(feature = "sevenz")]
pub use sevenz_adapter::SevenZAdapter;

/// Copy with a byte limit, returning the number of bytes written.
///
/// Stops as soon as `limit` bytes have been copied; the caller decides whether
/// hitting the limit means "done" or "the entry lied about its size".
pub fn copy_limited<R: Read + ?Sized, W: Write + ?Sized>(
    reader: &mut R,
    writer: &mut W,
    limit: u64,
) -> Result<u64, Error> {
    let mut total = 0u64;
    let mut buf = [0u8; 8192];

    loop {
        let remaining = limit.saturating_sub(total);
        if remaining == 0 {
            break;
        }

        let to_read = (buf.len() as u64).min(remaining) as usize;
        let n = match reader.read(&mut buf[..to_read]) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        if n == 0 {
            break;
        }

        writer.write_all(&buf[..n])?;
        total += n as u64;
    }

    Ok(total)
}

/// Returns true if `reader` still has data past the point where
/// [`copy_limited`] stopped, i.e. the entry is larger than it declared.
pub(crate) fn has_more_data<R: Read + ?Sized>(reader: &mut R) -> Result<bool, Error> {
    let mut probe = [0u8; 1];
    loop {
        match reader.read(&mut probe) {
            Ok(n) => return Ok(n > 0),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
}
