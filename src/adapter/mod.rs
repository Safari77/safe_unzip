//! Archive format adapters.
//!
//! Adapters normalize different archive formats into a common interface
//! for the extraction engine.

mod tar_adapter;
mod zip_adapter;

pub use tar_adapter::{copy_limited, TarAdapter};
pub use zip_adapter::ZipAdapter;
