//! Archive format adapters.
//!
//! Adapters normalize different archive formats into a common interface
//! for the extraction engine.

mod zip_adapter;

pub use zip_adapter::ZipAdapter;
