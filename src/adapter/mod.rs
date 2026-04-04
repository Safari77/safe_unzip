//! Archive format adapters.
//!
//! Adapters normalize different archive formats into a common interface
//! for the extraction engine.

#[cfg(feature = "tar")]
mod tar_adapter;
pub mod zip_adapter;

#[cfg(feature = "sevenz")]
mod sevenz_adapter;

#[cfg(feature = "tar")]
pub use tar_adapter::{TarAdapter, copy_limited};
pub use zip_adapter::ZipAdapter;

#[cfg(feature = "sevenz")]
pub use sevenz_adapter::SevenZAdapter;
