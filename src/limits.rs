#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Maximum total bytes to extract. Default: 1 GB.
    pub max_total_bytes: u64,

    /// Maximum number of files to extract. Default: 10,000.
    pub max_file_count: usize,

    /// Maximum size of a single file. Default: 100 MB.
    pub max_single_file: u64,

    /// Maximum directory depth. Default: 50.
    pub max_path_depth: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_total_bytes: 4096 * 1024 * 1024, // 4 GiB
            max_file_count: 100_000,
            max_single_file: 4096 * 1024 * 1024, // 4 GiB
            max_path_depth: 50,
        }
    }
}
