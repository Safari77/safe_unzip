use std::fmt;

#[derive(Debug)]
pub enum Error {
    /// Path escapes destination directory (Zip Slip).
    PathEscape { entry: String, detail: String },

    /// Archive contains symlink and policy is Error.
    SymlinkNotAllowed { entry: String },

    /// Exceeded maximum total bytes.
    TotalSizeExceeded { limit: u64, would_be: u64 },

    /// Exceeded maximum file count.
    FileCountExceeded { limit: usize },

    /// Single file exceeds size limit.
    FileTooLarge {
        entry: String,
        limit: u64,
        size: u64,
    },

    /// Path exceeds depth limit.
    PathTooDeep {
        entry: String,
        depth: usize,
        limit: usize,
    },

    /// File already exists and policy is Error.
    AlreadyExists { path: String },

    /// Destination directory does not exist or is invalid.
    DestinationNotFound { path: String },

    /// Filename contains invalid characters or reserved names.
    InvalidFilename { entry: String },

    /// Zip format error.
    Zip(zip::result::ZipError),

    /// IO error.
    Io(std::io::Error),

    /// Path jail error.
    Jail(path_jail::JailError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PathEscape { entry, detail } => {
                write!(f, "security error: path '{}' escapes jail: {}", entry, detail)
            }
            Self::SymlinkNotAllowed { entry } => {
                write!(f, "security error: symlink not allowed: '{}'", entry)
            }
            Self::TotalSizeExceeded { limit, would_be } => {
                write!(f, "quota error: total size {} bytes exceeds limit {}", would_be, limit)
            }
            Self::FileCountExceeded { limit } => {
                write!(f, "quota error: file count exceeds limit {}", limit)
            }
            Self::FileTooLarge { entry, limit, size } => {
                write!(f, "quota error: entry '{}' size {} exceeds limit {}", entry, size, limit)
            }
            Self::PathTooDeep { entry, depth, limit } => {
                write!(f, "quota error: entry '{}' depth {} exceeds limit {}", entry, depth, limit)
            }
            Self::AlreadyExists { path } => {
                write!(f, "file already exists: '{}'", path)
            }
            Self::DestinationNotFound { path } => {
                write!(f, "destination directory not found: '{}'", path)
            }
            Self::InvalidFilename { entry } => {
                write!(f, "security error: invalid filename: '{}'", entry)
            }
            Self::Zip(e) => write!(f, "zip error: {}", e),
            Self::Io(e) => write!(f, "io error: {}", e),
            Self::Jail(e) => write!(f, "jail error: {}", e),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Zip(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::Jail(e) => Some(e),
            _ => None,
        }
    }
}

// Automatic conversions for ease of use
impl From<zip::result::ZipError> for Error {
    fn from(e: zip::result::ZipError) -> Self { Self::Zip(e) }
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self { Self::Io(e) }
}
impl From<path_jail::JailError> for Error {
    fn from(e: path_jail::JailError) -> Self { Self::Jail(e) }
}