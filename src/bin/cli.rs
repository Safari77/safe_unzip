//! safe_unzip CLI - Secure archive extraction
//!
//! # Examples
//!
//! ```bash
//! # Simple extraction
//! safe_unzip archive.zip -d /tmp/out
//!
//! # With limits
//! safe_unzip archive.zip -d /tmp/out --max-size 100M --max-files 1000
//!
//! # Filter by pattern
//! safe_unzip archive.zip -d /tmp/out --include "**/*.py" --exclude "**/test_*"
//!
//! # Extract specific files
//! safe_unzip archive.zip -d /tmp/out --only README.md --only LICENSE
//!
//! # List contents without extracting
//! safe_unzip archive.zip --list
//!
//! # Read the archive from stdin (format is sniffed from the magic bytes)
//! cat archive.tar.gz | safe_unzip - -d /tmp/out
//! ssh host 'tar cf - /srv/data' | safe_unzip - -d /tmp/out --format tar
//!
//! # Generate shell completions
//! safe_unzip --completions bash > ~/.bash_completion.d/safe_unzip
//! safe_unzip --completions zsh > ~/.zfunc/_safe_unzip
//! safe_unzip --completions fish > ~/.config/fish/completions/safe_unzip.fish
//! ```

use clap::{CommandFactory, Parser, ValueEnum};
use clap_complete::{Shell, generate};
use std::io;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use unicode_segmentation::UnicodeSegmentation;

use safe_unzip::{
    Driver, EntryAction, Error, ExtractionMode, Extractor, Limits, OverwritePolicy, SymlinkPolicy,
};

const MAX_CHARS_PER_GRAPHEME: usize = 15;

/// Escape C0, DEL, and C1 control characters so a string from an untrusted
/// filename or path can be safely written to the terminal.
pub fn sanitize_for_terminal(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 8);

    for grapheme in input.graphemes(true) {
        let bounded_chars = grapheme.chars().take(MAX_CHARS_PER_GRAPHEME);

        for c in bounded_chars {
            match c {
                '\t' => out.push('\t'),
                '\x00'..='\x1F' => {
                    out.push('^');
                    out.push(char::from_u32(0x40 + c as u32).unwrap_or('?'));
                }
                '\x7F' => out.push_str("^?"),
                '\u{80}'..='\u{9F}' => {
                    use std::fmt::Write as _;
                    let _ = write!(out, "\\u{{{:x}}}", c as u32);
                }
                '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{2069}'
                | '\u{FEFF}'
                | '\u{E000}'..='\u{F8FF}' => {
                    use std::fmt::Write as _;
                    let _ = write!(out, "\\u{{{:x}}}", c as u32);
                }
                other => out.push(other),
            }
        }
    }

    out
}

const VCS_EXCLUSIONS: &[&str] = &[
    // CVS
    "CVS",
    ".cvsignore",
    // RCS
    "RCS",
    // SCCS
    "SCCS",
    // SVN
    ".svn",
    // git
    ".git",
    ".gitignore",
    ".gitattributes",
    ".gitmodules",
    // Arch
    ".arch-ids",
    "{arch}",
    "=RELEASE-ID",
    "=meta-update",
    "=update",
    // Bazaar
    ".bzr",
    ".bzrignore",
    ".bzrtags",
    // Mercurial
    ".hg",
    ".hgignore",
    ".hgtags",
    // darcs
    "_darcs",
];

#[derive(serde::Deserialize, Default)]
struct Config {
    passwords: Option<PasswordsConfig>,
    limits: Option<LimitsConfig>,
}

#[derive(serde::Deserialize, Default)]
struct PasswordsConfig {
    list: Option<Vec<String>>,
}

#[derive(serde::Deserialize, Default)]
struct LimitsConfig {
    files: Option<usize>,
    dirs: Option<usize>,
    renames: Option<usize>,
}

#[derive(Parser)]
#[command(
    name = "safe_unzip",
    about = "Secure archive extraction - prevents Zip Slip and Zip Bombs",
    version,
    after_help = "EXAMPLES:
    safe_unzip archive.zip -d /tmp/out
    safe_unzip archive.tar.gz -d /tmp/out --max-size 100M
    safe_unzip archive.zip -d /tmp/out --include '**/*.py'
    safe_unzip archive.zip --list"
)]
struct Cli {
    /// Archive files to extract (ZIP, TAR, TAR.GZ, 7Z). Use "-" to read from stdin
    #[arg(required_unless_present = "completions")]
    archives: Vec<PathBuf>,

    /// Destination directory (created if missing)
    #[arg(short, long, default_value = ".")]
    dest: PathBuf,

    /// List contents without extracting
    #[arg(short, long)]
    list: bool,

    /// Verify archive integrity (CRC32 check) without extracting
    #[arg(long)]
    verify: bool,

    /// Force fsync on every extracted file
    #[arg(long)]
    fsync: bool,

    /// Generate shell completions for the specified shell
    #[arg(long, value_enum)]
    completions: Option<Shell>,

    /// Maximum total size to extract (e.g., 100M, 1G)
    #[arg(long, value_parser = parse_size)]
    max_size: Option<u64>,

    /// Maximum number of files to extract
    #[arg(long)]
    max_files: Option<usize>,

    /// Maximum number of directories to extract/create
    #[arg(long)]
    max_dirs: Option<usize>,

    /// Maximum number of rename attempts on collision
    #[arg(long)]
    max_renames: Option<usize>,

    /// Maximum size of a single file (e.g., 50M)
    #[arg(long, value_parser = parse_size)]
    max_single_file: Option<u64>,

    /// Maximum directory depth
    #[arg(long)]
    max_depth: Option<usize>,

    /// Maximum path length
    #[arg(long)]
    max_path_len: Option<usize>,

    /// Restore file modification timestamps from the archive
    #[arg(long)]
    restore_timestamps: bool,

    /// Allow extracting Windows reserved filenames (e.g., CON, LPT1) on non-Windows OSs
    #[arg(long)]
    allow_windows_reserved: bool,

    /// Override file permissions (octal, e.g., 644)
    #[arg(long, value_parser = parse_mode)]
    file_mode: Option<u32>,

    /// Override directory permissions (octal, e.g., 755)
    #[arg(long, value_parser = parse_mode)]
    dir_mode: Option<u32>,

    /// Ignore directory structure and extract all files to the destination root
    #[arg(short = 'j', long)]
    junk_paths: bool,

    /// Extract only files matching glob patterns (can be repeated)
    #[arg(long = "include", value_name = "PATTERN")]
    include_patterns: Vec<String>,

    /// Exclude files matching glob patterns (can be repeated)
    #[arg(long = "exclude", value_name = "PATTERN")]
    exclude_patterns: Vec<String>,

    /// Exclude version control directories and files (like tar --exclude-vcs)
    #[arg(long)]
    exclude_vcs: bool,

    /// Extract only specific files by name (can be repeated)
    #[arg(long = "only", value_name = "FILE")]
    only_files: Vec<String>,

    /// What to do if file already exists
    #[arg(long, value_enum, default_value_t = OverwriteMode::Error)]
    overwrite: OverwriteMode,

    /// What to do with symlinks
    #[arg(long, value_enum, default_value_t = SymlinkMode::Skip)]
    symlinks: SymlinkMode,

    /// Validate all entries before extracting
    #[arg(long)]
    validate_first: bool,

    /// Quiet mode - only show errors
    #[arg(short, long)]
    quiet: bool,

    /// Verbose mode - show each file extracted
    #[arg(short, long)]
    verbose: bool,

    /// Password for encrypted archives
    #[arg(long)]
    password: Option<String>,

    /// Archive format (default: from the file name, or from content on stdin)
    #[arg(long, value_enum, default_value_t = FormatOpt::Auto)]
    format: FormatOpt,
}

#[derive(Clone, Copy, ValueEnum)]
enum OverwriteMode {
    /// Error if file exists
    Error,
    /// Skip existing files
    Skip,
    /// Overwrite existing files
    Overwrite,
    /// If exists, rename file.ext to file_1.ext
    RenameBase,
    /// If exists, rename file.ext to file.ext.1
    RenameExt,
}

#[derive(Clone, Copy, ValueEnum)]
enum SymlinkMode {
    /// Skip symlinks silently
    Skip,
    /// Error if archive contains symlinks
    Error,
}

fn parse_mode(s: &str) -> Result<u32, String> {
    u32::from_str_radix(s, 8).map_err(|_| format!("Invalid octal mode: {}", s))
}

fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim().to_uppercase();
    let (num, multiplier) = if s.ends_with("G") || s.ends_with("GB") {
        let num_str = s.trim_end_matches("GB").trim_end_matches('G');
        (num_str, 1024 * 1024 * 1024)
    } else if s.ends_with("M") || s.ends_with("MB") {
        let num_str = s.trim_end_matches("MB").trim_end_matches('M');
        (num_str, 1024 * 1024)
    } else if s.ends_with("K") || s.ends_with("KB") {
        let num_str = s.trim_end_matches("KB").trim_end_matches('K');
        (num_str, 1024)
    } else {
        (s.trim_end_matches('B'), 1)
    };

    let value: u64 = num.trim().parse().map_err(|_| format!("Invalid size: {}", s))?;
    value.checked_mul(multiplier).ok_or_else(|| format!("Size out of range: {}", s))
}

/// Resolve the effective limits from the command line, then the config file,
/// then the built-in defaults.
fn build_limits(cli: &Cli, config: &Config) -> Limits {
    let def = Limits::default();
    Limits {
        max_total_bytes: cli.max_size.unwrap_or(def.max_total_bytes),
        max_file_count: cli
            .max_files
            .or_else(|| config.limits.as_ref().and_then(|l| l.files))
            .unwrap_or(def.max_file_count),
        max_dir_count: cli
            .max_dirs
            .or_else(|| config.limits.as_ref().and_then(|l| l.dirs))
            .unwrap_or(def.max_dir_count),
        max_renames: cli
            .max_renames
            .or_else(|| config.limits.as_ref().and_then(|l| l.renames))
            .unwrap_or(def.max_renames),
        max_single_file: cli.max_single_file.unwrap_or(def.max_single_file),
        max_path_depth: cli.max_depth.unwrap_or(def.max_path_depth),
        max_path_len: cli.max_path_len.unwrap_or(def.max_path_len),
    }
}

fn detect_format(path: &Path) -> ArchiveFormat {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_lowercase();

    if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
        ArchiveFormat::TarGz
    } else if name.ends_with(".tar") {
        ArchiveFormat::Tar
    } else if name.ends_with(".7z") {
        ArchiveFormat::SevenZ
    } else {
        ArchiveFormat::Zip
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArchiveFormat {
    Zip,
    Tar,
    TarGz,
    SevenZ,
}

/// Explicit `--format` selection. `Auto` keeps the existing behaviour: guess
/// from the file name, or from the magic bytes when reading stdin.
#[derive(Clone, Copy, ValueEnum)]
enum FormatOpt {
    /// Detect from the file name, or from the content when reading stdin
    Auto,
    Zip,
    Tar,
    /// gzip-compressed tar (.tar.gz, .tgz)
    #[value(name = "tar.gz", alias = "tgz")]
    TarGz,
    #[value(name = "7z")]
    SevenZ,
}

impl FormatOpt {
    fn to_archive_format(self) -> Option<ArchiveFormat> {
        match self {
            FormatOpt::Auto => None,
            FormatOpt::Zip => Some(ArchiveFormat::Zip),
            FormatOpt::Tar => Some(ArchiveFormat::Tar),
            FormatOpt::TarGz => Some(ArchiveFormat::TarGz),
            FormatOpt::SevenZ => Some(ArchiveFormat::SevenZ),
        }
    }
}

/// Bytes sniffed from stdin to identify the archive format. The TAR "ustar"
/// magic sits at offset 257, so a whole header block is needed.
const SNIFF_LEN: usize = 512;

/// Names that mean "read the archive from standard input".
fn is_stdin_path(path: &Path) -> bool {
    matches!(path.to_str(), Some("-") | Some("/dev/stdin") | Some("/proc/self/fd/0"))
}

/// Fill `buf` as far as the reader allows. A pipe hands back short reads, so a
/// single `read()` is not enough to see the TAR magic.
fn read_upto<R: Read>(reader: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

/// Identify an archive from its leading bytes.
fn sniff_format(header: &[u8]) -> Option<ArchiveFormat> {
    // Local file header, end of central directory, or spanned marker
    if header.starts_with(b"PK\x03\x04")
        || header.starts_with(b"PK\x05\x06")
        || header.starts_with(b"PK\x07\x08")
    {
        return Some(ArchiveFormat::Zip);
    }
    if header.starts_with(&[0x1f, 0x8b]) {
        return Some(ArchiveFormat::TarGz);
    }
    if header.starts_with(&[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]) {
        return Some(ArchiveFormat::SevenZ);
    }
    // POSIX ("ustar\0") and GNU ("ustar  ") both carry the magic at offset 257.
    // Pre-POSIX V7 tars have no magic at all and need an explicit --format.
    if header.len() >= 262 && &header[257..262] == b"ustar" {
        return Some(ArchiveFormat::Tar);
    }
    None
}

fn load_config(verbose: bool) -> Config {
    if let Some(config_dir) = dirs_next::config_dir() {
        let config_path = config_dir.join("safe_unzip.toml");
        if config_path.exists() {
            if verbose {
                println!("Reading config from: {}", config_path.display());
            }
            if let Ok(content) = std::fs::read_to_string(&config_path) {
                match toml::from_str::<Config>(&content) {
                    Ok(config) => return config,
                    Err(e) => {
                        eprintln!(
                            "Warning: Failed to parse config {}: {}",
                            config_path.display(),
                            e
                        )
                    }
                }
            }
        }
    }
    Config::default()
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Handle completions generation
    if let Some(shell) = cli.completions {
        generate(shell, &mut Cli::command(), "safe_unzip", &mut io::stdout());
        return ExitCode::SUCCESS;
    }

    if let Err(e) = run(cli) {
        eprintln!("Error: {}", format_error(&e));
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn run(mut cli: Cli) -> Result<(), Error> {
    let config = load_config(cli.verbose);
    // Map --exclude-vcs directly to the existing glob engine
    if cli.exclude_vcs {
        for &vcs_name in VCS_EXCLUSIONS {
            // Exclude the file/directory itself at any depth
            cli.exclude_patterns.push(format!("**/{}", vcs_name));
            // Exclude all contents inside it if it is a directory
            cli.exclude_patterns.push(format!("**/{}/**", vcs_name));
        }
    }

    let archives = std::mem::take(&mut cli.archives);
    let mut processed_count = 0;
    let mut error_count = 0;

    for archive in &archives {
        if !cli.quiet {
            if is_stdin_path(archive) {
                println!("Processing standard input.");
            } else {
                let size = std::fs::metadata(archive).map(|m| m.len()).unwrap_or(0);
                let safe_archive_name = sanitize_for_terminal(&archive.to_string_lossy());
                println!("Processing {} ({} bytes).", safe_archive_name, size);
            }
        }

        match process_archive(&mut cli, archive, &config) {
            Ok(_) => processed_count += 1,
            Err(e) => {
                error_count += 1;
                eprintln!("Error: {}", format_error(&e));
            }
        }

        if !cli.quiet {
            println!();
        }
    }

    if !cli.quiet {
        println!(
            "Processed {} archives, {} archives with errors.",
            processed_count + error_count,
            error_count
        );
    }

    if error_count > 0 {
        Err(Error::Io(std::io::Error::other("One or more archives failed to process")))
    } else {
        Ok(())
    }
}

fn process_archive(cli: &mut Cli, archive: &Path, config: &Config) -> Result<(), Error> {
    if is_stdin_path(archive) {
        return process_stdin(cli, config);
    }

    let format = cli.format.to_archive_format().unwrap_or_else(|| detect_format(archive));
    process_path(cli, archive, format, config, true)
}

/// Handle an archive that exists as a real file.
///
/// `allow_prompt` is false when the archive itself arrived on stdin: there is
/// no longer a usable stdin to read a password from.
fn process_path(
    cli: &mut Cli,
    archive: &Path,
    format: ArchiveFormat,
    config: &Config,
    allow_prompt: bool,
) -> Result<(), Error> {
    if cli.password.is_none() {
        cli.password = resolve_password(archive, &format, cli.verbose, config, allow_prompt);
    }

    let max_bytes = build_limits(cli, config).max_total_bytes;

    // List mode
    if cli.list {
        return list_archive(archive, format, cli.quiet, cli.password.as_deref(), max_bytes);
    }

    // Verify mode
    if cli.verify {
        return verify_archive(archive, format, cli.quiet, cli.password.as_deref(), max_bytes);
    }

    match format {
        ArchiveFormat::Zip => extract_zip(cli, archive, config),
        ArchiveFormat::Tar | ArchiveFormat::TarGz => extract_tar(cli, archive, format, config),
        ArchiveFormat::SevenZ => {
            #[cfg(feature = "sevenz")]
            {
                extract_sevenz(cli, archive, config)
            }
            #[cfg(not(feature = "sevenz"))]
            {
                eprintln!("Error: 7z support requires --features sevenz");
                Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "7z not supported in this build",
                )))
            }
        }
    }
}

/// Read an archive from standard input.
///
/// TAR is a sequential format, so it is streamed straight through. ZIP needs
/// the central directory at the end of the file and 7z needs random access, so
/// those are spooled to a temporary file first.
fn process_stdin(cli: &mut Cli, config: &Config) -> Result<(), Error> {
    let stdin = io::stdin();
    let mut reader = io::BufReader::with_capacity(65536, stdin.lock());

    let mut header = vec![0u8; SNIFF_LEN];
    let read = read_upto(&mut reader, &mut header)?;
    header.truncate(read);

    let format = match cli.format.to_archive_format() {
        Some(explicit) => explicit,
        None => sniff_format(&header).ok_or_else(|| {
            Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "cannot identify the archive format on stdin (pre-POSIX tar has no magic bytes); pass --format",
            ))
        })?,
    };

    // Put the sniffed bytes back at the front of the stream
    let mut stream = io::Cursor::new(header).chain(reader);

    match format {
        ArchiveFormat::Tar => run_tar_stream(cli, config, stream),
        ArchiveFormat::TarGz => run_tar_stream(cli, config, flate2::read::GzDecoder::new(stream)),
        ArchiveFormat::Zip | ArchiveFormat::SevenZ => {
            let mut temp = tempfile::NamedTempFile::new()?;
            io::copy(&mut stream, temp.as_file_mut())?;
            let path = temp.path().to_path_buf();
            process_path(cli, &path, format, config, false)
        }
    }
}

/// Extract, list or verify a TAR stream that cannot be seeked.
fn run_tar_stream<R: Read>(cli: &Cli, config: &Config, reader: R) -> Result<(), Error> {
    if cli.list {
        let entries = safe_unzip::list_tar(reader)?;
        print_entries(&entries, "standard input", cli.quiet);
        return Ok(());
    }

    if cli.verify {
        if !cli.quiet {
            println!("Verifying standard input...");
        }
        // TAR carries no payload checksum, so walking every entry is the
        // strongest integrity check the format allows
        let entries = safe_unzip::list_tar(reader)?;
        if !cli.quiet {
            println!(
                "Verified {} entries ({})",
                entries.len(),
                format_bytes(total_entry_size(&entries))
            );
        }
        return Ok(());
    }

    let driver = build_tar_driver(cli, config)?;
    let report = driver.extract_tar(safe_unzip::TarAdapter::new(reader))?;

    report_extraction(
        cli,
        report.files_extracted,
        report.bytes_written,
        report.entries_skipped,
        &report.renames,
    );
    Ok(())
}

fn extract_zip(cli: &Cli, archive: &Path, config: &Config) -> Result<(), Error> {
    let limits = build_limits(cli, config);

    let overwrite = match cli.overwrite {
        OverwriteMode::Error => OverwritePolicy::Error,
        OverwriteMode::Skip => OverwritePolicy::Skip,
        OverwriteMode::Overwrite => OverwritePolicy::Overwrite,
        OverwriteMode::RenameBase => OverwritePolicy::RenameBase,
        OverwriteMode::RenameExt => OverwritePolicy::RenameExt,
    };

    let symlinks = match cli.symlinks {
        SymlinkMode::Skip => SymlinkPolicy::Skip,
        SymlinkMode::Error => SymlinkPolicy::Error,
    };

    let mode =
        if cli.validate_first { ExtractionMode::ValidateFirst } else { ExtractionMode::Streaming };

    let mut extractor = Extractor::new_or_create(&cli.dest)?
        .limits(limits)
        .overwrite(overwrite)
        .symlinks(symlinks)
        .mode(mode)
        .junk_paths(cli.junk_paths)
        .fsync(cli.fsync)
        .restore_timestamps(cli.restore_timestamps)
        .allow_windows_reserved(cli.allow_windows_reserved)
        .password(cli.password.as_deref());

    if let Some(m) = cli.file_mode {
        extractor = extractor.file_mode(m);
    }
    if let Some(m) = cli.dir_mode {
        extractor = extractor.dir_mode(m);
    }

    // Apply filters
    if !cli.only_files.is_empty() {
        extractor = extractor.only(&cli.only_files);
    }
    if !cli.include_patterns.is_empty() {
        extractor = extractor.include_glob(&cli.include_patterns);
    }
    if !cli.exclude_patterns.is_empty() {
        extractor = extractor.exclude_glob(&cli.exclude_patterns);
    }

    // Add progress callback if verbose
    if cli.verbose {
        extractor = extractor.on_progress(|p| {
            let prefix = match p.action {
                EntryAction::Skipped => "[skipped]   ",
                EntryAction::Overwritten => "[overwrite] ",
                EntryAction::Created => "[created]   ",
            };
            println!(
                "[{}/{}] {}{}",
                p.entry_index + 1,
                p.total_entries,
                prefix,
                sanitize_for_terminal(&p.entry_name)
            );
        });
    }

    let report = extractor.extract_file(archive)?;

    report_extraction(
        cli,
        report.files_extracted,
        report.bytes_written,
        report.entries_skipped,
        &report.renames,
    );

    Ok(())
}

/// Print the post-extraction summary shared by every format.
fn report_extraction(
    cli: &Cli,
    files_extracted: usize,
    bytes_written: u64,
    entries_skipped: usize,
    renames: &[(String, String)],
) {
    if cli.quiet {
        return;
    }

    println!(
        "Extracted {} files ({} bytes) to {}",
        files_extracted,
        format_bytes(bytes_written),
        cli.dest.display()
    );
    if !renames.is_empty() {
        println!("\nThe following files were renamed to avoid overwriting:");
        for (orig, new) in renames {
            println!("  {} -> {}", sanitize_for_terminal(orig), sanitize_for_terminal(new));
        }
    }
    if entries_skipped > 0 {
        println!("Skipped {} entries", entries_skipped);
    }
}

/// Sum entry sizes without panicking on a hostile archive.
fn total_entry_size(entries: &[safe_unzip::EntryInfo]) -> u64 {
    entries.iter().fold(0u64, |acc, e| acc.saturating_add(e.size))
}

/// Print an entry listing for one archive.
fn print_entries(entries: &[safe_unzip::EntryInfo], source: &str, quiet: bool) {
    if !quiet {
        println!("{} entries in {}:", entries.len(), source);
        println!();
    }

    for entry in entries {
        let kind = match entry.kind {
            safe_unzip::EntryKind::File => "",
            safe_unzip::EntryKind::Directory => "/",
            safe_unzip::EntryKind::Symlink { .. } => " -> [symlink]",
        };
        println!(
            "{:>10}  {}{}",
            format_bytes(entry.size),
            sanitize_for_terminal(&entry.name),
            kind
        );
    }

    if !quiet {
        println!();
        println!("Total: {} files, {}", entries.len(), format_bytes(total_entry_size(entries)));
    }
}

fn build_tar_driver(cli: &Cli, config: &Config) -> Result<Driver, Error> {
    let limits = build_limits(cli, config);

    let overwrite_mode = match cli.overwrite {
        OverwriteMode::Error => safe_unzip::OverwriteMode::Error,
        OverwriteMode::Skip => safe_unzip::OverwriteMode::Skip,
        OverwriteMode::Overwrite => safe_unzip::OverwriteMode::Overwrite,
        OverwriteMode::RenameBase => safe_unzip::OverwriteMode::RenameBase,
        OverwriteMode::RenameExt => safe_unzip::OverwriteMode::RenameExt,
    };

    let symlink_behavior = match cli.symlinks {
        SymlinkMode::Skip => safe_unzip::SymlinkBehavior::Skip,
        SymlinkMode::Error => safe_unzip::SymlinkBehavior::Error,
    };

    let validation = if cli.validate_first {
        safe_unzip::ValidationMode::ValidateFirst
    } else {
        safe_unzip::ValidationMode::Streaming
    };

    let mut driver = Driver::new_or_create(&cli.dest)?
        .limits(limits)
        .overwrite(overwrite_mode)
        .symlinks(symlink_behavior)
        .validation(validation)
        .junk_paths(cli.junk_paths)
        .fsync(cli.fsync)
        .allow_windows_reserved(cli.allow_windows_reserved)
        .restore_timestamps(cli.restore_timestamps);

    if let Some(m) = cli.file_mode {
        driver = driver.file_mode(m);
    }
    if let Some(m) = cli.dir_mode {
        driver = driver.dir_mode(m);
    }

    // Apply filters
    if !cli.only_files.is_empty() {
        driver = driver.only(&cli.only_files);
    }
    if !cli.include_patterns.is_empty() {
        driver = driver.include_glob(&cli.include_patterns);
    }
    if !cli.exclude_patterns.is_empty() {
        driver = driver.exclude_glob(&cli.exclude_patterns);
    }

    if cli.verbose {
        driver = driver.on_progress(|p| {
            let prefix = match p.action {
                EntryAction::Skipped => "[skipped]   ",
                EntryAction::Overwritten => "[overwrite] ",
                EntryAction::Created => "[created]   ",
            };
            if p.total_entries > 0 {
                println!(
                    "[{}/{}] {}{}",
                    p.entry_index + 1,
                    p.total_entries,
                    prefix,
                    sanitize_for_terminal(&p.entry_name)
                );
            } else {
                // For streaming TAR, we don't know the total
                println!(
                    "[{}] {}{}",
                    p.entry_index + 1,
                    prefix,
                    sanitize_for_terminal(&p.entry_name)
                );
            }
        });
    }

    Ok(driver)
}

fn extract_tar(
    cli: &Cli,
    archive: &Path,
    format: ArchiveFormat,
    config: &Config,
) -> Result<(), Error> {
    let driver = build_tar_driver(cli, config)?;

    let report = match format {
        ArchiveFormat::Tar => driver.extract_tar_file(archive)?,
        ArchiveFormat::TarGz => driver.extract_tar_gz_file(archive)?,
        other => {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("extract_tar called with a non-TAR format ({:?})", other),
            )));
        }
    };

    report_extraction(
        cli,
        report.files_extracted,
        report.bytes_written,
        report.entries_skipped,
        &report.renames,
    );

    Ok(())
}

#[cfg(feature = "sevenz")]
fn extract_sevenz(cli: &Cli, archive: &Path, config: &Config) -> Result<(), Error> {
    let limits = build_limits(cli, config);

    // Map policies to Driver types
    let overwrite_mode = match cli.overwrite {
        OverwriteMode::Error => safe_unzip::OverwriteMode::Error,
        OverwriteMode::Skip => safe_unzip::OverwriteMode::Skip,
        OverwriteMode::Overwrite => safe_unzip::OverwriteMode::Overwrite,
        OverwriteMode::RenameBase => safe_unzip::OverwriteMode::RenameBase,
        OverwriteMode::RenameExt => safe_unzip::OverwriteMode::RenameExt,
    };

    let symlink_behavior = match cli.symlinks {
        SymlinkMode::Skip => safe_unzip::SymlinkBehavior::Skip,
        SymlinkMode::Error => safe_unzip::SymlinkBehavior::Error,
    };

    let validation = if cli.validate_first {
        safe_unzip::ValidationMode::ValidateFirst
    } else {
        safe_unzip::ValidationMode::Streaming
    };

    let mut driver = Driver::new_or_create(&cli.dest)?
        .limits(limits)
        .overwrite(overwrite_mode)
        .symlinks(symlink_behavior)
        .validation(validation)
        .junk_paths(cli.junk_paths)
        .fsync(cli.fsync)
        .allow_windows_reserved(cli.allow_windows_reserved)
        .restore_timestamps(cli.restore_timestamps);

    if let Some(m) = cli.file_mode {
        driver = driver.file_mode(m);
    }
    if let Some(m) = cli.dir_mode {
        driver = driver.dir_mode(m);
    }

    // Apply filters
    if !cli.only_files.is_empty() {
        driver = driver.only(&cli.only_files);
    }
    if !cli.include_patterns.is_empty() {
        driver = driver.include_glob(&cli.include_patterns);
    }
    if !cli.exclude_patterns.is_empty() {
        driver = driver.exclude_glob(&cli.exclude_patterns);
    }

    // Decompress once, with the password resolved earlier, and reuse the
    // adapter for both the progress total and the extraction itself
    let adapter = safe_unzip::SevenZAdapter::open_with_limit(
        archive,
        cli.password.as_deref(),
        limits.max_total_bytes,
    )?;

    if cli.verbose {
        // We know total entries for 7z because it decompresses upfront
        let total_entries = adapter.len();

        driver = driver.on_progress(move |p| {
            let prefix = match p.action {
                EntryAction::Skipped => "[skipped]   ",
                EntryAction::Overwritten => "[overwrite] ",
                EntryAction::Created => "[created]   ",
            };
            println!(
                "[{}/{}] {}{}",
                p.entry_index + 1,
                total_entries,
                prefix,
                sanitize_for_terminal(&p.entry_name)
            );
        });
    }

    let report = driver.extract_7z(adapter)?;

    report_extraction(
        cli,
        report.files_extracted,
        report.bytes_written,
        report.entries_skipped,
        &report.renames,
    );

    Ok(())
}

fn list_archive(
    path: &Path,
    format: ArchiveFormat,
    quiet: bool,
    password: Option<&str>,
    max_bytes: u64,
) -> Result<(), Error> {
    #[cfg(not(feature = "sevenz"))]
    let _ = (password, max_bytes);

    let safe_archive_path = sanitize_for_terminal(&path.to_string_lossy());

    let entries = match format {
        ArchiveFormat::Zip => safe_unzip::list_zip_entries_with_password(path, password)?,
        ArchiveFormat::Tar => safe_unzip::list_tar_entries(path)?,
        ArchiveFormat::TarGz => safe_unzip::list_tar_gz_entries(path)?,
        ArchiveFormat::SevenZ => {
            #[cfg(feature = "sevenz")]
            {
                let adapter =
                    safe_unzip::SevenZAdapter::open_with_limit(path, password, max_bytes)?;
                adapter.entries_metadata()
            }
            #[cfg(not(feature = "sevenz"))]
            {
                eprintln!("Error: 7z listing requires --features sevenz");
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "7z not supported in this build",
                )));
            }
        }
    };

    print_entries(&entries, &safe_archive_path, quiet);

    Ok(())
}

fn verify_archive(
    path: &Path,
    format: ArchiveFormat,
    quiet: bool,
    password: Option<&str>,
    max_bytes: u64,
) -> Result<(), Error> {
    #[cfg(not(feature = "sevenz"))]
    let _ = max_bytes;

    let safe_archive_path = sanitize_for_terminal(&path.to_string_lossy());

    if !quiet {
        println!("Verifying {}...", safe_archive_path);
    }

    match format {
        ArchiveFormat::Zip => {
            let report = safe_unzip::verify_file_with_password(path, password)?;

            if !quiet {
                println!(
                    "Verified {} entries ({})",
                    report.entries_verified,
                    format_bytes(report.bytes_verified)
                );
            }
        }
        ArchiveFormat::Tar | ArchiveFormat::TarGz => {
            // For TAR, we can list entries (which reads them) as a basic integrity check
            let entries = if matches!(format, ArchiveFormat::TarGz) {
                safe_unzip::list_tar_gz_entries(path)?
            } else {
                safe_unzip::list_tar_entries(path)?
            };

            if !quiet {
                println!(
                    "Verified {} entries ({})",
                    entries.len(),
                    format_bytes(total_entry_size(&entries))
                );
            }
        }
        ArchiveFormat::SevenZ => {
            #[cfg(feature = "sevenz")]
            {
                // SevenZAdapter decompresses fully on open, effectively verifying integrity
                let adapter =
                    safe_unzip::SevenZAdapter::open_with_limit(path, password, max_bytes)?;
                let entries = adapter.entries_metadata();

                if !quiet {
                    println!(
                        "Verified {} entries ({})",
                        entries.len(),
                        format_bytes(total_entry_size(&entries))
                    );
                }
            }
            #[cfg(not(feature = "sevenz"))]
            {
                eprintln!("Error: 7z verification requires --features sevenz");
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "7z not supported in this build",
                )));
            }
        }
    }

    Ok(())
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.1}G", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.1}M", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1}K", bytes as f64 / 1024.0)
    } else {
        format!("{}B", bytes)
    }
}

fn format_error(e: &Error) -> String {
    match e {
        Error::PathEscape { entry, detail } => {
            format!("Path traversal blocked in '{}': {}", sanitize_for_terminal(entry), detail)
        }
        Error::TotalSizeExceeded { limit, would_be } => {
            format!(
                "Archive too large: {} (limit: {})",
                format_bytes(*would_be),
                format_bytes(*limit)
            )
        }
        Error::FileTooLarge { entry, size, limit } => {
            format!(
                "File '{}' too large: {} (limit: {})",
                sanitize_for_terminal(entry),
                format_bytes(*size),
                format_bytes(*limit)
            )
        }
        Error::FileCountExceeded { limit, .. } => {
            format!("Too many files (limit: {})", limit)
        }
        Error::DirCountExceeded { limit, .. } => {
            format!("Too many directories (limit: {})", limit)
        }
        Error::AlreadyExists { entry } => {
            format!("File already exists: {}", sanitize_for_terminal(entry))
        }
        Error::EncryptedEntry { entry } => {
            format!("Encrypted entry not supported: {}", sanitize_for_terminal(entry))
        }
        _ => sanitize_for_terminal(&e.to_string()),
    }
}

// Only attempt to resolve password if the archive actually needs one
fn resolve_password(
    archive: &Path,
    format: &ArchiveFormat,
    verbose: bool,
    config: &Config,
    allow_prompt: bool,
) -> Option<String> {
    if !requires_password(archive, format) {
        return None;
    }

    // 1. Try passwords from config
    if let Some(passwords_config) = &config.passwords
        && let Some(list) = &passwords_config.list
    {
        if verbose {
            println!("Checking passwords from config...");
        }
        for pwd in list {
            if verify_password(archive, format, pwd) {
                return Some(pwd.clone());
            }
        }
    }

    // stdin is the archive, so there is nothing left to read a password from
    if !allow_prompt {
        eprintln!("Archive is encrypted; pass --password (stdin is in use by the archive).");
        return None;
    }

    // 2. Prompt user securely
    eprint!("Archive is encrypted. Enter password: ");
    match rpassword::read_password() {
        Ok(pwd) => {
            if !pwd.is_empty() {
                Some(pwd)
            } else {
                None
            }
        }
        Err(e) => {
            eprintln!("Failed to read password: {}", e);
            None
        }
    }
}

fn requires_password(path: &Path, format: &ArchiveFormat) -> bool {
    match format {
        ArchiveFormat::Zip => {
            if let Ok(file) = std::fs::File::open(path)
                && let Ok(mut archive) = zip::ZipArchive::new(file)
            {
                for i in 0..archive.len() {
                    let is_encrypted = if let Ok(entry) = archive.by_index_raw(i) {
                        entry.encrypted()
                    } else {
                        false
                    };
                    if is_encrypted {
                        return true;
                    }
                }
            }
            false
        }
        ArchiveFormat::Tar | ArchiveFormat::TarGz => false,
        ArchiveFormat::SevenZ => {
            #[cfg(feature = "sevenz")]
            {
                sevenz_requires_password(path)
            }
            #[cfg(not(feature = "sevenz"))]
            {
                false
            }
        }
    }
}

/// Check whether a 7z archive actually needs a password.
///
/// Encrypted headers make `open()` fail outright. With plaintext headers the
/// open succeeds regardless, so we have to read a byte of real content to find
/// out whether the streams are 7zAES-encrypted.
#[cfg(feature = "sevenz")]
fn sevenz_requires_password(path: &Path) -> bool {
    use sevenz_rust2::{ArchiveReader, Password};

    match ArchiveReader::open(path, Password::empty()) {
        Ok(mut archive) => {
            let mut needs = false;
            let res = archive.for_each_entries(|entry, reader| {
                if entry.is_directory() {
                    return Ok(true);
                }
                let mut buf = [0u8; 1];
                match reader.read(&mut buf) {
                    Err(_) => {
                        needs = true;
                        Ok(false)
                    }
                    // Empty file tells us nothing, look at the next entry
                    Ok(0) => Ok(true),
                    // Content decrypted (or was never encrypted)
                    Ok(_) => Ok(false),
                }
            });
            needs || res.is_err()
        }
        // Encrypted header, or an archive we cannot read at all: prompting is
        // the more useful of the two failure modes
        Err(_) => true,
    }
}

fn verify_password(path: &Path, format: &ArchiveFormat, password: &str) -> bool {
    match format {
        ArchiveFormat::Zip => {
            if let Ok(file) = std::fs::File::open(path)
                && let Ok(mut archive) = zip::ZipArchive::new(file)
            {
                // Try to find an encrypted entry and decrypt it
                for i in 0..archive.len() {
                    let is_encrypted = if let Ok(entry) = archive.by_index_raw(i) {
                        entry.encrypted()
                    } else {
                        false
                    };

                    //eprintln!("Trying password {}", password);
                    if is_encrypted {
                        return archive.by_index_decrypt(i, password.as_bytes()).is_ok();
                    }
                }
            }
            false
        }
        ArchiveFormat::SevenZ => {
            #[cfg(feature = "sevenz")]
            {
                verify_7z_password(path, password)
            }
            #[cfg(not(feature = "sevenz"))]
            {
                false
            }
        }
        _ => false,
    }
}

#[cfg(feature = "sevenz")]
fn verify_7z_password(path: &Path, password: &str) -> bool {
    use sevenz_rust2::{ArchiveReader, Password};

    // 1. Try to open the archive with the password.
    // If headers are encrypted, this will fail if the password is wrong.
    match ArchiveReader::open(path, Password::from(password)) {
        Ok(mut archive) => {
            let mut valid = false;
            let mut found_file = false;

            // 2. If open succeeded (headers OK), we must verify content decryption.
            // If headers are NOT encrypted, open() succeeds with ANY password.
            // So we must try to read at least one file's content.
            // Empty files decrypt trivially and prove nothing, so keep looking
            // until an entry actually yields a byte.
            let res = archive.for_each_entries(|entry, reader| {
                if entry.is_directory() {
                    return Ok(true); // Skip directories
                }

                // Try to read some bytes to trigger decryption/decode
                let mut buf = [0u8; 4096];
                match reader.read(&mut buf) {
                    Err(_) => {
                        found_file = true;
                        valid = false;
                        Ok(false) // Wrong password, no point continuing
                    }
                    Ok(0) => Ok(true), // Empty file, inconclusive: try the next entry
                    Ok(_) => {
                        found_file = true;
                        valid = true;
                        Ok(false) // Stop after the first entry with real content
                    }
                }
            });

            // An error from the iteration itself (AES or LZMA2 failure while
            // setting up the next folder) also means the password is wrong.
            if res.is_err() {
                return false;
            }

            // If we found a file and read it successfully, password is correct.
            if found_file {
                valid
            } else {
                // Only dirs and/or empty files: nothing encrypted to check, and
                // we did open the archive, so assume the password is OK
                true
            }
        }
        Err(_) => false, // Open failed (e.g. encrypted headers with wrong password)
    }
}
