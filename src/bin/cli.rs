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
//! # Generate shell completions
//! safe_unzip --completions bash > ~/.bash_completion.d/safe_unzip
//! safe_unzip --completions zsh > ~/.zfunc/_safe_unzip
//! safe_unzip --completions fish > ~/.config/fish/completions/safe_unzip.fish
//! ```

use clap::{CommandFactory, Parser, ValueEnum};
use clap_complete::{generate, Shell};
use safe_unzip::{
    Driver, Error, ExtractionMode, Extractor, Limits, OverwritePolicy, SymlinkPolicy,
};
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(serde::Deserialize)]
struct Config {
    passwords: Option<PasswordsConfig>,
}

#[derive(serde::Deserialize)]
struct PasswordsConfig {
    list: Option<Vec<String>>,
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
    /// Archive files to extract (ZIP, TAR, TAR.GZ)
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

    /// Maximum size of a single file (e.g., 50M)
    #[arg(long, value_parser = parse_size)]
    max_single_file: Option<u64>,

    /// Maximum directory depth
    #[arg(long)]
    max_depth: Option<usize>,

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
}

#[derive(Clone, Copy, ValueEnum)]
enum OverwriteMode {
    /// Error if file exists
    Error,
    /// Skip existing files
    Skip,
    /// Overwrite existing files
    Overwrite,
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
        (s.as_str(), 1)
    };

    num.parse::<u64>()
        .map(|n| n * multiplier)
        .map_err(|_| format!("Invalid size: {}", s))
}

fn detect_format(path: &Path) -> ArchiveFormat {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();

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

enum ArchiveFormat {
    Zip,
    Tar,
    TarGz,
    SevenZ,
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
    let archives = std::mem::take(&mut cli.archives);
    let mut processed_count = 0;
    let mut error_count = 0;

    for archive in &archives {
        let size = std::fs::metadata(archive).map(|m| m.len()).unwrap_or(0);

        if !cli.quiet {
            println!("Processing {} ({} bytes).", archive.display(), size);
        }

        match process_archive(&mut cli, archive) {
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
        Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            "One or more archives failed to process",
        )))
    } else {
        Ok(())
    }
}

fn process_archive(cli: &mut Cli, archive: &Path) -> Result<(), Error> {
    let format = detect_format(archive);

    if cli.password.is_none() {
        cli.password = resolve_password(archive, &format, cli.verbose);
    }

    // List mode
    if cli.list {
        return list_archive(archive, format, cli.quiet);
    }

    // Verify mode
    if cli.verify {
        return verify_archive(archive, format, cli.quiet);
    }

    // Extract mode
    let limits = Limits {
        max_total_bytes: cli.max_size.unwrap_or(Limits::default().max_total_bytes),
        max_file_count: cli.max_files.unwrap_or(Limits::default().max_file_count),
        max_single_file: cli
            .max_single_file
            .unwrap_or(Limits::default().max_single_file),
        max_path_depth: cli.max_depth.unwrap_or(Limits::default().max_path_depth),
    };

    let overwrite = match cli.overwrite {
        OverwriteMode::Error => OverwritePolicy::Error,
        OverwriteMode::Skip => OverwritePolicy::Skip,
        OverwriteMode::Overwrite => OverwritePolicy::Overwrite,
    };

    let symlinks = match cli.symlinks {
        SymlinkMode::Skip => SymlinkPolicy::Skip,
        SymlinkMode::Error => SymlinkPolicy::Error,
    };

    let mode = if cli.validate_first {
        ExtractionMode::ValidateFirst
    } else {
        ExtractionMode::Streaming
    };

    // Build extractor based on format
    match format {
        ArchiveFormat::Zip => extract_zip(&cli, archive, limits, overwrite, symlinks, mode),
        ArchiveFormat::Tar | ArchiveFormat::TarGz => {
            extract_tar(&cli, archive, format, limits, overwrite, symlinks, mode)
        }
        ArchiveFormat::SevenZ => {
            #[cfg(feature = "sevenz")]
            {
                extract_sevenz(&cli, archive, limits, overwrite, symlinks, mode)
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

fn extract_zip(
    cli: &Cli,
    archive: &Path,
    limits: Limits,
    overwrite: OverwritePolicy,
    symlinks: SymlinkPolicy,
    mode: ExtractionMode,
) -> Result<(), Error> {
    let mut extractor = Extractor::new_or_create(&cli.dest)?
        .limits(limits)
        .overwrite(overwrite)
        .symlinks(symlinks)
        .mode(mode)
        .junk_paths(cli.junk_paths)
        .fsync(cli.fsync)
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
            println!(
                "[{}/{}] {}",
                p.entry_index + 1,
                p.total_entries,
                p.entry_name
            );
        });
    }

    let report = extractor.extract_file(archive)?;

    if !cli.quiet {
        println!(
            "Extracted {} files ({} bytes) to {}",
            report.files_extracted,
            format_bytes(report.bytes_written),
            cli.dest.display()
        );
        if report.entries_skipped > 0 {
            println!("Skipped {} entries", report.entries_skipped);
        }
    }

    Ok(())
}

fn extract_tar(
    cli: &Cli,
    archive: &Path,
    format: ArchiveFormat,
    limits: Limits,
    overwrite: OverwritePolicy,
    symlinks: SymlinkPolicy,
    mode: ExtractionMode,
) -> Result<(), Error> {
    let overwrite_mode = match overwrite {
        OverwritePolicy::Error => safe_unzip::OverwriteMode::Error,
        OverwritePolicy::Skip => safe_unzip::OverwriteMode::Skip,
        OverwritePolicy::Overwrite => safe_unzip::OverwriteMode::Overwrite,
    };

    let symlink_behavior = match symlinks {
        SymlinkPolicy::Skip => safe_unzip::SymlinkBehavior::Skip,
        SymlinkPolicy::Error => safe_unzip::SymlinkBehavior::Error,
    };

    let validation = match mode {
        ExtractionMode::Streaming => safe_unzip::ValidationMode::Streaming,
        ExtractionMode::ValidateFirst => safe_unzip::ValidationMode::ValidateFirst,
    };

    let mut driver = Driver::new_or_create(&cli.dest)?
        .limits(limits)
        .overwrite(overwrite_mode)
        .symlinks(symlink_behavior)
        .validation(validation)
        .junk_paths(cli.junk_paths)
        .fsync(cli.fsync);

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
            if p.total_entries > 0 {
                println!(
                    "[{}/{}] {}",
                    p.entry_index + 1,
                    p.total_entries,
                    p.entry_name
                );
            } else {
                // For streaming TAR, we don't know the total
                println!("[{}] {}", p.entry_index + 1, p.entry_name);
            }
        });
    }

    let report = match format {
        ArchiveFormat::Tar => driver.extract_tar_file(archive)?,
        ArchiveFormat::TarGz => driver.extract_tar_gz_file(archive)?,
        ArchiveFormat::SevenZ => {
            #[cfg(feature = "sevenz")]
            {
                driver.extract_7z_file(archive)?
            }
            #[cfg(not(feature = "sevenz"))]
            {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "7z not supported",
                )));
            }
        }
        _ => unreachable!(),
    };

    if !cli.quiet {
        println!(
            "Extracted {} files ({} bytes) to {}",
            report.files_extracted,
            format_bytes(report.bytes_written),
            cli.dest.display()
        );
        if report.entries_skipped > 0 {
            println!("Skipped {} entries", report.entries_skipped);
        }
    }

    Ok(())
}

#[cfg(feature = "sevenz")]
fn extract_sevenz(
    cli: &Cli,
    archive: &Path,
    limits: Limits,
    overwrite: OverwritePolicy,
    symlinks: SymlinkPolicy,
    mode: ExtractionMode,
) -> Result<(), Error> {
    // Map policies to Driver types
    let overwrite_mode = match overwrite {
        OverwritePolicy::Error => safe_unzip::OverwriteMode::Error,
        OverwritePolicy::Skip => safe_unzip::OverwriteMode::Skip,
        OverwritePolicy::Overwrite => safe_unzip::OverwriteMode::Overwrite,
    };

    let symlink_behavior = match symlinks {
        SymlinkPolicy::Skip => safe_unzip::SymlinkBehavior::Skip,
        SymlinkPolicy::Error => safe_unzip::SymlinkBehavior::Error,
    };

    // Note: 7z adapter currently loads all into memory, so ValidateFirst vs Streaming
    // distinction is less relevant here, but Driver handles validation.
    let validation = match mode {
        ExtractionMode::Streaming => safe_unzip::ValidationMode::Streaming,
        ExtractionMode::ValidateFirst => safe_unzip::ValidationMode::ValidateFirst,
    };

    let mut driver = Driver::new_or_create(&cli.dest)?
        .limits(limits)
        .overwrite(overwrite_mode)
        .symlinks(symlink_behavior)
        .validation(validation)
        .junk_paths(cli.junk_paths)
        .fsync(cli.fsync);

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
        // We know total entries for 7z because it decompresses upfront
        let adapter = safe_unzip::SevenZAdapter::open(archive)?;
        let total_entries = adapter.len();

        driver = driver.on_progress(move |p| {
            println!("[{}/{}] {}", p.entry_index + 1, total_entries, p.entry_name);
        });
    }

    let report = driver.extract_7z_file(archive)?;

    if !cli.quiet {
        println!(
            "Extracted {} files ({} bytes) to {}",
            report.files_extracted,
            format_bytes(report.bytes_written),
            cli.dest.display()
        );
        if report.entries_skipped > 0 {
            println!("Skipped {} entries", report.entries_skipped);
        }
    }

    Ok(())
}

fn list_archive(path: &Path, format: ArchiveFormat, quiet: bool) -> Result<(), Error> {
    match format {
        ArchiveFormat::Zip => {
            let entries = safe_unzip::list_zip_entries(path)?;

            if !quiet {
                println!("{} entries in {}:", entries.len(), path.display());
                println!();
            }

            let mut total_size = 0u64;
            for entry in &entries {
                let kind = match entry.kind {
                    safe_unzip::EntryKind::File => "",
                    safe_unzip::EntryKind::Directory => "/",
                    safe_unzip::EntryKind::Symlink { .. } => " -> [symlink]",
                };
                println!("{:>10}  {}{}", format_bytes(entry.size), entry.name, kind);
                total_size += entry.size;
            }

            if !quiet {
                println!();
                println!(
                    "Total: {} files, {}",
                    entries.len(),
                    format_bytes(total_size)
                );
            }
        }
        ArchiveFormat::Tar | ArchiveFormat::TarGz => {
            let entries = if matches!(format, ArchiveFormat::TarGz) {
                safe_unzip::list_tar_gz_entries(path)?
            } else {
                safe_unzip::list_tar_entries(path)?
            };

            if !quiet {
                println!("{} entries in {}:", entries.len(), path.display());
                println!();
            }

            let mut total_size = 0u64;
            for entry in &entries {
                let kind = match entry.kind {
                    safe_unzip::EntryKind::File => "",
                    safe_unzip::EntryKind::Directory => "/",
                    safe_unzip::EntryKind::Symlink { .. } => " -> [symlink]",
                };
                println!("{:>10}  {}{}", format_bytes(entry.size), entry.name, kind);
                total_size += entry.size;
            }

            if !quiet {
                println!();
                println!(
                    "Total: {} files, {}",
                    entries.len(),
                    format_bytes(total_size)
                );
            }
        }
        ArchiveFormat::SevenZ => {
            #[cfg(feature = "sevenz")]
            {
                let adapter = safe_unzip::SevenZAdapter::open(path)?;
                let entries = adapter.entries_metadata();

                if !quiet {
                    println!("{} entries in {}:", entries.len(), path.display());
                    println!();
                }

                let mut total_size = 0u64;
                for entry in &entries {
                    let kind = match entry.kind {
                        safe_unzip::EntryKind::File => "",
                        safe_unzip::EntryKind::Directory => "/",
                        safe_unzip::EntryKind::Symlink { .. } => " -> [symlink]",
                    };
                    println!("{:>10}  {}{}", format_bytes(entry.size), entry.name, kind);
                    total_size += entry.size;
                }
                if !quiet {
                    println!();
                    println!(
                        "Total: {} files, {}",
                        entries.len(),
                        format_bytes(total_size)
                    );
                }
            }
            #[cfg(not(feature = "sevenz"))]
            {
                eprintln!("Error: 7z listing requires --features sevenz");
                Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "7z not supported in this build",
                )))
            }
        }
    }

    Ok(())
}

fn verify_archive(path: &Path, format: ArchiveFormat, quiet: bool) -> Result<(), Error> {
    if !quiet {
        println!("Verifying {}...", path.display());
    }

    match format {
        ArchiveFormat::Zip => {
            let report = safe_unzip::verify_file(path)?;

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

            let total_size: u64 = entries.iter().map(|e| e.size).sum();

            if !quiet {
                println!(
                    "Verified {} entries ({})",
                    entries.len(),
                    format_bytes(total_size)
                );
            }
        }
        ArchiveFormat::SevenZ => {
            #[cfg(feature = "sevenz")]
            {
                // SevenZAdapter decompresses fully on open, effectively verifying integrity
                let adapter = safe_unzip::SevenZAdapter::open(path)?;
                let entries = adapter.entries_metadata();
                let total_size: u64 = entries.iter().map(|e| e.size).sum();

                if !quiet {
                    println!(
                        "Verified {} entries ({})",
                        entries.len(),
                        format_bytes(total_size)
                    );
                }
            }
            #[cfg(not(feature = "sevenz"))]
            {
                eprintln!("Error: 7z verification requires --features sevenz");
                Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "7z not supported in this build",
                )))
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
            format!("Path traversal blocked in '{}': {}", entry, detail)
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
                entry,
                format_bytes(*size),
                format_bytes(*limit)
            )
        }
        Error::FileCountExceeded { limit, .. } => {
            format!("Too many files (limit: {})", limit)
        }
        Error::AlreadyExists { entry } => {
            format!("File already exists: {}", entry)
        }
        Error::EncryptedEntry { entry } => {
            format!("Encrypted entry not supported: {}", entry)
        }
        _ => e.to_string(),
    }
}

fn resolve_password(archive: &Path, format: &ArchiveFormat, verbose: bool) -> Option<String> {
    // Only attempt to resolve password if the archive actually needs one
    if !requires_password(archive, format) {
        return None;
    }

    // 1. Try passwords from config file
    if let Some(config_passwords) = load_config_passwords(verbose) {
        if verbose {
            println!("Checking passwords from config...");
        }
        for pwd in config_passwords {
            if verify_password(archive, format, &pwd) {
                return Some(pwd);
            }
        }
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
            if let Ok(file) = std::fs::File::open(path) {
                if let Ok(mut archive) = zip::ZipArchive::new(file) {
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
            }
            false
        }
        // For other formats, assume password might be needed if prompted,
        // or we can't easily check without trying to extract.
        _ => true,
    }
}

fn verify_password(path: &Path, format: &ArchiveFormat, password: &str) -> bool {
    match format {
        ArchiveFormat::Zip => {
            if let Ok(file) = std::fs::File::open(path) {
                if let Ok(mut archive) = zip::ZipArchive::new(file) {
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
        // Cannot verify easily for other formats without partial extraction
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
            let _ = archive.for_each_entries(|entry, reader| {
                if !entry.is_directory() {
                    found_file = true;
                    // Try to read 1 byte to trigger decryption/MAC check
                    let mut buf = [0u8; 1];
                    match reader.read(&mut buf) {
                        Ok(_) => valid = true,
                        Err(_) => valid = false,
                    }
                    // Stop after checking the first file
                    return Ok(false);
                }
                Ok(true) // Skip directories
            });

            // If we found a file and read it successfully, password is correct.
            if found_file {
                valid
            } else {
                // If archive is empty or only has dirs, and we opened it, assume password is OK
                true
            }
        }
        Err(_) => false, // Open failed (e.g. encrypted headers with wrong password)
    }
}

fn load_config_passwords(verbose: bool) -> Option<Vec<String>> {
    let config_dir = dirs_next::config_dir()?;
    let config_path = config_dir.join("safe_unzip.toml");

    if config_path.exists() {
        if verbose {
            println!("Reading config from: {}", config_path.display());
        }
        match std::fs::read_to_string(&config_path) {
            Ok(content) => match toml::from_str::<Config>(&content) {
                Ok(config) => {
                    if let Some(passwords_config) = config.passwords {
                        if let Some(ref list) = passwords_config.list {
                            if verbose {
                                println!("Loaded {} passwords from config", list.len());
                            }
                        }
                        return passwords_config.list;
                    }
                }
                Err(e) => {
                    eprintln!(
                        "Warning: Failed to parse config file {}: {}",
                        config_path.display(),
                        e
                    );
                }
            },
            Err(e) => {
                eprintln!(
                    "Warning: Failed to read config file {}: {}",
                    config_path.display(),
                    e
                );
            }
        }
    }
    None
}
