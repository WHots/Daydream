use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Component, Path, PathBuf};

use serde_json::Value;

/// Contains the fixed output locations created for one raw-file triage scan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileTriageLayout
{
    pub root: PathBuf,
    pub pe: PathBuf,
    pub imports: PathBuf,
    pub peb: PathBuf,
    pub scanning: PathBuf,
}


/// Recreates one file-triage output tree under Daydream's current working directory.
/// `target_file`: the scanned file whose extension-free name prefixes the root folder.
/// `sha256`: the lowercase or uppercase 64-character SHA-256 digest for the target.
///
/// Returns the recreated root and category paths. An existing scan root is removed
/// before the new `PE`, `Imports`, `PEB`, and `Scanning` directories are created.
pub fn prepare_file_triage_layout(target_file: &Path, sha256: &str) -> io::Result<FileTriageLayout>
{
    let file_stem = validated_file_stem(target_file)?;
    validate_sha256(sha256)?;

    let working_directory = std::env::current_dir()?;
    let root = working_directory.join(format!("{}_{}", file_stem, sha256));
    let pe = root.join("PE");
    let imports = root.join("Imports");
    let peb = root.join("PEB");
    let scanning = root.join("Scanning");

    overwrite_existing_path(&root)?;
    
    fs::create_dir_all(&pe)?;
    fs::create_dir_all(&imports)?;
    fs::create_dir_all(&peb)?;
    fs::create_dir_all(&scanning)?;

    Ok(FileTriageLayout
    {
        root,
        pe,
        imports,
        peb,
        scanning,
    })
}


/// Serializes and overwrites one pretty-formatted JSON file inside an output directory.
/// `directory`: the already-selected scan root or category directory.
/// `file_name`: one local file-name component with no traversal or subdirectories.
/// `value`: the structured JSON value to serialize.
///
/// Returns the path written on success, or an I/O error for invalid names,
/// serialization failures, directory creation failures, or file writes.
pub fn write_json_file(directory: &Path, file_name: &str, value: &Value) -> io::Result<PathBuf>
{
    validate_file_name(file_name)?;

    let output_path = directory.join(file_name);
    fs::create_dir_all(directory)?;

    let output_file = File::create(&output_path)?;
    let mut writer = BufWriter::new(output_file);

    serde_json::to_writer_pretty(&mut writer, value)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    writer.flush()?;

    Ok(output_path)
}


/// Extracts one non-empty, extension-free target name for the scan root.
/// `target_file`: the scanned path whose file stem should be validated.
///
/// Returns the lossy Unicode file stem, or an invalid-input error.
fn validated_file_stem(target_file: &Path) -> io::Result<String>
{
    let file_stem = match target_file.file_stem()
    {
        Some(value) if !value.is_empty() => value.to_string_lossy().into_owned(),
        _ =>
        {
            eprintln!("failed to derive a file name for the triage output directory");
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "target file has no usable file stem"));
        }
    };

    if file_stem == "." || file_stem == ".."
    {
        eprintln!("refusing unsafe triage output file stem {:?}", file_stem);
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "target file stem is unsafe"));
    }

    Ok(file_stem)
}


/// Validates the digest component used in one scan-root directory name.
/// `sha256`: the digest text required to contain exactly 64 hexadecimal characters.
///
/// Returns success for a valid digest, or an invalid-input error.
fn validate_sha256(sha256: &str) -> io::Result<()>
{
    if sha256.len() != 64 || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        eprintln!("refusing invalid SHA-256 value for the triage output directory");
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "SHA-256 must contain exactly 64 hexadecimal characters"));
    }

    Ok(())
}


/// Removes one existing scan-root file, link, or directory before recreation.
/// `path`: the exact direct-child scan-root path selected by the public layout method.
///
/// Returns success when the path is absent or removed, or the underlying I/O error.
fn overwrite_existing_path(path: &Path) -> io::Result<()>
{
    let metadata = match fs::symlink_metadata(path)
    {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) =>
        {
            eprintln!("failed to inspect existing triage output path {:?}: {}", path, error);
            return Err(error);
        }
    };

    if metadata.file_type().is_dir() && !metadata.file_type().is_symlink()
    {
        fs::remove_dir_all(path)
    }
    else
    {
        fs::remove_file(path)
    }
}


/// Rejects empty, absolute, nested, and traversal-based JSON output names.
/// `file_name`: the local output name required to contain one normal path component.
///
/// Returns success for a safe name, or an invalid-input error.
fn validate_file_name(file_name: &str) -> io::Result<()>
{
    let path = Path::new(file_name);
    let mut components = path.components();
    let valid = matches!(components.next(), Some(Component::Normal(_)))
        && components.next().is_none();

    if !valid
    {
        eprintln!("refusing unsafe triage output file name {:?}", file_name);
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "output file name must be one normal path component"));
    }

    Ok(())
}
