use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::core::global_utils::fileutils::{get_validated_file_stem, validate_sha256_digest};

/// Directory-name component separating the process name from its SHA-256 identity.
pub const PROCESS_DUMP_MARKER: &str = "procdmp";

/// Version written into every process-triage JSON document.
pub const PROCESS_TRIAGE_SCHEMA_VERSION: u32 = 4;

/// Process dump directory containing PE-related results.
pub const PE_DIRECTORY_NAME: &str = "PE";

/// Process dump directory containing import-related results.
pub const IMPORTS_DIRECTORY_NAME: &str = "Imports";

/// Process dump directory containing PEB-related results.
pub const PEB_DIRECTORY_NAME: &str = "PEB";

/// PE image metadata output file name.
pub const IMAGE_FILE_NAME: &str = "image.json";

/// PE section metadata output file name.
pub const SECTIONS_FILE_NAME: &str = "sections.json";

/// PDB metadata output file name.
pub const PDB_FILE_NAME: &str = "pdb.json";

/// Process import metadata output file name.
pub const IMPORTS_FILE_NAME: &str = "imports.json";

/// PEB metadata output file name.
pub const PEB_FILE_NAME: &str = "peb.json";

/// TEB metadata output file name.
pub const TEBS_FILE_NAME: &str = "tebs.json";

/// Contains the fixed output locations for one completed process scan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessDumpLayout
{
    pub root: PathBuf,
    pub pe: PathBuf,
    pub imports: PathBuf,
    pub peb: PathBuf,
}


/// Creates the reduced process-dump tree under Daydream's current working directory.
/// `target_executable`: the validated target image whose file stem names the process.
/// `sha256`: the 64-character SHA-256 digest used to identify the target image.
///
/// Returns the root and retained category directories after removing obsolete outputs.
pub fn prepare_process_dump_layout(target_executable: &Path, sha256: &str) -> io::Result<ProcessDumpLayout>
{
    let process_name = get_validated_file_stem(target_executable)?;
    validate_sha256_digest(sha256)?;

    let root = std::env::current_dir()?.join(format!("{}_{}_{}", process_name, PROCESS_DUMP_MARKER, sha256));
    let pe = root.join(PE_DIRECTORY_NAME);
    let imports = root.join(IMPORTS_DIRECTORY_NAME);
    let peb = root.join(PEB_DIRECTORY_NAME);

    fs::create_dir_all(&pe)?;
    fs::create_dir_all(&imports)?;
    fs::create_dir_all(&peb)?;
    remove_obsolete_process_outputs(&root)?;

    Ok(ProcessDumpLayout {
        root,
        pe,
        imports,
        peb,
    })
}


/// Removes generated outputs belonging only to the deleted process collectors.
/// `root`: validated content-addressed process output root.
///
/// Returns unit when known obsolete files are absent or removed successfully.
fn remove_obsolete_process_outputs(root: &Path) -> io::Result<()>
{
    let patterns = root.join("Patterns");

    for path in [
        root.join("strings.json"),
        patterns.join("code_section.json"),
        patterns.join("pattern_hits64.json"),
        patterns.join("opcode_hits64.json"),
        patterns.join("entry_signature.json"),
        patterns.join("opcode_hits.json"),
    ]
    {
        match fs::remove_file(path)
        {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }

    match fs::remove_dir(patterns)
    {
        Ok(()) => {}
        Err(error) if matches!(error.kind(), io::ErrorKind::NotFound | io::ErrorKind::DirectoryNotEmpty) => {}
        Err(error) => return Err(error),
    }

    Ok(())
}
