use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::core::global_utils::fileutils::{get_validated_file_stem, validate_sha256_digest};

/// Directory-name component separating the process name from its SHA-256 identity.
pub const PROCESS_DUMP_MARKER: &str = "procdmp";

/// Version written into every process-triage JSON document.
pub const PROCESS_TRIAGE_SCHEMA_VERSION: u32 = 1;

/// Process dump directory containing PE-related results.
pub const PE_DIRECTORY_NAME: &str = "PE";

/// Process dump directory containing import-related results.
pub const IMPORTS_DIRECTORY_NAME: &str = "Imports";

/// Process dump directory containing PEB-related results.
pub const PEB_DIRECTORY_NAME: &str = "PEB";

/// Process dump directory containing pattern-scan results.
pub const PATTERNS_DIRECTORY_NAME: &str = "Patterns";

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

/// Detected code-section metadata output file name.
pub const CODE_SECTION_FILE_NAME: &str = "code_section.json";

/// Combined x64 pattern-hit metadata output file name.
pub const PATTERN_HITS64_FILE_NAME: &str = "pattern_hits64.json";

/// Breakpoint-related process opcode output file name.
pub const OPCODE_HITS64_FILE_NAME: &str = "opcode_hits64.json";

/// Root-level JSON file reserved for every collected string result.
pub const STRINGS_FILE_NAME: &str = "strings.json";

/// Initial valid JSON content used until collected strings are persisted.
const EMPTY_STRINGS_JSON: &[u8] = b"{\n  \"strings\": []\n}\n";


/// Contains the fixed output locations for one completed process scan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessDumpLayout
{
    pub root: PathBuf,
    pub pe: PathBuf,
    pub imports: PathBuf,
    pub peb: PathBuf,
    pub patterns: PathBuf,
    pub strings: PathBuf,
}


/// Creates one process-dump tree under Daydream's current working directory.
/// `target_executable`: the validated target image whose file stem names the process.
/// `sha256`: the 64-character SHA-256 digest of that on-disk target image.
///
/// Returns the root, category directories, and root string-file path. Existing
/// output is retained while missing directories and the initial JSON file are added.
pub fn prepare_process_dump_layout(target_executable: &Path, sha256: &str) -> io::Result<ProcessDumpLayout>
{
    let process_name = get_validated_file_stem(target_executable)?;
    validate_sha256_digest(sha256)?;

    let root = std::env::current_dir()?.join(format!("{}_{}_{}", process_name, PROCESS_DUMP_MARKER, sha256));
    let pe = root.join(PE_DIRECTORY_NAME);
    let imports = root.join(IMPORTS_DIRECTORY_NAME);
    let peb = root.join(PEB_DIRECTORY_NAME);
    let patterns = root.join(PATTERNS_DIRECTORY_NAME);
    let strings = root.join(STRINGS_FILE_NAME);

    fs::create_dir_all(&pe)?;
    fs::create_dir_all(&imports)?;
    fs::create_dir_all(&peb)?;
    fs::create_dir_all(&patterns)?;

    match OpenOptions::new().write(true).create_new(true).open(&strings)
    {
        Ok(mut file) => file.write_all(EMPTY_STRINGS_JSON)?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }

    Ok(ProcessDumpLayout
    {
        root,
        pe,
        imports,
        peb,
        patterns,
        strings,
    })
}
