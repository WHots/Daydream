use std::fmt;
use std::io::{self, Write};
use std::path::PathBuf;

use windows_sys::Win32::Foundation::{GetLastError, HANDLE};
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

use crate::core::file_ops::utils::validate as validate_file;
use crate::core::global_utils::fileutils::get_data_sha256;
use crate::core::internal::utils::handles::{CleanHandle, HandleAccessQueryError};
use crate::core::process_ops::outputs::process_triage_saves::save_process_triage;
use crate::core::process_ops::utils::foundation::validate_pe::{self, PeSectionInfo, PeValidationError, UnavailablePeRange, ValidatedPeSnapshot};
use crate::core::process_ops::utils::imports::{collect_process_imports_from_snapshot, ProcessImportCollection, ProcessImportCollectionError};
use crate::core::process_ops::utils::pdbutils::{self, PdbInfo, PdbInfoCollectionError};
use crate::core::process_ops::utils::processutils::{self, ProcessPeValidationError, ValidatedProcessPe};
use crate::core::process_ops::utils::tebutils::{self, ProcessTebCollection, ProcessTebCollectionError};

/// Access rights required by every retained process-memory collector.
const PROCESS_MEMORY_INSPECTION_ACCESS: u32 = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;

/// Character width of the process progress bar.
const PROCESS_PROGRESS_BAR_WIDTH: usize = 24;

/// Fixed phase-label width used to overwrite the preceding progress line completely.
const PROCESS_PROGRESS_PHASE_WIDTH: usize = 32;

/// Owns the single console line used while process triage is running.
struct ProcessProgress
{
    last_phase: &'static str,
    last_percentage: usize,
    rendered: bool,
}

impl ProcessProgress
{
    /// Creates an unrendered process progress display.
    ///
    /// Returns a reporter ready for its first phase update.
    fn new() -> Self
    {
        Self {
            last_phase: "",
            last_percentage: usize::MAX,
            rendered: false,
        }
    }


    /// Updates the process progress line when its phase or percentage changed.
    /// `phase`: the current collector or orchestration phase.
    /// `percentage`: the completed overall percentage, clamped to one hundred.
    ///
    /// Returns unit after rendering and flushing the current progress line.
    fn update(&mut self, phase: &'static str, percentage: usize)
    {
        let percentage = percentage.min(100);

        if self.rendered && self.last_phase == phase && self.last_percentage == percentage
        {
            return;
        }

        let filled = percentage * PROCESS_PROGRESS_BAR_WIDTH / 100;
        let bar = format!("{}{}", "#".repeat(filled), "-".repeat(PROCESS_PROGRESS_BAR_WIDTH - filled));

        eprint!("\r[{}] {:3}% {:<width$}", bar, percentage, phase, width = PROCESS_PROGRESS_PHASE_WIDTH);
        let _ = io::stderr().flush();

        self.last_phase = phase;
        self.last_percentage = percentage;
        self.rendered = true;
    }


    /// Completes the progress display and advances subsequent output to a fresh line.
    ///
    /// Returns unit after rendering the final one-hundred-percent phase.
    fn finish(&mut self)
    {
        self.update("Complete", 100);
        eprintln!();
        self.rendered = false;
    }
}

impl Drop for ProcessProgress
{
    fn drop(&mut self)
    {
        if self.rendered
        {
            eprintln!();
        }
    }
}


/// Owns every retained structured result produced by one process-memory triage scan.
#[derive(Debug)]
pub struct ProcessTriageCollection
{
    pub validated_process: ValidatedProcessPe,
    pub backing_file_sha256: Option<Box<str>>,
    pub output_identity_sha256: Box<str>,
    pub granted_access: u32,
    pub entry_point_file_offset: Option<usize>,
    pub unavailable_image_ranges: Vec<UnavailablePeRange>,
    pub sections: Vec<PeSectionInfo>,
    pub pdb: Result<Option<PdbInfo>, PdbInfoCollectionError>,
    pub imports: Result<ProcessImportCollection, ProcessImportCollectionError>,
    pub tebs: Result<ProcessTebCollection, ProcessTebCollectionError>,
}


/// Explains why a complete process scan could not be opened, validated, read, or saved.
#[derive(Debug)]
pub enum ProcessProcessingError
{
    OpenProcessFailed
    {
        process_id: u32,
        error: u32,
    },
    AccessQueryFailed(HandleAccessQueryError),
    InsufficientAccess
    {
        granted_access: u32,
        required_access: u32,
    },
    ProcessIdentityMismatch
    {
        expected_process_id: u32,
        actual_process_id: u32,
    },
    ProcessValidationFailed(ProcessPeValidationError),
    MainImageReadFailed(PeValidationError),
    OutputIdentityHashFailed(io::Error),
    SaveFailed(io::Error),
}


/// Opens, validates, collects, reports progress for, and saves one process target.
/// `process_id`: the CLI-selected target process identifier.
///
/// Returns the created process-dump root after every retained collector completes, or the
/// open, validation, image-read, or save failure that prevented a complete scan.
pub fn process_target(process_id: u32) -> Result<PathBuf, ProcessProcessingError>
{
    let mut progress = ProcessProgress::new();
    progress.update("Opening process", 0);

    // SAFETY: the process identifier and minimum required access mask are passed by value.
    let raw_process = unsafe { OpenProcess(PROCESS_MEMORY_INSPECTION_ACCESS, 0, process_id) };
    let process = match CleanHandle::new(raw_process)
    {
        Some(value) => value,
        None =>
        {
            // SAFETY: `GetLastError` only reads the calling thread's last-error value.
            let error = unsafe { GetLastError() };

            return Err(ProcessProcessingError::OpenProcessFailed {
                process_id,
                error,
            });
        }
    };
    progress.update("Checking process access", 3);

    let access = process.query_access().map_err(ProcessProcessingError::AccessQueryFailed)?;

    if !access.contains(PROCESS_MEMORY_INSPECTION_ACCESS)
    {
        return Err(ProcessProcessingError::InsufficientAccess {
            granted_access: access.granted_access(),
            required_access: PROCESS_MEMORY_INSPECTION_ACCESS,
        });
    }

    progress.update("Validating process", 5);

    let validated_process = processutils::validate_process_peb(process.as_raw()).map_err(ProcessProcessingError::ProcessValidationFailed)?;

    if validated_process.process_id != process_id
    {
        return Err(ProcessProcessingError::ProcessIdentityMismatch {
            expected_process_id: process_id,
            actual_process_id: validated_process.process_id,
        });
    }

    progress.update("Hashing backing image", 8);

    let backing_file_sha256 = match validate_file::validate_target_file(&validated_process.image_path)
    {
        Ok(file) => match get_data_sha256(&file.bytes)
        {
            Ok(value) => Some(value.into_boxed_str()),
            Err(error) =>
            {
                eprintln!("backing executable hash is unavailable: {error}");
                None
            }
        },
        Err(error) =>
        {
            eprintln!("backing executable hash is unavailable: {error}");
            None
        }
    };

    progress.update("Reading main image", 10);

    let snapshot = validate_pe::read_validated_image(process.as_raw(), &validated_process.image).map_err(ProcessProcessingError::MainImageReadFailed)?;
    let output_identity_sha256 = match backing_file_sha256.as_deref()
    {
        Some(value) => Box::<str>::from(value),
        None => get_data_sha256(&snapshot.bytes).map_err(ProcessProcessingError::OutputIdentityHashFailed)?.into_boxed_str(),
    };
    let collection = collect_validated_process_triage(process.as_raw(), validated_process, snapshot, backing_file_sha256, output_identity_sha256, access.granted_access(), &mut progress);

    progress.update("Saving results", 98);
    let layout = save_process_triage(&collection).map_err(ProcessProcessingError::SaveFailed)?;

    progress.finish();

    Ok(layout.root)
}

impl fmt::Display for ProcessProcessingError
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        match self
        {
            Self::OpenProcessFailed {
                process_id,
                error,
            } => write!(formatter, "failed to open process {}: {}", process_id, error),
            Self::AccessQueryFailed(error) => write!(formatter, "failed to query process handle access: {:?}", error),
            Self::InsufficientAccess {
                granted_access,
                required_access,
            } => write!(formatter, "process handle access 0x{:08X} does not contain required access 0x{:08X}", granted_access, required_access),
            Self::ProcessIdentityMismatch {
                expected_process_id,
                actual_process_id,
            } => write!(formatter, "process handle resolved to process {} instead of {}", actual_process_id, expected_process_id),
            Self::ProcessValidationFailed(error) => write!(formatter, "process PEB/PE validation failed: {:?}", error),
            Self::MainImageReadFailed(error) => write!(formatter, "validated main-image snapshot failed: {:?}", error),
            Self::OutputIdentityHashFailed(error) => write!(formatter, "process output identity could not be hashed: {}", error),
            Self::SaveFailed(error) => write!(formatter, "process scan completed but its JSON triage output could not be saved: {}", error),
        }
    }
}

impl std::error::Error for ProcessProcessingError
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)>
    {
        match self
        {
            Self::OutputIdentityHashFailed(error) => Some(error),
            Self::SaveFailed(error) => Some(error),
            _ => None,
        }
    }
}


/// Runs every retained helper against one central validation and mapped-image snapshot.
/// `process`: the open process handle represented by the validation and snapshot.
/// `validated_process`: the owned process, PEB, main-image, and executable identity.
/// `snapshot`: the matching mapped-image bytes, parsed PE, and unavailable ranges.
/// `backing_file_sha256`: digest of retained disk-path bytes when available.
/// `output_identity_sha256`: retained file or mapped-snapshot digest naming the output.
/// `granted_access`: the validated access mask used by the completed collectors.
/// `progress`: the single console reporter receiving phase and percentage updates.
///
/// Returns the retained process, PDB, import/IAT-xref, and TEB results.
fn collect_validated_process_triage(process: HANDLE, validated_process: ValidatedProcessPe, snapshot: ValidatedPeSnapshot, backing_file_sha256: Option<Box<str>>, output_identity_sha256: Box<str>, granted_access: u32, progress: &mut ProcessProgress) -> ProcessTriageCollection
{
    progress.update("Collecting PE metadata", 15);

    let sections = validate_pe::collect_sections_from_pe(&snapshot.pe);
    let entry_point_file_offset = validate_pe::get_file_offset_from_pe(&snapshot.pe, validated_process.image.entry_point_rva);

    progress.update("Collecting PDB metadata", 20);

    let pdb = pdbutils::collect_main_module_pdb_info_from_snapshot(&snapshot);

    progress.update("Scanning imports and IAT", 20);

    let imports = collect_process_imports_from_snapshot(&validated_process, &snapshot, &mut |completed, total| {
        progress.update("Scanning imports and IAT", phase_percentage(20, 85, completed, total));
    });

    progress.update("Collecting thread TEBs", 85);

    let tebs = tebutils::collect_process_tebs(process, &mut |completed, total| {
        progress.update("Collecting thread TEBs", phase_percentage(85, 97, completed, total));
    });

    progress.update("Collecting thread TEBs", 97);

    ProcessTriageCollection {
        validated_process,
        backing_file_sha256,
        output_identity_sha256,
        granted_access,
        entry_point_file_offset,
        unavailable_image_ranges: snapshot.unavailable_ranges.clone(),
        sections,
        pdb,
        imports,
        tebs,
    }
}


/// Maps completed collector work into one inclusive overall progress range.
/// `phase_start`: the overall percentage where the phase begins.
/// `phase_end`: the overall percentage where the phase completes.
/// `completed`: the collector work completed so far.
/// `total`: the collector's total work.
///
/// Returns the clamped overall percentage for the current phase.
fn phase_percentage(phase_start: usize, phase_end: usize, completed: usize, total: usize) -> usize
{
    if total == 0
    {
        return phase_end.min(100);
    }

    let phase_start = phase_start.min(100);
    let phase_end = phase_end.max(phase_start).min(100);
    let completed = completed.min(total);
    let span = phase_end - phase_start;
    let scaled = (completed as u128 * span as u128 / total as u128) as usize;

    phase_start + scaled
}
