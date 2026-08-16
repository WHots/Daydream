use std::fmt;
use std::io::{self, Write};
use std::path::PathBuf;

use windows_sys::Win32::Foundation::{GetLastError, HANDLE};
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

use crate::core::file_ops::utils::validate::{self as validate_file, FileValidationError, ValidatedPeFile};
use crate::core::global_utils::fileutils::get_data_sha256;
use crate::core::internal::utils::handles::{CleanHandle, HandleAccessQueryError};
use crate::core::process_ops::outputs::process_triage_saves::save_process_triage;
use crate::core::process_ops::utils::detect_code_section_utils::{self, CodeSectionAnalysis, CodeSectionConfidence};
use crate::core::process_ops::utils::foundation::validate_pe::{self, PeValidationError, UnavailablePeRange, ValidatedPeSnapshot};
use crate::core::process_ops::utils::importutils::{self, ProcessImportCollection, ProcessImportCollectionError};
use crate::core::process_ops::utils::pdbutils::{self, PdbInfo, PdbInfoCollectionError};
use crate::core::process_ops::utils::pe_utils::{self, PeSectionInfo, ProcessOpcodeCollection};
use crate::core::process_ops::utils::processutils::{self, ProcessPeValidationError, ValidatedProcessPe};
use crate::core::process_ops::utils::stringdumputils::{self, MainModuleStringCollection, TebStackStringCollection, TebStackStringCollectionError};
use crate::core::process_ops::utils::tebutils::{self, ProcessTebCollection, ProcessTebCollectionError};

/// Access rights required by every process-memory collector.
const PROCESS_MEMORY_INSPECTION_ACCESS: u32 = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;

/// Character width of the process progress bar.
const PROCESS_PROGRESS_BAR_WIDTH: usize = 24;

/// Fixed phase-label width used to overwrite the preceding progress line completely.
const PROCESS_PROGRESS_PHASE_WIDTH: usize = 32;

/// Default minimum decoded character count retained by process string collectors.
pub const DEFAULT_MINIMUM_PROCESS_STRING_LENGTH: usize = 4;

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


/// Owns detected code-section metadata and section-aware file locations.
#[derive(Debug)]
pub struct ProcessCodeSectionAnalysis
{
    pub analysis: CodeSectionAnalysis,
    pub primary_file_offset: Option<usize>,
    pub entry_section_file_offset: Option<usize>,
}


/// Describes one matched process-image pattern with mapped and raw-file locations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessPatternHit
{
    pub name: &'static str,
    pub address: Option<usize>,
    pub rva: usize,
    pub file_offset: Option<usize>,
}


/// Records whether one trusted TEB stack was collected, skipped, or failed.
#[derive(Debug)]
pub enum TebStackScanStatus
{
    Collected(TebStackStringCollection),
    SkippedUntrustedTeb,
    Failed(TebStackStringCollectionError),
}


/// Associates a thread identifier with its TEB-stack string collection status.
#[derive(Debug)]
pub struct TebStackScan
{
    pub thread_id: u32,
    pub status: TebStackScanStatus,
}


/// Owns every structured result produced by one process-memory triage scan.
#[derive(Debug)]
pub struct ProcessTriageCollection
{
    pub validated_process: ValidatedProcessPe,
    pub backing_file_sha256: Option<Box<str>>,
    pub output_identity_sha256: Box<str>,
    pub granted_access: u32,
    pub minimum_string_characters: usize,
    pub entry_point_file_offset: Option<usize>,
    pub unavailable_image_ranges: Vec<UnavailablePeRange>,
    pub sections: Vec<PeSectionInfo>,
    pub code_section: Option<ProcessCodeSectionAnalysis>,
    pub entry_signature: Option<ProcessPatternHit>,
    pub pattern_hits: Vec<ProcessPatternHit>,
    pub pattern_scan_complete: bool,
    pub opcode_hits: ProcessOpcodeCollection,
    pub pdb: Result<Option<PdbInfo>, PdbInfoCollectionError>,
    pub imports: Result<ProcessImportCollection, ProcessImportCollectionError>,
    pub main_module_strings: MainModuleStringCollection,
    pub tebs: Result<ProcessTebCollection, ProcessTebCollectionError>,
    pub teb_stack_scans: Vec<TebStackScan>,
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
/// Returns the created process-dump root after every collector completes, or the fatal
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

    progress.update("Validating backing image", 8);

    let backing_file = validate_file::validate_target_file(&validated_process.image_path);
    let backing_file_sha256 = match backing_file.as_ref()
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
            eprintln!("backing executable comparison is unavailable: {error}");
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
    let collection = collect_validated_process_triage(process.as_raw(), validated_process, snapshot, backing_file, backing_file_sha256, output_identity_sha256, access.granted_access(), &mut progress);

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
            Self::ProcessValidationFailed(error) =>
            {
                write!(formatter, "process PEB/PE validation failed: {:?}", error)
            }
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


/// Runs every helper against one central validation and one mapped-image snapshot.
/// `process`: the open process handle represented by the validation and snapshot.
/// `validated_process`: the owned process, PEB, main-image, and executable identity.
/// `snapshot`: the matching mapped-image bytes, parsed PE, and unavailable ranges.
/// `backing_file`: one retained raw executable or its typed validation failure.
/// `backing_file_sha256`: digest of retained disk-path bytes when available.
/// `output_identity_sha256`: retained file or mapped-snapshot digest naming the output.
/// `granted_access`: the validated access mask used by the completed collectors.
/// `progress`: the single console reporter receiving phase and percentage updates.
///
/// Returns the complete structured collection with nonfatal helper failures retained.
fn collect_validated_process_triage(process: HANDLE, validated_process: ValidatedProcessPe, snapshot: ValidatedPeSnapshot, backing_file: Result<ValidatedPeFile, FileValidationError>, backing_file_sha256: Option<Box<str>>, output_identity_sha256: Box<str>, granted_access: u32, progress: &mut ProcessProgress) -> ProcessTriageCollection
{
    progress.update("Collecting PE metadata", 15);

    let sections = pe_utils::collect_sections_from_pe(&snapshot.pe);
    let entry_point_file_offset = pe_utils::get_file_offset_from_pe(&snapshot.pe, validated_process.image.entry_point_rva);

    progress.update("Analyzing code sections", 18);

    let mut code_section = detect_code_section_utils::locate_text_section(&snapshot.bytes).map(|mut analysis| {
        if !snapshot.unavailable_ranges.is_empty()
        {
            analysis.image_complete = false;
            analysis.confidence = CodeSectionConfidence::Low;
        }

        let primary_file_offset = pe_utils::get_file_offset_from_pe(&snapshot.pe, analysis.primary.rva);
        let entry_section_file_offset = analysis.entry_point.as_ref().and_then(|section| pe_utils::get_file_offset_from_pe(&snapshot.pe, section.rva));

        ProcessCodeSectionAnalysis {
            analysis,
            primary_file_offset,
            entry_section_file_offset,
        }
    });

    progress.update("Scanning x64 patterns", 18);

    let pattern_scan = pe_utils::collect_pattern_hits_from_snapshot(&snapshot, &mut |completed, total| {
        progress.update("Scanning x64 patterns", phase_percentage(18, 22, completed, total));
    });
    let map_pattern_hit = |hit: pe_utils::PePatternMatch| ProcessPatternHit {
        name: hit.name,
        address: validated_process.image.base_address.checked_add(hit.rva),
        rva: hit.rva,
        file_offset: pe_utils::get_file_offset_from_pe(&snapshot.pe, hit.rva),
    };
    let entry_signature = pattern_scan.entry_signature.map(map_pattern_hit);
    let pattern_hits = pattern_scan.hits.into_iter().map(map_pattern_hit).collect();
    let pattern_scan_complete = pattern_scan.scan_complete;

    progress.update("Scanning breakpoint opcodes", 22);

    let runtime_functions = code_section.as_ref().map(|code| code.analysis.runtime_functions.as_slice()).unwrap_or(&[]);
    let opcode_hits = pe_utils::collect_opcode_hits_from_snapshot(&validated_process, &snapshot, backing_file.as_ref(), runtime_functions, &mut |completed, total| {
        progress.update("Scanning breakpoint opcodes", phase_percentage(22, 25, completed, total));
    });

    if let Some(code) = code_section.as_mut()
    {
        code.analysis.runtime_functions = Vec::new();
    }

    drop(backing_file);

    progress.update("Collecting PDB metadata", 25);

    let pdb = pdbutils::collect_main_module_pdb_info_from_snapshot(&snapshot);

    progress.update("Scanning imports and IAT", 25);

    let imports = importutils::collect_process_imports_from_snapshot(&validated_process, &snapshot, &mut |completed, total| {
        progress.update("Scanning imports and IAT", phase_percentage(25, 50, completed, total));
    });

    progress.update("Scanning imports and IAT", 50);
    progress.update("Scanning main-image strings", 50);

    let main_module_strings = stringdumputils::collect_main_module_strings_from_snapshot(&validated_process, &snapshot, DEFAULT_MINIMUM_PROCESS_STRING_LENGTH, &mut |completed, total| {
        progress.update("Scanning main-image strings", phase_percentage(50, 80, completed, total));
    });

    progress.update("Scanning main-image strings", 80);
    progress.update("Collecting thread TEBs", 80);

    let tebs = tebutils::collect_process_tebs(process, &mut |completed, total| {
        progress.update("Collecting thread TEBs", phase_percentage(80, 85, completed, total));
    });
    let mut teb_stack_scans = Vec::new();

    progress.update("Collecting thread TEBs", 85);
    progress.update("Scanning TEB stacks", 85);

    if let Ok(teb_collection) = &tebs
    {
        teb_stack_scans.reserve(teb_collection.tebs.len());
        let total_stack_bytes = teb_collection.tebs.iter().filter(|teb| teb.self_pointer_matches && teb.client_process_id_matches && teb.client_thread_id_matches && teb.process_environment_block == validated_process.peb_address).fold(0usize, |total, teb| total.saturating_add(teb.stack_base.checked_sub(teb.stack_limit).unwrap_or(0)));
        let mut completed_stack_bytes = 0usize;

        for teb in &teb_collection.tebs
        {
            let trusted_teb = teb.self_pointer_matches && teb.client_process_id_matches && teb.client_thread_id_matches && teb.process_environment_block == validated_process.peb_address;
            let stack_bytes = if trusted_teb { teb.stack_base.checked_sub(teb.stack_limit).unwrap_or(0) } else { 0 };
            let completed_before_stack = completed_stack_bytes;
            let status = if !trusted_teb
            {
                TebStackScanStatus::SkippedUntrustedTeb
            }
            else
            {
                match stringdumputils::collect_teb_stack_strings(process, teb, DEFAULT_MINIMUM_PROCESS_STRING_LENGTH, &mut |completed, _| {
                    let completed = completed_before_stack.saturating_add(completed);

                    progress.update("Scanning TEB stacks", phase_percentage(85, 97, completed, total_stack_bytes));
                })
                {
                    Ok(collection) => TebStackScanStatus::Collected(collection),
                    Err(error) => TebStackScanStatus::Failed(error),
                }
            };

            completed_stack_bytes = completed_stack_bytes.saturating_add(stack_bytes);
            progress.update("Scanning TEB stacks", phase_percentage(85, 97, completed_stack_bytes, total_stack_bytes));

            teb_stack_scans.push(TebStackScan {
                thread_id: teb.thread_id,
                status,
            });
        }
    }

    progress.update("Scanning TEB stacks", 97);

    ProcessTriageCollection {
        validated_process,
        backing_file_sha256,
        output_identity_sha256,
        granted_access,
        minimum_string_characters: DEFAULT_MINIMUM_PROCESS_STRING_LENGTH,
        entry_point_file_offset,
        unavailable_image_ranges: snapshot.unavailable_ranges.clone(),
        sections,
        code_section,
        entry_signature,
        pattern_hits,
        pattern_scan_complete,
        opcode_hits,
        pdb,
        imports,
        main_module_strings,
        tebs,
        teb_stack_scans,
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
