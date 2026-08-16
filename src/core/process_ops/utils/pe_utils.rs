use std::collections::{HashSet, VecDeque};
use std::mem::size_of;

use iced_x86::{Code, Decoder, DecoderOptions, FlowControl, Instruction, OpKind, Register};
use windows_sys::Win32::System::Diagnostics::Debug::{IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_EXCEPTION, IMAGE_SCN_MEM_EXECUTE};

use crate::core::data::opcode_specific64::opcodes64::{OpcodeBytecode, INT1_ICEBP_DEBUG_TRAP, INT3_BREAKPOINT, INT_VECTOR_1_DEBUG_INTERRUPT, INT_VECTOR_3_BREAKPOINT, MOV_FROM_DEBUG_REGISTER, MOV_TO_DEBUG_REGISTER, X64_BREAKPOINT_OPCODE_BYTECODES};
use crate::core::file_ops::utils::supports::rva_to_file_range;
use crate::core::file_ops::utils::validate::{FileValidationError, ValidatedPeFile};
use crate::core::process_ops::utils::detect_code_section_utils::RuntimeFunctionRange;
use crate::core::process_ops::utils::foundation::validate_pe;
use crate::core::process_ops::utils::processutils::ValidatedProcessPe;

/// Executable-byte interval between opcode-scan progress updates.
const OPCODE_PROGRESS_BYTE_INTERVAL: usize = 64 * 1024;

/// Executable-byte interval between x64 pattern-scan progress updates.
const PATTERN_PROGRESS_BYTE_INTERVAL: usize = 64 * 1024;

/// Maximum decoded instruction starts retained during one process scan.
const MAXIMUM_DECODED_INSTRUCTION_COUNT: usize = 10_000_000;

/// Maximum unique recursive decode tasks scheduled from metadata and direct branches.
const MAXIMUM_DECODE_TASK_COUNT: usize = 1_000_000;

/// Maximum likely-padding runs retained as analyst-facing samples.
const MAXIMUM_PADDING_RUN_SAMPLES: usize = 32;

/// Byte size of one PE base-relocation block header.
const BASE_RELOCATION_BLOCK_HEADER_SIZE: usize = 8;

/// Byte size of one x64 runtime-function table entry.
const RUNTIME_FUNCTION_ENTRY_SIZE: usize = 12;

/// PE base-relocation type used for x64 absolute addresses.
const IMAGE_REL_BASED_DIR64: u16 = 10;

/// Describes one section from an already validated mapped PE image.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeSectionInfo
{
    pub name: Box<str>,
    pub rva: usize,
    pub virtual_size: usize,
    pub raw_size: usize,
    pub mapped_size: usize,
    pub raw_file_offset: usize,
    pub characteristics: u32,
}


/// Identifies the evidence supporting one process opcode result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessOpcodeEvidence
{
    DecodedStaticInstruction,
    MappedTrapDifference,
}


/// Reports whether a raw-file baseline was safe to compare with the mapped image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessOpcodeBackingStatus
{
    Matched,
    Unavailable,
    Invalid,
    IdentityMismatch,
}


/// Reports whether loader relocation metadata was required and validated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessOpcodeRelocationStatus
{
    NotEvaluated,
    NotRequired,
    Validated,
    Invalid,
}


/// Describes one decoded breakpoint-related instruction or mapped trap difference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessOpcodeHit
{
    pub evidence: ProcessOpcodeEvidence,
    pub name: &'static str,
    pub bytecode: &'static [u8],
    pub requires_modrm: bool,
    pub modrm: Option<u8>,
    pub process_bytes: Box<[u8]>,
    pub backing_instruction_bytes: Box<[u8]>,
    pub backing_instruction_mnemonic: Box<str>,
    pub opcode_offset: usize,
    pub section_index: usize,
    pub address: Option<usize>,
    pub rva: usize,
    pub file_offset: Option<usize>,
    pub instruction_address: Option<usize>,
    pub instruction_rva: usize,
    pub instruction_file_offset: Option<usize>,
}


/// Describes one raw opcode occurrence in a mapped executable section.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessOpcodeRawHit
{
    pub name: &'static str,
    pub bytecode: &'static [u8],
    pub requires_modrm: bool,
    pub modrm: Option<u8>,
    pub section_index: usize,
    pub address: Option<usize>,
    pub rva: usize,
    pub file_offset: Option<usize>,
}


/// Aggregates raw byte-match counts for one configured opcode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessOpcodeRawSummary
{
    pub name: &'static str,
    pub bytecode: &'static [u8],
    pub requires_modrm: bool,
    pub match_count: usize,
    pub decoded_static_instruction_count: usize,
    pub mapped_trap_difference_count: usize,
}


/// Describes one unchanged consecutive `CC` run outside decoded control flow.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessOpcodePaddingSample
{
    pub section_index: usize,
    pub address: Option<usize>,
    pub rva: usize,
    pub file_offset: Option<usize>,
    pub length: usize,
}


/// Owns every classified and raw opcode hit plus scan summaries for the main image.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessOpcodeCollection
{
    pub module_base_address: usize,
    pub module_size: usize,
    pub scan_complete: bool,
    pub backing_status: ProcessOpcodeBackingStatus,
    pub backing_reason: Option<Box<str>>,
    pub relocation_status: ProcessOpcodeRelocationStatus,
    pub relocation_reason: Option<Box<str>>,
    pub mapped_trap_difference_detection_enabled: bool,
    pub runtime_function_seed_metadata_present: bool,
    pub runtime_function_seed_count: usize,
    pub runtime_function_seed_reason: Option<Box<str>>,
    pub decoded_seed_count: usize,
    pub decoded_instruction_count: usize,
    pub current_decoded_instruction_count: usize,
    pub decoded_byte_count: usize,
    pub decode_error_count: usize,
    pub decode_limit_reached: bool,
    pub hit_count: usize,
    pub hits_truncated: bool,
    pub hits: Vec<ProcessOpcodeHit>,
    pub raw_match_count: usize,
    pub raw_matches_truncated: bool,
    pub raw_matches: Vec<ProcessOpcodeRawHit>,
    pub raw_summaries: Vec<ProcessOpcodeRawSummary>,
    pub padding_candidate_run_count: usize,
    pub padding_candidate_byte_count: usize,
    pub padding_samples: Vec<ProcessOpcodePaddingSample>,
    pub unavailable_ranges: Vec<validate_pe::UnavailablePeRange>,
}


/// Holds one control-flow decode start and the trusted interval containing it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessDecodeTask
{
    rva: usize,
    bound_start: usize,
    bound_end: usize,
}


/// Describes one loader-relocated RVA interval excluded from mapped trap-difference claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessRelocationRange
{
    rva: usize,
    size: usize,
}


/// Owns bounded recursive-decoding state needed by later raw-byte classification.
struct ProcessDecodedOpcodeScan
{
    hits: Vec<ProcessOpcodeHit>,
    hit_count: usize,
    hits_truncated: bool,
    decoded_coverage: ProcessDecodeBitmap,
    coverage_available: bool,
    seed_count: usize,
    instruction_count: usize,
    current_instruction_count: usize,
    byte_count: usize,
    error_count: usize,
    limit_reached: bool,
}


/// Owns strict instruction starts decoded independently from current process bytes.
struct ProcessInstructionBoundaryScan
{
    instruction_starts: ProcessDecodeBitmap,
    decoded_coverage: ProcessDecodeBitmap,
    instruction_count: usize,
    error_count: usize,
    limit_reached: bool,
}


/// Stores one bit per mapped-image byte without allocating a byte for every position.
struct ProcessDecodeBitmap
{
    words: Vec<u64>,
    bit_length: usize,
}

impl ProcessDecodeBitmap
{
    /// Allocates a zeroed bitmap for one bounded mapped image.
    /// `bit_length`: number of image-relative byte positions represented.
    ///
    /// Returns the bitmap, or `None` after reporting allocation or size overflow.
    fn new(bit_length: usize) -> Option<Self>
    {
        let word_count = match bit_length.checked_add(u64::BITS as usize - 1)
        {
            Some(value) => value / u64::BITS as usize,
            None =>
            {
                eprintln!("opcode decode bitmap size overflowed");
                return None;
            }
        };
        let mut words = Vec::new();

        if words.try_reserve_exact(word_count).is_err()
        {
            eprintln!("failed to allocate the opcode decode bitmap");
            return None;
        }

        words.resize(word_count, 0);

        Some(Self {
            words,
            bit_length,
        })
    }


    /// Creates an unallocated bitmap that reports every position as unset.
    /// `bit_length`: logical image extent retained for bounds checks.
    ///
    /// Returns an empty fallback bitmap.
    fn empty(bit_length: usize) -> Self
    {
        Self {
            words: Vec::new(),
            bit_length,
        }
    }


    /// Reports whether one image-relative position was marked.
    /// `index`: image-relative byte position.
    ///
    /// Returns `false` for unset, out-of-range, or unallocated positions.
    fn contains(&self, index: usize) -> bool
    {
        if index >= self.bit_length
        {
            return false;
        }

        let word = match self.words.get(index / u64::BITS as usize)
        {
            Some(value) => *value,
            None => return false,
        };
        let mask = 1u64 << (index % u64::BITS as usize);

        word & mask != 0
    }


    /// Marks one in-range image-relative position.
    /// `index`: image-relative byte position to mark.
    ///
    /// Returns unit after ignoring an out-of-range or unallocated position.
    fn insert(&mut self, index: usize)
    {
        if index >= self.bit_length
        {
            return;
        }

        if let Some(word) = self.words.get_mut(index / u64::BITS as usize)
        {
            *word |= 1u64 << (index % u64::BITS as usize);
        }
    }


    /// Marks every byte position in one half-open image-relative interval.
    /// `start`: first byte position to mark.
    /// `end`: exclusive interval end.
    ///
    /// Returns unit after clamping the interval to the bitmap extent.
    fn insert_range(&mut self, start: usize, end: usize)
    {
        for index in start.min(self.bit_length)..end.min(self.bit_length)
        {
            self.insert(index);
        }
    }


    /// Merges every represented bit from another equally bounded bitmap.
    /// `other`: bitmap whose marked positions should become marked in this bitmap.
    ///
    /// Returns unit after merging the common allocated word extent.
    fn union_with(&mut self, other: &Self)
    {
        for (word, other_word) in self.words.iter_mut().zip(&other.words)
        {
            *word |= *other_word;
        }
    }
}


/// Describes one configured x64 pattern match before process-address metadata is attached.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PePatternMatch
{
    pub name: &'static str,
    pub rva: usize,
}


/// Owns every patterns64 match and the first configured CRT entry signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PePatternScan
{
    pub hits: Vec<PePatternMatch>,
    pub entry_signature: Option<PePatternMatch>,
    pub scan_complete: bool,
}


/// Scans executable process-image ranges for every configured x64 analyst signature.
/// `snapshot`: the validated process image, PE sections, and unavailable ranges.
/// `progress`: callback receiving completed and total signature-scan bytes.
///
/// Returns ordered matches, the first CRT entry signature, and scan completeness.
pub(crate) fn collect_pattern_hits_from_snapshot(snapshot: &validate_pe::ValidatedPeSnapshot, progress: &mut impl FnMut(usize, usize)) -> PePatternScan
{
    use crate::core::data::patterns64::patterns64::{X64_ANALYST_SIGNATURES, X64_CRT_STARTUP_SIGNATURES};

    let executable_snapshot_complete = snapshot.pe.sections.iter().filter(|section| section.Characteristics & IMAGE_SCN_MEM_EXECUTE != 0).all(|section| {
        let section_start = section.VirtualAddress as usize;
        let section_size = validate_pe::get_mapped_section_size(section);

        snapshot.unavailable_ranges.iter().all(|range| !ranges_overlap(section_start, section_size, range.rva, range.size))
    });
    let executable_bytes = snapshot.pe.sections.iter().filter(|section| section.Characteristics & IMAGE_SCN_MEM_EXECUTE != 0).fold(0usize, |total, section| {
        let section_start = section.VirtualAddress as usize;
        let section_size = validate_pe::get_mapped_section_size(section);
        let section_end = section_start.saturating_add(section_size).min(snapshot.bytes.len());

        total.saturating_add(section_end.saturating_sub(section_start))
    });
    let total_bytes = executable_bytes.saturating_mul(X64_ANALYST_SIGNATURES.len());
    let mut completed_bytes = 0usize;
    let mut hits = Vec::new();

    progress(0, total_bytes);

    for signature in X64_ANALYST_SIGNATURES
    {
        for section in &snapshot.pe.sections
        {
            if section.Characteristics & IMAGE_SCN_MEM_EXECUTE == 0
            {
                continue;
            }

            let section_start = section.VirtualAddress as usize;
            let section_size = validate_pe::get_mapped_section_size(section);
            let section_end = section_start.saturating_add(section_size).min(snapshot.bytes.len());

            if section_start >= section_end
            {
                continue;
            }

            let offsets = collect_available_pattern_offsets(&snapshot.bytes[section_start..section_end], section_start, signature.pattern, &snapshot.unavailable_ranges, completed_bytes, total_bytes, progress);

            hits.extend(offsets.into_iter().map(|offset| PePatternMatch {
                name: signature.name,
                rva: section_start + offset,
            }));

            completed_bytes = completed_bytes.saturating_add(section_end - section_start);
            progress(completed_bytes, total_bytes);
        }
    }

    hits.sort_unstable_by(|left, right| left.rva.cmp(&right.rva).then_with(|| left.name.cmp(right.name)));

    let entry_signature = hits.iter().find(|hit| X64_CRT_STARTUP_SIGNATURES.iter().any(|signature| signature.name == hit.name)).copied();

    PePatternScan {
        hits,
        entry_signature,
        scan_complete: executable_snapshot_complete,
    }
}


/// Collects complete section metadata from headers that already passed strict validation.
/// `pe`: safely copied and validated PE headers and section table.
///
/// Returns section records in image section-table order without reparsing image bytes.
pub(crate) fn collect_sections_from_pe(pe: &validate_pe::PeImage) -> Vec<PeSectionInfo>
{
    let mut sections = Vec::with_capacity(pe.sections.len());

    for section in &pe.sections
    {
        let name_length = section.Name.iter().position(|byte| *byte == 0).unwrap_or(section.Name.len());
        // SAFETY: `Misc.VirtualSize` is the image-section union member used for mapped images.
        let virtual_size = unsafe { section.Misc.VirtualSize } as usize;

        sections.push(PeSectionInfo {
            name: String::from_utf8_lossy(&section.Name[..name_length]).into_owned().into_boxed_str(),
            rva: section.VirtualAddress as usize,
            virtual_size,
            raw_size: section.SizeOfRawData as usize,
            mapped_size: validate_pe::get_mapped_section_size(section),
            raw_file_offset: section.PointerToRawData as usize,
            characteristics: section.Characteristics,
        });
    }

    sections
}


/// Classifies decoded x64 debug instructions and summarizes raw opcode bytes.
/// `process`: the validated process identity supplying mapped-image address metadata.
/// `snapshot`: the matching mapped-image bytes, PE sections, and unavailable ranges.
/// `backing_file`: the retained raw executable or its typed validation failure.
/// `runtime_functions`: validated x64 function intervals used as trusted decode seeds.
/// `progress`: callback receiving completed and total executable bytes.
///
/// Returns actionable decoded evidence plus bounded raw-match and padding summaries.
pub(crate) fn collect_opcode_hits_from_snapshot(process: &ValidatedProcessPe, snapshot: &validate_pe::ValidatedPeSnapshot, backing_file: Result<&ValidatedPeFile, &FileValidationError>, runtime_functions: &[RuntimeFunctionRange], progress: &mut impl FnMut(usize, usize)) -> ProcessOpcodeCollection
{
    let scan_complete = snapshot.pe.sections.iter().filter(|section| section.Characteristics & IMAGE_SCN_MEM_EXECUTE != 0).all(|section| {
        let section_start = section.VirtualAddress as usize;
        let section_size = validate_pe::get_mapped_section_size(section);

        snapshot.unavailable_ranges.iter().all(|range| !ranges_overlap(section_start, section_size, range.rva, range.size))
    });
    let total_bytes = snapshot.pe.sections.iter().filter(|section| section.Characteristics & IMAGE_SCN_MEM_EXECUTE != 0).fold(0usize, |total, section| {
        let section_start = section.VirtualAddress as usize;
        let section_size = validate_pe::get_mapped_section_size(section);
        let section_end = section_start.saturating_add(section_size).min(snapshot.bytes.len());

        total.saturating_add(section_end.saturating_sub(section_start))
    });
    let (backing_status, backing_reason, relocation_status, relocation_reason, relocation_ranges, matched_backing_file, matched_backing_pe) = match backing_file
    {
        Ok(file) => match validate_pe::validate_backing_file_identity(&process.image, &file.bytes)
        {
            Ok(pe) =>
            {
                if u64::try_from(process.image.base_address).ok() != Some(file.image_base)
                {
                    match collect_base_relocation_ranges(file, &pe)
                    {
                        Ok(ranges) => (ProcessOpcodeBackingStatus::Matched, None, ProcessOpcodeRelocationStatus::Validated, None, ranges, Some(file), Some(pe)),
                        Err(reason) => (ProcessOpcodeBackingStatus::Matched, None, ProcessOpcodeRelocationStatus::Invalid, Some(reason), Vec::new(), Some(file), Some(pe)),
                    }
                }
                else
                {
                    (ProcessOpcodeBackingStatus::Matched, None, ProcessOpcodeRelocationStatus::NotRequired, None, Vec::new(), Some(file), Some(pe))
                }
            }
            Err(validate_pe::PeValidationError::ValidatedImageIdentityMismatch {
                ..
            }) => (ProcessOpcodeBackingStatus::IdentityMismatch, Some(Box::<str>::from("raw executable headers do not match the validated mapped image")), ProcessOpcodeRelocationStatus::NotEvaluated, None, Vec::new(), None, None),
            Err(error) => (ProcessOpcodeBackingStatus::Invalid, Some(format!("raw executable identity validation failed: {error:?}").into_boxed_str()), ProcessOpcodeRelocationStatus::NotEvaluated, None, Vec::new(), None, None),
        },
        Err(error) =>
        {
            let status = match error
            {
                FileValidationError::FileAccess(_) | FileValidationError::NotRegularFile => ProcessOpcodeBackingStatus::Unavailable,
                _ => ProcessOpcodeBackingStatus::Invalid,
            };

            (status, Some(error.to_string().into_boxed_str()), ProcessOpcodeRelocationStatus::NotEvaluated, None, Vec::new(), None, None)
        }
    };

    let (trusted_runtime_functions, runtime_function_seed_metadata_present, runtime_function_seed_reason) = match (matched_backing_file, matched_backing_pe.as_ref())
    {
        (Some(file), Some(pe)) => match validate_runtime_functions_against_backing(file, pe, runtime_functions)
        {
            Ok(metadata_present) => (runtime_functions, metadata_present, None),
            Err(reason) =>
            {
                eprintln!("x64 runtime-function decode seeds were rejected: {reason}");
                (&[][..], false, Some(reason))
            }
        },
        _ => (&[][..], false, None),
    };
    let mapped_trap_difference_detection_enabled = backing_status == ProcessOpcodeBackingStatus::Matched && runtime_function_seed_reason.is_none() && matches!(relocation_status, ProcessOpcodeRelocationStatus::NotRequired | ProcessOpcodeRelocationStatus::Validated);
    let mut raw_summaries = X64_BREAKPOINT_OPCODE_BYTECODES
        .iter()
        .map(|opcode| ProcessOpcodeRawSummary {
            name: opcode.name,
            bytecode: opcode.bytecode,
            requires_modrm: opcode.requires_modrm,
            match_count: 0,
            decoded_static_instruction_count: 0,
            mapped_trap_difference_count: 0,
        })
        .collect::<Vec<ProcessOpcodeRawSummary>>();
    let decoded = match matched_backing_file
    {
        Some(file) => collect_decoded_opcode_hits(process, snapshot, file, trusted_runtime_functions, &relocation_ranges, &mut raw_summaries, mapped_trap_difference_detection_enabled),
        None => empty_decoded_opcode_scan(snapshot.bytes.len(), 0, false),
    };
    let mut raw_match_count = 0usize;
    let mut raw_matches_truncated = false;
    let mut raw_matches = Vec::new();
    let mut padding_candidate_run_count = 0usize;
    let mut padding_candidate_byte_count = 0usize;
    let mut padding_samples = Vec::new();
    let mut completed_bytes = 0usize;

    progress(0, total_bytes);

    for (section_index, section) in snapshot.pe.sections.iter().enumerate()
    {
        if section.Characteristics & IMAGE_SCN_MEM_EXECUTE == 0
        {
            continue;
        }

        let section_start = section.VirtualAddress as usize;
        let section_size = validate_pe::get_mapped_section_size(section);
        let section_end = section_start.saturating_add(section_size).min(snapshot.bytes.len());

        if section_start >= section_end
        {
            continue;
        }

        let section_bytes = &snapshot.bytes[section_start..section_end];
        let mut next_progress_offset = 0usize;
        let mut padding_run_start = None;

        for offset in 0..section_bytes.len()
        {
            if offset >= next_progress_offset
            {
                progress(completed_bytes.saturating_add(offset), total_bytes);
                next_progress_offset = offset.saturating_add(OPCODE_PROGRESS_BYTE_INTERVAL);
            }

            let rva = section_start + offset;
            let byte_available = snapshot.unavailable_ranges.iter().all(|range| !ranges_overlap(rva, 1, range.rva, range.size));

            for (summary, opcode) in raw_summaries.iter_mut().zip(X64_BREAKPOINT_OPCODE_BYTECODES)
            {
                let matched_size = opcode.bytecode.len() + usize::from(opcode.requires_modrm);

                if let Some(modrm) = opcode_modrm_at(section_bytes, offset, opcode).filter(|_| snapshot.unavailable_ranges.iter().all(|range| !ranges_overlap(rva, matched_size, range.rva, range.size)))
                {
                    summary.match_count = summary.match_count.saturating_add(1);
                    raw_match_count = raw_match_count.saturating_add(1);

                    if !raw_matches_truncated
                    {
                        if raw_matches.try_reserve(1).is_err()
                        {
                            eprintln!("failed to grow the raw opcode match buffer");
                            raw_matches_truncated = true;
                        }
                        else
                        {
                            raw_matches.push(ProcessOpcodeRawHit {
                                name: opcode.name,
                                bytecode: opcode.bytecode,
                                requires_modrm: opcode.requires_modrm,
                                modrm,
                                section_index,
                                address: process.image.base_address.checked_add(rva),
                                rva,
                                file_offset: get_file_offset_from_pe(&snapshot.pe, rva),
                            });
                        }
                    }
                }
            }

            let decoded_byte = decoded.decoded_coverage.contains(rva);
            let unchanged_backing_cc = matched_backing_file.and_then(|file| backing_byte_at_rva(file, rva)) == Some(0xCC);
            let likely_padding_byte = decoded.coverage_available && decoded.current_instruction_count != 0 && decoded.error_count == 0 && !decoded.limit_reached && byte_available && section_bytes[offset] == 0xCC && !decoded_byte && unchanged_backing_cc;

            if likely_padding_byte
            {
                if padding_run_start.is_none()
                {
                    padding_run_start = Some(offset);
                }
            }
            else if let Some(run_start) = padding_run_start.take()
            {
                record_padding_run(process, snapshot, section_index, section_start + run_start, offset - run_start, &mut padding_candidate_run_count, &mut padding_candidate_byte_count, &mut padding_samples);
            }
        }

        if let Some(run_start) = padding_run_start
        {
            record_padding_run(process, snapshot, section_index, section_start + run_start, section_bytes.len() - run_start, &mut padding_candidate_run_count, &mut padding_candidate_byte_count, &mut padding_samples);
        }

        completed_bytes = completed_bytes.saturating_add(section_bytes.len());
        progress(completed_bytes, total_bytes);
    }

    let mut hits = decoded.hits;

    hits.sort_unstable_by(|left, right| left.rva.cmp(&right.rva).then_with(|| left.name.cmp(right.name)));
    raw_matches.sort_unstable_by(|left, right| left.rva.cmp(&right.rva).then_with(|| left.name.cmp(right.name)));

    ProcessOpcodeCollection {
        module_base_address: process.image.base_address,
        module_size: process.image.image_size,
        scan_complete,
        backing_status,
        backing_reason,
        relocation_status,
        relocation_reason,
        mapped_trap_difference_detection_enabled,
        runtime_function_seed_metadata_present,
        runtime_function_seed_count: trusted_runtime_functions.len(),
        runtime_function_seed_reason,
        decoded_seed_count: decoded.seed_count,
        decoded_instruction_count: decoded.instruction_count,
        current_decoded_instruction_count: decoded.current_instruction_count,
        decoded_byte_count: decoded.byte_count,
        decode_error_count: decoded.error_count,
        decode_limit_reached: decoded.limit_reached,
        hit_count: decoded.hit_count,
        hits_truncated: decoded.hits_truncated,
        hits,
        raw_match_count,
        raw_matches_truncated,
        raw_matches,
        raw_summaries,
        padding_candidate_run_count,
        padding_candidate_byte_count,
        padding_samples,
        unavailable_ranges: snapshot.unavailable_ranges.clone(),
    }
}


/// Retrieves a raw-file offset from PE headers that were already strictly validated.
/// `pe`: safely copied and validated PE headers and sections.
/// `rva`: relative virtual address to translate.
///
/// Returns the section-aware file offset without reparsing the mapped image.
pub(crate) fn get_file_offset_from_pe(pe: &validate_pe::PeImage, rva: usize) -> Option<usize>
{
    let headers_size = pe.nt_headers.OptionalHeader.SizeOfHeaders as usize;

    if rva < headers_size
    {
        return Some(rva);
    }

    for section in &pe.sections
    {
        let section_start = section.VirtualAddress as usize;
        let raw_size = section.SizeOfRawData as usize;
        let raw_pointer = section.PointerToRawData as usize;
        let section_end = section_start.checked_add(validate_pe::get_mapped_section_size(section))?;

        if rva < section_start || rva >= section_end
        {
            continue;
        }

        let file_delta = rva.checked_sub(section_start)?;

        if raw_size == 0 || file_delta >= raw_size
        {
            return None;
        }

        return raw_pointer.checked_add(file_delta);
    }

    None
}


/// Recursively decodes current mapped bytes to independently establish instruction starts.
/// `process`: validated process identity supplying the loaded image base.
/// `snapshot`: mapped process bytes and availability metadata.
/// `runtime_functions`: raw-file-matched x64 function ranges used as trusted seeds.
///
/// Returns current-process boundaries and conservative traversal diagnostics.
fn collect_process_instruction_boundaries(process: &ValidatedProcessPe, snapshot: &validate_pe::ValidatedPeSnapshot, runtime_functions: &[RuntimeFunctionRange]) -> ProcessInstructionBoundaryScan
{
    let mut instruction_starts = match ProcessDecodeBitmap::new(snapshot.bytes.len())
    {
        Some(value) => value,
        None => return empty_instruction_boundary_scan(snapshot.bytes.len(), 1, false),
    };
    let mut decoded_coverage = match ProcessDecodeBitmap::new(snapshot.bytes.len())
    {
        Some(value) => value,
        None => return empty_instruction_boundary_scan(snapshot.bytes.len(), 1, false),
    };
    let (mut tasks, mut scheduled_starts) = match initialize_decode_tasks(snapshot, runtime_functions, process.image.entry_point_rva)
    {
        Some(value) => value,
        None => return empty_instruction_boundary_scan(snapshot.bytes.len(), 1, true),
    };

    let mut instruction_count = 0usize;
    let mut error_count = 0usize;
    let mut limit_reached = false;

    'decode_tasks: while let Some(task) = tasks.pop_front()
    {
        if task.rva < task.bound_start || task.rva >= task.bound_end || instruction_starts.contains(task.rva)
        {
            continue;
        }

        let mut current_rva = task.rva;

        while current_rva < task.bound_end
        {
            if instruction_count == MAXIMUM_DECODED_INSTRUCTION_COUNT
            {
                limit_reached = true;
                break 'decode_tasks;
            }

            if instruction_starts.contains(current_rva)
            {
                break;
            }

            let bytes_available = task.bound_end.saturating_sub(current_rva).min(snapshot.bytes.len().saturating_sub(current_rva));

            if bytes_available == 0
            {
                error_count = error_count.saturating_add(1);
                break;
            }

            let instruction_address = match process.image.base_address.checked_add(current_rva).and_then(|value| u64::try_from(value).ok())
            {
                Some(value) => value,
                None =>
                {
                    error_count = error_count.saturating_add(1);
                    break;
                }
            };
            let decoder_bytes = &snapshot.bytes[current_rva..current_rva + bytes_available];
            let mut decoder = Decoder::with_ip(64, decoder_bytes, instruction_address, DecoderOptions::NONE);
            let instruction = decoder.decode();
            let instruction_length = instruction.len();
            let instruction_end = match current_rva.checked_add(instruction_length)
            {
                Some(value) if instruction_length != 0 && value <= task.bound_end && value <= snapshot.bytes.len() => value,
                _ =>
                {
                    error_count = error_count.saturating_add(1);
                    break;
                }
            };

            if instruction.is_invalid() || !validate_pe::is_snapshot_range_available(snapshot, current_rva, instruction_length)
            {
                error_count = error_count.saturating_add(1);
                break;
            }

            let instruction_bytes = &snapshot.bytes[current_rva..instruction_end];
            let supported_interrupt = matches!(instruction.flow_control(), FlowControl::Interrupt | FlowControl::Exception) && decoded_catalog_opcode(&instruction, instruction_bytes).is_some();

            instruction_starts.insert(current_rva);
            decoded_coverage.insert_range(current_rva, instruction_end);
            instruction_count = instruction_count.saturating_add(1);

            let next_rva = instruction_end;
            let target_rva = near_branch_target_rva(&instruction, process.image.base_address, snapshot.bytes.len());

            match instruction.flow_control()
            {
                FlowControl::Next | FlowControl::IndirectCall =>
                {
                    current_rva = next_rva;
                }
                FlowControl::ConditionalBranch | FlowControl::Call | FlowControl::XbeginXabortXend =>
                {
                    if let Some(target) = target_rva
                    {
                        if enqueue_decode_task(&mut tasks, &mut scheduled_starts, snapshot, runtime_functions, target).is_none()
                        {
                            error_count = error_count.saturating_add(1);
                            limit_reached = true;
                            break 'decode_tasks;
                        }
                    }

                    current_rva = next_rva;
                }
                FlowControl::UnconditionalBranch =>
                {
                    if let Some(target) = target_rva
                    {
                        if enqueue_decode_task(&mut tasks, &mut scheduled_starts, snapshot, runtime_functions, target).is_none()
                        {
                            error_count = error_count.saturating_add(1);
                            limit_reached = true;
                            break 'decode_tasks;
                        }
                    }

                    break;
                }
                FlowControl::Interrupt | FlowControl::Exception if supported_interrupt =>
                {
                    current_rva = next_rva;
                }
                FlowControl::IndirectBranch | FlowControl::Return | FlowControl::Interrupt | FlowControl::Exception => break,
            }
        }
    }

    ProcessInstructionBoundaryScan {
        instruction_starts,
        decoded_coverage,
        instruction_count,
        error_count,
        limit_reached,
    }
}


/// Creates an unavailable current-process boundary result after a decode setup failure.
/// `image_size`: mapped image size retained for bounded empty bitmap behavior.
/// `error_count`: setup failure count reported to the combined decoder diagnostics.
/// `limit_reached`: whether a configured traversal or allocation limit stopped setup.
///
/// Returns a boundary result containing no trusted instruction starts.
fn empty_instruction_boundary_scan(image_size: usize, error_count: usize, limit_reached: bool) -> ProcessInstructionBoundaryScan
{
    ProcessInstructionBoundaryScan {
        instruction_starts: ProcessDecodeBitmap::empty(image_size),
        decoded_coverage: ProcessDecodeBitmap::empty(image_size),
        instruction_count: 0,
        error_count,
        limit_reached,
    }
}


/// Recursively decodes trusted raw-file control flow and compares matching process bytes.
/// `process`: validated process identity supplying the loaded image base.
/// `snapshot`: mapped process image used for runtime byte comparisons.
/// `backing_file`: identity-matched raw executable supplying original instructions.
/// `runtime_functions`: validated x64 function ranges used as decode seeds and bounds.
/// `relocation_ranges`: loader-modified fields excluded from mapped trap-difference evidence.
/// `raw_summaries`: aggregate raw counts updated with semantic classifications.
/// `mapped_trap_difference_detection_enabled`: whether identity and relocation checks passed.
///
/// Returns classified hits, decode coverage, and bounded traversal diagnostics.
fn collect_decoded_opcode_hits(process: &ValidatedProcessPe, snapshot: &validate_pe::ValidatedPeSnapshot, backing_file: &ValidatedPeFile, runtime_functions: &[RuntimeFunctionRange], relocation_ranges: &[ProcessRelocationRange], raw_summaries: &mut [ProcessOpcodeRawSummary], mapped_trap_difference_detection_enabled: bool) -> ProcessDecodedOpcodeScan
{
    let current_boundaries = collect_process_instruction_boundaries(process, snapshot, runtime_functions);
    let mut decoded_starts = match ProcessDecodeBitmap::new(snapshot.bytes.len())
    {
        Some(value) => value,
        None => return empty_decoded_opcode_scan(snapshot.bytes.len(), 1, false),
    };
    let mut decoded_coverage = match ProcessDecodeBitmap::new(snapshot.bytes.len())
    {
        Some(value) => value,
        None => return empty_decoded_opcode_scan(snapshot.bytes.len(), 1, false),
    };
    let (mut tasks, mut scheduled_starts) = match initialize_decode_tasks(snapshot, runtime_functions, process.image.entry_point_rva)
    {
        Some(value) => value,
        None => return empty_decoded_opcode_scan(snapshot.bytes.len(), 1, true),
    };

    let seed_count = scheduled_starts.len();
    let mut hits = Vec::new();
    let mut hit_count = 0usize;
    let mut hits_truncated = false;
    let mut instruction_count = 0usize;
    let mut byte_count = 0usize;
    let mut error_count = 0usize;
    let mut limit_reached = false;

    'decode_tasks: while let Some(task) = tasks.pop_front()
    {
        if task.rva < task.bound_start || task.rva >= task.bound_end
        {
            error_count = error_count.saturating_add(1);
            continue;
        }

        let mut current_rva = task.rva;

        while current_rva < task.bound_end
        {
            if instruction_count == MAXIMUM_DECODED_INSTRUCTION_COUNT
            {
                limit_reached = true;
                break 'decode_tasks;
            }

            if decoded_starts.contains(current_rva)
            {
                break;
            }

            let (file_offset, raw_end) = match rva_to_file_range(backing_file, current_rva)
            {
                Some(value) => value,
                None =>
                {
                    error_count = error_count.saturating_add(1);
                    break;
                }
            };
            let bytes_available = raw_end.saturating_sub(file_offset).min(task.bound_end - current_rva);

            if bytes_available == 0
            {
                error_count = error_count.saturating_add(1);
                break;
            }

            let decoder_bytes = &backing_file.bytes[file_offset..file_offset + bytes_available];
            let instruction_address = match process.image.base_address.checked_add(current_rva).and_then(|value| u64::try_from(value).ok())
            {
                Some(value) => value,
                None =>
                {
                    error_count = error_count.saturating_add(1);
                    break;
                }
            };
            let mut decoder = Decoder::with_ip(64, decoder_bytes, instruction_address, DecoderOptions::NONE);
            let instruction = decoder.decode();
            let instruction_length = instruction.len();
            let instruction_end = match current_rva.checked_add(instruction_length)
            {
                Some(value) if instruction_length != 0 && value <= task.bound_end && value <= snapshot.bytes.len() => value,
                _ =>
                {
                    error_count = error_count.saturating_add(1);
                    break;
                }
            };

            if instruction.is_invalid()
            {
                error_count = error_count.saturating_add(1);
                break;
            }

            decoded_starts.insert(current_rva);
            decoded_coverage.insert_range(current_rva, instruction_end);
            instruction_count = instruction_count.saturating_add(1);
            byte_count = byte_count.saturating_add(instruction_length);
            let backing_instruction_bytes = &decoder_bytes[..instruction_length];
            let backing_opcode = decoded_catalog_opcode(&instruction, backing_instruction_bytes);

            if is_dual_decode_hit_boundary(&current_boundaries.instruction_starts, current_rva) && validate_pe::is_snapshot_range_available(snapshot, current_rva, instruction_length)
            {
                let process_instruction_bytes = &snapshot.bytes[current_rva..instruction_end];
                let mapped_trap_opcode = if mapped_trap_difference_detection_enabled { mapped_trap_opcode_at(process_instruction_bytes) } else { None };
                let mapped_trap_difference = mapped_trap_opcode.filter(|opcode| opcode.bytecode.len() <= instruction_length && backing_instruction_bytes.get(..opcode.bytecode.len()) != Some(opcode.bytecode) && relocation_ranges.iter().all(|range| !ranges_overlap(current_rva, opcode.bytecode.len(), range.rva, range.size)));

                if let Some(opcode) = mapped_trap_difference
                {
                    record_decoded_opcode_hit(&mut hits, &mut hit_count, &mut hits_truncated, raw_summaries, opcode.name, ProcessOpcodeEvidence::MappedTrapDifference, || build_decoded_opcode_hit(process, snapshot, &instruction, current_rva, opcode, ProcessOpcodeEvidence::MappedTrapDifference, process_instruction_bytes, backing_instruction_bytes));
                }
                else if let Some(opcode) = backing_opcode.filter(|_| process_instruction_bytes == backing_instruction_bytes)
                {
                    record_decoded_opcode_hit(&mut hits, &mut hit_count, &mut hits_truncated, raw_summaries, opcode.name, ProcessOpcodeEvidence::DecodedStaticInstruction, || build_decoded_opcode_hit(process, snapshot, &instruction, current_rva, opcode, ProcessOpcodeEvidence::DecodedStaticInstruction, process_instruction_bytes, backing_instruction_bytes));
                }
            }

            let next_rva = instruction_end;
            let target_rva = near_branch_target_rva(&instruction, process.image.base_address, snapshot.bytes.len());

            match instruction.flow_control()
            {
                FlowControl::Next | FlowControl::IndirectCall =>
                {
                    current_rva = next_rva;
                }
                FlowControl::ConditionalBranch | FlowControl::Call | FlowControl::XbeginXabortXend =>
                {
                    if let Some(target) = target_rva
                    {
                        if enqueue_decode_task(&mut tasks, &mut scheduled_starts, snapshot, runtime_functions, target).is_none()
                        {
                            error_count = error_count.saturating_add(1);
                            limit_reached = true;
                            break 'decode_tasks;
                        }
                    }

                    current_rva = next_rva;
                }
                FlowControl::UnconditionalBranch =>
                {
                    if let Some(target) = target_rva
                    {
                        if enqueue_decode_task(&mut tasks, &mut scheduled_starts, snapshot, runtime_functions, target).is_none()
                        {
                            error_count = error_count.saturating_add(1);
                            limit_reached = true;
                            break 'decode_tasks;
                        }
                    }

                    break;
                }
                FlowControl::Interrupt | FlowControl::Exception if backing_opcode.is_some() =>
                {
                    current_rva = next_rva;
                }
                FlowControl::IndirectBranch | FlowControl::Return | FlowControl::Interrupt | FlowControl::Exception => break,
            }
        }
    }

    decoded_coverage.union_with(&current_boundaries.decoded_coverage);

    ProcessDecodedOpcodeScan {
        hits,
        hit_count,
        hits_truncated,
        decoded_coverage,
        coverage_available: seed_count != 0 && instruction_count != 0,
        seed_count,
        instruction_count,
        current_instruction_count: current_boundaries.instruction_count,
        byte_count,
        error_count: error_count.saturating_add(current_boundaries.error_count),
        limit_reached: limit_reached || current_boundaries.limit_reached,
    }
}


/// Confirms that a backing-file instruction start is also a current-process boundary.
/// `current_instruction_starts`: strict boundaries decoded independently from mapped bytes.
/// `rva`: backing-file instruction start under consideration.
///
/// Returns `true` only for the intersection of backing and current decoding.
fn is_dual_decode_hit_boundary(current_instruction_starts: &ProcessDecodeBitmap, rva: usize) -> bool
{
    current_instruction_starts.contains(rva)
}


/// Creates an empty decoded result when a trusted raw baseline cannot be used.
/// `image_size`: mapped image size used for optional padding coverage allocation.
/// `error_count`: failure count retained when decoding was expected but could not start.
/// `limit_reached`: whether a configured traversal or allocation limit stopped setup.
///
/// Returns a decode result containing no semantic hits or usable coverage evidence.
fn empty_decoded_opcode_scan(image_size: usize, error_count: usize, limit_reached: bool) -> ProcessDecodedOpcodeScan
{
    ProcessDecodedOpcodeScan {
        hits: Vec::new(),
        hit_count: 0,
        hits_truncated: false,
        decoded_coverage: ProcessDecodeBitmap::empty(image_size),
        coverage_available: false,
        seed_count: 0,
        instruction_count: 0,
        current_instruction_count: 0,
        byte_count: 0,
        error_count,
        limit_reached,
    }
}


/// Creates bounded, fallibly allocated decode queues from trusted metadata seeds.
/// `snapshot`: mapped image supplying executable section bounds.
/// `runtime_functions`: validated and raw-file-matched x64 function intervals.
/// `entry_point_rva`: validated image entry point added as an independent seed.
///
/// Returns initialized queues, or `None` after reporting a safe capacity failure.
fn initialize_decode_tasks(snapshot: &validate_pe::ValidatedPeSnapshot, runtime_functions: &[RuntimeFunctionRange], entry_point_rva: usize) -> Option<(VecDeque<ProcessDecodeTask>, HashSet<usize>)>
{
    let initial_capacity = runtime_functions.len().checked_add(1)?;

    if initial_capacity > MAXIMUM_DECODE_TASK_COUNT
    {
        eprintln!("initial opcode decode seeds exceed the safe task limit");
        return None;
    }

    let mut tasks = VecDeque::new();
    let mut scheduled_starts = HashSet::new();

    if tasks.try_reserve(initial_capacity).is_err() || scheduled_starts.try_reserve(initial_capacity).is_err()
    {
        eprintln!("failed to allocate initial opcode decode queues");
        return None;
    }

    for range in runtime_functions
    {
        enqueue_decode_task(&mut tasks, &mut scheduled_starts, snapshot, runtime_functions, range.begin_rva)?;
    }

    enqueue_decode_task(&mut tasks, &mut scheduled_starts, snapshot, runtime_functions, entry_point_rva)?;

    Some((tasks, scheduled_starts))
}


/// Queues one unique decode target with its narrowest trusted code bounds.
/// `tasks`: pending recursive control-flow work.
/// `scheduled_starts`: RVAs already queued during this traversal.
/// `snapshot`: mapped image supplying executable section bounds.
/// `runtime_functions`: validated function ranges preferred over whole sections.
/// `rva`: candidate instruction start to enqueue.
///
/// Returns `Some(true)` when queued, `Some(false)` when skipped, or `None` on a safe limit.
fn enqueue_decode_task(tasks: &mut VecDeque<ProcessDecodeTask>, scheduled_starts: &mut HashSet<usize>, snapshot: &validate_pe::ValidatedPeSnapshot, runtime_functions: &[RuntimeFunctionRange], rva: usize) -> Option<bool>
{
    if scheduled_starts.contains(&rva)
    {
        return Some(false);
    }

    let (bound_start, bound_end) = match decode_bounds_at_rva(snapshot, runtime_functions, rva)
    {
        Some(value) => value,
        None => return Some(false),
    };

    if scheduled_starts.len() == MAXIMUM_DECODE_TASK_COUNT
    {
        eprintln!("opcode decode task limit was reached");
        return None;
    }

    if tasks.try_reserve(1).is_err() || scheduled_starts.try_reserve(1).is_err()
    {
        eprintln!("failed to grow opcode decode queues");
        return None;
    }

    scheduled_starts.insert(rva);
    tasks.push_back(ProcessDecodeTask {
        rva,
        bound_start,
        bound_end,
    });

    Some(true)
}


/// Finds the validated runtime-function or executable-section interval containing an RVA.
/// `snapshot`: mapped image supplying executable section bounds.
/// `runtime_functions`: sorted validated function ranges preferred as narrow bounds.
/// `rva`: candidate instruction start whose bounds are required.
///
/// Returns the narrowest trusted half-open interval containing the RVA.
fn decode_bounds_at_rva(snapshot: &validate_pe::ValidatedPeSnapshot, runtime_functions: &[RuntimeFunctionRange], rva: usize) -> Option<(usize, usize)>
{
    let executable_section = snapshot.pe.sections.iter().find_map(|section| {
        if section.Characteristics & IMAGE_SCN_MEM_EXECUTE == 0
        {
            return None;
        }

        let section_start = section.VirtualAddress as usize;
        let section_end = section_start.checked_add(validate_pe::get_mapped_section_size(section))?.min(snapshot.bytes.len());

        (rva >= section_start && rva < section_end).then_some((section_start, section_end))
    })?;
    let insertion_index = runtime_functions.partition_point(|range| range.begin_rva <= rva);

    if let Some(range) = insertion_index.checked_sub(1).and_then(|index| runtime_functions.get(index))
    {
        if rva < range.end_rva && range.begin_rva >= executable_section.0 && range.end_rva <= executable_section.1
        {
            return Some((range.begin_rva, range.end_rva));
        }
    }

    Some(executable_section)
}


/// Converts one direct near branch target to a bounded main-image RVA.
/// `instruction`: decoded instruction whose first operand may be a near target.
/// `module_base_address`: loaded image base used to convert the virtual target.
/// `image_size`: complete mapped image extent.
///
/// Returns the target RVA only when it remains inside the main image.
fn near_branch_target_rva(instruction: &Instruction, module_base_address: usize, image_size: usize) -> Option<usize>
{
    if !matches!(instruction.op0_kind(), OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64)
    {
        return None;
    }

    let target = usize::try_from(instruction.near_branch_target()).ok()?;
    let rva = target.checked_sub(module_base_address)?;

    (rva < image_size).then_some(rva)
}


/// Maps one strictly decoded instruction to the configured analyst opcode catalog.
/// `instruction`: valid iced-x86 instruction decoded from the identity-matched file.
/// `instruction_bytes`: exact raw bytes consumed by the decoder.
///
/// Returns the matching catalog record only for exact supported instruction semantics.
fn decoded_catalog_opcode(instruction: &Instruction, instruction_bytes: &[u8]) -> Option<OpcodeBytecode>
{
    match instruction.code()
    {
        Code::Int3 => Some(INT3_BREAKPOINT),
        Code::Int1 => Some(INT1_ICEBP_DEBUG_TRAP),
        Code::Int_imm8 if instruction.immediate8() == 3 => Some(INT_VECTOR_3_BREAKPOINT),
        Code::Int_imm8 if instruction.immediate8() == 1 => Some(INT_VECTOR_1_DEBUG_INTERRUPT),
        Code::Mov_r64_dr if is_supported_debug_register(instruction.op1_register()) && catalog_opcode_offset(instruction_bytes, &MOV_FROM_DEBUG_REGISTER).is_some() => Some(MOV_FROM_DEBUG_REGISTER),
        Code::Mov_dr_r64 if is_supported_debug_register(instruction.op0_register()) && catalog_opcode_offset(instruction_bytes, &MOV_TO_DEBUG_REGISTER).is_some() => Some(MOV_TO_DEBUG_REGISTER),
        _ => None,
    }
}


/// Finds a catalog encoding within one complete decoded instruction.
/// `instruction_bytes`: exact bytes consumed by the x64 decoder.
/// `opcode`: semantic catalog entry whose prefix and ModR/M form must match.
///
/// Returns the catalog prefix offset relative to the instruction start.
fn catalog_opcode_offset(instruction_bytes: &[u8], opcode: &OpcodeBytecode) -> Option<usize>
{
    (0..instruction_bytes.len()).find(|offset| opcode_modrm_at(instruction_bytes, *offset, opcode).is_some())
}


/// Reports whether a decoded operand names one architecturally supported debug register.
/// `register`: decoded iced-x86 register operand.
///
/// Returns `true` for DR0 through DR7 only.
fn is_supported_debug_register(register: Register) -> bool
{
    matches!(register, Register::DR0 | Register::DR1 | Register::DR2 | Register::DR3 | Register::DR4 | Register::DR5 | Register::DR6 | Register::DR7)
}


/// Detects a complete trap encoding at a trusted original instruction start.
/// `data`: current process bytes beginning at a baseline-decoded boundary.
///
/// Returns the matching software-trap catalog record, preferring two-byte forms.
fn mapped_trap_opcode_at(data: &[u8]) -> Option<OpcodeBytecode>
{
    [INT_VECTOR_3_BREAKPOINT, INT_VECTOR_1_DEBUG_INTERRUPT, INT3_BREAKPOINT, INT1_ICEBP_DEBUG_TRAP].into_iter().find(|opcode| data.starts_with(opcode.bytecode))
}


/// Builds one owned opcode result from an original decoded instruction and process bytes.
/// `process`: validated process identity supplying the mapped address.
/// `snapshot`: mapped image supplying section and raw-file coordinates.
/// `instruction`: original instruction decoded from the identity-matched backing file.
/// `instruction_rva`: trusted original instruction start.
/// `opcode`: supported catalog classification.
/// `evidence`: static decoded instruction or mapped trap difference.
/// `process_bytes`: current mapped bytes spanning the original instruction length.
/// `backing_bytes`: exact original instruction bytes from the raw file.
///
/// Returns an owned hit when the RVA belongs to an executable section.
fn build_decoded_opcode_hit(process: &ValidatedProcessPe, snapshot: &validate_pe::ValidatedPeSnapshot, instruction: &Instruction, instruction_rva: usize, opcode: OpcodeBytecode, evidence: ProcessOpcodeEvidence, process_bytes: &[u8], backing_bytes: &[u8]) -> Option<ProcessOpcodeHit>
{
    let section_index = snapshot.pe.sections.iter().position(|section| {
        let section_start = section.VirtualAddress as usize;
        let section_end = section_start.saturating_add(validate_pe::get_mapped_section_size(section));

        section.Characteristics & IMAGE_SCN_MEM_EXECUTE != 0 && instruction_rva >= section_start && instruction_rva < section_end
    })?;
    let opcode_offset = match evidence
    {
        ProcessOpcodeEvidence::MappedTrapDifference => 0,
        ProcessOpcodeEvidence::DecodedStaticInstruction => catalog_opcode_offset(backing_bytes, &opcode)?,
    };
    let rva = instruction_rva.checked_add(opcode_offset)?;
    let modrm = if opcode.requires_modrm { opcode_modrm_at(backing_bytes, opcode_offset, &opcode)? } else { None };
    let process_instruction_bytes = match evidence
    {
        ProcessOpcodeEvidence::MappedTrapDifference => process_bytes.get(..opcode.bytecode.len())?,
        ProcessOpcodeEvidence::DecodedStaticInstruction => process_bytes,
    };

    Some(ProcessOpcodeHit {
        evidence,
        name: opcode.name,
        bytecode: opcode.bytecode,
        requires_modrm: opcode.requires_modrm,
        modrm,
        process_bytes: process_instruction_bytes.to_vec().into_boxed_slice(),
        backing_instruction_bytes: backing_bytes.to_vec().into_boxed_slice(),
        backing_instruction_mnemonic: format!("{:?}", instruction.mnemonic()).to_ascii_lowercase().into_boxed_str(),
        opcode_offset,
        section_index,
        address: process.image.base_address.checked_add(rva),
        rva,
        file_offset: get_file_offset_from_pe(&snapshot.pe, rva),
        instruction_address: process.image.base_address.checked_add(instruction_rva),
        instruction_rva,
        instruction_file_offset: get_file_offset_from_pe(&snapshot.pe, instruction_rva),
    })
}


/// Counts and retains one semantic hit without imposing a fixed result limit.
/// `hits`: analyst-facing semantic hit records.
/// `hit_count`: total semantic hits observed.
/// `hits_truncated`: whether any hit could not be retained.
/// `raw_summaries`: per-catalog aggregate classification counters.
/// `name`: catalog name used for aggregate classification counts.
/// `evidence`: semantic evidence class used for aggregate classification counts.
/// `build_hit`: lazy owned-record construction for the detected opcode.
///
/// Returns unit after recording the count even if allocation or metadata prevents retention.
fn record_decoded_opcode_hit(hits: &mut Vec<ProcessOpcodeHit>, hit_count: &mut usize, hits_truncated: &mut bool, raw_summaries: &mut [ProcessOpcodeRawSummary], name: &str, evidence: ProcessOpcodeEvidence, build_hit: impl FnOnce() -> Option<ProcessOpcodeHit>)
{
    *hit_count = (*hit_count).saturating_add(1);

    if let Some(summary) = raw_summaries.iter_mut().find(|summary| summary.name == name)
    {
        match evidence
        {
            ProcessOpcodeEvidence::DecodedStaticInstruction => summary.decoded_static_instruction_count = summary.decoded_static_instruction_count.saturating_add(1),
            ProcessOpcodeEvidence::MappedTrapDifference => summary.mapped_trap_difference_count = summary.mapped_trap_difference_count.saturating_add(1),
        }
    }

    let hit = match build_hit()
    {
        Some(value) => value,
        None =>
        {
            eprintln!("failed to build a detected semantic opcode hit");
            *hits_truncated = true;
            return;
        }
    };

    if hits.try_reserve(1).is_err()
    {
        eprintln!("failed to grow the semantic opcode hit buffer");
        *hits_truncated = true;
        return;
    }

    hits.push(hit);
}


/// Reads one raw-file byte at an image RVA.
/// `file`: validated raw executable supplying the byte.
/// `rva`: image-relative location to map into raw data.
///
/// Returns the byte only when the RVA is backed by file data.
fn backing_byte_at_rva(file: &ValidatedPeFile, rva: usize) -> Option<u8>
{
    let (file_offset, _) = rva_to_file_range(file, rva)?;

    file.bytes.get(file_offset).copied()
}


/// Retains one bounded sample and aggregates an unchanged out-of-flow `CC` run.
/// `process`: validated process identity supplying mapped addresses.
/// `snapshot`: mapped image supplying raw-file coordinate translation.
/// `section_index`: containing executable section index.
/// `rva`: first byte of the run.
/// `length`: consecutive unchanged run length.
/// `run_count`: aggregate qualifying run count.
/// `byte_count`: aggregate qualifying byte count.
/// `samples`: bounded analyst-facing run samples.
///
/// Returns unit after ignoring single bytes or recording one likely-padding run.
fn record_padding_run(process: &ValidatedProcessPe, snapshot: &validate_pe::ValidatedPeSnapshot, section_index: usize, rva: usize, length: usize, run_count: &mut usize, byte_count: &mut usize, samples: &mut Vec<ProcessOpcodePaddingSample>)
{
    if length < 2
    {
        return;
    }

    *run_count = run_count.saturating_add(1);
    *byte_count = byte_count.saturating_add(length);

    if samples.len() < MAXIMUM_PADDING_RUN_SAMPLES
    {
        if samples.try_reserve(1).is_err()
        {
            eprintln!("failed to grow the retained opcode padding sample buffer");
            return;
        }

        samples.push(ProcessOpcodePaddingSample {
            section_index,
            address: process.image.base_address.checked_add(rva),
            rva,
            file_offset: get_file_offset_from_pe(&snapshot.pe, rva),
            length,
        });
    }
}


/// Parses and validates every x64 DIR64 base-relocation target in a raw PE file.
/// `file`: validated raw executable supplying relocation directory bytes.
/// `pe`: identity-matched raw PE headers supplying the directory location.
///
/// Returns sorted relocation intervals, or a fail-closed diagnostic reason.
fn collect_base_relocation_ranges(file: &ValidatedPeFile, pe: &validate_pe::PeImage) -> Result<Vec<ProcessRelocationRange>, Box<str>>
{
    let directory = validate_pe::get_data_directory(pe, IMAGE_DIRECTORY_ENTRY_BASERELOC as usize).ok_or_else(|| Box::<str>::from("base-relocation directory is not declared"))?;
    let directory_rva = directory.VirtualAddress as usize;
    let directory_size = directory.Size as usize;

    if directory_rva == 0 || directory_size == 0
    {
        return Err("base-relocation directory is absent for a rebased image".into());
    }

    if !directory_rva.is_multiple_of(4)
    {
        return Err("base-relocation directory is not DWORD aligned".into());
    }

    let (file_offset, raw_end) = rva_to_file_range(file, directory_rva).ok_or_else(|| Box::<str>::from("base-relocation directory is not raw-file backed"))?;
    let directory_end = file_offset.checked_add(directory_size).ok_or_else(|| Box::<str>::from("base-relocation directory range overflowed"))?;

    if directory_end > raw_end || directory_end > file.bytes.len()
    {
        return Err("base-relocation directory exceeds its raw-file range".into());
    }

    let data = &file.bytes[file_offset..directory_end];

    parse_base_relocation_ranges(data, file.size_of_image)
}


/// Confirms that mapped runtime-function bounds exactly match the retained raw file.
/// `file`: identity-matched raw executable supplying exception-directory bytes.
/// `pe`: parsed raw headers declaring the exception directory.
/// `runtime_functions`: strictly validated bounds collected from mapped memory.
///
/// Returns unit only when every mapped Begin/End pair has an identical raw entry.
fn validate_runtime_functions_against_backing(file: &ValidatedPeFile, pe: &validate_pe::PeImage, runtime_functions: &[RuntimeFunctionRange]) -> Result<bool, Box<str>>
{
    let directory = match validate_pe::get_data_directory(pe, IMAGE_DIRECTORY_ENTRY_EXCEPTION as usize)
    {
        Some(value) => value,
        None if runtime_functions.is_empty() => return Ok(false),
        None => return Err("raw executable has no exception directory for mapped runtime-function seeds".into()),
    };
    let directory_rva = directory.VirtualAddress as usize;
    let directory_size = directory.Size as usize;

    if directory_rva == 0 && directory_size == 0 && runtime_functions.is_empty()
    {
        return Ok(false);
    }

    if directory_rva == 0 || directory_size == 0 || !directory_rva.is_multiple_of(4) || !directory_size.is_multiple_of(RUNTIME_FUNCTION_ENTRY_SIZE)
    {
        return Err("raw executable exception-directory layout is invalid".into());
    }

    if directory_size / RUNTIME_FUNCTION_ENTRY_SIZE != runtime_functions.len()
    {
        return Err("raw and mapped runtime-function entry counts differ".into());
    }

    let (file_offset, raw_end) = rva_to_file_range(file, directory_rva).ok_or_else(|| Box::<str>::from("raw exception directory is not file backed"))?;
    let directory_end = file_offset.checked_add(directory_size).ok_or_else(|| Box::<str>::from("raw exception-directory range overflowed"))?;

    if directory_end > raw_end || directory_end > file.bytes.len()
    {
        return Err("raw exception directory exceeds its file-backed range".into());
    }

    for (entry, range) in file.bytes[file_offset..directory_end].chunks_exact(RUNTIME_FUNCTION_ENTRY_SIZE).zip(runtime_functions)
    {
        let begin_rva = read_u32_at(entry, 0).ok_or_else(|| Box::<str>::from("raw runtime-function BeginAddress is truncated"))? as usize;
        let end_rva = read_u32_at(entry, 4).ok_or_else(|| Box::<str>::from("raw runtime-function EndAddress is truncated"))? as usize;

        if begin_rva != range.begin_rva || end_rva != range.end_rva
        {
            return Err("raw and mapped runtime-function bounds differ".into());
        }
    }

    Ok(true)
}


/// Parses one bounded PE base-relocation directory into x64 DIR64 exclusion ranges.
/// `data`: exact raw directory bytes containing complete relocation blocks.
/// `image_size`: validated SizeOfImage used to bound every relocation target.
///
/// Returns sorted unique DIR64 ranges, or a fail-closed structural diagnostic.
fn parse_base_relocation_ranges(data: &[u8], image_size: usize) -> Result<Vec<ProcessRelocationRange>, Box<str>>
{
    let mut ranges = Vec::new();
    let mut offset = 0usize;

    while offset < data.len()
    {
        let remaining = data.len() - offset;

        if remaining < BASE_RELOCATION_BLOCK_HEADER_SIZE
        {
            return Err("base-relocation directory ends with an incomplete block header".into());
        }

        let page_rva = read_u32_at(data, offset).ok_or_else(|| Box::<str>::from("base-relocation page RVA is truncated"))? as usize;
        let block_size = read_u32_at(data, offset + 4).ok_or_else(|| Box::<str>::from("base-relocation block size is truncated"))? as usize;

        if !page_rva.is_multiple_of(0x1000) || block_size < BASE_RELOCATION_BLOCK_HEADER_SIZE || !block_size.is_multiple_of(4) || block_size > remaining
        {
            return Err("base-relocation block layout is invalid".into());
        }

        let entries_end = offset + block_size;
        let mut entry_offset = offset + BASE_RELOCATION_BLOCK_HEADER_SIZE;

        while entry_offset < entries_end
        {
            let entry = read_u16_at(data, entry_offset).ok_or_else(|| Box::<str>::from("base-relocation entry is truncated"))?;
            let relocation_type = entry >> 12;
            let page_offset = (entry & 0x0FFF) as usize;

            match relocation_type
            {
                0 =>
                {}
                IMAGE_REL_BASED_DIR64 =>
                {
                    let rva = page_rva.checked_add(page_offset).ok_or_else(|| Box::<str>::from("base-relocation target overflowed"))?;
                    let end_rva = rva.checked_add(size_of::<u64>()).ok_or_else(|| Box::<str>::from("base-relocation target range overflowed"))?;

                    if end_rva > image_size
                    {
                        return Err("base-relocation target exceeds SizeOfImage".into());
                    }

                    ranges.push(ProcessRelocationRange {
                        rva,
                        size: size_of::<u64>(),
                    });
                }
                _ => return Err(format!("unsupported x64 base-relocation type {relocation_type}").into_boxed_str()),
            }

            entry_offset += size_of::<u16>();
        }

        offset = entries_end;
    }

    ranges.sort_unstable_by_key(|range| range.rva);
    ranges.dedup();

    Ok(ranges)
}


/// Reads one little-endian `u16` from a bounded byte slice.
/// `data`: source bytes.
/// `offset`: exact starting byte offset.
///
/// Returns the decoded value when both bytes are available.
fn read_u16_at(data: &[u8], offset: usize) -> Option<u16>
{
    let bytes = data.get(offset..offset.checked_add(size_of::<u16>())?)?;

    Some(u16::from_le_bytes(bytes.try_into().ok()?))
}


/// Reads one little-endian `u32` from a bounded byte slice.
/// `data`: source bytes.
/// `offset`: exact starting byte offset.
///
/// Returns the decoded value when all four bytes are available.
fn read_u32_at(data: &[u8], offset: usize) -> Option<u32>
{
    let bytes = data.get(offset..offset.checked_add(size_of::<u32>())?)?;

    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}


/// Collects every available byte offset matching one wildcard-aware signature.
/// `haystack`: contiguous mapped-section bytes to search.
/// `base_rva`: image RVA corresponding to `haystack[0]`.
/// `pattern`: exact bytes expressed as `Some` and single-byte wildcards as `None`.
/// `unavailable_ranges`: loader-discarded ranges excluded from candidate matches.
/// `completed_before_range`: signature-scan bytes completed before this range.
/// `total_bytes`: total bytes scheduled across signatures and executable ranges.
/// `progress`: callback receiving completed and total signature-scan bytes.
///
/// Returns every matching section-relative byte offset in ascending order.
fn collect_available_pattern_offsets(haystack: &[u8], base_rva: usize, pattern: &[Option<u8>], unavailable_ranges: &[validate_pe::UnavailablePeRange], completed_before_range: usize, total_bytes: usize, progress: &mut impl FnMut(usize, usize)) -> Vec<usize>
{
    if pattern.is_empty() || haystack.len() < pattern.len()
    {
        progress(completed_before_range.saturating_add(haystack.len()), total_bytes);
        return Vec::new();
    }

    let last_start = haystack.len() - pattern.len();
    let mut offsets = Vec::new();
    let mut next_progress_offset = 0usize;

    for start in 0..=last_start
    {
        if start >= next_progress_offset
        {
            progress(completed_before_range.saturating_add(start), total_bytes);
            next_progress_offset = start.saturating_add(PATTERN_PROGRESS_BYTE_INTERVAL);
        }

        let candidate_rva = match base_rva.checked_add(start)
        {
            Some(value) => value,
            None => continue,
        };

        if unavailable_ranges.iter().any(|range| ranges_overlap(candidate_rva, pattern.len(), range.rva, range.size))
        {
            continue;
        }

        let window = &haystack[start..start + pattern.len()];
        let is_match = pattern.iter().zip(window).all(|(expected, actual)| match expected
        {
            Some(byte) => *byte == *actual,
            None => true,
        });

        if is_match
        {
            offsets.push(start);
        }
    }

    progress(completed_before_range.saturating_add(haystack.len()), total_bytes);

    offsets
}


/// Reports whether two half-open image ranges overlap.
/// `left_rva`: first range start RVA.
/// `left_size`: first range byte length.
/// `right_rva`: second range start RVA.
/// `right_size`: second range byte length.
///
/// Returns `true` when the ranges share at least one byte.
fn ranges_overlap(left_rva: usize, left_size: usize, right_rva: usize, right_size: usize) -> bool
{
    let left_end = left_rva.saturating_add(left_size);
    let right_end = right_rva.saturating_add(right_size);

    left_rva < right_end && right_rva < left_end
}


/// Matches one configured opcode at an exact section-relative byte offset.
/// `data`: executable section bytes containing the candidate.
/// `offset`: exact byte offset where the opcode prefix must begin.
/// `opcode`: configured exact prefix and ModR/M requirement.
///
/// Returns the required ModR/M byte, or an empty option for an exact opcode without one.
fn opcode_modrm_at(data: &[u8], offset: usize, opcode: &OpcodeBytecode) -> Option<Option<u8>>
{
    let opcode_end = offset.checked_add(opcode.bytecode.len())?;

    if opcode.bytecode.is_empty() || data.get(offset..opcode_end)? != opcode.bytecode
    {
        return None;
    }

    if !opcode.requires_modrm
    {
        return Some(None);
    }

    let modrm = *data.get(opcode_end)?;

    if modrm & 0xC0 != 0xC0
    {
        return None;
    }

    Some(Some(modrm))
}

#[cfg(test)]
mod tests
{
    use iced_x86::{Code, Decoder, DecoderOptions, Instruction, Register};

    use super::{catalog_opcode_offset, collect_available_pattern_offsets, decoded_catalog_opcode, is_dual_decode_hit_boundary, mapped_trap_opcode_at, opcode_modrm_at, parse_base_relocation_ranges, ProcessDecodeBitmap, ProcessRelocationRange};
    use crate::core::data::opcode_specific64::opcodes64::{INT1_ICEBP_DEBUG_TRAP, INT3_BREAKPOINT, INT_VECTOR_1_DEBUG_INTERRUPT, INT_VECTOR_3_BREAKPOINT, MOV_FROM_DEBUG_REGISTER, MOV_TO_DEBUG_REGISTER, X64_BREAKPOINT_OPCODE_BYTECODES};

    #[test]
    fn collects_every_overlapping_pattern_offset()
    {
        let haystack = [0xAA, 0xAA, 0xAA, 0x00, 0xAA, 0xAA];
        let pattern = [Some(0xAA), Some(0xAA)];
        let mut progress_updates = Vec::new();
        let offsets = collect_available_pattern_offsets(&haystack, 0x1000, &pattern, &[], 0, haystack.len(), &mut |completed, total| progress_updates.push((completed, total)));

        assert_eq!(offsets, vec![0, 1, 4]);
        assert_eq!(progress_updates.last(), Some(&(haystack.len(), haystack.len())));
    }


    #[test]
    fn finds_every_raw_opcode_occurrence()
    {
        let bytes = [0xCC, 0xCC, 0x90, 0xCD, 0x03, 0xCC, 0x0F, 0x21, 0xC0, 0x0F, 0x21, 0x00];
        let mut matches = Vec::new();

        for offset in 0..bytes.len()
        {
            for opcode in X64_BREAKPOINT_OPCODE_BYTECODES
            {
                if let Some(modrm) = opcode_modrm_at(&bytes, offset, opcode)
                {
                    matches.push((offset, opcode.name, modrm));
                }
            }
        }

        assert_eq!(matches, vec![(0, INT3_BREAKPOINT.name, None), (1, INT3_BREAKPOINT.name, None), (3, INT_VECTOR_3_BREAKPOINT.name, None), (5, INT3_BREAKPOINT.name, None), (6, MOV_FROM_DEBUG_REGISTER.name, Some(0xC0))]);
    }

    #[test]
    fn classifies_exact_software_trap_instructions()
    {
        let cases = [(&[0xCC][..], INT3_BREAKPOINT), (&[0xF1][..], INT1_ICEBP_DEBUG_TRAP), (&[0xCD, 0x01][..], INT_VECTOR_1_DEBUG_INTERRUPT), (&[0xCD, 0x03][..], INT_VECTOR_3_BREAKPOINT)];

        for (bytes, expected) in cases
        {
            let instruction = decode_instruction(bytes);

            assert!(!instruction.is_invalid());
            assert_eq!(decoded_catalog_opcode(&instruction, bytes), Some(expected));
        }
    }

    #[test]
    fn ignores_trap_bytes_embedded_in_other_instructions()
    {
        let register_move = decode_instruction(&[0x48, 0x89, 0xF1]);
        let immediate_move = decode_instruction(&[0xB8, 0xCC, 0xCC, 0xCC, 0xCC]);

        assert_eq!(register_move.code(), Code::Mov_rm64_r64);
        assert_eq!(register_move.len(), 3);
        assert_eq!(decoded_catalog_opcode(&register_move, &[0x48, 0x89, 0xF1]), None);
        assert_eq!(immediate_move.code(), Code::Mov_r32_imm32);
        assert_eq!(immediate_move.len(), 5);
        assert_eq!(decoded_catalog_opcode(&immediate_move, &[0xB8, 0xCC, 0xCC, 0xCC, 0xCC]), None);
    }

    #[test]
    fn classifies_supported_debug_register_moves()
    {
        let read_debug_register = decode_instruction(&[0x0F, 0x21, 0xC0]);
        let write_debug_register = decode_instruction(&[0x0F, 0x23, 0xF8]);
        let rex_prefixed_read = decode_instruction(&[0x41, 0x0F, 0x21, 0xC0]);

        assert_eq!(read_debug_register.code(), Code::Mov_r64_dr);
        assert_eq!(read_debug_register.op1_register(), Register::DR0);
        assert_eq!(decoded_catalog_opcode(&read_debug_register, &[0x0F, 0x21, 0xC0]), Some(MOV_FROM_DEBUG_REGISTER));
        assert_eq!(write_debug_register.code(), Code::Mov_dr_r64);
        assert_eq!(write_debug_register.op0_register(), Register::DR7);
        assert_eq!(decoded_catalog_opcode(&write_debug_register, &[0x0F, 0x23, 0xF8]), Some(MOV_TO_DEBUG_REGISTER));
        assert_eq!(rex_prefixed_read.code(), Code::Mov_r64_dr);
        assert_eq!(rex_prefixed_read.op0_register(), Register::R8);
        assert_eq!(rex_prefixed_read.op1_register(), Register::DR0);
        assert_eq!(decoded_catalog_opcode(&rex_prefixed_read, &[0x41, 0x0F, 0x21, 0xC0]), Some(MOV_FROM_DEBUG_REGISTER));
        assert_eq!(catalog_opcode_offset(&[0x41, 0x0F, 0x21, 0xC0], &MOV_FROM_DEBUG_REGISTER), Some(1));
    }

    #[test]
    fn rejects_invalid_or_reserved_debug_register_moves()
    {
        let memory_read_form = decode_instruction(&[0x0F, 0x21, 0x00]);
        let memory_write_form = decode_instruction(&[0x0F, 0x23, 0x00]);
        let reserved_register = decode_instruction(&[0x44, 0x0F, 0x21, 0xC0]);

        assert_eq!(memory_read_form.code(), Code::Mov_r64_dr);
        assert_eq!(memory_read_form.op1_register(), Register::DR0);
        assert_eq!(decoded_catalog_opcode(&memory_read_form, &[0x0F, 0x21, 0x00]), None);
        assert_eq!(memory_write_form.code(), Code::Mov_dr_r64);
        assert_eq!(memory_write_form.op0_register(), Register::DR0);
        assert_eq!(decoded_catalog_opcode(&memory_write_form, &[0x0F, 0x23, 0x00]), None);
        assert!(reserved_register.is_invalid());
        assert_eq!(decoded_catalog_opcode(&reserved_register, &[0x44, 0x0F, 0x21, 0xC0]), None);
    }

    #[test]
    fn parses_only_valid_x64_base_relocations()
    {
        let directory = [0x00, 0x10, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x34, 0xA2, 0x00, 0x00];

        assert_eq!(
            parse_base_relocation_ranges(&directory, 0x4000),
            Ok(vec![ProcessRelocationRange {
                rva: 0x1234,
                size: 8,
            }])
        );
    }

    #[test]
    fn rejects_unsafe_x64_base_relocation_metadata()
    {
        let misaligned_block_size = [0x00, 0x10, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00];
        let unsupported_type = [0x00, 0x10, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00];
        let target_outside_image = [0x00, 0x30, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0xFC, 0xAF, 0x00, 0x00];

        assert!(parse_base_relocation_ranges(&misaligned_block_size, 0x4000).is_err());
        assert!(parse_base_relocation_ranges(&unsupported_type, 0x4000).is_err());
        assert!(parse_base_relocation_ranges(&target_outside_image, 0x4000).is_err());
        assert!(parse_base_relocation_ranges(&[0; 7], 0x4000).is_err());
    }

    #[test]
    fn requires_current_and_backing_instruction_boundaries_for_hits()
    {
        let shifted_current_starts = decode_test_fallthrough_starts(&[0xB0, 0xCC, 0xC3]);
        let patched_current_starts = decode_test_fallthrough_starts(&[0xCC, 0x90, 0xC3]);

        assert!(!is_dual_decode_hit_boundary(&shifted_current_starts, 1));
        assert!(is_dual_decode_hit_boundary(&patched_current_starts, 0));
        assert_eq!(mapped_trap_opcode_at(&[0xCC, 0x90, 0xC3]), Some(INT3_BREAKPOINT));
    }


    /// Decodes one complete x64 instruction from a bounded test byte slice.
    /// `bytes`: exact instruction bytes to decode from a synthetic address.
    ///
    /// Returns the first strict iced-x86 decode result.
    fn decode_instruction(bytes: &[u8]) -> Instruction
    {
        let mut decoder = Decoder::with_ip(64, bytes, 0x0000_0001_4000_1000, DecoderOptions::NONE);

        decoder.decode()
    }


    /// Decodes one synthetic fallthrough stream into a strict instruction-start bitmap.
    /// `bytes`: current-process bytes beginning at a trusted synthetic function seed.
    ///
    /// Returns every valid sequential start through the first return or invalid decode.
    fn decode_test_fallthrough_starts(bytes: &[u8]) -> ProcessDecodeBitmap
    {
        let mut starts = ProcessDecodeBitmap::new(bytes.len()).expect("test bitmap allocation should succeed");
        let mut offset = 0usize;

        while offset < bytes.len()
        {
            let mut decoder = Decoder::with_ip(64, &bytes[offset..], 0x0000_0001_4000_1000 + offset as u64, DecoderOptions::NONE);
            let instruction = decoder.decode();

            if instruction.is_invalid() || instruction.len() == 0
            {
                break;
            }

            starts.insert(offset);
            offset += instruction.len();

            if instruction.flow_control() == iced_x86::FlowControl::Return
            {
                break;
            }
        }

        starts
    }
}
