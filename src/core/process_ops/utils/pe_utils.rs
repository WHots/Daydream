use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_SCN_MEM_EXECUTE;

use crate::core::data::opcode_specific64::opcodes64::{OpcodeBytecode, X64_BREAKPOINT_OPCODE_BYTECODES};
use crate::core::process_ops::utils::foundation::validate_pe;
use crate::core::process_ops::utils::processutils::ValidatedProcessPe;

/// Executable-byte interval between opcode-scan progress updates.
const OPCODE_PROGRESS_BYTE_INTERVAL: usize = 64 * 1024;

/// Executable-byte interval between x64 pattern-scan progress updates.
const PATTERN_PROGRESS_BYTE_INTERVAL: usize = 64 * 1024;


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


/// Describes one breakpoint-related opcode found in an executable process-image section.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessOpcodeHit
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


/// Owns every breakpoint-related opcode hit found in executable main-image ranges.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessOpcodeCollection
{
    pub module_base_address: usize,
    pub module_size: usize,
    pub scan_complete: bool,
    pub hits: Vec<ProcessOpcodeHit>,
    pub unavailable_ranges: Vec<validate_pe::UnavailablePeRange>,
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

    let executable_snapshot_complete = snapshot.pe.sections.iter().filter(|section| section.Characteristics & IMAGE_SCN_MEM_EXECUTE != 0).all(|section|
    {
        let section_start = section.VirtualAddress as usize;
        let section_size = validate_pe::get_mapped_section_size(section);

        snapshot.unavailable_ranges.iter().all(|range| !ranges_overlap(section_start, section_size, range.rva, range.size))
    });
    let executable_bytes = snapshot.pe.sections.iter().filter(|section| section.Characteristics & IMAGE_SCN_MEM_EXECUTE != 0).fold(0usize, |total, section|
    {
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

            hits.extend(offsets.into_iter().map(|offset| PePatternMatch
            {
                name: signature.name,
                rva: section_start + offset,
            }));

            completed_bytes = completed_bytes.saturating_add(section_end - section_start);
            progress(completed_bytes, total_bytes);
        }
    }

    hits.sort_unstable_by(|left, right| left.rva.cmp(&right.rva).then_with(|| left.name.cmp(right.name)));

    let entry_signature = hits.iter().find(|hit| X64_CRT_STARTUP_SIGNATURES.iter().any(|signature| signature.name == hit.name)).copied();

    PePatternScan
    {
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

        sections.push(PeSectionInfo
        {
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


/// Scans executable ranges in a validated process snapshot for configured x64 opcodes.
/// `process`: the validated process identity supplying mapped-image address metadata.
/// `snapshot`: the matching mapped-image bytes, PE sections, and unavailable ranges.
/// `progress`: callback receiving completed and total executable bytes.
///
/// Returns ordered opcode hits with section, address, RVA, and raw-file locations.
pub(crate) fn collect_opcode_hits_from_snapshot(process: &ValidatedProcessPe, snapshot: &validate_pe::ValidatedPeSnapshot, progress: &mut impl FnMut(usize, usize)) -> ProcessOpcodeCollection
{
    let scan_complete = snapshot.pe.sections.iter().filter(|section| section.Characteristics & IMAGE_SCN_MEM_EXECUTE != 0).all(|section|
    {
        let section_start = section.VirtualAddress as usize;
        let section_size = validate_pe::get_mapped_section_size(section);

        snapshot.unavailable_ranges.iter().all(|range| !ranges_overlap(section_start, section_size, range.rva, range.size))
    });
    let total_bytes = snapshot.pe.sections.iter().filter(|section| section.Characteristics & IMAGE_SCN_MEM_EXECUTE != 0).fold(0usize, |total, section|
    {
        let section_start = section.VirtualAddress as usize;
        let section_size = validate_pe::get_mapped_section_size(section);
        let section_end = section_start.saturating_add(section_size).min(snapshot.bytes.len());

        total.saturating_add(section_end.saturating_sub(section_start))
    });
    let mut hits = Vec::new();
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

        for offset in 0..section_bytes.len()
        {
            if offset >= next_progress_offset
            {
                progress(completed_bytes.saturating_add(offset), total_bytes);
                next_progress_offset = offset.saturating_add(OPCODE_PROGRESS_BYTE_INTERVAL);
            }

            for opcode in X64_BREAKPOINT_OPCODE_BYTECODES
            {
                let modrm = match opcode_modrm_at(section_bytes, offset, opcode)
                {
                    Some(value) => value,
                    None => continue,
                };
                let matched_size = opcode.bytecode.len() + usize::from(opcode.requires_modrm);
                let rva = section_start + offset;

                if snapshot.unavailable_ranges.iter().any(|range| ranges_overlap(rva, matched_size, range.rva, range.size))
                {
                    continue;
                }

                hits.push(ProcessOpcodeHit
                {
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

        completed_bytes = completed_bytes.saturating_add(section_bytes.len());
        progress(completed_bytes, total_bytes);
    }

    hits.sort_unstable_by(|left, right| left.rva.cmp(&right.rva).then_with(|| left.name.cmp(right.name)));

    ProcessOpcodeCollection
    {
        module_base_address: process.image.base_address,
        module_size: process.image.image_size,
        scan_complete,
        hits,
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
    use super::{collect_available_pattern_offsets, opcode_modrm_at, ranges_overlap};
    use crate::core::data::opcode_specific64::opcodes64::{INT3_BREAKPOINT, MOV_FROM_DEBUG_REGISTER};
    use crate::core::data::patterns64::patterns64::MAIN_CRT_STARTUP;
    use crate::core::process_ops::utils::foundation::validate_pe::UnavailablePeRange;


    #[test]
    fn excludes_unavailable_signature_candidates()
    {
        let bytes = [0x48, 0x8B, 0x11, 0x48, 0x8B, 0x22];
        let pattern = [Some(0x48), Some(0x8B), None];
        let first_unavailable = [UnavailablePeRange { rva: 0x1000, size: 3 }];
        let all_unavailable = [UnavailablePeRange { rva: 0x1000, size: bytes.len() }];
        let mut progress = |_, _| {};

        assert_eq!(collect_available_pattern_offsets(&bytes, 0x1000, &pattern, &[], 0, bytes.len(), &mut progress), vec![0, 3]);
        assert_eq!(collect_available_pattern_offsets(&bytes, 0x1000, &pattern, &first_unavailable, 0, bytes.len(), &mut progress), vec![3]);
        assert!(collect_available_pattern_offsets(&bytes, 0x1000, &pattern, &all_unavailable, 0, bytes.len(), &mut progress).is_empty());
    }


    #[test]
    fn finds_catalog_crt_signature_with_wildcard_bytes()
    {
        let bytes = [
            0x90,
            0x48, 0x83, 0xEC, 0x28, 0xE8, 0x11, 0x22, 0x33, 0x44,
            0x48, 0x83, 0xC4, 0x28, 0xE9, 0x55, 0x66, 0x77, 0x88,
        ];
        let mut progress = |_, _| {};

        assert_eq!(collect_available_pattern_offsets(&bytes, 0x1000, MAIN_CRT_STARTUP.pattern, &[], 0, bytes.len(), &mut progress), vec![1]);
    }


    #[test]
    fn treats_touching_half_open_ranges_as_non_overlapping()
    {
        assert!(!ranges_overlap(0x1000, 0x100, 0x1100, 0x80));
        assert!(ranges_overlap(0x1000, 0x101, 0x1100, 0x80));
    }


    #[test]
    fn matches_exact_and_register_modrm_opcodes()
    {
        assert_eq!(opcode_modrm_at(&[0x90, 0xCC], 1, &INT3_BREAKPOINT), Some(None));
        assert_eq!(opcode_modrm_at(&[0x0F, 0x21, 0xC7], 0, &MOV_FROM_DEBUG_REGISTER), Some(Some(0xC7)));
        assert_eq!(opcode_modrm_at(&[0x0F, 0x21], 0, &MOV_FROM_DEBUG_REGISTER), None);
        assert_eq!(opcode_modrm_at(&[0x0F, 0x21, 0x07], 0, &MOV_FROM_DEBUG_REGISTER), None);
    }
}
