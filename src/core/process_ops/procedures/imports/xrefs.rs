use std::collections::HashSet;

use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_SCN_MEM_EXECUTE;

use crate::core::process_ops::procedures::foundation::validate_pe;

use super::{PeIatXref, PeIatXrefKind};

/// Executable-byte interval between IAT scan progress updates.
const IAT_PROGRESS_BYTE_INTERVAL: usize = 64 * 1024;

/// Scans executable sections once for every selected IAT target.
/// `pe_data`: loaded PE image bytes indexed by RVA.
/// `pe`: copied validated headers and sections for `pe_data`.
/// `targets`: unique IAT slot RVAs retained as references.
/// `progress`: callback receiving completed and total executable bytes.
///
/// Returns all matching direct call and jump xrefs ordered by instruction RVA.
pub(super) fn collect_iat_xrefs_for_targets(pe_data: &[u8], pe: &validate_pe::PeImage, targets: &HashSet<usize>, progress: &mut impl FnMut(usize, usize)) -> Vec<PeIatXref>
{
    if targets.is_empty()
    {
        progress(0, 0);
        return Vec::new();
    }

    let mut xrefs = Vec::new();
    let total_bytes = pe.sections.iter().filter(|section| section.Characteristics & IMAGE_SCN_MEM_EXECUTE != 0).fold(0usize, |total, section| {
        let section_start = section.VirtualAddress as usize;
        let section_size = validate_pe::get_mapped_section_size(section);
        let section_end = section_start.saturating_add(section_size).min(pe_data.len());

        total.saturating_add(section_end.saturating_sub(section_start))
    });
    let mut completed_bytes = 0usize;

    progress(0, total_bytes);

    for section in &pe.sections
    {
        if section.Characteristics & IMAGE_SCN_MEM_EXECUTE == 0
        {
            continue;
        }

        let section_start = section.VirtualAddress as usize;
        let section_size = validate_pe::get_mapped_section_size(section);

        let section_end = match section_start.checked_add(section_size)
        {
            Some(value) => value.min(pe_data.len()),
            None => continue,
        };
        let section_bytes = section_end.saturating_sub(section_start);

        collect_iat_xrefs_in_range(pe_data, pe, section_start, section_end, targets, &mut xrefs, completed_bytes, total_bytes, progress);

        completed_bytes = completed_bytes.saturating_add(section_bytes);
        progress(completed_bytes, total_bytes);
    }

    xrefs.sort_unstable_by_key(|xref| xref.instruction_rva);
    xrefs
}


/// Scans one executable image range for direct RIP-relative IAT references.
/// `pe_data`: loaded PE image bytes containing the executable range.
/// `pe`: copied validated headers and sections for `pe_data`.
/// `section_start`: inclusive RVA where scanning begins.
/// `section_end`: exclusive RVA where scanning stops.
/// `targets`: IAT RVAs retained as references.
/// `xrefs`: destination vector receiving matched references.
/// `completed_before_section`: executable bytes completed before this section.
/// `total_bytes`: total executable bytes scheduled for scanning.
/// `progress`: callback receiving completed and total executable bytes.
///
/// Returns unit after appending every requested reference found in the range.
fn collect_iat_xrefs_in_range(pe_data: &[u8], pe: &validate_pe::PeImage, section_start: usize, section_end: usize, targets: &HashSet<usize>, xrefs: &mut Vec<PeIatXref>, completed_before_section: usize, total_bytes: usize, progress: &mut impl FnMut(usize, usize))
{
    let mut opcode_rva = section_start;
    let mut next_progress_rva = section_start;

    while opcode_rva.checked_add(6).is_some_and(|instruction_end| instruction_end <= section_end)
    {
        if opcode_rva >= next_progress_rva
        {
            progress(completed_before_section.saturating_add(opcode_rva - section_start), total_bytes);
            next_progress_rva = opcode_rva.saturating_add(IAT_PROGRESS_BYTE_INTERVAL);
        }

        if pe_data[opcode_rva] != 0xFF
        {
            opcode_rva += 1;
            continue;
        }

        let kind = match pe_data[opcode_rva + 1]
        {
            0x15 => PeIatXrefKind::Call,
            0x25 => PeIatXrefKind::Jump,
            _ =>
            {
                opcode_rva += 1;
                continue;
            }
        };

        let displacement = i32::from_le_bytes([pe_data[opcode_rva + 2], pe_data[opcode_rva + 3], pe_data[opcode_rva + 4], pe_data[opcode_rva + 5]]);
        let next_instruction_rva = opcode_rva + 6;

        let iat_rva = match next_instruction_rva.checked_add_signed(displacement as isize)
        {
            Some(value) => value,
            None =>
            {
                opcode_rva += 6;
                continue;
            }
        };

        if targets.contains(&iat_rva)
        {
            let instruction_rva = if opcode_rva > section_start && matches!(pe_data[opcode_rva - 1], 0x40..=0x4F) { opcode_rva - 1 } else { opcode_rva };

            xrefs.push(PeIatXref {
                iat_rva,
                instruction_rva,
                file_offset: validate_pe::get_file_offset_from_pe(pe, instruction_rva),
                kind,
            });
        }

        opcode_rva += 6;
    }
}
