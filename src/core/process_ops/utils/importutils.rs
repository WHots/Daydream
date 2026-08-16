use std::collections::{HashMap, HashSet};

use windows_sys::Win32::System::Diagnostics::Debug::{IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_SCN_MEM_EXECUTE};

use crate::core::process_ops::utils::foundation::validate_pe;
use crate::core::process_ops::utils::pe_utils;
use crate::core::process_ops::utils::processutils::ValidatedProcessPe;

/// High-bit mask identifying an ordinal import in an x64 thunk.
const IMAGE_ORDINAL_FLAG64: u64 = 0x8000_0000_0000_0000;

/// Executable-byte interval between IAT scan progress updates.
const IAT_PROGRESS_BYTE_INTERVAL: usize = 64 * 1024;

/// Describes one import-table entry before its code references are grouped.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeImportEntry
{
    pub library_name: Box<str>,
    pub function_name: Box<str>,
    pub ordinal: Option<u16>,
    pub iat_rva: usize,
    pub file_offset: Option<usize>,
}


/// Describes the direct instruction form used to reference an IAT slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeIatXrefKind
{
    Call,
    Jump,
}


/// Describes one direct x64 call or jump reference to an IAT slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeIatXref
{
    pub iat_rva: usize,
    pub instruction_rva: usize,
    pub file_offset: Option<usize>,
    pub kind: PeIatXrefKind,
}


/// Stores one process import and every direct code reference found for its IAT slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessImportInfo
{
    pub library_name: Box<str>,
    pub function_name: Box<str>,
    pub ordinal: Option<u16>,
    pub iat_rva: usize,
    pub iat_address: Option<usize>,
    pub iat_file_offset: Option<usize>,
    pub xrefs: Vec<ProcessImportXref>,
}


/// Stores one direct process instruction reference to an imported IAT slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessImportXref
{
    pub kind: PeIatXrefKind,
    pub instruction_rva: usize,
    pub instruction_address: Option<usize>,
    pub instruction_file_offset: Option<usize>,
}


/// Owns process imports, IAT references, and any unrelated loader-discarded ranges.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessImportCollection
{
    pub module_base_address: usize,
    pub module_size: usize,
    pub imports: Vec<ProcessImportInfo>,
    pub unavailable_ranges: Vec<validate_pe::UnavailablePeRange>,
}


/// Explains why process import collection could not complete.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProcessImportCollectionError
{
    IncompleteMainModuleSnapshot
    {
        rva: usize, size: usize
    },
}


/// Collects main-module imports from a previously validated process image snapshot.
/// `process`: the validated process identity supplying the main-module address and size.
/// `snapshot`: the matching mapped-image bytes, PE headers, and unavailable ranges.
/// `progress`: callback receiving completed and total executable bytes during IAT scanning.
///
/// Returns owned import and xref records without revalidating the process or reading its
/// main image again.
pub(crate) fn collect_process_imports_from_snapshot(process: &ValidatedProcessPe, snapshot: &validate_pe::ValidatedPeSnapshot, progress: &mut impl FnMut(usize, usize)) -> Result<ProcessImportCollection, ProcessImportCollectionError>
{
    if let Some(range) = find_unavailable_import_range(snapshot)
    {
        return Err(ProcessImportCollectionError::IncompleteMainModuleSnapshot {
            rva: range.rva,
            size: range.size,
        });
    }

    let imports = collect_process_import_info(process.image.base_address, &snapshot.bytes, &snapshot.pe, progress);

    Ok(ProcessImportCollection {
        module_base_address: process.image.base_address,
        module_size: process.image.image_size,
        imports,
        unavailable_ranges: snapshot.unavailable_ranges.clone(),
    })
}


/// Finds loader-discarded bytes required by process import parsing or xref scanning.
/// `snapshot`: validated process image with exact discarded-range metadata.
///
/// Returns the first unavailable range that would make the result incomplete.
fn find_unavailable_import_range(snapshot: &validate_pe::ValidatedPeSnapshot) -> Option<validate_pe::UnavailablePeRange>
{
    use windows_sys::Win32::System::SystemServices::IMAGE_IMPORT_BY_NAME;
    use windows_sys::Win32::System::WindowsProgramming::IMAGE_THUNK_DATA64;

    if snapshot.unavailable_ranges.is_empty()
    {
        return None;
    }

    let import_directory = validate_pe::get_data_directory(&snapshot.pe, IMAGE_DIRECTORY_ENTRY_IMPORT as usize)?;
    let import_directory_rva = import_directory.VirtualAddress as usize;
    let import_directory_size = import_directory.Size as usize;

    if import_directory_rva == 0 || import_directory_size == 0
    {
        return None;
    }

    if let Some(range) = find_snapshot_unavailable_overlap(snapshot, import_directory_rva, import_directory_size)
    {
        eprintln!("process import-descriptor bytes are unavailable");
        return Some(range);
    }

    let import_descriptors = get_import_descriptors(&snapshot.bytes, &snapshot.pe)?;
    let thunk_size = std::mem::size_of::<IMAGE_THUNK_DATA64>();
    let mut has_import_targets = false;

    for descriptor in &import_descriptors
    {
        if is_empty_import_descriptor(descriptor)
        {
            break;
        }

        let library_name_rva = descriptor.Name as usize;
        let library_name_size = snapshot.bytes.get(library_name_rva..).and_then(|bytes| bytes.iter().position(|byte| *byte == 0)).and_then(|index| index.checked_add(1)).unwrap_or(1);

        if let Some(range) = find_snapshot_unavailable_overlap(snapshot, library_name_rva, library_name_size)
        {
            eprintln!("process import library-name bytes are unavailable");
            return Some(range);
        }

        // SAFETY: `OriginalFirstThunk` is the integer union member used for import lookup-table RVAs.
        let original_first_thunk = unsafe { descriptor.Anonymous.OriginalFirstThunk };
        let lookup_table_rva = if original_first_thunk != 0 { original_first_thunk as usize } else { descriptor.FirstThunk as usize };

        if lookup_table_rva == 0 || descriptor.FirstThunk == 0
        {
            continue;
        }

        let mut thunk_index = 0usize;

        loop
        {
            let thunk_rva = match thunk_index.checked_mul(thunk_size).and_then(|offset| lookup_table_rva.checked_add(offset))
            {
                Some(value) => value,
                None => break,
            };

            if let Some(range) = find_snapshot_unavailable_overlap(snapshot, thunk_rva, thunk_size)
            {
                eprintln!("process import lookup-thunk bytes are unavailable");
                return Some(range);
            }

            let thunk_end = match thunk_rva.checked_add(thunk_size)
            {
                Some(value) => value,
                None => break,
            };
            let thunk_bytes = match snapshot.bytes.get(thunk_rva..thunk_end)
            {
                Some(value) => value,
                None => break,
            };

            // SAFETY: the checked slice contains one complete unaligned thunk value.
            let thunk = unsafe { std::ptr::read_unaligned(thunk_bytes.as_ptr() as *const IMAGE_THUNK_DATA64) };
            // SAFETY: `AddressOfData` is the integer union member used by import lookup thunks.
            let thunk_value = unsafe { thunk.u1.AddressOfData };

            if thunk_value == 0
            {
                break;
            }

            has_import_targets = true;

            let iat_rva = match thunk_index.checked_mul(thunk_size).and_then(|offset| (descriptor.FirstThunk as usize).checked_add(offset))
            {
                Some(value) => value,
                None => break,
            };

            if let Some(range) = find_snapshot_unavailable_overlap(snapshot, iat_rva, thunk_size)
            {
                eprintln!("process import address-thunk bytes are unavailable");
                return Some(range);
            }

            if thunk_value & IMAGE_ORDINAL_FLAG64 == 0
            {
                let import_by_name_rva = match usize::try_from(thunk_value)
                {
                    Ok(value) => value,
                    Err(_) => break,
                };
                let function_name_rva = match import_by_name_rva.checked_add(std::mem::offset_of!(IMAGE_IMPORT_BY_NAME, Name))
                {
                    Some(value) => value,
                    None => break,
                };
                let function_name_size = snapshot.bytes.get(function_name_rva..).and_then(|bytes| bytes.iter().position(|byte| *byte == 0)).and_then(|index| index.checked_add(1)).unwrap_or(1);
                let import_by_name_size = match std::mem::offset_of!(IMAGE_IMPORT_BY_NAME, Name).checked_add(function_name_size)
                {
                    Some(value) => value,
                    None => break,
                };

                if let Some(range) = find_snapshot_unavailable_overlap(snapshot, import_by_name_rva, import_by_name_size)
                {
                    eprintln!("process import-by-name bytes are unavailable");
                    return Some(range);
                }
            }

            thunk_index = match thunk_index.checked_add(1)
            {
                Some(value) => value,
                None => break,
            };
        }
    }

    if has_import_targets
    {
        for section in &snapshot.pe.sections
        {
            if section.Characteristics & IMAGE_SCN_MEM_EXECUTE == 0
            {
                continue;
            }

            let section_rva = section.VirtualAddress as usize;
            let section_size = validate_pe::get_mapped_section_size(section);

            if let Some(range) = find_snapshot_unavailable_overlap(snapshot, section_rva, section_size)
            {
                eprintln!("process executable-section bytes required for IAT xrefs are unavailable");
                return Some(range);
            }
        }
    }

    None
}


/// Finds the first discarded snapshot range overlapping required image bytes.
/// `snapshot`: validated process image with discarded-range metadata.
/// `rva`: first required relative virtual address.
/// `size`: exact required byte length.
///
/// Returns the stored unavailable range when an overlap exists.
fn find_snapshot_unavailable_overlap(snapshot: &validate_pe::ValidatedPeSnapshot, rva: usize, size: usize) -> Option<validate_pe::UnavailablePeRange>
{
    let end_rva = match rva.checked_add(size)
    {
        Some(value) => value,
        None =>
        {
            eprintln!("required process import range overflowed");
            return None;
        }
    };

    for range in &snapshot.unavailable_ranges
    {
        let unavailable_end_rva = match range.rva.checked_add(range.size)
        {
            Some(value) => value,
            None =>
            {
                eprintln!("discarded process image range overflowed");
                return Some(*range);
            }
        };

        if rva < unavailable_end_rva && range.rva < end_rva
        {
            return Some(*range);
        }
    }

    None
}


/// Collects imports from a PE image that has already passed strict validation.
/// `pe_data`: loaded PE image bytes indexed by RVA.
/// `pe`: copied validated headers and sections for `pe_data`.
///
/// Returns every named and ordinal standard import without reparsing the image.
fn collect_import_entries_from_pe(pe_data: &[u8], pe: &validate_pe::PeImage) -> Vec<PeImportEntry>
{
    let import_descriptors = match get_import_descriptors(pe_data, pe)
    {
        Some(value) => value,
        None => return Vec::new(),
    };

    let mut imports = Vec::new();

    for descriptor in &import_descriptors
    {
        if is_empty_import_descriptor(descriptor)
        {
            break;
        }

        let library_name = match read_c_string_at_rva(pe_data, descriptor.Name as usize)
        {
            Some(value) => value,
            None => continue,
        };

        collect_import_entries_from_descriptor(pe_data, pe, descriptor, library_name.as_ref(), &mut imports);
    }

    imports
}


/// Builds grouped process import records from loaded module bytes.
/// `module_base_address`: the remote base address used for absolute-address mapping.
/// `pe_data`: loaded main-module bytes indexed by RVA.
/// `pe`: copied validated headers and sections for `pe_data`.
/// `progress`: callback receiving completed and total executable bytes.
///
/// Returns all standard imports with their direct IAT xrefs grouped by slot.
fn collect_process_import_info(module_base_address: usize, pe_data: &[u8], pe: &validate_pe::PeImage, progress: &mut impl FnMut(usize, usize)) -> Vec<ProcessImportInfo>
{
    let imports = collect_import_entries_from_pe(pe_data, pe);

    if imports.is_empty()
    {
        progress(0, 0);
        return Vec::new();
    }

    let targets: HashSet<usize> = imports.iter().map(|entry| entry.iat_rva).collect();
    let xrefs = collect_iat_xrefs_for_targets(pe_data, pe, &targets, progress);

    build_process_import_info(module_base_address, imports, xrefs)
}


/// Groups flat IAT xrefs into their owning process import records.
/// `module_base_address`: the remote base address used for absolute-address mapping.
/// `imports`: parsed standard import-table entries.
/// `xrefs`: direct code references collected for all imported IAT slots.
///
/// Returns owned import records while preserving import-table and instruction order.
fn build_process_import_info(module_base_address: usize, imports: Vec<PeImportEntry>, xrefs: Vec<PeIatXref>) -> Vec<ProcessImportInfo>
{
    let mut xrefs_by_iat: HashMap<usize, Vec<ProcessImportXref>> = HashMap::with_capacity(imports.len());

    for xref in xrefs
    {
        xrefs_by_iat.entry(xref.iat_rva).or_default().push(ProcessImportXref {
            kind: xref.kind,
            instruction_rva: xref.instruction_rva,
            instruction_address: module_base_address.checked_add(xref.instruction_rva),
            instruction_file_offset: xref.file_offset,
        });
    }

    let mut grouped = Vec::with_capacity(imports.len());

    for import in imports
    {
        let iat_rva = import.iat_rva;

        grouped.push(ProcessImportInfo {
            library_name: import.library_name,
            function_name: import.function_name,
            ordinal: import.ordinal,
            iat_rva,
            iat_address: module_base_address.checked_add(iat_rva),
            iat_file_offset: import.file_offset,
            xrefs: xrefs_by_iat.remove(&iat_rva).unwrap_or_default(),
        });
    }

    grouped
}


/// Scans executable sections once for every selected IAT target.
/// `pe_data`: loaded PE image bytes indexed by RVA.
/// `pe`: copied validated headers and sections for `pe_data`.
/// `targets`: unique IAT slot RVAs retained as references.
/// `progress`: callback receiving completed and total executable bytes.
///
/// Returns all matching direct call and jump xrefs ordered by instruction RVA.
fn collect_iat_xrefs_for_targets(pe_data: &[u8], pe: &validate_pe::PeImage, targets: &HashSet<usize>, progress: &mut impl FnMut(usize, usize)) -> Vec<PeIatXref>
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
                file_offset: pe_utils::get_file_offset_from_pe(pe, instruction_rva),
                kind,
            });
        }

        opcode_rva += 6;
    }
}


/// Retrieves import descriptors from a loaded PE standard import directory.
/// `pe_data`: loaded PE image bytes indexed by RVA.
///
/// Returns the validated descriptor slice when a standard import directory exists.
fn get_import_descriptors(pe_data: &[u8], pe: &validate_pe::PeImage) -> Option<Vec<windows_sys::Win32::System::SystemServices::IMAGE_IMPORT_DESCRIPTOR>>
{
    let import_directory = validate_pe::get_data_directory(pe, 1)?;

    if import_directory.Size == 0 || import_directory.VirtualAddress == 0
    {
        return None;
    }

    let import_descriptors_offset = import_directory.VirtualAddress as usize;
    let import_directory_end = import_descriptors_offset.checked_add(import_directory.Size as usize)?;

    if pe_data.len() < import_directory_end
    {
        return None;
    }

    let descriptor_count = (import_directory.Size as usize) / std::mem::size_of::<windows_sys::Win32::System::SystemServices::IMAGE_IMPORT_DESCRIPTOR>();

    if descriptor_count == 0
    {
        return None;
    }

    let descriptor_size = std::mem::size_of::<windows_sys::Win32::System::SystemServices::IMAGE_IMPORT_DESCRIPTOR>();
    let mut descriptors = Vec::new();

    descriptors.try_reserve_exact(descriptor_count).ok()?;

    for index in 0..descriptor_count
    {
        let offset = import_descriptors_offset.checked_add(index.checked_mul(descriptor_size)?)?;

        // SAFETY: the complete directory range is checked above, and unaligned reads are permitted.
        let descriptor = unsafe { std::ptr::read_unaligned(pe_data.as_ptr().add(offset) as *const windows_sys::Win32::System::SystemServices::IMAGE_IMPORT_DESCRIPTOR) };

        descriptors.push(descriptor);
    }

    Some(descriptors)
}


/// Collects every named or ordinal import from one import descriptor.
/// `pe_data`: loaded PE image bytes indexed by RVA.
/// `descriptor`: import descriptor whose lookup and address thunks are walked.
/// `library_name`: decoded library name for the descriptor.
/// `imports`: destination vector receiving each valid import entry.
///
/// Returns unit after appending every valid import from the descriptor.
fn collect_import_entries_from_descriptor(pe_data: &[u8], pe: &validate_pe::PeImage, descriptor: &windows_sys::Win32::System::SystemServices::IMAGE_IMPORT_DESCRIPTOR, library_name: &str, imports: &mut Vec<PeImportEntry>)
{
    use windows_sys::Win32::System::SystemServices::IMAGE_IMPORT_BY_NAME;
    use windows_sys::Win32::System::WindowsProgramming::IMAGE_THUNK_DATA64;

    // SAFETY: `OriginalFirstThunk` is the integer union member used for import lookup-table RVAs.
    let original_first_thunk = unsafe { descriptor.Anonymous.OriginalFirstThunk };
    let lookup_table_rva = if original_first_thunk != 0 { original_first_thunk as usize } else { descriptor.FirstThunk as usize };

    if lookup_table_rva == 0 || descriptor.FirstThunk == 0
    {
        return;
    }

    let thunk_size = std::mem::size_of::<IMAGE_THUNK_DATA64>();
    let mut thunk_index = 0usize;

    loop
    {
        let thunk_offset = match thunk_index.checked_mul(thunk_size).and_then(|offset| lookup_table_rva.checked_add(offset))
        {
            Some(value) => value,
            None => break,
        };

        let thunk_end = match thunk_offset.checked_add(thunk_size)
        {
            Some(value) => value,
            None => break,
        };

        let thunk_bytes = match pe_data.get(thunk_offset..thunk_end)
        {
            Some(value) => value,
            None => break,
        };

        // SAFETY: the checked byte slice contains one complete possibly unaligned thunk value.
        let thunk = unsafe { std::ptr::read_unaligned(thunk_bytes.as_ptr() as *const IMAGE_THUNK_DATA64) };
        // SAFETY: `AddressOfData` is the integer union member used by import lookup thunks.
        let thunk_value = unsafe { thunk.u1.AddressOfData };

        if thunk_value == 0
        {
            break;
        }

        let (function_name, ordinal) = if thunk_value & IMAGE_ORDINAL_FLAG64 != 0
        {
            let ordinal = (thunk_value & 0xFFFF) as u16;

            (format!("#{}", ordinal).into_boxed_str(), Some(ordinal))
        }
        else
        {
            let import_by_name_rva = match usize::try_from(thunk_value)
            {
                Ok(value) => value,
                Err(_) => break,
            };

            let function_name_rva = match import_by_name_rva.checked_add(std::mem::offset_of!(IMAGE_IMPORT_BY_NAME, Name))
            {
                Some(value) => value,
                None => break,
            };

            let function_name = match read_c_string_at_rva(pe_data, function_name_rva)
            {
                Some(value) => value,
                None =>
                {
                    thunk_index = match thunk_index.checked_add(1)
                    {
                        Some(value) => value,
                        None => break,
                    };
                    continue;
                }
            };

            (function_name, None)
        };

        let iat_rva = match thunk_index.checked_mul(thunk_size).and_then(|offset| (descriptor.FirstThunk as usize).checked_add(offset))
        {
            Some(value) => value,
            None => break,
        };

        imports.push(PeImportEntry {
            library_name: library_name.into(),
            function_name,
            ordinal,
            iat_rva,
            file_offset: pe_utils::get_file_offset_from_pe(pe, iat_rva),
        });

        thunk_index = match thunk_index.checked_add(1)
        {
            Some(value) => value,
            None => break,
        };
    }
}


/// Reports whether an import descriptor is the null terminator entry.
/// `descriptor`: import descriptor to test.
///
/// Returns `true` when the descriptor carries no import-table fields.
#[inline]
fn is_empty_import_descriptor(descriptor: &windows_sys::Win32::System::SystemServices::IMAGE_IMPORT_DESCRIPTOR) -> bool
{
    // SAFETY: `OriginalFirstThunk` is the integer union member used for import lookup-table RVAs.
    let original_first_thunk = unsafe { descriptor.Anonymous.OriginalFirstThunk };

    original_first_thunk == 0 && descriptor.Name == 0 && descriptor.FirstThunk == 0
}


/// Reads a NUL-terminated UTF-8-compatible string at a loaded PE RVA.
/// `pe_data`: loaded PE image bytes indexed by RVA.
/// `rva`: RVA where the string begins.
///
/// Returns an owned string when the RVA points to a valid NUL-terminated UTF-8 value.
#[inline]
fn read_c_string_at_rva(pe_data: &[u8], rva: usize) -> Option<Box<str>>
{
    let bytes = pe_data.get(rva..)?;
    let value = std::ffi::CStr::from_bytes_until_nul(bytes).ok()?.to_str().ok()?;

    Some(value.into())
}
