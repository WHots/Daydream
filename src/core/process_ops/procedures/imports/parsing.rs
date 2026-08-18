use windows_sys::Win32::System::Diagnostics::Debug::{IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_SCN_MEM_EXECUTE};

use crate::core::process_ops::procedures::foundation::validate_pe;

use super::PeImportEntry;

/// High-bit mask identifying an ordinal import in an x64 thunk.
const IMAGE_ORDINAL_FLAG64: u64 = 0x8000_0000_0000_0000;

/// Finds loader-discarded bytes required by process import parsing or xref scanning.
/// `snapshot`: validated process image with exact discarded-range metadata.
///
/// Returns the first unavailable range that would make the result incomplete.
pub(super) fn find_unavailable_import_range(snapshot: &validate_pe::ValidatedPeSnapshot) -> Option<validate_pe::UnavailablePeRange>
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


/// Collects imports from a PE image that has already passed strict validation.
/// `pe_data`: loaded PE image bytes indexed by RVA.
/// `pe`: copied validated headers and sections for `pe_data`.
///
/// Returns every named and ordinal standard import without reparsing the image.
pub(super) fn collect_import_entries_from_pe(pe_data: &[u8], pe: &validate_pe::PeImage) -> Vec<PeImportEntry>
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


/// Finds the first discarded snapshot range overlapping required image bytes.
/// `snapshot`: validated process image with exact discarded-range metadata.
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


/// Retrieves import descriptors from a loaded PE standard import directory.
/// `pe_data`: loaded PE image bytes indexed by RVA.
/// `pe`: copied validated headers and sections for `pe_data`.
///
/// Returns the validated descriptor list when a standard import directory exists.
fn get_import_descriptors(pe_data: &[u8], pe: &validate_pe::PeImage) -> Option<Vec<windows_sys::Win32::System::SystemServices::IMAGE_IMPORT_DESCRIPTOR>>
{
    let import_directory = validate_pe::get_data_directory(pe, IMAGE_DIRECTORY_ENTRY_IMPORT as usize)?;

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

    let descriptor_size = std::mem::size_of::<windows_sys::Win32::System::SystemServices::IMAGE_IMPORT_DESCRIPTOR>();
    let descriptor_count = (import_directory.Size as usize) / descriptor_size;

    if descriptor_count == 0
    {
        return None;
    }

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
/// `pe`: copied validated headers and sections for `pe_data`.
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
            file_offset: validate_pe::get_file_offset_from_pe(pe, iat_rva),
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
