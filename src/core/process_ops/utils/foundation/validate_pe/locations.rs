use core::mem::size_of;

use windows_sys::Win32::System::Diagnostics::Debug::{IMAGE_DATA_DIRECTORY, IMAGE_NT_HEADERS64, IMAGE_OPTIONAL_HEADER64, IMAGE_SECTION_HEADER};

use super::{PeImage, PeSectionInfo};

/// Retrieves one declared PE data-directory entry from safely parsed headers.
/// `pe`: copied PE headers and sections returned by `parse_pe` or `validate_pe`.
/// `directory_index`: zero-based optional-header data-directory index.
///
/// Returns the directory only when both its declared count and optional-header size include it.
pub(crate) fn get_data_directory(pe: &PeImage, directory_index: usize) -> Option<IMAGE_DATA_DIRECTORY>
{
    if pe.nt_headers.OptionalHeader.NumberOfRvaAndSizes as usize <= directory_index
    {
        return None;
    }

    let required_size = std::mem::offset_of!(IMAGE_OPTIONAL_HEADER64, DataDirectory).checked_add((directory_index + 1).checked_mul(size_of::<IMAGE_DATA_DIRECTORY>())?)?;

    if (pe.nt_headers.FileHeader.SizeOfOptionalHeader as usize) < required_size
    {
        return None;
    }

    Some(pe.nt_headers.OptionalHeader.DataDirectory[directory_index])
}


/// Retrieves the loaded-memory span represented by a PE section header.
/// `section`: copied PE section header to measure.
///
/// Returns `VirtualSize`, falling back to raw size only when the virtual size is zero.
pub(crate) fn get_mapped_section_size(section: &IMAGE_SECTION_HEADER) -> usize
{
    // SAFETY: `Misc.VirtualSize` is the image-section union member used for loaded images.
    let virtual_size = unsafe { section.Misc.VirtualSize } as usize;

    if virtual_size == 0
    {
        section.SizeOfRawData as usize
    }
    else
    {
        virtual_size
    }
}


/// Collects complete section metadata from headers that already passed strict validation.
/// `pe`: safely copied and validated PE headers and section table.
///
/// Returns section records in image section-table order without reparsing image bytes.
pub(crate) fn collect_sections_from_pe(pe: &PeImage) -> Vec<PeSectionInfo>
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
            mapped_size: get_mapped_section_size(section),
            raw_file_offset: section.PointerToRawData as usize,
            characteristics: section.Characteristics,
        });
    }

    sections
}


/// Retrieves a raw-file offset from PE headers that were already strictly validated.
/// `pe`: safely copied and validated PE headers and sections.
/// `rva`: relative virtual address to translate.
///
/// Returns the section-aware file offset without reparsing the mapped image.
pub(crate) fn get_file_offset_from_pe(pe: &PeImage, rva: usize) -> Option<usize>
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
        let section_end = section_start.checked_add(get_mapped_section_size(section))?;

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


/// Reports whether one RVA range is fully backed by mapped headers or section data.
/// `nt_headers`: validated headers defining image and header bounds.
/// `sections`: validated section table in ascending RVA order.
/// `rva`: first required relative virtual address.
/// `size`: exact required byte length.
///
/// Returns `true` only when the complete range avoids alignment padding.
pub(super) fn is_image_data_range(nt_headers: &IMAGE_NT_HEADERS64, sections: &[IMAGE_SECTION_HEADER], rva: usize, size: usize) -> bool
{
    if size == 0
    {
        return false;
    }

    let end_rva = match rva.checked_add(size)
    {
        Some(value) if value <= nt_headers.OptionalHeader.SizeOfImage as usize => value,
        _ =>
        {
            eprintln!("PE image-data range overflowed or exceeded SizeOfImage");
            return false;
        }
    };
    let size_of_headers = nt_headers.OptionalHeader.SizeOfHeaders as usize;

    if rva < size_of_headers
    {
        return end_rva <= size_of_headers;
    }

    let mut covered_end_rva = rva;

    for section in sections
    {
        let section_start_rva = section.VirtualAddress as usize;
        let section_end_rva = match section_start_rva.checked_add(get_mapped_section_size(section))
        {
            Some(value) => value,
            None =>
            {
                eprintln!("PE mapped section range overflowed while checking image data");
                return false;
            }
        };

        if covered_end_rva < section_start_rva
        {
            return false;
        }

        if covered_end_rva >= section_start_rva && covered_end_rva < section_end_rva
        {
            covered_end_rva = section_end_rva.min(end_rva);

            if covered_end_rva == end_rva
            {
                return true;
            }
        }
    }

    false
}
