use core::mem::{size_of, zeroed};

use windows_sys::Win32::System::Diagnostics::Debug::{IMAGE_DATA_DIRECTORY, IMAGE_DIRECTORY_ENTRY_ARCHITECTURE, IMAGE_DIRECTORY_ENTRY_GLOBALPTR, IMAGE_DIRECTORY_ENTRY_SECURITY, IMAGE_FILE_EXECUTABLE_IMAGE, IMAGE_FILE_HEADER, IMAGE_NT_HEADERS64, IMAGE_NT_OPTIONAL_HDR64_MAGIC, IMAGE_OPTIONAL_HEADER64, IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SECTION_HEADER};
use windows_sys::Win32::System::SystemInformation::IMAGE_FILE_MACHINE_AMD64;
use windows_sys::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE};

use super::locations::{get_mapped_section_size, is_image_data_range};
use super::{PeImage, PeValidationError};

/// Maximum section count accepted by the Windows image loader.
const WINDOWS_IMAGE_SECTION_LIMIT: usize = 96;

/// Maximum mapped size accepted for one PE32+ image.
const MAXIMUM_IMAGE_SIZE: usize = 0x8000_0000;

/// Required alignment of the PE signature and COFF header.
const PE_HEADER_ALIGNMENT: usize = 8;

/// Minimum standard raw-file alignment for page-aligned images.
const MIN_FILE_ALIGNMENT: usize = 0x200;

/// Maximum PE raw-file alignment accepted by the format.
const MAX_FILE_ALIGNMENT: usize = 0x1_0000;

/// x64 page size used by the PE low-alignment rule.
const IMAGE_PAGE_SIZE: usize = 0x1000;

/// Required alignment of the preferred PE image base.
const IMAGE_BASE_ALIGNMENT: u64 = 0x1_0000;

/// Final PE data-directory slot reserved by the format.
const RESERVED_DATA_DIRECTORY_INDEX: usize = 15;

/// Stores the strict NT-header facts needed to read and validate a section table.
pub(super) struct ValidatedNtHeaders
{
    pub(super) section_table_offset: usize,
    pub(super) section_table_size: usize,
    pub(super) image_size: usize,
}

/// Safely parses bounded PE headers and section entries without requiring a valid loaded layout.
/// `pe_data`: mapped-image bytes containing the complete PE headers.
///
/// Returns copied headers and sections, or a typed bounds/identity failure.
pub(crate) fn parse_pe(pe_data: &[u8]) -> Result<PeImage, PeValidationError>
{
    // SAFETY: `IMAGE_DOS_HEADER` permits every bit pattern and contains no references.
    let dos_header = unsafe { read_data_value::<IMAGE_DOS_HEADER>(pe_data, 0) }?;
    let nt_headers_offset = validate_dos_header(&dos_header)?;
    let nt_headers = read_nt_headers(pe_data, nt_headers_offset)?;
    let (section_count, _image_size, size_of_headers) = validate_header_fields(&nt_headers)?;

    if size_of_headers > pe_data.len()
    {
        return Err(PeValidationError::HeadersOutsideData {
            size_of_headers,
            data_size: pe_data.len(),
        });
    }

    let (section_table_offset, section_table_size, section_table_end) = get_section_table_range(&nt_headers, nt_headers_offset, section_count, size_of_headers)?;

    if section_table_end > pe_data.len()
    {
        return Err(PeValidationError::SectionTableOutsideData {
            section_table_end,
            data_size: pe_data.len(),
        });
    }

    let sections = read_section_headers(pe_data, section_table_offset, section_table_size, section_count)?;

    Ok(PeImage {
        nt_headers,
        nt_headers_offset,
        sections,
    })
}


/// Strictly validates a complete mapped x64 PE image.
/// `pe_data`: mapped-image bytes indexed by RVA.
///
/// Returns copied validated headers and sections, or the first structural failure.
pub(crate) fn validate_pe(pe_data: &[u8]) -> Result<PeImage, PeValidationError>
{
    let pe = parse_pe(pe_data)?;

    validate_parsed_pe(&pe, pe_data.len())?;

    Ok(pe)
}


/// Strictly validates an already parsed mapped PE image.
/// `pe`: safely copied headers and sections returned by `parse_pe`.
/// `data_size`: complete mapped-image byte length available to the caller.
///
/// Returns unit when header alignment, image bounds, sections, and entry point all agree.
pub(crate) fn validate_parsed_pe(pe: &PeImage, data_size: usize) -> Result<(), PeValidationError>
{
    let validated_headers = validate_nt_headers(&pe.nt_headers, pe.nt_headers_offset)?;

    if validated_headers.image_size > data_size
    {
        return Err(PeValidationError::ImageOutsideData {
            image_size: validated_headers.image_size,
            data_size,
        });
    }

    validate_section_layout(&pe.nt_headers, &pe.sections)?;
    validate_data_directory_layout(&pe.nt_headers, &pe.sections)?;

    Ok(())
}


/// Validates section ordering, alignment, ranges, overlap, and entry-point containment.
/// `nt_headers`: copied x64 NT headers defining the loaded image.
/// `sections`: the complete section table associated with the headers.
///
/// Returns `Ok(())` only when every mapped section fits the declared loaded image.
pub(super) fn validate_section_layout(nt_headers: &IMAGE_NT_HEADERS64, sections: &[IMAGE_SECTION_HEADER]) -> Result<(), PeValidationError>
{
    let image_size = nt_headers.OptionalHeader.SizeOfImage as usize;
    let size_of_headers = nt_headers.OptionalHeader.SizeOfHeaders as usize;
    let section_alignment = nt_headers.OptionalHeader.SectionAlignment as usize;
    let file_alignment = nt_headers.OptionalHeader.FileAlignment as usize;
    let entry_point_rva = nt_headers.OptionalHeader.AddressOfEntryPoint as usize;
    let base_of_code_rva = nt_headers.OptionalHeader.BaseOfCode as usize;
    let mut previous_end_rva = None;
    let mut previous_raw_end = None;
    let mut entry_point_is_executable = entry_point_rva == 0;
    let mut first_code_section_rva = None;
    
    let mut expected_section_rva = size_of_headers.checked_next_multiple_of(section_alignment).ok_or_else(|| {
        eprintln!("PE first-section alignment overflowed");
        PeValidationError::SectionTableRangeOverflow
    })?;

    for (index, section) in sections.iter().enumerate()
    {
        let section_rva = section.VirtualAddress as usize;

        if section_rva < expected_section_rva
        {
            eprintln!("PE mapped section overlaps the preceding aligned section range");
            return Err(PeValidationError::OverlappingSections {
                index,
                previous_end_rva: previous_end_rva.unwrap_or(size_of_headers),
                section_rva,
            });
        }

        if section_rva != expected_section_rva
        {
            eprintln!("PE mapped sections are not aligned and adjacent");
            return Err(PeValidationError::InvalidSectionLayout {
                index,
                section_rva,
            });
        }

        let mapped_size = get_mapped_section_size(section);

        if mapped_size == 0
        {
            eprintln!("PE section has no mapped extent");
            return Err(PeValidationError::InvalidSectionRange {
                index,
                section_rva,
                mapped_size,
                image_size,
            });
        }

        let maximum_raw_size = mapped_size.checked_next_multiple_of(file_alignment).ok_or_else(|| {
            eprintln!("PE aligned section raw-data limit overflowed");

            PeValidationError::InvalidSectionRawLayout {
                index,
                raw_size: section.SizeOfRawData as usize,
                raw_pointer: section.PointerToRawData as usize,
                file_alignment,
            }
        })?;
        let raw_size = section.SizeOfRawData as usize;
        let raw_pointer = section.PointerToRawData as usize;
        let raw_layout_invalid = if raw_size == 0 { raw_pointer != 0 } else { raw_size > maximum_raw_size || raw_pointer < size_of_headers || raw_pointer % file_alignment != 0 || raw_size % file_alignment != 0 || (section_alignment < IMAGE_PAGE_SIZE && raw_pointer != section_rva) };

        if raw_layout_invalid
        {
            eprintln!("PE section raw-data metadata is invalid");

            return Err(PeValidationError::InvalidSectionRawLayout {
                index,
                raw_size,
                raw_pointer,
                file_alignment,
            });
        }

        if raw_size != 0
        {
            let raw_end = raw_pointer.checked_add(raw_size).ok_or_else(|| {
                eprintln!("PE section raw-data range overflowed");
                PeValidationError::InvalidSectionRawLayout {
                    index,
                    raw_size,
                    raw_pointer,
                    file_alignment,
                }
            })?;

            if previous_raw_end.is_some_and(|end| raw_pointer < end)
            {
                eprintln!("PE section raw-data ranges overlap or are out of order");
                return Err(PeValidationError::InvalidSectionRawLayout {
                    index,
                    raw_size,
                    raw_pointer,
                    file_alignment,
                });
            }

            previous_raw_end = Some(raw_end);
        }

        if first_code_section_rva.is_none() && section.Characteristics & IMAGE_SCN_CNT_CODE != 0
        {
            first_code_section_rva = Some(section_rva);
        }

        let end_rva = match section_rva.checked_add(mapped_size)
        {
            Some(value) if value <= image_size => value,
            _ =>
            {
                eprintln!("PE mapped section extends beyond SizeOfImage");
                return Err(PeValidationError::InvalidSectionRange {
                    index,
                    section_rva,
                    mapped_size,
                    image_size,
                });
            }
        };

        if entry_point_rva >= section_rva && entry_point_rva < end_rva && section.Characteristics & IMAGE_SCN_MEM_EXECUTE != 0
        {
            entry_point_is_executable = true;
        }

        previous_end_rva = Some(end_rva);
        expected_section_rva = end_rva.checked_next_multiple_of(section_alignment).ok_or_else(|| {
            eprintln!("PE aligned section end overflowed");
            PeValidationError::InvalidSectionRange {
                index,
                section_rva,
                mapped_size,
                image_size,
            }
        })?;
    }

    if !entry_point_is_executable
    {
        eprintln!("PE entry point is not contained by an executable section");
        return Err(PeValidationError::InvalidEntryPoint {
            entry_point_rva,
            image_size,
        });
    }

    let expected_base_of_code_rva = first_code_section_rva.unwrap_or(0);

    if base_of_code_rva != expected_base_of_code_rva
    {
        eprintln!("PE BaseOfCode does not identify the first code section");
        return Err(PeValidationError::InvalidBaseOfCode {
            base_of_code_rva,
            expected_base_of_code_rva,
        });
    }

    if expected_section_rva != image_size
    {
        eprintln!("PE SizeOfImage does not equal the aligned end of the final section");
        return Err(PeValidationError::InvalidFinalImageSize {
            expected_image_size: expected_section_rva,
            actual_image_size: image_size,
        });
    }

    Ok(())
}


/// Validates that every mapped data directory occupies actual headers or section data.
/// `nt_headers`: copied x64 NT headers declaring the data directories.
/// `sections`: complete validated section table defining actual mapped extents.
///
/// Returns unit only when no directory points into image-alignment padding.
pub(super) fn validate_data_directory_layout(nt_headers: &IMAGE_NT_HEADERS64, sections: &[IMAGE_SECTION_HEADER]) -> Result<(), PeValidationError>
{
    for (index, directory) in nt_headers.OptionalHeader.DataDirectory.iter().take(nt_headers.OptionalHeader.NumberOfRvaAndSizes as usize).enumerate()
    {
        let virtual_address = directory.VirtualAddress as usize;
        let size = directory.Size as usize;

        if virtual_address == 0 && size == 0 || index == IMAGE_DIRECTORY_ENTRY_SECURITY as usize
        {
            continue;
        }

        let required_size = if index == IMAGE_DIRECTORY_ENTRY_GLOBALPTR as usize { 1 } else { size };

        if !is_image_data_range(nt_headers, sections, virtual_address, required_size)
        {
            eprintln!("PE data directory points into image-alignment padding");
            return Err(PeValidationError::InvalidDataDirectoryRange {
                index,
                virtual_address,
                size,
                image_size: nt_headers.OptionalHeader.SizeOfImage as usize,
            });
        }
    }

    Ok(())
}


/// Validates the DOS header and returns its bounded non-negative NT-header offset.
/// `dos_header`: copied DOS header from mapped bytes or target-process memory.
///
/// Returns the NT-header offset, or a signature/offset failure.
pub(super) fn validate_dos_header(dos_header: &IMAGE_DOS_HEADER) -> Result<usize, PeValidationError>
{
    if dos_header.e_magic != IMAGE_DOS_SIGNATURE
    {
        eprintln!("PE DOS signature is invalid");
        return Err(PeValidationError::InvalidDosSignature {
            signature: dos_header.e_magic,
        });
    }

    let nt_headers_offset = usize::try_from(dos_header.e_lfanew).map_err(|_| {
        eprintln!("PE NT-header offset is negative");

        PeValidationError::InvalidNtHeadersOffset {
            offset: dos_header.e_lfanew,
        }
    })?;

    if nt_headers_offset < size_of::<IMAGE_DOS_HEADER>() || nt_headers_offset % PE_HEADER_ALIGNMENT != 0
    {
        eprintln!("PE NT-header offset is outside the aligned DOS-stub range");

        return Err(PeValidationError::InvalidNtHeadersOffset {
            offset: dos_header.e_lfanew,
        });
    }

    Ok(nt_headers_offset)
}


/// Validates strict x64 NT-header fields and section-table bounds.
/// `nt_headers`: copied NT headers from a mapped image.
/// `nt_headers_offset`: DOS-header-relative NT-header offset.
///
/// Returns the validated section-table range and image size.
pub(super) fn validate_nt_headers(nt_headers: &IMAGE_NT_HEADERS64, nt_headers_offset: usize) -> Result<ValidatedNtHeaders, PeValidationError>
{
    let (section_count, image_size, size_of_headers) = validate_header_fields(nt_headers)?;
    let section_alignment = nt_headers.OptionalHeader.SectionAlignment as usize;
    let file_alignment = nt_headers.OptionalHeader.FileAlignment as usize;

    if nt_headers.FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE == 0
    {
        eprintln!("PE COFF header does not identify an executable image");

        return Err(PeValidationError::MissingExecutableImageCharacteristic {
            characteristics: nt_headers.FileHeader.Characteristics,
        });
    }

    if nt_headers.OptionalHeader.Win32VersionValue != 0 || nt_headers.OptionalHeader.LoaderFlags != 0
    {
        eprintln!("PE optional header contains nonzero reserved fields");

        return Err(PeValidationError::NonZeroReservedOptionalHeaderFields {
            win32_version_value: nt_headers.OptionalHeader.Win32VersionValue,
            loader_flags: nt_headers.OptionalHeader.LoaderFlags,
        });
    }

    if !section_alignment.is_power_of_two() || !file_alignment.is_power_of_two() || section_alignment < file_alignment || (section_alignment < IMAGE_PAGE_SIZE && section_alignment != file_alignment) || (section_alignment >= IMAGE_PAGE_SIZE && !(MIN_FILE_ALIGNMENT..=MAX_FILE_ALIGNMENT).contains(&file_alignment)) || image_size % section_alignment != 0
    {
        eprintln!("PE image or file alignment is invalid");

        return Err(PeValidationError::InvalidImageAlignment {
            section_alignment,
            file_alignment,
        });
    }

    if size_of_headers % file_alignment != 0
    {
        eprintln!("PE SizeOfHeaders is not file aligned");
        return Err(PeValidationError::InvalidHeadersSize {
            size_of_headers,
            image_size,
        });
    }

    let image_base = nt_headers.OptionalHeader.ImageBase;

    if image_base % IMAGE_BASE_ALIGNMENT != 0
    {
        eprintln!("PE preferred image base is not 64-KiB aligned");
        return Err(PeValidationError::InvalidImageBase {
            image_base,
        });
    }

    if image_size > MAXIMUM_IMAGE_SIZE
    {
        eprintln!("PE32+ SizeOfImage exceeds the 2-GiB format limit");
        return Err(PeValidationError::ImageSizeExceedsMaximum {
            image_size,
            maximum_image_size: MAXIMUM_IMAGE_SIZE,
        });
    }

    for (index, directory) in nt_headers.OptionalHeader.DataDirectory.iter().take(nt_headers.OptionalHeader.NumberOfRvaAndSizes as usize).enumerate()
    {
        let virtual_address = directory.VirtualAddress as usize;
        let size = directory.Size as usize;

        if index == IMAGE_DIRECTORY_ENTRY_ARCHITECTURE as usize || index == RESERVED_DATA_DIRECTORY_INDEX
        {
            if virtual_address != 0 || size != 0
            {
                eprintln!("PE reserved data directory is not zero");
                return Err(PeValidationError::InvalidDataDirectoryRange {
                    index,
                    virtual_address,
                    size,
                    image_size,
                });
            }

            continue;
        }

        if index == IMAGE_DIRECTORY_ENTRY_GLOBALPTR as usize
        {
            if size != 0 || virtual_address >= image_size && virtual_address != 0
            {
                eprintln!("PE global-pointer directory has an invalid RVA or nonzero size");
                return Err(PeValidationError::InvalidDataDirectoryRange {
                    index,
                    virtual_address,
                    size,
                    image_size,
                });
            }

            continue;
        }

        if virtual_address == 0 && size == 0
        {
            continue;
        }

        if virtual_address == 0 || size == 0
        {
            eprintln!("PE data directory has an incomplete range");
            return Err(PeValidationError::InvalidDataDirectoryRange {
                index,
                virtual_address,
                size,
                image_size,
            });
        }

        if index == IMAGE_DIRECTORY_ENTRY_SECURITY as usize
        {
            if virtual_address % PE_HEADER_ALIGNMENT != 0 || directory.VirtualAddress.checked_add(directory.Size).is_none()
            {
                eprintln!("PE certificate-table file range is misaligned or overflowing");
                return Err(PeValidationError::InvalidDataDirectoryRange {
                    index,
                    virtual_address,
                    size,
                    image_size,
                });
            }

            continue;
        }

        if virtual_address.checked_add(size).is_none_or(|end| end > image_size)
        {
            eprintln!("PE data directory extends beyond SizeOfImage");
            return Err(PeValidationError::InvalidDataDirectoryRange {
                index,
                virtual_address,
                size,
                image_size,
            });
        }
    }

    let (section_table_offset, section_table_size, _) = get_section_table_range(nt_headers, nt_headers_offset, section_count, size_of_headers)?;
    let entry_point_rva = nt_headers.OptionalHeader.AddressOfEntryPoint as usize;

    if entry_point_rva >= image_size && entry_point_rva != 0
    {
        eprintln!("PE entry point extends beyond SizeOfImage");
        return Err(PeValidationError::InvalidEntryPoint {
            entry_point_rva,
            image_size,
        });
    }

    Ok(ValidatedNtHeaders {
        section_table_offset,
        section_table_size,
        image_size,
    })
}


/// Validates PE identity fields and the header values required by every parser.
/// `nt_headers`: copied x64 NT headers.
///
/// Returns the declared section count, image size, and header size.
fn validate_header_fields(nt_headers: &IMAGE_NT_HEADERS64) -> Result<(usize, usize, usize), PeValidationError>
{
    if nt_headers.Signature != IMAGE_NT_SIGNATURE
    {
        eprintln!("PE NT signature is invalid");
        return Err(PeValidationError::InvalidNtSignature {
            signature: nt_headers.Signature,
        });
    }

    if nt_headers.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64
    {
        eprintln!("PE machine type is not x86-64");
        return Err(PeValidationError::UnsupportedMachine {
            machine: nt_headers.FileHeader.Machine,
        });
    }

    let required_optional_header_size = std::mem::offset_of!(IMAGE_OPTIONAL_HEADER64, NumberOfRvaAndSizes).checked_add(size_of::<u32>()).ok_or_else(|| {
        eprintln!("PE required optional-header size overflowed");
        PeValidationError::SectionTableRangeOverflow
    })?;

    if (nt_headers.FileHeader.SizeOfOptionalHeader as usize) < required_optional_header_size
    {
        eprintln!("PE optional header is too small for its required fields");
        return Err(PeValidationError::InvalidOptionalHeaderSize {
            size: nt_headers.FileHeader.SizeOfOptionalHeader,
        });
    }

    if nt_headers.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC
    {
        eprintln!("PE optional-header magic is not PE32+");
        return Err(PeValidationError::UnsupportedOptionalHeaderMagic {
            magic: nt_headers.OptionalHeader.Magic,
        });
    }

    let data_directory_offset = std::mem::offset_of!(IMAGE_OPTIONAL_HEADER64, DataDirectory);
    let available_directory_bytes = (nt_headers.FileHeader.SizeOfOptionalHeader as usize).saturating_sub(data_directory_offset);
    let available_directory_count = (available_directory_bytes / size_of::<IMAGE_DATA_DIRECTORY>()).min(nt_headers.OptionalHeader.DataDirectory.len());
    let declared_directory_count = nt_headers.OptionalHeader.NumberOfRvaAndSizes as usize;

    if declared_directory_count > available_directory_count
    {
        eprintln!("PE declares more data directories than its optional header contains");
        return Err(PeValidationError::InvalidDataDirectoryCount {
            declared_count: declared_directory_count,
            available_count: available_directory_count,
        });
    }

    let section_count = nt_headers.FileHeader.NumberOfSections as usize;

    if section_count == 0 || section_count > WINDOWS_IMAGE_SECTION_LIMIT
    {
        eprintln!("PE section count is outside the Windows loader limit");
        return Err(PeValidationError::InvalidSectionCount {
            count: nt_headers.FileHeader.NumberOfSections,
        });
    }

    let image_size = nt_headers.OptionalHeader.SizeOfImage as usize;

    if image_size == 0
    {
        eprintln!("PE SizeOfImage is zero");
        return Err(PeValidationError::InvalidImageSize);
    }

    let size_of_headers = nt_headers.OptionalHeader.SizeOfHeaders as usize;

    if size_of_headers == 0 || size_of_headers > image_size
    {
        eprintln!("PE SizeOfHeaders is zero or exceeds SizeOfImage");
        return Err(PeValidationError::InvalidHeadersSize {
            size_of_headers,
            image_size,
        });
    }

    Ok((section_count, image_size, size_of_headers))
}


/// Computes and validates the complete PE section-table range.
/// `nt_headers`: copied NT headers declaring the optional-header and section counts.
/// `nt_headers_offset`: DOS-header-relative NT-header offset.
/// `section_count`: validated number of section entries.
/// `size_of_headers`: validated mapped-header size.
///
/// Returns the table offset, byte size, and exclusive end.
fn get_section_table_range(nt_headers: &IMAGE_NT_HEADERS64, nt_headers_offset: usize, section_count: usize, size_of_headers: usize) -> Result<(usize, usize, usize), PeValidationError>
{
    let section_table_offset = nt_headers_offset.checked_add(std::mem::offset_of!(IMAGE_NT_HEADERS64, OptionalHeader)).and_then(|value| value.checked_add(nt_headers.FileHeader.SizeOfOptionalHeader as usize)).ok_or_else(|| {
        eprintln!("PE section-table offset overflowed");
        PeValidationError::SectionTableRangeOverflow
    })?;
    let section_table_size = section_count.checked_mul(size_of::<IMAGE_SECTION_HEADER>()).ok_or_else(|| {
        eprintln!("PE section-table size overflowed");
        PeValidationError::SectionTableRangeOverflow
    })?;
    let section_table_end = section_table_offset.checked_add(section_table_size).ok_or_else(|| {
        eprintln!("PE section-table range overflowed");
        PeValidationError::SectionTableRangeOverflow
    })?;

    if section_table_end > size_of_headers
    {
        eprintln!("PE section table extends beyond SizeOfHeaders");
        return Err(PeValidationError::SectionTableOutsideHeaders {
            section_table_end,
            size_of_headers,
        });
    }

    Ok((section_table_offset, section_table_size, section_table_end))
}


/// Reads the signature, COFF header, and only the declared optional-header bytes.
/// `bytes`: source bytes containing a bounded PE header.
/// `nt_headers_offset`: offset of the four-byte PE signature.
///
/// Returns an initialized fixed-size NT-header view without probing beyond the declared optional header.
pub(super) fn read_nt_headers(bytes: &[u8], nt_headers_offset: usize) -> Result<IMAGE_NT_HEADERS64, PeValidationError>
{
    // SAFETY: `u32` permits every bit pattern and contains no references.
    let signature = unsafe { read_data_value::<u32>(bytes, nt_headers_offset) }?;
    let file_header_offset = match nt_headers_offset.checked_add(size_of::<u32>())
    {
        Some(value) => value,
        None =>
        {
            eprintln!("PE file-header offset overflowed");
            return Err(PeValidationError::SectionTableRangeOverflow);
        }
    };

    // SAFETY: `IMAGE_FILE_HEADER` permits every bit pattern and contains no references.
    let file_header = unsafe { read_data_value::<IMAGE_FILE_HEADER>(bytes, file_header_offset) }?;
    let optional_header_offset = match file_header_offset.checked_add(size_of::<IMAGE_FILE_HEADER>())
    {
        Some(value) => value,
        None =>
        {
            eprintln!("PE optional-header offset overflowed");
            return Err(PeValidationError::SectionTableRangeOverflow);
        }
    };
    let optional_header_size = file_header.SizeOfOptionalHeader as usize;
    let optional_header_end = match optional_header_offset.checked_add(optional_header_size)
    {
        Some(value) => value,
        None =>
        {
            eprintln!("PE optional-header range overflowed");
            return Err(PeValidationError::SectionTableRangeOverflow);
        }
    };
    let optional_header_bytes = match bytes.get(optional_header_offset..optional_header_end)
    {
        Some(value) => value,
        None =>
        {
            eprintln!("PE optional header exceeds the available bytes");
            return Err(PeValidationError::DataTooSmall {
                offset: optional_header_offset,
                bytes_requested: optional_header_size,
                data_size: bytes.len(),
            });
        }
    };

    // SAFETY: all-zero bytes are valid for the integer-only Windows NT-header structure.
    let mut nt_headers: IMAGE_NT_HEADERS64 = unsafe { zeroed() };
    nt_headers.Signature = signature;
    nt_headers.FileHeader = file_header;

    let copied_optional_size = optional_header_bytes.len().min(size_of::<IMAGE_OPTIONAL_HEADER64>());

    // SAFETY: both buffers are valid for `copied_optional_size`, do not overlap, and the destination remains initialized beyond the copied prefix.
    unsafe { std::ptr::copy_nonoverlapping(optional_header_bytes.as_ptr(), &mut nt_headers.OptionalHeader as *mut IMAGE_OPTIONAL_HEADER64 as *mut u8, copied_optional_size) };

    Ok(nt_headers)
}


/// Reads copied section headers from a bounded byte range.
/// `bytes`: source bytes containing the complete section table.
/// `section_table_offset`: first section-header byte in the source.
/// `section_table_size`: complete section-table byte length.
/// `section_count`: validated number of section entries.
///
/// Returns owned section headers parsed with unaligned reads.
pub(super) fn read_section_headers(bytes: &[u8], section_table_offset: usize, section_table_size: usize, section_count: usize) -> Result<Vec<IMAGE_SECTION_HEADER>, PeValidationError>
{
    let expected_table_size = section_count.checked_mul(size_of::<IMAGE_SECTION_HEADER>()).ok_or_else(|| {
        eprintln!("PE section count overflows the section-table size");
        PeValidationError::SectionTableRangeOverflow
    })?;

    if section_table_size != expected_table_size
    {
        eprintln!("PE section-table size does not match its section count");
        return Err(PeValidationError::SectionTableSizeMismatch {
            expected_size: expected_table_size,
            actual_size: section_table_size,
        });
    }

    let section_table_end = section_table_offset.checked_add(section_table_size).ok_or_else(|| {
        eprintln!("PE section-table byte range overflowed");
        PeValidationError::SectionTableRangeOverflow
    })?;

    if section_table_end > bytes.len()
    {
        eprintln!("PE section table extends beyond the available bytes");
        return Err(PeValidationError::SectionTableOutsideData {
            section_table_end,
            data_size: bytes.len(),
        });
    }

    let mut sections = Vec::new();

    sections.try_reserve_exact(section_count).map_err(|_| {
        eprintln!("failed to allocate the PE section-header buffer");

        PeValidationError::SectionBufferAllocationFailed {
            section_count,
        }
    })?;

    for index in 0..section_count
    {
        let offset = section_table_offset + index * size_of::<IMAGE_SECTION_HEADER>();

        // SAFETY: the complete section-table range is checked above, and unaligned reads are permitted.
        let section = unsafe { std::ptr::read_unaligned(bytes.as_ptr().add(offset) as *const IMAGE_SECTION_HEADER) };

        sections.push(section);
    }

    Ok(sections)
}


/// Reads one bounded plain C-compatible value from local image bytes.
/// `bytes`: source mapped-image bytes.
/// `offset`: byte offset at which the value begins.
///
/// SAFETY: `T` must permit every possible bit pattern and contain no references.
/// Returns a copied value, or a precise range failure.
pub(super) unsafe fn read_data_value<T: Copy>(bytes: &[u8], offset: usize) -> Result<T, PeValidationError>
{
    let bytes_requested = size_of::<T>();
    let value_end = offset.checked_add(bytes_requested).ok_or_else(|| {
        eprintln!("PE typed-read range overflowed");

        PeValidationError::DataRangeOverflow {
            offset,
            bytes_requested,
        }
    })?;
    let value_bytes = bytes.get(offset..value_end).ok_or_else(|| {
        eprintln!("PE typed read exceeds the available bytes");

        PeValidationError::DataTooSmall {
            offset,
            bytes_requested,
            data_size: bytes.len(),
        }
    })?;

    // SAFETY: the checked slice contains a complete `T`, and unaligned reads are permitted.
    Ok(unsafe { std::ptr::read_unaligned(value_bytes.as_ptr() as *const T) })
}
