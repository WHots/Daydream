use core::mem::size_of;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Diagnostics::Debug::{IMAGE_FILE_HEADER, IMAGE_NT_HEADERS64, IMAGE_SCN_MEM_DISCARDABLE, IMAGE_SECTION_HEADER};
use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE, PAGE_GUARD, PAGE_NOACCESS};
use windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER;

use crate::core::process_ops::utils::mem::{self, MemoryRegion, MemoryRegionType};

use super::locations::get_mapped_section_size;
use super::parsing::{read_data_value, read_nt_headers, read_section_headers, validate_data_directory_layout, validate_dos_header, validate_nt_headers, validate_pe, validate_section_layout, ValidatedNtHeaders};
use super::{PeImage, PeReadTarget, PeValidationError, ValidatedPeImage, MAXIMUM_IMAGE_REGION_COUNT};

/// Mask containing the base page-protection value without protection modifiers.
const PAGE_BASE_PROTECTION_MASK: u32 = 0xFF;

/// Owns the strict remote-image facts needed while validating or copying a snapshot.
pub(super) struct ValidatedProcessImageDetails
{
    pub(super) validation: ValidatedPeImage,
    pub(super) nt_headers: IMAGE_NT_HEADERS64,
    pub(super) sections: Vec<IMAGE_SECTION_HEADER>,
}

/// Classifies whether one valid image region carries readable, absent, or inaccessible bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ImageRegionDisposition
{
    Readable,
    Padding,
    Discarded,
    Unreadable,
}

/// Strictly validates a loaded PE image in a target process.
/// `process`: an open handle with query and virtual-memory read access.
/// `image_base_address`: the candidate loaded-image allocation base.
///
/// Returns validated image facts only after headers, sections, and every mapped region agree.
pub(crate) fn validate_process_image(process: HANDLE, image_base_address: usize) -> Result<ValidatedPeImage, PeValidationError>
{
    Ok(validate_process_image_details(process, image_base_address)?.validation)
}


/// Strictly validates copied mapped-image bytes against previously validated image facts.
/// `validation`: facts returned by strict remote-image validation.
/// `pe_data`: subsequently copied mapped-image bytes indexed by RVA.
///
/// Returns the parsed image only when strict validation and critical image identity agree.
pub(crate) fn validate_matching_image(validation: &ValidatedPeImage, pe_data: &[u8]) -> Result<PeImage, PeValidationError>
{
    if pe_data.len() != validation.image_size
    {
        return Err(PeValidationError::ValidatedImageSizeMismatch {
            expected_size: validation.image_size,
            actual_size: pe_data.len(),
        });
    }

    let pe = validate_pe(pe_data)?;
    let actual_image_size = pe.nt_headers.OptionalHeader.SizeOfImage as usize;
    let actual_entry_point_rva = pe.nt_headers.OptionalHeader.AddressOfEntryPoint as usize;
    let actual_section_count = pe.nt_headers.FileHeader.NumberOfSections;

    let actual_validation = ValidatedPeImage {
        base_address: validation.base_address,
        image_size: actual_image_size,
        entry_point_rva: actual_entry_point_rva,
        section_count: actual_section_count,
        identity: create_pe_identity(&pe.nt_headers, &pe.sections)?,
    };

    validate_image_identity(validation, &actual_validation)?;

    Ok(pe)
}


/// Revalidates a remote image and retains the copied headers needed for sparse reads.
/// `process`: an open target-process handle with query and virtual-memory read access.
/// `image_base_address`: candidate loaded-image allocation base.
///
/// Returns validated image facts and their exact header/section source.
pub(super) fn validate_process_image_details(process: HANDLE, image_base_address: usize) -> Result<ValidatedProcessImageDetails, PeValidationError>
{
    if process.is_null()
    {
        eprintln!("cannot validate a PE through a null process handle");
        return Err(PeValidationError::InvalidProcessHandle);
    }

    if image_base_address == 0
    {
        eprintln!("cannot validate a PE at a null image base");
        return Err(PeValidationError::ImageBaseUnavailable);
    }

    let dos_header = unsafe { read_remote_value::<IMAGE_DOS_HEADER>(process, image_base_address, PeReadTarget::DosHeader) }?;
    let nt_headers_offset = validate_dos_header(&dos_header)?;

    let nt_headers_address = image_base_address.checked_add(nt_headers_offset).ok_or_else(|| {
        eprintln!("remote PE NT-header address overflowed");

        PeValidationError::NtHeadersAddressOverflow {
            base_address: image_base_address,
            nt_headers_offset,
        }
    })?;

    let nt_headers = read_remote_nt_headers(process, nt_headers_address)?;
    let validated_headers = validate_nt_headers(&nt_headers, nt_headers_offset)?;

    if image_base_address.checked_add(validated_headers.image_size).is_none()
    {
        eprintln!("remote PE image range overflowed");
        return Err(PeValidationError::ImageRangeOverflow {
            base_address: image_base_address,
            image_size: validated_headers.image_size,
        });
    }

    let sections = read_remote_section_headers(process, image_base_address, &nt_headers, &validated_headers)?;

    validate_section_layout(&nt_headers, &sections)?;
    validate_data_directory_layout(&nt_headers, &sections)?;
    validate_process_image_mapping(process, image_base_address, &nt_headers, &sections)?;

    let validation = ValidatedPeImage {
        base_address: image_base_address,
        image_size: validated_headers.image_size,
        entry_point_rva: nt_headers.OptionalHeader.AddressOfEntryPoint as usize,
        section_count: nt_headers.FileHeader.NumberOfSections,
        identity: create_pe_identity(&nt_headers, &sections)?,
    };

    Ok(ValidatedProcessImageDetails {
        validation,
        nt_headers,
        sections,
    })
}


/// Confirms that two strict image-validation records describe the same PE identity.
/// `expected`: previously trusted remote-image facts.
/// `actual`: newly collected or locally parsed image facts.
///
/// Returns unit only when all critical identity fields still agree.
pub(super) fn validate_image_identity(expected: &ValidatedPeImage, actual: &ValidatedPeImage) -> Result<(), PeValidationError>
{
    if actual.image_size != expected.image_size || actual.entry_point_rva != expected.entry_point_rva || actual.section_count != expected.section_count || actual.identity != expected.identity
    {
        return Err(PeValidationError::ValidatedImageIdentityMismatch {
            expected_image_size: expected.image_size,
            actual_image_size: actual.image_size,
            expected_entry_point_rva: expected.entry_point_rva,
            actual_entry_point_rva: actual.entry_point_rva,
            expected_section_count: expected.section_count,
            actual_section_count: actual.section_count,
            expected_identity_hash: calculate_identity_hash(&expected.identity),
            actual_identity_hash: calculate_identity_hash(&actual.identity),
        });
    }

    Ok(())
}


/// Reads one exact typed PE value from target-process memory.
/// `process`: an open target-process handle with virtual-memory read access.
/// `address`: target-process address containing the value.
/// `target`: PE component being read for error reporting.
///
/// SAFETY: `T` must permit every possible bit pattern and contain no references.
/// Returns the copied value or a stage-specific remote-read failure.
unsafe fn read_remote_value<T: Copy>(process: HANDLE, address: usize, target: PeReadTarget) -> Result<T, PeValidationError>
{
    unsafe { mem::read_value(process, address) }.map_err(|error| {

        eprintln!("failed to read a typed remote PE value");

        PeValidationError::RemoteReadFailed {target, address, error}
    })
}


/// Reads a remote NT header using its declared optional-header size.
/// `process`: an open target-process handle with virtual-memory read access.
/// `nt_headers_address`: address of the four-byte PE signature.
///
/// Returns a bounded initialized NT-header view or a stage-specific read failure.
fn read_remote_nt_headers(process: HANDLE, nt_headers_address: usize) -> Result<IMAGE_NT_HEADERS64, PeValidationError>
{
    let prefix_size = size_of::<u32>() + size_of::<IMAGE_FILE_HEADER>();

    let prefix = mem::read_exact(process, prefix_size, nt_headers_address).map_err(|error| {
        
        eprintln!("failed to read the remote PE signature and COFF header");

        PeValidationError::RemoteReadFailed {
            target: PeReadTarget::NtHeaders,
            address: nt_headers_address,
            error,
        }
    })?;

    // SAFETY: `IMAGE_FILE_HEADER` permits every bit pattern and contains no references.
    let file_header = unsafe { read_data_value::<IMAGE_FILE_HEADER>(&prefix, size_of::<u32>()) }?;
    let complete_size = match prefix_size.checked_add(file_header.SizeOfOptionalHeader as usize)
    {
        Some(value) => value,
        None =>
        {
            eprintln!("remote PE optional-header range overflowed");
            return Err(PeValidationError::SectionTableRangeOverflow);
        }
    };
    let header_bytes = mem::read_exact(process, complete_size, nt_headers_address).map_err(|error| {
        
        eprintln!("failed to read the declared remote PE optional header");

        PeValidationError::RemoteReadFailed {
            target: PeReadTarget::NtHeaders,
            address: nt_headers_address,
            error,
        }
    })?;

    read_nt_headers(&header_bytes, 0)
}


/// Reads the complete remote section table selected by validated NT headers.
/// `process`: an open target-process handle with virtual-memory read access.
/// `image_base_address`: loaded-image allocation base.
/// `nt_headers`: copied NT headers declaring the section count.
/// `validated_headers`: strict header facts containing the table range.
///
/// Returns owned section headers only after one complete bounded remote read.
fn read_remote_section_headers(process: HANDLE, image_base_address: usize, nt_headers: &IMAGE_NT_HEADERS64, validated_headers: &ValidatedNtHeaders) -> Result<Vec<IMAGE_SECTION_HEADER>, PeValidationError>
{
    let section_table_address = image_base_address.checked_add(validated_headers.section_table_offset).ok_or_else(|| {
        
        eprintln!("remote PE section-table address overflowed");

        PeValidationError::SectionTableAddressOverflow {
            base_address: image_base_address,
            section_table_offset: validated_headers.section_table_offset,
        }
    })?;
    let section_bytes = mem::read_exact(process, validated_headers.section_table_size, section_table_address).map_err(|error| {
        eprintln!("failed to read the remote PE section table");

        PeValidationError::RemoteReadFailed {
            target: PeReadTarget::SectionTable,
            address: section_table_address,
            error,
        }
    })?;

    read_section_headers(&section_bytes, 0, validated_headers.section_table_size, nt_headers.FileHeader.NumberOfSections as usize)
}


/// Serializes critical PE and section-table fields into an exact comparison identity.
/// `nt_headers`: strictly validated copied NT headers.
/// `sections`: strictly validated complete section table.
///
/// Returns deterministic identity bytes or a bounded allocation failure.
fn create_pe_identity(nt_headers: &IMAGE_NT_HEADERS64, sections: &[IMAGE_SECTION_HEADER]) -> Result<Vec<u8>, PeValidationError>
{
    let bytes_requested = match sections.len().checked_mul(size_of::<IMAGE_SECTION_HEADER>()).and_then(|section_bytes| size_of::<IMAGE_NT_HEADERS64>().checked_add(section_bytes))
    {
        Some(value) => value,
        None =>
        {
            eprintln!("PE identity buffer size overflowed");
            return Err(PeValidationError::IdentityBufferAllocationFailed {
                bytes_requested: usize::MAX,
            });
        }
    };
    let mut identity = Vec::new();

    identity.try_reserve_exact(bytes_requested).map_err(|_| {
        eprintln!("failed to allocate the exact PE identity buffer");

        PeValidationError::IdentityBufferAllocationFailed {
            bytes_requested,
        }
    })?;

    identity.extend_from_slice(&nt_headers.Signature.to_le_bytes());
    identity.extend_from_slice(&nt_headers.FileHeader.Machine.to_le_bytes());
    identity.extend_from_slice(&nt_headers.FileHeader.NumberOfSections.to_le_bytes());
    identity.extend_from_slice(&nt_headers.FileHeader.TimeDateStamp.to_le_bytes());
    identity.extend_from_slice(&nt_headers.FileHeader.SizeOfOptionalHeader.to_le_bytes());
    identity.extend_from_slice(&nt_headers.FileHeader.Characteristics.to_le_bytes());
    identity.extend_from_slice(&nt_headers.OptionalHeader.Magic.to_le_bytes());
    identity.extend_from_slice(&nt_headers.OptionalHeader.AddressOfEntryPoint.to_le_bytes());
    identity.extend_from_slice(&nt_headers.OptionalHeader.BaseOfCode.to_le_bytes());
    identity.extend_from_slice(&nt_headers.OptionalHeader.ImageBase.to_le_bytes());
    identity.extend_from_slice(&nt_headers.OptionalHeader.SectionAlignment.to_le_bytes());
    identity.extend_from_slice(&nt_headers.OptionalHeader.FileAlignment.to_le_bytes());
    identity.extend_from_slice(&nt_headers.OptionalHeader.SizeOfImage.to_le_bytes());
    identity.extend_from_slice(&nt_headers.OptionalHeader.SizeOfHeaders.to_le_bytes());
    identity.extend_from_slice(&nt_headers.OptionalHeader.CheckSum.to_le_bytes());
    identity.extend_from_slice(&nt_headers.OptionalHeader.Subsystem.to_le_bytes());
    identity.extend_from_slice(&nt_headers.OptionalHeader.DllCharacteristics.to_le_bytes());
    identity.extend_from_slice(&nt_headers.OptionalHeader.NumberOfRvaAndSizes.to_le_bytes());

    for directory in nt_headers.OptionalHeader.DataDirectory.iter().take(nt_headers.OptionalHeader.NumberOfRvaAndSizes as usize)
    {
        identity.extend_from_slice(&directory.VirtualAddress.to_le_bytes());
        identity.extend_from_slice(&directory.Size.to_le_bytes());
    }

    for section in sections
    {
        identity.extend_from_slice(&section.Name);

        let virtual_size = unsafe { section.Misc.VirtualSize };

        identity.extend_from_slice(&virtual_size.to_le_bytes());
        identity.extend_from_slice(&section.VirtualAddress.to_le_bytes());
        identity.extend_from_slice(&section.SizeOfRawData.to_le_bytes());
        identity.extend_from_slice(&section.PointerToRawData.to_le_bytes());
        identity.extend_from_slice(&section.Characteristics.to_le_bytes());
    }

    Ok(identity)
}


/// Calculates a compact diagnostic hash for already exact PE identity bytes.
/// `identity`: deterministic semantic PE identity bytes.
///
/// Returns FNV-1a output used only for mismatch diagnostics.
fn calculate_identity_hash(identity: &[u8]) -> u64
{
    let mut hash = 0xCBF2_9CE4_8422_2325u64;

    for byte in identity
    {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100_0000_01B3);
    }

    hash
}


/// Confirms that every region spanning a loaded image belongs to one valid image mapping.
/// `process`: an open target-process handle with query access.
/// `image_base_address`: validated image allocation base.
/// `nt_headers`: validated headers defining the image size and section alignment.
/// `sections`: validated section table used to recognize discarded ranges.
///
/// Returns unit only when committed ranges remain `MEM_IMAGE` and reserved ranges are valid padding or discarded data.
fn validate_process_image_mapping(process: HANDLE, image_base_address: usize, nt_headers: &IMAGE_NT_HEADERS64, sections: &[IMAGE_SECTION_HEADER]) -> Result<(), PeValidationError>
{
    let image_size = nt_headers.OptionalHeader.SizeOfImage as usize;
    let section_alignment = nt_headers.OptionalHeader.SectionAlignment as usize;
    
    let image_end = image_base_address.checked_add(image_size).ok_or_else(|| {
        
        eprintln!("remote PE mapping range overflowed");

        PeValidationError::ImageRangeOverflow {base_address: image_base_address, image_size}
    })?;

    let mut address = image_base_address;
    let mut region_count = 0;

    while address < image_end
    {
        if region_count == MAXIMUM_IMAGE_REGION_COUNT
        {
            eprintln!("remote PE mapping exceeded the virtual-memory region limit");
            return Err(PeValidationError::ImageRegionLimitExceeded {
                image_size,
                maximum_region_count: MAXIMUM_IMAGE_REGION_COUNT,
            });
        }

        region_count += 1;

        let region = mem::query_region(process, address).map_err(|error| {
            eprintln!("failed to query a remote PE mapping region");

            PeValidationError::ImageRegionQueryFailed {address, error}
        })?;

        let region_end = region.base_address.checked_add(region.region_size).ok_or_else(|| {
            eprintln!("remote PE mapping region range overflowed");

            PeValidationError::ImageRegionRangeOverflow {base_address: region.base_address, region_size: region.region_size}
        })?;

        if region.base_address > address || region_end <= address
        {
            eprintln!("remote PE mapping region did not cover the requested address");

            return Err(PeValidationError::ImageRegionDidNotAdvance {address, region_end});
        }

        let range_end = region_end.min(image_end);

        validate_image_region(&region, address, range_end, image_base_address, nt_headers.OptionalHeader.SizeOfHeaders as usize, section_alignment, sections)?;

        address = region_end;
    }

    Ok(())
}


/// Validates one queried image range and classifies its snapshot availability.
/// `region`: virtual-memory metadata covering the requested address.
/// `range_start`: first address from this region inside the image.
/// `range_end`: exclusive end of this region inside the image.
/// `image_base_address`: validated image allocation base.
/// `size_of_headers`: validated mapped-header extent.
/// `section_alignment`: validated PE section alignment.
/// `sections`: validated section table used to recognize discardable data and padding.
///
/// Returns a disposition only after the range remains part of the validated image allocation.
pub(super) fn validate_image_region(region: &MemoryRegion, range_start: usize, range_end: usize, image_base_address: usize, size_of_headers: usize, section_alignment: usize, sections: &[IMAGE_SECTION_HEADER]) -> Result<ImageRegionDisposition, PeValidationError>
{
    if range_start < image_base_address || range_end <= range_start || region.allocation_base != image_base_address
    {
        
        eprintln!("remote PE region has invalid bounds or belongs to a different allocation");

        return Err(PeValidationError::InvalidImageRegion {
            address: range_start,
            allocation_base: region.allocation_base,
            state: region.state,
            region_type: region.region_type,
        });
    }

    let start_rva = range_start - image_base_address;
    let end_rva = range_end - image_base_address;

    if region.state == MEM_RESERVE
    {
        if let Some(disposition) = classify_unavailable_image_range(start_rva, end_rva, size_of_headers, section_alignment, sections)
        {
            return Ok(disposition);
        }

        eprintln!("reserved remote PE range contains required image bytes");
        return Err(PeValidationError::InvalidImageRegion {
            address: range_start,
            allocation_base: region.allocation_base,
            state: region.state,
            region_type: region.region_type,
        });
    }

    if region.state != MEM_COMMIT || region.region_type != MemoryRegionType::Image
    {
        eprintln!("remote PE region is not backed by committed image memory");
        
        return Err(PeValidationError::InvalidImageRegion {
            address: range_start,
            allocation_base: region.allocation_base,
            state: region.state,
            region_type: region.region_type,
        });
    }

    let base_protection = region.protect & PAGE_BASE_PROTECTION_MASK;

    if region.protect & PAGE_GUARD != 0 || base_protection == PAGE_NOACCESS || base_protection == PAGE_EXECUTE
    {
        if classify_unavailable_image_range(start_rva, end_rva, size_of_headers, section_alignment, sections) == Some(ImageRegionDisposition::Padding)
        {
            return Ok(ImageRegionDisposition::Padding);
        }

        return Ok(ImageRegionDisposition::Unreadable);
    }

    Ok(ImageRegionDisposition::Readable)
}


/// Classifies an unavailable RVA range as loader padding or discarded section data.
/// `range_start_rva`: first RVA in the unavailable memory range.
/// `range_end_rva`: exclusive end RVA of the unavailable memory range.
/// `size_of_headers`: validated mapped-header extent.
/// `section_alignment`: validated PE section alignment.
/// `sections`: validated section table in ascending RVA order.
///
/// Returns a disposition only when no unavailable byte belongs to required section data.
fn classify_unavailable_image_range(range_start_rva: usize, range_end_rva: usize, size_of_headers: usize, section_alignment: usize, sections: &[IMAGE_SECTION_HEADER]) -> Option<ImageRegionDisposition>
{
    if range_start_rva >= range_end_rva
    {
        eprintln!("unavailable PE range has invalid bounds");
        return None;
    }

    let mut covered_end_rva = range_start_rva;
    let mut includes_discarded_data = false;

    if let Some(first_section) = sections.first()
    {
        let first_section_rva = first_section.VirtualAddress as usize;

        if covered_end_rva >= size_of_headers && covered_end_rva < first_section_rva
        {
            covered_end_rva = first_section_rva.min(range_end_rva);

            if covered_end_rva == range_end_rva
            {
                return Some(ImageRegionDisposition::Padding);
            }
        }
    }

    for section in sections
    {
        let section_start_rva = section.VirtualAddress as usize;

        let mapped_end_rva = match section_start_rva.checked_add(get_mapped_section_size(section))
        {
            Some(value) => value,
            None =>
            {
                eprintln!("unavailable PE section data range overflowed");
                return None;
            }
        };

        let section_slot_end_rva = match mapped_end_rva.checked_next_multiple_of(section_alignment)
        {
            Some(value) => value,
            None =>
            {
                eprintln!("unavailable PE section slot range overflowed");
                return None;
            }
        };

        if section.Characteristics & IMAGE_SCN_MEM_DISCARDABLE != 0 && covered_end_rva >= section_start_rva && covered_end_rva < mapped_end_rva
        {
            covered_end_rva = mapped_end_rva.min(range_end_rva);
            includes_discarded_data = true;

            if covered_end_rva == range_end_rva
            {
                return Some(ImageRegionDisposition::Discarded);
            }
        }

        if covered_end_rva >= mapped_end_rva && covered_end_rva < section_slot_end_rva
        {
            covered_end_rva = section_slot_end_rva.min(range_end_rva);

            if covered_end_rva == range_end_rva
            {
                if includes_discarded_data
                {
                    return Some(ImageRegionDisposition::Discarded);
                }

                return Some(ImageRegionDisposition::Padding);
            }
        }
    }

    eprintln!("unavailable PE range contains required image data");
    None
}
