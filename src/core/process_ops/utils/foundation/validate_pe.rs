use core::mem::{size_of, zeroed};

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Diagnostics::Debug::{IMAGE_DATA_DIRECTORY, IMAGE_DIRECTORY_ENTRY_ARCHITECTURE, IMAGE_DIRECTORY_ENTRY_GLOBALPTR, IMAGE_DIRECTORY_ENTRY_SECURITY, IMAGE_FILE_EXECUTABLE_IMAGE, IMAGE_FILE_HEADER, IMAGE_NT_HEADERS64, IMAGE_NT_OPTIONAL_HDR64_MAGIC, IMAGE_OPTIONAL_HEADER64, IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_DISCARDABLE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SECTION_HEADER};
use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE, PAGE_GUARD, PAGE_NOACCESS};
use windows_sys::Win32::System::SystemInformation::IMAGE_FILE_MACHINE_AMD64;
use windows_sys::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE};

use crate::core::process_ops::utils::memutils::{self, MemoryRegion, MemoryRegionQueryError, MemoryRegionType, ProcessMemoryReadError};

/// Maximum section count accepted by the Windows image loader.
const WINDOWS_IMAGE_SECTION_LIMIT: usize = 96;

/// Maximum mapped size accepted for one PE32+ image.
const MAXIMUM_IMAGE_SIZE: usize = 0x8000_0000;

/// Maximum mapped-image snapshot materialized for one process collector.
const MAXIMUM_IMAGE_SNAPSHOT_SIZE: usize = 0x1000_0000;

/// Maximum temporary allocation used for one process-image read.
const IMAGE_SNAPSHOT_READ_CHUNK_SIZE: usize = 0x10_0000;

/// Maximum virtual-memory regions accepted for one loaded image.
const MAXIMUM_IMAGE_REGION_COUNT: usize = 4096;

/// Required alignment of the PE signature and COFF header.
const PE_HEADER_ALIGNMENT: usize = 8;

/// Minimum standard raw-file alignment for page-aligned images.
const MIN_FILE_ALIGNMENT: usize = 0x200;

/// Maximum PE raw-file alignment accepted by the format.
const MAX_FILE_ALIGNMENT: usize = 0x1_0000;

/// x64 page size used by the PE low-alignment rule.
const IMAGE_PAGE_SIZE: usize = 0x1000;

/// Mask containing the base page-protection value without protection modifiers.
const PAGE_BASE_PROTECTION_MASK: u32 = 0xFF;

/// Required alignment of the preferred PE image base.
const IMAGE_BASE_ALIGNMENT: u64 = 0x1_0000;

/// Final PE data-directory slot reserved by the format.
const RESERVED_DATA_DIRECTORY_INDEX: usize = 15;

/// Owns safely copied headers and sections from mapped PE bytes.
pub(crate) struct PeImage
{
    pub nt_headers: IMAGE_NT_HEADERS64,
    pub sections: Vec<IMAGE_SECTION_HEADER>,
    nt_headers_offset: usize,
}


/// Owns a bounded mapped-image snapshot, its validated PE view, and discarded ranges.
pub(crate) struct ValidatedPeSnapshot
{
    pub bytes: Vec<u8>,
    pub pe: PeImage,
    pub unavailable_ranges: Vec<UnavailablePeRange>,
}


/// Describes process-image bytes that the loader validly discarded after mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnavailablePeRange
{
    pub rva: usize,
    pub size: usize,
}


/// Describes a loaded image whose remote PE headers and mapping passed strict validation.
#[derive(Debug, Eq, PartialEq)]
pub struct ValidatedPeImage
{
    pub base_address: usize,
    pub image_size: usize,
    pub entry_point_rva: usize,
    pub section_count: u16,
    identity: Vec<u8>,
}


/// Identifies the remote PE component that could not be read completely.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeReadTarget
{
    DosHeader,
    NtHeaders,
    SectionTable,
    ImageSnapshot,
}


/// Explains why PE parsing or strict loaded-image validation failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PeValidationError
{
    InvalidProcessHandle,
    ImageBaseUnavailable,
    DataRangeOverflow
    {
        offset: usize,
        bytes_requested: usize,
    },
    DataTooSmall
    {
        offset: usize,
        bytes_requested: usize,
        data_size: usize,
    },
    InvalidDosSignature
    {
        signature: u16,
    },
    InvalidNtHeadersOffset
    {
        offset: i32,
    },
    InvalidNtSignature
    {
        signature: u32,
    },
    UnsupportedMachine
    {
        machine: u16,
    },
    MissingExecutableImageCharacteristic
    {
        characteristics: u16,
    },
    InvalidOptionalHeaderSize
    {
        size: u16,
    },
    UnsupportedOptionalHeaderMagic
    {
        magic: u16,
    },
    InvalidDataDirectoryCount
    {
        declared_count: usize,
        available_count: usize,
    },
    NonZeroReservedOptionalHeaderFields
    {
        win32_version_value: u32,
        loader_flags: u32,
    },
    InvalidSectionCount
    {
        count: u16,
    },
    InvalidImageAlignment
    {
        section_alignment: usize,
        file_alignment: usize,
    },
    InvalidImageSize,
    ImageSizeExceedsMaximum
    {
        image_size: usize,
        maximum_image_size: usize,
    },
    InvalidImageBase
    {
        image_base: u64,
    },
    ImageOutsideData
    {
        image_size: usize,
        data_size: usize,
    },
    ValidatedImageSizeMismatch
    {
        expected_size: usize,
        actual_size: usize,
    },
    ValidatedImageIdentityMismatch
    {
        expected_image_size: usize,
        actual_image_size: usize,
        expected_entry_point_rva: usize,
        actual_entry_point_rva: usize,
        expected_section_count: u16,
        actual_section_count: u16,
        expected_identity_hash: u64,
        actual_identity_hash: u64,
    },
    InvalidHeadersSize
    {
        size_of_headers: usize,
        image_size: usize,
    },
    HeadersOutsideData
    {
        size_of_headers: usize,
        data_size: usize,
    },
    SectionTableRangeOverflow,
    SectionTableOutsideHeaders
    {
        section_table_end: usize,
        size_of_headers: usize,
    },
    SectionTableOutsideData
    {
        section_table_end: usize,
        data_size: usize,
    },
    SectionTableSizeMismatch
    {
        expected_size: usize,
        actual_size: usize,
    },
    SectionBufferAllocationFailed
    {
        section_count: usize,
    },
    InvalidSectionLayout
    {
        index: usize,
        section_rva: usize,
    },
    InvalidSectionRawLayout
    {
        index: usize,
        raw_size: usize,
        raw_pointer: usize,
        file_alignment: usize,
    },
    InvalidSectionRange
    {
        index: usize,
        section_rva: usize,
        mapped_size: usize,
        image_size: usize,
    },
    OverlappingSections
    {
        index: usize,
        previous_end_rva: usize,
        section_rva: usize,
    },
    InvalidEntryPoint
    {
        entry_point_rva: usize,
        image_size: usize,
    },
    InvalidBaseOfCode
    {
        base_of_code_rva: usize,
        expected_base_of_code_rva: usize,
    },
    InvalidFinalImageSize
    {
        expected_image_size: usize,
        actual_image_size: usize,
    },
    InvalidDataDirectoryRange
    {
        index: usize,
        virtual_address: usize,
        size: usize,
        image_size: usize,
    },
    NtHeadersAddressOverflow
    {
        base_address: usize,
        nt_headers_offset: usize,
    },
    SectionTableAddressOverflow
    {
        base_address: usize,
        section_table_offset: usize,
    },
    RemoteReadFailed
    {
        target: PeReadTarget,
        address: usize,
        error: ProcessMemoryReadError,
    },
    ImageRangeOverflow
    {
        base_address: usize,
        image_size: usize,
    },
    ImageRegionQueryFailed
    {
        address: usize,
        error: MemoryRegionQueryError,
    },
    InvalidImageRegion
    {
        address: usize,
        allocation_base: usize,
        state: u32,
        region_type: MemoryRegionType,
    },
    ImageRegionRangeOverflow
    {
        base_address: usize,
        region_size: usize,
    },
    ImageRegionDidNotAdvance
    {
        address: usize,
        region_end: usize,
    },
    ImageRegionLimitExceeded
    {
        image_size: usize,
        maximum_region_count: usize,
    },
    UnreadableImageRegion
    {
        address: usize,
        state: u32,
        protect: u32,
    },
    ImageBufferAllocationFailed
    {
        image_size: usize,
    },
    IdentityBufferAllocationFailed
    {
        bytes_requested: usize,
    },
    ImageSnapshotSizeExceedsLimit
    {
        image_size: usize,
        maximum_snapshot_size: usize,
    },
}


/// Stores the strict NT-header facts needed to read and validate a section table.
struct ValidatedNtHeaders
{
    section_table_offset: usize,
    section_table_size: usize,
    image_size: usize,
}


/// Owns the strict remote-image facts needed while validating or copying a snapshot.
struct ValidatedProcessImageDetails
{
    validation: ValidatedPeImage,
    nt_headers: IMAGE_NT_HEADERS64,
    sections: Vec<IMAGE_SECTION_HEADER>,
}


/// Classifies whether one valid image region carries readable, absent, or inaccessible bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ImageRegionDisposition
{
    Readable,
    Padding,
    Discarded,
    Unreadable,
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


/// Strictly validates a loaded PE image in a target process.
/// `process`: an open handle with query and virtual-memory read access.
/// `image_base_address`: the candidate loaded-image allocation base.
///
/// Returns validated image facts only after headers, sections, and every mapped region agree.
pub(crate) fn validate_process_image(process: HANDLE, image_base_address: usize) -> Result<ValidatedPeImage, PeValidationError>
{
    Ok(validate_process_image_details(process, image_base_address)?.validation)
}


/// Copies a previously validated process image without requiring discarded sections to remain committed.
/// `process`: the same open process handle used for strict PEB and image validation.
/// `validation`: the exact remote-image facts that the snapshot must still match.
///
/// Returns a bounded snapshot, discarded-range metadata, and a strictly matched PE view.
pub(crate) fn read_validated_image(process: HANDLE, validation: &ValidatedPeImage) -> Result<ValidatedPeSnapshot, PeValidationError>
{
    let details = validate_process_image_details(process, validation.base_address)?;

    validate_image_identity(validation, &details.validation)?;

    let (bytes, unavailable_ranges) = read_process_image_bytes(process, validation.base_address, &details.nt_headers, &details.sections)?;
    let pe = validate_matching_image(validation, &bytes)?;

    Ok(ValidatedPeSnapshot {
        bytes,
        pe,
        unavailable_ranges,
    })
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


/// Validates raw-file PE headers against the exact identity captured from a loaded image.
/// `validation`: trusted facts collected from the target's mapped main image.
/// `file_data`: complete raw executable bytes containing the corresponding PE headers.
///
/// Returns parsed raw-file headers only when every semantic identity field matches.
pub(crate) fn validate_backing_file_identity(validation: &ValidatedPeImage, file_data: &[u8]) -> Result<PeImage, PeValidationError>
{
    let pe = parse_pe(file_data)?;
    let actual = ValidatedPeImage {
        base_address: validation.base_address,
        image_size: pe.nt_headers.OptionalHeader.SizeOfImage as usize,
        entry_point_rva: pe.nt_headers.OptionalHeader.AddressOfEntryPoint as usize,
        section_count: pe.nt_headers.FileHeader.NumberOfSections,
        identity: create_pe_identity(&pe.nt_headers, &pe.sections)?,
    };

    validate_image_identity(validation, &actual)?;

    Ok(pe)
}


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


/// Reports whether a snapshot range contains only bytes copied from readable image memory.
/// `snapshot`: validated mapped-image snapshot with discarded ranges recorded.
/// `rva`: first relative virtual address required by a collector.
/// `size`: exact number of required bytes.
///
/// Returns `true` only when the complete range is in bounds and available.
pub(crate) fn is_snapshot_range_available(snapshot: &ValidatedPeSnapshot, rva: usize, size: usize) -> bool
{
    let end_rva = match rva.checked_add(size)
    {
        Some(value) if value <= snapshot.bytes.len() => value,
        _ => return false,
    };
    if !is_image_data_range(&snapshot.pe.nt_headers, &snapshot.pe.sections, rva, size)
    {
        return false;
    }

    snapshot.unavailable_ranges.iter().all(|range| range.rva >= end_rva || range.rva.saturating_add(range.size) <= rva)
}


/// Revalidates a remote image and retains the copied headers needed for sparse reads.
/// `process`: an open target-process handle with query and virtual-memory read access.
/// `image_base_address`: candidate loaded-image allocation base.
///
/// Returns validated image facts and their exact header/section source.
fn validate_process_image_details(process: HANDLE, image_base_address: usize) -> Result<ValidatedProcessImageDetails, PeValidationError>
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

    // SAFETY: `IMAGE_DOS_HEADER` permits every bit pattern and contains no references.
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


/// Copies committed image regions and leaves valid discarded-section ranges zero filled.
/// `process`: an open target-process handle with virtual-memory read access.
/// `image_base_address`: validated loaded-image allocation base.
/// `nt_headers`: validated headers defining the complete image span.
/// `sections`: validated section table used to recognize discardable ranges.
///
/// Returns an RVA-indexed image buffer, discarded ranges, or the exact mapping/read failure.
fn read_process_image_bytes(process: HANDLE, image_base_address: usize, nt_headers: &IMAGE_NT_HEADERS64, sections: &[IMAGE_SECTION_HEADER]) -> Result<(Vec<u8>, Vec<UnavailablePeRange>), PeValidationError>
{
    let image_size = nt_headers.OptionalHeader.SizeOfImage as usize;

    if image_size > MAXIMUM_IMAGE_SNAPSHOT_SIZE
    {
        eprintln!("remote PE image is too large to materialize safely");
        return Err(PeValidationError::ImageSnapshotSizeExceedsLimit {
            image_size,
            maximum_snapshot_size: MAXIMUM_IMAGE_SNAPSHOT_SIZE,
        });
    }

    let image_end = image_base_address.checked_add(image_size).ok_or_else(|| {
        eprintln!("remote PE snapshot range overflowed");

        PeValidationError::ImageRangeOverflow {
            base_address: image_base_address,
            image_size,
        }
    })?;
    let mut bytes = Vec::new();
    let mut unavailable_ranges: Vec<UnavailablePeRange> = Vec::new();

    bytes.try_reserve_exact(image_size).map_err(|_| {
        eprintln!("failed to allocate the remote PE snapshot buffer");

        PeValidationError::ImageBufferAllocationFailed {
            image_size,
        }
    })?;
    bytes.resize(image_size, 0);
    unavailable_ranges.try_reserve_exact(sections.len()).map_err(|_| {
        eprintln!("failed to allocate the discarded PE range buffer");

        PeValidationError::ImageBufferAllocationFailed {
            image_size,
        }
    })?;

    let mut address = image_base_address;
    let mut region_count = 0;

    while address < image_end
    {
        if region_count == MAXIMUM_IMAGE_REGION_COUNT
        {
            eprintln!("remote PE snapshot exceeded the virtual-memory region limit");
            return Err(PeValidationError::ImageRegionLimitExceeded {
                image_size,
                maximum_region_count: MAXIMUM_IMAGE_REGION_COUNT,
            });
        }

        region_count += 1;

        let region = memutils::query_region(process, address).map_err(|error| {
            eprintln!("failed to query a remote PE snapshot region");

            PeValidationError::ImageRegionQueryFailed {
                address,
                error,
            }
        })?;
        let region_end = region.base_address.checked_add(region.region_size).ok_or_else(|| {
            eprintln!("remote PE snapshot region range overflowed");

            PeValidationError::ImageRegionRangeOverflow {
                base_address: region.base_address,
                region_size: region.region_size,
            }
        })?;

        if region.base_address > address || region_end <= address
        {
            eprintln!("remote PE snapshot region did not cover the requested address");
            return Err(PeValidationError::ImageRegionDidNotAdvance {
                address,
                region_end,
            });
        }

        let range_end = region_end.min(image_end);
        let disposition = validate_image_region(&region, address, range_end, image_base_address, nt_headers.OptionalHeader.SizeOfHeaders as usize, nt_headers.OptionalHeader.SectionAlignment as usize, sections)?;

        match disposition
        {
            ImageRegionDisposition::Readable =>
            {
                let mut read_address = address;

                while read_address < range_end
                {
                    let bytes_requested = (range_end - read_address).min(IMAGE_SNAPSHOT_READ_CHUNK_SIZE);
                    let region_bytes = memutils::read_exact(process, bytes_requested, read_address).map_err(|error| {
                        eprintln!("failed to read a committed remote PE snapshot region");

                        PeValidationError::RemoteReadFailed {
                            target: PeReadTarget::ImageSnapshot,
                            address: read_address,
                            error,
                        }
                    })?;
                    let buffer_offset = read_address - image_base_address;
                    let buffer_end = buffer_offset + bytes_requested;

                    bytes[buffer_offset..buffer_end].copy_from_slice(&region_bytes);
                    read_address += bytes_requested;
                }
            }
            ImageRegionDisposition::Padding =>
            {}
            ImageRegionDisposition::Discarded =>
            {
                let rva = address - image_base_address;
                let size = range_end - address;
                let mut merged = false;

                if let Some(previous) = unavailable_ranges.last_mut()
                {
                    if previous.rva.checked_add(previous.size) == Some(rva)
                    {
                        previous.size += size;
                        merged = true;
                    }
                }

                if !merged
                {
                    unavailable_ranges.try_reserve(1).map_err(|_| {
                        eprintln!("failed to grow the discarded PE range buffer");

                        PeValidationError::ImageBufferAllocationFailed {
                            image_size,
                        }
                    })?;
                    unavailable_ranges.push(UnavailablePeRange {
                        rva,
                        size,
                    });
                }
            }
            ImageRegionDisposition::Unreadable =>
            {
                eprintln!("committed remote PE data is not readable");
                return Err(PeValidationError::UnreadableImageRegion {
                    address,
                    state: region.state,
                    protect: region.protect,
                });
            }
        }

        address = region_end;
    }

    Ok((bytes, unavailable_ranges))
}


/// Confirms that two strict image-validation records describe the same PE identity.
/// `expected`: previously trusted remote-image facts.
/// `actual`: newly collected or locally parsed image facts.
///
/// Returns unit only when all critical identity fields still agree.
fn validate_image_identity(expected: &ValidatedPeImage, actual: &ValidatedPeImage) -> Result<(), PeValidationError>
{
    if actual.image_size != expected.image_size || actual.entry_point_rva != expected.entry_point_rva || actual.section_count != expected.section_count || actual.identity != expected.identity
    {
        eprintln!("validated PE identities do not match");
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


/// Validates section ordering, alignment, ranges, overlap, and entry-point containment.
/// `nt_headers`: copied x64 NT headers defining the loaded image.
/// `sections`: the complete section table associated with the headers.
///
/// Returns `Ok(())` only when every mapped section fits the declared loaded image.
fn validate_section_layout(nt_headers: &IMAGE_NT_HEADERS64, sections: &[IMAGE_SECTION_HEADER]) -> Result<(), PeValidationError>
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
fn validate_data_directory_layout(nt_headers: &IMAGE_NT_HEADERS64, sections: &[IMAGE_SECTION_HEADER]) -> Result<(), PeValidationError>
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


/// Reports whether one RVA range is fully backed by mapped headers or section data.
/// `nt_headers`: validated headers defining image and header bounds.
/// `sections`: validated section table in ascending RVA order.
/// `rva`: first required relative virtual address.
/// `size`: exact required byte length.
///
/// Returns `true` only when the complete range avoids alignment padding.
fn is_image_data_range(nt_headers: &IMAGE_NT_HEADERS64, sections: &[IMAGE_SECTION_HEADER], rva: usize, size: usize) -> bool
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


/// Validates the DOS header and returns its bounded non-negative NT-header offset.
/// `dos_header`: copied DOS header from mapped bytes or target-process memory.
///
/// Returns the NT-header offset, or a signature/offset failure.
fn validate_dos_header(dos_header: &IMAGE_DOS_HEADER) -> Result<usize, PeValidationError>
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
fn validate_nt_headers(nt_headers: &IMAGE_NT_HEADERS64, nt_headers_offset: usize) -> Result<ValidatedNtHeaders, PeValidationError>
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
fn read_nt_headers(bytes: &[u8], nt_headers_offset: usize) -> Result<IMAGE_NT_HEADERS64, PeValidationError>
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
fn read_section_headers(bytes: &[u8], section_table_offset: usize, section_table_size: usize, section_count: usize) -> Result<Vec<IMAGE_SECTION_HEADER>, PeValidationError>
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
unsafe fn read_data_value<T: Copy>(bytes: &[u8], offset: usize) -> Result<T, PeValidationError>
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


/// Reads one exact typed PE value from target-process memory.
/// `process`: an open target-process handle with virtual-memory read access.
/// `address`: target-process address containing the value.
/// `target`: PE component being read for error reporting.
///
/// SAFETY: `T` must permit every possible bit pattern and contain no references.
/// Returns the copied value or a stage-specific remote-read failure.
unsafe fn read_remote_value<T: Copy>(process: HANDLE, address: usize, target: PeReadTarget) -> Result<T, PeValidationError>
{
    // SAFETY: callers use only Windows PE structs composed of integer, byte-array, and raw-union fields.
    unsafe { memutils::read_value(process, address) }.map_err(|error| {
        eprintln!("failed to read a typed remote PE value");

        PeValidationError::RemoteReadFailed {
            target,
            address,
            error,
        }
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
    let prefix = memutils::read_exact(process, prefix_size, nt_headers_address).map_err(|error| {
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
    let header_bytes = memutils::read_exact(process, complete_size, nt_headers_address).map_err(|error| {
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
    let section_bytes = memutils::read_exact(process, validated_headers.section_table_size, section_table_address).map_err(|error| {
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

        // SAFETY: `Misc.VirtualSize` is the image-section union member used for loaded images.
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

        PeValidationError::ImageRangeOverflow {
            base_address: image_base_address,
            image_size,
        }
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

        let region = memutils::query_region(process, address).map_err(|error| {
            eprintln!("failed to query a remote PE mapping region");

            PeValidationError::ImageRegionQueryFailed {
                address,
                error,
            }
        })?;
        let region_end = region.base_address.checked_add(region.region_size).ok_or_else(|| {
            eprintln!("remote PE mapping region range overflowed");

            PeValidationError::ImageRegionRangeOverflow {
                base_address: region.base_address,
                region_size: region.region_size,
            }
        })?;

        if region.base_address > address || region_end <= address
        {
            eprintln!("remote PE mapping region did not cover the requested address");
            return Err(PeValidationError::ImageRegionDidNotAdvance {
                address,
                region_end,
            });
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
fn validate_image_region(region: &MemoryRegion, range_start: usize, range_end: usize, image_base_address: usize, size_of_headers: usize, section_alignment: usize, sections: &[IMAGE_SECTION_HEADER]) -> Result<ImageRegionDisposition, PeValidationError>
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
