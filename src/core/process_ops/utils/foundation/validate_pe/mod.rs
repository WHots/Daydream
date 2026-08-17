mod locations;
mod parsing;
mod process;
mod snapshot;

use windows_sys::Win32::System::Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER};

use crate::core::process_ops::utils::memutils::{MemoryRegionQueryError, MemoryRegionType, ProcessMemoryReadError};

pub(crate) use locations::{collect_sections_from_pe, get_data_directory, get_file_offset_from_pe, get_mapped_section_size};
pub(crate) use process::validate_process_image;
pub(crate) use snapshot::{is_snapshot_range_available, read_validated_image};

/// Maximum virtual-memory regions accepted for one loaded image.
const MAXIMUM_IMAGE_REGION_COUNT: usize = 4096;

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
