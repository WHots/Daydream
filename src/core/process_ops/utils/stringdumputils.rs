use windows_sys::Win32::Foundation::{GetLastError, HANDLE, NTSTATUS};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
    PAGE_GUARD, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
};
use windows_sys::Win32::System::Threading::GetProcessId;

use crate::core::process_ops::utils::foundation::validate_pe::{self, ValidatedPeSnapshot};
use crate::core::process_ops::utils::memutils::{self, MemoryRegion, MemoryRegionQueryError, ProcessMemoryReadError};
use crate::core::process_ops::utils::pe_utils;
use crate::core::process_ops::utils::processutils::{ProcessPeValidationError, ValidatedProcessPe};
use crate::core::process_ops::utils::strings::{self, StringEncoding};
use crate::core::process_ops::utils::tebutils::ThreadTebInfo;

/// Mask containing the base page-protection value without protection modifiers.
const PAGE_BASE_PROTECTION_MASK: u32 = 0xFF;

/// Scanned-byte interval between string progress updates.
const STRING_PROGRESS_BYTE_INTERVAL: usize = 64 * 1024;

/// Describes one decoded string found in the loaded main module.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MainModuleString
{
    pub value: Box<str>,
    pub encoding: StringEncoding,
    pub address: usize,
    pub rva: usize,
    pub file_offset: Option<usize>,
}


/// Owns decoded main-module strings and ranges unavailable because the loader discarded them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MainModuleStringCollection
{
    pub module_base_address: usize,
    pub module_size: usize,
    pub strings: Vec<MainModuleString>,
    pub unavailable_ranges: Vec<validate_pe::UnavailablePeRange>,
}


/// Describes one decoded string stored directly in a thread stack.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TebStackString
{
    pub thread_id: u32,
    pub value: Box<str>,
    pub encoding: StringEncoding,
    pub address: usize,
    pub stack_offset: usize,
}


/// Owns every decoded string and region-read failure collected from one TEB-described stack.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TebStackStringCollection
{
    pub thread_id: u32,
    pub teb_address: usize,
    pub stack_base: usize,
    pub stack_limit: usize,
    pub bytes_read: usize,
    pub strings: Vec<TebStackString>,
    pub failures: Vec<TebStackRegionFailure>,
}


/// Associates one stack-memory range with the reason it could not be read completely.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TebStackRegionFailure
{
    pub address: usize,
    pub bytes_requested: usize,
    pub error: TebStackRegionReadError,
}


/// Explains why one readable stack-memory region was not copied completely.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TebStackRegionReadError
{
    ReadFailed(ProcessMemoryReadError),
    ReadIncomplete
    {
        status: NTSTATUS,
        bytes_read: usize,
    },
}


/// Explains why main-module string collection could not complete.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MainModuleStringCollectionError
{
    ProcessValidationFailed(ProcessPeValidationError),
    InvalidMainModulePe(validate_pe::PeValidationError),
}


/// Explains why one TEB-described stack scan could not safely reach its next memory region.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TebStackStringCollectionError
{
    InvalidProcessHandle,
    ProcessIdUnavailable
    {
        error: u32,
    },
    TebProcessIdentityMismatch
    {
        thread_id: u32,
        process_id: u32,
        teb_process_id: usize,
    },
    InvalidStackBounds
    {
        thread_id: u32,
        stack_base: usize,
        stack_limit: usize,
    },
    StackRegionQueryFailed
    {
        thread_id: u32,
        address: usize,
        error: MemoryRegionQueryError,
    },
    StackRegionRangeOverflow
    {
        thread_id: u32,
        base_address: usize,
        region_size: usize,
    },
    StackRegionDidNotAdvance
    {
        thread_id: u32,
        address: usize,
        region_base_address: usize,
        region_size: usize,
    },
}


/// Collects printable strings stored directly between one thread's TEB stack limits.
/// `process`: an open handle with query and virtual-memory read access.
/// `teb`: the previously collected TEB record that supplies the thread and stack bounds.
/// `minimum_chars`: the minimum decoded character count required for a result.
/// `progress`: callback receiving completed and total stack bytes.
///
/// Returns owned strings with absolute addresses and offsets from `StackLimit`, or
/// `TebStackStringCollectionError` when the stack bounds or a readable region cannot be processed.
pub fn collect_teb_stack_strings(process: HANDLE, teb: &ThreadTebInfo, minimum_chars: usize, progress: &mut impl FnMut(usize, usize)) -> Result<TebStackStringCollection, TebStackStringCollectionError>
{
    if process.is_null()
    {
        return Err(TebStackStringCollectionError::InvalidProcessHandle);
    }

    // SAFETY: `process` is checked for null above, and the API only reads the handle value.
    let process_id = unsafe { GetProcessId(process) };

    if process_id == 0
    {
        // SAFETY: `GetLastError` only reads the calling thread's last-error value.
        let error = unsafe { GetLastError() };

        return Err(TebStackStringCollectionError::ProcessIdUnavailable
        {
            error,
        });
    }

    if teb.client_process_id != process_id as usize
    {
        return Err(TebStackStringCollectionError::TebProcessIdentityMismatch
        {
            thread_id: teb.thread_id,
            process_id,
            teb_process_id: teb.client_process_id,
        });
    }

    if teb.stack_limit == 0 || teb.stack_base == 0 || teb.stack_limit >= teb.stack_base
    {
        return Err(TebStackStringCollectionError::InvalidStackBounds
        {
            thread_id: teb.thread_id,
            stack_base: teb.stack_base,
            stack_limit: teb.stack_limit,
        });
    }

    let mut collection = TebStackStringCollection
    {
        thread_id: teb.thread_id,
        teb_address: teb.teb_address,
        stack_base: teb.stack_base,
        stack_limit: teb.stack_limit,
        bytes_read: 0,
        strings: Vec::new(),
        failures: Vec::new(),
    };
    let mut address = teb.stack_limit;
    let total_stack_bytes = teb.stack_base - teb.stack_limit;

    progress(0, total_stack_bytes);

    while address < teb.stack_base
    {
        let region = memutils::query_region(process, address).map_err(|error|
        {
            TebStackStringCollectionError::StackRegionQueryFailed
            {
                thread_id: teb.thread_id,
                address,
                error,
            }
        })?;
        let region_end = region.base_address.checked_add(region.region_size).ok_or(TebStackStringCollectionError::StackRegionRangeOverflow
        {
            thread_id: teb.thread_id,
            base_address: region.base_address,
            region_size: region.region_size,
        })?;
        let read_end = region_end.min(teb.stack_base);

        if region.base_address > address || read_end <= address
        {
            return Err(TebStackStringCollectionError::StackRegionDidNotAdvance
            {
                thread_id: teb.thread_id,
                address,
                region_base_address: region.base_address,
                region_size: region.region_size,
            });
        }

        if is_readable_region(&region)
        {
            let bytes_requested = read_end - address;
            let region_read = match memutils::find_signature(process, bytes_requested, address, &[])
            {
                Ok(value) => value,
                Err(error) =>
                {
                    collection.failures.push(TebStackRegionFailure
                    {
                        address,
                        bytes_requested,
                        error: TebStackRegionReadError::ReadFailed(error),
                    });

                    progress(read_end - teb.stack_limit, total_stack_bytes);
                    address = read_end;
                    continue;
                }
            };

            if region_read.bytes.len() != bytes_requested
            {
                collection.failures.push(TebStackRegionFailure
                {
                    address,
                    bytes_requested,
                    error: TebStackRegionReadError::ReadIncomplete
                    {
                        status: region_read.status,
                        bytes_read: region_read.bytes.len(),
                    },
                });
            }

            collection.bytes_read += region_read.bytes.len();
            let completed_before_region = address - teb.stack_limit;
            let decoded_strings = collect_buffer_strings(&region_read.bytes, minimum_chars, &mut |completed, _|
            {
                progress(completed_before_region.saturating_add(completed), total_stack_bytes);
            });

            for decoded in decoded_strings
            {
                let string_address = address + decoded.offset;

                collection.strings.push(TebStackString
                {
                    thread_id: teb.thread_id,
                    value: decoded.value,
                    encoding: decoded.encoding,
                    address: string_address,
                    stack_offset: string_address - teb.stack_limit,
                });
            }
        }

        progress(read_end - teb.stack_limit, total_stack_bytes);
        address = read_end;
    }

    progress(total_stack_bytes, total_stack_bytes);

    Ok(collection)
}


/// Collects printable strings from an already validated main-module snapshot.
/// `process`: the validated process identity supplying the mapped image address and size.
/// `snapshot`: the validated mapped-image bytes and parsed PE section layout.
/// `minimum_chars`: the minimum decoded character count required for a result.
/// `progress`: callback receiving completed and total mapped-image bytes.
///
/// Returns owned string records without repeating process validation or image reads.
pub(crate) fn collect_main_module_strings_from_snapshot(process: &ValidatedProcessPe, snapshot: &ValidatedPeSnapshot, minimum_chars: usize, progress: &mut impl FnMut(usize, usize)) -> MainModuleStringCollection
{
    let decoded_strings = collect_buffer_strings(&snapshot.bytes, minimum_chars, progress);
    let mut records = Vec::with_capacity(decoded_strings.len());

    for decoded in decoded_strings
    {
        records.push(MainModuleString
        {
            value: decoded.value,
            encoding: decoded.encoding,
            address: process.image.base_address + decoded.offset,
            rva: decoded.offset,
            file_offset: pe_utils::get_file_offset_from_pe(&snapshot.pe, decoded.offset),
        });
    }

    MainModuleStringCollection
    {
        module_base_address: process.image.base_address,
        module_size: process.image.image_size,
        strings: records,
        unavailable_ranges: snapshot.unavailable_ranges.clone(),
    }
}


/// Holds one decoded buffer string before address metadata is attached.
struct DecodedString
{
    value: Box<str>,
    encoding: StringEncoding,
    offset: usize,
    byte_length: usize,
    character_count: usize,
}


/// Collects decoded strings from one already-read contiguous byte buffer.
/// `data`: the mapped-image or stack-region bytes to scan.
/// `minimum_chars`: the minimum decoded character count required for a result.
/// `progress`: callback receiving completed and total buffer bytes.
///
/// Returns decoded strings in ascending byte-offset order.
fn collect_buffer_strings(data: &[u8], minimum_chars: usize, progress: &mut impl FnMut(usize, usize)) -> Vec<DecodedString>
{
    let minimum_chars = minimum_chars.max(1);
    let mut results = Vec::new();
    let mut offset = 0usize;
    let mut next_progress_offset = 0usize;

    progress(0, data.len());

    while offset < data.len()
    {
        if offset >= next_progress_offset
        {
            progress(offset, data.len());
            next_progress_offset = offset.saturating_add(STRING_PROGRESS_BYTE_INTERVAL);
        }

        let candidate = match read_string_candidate(data, offset)
        {
            Some(value) => value,
            None =>
            {
                offset += 1;
                continue;
            }
        };
        let next_offset = next_scan_offset(data, &candidate);

        if candidate.character_count >= minimum_chars
        {
            results.push(candidate);
        }

        offset = next_offset;
    }

    progress(data.len(), data.len());

    results
}


/// Decodes a supported printable string beginning at an exact byte offset.
fn read_string_candidate(data: &[u8], offset: usize) -> Option<DecodedString>
{
    let region = data.get(offset..)?;
    let utf16le_length = strings::utf16le_len(region);

    if utf16le_length > 0
    {
        return Some(DecodedString
        {
            value: strings::read_utf16le(data, offset)?.into_boxed_str(),
            encoding: StringEncoding::Utf16Le,
            offset,
            byte_length: utf16le_length * 2,
            character_count: utf16le_length,
        });
    }

    let ascii_length = strings::ascii_len(region);
    let possible_utf8 = region.get(ascii_length).is_some_and(|byte| !byte.is_ascii());

    if possible_utf8
    {
        if let Some(value) = strings::read_utf8(data, offset)
        {
            if value.len() > ascii_length
            {
                return Some(DecodedString
                {
                    byte_length: value.len(),
                    character_count: value.chars().count(),
                    value: value.into_boxed_str(),
                    encoding: StringEncoding::Utf8,
                    offset,
                });
            }
        }
    }

    if ascii_length == 0
    {
        return None;
    }

    Some(DecodedString
    {
        value: strings::read_ascii(data, offset)?.into_boxed_str(),
        encoding: StringEncoding::Ascii,
        offset,
        byte_length: ascii_length,
        character_count: ascii_length,
    })
}


/// Computes the next byte offset after a decoded string and its optional NUL terminator.
fn next_scan_offset(data: &[u8], candidate: &DecodedString) -> usize
{
    let terminator_size = match candidate.encoding
    {
        StringEncoding::Utf16Le => 2,
        _ => 1,
    };
    let string_end = candidate.offset.saturating_add(candidate.byte_length);
    let terminator_end = string_end.saturating_add(terminator_size);

    if data.get(string_end..terminator_end).is_some_and(|terminator| terminator.iter().all(|byte| *byte == 0))
    {
        return terminator_end;
    }

    string_end.max(candidate.offset + 1)
}


/// Reports whether a queried virtual-memory region can be read as string data.
fn is_readable_region(region: &MemoryRegion) -> bool
{
    if region.state != MEM_COMMIT || region.protect & PAGE_GUARD != 0
    {
        return false;
    }

    matches!(
        region.protect & PAGE_BASE_PROTECTION_MASK,
        PAGE_READONLY
            | PAGE_READWRITE
            | PAGE_WRITECOPY
            | PAGE_EXECUTE_READ
            | PAGE_EXECUTE_READWRITE
            | PAGE_EXECUTE_WRITECOPY
    )
}
