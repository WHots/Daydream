use core::ffi::c_void;
use core::mem::{size_of, zeroed};

use windows_sys::Win32::Foundation::{HANDLE, NTSTATUS};
use windows_sys::Win32::System::Memory::{
    MEMORY_BASIC_INFORMATION, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE,
};

use crate::core::internal::imports::imports::{nt_query_virtual_memory, nt_read_virtual_memory};

/// Native `MEMORY_INFORMATION_CLASS` value selecting `MemoryBasicInformation`.
const MEMORY_BASIC_INFORMATION_CLASS: i32 = 0;

/// Describes a single byte-pattern match in process memory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessMemoryMatch
{
    pub offset: usize,
    pub address: usize,
}


/// Contains bytes read from a process and any byte-pattern matches found in them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessMemoryRead
{
    pub starting_address: usize,
    pub bytes_requested: usize,
    pub bytes_read: usize,
    pub status: NTSTATUS,
    pub bytes: Vec<u8>,
    pub matches: Vec<ProcessMemoryMatch>,
}


/// Explains why a process-memory read could not be completed safely.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProcessMemoryReadError
{
    InvalidProcessHandle,
    NullBaseAddress,
    ZeroBytesRequested,

    AddressRangeOverflow
    {
        starting_address: usize,
        bytes_requested: usize,
    },
    BufferAllocationFailed
    {
        bytes_requested: usize,
    },
    BytesReadExceededRequest
    {
        bytes_requested: usize,
        bytes_read: usize,
    },
    ReadFailed
    {
        status: NTSTATUS,
        bytes_read: usize,
    },
    ReadIncomplete
    {
        bytes_requested: usize,
        bytes_read: usize,
    },
}


/// Coarse classification of the storage that backs a virtual-memory region.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryRegionType
{
    Image,
    Mapped,
    Private,
    Unknown,
}


/// Describes the virtual-memory region that contains a queried address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryRegion
{
    pub base_address: usize,
    pub allocation_base: usize,
    pub region_size: usize,
    pub state: u32,
    pub protect: u32,
    pub region_type: MemoryRegionType,
}


/// Explains why a memory-region query could not be completed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryRegionQueryError
{
    InvalidProcessHandle,
    NullBaseAddress,
    QueryFailed { status: NTSTATUS },
}


/// Reads a fixed byte range from a process and searches the result for a byte pattern.
/// `process`: an open handle to the target process with virtual-memory read access.
/// `total_bytes`: the total number of bytes to read from the starting address.
/// `starting_address`: the base address in the target process to read from.
/// `search_pattern`: the symbol bytes, bytecode, or opcode bytes to search for.
///
/// Returns `Ok(ProcessMemoryRead)` with the bytes read and matches found, or
/// `ProcessMemoryReadError` if the request cannot be completed safely.
pub fn find_signature(process: HANDLE, total_bytes: usize, starting_address: usize, search_pattern: &[u8]) -> Result<ProcessMemoryRead, ProcessMemoryReadError>
{
    let mut read = read_process_memory(process, total_bytes, starting_address)?;

    read.matches = find_pattern_matches(&read.bytes, starting_address, search_pattern);

    Ok(read)
}


/// Reads an exact byte range from a target process.
/// `process`: an open handle with virtual-memory read access.
/// `total_bytes`: the exact number of bytes required by the caller.
/// `starting_address`: the first address to copy from the target process.
///
/// Returns owned bytes only when the complete requested range was copied.
pub(crate) fn read_exact(process: HANDLE, total_bytes: usize, starting_address: usize) -> Result<Vec<u8>, ProcessMemoryReadError>
{
    let read = read_process_memory(process, total_bytes, starting_address)?;

    if read.bytes_read != total_bytes
    {
        return Err(ProcessMemoryReadError::ReadIncomplete
        {
            bytes_requested: total_bytes,
            bytes_read: read.bytes_read,
        });
    }

    Ok(read.bytes)
}


/// Reads one plain C-compatible value from an exact target-process address.
/// `process`: an open handle with virtual-memory read access.
/// `address`: the target-process address containing the value.
///
/// SAFETY: `T` must permit every possible bit pattern and contain no references.
/// Returns a copied value only when every byte was read.
pub(crate) unsafe fn read_value<T: Copy>(process: HANDLE, address: usize) -> Result<T, ProcessMemoryReadError>
{
    let bytes = read_exact(process, size_of::<T>(), address)?;

    Ok(unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const T) })
}


/// Queries the virtual-memory region that contains an address in a target process.
/// `process`: an open handle to the target process with query access.
/// `address`: the address in the target process to classify.
///
/// Returns `Ok(MemoryRegion)` describing the containing region, or
/// `MemoryRegionQueryError` if the region cannot be queried.
pub fn query_region(process: HANDLE, address: usize) -> Result<MemoryRegion, MemoryRegionQueryError>
{
    if process.is_null()
    {
        return Err(MemoryRegionQueryError::InvalidProcessHandle);
    }

    if address == 0
    {
        return Err(MemoryRegionQueryError::NullBaseAddress);
    }

    let information = query_basic_information(process, address)?;

    Ok(MemoryRegion
    {
        base_address: information.BaseAddress as usize,
        allocation_base: information.AllocationBase as usize,
        region_size: information.RegionSize,
        state: information.State,
        protect: information.Protect,
        region_type: classify_region_type(information.Type),
    })
}


/// Reads a process-memory range without applying pattern matching.
/// `process`: an open handle to the target process with virtual-memory read access.
/// `total_bytes`: the number of bytes requested from the process.
/// `starting_address`: the first target-process address to read.
///
/// Returns the raw read result, preserving a successful partial read for callers that allow it.
fn read_process_memory(process: HANDLE, total_bytes: usize, starting_address: usize) -> Result<ProcessMemoryRead, ProcessMemoryReadError>
{
    if process.is_null()
    {
        return Err(ProcessMemoryReadError::InvalidProcessHandle);
    }

    if starting_address == 0
    {
        return Err(ProcessMemoryReadError::NullBaseAddress);
    }

    if total_bytes == 0
    {
        return Err(ProcessMemoryReadError::ZeroBytesRequested);
    }

    if starting_address.checked_add(total_bytes).is_none()
    {
        return Err(ProcessMemoryReadError::AddressRangeOverflow
        {
            starting_address,
            bytes_requested: total_bytes,
        });
    }

    let mut bytes = create_read_buffer(total_bytes)?;
    let (status, bytes_read) = read_virtual_memory(process, starting_address, &mut bytes);

    if status < 0
    {
        return Err(ProcessMemoryReadError::ReadFailed { status, bytes_read });
    }

    if bytes_read > total_bytes
    {
        return Err(ProcessMemoryReadError::BytesReadExceededRequest
        {
            bytes_requested: total_bytes,
            bytes_read,
        });
    }

    bytes.truncate(bytes_read);

    Ok(ProcessMemoryRead
    {
        starting_address,
        bytes_requested: total_bytes,
        bytes_read,
        status,
        bytes,
        matches: Vec::new(),
    })
}


/// Allocates an initialized buffer for an NT memory read.
/// `total_bytes`: the exact number of bytes the caller intends to read.
///
/// Returns `Ok(Vec<u8>)` with zeroed capacity for the read, or `ProcessMemoryReadError`
/// if allocation fails.
fn create_read_buffer(total_bytes: usize) -> Result<Vec<u8>, ProcessMemoryReadError>
{
    let mut buffer = Vec::new();

    buffer.try_reserve_exact(total_bytes).map_err(|_|
    {
        ProcessMemoryReadError::BufferAllocationFailed
        {
            bytes_requested: total_bytes,
        }
    })?;

    buffer.resize(total_bytes, 0);

    Ok(buffer)
}


/// Searches a byte buffer for an exact byte pattern.
/// `bytes`: the bytes returned from the target process.
/// `starting_address`: the base address corresponding to the first byte in `bytes`.
/// `search_pattern`: the exact sequence of bytes to locate.
///
/// Returns all match offsets and absolute process addresses.
fn find_pattern_matches(bytes: &[u8], starting_address: usize, search_pattern: &[u8]) -> Vec<ProcessMemoryMatch>
{
    if search_pattern.is_empty() || search_pattern.len() > bytes.len()
    {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for (offset, window) in bytes.windows(search_pattern.len()).enumerate()
    {
        if window == search_pattern
        {
            if let Some(address) = starting_address.checked_add(offset)
            {
                matches.push(ProcessMemoryMatch { offset, address });
            }
        }
    }

    matches
}


/// Calls `NtReadVirtualMemory` with a validated target range and local output buffer.
/// `process`: an open handle to the target process.
/// `starting_address`: the process address to read from.
/// `bytes`: the initialized local output buffer that receives bytes from the target process.
///
/// Returns the raw NTSTATUS and the byte count reported by the native call.
fn read_virtual_memory(process: HANDLE, starting_address: usize, bytes: &mut [u8]) -> (NTSTATUS, usize)
{
    let mut bytes_read = 0usize;

    // SAFETY: the destination slice is writable for its full length, and the caller validates the process handle and address range before this native read.
    let status = unsafe
    {
        nt_read_virtual_memory(process, starting_address as *const c_void, bytes.as_mut_ptr() as *mut c_void, bytes.len(), &mut bytes_read)
    };

    (status, bytes_read)
}


/// Queries the `MemoryBasicInformation` block for an address in a target process.
/// `process`: an open handle to the target process.
/// `address`: the address whose containing region is queried.
///
/// Returns `Ok(MEMORY_BASIC_INFORMATION)` for the containing region, or
/// `MemoryRegionQueryError` when the native call fails.
fn query_basic_information(process: HANDLE, address: usize) -> Result<MEMORY_BASIC_INFORMATION, MemoryRegionQueryError>
{
    // SAFETY: all-zero bytes are a valid initial state for `MEMORY_BASIC_INFORMATION` before the native query initializes its fields.
    let mut information = unsafe { zeroed::<MEMORY_BASIC_INFORMATION>() };
    let mut return_length = 0usize;

    // SAFETY: `information` is a writable buffer of the exact requested size and remains valid for the duration of the native query.
    let status = unsafe
    {
        nt_query_virtual_memory(process, address as *const c_void, MEMORY_BASIC_INFORMATION_CLASS, &mut information as *mut MEMORY_BASIC_INFORMATION as *mut c_void, size_of::<MEMORY_BASIC_INFORMATION>(), &mut return_length)
    };

    if status < 0
    {
        return Err(MemoryRegionQueryError::QueryFailed { status });
    }

    Ok(information)
}


/// Maps a raw `MEMORY_BASIC_INFORMATION` type field to a `MemoryRegionType`.
/// `region_type`: the raw `Type` value reported by the kernel.
///
/// Returns the coarse `MemoryRegionType` classification.
fn classify_region_type(region_type: u32) -> MemoryRegionType
{
    match region_type
    {
        MEM_IMAGE => MemoryRegionType::Image,
        MEM_MAPPED => MemoryRegionType::Mapped,
        MEM_PRIVATE => MemoryRegionType::Private,
        _ => MemoryRegionType::Unknown,
    }
}
