use core::ffi::c_void;
use core::mem::{align_of, size_of, zeroed, MaybeUninit};
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;

use windows_sys::Win32::Foundation::{GetLastError, ERROR_BAD_LENGTH, HANDLE, INVALID_HANDLE_VALUE, NTSTATUS};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Module32FirstW, MODULEENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32};
use windows_sys::Win32::System::Memory::{MEM_COMMIT, PAGE_GUARD, PAGE_NOACCESS};
use windows_sys::Win32::System::Threading::GetProcessId;

use crate::core::internal::handles::handles::{HandleGuard, HandleGuardError};
use crate::core::internal::imports::imports::nt_query_information_process;
use crate::core::process_ops::procedures::foundation::validate_pe::{self, PeValidationError, ValidatedPeImage};
use crate::core::process_ops::utils::mem::{self, MemoryRegionQueryError, MemoryRegionType, ProcessMemoryReadError};

/// Native `PROCESSINFOCLASS` value selecting `ProcessBasicInformation`.
const PROCESS_BASIC_INFORMATION_CLASS: i32 = 0;

/// Maximum attempts used for transient `ERROR_BAD_LENGTH` module-snapshot failures.
const TOOLHELP_SNAPSHOT_RETRY_LIMIT: usize = 4;

/// Mask containing the base page-protection value without protection modifiers.
const PAGE_BASE_PROTECTION_MASK: u32 = 0xFF;

/// Describes the process identity, PEB, and validated main image proven by one strict pass.
#[derive(Debug, Eq, PartialEq)]
pub struct ValidatedProcessPe
{
    pub process_id: u32,
    pub peb_address: usize,
    pub being_debugged: bool,
    pub image: ValidatedPeImage,
    pub image_path: PathBuf,
}


/// Explains why process identity, PEB discovery, or loaded-image validation failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProcessPeValidationError
{
    InvalidProcessHandle,
    ProcessIdUnavailable
    {
        error: u32,
    },
    ProcessBasicInformationQueryFailed
    {
        status: NTSTATUS,
        return_length: u32,
    },
    ProcessBasicInformationTooSmall
    {
        return_length: u32,
    },
    ProcessIdentityMismatch
    {
        handle_process_id: u32,
        basic_information_process_id: usize,
    },
    ModuleSnapshotFailed
    {
        error: u32,
    },
    ModuleSnapshotHandleFailed(HandleGuardError),
    MainModuleEntryUnavailable
    {
        error: u32,
    },
    MainImagePathUnavailable,
    ToolhelpProcessIdentityMismatch
    {
        expected_process_id: u32,
        actual_process_id: u32,
    },
    PebAddressUnavailable,
    PebAddressMisaligned
    {
        peb_address: usize,
    },
    PebRangeOverflow
    {
        peb_address: usize,
        bytes_required: usize,
    },
    PebRegionQueryFailed
    {
        peb_address: usize,
        error: MemoryRegionQueryError,
    },
    InvalidPebRegion
    {
        peb_address: usize,
        region_base_address: usize,
        region_size: usize,
        state: u32,
        protect: u32,
        region_type: MemoryRegionType,
    },
    PebReadFailed(ProcessMemoryReadError),
    PeValidationFailed(PeValidationError),
    MainImageBaseMismatch
    {
        peb_image_base: usize,
        toolhelp_image_base: usize,
    },
    MainImageSizeMismatch
    {
        validated_image_size: usize,
        toolhelp_image_size: usize,
    },
}


/// Mirrors the native process-basic-information fields needed to locate the target PEB.
#[repr(C)]
#[derive(Clone, Copy)]
struct ProcessBasicInformation
{
    _exit_status: NTSTATUS,
    peb_base_address: *mut c_void,
    _affinity_mask: usize,
    _base_priority: i32,
    unique_process_id: usize,
    _inherited_from_unique_process_id: usize,
}


/// Mirrors the initial PEB bytes through the main-image base slot.
#[repr(C)]
#[derive(Clone, Copy)]
struct PebImageBaseBlock
{
    _reserved1: [u8; 2],
    being_debugged: u8,
    _reserved2: [u8; 1],
    reserved3: [*mut c_void; 2],
}


/// Contains the independent main-image identity returned by Toolhelp.
#[derive(Debug, Eq, PartialEq)]
struct ToolhelpMainImage
{
    base_address: usize,
    image_size: usize,
    path: PathBuf,
}


/// Strictly validates a process handle, its native PEB location, and its loaded x64 main image.
/// `process`: an open target-process handle with query and virtual-memory read access.
///
/// Returns a point-in-time validated process/PE snapshot or a typed validation failure.
pub fn validate_process_peb(process: HANDLE) -> Result<ValidatedProcessPe, ProcessPeValidationError>
{
    if process.is_null()
    {
        return Err(ProcessPeValidationError::InvalidProcessHandle);
    }

    // SAFETY: `process` is non-null, and the API reads only the supplied handle value.
    let process_id = unsafe { GetProcessId(process) };

    if process_id == 0
    {
        // SAFETY: `GetLastError` only reads the calling thread's last-error value.
        let error = unsafe { GetLastError() };

        return Err(ProcessPeValidationError::ProcessIdUnavailable {
            error,
        });
    }

    let process_information = query_process_basic_information(process)?;

    if process_information.unique_process_id != process_id as usize
    {
        return Err(ProcessPeValidationError::ProcessIdentityMismatch {
            handle_process_id: process_id,
            basic_information_process_id: process_information.unique_process_id,
        });
    }

    let peb_address = process_information.peb_base_address as usize;

    if peb_address == 0
    {
        return Err(ProcessPeValidationError::PebAddressUnavailable);
    }

    if peb_address % align_of::<usize>() != 0
    {
        return Err(ProcessPeValidationError::PebAddressMisaligned {
            peb_address,
        });
    }

    let peb_bytes_required = size_of::<PebImageBaseBlock>();
    let peb_end = peb_address.checked_add(peb_bytes_required).ok_or(ProcessPeValidationError::PebRangeOverflow {
        peb_address,
        bytes_required: peb_bytes_required,
    })?;
    let peb_region = mem::query_region(process, peb_address).map_err(|error| ProcessPeValidationError::PebRegionQueryFailed {
        peb_address,
        error,
    })?;
    let peb_region_end = peb_region.base_address.checked_add(peb_region.region_size).ok_or(ProcessPeValidationError::PebRangeOverflow {
        peb_address: peb_region.base_address,
        bytes_required: peb_region.region_size,
    })?;

    if peb_region.base_address > peb_address || peb_end > peb_region_end || peb_region.state != MEM_COMMIT || peb_region.region_type != MemoryRegionType::Private || peb_region.protect & PAGE_GUARD != 0 || peb_region.protect & PAGE_BASE_PROTECTION_MASK == PAGE_NOACCESS
    {
        return Err(ProcessPeValidationError::InvalidPebRegion {
            peb_address,
            region_base_address: peb_region.base_address,
            region_size: peb_region.region_size,
            state: peb_region.state,
            protect: peb_region.protect,
            region_type: peb_region.region_type,
        });
    }

    // SAFETY: `PebImageBaseBlock` contains only byte arrays and raw pointers, so every copied bit pattern is valid.
    let peb = unsafe { mem::read_value::<PebImageBaseBlock>(process, peb_address) }.map_err(ProcessPeValidationError::PebReadFailed)?;
    let image = validate_pe::validate_process_image(process, peb.reserved3[1] as usize).map_err(ProcessPeValidationError::PeValidationFailed)?;
    let toolhelp_image = query_toolhelp_main_image(process_id)?;

    if toolhelp_image.base_address != image.base_address
    {
        return Err(ProcessPeValidationError::MainImageBaseMismatch {
            peb_image_base: image.base_address,
            toolhelp_image_base: toolhelp_image.base_address,
        });
    }

    if toolhelp_image.image_size != image.image_size
    {
        return Err(ProcessPeValidationError::MainImageSizeMismatch {
            validated_image_size: image.image_size,
            toolhelp_image_size: toolhelp_image.image_size,
        });
    }

    Ok(ValidatedProcessPe {
        process_id,
        peb_address,
        being_debugged: peb.being_debugged != 0,
        image,
        image_path: toolhelp_image.path,
    })
}


/// Queries `ProcessBasicInformation` for a target process handle.
/// `process`: an open target-process handle with query access.
///
/// Returns a complete native basic-information record or a typed query failure.
fn query_process_basic_information(process: HANDLE) -> Result<ProcessBasicInformation, ProcessPeValidationError>
{
    let mut information = MaybeUninit::<ProcessBasicInformation>::uninit();
    let mut return_length = 0u32;
    let information_length = size_of::<ProcessBasicInformation>() as u32;

    // SAFETY: the output buffer has the exact requested size and lives through the native call.
    let status = unsafe { nt_query_information_process(process, PROCESS_BASIC_INFORMATION_CLASS, information.as_mut_ptr() as *mut c_void, information_length, &mut return_length) };

    if status < 0
    {
        eprintln!("failed to query native process basic information");
        return Err(ProcessPeValidationError::ProcessBasicInformationQueryFailed {
            status,
            return_length,
        });
    }

    if return_length < information_length
    {
        eprintln!("native process basic information was shorter than expected");
        return Err(ProcessPeValidationError::ProcessBasicInformationTooSmall {
            return_length,
        });
    }

    // SAFETY: a successful query reporting the full structure size initialized the output buffer.
    Ok(unsafe { information.assume_init() })
}


/// Retrieves the first Toolhelp module as an independent main-image identity source.
/// `process_id`: the validated identifier of the target process.
///
/// Returns the first module base, size, and executable path after bounded retries.
fn query_toolhelp_main_image(process_id: u32) -> Result<ToolhelpMainImage, ProcessPeValidationError>
{
    let mut snapshot = None;
    let mut snapshot_error = 0u32;

    for _ in 0..TOOLHELP_SNAPSHOT_RETRY_LIMIT
    {
        // SAFETY: the snapshot flags and validated process identifier are passed by value.
        let raw_snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id) };

        if raw_snapshot != INVALID_HANDLE_VALUE
        {
            // SAFETY: `CreateToolhelp32Snapshot` returned an owned handle closed by `CloseHandle`.
            snapshot = Some(unsafe { HandleGuard::from_owned_raw(raw_snapshot, 0) }.map_err(ProcessPeValidationError::ModuleSnapshotHandleFailed)?);
            break;
        }

        // SAFETY: `GetLastError` only reads the calling thread's last-error value.
        snapshot_error = unsafe { GetLastError() };

        if snapshot_error != ERROR_BAD_LENGTH
        {
            eprintln!("failed to create the target process module snapshot");
            return Err(ProcessPeValidationError::ModuleSnapshotFailed {
                error: snapshot_error,
            });
        }
    }

    let snapshot = match snapshot
    {
        Some(value) => value,
        None =>
        {
            eprintln!("target process module snapshot retries were exhausted");
            return Err(ProcessPeValidationError::ModuleSnapshotFailed {
                error: snapshot_error,
            });
        }
    };

    // SAFETY: all-zero bytes are a valid initial state before the required `dwSize` assignment.
    let mut entry: MODULEENTRY32W = unsafe { zeroed() };
    entry.dwSize = size_of::<MODULEENTRY32W>() as u32;

    // SAFETY: `snapshot` is valid, and `entry` is a writable buffer with its required size set.
    let found = unsafe { Module32FirstW(snapshot.as_raw(), &mut entry) };
    let entry_error = if found == 0
    {
        // SAFETY: `GetLastError` only reads the calling thread's last-error value.
        unsafe { GetLastError() }
    }
    else
    {
        0
    };

    drop(snapshot);

    if found == 0
    {
        eprintln!("target process module snapshot did not contain a main module");
        return Err(ProcessPeValidationError::MainModuleEntryUnavailable {
            error: entry_error,
        });
    }

    if entry.th32ProcessID != process_id
    {
        eprintln!("Toolhelp main-module entry belongs to a different process");
        return Err(ProcessPeValidationError::ToolhelpProcessIdentityMismatch {
            expected_process_id: process_id,
            actual_process_id: entry.th32ProcessID,
        });
    }

    let path_length = entry.szExePath.iter().position(|character| *character == 0).unwrap_or(entry.szExePath.len());

    if path_length == 0
    {
        eprintln!("Toolhelp main-module entry did not contain an executable path");
        return Err(ProcessPeValidationError::MainImagePathUnavailable);
    }

    Ok(ToolhelpMainImage {
        base_address: entry.modBaseAddr as usize,
        image_size: entry.modBaseSize as usize,
        path: PathBuf::from(OsString::from_wide(&entry.szExePath[..path_length])),
    })
}
