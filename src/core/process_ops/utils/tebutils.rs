use core::ffi::c_void;
use core::mem::{size_of, MaybeUninit};

use windows_sys::Win32::Foundation::{GetLastError, HANDLE, INVALID_HANDLE_VALUE, NTSTATUS, ERROR_NO_MORE_FILES};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32, TH32CS_SNAPTHREAD};
use windows_sys::Win32::System::Threading::{GetProcessId, OpenThread, THREAD_QUERY_INFORMATION};

use crate::core::internal::imports::imports::nt_query_information_thread;
use crate::core::internal::utils::handles::CleanHandle;
use crate::core::process_ops::utils::memutils::{self, ProcessMemoryReadError};

/// Native `THREADINFOCLASS` value selecting `ThreadBasicInformation`.
const THREAD_BASIC_INFORMATION_CLASS: i32 = 0;

/// Minimum bytes required to copy the x64 TEB fields through the PEB pointer.
const TEB_HEADER64_SIZE: usize = size_of::<TebHeader64>();

/// Contains every TEB record collected for a process and any thread-scoped failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessTebCollection
{
    pub process_id: u32,
    pub tebs: Vec<ThreadTebInfo>,
    pub failures: Vec<ThreadTebFailure>,
}


/// Describes the useful x64 TEB header fields collected for one process thread.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThreadTebInfo
{
    pub thread_id: u32,
    pub teb_address: usize,
    pub exit_status: NTSTATUS,
    pub affinity_mask: usize,
    pub priority: i32,
    pub base_priority: i32,
    pub exception_list: usize,
    pub stack_base: usize,
    pub stack_limit: usize,
    pub stack_size_bytes: Option<usize>,
    pub subsystem_tib: usize,
    pub fiber_data_or_version: usize,
    pub arbitrary_user_pointer: usize,
    pub self_address: usize,
    pub environment_pointer: usize,
    pub client_process_id: usize,
    pub client_thread_id: usize,
    pub active_rpc_handle: usize,
    pub thread_local_storage_pointer: usize,
    pub process_environment_block: usize,
    pub self_pointer_matches: bool,
    pub client_process_id_matches: bool,
    pub client_thread_id_matches: bool,
}


/// Associates a thread identifier with the reason its TEB could not be collected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThreadTebFailure
{
    pub thread_id: u32,
    pub error: ThreadTebCollectionError,
}


/// Explains why process-wide TEB enumeration could not start or finish.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProcessTebCollectionError
{
    InvalidProcessHandle,
    ProcessIdUnavailable
    {
        error: u32,
    },
    ThreadSnapshotFailed
    {
        error: u32,
    },
    ThreadSnapshotIterationFailed
    {
        error: u32,
    },
}


/// Explains why one enumerated thread did not produce a TEB record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ThreadTebCollectionError
{
    InvalidProcessHandle,
    ProcessIdUnavailable
    {
        error: u32,
    },
    InvalidThreadId,
    ThreadOpenFailed
    {
        error: u32,
    },
    ThreadInformationQueryFailed
    {
        status: NTSTATUS,
        return_length: u32,
    },
    ThreadInformationTooSmall
    {
        return_length: u32,
    },
    ThreadIdentityMismatch
    {
        expected_process_id: u32,
        actual_process_id: usize,
        expected_thread_id: u32,
        actual_thread_id: usize,
    },
    TebAddressUnavailable,
    TebReadFailed(ProcessMemoryReadError),
    TebReadIncomplete
    {
        bytes_requested: usize,
        bytes_read: usize,
    },
}


/// Mirrors the native thread-basic-information fields used to locate a remote TEB.
#[repr(C)]
#[derive(Clone, Copy)]
struct ThreadBasicInformation
{
    exit_status: NTSTATUS,
    teb_base_address: usize,
    client_id: ClientId,
    affinity_mask: usize,
    priority: i32,
    base_priority: i32,
}


/// Mirrors the native pointer-sized process and thread identifiers in a `CLIENT_ID`.
#[repr(C)]
#[derive(Clone, Copy)]
struct ClientId
{
    unique_process: usize,
    unique_thread: usize,
}


/// Mirrors the stable x64 TEB prefix from `NT_TIB64` through `ProcessEnvironmentBlock`.
#[repr(C)]
#[derive(Clone, Copy)]
struct TebHeader64
{
    exception_list: usize,
    stack_base: usize,
    stack_limit: usize,
    subsystem_tib: usize,
    fiber_data_or_version: usize,
    arbitrary_user_pointer: usize,
    self_address: usize,
    environment_pointer: usize,
    client_process_id: usize,
    client_thread_id: usize,
    active_rpc_handle: usize,
    thread_local_storage_pointer: usize,
    process_environment_block: usize,
}


/// Collects the x64 TEB header for every thread owned by a target process.
/// `process`: an open handle to the target process with query and virtual-memory read access.
/// `progress`: callback receiving completed and total thread counts.
///
/// Returns `Ok(ProcessTebCollection)` with successful TEB records and thread-scoped failures,
/// or `ProcessTebCollectionError` when the process or system thread snapshot cannot be queried.
pub fn collect_process_tebs(process: HANDLE, progress: &mut impl FnMut(usize, usize)) -> Result<ProcessTebCollection, ProcessTebCollectionError>
{
    if process.is_null()
    {
        return Err(ProcessTebCollectionError::InvalidProcessHandle);
    }

    let process_id = unsafe { GetProcessId(process) };

    if process_id == 0
    {
        let error = unsafe { GetLastError() };

        return Err(ProcessTebCollectionError::ProcessIdUnavailable
        {
            error,
        });
    }

    let thread_ids = enumerate_process_thread_ids(process_id)?;
    let thread_count = thread_ids.len();
    let mut collection = ProcessTebCollection
    {
        process_id,
        tebs: Vec::with_capacity(thread_ids.len()),
        failures: Vec::new(),
    };

    progress(0, thread_count);

    for (index, thread_id) in thread_ids.into_iter().enumerate()
    {
        match collect_thread_teb_for_process(process, process_id, thread_id)
        {
            Ok(teb) => collection.tebs.push(teb),
            Err(error) =>
            {
                collection.failures.push(ThreadTebFailure { thread_id, error });
            }
        }

        progress(index + 1, thread_count);
    }

    Ok(collection)
}


/// Enumerates every thread identifier owned by a process identifier.
/// `process_id`: the owner process identifier retained from the target process handle.
///
/// Returns an ordered vector of thread identifiers or a process-wide snapshot error.
fn enumerate_process_thread_ids(process_id: u32) -> Result<Vec<u32>, ProcessTebCollectionError>
{
    let raw_snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };

    if raw_snapshot == INVALID_HANDLE_VALUE
    {
        let error = unsafe { GetLastError() };

        return Err(ProcessTebCollectionError::ThreadSnapshotFailed
        {
            error,
        });
    }

    let snapshot = match CleanHandle::new(raw_snapshot)
    {
        Some(value) => value,
        None =>
        {
            let error = unsafe { GetLastError() };

            return Err(ProcessTebCollectionError::ThreadSnapshotFailed
            {
                error,
            });
        }
    };
    let mut thread_ids = Vec::new();
    let mut entry = THREADENTRY32::default();
    entry.dwSize = size_of::<THREADENTRY32>() as u32;

    let found = unsafe { Thread32First(snapshot.as_raw(), &mut entry) };

    if found == 0
    {
        let error = unsafe { GetLastError() };

        if error == ERROR_NO_MORE_FILES
        {
            return Ok(thread_ids);
        }

        return Err(ProcessTebCollectionError::ThreadSnapshotIterationFailed
        {
            error,
        });
    }

    loop
    {
        if entry.th32OwnerProcessID == process_id
        {
            thread_ids.push(entry.th32ThreadID);
        }

        entry.dwSize = size_of::<THREADENTRY32>() as u32;

        let found = unsafe { Thread32Next(snapshot.as_raw(), &mut entry) };

        if found != 0
        {
            continue;
        }

        let error = unsafe { GetLastError() };

        if error == ERROR_NO_MORE_FILES
        {
            break;
        }

        return Err(ProcessTebCollectionError::ThreadSnapshotIterationFailed
        {
            error,
        });
    }

    thread_ids.sort_unstable();

    Ok(thread_ids)
}


/// Collects one TEB after opening and validating an enumerated target thread.
/// `process`: an open handle to the process that owns the thread.
/// `process_id`: the expected owner process identifier.
/// `thread_id`: the enumerated target thread identifier.
///
/// Returns `Ok(ThreadTebInfo)` when the native thread information and TEB header are readable.
fn collect_thread_teb_for_process(process: HANDLE, process_id: u32, thread_id: u32) -> Result<ThreadTebInfo, ThreadTebCollectionError>
{
    let raw_thread = unsafe { OpenThread(THREAD_QUERY_INFORMATION, 0, thread_id) };
    let thread = match CleanHandle::new(raw_thread)
    {
        Some(value) => value,
        None =>
        {
            let error = unsafe { GetLastError() };

            return Err(ThreadTebCollectionError::ThreadOpenFailed
            {
                error,
            });
        }
    };
    let basic_information = query_thread_basic_information(thread.as_raw())?;

    if basic_information.client_id.unique_process != process_id as usize || basic_information.client_id.unique_thread != thread_id as usize
    {
        return Err(ThreadTebCollectionError::ThreadIdentityMismatch
        {
            expected_process_id: process_id,
            actual_process_id: basic_information.client_id.unique_process,
            expected_thread_id: thread_id,
            actual_thread_id: basic_information.client_id.unique_thread,
        });
    }

    let teb_address = basic_information.teb_base_address;

    if teb_address == 0
    {
        return Err(ThreadTebCollectionError::TebAddressUnavailable);
    }

    let header = read_teb_header(process, teb_address)?;

    Ok(ThreadTebInfo
    {
        thread_id,
        teb_address,
        exit_status: basic_information.exit_status,
        affinity_mask: basic_information.affinity_mask,
        priority: basic_information.priority,
        base_priority: basic_information.base_priority,
        exception_list: header.exception_list,
        stack_base: header.stack_base,
        stack_limit: header.stack_limit,
        stack_size_bytes: header.stack_base.checked_sub(header.stack_limit),
        subsystem_tib: header.subsystem_tib,
        fiber_data_or_version: header.fiber_data_or_version,
        arbitrary_user_pointer: header.arbitrary_user_pointer,
        self_address: header.self_address,
        environment_pointer: header.environment_pointer,
        client_process_id: header.client_process_id,
        client_thread_id: header.client_thread_id,
        active_rpc_handle: header.active_rpc_handle,
        thread_local_storage_pointer: header.thread_local_storage_pointer,
        process_environment_block: header.process_environment_block,
        self_pointer_matches: header.self_address == teb_address,
        client_process_id_matches: header.client_process_id == process_id as usize,
        client_thread_id_matches: header.client_thread_id == thread_id as usize,
    })
}


/// Queries the native basic-information record for a thread handle.
/// `thread`: an open thread handle with query-information access.
///
/// Returns the initialized native record or a thread-scoped collection error.
fn query_thread_basic_information(thread: HANDLE) -> Result<ThreadBasicInformation, ThreadTebCollectionError>
{
    let mut information = MaybeUninit::<ThreadBasicInformation>::uninit();
    let mut return_length = 0u32;
    let information_length = size_of::<ThreadBasicInformation>() as u32;

    let status = unsafe { nt_query_information_thread(thread, THREAD_BASIC_INFORMATION_CLASS, information.as_mut_ptr() as *mut c_void, information_length, &mut return_length) };

    if status < 0
    {
        return Err(ThreadTebCollectionError::ThreadInformationQueryFailed
        {
            status,
            return_length,
        });
    }

    if return_length != 0 && return_length < information_length
    {
        return Err(ThreadTebCollectionError::ThreadInformationTooSmall
        {
            return_length,
        });
    }

    Ok(unsafe { information.assume_init() })
}


/// Reads the stable x64 TEB prefix from a remote process.
/// `process`: an open process handle with virtual-memory read access.
/// `teb_address`: the remote base address returned by `ThreadBasicInformation`.
///
/// Returns the copied TEB header or a thread-scoped collection error.
fn read_teb_header(process: HANDLE, teb_address: usize) -> Result<TebHeader64, ThreadTebCollectionError>
{
    let read = memutils::find_signature(process, TEB_HEADER64_SIZE, teb_address, &[]).map_err(ThreadTebCollectionError::TebReadFailed)?;

    if read.bytes.len() < TEB_HEADER64_SIZE
    {
        return Err(ThreadTebCollectionError::TebReadIncomplete
        {
            bytes_requested: TEB_HEADER64_SIZE,
            bytes_read: read.bytes.len(),
        });
    }

    Ok(unsafe { std::ptr::read_unaligned(read.bytes.as_ptr() as *const TebHeader64) })
}
