use core::ffi::c_void;
use core::mem::size_of;
use std::fmt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr;

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Win32::Foundation::{GetLastError, HANDLE, INVALID_HANDLE_VALUE, NTSTATUS};
use windows_sys::Win32::System::Threading::OpenProcess;
use windows_sys::Win32::System::WindowsProgramming::{CLIENT_ID, PUBLIC_OBJECT_BASIC_INFORMATION};

use crate::core::internal::imports::imports::{nt_open_thread, nt_query_object};

/// Native object-information class that returns the granted access mask.
const OBJECT_BASIC_INFORMATION_CLASS: i32 = 0;

/// Explains why an owned Windows handle could not be opened or validated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandleGuardError
{
    InvalidHandle,
    OpenProcessFailed
    {
        process_id: u32,
        requested_access: u32,
        error: u32,
    },
    NtOpenThreadFailed
    {
        process_id: u32,
        thread_id: u32,
        requested_access: u32,
        status: NTSTATUS,
    },
    AccessQueryFailed
    {
        status: NTSTATUS, return_length: u32
    },
    InsufficientAccess
    {
        granted_access: u32, required_access: u32
    },
}


/// Owns a validated `CloseHandle`-compatible Windows handle.
pub struct HandleGuard
{
    handle: OwnedHandle,
    granted_access: u32,
}

impl HandleGuard
{
    /// Opens a process with the requested access and validates the granted mask.
    /// `process_id`: identifier of the local process to open.
    /// `requested_access`: exact process rights required by the caller.
    ///
    /// Returns an owned handle that closes itself, or the open/validation failure.
    pub(crate) fn open_process(process_id: u32, requested_access: u32) -> Result<Self, HandleGuardError>
    {
        // SAFETY: the identifier and access mask are passed by value, and inheritance is disabled.
        let handle = unsafe { OpenProcess(requested_access, 0, process_id) };

        if handle.is_null()
        {
            // SAFETY: `GetLastError` only reads the calling thread's last-error value.
            let error = unsafe { GetLastError() };

            return Err(HandleGuardError::OpenProcessFailed {
                process_id,
                requested_access,
                error,
            });
        }

        // SAFETY: `OpenProcess` returned a non-null owned process handle.
        unsafe { Self::from_owned_raw(handle, requested_access) }
    }


    /// Opens a thread through `NtOpenThread` and validates the granted mask.
    /// `process_id`: expected owner process identifier included in the native client ID.
    /// `thread_id`: identifier of the local thread to open.
    /// `requested_access`: exact thread rights required by the caller.
    ///
    /// Returns an owned handle that closes itself, or the open/validation failure.
    pub(crate) fn open_thread(process_id: u32, thread_id: u32, requested_access: u32) -> Result<Self, HandleGuardError>
    {
        let object_attributes = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: ptr::null_mut(),
            ObjectName: ptr::null(),
            Attributes: 0,
            SecurityDescriptor: ptr::null(),
            SecurityQualityOfService: ptr::null(),
        };
        let client_id = CLIENT_ID {
            UniqueProcess: process_id as usize as HANDLE,
            UniqueThread: thread_id as usize as HANDLE,
        };
        let mut handle: HANDLE = ptr::null_mut();

        // SAFETY: output storage and initialized object/client structures remain valid for the call.
        let status = unsafe { nt_open_thread(&mut handle, requested_access, &object_attributes, &client_id) };

        if status < 0
        {
            return Err(HandleGuardError::NtOpenThreadFailed {
                process_id,
                thread_id,
                requested_access,
                status,
            });
        }

        // SAFETY: successful `NtOpenThread` returns an owned thread handle closed by `CloseHandle`.
        unsafe { Self::from_owned_raw(handle, requested_access) }
    }


    /// Adopts and validates an owned raw handle closed by `CloseHandle`.
    /// `handle`: uniquely owned raw handle returned by a successful Windows API call.
    /// `required_access`: exact rights the handle must contain, or zero when not requested.
    ///
    /// Returns a validated self-closing guard, or the handle/access validation failure.
    pub(crate) unsafe fn from_owned_raw(handle: HANDLE, required_access: u32) -> Result<Self, HandleGuardError>
    {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE
        {
            return Err(HandleGuardError::InvalidHandle);
        }

        // SAFETY: the caller transfers unique ownership of a valid `CloseHandle`-compatible handle.
        let owned_handle = unsafe { OwnedHandle::from_raw_handle(handle) };
        let mut information = PUBLIC_OBJECT_BASIC_INFORMATION::default();
        let mut return_length = 0u32;

        // SAFETY: `information` is a valid output buffer and `handle` remains owned for the query.
        let status = unsafe { nt_query_object(handle, OBJECT_BASIC_INFORMATION_CLASS, &mut information as *mut PUBLIC_OBJECT_BASIC_INFORMATION as *mut c_void, size_of::<PUBLIC_OBJECT_BASIC_INFORMATION>() as u32, &mut return_length) };

        if status < 0
        {
            return Err(HandleGuardError::AccessQueryFailed {
                status,
                return_length,
            });
        }

        if information.GrantedAccess & required_access != required_access
        {
            return Err(HandleGuardError::InsufficientAccess {
                granted_access: information.GrantedAccess,
                required_access,
            });
        }

        Ok(Self {
            handle: owned_handle,
            granted_access: information.GrantedAccess,
        })
    }


    /// Returns the wrapped raw Windows handle without transferring ownership.
    ///
    /// Returns the handle for borrowed use by Windows APIs.
    pub(crate) fn as_raw(&self) -> HANDLE
    {
        self.handle.as_raw_handle()
    }


    /// Returns the access mask reported by the kernel during validation.
    ///
    /// Returns the cached `ObjectBasicInformation.GrantedAccess` value.
    pub(crate) fn granted_access(&self) -> u32
    {
        self.granted_access
    }
}

impl fmt::Display for HandleGuardError
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        match self
        {
            Self::InvalidHandle => write!(formatter, "Windows returned an invalid handle"),
            Self::OpenProcessFailed {process_id, requested_access, error} => write!(formatter, "failed to open process {} with access 0x{:08X}: {}", process_id, requested_access, error),
            Self::NtOpenThreadFailed {process_id, thread_id, requested_access, status} => write!(formatter, "NtOpenThread failed for process {} thread {} with access 0x{:08X}: 0x{:08X}", process_id, thread_id, requested_access, *status as u32),
            Self::AccessQueryFailed {status, return_length} => write!(formatter, "failed to query handle access: status 0x{:08X}, return length 0x{:X}", *status as u32, return_length),
            Self::InsufficientAccess {granted_access, required_access} => write!(formatter, "handle access 0x{:08X} does not contain required access 0x{:08X}", granted_access, required_access),
        }
    }
}

impl std::error::Error for HandleGuardError {}

#[cfg(test)]
mod tests
{
    use windows_sys::Win32::System::Threading::{GetCurrentThreadId, THREAD_QUERY_INFORMATION};

    use super::HandleGuard;

    /// Verifies the native thread-open path and retained access mask against this test thread.
    #[test]
    fn opens_current_thread_through_nt_open_thread()
    {
        // SAFETY: `GetCurrentThreadId` takes no parameters and returns the calling thread ID.
        let thread_id = unsafe { GetCurrentThreadId() };
        let handle = HandleGuard::open_thread(std::process::id(), thread_id, THREAD_QUERY_INFORMATION).expect("NtOpenThread should open the current test thread");

        assert_eq!(handle.granted_access() & THREAD_QUERY_INFORMATION, THREAD_QUERY_INFORMATION);
    }
}
