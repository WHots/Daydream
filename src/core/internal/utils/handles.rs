use core::ffi::c_void;
use core::mem::size_of;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, NTSTATUS};
use windows_sys::Win32::System::WindowsProgramming::PUBLIC_OBJECT_BASIC_INFORMATION;

use crate::core::internal::imports::imports::nt_query_object;

const OBJECT_BASIC_INFORMATION_CLASS: i32 = 0;

/// Describes the access rights granted to a Windows handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandleAccess
{
    granted_access: u32,
}


impl HandleAccess
{
    /// Returns the access mask granted to the handle by the kernel.
    ///
    /// Returns the raw granted access mask from `ObjectBasicInformation`.
    pub(crate) fn granted_access(&self) -> u32
    {
        self.granted_access
    }

    /// Checks whether the granted access mask contains every required access bit.
    /// `required_access`: the complete access subset needed by the pending operation.
    ///
    /// Returns `true` when no required bit is missing from the granted mask.
    pub(crate) fn contains(&self, required_access: u32) -> bool
    {
        self.granted_access & required_access == required_access
    }
}


/// Explains why the granted access rights for a handle could not be queried.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandleAccessQueryError
{
    QueryFailed
    {
        status: NTSTATUS,
        return_length: u32,
    },
}


/// Owns a Windows handle and closes it when dropped.
pub struct CleanHandle
{
    handle: HANDLE,
}


impl CleanHandle
{
    /// Wraps a raw Windows handle.
    /// `handle`: the raw handle returned by the Windows API.
    ///
    /// Returns `Some(CleanHandle)` for a non-null handle, or `None` for a null handle.
    pub(crate) fn new(handle: HANDLE) -> Option<Self>
    {
        if handle.is_null()
        {
            None
        }
        else
        {
            Some(Self { handle })
        }
    }

    /// Returns the wrapped raw Windows handle.
    ///
    /// Returns the owned handle value without transferring ownership.
    pub(crate) fn as_raw(&self) -> HANDLE
    {
        self.handle
    }

    /// Queries the access mask granted to the handle by the kernel.
    ///
    /// Returns `Ok(HandleAccess)` with the granted mask, or `HandleAccessQueryError` on failure.
    pub(crate) fn query_access(&self) -> Result<HandleAccess, HandleAccessQueryError>
    {
        let mut information = PUBLIC_OBJECT_BASIC_INFORMATION::default();
        let mut return_length = 0u32;

        // SAFETY: `information` is a valid output buffer for `ObjectBasicInformation`, and `self.handle` is non-null for every `CleanHandle`.
        let status = unsafe
        {
            nt_query_object(
                self.handle,
                OBJECT_BASIC_INFORMATION_CLASS,
                &mut information as *mut PUBLIC_OBJECT_BASIC_INFORMATION as *mut c_void,
                size_of::<PUBLIC_OBJECT_BASIC_INFORMATION>() as u32,
                &mut return_length,
            )
        };

        if status < 0
        {
            Err(HandleAccessQueryError::QueryFailed
            {
                status,
                return_length,
            })
        }
        else
        {
            Ok(HandleAccess
            {
                granted_access: information.GrantedAccess,
            })
        }
    }
}


impl Drop for CleanHandle
{
    fn drop(&mut self)
    {
        // SAFETY: `CleanHandle` owns a non-null handle and closes it exactly once during drop.
        unsafe { CloseHandle(self.handle) };
    }
}
