use core::ffi::c_void;

use windows_sys::Win32::Foundation::{HANDLE, NTSTATUS};

#[link(name = "ntdll")]
unsafe extern "system"
{
    /// Queries metadata for a kernel object handle.
    /// `handle`: the handle whose object information is queried.
    /// `object_information_class`: the native object information class.
    /// `object_information`: the output buffer for the selected information class.
    /// `object_information_length`: the size of `object_information`, in bytes.
    /// `return_length`: receives the number of bytes required or written.
    ///
    /// Returns the raw `NTSTATUS` reported by the native call.
    #[link_name = "NtQueryObject"]
    pub(crate) fn nt_query_object(
        handle: HANDLE,
        object_information_class: i32,
        object_information: *mut c_void,
        object_information_length: u32,
        return_length: *mut u32,
    ) -> NTSTATUS;

    /// Queries native information for a process handle.
    /// `process`: an open handle to the target process.
    /// `process_information_class`: the native process information class.
    /// `process_information`: the output buffer for the selected information class.
    /// `process_information_length`: the size of `process_information`, in bytes.
    /// `return_length`: receives the number of bytes required or written.
    ///
    /// Returns the raw `NTSTATUS` reported by the native call.
    #[link_name = "NtQueryInformationProcess"]
    pub(crate) fn nt_query_information_process(
        process: HANDLE,
        process_information_class: i32,
        process_information: *mut c_void,
        process_information_length: u32,
        return_length: *mut u32,
    ) -> NTSTATUS;


    /// Queries native information for a thread handle.
    /// `thread`: an open handle to the target thread.
    /// `thread_information_class`: the native thread information class.
    /// `thread_information`: the output buffer for the selected information class.
    /// `thread_information_length`: the size of `thread_information`, in bytes.
    /// `return_length`: receives the number of bytes required or written.
    ///
    /// Returns the raw `NTSTATUS` reported by the native call.
    #[link_name = "NtQueryInformationThread"]
    pub(crate) fn nt_query_information_thread(thread: HANDLE, thread_information_class: i32, thread_information: *mut c_void, thread_information_length: u32, return_length: *mut u32) -> NTSTATUS;


    /// Reads a range of virtual memory from a target process into a local buffer.
    /// `process`: an open handle to the target process with read access.
    /// `base_address`: the address in the target process to begin reading from; it is a
    /// remote address and is never dereferenced by the caller.
    /// `buffer`: the local output buffer that receives the bytes read.
    /// `number_of_bytes_to_read`: the number of bytes to copy into `buffer`.
    /// `number_of_bytes_read`: receives the number of bytes actually read.
    ///
    /// Returns the raw `NTSTATUS` reported by the native call.
    #[allow(dead_code)]
    #[link_name = "NtReadVirtualMemory"]
    pub(crate) fn nt_read_virtual_memory(
        process: HANDLE,
        base_address: *const c_void,
        buffer: *mut c_void,
        number_of_bytes_to_read: usize,
        number_of_bytes_read: *mut usize,
    ) -> NTSTATUS;

    /// Queries information about a range of virtual memory in a target process.
    /// `process`: an open handle to the target process with query access.
    /// `base_address`: the address in the target process whose region is queried; it is a
    /// remote address and is never dereferenced by the caller.
    /// `memory_information_class`: the native memory information class to retrieve.
    /// `memory_information`: the local output buffer that receives the requested information.
    /// `memory_information_length`: the size of `memory_information`, in bytes.
    /// `return_length`: receives the number of bytes required or written.
    ///
    /// Returns the raw `NTSTATUS` reported by the native call.
    #[allow(dead_code)]
    #[link_name = "NtQueryVirtualMemory"]
    pub(crate) fn nt_query_virtual_memory(
        process: HANDLE,
        base_address: *const c_void,
        memory_information_class: i32,
        memory_information: *mut c_void,
        memory_information_length: usize,
        return_length: *mut usize,
    ) -> NTSTATUS;
}
