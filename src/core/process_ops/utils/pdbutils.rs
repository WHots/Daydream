use core::mem::size_of;
use std::ffi::CStr;
use std::path::Path;

use windows_sys::Win32::System::Diagnostics::Debug::{
    IMAGE_DEBUG_DIRECTORY, IMAGE_DEBUG_TYPE_CODEVIEW, IMAGE_DIRECTORY_ENTRY_DEBUG,
};

use crate::core::process_ops::utils::foundation::validate_pe::{self, ValidatedPeSnapshot};
use crate::core::process_ops::utils::pe_utils;
use crate::core::process_ops::utils::processutils::ProcessPeValidationError;

/// Byte length of a CodeView record signature.
const CODEVIEW_SIGNATURE_SIZE: usize = 4;

/// Byte offset of the GUID in an RSDS CodeView record.
const RSDS_GUID_OFFSET: usize = 4;

/// Byte offset of the age in an RSDS CodeView record.
const RSDS_AGE_OFFSET: usize = 20;

/// Byte offset of the PDB path in an RSDS CodeView record.
const RSDS_PATH_OFFSET: usize = 24;

/// Byte offset of the signature in an NB10 CodeView record.
const NB10_SIGNATURE_OFFSET: usize = 8;

/// Byte offset of the age in an NB10 CodeView record.
const NB10_AGE_OFFSET: usize = 12;

/// Byte offset of the PDB path in an NB10 CodeView record.
const NB10_PATH_OFFSET: usize = 16;

/// Describes the supported CodeView record format used to reference a PDB.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PdbCodeViewFormat
{
    Rsds,
    Nb10,
}


/// Stores a CodeView RSDS GUID in display-ready PE/PDB byte order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PdbGuid
{
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}


/// Describes the file-system parts extracted from a PDB path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PdbPathInfo
{
    pub full_path: Box<str>,
    pub directory: Option<Box<str>>,
    pub file_name: Option<Box<str>>,
    pub file_stem: Option<Box<str>>,
    pub extension: Option<Box<str>>,
    pub exists_on_disk: bool,
}


/// Describes PDB metadata extracted from a PE CodeView debug record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PdbInfo
{
    pub format: PdbCodeViewFormat,
    pub path: PdbPathInfo,
    pub guid: Option<PdbGuid>,
    pub signature: Option<u32>,
    pub age: u32,
    pub debug_directory_rva: usize,
    pub debug_directory_file_offset: Option<usize>,
    pub codeview_rva: usize,
    pub codeview_file_offset: Option<usize>,
    pub codeview_size: usize,
}


/// Explains why main-module PDB collection could not complete.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PdbInfoCollectionError
{
    ProcessValidationFailed(ProcessPeValidationError),
    InvalidMainModulePe(validate_pe::PeValidationError),
    IncompleteMainModuleSnapshot
    {
        rva: usize,
        size: usize,
    },
}


/// Collects PDB metadata from an already validated main-module snapshot.
/// `snapshot`: the validated mapped-image bytes, PE layout, and unavailable ranges.
///
/// Returns supported CodeView metadata, absence, or the original unavailable-range error.
pub(crate) fn collect_main_module_pdb_info_from_snapshot(snapshot: &ValidatedPeSnapshot) -> Result<Option<PdbInfo>, PdbInfoCollectionError>
{
    collect_pdb_info_from_pe(&snapshot.bytes, &snapshot.pe, Some(snapshot)).map_err(|range| PdbInfoCollectionError::IncompleteMainModuleSnapshot
    {
        rva: range.rva,
        size: range.size,
    })
}


/// Collects PDB metadata from a PE image that has already passed strict validation.
/// `module_bytes`: mapped PE bytes indexed by RVA.
/// `pe`: copied validated headers and sections for `module_bytes`.
/// `snapshot`: process snapshot whose discarded ranges must remain distinguishable.
///
/// Returns CodeView metadata, absence, or the first unavailable required range.
fn collect_pdb_info_from_pe(module_bytes: &[u8], pe: &validate_pe::PeImage, snapshot: Option<&validate_pe::ValidatedPeSnapshot>) -> Result<Option<PdbInfo>, validate_pe::UnavailablePeRange>
{
    let debug_directory = match validate_pe::get_data_directory(pe, IMAGE_DIRECTORY_ENTRY_DEBUG as usize)
    {
        Some(value) => value,
        None => return Ok(None),
    };

    let debug_directory_rva = debug_directory.VirtualAddress as usize;
    let debug_directory_size = debug_directory.Size as usize;

    if debug_directory_rva == 0 || debug_directory_size == 0
    {
        return Ok(None);
    }

    if snapshot.is_some_and(|value| !validate_pe::is_snapshot_range_available(value, debug_directory_rva, debug_directory_size))
    {
        eprintln!("process PDB debug-directory bytes are unavailable");
        return Err(validate_pe::UnavailablePeRange
        {
            rva: debug_directory_rva,
            size: debug_directory_size,
        });
    }

    let debug_directory_end = match debug_directory_rva.checked_add(debug_directory_size)
    {
        Some(value) => value,
        None => return Ok(None),
    };

    if module_bytes.get(debug_directory_rva..debug_directory_end).is_none()
    {
        return Ok(None);
    }

    let entry_size = size_of::<IMAGE_DEBUG_DIRECTORY>();
    let entry_count = debug_directory_size / entry_size;

    for entry_index in 0..entry_count
    {
        let entry_rva = match entry_index.checked_mul(entry_size).and_then(|offset| debug_directory_rva.checked_add(offset))
        {
            Some(value) => value,
            None => continue,
        };

        let entry = match read_value::<IMAGE_DEBUG_DIRECTORY>(module_bytes, entry_rva)
        {
            Some(value) => value,
            None => continue,
        };

        if entry.Type != IMAGE_DEBUG_TYPE_CODEVIEW || entry.SizeOfData == 0 || entry.AddressOfRawData == 0
        {
            continue;
        }

        let codeview_rva = entry.AddressOfRawData as usize;
        let codeview_size = entry.SizeOfData as usize;

        if snapshot.is_some_and(|value| !validate_pe::is_snapshot_range_available(value, codeview_rva, codeview_size))
        {
            eprintln!("process PDB CodeView bytes are unavailable");
            return Err(validate_pe::UnavailablePeRange
            {
                rva: codeview_rva,
                size: codeview_size,
            });
        }

        let codeview_end = match codeview_rva.checked_add(codeview_size)
        {
            Some(value) => value,
            None => continue,
        };

        let codeview_data = match module_bytes.get(codeview_rva..codeview_end)
        {
            Some(value) => value,
            None => continue,
        };

        let codeview_signature = match codeview_data.get(..CODEVIEW_SIGNATURE_SIZE)
        {
            Some(value) => value,
            None => continue,
        };

        let pdb_record = if codeview_signature == b"RSDS"
        {
            match (
                read_guid(codeview_data, RSDS_GUID_OFFSET),
                read_u32_le(codeview_data, RSDS_AGE_OFFSET),
                read_pdb_path(codeview_data, RSDS_PATH_OFFSET),
            )
            {
                (Some(guid), Some(age), Some(pdb_path)) => Some((PdbCodeViewFormat::Rsds, Some(guid), None, age, pdb_path)),
                _ => None,
            }
        }
        else if codeview_signature == b"NB10"
        {
            match (
                read_u32_le(codeview_data, NB10_SIGNATURE_OFFSET),
                read_u32_le(codeview_data, NB10_AGE_OFFSET),
                read_pdb_path(codeview_data, NB10_PATH_OFFSET),
            )
            {
                (Some(signature), Some(age), Some(pdb_path)) => Some((PdbCodeViewFormat::Nb10, None, Some(signature), age, pdb_path)),
                _ => None,
            }
        }
        else
        {
            continue;
        };

        let (format, guid, signature, age, pdb_path) = match pdb_record
        {
            Some(value) => value,
            None => continue,
        };

        return Ok(Some(PdbInfo
        {
            format,
            path: build_path_info(pdb_path),
            guid,
            signature,
            age,
            debug_directory_rva: entry_rva,
            debug_directory_file_offset: pe_utils::get_file_offset_from_pe(pe, entry_rva),
            codeview_rva,
            codeview_file_offset: pe_utils::get_file_offset_from_pe(pe, codeview_rva).or_else(||
            {
                if entry.PointerToRawData == 0
                {
                    None
                }
                else
                {
                    Some(entry.PointerToRawData as usize)
                }
            }),
            codeview_size,
        }));
    }

    Ok(None)
}


/// Reads a plain C-compatible value from a possibly unaligned byte offset.
/// `bytes`: the source byte buffer.
/// `offset`: the byte offset where the value begins.
///
/// Returns the copied value when the range is present.
fn read_value<T: Copy>(bytes: &[u8], offset: usize) -> Option<T>
{
    let value_end = offset.checked_add(size_of::<T>())?;
    let value_bytes = bytes.get(offset..value_end)?;

    // SAFETY: the range check guarantees a complete copied `T`, and `read_unaligned` permits byte-aligned PE fields.
    Some(unsafe { std::ptr::read_unaligned(value_bytes.as_ptr() as *const T) })
}


/// Reads an RSDS GUID from CodeView bytes.
/// `bytes`: the CodeView record bytes.
/// `offset`: the byte offset where the GUID begins.
///
/// Returns the GUID in display-ready field order.
fn read_guid(bytes: &[u8], offset: usize) -> Option<PdbGuid>
{
    let data4_start = offset.checked_add(8)?;
    let data4_end = data4_start.checked_add(8)?;

    Some(PdbGuid
    {
        data1: read_u32_le(bytes, offset)?,
        data2: u16::from_le_bytes(bytes.get(offset.checked_add(4)?..offset.checked_add(6)?)?.try_into().ok()?),
        data3: u16::from_le_bytes(bytes.get(offset.checked_add(6)?..offset.checked_add(8)?)?.try_into().ok()?),
        data4: bytes.get(data4_start..data4_end)?.try_into().ok()?,
    })
}


/// Reads a little-endian `u32` from a byte buffer.
/// `bytes`: the source bytes.
/// `offset`: the byte offset where the value begins.
///
/// Returns the parsed value when four bytes are available.
fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32>
{
    Some(u32::from_le_bytes(bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?))
}


/// Reads a NUL-terminated PDB path string from CodeView bytes.
/// `bytes`: the CodeView record bytes.
/// `offset`: the byte offset where the string begins.
///
/// Returns a lossy UTF-8 path string when a non-empty NUL-terminated value exists.
fn read_pdb_path(bytes: &[u8], offset: usize) -> Option<Box<str>>
{
    let bytes = bytes.get(offset..)?;
    let path = CStr::from_bytes_until_nul(bytes).ok()?.to_string_lossy();

    if path.is_empty()
    {
        return None;
    }

    Some(path.into_owned().into_boxed_str())
}


/// Extracts file-system parts from a PDB path string.
/// `full_path`: the PDB path extracted from CodeView data.
///
/// Returns the path split into reusable analyst-facing fields.
fn build_path_info(full_path: Box<str>) -> PdbPathInfo
{
    let path = Path::new(full_path.as_ref());
    
    let directory = path
        .parent()
        .map(|value| value.to_string_lossy().into_owned().into_boxed_str())
        .filter(|value| !value.is_empty());
    let file_name = path
        .file_name()
        .map(|value| value.to_string_lossy().into_owned().into_boxed_str())
        .filter(|value| !value.is_empty());
    let file_stem = path
        .file_stem()
        .map(|value| value.to_string_lossy().into_owned().into_boxed_str())
        .filter(|value| !value.is_empty());
    let extension = path
        .extension()
        .map(|value| value.to_string_lossy().into_owned().into_boxed_str())
        .filter(|value| !value.is_empty());
    let exists_on_disk = path.is_file();

    PdbPathInfo
    {
        full_path,
        directory,
        file_name,
        file_stem,
        extension,
        exists_on_disk,
    }
}
