use crate::core::file_ops::procedures::pdb::payloads::{parse_debug_details, DebugParseBudget, MAX_DECODED_DEBUG_BYTES, MAX_SCANNED_DEBUG_BYTES};
use crate::core::file_ops::procedures::pdb::types::{FileDebugEntry, FileDebugType};
use crate::core::file_ops::utils::supports::{read_u16, read_u32, rva_to_file_range};
use crate::core::file_ops::utils::validate::ValidatedPeFile;

const PE_SIGNATURE_SIZE: usize = 4;
const COFF_HEADER_SIZE: usize = 20;
const OPTIONAL_HEADER_DATA_DIRECTORY_COUNT_OFFSET: usize = 108;
const OPTIONAL_HEADER_DATA_DIRECTORY_OFFSET: usize = 112;
const DATA_DIRECTORY_SIZE: usize = 8;
const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6;
const DEBUG_DIRECTORY_ENTRY_SIZE: usize = 28;

/// Maximum number of debug-directory entries collected from one file.
pub const MAX_DEBUG_DIRECTORY_ENTRIES: usize = 1024;

/// Collects every entry and available payload from a validated raw PE debug directory.
/// `file`: the validated EXE or DLL whose debug data should be parsed without loading it.
///
/// Returns up to 1024 readable directory entries in table order. Malformed or
/// unsupported payloads remain represented by their header fields and bounded
/// raw bytes. Directory-level failures are reported on stderr.
pub fn collect_file_debug_directory<'a>(file: &'a ValidatedPeFile) -> Vec<FileDebugEntry<'a>>
{
    let (directory_rva, directory_size) = match get_debug_directory(file)
    {
        Some(value) => value,
        None => return Vec::new(),
    };
    let (directory_file_offset, directory_mapped_end) = match rva_to_file_range(file, directory_rva)
    {
        Some(value) => value,
        None =>
        {
            eprintln!("debug directory RVA 0x{:08X} is not backed by raw data", directory_rva);
            return Vec::new();
        }
    };
    let mapped_size = directory_mapped_end - directory_file_offset;
    let readable_size = directory_size.min(mapped_size);
    let entry_count = (readable_size / DEBUG_DIRECTORY_ENTRY_SIZE).min(MAX_DEBUG_DIRECTORY_ENTRIES);
    let mut entries = Vec::with_capacity(entry_count);
    let mut parse_budget = DebugParseBudget {
        decoded_bytes: file.bytes.len().min(MAX_DECODED_DEBUG_BYTES),
        scanned_bytes: file.bytes.len().min(MAX_SCANNED_DEBUG_BYTES),
    };

    for index in 0..entry_count
    {
        let entry_rva = match index.checked_mul(DEBUG_DIRECTORY_ENTRY_SIZE).and_then(|offset| directory_rva.checked_add(offset))
        {
            Some(value) => value,
            None =>
            {
                eprintln!("debug directory entry {} RVA overflowed", index);
                break;
            }
        };
        let entry_file_offset = match index.checked_mul(DEBUG_DIRECTORY_ENTRY_SIZE).and_then(|offset| directory_file_offset.checked_add(offset))
        {
            Some(value) => value,
            None =>
            {
                eprintln!("debug directory entry {} file offset overflowed", index);
                break;
            }
        };
        let entry_end = match entry_file_offset.checked_add(DEBUG_DIRECTORY_ENTRY_SIZE)
        {
            Some(value) => value,
            None =>
            {
                eprintln!("debug directory entry {} end offset overflowed", index);
                break;
            }
        };
        let entry_bytes = match file.bytes.get(entry_file_offset..entry_end)
        {
            Some(value) => value,
            None =>
            {
                eprintln!("failed to read debug directory entry {} at file offset 0x{:08X}", index, entry_file_offset);
                break;
            }
        };

        let Some(characteristics) = read_u32(entry_bytes, 0)
        else
        {
            eprintln!("failed to read debug directory entry {} characteristics", index);
            break;
        };

        let Some(timestamp) = read_u32(entry_bytes, 4)
        else
        {
            eprintln!("failed to read debug directory entry {} timestamp", index);
            break;
        };

        let Some(major_version) = read_u16(entry_bytes, 8)
        else
        {
            eprintln!("failed to read debug directory entry {} major version", index);
            break;
        };

        let Some(minor_version) = read_u16(entry_bytes, 10)
        else
        {
            eprintln!("failed to read debug directory entry {} minor version", index);
            break;
        };

        let Some(raw_type) = read_u32(entry_bytes, 12)
        else
        {
            eprintln!("failed to read debug directory entry {} type", index);
            break;
        };

        let Some(size_of_data) = read_u32(entry_bytes, 16).map(|value| value as usize)
        else
        {
            eprintln!("failed to read debug directory entry {} data size", index);
            break;
        };

        let Some(address_of_raw_data) = read_u32(entry_bytes, 20)
        else
        {
            eprintln!("failed to read debug directory entry {} data RVA", index);
            break;
        };

        let Some(pointer_to_raw_data) = read_u32(entry_bytes, 24)
        else
        {
            eprintln!("failed to read debug directory entry {} data pointer", index);
            break;
        };

        let debug_type = FileDebugType::from(raw_type);

        let rva_data_file_offset = (address_of_raw_data != 0).then(|| rva_to_file_range(file, address_of_raw_data as usize).map(|(file_offset, _)| file_offset)).flatten();

        let data_location_mismatch = pointer_to_raw_data != 0 && rva_data_file_offset.is_some_and(|offset| offset != pointer_to_raw_data as usize);

        let (data_file_offset, raw_data) = collect_debug_data(file, size_of_data, address_of_raw_data, pointer_to_raw_data);

        let details = parse_debug_details(debug_type, raw_data, &mut parse_budget);

        entries.push(FileDebugEntry {
            index,
            entry_rva,
            entry_file_offset,
            characteristics,
            timestamp,
            major_version,
            minor_version,
            raw_type,
            debug_type,
            size_of_data,
            address_of_raw_data,
            pointer_to_raw_data,
            rva_data_file_offset,
            data_file_offset,
            data_location_mismatch,
            raw_data,
            details,
        });
    }

    entries
}


/// Reads the debug data-directory RVA and size from the PE optional header.
/// `file`: the validated EXE or DLL whose optional header should be read.
///
/// Returns the directory RVA and size when the entry exists inside the optional
/// header, is non-zero, and holds at least one entry; `None` otherwise, with
/// the failure reported on stderr.
fn get_debug_directory(file: &ValidatedPeFile) -> Option<(usize, usize)>
{
    let nt_header_offset = match read_u32(&file.bytes, 0x3C)
    {
        Some(value) => value as usize,
        None =>
        {
            eprintln!("failed to read the NT header offset at 0x3C");
            return None;
        }
    };

    let optional_header_offset = match nt_header_offset.checked_add(PE_SIGNATURE_SIZE).and_then(|offset| offset.checked_add(COFF_HEADER_SIZE))
    {
        Some(value) => value,
        None =>
        {
            eprintln!("optional header offset overflowed from NT header offset 0x{:08X}", nt_header_offset);
            return None;
        }
    };

    let optional_header_size = match nt_header_offset.checked_add(PE_SIGNATURE_SIZE + 16).and_then(|offset| read_u16(&file.bytes, offset))
    {
        Some(value) => value as usize,
        None =>
        {
            eprintln!("failed to read the optional header size from the COFF header");
            return None;
        }
    };

    let optional_header_end = match optional_header_offset.checked_add(optional_header_size)
    {
        Some(value) => value,
        None =>
        {
            eprintln!("optional header end overflowed at offset 0x{:08X}", optional_header_offset);
            return None;
        }
    };

    let directory_count = match optional_header_offset.checked_add(OPTIONAL_HEADER_DATA_DIRECTORY_COUNT_OFFSET).and_then(|offset| read_u32(&file.bytes, offset))
    {
        Some(value) => value as usize,
        None =>
        {
            eprintln!("failed to read the data-directory count from the optional header");
            return None;
        }
    };

    if directory_count <= IMAGE_DIRECTORY_ENTRY_DEBUG
    {
        eprintln!("data-directory count {} has no debug directory entry", directory_count);
        return None;
    }

    let debug_directory_offset = match IMAGE_DIRECTORY_ENTRY_DEBUG.checked_mul(DATA_DIRECTORY_SIZE).and_then(|offset| OPTIONAL_HEADER_DATA_DIRECTORY_OFFSET.checked_add(offset)).and_then(|offset| optional_header_offset.checked_add(offset))
    {
        Some(value) => value,
        None =>
        {
            eprintln!("debug data-directory entry offset overflowed");
            return None;
        }
    };
    let debug_directory_end = match debug_directory_offset.checked_add(DATA_DIRECTORY_SIZE)
    {
        Some(value) => value,
        None =>
        {
            eprintln!("debug data-directory entry end overflowed at offset 0x{:08X}", debug_directory_offset);
            return None;
        }
    };

    if debug_directory_end > optional_header_end
    {
        eprintln!("debug data-directory entry ends outside the optional header");
        return None;
    }

    let directory_rva = match read_u32(&file.bytes, debug_directory_offset)
    {
        Some(value) => value as usize,
        None =>
        {
            eprintln!("failed to read the debug directory RVA at offset 0x{:08X}", debug_directory_offset);
            return None;
        }
    };
    let directory_size = match read_u32(&file.bytes, debug_directory_offset + 4)
    {
        Some(value) => value as usize,
        None =>
        {
            eprintln!("failed to read the debug directory size at offset 0x{:08X}", debug_directory_offset + 4);
            return None;
        }
    };

    if directory_rva == 0 || directory_size < DEBUG_DIRECTORY_ENTRY_SIZE
    {
        eprintln!("debug directory RVA 0x{:08X} with size 0x{:08X} holds no entries", directory_rva, directory_size);
        return None;
    }

    Some((directory_rva, directory_size))
}


/// Collects raw debug payload bytes using the file pointer before the optional RVA fallback.
fn collect_debug_data(file: &ValidatedPeFile, size: usize, address_of_raw_data: u32, pointer_to_raw_data: u32) -> (Option<usize>, Option<&[u8]>)
{
    if size == 0
    {
        return (None, Some(&[]));
    }

    if pointer_to_raw_data != 0
    {
        let file_offset = pointer_to_raw_data as usize;
        let data_end = file_offset.checked_add(size);

        if let Some(data) = data_end.filter(|end| *end <= file.bytes.len()).and_then(|end| file.bytes.get(file_offset..end))
        {
            return (Some(file_offset), Some(data));
        }
    }

    if address_of_raw_data != 0
    {
        let rva = address_of_raw_data as usize;

        if let Some((file_offset, mapped_end)) = rva_to_file_range(file, rva)
        {
            let requested_end = file_offset.checked_add(size);

            if let Some(data) = requested_end.filter(|end| *end <= mapped_end).and_then(|end| file.bytes.get(file_offset..end))
            {
                return (Some(file_offset), Some(data));
            }
        }
    }

    (None, None)
}
