use std::fmt;

use crate::core::file_ops::utils::supports::{read_u16, read_u32, rva_to_file_range};
use crate::core::file_ops::utils::validate::ValidatedPeFile;
use crate::core::process_ops::utils::pdbutils::PdbGuid;

const PE_SIGNATURE_SIZE: usize = 4;
const COFF_HEADER_SIZE: usize = 20;
const OPTIONAL_HEADER_DATA_DIRECTORY_COUNT_OFFSET: usize = 108;
const OPTIONAL_HEADER_DATA_DIRECTORY_OFFSET: usize = 112;
const DATA_DIRECTORY_SIZE: usize = 8;
const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6;
const DEBUG_DIRECTORY_ENTRY_SIZE: usize = 28;
const RSDS_AGE_OFFSET: usize = 20;
const RSDS_PATH_OFFSET: usize = 24;
const NB10_OFFSET_OFFSET: usize = 4;
const NB10_SIGNATURE_OFFSET: usize = 8;
const NB10_AGE_OFFSET: usize = 12;
const NB10_PATH_OFFSET: usize = 16;
/// Maximum number of debug-directory entries collected from one file.
pub const MAX_DEBUG_DIRECTORY_ENTRIES: usize = 1024;
const MAX_DECODED_DEBUG_BYTES: usize = 8 * 1024 * 1024;
const MAX_SCANNED_DEBUG_BYTES: usize = 8 * 1024 * 1024;

/// Identifies the payload format declared by an `IMAGE_DEBUG_DIRECTORY` entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileDebugType
{
    Unknown,
    Coff,
    CodeView,
    Fpo,
    Misc,
    Exception,
    Fixup,
    OmapToSource,
    OmapFromSource,
    Borland,
    Reserved10,
    Clsid,
    VcFeature,
    Pogo,
    Iltcg,
    Mpx,
    Reproducible,
    EmbeddedPortablePdb,
    Spgo,
    PdbChecksum,
    ExtendedDllCharacteristics,
    Other(u32),
}


/// Contains parsed CodeView metadata for an RSDS, NB10, or unknown signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FileCodeViewInfo
{
    Rsds
    {
        guid: PdbGuid,
        age: u32,
        path: Box<str>,
    },
    Nb10
    {
        offset: u32,
        signature: u32,
        age: u32,
        path: Box<str>,
    },
    Other([u8; 4]),
}


/// Contains the five counters stored in a Visual C++ feature debug payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileVcFeatureInfo
{
    pub pre_vc11: u32,
    pub c_cpp: u32,
    pub gs: u32,
    pub sdl: u32,
    pub guard_n: u32,
}


/// Describes one procedure group stored in a POGO debug payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilePogoEntry
{
    pub rva: u32,
    pub size: u32,
    pub name: Box<str>,
}


/// Contains a POGO signature and every aligned procedure group in its payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilePogoInfo
{
    pub signature: [u8; 4],
    pub entries: Vec<FilePogoEntry>,
}


/// Contains the optional length-prefixed hash stored by a reproducible-build entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileReproducibleInfo
{
    pub declared_hash_length: Option<usize>,
    pub hash: Box<[u8]>,
    pub length_matches: bool,
}


/// Contains parsed `IMAGE_DEBUG_MISC` metadata and its optional text value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileMiscDebugInfo
{
    pub data_type: u32,
    pub declared_length: usize,
    pub unicode: bool,
    pub text: Option<Box<str>>,
}


/// Contains a symbol-file checksum algorithm name and checksum bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilePdbChecksumInfo
{
    pub algorithm: Box<str>,
    pub checksum: Box<[u8]>,
}


/// Contains the envelope metadata for an embedded compressed Portable PDB.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileEmbeddedPortablePdbInfo
{
    pub uncompressed_size: usize,
    pub compressed_size: usize,
}


/// Describes typed interpretation status for one debug payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FileDebugDetails
{
    None,
    CodeView(FileCodeViewInfo),
    VcFeature(FileVcFeatureInfo),
    Pogo(FilePogoInfo),
    Reproducible(FileReproducibleInfo),
    Misc(FileMiscDebugInfo),
    PdbChecksum(FilePdbChecksumInfo),
    EmbeddedPortablePdb(FileEmbeddedPortablePdbInfo),
    ExtendedDllCharacteristics(u32),
    Raw,
    Malformed,
    DecodeLimitExceeded,
    Unavailable,
}


/// Contains one raw PE debug-directory entry and its safely collected payload metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileDebugEntry<'a>
{
    pub index: usize,
    pub entry_rva: usize,
    pub entry_file_offset: usize,
    pub characteristics: u32,
    pub timestamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub raw_type: u32,
    pub debug_type: FileDebugType,
    pub size_of_data: usize,
    pub address_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub rva_data_file_offset: Option<usize>,
    pub data_file_offset: Option<usize>,
    pub data_location_mismatch: bool,
    pub raw_data: Option<&'a [u8]>,
    pub details: FileDebugDetails,
}


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
    let entry_count = (readable_size / DEBUG_DIRECTORY_ENTRY_SIZE)
        .min(MAX_DEBUG_DIRECTORY_ENTRIES);
    let mut entries = Vec::with_capacity(entry_count);
    let mut parse_budget = DebugParseBudget
    {
        decoded_bytes: file.bytes.len().min(MAX_DECODED_DEBUG_BYTES),
        scanned_bytes: file.bytes.len().min(MAX_SCANNED_DEBUG_BYTES),
    };

    for index in 0..entry_count
    {
        let entry_rva = match index
            .checked_mul(DEBUG_DIRECTORY_ENTRY_SIZE)
            .and_then(|offset| directory_rva.checked_add(offset))
        {
            Some(value) => value,
            None =>
            {
                eprintln!("debug directory entry {} RVA overflowed", index);
                break;
            }
        };
        let entry_file_offset = match index
            .checked_mul(DEBUG_DIRECTORY_ENTRY_SIZE)
            .and_then(|offset| directory_file_offset.checked_add(offset))
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
                eprintln!(
                    "failed to read debug directory entry {} at file offset 0x{:08X}",
                    index, entry_file_offset
                );
                break;
            }
        };

        let Some(characteristics) = read_u32(entry_bytes, 0) else
        {
            eprintln!("failed to read debug directory entry {} characteristics", index);
            break;
        };

        let Some(timestamp) = read_u32(entry_bytes, 4) else
        {
            eprintln!("failed to read debug directory entry {} timestamp", index);
            break;
        };

        let Some(major_version) = read_u16(entry_bytes, 8) else
        {
            eprintln!("failed to read debug directory entry {} major version", index);
            break;
        };

        let Some(minor_version) = read_u16(entry_bytes, 10) else
        {
            eprintln!("failed to read debug directory entry {} minor version", index);
            break;
        };

        let Some(raw_type) = read_u32(entry_bytes, 12) else
        {
            eprintln!("failed to read debug directory entry {} type", index);
            break;
        };

        let Some(size_of_data) = read_u32(entry_bytes, 16).map(|value| value as usize) else
        {
            eprintln!("failed to read debug directory entry {} data size", index);
            break;
        };

        let Some(address_of_raw_data) = read_u32(entry_bytes, 20) else
        {
            eprintln!("failed to read debug directory entry {} data RVA", index);
            break;
        };

        let Some(pointer_to_raw_data) = read_u32(entry_bytes, 24) else
        {
            eprintln!("failed to read debug directory entry {} data pointer", index);
            break;
        };

        let debug_type = FileDebugType::from(raw_type);

        let rva_data_file_offset = (address_of_raw_data != 0)
            .then(|| rva_to_file_range(file, address_of_raw_data as usize)
                .map(|(file_offset, _)| file_offset))
            .flatten();

        let data_location_mismatch = pointer_to_raw_data != 0
            && rva_data_file_offset
                .is_some_and(|offset| offset != pointer_to_raw_data as usize);

        let (data_file_offset, raw_data) = collect_debug_data(
            file,
            size_of_data,
            address_of_raw_data,
            pointer_to_raw_data,
        );
        
        let details = parse_debug_details(
            debug_type,
            raw_data,
            &mut parse_budget,
        );

        entries.push(FileDebugEntry
        {
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


impl From<u32> for FileDebugType
{
    fn from(value: u32) -> Self
    {
        match value
        {
            0 => Self::Unknown,
            1 => Self::Coff,
            2 => Self::CodeView,
            3 => Self::Fpo,
            4 => Self::Misc,
            5 => Self::Exception,
            6 => Self::Fixup,
            7 => Self::OmapToSource,
            8 => Self::OmapFromSource,
            9 => Self::Borland,
            10 => Self::Reserved10,
            11 => Self::Clsid,
            12 => Self::VcFeature,
            13 => Self::Pogo,
            14 => Self::Iltcg,
            15 => Self::Mpx,
            16 => Self::Reproducible,
            17 => Self::EmbeddedPortablePdb,
            18 => Self::Spgo,
            19 => Self::PdbChecksum,
            20 => Self::ExtendedDllCharacteristics,
            other => Self::Other(other),
        }
    }
}


impl fmt::Display for FileDebugType
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        let name = match self
        {
            Self::Unknown => "Unknown",
            Self::Coff => "COFF",
            Self::CodeView => "CodeView",
            Self::Fpo => "FPO",
            Self::Misc => "Misc",
            Self::Exception => "Exception",
            Self::Fixup => "Fixup",
            Self::OmapToSource => "OMAP to source",
            Self::OmapFromSource => "OMAP from source",
            Self::Borland => "Borland",
            Self::Reserved10 => "Reserved/BBT",
            Self::Clsid => "CLSID",
            Self::VcFeature => "VC feature",
            Self::Pogo => "POGO",
            Self::Iltcg => "ILTCG",
            Self::Mpx => "MPX",
            Self::Reproducible => "Reproducible",
            Self::EmbeddedPortablePdb => "Embedded Portable PDB",
            Self::Spgo => "SPGO",
            Self::PdbChecksum => "PDB checksum",
            Self::ExtendedDllCharacteristics => "Extended DLL characteristics",
            Self::Other(_) => "Other",
        };

        formatter.write_str(name)
    }
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

    let optional_header_offset = match nt_header_offset
        .checked_add(PE_SIGNATURE_SIZE)
        .and_then(|offset| offset.checked_add(COFF_HEADER_SIZE))
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

    let directory_count = match optional_header_offset
        .checked_add(OPTIONAL_HEADER_DATA_DIRECTORY_COUNT_OFFSET)
        .and_then(|offset| read_u32(&file.bytes, offset))
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

    let debug_directory_offset = match IMAGE_DIRECTORY_ENTRY_DEBUG
        .checked_mul(DATA_DIRECTORY_SIZE)
        .and_then(|offset| OPTIONAL_HEADER_DATA_DIRECTORY_OFFSET.checked_add(offset))
        .and_then(|offset| optional_header_offset.checked_add(offset))
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
        eprintln!(
            "debug directory RVA 0x{:08X} with size 0x{:08X} holds no entries",
            directory_rva, directory_size
        );
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

        if let Some(data) = data_end
            .filter(|end| *end <= file.bytes.len())
            .and_then(|end| file.bytes.get(file_offset..end))
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

            if let Some(data) = requested_end
                .filter(|end| *end <= mapped_end)
                .and_then(|end| file.bytes.get(file_offset..end))
            {
                return (Some(file_offset), Some(data));
            }
        }
    }

    (None, None)
}


/// Selects the typed parser for one available debug payload.
fn parse_debug_details(debug_type: FileDebugType, data: Option<&[u8]>, parse_budget: &mut DebugParseBudget) -> FileDebugDetails
{
    let data = match data
    {
        Some(value) => value,
        None => return FileDebugDetails::Unavailable,
    };
    let scanned_bytes = match debug_type
    {
        FileDebugType::CodeView
        | FileDebugType::Misc
        | FileDebugType::VcFeature
        | FileDebugType::Pogo
        | FileDebugType::Reproducible
        | FileDebugType::EmbeddedPortablePdb
        | FileDebugType::PdbChecksum
        | FileDebugType::ExtendedDllCharacteristics => data.len(),
        _ => 0,
    };
    parse_budget.scanned_bytes = match parse_budget.scanned_bytes.checked_sub(scanned_bytes)
    {
        Some(value) => value,
        None => return FileDebugDetails::DecodeLimitExceeded,
    };

    let mut remaining_budget = parse_budget.decoded_bytes;
    let parsed = match debug_type
    {
        FileDebugType::CodeView => parse_codeview(data, &mut remaining_budget)
            .map(FileDebugDetails::CodeView),
        FileDebugType::VcFeature => parse_vc_feature(data)
            .ok_or(DebugParseError::Malformed)
            .map(FileDebugDetails::VcFeature),
        FileDebugType::Pogo => parse_pogo(data, &mut remaining_budget)
            .map(FileDebugDetails::Pogo),
        FileDebugType::Reproducible => parse_reproducible(data, &mut remaining_budget)
            .map(FileDebugDetails::Reproducible),
        FileDebugType::Misc => parse_misc(data, &mut remaining_budget)
            .map(FileDebugDetails::Misc),
        FileDebugType::PdbChecksum => parse_pdb_checksum(data, &mut remaining_budget)
            .map(FileDebugDetails::PdbChecksum),
        FileDebugType::EmbeddedPortablePdb => parse_embedded_portable_pdb(data)
            .ok_or(DebugParseError::Malformed)
            .map(FileDebugDetails::EmbeddedPortablePdb),
        FileDebugType::ExtendedDllCharacteristics => read_u32(data, 0)
            .ok_or(DebugParseError::Malformed)
            .map(FileDebugDetails::ExtendedDllCharacteristics),
        _ if data.is_empty() => Ok(FileDebugDetails::None),
        _ => Ok(FileDebugDetails::Raw),
    };

    match parsed
    {
        Ok(details) =>
        {
            parse_budget.decoded_bytes = remaining_budget;

            details
        }
        Err(DebugParseError::Malformed) => FileDebugDetails::Malformed,
        Err(DebugParseError::DecodeLimitExceeded) => FileDebugDetails::DecodeLimitExceeded,
    }
}


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DebugParseBudget
{
    decoded_bytes: usize,
    scanned_bytes: usize,
}


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DebugParseError
{
    Malformed,
    DecodeLimitExceeded,
}


/// Charges retained decoded data before its allocation.
fn charge_decoded_data(decoded_data_budget: &mut usize, retained_bytes: usize) -> Result<(), DebugParseError>
{
    *decoded_data_budget = decoded_data_budget
        .checked_sub(retained_bytes)
        .ok_or(DebugParseError::DecodeLimitExceeded)?;

    Ok(())
}


/// Computes a conservative decoded string size without overflowing.
fn decoded_string_size(byte_length: usize) -> Result<usize, DebugParseError>
{
    byte_length.checked_mul(3).ok_or(DebugParseError::DecodeLimitExceeded)
}


/// Parses RSDS, NB10, or an unknown four-byte CodeView signature.
fn parse_codeview(data: &[u8], decoded_data_budget: &mut usize) -> Result<FileCodeViewInfo, DebugParseError>
{
    let signature: [u8; 4] = data
        .get(..4)
        .ok_or(DebugParseError::Malformed)?
        .try_into()
        .map_err(|_| DebugParseError::Malformed)?;

    if signature == *b"RSDS"
    {
        return Ok(FileCodeViewInfo::Rsds
        {
            guid: read_guid(data, 4).ok_or(DebugParseError::Malformed)?,
            age: read_u32(data, RSDS_AGE_OFFSET).ok_or(DebugParseError::Malformed)?,
            path: read_c_string(data, RSDS_PATH_OFFSET, decoded_data_budget)?,
        });
    }

    if signature == *b"NB10"
    {
        return Ok(FileCodeViewInfo::Nb10
        {
            offset: read_u32(data, NB10_OFFSET_OFFSET).ok_or(DebugParseError::Malformed)?,
            signature: read_u32(data, NB10_SIGNATURE_OFFSET).ok_or(DebugParseError::Malformed)?,
            age: read_u32(data, NB10_AGE_OFFSET).ok_or(DebugParseError::Malformed)?,
            path: read_c_string(data, NB10_PATH_OFFSET, decoded_data_budget)?,
        });
    }

    Ok(FileCodeViewInfo::Other(signature))
}


/// Parses the five little-endian counters in a VC feature payload.
fn parse_vc_feature(data: &[u8]) -> Option<FileVcFeatureInfo>
{
    Some(FileVcFeatureInfo
    {
        pre_vc11: read_u32(data, 0)?,
        c_cpp: read_u32(data, 4)?,
        gs: read_u32(data, 8)?,
        sdl: read_u32(data, 12)?,
        guard_n: read_u32(data, 16)?,
    })
}


/// Parses aligned POGO procedure-group records after their four-byte signature.
fn parse_pogo(data: &[u8], decoded_data_budget: &mut usize) -> Result<FilePogoInfo, DebugParseError>
{
    let signature = data
        .get(..4)
        .ok_or(DebugParseError::Malformed)?
        .try_into()
        .map_err(|_| DebugParseError::Malformed)?;

    let mut entries = Vec::new();
    let mut offset = 4usize;

    while offset < data.len()
    {
        if data[offset..].iter().all(|byte| *byte == 0)
        {
            break;
        }

        let rva = read_u32(data, offset).ok_or(DebugParseError::Malformed)?;
        let size_offset = offset.checked_add(4).ok_or(DebugParseError::Malformed)?;
        let size = read_u32(data, size_offset).ok_or(DebugParseError::Malformed)?;
        let name_offset = offset.checked_add(8).ok_or(DebugParseError::Malformed)?;
        let name_bytes = data.get(name_offset..).ok_or(DebugParseError::Malformed)?;

        let name_length = name_bytes
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(DebugParseError::Malformed)?;

        if name_length == 0
        {
            return Err(DebugParseError::Malformed);
        }

        let next_offset = name_offset
            .checked_add(name_length)
            .and_then(|value| value.checked_add(1))
            .ok_or(DebugParseError::Malformed)?;

        let aligned_offset = next_offset
            .checked_add(3)
            .ok_or(DebugParseError::Malformed)? & !3;

        if aligned_offset > data.len()
        {
            return Err(DebugParseError::Malformed);
        }

        let retained_bytes = decoded_string_size(name_length)?
            .checked_add(std::mem::size_of::<FilePogoEntry>())
            .ok_or(DebugParseError::DecodeLimitExceeded)?;

        charge_decoded_data(decoded_data_budget, retained_bytes)?;
        entries
            .try_reserve(1)
            .map_err(|_| DebugParseError::DecodeLimitExceeded)?;

        let name = String::from_utf8_lossy(&name_bytes[..name_length])
            .into_owned()
            .into_boxed_str();

        entries.push(FilePogoEntry
        {
            rva,
            size,
            name,
        });
        offset = aligned_offset;
    }

    Ok(FilePogoInfo
    {
        signature,
        entries,
    })
}


/// Parses an empty reproducible marker or its optional length-prefixed hash.
fn parse_reproducible(data: &[u8], decoded_data_budget: &mut usize) -> Result<FileReproducibleInfo, DebugParseError>
{
    if data.is_empty()
    {
        return Ok(FileReproducibleInfo
        {
            declared_hash_length: None,
            hash: Box::default(),
            length_matches: true,
        });
    }

    let declared_hash_length = read_u32(data, 0).ok_or(DebugParseError::Malformed)? as usize;
    let hash_bytes = data.get(4..).ok_or(DebugParseError::Malformed)?;
    let retained_length = declared_hash_length.min(hash_bytes.len());

    charge_decoded_data(decoded_data_budget, retained_length)?;

    Ok(FileReproducibleInfo
    {
        declared_hash_length: Some(declared_hash_length),
        hash: hash_bytes[..retained_length].into(),
        length_matches: declared_hash_length == hash_bytes.len(),
    })
}


/// Parses the fixed `IMAGE_DEBUG_MISC` header and optional ANSI or UTF-16 text.
fn parse_misc(data: &[u8], decoded_data_budget: &mut usize) -> Result<FileMiscDebugInfo, DebugParseError>
{
    let data_type = read_u32(data, 0).ok_or(DebugParseError::Malformed)?;
    let declared_length = read_u32(data, 4)
        .ok_or(DebugParseError::Malformed)? as usize;
    let unicode = *data.get(8).ok_or(DebugParseError::Malformed)? != 0;

    if declared_length < 12 || declared_length > data.len()
    {
        return Err(DebugParseError::Malformed);
    }

    let value_bytes = data
        .get(12..declared_length)
        .ok_or(DebugParseError::Malformed)?;
    let text = if unicode
    {
        if value_bytes.len() % 2 != 0
        {
            return Err(DebugParseError::Malformed);
        }

        let word_count = value_bytes
            .chunks_exact(2)
            .position(|pair| pair == [0, 0])
            .unwrap_or(value_bytes.len() / 2);

        if word_count == 0
        {
            None
        }
        else
        {
            charge_decoded_data(
                decoded_data_budget,
                decoded_string_size(word_count)?,
            )?;

            let string = std::char::decode_utf16(
                value_bytes[..word_count * 2]
                    .chunks_exact(2)
                    .map(|pair| u16::from_le_bytes([pair[0], pair[1]])),
            )
            .map(|character| character.unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect::<String>()
            .into_boxed_str();

            Some(string)
        }
    }
    else
    {
        let length = value_bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(value_bytes.len());

        if length == 0
        {
            None
        }
        else
        {
            charge_decoded_data(
                decoded_data_budget,
                decoded_string_size(length)?,
            )?;

            Some(String::from_utf8_lossy(&value_bytes[..length])
                .into_owned()
                .into_boxed_str())
        }
    };

    Ok(FileMiscDebugInfo
    {
        data_type,
        declared_length,
        unicode,
        text,
    })
}


/// Parses a NUL-terminated UTF-8 algorithm name followed by checksum bytes.
fn parse_pdb_checksum(
    data: &[u8],
    decoded_data_budget: &mut usize,
) -> Result<FilePdbChecksumInfo, DebugParseError>
{
    let algorithm_length = data
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(DebugParseError::Malformed)?;

    if algorithm_length == 0
    {
        return Err(DebugParseError::Malformed);
    }

    let algorithm = std::str::from_utf8(&data[..algorithm_length])
        .map_err(|_| DebugParseError::Malformed)?;
    let checksum_offset = algorithm_length
        .checked_add(1)
        .ok_or(DebugParseError::Malformed)?;
    let checksum = data.get(checksum_offset..).ok_or(DebugParseError::Malformed)?;

    if checksum.is_empty()
    {
        return Err(DebugParseError::Malformed);
    }

    let retained_bytes = algorithm_length
        .checked_add(checksum.len())
        .ok_or(DebugParseError::DecodeLimitExceeded)?;

    charge_decoded_data(decoded_data_budget, retained_bytes)?;

    Ok(FilePdbChecksumInfo
    {
        algorithm: algorithm.into(),
        checksum: checksum.into(),
    })
}


/// Parses the MPDB signature, decompressed size, and compressed payload size.
fn parse_embedded_portable_pdb(data: &[u8]) -> Option<FileEmbeddedPortablePdbInfo>
{
    let signature: [u8; 4] = data.get(..4)?.try_into().ok()?;

    if signature != *b"MPDB"
    {
        return None;
    }

    Some(FileEmbeddedPortablePdbInfo
    {
        uncompressed_size: read_u32(data, 4)? as usize,
        compressed_size: data.len().checked_sub(8)?,
    })
}


/// Reads a CodeView GUID in PE/PDB field order.
fn read_guid(data: &[u8], offset: usize) -> Option<PdbGuid>
{
    let data4_offset = offset.checked_add(8)?;
    let data4_end = data4_offset.checked_add(8)?;

    Some(PdbGuid
    {
        data1: read_u32(data, offset)?,
        data2: read_u16(data, offset.checked_add(4)?)?,
        data3: read_u16(data, offset.checked_add(6)?)?,
        data4: data.get(data4_offset..data4_end)?.try_into().ok()?,
    })
}


/// Reads one non-empty NUL-terminated string from a byte offset.
fn read_c_string(data: &[u8], offset: usize, decoded_data_budget: &mut usize) -> Result<Box<str>, DebugParseError>
{
    let bytes = data.get(offset..).ok_or(DebugParseError::Malformed)?;
    let length = bytes
        .iter()
        .position(|byte| *byte == 0)
        .filter(|length| *length != 0)
        .ok_or(DebugParseError::Malformed)?;

    charge_decoded_data(
        decoded_data_budget,
        decoded_string_size(length)?,
    )?;

    Ok(String::from_utf8_lossy(&bytes[..length])
        .into_owned()
        .into_boxed_str())
}

