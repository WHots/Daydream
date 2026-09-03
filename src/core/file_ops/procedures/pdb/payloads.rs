use crate::core::file_ops::procedures::pdb::codeview::parse_codeview;
use crate::core::file_ops::procedures::pdb::types::{FileDebugDetails, FileDebugType, FileEmbeddedPortablePdbInfo, FileMiscDebugInfo, FilePdbChecksumInfo, FilePogoEntry, FilePogoInfo, FileReproducibleInfo, FileVcFeatureInfo};
use crate::core::file_ops::utils::supports::read_u32;

pub(super) const MAX_DECODED_DEBUG_BYTES: usize = 8 * 1024 * 1024;
pub(super) const MAX_SCANNED_DEBUG_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct DebugParseBudget
{
    pub(super) decoded_bytes: usize,
    pub(super) scanned_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DebugParseError
{
    Malformed,
    DecodeLimitExceeded,
}


/// Selects the typed parser for one available debug payload.
pub(super) fn parse_debug_details(debug_type: FileDebugType, data: Option<&[u8]>, parse_budget: &mut DebugParseBudget) -> FileDebugDetails
{
    let data = match data
    {
        Some(value) => value,
        None => return FileDebugDetails::Unavailable,
    };
    let scanned_bytes = match debug_type
    {
        FileDebugType::CodeView | FileDebugType::Misc | FileDebugType::VcFeature | FileDebugType::Pogo | FileDebugType::Reproducible | FileDebugType::EmbeddedPortablePdb | FileDebugType::PdbChecksum | FileDebugType::ExtendedDllCharacteristics => data.len(),
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
        FileDebugType::CodeView => parse_codeview(data, &mut remaining_budget).map(FileDebugDetails::CodeView),
        FileDebugType::VcFeature => parse_vc_feature(data).ok_or(DebugParseError::Malformed).map(FileDebugDetails::VcFeature),
        FileDebugType::Pogo => parse_pogo(data, &mut remaining_budget).map(FileDebugDetails::Pogo),
        FileDebugType::Reproducible => parse_reproducible(data, &mut remaining_budget).map(FileDebugDetails::Reproducible),
        FileDebugType::Misc => parse_misc(data, &mut remaining_budget).map(FileDebugDetails::Misc),
        FileDebugType::PdbChecksum => parse_pdb_checksum(data, &mut remaining_budget).map(FileDebugDetails::PdbChecksum),
        FileDebugType::EmbeddedPortablePdb => parse_embedded_portable_pdb(data).ok_or(DebugParseError::Malformed).map(FileDebugDetails::EmbeddedPortablePdb),
        FileDebugType::ExtendedDllCharacteristics => read_u32(data, 0).ok_or(DebugParseError::Malformed).map(FileDebugDetails::ExtendedDllCharacteristics),
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


/// Charges retained decoded data before its allocation.
pub(super) fn charge_decoded_data(decoded_data_budget: &mut usize, retained_bytes: usize) -> Result<(), DebugParseError>
{
    *decoded_data_budget = decoded_data_budget.checked_sub(retained_bytes).ok_or(DebugParseError::DecodeLimitExceeded)?;

    Ok(())
}


/// Computes a conservative decoded string size without overflowing.
pub(super) fn decoded_string_size(byte_length: usize) -> Result<usize, DebugParseError>
{
    byte_length.checked_mul(3).ok_or(DebugParseError::DecodeLimitExceeded)
}


/// Parses the five little-endian counters in a VC feature payload.
fn parse_vc_feature(data: &[u8]) -> Option<FileVcFeatureInfo>
{
    Some(FileVcFeatureInfo {
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
    let signature = data.get(..4).ok_or(DebugParseError::Malformed)?.try_into().map_err(|_| DebugParseError::Malformed)?;

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

        let name_length = name_bytes.iter().position(|byte| *byte == 0).ok_or(DebugParseError::Malformed)?;

        if name_length == 0
        {
            return Err(DebugParseError::Malformed);
        }

        let next_offset = name_offset.checked_add(name_length).and_then(|value| value.checked_add(1)).ok_or(DebugParseError::Malformed)?;

        let aligned_offset = next_offset.checked_add(3).ok_or(DebugParseError::Malformed)? & !3;

        if aligned_offset > data.len()
        {
            return Err(DebugParseError::Malformed);
        }

        let retained_bytes = decoded_string_size(name_length)?.checked_add(std::mem::size_of::<FilePogoEntry>()).ok_or(DebugParseError::DecodeLimitExceeded)?;

        charge_decoded_data(decoded_data_budget, retained_bytes)?;
        entries.try_reserve(1).map_err(|_| DebugParseError::DecodeLimitExceeded)?;

        let name = String::from_utf8_lossy(&name_bytes[..name_length]).into_owned().into_boxed_str();

        entries.push(FilePogoEntry {
            rva,
            size,
            name,
        });
        offset = aligned_offset;
    }

    Ok(FilePogoInfo {
        signature,
        entries,
    })
}


/// Parses an empty reproducible marker or its optional length-prefixed hash.
fn parse_reproducible(data: &[u8], decoded_data_budget: &mut usize) -> Result<FileReproducibleInfo, DebugParseError>
{
    if data.is_empty()
    {
        return Ok(FileReproducibleInfo {
            declared_hash_length: None,
            hash: Box::default(),
            length_matches: true,
        });
    }

    let declared_hash_length = read_u32(data, 0).ok_or(DebugParseError::Malformed)? as usize;
    let hash_bytes = data.get(4..).ok_or(DebugParseError::Malformed)?;
    let retained_length = declared_hash_length.min(hash_bytes.len());

    charge_decoded_data(decoded_data_budget, retained_length)?;

    Ok(FileReproducibleInfo {
        declared_hash_length: Some(declared_hash_length),
        hash: hash_bytes[..retained_length].into(),
        length_matches: declared_hash_length == hash_bytes.len(),
    })
}


/// Parses the fixed `IMAGE_DEBUG_MISC` header and optional ANSI or UTF-16 text.
fn parse_misc(data: &[u8], decoded_data_budget: &mut usize) -> Result<FileMiscDebugInfo, DebugParseError>
{
    let data_type = read_u32(data, 0).ok_or(DebugParseError::Malformed)?;
    let declared_length = read_u32(data, 4).ok_or(DebugParseError::Malformed)? as usize;
    let unicode = *data.get(8).ok_or(DebugParseError::Malformed)? != 0;

    if declared_length < 12 || declared_length > data.len()
    {
        return Err(DebugParseError::Malformed);
    }

    let value_bytes = data.get(12..declared_length).ok_or(DebugParseError::Malformed)?;
    let text = if unicode
    {
        if value_bytes.len() % 2 != 0
        {
            return Err(DebugParseError::Malformed);
        }

        let word_count = value_bytes.chunks_exact(2).position(|pair| pair == [0, 0]).unwrap_or(value_bytes.len() / 2);

        if word_count == 0
        {
            None
        }
        else
        {
            charge_decoded_data(decoded_data_budget, decoded_string_size(word_count)?)?;

            let string = std::char::decode_utf16(value_bytes[..word_count * 2].chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]]))).map(|character| character.unwrap_or(char::REPLACEMENT_CHARACTER)).collect::<String>().into_boxed_str();

            Some(string)
        }
    }
    else
    {
        let length = value_bytes.iter().position(|byte| *byte == 0).unwrap_or(value_bytes.len());

        if length == 0
        {
            None
        }
        else
        {
            charge_decoded_data(decoded_data_budget, decoded_string_size(length)?)?;

            Some(String::from_utf8_lossy(&value_bytes[..length]).into_owned().into_boxed_str())
        }
    };

    Ok(FileMiscDebugInfo {
        data_type,
        declared_length,
        unicode,
        text,
    })
}


/// Parses a NUL-terminated UTF-8 algorithm name followed by checksum bytes.
fn parse_pdb_checksum(data: &[u8], decoded_data_budget: &mut usize) -> Result<FilePdbChecksumInfo, DebugParseError>
{
    let algorithm_length = data.iter().position(|byte| *byte == 0).ok_or(DebugParseError::Malformed)?;

    if algorithm_length == 0
    {
        return Err(DebugParseError::Malformed);
    }

    let algorithm = std::str::from_utf8(&data[..algorithm_length]).map_err(|_| DebugParseError::Malformed)?;
    let checksum_offset = algorithm_length.checked_add(1).ok_or(DebugParseError::Malformed)?;
    let checksum = data.get(checksum_offset..).ok_or(DebugParseError::Malformed)?;

    if checksum.is_empty()
    {
        return Err(DebugParseError::Malformed);
    }

    let retained_bytes = algorithm_length.checked_add(checksum.len()).ok_or(DebugParseError::DecodeLimitExceeded)?;

    charge_decoded_data(decoded_data_budget, retained_bytes)?;

    Ok(FilePdbChecksumInfo {
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

    Some(FileEmbeddedPortablePdbInfo {
        uncompressed_size: read_u32(data, 4)? as usize,
        compressed_size: data.len().checked_sub(8)?,
    })
}
