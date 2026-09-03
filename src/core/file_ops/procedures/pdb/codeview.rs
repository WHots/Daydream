use crate::core::file_ops::procedures::pdb::payloads::{charge_decoded_data, decoded_string_size, DebugParseError};
use crate::core::file_ops::procedures::pdb::types::FileCodeViewInfo;
use crate::core::file_ops::utils::supports::{read_u16, read_u32};
use crate::core::process_ops::procedures::debuginfo::pdb::PdbGuid;

const RSDS_AGE_OFFSET: usize = 20;
const RSDS_PATH_OFFSET: usize = 24;
const NB10_OFFSET_OFFSET: usize = 4;
const NB10_SIGNATURE_OFFSET: usize = 8;
const NB10_AGE_OFFSET: usize = 12;
const NB10_PATH_OFFSET: usize = 16;

/// Parses RSDS, NB10, or an unknown four-byte CodeView signature.
pub(super) fn parse_codeview(data: &[u8], decoded_data_budget: &mut usize) -> Result<FileCodeViewInfo, DebugParseError>
{
    let signature: [u8; 4] = data.get(..4).ok_or(DebugParseError::Malformed)?.try_into().map_err(|_| DebugParseError::Malformed)?;

    if signature == *b"RSDS"
    {
        return Ok(FileCodeViewInfo::Rsds {
            guid: read_guid(data, 4).ok_or(DebugParseError::Malformed)?,
            age: read_u32(data, RSDS_AGE_OFFSET).ok_or(DebugParseError::Malformed)?,
            path: read_c_string(data, RSDS_PATH_OFFSET, decoded_data_budget)?,
        });
    }

    if signature == *b"NB10"
    {
        return Ok(FileCodeViewInfo::Nb10 {
            offset: read_u32(data, NB10_OFFSET_OFFSET).ok_or(DebugParseError::Malformed)?,
            signature: read_u32(data, NB10_SIGNATURE_OFFSET).ok_or(DebugParseError::Malformed)?,
            age: read_u32(data, NB10_AGE_OFFSET).ok_or(DebugParseError::Malformed)?,
            path: read_c_string(data, NB10_PATH_OFFSET, decoded_data_budget)?,
        });
    }

    Ok(FileCodeViewInfo::Other(signature))
}


/// Reads a CodeView GUID in PE/PDB field order.
fn read_guid(data: &[u8], offset: usize) -> Option<PdbGuid>
{
    let data4_offset = offset.checked_add(8)?;
    let data4_end = data4_offset.checked_add(8)?;

    Some(PdbGuid {
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
    let length = bytes.iter().position(|byte| *byte == 0).filter(|length| *length != 0).ok_or(DebugParseError::Malformed)?;

    charge_decoded_data(decoded_data_budget, decoded_string_size(length)?)?;

    Ok(String::from_utf8_lossy(&bytes[..length]).into_owned().into_boxed_str())
}
