use crate::core::file_ops::utils::validate::ValidatedPeFile;

/// Maps an RVA to its raw file offset and containing raw-region end.
/// `file`: the validated PE file whose headers and sections back the mapping.
/// `rva`: the relative virtual address to resolve against the raw bytes.
///
/// Returns the raw file offset and the exclusive end of its mapped region.
pub fn rva_to_file_range(file: &ValidatedPeFile, rva: usize) -> Option<(usize, usize)>
{
    if rva < file.size_of_headers && rva < file.bytes.len()
    {
        return Some((rva, file.size_of_headers.min(file.bytes.len())));
    }

    for section in file.sections.iter()
    {
        let virtual_span = section.virtual_size.max(section.raw_size);
        let virtual_end = match section.virtual_address.checked_add(virtual_span)
        {
            Some(value) => value,
            None => continue,
        };

        if rva < section.virtual_address || rva >= virtual_end
        {
            continue;
        }

        let section_delta = match rva.checked_sub(section.virtual_address)
        {
            Some(value) if value < section.raw_size => value,
            _ => continue,
        };
        let file_offset = section.raw_offset.checked_add(section_delta)?;
        let mapped_end = section.raw_offset.checked_add(section.raw_size)?;

        if file_offset < mapped_end && mapped_end <= file.bytes.len()
        {
            return Some((file_offset, mapped_end));
        }
    }

    None
}


/// Reads a little-endian `u16` from an exact byte offset.
/// `bytes`: the source slice to read from.
/// `offset`: the exact byte offset where the value begins.
///
/// Returns the decoded value when the slice fully contains it.
pub fn read_u16(bytes: &[u8], offset: usize) -> Option<u16>
{
    let value = bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?;

    Some(u16::from_le_bytes(value))
}


/// Reads a little-endian `u32` from an exact byte offset.
/// `bytes`: the source slice to read from.
/// `offset`: the exact byte offset where the value begins.
///
/// Returns the decoded value when the slice fully contains it.
pub fn read_u32(bytes: &[u8], offset: usize) -> Option<u32>
{
    let value = bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?;

    Some(u32::from_le_bytes(value))
}


/// Reads a little-endian `u64` from an exact byte offset.
/// `bytes`: the source slice to read from.
/// `offset`: the exact byte offset where the value begins.
///
/// Returns the decoded value when the slice fully contains it.
pub fn read_u64(bytes: &[u8], offset: usize) -> Option<u64>
{
    let value = bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?;

    Some(u64::from_le_bytes(value))
}
