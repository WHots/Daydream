use crate::core::file_ops::utils::validate::ValidatedPeFile;
use crate::core::process_ops::utils::strings::{self, StringEncoding};

/// Describes one decoded string found in a raw PE file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileString
{
    pub value: Box<str>,
    pub encoding: StringEncoding,
    pub file_offset: usize,
    pub rva: Option<usize>,
}


/// Collects printable strings from an already-validated raw PE file.
/// `file`: the validated EXE or DLL whose bytes should be scanned once.
/// `minimum_chars`: the minimum decoded character count required for a result.
///
/// Returns strings in raw file order with their encoding, file offset, and
/// section-aware RVA when the bytes are part of the mapped PE image.
pub fn collect_file_strings(file: &ValidatedPeFile, minimum_chars: usize) -> Vec<FileString>
{
    let minimum_chars = minimum_chars.max(1);
    let mut results = Vec::new();
    let mut file_offset = 0usize;

    while file_offset < file.bytes.len()
    {
        let candidate = match read_string_candidate(&file.bytes, file_offset)
        {
            Some(value) => value,
            None =>
            {
                file_offset += 1;
                continue;
            }
        };
        let next_offset = next_scan_offset(&file.bytes, file_offset, &candidate);

        if candidate.character_count >= minimum_chars
        {
            if let Some(file_string) = build_file_string(file, file_offset, candidate)
            {
                results.push(file_string);
            }
        }

        file_offset = next_offset;
    }

    results
}


/// Holds the measured shape of one string before an accepted result is allocated.
struct StringCandidate
{
    encoding: StringEncoding,
    byte_length: usize,
    character_count: usize,
    utf8_value: Option<String>,
}


/// Measures a supported string at an exact byte offset.
fn read_string_candidate(data: &[u8], offset: usize) -> Option<StringCandidate>
{
    let region = data.get(offset..)?;
    let utf16le_length = strings::utf16le_len(region);

    if utf16le_length > 0
    {
        return Some(StringCandidate {
            encoding: StringEncoding::Utf16Le,
            byte_length: utf16le_length * 2,
            character_count: utf16le_length,
            utf8_value: None,
        });
    }

    let ascii_length = strings::ascii_len(region);
    let possible_utf8 = region.get(ascii_length).is_some_and(|byte| !byte.is_ascii());

    if possible_utf8
    {
        if let Some(value) = strings::read_utf8(data, offset)
        {
            if value.len() > ascii_length
            {
                return Some(StringCandidate {
                    encoding: StringEncoding::Utf8,
                    byte_length: value.len(),
                    character_count: value.chars().count(),
                    utf8_value: Some(value),
                });
            }
        }
    }

    if ascii_length > 0
    {
        return Some(StringCandidate {
            encoding: StringEncoding::Ascii,
            byte_length: ascii_length,
            character_count: ascii_length,
            utf8_value: None,
        });
    }

    None
}


/// Builds an owned file-string record from a measured candidate.
fn build_file_string(file: &ValidatedPeFile, file_offset: usize, candidate: StringCandidate) -> Option<FileString>
{
    let value = match candidate.encoding
    {
        StringEncoding::Ascii => strings::read_ascii(&file.bytes, file_offset)?,
        StringEncoding::Utf16Le => strings::read_utf16le(&file.bytes, file_offset)?,
        StringEncoding::Utf8 => candidate.utf8_value?,
    };

    Some(FileString {
        value: value.into_boxed_str(),
        encoding: candidate.encoding,
        file_offset,
        rva: file_offset_to_rva(file, file_offset),
    })
}


/// Computes the next byte offset after a measured string and its NUL terminator.
fn next_scan_offset(data: &[u8], offset: usize, candidate: &StringCandidate) -> usize
{
    let terminator_size = match candidate.encoding
    {
        StringEncoding::Utf16Le => 2,
        _ => 1,
    };
    let string_end = offset.saturating_add(candidate.byte_length);
    let terminator_end = string_end.saturating_add(terminator_size);

    if data.get(string_end..terminator_end).is_some_and(|terminator| terminator.iter().all(|byte| *byte == 0))
    {
        return terminator_end;
    }

    string_end.max(offset + 1)
}


/// Maps a raw PE file offset back to its section-aware RVA.
fn file_offset_to_rva(file: &ValidatedPeFile, file_offset: usize) -> Option<usize>
{
    if file_offset < file.size_of_headers
    {
        return Some(file_offset);
    }

    for section in file.sections.iter()
    {
        let section_end = section.raw_offset.checked_add(section.raw_size)?;

        if file_offset < section.raw_offset || file_offset >= section_end
        {
            continue;
        }

        let section_offset = file_offset.checked_sub(section.raw_offset)?;
        let rva = section.virtual_address.checked_add(section_offset)?;

        return (rva < file.size_of_image).then_some(rva);
    }

    None
}
