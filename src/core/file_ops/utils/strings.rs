use crate::core::file_ops::utils::validate::ValidatedPeFile;

/// The supported encoding used for a decoded string within a byte buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StringEncoding
{
    Ascii,
    Utf16Le,
    Utf8,
}

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
    let utf16le_length = utf16le_len(region);

    if utf16le_length > 0
    {
        return Some(StringCandidate {
            encoding: StringEncoding::Utf16Le,
            byte_length: utf16le_length * 2,
            character_count: utf16le_length,
            utf8_value: None,
        });
    }

    let ascii_length = ascii_len(region);
    let possible_utf8 = region.get(ascii_length).is_some_and(|byte| !byte.is_ascii());

    if possible_utf8
    {
        if let Some(value) = read_utf8(data, offset)
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
        StringEncoding::Ascii => read_ascii(&file.bytes, file_offset)?,
        StringEncoding::Utf16Le => read_utf16le(&file.bytes, file_offset)?,
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


/// Measures the leading run of printable ASCII characters in a buffer.
/// `data`: the bytes to measure from the start.
///
/// Returns the length of the run in characters and bytes.
fn ascii_len(data: &[u8]) -> usize
{
    let mut length = 0;

    while length < data.len() && is_printable_ascii(data[length])
    {
        length += 1;
    }

    length
}


/// Measures the leading run of printable UTF-16LE characters in a buffer.
/// `data`: the bytes to measure from the start.
///
/// Returns the length of the run in characters.
fn utf16le_len(data: &[u8]) -> usize
{
    let mut length = 0;
    let mut index = 0;

    while index + 1 < data.len() && is_printable_ascii(data[index]) && data[index + 1] == 0
    {
        length += 1;
        index += 2;
    }

    length
}


/// Decodes the printable ASCII string beginning at an exact byte offset.
/// `data`: the bytes to decode from.
/// `offset`: the starting byte position.
///
/// Returns an owned string when at least one printable ASCII character exists.
fn read_ascii(data: &[u8], offset: usize) -> Option<String>
{
    let region = data.get(offset..)?;
    let length = ascii_len(region);

    if length == 0
    {
        return None;
    }

    Some(region[..length].iter().map(|&byte| byte as char).collect())
}


/// Decodes the printable UTF-16LE string beginning at an exact byte offset.
/// `data`: the bytes to decode from.
/// `offset`: the starting byte position.
///
/// Returns an owned string when at least one supported wide character exists.
fn read_utf16le(data: &[u8], offset: usize) -> Option<String>
{
    let region = data.get(offset..)?;
    let length = utf16le_len(region);

    if length == 0
    {
        return None;
    }

    let mut value = String::with_capacity(length);
    let mut index = 0;

    while index < length * 2
    {
        value.push(region[index] as char);
        index += 2;
    }

    Some(value)
}


/// Decodes the printable UTF-8 string beginning at an exact byte offset.
/// `data`: the bytes to decode from.
/// `offset`: the starting byte position.
///
/// Returns an owned string when at least one printable character exists.
fn read_utf8(data: &[u8], offset: usize) -> Option<String>
{
    let region = data.get(offset..)?;
    let run = utf8_run(region);

    if run.is_empty()
    {
        return None;
    }

    Some(run.to_owned())
}


/// Reports whether one byte is a printable ASCII character, including space.
/// `byte`: the byte to test.
///
/// Returns `true` for bytes in the inclusive range `0x20..=0x7E`.
fn is_printable_ascii(byte: u8) -> bool
{
    byte.is_ascii_graphic() || byte == b' '
}


/// Returns the leading printable UTF-8 text in a buffer.
/// `data`: bytes to decode from the start.
///
/// Returns the borrowed printable run, stopping at invalid or control bytes.
fn utf8_run(data: &[u8]) -> &str
{
    let valid = match std::str::from_utf8(data)
    {
        Ok(text) => text,
        Err(error) => std::str::from_utf8(&data[..error.valid_up_to()]).unwrap_or(""),
    };

    match valid.char_indices().find(|(_, character)| character.is_control())
    {
        Some((index, _)) => &valid[..index],
        None => valid,
    }
}
