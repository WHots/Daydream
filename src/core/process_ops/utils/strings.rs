/// The supported encoding used for a decoded string within a byte buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StringEncoding
{
    Ascii,
    Utf16Le,
    Utf8,
}


/// Measures the leading run of printable ASCII characters in a buffer.
/// Scanning stops at the first non-printable byte (including a NUL terminator) or the buffer end.
///
/// `data`: the bytes to measure from the start.
///
/// Returns the length of the run in characters, which for ASCII equals its length in bytes.
pub fn ascii_len(data: &[u8]) -> usize
{
    let mut length = 0;

    while length < data.len() && is_printable_ascii(data[length])
    {
        length += 1;
    }

    length
}


/// Measures the leading run of printable UTF-16LE characters in a buffer.
/// Each character is a printable ASCII byte followed by a zero high byte; scanning stops at the
/// first pair that breaks the pattern (including a NUL terminator) or the buffer end.
///
/// `data`: the bytes to measure from the start.
///
/// Returns the length of the run in characters; its length in bytes is twice this value.
pub fn utf16le_len(data: &[u8]) -> usize
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


/// Decodes the printable ASCII string beginning at `offset` in a buffer.
/// `data`: the bytes to decode from.
/// `offset`: the byte position within `data` where the string begins.
///
/// Returns `Some(String)` with the decoded run, or `None` when `offset` is out of range or no
/// printable ASCII character is present.
pub fn read_ascii(data: &[u8], offset: usize) -> Option<String>
{
    let region = data.get(offset..)?;
    let length = ascii_len(region);

    if length == 0
    {
        return None;
    }

    Some(region[..length].iter().map(|&byte| byte as char).collect())
}


/// Decodes the printable UTF-16LE string beginning at `offset` in a buffer.
/// `data`: the bytes to decode from.
/// `offset`: the byte position within `data` where the string begins.
///
/// Returns `Some(String)` with the decoded run, or `None` when `offset` is out of range or no
/// printable wide character is present.
pub fn read_utf16le(data: &[u8], offset: usize) -> Option<String>
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


/// Decodes the printable UTF-8 string beginning at `offset` in a buffer.
/// `data`: the bytes to decode from.
/// `offset`: the byte position within `data` where the string begins.
///
/// Returns `Some(String)` with the decoded run, or `None` when `offset` is out of range or no
/// printable character is present.
pub fn read_utf8(data: &[u8], offset: usize) -> Option<String>
{
    let region = data.get(offset..)?;
    let run = utf8_run(region);

    if run.is_empty()
    {
        return None;
    }

    Some(run.to_owned())
}


/// Reports whether a byte is a printable ASCII character, including the space.
/// `byte`: the byte to test.
///
/// Returns `true` for bytes in the inclusive range `0x20..=0x7E`.
fn is_printable_ascii(byte: u8) -> bool
{
    byte.is_ascii_graphic() || byte == b' '
}


/// Returns the leading run of printable UTF-8 text in a buffer as a string slice.
/// Decoding stops at the first invalid byte or control character (including a NUL terminator).
///
/// `data`: the bytes to decode from the start.
///
/// Returns the borrowed printable run, which is empty when the buffer starts with invalid or
/// non-printable bytes.
fn utf8_run(data: &[u8]) -> &str
{
    let valid = match std::str::from_utf8(data)
    {
        Ok(text) => text,
        Err(error) => std::str::from_utf8(&data[..error.valid_up_to()]).unwrap_or(""),
    };

    match valid
        .char_indices()
        .find(|(_, character)| character.is_control())
    {
        Some((index, _)) => &valid[..index],
        None => valid,
    }
}
