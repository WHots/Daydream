use crate::core::data::patterns64::patterns64::{Signature, X64_FILE_SCAN_SIGNATURES};
use crate::core::file_ops::utils::validate::{PeFileSection, ValidatedPeFile};

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

/// Borrows one raw byte region from a validated PE image with its mapped location.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileImageRegion<'a>
{
    pub section_name: &'a str,
    pub bytes: &'a [u8],
    pub rva: usize,
    pub file_offset: usize,
}


/// Owns one named byte-signature trigger collected from a raw PE code section.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileSignatureHit
{
    pub trigger: &'static str,
    pub section_name: Box<str>,
    pub rva: usize,
    pub file_offset: usize,
}


/// Scans every raw-backed executable section with the signatures designated for raw
/// file detection. Runtime-only process state is excluded by the signature catalog.
/// `file`: the validated PE whose executable sections should be scanned.
///
/// Returns owned file-detection hits ordered by raw file offset for later reuse.
pub fn scan_file_signatures(file: &ValidatedPeFile) -> Vec<FileSignatureHit>
{
    scan_code_signatures(file, X64_FILE_SCAN_SIGNATURES)
}


/// Scans every raw-backed executable section for every supplied wildcard signature.
/// `file`: the validated PE whose executable sections should be scanned.
/// `signatures`: named patterns containing exact bytes and optional wildcard bytes.
///
/// Returns owned hits ordered by raw file offset. Empty patterns and patterns containing
/// only wildcards are ignored.
pub fn scan_code_signatures(file: &ValidatedPeFile, signatures: &[Signature]) -> Vec<FileSignatureHit>
{
    let mut matches = Vec::new();

    for section in file.sections.iter()
    {
        if section.characteristics & IMAGE_SCN_MEM_EXECUTE == 0 || section.raw_size == 0
        {
            continue;
        }

        let region = match section_region(file, section)
        {
            Some(value) => value,
            None => continue,
        };
        let mut byte_frequencies = [0usize; 256];

        for byte in region.bytes.iter()
        {
            byte_frequencies[*byte as usize] += 1;
        }

        let mut anchored_signatures: [Vec<(usize, &Signature)>; 256] = std::array::from_fn(|_| Vec::new());

        for signature in signatures
        {
            if signature.pattern.is_empty() || signature.pattern.len() > region.bytes.len()
            {
                continue;
            }

            if let Some((anchor_index, anchor_byte)) = choose_signature_anchor(signature.pattern, &byte_frequencies)
            {
                anchored_signatures[anchor_byte as usize].push((anchor_index, signature));
            }
        }

        for (anchor_offset, byte) in region.bytes.iter().enumerate()
        {
            for (anchor_index, signature) in anchored_signatures[*byte as usize].iter()
            {
                let match_offset = match anchor_offset.checked_sub(*anchor_index)
                {
                    Some(value) => value,
                    None => continue,
                };
                let match_end = match match_offset.checked_add(signature.pattern.len())
                {
                    Some(value) if value <= region.bytes.len() => value,
                    _ => continue,
                };

                if !matches_signature(&region.bytes[match_offset..match_end], signature.pattern)
                {
                    continue;
                }

                let rva = match region.rva.checked_add(match_offset)
                {
                    Some(value) => value,
                    None =>
                    {
                        eprintln!("signature {:?} produced an overflowing RVA", signature.name);
                        continue;
                    }
                };
                let file_offset = match region.file_offset.checked_add(match_offset)
                {
                    Some(value) => value,
                    None =>
                    {
                        eprintln!("signature {:?} produced an overflowing file offset", signature.name);
                        continue;
                    }
                };

                matches.push(FileSignatureHit {
                    trigger: signature.name,
                    section_name: region.section_name.into(),
                    rva,
                    file_offset,
                });
            }
        }
    }

    matches.sort_unstable_by(|left, right| left.file_offset.cmp(&right.file_offset).then_with(|| left.trigger.cmp(right.trigger)));

    matches
}


/// Borrows a section's validated raw byte range with its image coordinates.
/// `file`: the validated PE whose existing byte buffer should be borrowed.
/// `section`: the raw-backed section whose exact byte range should be returned.
///
/// Returns the borrowed section region, or `None` after reporting an invalid raw range.
fn section_region<'a>(file: &'a ValidatedPeFile, section: &'a PeFileSection) -> Option<FileImageRegion<'a>>
{
    let section_end = match section.raw_offset.checked_add(section.raw_size)
    {
        Some(value) => value,
        None =>
        {
            eprintln!("section {:?} has an overflowing raw byte range", section.name);
            return None;
        }
    };
    let bytes = match file.bytes.get(section.raw_offset..section_end)
    {
        Some(value) => value,
        None =>
        {
            eprintln!("section {:?} has raw bytes outside the validated image", section.name);
            return None;
        }
    };

    Some(FileImageRegion {
        section_name: &section.name,
        bytes,
        rva: section.virtual_address,
        file_offset: section.raw_offset,
    })
}


/// Selects the least frequent exact pattern byte as the scan anchor.
/// `pattern`: the exact-and-wildcard byte pattern whose anchor should be selected.
/// `byte_frequencies`: the frequency of each byte value in the scanned code section.
///
/// Returns the selected pattern index and byte, or `None` after reporting that the
/// pattern contains no exact byte.
fn choose_signature_anchor(pattern: &[Option<u8>], byte_frequencies: &[usize; 256]) -> Option<(usize, u8)>
{
    let mut anchor = None;

    for (index, expected) in pattern.iter().enumerate()
    {
        let byte = match expected
        {
            Some(value) => *value,
            None => continue,
        };

        match anchor
        {
            Some((current_index, current_byte)) if byte_frequencies[current_byte as usize] < byte_frequencies[byte as usize] || (byte_frequencies[current_byte as usize] == byte_frequencies[byte as usize] && current_index >= index) => continue,
            _ => anchor = Some((index, byte)),
        }
    }

    if anchor.is_none()
    {
        eprintln!("signature pattern contains no exact byte to use as a scan anchor");
    }

    anchor
}


/// Checks one candidate window against an exact-and-wildcard signature.
/// `bytes`: the candidate code-section window to verify.
/// `pattern`: the exact-and-wildcard byte pattern expected in the window.
///
/// Returns `true` when every exact byte matches and each wildcard is accepted.
fn matches_signature(bytes: &[u8], pattern: &[Option<u8>]) -> bool
{
    if bytes.len() != pattern.len()
    {
        eprintln!("signature candidate and pattern lengths do not match");
        return false;
    }

    pattern.iter().zip(bytes).all(|(expected, actual)| expected.is_none_or(|byte| byte == *actual))
}
