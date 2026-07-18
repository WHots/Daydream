use crate::core::data::patterns64::patterns64::{Signature, X64_FILE_SCAN_SIGNATURES};
use crate::core::file_ops::utils::supports::rva_to_file_range;
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


/// Reads an exact byte range from a mapped RVA in a validated raw PE image.
/// `file`: the validated PE whose existing byte buffer should be borrowed.
/// `rva`: the relative virtual address where the read begins.
/// `byte_count`: the exact number of raw-backed bytes to read.
///
/// Returns the borrowed bytes when the entire range belongs to one mapped raw region.
pub fn read_image_bytes(file: &ValidatedPeFile, rva: usize, byte_count: usize) -> Option<&[u8]>
{
    let (file_offset, mapped_end) = rva_to_file_range(file, rva)?;
    let read_end = file_offset.checked_add(byte_count)?;

    if read_end > mapped_end
    {
        return None;
    }

    file.bytes.get(file_offset..read_end)
}


/// Locates and borrows the preferred executable code section from a validated PE image.
/// `file`: the validated PE whose raw executable section bytes should be borrowed.
///
/// Returns the executable section containing the entry point, or the first raw-backed
/// executable section when the entry point is not contained by one.
pub fn read_code_section(file: &ValidatedPeFile) -> Option<FileImageRegion<'_>>
{
    let mut fallback = None;

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
        let virtual_span = section.virtual_size.max(section.raw_size);
        let virtual_end = match section.virtual_address.checked_add(virtual_span)
        {
            Some(value) => value,
            None =>
            {
                eprintln!("executable section {:?} has an overflowing virtual range", section.name);
                continue;
            }
        };

        if file.entry_point_rva >= section.virtual_address && file.entry_point_rva < virtual_end
        {
            return Some(region);
        }

        if fallback.is_none()
        {
            fallback = Some(region);
        }
    }

    fallback
}


/// Scans the preferred executable code section with the signatures designated for raw
/// file detection. Runtime-only process state is excluded by the signature catalog.
/// `file`: the validated PE whose preferred code section should be scanned.
///
/// Returns owned file-detection hits ordered by raw file offset for later reuse.
pub fn scan_file_signatures(file: &ValidatedPeFile) -> Vec<FileSignatureHit>
{
    scan_code_signatures(file, X64_FILE_SCAN_SIGNATURES)
}


/// Scans the preferred executable code section for every supplied wildcard signature.
/// `file`: the validated PE whose preferred code section should be scanned.
/// `signatures`: named patterns containing exact bytes and optional wildcard bytes.
///
/// Returns owned hits ordered by raw file offset. Empty patterns and patterns containing
/// only wildcards are ignored.
pub fn scan_code_signatures(file: &ValidatedPeFile, signatures: &[Signature]) -> Vec<FileSignatureHit>
{
    let region = match read_code_section(file)
    {
        Some(value) => value,
        None => return Vec::new(),
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

    let mut matches = Vec::new();

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

            matches.push(FileSignatureHit
            {
                trigger: signature.name,
                section_name: region.section_name.into(),
                rva,
                file_offset,
            });
        }
    }

    matches.sort_unstable_by(|left, right|
    {
        left.file_offset.cmp(&right.file_offset).then_with(|| left.trigger.cmp(right.trigger))
    });

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

    Some(FileImageRegion
    {
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
            Some((current_index, current_byte))
                if byte_frequencies[current_byte as usize] < byte_frequencies[byte as usize]
                    || (byte_frequencies[current_byte as usize] == byte_frequencies[byte as usize]
                        && current_index >= index) => continue,
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

    pattern.iter().zip(bytes).all(|(expected, actual)|
    {
        expected.is_none_or(|byte| byte == *actual)
    })
}


#[cfg(test)]
mod tests
{
    use super::{
        read_code_section, read_image_bytes, scan_code_signatures, scan_file_signatures,
        FileSignatureHit,
    };
    use crate::core::data::patterns64::patterns64::Signature;
    use crate::core::file_ops::utils::validate::{PeFileSection, ValidatedPeFile};

    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
    const WILDCARD_SIGNATURE: Signature = Signature
    {
        name: "wildcard test",
        pattern: &[Some(0x48), None, Some(0xC3)],
    };


    #[test]
    fn reads_mapped_image_bytes_by_rva()
    {
        let mut file = test_file(vec![test_section(".text", 0x1000, 0x20, 8)], 0x1000);
        file.bytes[0x20..0x28].copy_from_slice(&[0x48, 0x83, 0xEC, 0x28, 0x90, 0x90, 0xC3, 0xCC]);

        assert_eq!(read_image_bytes(&file, 0x1002, 4), Some(&[0xEC, 0x28, 0x90, 0x90][..]));
        assert_eq!(read_image_bytes(&file, 0x1006, 3), None);
    }


    #[test]
    fn prefers_executable_section_containing_entry_point()
    {
        let file = test_file(
            vec![
                test_section("first", 0x1000, 0x20, 8),
                test_section("entry", 0x2000, 0x30, 8),
            ],
            0x2002,
        );

        let region = read_code_section(&file).expect("entry-point code section should be found");

        assert_eq!(region.section_name, "entry");
        assert_eq!(region.rva, 0x2000);
        assert_eq!(region.file_offset, 0x30);
    }


    #[test]
    fn collects_overlapping_wildcard_signature_matches()
    {
        let mut file = test_file(vec![test_section(".text", 0x1000, 0x20, 7)], 0x1000);
        file.bytes[0x20..0x27].copy_from_slice(&[0x48, 0x11, 0xC3, 0x48, 0x22, 0xC3, 0x90]);

        let matches = scan_code_signatures(&file, &[WILDCARD_SIGNATURE]);

        assert_eq!(matches, vec![
            FileSignatureHit
            {
                trigger: "wildcard test",
                section_name: ".text".into(),
                rva: 0x1000,
                file_offset: 0x20,
            },
            FileSignatureHit
            {
                trigger: "wildcard test",
                section_name: ".text".into(),
                rva: 0x1003,
                file_offset: 0x23,
            },
        ]);
    }


    #[test]
    fn scans_catalog_signatures_with_wildcard_bytes()
    {
        let mut file = test_file(vec![test_section(".text", 0x1000, 0x20, 11)], 0x1000);
        file.bytes[0x20..0x2B].copy_from_slice(&[
            0x4C, 0x8B, 0xD1, 0xB8, 0x34, 0x12, 0x00, 0x00, 0x0F, 0x05, 0xC3,
        ]);

        let matches = scan_file_signatures(&file);

        assert_eq!(matches, vec![FileSignatureHit
        {
            trigger: "direct syscall wrapper",
            section_name: ".text".into(),
            rva: 0x1000,
            file_offset: 0x20,
        }]);
    }


    #[test]
    fn scans_contextual_runtime_and_anti_analysis_signatures()
    {
        let mut file = test_file(vec![test_section(".text", 0x1000, 0x20, 67)], 0x1000);
        file.bytes[0x20..0x63].copy_from_slice(&[
            0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,
            0x48, 0x8B, 0x40, 0x18, 0x48, 0x8B, 0x40, 0x20, 0x90,
            0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,
            0x8B, 0x80, 0xBC, 0x00, 0x00, 0x00, 0x83, 0xE0, 0x70, 0x90,
            0x0F, 0xB6, 0x04, 0x25, 0xD4, 0x02, 0xFE, 0x7F, 0x90,
            0x4C, 0x8B, 0xD1, 0xB8, 0x34, 0x12, 0x00, 0x00,
            0xF6, 0x04, 0x25, 0x08, 0x03, 0xFE, 0x7F, 0x01,
            0x75, 0x05, 0x0F, 0x05, 0xC3,
        ]);

        let matches = scan_file_signatures(&file);

        assert_eq!(matches, vec![
            FileSignatureHit
            {
                trigger: "PEB loader InMemoryOrder walk",
                section_name: ".text".into(),
                rva: 0x1000,
                file_offset: 0x20,
            },
            FileSignatureHit
            {
                trigger: "PEB NtGlobalFlag heap-debug check",
                section_name: ".text".into(),
                rva: 0x1012,
                file_offset: 0x32,
            },
            FileSignatureHit
            {
                trigger: "KUSER_SHARED_DATA KdDebuggerEnabled read",
                section_name: ".text".into(),
                rva: 0x1025,
                file_offset: 0x45,
            },
            FileSignatureHit
            {
                trigger: "SharedUserData-gated syscall wrapper",
                section_name: ".text".into(),
                rva: 0x102E,
                file_offset: 0x4E,
            },
        ]);
    }


    #[test]
    fn scans_only_the_designated_file_detection_signatures()
    {
        let matches =
        {
            let mut file = test_file(vec![test_section(".text", 0x1000, 0x20, 23)], 0x1000);
            file.bytes[0x20..0x37].copy_from_slice(&[
                0x33, 0xC0, 0xCD, 0x2D, 0xC3,
                0x48, 0x83, 0xEC, 0x28, 0xE8, 0x00, 0x00, 0x00, 0x00,
                0x48, 0x83, 0xC4, 0x28, 0xE9, 0x00, 0x00, 0x00, 0x00,
            ]);

            scan_file_signatures(&file)
        };

        assert_eq!(matches, vec![FileSignatureHit
        {
            trigger: "INT 2D anti-debug check",
            section_name: ".text".into(),
            rva: 0x1000,
            file_offset: 0x20,
        }]);
    }


    /// Creates a validated-file fixture with raw-backed executable sections.
    /// `sections`: the executable section metadata to store in the fixture.
    /// `entry_point_rva`: the image entry-point RVA used for preferred-section selection.
    ///
    /// Returns a minimal validated PE fixture backed by a zero-initialized byte buffer.
    fn test_file(sections: Vec<PeFileSection>, entry_point_rva: usize) -> ValidatedPeFile
    {
        let byte_count = sections
            .iter()
            .map(|section| section.raw_offset + section.raw_size)
            .max()
            .unwrap_or(0x20)
            .max(0x20);

        ValidatedPeFile
        {
            bytes: vec![0u8; byte_count].into_boxed_slice(),
            machine: 0x8664,
            timestamp: 0,
            characteristics: 0x0002,
            entry_point_rva,
            image_base: 0x1400_0000_0,
            section_alignment: 0x1000,
            file_alignment: 0x200,
            size_of_image: 0x4000,
            size_of_headers: 0x20,
            sections: sections.into_boxed_slice(),
        }
    }


    /// Creates one raw-backed executable section fixture.
    /// `name`: the section name stored in the fixture.
    /// `virtual_address`: the section's starting RVA.
    /// `raw_offset`: the section's starting raw file offset.
    /// `raw_size`: the number of bytes backing the section.
    ///
    /// Returns executable section metadata with matching virtual and raw sizes.
    fn test_section(name: &str, virtual_address: usize, raw_offset: usize, raw_size: usize) -> PeFileSection
    {
        PeFileSection
        {
            name: name.into(),
            virtual_address,
            virtual_size: raw_size,
            raw_offset,
            raw_size,
            characteristics: IMAGE_SCN_MEM_EXECUTE,
        }
    }
}
