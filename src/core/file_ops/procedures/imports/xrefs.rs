use std::collections::{HashMap, HashSet};

use crate::core::file_ops::procedures::imports::types::{FileApiXref, FileApiXrefKind};
use crate::core::file_ops::utils::validate::ValidatedPeFile;

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

/// Collects direct IAT references and near references to matching import thunks.
/// `file`: the validated EXE or DLL whose executable sections should be scanned.
/// `iat_rvas`: the IAT entry RVAs to match displacement targets against.
///
/// Returns per-IAT xref lists, sorted and deduplicated; RVAs with no supported
/// references have no entry, and unscannable sections are skipped and reported
/// on stderr.
pub(super) fn collect_iat_xrefs(file: &ValidatedPeFile, iat_rvas: &HashSet<usize>) -> HashMap<usize, Vec<FileApiXref>>
{
    let mut xrefs_by_iat: HashMap<usize, Vec<FileApiXref>> = HashMap::new();
    let mut thunk_iat_by_rva = HashMap::new();

    for section in file.sections.iter()
    {
        if section.characteristics & IMAGE_SCN_MEM_EXECUTE == 0 || section.raw_size == 0
        {
            continue;
        }

        let section_end = match section.raw_offset.checked_add(section.raw_size)
        {
            Some(value) if value <= file.bytes.len() => value,
            _ =>
            {
                eprintln!("executable section at RVA 0x{:08X} has raw data outside the file", section.virtual_address);
                continue;
            }
        };

        let mut opcode_file_offset = section.raw_offset;

        while opcode_file_offset.checked_add(6).is_some_and(|instruction_end| instruction_end <= section_end)
        {
            if file.bytes[opcode_file_offset] != 0xFF
            {
                opcode_file_offset += 1;
                continue;
            }

            let kind = match file.bytes[opcode_file_offset + 1]
            {
                0x15 => FileApiXrefKind::Call,
                0x25 => FileApiXrefKind::Jump,
                _ =>
                {
                    opcode_file_offset += 1;
                    continue;
                }
            };

            let displacement = i32::from_le_bytes([file.bytes[opcode_file_offset + 2], file.bytes[opcode_file_offset + 3], file.bytes[opcode_file_offset + 4], file.bytes[opcode_file_offset + 5]]);

            let opcode_delta = match opcode_file_offset.checked_sub(section.raw_offset)
            {
                Some(value) => value,
                None =>
                {
                    eprintln!("opcode file offset 0x{:08X} fell below its section start", opcode_file_offset);
                    break;
                }
            };

            let opcode_rva = match section.virtual_address.checked_add(opcode_delta)
            {
                Some(value) => value,
                None =>
                {
                    eprintln!("opcode RVA overflowed at file offset 0x{:08X}", opcode_file_offset);
                    break;
                }
            };

            let next_instruction_rva = match opcode_rva.checked_add(6)
            {
                Some(value) => value,
                None =>
                {
                    eprintln!("next-instruction RVA overflowed after RVA 0x{:08X}", opcode_rva);
                    break;
                }
            };

            let iat_rva = match next_instruction_rva.checked_add_signed(displacement as isize)
            {
                Some(value) => value,
                None =>
                {
                    opcode_file_offset += 6;
                    continue;
                }
            };

            if iat_rvas.contains(&iat_rva)
            {
                let instruction_file_offset = if opcode_file_offset > section.raw_offset && matches!(file.bytes[opcode_file_offset - 1], 0x40..=0x4F) { opcode_file_offset - 1 } else { opcode_file_offset };
                let instruction_delta = instruction_file_offset - section.raw_offset;

                let instruction_rva = match section.virtual_address.checked_add(instruction_delta)
                {
                    Some(value) => value,
                    None =>
                    {
                        eprintln!("instruction RVA overflowed at file offset 0x{:08X}", instruction_file_offset);
                        opcode_file_offset += 6;
                        continue;
                    }
                };

                if kind == FileApiXrefKind::Jump
                {
                    thunk_iat_by_rva.insert(instruction_rva, iat_rva);
                }

                xrefs_by_iat.entry(iat_rva).or_default().push(FileApiXref {
                    kind,
                    rva: instruction_rva,
                    file_offset: instruction_file_offset,
                });
            }

            opcode_file_offset += 6;
        }
    }

    if !thunk_iat_by_rva.is_empty()
    {
        for section in file.sections.iter()
        {
            if section.characteristics & IMAGE_SCN_MEM_EXECUTE == 0 || section.raw_size == 0
            {
                continue;
            }

            let section_end = match section.raw_offset.checked_add(section.raw_size)
            {
                Some(value) if value <= file.bytes.len() => value,
                _ => continue,
            };
            let mut opcode_file_offset = section.raw_offset;

            while opcode_file_offset.checked_add(5).is_some_and(|instruction_end| instruction_end <= section_end)
            {
                let kind = match file.bytes[opcode_file_offset]
                {
                    0xE8 => FileApiXrefKind::Call,
                    0xE9 => FileApiXrefKind::Jump,
                    _ =>
                    {
                        opcode_file_offset += 1;
                        continue;
                    }
                };

                let displacement = i32::from_le_bytes([file.bytes[opcode_file_offset + 1], file.bytes[opcode_file_offset + 2], file.bytes[opcode_file_offset + 3], file.bytes[opcode_file_offset + 4]]);
                let opcode_delta = opcode_file_offset - section.raw_offset;

                let opcode_rva = match section.virtual_address.checked_add(opcode_delta)
                {
                    Some(value) => value,
                    None =>
                    {
                        eprintln!("opcode RVA overflowed at file offset 0x{:08X}", opcode_file_offset);
                        break;
                    }
                };

                let next_instruction_rva = match opcode_rva.checked_add(5)
                {
                    Some(value) => value,
                    None =>
                    {
                        eprintln!("next-instruction RVA overflowed after RVA 0x{:08X}", opcode_rva);
                        break;
                    }
                };
                
                let target_rva = match next_instruction_rva.checked_add_signed(displacement as isize)
                {
                    Some(value) => value,
                    None =>
                    {
                        opcode_file_offset += 5;
                        continue;
                    }
                };

                if let Some(iat_rva) = thunk_iat_by_rva.get(&target_rva)
                {
                    xrefs_by_iat.entry(*iat_rva).or_default().push(FileApiXref {
                        kind,
                        rva: opcode_rva,
                        file_offset: opcode_file_offset,
                    });
                }

                opcode_file_offset += 5;
            }
        }
    }

    for xrefs in xrefs_by_iat.values_mut()
    {
        xrefs.sort_unstable_by_key(|xref| (xref.rva, xref.file_offset));
        xrefs.dedup();
    }

    xrefs_by_iat
}
