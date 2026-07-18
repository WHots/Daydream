use std::collections::{HashMap, HashSet};
use std::fmt;

use crate::core::file_ops::utils::supports::{read_u16, read_u32, read_u64, rva_to_file_range};
use crate::core::file_ops::utils::validate::ValidatedPeFile;

const PE_SIGNATURE_SIZE: usize = 4;
const COFF_HEADER_SIZE: usize = 20;
const OPTIONAL_HEADER_DATA_DIRECTORY_COUNT_OFFSET: usize = 108;
const OPTIONAL_HEADER_DATA_DIRECTORY_OFFSET: usize = 112;
const DATA_DIRECTORY_SIZE: usize = 8;
const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
const IMPORT_DESCRIPTOR_SIZE: usize = 20;
const IMPORT_LOOKUP_ENTRY_SIZE: usize = 8;
const IMPORT_BY_NAME_HINT_SIZE: usize = 2;
const IMAGE_ORDINAL_FLAG64: u64 = 0x8000_0000_0000_0000;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

/// Describes the instruction form used by one supported API IAT cross-reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileApiXrefKind
{
    Call,
    Jump,
}


/// Describes one direct IAT reference or near reference to an import thunk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileApiXref
{
    pub kind: FileApiXrefKind,
    pub rva: usize,
    pub file_offset: usize,
}


/// Contains one PE import and its direct or thunk-mediated call and jump references.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileApiImport
{
    pub library_name: Box<str>,
    pub import_name: Box<str>,
    pub iat_rva: usize,
    pub file_offset: Option<usize>,
    pub xrefs: Vec<FileApiXref>,
}


/// Collects imports and their supported x64 IAT call or jump references from a raw PE file.
/// `file`: the validated EXE or DLL whose import directory and executable sections should be read.
///
/// Returns every normal name or ordinal import with its IAT file offset, direct
/// `FF /2` calls and `FF /4` jumps, and near calls or jumps to matching import thunks.
pub fn collect_file_api_imports(file: &ValidatedPeFile) -> Vec<FileApiImport>
{
    let mut imports = collect_imports(file);

    if imports.is_empty()
    {
        return imports;
    }

    let iat_rvas: HashSet<usize> = imports
        .iter()
        .map(|api_import| api_import.iat_rva)
        .collect();
    let mut xrefs_by_iat = collect_iat_xrefs(file, &iat_rvas);

    for api_import in &mut imports
    {
        api_import.xrefs = xrefs_by_iat
            .remove(&api_import.iat_rva)
            .unwrap_or_default();
    }

    imports
}


impl fmt::Display for FileApiImport
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        match self.file_offset
        {
            Some(file_offset) => write!(
                formatter,
                "{}!{}: File offset 0x{:08X} | IAT RVA 0x{:08X}",
                self.library_name, self.import_name, file_offset, self.iat_rva
            ),
            None => write!(
                formatter,
                "{}!{}: File offset N/A | IAT RVA 0x{:08X}",
                self.library_name, self.import_name, self.iat_rva
            ),
        }
    }
}


impl fmt::Display for FileApiXref
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        let kind = match self.kind
        {
            FileApiXrefKind::Call => "Call",
            FileApiXrefKind::Jump => "Jump",
        };

        write!(
            formatter,
            "{} XREF: RVA 0x{:08X}, File offset 0x{:08X}",
            kind, self.rva, self.file_offset
        )
    }
}


/// Collects every normal name or ordinal import before xrefs are attached.
/// `file`: the validated EXE or DLL whose import directory should be read.
///
/// Returns the parsed imports; empty when the import directory is missing,
/// out of bounds, or contains no readable descriptors. Failures are reported
/// on stderr.
fn collect_imports(file: &ValidatedPeFile) -> Vec<FileApiImport>
{
    let (import_directory_rva, import_directory_size) = match get_import_directory(file)
    {
        Some(value) => value,
        None => return Vec::new(),
    };
    let descriptor_count = (import_directory_size / IMPORT_DESCRIPTOR_SIZE)
        .min(file.bytes.len() / IMPORT_DESCRIPTOR_SIZE);
    let mut imports = Vec::new();

    for descriptor_index in 0..descriptor_count
    {
        let descriptor_rva = match descriptor_index
            .checked_mul(IMPORT_DESCRIPTOR_SIZE)
            .and_then(|offset| import_directory_rva.checked_add(offset))
        {
            Some(value) => value,
            None =>
            {
                eprintln!("import descriptor {} RVA overflowed", descriptor_index);
                break;
            }
        };
        let descriptor = match read_mapped_bytes(file, descriptor_rva, IMPORT_DESCRIPTOR_SIZE)
        {
            Some(value) => value,
            None =>
            {
                eprintln!(
                    "failed to read import descriptor {} at RVA 0x{:08X}",
                    descriptor_index, descriptor_rva
                );
                break;
            }
        };
        let original_first_thunk = read_u32(descriptor, 0).unwrap_or(0) as usize;
        let library_name_rva = read_u32(descriptor, 12).unwrap_or(0) as usize;
        let first_thunk = read_u32(descriptor, 16).unwrap_or(0) as usize;

        if original_first_thunk == 0 && library_name_rva == 0 && first_thunk == 0
        {
            break;
        }

        if library_name_rva == 0 || first_thunk == 0
        {
            continue;
        }

        let library_name = match read_mapped_c_string(file, library_name_rva)
        {
            Some(value) if !value.is_empty() => value,
            _ =>
            {
                eprintln!(
                    "failed to read the library name of import descriptor {} at RVA 0x{:08X}",
                    descriptor_index, library_name_rva
                );
                continue;
            }
        };
        let lookup_table_rva = if original_first_thunk != 0
        {
            original_first_thunk
        }
        else
        {
            first_thunk
        };

        collect_descriptor_imports(file, library_name, lookup_table_rva, first_thunk, &mut imports);
    }

    imports
}


/// Collects name and ordinal thunk entries from one import descriptor.
/// `file`: the validated EXE or DLL backing the thunk tables.
/// `library_name`: the owning library name attached to each collected import.
/// `lookup_table_rva`: the RVA of the import lookup (or bound IAT) table.
/// `first_thunk_rva`: the RVA of the IAT used to compute each entry's IAT RVA.
/// `imports`: the output list appended in place.
///
/// Appends nothing when the lookup table RVA is unmapped; entries with
/// unreadable or empty names, or overflowing offsets, are skipped. Failures
/// are reported on stderr.
fn collect_descriptor_imports(
    file: &ValidatedPeFile,
    library_name: Box<str>,
    lookup_table_rva: usize,
    first_thunk_rva: usize,
    imports: &mut Vec<FileApiImport>,
)
{
    let lookup_bytes = match mapped_bytes_from_rva(file, lookup_table_rva)
    {
        Some(value) => value,
        None =>
        {
            eprintln!(
                "failed to map the {} import lookup table at RVA 0x{:08X}",
                library_name, lookup_table_rva
            );
            return;
        }
    };

    for (thunk_index, thunk_bytes) in lookup_bytes
        .chunks_exact(IMPORT_LOOKUP_ENTRY_SIZE)
        .enumerate()
    {
        let thunk_value = match read_u64(thunk_bytes, 0)
        {
            Some(value) => value,
            None =>
            {
                eprintln!("failed to read {} import thunk {}", library_name, thunk_index);
                break;
            }
        };

        if thunk_value == 0
        {
            break;
        }

        let import_name = if thunk_value & IMAGE_ORDINAL_FLAG64 != 0
        {
            format!("#{}", thunk_value & 0xFFFF).into_boxed_str()
        }
        else
        {
            let import_by_name_rva = match usize::try_from(thunk_value)
            {
                Ok(value) => value,
                Err(_) =>
                {
                    eprintln!(
                        "{} import thunk {} value 0x{:016X} does not fit an RVA",
                        library_name, thunk_index, thunk_value
                    );
                    continue;
                }
            };
            let function_name_rva = match import_by_name_rva.checked_add(IMPORT_BY_NAME_HINT_SIZE)
            {
                Some(value) => value,
                None =>
                {
                    eprintln!("{} import thunk {} name RVA overflowed", library_name, thunk_index);
                    continue;
                }
            };

            match read_mapped_c_string(file, function_name_rva)
            {
                Some(value) if !value.is_empty() => value,
                _ =>
                {
                    eprintln!(
                        "failed to read the {} import name at RVA 0x{:08X}",
                        library_name, function_name_rva
                    );
                    continue;
                }
            }
        };
        let iat_rva = match thunk_index
            .checked_mul(IMPORT_LOOKUP_ENTRY_SIZE)
            .and_then(|offset| first_thunk_rva.checked_add(offset))
        {
            Some(value) => value,
            None =>
            {
                eprintln!("{} import thunk {} IAT RVA overflowed", library_name, thunk_index);
                break;
            }
        };

        imports.push(FileApiImport
        {
            library_name: library_name.clone(),
            import_name,
            iat_rva,
            file_offset: read_mapped_bytes(file, iat_rva, IMPORT_LOOKUP_ENTRY_SIZE)
                .and_then(|_| rva_to_file_offset(file, iat_rva)),
            xrefs: Vec::new(),
        });
    }
}


/// Collects direct IAT references and near references to matching import thunks.
/// `file`: the validated EXE or DLL whose executable sections should be scanned.
/// `iat_rvas`: the IAT entry RVAs to match displacement targets against.
///
/// Returns per-IAT xref lists, sorted and deduplicated; RVAs with no supported
/// references have no entry, and unscannable sections are skipped and reported
/// on stderr.
fn collect_iat_xrefs(file: &ValidatedPeFile, iat_rvas: &HashSet<usize>) -> HashMap<usize, Vec<FileApiXref>>
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
                eprintln!(
                    "executable section at RVA 0x{:08X} has raw data outside the file",
                    section.virtual_address
                );
                continue;
            }
        };
        let mut opcode_file_offset = section.raw_offset;

        while opcode_file_offset
            .checked_add(6)
            .is_some_and(|instruction_end| instruction_end <= section_end)
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
            let displacement = i32::from_le_bytes([
                file.bytes[opcode_file_offset + 2],
                file.bytes[opcode_file_offset + 3],
                file.bytes[opcode_file_offset + 4],
                file.bytes[opcode_file_offset + 5],
            ]);
            let opcode_delta = match opcode_file_offset.checked_sub(section.raw_offset)
            {
                Some(value) => value,
                None =>
                {
                    eprintln!(
                        "opcode file offset 0x{:08X} fell below its section start",
                        opcode_file_offset
                    );
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
                let instruction_file_offset = if opcode_file_offset > section.raw_offset
                    && matches!(file.bytes[opcode_file_offset - 1], 0x40..=0x4F)
                {
                    opcode_file_offset - 1
                }
                else
                {
                    opcode_file_offset
                };
                let instruction_delta = instruction_file_offset - section.raw_offset;
                let instruction_rva = match section.virtual_address.checked_add(instruction_delta)
                {
                    Some(value) => value,
                    None =>
                    {
                        eprintln!(
                            "instruction RVA overflowed at file offset 0x{:08X}",
                            instruction_file_offset
                        );
                        opcode_file_offset += 6;
                        continue;
                    }
                };

                if kind == FileApiXrefKind::Jump
                {
                    thunk_iat_by_rva.insert(instruction_rva, iat_rva);
                }

                xrefs_by_iat.entry(iat_rva).or_default().push(FileApiXref
                {
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

            while opcode_file_offset
                .checked_add(5)
                .is_some_and(|instruction_end| instruction_end <= section_end)
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
                let displacement = i32::from_le_bytes([
                    file.bytes[opcode_file_offset + 1],
                    file.bytes[opcode_file_offset + 2],
                    file.bytes[opcode_file_offset + 3],
                    file.bytes[opcode_file_offset + 4],
                ]);
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
                    xrefs_by_iat.entry(*iat_rva).or_default().push(FileApiXref
                    {
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


/// Reads the normal import data-directory RVA and size from the optional header.
/// `file`: the validated EXE or DLL whose optional header should be read.
///
/// Returns the directory RVA and size when the entry exists inside the optional
/// header, is non-zero, and holds at least one descriptor; `None` otherwise,
/// with the failure reported on stderr.
fn get_import_directory(file: &ValidatedPeFile) -> Option<(usize, usize)>
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

    let optional_header_size = match nt_header_offset
        .checked_add(PE_SIGNATURE_SIZE + 16)
        .and_then(|offset| read_u16(&file.bytes, offset))
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

    if directory_count <= IMAGE_DIRECTORY_ENTRY_IMPORT
    {
        eprintln!("data-directory count {} has no import directory entry", directory_count);
        return None;
    }

    let import_directory_offset = match IMAGE_DIRECTORY_ENTRY_IMPORT
        .checked_mul(DATA_DIRECTORY_SIZE)
        .and_then(|offset| OPTIONAL_HEADER_DATA_DIRECTORY_OFFSET.checked_add(offset))
        .and_then(|offset| optional_header_offset.checked_add(offset))
    {
        Some(value) => value,
        None =>
        {
            eprintln!("import data-directory entry offset overflowed");
            return None;
        }
    };

    let import_directory_end = match import_directory_offset.checked_add(DATA_DIRECTORY_SIZE)
    {
        Some(value) => value,
        None =>
        {
            eprintln!("import data-directory entry end overflowed at offset 0x{:08X}", import_directory_offset);
            return None;
        }
    };

    if import_directory_end > optional_header_end
    {
        eprintln!("import data-directory entry ends outside the optional header");
        return None;
    }

    let import_directory_rva = match read_u32(&file.bytes, import_directory_offset)
    {
        Some(value) => value as usize,
        None =>
        {
            eprintln!("failed to read the import directory RVA at offset 0x{:08X}", import_directory_offset);
            return None;
        }
    };
    
    let import_directory_size = match read_u32(&file.bytes, import_directory_offset + 4)
    {
        Some(value) => value as usize,
        None =>
        {
            eprintln!("failed to read the import directory size at offset 0x{:08X}", import_directory_offset + 4);
            return None;
        }
    };

    if import_directory_rva == 0 || import_directory_size < IMPORT_DESCRIPTOR_SIZE
    {
        eprintln!(
            "import directory RVA 0x{:08X} with size 0x{:08X} holds no descriptors",
            import_directory_rva, import_directory_size
        );
        return None;
    }

    Some((import_directory_rva, import_directory_size))
}


/// Reads an exact raw slice through an RVA mapping without crossing its mapped region.
/// `file`: the validated EXE or DLL whose raw bytes back the mapping.
/// `rva`: the relative virtual address where the slice begins.
/// `length`: the exact number of bytes to read.
///
/// Returns the slice when the RVA maps to raw data and the full length fits
/// inside that mapped region; `None` otherwise.
fn read_mapped_bytes(file: &ValidatedPeFile, rva: usize, length: usize) -> Option<&[u8]>
{
    let (file_offset, mapped_end) = rva_to_file_range(file, rva)?;
    let requested_end = file_offset.checked_add(length)?;

    if requested_end > mapped_end
    {
        return None;
    }

    file.bytes.get(file_offset..requested_end)
}


/// Returns the remaining raw bytes in the mapped region containing an RVA.
/// `file`: the validated EXE or DLL whose raw bytes back the mapping.
/// `rva`: the relative virtual address where the slice begins.
///
/// Returns the bytes from the RVA to the end of its mapped region; `None`
/// when the RVA is not backed by headers or raw section data.
fn mapped_bytes_from_rva(file: &ValidatedPeFile, rva: usize) -> Option<&[u8]>
{
    let (file_offset, mapped_end) = rva_to_file_range(file, rva)?;

    file.bytes.get(file_offset..mapped_end)
}


/// Reads a NUL-terminated UTF-8 import string through an RVA mapping.
/// `file`: the validated EXE or DLL whose raw bytes back the mapping.
/// `rva`: the relative virtual address where the string begins.
///
/// Returns the string when the RVA is mapped, a NUL terminator exists within
/// the mapped region, and the bytes are valid UTF-8; `None` otherwise.
fn read_mapped_c_string(file: &ValidatedPeFile, rva: usize) -> Option<Box<str>>
{
    let bytes = mapped_bytes_from_rva(file, rva)?;
    let terminator = bytes.iter().position(|byte| *byte == 0)?;
    let value = std::str::from_utf8(&bytes[..terminator]).ok()?;

    Some(value.into())
}


/// Maps an RVA to a raw file offset when it is backed by headers or section data.
/// `file`: the validated EXE or DLL whose headers and sections back the mapping.
/// `rva`: the relative virtual address to resolve.
///
/// Returns the raw file offset; `None` when the RVA has no raw backing.
fn rva_to_file_offset(file: &ValidatedPeFile, rva: usize) -> Option<usize>
{
    rva_to_file_range(file, rva).map(|(file_offset, _)| file_offset)
}
