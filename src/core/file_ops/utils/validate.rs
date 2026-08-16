use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, Read};
use std::os::windows::fs::OpenOptionsExt;
use std::path::Path;

use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;

const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
const IMAGE_FILE_DLL: u16 = 0x2000;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x020B;
const DOS_HEADER_MINIMUM_SIZE: usize = 0x40;
const PE_SIGNATURE_SIZE: usize = 4;
const COFF_HEADER_SIZE: usize = 20;
const OPTIONAL_HEADER64_MINIMUM_SIZE: usize = 112;
const SECTION_HEADER_SIZE: usize = 40;
const MAXIMUM_PE_FILE_SIZE: u64 = 0x1000_0000;

/// Surface-level information about one section in a validated raw PE file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeFileSection
{
    pub name: Box<str>,
    pub virtual_address: usize,
    pub virtual_size: usize,
    pub raw_offset: usize,
    pub raw_size: usize,
    pub characteristics: u32,
}


/// Owns a validated raw x64 PE file and the metadata needed by later collectors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedPeFile
{
    pub bytes: Box<[u8]>,
    pub machine: u16,
    pub timestamp: u32,
    pub characteristics: u16,
    pub entry_point_rva: usize,
    pub image_base: u64,
    pub section_alignment: usize,
    pub file_alignment: usize,
    pub size_of_image: usize,
    pub size_of_headers: usize,
    pub sections: Box<[PeFileSection]>,
}


/// Explains why a target file could not be accepted as a raw x64 PE executable.
#[derive(Debug)]
pub enum FileValidationError
{
    FileAccess(io::Error),
    NotRegularFile,
    FileTooSmall,
    FileTooLarge
    {
        file_size: u64,
        maximum_size: u64,
    },
    InvalidDosSignature,
    InvalidNtHeaderOffset,
    InvalidNtSignature,
    UnsupportedMachine(u16),
    MissingSections,
    InvalidOptionalHeader,
    UnsupportedOptionalHeader(u16),
    NotExecutableImage,
    DynamicLibrary,
    InvalidImageSize,
    InvalidHeaderSize,
    InvalidAlignment,
    EntryPointOutOfRange
    {
        entry_point_rva: usize,
        size_of_image: usize,
    },
    InvalidSectionTable,
    InvalidSectionRawRange
    {
        section_index: usize,
    },
    InvalidSectionVirtualRange
    {
        section_index: usize,
    },
}


/// Reads a target file once, validates its x64 PE structure, and returns its bytes
/// with the surface-level metadata required by later raw-file collectors.
/// `path`: the executable file to validate without loading or executing it.
///
/// Returns `Ok(ValidatedPeFile)` when the file is safe to continue parsing, or a
/// `FileValidationError` describing the first structural validation failure.
pub fn validate_target_file(path: &Path) -> Result<ValidatedPeFile, FileValidationError>
{
    let mut file = OpenOptions::new().read(true).share_mode(FILE_SHARE_READ).open(path).map_err(FileValidationError::FileAccess)?;
    let metadata = file.metadata().map_err(FileValidationError::FileAccess)?;

    if !metadata.is_file()
    {
        return Err(FileValidationError::NotRegularFile);
    }

    let metadata_size = metadata.len();

    if metadata_size > MAXIMUM_PE_FILE_SIZE
    {
        return Err(FileValidationError::FileTooLarge {
            file_size: metadata_size,
            maximum_size: MAXIMUM_PE_FILE_SIZE,
        });
    }

    let file_size = usize::try_from(metadata_size).map_err(|_| FileValidationError::FileAccess(io::Error::new(io::ErrorKind::InvalidData, "target file size does not fit in memory")))?;
    let read_limit = metadata_size.checked_add(1).ok_or_else(|| FileValidationError::FileAccess(io::Error::new(io::ErrorKind::InvalidData, "target file read limit overflowed")))?;
    let mut bytes = Vec::new();

    bytes.try_reserve_exact(file_size).map_err(|_| FileValidationError::FileAccess(io::Error::new(io::ErrorKind::OutOfMemory, "failed to allocate the target file buffer")))?;
    file.by_ref().take(read_limit).read_to_end(&mut bytes).map_err(FileValidationError::FileAccess)?;

    if bytes.len() != file_size
    {
        return Err(FileValidationError::FileAccess(io::Error::new(io::ErrorKind::InvalidData, "target file size changed while it was being read")));
    }

    if bytes.len() < DOS_HEADER_MINIMUM_SIZE
    {
        return Err(FileValidationError::FileTooSmall);
    }

    if bytes.get(0..2) != Some(b"MZ")
    {
        return Err(FileValidationError::InvalidDosSignature);
    }

    let nt_header_offset = read_u32(&bytes, 0x3C).and_then(|value| usize::try_from(value).ok()).ok_or(FileValidationError::InvalidNtHeaderOffset)?;
    let coff_header_offset = nt_header_offset.checked_add(PE_SIGNATURE_SIZE).ok_or(FileValidationError::InvalidNtHeaderOffset)?;
    let optional_header_offset = coff_header_offset.checked_add(COFF_HEADER_SIZE).ok_or(FileValidationError::InvalidNtHeaderOffset)?;

    if bytes.get(nt_header_offset..coff_header_offset) != Some(b"PE\0\0")
    {
        return Err(FileValidationError::InvalidNtSignature);
    }

    let machine = read_u16(&bytes, coff_header_offset).ok_or(FileValidationError::InvalidNtHeaderOffset)?;

    if machine != IMAGE_FILE_MACHINE_AMD64
    {
        return Err(FileValidationError::UnsupportedMachine(machine));
    }

    let number_of_sections = read_u16(&bytes, coff_header_offset + 2).ok_or(FileValidationError::InvalidNtHeaderOffset)? as usize;

    if number_of_sections == 0
    {
        return Err(FileValidationError::MissingSections);
    }

    let timestamp = read_u32(&bytes, coff_header_offset + 4).ok_or(FileValidationError::InvalidNtHeaderOffset)?;
    let optional_header_size = read_u16(&bytes, coff_header_offset + 16).ok_or(FileValidationError::InvalidNtHeaderOffset)? as usize;
    let characteristics = read_u16(&bytes, coff_header_offset + 18).ok_or(FileValidationError::InvalidNtHeaderOffset)?;

    if characteristics & IMAGE_FILE_EXECUTABLE_IMAGE == 0
    {
        return Err(FileValidationError::NotExecutableImage);
    }

    if characteristics & IMAGE_FILE_DLL != 0
    {
        return Err(FileValidationError::DynamicLibrary);
    }

    if optional_header_size < OPTIONAL_HEADER64_MINIMUM_SIZE
    {
        return Err(FileValidationError::InvalidOptionalHeader);
    }

    let optional_header_end = optional_header_offset.checked_add(optional_header_size).ok_or(FileValidationError::InvalidOptionalHeader)?;

    if optional_header_end > bytes.len()
    {
        return Err(FileValidationError::InvalidOptionalHeader);
    }

    let optional_header_magic = read_u16(&bytes, optional_header_offset).ok_or(FileValidationError::InvalidOptionalHeader)?;

    if optional_header_magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC
    {
        return Err(FileValidationError::UnsupportedOptionalHeader(optional_header_magic));
    }

    let entry_point_rva = read_u32(&bytes, optional_header_offset + 16).ok_or(FileValidationError::InvalidOptionalHeader)? as usize;
    let image_base = read_u64(&bytes, optional_header_offset + 24).ok_or(FileValidationError::InvalidOptionalHeader)?;
    let section_alignment = read_u32(&bytes, optional_header_offset + 32).ok_or(FileValidationError::InvalidOptionalHeader)? as usize;
    let file_alignment = read_u32(&bytes, optional_header_offset + 36).ok_or(FileValidationError::InvalidOptionalHeader)? as usize;
    let size_of_image = read_u32(&bytes, optional_header_offset + 56).ok_or(FileValidationError::InvalidOptionalHeader)? as usize;
    let size_of_headers = read_u32(&bytes, optional_header_offset + 60).ok_or(FileValidationError::InvalidOptionalHeader)? as usize;

    if size_of_image == 0
    {
        return Err(FileValidationError::InvalidImageSize);
    }

    if section_alignment == 0 || file_alignment == 0
    {
        return Err(FileValidationError::InvalidAlignment);
    }

    if entry_point_rva >= size_of_image
    {
        return Err(FileValidationError::EntryPointOutOfRange {
            entry_point_rva,
            size_of_image,
        });
    }

    let section_table_size = number_of_sections.checked_mul(SECTION_HEADER_SIZE).ok_or(FileValidationError::InvalidSectionTable)?;
    let section_table_end = optional_header_end.checked_add(section_table_size).ok_or(FileValidationError::InvalidSectionTable)?;

    if section_table_end > bytes.len()
    {
        return Err(FileValidationError::InvalidSectionTable);
    }

    if size_of_headers < section_table_end || size_of_headers > bytes.len()
    {
        return Err(FileValidationError::InvalidHeaderSize);
    }

    let mut sections = Vec::with_capacity(number_of_sections);

    for section_index in 0..number_of_sections
    {
        let section_offset = optional_header_end + section_index * SECTION_HEADER_SIZE;
        let name_bytes = bytes.get(section_offset..section_offset + 8).ok_or(FileValidationError::InvalidSectionTable)?;
        let name = String::from_utf8_lossy(name_bytes).trim_end_matches('\0').to_string().into_boxed_str();
        let virtual_size = read_u32(&bytes, section_offset + 8).ok_or(FileValidationError::InvalidSectionTable)? as usize;
        let virtual_address = read_u32(&bytes, section_offset + 12).ok_or(FileValidationError::InvalidSectionTable)? as usize;
        let raw_size = read_u32(&bytes, section_offset + 16).ok_or(FileValidationError::InvalidSectionTable)? as usize;
        let raw_offset = read_u32(&bytes, section_offset + 20).ok_or(FileValidationError::InvalidSectionTable)? as usize;
        let section_characteristics = read_u32(&bytes, section_offset + 36).ok_or(FileValidationError::InvalidSectionTable)?;

        if raw_size != 0
        {
            let raw_end = raw_offset.checked_add(raw_size).ok_or(FileValidationError::InvalidSectionRawRange {
                section_index,
            })?;

            if raw_end > bytes.len()
            {
                return Err(FileValidationError::InvalidSectionRawRange {
                    section_index,
                });
            }
        }

        let virtual_span = virtual_size.max(raw_size);
        let virtual_end = virtual_address.checked_add(virtual_span).ok_or(FileValidationError::InvalidSectionVirtualRange {
            section_index,
        })?;

        if virtual_end > size_of_image
        {
            return Err(FileValidationError::InvalidSectionVirtualRange {
                section_index,
            });
        }

        sections.push(PeFileSection {
            name,
            virtual_address,
            virtual_size,
            raw_offset,
            raw_size,
            characteristics: section_characteristics,
        });
    }

    Ok(ValidatedPeFile {
        bytes: bytes.into_boxed_slice(),
        machine,
        timestamp,
        characteristics,
        entry_point_rva,
        image_base,
        section_alignment,
        file_alignment,
        size_of_image,
        size_of_headers,
        sections: sections.into_boxed_slice(),
    })
}

impl fmt::Display for FileValidationError
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        match self
        {
            Self::FileAccess(error) => write!(formatter, "file access failed: {error}"),
            Self::NotRegularFile => write!(formatter, "target is not a regular file"),
            Self::FileTooSmall => write!(formatter, "file is too small to contain a PE header"),
            Self::FileTooLarge {
                file_size,
                maximum_size,
            } => write!(formatter, "file size {file_size} exceeds the safe in-memory limit of {maximum_size} bytes"),
            Self::InvalidDosSignature => write!(formatter, "DOS MZ signature is invalid"),
            Self::InvalidNtHeaderOffset => write!(formatter, "NT header offset is invalid"),
            Self::InvalidNtSignature => write!(formatter, "PE signature is invalid"),
            Self::UnsupportedMachine(machine) =>
            {
                write!(formatter, "unsupported PE machine type 0x{machine:04X}")
            }
            Self::MissingSections => write!(formatter, "PE file has no sections"),
            Self::InvalidOptionalHeader => write!(formatter, "PE optional header is invalid"),
            Self::UnsupportedOptionalHeader(magic) =>
            {
                write!(formatter, "unsupported optional-header magic 0x{magic:04X}")
            }
            Self::NotExecutableImage =>
            {
                write!(formatter, "PE is not marked as an executable image")
            }
            Self::DynamicLibrary =>
            {
                write!(formatter, "PE target is a DLL rather than an executable")
            }
            Self::InvalidImageSize => write!(formatter, "PE image size is invalid"),
            Self::InvalidHeaderSize => write!(formatter, "PE header size is invalid"),
            Self::InvalidAlignment => write!(formatter, "PE file or section alignment is invalid"),
            Self::EntryPointOutOfRange {
                entry_point_rva,
                size_of_image,
            } => write!(formatter, "entry-point RVA 0x{entry_point_rva:X} exceeds image size 0x{size_of_image:X}"),
            Self::InvalidSectionTable => write!(formatter, "PE section table is invalid"),
            Self::InvalidSectionRawRange {
                section_index,
            } => write!(formatter, "section {section_index} raw-data range exceeds the file"),
            Self::InvalidSectionVirtualRange {
                section_index,
            } => write!(formatter, "section {section_index} virtual range exceeds the image"),
        }
    }
}

impl std::error::Error for FileValidationError
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)>
    {
        match self
        {
            Self::FileAccess(error) => Some(error),
            _ => None,
        }
    }
}


/// Reads a little-endian `u16` from an exact byte offset.
fn read_u16(bytes: &[u8], offset: usize) -> Option<u16>
{
    let value = bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?;

    Some(u16::from_le_bytes(value))
}


/// Reads a little-endian `u32` from an exact byte offset.
fn read_u32(bytes: &[u8], offset: usize) -> Option<u32>
{
    let value = bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?;

    Some(u32::from_le_bytes(value))
}


/// Reads a little-endian `u64` from an exact byte offset.
fn read_u64(bytes: &[u8], offset: usize) -> Option<u64>
{
    let value = bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?;

    Some(u64::from_le_bytes(value))
}
