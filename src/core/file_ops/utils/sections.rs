use std::fmt;

use crate::core::file_ops::utils::validate::ValidatedPeFile;

const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;
const IMAGE_SCN_MEM_SHARED: u32 = 0x1000_0000;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

/// Describes the content declared by a PE section's characteristics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeSectionContent
{
    Code,
    InitializedData,
    UninitializedData,
}


/// Describes the memory traits declared by a PE section's characteristics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeSectionMemory
{
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub shared: bool,
    pub discardable: bool,
}


/// Contains structured section metadata collected from a validated raw PE file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeSectionInfo
{
    pub name: Box<str>,
    pub content: Vec<PeSectionContent>,
    pub memory: PeSectionMemory,
    pub rva: usize,
    pub virtual_size: usize,
    pub file_offset: usize,
    pub raw_size: usize,
    pub characteristics: u32,
}


/// Collects every section from an already-validated raw PE file into reusable records.
/// `file`: the validated EXE or DLL whose section metadata should be collected.
///
/// Returns one `PeSectionInfo` per section in original section-table order.
pub fn collect_file_sections(file: &ValidatedPeFile) -> Vec<PeSectionInfo>
{
    let mut sections = Vec::with_capacity(file.sections.len());

    for section in file.sections.iter()
    {
        sections.push(PeSectionInfo {
            name: section.name.clone(),
            content: collect_section_content(section.characteristics),
            memory: collect_section_memory(section.characteristics),
            rva: section.virtual_address,
            virtual_size: section.virtual_size,
            file_offset: section.raw_offset,
            raw_size: section.raw_size,
            characteristics: section.characteristics,
        });
    }

    sections
}

impl fmt::Display for PeSectionContent
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        let name = match self
        {
            Self::Code => "Code",
            Self::InitializedData => "Initialized data",
            Self::UninitializedData => "Uninitialized data",
        };

        formatter.write_str(name)
    }
}

impl fmt::Display for PeSectionMemory
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        let readable = if self.readable { 'R' } else { '-' };
        let writable = if self.writable { 'W' } else { '-' };
        let executable = if self.executable { 'X' } else { '-' };

        write!(formatter, "{}{}{}", readable, writable, executable)?;

        if self.shared
        {
            write!(formatter, " shared")?;
        }

        if self.discardable
        {
            write!(formatter, " discardable")?;
        }

        Ok(())
    }
}


/// Collects every declared content type from PE section characteristics.
fn collect_section_content(characteristics: u32) -> Vec<PeSectionContent>
{
    let mut content = Vec::with_capacity(3);

    if characteristics & IMAGE_SCN_CNT_CODE != 0
    {
        content.push(PeSectionContent::Code);
    }

    if characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA != 0
    {
        content.push(PeSectionContent::InitializedData);
    }

    if characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0
    {
        content.push(PeSectionContent::UninitializedData);
    }

    content
}


/// Collects the declared memory traits from PE section characteristics.
fn collect_section_memory(characteristics: u32) -> PeSectionMemory
{
    PeSectionMemory {
        readable: characteristics & IMAGE_SCN_MEM_READ != 0,
        writable: characteristics & IMAGE_SCN_MEM_WRITE != 0,
        executable: characteristics & IMAGE_SCN_MEM_EXECUTE != 0,
        shared: characteristics & IMAGE_SCN_MEM_SHARED != 0,
        discardable: characteristics & IMAGE_SCN_MEM_DISCARDABLE != 0,
    }
}
