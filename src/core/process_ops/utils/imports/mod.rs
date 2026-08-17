mod collector;
mod parsing;
mod xrefs;

use crate::core::process_ops::utils::foundation::validate_pe;

pub(crate) use collector::collect_process_imports_from_snapshot;

/// Describes one import-table entry before its code references are grouped.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeImportEntry
{
    pub library_name: Box<str>,
    pub function_name: Box<str>,
    pub ordinal: Option<u16>,
    pub iat_rva: usize,
    pub file_offset: Option<usize>,
}


/// Describes the direct instruction form used to reference an IAT slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeIatXrefKind
{
    Call,
    Jump,
}


/// Describes one direct x64 call or jump reference to an IAT slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeIatXref
{
    pub iat_rva: usize,
    pub instruction_rva: usize,
    pub file_offset: Option<usize>,
    pub kind: PeIatXrefKind,
}


/// Stores one process import and every direct code reference found for its IAT slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessImportInfo
{
    pub library_name: Box<str>,
    pub function_name: Box<str>,
    pub ordinal: Option<u16>,
    pub iat_rva: usize,
    pub iat_address: Option<usize>,
    pub iat_file_offset: Option<usize>,
    pub xrefs: Vec<ProcessImportXref>,
}


/// Stores one direct process instruction reference to an imported IAT slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessImportXref
{
    pub kind: PeIatXrefKind,
    pub instruction_rva: usize,
    pub instruction_address: Option<usize>,
    pub instruction_file_offset: Option<usize>,
}


/// Owns process imports, IAT references, and any unrelated loader-discarded ranges.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessImportCollection
{
    pub module_base_address: usize,
    pub module_size: usize,
    pub imports: Vec<ProcessImportInfo>,
    pub unavailable_ranges: Vec<validate_pe::UnavailablePeRange>,
}


/// Explains why process import collection could not complete.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProcessImportCollectionError
{
    IncompleteMainModuleSnapshot
    {
        rva: usize, size: usize
    },
}
