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
