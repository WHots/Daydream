use crate::core::process_ops::procedures::debuginfo::pdb::PdbGuid;

/// Identifies the payload format declared by an `IMAGE_DEBUG_DIRECTORY` entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileDebugType
{
    Unknown,
    Coff,
    CodeView,
    Fpo,
    Misc,
    Exception,
    Fixup,
    OmapToSource,
    OmapFromSource,
    Borland,
    Reserved10,
    Clsid,
    VcFeature,
    Pogo,
    Iltcg,
    Mpx,
    Reproducible,
    EmbeddedPortablePdb,
    Spgo,
    PdbChecksum,
    ExtendedDllCharacteristics,
    Other(u32),
}


/// Contains parsed CodeView metadata for an RSDS, NB10, or unknown signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FileCodeViewInfo
{
    Rsds
    {
        guid: PdbGuid,
        age: u32,
        path: Box<str>,
    },
    Nb10
    {
        offset: u32,
        signature: u32,
        age: u32,
        path: Box<str>,
    },
    Other([u8; 4]),
}


/// Contains the five counters stored in a Visual C++ feature debug payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileVcFeatureInfo
{
    pub pre_vc11: u32,
    pub c_cpp: u32,
    pub gs: u32,
    pub sdl: u32,
    pub guard_n: u32,
}


/// Describes one procedure group stored in a POGO debug payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilePogoEntry
{
    pub rva: u32,
    pub size: u32,
    pub name: Box<str>,
}


/// Contains a POGO signature and every aligned procedure group in its payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilePogoInfo
{
    pub signature: [u8; 4],
    pub entries: Vec<FilePogoEntry>,
}


/// Contains the optional length-prefixed hash stored by a reproducible-build entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileReproducibleInfo
{
    pub declared_hash_length: Option<usize>,
    pub hash: Box<[u8]>,
    pub length_matches: bool,
}


/// Contains parsed `IMAGE_DEBUG_MISC` metadata and its optional text value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileMiscDebugInfo
{
    pub data_type: u32,
    pub declared_length: usize,
    pub unicode: bool,
    pub text: Option<Box<str>>,
}


/// Contains a symbol-file checksum algorithm name and checksum bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilePdbChecksumInfo
{
    pub algorithm: Box<str>,
    pub checksum: Box<[u8]>,
}


/// Contains the envelope metadata for an embedded compressed Portable PDB.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileEmbeddedPortablePdbInfo
{
    pub uncompressed_size: usize,
    pub compressed_size: usize,
}


/// Describes typed interpretation status for one debug payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FileDebugDetails
{
    None,
    CodeView(FileCodeViewInfo),
    VcFeature(FileVcFeatureInfo),
    Pogo(FilePogoInfo),
    Reproducible(FileReproducibleInfo),
    Misc(FileMiscDebugInfo),
    PdbChecksum(FilePdbChecksumInfo),
    EmbeddedPortablePdb(FileEmbeddedPortablePdbInfo),
    ExtendedDllCharacteristics(u32),
    Raw,
    Malformed,
    DecodeLimitExceeded,
    Unavailable,
}


/// Contains one raw PE debug-directory entry and its safely collected payload metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileDebugEntry<'a>
{
    pub index: usize,
    pub entry_rva: usize,
    pub entry_file_offset: usize,
    pub characteristics: u32,
    pub timestamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub raw_type: u32,
    pub debug_type: FileDebugType,
    pub size_of_data: usize,
    pub address_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub rva_data_file_offset: Option<usize>,
    pub data_file_offset: Option<usize>,
    pub data_location_mismatch: bool,
    pub raw_data: Option<&'a [u8]>,
    pub details: FileDebugDetails,
}

impl From<u32> for FileDebugType
{
    fn from(value: u32) -> Self
    {
        match value
        {
            0 => Self::Unknown,
            1 => Self::Coff,
            2 => Self::CodeView,
            3 => Self::Fpo,
            4 => Self::Misc,
            5 => Self::Exception,
            6 => Self::Fixup,
            7 => Self::OmapToSource,
            8 => Self::OmapFromSource,
            9 => Self::Borland,
            10 => Self::Reserved10,
            11 => Self::Clsid,
            12 => Self::VcFeature,
            13 => Self::Pogo,
            14 => Self::Iltcg,
            15 => Self::Mpx,
            16 => Self::Reproducible,
            17 => Self::EmbeddedPortablePdb,
            18 => Self::Spgo,
            19 => Self::PdbChecksum,
            20 => Self::ExtendedDllCharacteristics,
            other => Self::Other(other),
        }
    }
}
