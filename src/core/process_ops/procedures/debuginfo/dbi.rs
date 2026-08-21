use std::path::Path;

use ms_pdb::Pdb;

/// Owns every source-path occurrence stored in the DBI Sources substream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DbiSourcePaths
{
    pub paths: Vec<Box<str>>,
}


/// Explains why DBI source-path collection could not complete.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DbiSourcePathCollectionError
{
    PdbOpen
    {
        message: Box<str>,
    },
    SourcesRead
    {
        message: Box<str>,
    },
    InvalidSourcePath
    {
        source_index: usize,
    },
    InvalidSourcePathEncoding
    {
        source_index: usize,
    },
}


/// Opens an explicit local PDB and retains every DBI source-path occurrence.
/// `pdb_path`: local PDB path supplied by the caller.
///
/// Returns source paths in DBI order, including repeated paths.
pub(crate) fn collect_dbi_source_paths(pdb_path: &Path) -> Result<DbiSourcePaths, DbiSourcePathCollectionError>
{
    let pdb = Pdb::open(pdb_path).map_err(|error| DbiSourcePathCollectionError::PdbOpen {
        message: error.to_string().into_boxed_str(),
    })?;

    let sources = pdb.sources().map_err(|error| DbiSourcePathCollectionError::SourcesRead {
        message: error.to_string().into_boxed_str(),
    })?;

    let expected_path_count = sources.file_name_offsets().len();

    let mut paths = Vec::with_capacity(expected_path_count);

    for (source_index, (_, source_path)) in sources.iter_sources().enumerate()
    {
        let source_path = std::str::from_utf8(source_path.as_ref()).map_err(|_| DbiSourcePathCollectionError::InvalidSourcePathEncoding {
            source_index,
        })?;

        paths.push(source_path.into());
    }

    if paths.len() != expected_path_count
    {
        return Err(DbiSourcePathCollectionError::InvalidSourcePath { source_index: paths.len()});
    }

    Ok(DbiSourcePaths {paths})
}
