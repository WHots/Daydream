use std::collections::HashSet;

use crate::core::file_ops::procedures::imports::parsing::collect_imports;
use crate::core::file_ops::procedures::imports::types::FileApiImport;
use crate::core::file_ops::procedures::imports::xrefs::collect_iat_xrefs;
use crate::core::file_ops::utils::validate::ValidatedPeFile;

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

    let iat_rvas: HashSet<usize> = imports.iter().map(|api_import| api_import.iat_rva).collect();
    let mut xrefs_by_iat = collect_iat_xrefs(file, &iat_rvas);

    for api_import in &mut imports
    {
        api_import.xrefs = xrefs_by_iat.remove(&api_import.iat_rva).unwrap_or_default();
    }

    imports
}
