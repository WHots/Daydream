use std::collections::{HashMap, HashSet};

use crate::core::process_ops::procedures::foundation::validate_pe;
use crate::core::process_ops::utils::process::ValidatedProcessPe;

use super::{parsing, xrefs, PeIatXref, PeImportEntry, ProcessImportCollection, ProcessImportCollectionError, ProcessImportInfo, ProcessImportXref};

/// Collects main-module imports from a previously validated process image snapshot.
/// `process`: the validated process identity supplying the main-module address and size.
/// `snapshot`: the matching mapped-image bytes, PE headers, and unavailable ranges.
/// `progress`: callback receiving completed and total executable bytes during IAT scanning.
///
/// Returns owned import and xref records without revalidating the process or reading its
/// main image again.
pub(crate) fn collect_process_imports_from_snapshot(process: &ValidatedProcessPe, snapshot: &validate_pe::ValidatedPeSnapshot, progress: &mut impl FnMut(usize, usize)) -> Result<ProcessImportCollection, ProcessImportCollectionError>
{
    if let Some(range) = parsing::find_unavailable_import_range(snapshot)
    {
        return Err(ProcessImportCollectionError::IncompleteMainModuleSnapshot {
            rva: range.rva,
            size: range.size,
        });
    }

    let imports = collect_process_import_info(process.image.base_address, &snapshot.bytes, &snapshot.pe, progress);

    Ok(ProcessImportCollection {
        module_base_address: process.image.base_address,
        module_size: process.image.image_size,
        imports,
        unavailable_ranges: snapshot.unavailable_ranges.clone(),
    })
}


/// Builds grouped process import records from loaded module bytes.
/// `module_base_address`: the remote base address used for absolute-address mapping.
/// `pe_data`: loaded main-module bytes indexed by RVA.
/// `pe`: copied validated headers and sections for `pe_data`.
/// `progress`: callback receiving completed and total executable bytes.
///
/// Returns all standard imports with their direct IAT xrefs grouped by slot.
fn collect_process_import_info(module_base_address: usize, pe_data: &[u8], pe: &validate_pe::PeImage, progress: &mut impl FnMut(usize, usize)) -> Vec<ProcessImportInfo>
{
    let imports = parsing::collect_import_entries_from_pe(pe_data, pe);

    if imports.is_empty()
    {
        progress(0, 0);
        return Vec::new();
    }

    let targets: HashSet<usize> = imports.iter().map(|entry| entry.iat_rva).collect();
    let xrefs = xrefs::collect_iat_xrefs_for_targets(pe_data, pe, &targets, progress);

    build_process_import_info(module_base_address, imports, xrefs)
}


/// Groups flat IAT xrefs into their owning process import records.
/// `module_base_address`: the remote base address used for absolute-address mapping.
/// `imports`: parsed standard import-table entries.
/// `xrefs`: direct code references collected for all imported IAT slots.
///
/// Returns owned import records while preserving import-table and instruction order.
fn build_process_import_info(module_base_address: usize, imports: Vec<PeImportEntry>, xrefs: Vec<PeIatXref>) -> Vec<ProcessImportInfo>
{
    let mut xrefs_by_iat: HashMap<usize, Vec<ProcessImportXref>> = HashMap::with_capacity(imports.len());

    for xref in xrefs
    {
        xrefs_by_iat.entry(xref.iat_rva).or_default().push(ProcessImportXref {
            kind: xref.kind,
            instruction_rva: xref.instruction_rva,
            instruction_address: module_base_address.checked_add(xref.instruction_rva),
            instruction_file_offset: xref.file_offset,
        });
    }

    let mut grouped = Vec::with_capacity(imports.len());

    for import in imports
    {
        let iat_rva = import.iat_rva;

        grouped.push(ProcessImportInfo {
            library_name: import.library_name,
            function_name: import.function_name,
            ordinal: import.ordinal,
            iat_rva,
            iat_address: module_base_address.checked_add(iat_rva),
            iat_file_offset: import.file_offset,
            xrefs: xrefs_by_iat.remove(&iat_rva).unwrap_or_default(),
        });
    }

    grouped
}
