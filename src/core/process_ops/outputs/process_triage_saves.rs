use std::io;

use serde_json::{json, Value};
use windows_sys::Win32::System::Diagnostics::Debug::{IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE};

use crate::core::global_utils::fileutils::write_json_file;
use crate::core::internal::handles::handles::HandleGuardError;
use crate::core::process_ops::outputs::config::{prepare_process_dump_layout, ProcessDumpLayout, IMAGE_FILE_NAME, IMPORTS_FILE_NAME, PDB_FILE_NAME, PEB_FILE_NAME, PROCESS_TRIAGE_SCHEMA_VERSION, SECTIONS_FILE_NAME, TEBS_FILE_NAME};
use crate::core::process_ops::process_processing::ProcessTriageCollection;
use crate::core::process_ops::procedures::foundation::validate_pe::UnavailablePeRange;
use crate::core::process_ops::procedures::imports::{PeIatXrefKind, ProcessImportCollectionError};
use crate::core::process_ops::utils::mem::ProcessMemoryReadError;
use crate::core::process_ops::utils::pdb::{PdbCodeViewFormat, PdbInfoCollectionError};
use crate::core::process_ops::utils::teb::{ProcessTebCollectionError, ThreadTebCollectionError, ThreadTebInfo};

/// Saves every retained process-triage result into its configured JSON location.
/// `collection`: the single validated process collection accumulated before persistence.
///
/// Returns the reduced process dump layout after every JSON file is written.
pub fn save_process_triage(collection: &ProcessTriageCollection) -> io::Result<ProcessDumpLayout>
{
    let sha256 = collection.output_identity_sha256.to_string();
    let layout = prepare_process_dump_layout(&collection.validated_process.image_path, &sha256)?;

    write_json_file(&layout.pe, IMAGE_FILE_NAME, &build_image_json(collection, &sha256))?;
    write_json_file(&layout.pe, SECTIONS_FILE_NAME, &build_sections_json(collection))?;
    write_json_file(&layout.pe, PDB_FILE_NAME, &build_pdb_json(collection))?;
    write_json_file(&layout.imports, IMPORTS_FILE_NAME, &build_imports_json(collection))?;
    write_json_file(&layout.peb, PEB_FILE_NAME, &build_peb_json(collection))?;
    write_json_file(&layout.peb, TEBS_FILE_NAME, &build_tebs_json(collection))?;

    Ok(layout)
}


/// Builds validated target identity, image metadata, and snapshot-completeness JSON.
/// `collection`: process collection containing central validation and image facts.
/// `sha256`: retained disk-file or mapped-snapshot digest used to name the dump root.
///
/// Returns one versioned image JSON object.
fn build_image_json(collection: &ProcessTriageCollection, sha256: &str) -> Value
{
    let process = &collection.validated_process;
    let image_end = process.image.base_address.checked_add(process.image.image_size);
    let entry_point_address = process.image.base_address.checked_add(process.image.entry_point_rva);

    json!
    ({
        "schema_version": PROCESS_TRIAGE_SCHEMA_VERSION,
        "status": if collection.unavailable_image_ranges.is_empty() { "collected" } else { "partial" },
        "process":

      {
            "process_id": process.process_id,
            "process_id_hex": format!("0x{:X}", process.process_id),
            "granted_access": collection.granted_access,
            "granted_access_hex": format!("0x{:08X}", collection.granted_access),
            "image_path": process.image_path.display().to_string(),
            "image_file_name": process.image_path.file_name().map(|value| value.to_string_lossy().into_owned()),
            "sha256": sha256,
            "sha256_source": if collection.backing_file_sha256.is_some() { "retained_disk_path_file_bytes" } else { "mapped_image_snapshot_bytes" }
        },
        "image":

      {
            "base_address": process.image.base_address,
            "base_address_hex": format_hex(process.image.base_address),
            "end_address": image_end,
            "end_address_hex": format_optional_hex(image_end),
            "size": process.image.image_size,
            "size_hex": format_hex(process.image.image_size),
            "entry_point_rva": process.image.entry_point_rva,
            "entry_point_rva_hex": format_hex(process.image.entry_point_rva),
            "entry_point_address": entry_point_address,
            "entry_point_address_hex": format_optional_hex(entry_point_address),
            "entry_point_file_offset": collection.entry_point_file_offset,
            "entry_point_file_offset_hex": format_optional_hex(collection.entry_point_file_offset),
            "section_count": process.image.section_count
        },
        "snapshot":

      {
            "complete": collection.unavailable_image_ranges.is_empty(),
            "unavailable_range_count": collection.unavailable_image_ranges.len(),
            "unavailable_ranges": build_unavailable_ranges_json(&collection.unavailable_image_ranges)
        }
    })
}


/// Builds ordered mapped-image section metadata JSON.
/// `collection`: process collection containing validated section records.
///
/// Returns one counted section array with mapped and raw-file locations.
fn build_sections_json(collection: &ProcessTriageCollection) -> Value
{
    let image_base = collection.validated_process.image.base_address;
    let sections = collection
        .sections
        .iter()
        .enumerate()
        .map(|(index, section)| {
            let address = image_base.checked_add(section.rva);

            json!
            ({
                "index": index,
                "name": section.name.as_ref(),
                "rva": section.rva,
                "rva_hex": format_hex(section.rva),
                "address": address,
                "address_hex": format_optional_hex(address),
                "virtual_size": section.virtual_size,
                "virtual_size_hex": format_hex(section.virtual_size),
                "raw_size": section.raw_size,
                "raw_size_hex": format_hex(section.raw_size),
                "mapped_size": section.mapped_size,
                "mapped_size_hex": format_hex(section.mapped_size),
                "raw_file_offset": section.raw_file_offset,
                "raw_file_offset_hex": format_hex(section.raw_file_offset),
                "characteristics": section.characteristics,
                "characteristics_hex": format!("0x{:08X}", section.characteristics),
                "content":

              {
                    "code": section.characteristics & IMAGE_SCN_CNT_CODE != 0,
                    "readable": section.characteristics & IMAGE_SCN_MEM_READ != 0,
                    "writable": section.characteristics & IMAGE_SCN_MEM_WRITE != 0,
                    "executable": section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
                }
            })
        })
        .collect::<Vec<Value>>();

    json!
    ({
        "schema_version": PROCESS_TRIAGE_SCHEMA_VERSION,
        "status": "collected",
        "count": sections.len(),
        "sections": sections
    })
}


/// Builds CodeView PDB metadata and tri-state collection status JSON.
/// `collection`: process collection containing PDB metadata, absence, or failure.
///
/// Returns one PDB object that distinguishes not present and incomplete collection.
fn build_pdb_json(collection: &ProcessTriageCollection) -> Value
{
    match &collection.pdb
    {
        Ok(Some(info)) =>
        {
            let guid = info.guid.map(|value| {
                json!
                ({
                    "value": format!("{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}", value.data1, value.data2, value.data3, value.data4[0], value.data4[1], value.data4[2], value.data4[3], value.data4[4], value.data4[5], value.data4[6], value.data4[7]),
                    "data1": value.data1,
                    "data2": value.data2,
                    "data3": value.data3,
                    "data4": value.data4
                })
            });

            json!
            ({
                "schema_version": PROCESS_TRIAGE_SCHEMA_VERSION,
                "status": "found",
                "pdb":

              {
                    "format": pdb_format_name(info.format),
                    "path":

                  {
                        "full": info.path.full_path.as_ref(),
                        "directory": info.path.directory.as_deref(),
                        "file_name": info.path.file_name.as_deref(),
                        "file_stem": info.path.file_stem.as_deref(),
                        "extension": info.path.extension.as_deref(),
                        "exists_on_disk": info.path.exists_on_disk
                    },
                    "guid": guid,
                    "signature": info.signature,
                    "signature_hex": info.signature.map(|value| format!("0x{:08X}", value)),
                    "age": info.age,
                    "debug_directory_rva": info.debug_directory_rva,
                    "debug_directory_rva_hex": format_hex(info.debug_directory_rva),
                    "debug_directory_file_offset": info.debug_directory_file_offset,
                    "debug_directory_file_offset_hex": format_optional_hex(info.debug_directory_file_offset),
                    "codeview_rva": info.codeview_rva,
                    "codeview_rva_hex": format_hex(info.codeview_rva),
                    "codeview_file_offset": info.codeview_file_offset,
                    "codeview_file_offset_hex": format_optional_hex(info.codeview_file_offset),
                    "codeview_size": info.codeview_size,
                    "codeview_size_hex": format_hex(info.codeview_size)
                }
            })
        }
        Ok(None) => json!
        ({
            "schema_version": PROCESS_TRIAGE_SCHEMA_VERSION,
            "status": "not_present",
            "pdb": Value::Null
        }),
        Err(error) => json!
        ({
            "schema_version": PROCESS_TRIAGE_SCHEMA_VERSION,
            "status": "incomplete",
            "error": build_pdb_error_json(error)
        }),
    }
}


/// Builds standard import-table and direct IAT-xref JSON.
/// `collection`: process collection containing imports or a typed collection failure.
///
/// Returns one status-bearing import result with all IAT and instruction locations.
fn build_imports_json(collection: &ProcessTriageCollection) -> Value
{
    match &collection.imports
    {
        Ok(import_collection) =>
        {
            let imports = import_collection
                .imports
                .iter()
                .map(|process_import| {
                    let xrefs = process_import
                        .xrefs
                        .iter()
                        .map(|xref| {
                            json!
                            ({
                                "kind": iat_xref_kind_name(xref.kind),
                                "instruction_rva": xref.instruction_rva,
                                "instruction_rva_hex": format_hex(xref.instruction_rva),
                                "instruction_address": xref.instruction_address,
                                "instruction_address_hex": format_optional_hex(xref.instruction_address),
                                "instruction_file_offset": xref.instruction_file_offset,
                                "instruction_file_offset_hex": format_optional_hex(xref.instruction_file_offset)
                            })
                        })
                        .collect::<Vec<Value>>();

                    json!
                    ({
                        "library": process_import.library_name.as_ref(),
                        "function": process_import.function_name.as_ref(),
                        "ordinal": process_import.ordinal,
                        "iat_rva": process_import.iat_rva,
                        "iat_rva_hex": format_hex(process_import.iat_rva),
                        "iat_address": process_import.iat_address,
                        "iat_address_hex": format_optional_hex(process_import.iat_address),
                        "iat_file_offset": process_import.iat_file_offset,
                        "iat_file_offset_hex": format_optional_hex(process_import.iat_file_offset),
                        "xref_count": xrefs.len(),
                        "xrefs": xrefs
                    })
                })
                .collect::<Vec<Value>>();
            let xref_count = import_collection.imports.iter().map(|value| value.xrefs.len()).sum::<usize>();

            json!
            ({
                "schema_version": PROCESS_TRIAGE_SCHEMA_VERSION,
                "status": if import_collection.unavailable_ranges.is_empty() { "collected" } else { "partial" },
                "scope":

              {
                    "imports": "standard_pe_import_directory",
                    "xrefs": ["direct_x64_rip_relative_iat_call", "direct_x64_rip_relative_iat_jump"]
                },
                "module_base_address": import_collection.module_base_address,
                "module_base_address_hex": format_hex(import_collection.module_base_address),
                "module_size": import_collection.module_size,
                "module_size_hex": format_hex(import_collection.module_size),
                "import_count": imports.len(),
                "xref_count": xref_count,
                "unavailable_ranges": build_unavailable_ranges_json(&import_collection.unavailable_ranges),
                "imports": imports
            })
        }
        Err(error) => json!
        ({
            "schema_version": PROCESS_TRIAGE_SCHEMA_VERSION,
            "status": "incomplete",
            "scope":

          {
                "imports": "standard_pe_import_directory",
                "xrefs": ["direct_x64_rip_relative_iat_call", "direct_x64_rip_relative_iat_jump"]
            },
            "error": build_import_error_json(error)
        }),
    }
}


/// Builds the validated PEB and main-image relationship JSON.
/// `collection`: process collection containing PEB and image identities.
///
/// Returns one validated PEB object.
fn build_peb_json(collection: &ProcessTriageCollection) -> Value
{
    let process = &collection.validated_process;

    json!
    ({
        "schema_version": PROCESS_TRIAGE_SCHEMA_VERSION,
        "status": "validated",
        "process_id": process.process_id,
        "process_id_hex": format!("0x{:X}", process.process_id),
        "peb_address": process.peb_address,
        "peb_address_hex": format_hex(process.peb_address),
        "being_debugged": process.being_debugged,
        "main_image_base_address": process.image.base_address,
        "main_image_base_address_hex": format_hex(process.image.base_address),
        "main_image_path": process.image_path.display().to_string()
    })
}


/// Builds process TEB collection, trust checks, and per-thread failure JSON.
/// `collection`: process collection containing TEB results or enumeration failure.
///
/// Returns one collected, partial, or failed TEB result.
fn build_tebs_json(collection: &ProcessTriageCollection) -> Value
{
    match &collection.tebs
    {
        Ok(teb_collection) =>
        {
            let tebs = teb_collection.tebs.iter().map(|teb| build_teb_json(teb, collection.validated_process.peb_address)).collect::<Vec<Value>>();
            let failures = teb_collection
                .failures
                .iter()
                .map(|failure| {
                    json!
                    ({
                        "thread_id": failure.thread_id,
                        "thread_id_hex": format!("0x{:X}", failure.thread_id),
                        "error": build_thread_teb_error_json(&failure.error)
                    })
                })
                .collect::<Vec<Value>>();

            json!
            ({
                "schema_version": PROCESS_TRIAGE_SCHEMA_VERSION,
                "status": if failures.is_empty() { "collected" } else { "partial" },
                "process_id": teb_collection.process_id,
                "process_id_hex": format!("0x{:X}", teb_collection.process_id),
                "teb_count": tebs.len(),
                "failure_count": failures.len(),
                "tebs": tebs,
                "failures": failures
            })
        }
        Err(error) => json!
        ({
            "schema_version": PROCESS_TRIAGE_SCHEMA_VERSION,
            "status": "failed",
            "teb_count": 0,
            "failure_count": 1,
            "tebs": [],
            "error": build_process_teb_error_json(error)
        }),
    }
}


/// Builds all saved fields and trust decisions for one TEB.
/// `teb`: collected x64 TEB header and native thread metadata.
/// `expected_peb_address`: centrally validated process PEB address.
///
/// Returns one complete TEB JSON object.
fn build_teb_json(teb: &ThreadTebInfo, expected_peb_address: usize) -> Value
{
    let peb_pointer_matches = teb.process_environment_block == expected_peb_address;
    let identity_matches = teb.self_pointer_matches && teb.client_process_id_matches && teb.client_thread_id_matches && peb_pointer_matches;

    json!
    ({
        "teb_address": teb.teb_address,
        "teb_address_hex": format_hex(teb.teb_address),
        "thread":

      {
            "thread_id": teb.thread_id,
            "thread_id_hex": format!("0x{:X}", teb.thread_id),
            "exit_status": teb.exit_status,
            "exit_status_hex": format!("0x{:08X}", teb.exit_status as u32),
            "affinity_mask": teb.affinity_mask,
            "affinity_mask_hex": format_hex(teb.affinity_mask),
            "priority": teb.priority,
            "base_priority": teb.base_priority
        },
        "nt_tib":

      {
            "exception_list": teb.exception_list,
            "exception_list_hex": format_hex(teb.exception_list),
            "stack_base": teb.stack_base,
            "stack_base_hex": format_hex(teb.stack_base),
            "stack_limit": teb.stack_limit,
            "stack_limit_hex": format_hex(teb.stack_limit),
            "stack_size_bytes": teb.stack_size_bytes,
            "stack_size_hex": format_optional_hex(teb.stack_size_bytes),
            "subsystem_tib": teb.subsystem_tib,
            "subsystem_tib_hex": format_hex(teb.subsystem_tib),
            "fiber_data_or_version": teb.fiber_data_or_version,
            "fiber_data_or_version_hex": format_hex(teb.fiber_data_or_version),
            "arbitrary_user_pointer": teb.arbitrary_user_pointer,
            "arbitrary_user_pointer_hex": format_hex(teb.arbitrary_user_pointer),
            "self_address": teb.self_address,
            "self_address_hex": format_hex(teb.self_address)
        },
        "environment":

      {
            "environment_pointer": teb.environment_pointer,
            "environment_pointer_hex": format_hex(teb.environment_pointer),
            "client_process_id": teb.client_process_id,
            "client_process_id_hex": format_hex(teb.client_process_id),
            "client_thread_id": teb.client_thread_id,
            "client_thread_id_hex": format_hex(teb.client_thread_id),
            "active_rpc_handle": teb.active_rpc_handle,
            "active_rpc_handle_hex": format_hex(teb.active_rpc_handle),
            "thread_local_storage_pointer": teb.thread_local_storage_pointer,
            "thread_local_storage_pointer_hex": format_hex(teb.thread_local_storage_pointer),
            "process_environment_block": teb.process_environment_block,
            "process_environment_block_hex": format_hex(teb.process_environment_block)
        },
        "trust":

      {
            "self_pointer_matches": teb.self_pointer_matches,
            "client_process_id_matches": teb.client_process_id_matches,
            "client_thread_id_matches": teb.client_thread_id_matches,
            "process_environment_block_matches": peb_pointer_matches,
            "identity_matches": identity_matches
        }
    })
}


/// Builds JSON for mapped-image ranges unavailable after valid loader discards.
/// `ranges`: unavailable RVA and size pairs to retain.
///
/// Returns the ordered JSON range array.
fn build_unavailable_ranges_json(ranges: &[UnavailablePeRange]) -> Vec<Value>
{
    ranges
        .iter()
        .map(|range| {
            json!
            ({
                "rva": range.rva,
                "rva_hex": format_hex(range.rva),
                "size": range.size,
                "size_hex": format_hex(range.size)
            })
        })
        .collect()
}


/// Builds a stable structured PDB collector error.
/// `error`: original PDB collection error.
///
/// Returns a typed JSON error with the unavailable range retained.
fn build_pdb_error_json(error: &PdbInfoCollectionError) -> Value
{
    match error
    {
        PdbInfoCollectionError::IncompleteMainModuleSnapshot {
            rva,
            size,
        } => json!
        ({
            "type": "PdbInfoCollectionError",
            "kind": "incomplete_main_module_snapshot",
            "fields":

          {
                "rva": rva,
                "rva_hex": format_hex(*rva),
                "size": size,
                "size_hex": format_hex(*size)
            }
        }),
    }
}


/// Builds a stable structured import collector error.
/// `error`: original import collection error.
///
/// Returns a typed JSON error with the unavailable range retained.
fn build_import_error_json(error: &ProcessImportCollectionError) -> Value
{
    match error
    {
        ProcessImportCollectionError::IncompleteMainModuleSnapshot {
            rva,
            size,
        } => json!
        ({
            "type": "ProcessImportCollectionError",
            "kind": "incomplete_main_module_snapshot",
            "fields":

          {
                "rva": rva,
                "rva_hex": format_hex(*rva),
                "size": size,
                "size_hex": format_hex(*size)
            }
        }),
    }
}


/// Builds a stable structured process-wide TEB collector error.
/// `error`: original process TEB collection error.
///
/// Returns a typed JSON error with Win32 status fields retained.
fn build_process_teb_error_json(error: &ProcessTebCollectionError) -> Value
{
    match error
    {
        ProcessTebCollectionError::InvalidProcessHandle => simple_error_json("ProcessTebCollectionError", "invalid_process_handle"),
        ProcessTebCollectionError::ProcessIdUnavailable {
            error,
        } => win32_error_json("ProcessTebCollectionError", "process_id_unavailable", *error),
        ProcessTebCollectionError::ThreadSnapshotFailed {
            error,
        } => win32_error_json("ProcessTebCollectionError", "thread_snapshot_failed", *error),
        ProcessTebCollectionError::ThreadSnapshotHandleFailed(cause) => json!
        ({
            "type": "ProcessTebCollectionError",
            "kind": "thread_snapshot_handle_failed",
            "cause": build_handle_guard_error_json(cause)
        }),
        ProcessTebCollectionError::ThreadSnapshotIterationFailed {
            error,
        } => win32_error_json("ProcessTebCollectionError", "thread_snapshot_iteration_failed", *error),
    }
}


/// Builds a stable structured thread-scoped TEB collector error.
/// `error`: original thread TEB collection error.
///
/// Returns a typed JSON error with native identifiers and read details retained.
fn build_thread_teb_error_json(error: &ThreadTebCollectionError) -> Value
{
    match error
    {
        ThreadTebCollectionError::ThreadOpenFailed(cause) => json!
        ({
            "type": "ThreadTebCollectionError",
            "kind": "thread_open_failed",
            "cause": build_handle_guard_error_json(cause)
        }),
        ThreadTebCollectionError::ThreadInformationQueryFailed {
            status,
            return_length,
        } => json!
        ({
            "type": "ThreadTebCollectionError",
            "kind": "thread_information_query_failed",
            "fields":

          {
                "status": status,
                "status_hex": format!("0x{:08X}", *status as u32),
                "return_length": return_length,
                "return_length_hex": format!("0x{:X}", return_length)
            }
        }),
        ThreadTebCollectionError::ThreadInformationTooSmall {
            return_length,
        } => json!
        ({
            "type": "ThreadTebCollectionError",
            "kind": "thread_information_too_small",
            "fields":

          {
                "return_length": return_length,
                "return_length_hex": format!("0x{:X}", return_length)
            }
        }),
        ThreadTebCollectionError::ThreadIdentityMismatch {
            expected_process_id,
            actual_process_id,
            expected_thread_id,
            actual_thread_id,
        } => json!
        ({
            "type": "ThreadTebCollectionError",
            "kind": "thread_identity_mismatch",
            "fields":

          {
                "expected_process_id": expected_process_id,
                "actual_process_id": actual_process_id,
                "expected_thread_id": expected_thread_id,
                "actual_thread_id": actual_thread_id
            }
        }),
        ThreadTebCollectionError::TebAddressUnavailable => simple_error_json("ThreadTebCollectionError", "teb_address_unavailable"),
        ThreadTebCollectionError::TebReadFailed(cause) => json!
        ({
            "type": "ThreadTebCollectionError",
            "kind": "teb_read_failed",
            "cause": build_memory_read_error_json(cause)
        }),
        ThreadTebCollectionError::TebReadIncomplete {
            bytes_requested,
            bytes_read,
        } => json!
        ({
            "type": "ThreadTebCollectionError",
            "kind": "teb_read_incomplete",
            "fields":

          {
                "bytes_requested": bytes_requested,
                "bytes_read": bytes_read
            }
        }),
    }
}


/// Builds a stable structured owned-handle validation error.
/// `error`: original handle open, query, or access failure.
///
/// Returns a typed JSON error retaining identifiers, access masks, and native status.
fn build_handle_guard_error_json(error: &HandleGuardError) -> Value
{
    match error
    {
        HandleGuardError::InvalidHandle => simple_error_json("HandleGuardError", "invalid_handle"),
        HandleGuardError::OpenProcessFailed {process_id, requested_access, error} => json!
        ({
            "type": "HandleGuardError",
            "kind": "open_process_failed",
            "fields":

          {
                "process_id": process_id,
                "requested_access": requested_access,
                "requested_access_hex": format!("0x{:08X}", requested_access),
                "error": error,
                "error_hex": format!("0x{:08X}", error)
            }
        }),
        HandleGuardError::NtOpenThreadFailed {process_id, thread_id, requested_access, status} => json!
        ({
            "type": "HandleGuardError",
            "kind": "nt_open_thread_failed",
            "fields":

          {
                "process_id": process_id,
                "thread_id": thread_id,
                "requested_access": requested_access,
                "requested_access_hex": format!("0x{:08X}", requested_access),
                "status": status,
                "status_hex": format!("0x{:08X}", *status as u32)
            }
        }),
        HandleGuardError::AccessQueryFailed {status, return_length} => json!
        ({
            "type": "HandleGuardError",
            "kind": "access_query_failed",
            "fields":

          {
                "status": status,
                "status_hex": format!("0x{:08X}", *status as u32),
                "return_length": return_length,
                "return_length_hex": format!("0x{:X}", return_length)
            }
        }),
        HandleGuardError::InsufficientAccess {granted_access, required_access} => json!
        ({
            "type": "HandleGuardError",
            "kind": "insufficient_access",
            "fields":

          {
                "granted_access": granted_access,
                "granted_access_hex": format!("0x{:08X}", granted_access),
                "required_access": required_access,
                "required_access_hex": format!("0x{:08X}", required_access)
            }
        }),
    }
}


/// Builds a stable structured process-memory read error.
/// `error`: original memory read error.
///
/// Returns a typed JSON error retaining range and native status fields.
fn build_memory_read_error_json(error: &ProcessMemoryReadError) -> Value
{
    match error
    {
        ProcessMemoryReadError::InvalidProcessHandle => simple_error_json("ProcessMemoryReadError", "invalid_process_handle"),
        ProcessMemoryReadError::NullBaseAddress => simple_error_json("ProcessMemoryReadError", "null_base_address"),
        ProcessMemoryReadError::ZeroBytesRequested => simple_error_json("ProcessMemoryReadError", "zero_bytes_requested"),
        ProcessMemoryReadError::AddressRangeOverflow {
            starting_address,
            bytes_requested,
        } => json!
        ({
            "type": "ProcessMemoryReadError",
            "kind": "address_range_overflow",
            "fields":

          {
                "starting_address": starting_address,
                "starting_address_hex": format_hex(*starting_address),
                "bytes_requested": bytes_requested
            }
        }),
        ProcessMemoryReadError::BufferAllocationFailed {
            bytes_requested,
        } => json!
        ({
            "type": "ProcessMemoryReadError",
            "kind": "buffer_allocation_failed",
            "fields": { "bytes_requested": bytes_requested }
        }),
        ProcessMemoryReadError::BytesReadExceededRequest {
            bytes_requested,
            bytes_read,
        } => json!
        ({
            "type": "ProcessMemoryReadError",
            "kind": "bytes_read_exceeded_request",
            "fields":

          {
                "bytes_requested": bytes_requested,
                "bytes_read": bytes_read
            }
        }),
        ProcessMemoryReadError::ReadFailed {
            status,
            bytes_read,
        } => json!
        ({
            "type": "ProcessMemoryReadError",
            "kind": "read_failed",
            "fields":

          {
                "status": status,
                "status_hex": format!("0x{:08X}", *status as u32),
                "bytes_read": bytes_read
            }
        }),
        ProcessMemoryReadError::ReadIncomplete {
            bytes_requested,
            bytes_read,
        } => json!
        ({
            "type": "ProcessMemoryReadError",
            "kind": "read_incomplete",
            "fields":

          {
                "bytes_requested": bytes_requested,
                "bytes_read": bytes_read
            }
        }),
    }
}


/// Builds a typed fieldless error JSON object.
/// `error_type`: Rust error type label.
/// `kind`: stable snake-case variant label.
///
/// Returns one minimal structured error.
fn simple_error_json(error_type: &str, kind: &str) -> Value
{
    json!
    ({
        "type": error_type,
        "kind": kind
    })
}


/// Builds a typed error JSON object containing one Win32 error value.
/// `error_type`: Rust error type label.
/// `kind`: stable snake-case variant label.
/// `error`: original Win32 error code.
///
/// Returns one structured Win32 error.
fn win32_error_json(error_type: &str, kind: &str, error: u32) -> Value
{
    json!
    ({
        "type": error_type,
        "kind": kind,
        "fields":

      {
            "error": error,
            "error_hex": format!("0x{:08X}", error)
        }
    })
}


/// Returns the stable JSON label for one supported CodeView format.
/// `format`: parsed PDB CodeView record format.
///
/// Returns the lowercase format label.
fn pdb_format_name(format: PdbCodeViewFormat) -> &'static str
{
    match format
    {
        PdbCodeViewFormat::Rsds => "rsds",
        PdbCodeViewFormat::Nb10 => "nb10",
    }
}


/// Returns the stable JSON label for one direct IAT reference form.
/// `kind`: collected call or jump classification.
///
/// Returns the lowercase instruction kind.
fn iat_xref_kind_name(kind: PeIatXrefKind) -> &'static str
{
    match kind
    {
        PeIatXrefKind::Call => "call",
        PeIatXrefKind::Jump => "jump",
    }
}


/// Formats one pointer-sized value as uppercase hexadecimal.
/// `value`: numeric address, RVA, offset, or size.
///
/// Returns a `0x`-prefixed hexadecimal string.
fn format_hex(value: usize) -> String
{
    format!("0x{:X}", value)
}


/// Formats one optional pointer-sized value as uppercase hexadecimal.
/// `value`: optional address or file offset.
///
/// Returns the formatted value or `None` when absent.
fn format_optional_hex(value: Option<usize>) -> Option<String>
{
    value.map(format_hex)
}
