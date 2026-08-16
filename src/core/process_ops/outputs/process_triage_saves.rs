use std::fs;
use std::io;
use std::path::Path;

use serde_json::{json, Value};
use windows_sys::Win32::System::Diagnostics::Debug::{IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE};

use crate::core::global_utils::fileutils::write_json_file;
use crate::core::process_ops::outputs::config::{prepare_process_dump_layout, ProcessDumpLayout, CODE_SECTION_FILE_NAME, IMAGE_FILE_NAME, IMPORTS_FILE_NAME, OPCODE_HITS64_FILE_NAME, PATTERN_HITS64_FILE_NAME, PDB_FILE_NAME, PEB_FILE_NAME, PROCESS_TRIAGE_SCHEMA_VERSION, SECTIONS_FILE_NAME, STRINGS_FILE_NAME, TEBS_FILE_NAME};
use crate::core::process_ops::process_processing::{ProcessPatternHit, ProcessTriageCollection, TebStackScan, TebStackScanStatus};
use crate::core::process_ops::utils::detect_code_section_utils::{CodeSectionConfidence, CodeSectionLocation, RuntimeFunctionEvidence};
use crate::core::process_ops::utils::foundation::validate_pe::UnavailablePeRange;
use crate::core::process_ops::utils::importutils::{PeIatXrefKind, ProcessImportCollectionError};
use crate::core::process_ops::utils::memutils::{MemoryRegionQueryError, ProcessMemoryReadError};
use crate::core::process_ops::utils::pdbutils::{PdbCodeViewFormat, PdbInfoCollectionError};
use crate::core::process_ops::utils::pe_utils::{ProcessOpcodeBackingStatus, ProcessOpcodeEvidence, ProcessOpcodeRelocationStatus};
use crate::core::process_ops::utils::stringdumputils::{TebStackRegionReadError, TebStackStringCollectionError};
use crate::core::process_ops::utils::strings::StringEncoding;
use crate::core::process_ops::utils::tebutils::{ProcessTebCollectionError, ThreadTebCollectionError, ThreadTebInfo};

/// Previous standalone entry-signature output replaced by the combined pattern file.
const LEGACY_ENTRY_SIGNATURE_FILE_NAME: &str = "entry_signature.json";

/// Previous opcode output name replaced by the architecture-qualified file.
const LEGACY_OPCODE_HITS_FILE_NAME: &str = "opcode_hits.json";

/// Saves every completed process-triage collector result into its configured JSON location.
/// `collection`: the single validated process collection accumulated before persistence.
///
/// Returns the process dump layout after every JSON file is written, or the first hash,
/// directory, serialization, or file-write failure.
pub fn save_process_triage(collection: &ProcessTriageCollection) -> io::Result<ProcessDumpLayout>
{
    let process = &collection.validated_process;
    let sha256 = collection.output_identity_sha256.to_string();
    let layout = prepare_process_dump_layout(&process.image_path, &sha256)?;

    remove_legacy_pattern_files(&layout.patterns)?;

    write_json_file(&layout.pe, IMAGE_FILE_NAME, &build_image_json(collection, &sha256))?;
    write_json_file(&layout.pe, SECTIONS_FILE_NAME, &build_sections_json(collection))?;
    write_json_file(&layout.pe, PDB_FILE_NAME, &build_pdb_json(collection))?;
    write_json_file(&layout.imports, IMPORTS_FILE_NAME, &build_imports_json(collection))?;
    write_json_file(&layout.peb, PEB_FILE_NAME, &build_peb_json(collection))?;
    write_json_file(&layout.peb, TEBS_FILE_NAME, &build_tebs_json(collection))?;
    write_json_file(&layout.patterns, CODE_SECTION_FILE_NAME, &build_code_section_json(collection))?;
    write_json_file(&layout.patterns, PATTERN_HITS64_FILE_NAME, &build_pattern_hits64_json(collection))?;
    write_json_file(&layout.patterns, OPCODE_HITS64_FILE_NAME, &build_opcode_hits64_json(collection))?;
    write_json_file(&layout.root, STRINGS_FILE_NAME, &build_strings_json(collection))?;

    Ok(layout)
}


/// Removes exact obsolete process-pattern outputs from a reused dump directory.
/// `pattern_directory`: the prepared Patterns directory owned by the current dump.
///
/// Returns unit when both files are absent or removed, or the first removal error.
fn remove_legacy_pattern_files(pattern_directory: &Path) -> io::Result<()>
{
    for file_name in [LEGACY_ENTRY_SIGNATURE_FILE_NAME, LEGACY_OPCODE_HITS_FILE_NAME]
    {
        let path = pattern_directory.join(file_name);

        match fs::remove_file(path)
        {
            Ok(()) =>
            {}
            Err(error) if error.kind() == io::ErrorKind::NotFound =>
            {}
            Err(error) => return Err(error),
        }
    }

    Ok(())
}


/// Builds validated target identity, image metadata, and snapshot-completeness JSON.
/// `collection`: the process collection containing central validation and image facts.
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
/// `collection`: the process collection containing validated section records.
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


/// Builds evidence-bearing code-section detection JSON.
/// `collection`: the process collection containing the optional code-section analysis.
///
/// Returns detected, absent, or inconclusive selection state without hiding partial image reads.
fn build_code_section_json(collection: &ProcessTriageCollection) -> Value
{
    let image_complete = collection.unavailable_image_ranges.is_empty();
    let status = match (&collection.code_section, image_complete)
    {
        (Some(_), true) => "detected",
        (Some(_), false) => "detected_partial_image",
        (None, true) => "not_detected",
        (None, false) => "inconclusive",
    };
    let analysis = collection.code_section.as_ref().map(|code| {
        json!
        ({
            "confidence": code_section_confidence_name(code.analysis.confidence),
            "candidate_count": code.analysis.candidate_count,
            "image_complete": code.analysis.image_complete,
            "section_ranges_valid": code.analysis.section_ranges_valid,
            "section_layout_valid": code.analysis.section_layout_valid,
            "overlapping_sections": code.analysis.overlapping_sections,
            "runtime_function_evidence": runtime_function_evidence_name(code.analysis.runtime_function_evidence),
            "primary": build_code_section_location_json(&code.analysis.primary, collection.validated_process.image.base_address, code.primary_file_offset),
            "entry_point_section": code.analysis.entry_point.as_ref().map(|section| build_code_section_location_json(section, collection.validated_process.image.base_address, code.entry_section_file_offset))
        })
    });

    json!
    ({
        "schema_version": PROCESS_TRIAGE_SCHEMA_VERSION,
        "status": status,
        "scope": "mapped_main_image_sections",
        "evidence": "pe_structure_and_x64_runtime_functions",
        "analysis": analysis,
        "unavailable_ranges": build_unavailable_ranges_json(&collection.unavailable_image_ranges)
    })
}


/// Builds combined x64 analyst-pattern JSON with the CRT entry hit distinguished.
/// `collection`: the process collection containing every patterns64 match.
///
/// Returns all mapped-image pattern hits and explicit entry-signature scan state.
fn build_pattern_hits64_json(collection: &ProcessTriageCollection) -> Value
{
    let entry_status = match (&collection.entry_signature, collection.pattern_scan_complete)
    {
        (Some(_), true) => "found",
        (Some(_), false) => "found_partial_scan",
        (None, true) => "not_found",
        (None, false) => "inconclusive",
    };
    let build_hit = |value: &ProcessPatternHit| {
        let section_index = collection.sections.iter().position(|section| {
            let section_end = section.rva.saturating_add(section.mapped_size);

            value.rva >= section.rva && value.rva < section_end
        });
        let section_name = section_index.and_then(|index| collection.sections.get(index)).map(|section| section.name.as_ref());

        json!
        ({
            "name": value.name,
            "section_index": section_index,
            "section_name": section_name,
            "rva": value.rva,
            "rva_hex": format_hex(value.rva),
            "address": value.address,
            "address_hex": format_optional_hex(value.address),
            "file_offset": value.file_offset,
            "file_offset_hex": format_optional_hex(value.file_offset)
        })
    };
    let entry_hit = collection.entry_signature.as_ref().map(&build_hit);
    let hits = collection.pattern_hits.iter().map(build_hit).collect::<Vec<Value>>();

    json!
    ({
        "schema_version": PROCESS_TRIAGE_SCHEMA_VERSION,
        "status": if collection.pattern_scan_complete { "collected" } else { "partial" },
        "scope": "mapped_main_image_executable_sections",
        "catalog": "x64_analyst_signatures",
        "evidence": "raw_exact_and_wildcard_byte_matches",
        "scan_complete": collection.pattern_scan_complete,
        "entry_signature":

      {
            "status": entry_status,
            "hit": entry_hit
        },
        "hit_count": hits.len(),
        "unavailable_ranges": build_unavailable_ranges_json(&collection.unavailable_image_ranges),
        "hits": hits
    })
}


/// Builds classified opcode evidence and every raw opcode occurrence as JSON.
/// `collection`: process collection containing decoded hits and aggregate raw evidence.
///
/// Returns one complete or partial opcode result with every retained match location.
fn build_opcode_hits64_json(collection: &ProcessTriageCollection) -> Value
{
    let opcode_collection = &collection.opcode_hits;
    let semantic_scan_complete = opcode_collection.scan_complete && opcode_collection.backing_status == ProcessOpcodeBackingStatus::Matched && matches!(opcode_collection.relocation_status, ProcessOpcodeRelocationStatus::NotRequired | ProcessOpcodeRelocationStatus::Validated) && opcode_collection.runtime_function_seed_reason.is_none() && opcode_collection.decoded_seed_count != 0 && opcode_collection.decoded_instruction_count != 0 && opcode_collection.current_decoded_instruction_count != 0 && opcode_collection.decode_error_count == 0 && !opcode_collection.decode_limit_reached && !opcode_collection.hits_truncated;
    let output_complete = semantic_scan_complete && !opcode_collection.raw_matches_truncated;
    let decoded_static_instruction_count = opcode_collection.raw_summaries.iter().fold(0usize, |total, summary| total.saturating_add(summary.decoded_static_instruction_count));
    let mapped_trap_difference_count = opcode_collection.raw_summaries.iter().fold(0usize, |total, summary| total.saturating_add(summary.mapped_trap_difference_count));
    let hits = opcode_collection
        .hits
        .iter()
        .map(|hit| {
            let section_name = collection.sections.get(hit.section_index).map(|section| section.name.as_ref());
            let opcode_hex = format_byte_slice_hex(hit.bytecode);
            let process_instruction_hex = format_byte_slice_hex(&hit.process_bytes);
            let backing_instruction_hex = format_byte_slice_hex(&hit.backing_instruction_bytes);

            json!
            ({
                "evidence_class": process_opcode_evidence_name(hit.evidence),
                "confidence": "high",
                "name": hit.name,
                "opcode_bytes": hit.bytecode,
                "opcode_hex": opcode_hex,
                "requires_modrm": hit.requires_modrm,
                "modrm": hit.modrm,
                "modrm_hex": hit.modrm.map(|value| format!("0x{:02X}", value)),
                "matched_length": hit.bytecode.len() + usize::from(hit.requires_modrm),
                "opcode_offset_in_instruction": hit.opcode_offset,
                "instruction_length": hit.process_bytes.len(),
                "instruction_start_source": "backing_and_current_recursive_decode_start_intersection",
                "process_instruction_bytes": hit.process_bytes,
                "process_instruction_hex": process_instruction_hex,
                "backing_file_matches": hit.evidence == ProcessOpcodeEvidence::DecodedStaticInstruction,
                "backing_instruction":

              {
                    "mnemonic": hit.backing_instruction_mnemonic,
                    "bytes": hit.backing_instruction_bytes,
                    "hex": backing_instruction_hex,
                    "length": hit.backing_instruction_bytes.len()
                },
                "attribution": if hit.evidence == ProcessOpcodeEvidence::MappedTrapDifference { Some("unknown") } else { None },
                "section_index": hit.section_index,
                "section_name": section_name,
                "rva": hit.rva,
                "rva_hex": format_hex(hit.rva),
                "address": hit.address,
                "address_hex": format_optional_hex(hit.address),
                "file_offset": hit.file_offset,
                "file_offset_hex": format_optional_hex(hit.file_offset),
                "instruction_rva": hit.instruction_rva,
                "instruction_rva_hex": format_hex(hit.instruction_rva),
                "instruction_address": hit.instruction_address,
                "instruction_address_hex": format_optional_hex(hit.instruction_address),
                "instruction_file_offset": hit.instruction_file_offset,
                "instruction_file_offset_hex": format_optional_hex(hit.instruction_file_offset)
            })
        })
        .collect::<Vec<Value>>();
    let raw_matches = opcode_collection
        .raw_matches
        .iter()
        .map(|hit| {
            let section_name = collection.sections.get(hit.section_index).map(|section| section.name.as_ref());

            json!
            ({
                "name": hit.name,
                "opcode_bytes": hit.bytecode,
                "opcode_hex": format_byte_slice_hex(hit.bytecode),
                "requires_modrm": hit.requires_modrm,
                "modrm": hit.modrm,
                "modrm_hex": hit.modrm.map(|value| format!("0x{:02X}", value)),
                "matched_length": hit.bytecode.len() + usize::from(hit.requires_modrm),
                "section_index": hit.section_index,
                "section_name": section_name,
                "rva": hit.rva,
                "rva_hex": format_hex(hit.rva),
                "address": hit.address,
                "address_hex": format_optional_hex(hit.address),
                "file_offset": hit.file_offset,
                "file_offset_hex": format_optional_hex(hit.file_offset)
            })
        })
        .collect::<Vec<Value>>();
    let raw_summaries = opcode_collection
        .raw_summaries
        .iter()
        .map(|summary| {
            let decoded_count = summary.decoded_static_instruction_count;
            let mapped_trap_difference_count = summary.mapped_trap_difference_count;
            let padding_candidate_count = if summary.bytecode == [0xCC] { opcode_collection.padding_candidate_byte_count } else { 0 };
            let classified_count = decoded_count.saturating_add(mapped_trap_difference_count).saturating_add(padding_candidate_count);

            json!
            ({
                "name": summary.name,
                "opcode_bytes": summary.bytecode,
                "opcode_hex": format_byte_slice_hex(summary.bytecode),
                "requires_modrm": summary.requires_modrm,
                "match_count": summary.match_count,
                "decoded_static_instruction_count": decoded_count,
                "mapped_trap_difference_count": mapped_trap_difference_count,
                "padding_candidate_count": padding_candidate_count,
                "unclassified_count": summary.match_count.saturating_sub(classified_count)
            })
        })
        .collect::<Vec<Value>>();
    let padding_samples = opcode_collection
        .padding_samples
        .iter()
        .map(|sample| {
            let section_name = collection.sections.get(sample.section_index).map(|section| section.name.as_ref());

            json!
            ({
                "byte": 0xCC,
                "byte_hex": "CC",
                "run_length": sample.length,
                "reason": "unchanged_consecutive_cc_outside_decoded_control_flow",
                "confidence": "low",
                "backing_file_matches": true,
                "section_index": sample.section_index,
                "section_name": section_name,
                "rva": sample.rva,
                "rva_hex": format_hex(sample.rva),
                "address": sample.address,
                "address_hex": format_optional_hex(sample.address),
                "file_offset": sample.file_offset,
                "file_offset_hex": format_optional_hex(sample.file_offset)
            })
        })
        .collect::<Vec<Value>>();

    json!
    ({
        "schema_version": PROCESS_TRIAGE_SCHEMA_VERSION,
        "status": if output_complete { "collected" } else { "partial" },
        "scope": "mapped_main_image_executable_sections",
        "catalog": "x64_breakpoint_opcode_bytecodes",
        "evidence": "decoded_static_instructions_mapped_trap_differences_and_aggregated_raw_matches",
        "module_base_address": opcode_collection.module_base_address,
        "module_base_address_hex": format_hex(opcode_collection.module_base_address),
        "module_size": opcode_collection.module_size,
        "module_size_hex": format_hex(opcode_collection.module_size),
        "scan_complete": opcode_collection.scan_complete,
        "semantic_scan_complete": semantic_scan_complete,
        "output_complete": output_complete,
        "backing_file_comparison":

      {
            "status": process_opcode_backing_status_name(opcode_collection.backing_status),
            "reason": opcode_collection.backing_reason,
            "disk_path_sha256": collection.backing_file_sha256,
            "baseline_sha256": if opcode_collection.backing_status == ProcessOpcodeBackingStatus::Matched { collection.backing_file_sha256.as_deref() } else { None },
            "identity_basis": "semantic_pe_headers_and_section_table",
            "file_object_identity_verified": false,
            "mapped_trap_difference_detection_enabled": opcode_collection.mapped_trap_difference_detection_enabled
        },
        "base_relocations":

      {
            "status": process_opcode_relocation_status_name(opcode_collection.relocation_status),
            "reason": opcode_collection.relocation_reason
        },
        "decode":

      {
            "architecture": "x86_64",
            "strategy": "trusted_seed_recursive_descent",
            "runtime_function_seed_count": opcode_collection.runtime_function_seed_count,
            "runtime_function_seed_status": if opcode_collection.backing_status != ProcessOpcodeBackingStatus::Matched { "not_evaluated" } else if opcode_collection.runtime_function_seed_reason.is_some() { "rejected" } else if !opcode_collection.runtime_function_seed_metadata_present { "absent" } else { "validated_against_backing_file" },
            "runtime_function_seed_reason": opcode_collection.runtime_function_seed_reason,
            "seed_count": opcode_collection.decoded_seed_count,
            "backing_instruction_count": opcode_collection.decoded_instruction_count,
            "current_instruction_count": opcode_collection.current_decoded_instruction_count,
            "instruction_count": opcode_collection.decoded_instruction_count,
            "byte_count": opcode_collection.decoded_byte_count,
            "error_count": opcode_collection.decode_error_count,
            "limit_reached": opcode_collection.decode_limit_reached
        },
        "hit_count": opcode_collection.hit_count,
        "retained_hit_count": hits.len(),
        "hits_truncated": opcode_collection.hits_truncated,
        "hit_counts":

      {
            "decoded_static_instruction": decoded_static_instruction_count,
            "mapped_trap_difference": mapped_trap_difference_count
        },
        "raw_match_count": opcode_collection.raw_match_count,
        "retained_raw_match_count": raw_matches.len(),
        "raw_matches_truncated": opcode_collection.raw_matches_truncated,
        "raw_byte_match_summary":

      {
            "match_count": opcode_collection.raw_match_count,
            "by_opcode": raw_summaries
        },
        "raw_matches": raw_matches,
        "padding_candidates":

      {
            "run_count": opcode_collection.padding_candidate_run_count,
            "byte_count": opcode_collection.padding_candidate_byte_count,
            "retained_sample_count": padding_samples.len(),
            "samples_truncated": opcode_collection.padding_candidate_run_count > padding_samples.len(),
            "sample_runs": padding_samples
        },
        "unavailable_ranges": build_unavailable_ranges_json(&opcode_collection.unavailable_ranges),
        "hits": hits
    })
}


/// Builds CodeView PDB metadata and tri-state collection status JSON.
/// `collection`: the process collection containing PDB metadata, absence, or failure.
///
/// Returns one PDB object that distinguishes not present, incomplete, and failed collection.
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
            "status": if matches!(error, PdbInfoCollectionError::IncompleteMainModuleSnapshot { .. }) { "incomplete" } else { "failed" },
            "error": build_pdb_error_json(error)
        }),
    }
}


/// Builds standard import-table and direct IAT-xref JSON.
/// `collection`: the process collection containing imports or a typed collection failure.
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
            "status": if matches!(error, ProcessImportCollectionError::IncompleteMainModuleSnapshot { .. }) { "incomplete" } else { "failed" },
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
/// `collection`: the process collection containing PEB and image identities.
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
/// `collection`: the process collection containing TEB results or enumeration failure.
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


/// Builds all main-module and TEB-stack string collection JSON.
/// `collection`: the process collection containing both string sources and their failures.
///
/// Returns one root-level strings document with independent source status.
fn build_strings_json(collection: &ProcessTriageCollection) -> Value
{
    let main_strings = collection
        .main_module_strings
        .strings
        .iter()
        .map(|value| {
            json!
            ({
                "value": value.value.as_ref(),
                "encoding": string_encoding_name(value.encoding),
                "address": value.address,
                "address_hex": format_hex(value.address),
                "rva": value.rva,
                "rva_hex": format_hex(value.rva),
                "file_offset": value.file_offset,
                "file_offset_hex": format_optional_hex(value.file_offset)
            })
        })
        .collect::<Vec<Value>>();
    let stack_scans = collection.teb_stack_scans.iter().map(build_teb_stack_scan_json).collect::<Vec<Value>>();
    let stack_string_count = collection
        .teb_stack_scans
        .iter()
        .map(|scan| match &scan.status
        {
            TebStackScanStatus::Collected(value) => value.strings.len(),
            _ => 0,
        })
        .sum::<usize>();
    let stack_status = teb_stack_collection_status(collection);
    let overall_status = if collection.main_module_strings.unavailable_ranges.is_empty() && stack_status == "collected" { "collected" } else { "partial" };

    json!
    ({
        "schema_version": PROCESS_TRIAGE_SCHEMA_VERSION,
        "status": overall_status,
        "minimum_characters": collection.minimum_string_characters,
        "total_string_count": main_strings.len() + stack_string_count,
        "main_module":

      {
            "status": if collection.main_module_strings.unavailable_ranges.is_empty() { "collected" } else { "partial" },
            "module_base_address": collection.main_module_strings.module_base_address,
            "module_base_address_hex": format_hex(collection.main_module_strings.module_base_address),
            "module_size": collection.main_module_strings.module_size,
            "module_size_hex": format_hex(collection.main_module_strings.module_size),
            "string_count": main_strings.len(),
            "unavailable_ranges": build_unavailable_ranges_json(&collection.main_module_strings.unavailable_ranges),
            "strings": main_strings
        },
        "teb_stacks":

      {
            "status": stack_status,
            "scan_count": stack_scans.len(),
            "string_count": stack_string_count,
            "scans": stack_scans
        }
    })
}


/// Builds one detected code-section location with mapped and raw-file positions.
/// `section`: the evidence-bearing section record.
/// `image_base`: the validated mapped main-image base.
/// `file_offset`: the section-aware raw-file position when backed on disk.
///
/// Returns one JSON section location.
fn build_code_section_location_json(section: &CodeSectionLocation, image_base: usize, file_offset: Option<usize>) -> Value
{
    let address = image_base.checked_add(section.rva);

    json!
    ({
        "name": section.name.as_ref(),
        "rva": section.rva,
        "rva_hex": format_hex(section.rva),
        "address": address,
        "address_hex": format_optional_hex(address),
        "file_offset": file_offset,
        "file_offset_hex": format_optional_hex(file_offset),
        "virtual_size": section.virtual_size,
        "virtual_size_hex": format_hex(section.virtual_size),
        "raw_size": section.raw_size,
        "raw_size_hex": format_hex(section.raw_size),
        "mapped_size": section.mapped_size,
        "mapped_size_hex": format_hex(section.mapped_size),
        "characteristics": section.characteristics,
        "characteristics_hex": format!("0x{:08X}", section.characteristics),
        "contains_entry_point": section.contains_entry_point,
        "contains_base_of_code": section.contains_base_of_code,
        "runtime_function_count": section.runtime_function_count,
        "runtime_code_bytes": section.runtime_code_bytes,
        "runtime_code_bytes_hex": format_hex(section.runtime_code_bytes)
    })
}


/// Builds all saved fields and trust decisions for one TEB.
/// `teb`: the collected x64 TEB header and native thread metadata.
/// `expected_peb_address`: the centrally validated process PEB address.
///
/// Returns one complete TEB JSON object.
fn build_teb_json(teb: &ThreadTebInfo, expected_peb_address: usize) -> Value
{
    let peb_pointer_matches = teb.process_environment_block == expected_peb_address;
    let trusted_for_stack_scan = teb.self_pointer_matches && teb.client_process_id_matches && teb.client_thread_id_matches && peb_pointer_matches;
    let thread = json!
    ({
        "thread_id": teb.thread_id,
        "thread_id_hex": format!("0x{:X}", teb.thread_id),
        "exit_status": teb.exit_status,
        "exit_status_hex": format!("0x{:08X}", teb.exit_status as u32),
        "affinity_mask": teb.affinity_mask,
        "affinity_mask_hex": format_hex(teb.affinity_mask),
        "priority": teb.priority,
        "base_priority": teb.base_priority
    });
    let nt_tib = json!
    ({
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
    });
    let environment = json!
    ({
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
    });

    json!
    ({
        "teb_address": teb.teb_address,
        "teb_address_hex": format_hex(teb.teb_address),
        "thread": thread,
        "nt_tib": nt_tib,
        "environment": environment,
        "trust":

      {
            "self_pointer_matches": teb.self_pointer_matches,
            "client_process_id_matches": teb.client_process_id_matches,
            "client_thread_id_matches": teb.client_thread_id_matches,
            "process_environment_block_matches": peb_pointer_matches,
            "trusted_for_stack_scan": trusted_for_stack_scan
        }
    })
}


/// Builds one TEB-stack string scan with partial and error details retained.
/// `scan`: the thread-scoped stack scan result.
///
/// Returns one collected, partial, skipped, or failed stack-scan JSON object.
fn build_teb_stack_scan_json(scan: &TebStackScan) -> Value
{
    match &scan.status
    {
        TebStackScanStatus::Collected(collection) =>
        {
            let strings = collection
                .strings
                .iter()
                .map(|value| {
                    json!
                    ({
                        "value": value.value.as_ref(),
                        "encoding": string_encoding_name(value.encoding),
                        "address": value.address,
                        "address_hex": format_hex(value.address),
                        "stack_offset": value.stack_offset,
                        "stack_offset_hex": format_hex(value.stack_offset)
                    })
                })
                .collect::<Vec<Value>>();
            let failures = collection
                .failures
                .iter()
                .map(|failure| {
                    json!
                    ({
                        "address": failure.address,
                        "address_hex": format_hex(failure.address),
                        "bytes_requested": failure.bytes_requested,
                        "bytes_requested_hex": format_hex(failure.bytes_requested),
                        "error": build_stack_region_error_json(&failure.error)
                    })
                })
                .collect::<Vec<Value>>();

            json!
            ({
                "thread_id": scan.thread_id,
                "thread_id_hex": format!("0x{:X}", scan.thread_id),
                "status": if failures.is_empty() { "collected" } else { "partial" },
                "teb_address": collection.teb_address,
                "teb_address_hex": format_hex(collection.teb_address),
                "stack_base": collection.stack_base,
                "stack_base_hex": format_hex(collection.stack_base),
                "stack_limit": collection.stack_limit,
                "stack_limit_hex": format_hex(collection.stack_limit),
                "bytes_read": collection.bytes_read,
                "bytes_read_hex": format_hex(collection.bytes_read),
                "string_count": strings.len(),
                "failure_count": failures.len(),
                "strings": strings,
                "failures": failures
            })
        }
        TebStackScanStatus::SkippedUntrustedTeb => json!
        ({
            "thread_id": scan.thread_id,
            "thread_id_hex": format!("0x{:X}", scan.thread_id),
            "status": "skipped_untrusted_teb"
        }),
        TebStackScanStatus::Failed(error) => json!
        ({
            "thread_id": scan.thread_id,
            "thread_id_hex": format!("0x{:X}", scan.thread_id),
            "status": "failed",
            "error": build_teb_stack_error_json(error)
        }),
    }
}


/// Builds JSON for mapped-image ranges unavailable after valid loader discards.
/// `ranges`: the unavailable RVA and size pairs to retain.
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
/// `error`: the original PDB collection error.
///
/// Returns a typed JSON error with direct fields retained where available.
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
/// `error`: the original import collection error.
///
/// Returns a typed JSON error with direct fields retained where available.
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
/// `error`: the original process TEB collection error.
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
        ProcessTebCollectionError::ThreadSnapshotIterationFailed {
            error,
        } => win32_error_json("ProcessTebCollectionError", "thread_snapshot_iteration_failed", *error),
    }
}


/// Builds a stable structured thread-scoped TEB collector error.
/// `error`: the original thread TEB collection error.
///
/// Returns a typed JSON error with native identifiers and read details retained.
fn build_thread_teb_error_json(error: &ThreadTebCollectionError) -> Value
{
    match error
    {
        ThreadTebCollectionError::ThreadOpenFailed {
            error,
        } => win32_error_json("ThreadTebCollectionError", "thread_open_failed", *error),
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


/// Builds a stable structured TEB-stack collection error.
/// `error`: the original stack collection error.
///
/// Returns a typed JSON error retaining thread, range, and nested query details.
fn build_teb_stack_error_json(error: &TebStackStringCollectionError) -> Value
{
    match error
    {
        TebStackStringCollectionError::InvalidProcessHandle => simple_error_json("TebStackStringCollectionError", "invalid_process_handle"),
        TebStackStringCollectionError::ProcessIdUnavailable {
            error,
        } => win32_error_json("TebStackStringCollectionError", "process_id_unavailable", *error),
        TebStackStringCollectionError::TebProcessIdentityMismatch {
            thread_id,
            process_id,
            teb_process_id,
        } => json!
        ({
            "type": "TebStackStringCollectionError",
            "kind": "teb_process_identity_mismatch",
            "fields":

          {
                "thread_id": thread_id,
                "process_id": process_id,
                "teb_process_id": teb_process_id
            }
        }),
        TebStackStringCollectionError::InvalidStackBounds {
            thread_id,
            stack_base,
            stack_limit,
        } => json!
        ({
            "type": "TebStackStringCollectionError",
            "kind": "invalid_stack_bounds",
            "fields":

          {
                "thread_id": thread_id,
                "stack_base": stack_base,
                "stack_base_hex": format_hex(*stack_base),
                "stack_limit": stack_limit,
                "stack_limit_hex": format_hex(*stack_limit)
            }
        }),
        TebStackStringCollectionError::StackRegionQueryFailed {
            thread_id,
            address,
            error,
        } => json!
        ({
            "type": "TebStackStringCollectionError",
            "kind": "stack_region_query_failed",
            "fields":

          {
                "thread_id": thread_id,
                "address": address,
                "address_hex": format_hex(*address)
            },
            "cause": build_memory_query_error_json(error)
        }),
        TebStackStringCollectionError::StackRegionRangeOverflow {
            thread_id,
            base_address,
            region_size,
        } => json!
        ({
            "type": "TebStackStringCollectionError",
            "kind": "stack_region_range_overflow",
            "fields":

          {
                "thread_id": thread_id,
                "base_address": base_address,
                "base_address_hex": format_hex(*base_address),
                "region_size": region_size,
                "region_size_hex": format_hex(*region_size)
            }
        }),
        TebStackStringCollectionError::StackRegionDidNotAdvance {
            thread_id,
            address,
            region_base_address,
            region_size,
        } => json!
        ({
            "type": "TebStackStringCollectionError",
            "kind": "stack_region_did_not_advance",
            "fields":

          {
                "thread_id": thread_id,
                "address": address,
                "address_hex": format_hex(*address),
                "region_base_address": region_base_address,
                "region_base_address_hex": format_hex(*region_base_address),
                "region_size": region_size,
                "region_size_hex": format_hex(*region_size)
            }
        }),
    }
}


/// Builds a stable structured stack-region read error.
/// `error`: the original region read error.
///
/// Returns a typed JSON error retaining native status and nested memory-read details.
fn build_stack_region_error_json(error: &TebStackRegionReadError) -> Value
{
    match error
    {
        TebStackRegionReadError::ReadFailed(cause) => json!
        ({
            "type": "TebStackRegionReadError",
            "kind": "read_failed",
            "cause": build_memory_read_error_json(cause)
        }),
        TebStackRegionReadError::ReadIncomplete {
            status,
            bytes_read,
        } => json!
        ({
            "type": "TebStackRegionReadError",
            "kind": "read_incomplete",
            "fields":

          {
                "status": status,
                "status_hex": format!("0x{:08X}", *status as u32),
                "bytes_read": bytes_read
            }
        }),
    }
}


/// Builds a stable structured process-memory read error.
/// `error`: the original memory read error.
///
/// Returns a typed JSON error retaining every available range and native status field.
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


/// Builds a stable structured virtual-memory query error.
/// `error`: the original query error.
///
/// Returns a typed JSON error retaining its native status when present.
fn build_memory_query_error_json(error: &MemoryRegionQueryError) -> Value
{
    match error
    {
        MemoryRegionQueryError::InvalidProcessHandle => simple_error_json("MemoryRegionQueryError", "invalid_process_handle"),
        MemoryRegionQueryError::NullBaseAddress => simple_error_json("MemoryRegionQueryError", "null_base_address"),
        MemoryRegionQueryError::QueryFailed {
            status,
        } => json!
        ({
            "type": "MemoryRegionQueryError",
            "kind": "query_failed",
            "fields":

          {
                "status": status,
                "status_hex": format!("0x{:08X}", *status as u32)
            }
        }),
    }
}


/// Builds a typed fieldless error JSON object.
/// `error_type`: the Rust error type label.
/// `kind`: the stable snake-case variant label.
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
/// `error_type`: the Rust error type label.
/// `kind`: the stable snake-case variant label.
/// `error`: the original Win32 error code.
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


/// Returns aggregate status for all TEB-stack string scans.
/// `collection`: the complete process triage collection.
///
/// Returns `not_run`, `collected`, or `partial` without treating failures as empty success.
fn teb_stack_collection_status(collection: &ProcessTriageCollection) -> &'static str
{
    if collection.tebs.is_err()
    {
        return "not_run";
    }

    let has_teb_failures = collection.tebs.as_ref().is_ok_and(|value| !value.failures.is_empty());
    let has_scan_failures = collection.teb_stack_scans.iter().any(|scan| match &scan.status
    {
        TebStackScanStatus::Collected(value) => !value.failures.is_empty(),
        TebStackScanStatus::SkippedUntrustedTeb | TebStackScanStatus::Failed(_) => true,
    });

    if has_teb_failures || has_scan_failures
    {
        "partial"
    }
    else
    {
        "collected"
    }
}


/// Returns the stable JSON label for code-section confidence.
/// `confidence`: the detector confidence classification.
///
/// Returns the lowercase confidence name.
fn code_section_confidence_name(confidence: CodeSectionConfidence) -> &'static str
{
    match confidence
    {
        CodeSectionConfidence::Low => "low",
        CodeSectionConfidence::Medium => "medium",
        CodeSectionConfidence::High => "high",
    }
}


/// Returns the stable JSON label for runtime-function evidence.
/// `evidence`: the x64 exception-directory evidence state.
///
/// Returns the lowercase evidence name.
fn runtime_function_evidence_name(evidence: RuntimeFunctionEvidence) -> &'static str
{
    match evidence
    {
        RuntimeFunctionEvidence::NotPresent => "not_present",
        RuntimeFunctionEvidence::Valid => "valid",
        RuntimeFunctionEvidence::Invalid => "invalid",
    }
}


/// Returns the stable JSON label for classified process opcode evidence.
/// `evidence`: decoded static instruction or mapped trap difference classification.
///
/// Returns the lowercase evidence class name.
fn process_opcode_evidence_name(evidence: ProcessOpcodeEvidence) -> &'static str
{
    match evidence
    {
        ProcessOpcodeEvidence::DecodedStaticInstruction => "decoded_static_instruction",
        ProcessOpcodeEvidence::MappedTrapDifference => "mapped_trap_differs_from_disk_baseline",
    }
}


/// Returns the stable JSON label for raw-file opcode comparison availability.
/// `status`: validated backing-file comparison state.
///
/// Returns the lowercase comparison status name.
fn process_opcode_backing_status_name(status: ProcessOpcodeBackingStatus) -> &'static str
{
    match status
    {
        ProcessOpcodeBackingStatus::Matched => "identity_matched",
        ProcessOpcodeBackingStatus::Unavailable => "unavailable",
        ProcessOpcodeBackingStatus::Invalid => "invalid",
        ProcessOpcodeBackingStatus::IdentityMismatch => "identity_mismatch",
    }
}


/// Returns the stable JSON label for opcode relocation validation.
/// `status`: loader-relocation validation state.
///
/// Returns the lowercase relocation status name.
fn process_opcode_relocation_status_name(status: ProcessOpcodeRelocationStatus) -> &'static str
{
    match status
    {
        ProcessOpcodeRelocationStatus::NotEvaluated => "not_evaluated",
        ProcessOpcodeRelocationStatus::NotRequired => "not_required",
        ProcessOpcodeRelocationStatus::Validated => "validated",
        ProcessOpcodeRelocationStatus::Invalid => "invalid",
    }
}


/// Returns the stable JSON label for a CodeView record format.
/// `format`: the collected RSDS or NB10 record type.
///
/// Returns the conventional uppercase record name.
fn pdb_format_name(format: PdbCodeViewFormat) -> &'static str
{
    match format
    {
        PdbCodeViewFormat::Rsds => "RSDS",
        PdbCodeViewFormat::Nb10 => "NB10",
    }
}


/// Returns the stable JSON label for one direct IAT xref kind.
/// `kind`: the collected call or jump classification.
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


/// Returns the stable JSON label for one decoded string encoding.
/// `encoding`: the collector encoding classification.
///
/// Returns a lowercase JSON encoding name.
fn string_encoding_name(encoding: StringEncoding) -> &'static str
{
    match encoding
    {
        StringEncoding::Ascii => "ascii",
        StringEncoding::Utf16Le => "utf-16le",
        StringEncoding::Utf8 => "utf-8",
    }
}


/// Formats one pointer-sized value as uppercase hexadecimal.
/// `value`: the numeric address, RVA, offset, or size.
///
/// Returns a `0x`-prefixed hexadecimal string.
fn format_hex(value: usize) -> String
{
    format!("0x{:X}", value)
}


/// Formats one byte slice as uppercase hexadecimal octets.
/// `bytes`: exact instruction or opcode bytes to format.
///
/// Returns space-separated hexadecimal without a prefix.
fn format_byte_slice_hex(bytes: &[u8]) -> String
{
    bytes.iter().map(|byte| format!("{:02X}", byte)).collect::<Vec<String>>().join(" ")
}


/// Formats one optional pointer-sized value as uppercase hexadecimal.
/// `value`: the optional address or file offset.
///
/// Returns the formatted value or `None` when the numeric value is absent.
fn format_optional_hex(value: Option<usize>) -> Option<String>
{
    value.map(format_hex)
}
