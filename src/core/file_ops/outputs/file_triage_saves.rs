use std::fmt::Write;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::core::file_ops::outputs::configs::prepare_file_triage_layout;
use crate::core::file_ops::utils::apis::{collect_file_api_imports, FileApiImport, FileApiXrefKind};
use crate::core::file_ops::utils::pdb::{collect_file_debug_directory, FileCodeViewInfo, FileDebugDetails, FileDebugEntry, MAX_DEBUG_DIRECTORY_ENTRIES};
use crate::core::file_ops::utils::scanning::{scan_file_signatures, FileSignatureHit};
use crate::core::file_ops::utils::sections::{collect_file_sections, PeSectionInfo};
use crate::core::file_ops::utils::strings::{collect_file_strings, FileString};
use crate::core::file_ops::utils::validate::ValidatedPeFile;
use crate::core::global_utils::fileutils::{get_file_entropy, get_file_sha256, write_json_file};
use crate::core::process_ops::utils::strings::StringEncoding;

/// Number of bytes represented by one binary megabyte in saved size fields.
const BYTES_PER_MEGABYTE: f64 = 1024.0 * 1024.0;

/// Owns every reusable result produced by the raw-file triage collectors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileTriageCollection<'a>
{
    pub sections: Vec<PeSectionInfo>,
    pub imports: Vec<FileApiImport>,
    pub debug_entries: Vec<FileDebugEntry<'a>>,
    pub signature_hits: Vec<FileSignatureHit>,
    pub strings: Vec<FileString>,
}


/// Runs every raw-file collector once against an already-validated PE image.
/// `file`: the validated image shared by each collector.
/// `minimum_string_chars`: the minimum decoded character count stored for strings.
///
/// Returns one collection bundle suitable for console display and JSON persistence.
pub fn collect_file_triage(file: &ValidatedPeFile, minimum_string_chars: usize) -> FileTriageCollection<'_>
{
    FileTriageCollection
    {
        sections: collect_file_sections(file),
        imports: collect_file_api_imports(file),
        debug_entries: collect_file_debug_directory(file),
        signature_hits: scan_file_signatures(file),
        strings: collect_file_strings(file, minimum_string_chars),
    }
}


/// Recreates and saves one complete file-triage collection as organized JSON output.
/// `target_path`: the scanned file path used for hashing and output-root naming.
/// `file`: the validated PE metadata represented by the collection.
/// `collection`: the reusable collector output to serialize without rescanning.
/// `minimum_string_chars`: the string threshold recorded with the saved results.
///
/// Returns the scan-root directory created under Daydream's current working directory.
pub fn save_file_triage(target_path: &Path, file: &ValidatedPeFile, collection: &FileTriageCollection<'_>, minimum_string_chars: usize) -> io::Result<PathBuf>
{
    let sha256 = get_file_sha256(target_path.as_os_str())?;
    let entropy = get_file_entropy(target_path.as_os_str())?;
    let layout = prepare_file_triage_layout(target_path, &sha256)?;

    write_json_file(&layout.pe, "file_metadata.json", &build_file_metadata_json(target_path, file, &sha256, entropy))?;
    write_json_file(&layout.pe, "sections.json", &build_sections_json(&collection.sections))?;
    write_json_file(&layout.imports, "imports.json", &build_imports_json(&collection.imports))?;
    write_json_file(&layout.peb, "debug_directory.json", &build_debug_directory_json(&collection.debug_entries))?;
    write_json_file(&layout.scanning, "signature_hits.json", &build_signature_hits_json(&collection.signature_hits))?;
    write_json_file(&layout.root, "strings.json", &build_strings_json(&collection.strings, minimum_string_chars))?;

    Ok(layout.root)
}


/// Builds target identity and validated PE-header JSON.
/// `target_path`: the scanned path represented by the metadata.
/// `file`: the validated PE header and byte-length source.
/// `sha256`: the digest used to identify the exact target content.
/// `entropy`: the target's Shannon entropy in bits per byte.
///
/// Returns one JSON object containing target and PE-header groups.
fn build_file_metadata_json(target_path: &Path, file: &ValidatedPeFile, sha256: &str, entropy: f64) -> Value
{
    json!
    ({
        "target":
        {
            "path": target_path.display().to_string(),
            "file_name": target_path.file_name().map(|value| value.to_string_lossy().into_owned()),
            "file_stem": target_path.file_stem().map(|value| value.to_string_lossy().into_owned()),
            "sha256": sha256,
            "entropy": entropy,
            "entropy_unit": "bits_per_byte",
            "raw_size": file.bytes.len(),
            "raw_size_bytes": file.bytes.len(),
            "raw_size_mb": bytes_to_megabytes(file.bytes.len()),
            "raw_size_hex": format!("0x{:X}", file.bytes.len())
        },
        "pe_header":
        {
            "machine": file.machine,
            "machine_hex": format!("0x{:04X}", file.machine),
            "timestamp": file.timestamp,
            "timestamp_hex": format!("0x{:08X}", file.timestamp),
            "characteristics": file.characteristics,
            "characteristics_hex": format!("0x{:04X}", file.characteristics),
            "image_base": file.image_base,
            "image_base_hex": format!("0x{:016X}", file.image_base),
            "entry_point_rva": file.entry_point_rva,
            "entry_point_rva_hex": format!("0x{:08X}", file.entry_point_rva),
            "image_size": file.size_of_image,
            "image_size_bytes": file.size_of_image,
            "image_size_mb": bytes_to_megabytes(file.size_of_image),
            "image_size_hex": format!("0x{:X}", file.size_of_image),
            "header_size": file.size_of_headers,
            "header_size_bytes": file.size_of_headers,
            "header_size_mb": bytes_to_megabytes(file.size_of_headers),
            "header_size_hex": format!("0x{:X}", file.size_of_headers),
            "section_alignment": file.section_alignment,
            "section_alignment_bytes": file.section_alignment,
            "section_alignment_mb": bytes_to_megabytes(file.section_alignment),
            "section_alignment_hex": format!("0x{:X}", file.section_alignment),
            "file_alignment": file.file_alignment,
            "file_alignment_bytes": file.file_alignment,
            "file_alignment_mb": bytes_to_megabytes(file.file_alignment),
            "file_alignment_hex": format!("0x{:X}", file.file_alignment),
            "section_count": file.sections.len()
        }
    })
}


/// Builds ordered PE-section JSON with content, memory, size, and location groups.
/// `sections`: the collected PE section records in table order.
///
/// Returns one counted JSON section array.
fn build_sections_json(sections: &[PeSectionInfo]) -> Value
{
    let values = sections
        .iter()
        .enumerate()
        .map(|(index, section)|
        {
            let content = section.content
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<String>>();

            json!
            ({
                "index": index,
                "name": section.name.as_ref(),
                "content": content,
                "memory":
                {
                    "readable": section.memory.readable,
                    "writable": section.memory.writable,
                    "executable": section.memory.executable,
                    "shared": section.memory.shared,
                    "discardable": section.memory.discardable
                },
                "location":
                {
                    "rva": section.rva,
                    "rva_hex": format!("0x{:08X}", section.rva),
                    "file_offset": section.file_offset,
                    "file_offset_hex": format!("0x{:08X}", section.file_offset)
                },
                "size":
                {
                    "virtual": section.virtual_size,
                    "virtual_bytes": section.virtual_size,
                    "virtual_mb": bytes_to_megabytes(section.virtual_size),
                    "virtual_hex": format!("0x{:X}", section.virtual_size),
                    "raw_bytes": section.raw_size,
                    "raw_mb": bytes_to_megabytes(section.raw_size),
                    "raw_hex": format!("0x{:X}", section.raw_size)
                },
                "characteristics": section.characteristics,
                "characteristics_hex": format!("0x{:08X}", section.characteristics)
            })
        })
        .collect::<Vec<Value>>();

    json!
    ({
        "count": values.len(),
        "sections": values
    })
}


/// Builds import-table JSON with IAT locations and grouped xrefs.
/// `imports`: the collected API import records and their xrefs.
///
/// Returns one counted JSON import array.
fn build_imports_json(imports: &[FileApiImport]) -> Value
{
    let values = imports
        .iter()
        .map(|api_import|
        {
            let xrefs = api_import.xrefs
                .iter()
                .map(|xref|
                {
                    json!
                    ({
                        "kind": api_xref_kind_name(xref.kind),
                        "rva": xref.rva,
                        "rva_hex": format!("0x{:08X}", xref.rva),
                        "file_offset": xref.file_offset,
                        "file_offset_hex": format!("0x{:08X}", xref.file_offset)
                    })
                })
                .collect::<Vec<Value>>();

            json!
            ({
                "library": api_import.library_name.as_ref(),
                "name": api_import.import_name.as_ref(),
                "iat":
                {
                    "rva": api_import.iat_rva,
                    "rva_hex": format!("0x{:08X}", api_import.iat_rva),
                    "file_offset": api_import.file_offset,
                    "file_offset_hex": api_import.file_offset.map(|value| format!("0x{:08X}", value))
                },
                "xref_count": xrefs.len(),
                "xrefs": xrefs
            })
        })
        .collect::<Vec<Value>>();

    json!
    ({
        "count": values.len(),
        "imports": values
    })
}


/// Builds debug-directory and PDB JSON with typed payload details.
/// `entries`: the collected debug-directory records and borrowed payload bytes.
///
/// Returns one counted JSON entry array with the collector-limit status.
fn build_debug_directory_json(entries: &[FileDebugEntry<'_>]) -> Value
{
    let values = entries
        .iter()
        .map(|entry|
        {
            json!
            ({
                "index": entry.index,
                "type":
                {
                    "name": entry.debug_type.to_string(),
                    "raw": entry.raw_type
                },
                "entry_location":
                {
                    "rva": entry.entry_rva,
                    "rva_hex": format!("0x{:08X}", entry.entry_rva),
                    "file_offset": entry.entry_file_offset,
                    "file_offset_hex": format!("0x{:08X}", entry.entry_file_offset)
                },
                "header":
                {
                    "characteristics": entry.characteristics,
                    "characteristics_hex": format!("0x{:08X}", entry.characteristics),
                    "timestamp": entry.timestamp,
                    "timestamp_hex": format!("0x{:08X}", entry.timestamp),
                    "major_version": entry.major_version,
                    "minor_version": entry.minor_version,
                    "data_size": entry.size_of_data,
                    "data_size_bytes": entry.size_of_data,
                    "data_size_mb": bytes_to_megabytes(entry.size_of_data),
                    "data_size_hex": format!("0x{:X}", entry.size_of_data)
                },
                "data_location":
                {
                    "address_of_raw_data": entry.address_of_raw_data,
                    "address_of_raw_data_hex": format!("0x{:08X}", entry.address_of_raw_data),
                    "pointer_to_raw_data": entry.pointer_to_raw_data,
                    "pointer_to_raw_data_hex": format!("0x{:08X}", entry.pointer_to_raw_data),
                    "rva_mapped_file_offset": entry.rva_data_file_offset,
                    "rva_mapped_file_offset_hex": entry.rva_data_file_offset.map(|value| format!("0x{:08X}", value)),
                    "effective_file_offset": entry.data_file_offset,
                    "effective_file_offset_hex": entry.data_file_offset.map(|value| format!("0x{:08X}", value)),
                    "location_mismatch": entry.data_location_mismatch
                },
                "details": build_debug_details_json(entry),
                "raw_data": build_raw_debug_data_json(entry.raw_data)
            })
        })
        .collect::<Vec<Value>>();

    json!
    ({
        "count": values.len(),
        "entry_limit": MAX_DEBUG_DIRECTORY_ENTRIES,
        "entry_limit_reached": values.len() == MAX_DEBUG_DIRECTORY_ENTRIES,
        "entries": values
    })
}


/// Builds one typed debug payload JSON object.
/// `entry`: the debug-directory record whose parsed details should be represented.
///
/// Returns one status-bearing JSON payload object.
fn build_debug_details_json(entry: &FileDebugEntry<'_>) -> Value
{
    match &entry.details
    {
        FileDebugDetails::None => json!({ "status": "none" }),
        FileDebugDetails::CodeView(info) => build_codeview_json(info),
        FileDebugDetails::VcFeature(info) => json!
        ({
            "status": "parsed",
            "kind": "vc_feature",
            "counts":
            {
                "pre_vc11": info.pre_vc11,
                "c_cpp": info.c_cpp,
                "gs": info.gs,
                "sdl": info.sdl,
                "guard_n": info.guard_n
            }
        }),
        FileDebugDetails::Pogo(info) =>
        {
            let groups = info.entries
                .iter()
                .map(|group| json!
                ({
                    "name": group.name.as_ref(),
                    "rva": group.rva,
                    "rva_hex": format!("0x{:08X}", group.rva),
                    "size": group.size,
                    "size_bytes": group.size,
                    "size_mb": bytes_to_megabytes(group.size as usize),
                    "size_hex": format!("0x{:X}", group.size)
                }))
                .collect::<Vec<Value>>();

            json!
            ({
                "status": "parsed",
                "kind": "pogo",
                "signature_text": String::from_utf8_lossy(&info.signature),
                "signature_hex": encode_hex(&info.signature, info.signature.len()),
                "group_count": groups.len(),
                "groups": groups
            })
        }
        FileDebugDetails::Reproducible(info) => json!
        ({
            "status": "parsed",
            "kind": "reproducible",
            "declared_hash_length": info.declared_hash_length,
            "actual_hash_length": info.hash.len(),
            "length_matches": info.length_matches,
            "hash_hex": encode_hex(&info.hash, info.hash.len())
        }),
        FileDebugDetails::Misc(info) => json!
        ({
            "status": "parsed",
            "kind": "misc",
            "data_type": info.data_type,
            "declared_length": info.declared_length,
            "unicode": info.unicode,
            "text": info.text.as_deref()
        }),
        FileDebugDetails::PdbChecksum(info) => json!
        ({
            "status": "parsed",
            "kind": "pdb_checksum",
            "algorithm": info.algorithm.as_ref(),
            "checksum_size": info.checksum.len(),
            "checksum_size_bytes": info.checksum.len(),
            "checksum_size_mb": bytes_to_megabytes(info.checksum.len()),
            "checksum_size_hex": format!("0x{:X}", info.checksum.len()),
            "checksum_hex": encode_hex(&info.checksum, info.checksum.len())
        }),
        FileDebugDetails::EmbeddedPortablePdb(info) => json!
        ({
            "status": "parsed",
            "kind": "embedded_portable_pdb",
            "signature": "MPDB",
            "uncompressed_size": info.uncompressed_size,
            "uncompressed_size_bytes": info.uncompressed_size,
            "uncompressed_size_mb": bytes_to_megabytes(info.uncompressed_size),
            "uncompressed_size_hex": format!("0x{:X}", info.uncompressed_size),
            "compressed_size": info.compressed_size,
            "compressed_size_bytes": info.compressed_size,
            "compressed_size_mb": bytes_to_megabytes(info.compressed_size),
            "compressed_size_hex": format!("0x{:X}", info.compressed_size)
        }),
        FileDebugDetails::ExtendedDllCharacteristics(value) => json!
        ({
            "status": "parsed",
            "kind": "extended_dll_characteristics",
            "value": value,
            "value_hex": format!("0x{:08X}", value)
        }),
        FileDebugDetails::Raw => json!({ "status": "raw", "kind": "unsupported" }),
        FileDebugDetails::Malformed => json!({ "status": "malformed" }),
        FileDebugDetails::DecodeLimitExceeded => json!({ "status": "decode_limit_exceeded" }),
        FileDebugDetails::Unavailable => json!({ "status": "unavailable" }),
    }
}


/// Builds parsed RSDS, NB10, or unknown CodeView/PDB JSON.
/// `info`: the parsed CodeView variant to represent.
///
/// Returns one JSON object containing the available PDB metadata.
fn build_codeview_json(info: &FileCodeViewInfo) -> Value
{
    match info
    {
        FileCodeViewInfo::Rsds
        {
            guid,
            age,
            path,
        } => json!
        ({
            "status": "parsed",
            "kind": "codeview",
            "format": "RSDS",
            "guid": format!("{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}", guid.data1, guid.data2, guid.data3, guid.data4[0], guid.data4[1], guid.data4[2], guid.data4[3], guid.data4[4], guid.data4[5], guid.data4[6], guid.data4[7]),
            "age": age,
            "pdb_path": build_pdb_path_json(path)
        }),
        FileCodeViewInfo::Nb10
        {
            offset,
            signature,
            age,
            path,
        } => json!
        ({
            "status": "parsed",
            "kind": "codeview",
            "format": "NB10",
            "offset": offset,
            "offset_hex": format!("0x{:08X}", offset),
            "signature": signature,
            "signature_hex": format!("0x{:08X}", signature),
            "age": age,
            "pdb_path": build_pdb_path_json(path)
        }),
        FileCodeViewInfo::Other(signature) => json!
        ({
            "status": "parsed",
            "kind": "codeview",
            "format": "other",
            "signature_text": String::from_utf8_lossy(signature),
            "signature_hex": encode_hex(signature, signature.len())
        }),
    }
}


/// Splits one embedded PDB path into inert display components without accessing it.
/// `pdb_path`: the untrusted path text embedded in the CodeView payload.
///
/// Returns one JSON object containing string-only path components.
fn build_pdb_path_json(pdb_path: &str) -> Value
{
    let path = Path::new(pdb_path);

    json!
    ({
        "full": pdb_path,
        "directory": path.parent().map(|value| value.to_string_lossy().into_owned()),
        "file_name": path.file_name().map(|value| value.to_string_lossy().into_owned()),
        "file_stem": path.file_stem().map(|value| value.to_string_lossy().into_owned()),
        "extension": path.extension().map(|value| value.to_string_lossy().into_owned())
    })
}


/// Builds bounded raw debug-payload JSON.
/// `raw_data`: the optional payload bytes borrowed from the validated image.
///
/// Returns availability, size, and at most 64 preview bytes as JSON.
fn build_raw_debug_data_json(raw_data: Option<&[u8]>) -> Value
{
    match raw_data
    {
        Some(bytes) => json!
        ({
            "available": true,
            "size": bytes.len(),
            "size_bytes": bytes.len(),
            "size_mb": bytes_to_megabytes(bytes.len()),
            "size_hex": format!("0x{:X}", bytes.len()),
            "hex_preview": encode_hex(bytes, 64),
            "preview_bytes": bytes.len().min(64),
            "preview_truncated": bytes.len() > 64
        }),
        None => json!
        ({
            "available": false,
            "size": 0,
            "size_bytes": 0,
            "size_mb": 0.0,
            "size_hex": "0x0",
            "hex_preview": "",
            "preview_bytes": 0,
            "preview_truncated": false
        }),
    }
}


/// Builds raw-file signature-hit JSON.
/// `hits`: the collected signature hits in file-offset order.
///
/// Returns one counted JSON hit array.
fn build_signature_hits_json(hits: &[FileSignatureHit]) -> Value
{
    let values = hits
        .iter()
        .map(|hit| json!
        ({
            "trigger": hit.trigger,
            "section": hit.section_name.as_ref(),
            "rva": hit.rva,
            "rva_hex": format!("0x{:08X}", hit.rva),
            "file_offset": hit.file_offset,
            "file_offset_hex": format!("0x{:08X}", hit.file_offset)
        }))
        .collect::<Vec<Value>>();

    json!
    ({
        "count": values.len(),
        "hits": values
    })
}


/// Builds root-level decoded-string JSON with encoding and mapped locations.
/// `strings`: the decoded strings in raw file order.
/// `minimum_string_chars`: the effective collection threshold to record.
///
/// Returns one counted JSON string array.
fn build_strings_json(strings: &[FileString], minimum_string_chars: usize) -> Value
{
    let values = strings
        .iter()
        .map(|file_string| json!
        ({
            "value": file_string.value.as_ref(),
            "encoding": string_encoding_name(file_string.encoding),
            "rva": file_string.rva,
            "rva_hex": file_string.rva.map(|value| format!("0x{:08X}", value)),
            "file_offset": file_string.file_offset,
            "file_offset_hex": format!("0x{:08X}", file_string.file_offset)
        }))
        .collect::<Vec<Value>>();

    json!
    ({
        "minimum_characters": minimum_string_chars.max(1),
        "count": values.len(),
        "strings": values
    })
}


/// Returns the stable JSON name for one API xref kind.
/// `kind`: the collected call or jump xref classification.
///
/// Returns the lowercase JSON label.
fn api_xref_kind_name(kind: FileApiXrefKind) -> &'static str
{
    match kind
    {
        FileApiXrefKind::Call => "call",
        FileApiXrefKind::Jump => "jump",
    }
}


/// Returns the stable JSON name for one decoded string encoding.
/// `encoding`: the collector's decoded encoding classification.
///
/// Returns the lowercase JSON label.
fn string_encoding_name(encoding: StringEncoding) -> &'static str
{
    match encoding
    {
        StringEncoding::Ascii => "ascii",
        StringEncoding::Utf16Le => "utf16_le",
        StringEncoding::Utf8 => "utf8",
        StringEncoding::Unknown => "unknown",
    }
}


/// Converts one byte count into a stable six-decimal binary-megabyte value.
/// `bytes`: the byte count to convert using 1,048,576 bytes per megabyte.
///
/// Returns the converted and rounded megabyte value.
fn bytes_to_megabytes(bytes: usize) -> f64
{
    let megabytes = bytes as f64 / BYTES_PER_MEGABYTE;

    (megabytes * 1_000_000.0).round() / 1_000_000.0
}


/// Encodes a bounded byte sequence as uppercase hexadecimal text.
/// `bytes`: the source byte sequence.
/// `maximum_bytes`: the maximum prefix length to encode before a truncation suffix.
///
/// Returns the hexadecimal preview and omitted-byte count when truncated.
fn encode_hex(bytes: &[u8], maximum_bytes: usize) -> String
{
    let retained_length = bytes.len().min(maximum_bytes);
    let mut value = String::with_capacity(retained_length.saturating_mul(2).saturating_add(32));

    for byte in &bytes[..retained_length]
    {
        let _ = write!(value, "{:02X}", byte);
    }

    if retained_length < bytes.len()
    {
        let _ = write!(value, "... (+{} bytes)", bytes.len() - retained_length);
    }

    value
}
