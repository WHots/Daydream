use std::fmt::{self, Write};
use std::io;
use std::path::Path;

use crate::core::file_ops::outputs::file_triage_saves::{collect_file_triage, save_file_triage};
use crate::core::file_ops::utils::apis::FileApiImport;
use crate::core::file_ops::utils::pdb::{FileCodeViewInfo, FileDebugDetails, FileDebugEntry, MAX_DEBUG_DIRECTORY_ENTRIES};
use crate::core::file_ops::utils::sections::PeSectionInfo;
use crate::core::file_ops::utils::validate::{validate_target_file, FileValidationError};

/// Default minimum printable character count for file-string collection.
pub const DEFAULT_MINIMUM_FILE_STRING_LENGTH: usize = 4;

/// Explains whether file processing failed during PE validation or JSON persistence.
#[derive(Debug)]
pub enum FileProcessingError
{
    Validation(FileValidationError),
    Save(io::Error),
}


/// Validates, analyzes, and displays the available metadata from one raw PE file.
/// `path`: the executable path to read without loading or executing it.
/// `is_self_target`: whether the path represents the currently running application.
///
/// Returns success after every file-side collector has completed, or the validation
/// or save error that prevented the complete triage workflow from finishing.
pub fn process_file(path: &Path, is_self_target: bool) -> Result<(), FileProcessingError>
{
    let file = validate_target_file(path).map_err(FileProcessingError::Validation)?;
    let collection = collect_file_triage(&file, DEFAULT_MINIMUM_FILE_STRING_LENGTH);
    let sections = collection.sections.as_slice();
    let imports = collection.imports.as_slice();
    let debug_entries = collection.debug_entries.as_slice();
    let signature_hits = collection.signature_hits.as_slice();
    let strings = collection.strings.as_slice();

    println!("File target: {}", path.display());
    println!("Raw size: 0x{:X} bytes", file.bytes.len());

    println!("Machine: 0x{:04X} | Timestamp: 0x{:08X} | Characteristics: 0x{:04X}", file.machine, file.timestamp, file.characteristics);

    println!("Image base: 0x{:016X} | Entry-point RVA: 0x{:08X} | Image size: 0x{:X}", file.image_base, file.entry_point_rva, file.size_of_image);

    println!("Header size: 0x{:X} | Section alignment: 0x{:X} | File alignment: 0x{:X}", file.size_of_headers, file.section_alignment, file.file_alignment);

    println!("\nPE sections ({})", sections.len());

    print_file_sections(sections);

    println!("\nAPI imports ({})", imports.len());

    if imports.is_empty()
    {
        println!("None collected");
    }
    else
    {
        print_file_api_imports(imports);
    }

    println!("\nDebug directory entries ({})", debug_entries.len());

    if debug_entries.is_empty()
    {
        println!("None collected");
    }
    else
    {
        print_file_debug_directory(debug_entries);
    }

    println!("\nFile signature hits ({})", signature_hits.len());

    if signature_hits.is_empty()
    {
        println!("None collected");
    }
    else
    {
        for hit in signature_hits
        {
            println!("{} | Section {:?} | RVA 0x{:08X} | File offset 0x{:08X}", hit.trigger, hit.section_name, hit.rva, hit.file_offset);
        }
    }

    if !is_self_target
    {
        println!("\nFile strings ({}, minimum {} characters)", strings.len(), DEFAULT_MINIMUM_FILE_STRING_LENGTH);

        if strings.is_empty()
        {
            println!("None collected");
        }
        else
        {
            for file_string in strings
            {
                match file_string.rva
                {
                    Some(rva) => println!("RVA 0x{:08X} | File offset 0x{:08X} | {:?} | {}", rva, file_string.file_offset, file_string.encoding, file_string.value),
                    None => println!("RVA N/A | File offset 0x{:08X} | {:?} | {}", file_string.file_offset, file_string.encoding, file_string.value),
                }
            }
        }
    }

    let output_root = save_file_triage(path, &file, &collection, DEFAULT_MINIMUM_FILE_STRING_LENGTH).map_err(FileProcessingError::Save)?;

    println!("\nFile triage saved to {}", output_root.display());

    Ok(())
}

impl fmt::Display for FileProcessingError
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        match self
        {
            Self::Validation(error) => write!(formatter, "{}", error),
            Self::Save(error) => write!(formatter, "failed to save file triage: {}", error),
        }
    }
}

impl std::error::Error for FileProcessingError
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)>
    {
        match self
        {
            Self::Validation(error) => Some(error),
            Self::Save(error) => Some(error),
        }
    }
}


/// Displays collected PE section layout, content, and memory-trait information.
/// `sections`: the section records to display without consuming them.
fn print_file_sections(sections: &[PeSectionInfo])
{
    if sections.is_empty()
    {
        println!("PE sections: None collected");
        return;
    }

    for (index, section) in sections.iter().enumerate()
    {
        let content = if section.content.is_empty() { String::from("None declared") } else { section.content.iter().map(|value| value.to_string()).collect::<Vec<String>>().join(", ") };

        println!("[{}] {:?} | RVA 0x{:08X} | Virtual size 0x{:X} | File offset 0x{:08X} | Raw size 0x{:X}", index, section.name, section.rva, section.virtual_size, section.file_offset, section.raw_size);
        println!("  Content {} | Memory {} | Characteristics 0x{:08X}", content, section.memory, section.characteristics);
    }
}


/// Displays each collected API import followed by its supported IAT xrefs.
/// `imports`: the API records to display without consuming them.
fn print_file_api_imports(imports: &[FileApiImport])
{
    for api_import in imports
    {
        println!("{}", api_import);

        if api_import.xrefs.is_empty()
        {
            println!("  XREF locations: None");
            continue;
        }

        for xref in &api_import.xrefs
        {
            println!("  {}", xref);
        }
    }
}


/// Displays collected debug-directory headers, locations, and typed payloads.
/// `entries`: the debug records to display without consuming their raw payloads.
fn print_file_debug_directory(entries: &[FileDebugEntry<'_>])
{
    for entry in entries
    {
        println!("[{}] {} ({}) | Entry RVA 0x{:08X} | File offset 0x{:08X} | Data size 0x{:X}", entry.index, entry.debug_type, entry.raw_type, entry.entry_rva, entry.entry_file_offset, entry.size_of_data);
        println!("  Characteristics 0x{:08X} | Timestamp 0x{:08X} | Version {}.{}", entry.characteristics, entry.timestamp, entry.major_version, entry.minor_version);
        println!("  AddressOfRawData 0x{:08X} | PointerToRawData 0x{:08X}", entry.address_of_raw_data, entry.pointer_to_raw_data);

        match entry.rva_data_file_offset
        {
            Some(offset) => println!("  RVA-mapped file offset 0x{:08X}", offset),
            None => println!("  RVA-mapped file offset N/A"),
        }

        match entry.data_file_offset
        {
            Some(offset) => println!("  Effective data file offset 0x{:08X} | Location mismatch {}", offset, entry.data_location_mismatch),
            None => println!("  Effective data file offset N/A | Location mismatch {}", entry.data_location_mismatch),
        }

        print_debug_details(entry);
    }

    if entries.len() == MAX_DEBUG_DIRECTORY_ENTRIES
    {
        println!("Debug directory entry limit reached at {}; additional entries may exist", MAX_DEBUG_DIRECTORY_ENTRIES);
    }
}


/// Displays the typed payload fields while keeping raw-only data compact.
/// `entry`: the collected debug entry whose typed details should be displayed.
fn print_debug_details(entry: &FileDebugEntry<'_>)
{
    match &entry.details
    {
        FileDebugDetails::None => println!("  Payload: None"),

        FileDebugDetails::CodeView(info) =>
        {
            let pdb_path = match info
            {
                FileCodeViewInfo::Rsds {
                    guid,
                    age,
                    path,
                } =>
                {
                    println!("  CodeView format: RSDS");
                    println!("  GUID {:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}", guid.data1, guid.data2, guid.data3, guid.data4[0], guid.data4[1], guid.data4[2], guid.data4[3], guid.data4[4], guid.data4[5], guid.data4[6], guid.data4[7]);
                    println!("  PDB age {}", age);

                    Some(path.as_ref())
                }

                FileCodeViewInfo::Nb10 {
                    offset,
                    signature,
                    age,
                    path,
                } =>
                {
                    println!("  CodeView format: NB10");
                    println!("  NB10 offset 0x{:08X}", offset);
                    println!("  NB10 signature 0x{:08X}", signature);
                    println!("  PDB age {}", age);

                    Some(path.as_ref())
                }

                FileCodeViewInfo::Other(signature) =>
                {
                    println!("  CodeView format: Other {:?}", String::from_utf8_lossy(signature));

                    None
                }
            };

            if let Some(pdb_path) = pdb_path
            {
                let path = Path::new(pdb_path);

                println!("  PDB path {:?}", pdb_path);
                println!("  PDB directory {:?}", path.parent());
                println!("  PDB file {:?}", path.file_name());
                println!("  PDB stem {:?} | Extension {:?}", path.file_stem(), path.extension());
            }
        }
        FileDebugDetails::VcFeature(info) => println!("  VC feature counts: pre-VC11 {} | C/C++ {} | GS {} | SDL {} | guardN {}", info.pre_vc11, info.c_cpp, info.gs, info.sdl, info.guard_n),

        FileDebugDetails::Pogo(info) =>
        {
            println!("  POGO signature {:?} | Groups {}", String::from_utf8_lossy(&info.signature), info.entries.len());

            for group in &info.entries
            {
                println!("    {:?} | RVA 0x{:08X} | Size 0x{:X}", group.name, group.rva, group.size);
            }
        }

        FileDebugDetails::Reproducible(info) => println!("  Reproducible hash length {:?} | Matches {} | Hash {}", info.declared_hash_length, info.length_matches, encode_hex_preview(&info.hash, 64)),
        FileDebugDetails::Misc(info) => println!("  Misc type {} | Length {} | Unicode {} | Text {:?}", info.data_type, info.declared_length, info.unicode, info.text),
        FileDebugDetails::PdbChecksum(info) => println!("  PDB checksum {:?}:{}", info.algorithm, encode_hex_preview(&info.checksum, 64)),
        FileDebugDetails::EmbeddedPortablePdb(info) => println!("  Embedded Portable PDB MPDB | Uncompressed {} | Compressed {}", info.uncompressed_size, info.compressed_size),
        FileDebugDetails::ExtendedDllCharacteristics(value) => println!("  Extended DLL characteristics 0x{:08X}", value),

        FileDebugDetails::Raw =>
        {
            let data = entry.raw_data.unwrap_or_default();

            println!("  Raw payload preserved: {} bytes | Hex {}", data.len(), encode_hex_preview(data, 64));
        }

        FileDebugDetails::Malformed =>
        {
            let data = entry.raw_data.unwrap_or_default();

            println!("  Payload malformed; raw bytes preserved: {} | Hex {}", data.len(), encode_hex_preview(data, 64));
        }

        FileDebugDetails::DecodeLimitExceeded => println!("  Typed payload decoding skipped by the decoded-data limit; raw bytes remain available"),
        FileDebugDetails::Unavailable => println!("  Payload unavailable"),
    }
}


/// Encodes a bounded analyst-facing byte preview as uppercase hexadecimal text.
/// `bytes`: the bytes to encode.
/// `maximum_bytes`: the maximum number of bytes retained before a truncation suffix.
///
/// Returns the encoded preview and any omitted-byte count.
fn encode_hex_preview(bytes: &[u8], maximum_bytes: usize) -> String
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
