use windows_sys::Win32::System::Diagnostics::Debug::{
    IMAGE_DIRECTORY_ENTRY_EXCEPTION, IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_DISCARDABLE,
    IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
};

use super::foundation::validate_pe;


/// Byte size of one x64 runtime-function table entry.
const RUNTIME_FUNCTION_ENTRY_SIZE: usize = 12;


/// Expresses how strongly independent PE signals support the selected primary code section.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodeSectionConfidence
{
    Low,
    Medium,
    High,
}


/// Reports whether x64 exception-directory function metadata corroborated the selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeFunctionEvidence
{
    NotPresent,
    Valid,
    Invalid,
}


/// Describes one mapped PE section and the code-location evidence associated with it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodeSectionLocation
{
    pub name: Box<str>,
    pub rva: usize,
    pub virtual_size: usize,
    pub raw_size: usize,
    pub mapped_size: usize,
    pub characteristics: u32,
    pub contains_entry_point: bool,
    pub contains_base_of_code: bool,
    pub runtime_function_count: usize,
    pub runtime_code_bytes: usize,
}


/// Owns the selected primary code section and the independently located loader entry section.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodeSectionAnalysis
{
    pub primary: CodeSectionLocation,
    pub entry_point: Option<CodeSectionLocation>,
    pub confidence: CodeSectionConfidence,
    pub candidate_count: usize,
    pub image_complete: bool,
    pub section_ranges_valid: bool,
    pub section_layout_valid: bool,
    pub overlapping_sections: bool,
    pub runtime_function_evidence: RuntimeFunctionEvidence,
}


/// Holds internal ranking state for one structurally valid mapped section.
struct CodeSectionCandidate
{
    location: CodeSectionLocation,
    end_rva: usize,
    score: i32,
}


/// Locates the most strongly supported primary code section in a mapped x64 PE image.
/// Selection combines `BaseOfCode`, `AddressOfEntryPoint`, section characteristics,
/// mapped-range validity, and x64 exception-directory function coverage. The loader entry
/// section is retained separately when it differs from the primary section.
///
/// `pe_data`: mapped image bytes indexed by RVA.
///
/// Returns an evidence-bearing analysis, or `None` when the headers or all section ranges
/// are invalid or no section carries credible code evidence.
pub fn locate_text_section(pe_data: &[u8]) -> Option<CodeSectionAnalysis>
{
    let pe = validate_pe::parse_pe(pe_data).ok()?;
    let nt_headers = &pe.nt_headers;
    let entry_point_rva = nt_headers.OptionalHeader.AddressOfEntryPoint as usize;
    let base_of_code_rva = nt_headers.OptionalHeader.BaseOfCode as usize;
    let image_size = nt_headers.OptionalHeader.SizeOfImage as usize;
    let sections = &pe.sections;
    let image_complete = image_size <= pe_data.len();
    let mut section_ranges_valid = true;
    let section_layout_valid = validate_pe::validate_parsed_pe(&pe, pe_data.len()).is_ok();
    let mut candidates = Vec::with_capacity(sections.len());

    for section in sections
    {
        // SAFETY: `Misc.VirtualSize` is the image-section union member used for mapped images.
        let virtual_size = unsafe { section.Misc.VirtualSize } as usize;
        let raw_size = section.SizeOfRawData as usize;
        let rva = section.VirtualAddress as usize;

        let mapped_size = validate_pe::get_mapped_section_size(section);

        if mapped_size == 0
        {
            continue;
        }

        let end_rva = match rva.checked_add(mapped_size)
        {
            Some(value) if value <= image_size && value <= pe_data.len() => value,
            _ =>
            {
                section_ranges_valid = false;
                continue;
            }
        };

        let contains_entry_point = entry_point_rva != 0 && entry_point_rva >= rva && entry_point_rva < end_rva;
        let contains_base_of_code = base_of_code_rva != 0 && base_of_code_rva >= rva && base_of_code_rva < end_rva;
        let name_length = section.Name.iter().position(|byte| *byte == 0).unwrap_or(section.Name.len());
        let name = String::from_utf8_lossy(&section.Name[..name_length]).into_owned().into_boxed_str();

        candidates.push(CodeSectionCandidate
        {
            location: CodeSectionLocation
            {
                name,
                rva,
                virtual_size,
                raw_size,
                mapped_size,
                characteristics: section.Characteristics,
                contains_entry_point,
                contains_base_of_code,
                runtime_function_count: 0,
                runtime_code_bytes: 0,
            },
            end_rva,
            score: 0,
        });
    }

    if candidates.is_empty()
    {
        return None;
    }

    let runtime_function_evidence = collect_runtime_function_evidence(pe_data, &pe, &mut candidates);
    let runtime_metadata_valid = runtime_function_evidence == RuntimeFunctionEvidence::Valid;

    if runtime_function_evidence == RuntimeFunctionEvidence::Invalid
    {
        for candidate in candidates.iter_mut()
        {
            candidate.location.runtime_function_count = 0;
            candidate.location.runtime_code_bytes = 0;
        }
    }

    let largest_runtime_function_count = candidates.iter().map(|candidate| candidate.location.runtime_function_count).max().unwrap_or(0);
    let largest_runtime_code_bytes = candidates.iter().map(|candidate| candidate.location.runtime_code_bytes).max().unwrap_or(0);

    for candidate in candidates.iter_mut()
    {
        candidate.score = score_code_section(candidate, runtime_metadata_valid, largest_runtime_function_count, largest_runtime_code_bytes);
    }

    let is_code_candidate = |candidate: &&CodeSectionCandidate|
    {
        let characteristics = candidate.location.characteristics;

        characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE) != 0 || (runtime_metadata_valid && candidate.location.runtime_function_count != 0)
    };
    let mut ranked_candidates: Vec<&CodeSectionCandidate> = candidates.iter().filter(is_code_candidate).collect();

    ranked_candidates.sort_unstable_by(|left, right|
    {
        right.score.cmp(&left.score).then_with(|| right.location.runtime_function_count.cmp(&left.location.runtime_function_count)).then_with(|| right.location.runtime_code_bytes.cmp(&left.location.runtime_code_bytes)).then_with(|| right.location.mapped_size.cmp(&left.location.mapped_size)).then_with(|| left.location.rva.cmp(&right.location.rva))
    });

    let primary_candidate = *ranked_candidates.first()?;
    let runner_up_score = ranked_candidates.get(1).map(|candidate| candidate.score);
    let candidate_count = ranked_candidates.len();
    let overlapping_sections = has_overlapping_sections(&candidates);
    let confidence = classify_code_section_confidence(primary_candidate, runner_up_score, runtime_function_evidence, image_complete, section_ranges_valid, section_layout_valid, overlapping_sections, entry_point_rva);
    let entry_point = candidates.iter().filter(|candidate| candidate.location.contains_entry_point).max_by(|left, right|
    {
        left.score.cmp(&right.score).then_with(|| left.location.runtime_function_count.cmp(&right.location.runtime_function_count)).then_with(|| right.location.rva.cmp(&left.location.rva))
    }).map(|candidate| candidate.location.clone());

    Some(CodeSectionAnalysis
    {
        primary: primary_candidate.location.clone(),
        entry_point,
        confidence,
        candidate_count,
        image_complete,
        section_ranges_valid,
        section_layout_valid,
        overlapping_sections,
        runtime_function_evidence,
    })
}


/// Attributes valid x64 exception-directory function ranges to their containing sections.
/// `pe_data`: mapped image bytes indexed by RVA.
/// `pe`: safely parsed PE32+ headers and sections describing the mapped image.
/// `candidates`: structurally valid sections receiving function counts and covered bytes.
///
/// Returns whether exception metadata is absent, valid, or structurally inconsistent.
fn collect_runtime_function_evidence(pe_data: &[u8], pe: &validate_pe::PeImage, candidates: &mut [CodeSectionCandidate]) -> RuntimeFunctionEvidence
{
    let nt_headers = &pe.nt_headers;
    let directory = match validate_pe::get_data_directory(pe, IMAGE_DIRECTORY_ENTRY_EXCEPTION as usize)
    {
        Some(value) => value,
        None => return RuntimeFunctionEvidence::NotPresent,
    };
    let directory_rva = directory.VirtualAddress as usize;
    let directory_size = directory.Size as usize;

    if directory_rva == 0 && directory_size == 0
    {
        return RuntimeFunctionEvidence::NotPresent;
    }

    if directory_rva == 0 || directory_size == 0
    {
        eprintln!("x64 exception directory has an incomplete RVA or size");
        return RuntimeFunctionEvidence::Invalid;
    }

    if directory_rva % 4 != 0
    {
        eprintln!("x64 exception directory is not DWORD aligned");
        return RuntimeFunctionEvidence::Invalid;
    }

    let directory_end = match directory_rva.checked_add(directory_size)
    {
        Some(value) if value <= nt_headers.OptionalHeader.SizeOfImage as usize && value <= pe_data.len() => value,
        _ =>
        {
            eprintln!("x64 exception directory exceeds the mapped PE image");
            return RuntimeFunctionEvidence::Invalid;
        }
    };

    if !candidates.iter().any(|candidate| directory_rva >= candidate.location.rva && directory_end <= candidate.end_rva)
    {
        eprintln!("x64 exception directory is not contained by a mapped PE section");
        return RuntimeFunctionEvidence::Invalid;
    }

    let mut metadata_valid = directory_size % RUNTIME_FUNCTION_ENTRY_SIZE == 0;
    let mut previous_begin_rva = None;

    for entry in pe_data[directory_rva..directory_end].chunks_exact(RUNTIME_FUNCTION_ENTRY_SIZE)
    {
        let begin_rva = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]) as usize;
        let end_rva = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]) as usize;
        let unwind_info_rva = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]) as usize;

        if begin_rva >= end_rva || end_rva > nt_headers.OptionalHeader.SizeOfImage as usize
        {
            metadata_valid = false;
            continue;
        }

        if previous_begin_rva.is_some_and(|previous| begin_rva <= previous)
        {
            metadata_valid = false;
        }

        previous_begin_rva = Some(begin_rva);

        if !validate_unwind_info(pe_data, nt_headers.OptionalHeader.SizeOfImage as usize, candidates, unwind_info_rva)
        {
            metadata_valid = false;
            continue;
        }

        let mut containing_section = None;

        for (section_index, candidate) in candidates.iter().enumerate()
        {
            if begin_rva < candidate.location.rva || end_rva > candidate.end_rva
            {
                continue;
            }

            if containing_section.is_some()
            {
                containing_section = None;
                metadata_valid = false;
                break;
            }

            containing_section = Some(section_index);
        }

        let section_index = match containing_section
        {
            Some(value) => value,
            None =>
            {
                metadata_valid = false;
                continue;
            }
        };
        let candidate = &mut candidates[section_index];

        candidate.location.runtime_function_count += 1;
        candidate.location.runtime_code_bytes = candidate.location.runtime_code_bytes.saturating_add(end_rva - begin_rva);
    }

    if !metadata_valid
    {
        eprintln!("x64 exception directory contains inconsistent function metadata");
        return RuntimeFunctionEvidence::Invalid;
    }

    RuntimeFunctionEvidence::Valid
}


/// Validates the mapped minimum extent of one x64 `UNWIND_INFO` record.
/// `pe_data`: mapped image bytes indexed by RVA.
/// `image_size`: the image size declared by the optional header.
/// `candidates`: structurally valid sections used to verify single-section containment.
/// `unwind_info_rva`: the DWORD-aligned image-relative unwind record address.
///
/// Returns `true` when the header, payload, and any fixed handler or chained trailer fit
/// entirely inside one mapped section.
fn validate_unwind_info(pe_data: &[u8], image_size: usize, candidates: &[CodeSectionCandidate], unwind_info_rva: usize) -> bool
{
    let header_end = match unwind_info_rva.checked_add(4)
    {
        Some(value) if unwind_info_rva % 4 == 0 && value <= image_size && value <= pe_data.len() => value,
        _ =>
        {
            eprintln!("x64 unwind information header is unaligned or outside the mapped PE image");
            return false;
        }
    };

    let header = &pe_data[unwind_info_rva..header_end];
    let version = header[0] & 0x07;
    let flags = header[0] >> 3;

    if !(1..=3).contains(&version)
    {
        eprintln!("x64 unwind information has an unsupported version");
        return false;
    }

    if version <= 2 && flags & !0x07 != 0
    {
        eprintln!("x64 unwind information has invalid version 1 or 2 flags");
        return false;
    }

    if version == 3 && flags & !0x0F != 0
    {
        eprintln!("x64 unwind information has invalid version 3 flags");
        return false;
    }

    let has_handler = flags & 0x03 != 0;
    let has_chained_info = flags & 0x04 != 0;

    if has_handler && has_chained_info
    {
        eprintln!("x64 unwind information combines incompatible handler and chained flags");
        return false;
    }

    let payload_units = header[2] as usize;

    let payload_bytes = if version == 3
    {
        if flags & 0x08 != 0 && payload_units == 0
        {
            eprintln!("x64 version 3 unwind information declares an empty epilog payload");
            return false;
        }

        payload_units * 2
    }
    else
    {
        ((payload_units + 1) & !1) * 2
    };
    let payload_end = match header_end.checked_add(payload_bytes)
    {
        Some(value) => value,
        None =>
        {
            eprintln!("x64 unwind information payload range overflowed");
            return false;
        }
    };

    let trailer_size = if has_chained_info
    {
        12
    }
    else if has_handler
    {
        4
    }
    else
    {
        0
    };
    let record_end = if trailer_size == 0
    {
        payload_end
    }
    else
    {
        let aligned_payload_end = match payload_end.checked_add(3)
        {
            Some(value) => value & !3,
            None =>
            {
                eprintln!("x64 unwind information trailer alignment overflowed");
                return false;
            }
        };

        match aligned_payload_end.checked_add(trailer_size)
        {
            Some(value) => value,
            None =>
            {
                eprintln!("x64 unwind information trailer range overflowed");
                return false;
            }
        }
    };

    if record_end > image_size || record_end > pe_data.len()
    {
        eprintln!("x64 unwind information extends beyond the mapped PE image");
        return false;
    }

    let containing_section_count = candidates.iter().filter(|candidate| unwind_info_rva >= candidate.location.rva && record_end <= candidate.end_rva).count();

    if containing_section_count != 1
    {
        eprintln!("x64 unwind information is not contained by exactly one mapped PE section");
        return false;
    }

    true
}


/// Scores one code-section candidate using independent header and runtime-table evidence.
/// `candidate`: the mapped section and evidence to rank.
/// `runtime_metadata_valid`: whether exception-directory evidence can be trusted.
/// `largest_runtime_function_count`: the strongest function-count signal in the image.
/// `largest_runtime_code_bytes`: the strongest function-coverage signal in the image.
///
/// Returns a relative score used only to rank sections within the same PE image.
fn score_code_section(candidate: &CodeSectionCandidate, runtime_metadata_valid: bool, largest_runtime_function_count: usize, largest_runtime_code_bytes: usize) -> i32
{
    let location = &candidate.location;
    let characteristics = location.characteristics;
    let mut score = 0;

    if location.contains_base_of_code
    {
        score += 45;
    }

    if location.contains_entry_point
    {
        score += 35;
    }

    if characteristics & IMAGE_SCN_CNT_CODE != 0
    {
        score += 30;
    }

    if characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    {
        score += 30;
    }

    if runtime_metadata_valid && location.runtime_function_count != 0
    {
        score += 25;

        if location.runtime_function_count == largest_runtime_function_count
        {
            score += 35;
        }

        if location.runtime_code_bytes == largest_runtime_code_bytes
        {
            score += 20;
        }
    }

    if characteristics & IMAGE_SCN_MEM_READ != 0
    {
        score += 5;
    }

    if characteristics & IMAGE_SCN_MEM_WRITE == 0
    {
        score += 5;
    }
    else
    {
        score -= 25;
    }

    if characteristics & IMAGE_SCN_MEM_DISCARDABLE != 0
    {
        score -= 20;
    }

    if location.name.eq_ignore_ascii_case(".text") || location.name.eq_ignore_ascii_case(".code") || location.name.eq_ignore_ascii_case("code")
    {
        score += 4;
    }

    if location.virtual_size == 0
    {
        score -= 10;
    }

    score
}


/// Detects ambiguous mapped ranges among structurally valid PE sections.
/// `candidates`: mapped sections whose half-open RVA ranges should be compared.
///
/// Returns `true` when any two section ranges overlap.
fn has_overlapping_sections(candidates: &[CodeSectionCandidate]) -> bool
{
    for (left_index, left) in candidates.iter().enumerate()
    {
        for right in candidates.iter().skip(left_index + 1)
        {
            if left.location.rva < right.end_rva && right.location.rva < left.end_rva
            {
                return true;
            }
        }
    }

    false
}


/// Classifies how decisively the selected section is supported over competing sections.
/// `primary`: the highest-ranked code-section candidate.
/// `runner_up_score`: the next candidate score when one exists.
/// `runtime_function_evidence`: whether x64 exception metadata was absent, valid, or invalid.
/// `image_complete`: whether the supplied byte buffer covers the declared image size.
/// `section_ranges_valid`: whether every nonempty section range fit the mapped image.
/// `section_layout_valid`: whether PE alignment, ordering, and header boundaries are coherent.
/// `overlapping_sections`: whether any mapped section ranges are ambiguous.
/// `entry_point_rva`: the loader entry-point RVA, or zero when the image has no entry point.
///
/// Returns a conservative confidence tier for the primary-section selection.
fn classify_code_section_confidence(primary: &CodeSectionCandidate, runner_up_score: Option<i32>, runtime_function_evidence: RuntimeFunctionEvidence, image_complete: bool, section_ranges_valid: bool, section_layout_valid: bool, overlapping_sections: bool, entry_point_rva: usize) -> CodeSectionConfidence
{
    let location = &primary.location;
    let characteristics = location.characteristics;
    let code_and_executable = characteristics & IMAGE_SCN_CNT_CODE != 0 && characteristics & IMAGE_SCN_MEM_EXECUTE != 0;
    let writable_or_discardable = characteristics & (IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_DISCARDABLE) != 0;
    let entry_point_agrees = entry_point_rva == 0 || location.contains_entry_point;
    let score_margin = runner_up_score.map(|score| primary.score - score).unwrap_or(i32::MAX);

    if runtime_function_evidence == RuntimeFunctionEvidence::Invalid || !image_complete || !section_ranges_valid || !section_layout_valid || overlapping_sections || writable_or_discardable
    {
        return CodeSectionConfidence::Low;
    }

    if code_and_executable && location.contains_base_of_code && entry_point_agrees && location.virtual_size != 0 && score_margin >= 20
    {
        return CodeSectionConfidence::High;
    }

    if code_and_executable && (location.contains_base_of_code || location.contains_entry_point || location.runtime_function_count != 0) && score_margin >= 15
    {
        return CodeSectionConfidence::Medium;
    }

    CodeSectionConfidence::Low
}