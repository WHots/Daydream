use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER};

use crate::core::process_ops::utils::mem;

use super::locations::is_image_data_range;
use super::process::{validate_image_identity, validate_image_region, validate_matching_image, validate_process_image_details, ImageRegionDisposition};
use super::{PeReadTarget, PeValidationError, UnavailablePeRange, ValidatedPeImage, ValidatedPeSnapshot, MAXIMUM_IMAGE_REGION_COUNT};

/// Maximum mapped-image snapshot materialized for one process collector.
const MAXIMUM_IMAGE_SNAPSHOT_SIZE: usize = 0x1000_0000;

/// Maximum temporary allocation used for one process-image read.
const IMAGE_SNAPSHOT_READ_CHUNK_SIZE: usize = 0x10_0000;

/// Copies a previously validated process image without requiring discarded sections to remain committed.
/// `process`: the same open process handle used for strict PEB and image validation.
/// `validation`: the exact remote-image facts that the snapshot must still match.
///
/// Returns a bounded snapshot, discarded-range metadata, and a strictly matched PE view.
pub(crate) fn read_validated_image(process: HANDLE, validation: &ValidatedPeImage) -> Result<ValidatedPeSnapshot, PeValidationError>
{
    let details = validate_process_image_details(process, validation.base_address)?;

    validate_image_identity(validation, &details.validation)?;

    let (bytes, unavailable_ranges) = read_process_image_bytes(process, validation.base_address, &details.nt_headers, &details.sections)?;
    let pe = validate_matching_image(validation, &bytes)?;

    Ok(ValidatedPeSnapshot {
        bytes,
        pe,
        unavailable_ranges,
    })
}


/// Reports whether a snapshot range contains only bytes copied from readable image memory.
/// `snapshot`: validated mapped-image snapshot with discarded ranges recorded.
/// `rva`: first relative virtual address required by a collector.
/// `size`: exact number of required bytes.
///
/// Returns `true` only when the complete range is in bounds and available.
pub(crate) fn is_snapshot_range_available(snapshot: &ValidatedPeSnapshot, rva: usize, size: usize) -> bool
{
    let end_rva = match rva.checked_add(size)
    {
        Some(value) if value <= snapshot.bytes.len() => value,
        _ => return false,
    };
    if !is_image_data_range(&snapshot.pe.nt_headers, &snapshot.pe.sections, rva, size)
    {
        return false;
    }

    snapshot.unavailable_ranges.iter().all(|range| range.rva >= end_rva || range.rva.saturating_add(range.size) <= rva)
}


/// Copies committed image regions and leaves valid discarded-section ranges zero filled.
/// `process`: an open target-process handle with virtual-memory read access.
/// `image_base_address`: validated loaded-image allocation base.
/// `nt_headers`: validated headers defining the complete image span.
/// `sections`: validated section table used to recognize discardable ranges.
///
/// Returns an RVA-indexed image buffer, discarded ranges, or the exact mapping/read failure.
fn read_process_image_bytes(process: HANDLE, image_base_address: usize, nt_headers: &IMAGE_NT_HEADERS64, sections: &[IMAGE_SECTION_HEADER]) -> Result<(Vec<u8>, Vec<UnavailablePeRange>), PeValidationError>
{
    let image_size = nt_headers.OptionalHeader.SizeOfImage as usize;

    if image_size > MAXIMUM_IMAGE_SNAPSHOT_SIZE
    {
        eprintln!("remote PE image is too large to materialize safely");
        return Err(PeValidationError::ImageSnapshotSizeExceedsLimit {
            image_size,
            maximum_snapshot_size: MAXIMUM_IMAGE_SNAPSHOT_SIZE,
        });
    }

    let image_end = image_base_address.checked_add(image_size).ok_or_else(|| {
        eprintln!("remote PE snapshot range overflowed");

        PeValidationError::ImageRangeOverflow {
            base_address: image_base_address,
            image_size,
        }
    })?;
    let mut bytes = Vec::new();
    let mut unavailable_ranges: Vec<UnavailablePeRange> = Vec::new();

    bytes.try_reserve_exact(image_size).map_err(|_| {
        eprintln!("failed to allocate the remote PE snapshot buffer");

        PeValidationError::ImageBufferAllocationFailed {
            image_size,
        }
    })?;
    bytes.resize(image_size, 0);
    unavailable_ranges.try_reserve_exact(sections.len()).map_err(|_| {
        eprintln!("failed to allocate the discarded PE range buffer");

        PeValidationError::ImageBufferAllocationFailed {
            image_size,
        }
    })?;

    let mut address = image_base_address;
    let mut region_count = 0;

    while address < image_end
    {
        if region_count == MAXIMUM_IMAGE_REGION_COUNT
        {
            eprintln!("remote PE snapshot exceeded the virtual-memory region limit");
            return Err(PeValidationError::ImageRegionLimitExceeded {
                image_size,
                maximum_region_count: MAXIMUM_IMAGE_REGION_COUNT,
            });
        }

        region_count += 1;

        let region = mem::query_region(process, address).map_err(|error| {
            eprintln!("failed to query a remote PE snapshot region");

            PeValidationError::ImageRegionQueryFailed {
                address,
                error,
            }
        })?;
        let region_end = region.base_address.checked_add(region.region_size).ok_or_else(|| {
            eprintln!("remote PE snapshot region range overflowed");

            PeValidationError::ImageRegionRangeOverflow {
                base_address: region.base_address,
                region_size: region.region_size,
            }
        })?;

        if region.base_address > address || region_end <= address
        {
            eprintln!("remote PE snapshot region did not cover the requested address");
            return Err(PeValidationError::ImageRegionDidNotAdvance {
                address,
                region_end,
            });
        }

        let range_end = region_end.min(image_end);
        let disposition = validate_image_region(&region, address, range_end, image_base_address, nt_headers.OptionalHeader.SizeOfHeaders as usize, nt_headers.OptionalHeader.SectionAlignment as usize, sections)?;

        match disposition
        {
            ImageRegionDisposition::Readable =>
            {
                let mut read_address = address;

                while read_address < range_end
                {
                    let bytes_requested = (range_end - read_address).min(IMAGE_SNAPSHOT_READ_CHUNK_SIZE);
                    let region_bytes = mem::read_exact(process, bytes_requested, read_address).map_err(|error| {
                        eprintln!("failed to read a committed remote PE snapshot region");

                        PeValidationError::RemoteReadFailed {
                            target: PeReadTarget::ImageSnapshot,
                            address: read_address,
                            error,
                        }
                    })?;
                    let buffer_offset = read_address - image_base_address;
                    let buffer_end = buffer_offset + bytes_requested;

                    bytes[buffer_offset..buffer_end].copy_from_slice(&region_bytes);
                    read_address += bytes_requested;
                }
            }
            ImageRegionDisposition::Padding =>
            {}
            ImageRegionDisposition::Discarded =>
            {
                let rva = address - image_base_address;
                let size = range_end - address;
                let mut merged = false;

                if let Some(previous) = unavailable_ranges.last_mut()
                {
                    if previous.rva.checked_add(previous.size) == Some(rva)
                    {
                        previous.size += size;
                        merged = true;
                    }
                }

                if !merged
                {
                    unavailable_ranges.try_reserve(1).map_err(|_| {
                        eprintln!("failed to grow the discarded PE range buffer");

                        PeValidationError::ImageBufferAllocationFailed {
                            image_size,
                        }
                    })?;
                    unavailable_ranges.push(UnavailablePeRange {
                        rva,
                        size,
                    });
                }
            }
            ImageRegionDisposition::Unreadable =>
            {
                eprintln!("committed remote PE data is not readable");
                return Err(PeValidationError::UnreadableImageRegion {
                    address,
                    state: region.state,
                    protect: region.protect,
                });
            }
        }

        address = region_end;
    }

    Ok((bytes, unavailable_ranges))
}
