# Process PE validation

This directory validates the x64 PE image mapped as a target process's main
module. It turns untrusted remote headers and memory-region metadata into a
bounded `ValidatedPeSnapshot` that downstream collectors can share without
reopening or repeatedly copying the image.

The validator handles mapped-image bytes, where indexes are RVAs. It does not
replace the raw-file validator in `file_ops/utils/validate.rs`, where indexes
are file offsets.

## Module responsibilities

| File | Responsibility |
| --- | --- |
| `mod.rs` | Defines the shared validated-image, snapshot, section, unavailable-range, and error types. It also exposes the small module interface used by collectors. |
| `parsing.rs` | Performs bounded parsing and strict structural validation of copied DOS, NT, optional, and section headers. |
| `process.rs` | Reads remote headers, validates the live image mapping, builds a deterministic PE identity, and compares validation passes. |
| `snapshot.rs` | Revalidates the live image, copies readable regions into one bounded RVA-indexed buffer, and records loader-discarded ranges. |
| `locations.rs` | Reuses validated headers for data-directory lookup, section metadata, mapped section sizes, RVA-to-file-offset conversion, and range checks. |

## End-to-end flow

The normal process pipeline has two validation stages around a single snapshot:

```text
PEB main-image base
        |
        v
validate_process_image
  remote headers -> structural checks -> mapping checks -> PE identity
        |
        v
ValidatedPeImage
        |
        v
read_validated_image
  revalidate remote identity -> copy regions -> validate copied bytes and identity
        |
        v
ValidatedPeSnapshot
        |
        +--> section metadata
        +--> PDB parsing
        +--> imports and IAT cross-references
```

`process::validate_process_peb` obtains the candidate base address from the
PEB and calls `validate_process_image`. Outside this directory, it also compares
the validated base and image size with the first Toolhelp module entry.

### 1. Validate the live image

`validate_process_image` delegates to `validate_process_image_details`, which:

1. Rejects a null process handle or image base.
2. Reads the DOS header and validates its signature and aligned `e_lfanew`.
3. Reads the PE signature and COFF prefix, then reads only the declared optional
   header length.
4. Validates the x64 NT and optional headers and calculates the bounded section
   table range.
5. Reads the complete section table in one exact remote-memory operation.
6. Validates section layout and mapped data-directory ranges.
7. Walks every virtual-memory region through `SizeOfImage` and confirms that it
   belongs to the same image allocation.
8. Serializes critical header, directory, and section fields into an exact PE
   identity stored by `ValidatedPeImage`.

The result retains the image base, image size, entry-point RVA, section count,
and private identity bytes. Callers can keep this small record without retaining
the temporary remote header buffers.

### 2. Revalidate and snapshot

`read_validated_image` does not assume the earlier process state is unchanged.
It repeats live header, section, and mapping validation, then compares the new
identity with the original `ValidatedPeImage` before copying memory.

The snapshot reader allocates one zero-initialized buffer indexed by RVA and
walks the image's memory regions again:

- Readable committed `MEM_IMAGE` ranges are copied in chunks of at most 1 MiB.
- Alignment padding remains zero-filled and is not treated as image data.
- Valid loader-discarded section ranges remain zero-filled and are recorded as
  merged `UnavailablePeRange` entries.
- Guarded, no-access, or execute-only non-padding ranges cause the snapshot to
  fail instead of silently returning incomplete bytes.

After copying, `validate_matching_image` strictly parses the snapshot and checks
its size and PE identity against the original validation. The returned
`ValidatedPeSnapshot` therefore contains one shared byte buffer, its validated
`PeImage` view, and explicit unavailable ranges.

Downstream parsers must call `is_snapshot_range_available` before consuming a
range that could overlap discarded data. That helper also rejects overflow,
out-of-bounds ranges, and bytes that occupy alignment padding rather than actual
headers or section data.

## Structural invariants

Validation rejects the image unless all relevant invariants agree:

- The image is an executable AMD64 PE32+ image with valid DOS and NT signatures.
- Optional-header size and declared data-directory count fit the copied header.
- Reserved optional-header fields and reserved data directories are zero.
- The section count is between 1 and the Windows loader limit of 96.
- File and section alignment obey the normal and low-alignment PE rules.
- `SizeOfHeaders`, `SizeOfImage`, the preferred image base, the entry point, and
  every checked arithmetic range are valid and bounded.
- Section RVAs are aligned, adjacent, non-overlapping, and end at the declared
  image size; raw ranges are aligned, ordered, and non-overlapping.
- `BaseOfCode` identifies the first code section, and a nonzero entry point lies
  in an executable section.
- Mapped data directories occupy actual headers or section bytes rather than
  alignment padding. Certificate-table metadata is handled as a file range.
- Every committed live region belongs to the same `MEM_IMAGE` allocation.
  Reserved ranges are accepted only when they are alignment padding or data from
  discardable sections.

The live image walk is limited to 4,096 virtual-memory regions. Strict mapped-image
validation accepts images up to 2 GiB, while materialized process snapshots are
limited to 256 MiB. Allocation and address arithmetic failures are returned as typed
`PeValidationError` variants.

## Identity matching

The identity is an exact byte sequence assembled from the critical PE signature,
COFF fields, optional-header fields, declared data directories, and section-table
fields. It is compared byte-for-byte between validation passes. The FNV-1a value
in an identity-mismatch error is diagnostic only; it is not used as the equality
or security decision.

This detects meaningful header or section-table changes between initial process
validation, snapshot acquisition, and validation of the copied image.

## Location helpers

Collectors should reuse the `PeImage` already stored in the snapshot:

- `collect_sections_from_pe` produces stable section metadata without reparsing.
- `get_data_directory` respects both the declared directory count and the
  optional-header size.
- `get_mapped_section_size` uses `VirtualSize`, falling back to `SizeOfRawData`
  only when the virtual size is zero.
- `get_file_offset_from_pe` translates an RVA only when it is backed by raw-file
  bytes. Mapped zero-fill and padding correctly return `None`.

## Performance expectations

This validation path runs before every process collector, so keep its hot path
direct and bounded:

- Reuse validated headers, section vectors, identities, and the shared snapshot.
- Prefer one pass over sections or regions and one exact read for known-size
  header tables.
- Avoid repeated remote reads, reparsing, temporary copies, and unnecessary
  allocation growth.
- Keep hard limits and checked arithmetic in place before allocating or reading.
- Add abstraction only when it removes repeated work or makes a required
  invariant materially clearer.

Any change to this directory's validation code or workflow must update this
README in the same change.
