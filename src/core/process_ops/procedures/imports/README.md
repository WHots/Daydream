# Process import collection

This directory extracts standard PE imports from a previously validated mapped
main-image snapshot and finds direct x64 call and jump references to the imported
IAT slots. It does not reopen the process, reread remote image memory, or
revalidate PE structure.

The collector operates on `ValidatedProcessPe` for process identity and address
mapping, plus `ValidatedPeSnapshot` for RVA-indexed image bytes, validated PE
headers, sections, and loader-discarded ranges.

## Module responsibilities

| File | Responsibility |
| --- | --- |
| `mod.rs` | Defines import, xref, grouped process output, and collection-error types. It exposes the collector entry point. |
| `collector.rs` | Coordinates completeness checks, parsing, target selection, xref collection, address mapping, and grouping. |
| `parsing.rs` | Checks required snapshot ranges and parses standard import descriptors, lookup thunks, IAT slots, names, and ordinals. |
| `xrefs.rs` | Scans executable mapped sections for supported direct RIP-relative references to selected IAT RVAs. |

## End-to-end flow

```text
ValidatedProcessPe + ValidatedPeSnapshot
                  |
                  v
     preflight required ranges
                  |
                  v
       parse import directory
                  |
                  v
       collect unique IAT RVAs
                  |
                  v
 scan executable sections once for xrefs
                  |
                  v
 group xrefs by import and map locations
                  |
                  v
       ProcessImportCollection
```

`collect_process_imports_from_snapshot` is the module entry point. It first
checks whether loader-discarded bytes would make parsing or xref scanning
incomplete. It then builds the output entirely from the retained snapshot.

## Snapshot completeness preflight

`find_unavailable_import_range` returns the first recorded
`UnavailablePeRange` that overlaps data required for a complete result. It checks:

- The standard import directory containing the descriptor table.
- Each referenced DLL name, including its NUL terminator.
- Each import lookup-table thunk.
- Each corresponding IAT thunk.
- Each `IMAGE_IMPORT_BY_NAME` record required by a named thunk.
- Every executable section that must be scanned when at least one IAT target was
  found.

The lookup table uses `OriginalFirstThunk` when present and falls back to
`FirstThunk` otherwise. Ordinal thunks do not require an import-by-name range.

If a required range overlaps loader-discarded data, collection stops with
`IncompleteMainModuleSnapshot`. Successful results retain a copy of all snapshot
unavailable ranges, including ranges unrelated to imports, so output consumers
still have the image's availability context.

## Import parsing

`collect_import_entries_from_pe` reads only the standard import directory
identified by `IMAGE_DIRECTORY_ENTRY_IMPORT`:

1. `get_import_descriptors` obtains the directory from the already validated
   `PeImage`, checks its complete RVA range against the snapshot buffer, reserves
   the bounded descriptor count, and copies each possibly unaligned descriptor.
2. Descriptor traversal stops at the all-zero terminator.
3. The DLL name is read as a NUL-terminated UTF-8 string. A descriptor with an
   invalid name is skipped.
4. The selected lookup table is walked in 8-byte `IMAGE_THUNK_DATA64` entries
   until a zero thunk or an invalid range is reached.
5. A thunk with `IMAGE_ORDINAL_FLAG64` set becomes an ordinal import named
   `#<ordinal>`. Other thunks point to `IMAGE_IMPORT_BY_NAME`; the hint is skipped
   and the NUL-terminated UTF-8 function name is retained.
6. The matching IAT RVA is calculated from `FirstThunk` and the thunk index.
   `get_file_offset_from_pe` adds a raw-file offset only when the slot is backed
   by raw file data.

Imports remain in descriptor and thunk order. The parser uses checked arithmetic
and slice bounds throughout. A missing import directory produces an empty,
successful collection.

Malformed semantic import data does not currently produce a separate typed
error. Depending on where validation fails, the parser returns no imports, skips
one invalid descriptor or name, or stops the affected thunk walk. The PE
validator has already established structural image bounds, but it does not
guarantee that every import string and thunk is semantically valid.

## IAT cross-reference scanning

After parsing, the collector places the import IAT RVAs in a `HashSet`. This
deduplicates targets and provides constant-time membership checks during one scan
of each executable section.

The scanner recognizes these six-byte x64 RIP-relative forms beginning at the
`FF` opcode:

| Bytes | Result |
| --- | --- |
| `FF 15 <disp32>` | Direct indirect call through `[RIP + disp32]` |
| `FF 25 <disp32>` | Direct indirect jump through `[RIP + disp32]` |

The signed displacement is added to the RVA immediately following the six-byte
opcode sequence. A match is retained only when the resulting RVA exists in the
IAT target set. If a byte in the REX prefix range immediately precedes `FF`, the
recorded instruction RVA and file offset include that prefix.

This is a focused byte scanner, not a general disassembler or control-flow
analysis. Matching bytes in executable sections can occur in unreachable code,
instruction operands, or embedded data. The result proves that the supported
encoding references an imported IAT slot at that byte location; it does not prove
that the instruction executed.

Progress is measured over mapped bytes in executable sections and is reported at
64 KiB intervals and section boundaries. Xrefs are sorted by instruction RVA
after scanning.

## Grouping and locations

`build_process_import_info` groups flat xrefs by IAT RVA with a `HashMap`, then
emits one `ProcessImportInfo` for every parsed import. Import order is preserved,
and each import's xrefs retain instruction-RVA order.

Every location system remains explicit:

| Field | Meaning |
| --- | --- |
| `iat_rva` | IAT slot relative to the mapped main-image base. |
| `iat_address` | Checked `module_base_address + iat_rva`. |
| `iat_file_offset` | Raw-file offset when the IAT slot has raw backing. |
| `instruction_rva` | Referencing instruction relative to the image base. |
| `instruction_address` | Checked `module_base_address + instruction_rva`. |
| `instruction_file_offset` | Raw-file offset when the instruction has raw backing. |

Absolute-address overflow produces `None` rather than a wrapped address.

## Scope and limitations

- Only the standard import directory is parsed. Delay-load, bound-import, and
  other import-related directories are not collected here.
- Only the two supported direct RIP-relative `FF` call/jump forms are reported.
- Indirect register flows, rewritten code, and other instruction forms are not
  resolved.
- Invalid UTF-8 names are not retained.
- Process memory can change after the shared snapshot is acquired; this module
  intentionally reports the snapshot's point-in-time contents.

## Performance expectations

Import collection can scan every executable byte, so keep the hot path simple:

- Reuse the validated snapshot and `PeImage`; do not add remote-memory reads or
  repeat PE validation here.
- Parse the descriptor and thunk tables once, deduplicate IAT targets once, and
  scan each executable section once.
- Preserve constant-time target lookup and avoid per-byte allocation.
- Allocate only for retained descriptors, imports, xrefs, and grouped output.
- Keep progress reporting coarse enough that callbacks do not dominate scanning.
- Avoid generalized decoding or abstraction layers unless a required feature
  justifies their runtime and maintenance cost.

Any change to this directory's import behavior, supported encodings, output
types, limits, or workflow must update this README in the same change.
