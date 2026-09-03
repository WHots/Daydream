# Raw-file import collection

This directory parses the standard import directory from an already validated x64
PE file and finds supported call and jump references to its Import Address Table
(IAT) slots. Everything operates on the immutable bytes owned by
`ValidatedPeFile`; the collector never loads or executes the target and never
attaches to a process.

The module returns structured records for JSON persistence. It does not print a
success summary. Invalid or unavailable import data is skipped where possible,
with diagnostics written to stderr.

## Module responsibilities

| File | Responsibility |
| --- | --- |
| `mod.rs` | Keeps the implementation modules private and re-exports the collector entry point and result types within the crate. |
| `collector.rs` | Orchestrates import parsing, deduplicates IAT targets, collects xrefs, and attaches each xref list to its import. |
| `parsing.rs` | Locates the standard import data directory and parses descriptors, DLL names, name/ordinal thunks, IAT RVAs, and raw file offsets. |
| `xrefs.rs` | Scans raw-backed executable sections for supported direct IAT references and near references to discovered import jump thunks. |
| `types.rs` | Defines the owned import record and the call/jump xref classifications. |

## End-to-end flow

```text
ValidatedPeFile
      |
      v
locate IMAGE_DIRECTORY_ENTRY_IMPORT
      |
      v
parse descriptors and 64-bit thunk tables
      |
      v
collect unique IAT RVAs
      |
      v
scan executable raw bytes for direct IAT references
      |
      v
scan for near calls/jumps to discovered IAT jump thunks
      |
      v
sort, deduplicate, and attach xrefs
      |
      v
Vec<FileApiImport>
```

`collect_file_api_imports` is the public module entry point. It calls
`collect_imports`, returns immediately when no imports were recovered, then places
every IAT RVA in a `HashSet` for constant-time xref target checks. Xrefs are grouped
by IAT RVA in a `HashMap` and moved into the corresponding import record without
changing descriptor or thunk order.

## Import-directory discovery

`get_import_directory` obtains the standard import data-directory entry directly
from the validated file bytes:

1. Read `e_lfanew` from DOS offset `0x3C`.
2. Calculate the optional-header offset after the four-byte PE signature and the
   20-byte COFF header.
3. Read `SizeOfOptionalHeader` from the COFF header and calculate its checked end.
4. Read `NumberOfRvaAndSizes` at PE32+ optional-header offset `108`.
5. Require directory index `1` (`IMAGE_DIRECTORY_ENTRY_IMPORT`) to exist.
6. Require the complete eight-byte directory entry to remain inside the declared
   optional header.
7. Read a nonzero RVA and a size large enough for at least one 20-byte import
   descriptor.

All additions and multiplications that can depend on file metadata use checked
arithmetic. RVA reads use `rva_to_file_range`, which accepts only bytes backed by
the validated headers or a section's raw data.

## Descriptor and thunk parsing

The descriptor walk is bounded by both the declared import-directory size and the
total file size. Each descriptor is read as an exact 20-byte mapped slice. Parsing
stops at the normal descriptor terminator where `OriginalFirstThunk`, `Name`, and
`FirstThunk` are all zero.

For every usable descriptor:

- `Name` must resolve to a non-empty, NUL-terminated UTF-8 DLL name inside one
  mapped raw region.
- `FirstThunk` must be nonzero because it supplies the IAT base.
- `OriginalFirstThunk` supplies the lookup table when present; otherwise the
  parser falls back to `FirstThunk`.
- The selected lookup table is walked in eight-byte `IMAGE_THUNK_DATA64` entries
  until a zero thunk or the end of its mapped raw region.
- A thunk with `IMAGE_ORDINAL_FLAG64` set becomes `#<ordinal>`, using its low
  16 bits.
- A name thunk is converted to an RVA, skips the two-byte hint, and retains a
  non-empty, NUL-terminated UTF-8 function name.
- The IAT RVA is `FirstThunk + thunk_index * 8`, calculated with checked
  arithmetic.
- `file_offset` is present only when the complete eight-byte IAT slot has raw
  backing.

Unreadable DLL names skip their descriptor. Unreadable function names, invalid
name RVAs, and individual arithmetic failures skip the affected thunk. A broken
descriptor or table boundary can stop the current walk. Imports successfully
decoded before a later failure remain available.

## IAT cross-reference scanning

`collect_iat_xrefs` inspects only sections whose characteristics include
`IMAGE_SCN_MEM_EXECUTE` and whose raw size is nonzero. The raw range must fit the
validated file buffer.

### Direct RIP-relative references

The first pass recognizes the six bytes beginning with the `FF` opcode:

| Bytes | Classification | Target calculation |
| --- | --- | --- |
| `FF 15 <disp32>` | `Call` | next instruction RVA plus signed `disp32` |
| `FF 25 <disp32>` | `Jump` | next instruction RVA plus signed `disp32` |

A candidate is retained only when the calculated target is an IAT RVA from the
parsed import set. When a byte in the x64 REX range `0x40..=0x4F` immediately
precedes `FF`, the recorded instruction RVA and file offset include that prefix.

Every retained `FF 25` jump is also recorded as a possible import thunk, mapping
the thunk instruction RVA to its IAT RVA.

### Near references to import thunks

When at least one import thunk was found, a second executable-section pass scans
the five-byte relative forms:

| Bytes | Classification | Required target |
| --- | --- | --- |
| `E8 <disp32>` | `Call` | A discovered `FF 25` import-thunk RVA |
| `E9 <disp32>` | `Jump` | A discovered `FF 25` import-thunk RVA |

The near instruction is associated with the IAT used by the target thunk. This
captures common compiler-generated calls or jumps that reach an import through a
local jump stub.

The scanner is intentionally focused and is not a general x64 decoder. It walks
bytes looking for these opcode forms, so a hit can occur in unreachable code,
embedded data, or bytes that a full disassembler would assign to another
instruction. A hit proves only that the byte sequence resolves to a collected IAT
or thunk RVA.

## Result types and ownership

`FileApiImport` owns its DLL name, import name, and xref vector. It stores:

| Field | Meaning |
| --- | --- |
| `library_name` | Decoded DLL name from the descriptor's `Name` RVA. |
| `import_name` | Decoded function name or synthesized `#<ordinal>` value. |
| `iat_rva` | RVA of the corresponding eight-byte IAT slot. |
| `file_offset` | Raw file offset of that slot when fully backed by file bytes. |
| `xrefs` | Sorted and deduplicated direct or thunk-mediated references. |

Each `FileApiXref` contains its `Call` or `Jump` kind plus the instruction RVA and
raw file offset. Xrefs sort by `(rva, file_offset)` and exact duplicates are
removed before attachment.

## Failure behavior

The public collector returns a vector rather than a typed error. A missing,
malformed, or inaccessible import directory can therefore produce an empty or
partial result. Diagnostics explain rejected ranges and overflow conditions on
stderr, while successful records remain suitable for saving.

This behavior is deliberate for file triage: local corruption should not prevent
unrelated collectors from analyzing the same validated target. Fatal raw-file
validation and output-write errors are handled outside this directory.

## JSON integration

`collect_file_triage` stores the returned vector in `FileTriageCollection.imports`.
`save_file_triage` serializes it to:

```text
<file_stem>_<sha256>/Imports/imports.json
```

The JSON root contains `count` and `imports`. Each import contains `library`,
`name`, an `iat` object, `xref_count`, and `xrefs`. Numeric RVAs and file offsets
are paired with hexadecimal strings; absent IAT file offsets serialize as null.
Xref kinds serialize as lowercase `call` or `jump`.

## Scope and limitations

- Only `IMAGE_DIRECTORY_ENTRY_IMPORT` is parsed. Delay-load, bound-import, and
  other import-related directories are outside this module.
- Only PE32+ eight-byte thunk entries are supported because raw-file validation
  accepts x86-64 images.
- Import names must be valid UTF-8; undecodable names are not retained.
- Only `FF 15`, `FF 25`, `E8`, and `E9` xref forms described above are recognized.
- Register-indirect data flow, address materialization, tail-call analysis, and
  general control-flow recovery are not attempted.
- Raw-file results describe stored bytes and do not prove that an instruction is
  reachable or executes at runtime.

## Maintenance expectations

Keep parsing bounded and direct: reuse `ValidatedPeFile`, preserve checked
arithmetic, avoid per-byte allocation in xref scans, and retain the current
two-pass maximum only when thunk discovery requires it. Any change to supported
directories, instruction forms, result fields, limits, failure behavior, or JSON
integration must update this README in the same change.
