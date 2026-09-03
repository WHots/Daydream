# Raw-file debug-directory and PDB metadata collection

This directory parses `IMAGE_DEBUG_DIRECTORY` records and selected debug payloads
from an already validated x64 PE file. Its PDB-related responsibility is metadata
embedded in the PE—such as CodeView `RSDS`/`NB10` records and checksum data—not
opening, downloading, or parsing a standalone PDB file.

All reads borrow from the immutable byte buffer in `ValidatedPeFile`. The target
is never loaded or executed. The collector keeps readable header and raw payload
evidence even when a typed payload is unsupported, malformed, unavailable, or
blocked by a decoding budget.

## Module responsibilities

| File | Responsibility |
| --- | --- |
| `mod.rs` | Keeps implementation modules private and re-exports the collector entry point, entry limit, and result types within the crate. |
| `collector.rs` | Locates the debug directory, bounds entry traversal, reads every 28-byte header, resolves payload locations, tracks mismatches, and owns the shared parse budgets. |
| `codeview.rs` | Parses CodeView `RSDS`, `NB10`, and unknown four-byte signatures, including GUIDs, ages, and embedded PDB paths. |
| `payloads.rs` | Dispatches by debug type and parses VC feature, POGO, reproducible-build, miscellaneous, PDB-checksum, embedded Portable PDB, and extended-DLL-characteristics payloads. |
| `types.rs` | Defines debug-type classifications, typed payload models, parse-status variants, and the borrowed entry record. |

## End-to-end flow

```text
ValidatedPeFile
      |
      v
locate IMAGE_DIRECTORY_ENTRY_DEBUG
      |
      v
map the directory's raw-backed range
      |
      v
read at most 1,024 complete headers
      |
      v
resolve payload: file pointer first, RVA fallback second
      |
      v
dispatch through shared scan/decode budgets
      |
      +--> parsed typed details
      +--> raw / malformed / unavailable / limit status
      |
      v
Vec<FileDebugEntry<'file>>
```

`collect_file_debug_directory` is the public module entry point. Entries remain in
directory order and retain their original index.

## Debug-directory discovery

`get_debug_directory` reads the standard debug data-directory entry directly from
the validated raw file:

1. Read `e_lfanew` from DOS offset `0x3C`.
2. Calculate the optional-header offset after the PE signature and COFF header.
3. Read and bound `SizeOfOptionalHeader`.
4. Read the PE32+ `NumberOfRvaAndSizes` field at optional-header offset `108`.
5. Require index `6` (`IMAGE_DIRECTORY_ENTRY_DEBUG`) to exist.
6. Require the complete eight-byte directory entry to fit inside the declared
   optional header.
7. Require a nonzero directory RVA and at least one 28-byte entry.

The directory RVA is translated through `rva_to_file_range`. Collection uses the
smaller of the declared directory size and the remaining mapped raw region, then
counts only complete 28-byte records. The result is capped by
`MAX_DEBUG_DIRECTORY_ENTRIES` at 1,024 entries.

The saved `entry_limit_reached` field is true when 1,024 entries were retained. It
signals that the collector reached its cap; it does not independently prove that
another entry exists.

## Entry headers

Every retained `FileDebugEntry` contains the decoded fields of one
`IMAGE_DEBUG_DIRECTORY`:

| Field group | Values retained |
| --- | --- |
| Identity | directory index, raw type value, classified `FileDebugType` |
| Entry location | entry RVA and raw file offset |
| Header | characteristics, timestamp, major/minor version, payload size |
| Payload location | `AddressOfRawData`, `PointerToRawData`, mapped RVA offset, effective offset, mismatch flag |
| Evidence | optional borrowed raw payload and `FileDebugDetails` status/data |

Header field reads are little-endian and checked. An unreadable complete header or
overflow stops further entry traversal; entries already collected remain valid.

## Payload location resolution

Debug records can describe payload data with a raw file pointer, an RVA, or both.
`collect_debug_data` resolves them in this order:

1. For a zero-size payload, retain an available empty slice with no effective
   offset.
2. If `PointerToRawData` is nonzero and the full declared payload fits the file,
   use that raw file range.
3. Otherwise, if `AddressOfRawData` is nonzero, map its RVA and require the full
   payload to fit the same raw-backed mapped region.
4. If neither complete range is readable, mark the payload unavailable.

The collector separately maps `AddressOfRawData` when possible. If both location
forms exist and that RVA maps to a different file offset than
`PointerToRawData`, `data_location_mismatch` is true. The valid raw pointer still
has precedence for the effective payload.

## Debug-type classification

`FileDebugType::from(u32)` maps the standard raw values without discarding unknown
values:

| Value | Classification | Typed handling |
| ---: | --- | --- |
| 0 | `Unknown` | Empty becomes `None`; non-empty remains `Raw`. |
| 1 | `Coff` | Raw preservation only. |
| 2 | `CodeView` | `RSDS`, `NB10`, or unknown signature parsing. |
| 3 | `Fpo` | Raw preservation only. |
| 4 | `Misc` | `IMAGE_DEBUG_MISC` header and optional text. |
| 5 | `Exception` | Raw preservation only. |
| 6 | `Fixup` | Raw preservation only. |
| 7 | `OmapToSource` | Raw preservation only. |
| 8 | `OmapFromSource` | Raw preservation only. |
| 9 | `Borland` | Raw preservation only. |
| 10 | `Reserved10` | Raw preservation only. |
| 11 | `Clsid` | Raw preservation only. |
| 12 | `VcFeature` | Five little-endian counters. |
| 13 | `Pogo` | Signature and aligned procedure groups. |
| 14 | `Iltcg` | Raw preservation only. |
| 15 | `Mpx` | Raw preservation only. |
| 16 | `Reproducible` | Empty marker or length-prefixed hash. |
| 17 | `EmbeddedPortablePdb` | `MPDB` envelope sizes. |
| 18 | `Spgo` | Raw preservation only. |
| 19 | `PdbChecksum` | Algorithm name and checksum bytes. |
| 20 | `ExtendedDllCharacteristics` | One little-endian `u32`. |
| other | `Other(value)` | Raw preservation only. |

## Typed payload parsing

### CodeView

`parse_codeview` requires a four-byte signature:

- `RSDS` reads a GUID in PE/PDB field order, an age at offset `20`, and a
  non-empty NUL-terminated path at offset `24`.
- `NB10` reads its offset, signature/timestamp value, age, and a non-empty
  NUL-terminated path beginning at offset `16`.
- Any other four-byte signature becomes `FileCodeViewInfo::Other` and is retained
  without assuming a path layout.

CodeView paths are decoded lossily to preserve analyst-visible evidence. During
JSON serialization the path is split into full, directory, file-name, stem, and
extension strings. It is treated as inert untrusted text and is never accessed.

### VC feature

The payload must contain five little-endian `u32` counters: pre-VC11, C/C++, GS,
SDL, and guardN.

### POGO

The first four bytes are retained as the signature. Remaining records contain an
RVA, size, non-empty NUL-terminated name, and padding to the next four-byte
boundary. All-zero trailing bytes end the walk. Invalid records make the payload
malformed rather than returning a partial group list.

### Reproducible build

An empty payload is a valid reproducible marker. A non-empty payload begins with a
declared `u32` hash length. The collector retains at most the available hash bytes
and records whether declared and available lengths match.

### Miscellaneous

The fixed 12-byte prefix supplies data type, declared length, and an ANSI/Unicode
flag. The declared length must fit the payload. ANSI text stops at a zero byte;
UTF-16LE text requires an even byte count and stops at a zero word. Invalid UTF-16
code units become the Unicode replacement character.

### PDB checksum

A non-empty, NUL-terminated UTF-8 algorithm name must be followed by at least one
checksum byte. Both are retained.

### Embedded Portable PDB

The payload must begin with `MPDB`, followed by a little-endian uncompressed size.
The collector records that size and the remaining compressed byte count. It does
not decompress or parse the embedded Portable PDB.

### Extended DLL characteristics

The first four payload bytes are retained as a little-endian `u32` bit field. This
module does not interpret individual bits.

## Parse budgets and allocation safety

One `DebugParseBudget` is shared across every entry in a file. Both counters start
at the smaller of the validated file length and 8 MiB:

| Budget | Charged for |
| --- | --- |
| `scanned_bytes` | Full payload lengths for debug types that have typed parsers. |
| `decoded_bytes` | Retained dynamic strings, hashes, checksums, and POGO entry allocations. |

String charges use a conservative three-times-byte estimate, and arithmetic is
checked before allocation. POGO reserves one entry at a time only after charging
its estimated retained size. Exceeding either budget produces
`DecodeLimitExceeded`; it does not discard the already borrowed raw payload.

## Detail states

`FileDebugDetails` distinguishes why typed metadata is or is not present:

| State | Meaning |
| --- | --- |
| Typed variant | The selected payload parser succeeded. |
| `None` | An unsupported/unclassified payload was available but empty. |
| `Raw` | A non-empty unsupported payload was preserved without typed decoding. |
| `Malformed` | A supported payload failed structural parsing. |
| `DecodeLimitExceeded` | The shared scan or decoded-data budget was exhausted. |
| `Unavailable` | The declared payload could not be read completely from either location. |

This separation lets JSON consumers distinguish absent bytes from unsupported
formats and malformed supported data.

## Borrowing and raw evidence

`FileDebugEntry<'a>` borrows `raw_data` directly from `ValidatedPeFile.bytes`; no
second full payload copy is made. Parsed structures own only decoded data that
must outlive local parser buffers.

JSON records raw availability and declared/actual size metadata. The raw evidence
preview is capped at 64 bytes and reports whether it was truncated. Typed hashes
and checksums are serialized separately when their parser succeeds.

## Failure behavior

The public collector returns a vector rather than a typed error. Directory-level
problems can produce an empty result, and an entry-level failure can produce a
partial result. Checked-overflow, range, and header failures are reported on
stderr. Payload-level problems normally remain in the entry as one of the detail
states above.

Fatal PE validation and JSON-write failures are handled by the surrounding
raw-file pipeline, allowing unrelated file collectors to continue when only debug
metadata is damaged.

## JSON integration

`collect_file_triage` stores entries in `FileTriageCollection.debug_entries`.
`save_file_triage` serializes them to:

```text
<file_stem>_<sha256>/PEB/debug_directory.json
```

The JSON root contains the entry count, the 1,024-entry limit, the limit flag, and
the entry array. Each entry has type, location, header, payload-location, typed
details, and raw-evidence groups. Numeric locations and sizes generally include
both numeric and hexadecimal forms.

The `PEB` directory name is an output-layout convention; this collector analyzes
raw PE debug-directory data and does not inspect a live process PEB.

## Scope and limitations

- This module does not locate a PDB on disk, query a symbol server, or parse PDB
  streams such as DBI.
- Embedded Portable PDB data is identified but not decompressed.
- Unsupported debug types retain raw evidence but receive no type-specific parser.
- The collector requires complete declared payload ranges and does not stitch
  bytes across unrelated raw mappings.
- An empty or partial vector must be interpreted with stderr diagnostics because
  directory-level failures are not returned as typed errors.
- Results describe bytes stored in the raw file and do not represent loader or
  runtime modifications.

## Maintenance expectations

Preserve the entry cap, shared budgets, checked arithmetic, payload-location
precedence, borrowed raw slices, and explicit status distinctions unless a feature
requires a documented change. Any change to supported debug types, payload
layouts, limits, result fields, failure behavior, or JSON integration must update
this README in the same change.
