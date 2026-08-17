> [!IMPORTANT]
> **AI-assisted development disclosure**
>
> AI assistance was used during the development of Daydream. **ChatGPT Sol** was the
> primary model and main development module used for the project. **Claude Opus 4.8**
> and **Fable** were also tried, but failed to perform adequately for the project's
> development needs. **Grok** was used purely for research and prototyping.

<p align="center">
  <img src="Assets/Images/image.png" alt="Daydream project banner" width="560">
</p>

<h1 align="center">Daydream</h1>

<p align="center">
  Windows x64 PE and process-memory triage for defensive reverse engineering.
</p>

> [!WARNING]
> <u>Daydream is still under active development. Interfaces, collectors, output schemas,
> and behavior may change without backward-compatibility guarantees.</u>
>
> <u>This project is intended only for defensive security, malware analysis, education,
> research, and inspection of software or systems you own or are explicitly authorized
> to analyze.</u>

## Table of contents

- [Overview](#overview)
- [How Daydream works](#how-daydream-works)
  - [Command dispatch](#command-dispatch)
  - [Raw-file pipeline](#raw-file-pipeline)
  - [Process pipeline](#process-pipeline)
  - [Locations and identity](#locations-and-identity)
  - [Fatal and partial failures](#fatal-and-partial-failures)
- [Project status](#project-status)
- [Intended usage](#intended-usage)
- [Current capabilities](#current-capabilities)
- [Requirements](#requirements)
- [Dependency roles](#dependency-roles)
- [Build and test](#build-and-test)
- [Usage](#usage)
- [Output structure](#output-structure)
- [Raw-file signature catalog](#raw-file-signature-catalog)
- [Extending and integrating](#extending-and-integrating)
- [Project layout](#project-layout)
- [Accuracy and limitations](#accuracy-and-limitations)
- [Development principles](#development-principles)
- [Contributing](#contributing)

## Overview

Daydream is a Windows-only, x86-64 Rust application for collecting structured triage
data from either:

- A running process and its mapped main image.
- A raw x64 Portable Executable file on disk.

The project is designed to give malware analysts, reverse engineers, security
researchers, students, and defenders a useful first-pass view before deeper analysis in
a debugger or disassembler. It combines PE structure, imports, strings, debug metadata,
process structures, raw-file pattern matches, and exact location metadata in one workflow.

Daydream is a triage tool. It is not intended to automatically declare that a file or
process is malicious. Collected values should be treated as analyst evidence and
correlated with surrounding code, provenance, behavior, and other tooling.

Daydream currently has no dynamically loaded plug-in system. In this document, a
component "plugs in" by being declared in the binary's module tree, called by the
appropriate orchestration layer, represented in its collection type, and serialized by
the matching output layer. The exact extension points are documented below.

## How Daydream works

The crate is organized around two analysis pipelines. They deliberately do not share a
target abstraction: a raw file has raw offsets and immutable bytes, while a process has
virtual addresses, changing memory protections, unavailable ranges, and an independently
validated disk image. Keeping those paths separate prevents a file parser from silently
assuming process-memory semantics, or the process path from treating mapped bytes like a
raw file.

```text
                         src/main.rs
                              |
                   parse zero or two arguments
                         /             \
              -f <path>                 -p <pid> / no arguments
                  |                                |
          process_file(...)                 process_target(...)
                  |                                |
       validate one raw PE                 open + verify handle access
                  |                                |
     collect from shared file bytes       validate PEB + mapped main image
                  |                                |
       print summary + save JSON          snapshot once + run collectors
                                                   |
                                          save versioned JSON
```

### Command dispatch

`src/main.rs` owns the complete module declaration tree and the CLI. It accepts exactly
one mode/value pair. `-f` calls `file_ops::file_processing::process_file`; `-p` calls
`process_ops::process_processing::process_target`. With no arguments, it passes
`std::process::id()` to process mode, so Daydream analyzes its own running image. Invalid
mode names, missing values, extra arguments, and non-numeric PIDs fail before analysis.

This is a binary crate, not a library crate. Most reusable-looking functions are
`pub(crate)` and are wired together internally; there is currently no stable Rust API
for another crate to import.

### Raw-file pipeline

Raw-file mode follows this sequence:

1. `validate_target_file` opens the target read-only with Windows file sharing, reads it
   once, and constructs a `ValidatedPeFile` that owns the bytes and checked PE metadata.
   It accepts AMD64 PE32+ executable images, rejects DLLs, validates section and entry
   point ranges, and caps the in-memory file at `0x10000000` bytes (256 MiB).
2. `collect_file_triage` lends that one validated object to the section, import/IAT,
   debug-directory, signature, and string collectors. Collectors do not reopen or execute
   the target.
3. `process_file` prints the human-readable summary.
4. `save_file_triage` computes SHA-256 and Shannon entropy, creates the output layout,
   and serializes each result as pretty JSON.

The raw-file output root is content-addressed with the SHA-256 digest. Running the same
scan again removes and recreates that exact output root before writing the new results.

### Process pipeline

Process mode follows a stricter identity and snapshot sequence:

1. `OpenProcess` requests only `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`.
   `CleanHandle` owns the handle and closes it on drop, while `NtQueryObject` confirms the
   handle actually contains the requested access mask.
2. `validate_process_peb` cross-checks the process ID from the handle and native process
   information, locates and validates the PEB, reads `BeingDebugged` and the main-image
   base, validates the mapped x64 PE, and compares its base/size with the first Toolhelp
   module entry.
3. Daydream tries to validate and hash the executable path reported by Toolhelp for a
   stable output identity. Failure does not prevent mapped-image triage.
4. `read_validated_image` creates one bounded, sparse-aware `ValidatedPeSnapshot`. Its PE
   identity must still match the earlier validation. Loader-discarded ranges that cannot
   be read are retained as explicit unavailable ranges. The complete validation stages
   and invariants are documented in
   [`validate_pe/readme.md`](src/core/process_ops/utils/foundation/validate_pe/readme.md).
5. `collect_validated_process_triage` passes the same validated process and snapshot
   through PE-section collection, PDB parsing, imports/IAT xref tracing, and TEB
   collection.
6. `save_process_triage` writes process schema version 4 JSON. The progress display uses
   one updating stderr line; detailed evidence goes to the output files.

### Locations and identity

Daydream keeps location systems explicit instead of treating them as interchangeable:

| Location | Meaning | Availability |
| --- | --- | --- |
| File offset | Byte position in the raw executable | Only for raw-backed bytes |
| RVA | Offset from the PE image base | Primary shared PE coordinate |
| Process address | `module_base + RVA` in the target | Process mode only, if addition is valid |
| Section | PE section containing the RVA | When a validated section covers it |

Process output roots prefer the SHA-256 of the validated backing file. If that file is
unavailable or invalid, Daydream hashes the mapped snapshot for the output identity and
records that no validated backing-file digest was available. Raw-file roots always use
the hash of the exact file bytes analyzed.

### Fatal and partial failures

Failures before a trustworthy analysis base exists are fatal. Examples include failing
to open a process, insufficient handle access, a process/PE identity mismatch, an invalid
raw PE, inability to create the mapped-image snapshot, or failure to save the final
output.

Collector-local problems are retained where the collection model supports them. Missing
PDB data, an unavailable import range, or a thread that exits during enumeration can
therefore appear as typed status/error
data beside the successful results. A completed command means the orchestration and save
succeeded; it does not imply that every target byte was readable.

## Project status

| Area | Current state |
| --- | --- |
| Development stage | Active development / prototype |
| Supported operating system | Windows only |
| Supported architecture | x86-64 / PE32+ |
| Rust toolchain | Stable `x86_64-pc-windows-msvc` |
| Process output schema | Version 4 |
| Public API stability | Not guaranteed |
| Primary interface | Command-line application |

<u>Do not treat the current output format, module boundaries, or collector behavior as a
stable public API yet.</u>

## Intended usage

Daydream is intended for legitimate defensive work such as:

- Inspecting malware samples inside a controlled analysis environment.
- Collecting indicators and structural evidence for incident response.
- Examining binaries during an authorized security assessment.
- Investigating software you own or have permission to reverse engineer.
- Learning Windows process structures, PE internals, imports, PDB records, and x64 code
  patterns.
- Producing JSON artifacts for later review, comparison, or integration into a defensive
  analysis pipeline.

Daydream must not be used to access systems or processes without authorization, deploy
payloads, evade defenders, or cause harm. Process-memory inspection is a dual-use
capability; responsibility for lawful and ethical use remains with the operator.

## Current capabilities

### Running-process triage

Process mode opens a target with query and memory-read access, validates its identity,
and reuses one validated main-image snapshot across its collectors.

Current process collectors include:

- Process identity, executable path, handle access, and PEB validation.
- Main-module base address, image size, entry-point RVA, and section table.
- Sparse mapped-image reads with explicit unavailable-range tracking.
- Standard PE imports and direct RIP-relative IAT call/jump references. The
  collection flow and supported encodings are documented in
  [`imports/readme.md`](src/core/process_ops/utils/imports/readme.md).
- CodeView PDB discovery for supported `RSDS` and `NB10` records.
- Per-thread TEB collection with identity and PEB-pointer checks.
- RVA, process address, section, and raw-file offset metadata where applicable.

Process mode keeps the terminal quiet during normal collection. It displays one updating
progress line containing the current phase and overall percentage, while detailed results
are written to JSON.

### Raw-file triage

File mode analyzes bytes on disk without loading the target as a process.

Current file collectors include:

- Strict x64 PE validation.
- File identity, SHA-256, Shannon entropy, raw size, and PE header metadata.
- Section layout, content classification, memory traits, RVA, and file offsets.
- Standard imports and supported direct IAT call/jump references.
- Debug-directory inspection and typed debug payload metadata.
- `RSDS`, `NB10`, POGO, VC feature, reproducible-build, checksum, miscellaneous, and
  embedded portable PDB-related records where supported.
- ASCII, UTF-8, and UTF-16LE string extraction.
- Wildcard-aware scanning of every raw-backed executable section through
  `X64_FILE_SCAN_SIGNATURES`, retaining repeated and overlapping matches.

File mode currently prints its collected summary to the console and also saves organized
JSON output.

## Requirements

- Windows x64.
- Rust through [rustup](https://rustup.rs/).
- The stable Rust toolchain.
- The `x86_64-pc-windows-msvc` target.
- Microsoft Visual Studio Build Tools with the MSVC linker and Windows SDK.
- Sufficient rights to open the selected process with query and virtual-memory read
  access.

The repository's `rust-toolchain.toml` selects:

```toml
[toolchain]
channel = "stable"
targets = ["x86_64-pc-windows-msvc"]
components = ["rustfmt", "clippy"]
```

Some protected, elevated, cross-session, security-sensitive, or architecture-mismatched
processes may remain inaccessible even when Daydream itself runs correctly.

## Dependency roles

The dependency set is intentionally small:

| Dependency | Role in Daydream |
| --- | --- |
| `windows-sys` | Low-level Win32 types, constants, process/thread APIs, Toolhelp snapshots, memory information, file access, console behavior, and Windows cryptography |
| `serde_json` | Construction and pretty serialization of analyst-facing JSON artifacts |
| Rust standard library | CLI parsing, paths/files, collections, checked arithmetic, owned buffers, and RAII |

The small native declarations in `core/internal/imports/imports.rs` link directly to
`ntdll` for `NtQueryObject`, `NtQueryInformationProcess`,
`NtQueryInformationThread`, `NtReadVirtualMemory`, and `NtQueryVirtualMemory`.
`core/internal/utils/handles.rs` wraps owned Win32 handles so normal and error exits close
them consistently.

## Build and test

Clone or open the repository from a Windows terminal and run:

```powershell
cargo build
cargo test
```

For an optimized build:

```powershell
cargo build --release
```

The release binary will be located at:

```text
target\release\daydream.exe
```

Useful development checks include:

```powershell
cargo check
cargo test
cargo clippy
```

## Usage

### Analyze the current Daydream process

Running without arguments falls back to process analysis of Daydream itself:

```powershell
cargo run
```

Or with a built binary:

```powershell
.\target\release\daydream.exe
```

### Analyze a running process by PID

```powershell
cargo run -- -p 1234
```

```powershell
.\target\release\daydream.exe -p 1234
```

The target must be a process Daydream is permitted to query and read. Running an elevated
terminal may be necessary for an authorized elevated target, but elevation does not
bypass Windows security boundaries or protected-process restrictions.

### Analyze a raw PE file

```powershell
cargo run -- -f "C:\Samples\target.exe"
```

```powershell
.\target\release\daydream.exe -f "C:\Samples\target.exe"
```

The current CLI accepts exactly one target mode and target value:

```text
usage: daydream [-f <executable path> | -p <process id>]
```

## Output structure

Output is created under the terminal's current working directory. JSON files are written
in pretty-printed form.

### Process output

Process roots use the target executable's file stem and SHA-256 identity:

```text
<process-name>_procdmp_<sha256>/
├── PE/
│   ├── image.json
│   ├── sections.json
│   └── pdb.json
├── Imports/
│   └── imports.json
└── PEB/
    ├── peb.json
    └── tebs.json
```

Process JSON preserves typed failure or partial-read information instead of silently
dismissing unavailable data. Reusing the same process output root updates retained JSON
and removes known outputs from the deleted pattern, opcode, and string collectors.

### Raw-file output

Raw-file roots use the target's file stem and SHA-256:

```text
<file-name>_<sha256>/
├── PE/
│   ├── file_metadata.json
│   └── sections.json
├── Imports/
│   └── imports.json
├── PEB/
│   └── debug_directory.json
├── Scanning/
│   └── signature_hits.json
└── strings.json
```

The existing raw-file output root is recreated when the same target content is scanned
again.

## Raw-file signature catalog

### Adding x64 analyst patterns

The x64 signature catalog lives in:

```text
src/core/data/patterns64/patterns64.rs
```

Patterns use `x64_signature!` and accept exact bytes plus one-byte wildcards. Contributors
can express a wildcard as `??`, `?`, or `WILDCARD`:

```rust
pub const EXAMPLE_SIGNATURE: Signature = x64_signature!(
    "example signature",
    [0x48, 0x8B, ??, 0xE8, WILDCARD, WILDCARD, WILDCARD, WILDCARD]
);
```

Each wildcard consumes exactly one byte; it is not a variable-length gap. Add each
signature to `X64_FILE_SCAN_SIGNATURES`. The raw-file scanner continues through every
available executable-section byte after a match, including overlapping occurrences.

## Extending and integrating

There are three common ways to plug new behavior into the current codebase.

### Add a raw-file collector

1. Put parsing logic under `src/core/file_ops/utils/` and make it consume
   `&ValidatedPeFile`. Use the checked byte/RVA helpers in `supports.rs` before adding new
   offset arithmetic.
2. Declare the module in the `core::file_ops::utils` tree in `src/main.rs`; this project
   currently uses an inline module tree rather than `mod.rs` files.
3. Add the collector result to `FileTriageCollection` and invoke it once in
   `collect_file_triage`.
4. Add its JSON builder and write call in `file_triage_saves.rs`. If it needs a new output
   directory, extend `FileTriageLayout` and `prepare_file_triage_layout` in `configs.rs`.
5. Add console presentation in `file_processing.rs` only when an interactive summary is
   useful; JSON is the integration surface for full results.
6. Add focused parser/range tests and run the checks in [Build and test](#build-and-test).

This path should never open, attach to, or execute the target.

### Add a process collector

1. Put process-specific logic under `src/core/process_ops/utils/`. Prefer consuming
   `&ValidatedProcessPe` and `&ValidatedPeSnapshot` so the target is not independently
   revalidated or reread.
2. Declare the module in `src/main.rs`.
3. Add a field to `ProcessTriageCollection` and call the collector from
   `collect_validated_process_triage`. Keep expensive phases connected to the existing
   progress callback.
4. Preserve partial-read and unavailable-range information in a typed result instead of
   flattening it into an empty collection.
5. Add a JSON builder/write in `process_triage_saves.rs`; define stable directory and
   file names in `process_ops/outputs/config.rs`.
6. Increment `PROCESS_TRIAGE_SCHEMA_VERSION` when the change breaks the meaning or shape
   expected by existing process-output consumers.

Process collectors should use only the access already requested unless a feature has a
documented need for more. Expanding the process access mask changes the tool's security
and compatibility profile and should be treated as an architectural change.

### Add a raw-file signature

Catalog-only additions do not require another orchestrator:

- Add a wildcard-aware signature to `patterns64.rs` and include it in
  `X64_FILE_SCAN_SIGNATURES` as described in
  [Raw-file signature catalog](#raw-file-signature-catalog).

Every new detection should document what the raw bytes prove and likely false-positive
conditions.

### Consume Daydream from another tool

The supported integration point today is the command plus its JSON output:

```powershell
$daydream = ".\target\release\daydream.exe"
& $daydream -f "C:\Samples\target.exe"
if ($LASTEXITCODE -ne 0)
{
    throw "Daydream analysis failed"
}
```

Use the content-addressed output directory to associate results with a target. Process
JSON includes `schema_version`; check it before relying on field shapes. Raw-file JSON
does not yet carry an explicit schema version, so consumers should tolerate additional
fields and treat its current shape as unstable. Numeric locations are generally paired
with formatted hexadecimal strings for display, but automation should use the numeric
field.

Embedding Daydream as a Rust dependency would currently require a deliberate refactor:
add a library target, move the inline module declarations out of `main.rs`, decide which
types form a supported public API, and separate console/output policy from collection.
Until that work is done, depending on internal module paths is not supported.

## Project layout

```text
src/
├── main.rs                         CLI parsing and mode dispatch
└── core/
    ├── data/
    │   └── patterns64/
    │       └── patterns64.rs       wildcard-aware x64 signature catalog
    ├── file_ops/
    │   ├── file_processing.rs      raw-file orchestration and console presentation
    │   ├── outputs/
    │   │   ├── configs.rs          raw-file output layout
    │   │   └── file_triage_saves.rs
    │   └── utils/
    │       ├── apis.rs             imports and direct IAT references
    │       ├── pdb.rs              debug-directory and CodeView parsing
    │       ├── scanning.rs         executable-section signature scanning
    │       ├── sections.rs         section metadata and traits
    │       ├── strings.rs          raw-file string collection
    │       ├── supports.rs         checked PE byte/RVA helpers
    │       └── validate.rs         x64 raw-file validation
    ├── process_ops/
    │   ├── process_processing.rs   process orchestration and progress reporting
    │   ├── outputs/
    │   │   ├── config.rs           process dump layout and filenames
    │   │   └── process_triage_saves.rs
    │   └── utils/
    │       ├── foundation/
    │       │   └── validate_pe/
    │       │       ├── AGENTS.md    local maintenance and performance guidance
    │       │       ├── readme.md    validation pipeline and invariants
    │       │       ├── mod.rs       validation types and module interface
    │       │       ├── locations.rs section metadata and RVA/file locations
    │       │       ├── parsing.rs   mapped PE parsing and structural validation
    │       │       ├── process.rs   remote image identity and mapping validation
    │       │       └── snapshot.rs  bounded image copying and unavailable ranges
    │       ├── imports/
    │       │   ├── AGENTS.md       local maintenance and performance guidance
    │       │   ├── readme.md       import parsing and IAT-xref pipeline
    │       │   ├── mod.rs          import types and module interface
    │       │   ├── collector.rs    import collection and result grouping
    │       │   ├── parsing.rs      descriptors, thunks, names, and ordinals
    │       │   └── xrefs.rs        direct IAT call and jump references
    │       ├── memutils.rs         memory reads and region queries
    │       ├── pdbutils.rs         process main-module PDB metadata
    │       ├── processutils.rs     process, PEB, and main-module validation
    │       └── tebutils.rs         per-thread TEB collection
    ├── internal/
    │   ├── imports/imports.rs
    │   └── utils/handles.rs        owned Win32 handle wrapper
    └── global_utils/
        └── fileutils.rs            SHA-256, entropy, and JSON writing
```

## Accuracy and limitations

- Raw-file wildcard pattern hits prove only that matching bytes are present; they are not
  decoded instruction semantics or proof that the matched behavior executed.
- File offsets may be unavailable for mapped bytes that do not correspond to raw-backed
  file data.
- Process memory can change while collection is running. Threads may exit, stacks may
  change, and pages may become inaccessible.
- Loader-discarded, guarded, reserved, protected, or unreadable ranges can produce partial
  results. Daydream records these conditions when its collector shape supports them.
- Direct IAT xref collection currently focuses on supported x64 RIP-relative call and jump
  forms; it is not a complete disassembler or control-flow engine.
- Daydream does not replace a debugger, disassembler, sandbox, YARA engine, EDR product,
  or analyst judgment.

## Development principles

- Validate once and reuse structured PE/process state.
- Preserve RVA, process address, file offset, section, and completeness metadata.
- Keep raw-file operations separate from target-process operations.
- Retain typed partial failures instead of treating every unavailable page as a total scan
  failure.
- Restrict process access to the rights required for query and memory inspection.
- Prefer exact, contextual evidence over generic byte fragments.
- Keep large scans bounded and report progress for expensive phases.
- Assume Windows x64 directly; the project intentionally does not provide cross-platform
  fallback stubs.

## Contributing

Daydream is evolving quickly. Before making changes:

1. Read `AGENTS.md` and `CLAUDE.md` for repository-specific rules.
2. Keep new raw-file collectors under `file_ops` and process-memory collectors under
   `process_ops`.
3. Reuse the validated file or process snapshot instead of reparsing or rereading without
   a clear need.
4. Add focused tests for matching, range, parser, or output behavior.
5. Run at least:

   ```powershell
   cargo check
   cargo test
   cargo build
   ```

6. Treat detections as evidence and document known false-positive conditions.

Contributions must remain within the project's defensive, authorized malware-analysis and
reverse-engineering purpose.
