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
- [Project status](#project-status)
- [Intended usage](#intended-usage)
- [Current capabilities](#current-capabilities)
- [Requirements](#requirements)
- [Build and test](#build-and-test)
- [Usage](#usage)
- [Output structure](#output-structure)
- [Pattern and opcode catalogs](#pattern-and-opcode-catalogs)
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
process structures, pattern matches, opcode hits, and exact location metadata in one
workflow.

Daydream is a triage tool. It is not intended to automatically declare that a file or
process is malicious. Collected values should be treated as analyst evidence and
correlated with surrounding code, provenance, behavior, and other tooling.

## Project status

| Area | Current state |
| --- | --- |
| Development stage | Active development / prototype |
| Supported operating system | Windows only |
| Supported architecture | x86-64 / PE32+ |
| Rust toolchain | Stable `x86_64-pc-windows-msvc` |
| Process output schema | Version 1 |
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
- Evidence-based x64 code-section selection using PE structure, entry-point,
  `BaseOfCode`, and runtime-function information.
- Standard PE imports and direct RIP-relative IAT call/jump references.
- CodeView PDB discovery for supported `RSDS` and `NB10` records.
- ASCII, UTF-8, and UTF-16LE strings from the mapped main image.
- Per-thread TEB collection with identity and PEB-pointer checks.
- Region-by-region string scanning between trusted TEB `StackLimit` and `StackBase`
  values.
- Every configured x64 analyst signature from `patterns64.rs`.
- Breakpoint, debug-trap, and debug-register opcode hits from `opcodes64.rs`.
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
- Wildcard-aware executable-section scanning through `X64_FILE_SCAN_SIGNATURES`.

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
├── PEB/
│   ├── peb.json
│   └── tebs.json
├── Patterns/
│   ├── code_section.json
│   ├── pattern_hits64.json
│   └── opcode_hits64.json
└── strings.json
```

Key pattern outputs are:

- `code_section.json` — selected code-section evidence and confidence.
- `pattern_hits64.json` — the distinguished CRT entry signature and every configured
  `X64_ANALYST_SIGNATURES` match.
- `opcode_hits64.json` — every configured breakpoint/debug opcode match, including
  ModR/M metadata where required.

Process JSON preserves typed failure or partial-read information instead of silently
dismissing unavailable data. Reusing the same process output root updates the generated
JSON files and removes obsolete legacy pattern filenames.

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

## Pattern and opcode catalogs

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

Each wildcard consumes exactly one byte; it is not a variable-length gap. After declaring
a signature, add it to the catalog matching its intended scope:

- `X64_CRT_STARTUP_SIGNATURES`
- `X64_RUNTIME_ANCHOR_SIGNATURES`
- `X64_ANTI_ANALYSIS_SIGNATURES`
- `X64_FILE_SCAN_SIGNATURES`
- `X64_ANALYST_SIGNATURES`

Process pattern collection consumes `X64_ANALYST_SIGNATURES`. Raw-file scanning consumes
`X64_FILE_SCAN_SIGNATURES`.

### Adding x64 opcode records

Breakpoint and debug-related opcode data lives in:

```text
src/core/data/opcode_specific64/opcodes64.rs
```

Each `OpcodeBytecode` provides a name, an exact opcode prefix, and a `requires_modrm`
flag. Records intended for process scanning must be included in
`X64_BREAKPOINT_OPCODE_BYTECODES`.

For opcodes such as `0F 21` and `0F 23`, the collector requires and validates a trailing
register-form ModR/M byte before recording a hit.

## Project layout

```text
src/
├── main.rs                         CLI parsing and mode dispatch
└── core/
    ├── data/
    │   ├── opcode_specific64/
    │   │   └── opcodes64.rs        x64 breakpoint/debug opcode catalog
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
    │       ├── detect_code_section_utils.rs
    │       ├── foundation/
    │       │   └── validate_pe.rs  mapped-image validation and snapshotting
    │       ├── importutils.rs      process imports and IAT references
    │       ├── memutils.rs         memory reads and region queries
    │       ├── pdbutils.rs         process main-module PDB metadata
    │       ├── pe_utils.rs         sections, locations, patterns, and opcodes
    │       ├── processutils.rs     process, PEB, and main-module validation
    │       ├── stringdumputils.rs  main-image and TEB-stack strings
    │       ├── strings.rs          shared string decoding primitives
    │       └── tebutils.rs         per-thread TEB collection
    ├── internal/
    │   ├── imports/imports.rs
    │   └── utils/handles.rs        owned Win32 handle wrapper
    └── global_utils/
        └── fileutils.rs            SHA-256, entropy, and JSON writing
```

`src/core/internal/saves/structure.rs` also exists in the repository but is not currently
declared by `src/main.rs`.

## Accuracy and limitations

- A pattern or opcode hit proves only that matching bytes were present in the scanned
  range. It does not prove malicious intent or execution.
- Short opcode patterns—especially `INT3` (`0xCC`)—may also represent compiler padding,
  alignment, data embedded in executable sections, or legitimate debugger behavior.
- Wildcard patterns are byte patterns, not decoded instruction semantics.
- File offsets may be unavailable for mapped bytes that do not correspond to raw-backed
  file data.
- Process memory can change while collection is running. Threads may exit, stacks may
  change, and pages may become inaccessible.
- Loader-discarded, guarded, reserved, protected, or unreadable ranges can produce partial
  results. Daydream records these conditions when its collector shape supports them.
- Stack strings may be stale artifacts left behind after a function returns.
- TEB stack scanning uses committed readable regions and skips guard or inaccessible
  pages. Strings split across unreadable boundaries may not be recoverable.
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
