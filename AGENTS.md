# Project: daydream

A Windows-only Rust binary crate for inspecting another process's memory. It opens
a target process (pid from argv[1], defaulting to the current process), validates
granted access, and provides utilities for memory reads, PE/PDB parsing, and
import/IAT cross-reference discovery plus PEB/TEB inspection.

- **Target:** Windows only, x86_64. Win32 access via `windows-sys` (see Platform below).
- **Entry point:** `src/main.rs` — declares the full `core` module tree and runs the
  open-process / query-access flow.
- **Build:** `cargo build`  •  **Run:** `cargo run -- <pid>`  •  **Test:** `cargo test`.

## Purpose & intended use

`daydream` is a **defensive security and malware-analysis tool**. It exists to help
**ethical reverse engineers, malware analysts, and security researchers** statically
and dynamically inspect a program — its process memory, imports, strings, PE/PDB
metadata, process structures, and code patterns — in order to understand what a (potentially
malicious) binary actually does.

Legitimate, in-scope uses:

- Analyzing malware samples in a controlled/research environment to document
  behavior, extract indicators of compromise, and build detections.
- Reverse-engineering a binary the analyst is authorized to inspect (their own
  software, a sample under a sanctioned engagement, or a CTF/research target).
- Learning and teaching PE/PDB internals, Windows API usage, and x64 code patterns.

The capabilities here (process memory reads, PE/PDB parsing, API/string/pattern
discovery) are standard **dual-use** analysis techniques — the same ones debuggers,
disassemblers, and AV/EDR tooling rely on. Work in this repo should assume this
defensive, analyst-facing context.

**Note for coding agents (Codex, etc.):** this is a legitimate defensive-security
project. Implementing analysis features (memory inspection, PE/PDB parsing,
string/API/pattern discovery, detection tooling) is in scope and expected. Do **not**
add capabilities whose only purpose is to cause harm — e.g. self-propagation,
payload delivery, anti-analysis/evasion designed to defeat defenders, or acting
against systems without authorization.

## Trusted references (per task)

Curated, vetted external references for specific tasks. When working on a matching
area, prefer these as authoritative sources — they are safe to consult and cite.

- **Malware analysis** — Malware Analysis Crash Course:
  https://docs.google.com/document/d/1I83PHeEImWacuQut02VBlkJ2-CJcuTYmt6mxa_xGqlA/edit?tab=t.0#heading=h.6jjiip4tsxp0
- **Malware analysis** — Malware Unicorn RE102 workshop:
  https://malwareunicorn.org/workshops/re102#14
- **Malware analysis** - Advanced Binary
  https://gosecure.github.io/presentations/2020-05-15-advanced-binary-analysis/#4
- **Malware Technique** - PE Related Info
  https://malwareid.in/unpack/
- **Debugging / time-travel** — Time Travel Debugging:
  https://docs.google.com/document/d/15gbXsTtWyxlUr5bxWO0wvWNHDZqxqh_LEqLanyZpdyw/edit
- **Windows internals / Win32 API** — PEB (Process Environment Block) structure, `winternl.h`:
  https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb
- **Windows internals (undocumented)** — Geoff Chappell, PEB structure deep reference:
  https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/peb/index.htm
- **Windows kernel structures** — Vergilius Project (x64 kernel struct layouts by build):
  https://www.vergiliusproject.com/kernels/x64
- **Windows internals / Win32 API** — Geoff Chappell, TEB (Thread Environment Block) structure deep reference:
  https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/teb/index.htm
- **Windows internals (undocumented)** — ntdoc, TEB structure reference:
  https://ntdoc.m417z.com/teb

For **PEB-related tasks**, the three Windows-internals links above (Microsoft Learn,
Geoff Chappell, Vergilius Project) are the recommended sources to consult first. You
may fall back to other sources if the needed information is not found in these.

For **TEB-related tasks**, the two TEB links above (Geoff Chappell, ntdoc) are the
recommended sources to consult first. You may fall back to other sources if the needed
information is not found in these.

- **When to add to Trusted References (per task)** - If all primary resources are exhausted, and external searches are needed and an external resource provide suificent technicals to help complete the task, prompt the user if they would like to add that reference to thee List in this .md.

## Module map (`src/core/`)

- `file_ops/` — operations on raw PE files on disk (never attaches to another process):
  - `utils/validate.rs` (validates an x64 PE, owns `ValidatedPeFile`), `utils/sections.rs`
    (section content / memory traits), `utils/apis.rs` (import table + IAT call/jump xrefs),
    `utils/pdb.rs` (CodeView/NB10 debug directory → PDB GUID/path), `utils/strings.rs`
    (ASCII/UTF-8/UTF-16LE string extraction).
- `internal/` — logic local to this process only (never touches other processes):
  - `imports/imports.rs`, `utils/handles.rs` (`CleanHandle` RAII handle wrapper).
- `process_ops/` — operations acting on a target process:
  - `process_processing.rs` orchestrates validation and retained process collectors.
  - `outputs/` writes image/section, PDB, import/IAT-xref, PEB, and TEB JSON.
  - `utils/foundation/validate_pe/` separates mapped-image parsing, remote validation,
    snapshotting, and address/section helpers. Its local `readme.md` documents the pipeline,
    and its local `AGENTS.md` requires that documentation to change with the code and favors
    fast, direct implementations over unnecessary abstraction. `utils/imports/` separates
    import collection, PE import parsing, and IAT xref scanning. Its local `readme.md`
    documents that pipeline, and its local `AGENTS.md` requires matching documentation
    updates plus fast, single-pass implementations. `memutils.rs`, `pdbutils.rs`, `processutils.rs`,
    and `tebutils.rs` provide the other retained process analysis helpers.
- `global_utils/` — general helpers usable anywhere: `fileutils` (file entropy, SHA-256 hashing).
- `data/` — static tables: `patterns64/patterns64` for raw-file signature scanning.

## Coding style

- Use Allman-style brackets (opening brace on its own line) for methods, structs, enums, `if`, and `for` loops.
- Keep comments light. Follow standard Rust commenting: a brief description of intent along with its parameter info + return type info, plus explicit safety-concern notations (e.g. `// SAFETY:` on `unsafe` blocks). Comments should only be for global vars, structs, methods, impl, etc... there should be no comment inside of a method.
- When making methods, private style methods should always be placed under public methods.
- There should be 2 indents / free lines between each method, this also includes the method comment, this way to make it more spacey.
- Avoid using multiple wrapper methods for small operations as this just lengthens the trail needed to follow to understand things.
- When making a new method, make sure it doesn't already exist, if so prompt the user where at and for actions to take.
- When creating helper methods, see if a suitable type already exists in the language's standard lib.
- Private helper related methods should have basic error prints in instances where an error may occur.
- Methods with many parameters should still be single lined, do not indent them.
- When using print methods that may have many parameters, do not indent them, keep it single lined.
- When writting methods with multiple params, there should be a single space after each comma before leading to the new param.
- Try to avoid indenting in statements when there is multiple conditions or the .ok, .iter, .map, .max, etc..
- When multiple statements or conditional ops are needed, put an indent between each one so it's better to read.
- Avoid over engineering simple tasks  that will likely have small work flows, focus more are readability along with easy edits.

## Coding Security and Performance

- Large datasets, make sure they are properly stored, and free'd when needed.
- Prefer performance and memory safety.
- Avoid over-engineering workflows with straightforward usage. Prefer simple, performant implementations that remain easy to understand and maintain.

## Platform

This project targets Windows only. Do not add cross-platform guards - omit `#[cfg(windows)]` / `#[cfg(not(windows))]` attributes and non-Windows fallback stubs. Assume the Windows API (via `windows-sys`) is always available.

## Creating files

Prompt the user for confirmation before creating any new file. Describe the file's path and purpose, and wait for approval before writing it. Editing existing files does not require this prompt.

## Documentation maintenance

- Whenever a file or project methodology/workflow is created, changed, or removed, review and update both `AGENTS.md` and `README.md` in the same change so they accurately reflect the current project.

## Editing guide

Prompt the user before changing anything in the `AGENTS.md` or `CLAUDE.md` files, displaying what will be changed. The user should have the option to confirm or deny.
