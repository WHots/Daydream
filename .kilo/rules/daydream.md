# daydream — project rules

Authoritative source: `CLAUDE.md` at the repo root (`AGENTS.md` defers to it). If
this file and `CLAUDE.md` ever disagree, `CLAUDE.md` wins — stop and say so rather
than silently picking one.

## Project

Windows-only, x86_64 Rust binary crate for inspecting another process's memory.
Opens a target process (pid from `argv[1]`, defaulting to the current process),
validates granted access, and provides utilities for memory reads, PE/PDB parsing,
and opcode/API pattern discovery. Win32 access goes through `windows-sys`.

- Build: `cargo build`
- Run: `cargo run -- <pid>`
- Test: `cargo test`

## Platform

This project targets Windows only. Do **not** add cross-platform guards. Omit
`#[cfg(windows)]` / `#[cfg(not(windows))]` attributes and do not write non-Windows
fallback stubs. Assume the Windows API via `windows-sys` is always available.

## Formatting — do not run rustfmt

Brace style is hand-written **Allman** (opening brace on its own line) for methods,
structs, enums, `impl`, `if`, and `for`. `editor.formatOnSave` is deliberately
disabled for Rust in `.vscode/settings.json`.

Never run `cargo fmt` / rustfmt and never reformat existing code to rustfmt's
default same-line brace style. Match the surrounding style exactly.

```rust
fn read_region(handle: &CleanHandle, addr: usize) -> Option<Vec<u8>>
{
    if addr == 0
    {
        return None;
    }

    for byte in buffer.iter()
    {
        // ...
    }
}
```

## Comments

Keep comments light, standard Rust style.

- Comment **only** globals, structs, enums, methods, and `impl` blocks.
- **No comments inside a method body**, with one exception: `// SAFETY:` notations
  on `unsafe` blocks, which are required.
- A method comment gives a brief description of intent, its parameter info, and its
  return type info.

## Layout

- Put **2 blank lines between each method**, counting the method's doc comment as
  part of the method (the blank lines go above the comment). Keep it spacey.
- Private methods always go **below** public methods within the same `impl`.

## Methods

- Prefer performance and memory safety.
- Before adding a method, check it does not already exist. If it does, stop, tell
  the user where it lives, and ask how to proceed.
- Do not add thin wrapper methods around small operations — they only lengthen the
  trail needed to understand the code.
- Before writing a helper type, check whether a suitable type already exists in the
  Rust standard library.

## Where code goes

All source lives under `src/core/`. Place new code in the subtree matching its role:

1. `utils/` — general helpers: memory (`memutils`), PE (`pe_utils`), PDB
   (`pdbutils`), process boilerplate (`processutils`), strings (`strings`), files
   (`fileutils`).
2. `internal/` — logic local to this process only, never touching other processes:
   `imports`, `saves`, `utils/handles` (the `CleanHandle` RAII handle wrapper).
3. `ops/` — operational logic acting on a target: `api_discovery`, `bytecode`,
   `string_parsing`.
4. `data/` — static reference tables: `opcode_specific64`, `patterns64`,
   `windowapis`.

`src/main.rs` is the entry point; it declares the full `core` module tree and runs
the open-process / query-access flow.

## Creating files

Ask the user for confirmation before creating **any** new file. Describe the path
and its purpose, then wait for approval. Editing existing files needs no prompt.

Ask before changing `CLAUDE.md` or `AGENTS.md`, showing what would change so the
user can confirm or deny.