# Instructions for `imports`

These instructions apply to every file in this directory.

- Update `readme.md` in the same change whenever import parsing, unavailable-range
  handling, xref scanning, supported encodings, output types, or data flow changes.
- Prioritize processing speed while preserving checked arithmetic, validated
  snapshot boundaries, explicit location types, and typed fatal failures.
- Reuse `ValidatedPeSnapshot` and its `PeImage`. Do not add repeated PE validation
  or remote process-memory reads to this module.
- Prefer one descriptor/thunk parse and one executable-section scan with
  constant-time IAT target lookup. Avoid per-byte allocation and repeated work.
- Do not overengineer straightforward collection. Avoid extra wrappers, layers,
  generalized decoders, or state unless a required feature clearly justifies
  their runtime and maintenance cost.
- Keep raw byte-pattern evidence distinct from decoded instruction semantics or
  proof of execution.
