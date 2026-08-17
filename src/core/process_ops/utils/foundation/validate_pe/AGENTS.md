# Instructions for `validate_pe`

These instructions apply to every file in this directory.

- Update `readme.md` in the same change whenever validation code, data flow,
  invariants, limits, module responsibilities, or public module behavior changes.
- Prioritize processing speed while preserving strict validation, memory safety,
  checked arithmetic, bounded reads, and typed failures.
- Reuse the validated `PeImage`, PE identity, section table, and shared snapshot.
  Avoid repeated remote reads, reparsing, copies, and unnecessary allocations.
- Prefer direct single-pass section and memory-region processing where practical.
- Do not overengineer straightforward work. Avoid extra wrappers, layers, state,
  or generalized frameworks unless they remove real repeated work or clarify a
  required validation invariant.
- Preserve the distinction between mapped-image RVAs and raw-file offsets, and
  keep unavailable loader-discarded data explicit for downstream collectors.
