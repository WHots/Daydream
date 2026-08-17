//! Contributor-owned x64 byte-signature catalog.
//!
//! Add a signature by declaring one `Signature` constant with `x64_signature!`, using `??`,
//! `?`, or `WILDCARD` for each arbitrary byte. Then add the constant to
//! `X64_FILE_SCAN_SIGNATURES` so the raw-file scanner consumes it.

/// A named x64 byte signature used to locate analyst-relevant code inside a PE image's
/// executable section. Each element of `pattern` is `Some(byte)` for an exact
/// match or `None` for a single-byte wildcard (the `??` of a classic array-of-bytes scan).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Signature
{
    /// Human-readable name of the routine the signature identifies.
    pub name: &'static str,
    /// The byte pattern to match, where each `None` matches any single byte.
    pub pattern: &'static [Option<u8>],
}


/// Converts a comma-separated contributor pattern into the scanner's existing optional-byte
/// representation. `??`, `?`, and `WILDCARD` each represent one arbitrary byte.
macro_rules! signature_pattern
{
    (@collect [$($output:expr,)*]) =>

  {
        &[$($output,)*]
    };
    (@collect [$($output:expr,)*] ? ?, $($remaining:tt)*) =>

  {
        signature_pattern!(@collect [$($output,)* None,] $($remaining)*)
    };
    (@collect [$($output:expr,)*] ? ?) =>

  {
        signature_pattern!(@collect [$($output,)* None,])
    };
    (@collect [$($output:expr,)*] ?, $($remaining:tt)*) =>

  {
        signature_pattern!(@collect [$($output,)* None,] $($remaining)*)
    };
    (@collect [$($output:expr,)*] ?) =>

  {
        signature_pattern!(@collect [$($output,)* None,])
    };
    (@collect [$($output:expr,)*] WILDCARD, $($remaining:tt)*) =>

  {
        signature_pattern!(@collect [$($output,)* None,] $($remaining)*)
    };
    (@collect [$($output:expr,)*] WILDCARD) =>

  {
        signature_pattern!(@collect [$($output,)* None,])
    };
    (@collect [$($output:expr,)*] $byte:literal, $($remaining:tt)*) =>

  {
        signature_pattern!(@collect [$($output,)* Some($byte),] $($remaining)*)
    };
    (@collect [$($output:expr,)*] $byte:literal) =>

  {
        signature_pattern!(@collect [$($output,)* Some($byte),])
    };
}


/// Builds one named x64 signature from compact byte tokens. Contributors should declare a
/// constant with this macro, then add that constant to one or more catalog slices below.
/// Each wildcard consumes exactly one byte; it is not a variable-length gap.
macro_rules! x64_signature
{
    ($name:literal, [$($pattern:tt)+] $(,)?) =>

  {
        Signature

      {
            name: $name,
            pattern: signature_pattern!(@collect [] $($pattern)+),
        }
    };
}


/// Direct `PEB.BeingDebugged` lookup commonly emitted by binaries that avoid importing
/// `IsDebuggerPresent`.
///   65 48 8B 04 25 60 00 00 00  mov rax, gs:[60h]
///   0F B6 40 02                    movzx eax, byte ptr [rax+2]
pub const PEB_BEING_DEBUGGED_CHECK: Signature = x64_signature!("PEB BeingDebugged check", [0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x0F, 0xB6, 0x40, 0x02]);

/// Reads the x64 PEB `NtGlobalFlag` field and isolates the heap-debug flags commonly
/// inspected by anti-debug checks.
///   65 48 8B 04 25 60 00 00 00  mov rax, gs:[60h]
///   8B 80 BC 00 00 00              mov eax, [rax+0BCh]
///   83 E0 70                       and eax, 70h
pub const NT_GLOBAL_FLAG_HEAP_DEBUG_CHECK: Signature = x64_signature!("PEB NtGlobalFlag heap-debug check", [0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x8B, 0x80, 0xBC, 0x00, 0x00, 0x00, 0x83, 0xE0, 0x70,]);

/// Reads `KUSER_SHARED_DATA.KdDebuggerEnabled` through its fixed user-mode address.
/// The hit identifies code that queries debugger state, not the returned state itself.
///   0F B6 04 25 D4 02 FE 7F  movzx eax, byte ptr [7FFE02D4h]
pub const KD_DEBUGGER_ENABLED_READ: Signature = x64_signature!("KUSER_SHARED_DATA KdDebuggerEnabled read", [0x0F, 0xB6, 0x04, 0x25, 0xD4, 0x02, 0xFE, 0x7F]);

/// Walks from the x64 PEB through `PEB.Ldr` to the loader's in-memory module list.
/// This contextual chain is stronger for raw-file triage than the PEB load alone.
///   65 48 8B 04 25 60 00 00 00  mov rax, gs:[60h]
///   48 8B 40 18                    mov rax, [rax+18h]
///   48 8B 40 20                    mov rax, [rax+20h]
pub const PEB_LDR_IN_MEMORY_ORDER_WALK: Signature = x64_signature!("PEB loader InMemoryOrder walk", [0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x40, 0x18, 0x48, 0x8B, 0x40, 0x20,]);

/// Canonical x64 syscall wrapper used by `ntdll` and sometimes copied into private code.
/// A hit is especially notable when it appears outside a known `ntdll` image.
///   4C 8B D1              mov r10, rcx
///   B8 ?? ?? ?? ??        mov eax, syscall_number
///   0F 05                 syscall
///   C3                    ret
pub const DIRECT_SYSCALL_STUB: Signature = x64_signature!(
    "direct syscall wrapper",
    [0x4C, 0x8B, 0xD1, 0xB8, ??, ??, ??, ??, 0x0F, 0x05, 0xC3]
);

/// Native x64 syscall wrapper that consults the shared-user-data system-call gate before
/// choosing its transition path. The syscall number and conditional branch vary by build.
///   4C 8B D1                       mov r10, rcx
///   B8 ?? ?? ?? ??                 mov eax, syscall_number
///   F6 04 25 08 03 FE 7F 01        test byte ptr [7FFE0308h], 1
///   75 ??                          jne alternate_path
///   0F 05                          syscall
///   C3                             ret
pub const SHARED_USER_DATA_SYSCALL_GATE: Signature = x64_signature!(
    "SharedUserData-gated syscall wrapper",
    [
        0x4C, 0x8B, 0xD1, 0xB8, ??, ??, ??, ??,
        0xF6, 0x04, 0x25, 0x08, 0x03, 0xFE, 0x7F, 0x01,
        0x75, ??, 0x0F, 0x05, 0xC3,
    ]
);

/// A common x64 `RDTSC` sequence that combines the high and low timestamp halves into
/// `rax`. The surrounding instructions make this a stronger raw-byte signature than a
/// two-byte `RDTSC` opcode match.
///   0F 31                 rdtsc
///   48 C1 E2 20           shl rdx, 20h
///   48 0B C2              or rax, rdx
pub const RDTSC_TIMESTAMP_COMBINE: Signature = x64_signature!("RDTSC timestamp combine", [0x0F, 0x31, 0x48, 0xC1, 0xE2, 0x20, 0x48, 0x0B, 0xC2]);

/// A common x64 `RDTSCP` sequence that combines the high and low timestamp halves into
/// `rax`. Malware can use timestamp instructions for timing-based anti-debugging.
///   0F 01 F9              rdtscp
///   48 C1 E2 20           shl rdx, 20h
///   48 0B C2              or rax, rdx
pub const RDTSCP_TIMESTAMP_COMBINE: Signature = x64_signature!("RDTSCP timestamp combine", [0x0F, 0x01, 0xF9, 0x48, 0xC1, 0xE2, 0x20, 0x48, 0x0B, 0xC2]);

/// A `CPUID` query where the leaf is loaded directly into `eax`. It can identify virtual
/// machine and debugger environment probes without relying on a two-byte opcode match.
///   B8 ?? ?? ?? ??        mov eax, leaf
///   0F A2                 cpuid
pub const CPUID_LEAF_QUERY: Signature = x64_signature!(
    "CPUID leaf query",
    [0xB8, ??, ??, ??, ??, 0x0F, 0xA2]
);

/// A common `INT 2D` anti-debug check with `eax` cleared before the interrupt.
///   33 C0                 xor eax, eax
///   CD 2D                 int 2dh
pub const INT_2D_ANTI_DEBUG_CHECK: Signature = x64_signature!("INT 2D anti-debug check", [0x33, 0xC0, 0xCD, 0x2D]);

/// Behavior-bearing signatures intended for raw PE executable-section scans. A hit
/// means the matching code exists in the stored image; it does not prove that a runtime
/// check succeeded. Debugger state, debug-register values, and post-load breakpoint
/// patches are process-only detections and intentionally do not belong in this group.
pub const X64_FILE_SCAN_SIGNATURES: &[Signature] = &[PEB_BEING_DEBUGGED_CHECK, NT_GLOBAL_FLAG_HEAP_DEBUG_CHECK, KD_DEBUGGER_ENABLED_READ, PEB_LDR_IN_MEMORY_ORDER_WALK, DIRECT_SYSCALL_STUB, SHARED_USER_DATA_SYSCALL_GATE, RDTSC_TIMESTAMP_COMBINE, RDTSCP_TIMESTAMP_COMBINE, CPUID_LEAF_QUERY, INT_2D_ANTI_DEBUG_CHECK];
