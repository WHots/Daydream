#![allow(dead_code)]

/// Describes an x64 opcode byte sequence that can be searched in process memory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpcodeBytecode
{
    pub name: &'static str,
    pub bytecode: &'static [u8],
    pub requires_modrm: bool,
}


/// One-byte `INT3` software breakpoint.
pub const INT3_BREAKPOINT: OpcodeBytecode = OpcodeBytecode
{
    name: "INT3 software breakpoint",
    bytecode: &[0xCC],
    requires_modrm: false,
};

/// Two-byte interrupt-vector 3 breakpoint form.
pub const INT_VECTOR_3_BREAKPOINT: OpcodeBytecode = OpcodeBytecode
{
    name: "INT imm8 vector 3 breakpoint",
    bytecode: &[0xCD, 0x03],
    requires_modrm: false,
};

/// Two-byte interrupt-vector 1 debug interrupt form.
pub const INT_VECTOR_1_DEBUG_INTERRUPT: OpcodeBytecode = OpcodeBytecode
{
    name: "INT imm8 vector 1 debug interrupt",
    bytecode: &[0xCD, 0x01],
    requires_modrm: false,
};

/// One-byte `INT1` or `ICEBP` debug trap form.
pub const INT1_ICEBP_DEBUG_TRAP: OpcodeBytecode = OpcodeBytecode
{
    name: "INT1 ICEBP debug trap",
    bytecode: &[0xF1],
    requires_modrm: false,
};

/// Debug-register read opcode prefix used by hardware-breakpoint setup code.
pub const MOV_FROM_DEBUG_REGISTER: OpcodeBytecode = OpcodeBytecode
{
    name: "MOV r64, DR0-DR7",
    bytecode: &[0x0F, 0x21],
    requires_modrm: true,
};

/// Debug-register write opcode prefix used by hardware-breakpoint setup code.
pub const MOV_TO_DEBUG_REGISTER: OpcodeBytecode = OpcodeBytecode
{
    name: "MOV DR0-DR7, r64",
    bytecode: &[0x0F, 0x23],
    requires_modrm: true,
};

/// x64 software breakpoint bytecodes that can be searched as exact byte sequences.
pub const X64_SOFTWARE_BREAKPOINT_OPCODE_BYTECODES: &[OpcodeBytecode] =
    &[INT3_BREAKPOINT, INT_VECTOR_3_BREAKPOINT];

/// x64 software debug-trap bytecodes that can be searched as exact byte sequences.
pub const X64_SOFTWARE_DEBUG_TRAP_OPCODE_BYTECODES: &[OpcodeBytecode] =
    &[INT_VECTOR_1_DEBUG_INTERRUPT, INT1_ICEBP_DEBUG_TRAP];

/// x64 debug-register opcode prefixes related to hardware breakpoint setup.
pub const X64_DEBUG_REGISTER_OPCODE_BYTECODES: &[OpcodeBytecode] =
    &[MOV_FROM_DEBUG_REGISTER, MOV_TO_DEBUG_REGISTER];

/// x64 breakpoint-related opcode bytecodes intended for process-memory scanning.
pub const X64_BREAKPOINT_OPCODE_BYTECODES: &[OpcodeBytecode] = &[
    INT3_BREAKPOINT,
    INT_VECTOR_3_BREAKPOINT,
    INT_VECTOR_1_DEBUG_INTERRUPT,
    INT1_ICEBP_DEBUG_TRAP,
    MOV_FROM_DEBUG_REGISTER,
    MOV_TO_DEBUG_REGISTER,
];
