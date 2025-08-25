use crate::cpu::Register;
use crate::error::{EmulatorError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperandSize {
    Byte,
    Word,
    DWord,
    QWord,
    XmmWord,
    YmmWord,
}

#[derive(Debug, Clone)]
pub enum Operand {
    Register(Register),
    Memory {
        base: Option<Register>,
        index: Option<Register>,
        scale: u8,
        displacement: i64,
        size: OperandSize,
    },
    Immediate(i64),
    Relative(i64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    ADD,
    ADC,
    SUB,
    SBB,
    MOV,
    XOR,
    AND,
    OR,
    CMP,
    TEST,
    PUSH,
    POP,
    CALL,
    RET,
    JMP,
    JZ,
    JNZ,
    JS,
    JNS,
    JO,
    JNO,
    JB,
    JAE,
    JBE,
    JA,
    JL,
    JGE,
    JLE,
    JG,
    LEA,
    INC,
    DEC,
    NEG,
    NOT,
    SHL,
    SHR,
    SAR,
    ROL,
    ROR,
    XCHG,
    XADD,
    CDQ,
    MUL,
    DIV,
    IMUL,
    IDIV,
    LOOP,
    LOOPE,
    LOOPNE,
    NOP,
    HLT,
    INT,
    SYSCALL,
    MOVS,
    CMPS,
    SCAS,
    STOS,
    LODS,
    REP,
    REPZ,
    REPNZ,
    MOVAPS,
    MOVUPS,
    MOVSS,
    MOVSD,
    MOVQ,
    MOVLHPS,
    ADDPS,
    SUBPS,
    MULPS,
    DIVPS,
    ADDSS,
    SUBSS,
    MULSS,
    DIVSS,
    ADDPD,
    SUBPD,
    MULPD,
    DIVPD,
    ADDSD,
    SUBSD,
    MULSD,
    DIVSD,
    XORPS,
    XORPD,
    ANDPS,
    ANDPD,
    ORPS,
    ORPD,
    CMPPS,
    CMPSS,
    CMPSDSSE,
    CMPPD,
    COMISS,
    UCOMISS,
    COMISD,
    UCOMISD,
    MOVSXD,
    MOVZX,
    SETBE,
    SETNE,
    CMOVAE,
    CMOVB,
    CMOVBE,
    CMOVE,
    CMOVG,
    CMOVNE,
    RDTSC,
    MONITORX,
    PREFETCHW,
    CMPXCHG,
    BT,
    BTS,
    BTR,
    BTC,
    VINSERTF128,
    VZEROUPPER,
    MOVDQA,
    BSR,
}

#[derive(Debug, Clone)]
pub struct Instruction {
    pub address: u64,
    pub opcode: Opcode,
    pub operands: Vec<Operand>,
    pub size: usize,
    pub prefix: InstructionPrefix,
    pub operand_size: OperandSize,
}

#[derive(Debug, Clone, Default)]
pub struct InstructionPrefix {
    pub rex: Option<RexPrefix>,
    pub operand_size_override: bool,
    pub address_size_override: bool,
    pub segment: Option<Register>,
    pub rep: Option<RepPrefix>,
    pub lock: bool,
    pub vex: Option<VexPrefix>,
}

#[derive(Debug, Clone, Copy)]
pub struct RexPrefix {
    pub w: bool,
    pub r: bool,
    pub x: bool,
    pub b: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct VexPrefix {
    pub r: bool,  // inverted
    pub x: bool,  // inverted
    pub b: bool,  // inverted
    pub m: u8,    // map_select (0=0F, 1=0F38, 2=0F3A, etc)
    pub w: bool,  // REX.W equivalent
    pub vvvv: u8, // inverted additional operand specifier
    pub l: bool,  // vector length (0=128-bit, 1=256-bit)
    pub pp: u8,   // mandatory prefix (0=none, 1=66, 2=F3, 3=F2)
}

#[derive(Debug, Clone, Copy)]
pub enum RepPrefix {
    Rep,
    RepZ,
    RepNZ,
}

pub struct Decoder {
    mode: DecoderMode,
}

#[derive(Debug, Clone, Copy)]
pub enum DecoderMode {
    Mode64,
    Mode32,
    Mode16,
}

impl Decoder {
    pub fn new(mode: DecoderMode) -> Self {
        Self { mode }
    }

    pub fn decode(&self, bytes: &[u8], address: u64) -> Result<Instruction> {
        if bytes.is_empty() {
            return Err(EmulatorError::InvalidInstruction(address));
        }

        let mut offset = 0;
        let mut prefix = InstructionPrefix::default();

        while offset < bytes.len() {
            match bytes[offset] {
                0x66 => prefix.operand_size_override = true,
                0x67 => prefix.address_size_override = true,
                0x26 => prefix.segment = Some(Register::ES),
                0x2E => prefix.segment = Some(Register::CS),
                0x36 => prefix.segment = Some(Register::SS),
                0x3E => prefix.segment = Some(Register::DS),
                0x64 => prefix.segment = Some(Register::FS),
                0x65 => prefix.segment = Some(Register::GS),
                0xF0 => prefix.lock = true,
                0xF2 => prefix.rep = Some(RepPrefix::RepNZ),
                0xF3 => prefix.rep = Some(RepPrefix::RepZ),
                0x40..=0x4F if matches!(self.mode, DecoderMode::Mode64) => {
                    let rex_byte = bytes[offset];
                    prefix.rex = Some(RexPrefix {
                        w: (rex_byte & 0x08) != 0,
                        r: (rex_byte & 0x04) != 0,
                        x: (rex_byte & 0x02) != 0,
                        b: (rex_byte & 0x01) != 0,
                    });
                }
                0xC4 => {
                    // 3-byte VEX prefix
                    if bytes.len() < offset + 3 {
                        return Err(EmulatorError::InvalidInstruction(address));
                    }
                    let vex1 = bytes[offset + 1];
                    let vex2 = bytes[offset + 2];

                    prefix.vex = Some(VexPrefix {
                        r: (vex1 & 0x80) == 0, // inverted
                        x: (vex1 & 0x40) == 0, // inverted
                        b: (vex1 & 0x20) == 0, // inverted
                        m: vex1 & 0x1F,
                        w: (vex2 & 0x80) != 0,
                        vvvv: (vex2 >> 3) & 0x0F,
                        l: (vex2 & 0x04) != 0,
                        pp: vex2 & 0x03,
                    });
                    offset += 2; // Skip the additional VEX bytes
                }
                0xC5 => {
                    // 2-byte VEX prefix
                    if bytes.len() < offset + 2 {
                        return Err(EmulatorError::InvalidInstruction(address));
                    }
                    let vex1 = bytes[offset + 1];

                    prefix.vex = Some(VexPrefix {
                        r: (vex1 & 0x80) == 0, // inverted
                        x: false,              // implied 0 in 2-byte VEX
                        b: false,              // implied 0 in 2-byte VEX
                        m: 1,                  // implied 0F in 2-byte VEX
                        w: false,              // implied 0 in 2-byte VEX
                        vvvv: (vex1 >> 3) & 0x0F,
                        l: (vex1 & 0x04) != 0,
                        pp: vex1 & 0x03,
                    });
                    offset += 1; // Skip the additional VEX byte
                }
                _ => break,
            }
            offset += 1;
        }

        if offset >= bytes.len() {
            return Err(EmulatorError::InvalidInstruction(address));
        }

        // Handle VEX prefix - if we have VEX, skip the prefix and decode the actual opcode
        if prefix.vex.is_some() {
            // For VEX prefix, the actual opcode is after the prefix bytes
            // The offset is already positioned at the opcode byte after VEX prefix parsing
            let (opcode, operands, consumed) =
                self.decode_vex_instruction(&bytes[offset..], &prefix)?;
            let total_size = offset + consumed;
            let operand_size = self.operand_size(&prefix);
            return Ok(Instruction {
                address,
                opcode,
                operands,
                size: total_size,
                prefix,
                operand_size,
            });
        }

        let _opcode_byte = bytes[offset];
        offset += 1;

        let (opcode, operands, consumed) =
            self.decode_instruction(&bytes[offset - 1..], &prefix)?;
        // consumed includes the opcode byte, and offset-1 is the position before we read the opcode
        let total_size = (offset - 1) + consumed;

        let operand_size = self.operand_size(&prefix);
        Ok(Instruction {
            address,
            opcode,
            operands,
            size: total_size,
            prefix,
            operand_size,
        })
    }

    fn decode_instruction(
        &self,
        bytes: &[u8],
        prefix: &InstructionPrefix,
    ) -> Result<(Opcode, Vec<Operand>, usize)> {
        if bytes.is_empty() {
            return Err(EmulatorError::InvalidInstruction(0));
        }

        let opcode_byte = bytes[0];
        let mut offset = 1;

        let (opcode, operands) = match opcode_byte {
            0x00 | 0x01 => {
                // ADD r/m, r - memory/rm is destination
                let (rm_op, reg_op, consumed) =
                    self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;
                (Opcode::ADD, vec![rm_op, reg_op])
            }
            0x02 | 0x03 => {
                // ADD r, r/m - register is destination
                let (rm_op, reg_op, consumed) =
                    self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;
                (Opcode::ADD, vec![reg_op, rm_op])
            }
            0x04 => {
                // ADD AL, imm8
                let imm = bytes
                    .get(offset)
                    .copied()
                    .ok_or(EmulatorError::InvalidInstruction(0))?;
                offset += 1;
                (
                    Opcode::ADD,
                    vec![
                        Operand::Register(Register::AL),
                        Operand::Immediate(imm as i64),
                    ],
                )
            }
            0x05 => {
                // ADD rAX, imm
                let imm = self.decode_immediate(&bytes[offset..], self.operand_size(prefix))?;
                offset += self.operand_size(prefix).bytes();
                let reg = if prefix.rex.as_ref().is_some_and(|r| r.w) {
                    Register::RAX
                } else if prefix.operand_size_override {
                    Register::AX
                } else {
                    Register::EAX
                };
                (
                    Opcode::ADD,
                    vec![Operand::Register(reg), Operand::Immediate(imm)],
                )
            }
            0x08 | 0x09 => {
                // OR r/m, r - memory/rm is destination
                let (rm_op, reg_op, consumed) =
                    self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;
                (Opcode::OR, vec![rm_op, reg_op])
            }
            0x0A | 0x0B => {
                // OR r, r/m - register is destination
                let (rm_op, reg_op, consumed) =
                    self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;
                (Opcode::OR, vec![reg_op, rm_op])
            }
            0x0C => {
                // OR AL, imm8
                let imm = bytes
                    .get(offset)
                    .copied()
                    .ok_or(EmulatorError::InvalidInstruction(0))?;
                offset += 1;
                (
                    Opcode::OR,
                    vec![
                        Operand::Register(Register::AL),
                        Operand::Immediate(imm as i64),
                    ],
                )
            }
            0x0D => {
                // OR rAX, imm
                let imm = self.decode_immediate(&bytes[offset..], self.operand_size(prefix))?;
                offset += self.operand_size(prefix).bytes();
                let reg = if prefix.rex.as_ref().is_some_and(|r| r.w) {
                    Register::RAX
                } else if prefix.operand_size_override {
                    Register::AX
                } else {
                    Register::EAX
                };
                (
                    Opcode::OR,
                    vec![Operand::Register(reg), Operand::Immediate(imm)],
                )
            }
            0x10 | 0x11 => {
                // ADC r/m, r - memory/rm is destination
                let (rm_op, reg_op, consumed) =
                    self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;
                (Opcode::ADC, vec![rm_op, reg_op])
            }
            0x12 | 0x13 => {
                // ADC r, r/m - register is destination
                let (rm_op, reg_op, consumed) =
                    self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;
                (Opcode::ADC, vec![reg_op, rm_op])
            }
            0x14 => {
                // ADC AL, imm8
                let imm = bytes
                    .get(offset)
                    .copied()
                    .ok_or(EmulatorError::InvalidInstruction(0))?;
                offset += 1;
                (
                    Opcode::ADC,
                    vec![
                        Operand::Register(Register::AL),
                        Operand::Immediate(imm as i64),
                    ],
                )
            }
            0x15 => {
                // ADC rAX, imm
                let imm = self.decode_immediate(&bytes[offset..], self.operand_size(prefix))?;
                offset += self.operand_size(prefix).bytes();
                let reg = if prefix.rex.as_ref().is_some_and(|r| r.w) {
                    Register::RAX
                } else if prefix.operand_size_override {
                    Register::AX
                } else {
                    Register::EAX
                };
                (
                    Opcode::ADC,
                    vec![Operand::Register(reg), Operand::Immediate(imm)],
                )
            }
            0x18 | 0x19 => {
                // SBB r/m, r - memory/rm is destination
                let (rm_op, reg_op, consumed) =
                    self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;
                (Opcode::SBB, vec![rm_op, reg_op])
            }
            0x1A | 0x1B => {
                // SBB r, r/m - register is destination
                let (rm_op, reg_op, consumed) =
                    self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;
                (Opcode::SBB, vec![reg_op, rm_op])
            }
            0x1C => {
                // SBB AL, imm8
                let imm = bytes
                    .get(offset)
                    .copied()
                    .ok_or(EmulatorError::InvalidInstruction(0))?;
                offset += 1;
                (
                    Opcode::SBB,
                    vec![
                        Operand::Register(Register::AL),
                        Operand::Immediate(imm as i64),
                    ],
                )
            }
            0x1D => {
                // SBB rAX, imm
                let imm = self.decode_immediate(&bytes[offset..], self.operand_size(prefix))?;
                offset += self.operand_size(prefix).bytes();
                let reg = if prefix.rex.as_ref().is_some_and(|r| r.w) {
                    Register::RAX
                } else if prefix.operand_size_override {
                    Register::AX
                } else {
                    Register::EAX
                };
                (
                    Opcode::SBB,
                    vec![Operand::Register(reg), Operand::Immediate(imm)],
                )
            }
            0x20 | 0x21 => {
                // AND r/m, r - memory/rm is destination
                let (rm_op, reg_op, consumed) =
                    self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;
                (Opcode::AND, vec![rm_op, reg_op])
            }
            0x22 | 0x23 => {
                // AND r, r/m - register is destination
                let (rm_op, reg_op, consumed) =
                    self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;
                (Opcode::AND, vec![reg_op, rm_op])
            }
            0x24 => {
                // AND AL, imm8
                let imm = bytes
                    .get(offset)
                    .copied()
                    .ok_or(EmulatorError::InvalidInstruction(0))?;
                offset += 1;
                (
                    Opcode::AND,
                    vec![
                        Operand::Register(Register::AL),
                        Operand::Immediate(imm as i64),
                    ],
                )
            }
            0x25 => {
                // AND rAX, imm
                let imm = self.decode_immediate(&bytes[offset..], self.operand_size(prefix))?;
                offset += self.operand_size(prefix).bytes();
                let reg = if prefix.rex.as_ref().is_some_and(|r| r.w) {
                    Register::RAX
                } else if prefix.operand_size_override {
                    Register::AX
                } else {
                    Register::EAX
                };
                (
                    Opcode::AND,
                    vec![Operand::Register(reg), Operand::Immediate(imm)],
                )
            }
            0x28 | 0x29 => {
                // SUB r/m, r - memory/rm is destination
                let (rm_op, reg_op, consumed) =
                    self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;
                (Opcode::SUB, vec![rm_op, reg_op])
            }
            0x2A | 0x2B => {
                // SUB r, r/m - register is destination
                let (rm_op, reg_op, consumed) =
                    self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;
                (Opcode::SUB, vec![reg_op, rm_op])
            }
            0x2C => {
                // SUB AL, imm8
                let imm = bytes
                    .get(offset)
                    .copied()
                    .ok_or(EmulatorError::InvalidInstruction(0))?;
                offset += 1;
                (
                    Opcode::SUB,
                    vec![
                        Operand::Register(Register::AL),
                        Operand::Immediate(imm as i64),
                    ],
                )
            }
            0x2D => {
                // SUB rAX, imm
                let imm = self.decode_immediate(&bytes[offset..], self.operand_size(prefix))?;
                offset += self.operand_size(prefix).bytes();
                let reg = if prefix.rex.as_ref().is_some_and(|r| r.w) {
                    Register::RAX
                } else if prefix.operand_size_override {
                    Register::AX
                } else {
                    Register::EAX
                };
                (
                    Opcode::SUB,
                    vec![Operand::Register(reg), Operand::Immediate(imm)],
                )
            }
            0x30 | 0x31 => {
                // XOR r/m, r
                let (rm_op, reg_op, consumed) =
                    self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;
                (Opcode::XOR, vec![rm_op, reg_op])
            }
            0x32 | 0x33 => {
                // XOR r, r/m
                let (rm_op, reg_op, consumed) =
                    self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;
                (Opcode::XOR, vec![reg_op, rm_op])
            }
            0x38 | 0x39 => {
                // CMP r/m, r
                let (rm_op, reg_op, consumed) =
                    self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;
                (Opcode::CMP, vec![rm_op, reg_op])
            }
            0x3A | 0x3B => {
                // CMP r, r/m
                let (rm_op, reg_op, consumed) =
                    self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;
                (Opcode::CMP, vec![reg_op, rm_op])
            }
            0x3D => {
                // CMP EAX, imm32 - Compare EAX with immediate
                let imm = self.decode_immediate(&bytes[offset..], OperandSize::DWord)?;
                offset += 4;
                let reg = if prefix.rex.is_some_and(|r| r.w) {
                    Register::RAX
                } else {
                    Register::EAX
                };
                (
                    Opcode::CMP,
                    vec![Operand::Register(reg), Operand::Immediate(imm)],
                )
            }
            0x50..=0x57 => {
                let reg = self.decode_register_from_opcode(
                    opcode_byte - 0x50,
                    prefix,
                    OperandSize::QWord,
                );
                (Opcode::PUSH, vec![Operand::Register(reg)])
            }
            0x58..=0x5F => {
                let reg = self.decode_register_from_opcode(
                    opcode_byte - 0x58,
                    prefix,
                    OperandSize::QWord,
                );
                (Opcode::POP, vec![Operand::Register(reg)])
            }
            0x63 => {
                // MOVSXD - Move with Sign-Extend Doubleword
                let (rm_op, reg_op, consumed) =
                    self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;
                (Opcode::MOVSXD, vec![reg_op, rm_op])
            }
            0x6B => {
                // IMUL r, r/m, imm8 - Three-operand signed multiply with 8-bit immediate
                let (rm_op, reg_op, consumed) =
                    self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;

                // Get the 8-bit immediate value (sign-extended)
                let imm = bytes
                    .get(offset)
                    .copied()
                    .ok_or(EmulatorError::InvalidInstruction(0))? as i8
                    as i64;
                offset += 1;

                (Opcode::IMUL, vec![reg_op, rm_op, Operand::Immediate(imm)])
            }
            0x69 => {
                // IMUL r, r/m, imm32 - Three-operand signed multiply with 32-bit immediate
                let (rm_op, reg_op, consumed) =
                    self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;

                // Get the 32-bit immediate value (sign-extended)
                let imm = self.decode_immediate(&bytes[offset..], OperandSize::DWord)?;
                offset += 4;

                (Opcode::IMUL, vec![reg_op, rm_op, Operand::Immediate(imm)])
            }
            0x74 => {
                let rel = bytes
                    .get(offset)
                    .copied()
                    .ok_or(EmulatorError::InvalidInstruction(0))? as i8;
                offset += 1;
                (Opcode::JZ, vec![Operand::Relative(rel as i64)])
            }
            0x75 => {
                let rel = bytes
                    .get(offset)
                    .copied()
                    .ok_or(EmulatorError::InvalidInstruction(0))? as i8;
                offset += 1;
                (Opcode::JNZ, vec![Operand::Relative(rel as i64)])
            }
            0x76 => {
                // JBE/JNA rel8 - Jump if below or equal (CF=1 OR ZF=1)
                let rel = bytes
                    .get(offset)
                    .copied()
                    .ok_or(EmulatorError::InvalidInstruction(0))? as i8;
                offset += 1;
                (Opcode::JBE, vec![Operand::Relative(rel as i64)])
            }
            0x77 => {
                // JA/JNBE rel8 - Jump if above (CF=0 AND ZF=0)
                let rel = bytes
                    .get(offset)
                    .copied()
                    .ok_or(EmulatorError::InvalidInstruction(0))? as i8;
                offset += 1;
                (Opcode::JA, vec![Operand::Relative(rel as i64)])
            }
            0x78 => {
                let rel = bytes
                    .get(offset)
                    .copied()
                    .ok_or(EmulatorError::InvalidInstruction(0))? as i8;
                offset += 1;
                (Opcode::JS, vec![Operand::Relative(rel as i64)])
            }
            0x72 => {
                let rel = bytes
                    .get(offset)
                    .copied()
                    .ok_or(EmulatorError::InvalidInstruction(0))? as i8;
                offset += 1;
                (Opcode::JB, vec![Operand::Relative(rel as i64)])
            }
            0x73 => {
                let rel = bytes
                    .get(offset)
                    .copied()
                    .ok_or(EmulatorError::InvalidInstruction(0))? as i8;
                offset += 1;
                (Opcode::JAE, vec![Operand::Relative(rel as i64)])
            }
            0x79 => {
                let rel = bytes
                    .get(offset)
                    .copied()
                    .ok_or(EmulatorError::InvalidInstruction(0))? as i8;
                offset += 1;
                (Opcode::JNS, vec![Operand::Relative(rel as i64)])
            }
            0x7C => {
                let rel = bytes
                    .get(offset)
                    .copied()
                    .ok_or(EmulatorError::InvalidInstruction(0))? as i8;
                offset += 1;
                (Opcode::JL, vec![Operand::Relative(rel as i64)])
            }
            0x7D => {
                let rel = bytes
                    .get(offset)
                    .copied()
                    .ok_or(EmulatorError::InvalidInstruction(0))? as i8;
                offset += 1;
                (Opcode::JGE, vec![Operand::Relative(rel as i64)])
            }
            0x7E => {
                let rel = bytes
                    .get(offset)
                    .copied()
                    .ok_or(EmulatorError::InvalidInstruction(0))? as i8;
                offset += 1;
                (Opcode::JLE, vec![Operand::Relative(rel as i64)])
            }
            0x7F => {
                let rel = bytes
                    .get(offset)
                    .copied()
                    .ok_or(EmulatorError::InvalidInstruction(0))? as i8;
                offset += 1;
                (Opcode::JG, vec![Operand::Relative(rel as i64)])
            }
            0x80 => {
                // Arithmetic group with 8-bit immediate on byte operands
                if bytes.len() <= offset {
                    return Err(EmulatorError::InvalidInstruction(0));
                }
                let modrm = bytes[offset];
                let reg_bits = (modrm >> 3) & 0x07;
                let (rm_op, _, consumed) = self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;

                // Get the 8-bit immediate value
                let imm = bytes
                    .get(offset)
                    .copied()
                    .ok_or(EmulatorError::InvalidInstruction(0))? as i8
                    as i64;
                offset += 1;

                let opcode = match reg_bits {
                    0 => Opcode::ADD, // ADD r/m8, imm8
                    1 => Opcode::OR,  // OR r/m8, imm8
                    2 => Opcode::ADC, // ADC r/m8, imm8
                    3 => Opcode::SBB, // SBB r/m8, imm8
                    4 => Opcode::AND, // AND r/m8, imm8
                    5 => Opcode::SUB, // SUB r/m8, imm8
                    6 => Opcode::XOR, // XOR r/m8, imm8
                    7 => Opcode::CMP, // CMP r/m8, imm8
                    _ => unreachable!(),
                };
                (opcode, vec![rm_op, Operand::Immediate(imm)])
            }
            0x81 => {
                // Arithmetic group with 32-bit immediate
                if bytes.len() <= offset {
                    return Err(EmulatorError::InvalidInstruction(0));
                }
                let modrm = bytes[offset];
                let reg_bits = (modrm >> 3) & 0x07;
                let (rm_op, _, consumed) = self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;

                // Get the 32-bit immediate value (sign-extended to 64-bit)
                let imm = self.decode_immediate(&bytes[offset..], OperandSize::DWord)?;
                offset += 4;

                let opcode = match reg_bits {
                    0 => Opcode::ADD, // ADD r/m, imm32
                    1 => Opcode::OR,  // OR r/m, imm32
                    2 => Opcode::ADC, // ADC r/m, imm32
                    3 => Opcode::SBB, // SBB r/m, imm32
                    4 => Opcode::AND, // AND r/m, imm32
                    5 => Opcode::SUB, // SUB r/m, imm32
                    6 => Opcode::XOR, // XOR r/m, imm32
                    7 => Opcode::CMP, // CMP r/m, imm32
                    _ => unreachable!(),
                };
                (opcode, vec![rm_op, Operand::Immediate(imm)])
            }
            0x83 => {
                // Arithmetic group with 8-bit immediate
                if bytes.len() <= offset {
                    return Err(EmulatorError::InvalidInstruction(0));
                }
                let modrm = bytes[offset];
                let reg_bits = (modrm >> 3) & 0x07;
                let (rm_op, _, consumed) = self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;

                // Get the 8-bit immediate value (sign-extended to 64-bit)
                let imm = bytes
                    .get(offset)
                    .copied()
                    .ok_or(EmulatorError::InvalidInstruction(0))? as i8
                    as i64;
                offset += 1;

                let opcode = match reg_bits {
                    0 => Opcode::ADD, // ADD r/m, imm8
                    1 => Opcode::OR,  // OR r/m, imm8
                    2 => Opcode::ADC, // ADC r/m, imm8 (now supported)
                    3 => Opcode::SBB, // SBB r/m, imm8 (now supported)
                    4 => Opcode::AND, // AND r/m, imm8
                    5 => Opcode::SUB, // SUB r/m, imm8
                    6 => Opcode::XOR, // XOR r/m, imm8
                    7 => Opcode::CMP, // CMP r/m, imm8
                    _ => unreachable!(),
                };
                (opcode, vec![rm_op, Operand::Immediate(imm)])
            }
            0x84 => {
                // TEST r/m8, r8
                let (op1, op2, consumed) = self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;
                (Opcode::TEST, vec![op1, op2])
            }
            0x85 => {
                let (op1, op2, consumed) = self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;
                (Opcode::TEST, vec![op1, op2])
            }
            0x87 => {
                // XCHG r/m, r
                let (rm_op, reg_op, consumed) =
                    self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;
                (Opcode::XCHG, vec![rm_op, reg_op])
            }
            0x88 | 0x89 => {
                // MOV r/m, r - memory/rm is destination
                let (rm_op, reg_op, consumed) =
                    self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;
                (Opcode::MOV, vec![rm_op, reg_op])
            }
            0x8D => {
                // LEA r, m
                let (mem_op, reg_op, consumed) =
                    self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;
                (Opcode::LEA, vec![reg_op, mem_op])
            }
            0x8A | 0x8B => {
                // MOV r, r/m - register is destination
                let (rm_op, reg_op, consumed) =
                    self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;
                (Opcode::MOV, vec![reg_op, rm_op])
            }
            0x90 => (Opcode::NOP, vec![]),
            0x99 => (Opcode::CDQ, vec![]),
            0xA4 => {
                // MOVS BYTE PTR [RDI], [RSI]
                (Opcode::MOVS, vec![Operand::Immediate(1)]) // Size indicator: 1 = byte
            }
            0xA5 => {
                // MOVS WORD/DWORD/QWORD PTR [RDI], [RSI]
                (Opcode::MOVS, vec![Operand::Immediate(0)]) // Size indicator: 0 = use operand_size
            }
            0xA6 => {
                // CMPS BYTE PTR [RSI], [RDI]
                (Opcode::CMPS, vec![Operand::Immediate(1)]) // Size indicator: 1 = byte
            }
            0xA7 => {
                // CMPS WORD/DWORD/QWORD PTR [RSI], [RDI]
                (Opcode::CMPS, vec![Operand::Immediate(0)]) // Size indicator: 0 = use operand_size
            }
            0xA8 => {
                // TEST AL, imm8
                if bytes.len() <= offset {
                    return Err(EmulatorError::InvalidInstruction(0));
                }
                let imm = bytes[offset] as i64;
                offset += 1;
                (
                    Opcode::TEST,
                    vec![Operand::Register(Register::AL), Operand::Immediate(imm)],
                )
            }
            0xAA => {
                // STOS BYTE PTR [RDI], AL
                (Opcode::STOS, vec![Operand::Immediate(1)]) // Size indicator: 1 = byte
            }
            0xAB => {
                // STOS WORD/DWORD/QWORD PTR [RDI], AX/EAX/RAX
                (Opcode::STOS, vec![Operand::Immediate(0)]) // Size indicator: 0 = use operand_size
            }
            0xAC => {
                // LODS AL, BYTE PTR [RSI]
                (Opcode::LODS, vec![Operand::Immediate(1)]) // Size indicator: 1 = byte
            }
            0xAD => {
                // LODS AX/EAX/RAX, WORD/DWORD/QWORD PTR [RSI]
                (Opcode::LODS, vec![Operand::Immediate(0)]) // Size indicator: 0 = use operand_size
            }
            0xAE => {
                // SCAS AL, BYTE PTR [RDI]
                (Opcode::SCAS, vec![Operand::Immediate(1)]) // Size indicator: 1 = byte
            }
            0xAF => {
                // SCAS AX/EAX/RAX, WORD/DWORD/QWORD PTR [RDI]
                (Opcode::SCAS, vec![Operand::Immediate(0)]) // Size indicator: 0 = use operand_size
            }
            0xB0..=0xB7 => {
                let reg =
                    self.decode_register_from_opcode(opcode_byte - 0xB0, prefix, OperandSize::Byte);
                let imm = bytes
                    .get(offset)
                    .copied()
                    .ok_or(EmulatorError::InvalidInstruction(0))?;
                offset += 1;
                (
                    Opcode::MOV,
                    vec![Operand::Register(reg), Operand::Immediate(imm as i64)],
                )
            }
            0xB8..=0xBF => {
                let reg = self.decode_register_from_opcode(
                    opcode_byte - 0xB8,
                    prefix,
                    OperandSize::QWord,
                );
                let imm = self.decode_immediate(&bytes[offset..], self.operand_size(prefix))?;
                offset += self.operand_size(prefix).bytes();
                (
                    Opcode::MOV,
                    vec![Operand::Register(reg), Operand::Immediate(imm)],
                )
            }
            0xC1 => {
                // Shift/rotate group with 8-bit immediate
                if bytes.len() <= offset {
                    return Err(EmulatorError::InvalidInstruction(0));
                }
                let modrm = bytes[offset];
                let reg_bits = (modrm >> 3) & 0x07;
                let (rm_op, _, consumed) = self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;

                // Get the 8-bit immediate count
                let imm = bytes
                    .get(offset)
                    .copied()
                    .ok_or(EmulatorError::InvalidInstruction(0))?;
                offset += 1;

                let opcode = match reg_bits {
                    0 => Opcode::ROL, // ROL r/m, imm8
                    1 => Opcode::ROR, // ROR r/m, imm8
                    4 => Opcode::SHL, // SHL r/m, imm8
                    5 => Opcode::SHR, // SHR r/m, imm8
                    7 => Opcode::SAR, // SAR r/m, imm8
                    _ => {
                        return Err(EmulatorError::UnsupportedInstruction(format!(
                            "C1 /{}",
                            reg_bits
                        )))
                    }
                };
                (opcode, vec![rm_op, Operand::Immediate(imm as i64)])
            }
            0xC3 => (Opcode::RET, vec![]),
            0xD1 => {
                // Shift/rotate group with count of 1
                if bytes.len() <= offset {
                    return Err(EmulatorError::InvalidInstruction(0));
                }
                let modrm = bytes[offset];
                let reg_bits = (modrm >> 3) & 0x07;
                let (rm_op, _, consumed) = self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;

                let opcode = match reg_bits {
                    0 => Opcode::ROL, // ROL r/m, 1
                    1 => Opcode::ROR, // ROR r/m, 1
                    4 => Opcode::SHL, // SHL r/m, 1
                    5 => Opcode::SHR, // SHR r/m, 1
                    7 => Opcode::SAR, // SAR r/m, 1
                    _ => {
                        return Err(EmulatorError::UnsupportedInstruction(format!(
                            "D1 /{}",
                            reg_bits
                        )))
                    }
                };
                (opcode, vec![rm_op, Operand::Immediate(1)])
            }
            0xD3 => {
                // Shift/rotate group with CL
                if bytes.len() <= offset {
                    return Err(EmulatorError::InvalidInstruction(0));
                }
                let modrm = bytes[offset];
                let reg_bits = (modrm >> 3) & 0x07;
                let (rm_op, _, consumed) = self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;

                let opcode = match reg_bits {
                    0 => Opcode::ROL,
                    1 => Opcode::ROR,
                    4 => Opcode::SHL,
                    5 => Opcode::SHR,
                    7 => Opcode::SAR,
                    _ => {
                        return Err(EmulatorError::UnsupportedInstruction(format!(
                            "D3 /{}",
                            reg_bits
                        )))
                    }
                };
                (opcode, vec![rm_op, Operand::Register(Register::CL)])
            }
            0xC6 => {
                // MOV r/m8, imm8
                let (rm_op, _reg_op, consumed) =
                    self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;

                if bytes.len() <= offset {
                    return Err(EmulatorError::InvalidInstruction(0));
                }
                let imm = bytes[offset] as i64;
                offset += 1;
                (Opcode::MOV, vec![rm_op, Operand::Immediate(imm)])
            }
            0xC7 => {
                let (rm_op, _reg_op, consumed) =
                    self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;
                // 0xC7 always uses imm32 even with REX.W
                let imm = self.decode_immediate(&bytes[offset..], OperandSize::DWord)?;
                offset += 4;
                (Opcode::MOV, vec![rm_op, Operand::Immediate(imm)])
            }
            0xE0 => {
                // LOOPNE/LOOPNZ rel8
                let rel = bytes
                    .get(offset)
                    .copied()
                    .ok_or(EmulatorError::InvalidInstruction(0))? as i8;
                offset += 1;
                (Opcode::LOOPNE, vec![Operand::Relative(rel as i64)])
            }
            0xE1 => {
                // LOOPE/LOOPZ rel8
                let rel = bytes
                    .get(offset)
                    .copied()
                    .ok_or(EmulatorError::InvalidInstruction(0))? as i8;
                offset += 1;
                (Opcode::LOOPE, vec![Operand::Relative(rel as i64)])
            }
            0xE2 => {
                // LOOP rel8
                let rel = bytes
                    .get(offset)
                    .copied()
                    .ok_or(EmulatorError::InvalidInstruction(0))? as i8;
                offset += 1;
                (Opcode::LOOP, vec![Operand::Relative(rel as i64)])
            }
            0xE8 => {
                let rel = self.decode_immediate(&bytes[offset..], OperandSize::DWord)?;
                offset += 4;
                (Opcode::CALL, vec![Operand::Relative(rel)])
            }
            0xE9 => {
                let rel = self.decode_immediate(&bytes[offset..], OperandSize::DWord)?;
                offset += 4;
                (Opcode::JMP, vec![Operand::Relative(rel)])
            }
            0xEB => {
                let rel = bytes
                    .get(offset)
                    .copied()
                    .ok_or(EmulatorError::InvalidInstruction(0))? as i8;
                offset += 1;
                (Opcode::JMP, vec![Operand::Relative(rel as i64)])
            }
            0xF4 => (Opcode::HLT, vec![]),
            0xF6 => {
                // Unary Group 3 - byte operations
                if bytes.len() <= offset {
                    return Err(EmulatorError::InvalidInstruction(0));
                }
                let modrm = bytes[offset];
                let reg_bits = (modrm >> 3) & 0x07;
                let (rm_op, _, consumed) = self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;

                match reg_bits {
                    0 => {
                        // TEST r/m8, imm8
                        let imm = bytes
                            .get(offset)
                            .copied()
                            .ok_or(EmulatorError::InvalidInstruction(0))?;
                        offset += 1;
                        (Opcode::TEST, vec![rm_op, Operand::Immediate(imm as i64)])
                    }
                    _ => {
                        return Err(EmulatorError::UnsupportedInstruction(format!(
                            "F6 /{}",
                            reg_bits
                        )))
                    }
                }
            }
            0xF7 => {
                // NEG/NOT group
                if bytes.len() <= offset {
                    return Err(EmulatorError::InvalidInstruction(0));
                }
                let modrm = bytes[offset];
                let reg_bits = (modrm >> 3) & 0x07;
                let (rm_op, _, consumed) = self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;

                match reg_bits {
                    0 => {
                        // TEST r/m, imm - immediate operand size depends on operand size
                        let imm =
                            self.decode_immediate(&bytes[offset..], self.operand_size(prefix))?;
                        offset += self.operand_size(prefix).bytes();
                        (Opcode::TEST, vec![rm_op, Operand::Immediate(imm)])
                    }
                    1 => {
                        // Also TEST r/m, imm (same as /0)
                        let imm =
                            self.decode_immediate(&bytes[offset..], self.operand_size(prefix))?;
                        offset += self.operand_size(prefix).bytes();
                        (Opcode::TEST, vec![rm_op, Operand::Immediate(imm)])
                    }
                    2 => (Opcode::NOT, vec![rm_op]),
                    3 => (Opcode::NEG, vec![rm_op]),
                    4 => (Opcode::MUL, vec![rm_op]),
                    5 => (Opcode::IMUL, vec![rm_op]),
                    6 => (Opcode::DIV, vec![rm_op]),
                    7 => (Opcode::IDIV, vec![rm_op]),
                    _ => {
                        return Err(EmulatorError::UnsupportedInstruction(format!(
                            "F7 /{}",
                            reg_bits
                        )))
                    }
                }
            }
            0xFF => {
                if bytes.len() <= offset {
                    return Err(EmulatorError::InvalidInstruction(0));
                }
                let modrm = bytes[offset];
                let reg_bits = (modrm >> 3) & 0x07;

                // For CALL and JMP in 64-bit mode, we need 64-bit operands
                let (rm_op, _, consumed) = if (reg_bits == 2 || reg_bits == 4)
                    && matches!(self.mode, DecoderMode::Mode64)
                {
                    self.decode_modrm_operands_with_size(
                        &bytes[offset..],
                        prefix,
                        OperandSize::QWord,
                    )?
                } else {
                    self.decode_modrm_operands(&bytes[offset..], prefix)?
                };
                offset += consumed;

                match reg_bits {
                    0 => (Opcode::INC, vec![rm_op]),
                    1 => (Opcode::DEC, vec![rm_op]),
                    2 => (Opcode::CALL, vec![rm_op]),
                    4 => (Opcode::JMP, vec![rm_op]),
                    6 => (Opcode::PUSH, vec![rm_op]),
                    _ => {
                        return Err(EmulatorError::UnsupportedInstruction(format!(
                            "FF /{}",
                            reg_bits
                        )))
                    }
                }
            }
            0x0F => {
                if bytes.len() <= offset {
                    return Err(EmulatorError::InvalidInstruction(0));
                }
                let secondary = bytes[offset];
                offset += 1;
                match secondary {
                    0x01 => {
                        // 0F 01 group - need to check ModRM byte
                        if bytes.len() <= offset {
                            return Err(EmulatorError::InvalidInstruction(0));
                        }
                        let modrm = bytes[offset];
                        offset += 1;

                        match modrm {
                            0xFA => (Opcode::MONITORX, vec![]),
                            _ => {
                                return Err(EmulatorError::UnsupportedInstruction(format!(
                                    "0F 01 {:02X}",
                                    modrm
                                )))
                            }
                        }
                    }
                    0x05 => (Opcode::SYSCALL, vec![]),
                    0x0D => {
                        // PREFETCHW m8
                        let (rm_op, _reg_op, consumed) =
                            self.decode_modrm_operands(&bytes[offset..], prefix)?;
                        offset += consumed;
                        (Opcode::PREFETCHW, vec![rm_op])
                    }
                    0x31 => (Opcode::RDTSC, vec![]),
                    0x10 => {
                        let (dst, src, consumed) =
                            self.decode_modrm_xmm(&bytes[offset..], prefix)?;
                        offset += consumed;
                        (Opcode::MOVUPS, vec![dst, src])
                    }
                    0x11 => {
                        let (dst, src, consumed) =
                            self.decode_modrm_xmm(&bytes[offset..], prefix)?;
                        offset += consumed;
                        (Opcode::MOVUPS, vec![src, dst])
                    }
                    0x16 => {
                        // MOVLHPS xmm1, xmm2 - Move low to high packed single
                        let (dst, src, consumed) =
                            self.decode_modrm_xmm(&bytes[offset..], prefix)?;
                        offset += consumed;
                        (Opcode::MOVLHPS, vec![dst, src])
                    }
                    0x1F => {
                        // Multi-byte NOP - 0x0F 0x1F /0
                        if bytes.len() <= offset {
                            return Err(EmulatorError::InvalidInstruction(0));
                        }
                        let modrm = bytes[offset];
                        let reg_bits = (modrm >> 3) & 0x07;

                        if reg_bits != 0 {
                            return Err(EmulatorError::UnsupportedInstruction(format!(
                                "0F 1F /{}",
                                reg_bits
                            )));
                        }

                        // Decode the ModR/M operand but ignore it (it's just for encoding length)
                        let (_, _, consumed) =
                            self.decode_modrm_operands(&bytes[offset..], prefix)?;
                        offset += consumed;
                        (Opcode::NOP, vec![])
                    }
                    0x28 => {
                        let (dst, src, consumed) =
                            self.decode_modrm_xmm(&bytes[offset..], prefix)?;
                        offset += consumed;
                        (Opcode::MOVAPS, vec![dst, src])
                    }
                    0x29 => {
                        let (dst, src, consumed) =
                            self.decode_modrm_xmm(&bytes[offset..], prefix)?;
                        offset += consumed;
                        (Opcode::MOVAPS, vec![src, dst])
                    }
                    0x54 => {
                        let (dst, src, consumed) =
                            self.decode_modrm_xmm(&bytes[offset..], prefix)?;
                        offset += consumed;
                        (Opcode::ANDPS, vec![dst, src])
                    }
                    0x56 => {
                        let (dst, src, consumed) =
                            self.decode_modrm_xmm(&bytes[offset..], prefix)?;
                        offset += consumed;
                        (Opcode::ORPS, vec![dst, src])
                    }
                    0x57 => {
                        let (dst, src, consumed) =
                            self.decode_modrm_xmm(&bytes[offset..], prefix)?;
                        offset += consumed;
                        (Opcode::XORPS, vec![dst, src])
                    }
                    0x58 => {
                        let (dst, src, consumed) =
                            self.decode_modrm_xmm(&bytes[offset..], prefix)?;
                        offset += consumed;
                        (Opcode::ADDPS, vec![dst, src])
                    }
                    0x59 => {
                        let (dst, src, consumed) =
                            self.decode_modrm_xmm(&bytes[offset..], prefix)?;
                        offset += consumed;
                        (Opcode::MULPS, vec![dst, src])
                    }
                    0x5C => {
                        let (dst, src, consumed) =
                            self.decode_modrm_xmm(&bytes[offset..], prefix)?;
                        offset += consumed;
                        (Opcode::SUBPS, vec![dst, src])
                    }
                    0x5E => {
                        let (dst, src, consumed) =
                            self.decode_modrm_xmm(&bytes[offset..], prefix)?;
                        offset += consumed;
                        (Opcode::DIVPS, vec![dst, src])
                    }
                    0x2E => {
                        // UCOMISS xmm1, xmm2/m32
                        let (dst, src, consumed) =
                            self.decode_modrm_xmm(&bytes[offset..], prefix)?;
                        offset += consumed;
                        (Opcode::UCOMISS, vec![dst, src])
                    }
                    0x2F => {
                        // COMISS xmm1, xmm2/m32
                        let (dst, src, consumed) =
                            self.decode_modrm_xmm(&bytes[offset..], prefix)?;
                        offset += consumed;
                        (Opcode::COMISS, vec![dst, src])
                    }
                    0xC2 => {
                        // CMPPS xmm1, xmm2/m128, imm8 (or CMPSS if F3 prefix)
                        let (dst, src, consumed) =
                            self.decode_modrm_xmm(&bytes[offset..], prefix)?;
                        offset += consumed;
                        if bytes.len() <= offset {
                            return Err(EmulatorError::InvalidInstruction(0));
                        }
                        let imm = bytes[offset] as i64;
                        offset += 1;

                        let opcode = if matches!(prefix.rep, Some(RepPrefix::RepZ)) {
                            Opcode::CMPSS
                        } else {
                            Opcode::CMPPS
                        };
                        (opcode, vec![dst, src, Operand::Immediate(imm)])
                    }
                    0x82 => {
                        let rel = self.decode_immediate(&bytes[offset..], OperandSize::DWord)?;
                        offset += 4;
                        (Opcode::JB, vec![Operand::Relative(rel)])
                    }
                    0x83 => {
                        let rel = self.decode_immediate(&bytes[offset..], OperandSize::DWord)?;
                        offset += 4;
                        (Opcode::JAE, vec![Operand::Relative(rel)])
                    }
                    0x84 => {
                        let rel = self.decode_immediate(&bytes[offset..], OperandSize::DWord)?;
                        offset += 4;
                        (Opcode::JZ, vec![Operand::Relative(rel)])
                    }
                    0x85 => {
                        let rel = self.decode_immediate(&bytes[offset..], OperandSize::DWord)?;
                        offset += 4;
                        (Opcode::JNZ, vec![Operand::Relative(rel)])
                    }
                    0x86 => {
                        let rel = self.decode_immediate(&bytes[offset..], OperandSize::DWord)?;
                        offset += 4;
                        (Opcode::JBE, vec![Operand::Relative(rel)])
                    }
                    0x87 => {
                        let rel = self.decode_immediate(&bytes[offset..], OperandSize::DWord)?;
                        offset += 4;
                        (Opcode::JA, vec![Operand::Relative(rel)])
                    }
                    0x88 => {
                        let rel = self.decode_immediate(&bytes[offset..], OperandSize::DWord)?;
                        offset += 4;
                        (Opcode::JS, vec![Operand::Relative(rel)])
                    }
                    0x7F => {
                        // MOVDQA xmm/m128, xmm - Move Aligned Double Quadword
                        if bytes.len() <= offset {
                            return Err(EmulatorError::InvalidInstruction(0));
                        }

                        let modrm = bytes[offset];
                        let reg_bits = (modrm >> 3) & 0x07;
                        let rm_bits = modrm & 0x07;
                        let mod_bits = (modrm >> 6) & 0x03;

                        // Source register (in reg field)
                        let src_reg = self.decode_xmm_register(reg_bits, prefix);

                        offset += 1;

                        // Destination operand (r/m field)
                        let dst_operand = if mod_bits == 0x03 {
                            // Register to register
                            let rm_reg = self.decode_xmm_register(rm_bits, prefix);
                            Operand::Register(rm_reg)
                        } else {
                            // Memory operand - decode SIB and displacement
                            let (base, index, scale, consumed_and_disp_size) = self
                                .decode_sib_and_displacement(
                                    mod_bits,
                                    rm_bits,
                                    &bytes[offset..],
                                    prefix,
                                )?;

                            let sib_consumed = if rm_bits == 4 { 1 } else { 0 };
                            let disp_size = if rm_bits == 4 {
                                consumed_and_disp_size - 1
                            } else {
                                consumed_and_disp_size
                            };

                            offset += sib_consumed;

                            let displacement = if disp_size > 0 {
                                let disp = self.decode_displacement(&bytes[offset..], disp_size)?;
                                offset += disp_size;
                                disp
                            } else {
                                0
                            };

                            Operand::Memory {
                                base,
                                index,
                                scale,
                                displacement,
                                size: OperandSize::XmmWord,
                            }
                        };

                        (
                            Opcode::MOVDQA,
                            vec![dst_operand, Operand::Register(src_reg)],
                        )
                    }
                    0xBD => {
                        // BSR r, r/m - Bit Scan Reverse
                        let (rm_op, reg_op, consumed) =
                            self.decode_modrm_operands(&bytes[offset..], prefix)?;
                        offset += consumed;
                        (Opcode::BSR, vec![reg_op, rm_op])
                    }
                    0xB6 => {
                        // MOVZX r, r/m8 - Move with Zero-Extend byte to word/dword/qword
                        let (rm_op, reg_op, consumed) =
                            self.decode_modrm_operands(&bytes[offset..], prefix)?;
                        offset += consumed;
                        (Opcode::MOVZX, vec![reg_op, rm_op])
                    }
                    0xB7 => {
                        // MOVZX r, r/m16 - Move with Zero-Extend word to dword/qword
                        let (rm_op, reg_op, consumed) =
                            self.decode_modrm_operands(&bytes[offset..], prefix)?;
                        offset += consumed;
                        (Opcode::MOVZX, vec![reg_op, rm_op])
                    }
                    0x42 => {
                        // CMOVB r, r/m - Conditional move if below (CF=1)
                        let (rm_op, reg_op, consumed) =
                            self.decode_modrm_operands(&bytes[offset..], prefix)?;
                        offset += consumed;
                        (Opcode::CMOVB, vec![reg_op, rm_op])
                    }
                    0x43 => {
                        // CMOVAE r, r/m - Conditional move if above or equal (CF=0)
                        let (rm_op, reg_op, consumed) =
                            self.decode_modrm_operands(&bytes[offset..], prefix)?;
                        offset += consumed;
                        (Opcode::CMOVAE, vec![reg_op, rm_op])
                    }
                    0x44 => {
                        // CMOVE r, r/m - Conditional move if equal (ZF=1)
                        let (rm_op, reg_op, consumed) =
                            self.decode_modrm_operands(&bytes[offset..], prefix)?;
                        offset += consumed;
                        (Opcode::CMOVE, vec![reg_op, rm_op])
                    }
                    0x45 => {
                        // CMOVNE r, r/m - Conditional move if not equal (ZF=0)
                        let (rm_op, reg_op, consumed) =
                            self.decode_modrm_operands(&bytes[offset..], prefix)?;
                        offset += consumed;
                        (Opcode::CMOVNE, vec![reg_op, rm_op])
                    }
                    0x46 => {
                        // CMOVBE r, r/m - Conditional move if below or equal (CF=1 OR ZF=1)
                        let (rm_op, reg_op, consumed) =
                            self.decode_modrm_operands(&bytes[offset..], prefix)?;
                        offset += consumed;
                        (Opcode::CMOVBE, vec![reg_op, rm_op])
                    }
                    0x4F => {
                        // CMOVG r, r/m - Conditional move if greater (ZF=0 AND SF=OF)
                        let (rm_op, reg_op, consumed) =
                            self.decode_modrm_operands(&bytes[offset..], prefix)?;
                        offset += consumed;
                        (Opcode::CMOVG, vec![reg_op, rm_op])
                    }
                    0x95 => {
                        // SETNE r/m8 - Set byte if not equal (ZF=0)
                        let (rm_op, _, consumed) =
                            self.decode_modrm_operands(&bytes[offset..], prefix)?;
                        offset += consumed;
                        (Opcode::SETNE, vec![rm_op])
                    }
                    0x96 => {
                        // SETBE r/m8 - Set byte if below or equal (CF=1 or ZF=1)
                        let (rm_op, _, consumed) =
                            self.decode_modrm_operands(&bytes[offset..], prefix)?;
                        offset += consumed;
                        (Opcode::SETBE, vec![rm_op])
                    }
                    0xBA => {
                        // Group 8 bit manipulation instructions: BT, BTS, BTR, BTC
                        if bytes.len() <= offset {
                            return Err(EmulatorError::InvalidInstruction(0));
                        }
                        let modrm = bytes[offset];
                        let reg_bits = (modrm >> 3) & 0x07;

                        let opcode = match reg_bits {
                            4 => Opcode::BT,  // BT r/m, imm8
                            5 => Opcode::BTS, // BTS r/m, imm8
                            6 => Opcode::BTR, // BTR r/m, imm8
                            7 => Opcode::BTC, // BTC r/m, imm8
                            _ => {
                                return Err(EmulatorError::UnsupportedInstruction(format!(
                                    "0F BA /{}",
                                    reg_bits
                                )))
                            }
                        };

                        let (rm_op, _, consumed) =
                            self.decode_modrm_operands(&bytes[offset..], prefix)?;
                        offset += consumed;

                        // Add immediate byte operand
                        if bytes.len() <= offset {
                            return Err(EmulatorError::InvalidInstruction(0));
                        }
                        let imm = bytes[offset] as i64;
                        offset += 1;

                        (opcode, vec![rm_op, Operand::Immediate(imm)])
                    }
                    0x6E => {
                        // MOVD/MOVQ xmm, r/m - Move doubleword/quadword from r/m to xmm
                        if bytes.len() <= offset {
                            return Err(EmulatorError::InvalidInstruction(0));
                        }
                        let modrm = bytes[offset];
                        let reg_bits = (modrm >> 3) & 0x07;

                        // Destination is always XMM
                        let xmm_reg = self.decode_xmm_register(reg_bits, prefix);

                        // Source can be GPR or memory, use regular modrm decoding
                        let (rm_op, _, consumed) =
                            self.decode_modrm_operands(&bytes[offset..], prefix)?;
                        offset += consumed;

                        (Opcode::MOVQ, vec![Operand::Register(xmm_reg), rm_op])
                    }
                    0xAF => {
                        // IMUL r, r/m - Two operand integer multiply
                        let (rm_op, reg_op, consumed) =
                            self.decode_modrm_operands(&bytes[offset..], prefix)?;
                        offset += consumed;
                        (Opcode::IMUL, vec![reg_op, rm_op])
                    }
                    0xB1 => {
                        // CMPXCHG r/m, r
                        let (rm_op, reg_op, consumed) =
                            self.decode_modrm_operands(&bytes[offset..], prefix)?;
                        offset += consumed;
                        (Opcode::CMPXCHG, vec![rm_op, reg_op])
                    }
                    0xC1 => {
                        // XADD r/m, r
                        let (rm_op, reg_op, consumed) =
                            self.decode_modrm_operands(&bytes[offset..], prefix)?;
                        offset += consumed;
                        (Opcode::XADD, vec![rm_op, reg_op])
                    }
                    _ => {
                        return Err(EmulatorError::UnsupportedInstruction(format!(
                            "0F {:02X}",
                            secondary
                        )))
                    }
                }
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(format!(
                    "{:02X}",
                    opcode_byte
                )))
            }
        };

        Ok((opcode, operands, offset))
    }

    fn decode_modrm_operands_with_size(
        &self,
        bytes: &[u8],
        prefix: &InstructionPrefix,
        forced_size: OperandSize,
    ) -> Result<(Operand, Operand, usize)> {
        if bytes.is_empty() {
            return Err(EmulatorError::InvalidInstruction(0));
        }

        let modrm = bytes[0];
        let mod_bits = (modrm >> 6) & 0x03;
        let reg_bits = (modrm >> 3) & 0x07;
        let rm_bits = modrm & 0x07;

        let size = forced_size;
        let reg = self.decode_register(reg_bits, prefix, size);

        let mut offset = 1;

        let rm_operand = match mod_bits {
            0x03 => {
                let rm_reg = self.decode_register(rm_bits, prefix, size);
                Operand::Register(rm_reg)
            }
            _ => {
                let (base, index, scale, consumed_and_disp_size) =
                    self.decode_sib_and_displacement(mod_bits, rm_bits, &bytes[offset..], prefix)?;

                // Extract SIB byte consumption (1 if SIB was present, 0 otherwise)
                let sib_consumed = if rm_bits == 4 { 1 } else { 0 };
                let disp_size = if rm_bits == 4 {
                    consumed_and_disp_size - 1 // Subtract the SIB byte
                } else {
                    consumed_and_disp_size
                };

                offset += sib_consumed;

                let displacement = if disp_size > 0 {
                    let disp = self.decode_displacement(&bytes[offset..], disp_size)?;
                    offset += disp_size;
                    disp
                } else {
                    0
                };

                Operand::Memory {
                    base,
                    index,
                    scale,
                    displacement,
                    size,
                }
            }
        };

        Ok((rm_operand, Operand::Register(reg), offset))
    }

    fn decode_modrm_operands(
        &self,
        bytes: &[u8],
        prefix: &InstructionPrefix,
    ) -> Result<(Operand, Operand, usize)> {
        if bytes.is_empty() {
            return Err(EmulatorError::InvalidInstruction(0));
        }

        let modrm = bytes[0];
        let mod_bits = (modrm >> 6) & 0x03;
        let reg_bits = (modrm >> 3) & 0x07;
        let rm_bits = modrm & 0x07;

        let size = self.operand_size(prefix);
        let reg = self.decode_register(reg_bits, prefix, size);

        let mut offset = 1;

        let rm_operand = match mod_bits {
            0x03 => {
                // For register-to-register ModRM, r/m field uses REX.B extension
                let rm_reg = self.decode_rm_register(rm_bits, prefix, size);
                Operand::Register(rm_reg)
            }
            _ => {
                let (base, index, scale, consumed_and_disp_size) =
                    self.decode_sib_and_displacement(mod_bits, rm_bits, &bytes[offset..], prefix)?;

                // Extract SIB byte consumption (1 if SIB was present, 0 otherwise)
                let sib_consumed = if rm_bits == 4 { 1 } else { 0 };
                let disp_size = if rm_bits == 4 {
                    consumed_and_disp_size - 1 // Subtract the SIB byte
                } else {
                    consumed_and_disp_size
                };

                offset += sib_consumed;

                let displacement = if disp_size > 0 {
                    let disp = self.decode_displacement(&bytes[offset..], disp_size)?;
                    offset += disp_size;
                    disp
                } else {
                    0
                };

                Operand::Memory {
                    base,
                    index,
                    scale,
                    displacement,
                    size,
                }
            }
        };

        Ok((rm_operand, Operand::Register(reg), offset))
    }

    fn decode_sib_and_displacement(
        &self,
        mod_bits: u8,
        rm_bits: u8,
        bytes: &[u8],
        prefix: &InstructionPrefix,
    ) -> Result<(Option<Register>, Option<Register>, u8, usize)> {
        // Handle SIB byte case (rm_bits == 4)
        if rm_bits == 4 {
            if bytes.is_empty() {
                return Err(EmulatorError::InvalidInstruction(0));
            }

            let sib = bytes[0];
            let scale = 1 << ((sib >> 6) & 0x03);
            let index_bits = (sib >> 3) & 0x07;
            let base_bits = sib & 0x07;

            let base = if base_bits == 5 && mod_bits == 0 {
                None // [disp32] or [index*scale + disp32]
            } else {
                // For SIB base register, use REX.B extension
                Some(self.decode_rm_register(base_bits, prefix, OperandSize::QWord))
            };

            let index = if index_bits == 4 {
                None // No index register (RSP can't be index)
            } else {
                // For SIB index register, use REX.X extension
                Some(self.decode_index_register(index_bits, prefix, OperandSize::QWord))
            };

            let disp_size = match mod_bits {
                0 if base_bits == 5 => 4, // [disp32] or [index*scale + disp32]
                1 => 1,                   // [base + disp8]
                2 => 4,                   // [base + disp32]
                _ => 0,                   // [base]
            };

            // Return 1 to indicate we consumed the SIB byte
            return Ok((base, index, scale, disp_size + 1));
        }

        // Non-SIB cases - need to handle REX.B extension
        let base = match rm_bits {
            5 if mod_bits == 0 => {
                // In 64-bit mode, [disp32] is RIP-relative
                if matches!(self.mode, DecoderMode::Mode64) {
                    Some(Register::RIP)
                } else {
                    None // Absolute addressing in 32/16-bit modes
                }
            }
            _ => {
                // Use decode_rm_register to properly handle REX.B extensions
                Some(self.decode_rm_register(rm_bits, prefix, OperandSize::QWord))
            }
        };

        let disp_size = match mod_bits {
            0 if rm_bits == 5 => 4, // RIP-relative or absolute
            1 => 1,                 // [reg + disp8]
            2 => 4,                 // [reg + disp32]
            _ => 0,                 // [reg]
        };

        Ok((base, None, 1, disp_size))
    }

    fn decode_register(&self, reg: u8, prefix: &InstructionPrefix, size: OperandSize) -> Register {
        let extended = prefix.rex.as_ref().is_some_and(|r| r.r);
        let reg_num = if extended { reg + 8 } else { reg };

        self.decode_register_by_num(reg_num, size)
    }

    fn decode_rm_register(
        &self,
        reg: u8,
        prefix: &InstructionPrefix,
        size: OperandSize,
    ) -> Register {
        let extended = prefix.rex.as_ref().is_some_and(|r| r.b);
        let reg_num = if extended { reg + 8 } else { reg };

        self.decode_register_by_num(reg_num, size)
    }

    fn decode_index_register(
        &self,
        reg: u8,
        prefix: &InstructionPrefix,
        size: OperandSize,
    ) -> Register {
        let extended = prefix.rex.as_ref().is_some_and(|r| r.x);
        let reg_num = if extended { reg + 8 } else { reg };

        self.decode_register_by_num(reg_num, size)
    }

    fn decode_register_by_num(&self, reg_num: u8, size: OperandSize) -> Register {
        match size {
            OperandSize::Byte => match reg_num {
                0 => Register::AL,
                1 => Register::CL,
                2 => Register::DL,
                3 => Register::BL,
                4 => Register::SPL,
                5 => Register::BPL,
                6 => Register::SIL,
                7 => Register::DIL,
                8 => Register::R8B,
                9 => Register::R9B,
                10 => Register::R10B,
                11 => Register::R11B,
                12 => Register::R12B,
                13 => Register::R13B,
                14 => Register::R14B,
                15 => Register::R15B,
                _ => unreachable!(),
            },
            OperandSize::Word => match reg_num {
                0 => Register::AX,
                1 => Register::CX,
                2 => Register::DX,
                3 => Register::BX,
                4 => Register::SP,
                5 => Register::BP,
                6 => Register::SI,
                7 => Register::DI,
                8 => Register::R8W,
                9 => Register::R9W,
                10 => Register::R10W,
                11 => Register::R11W,
                12 => Register::R12W,
                13 => Register::R13W,
                14 => Register::R14W,
                15 => Register::R15W,
                _ => unreachable!(),
            },
            OperandSize::DWord => match reg_num {
                0 => Register::EAX,
                1 => Register::ECX,
                2 => Register::EDX,
                3 => Register::EBX,
                4 => Register::ESP,
                5 => Register::EBP,
                6 => Register::ESI,
                7 => Register::EDI,
                8 => Register::R8D,
                9 => Register::R9D,
                10 => Register::R10D,
                11 => Register::R11D,
                12 => Register::R12D,
                13 => Register::R13D,
                14 => Register::R14D,
                15 => Register::R15D,
                _ => unreachable!(),
            },
            OperandSize::QWord => match reg_num {
                0 => Register::RAX,
                1 => Register::RCX,
                2 => Register::RDX,
                3 => Register::RBX,
                4 => Register::RSP,
                5 => Register::RBP,
                6 => Register::RSI,
                7 => Register::RDI,
                8 => Register::R8,
                9 => Register::R9,
                10 => Register::R10,
                11 => Register::R11,
                12 => Register::R12,
                13 => Register::R13,
                14 => Register::R14,
                15 => Register::R15,
                _ => unreachable!(),
            },
            OperandSize::XmmWord => match reg_num {
                0 => Register::XMM0,
                1 => Register::XMM1,
                2 => Register::XMM2,
                3 => Register::XMM3,
                4 => Register::XMM4,
                5 => Register::XMM5,
                6 => Register::XMM6,
                7 => Register::XMM7,
                8 => Register::XMM8,
                9 => Register::XMM9,
                10 => Register::XMM10,
                11 => Register::XMM11,
                12 => Register::XMM12,
                13 => Register::XMM13,
                14 => Register::XMM14,
                15 => Register::XMM15,
                _ => unreachable!(),
            },
            OperandSize::YmmWord => match reg_num {
                0 => Register::YMM0,
                1 => Register::YMM1,
                2 => Register::YMM2,
                3 => Register::YMM3,
                4 => Register::YMM4,
                5 => Register::YMM5,
                6 => Register::YMM6,
                7 => Register::YMM7,
                8 => Register::YMM8,
                9 => Register::YMM9,
                10 => Register::YMM10,
                11 => Register::YMM11,
                12 => Register::YMM12,
                13 => Register::YMM13,
                14 => Register::YMM14,
                15 => Register::YMM15,
                _ => unreachable!(),
            },
        }
    }

    fn decode_register_from_opcode(
        &self,
        reg: u8,
        prefix: &InstructionPrefix,
        size: OperandSize,
    ) -> Register {
        let extended = prefix.rex.as_ref().is_some_and(|r| r.b);
        let reg_num = if extended { reg + 8 } else { reg };
        self.decode_register_by_num(reg_num, size)
    }

    fn operand_size(&self, prefix: &InstructionPrefix) -> OperandSize {
        if prefix.rex.as_ref().is_some_and(|r| r.w) {
            OperandSize::QWord
        } else if prefix.operand_size_override {
            OperandSize::Word
        } else {
            match self.mode {
                DecoderMode::Mode64 => OperandSize::DWord,
                DecoderMode::Mode32 => OperandSize::DWord,
                DecoderMode::Mode16 => OperandSize::Word,
            }
        }
    }

    fn decode_immediate(&self, bytes: &[u8], size: OperandSize) -> Result<i64> {
        match size {
            OperandSize::Byte => bytes
                .first()
                .map(|&b| b as i8 as i64)
                .ok_or(EmulatorError::InvalidInstruction(0)),
            OperandSize::Word => {
                if bytes.len() < 2 {
                    return Err(EmulatorError::InvalidInstruction(0));
                }
                Ok(i16::from_le_bytes([bytes[0], bytes[1]]) as i64)
            }
            OperandSize::DWord => {
                if bytes.len() < 4 {
                    return Err(EmulatorError::InvalidInstruction(0));
                }
                Ok(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as i64)
            }
            OperandSize::QWord => {
                if bytes.len() < 8 {
                    return Err(EmulatorError::InvalidInstruction(0));
                }
                Ok(i64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]))
            }
            OperandSize::XmmWord => Err(EmulatorError::InvalidInstruction(0)),
            OperandSize::YmmWord => Err(EmulatorError::InvalidInstruction(0)),
        }
    }

    fn decode_displacement(&self, bytes: &[u8], size: usize) -> Result<i64> {
        match size {
            1 => bytes
                .first()
                .map(|&b| b as i8 as i64)
                .ok_or(EmulatorError::InvalidInstruction(0)),
            4 => {
                if bytes.len() < 4 {
                    return Err(EmulatorError::InvalidInstruction(0));
                }
                Ok(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as i64)
            }
            _ => Err(EmulatorError::InvalidInstruction(0)),
        }
    }

    fn decode_modrm_xmm(
        &self,
        bytes: &[u8],
        prefix: &InstructionPrefix,
    ) -> Result<(Operand, Operand, usize)> {
        if bytes.is_empty() {
            return Err(EmulatorError::InvalidInstruction(0));
        }

        let modrm = bytes[0];
        let mod_bits = (modrm >> 6) & 0x03;
        let reg_bits = (modrm >> 3) & 0x07;
        let rm_bits = modrm & 0x07;

        let reg_xmm = self.decode_xmm_register(reg_bits, prefix);

        let mut offset = 1;

        let rm_operand = match mod_bits {
            0x03 => {
                let rm_xmm = self.decode_xmm_register(rm_bits, prefix);
                Operand::Register(rm_xmm)
            }
            _ => {
                let (base, index, scale, consumed_and_disp_size) =
                    self.decode_sib_and_displacement(mod_bits, rm_bits, &bytes[offset..], prefix)?;

                let sib_consumed = if rm_bits == 4 { 1 } else { 0 };
                let disp_size = if rm_bits == 4 {
                    consumed_and_disp_size - 1
                } else {
                    consumed_and_disp_size
                };

                offset += sib_consumed;

                let displacement = if disp_size > 0 {
                    let disp = self.decode_displacement(&bytes[offset..], disp_size)?;
                    offset += disp_size;
                    disp
                } else {
                    0
                };

                Operand::Memory {
                    base,
                    index,
                    scale,
                    displacement,
                    size: OperandSize::XmmWord,
                }
            }
        };

        Ok((Operand::Register(reg_xmm), rm_operand, offset))
    }

    fn decode_xmm_register(&self, reg: u8, prefix: &InstructionPrefix) -> Register {
        use Register::*;
        let reg_num = if let Some(vex) = prefix.vex {
            reg + if vex.r { 8 } else { 0 }
        } else if let Some(rex) = prefix.rex {
            reg + if rex.r { 8 } else { 0 }
        } else {
            reg
        };

        match reg_num {
            0 => XMM0,
            1 => XMM1,
            2 => XMM2,
            3 => XMM3,
            4 => XMM4,
            5 => XMM5,
            6 => XMM6,
            7 => XMM7,
            8 => XMM8,
            9 => XMM9,
            10 => XMM10,
            11 => XMM11,
            12 => XMM12,
            13 => XMM13,
            14 => XMM14,
            15 => XMM15,
            _ => panic!("Invalid XMM register number: {}", reg_num),
        }
    }

    fn decode_ymm_register(&self, reg: u8, prefix: &InstructionPrefix) -> Register {
        use Register::*;
        let reg_num = if let Some(vex) = prefix.vex {
            reg + if vex.r { 8 } else { 0 }
        } else if let Some(rex) = prefix.rex {
            reg + if rex.r { 8 } else { 0 }
        } else {
            reg
        };

        match reg_num {
            0 => YMM0,
            1 => YMM1,
            2 => YMM2,
            3 => YMM3,
            4 => YMM4,
            5 => YMM5,
            6 => YMM6,
            7 => YMM7,
            8 => YMM8,
            9 => YMM9,
            10 => YMM10,
            11 => YMM11,
            12 => YMM12,
            13 => YMM13,
            14 => YMM14,
            15 => YMM15,
            _ => panic!("Invalid YMM register number: {}", reg_num),
        }
    }

    fn decode_vex_instruction(
        &self,
        bytes: &[u8],
        prefix: &InstructionPrefix,
    ) -> Result<(Opcode, Vec<Operand>, usize)> {
        if bytes.is_empty() {
            return Err(EmulatorError::InvalidInstruction(0));
        }

        let vex = prefix.vex.unwrap();
        let opcode_byte = bytes[0];
        let mut offset = 1;

        // Handle different VEX maps (m field in VEX prefix)
        let (opcode, operands) = match vex.m {
            1 => {
                // VEX.0F map - corresponds to legacy 0F prefix
                match opcode_byte {
                    0x11 => {
                        // VMOVUPS xmm/ymm, xmm/ymm/m128/m256 (store register to memory/register)
                        if bytes.len() <= offset {
                            return Err(EmulatorError::InvalidInstruction(0));
                        }

                        let modrm = bytes[offset];
                        let reg_bits = (modrm >> 3) & 0x07;
                        let rm_bits = modrm & 0x07;
                        let mod_bits = (modrm >> 6) & 0x03;

                        // Source register (in reg field)
                        let src_reg = if vex.l {
                            self.decode_ymm_register(reg_bits, prefix)
                        } else {
                            self.decode_xmm_register(reg_bits, prefix)
                        };

                        offset += 1;

                        // Destination operand (r/m field)
                        let dst_operand = if mod_bits == 0x03 {
                            // Register to register
                            let rm_reg = if vex.l {
                                self.decode_ymm_register(rm_bits, prefix)
                            } else {
                                self.decode_xmm_register(rm_bits, prefix)
                            };
                            Operand::Register(rm_reg)
                        } else {
                            // Memory operand - decode SIB and displacement
                            let (base, index, scale, consumed_and_disp_size) = self
                                .decode_sib_and_displacement(
                                    mod_bits,
                                    rm_bits,
                                    &bytes[offset..],
                                    prefix,
                                )?;

                            let sib_consumed = if rm_bits == 4 { 1 } else { 0 };
                            let disp_size = if rm_bits == 4 {
                                consumed_and_disp_size - 1
                            } else {
                                consumed_and_disp_size
                            };

                            offset += sib_consumed;

                            let displacement = if disp_size > 0 {
                                let disp = self.decode_displacement(&bytes[offset..], disp_size)?;
                                offset += disp_size;
                                disp
                            } else {
                                0
                            };

                            Operand::Memory {
                                base,
                                index,
                                scale,
                                displacement,
                                size: if vex.l {
                                    OperandSize::YmmWord
                                } else {
                                    OperandSize::XmmWord
                                },
                            }
                        };

                        (
                            Opcode::MOVUPS,
                            vec![dst_operand, Operand::Register(src_reg)],
                        )
                    }
                    0x77 => {
                        // VZEROUPPER - Zero upper bits of YMM registers
                        // This instruction has no operands
                        (Opcode::VZEROUPPER, vec![])
                    }
                    _ => {
                        return Err(EmulatorError::UnsupportedInstruction(format!(
                            "VEX.0F {:02X}",
                            opcode_byte
                        )))
                    }
                }
            }
            3 => {
                // VEX.0F3A map - extended instructions
                match opcode_byte {
                    0x18 => {
                        // VINSERTF128 ymm1, ymm2, xmm3/m128, imm8
                        if bytes.len() <= offset {
                            return Err(EmulatorError::InvalidInstruction(0));
                        }

                        let modrm = bytes[offset];
                        let reg_bits = (modrm >> 3) & 0x07;
                        let rm_bits = modrm & 0x07;
                        let mod_bits = (modrm >> 6) & 0x03;

                        // Destination is YMM register (L=1 for 256-bit)
                        let dst_reg = if vex.l {
                            self.decode_ymm_register(reg_bits, prefix)
                        } else {
                            self.decode_xmm_register(reg_bits, prefix)
                        };

                        // VEX.vvvv encodes the first source operand (inverted)
                        let vvvv_reg = if vex.l {
                            self.decode_ymm_register(!vex.vvvv & 0x0F, prefix)
                        } else {
                            self.decode_xmm_register(!vex.vvvv & 0x0F, prefix)
                        };

                        offset += 1;

                        // Second source operand (XMM/m128)
                        let src2_operand = if mod_bits == 0x03 {
                            // Register to register
                            let rm_reg = self.decode_xmm_register(rm_bits, prefix);
                            Operand::Register(rm_reg)
                        } else {
                            // Memory operand - decode SIB and displacement
                            let (base, index, scale, consumed_and_disp_size) = self
                                .decode_sib_and_displacement(
                                    mod_bits,
                                    rm_bits,
                                    &bytes[offset..],
                                    prefix,
                                )?;

                            let sib_consumed = if rm_bits == 4 { 1 } else { 0 };
                            let disp_size = if rm_bits == 4 {
                                consumed_and_disp_size - 1
                            } else {
                                consumed_and_disp_size
                            };

                            offset += sib_consumed;

                            let displacement = if disp_size > 0 {
                                let disp = self.decode_displacement(&bytes[offset..], disp_size)?;
                                offset += disp_size;
                                disp
                            } else {
                                0
                            };

                            Operand::Memory {
                                base,
                                index,
                                scale,
                                displacement,
                                size: OperandSize::XmmWord,
                            }
                        };

                        // Immediate operand
                        if bytes.len() <= offset {
                            return Err(EmulatorError::InvalidInstruction(0));
                        }
                        let imm = bytes[offset] as i64;
                        offset += 1;

                        (
                            Opcode::VINSERTF128,
                            vec![
                                Operand::Register(dst_reg),
                                Operand::Register(vvvv_reg),
                                src2_operand,
                                Operand::Immediate(imm),
                            ],
                        )
                    }
                    _ => {
                        return Err(EmulatorError::UnsupportedInstruction(format!(
                            "VEX.0F3A {:02X}",
                            opcode_byte
                        )))
                    }
                }
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(format!(
                    "VEX map {}: {:02X}",
                    vex.m, opcode_byte
                )))
            }
        };

        Ok((opcode, operands, offset))
    }
}

impl OperandSize {
    pub fn bytes(&self) -> usize {
        match self {
            OperandSize::Byte => 1,
            OperandSize::Word => 2,
            OperandSize::DWord => 4,
            OperandSize::QWord => 8,
            OperandSize::XmmWord => 16,
            OperandSize::YmmWord => 32,
        }
    }
}
