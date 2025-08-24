use crate::error::{EmulatorError, Result};
use crate::cpu::Register;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperandSize {
    Byte,
    Word,
    DWord,
    QWord,
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
    SUB,
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
    NOP,
    HLT,
    INT,
    SYSCALL,
}

#[derive(Debug, Clone)]
pub struct Instruction {
    pub address: u64,
    pub opcode: Opcode,
    pub operands: Vec<Operand>,
    pub size: usize,
    pub prefix: InstructionPrefix,
}

#[derive(Debug, Clone, Default)]
pub struct InstructionPrefix {
    pub rex: Option<RexPrefix>,
    pub operand_size_override: bool,
    pub address_size_override: bool,
    pub segment: Option<Register>,
    pub rep: Option<RepPrefix>,
}

#[derive(Debug, Clone, Copy)]
pub struct RexPrefix {
    pub w: bool,
    pub r: bool,
    pub x: bool,
    pub b: bool,
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
                _ => break,
            }
            offset += 1;
        }
        
        if offset >= bytes.len() {
            return Err(EmulatorError::InvalidInstruction(address));
        }
        
        let _opcode_byte = bytes[offset];
        offset += 1;
        
        let (opcode, operands, consumed) = self.decode_instruction(
            &bytes[offset - 1..],
            &prefix,
        )?;
        // consumed includes the opcode byte, and offset-1 is the position before we read the opcode
        let total_size = (offset - 1) + consumed;
        
        Ok(Instruction {
            address,
            opcode,
            operands,
            size: total_size,
            prefix,
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
            0x00..=0x05 => {
                let (op1, op2, consumed) = self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;
                (Opcode::ADD, vec![op1, op2])
            }
            0x28..=0x2D => {
                let (op1, op2, consumed) = self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;
                (Opcode::SUB, vec![op1, op2])
            }
            0x30..=0x35 => {
                let (op1, op2, consumed) = self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;
                (Opcode::XOR, vec![op1, op2])
            }
            0x38..=0x3D => {
                let (op1, op2, consumed) = self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;
                (Opcode::CMP, vec![op1, op2])
            }
            0x50..=0x57 => {
                let reg = self.decode_register_from_opcode(opcode_byte - 0x50, prefix, OperandSize::QWord);
                (Opcode::PUSH, vec![Operand::Register(reg)])
            }
            0x58..=0x5F => {
                let reg = self.decode_register_from_opcode(opcode_byte - 0x58, prefix, OperandSize::QWord);
                (Opcode::POP, vec![Operand::Register(reg)])
            }
            0x74 => {
                let rel = bytes.get(offset).copied().ok_or(EmulatorError::InvalidInstruction(0))? as i8;
                offset += 1;
                (Opcode::JZ, vec![Operand::Relative(rel as i64)])
            }
            0x75 => {
                let rel = bytes.get(offset).copied().ok_or(EmulatorError::InvalidInstruction(0))? as i8;
                offset += 1;
                (Opcode::JNZ, vec![Operand::Relative(rel as i64)])
            }
            0x85 => {
                let (op1, op2, consumed) = self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;
                (Opcode::TEST, vec![op1, op2])
            }
            0x88 | 0x89 => {
                // MOV r/m, r - memory/rm is destination
                let (rm_op, reg_op, consumed) = self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;
                (Opcode::MOV, vec![rm_op, reg_op])
            }
            0x8A | 0x8B => {
                // MOV r, r/m - register is destination
                let (rm_op, reg_op, consumed) = self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;
                (Opcode::MOV, vec![reg_op, rm_op])
            }
            0x90 => (Opcode::NOP, vec![]),
            0xB0..=0xB7 => {
                let reg = self.decode_register_from_opcode(opcode_byte - 0xB0, prefix, OperandSize::Byte);
                let imm = bytes.get(offset).copied().ok_or(EmulatorError::InvalidInstruction(0))?;
                offset += 1;
                (Opcode::MOV, vec![Operand::Register(reg), Operand::Immediate(imm as i64)])
            }
            0xB8..=0xBF => {
                let reg = self.decode_register_from_opcode(opcode_byte - 0xB8, prefix, OperandSize::QWord);
                let imm = self.decode_immediate(&bytes[offset..], self.operand_size(prefix))?;
                offset += self.operand_size(prefix).bytes();
                (Opcode::MOV, vec![Operand::Register(reg), Operand::Immediate(imm)])
            }
            0xC3 => (Opcode::RET, vec![]),
            0xC7 => {
                let (rm_op, _reg_op, consumed) = self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;
                // 0xC7 always uses imm32 even with REX.W
                let imm = self.decode_immediate(&bytes[offset..], OperandSize::DWord)?;
                offset += 4;
                (Opcode::MOV, vec![rm_op, Operand::Immediate(imm)])
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
                let rel = bytes.get(offset).copied().ok_or(EmulatorError::InvalidInstruction(0))? as i8;
                offset += 1;
                (Opcode::JMP, vec![Operand::Relative(rel as i64)])
            }
            0xF4 => (Opcode::HLT, vec![]),
            0xFF => {
                if bytes.len() <= offset {
                    return Err(EmulatorError::InvalidInstruction(0));
                }
                let modrm = bytes[offset];
                let reg_bits = (modrm >> 3) & 0x07;
                let (rm_op, _, consumed) = self.decode_modrm_operands(&bytes[offset..], prefix)?;
                offset += consumed;
                
                match reg_bits {
                    0 => (Opcode::INC, vec![rm_op]),
                    1 => (Opcode::DEC, vec![rm_op]),
                    2 => (Opcode::CALL, vec![rm_op]),
                    4 => (Opcode::JMP, vec![rm_op]),
                    6 => (Opcode::PUSH, vec![rm_op]),
                    _ => return Err(EmulatorError::UnsupportedInstruction(format!("FF /{}", reg_bits))),
                }
            }
            0x0F => {
                if bytes.len() <= offset {
                    return Err(EmulatorError::InvalidInstruction(0));
                }
                let secondary = bytes[offset];
                offset += 1;
                match secondary {
                    0x05 => (Opcode::SYSCALL, vec![]),
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
                    _ => return Err(EmulatorError::UnsupportedInstruction(format!("0F {:02X}", secondary))),
                }
            }
            _ => return Err(EmulatorError::UnsupportedInstruction(format!("{:02X}", opcode_byte))),
        };
        
        Ok((opcode, operands, offset))
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
                let rm_reg = self.decode_register(rm_bits, prefix, size);
                Operand::Register(rm_reg)
            }
            _ => {
                let (base, index, scale, consumed_and_disp_size) = self.decode_sib_and_displacement(
                    mod_bits,
                    rm_bits,
                    &bytes[offset..],
                    prefix,
                )?;
                
                // Extract SIB byte consumption (1 if SIB was present, 0 otherwise)
                let sib_consumed = if rm_bits == 4 { 1 } else { 0 };
                let disp_size = if rm_bits == 4 {
                    consumed_and_disp_size - 1  // Subtract the SIB byte
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
                Some(self.decode_register(base_bits, prefix, OperandSize::QWord))
            };
            
            let index = if index_bits == 4 {
                None // No index register (RSP can't be index)
            } else {
                Some(self.decode_register(index_bits, prefix, OperandSize::QWord))
            };
            
            let disp_size = match mod_bits {
                0 if base_bits == 5 => 4,  // [disp32] or [index*scale + disp32]
                1 => 1,  // [base + disp8]
                2 => 4,  // [base + disp32]
                _ => 0,  // [base]
            };
            
            // Return 1 to indicate we consumed the SIB byte
            return Ok((base, index, scale, disp_size + 1));
        }
        
        // Non-SIB cases
        let base = match rm_bits {
            0 => Some(Register::RAX),
            1 => Some(Register::RCX),
            2 => Some(Register::RDX),
            3 => Some(Register::RBX),
            5 if mod_bits == 0 => None,  // RIP-relative or absolute
            5 => Some(Register::RBP),
            6 => Some(Register::RSI),
            7 => Some(Register::RDI),
            _ => None,
        };
        
        let disp_size = match mod_bits {
            0 if rm_bits == 5 => 4,  // RIP-relative or absolute
            1 => 1,  // [reg + disp8]
            2 => 4,  // [reg + disp32]
            _ => 0,  // [reg]
        };
        
        Ok((base, None, 1, disp_size))
    }
    
    fn decode_register(&self, reg: u8, prefix: &InstructionPrefix, size: OperandSize) -> Register {
        let extended = prefix.rex.as_ref().map_or(false, |r| r.r);
        let reg_num = if extended { reg + 8 } else { reg };
        
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
                _ => Register::AL,
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
                _ => Register::AX,
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
                _ => Register::EAX,
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
                _ => Register::RAX,
            },
        }
    }
    
    fn decode_register_from_opcode(&self, reg: u8, prefix: &InstructionPrefix, size: OperandSize) -> Register {
        let extended = prefix.rex.as_ref().map_or(false, |r| r.b);
        let reg_num = if extended { reg + 8 } else { reg };
        self.decode_register(reg_num, prefix, size)
    }
    
    fn operand_size(&self, prefix: &InstructionPrefix) -> OperandSize {
        if prefix.rex.as_ref().map_or(false, |r| r.w) {
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
            OperandSize::Byte => {
                bytes.get(0)
                    .map(|&b| b as i8 as i64)
                    .ok_or(EmulatorError::InvalidInstruction(0))
            }
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
                    bytes[0], bytes[1], bytes[2], bytes[3],
                    bytes[4], bytes[5], bytes[6], bytes[7],
                ]))
            }
        }
    }
    
    fn decode_displacement(&self, bytes: &[u8], size: usize) -> Result<i64> {
        match size {
            1 => bytes.get(0)
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
}

impl OperandSize {
    pub fn bytes(&self) -> usize {
        match self {
            OperandSize::Byte => 1,
            OperandSize::Word => 2,
            OperandSize::DWord => 4,
            OperandSize::QWord => 8,
        }
    }
}