use crate::engine::ExecutionContext;
use crate::error::{EmulatorError, Result};
use crate::memory::MemoryTrait;
use crate::{HookManager, Register};
use iced_x86::{Code, Instruction, OpKind};

impl<H: HookManager<M>, M: MemoryTrait> ExecutionContext<'_, H, M> {
    pub(crate) fn execute_mov(&mut self, inst: &Instruction) -> Result<()> {
        let src_value = self.read_operand(inst, 1)?;
        self.write_operand(inst, 0, src_value)?;
        Ok(())
    }

    pub(crate) fn execute_push(&mut self, inst: &Instruction) -> Result<()> {
        let value = self.read_operand(inst, 0)?;
        let stack_size = match inst.code() {
            Code::Push_r64 | Code::Push_rm64 | Code::Pushd_imm32 => 8,
            Code::Push_r32 | Code::Push_rm32 => 4,
            Code::Push_r16 | Code::Push_rm16 | Code::Pushw_imm8 => 2,
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(format!(
                    "Unsupported push variant: {:?}",
                    inst.code()
                )));
            }
        };

        // Update RSP first
        let new_rsp = self
            .engine
            .cpu
            .read_reg(Register::RSP)
            .wrapping_sub(stack_size as u64);
        self.engine.cpu.write_reg(Register::RSP, new_rsp);

        // Write value to stack
        self.write_memory_sized(new_rsp, value, stack_size)?;
        Ok(())
    }

    pub(crate) fn execute_lea(&mut self, inst: &Instruction) -> Result<()> {
        // LEA (Load Effective Address) calculates the memory address but doesn't actually access memory
        let address = self.calculate_memory_address(inst, 1)?;
        self.write_operand(inst, 0, address)?;
        Ok(())
    }

    pub(crate) fn execute_pop(&mut self, inst: &Instruction) -> Result<()> {
        // Read value from top of stack
        let rsp = self.engine.cpu.read_reg(Register::RSP);
        let stack_size = match inst.code() {
            Code::Pop_r64 | Code::Pop_rm64 => 8,
            Code::Pop_r32 | Code::Pop_rm32 => 4,
            Code::Pop_r16 | Code::Pop_rm16 => 2,
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(format!(
                    "Unsupported pop variant: {:?}",
                    inst.code()
                )));
            }
        };

        let value = self.read_memory_sized(rsp, stack_size)?;

        // Update RSP first
        let new_rsp = rsp + stack_size as u64;
        self.engine.cpu.write_reg(Register::RSP, new_rsp);

        // Write value to destination
        self.write_operand(inst, 0, value)?;
        Ok(())
    }

    pub(crate) fn execute_movsxd(&mut self, inst: &Instruction) -> Result<()> {
        // MOVSXD: Move with sign extension from 32-bit to 64-bit
        let src_value = self.read_operand(inst, 1)? as u32; // Read as 32-bit
        let result = src_value as i32 as i64 as u64; // Sign extend to 64-bit

        // Write 64-bit result to destination
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    pub(crate) fn execute_movzx(&mut self, inst: &Instruction) -> Result<()> {
        // MOVZX: Move with zero extension
        let src_value = self.read_operand(inst, 1)?;
        let src_size = self.get_operand_size_from_instruction(inst, 1)?;

        // Zero extend based on source size
        let result = match src_size {
            1 => src_value & 0xFF,   // byte to word/dword/qword
            2 => src_value & 0xFFFF, // word to dword/qword
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(format!(
                    "Invalid MOVZX source size: {}",
                    src_size
                )));
            }
        };

        // Write result to destination (automatically zero-extends to full register size)
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    pub(crate) fn execute_movsx(&mut self, inst: &Instruction) -> Result<()> {
        // MOVSX: Move with sign extension
        let src_value = self.read_operand(inst, 1)?;
        let src_size = self.get_operand_size_from_instruction(inst, 1)?;

        // Sign extend based on source size
        let result = match src_size {
            1 => ((src_value as i8) as i64) as u64, // byte to word/dword/qword (sign extend)
            2 => ((src_value as i16) as i64) as u64, // word to dword/qword (sign extend)
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(format!(
                    "Invalid MOVSX source size: {}",
                    src_size
                )));
            }
        };

        // Write result to destination
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    pub(crate) fn execute_vmovdqu(&mut self, inst: &Instruction) -> Result<()> {
        // VMOVDQU: Vector Move Unaligned Packed Integer Values (256-bit)
        // Can move from YMM to memory, memory to YMM, or YMM to YMM

        match (inst.op_kind(0), inst.op_kind(1)) {
            (OpKind::Register, OpKind::Memory) => {
                // ymm, [mem] - load from memory to YMM register
                let src_data = self.read_ymm_memory(inst, 1)?;
                let dst_reg = self.convert_register(inst.op_register(0))?;
                self.engine.cpu.write_ymm(dst_reg, src_data);
                Ok(())
            }
            (OpKind::Memory, OpKind::Register) => {
                // [mem], ymm - store from YMM register to memory
                let src_reg = self.convert_register(inst.op_register(1))?;
                let src_data = self.engine.cpu.read_ymm(src_reg);
                self.write_ymm_memory(inst, 0, src_data)?;
                Ok(())
            }
            (OpKind::Register, OpKind::Register) => {
                // ymm, ymm - move YMM register to YMM register
                let src_reg = self.convert_register(inst.op_register(1))?;
                let dst_reg = self.convert_register(inst.op_register(0))?;
                let src_data = self.engine.cpu.read_ymm(src_reg);
                self.engine.cpu.write_ymm(dst_reg, src_data);
                Ok(())
            }
            _ => Err(EmulatorError::UnsupportedInstruction(format!(
                "Unsupported VMOVDQU operand types: {:?}, {:?}",
                inst.op_kind(0),
                inst.op_kind(1)
            ))),
        }
    }

    pub(crate) fn execute_vmovdqa(&mut self, inst: &Instruction) -> Result<()> {
        // VMOVDQA: Vector Move Aligned Packed Integer Values (256-bit)
        // Same as VMOVDQU but requires 32-byte alignment (we'll ignore alignment for now)
        match (inst.op_kind(0), inst.op_kind(1)) {
            (OpKind::Register, OpKind::Memory) => {
                // ymm, [mem] - load from memory to YMM register
                let src_data = self.read_ymm_memory(inst, 1)?;
                let dst_reg = self.convert_register(inst.op_register(0))?;
                self.engine.cpu.write_ymm(dst_reg, src_data);
                Ok(())
            }
            (OpKind::Memory, OpKind::Register) => {
                // [mem], ymm - store from YMM register to memory
                let src_reg = self.convert_register(inst.op_register(1))?;
                let src_data = self.engine.cpu.read_ymm(src_reg);
                self.write_ymm_memory(inst, 0, src_data)?;
                Ok(())
            }
            (OpKind::Register, OpKind::Register) => {
                // ymm, ymm - move YMM register to YMM register
                let src_reg = self.convert_register(inst.op_register(1))?;
                let dst_reg = self.convert_register(inst.op_register(0))?;
                let src_data = self.engine.cpu.read_ymm(src_reg);
                self.engine.cpu.write_ymm(dst_reg, src_data);
                Ok(())
            }
            _ => Err(EmulatorError::UnsupportedInstruction(format!(
                "Unsupported VMOVDQA operand types: {:?}, {:?}",
                inst.op_kind(0),
                inst.op_kind(1)
            ))),
        }
    }

    pub(crate) fn execute_movups(&mut self, inst: &Instruction) -> Result<()> {
        // MOVUPS: Move Unaligned Packed Single Precision Floating-Point Values (128-bit SSE)
        match (inst.op_kind(0), inst.op_kind(1)) {
            (OpKind::Register, OpKind::Memory) => {
                // xmm, [mem] - load from memory to XMM register
                let addr = self.calculate_memory_address(inst, 1)?;
                let src_data = self.read_memory_128(addr)?;
                let dst_reg = self.convert_register(inst.op_register(0))?;
                self.engine.cpu.write_xmm(dst_reg, src_data);
                Ok(())
            }
            (OpKind::Memory, OpKind::Register) => {
                // [mem], xmm - store from XMM register to memory
                let addr = self.calculate_memory_address(inst, 0)?;
                let src_reg = self.convert_register(inst.op_register(1))?;
                let src_data = self.engine.cpu.read_xmm(src_reg);
                self.write_memory_128(addr, src_data)?;
                Ok(())
            }
            (OpKind::Register, OpKind::Register) => {
                // xmm, xmm - move XMM register to XMM register
                let src_reg = self.convert_register(inst.op_register(1))?;
                let dst_reg = self.convert_register(inst.op_register(0))?;
                let src_data = self.engine.cpu.read_xmm(src_reg);
                self.engine.cpu.write_xmm(dst_reg, src_data);
                Ok(())
            }
            _ => Err(EmulatorError::UnsupportedInstruction(format!(
                "Unsupported MOVUPS operand types: {:?}, {:?}",
                inst.op_kind(0),
                inst.op_kind(1)
            ))),
        }
    }

    pub(crate) fn execute_movdqu(&mut self, inst: &Instruction) -> Result<()> {
        // MOVDQU: Move Unaligned Packed Integer Values (128-bit SSE)
        match (inst.op_kind(0), inst.op_kind(1)) {
            (OpKind::Register, OpKind::Memory) => {
                // xmm, [mem] - load from memory to XMM register
                let addr = self.calculate_memory_address(inst, 1)?;
                let src_data = self.read_memory_128(addr)?;
                let dst_reg = self.convert_register(inst.op_register(0))?;
                self.engine.cpu.write_xmm(dst_reg, src_data);
                Ok(())
            }
            (OpKind::Memory, OpKind::Register) => {
                // [mem], xmm - store from XMM register to memory
                let addr = self.calculate_memory_address(inst, 0)?;
                let src_reg = self.convert_register(inst.op_register(1))?;
                let src_data = self.engine.cpu.read_xmm(src_reg);
                self.write_memory_128(addr, src_data)?;
                Ok(())
            }
            (OpKind::Register, OpKind::Register) => {
                // xmm, xmm - move XMM register to XMM register
                let src_reg = self.convert_register(inst.op_register(1))?;
                let dst_reg = self.convert_register(inst.op_register(0))?;
                let src_data = self.engine.cpu.read_xmm(src_reg);
                self.engine.cpu.write_xmm(dst_reg, src_data);
                Ok(())
            }
            _ => Err(EmulatorError::UnsupportedInstruction(format!(
                "Unsupported MOVDQU operand types: {:?}, {:?}",
                inst.op_kind(0),
                inst.op_kind(1)
            ))),
        }
    }

    pub(crate) fn execute_movdqa(&mut self, inst: &Instruction) -> Result<()> {
        // MOVDQA: Move Aligned Packed Integer Values (128-bit SSE)
        // Same as MOVDQU but requires 16-byte alignment (we'll ignore alignment for now)
        match (inst.op_kind(0), inst.op_kind(1)) {
            (OpKind::Register, OpKind::Memory) => {
                // xmm, [mem] - load from memory to XMM register
                let addr = self.calculate_memory_address(inst, 1)?;
                let src_data = self.read_memory_128(addr)?;
                let dst_reg = self.convert_register(inst.op_register(0))?;
                self.engine.cpu.write_xmm(dst_reg, src_data);
                Ok(())
            }
            (OpKind::Memory, OpKind::Register) => {
                // [mem], xmm - store from XMM register to memory
                let addr = self.calculate_memory_address(inst, 0)?;
                let src_reg = self.convert_register(inst.op_register(1))?;
                let src_data = self.engine.cpu.read_xmm(src_reg);
                self.write_memory_128(addr, src_data)?;
                Ok(())
            }
            (OpKind::Register, OpKind::Register) => {
                // xmm, xmm - move XMM register to XMM register
                let src_reg = self.convert_register(inst.op_register(1))?;
                let dst_reg = self.convert_register(inst.op_register(0))?;
                let src_data = self.engine.cpu.read_xmm(src_reg);
                self.engine.cpu.write_xmm(dst_reg, src_data);
                Ok(())
            }
            _ => Err(EmulatorError::UnsupportedInstruction(format!(
                "Unsupported MOVDQA operand types: {:?}, {:?}",
                inst.op_kind(0),
                inst.op_kind(1)
            ))),
        }
    }

    pub(crate) fn execute_movd(&mut self, inst: &Instruction) -> Result<()> {
        // MOVD: Move 32-bit value between general-purpose register and XMM register
        match (inst.op_kind(0), inst.op_kind(1)) {
            (OpKind::Register, OpKind::Register) => {
                let dst_reg = self.convert_register(inst.op_register(0))?;
                let src_reg = self.convert_register(inst.op_register(1))?;

                // Check if destination is XMM and source is general-purpose
                if matches!(
                    dst_reg,
                    Register::XMM0
                        | Register::XMM1
                        | Register::XMM2
                        | Register::XMM3
                        | Register::XMM4
                        | Register::XMM5
                        | Register::XMM6
                        | Register::XMM7
                        | Register::XMM8
                        | Register::XMM9
                        | Register::XMM10
                        | Register::XMM11
                        | Register::XMM12
                        | Register::XMM13
                        | Register::XMM14
                        | Register::XMM15
                ) {
                    // Moving from general-purpose register to XMM
                    let src_value = self.engine.cpu.read_reg(src_reg) as u32; // Take lower 32 bits
                    // Zero out the XMM register and set the lower 32 bits
                    self.engine.cpu.write_xmm(dst_reg, src_value as u128);
                } else if matches!(
                    src_reg,
                    Register::XMM0
                        | Register::XMM1
                        | Register::XMM2
                        | Register::XMM3
                        | Register::XMM4
                        | Register::XMM5
                        | Register::XMM6
                        | Register::XMM7
                        | Register::XMM8
                        | Register::XMM9
                        | Register::XMM10
                        | Register::XMM11
                        | Register::XMM12
                        | Register::XMM13
                        | Register::XMM14
                        | Register::XMM15
                ) {
                    // Moving from XMM register to general-purpose register
                    let src_value = self.engine.cpu.read_xmm(src_reg) as u32; // Take lower 32 bits
                    self.engine.cpu.write_reg(dst_reg, src_value as u64);
                } else {
                    return Err(EmulatorError::UnsupportedInstruction(
                        "MOVD requires one XMM and one general-purpose register".to_string(),
                    ));
                }
                Ok(())
            }
            (OpKind::Register, OpKind::Memory) => {
                // xmm, [mem] - load 32 bits from memory to XMM register
                let dst_reg = self.convert_register(inst.op_register(0))?;
                let addr = self.calculate_memory_address(inst, 1)?;
                let src_value = self.read_memory_sized(addr, 4)? as u32;
                self.engine.cpu.write_xmm(dst_reg, src_value as u128);
                Ok(())
            }
            (OpKind::Memory, OpKind::Register) => {
                // [mem], xmm - store lower 32 bits of XMM register to memory
                let src_reg = self.convert_register(inst.op_register(1))?;
                let addr = self.calculate_memory_address(inst, 0)?;
                let src_value = self.engine.cpu.read_xmm(src_reg) as u32;
                self.write_memory_sized(addr, src_value as u64, 4)?;
                Ok(())
            }
            _ => Err(EmulatorError::UnsupportedInstruction(format!(
                "Unsupported MOVD operand types: {:?}, {:?}",
                inst.op_kind(0),
                inst.op_kind(1)
            ))),
        }
    }

    pub(crate) fn execute_movaps(&mut self, inst: &Instruction) -> Result<()> {
        // MOVAPS: Move Aligned Packed Single-Precision Floating-Point Values
        // Same as MOVDQA/MOVDQU but with float semantics (we ignore alignment requirements)
        match (inst.op_kind(0), inst.op_kind(1)) {
            (OpKind::Register, OpKind::Register) => {
                let dst_reg = self.convert_register(inst.op_register(0))?;
                let src_reg = self.convert_register(inst.op_register(1))?;
                let src_value = self.engine.cpu.read_xmm(src_reg);
                self.engine.cpu.write_xmm(dst_reg, src_value);
                Ok(())
            }
            (OpKind::Register, OpKind::Memory) => {
                let dst_reg = self.convert_register(inst.op_register(0))?;
                let addr = self.calculate_memory_address(inst, 1)?;
                let src_value = self.read_memory_128(addr)?;
                self.engine.cpu.write_xmm(dst_reg, src_value);
                Ok(())
            }
            (OpKind::Memory, OpKind::Register) => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                let addr = self.calculate_memory_address(inst, 0)?;
                let src_value = self.engine.cpu.read_xmm(src_reg);
                self.write_memory_128(addr, src_value)?;
                Ok(())
            }
            _ => Err(EmulatorError::UnsupportedInstruction(format!(
                "Unsupported MOVAPS operand types: {:?}, {:?}",
                inst.op_kind(0),
                inst.op_kind(1)
            ))),
        }
    }

    pub(crate) fn execute_xchg(&mut self, inst: &Instruction) -> Result<()> {
        // XCHG: Exchange values between two operands
        let operand1_value = self.read_operand(inst, 0)?;
        let operand2_value = self.read_operand(inst, 1)?;

        // Write values in swapped positions
        self.write_operand(inst, 0, operand2_value)?;
        self.write_operand(inst, 1, operand1_value)?;

        // XCHG doesn't affect flags
        Ok(())
    }
}
