use crate::HookManager;
use crate::engine::ExecutionContext;
use crate::error::{EmulatorError, Result};
use crate::memory::MemoryTrait;
use iced_x86::{Instruction, OpKind};

impl<H: HookManager<M, PS>, M: MemoryTrait<PS>, const PS: u64> ExecutionContext<'_, H, M, PS> {
    pub(crate) fn execute_shufps(&mut self, inst: &Instruction) -> Result<()> {
        // SHUFPS: Shuffle Packed Single-Precision Floating-Point Values
        // Shuffles floats from dst and src according to imm8 control byte
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let src_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_xmm(src_reg)
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                self.read_memory_128(addr)?
            }
            _ => return Err(EmulatorError::UnsupportedOperandType),
        };

        // Get the immediate control byte
        let imm8 = inst.immediate8();
        let dst_value = self.engine.cpu.read_xmm(dst_reg);

        // Extract four 32-bit floats from each operand
        let dst_floats = [
            (dst_value as u32),
            ((dst_value >> 32) as u32),
            ((dst_value >> 64) as u32),
            ((dst_value >> 96) as u32),
        ];
        let src_floats = [
            (src_value as u32),
            ((src_value >> 32) as u32),
            ((src_value >> 64) as u32),
            ((src_value >> 96) as u32),
        ];

        // Shuffle according to immediate bits
        // Bits 0-1 select from dst for result[0]
        // Bits 2-3 select from dst for result[1]
        // Bits 4-5 select from src for result[2]
        // Bits 6-7 select from src for result[3]
        let result0 = dst_floats[(imm8 & 0x03) as usize];
        let result1 = dst_floats[((imm8 >> 2) & 0x03) as usize];
        let result2 = src_floats[((imm8 >> 4) & 0x03) as usize];
        let result3 = src_floats[((imm8 >> 6) & 0x03) as usize];

        // Pack results into u128
        let result = (result0 as u128)
            | ((result1 as u128) << 32)
            | ((result2 as u128) << 64)
            | ((result3 as u128) << 96);

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_unpcklps(&mut self, inst: &Instruction) -> Result<()> {
        // UNPCKLPS: Unpack and Interleave Low Packed Single-Precision Floating-Point Values
        // Interleaves the low quadword (2 floats) of destination and source
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let src_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_xmm(src_reg)
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                self.read_memory_128(addr)?
            }
            _ => return Err(EmulatorError::UnsupportedOperandType),
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);

        // Extract the low quadword (first 2 floats) from each operand
        let dst_float0 = dst_value as u32;
        let dst_float1 = (dst_value >> 32) as u32;
        let src_float0 = src_value as u32;
        let src_float1 = (src_value >> 32) as u32;

        // Interleave: dst[0], src[0], dst[1], src[1]
        let result = (dst_float0 as u128)
            | ((src_float0 as u128) << 32)
            | ((dst_float1 as u128) << 64)
            | ((src_float1 as u128) << 96);

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_unpckhps(&mut self, inst: &Instruction) -> Result<()> {
        // UNPCKHPS: Unpack and Interleave High Packed Single-Precision Floating-Point Values
        // Interleaves the high quadword (2 floats) of destination and source
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let src_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_xmm(src_reg)
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                self.read_memory_128(addr)?
            }
            _ => return Err(EmulatorError::UnsupportedOperandType),
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);

        // Extract the high quadword (last 2 floats) from each operand
        let dst_float2 = (dst_value >> 64) as u32;
        let dst_float3 = (dst_value >> 96) as u32;
        let src_float2 = (src_value >> 64) as u32;
        let src_float3 = (src_value >> 96) as u32;

        // Interleave: dst[2], src[2], dst[3], src[3]
        let result = (dst_float2 as u128)
            | ((src_float2 as u128) << 32)
            | ((dst_float3 as u128) << 64)
            | ((src_float3 as u128) << 96);

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_shufpd(&mut self, inst: &Instruction) -> Result<()> {
        // SHUFPD: Shuffle Packed Double-Precision Floating-Point Values
        // Shuffles doubles from dst and src according to imm8 control byte
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let src_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_xmm(src_reg)
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                self.read_memory_128(addr)?
            }
            _ => return Err(EmulatorError::UnsupportedOperandType),
        };

        // Get the immediate control byte
        let imm8 = inst.immediate8();
        let dst_value = self.engine.cpu.read_xmm(dst_reg);

        // Extract two 64-bit doubles from each operand
        let dst_doubles = [(dst_value as u64), ((dst_value >> 64) as u64)];
        let src_doubles = [(src_value as u64), ((src_value >> 64) as u64)];

        // Shuffle according to immediate bits
        // Bit 0 selects from dst for result[0]
        // Bit 1 selects from src for result[1]
        let result0 = dst_doubles[(imm8 & 0x01) as usize];
        let result1 = src_doubles[((imm8 >> 1) & 0x01) as usize];

        // Pack results into u128
        let result = (result0 as u128) | ((result1 as u128) << 64);

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_unpcklpd(&mut self, inst: &Instruction) -> Result<()> {
        // UNPCKLPD: Unpack and Interleave Low Packed Double-Precision Floating-Point Values
        // Takes the low double from each operand
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let src_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_xmm(src_reg)
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                self.read_memory_128(addr)?
            }
            _ => return Err(EmulatorError::UnsupportedOperandType),
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);

        // Extract the low double from each operand
        let dst_low = dst_value as u64;
        let src_low = src_value as u64;

        // Result is: dst[0], src[0]
        let result = (dst_low as u128) | ((src_low as u128) << 64);

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_unpckhpd(&mut self, inst: &Instruction) -> Result<()> {
        // UNPCKHPD: Unpack and Interleave High Packed Double-Precision Floating-Point Values
        // Takes the high double from each operand
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let src_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_xmm(src_reg)
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                self.read_memory_128(addr)?
            }
            _ => return Err(EmulatorError::UnsupportedOperandType),
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);

        // Extract the high double from each operand
        let dst_high = (dst_value >> 64) as u64;
        let src_high = (src_value >> 64) as u64;

        // Result is: dst[1], src[1]
        let result = (dst_high as u128) | ((src_high as u128) << 64);

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }
}
