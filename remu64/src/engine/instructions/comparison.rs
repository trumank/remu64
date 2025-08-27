use crate::HookManager;
use crate::engine::ExecutionContext;
use crate::error::{EmulatorError, Result};
use crate::memory::MemoryTrait;
use iced_x86::{Instruction, OpKind};

impl<H: HookManager<M>, M: MemoryTrait> ExecutionContext<'_, H, M> {
    pub(crate) fn execute_test(&mut self, inst: &Instruction) -> Result<()> {
        let src1 = self.read_operand(inst, 0)?;
        let src2 = self.read_operand(inst, 1)?;
        let result = src1 & src2;

        // Update flags (TEST only affects flags, doesn't write result)
        self.update_flags_logical_iced(result, inst)?;
        Ok(())
    }

    pub(crate) fn execute_cmp(&mut self, inst: &Instruction) -> Result<()> {
        let dst_value = self.read_operand(inst, 0)?;
        let src_value = self.read_operand(inst, 1)?;
        let result = dst_value.wrapping_sub(src_value);

        // Update flags (CMP is like SUB but doesn't write result)
        self.update_flags_arithmetic_iced(dst_value, src_value, result, true, inst)?;
        Ok(())
    }

    pub(crate) fn execute_cmpps(&mut self, inst: &Instruction) -> Result<()> {
        // CMPPS: Compare Packed Single-Precision Floating-Point Values
        // Compares four 32-bit floats simultaneously
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
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid CMPPS source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let imm = inst.immediate(2) as u8;

        // Extract four 32-bit floats from each operand
        let dst_floats = [
            f32::from_bits(dst_value as u32),
            f32::from_bits((dst_value >> 32) as u32),
            f32::from_bits((dst_value >> 64) as u32),
            f32::from_bits((dst_value >> 96) as u32),
        ];
        let src_floats = [
            f32::from_bits(src_value as u32),
            f32::from_bits((src_value >> 32) as u32),
            f32::from_bits((src_value >> 64) as u32),
            f32::from_bits((src_value >> 96) as u32),
        ];

        let mut result = 0u128;
        for i in 0..4 {
            let cmp_result = self.compare_floats(dst_floats[i], src_floats[i], imm);
            if cmp_result {
                result |= 0xFFFFFFFFu128 << (i * 32);
            }
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_cmpss(&mut self, inst: &Instruction) -> Result<()> {
        // CMPSS: Compare Scalar Single-Precision Floating-Point Values
        // Compares only the lowest 32-bit float, preserves upper bits
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let src_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_xmm(src_reg) as u32
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                self.read_memory_sized(addr, 4)? as u32
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid CMPSS source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let imm = inst.immediate(2) as u8;

        let dst_float = f32::from_bits(dst_value as u32);
        let src_float = f32::from_bits(src_value);

        let cmp_result = self.compare_floats(dst_float, src_float, imm);
        let result_low = if cmp_result { 0xFFFFFFFFu32 } else { 0 };

        // Preserve upper 96 bits, replace lower 32 bits
        let result = (dst_value & !0xFFFFFFFF) | result_low as u128;

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_comiss(&mut self, inst: &Instruction) -> Result<()> {
        // COMISS: Compare Ordered Scalar Single-Precision Floating-Point Values and Set EFLAGS
        let src1_reg = self.convert_register(inst.op_register(0))?;
        let src1_float = f32::from_bits(self.engine.cpu.read_xmm(src1_reg) as u32);

        let src2_float = match inst.op_kind(1) {
            OpKind::Register => {
                let src2_reg = self.convert_register(inst.op_register(1))?;
                f32::from_bits(self.engine.cpu.read_xmm(src2_reg) as u32)
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                f32::from_bits(self.read_memory_sized(addr, 4)? as u32)
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid COMISS source".to_string(),
                ));
            }
        };

        self.set_comparison_flags(src1_float, src2_float, false);
        Ok(())
    }

    pub(crate) fn execute_ucomiss(&mut self, inst: &Instruction) -> Result<()> {
        // UCOMISS: Compare Unordered Scalar Single-Precision Floating-Point Values and Set EFLAGS
        let src1_reg = self.convert_register(inst.op_register(0))?;
        let src1_float = f32::from_bits(self.engine.cpu.read_xmm(src1_reg) as u32);

        let src2_float = match inst.op_kind(1) {
            OpKind::Register => {
                let src2_reg = self.convert_register(inst.op_register(1))?;
                f32::from_bits(self.engine.cpu.read_xmm(src2_reg) as u32)
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                f32::from_bits(self.read_memory_sized(addr, 4)? as u32)
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid UCOMISS source".to_string(),
                ));
            }
        };

        self.set_comparison_flags(src1_float, src2_float, true);
        Ok(())
    }
}
