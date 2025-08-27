use crate::HookManager;
use crate::engine::ExecutionContext;
use crate::error::{EmulatorError, Result};
use crate::memory::MemoryTrait;
use iced_x86::{Instruction, OpKind};

impl<H: HookManager<M, PS>, M: MemoryTrait<PS>, const PS: u64> ExecutionContext<'_, H, M, PS> {
    pub(crate) fn execute_addps(&mut self, inst: &Instruction) -> Result<()> {
        // ADDPS: Add Packed Single-Precision Floating-Point Values
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
                    "Invalid ADDPS source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let result = self.packed_float_operation(dst_value, src_value, |a, b| a + b);
        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_subps(&mut self, inst: &Instruction) -> Result<()> {
        // SUBPS: Subtract Packed Single-Precision Floating-Point Values
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
                    "Invalid SUBPS source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let result = self.packed_float_operation(dst_value, src_value, |a, b| a - b);
        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_mulps(&mut self, inst: &Instruction) -> Result<()> {
        // MULPS: Multiply Packed Single-Precision Floating-Point Values
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
                    "Invalid MULPS source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let result = self.packed_float_operation(dst_value, src_value, |a, b| a * b);
        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_divps(&mut self, inst: &Instruction) -> Result<()> {
        // DIVPS: Divide Packed Single-Precision Floating-Point Values
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
                    "Invalid DIVPS source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let result = self.packed_float_operation(dst_value, src_value, |a, b| a / b);
        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_addsd(&mut self, inst: &Instruction) -> Result<()> {
        // ADDSD: Add Scalar Double-Precision Floating-Point Value
        // Adds the low double-precision float values, preserves upper bits
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let src_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_xmm(src_reg) as u64
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                self.read_memory_64(addr)?
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid ADDSD source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let dst_double = f64::from_bits(dst_value as u64);
        let src_double = f64::from_bits(src_value);
        let result_double = dst_double + src_double;

        // Replace lower 64 bits with result, preserve upper 64 bits
        let result =
            (result_double.to_bits() as u128) | (dst_value & 0xFFFFFFFFFFFFFFFF0000000000000000);
        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_subsd(&mut self, inst: &Instruction) -> Result<()> {
        // SUBSD: Subtract Scalar Double-Precision Floating-Point Value
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let src_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_xmm(src_reg) as u64
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                self.read_memory_64(addr)?
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid SUBSD source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let dst_double = f64::from_bits(dst_value as u64);
        let src_double = f64::from_bits(src_value);
        let result_double = dst_double - src_double;

        let result =
            (result_double.to_bits() as u128) | (dst_value & 0xFFFFFFFFFFFFFFFF0000000000000000);
        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_mulsd(&mut self, inst: &Instruction) -> Result<()> {
        // MULSD: Multiply Scalar Double-Precision Floating-Point Value
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let src_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_xmm(src_reg) as u64
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                self.read_memory_64(addr)?
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid MULSD source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let dst_double = f64::from_bits(dst_value as u64);
        let src_double = f64::from_bits(src_value);
        let result_double = dst_double * src_double;

        let result =
            (result_double.to_bits() as u128) | (dst_value & 0xFFFFFFFFFFFFFFFF0000000000000000);
        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_divsd(&mut self, inst: &Instruction) -> Result<()> {
        // DIVSD: Divide Scalar Double-Precision Floating-Point Value
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let src_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_xmm(src_reg) as u64
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                self.read_memory_64(addr)?
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid DIVSD source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let dst_double = f64::from_bits(dst_value as u64);
        let src_double = f64::from_bits(src_value);
        let result_double = dst_double / src_double;

        let result =
            (result_double.to_bits() as u128) | (dst_value & 0xFFFFFFFFFFFFFFFF0000000000000000);
        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_addss(&mut self, inst: &Instruction) -> Result<()> {
        // ADDSS: Add Scalar Single-Precision Floating-Point Value
        // Adds the low single-precision float values, preserves upper bits
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let src_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_xmm(src_reg) as u32
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                self.read_memory_32(addr)?
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid ADDSS source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let dst_float = f32::from_bits(dst_value as u32);
        let src_float = f32::from_bits(src_value);
        let result_float = dst_float + src_float;

        // Replace lower 32 bits with result, preserve upper 96 bits
        let result =
            (result_float.to_bits() as u128) | (dst_value & 0xFFFFFFFFFFFFFFFFFFFFFFFF00000000);
        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_subss(&mut self, inst: &Instruction) -> Result<()> {
        // SUBSS: Subtract Scalar Single-Precision Floating-Point Value
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let src_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_xmm(src_reg) as u32
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                self.read_memory_32(addr)?
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid SUBSS source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let dst_float = f32::from_bits(dst_value as u32);
        let src_float = f32::from_bits(src_value);
        let result_float = dst_float - src_float;

        let result =
            (result_float.to_bits() as u128) | (dst_value & 0xFFFFFFFFFFFFFFFFFFFFFFFF00000000);
        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_mulss(&mut self, inst: &Instruction) -> Result<()> {
        // MULSS: Multiply Scalar Single-Precision Floating-Point Value
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let src_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_xmm(src_reg) as u32
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                self.read_memory_32(addr)?
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid MULSS source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let dst_float = f32::from_bits(dst_value as u32);
        let src_float = f32::from_bits(src_value);
        let result_float = dst_float * src_float;

        let result =
            (result_float.to_bits() as u128) | (dst_value & 0xFFFFFFFFFFFFFFFFFFFFFFFF00000000);
        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_divss(&mut self, inst: &Instruction) -> Result<()> {
        // DIVSS: Divide Scalar Single-Precision Floating-Point Value
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let src_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_xmm(src_reg) as u32
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                self.read_memory_32(addr)?
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid DIVSS source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let dst_float = f32::from_bits(dst_value as u32);
        let src_float = f32::from_bits(src_value);
        let result_float = dst_float / src_float;

        let result =
            (result_float.to_bits() as u128) | (dst_value & 0xFFFFFFFFFFFFFFFFFFFFFFFF00000000);
        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }
}
