#![allow(clippy::needless_range_loop)]

use crate::HookManager;
use crate::engine::ExecutionContext;
use crate::error::{EmulatorError, Result};
use crate::memory::MemoryTrait;
use iced_x86::{Instruction, OpKind};

impl<H: HookManager<M, PS>, M: MemoryTrait<PS>, const PS: u64> ExecutionContext<'_, H, M, PS> {
    pub(crate) fn execute_cvtps2pd(&mut self, inst: &Instruction) -> Result<()> {
        // Convert Packed Single-Precision FP to Packed Double-Precision FP
        // Converts 2 single-precision floats from source to 2 double-precision floats in destination
        let (dst_reg, src_value) = match (inst.op_kind(0), inst.op_kind(1)) {
            (OpKind::Register, OpKind::Register) => {
                let dst = self.convert_register(inst.op_register(0))?;
                let src = self.convert_register(inst.op_register(1))?;
                (dst, self.engine.cpu.read_xmm(src))
            }
            (OpKind::Register, OpKind::Memory) => {
                let dst = self.convert_register(inst.op_register(0))?;
                let addr = self.calculate_memory_address(inst, 1)?;
                // Only read 64 bits (2 floats) from memory
                let value = self.read_memory_64(addr)?;
                (dst, value as u128)
            }
            _ => return Err(EmulatorError::UnsupportedOperandType),
        };

        // Extract two single-precision floats
        let float1 = f32::from_bits(src_value as u32);
        let float2 = f32::from_bits((src_value >> 32) as u32);

        // Convert to double-precision
        let double1 = float1 as f64;
        let double2 = float2 as f64;

        // Pack the two doubles into the XMM register
        let result = double1.to_bits() as u128 | ((double2.to_bits() as u128) << 64);
        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_cvtpd2ps(&mut self, inst: &Instruction) -> Result<()> {
        // Convert Packed Double-Precision FP to Packed Single-Precision FP
        // Converts 2 double-precision floats from source to 2 single-precision floats in destination (lower 64 bits)
        let (dst_reg, src_value) = match (inst.op_kind(0), inst.op_kind(1)) {
            (OpKind::Register, OpKind::Register) => {
                let dst = self.convert_register(inst.op_register(0))?;
                let src = self.convert_register(inst.op_register(1))?;
                (dst, self.engine.cpu.read_xmm(src))
            }
            (OpKind::Register, OpKind::Memory) => {
                let dst = self.convert_register(inst.op_register(0))?;
                let addr = self.calculate_memory_address(inst, 1)?;
                let value = self.read_memory_128(addr)?;
                (dst, value)
            }
            _ => return Err(EmulatorError::UnsupportedOperandType),
        };

        // Extract two double-precision floats
        let double1 = f64::from_bits(src_value as u64);
        let double2 = f64::from_bits((src_value >> 64) as u64);

        // Convert to single-precision
        let float1 = double1 as f32;
        let float2 = double2 as f32;

        // Pack the two floats into the lower 64 bits, upper 64 bits are zeroed
        let result = float1.to_bits() as u128 | ((float2.to_bits() as u128) << 32);
        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_cvtss2sd(&mut self, inst: &Instruction) -> Result<()> {
        // Convert Scalar Single-Precision FP to Scalar Double-Precision FP
        // Converts the lower single-precision float to double-precision, preserves upper bits
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let src_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_xmm(src)
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                self.read_memory_32(addr)? as u128
            }
            _ => return Err(EmulatorError::UnsupportedOperandType),
        };

        // Extract the single-precision float
        let float = f32::from_bits(src_value as u32);

        // Convert to double-precision
        let double = float as f64;

        // Get current destination value to preserve upper bits
        let dst_value = self.engine.cpu.read_xmm(dst_reg);

        // Replace lower 64 bits with the converted double, preserve upper 64 bits
        let result = double.to_bits() as u128 | (dst_value & 0xFFFFFFFFFFFFFFFF0000000000000000);
        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_cvtsd2ss(&mut self, inst: &Instruction) -> Result<()> {
        // Convert Scalar Double-Precision FP to Scalar Single-Precision FP
        // Converts the lower double-precision float to single-precision, preserves upper bits
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let src_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_xmm(src)
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                self.read_memory_64(addr)? as u128
            }
            _ => return Err(EmulatorError::UnsupportedOperandType),
        };

        // Extract the double-precision float
        let double = f64::from_bits(src_value as u64);

        // Convert to single-precision
        let float = double as f32;

        // Get current destination value to preserve upper bits
        let dst_value = self.engine.cpu.read_xmm(dst_reg);

        // Replace lower 32 bits with the converted float, preserve upper 96 bits
        let result = float.to_bits() as u128 | (dst_value & 0xFFFFFFFFFFFFFFFFFFFFFFFF00000000);
        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_cvtps2dq(&mut self, inst: &Instruction) -> Result<()> {
        // Convert Packed Single-Precision FP to Packed Signed Doubleword Integers
        // Converts 4 single-precision floats to 4 signed 32-bit integers with rounding
        let (dst_reg, src_value) = match (inst.op_kind(0), inst.op_kind(1)) {
            (OpKind::Register, OpKind::Register) => {
                let dst = self.convert_register(inst.op_register(0))?;
                let src = self.convert_register(inst.op_register(1))?;
                (dst, self.engine.cpu.read_xmm(src))
            }
            (OpKind::Register, OpKind::Memory) => {
                let dst = self.convert_register(inst.op_register(0))?;
                let addr = self.calculate_memory_address(inst, 1)?;
                let value = self.read_memory_128(addr)?;
                (dst, value)
            }
            _ => return Err(EmulatorError::UnsupportedOperandType),
        };

        // Extract four single-precision floats
        let floats = [
            f32::from_bits(src_value as u32),
            f32::from_bits((src_value >> 32) as u32),
            f32::from_bits((src_value >> 64) as u32),
            f32::from_bits((src_value >> 96) as u32),
        ];

        // Convert to signed integers with rounding
        let mut result = 0u128;
        for i in 0..4 {
            let int_val = if floats[i].is_nan() {
                i32::MIN // Indefinite integer value
            } else if floats[i] > i32::MAX as f32 {
                i32::MAX
            } else if floats[i] < i32::MIN as f32 {
                i32::MIN
            } else {
                floats[i].round() as i32
            };
            result |= (int_val as u32 as u128) << (i * 32);
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_cvttps2dq(&mut self, inst: &Instruction) -> Result<()> {
        // Convert Packed Single-Precision FP to Packed Signed Doubleword Integers with Truncation
        // Converts 4 single-precision floats to 4 signed 32-bit integers with truncation
        let (dst_reg, src_value) = match (inst.op_kind(0), inst.op_kind(1)) {
            (OpKind::Register, OpKind::Register) => {
                let dst = self.convert_register(inst.op_register(0))?;
                let src = self.convert_register(inst.op_register(1))?;
                (dst, self.engine.cpu.read_xmm(src))
            }
            (OpKind::Register, OpKind::Memory) => {
                let dst = self.convert_register(inst.op_register(0))?;
                let addr = self.calculate_memory_address(inst, 1)?;
                let value = self.read_memory_128(addr)?;
                (dst, value)
            }
            _ => return Err(EmulatorError::UnsupportedOperandType),
        };

        // Extract four single-precision floats
        let floats = [
            f32::from_bits(src_value as u32),
            f32::from_bits((src_value >> 32) as u32),
            f32::from_bits((src_value >> 64) as u32),
            f32::from_bits((src_value >> 96) as u32),
        ];

        // Convert to signed integers with truncation
        let mut result = 0u128;
        for i in 0..4 {
            let int_val = if floats[i].is_nan() {
                i32::MIN // Indefinite integer value
            } else if floats[i] > i32::MAX as f32 {
                i32::MAX
            } else if floats[i] < i32::MIN as f32 {
                i32::MIN
            } else {
                floats[i].trunc() as i32
            };
            result |= (int_val as u32 as u128) << (i * 32);
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_cvtdq2ps(&mut self, inst: &Instruction) -> Result<()> {
        // Convert Packed Signed Doubleword Integers to Packed Single-Precision FP
        // Converts 4 signed 32-bit integers to 4 single-precision floats
        let (dst_reg, src_value) = match (inst.op_kind(0), inst.op_kind(1)) {
            (OpKind::Register, OpKind::Register) => {
                let dst = self.convert_register(inst.op_register(0))?;
                let src = self.convert_register(inst.op_register(1))?;
                (dst, self.engine.cpu.read_xmm(src))
            }
            (OpKind::Register, OpKind::Memory) => {
                let dst = self.convert_register(inst.op_register(0))?;
                let addr = self.calculate_memory_address(inst, 1)?;
                let value = self.read_memory_128(addr)?;
                (dst, value)
            }
            _ => return Err(EmulatorError::UnsupportedOperandType),
        };

        // Extract four signed 32-bit integers
        let ints = [
            src_value as u32 as i32,
            (src_value >> 32) as u32 as i32,
            (src_value >> 64) as u32 as i32,
            (src_value >> 96) as u32 as i32,
        ];

        // Convert to single-precision floats
        let mut result = 0u128;
        for i in 0..4 {
            let float_val = ints[i] as f32;
            result |= (float_val.to_bits() as u128) << (i * 32);
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_cvtsi2ss(&mut self, inst: &Instruction) -> Result<()> {
        // Convert Signed Integer to Scalar Single-Precision FP
        // Converts a 32/64-bit signed integer to single-precision float in lower 32 bits
        let dst_reg = self.convert_register(inst.op_register(0))?;

        let int_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_reg(src) as i64
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                // Check operand size to determine if we read 32 or 64 bits
                if inst.memory_size().size() == 4 {
                    self.read_memory_32(addr)? as i32 as i64
                } else {
                    self.read_memory_64(addr)? as i64
                }
            }
            _ => return Err(EmulatorError::UnsupportedOperandType),
        };

        // Convert to single-precision float
        let float_val = int_value as f32;

        // Get current destination value to preserve upper bits
        let dst_value = self.engine.cpu.read_xmm(dst_reg);

        // Replace lower 32 bits with the converted float, preserve upper 96 bits
        let result = float_val.to_bits() as u128 | (dst_value & 0xFFFFFFFFFFFFFFFFFFFFFFFF00000000);
        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_cvtsi2sd(&mut self, inst: &Instruction) -> Result<()> {
        // Convert Signed Integer to Scalar Double-Precision FP
        // Converts a 32/64-bit signed integer to double-precision float in lower 64 bits
        let dst_reg = self.convert_register(inst.op_register(0))?;

        let int_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_reg(src) as i64
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                // Check operand size to determine if we read 32 or 64 bits
                if inst.memory_size().size() == 4 {
                    self.read_memory_32(addr)? as i32 as i64
                } else {
                    self.read_memory_64(addr)? as i64
                }
            }
            _ => return Err(EmulatorError::UnsupportedOperandType),
        };

        // Convert to double-precision float
        let double_val = int_value as f64;

        // Get current destination value to preserve upper bits
        let dst_value = self.engine.cpu.read_xmm(dst_reg);

        // Replace lower 64 bits with the converted double, preserve upper 64 bits
        let result =
            double_val.to_bits() as u128 | (dst_value & 0xFFFFFFFFFFFFFFFF0000000000000000);
        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_cvtss2si(&mut self, inst: &Instruction) -> Result<()> {
        // Convert Scalar Single-Precision FP to Signed Integer
        // Converts the lower single-precision float to a 32/64-bit signed integer with rounding
        let dst_reg = self.convert_register(inst.op_register(0))?;

        let float_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src = self.convert_register(inst.op_register(1))?;
                let value = self.engine.cpu.read_xmm(src);
                f32::from_bits(value as u32)
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                let value = self.read_memory_32(addr)?;
                f32::from_bits(value)
            }
            _ => return Err(EmulatorError::UnsupportedOperandType),
        };

        // Convert to signed integer with rounding
        let int_val = if float_value.is_nan() {
            i64::MIN // Indefinite integer value
        } else if self.is_64bit_register(dst_reg) {
            // 64-bit destination
            if float_value > i64::MAX as f32 {
                i64::MAX
            } else if float_value < i64::MIN as f32 {
                i64::MIN
            } else {
                float_value.round() as i64
            }
        } else {
            // 32-bit destination
            if float_value > i32::MAX as f32 {
                i32::MAX as i64
            } else if float_value < i32::MIN as f32 {
                i32::MIN as i64
            } else {
                float_value.round() as i32 as i64
            }
        };

        self.engine.cpu.write_reg(dst_reg, int_val as u64);
        Ok(())
    }

    pub(crate) fn execute_cvtsd2si(&mut self, inst: &Instruction) -> Result<()> {
        // Convert Scalar Double-Precision FP to Signed Integer
        // Converts the lower double-precision float to a 32/64-bit signed integer with rounding
        let dst_reg = self.convert_register(inst.op_register(0))?;

        let double_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src = self.convert_register(inst.op_register(1))?;
                let value = self.engine.cpu.read_xmm(src);
                f64::from_bits(value as u64)
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                let value = self.read_memory_64(addr)?;
                f64::from_bits(value)
            }
            _ => return Err(EmulatorError::UnsupportedOperandType),
        };

        // Convert to signed integer with rounding
        let int_val = if double_value.is_nan() {
            i64::MIN // Indefinite integer value
        } else if self.is_64bit_register(dst_reg) {
            // 64-bit destination
            if double_value > i64::MAX as f64 {
                i64::MAX
            } else if double_value < i64::MIN as f64 {
                i64::MIN
            } else {
                double_value.round() as i64
            }
        } else {
            // 32-bit destination
            if double_value > i32::MAX as f64 {
                i32::MAX as i64
            } else if double_value < i32::MIN as f64 {
                i32::MIN as i64
            } else {
                double_value.round() as i32 as i64
            }
        };

        self.engine.cpu.write_reg(dst_reg, int_val as u64);
        Ok(())
    }

    pub(crate) fn execute_cvttss2si(&mut self, inst: &Instruction) -> Result<()> {
        // Convert Scalar Single-Precision FP to Signed Integer with Truncation
        // Converts the lower single-precision float to a 32/64-bit signed integer with truncation
        let dst_reg = self.convert_register(inst.op_register(0))?;

        let float_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src = self.convert_register(inst.op_register(1))?;
                let value = self.engine.cpu.read_xmm(src);
                f32::from_bits(value as u32)
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                let value = self.read_memory_32(addr)?;
                f32::from_bits(value)
            }
            _ => return Err(EmulatorError::UnsupportedOperandType),
        };

        // Convert to signed integer with truncation
        let int_val = if float_value.is_nan() {
            i64::MIN // Indefinite integer value
        } else if self.is_64bit_register(dst_reg) {
            // 64-bit destination
            if float_value > i64::MAX as f32 {
                i64::MAX
            } else if float_value < i64::MIN as f32 {
                i64::MIN
            } else {
                float_value.trunc() as i64
            }
        } else {
            // 32-bit destination
            if float_value > i32::MAX as f32 {
                i32::MAX as i64
            } else if float_value < i32::MIN as f32 {
                i32::MIN as i64
            } else {
                float_value.trunc() as i32 as i64
            }
        };

        self.engine.cpu.write_reg(dst_reg, int_val as u64);
        Ok(())
    }

    pub(crate) fn execute_cvttsd2si(&mut self, inst: &Instruction) -> Result<()> {
        // Convert Scalar Double-Precision FP to Signed Integer with Truncation
        // Converts the lower double-precision float to a 32/64-bit signed integer with truncation
        let dst_reg = self.convert_register(inst.op_register(0))?;

        let double_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src = self.convert_register(inst.op_register(1))?;
                let value = self.engine.cpu.read_xmm(src);
                f64::from_bits(value as u64)
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                let value = self.read_memory_64(addr)?;
                f64::from_bits(value)
            }
            _ => return Err(EmulatorError::UnsupportedOperandType),
        };

        // Convert to signed integer with truncation
        let int_val = if double_value.is_nan() {
            i64::MIN // Indefinite integer value
        } else if self.is_64bit_register(dst_reg) {
            // 64-bit destination
            if double_value > i64::MAX as f64 {
                i64::MAX
            } else if double_value < i64::MIN as f64 {
                i64::MIN
            } else {
                double_value.trunc() as i64
            }
        } else {
            // 32-bit destination
            if double_value > i32::MAX as f64 {
                i32::MAX as i64
            } else if double_value < i32::MIN as f64 {
                i32::MIN as i64
            } else {
                double_value.trunc() as i32 as i64
            }
        };

        self.engine.cpu.write_reg(dst_reg, int_val as u64);
        Ok(())
    }
}
