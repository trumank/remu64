use crate::HookManager;
use crate::engine::ExecutionContext;
use crate::error::{EmulatorError, Result};
use crate::memory::MemoryTrait;
use iced_x86::{Instruction, OpKind};

impl<H: HookManager<M, PS>, M: MemoryTrait<PS>, const PS: u64> ExecutionContext<'_, H, M, PS> {
    pub(crate) fn execute_vaddps(&mut self, inst: &Instruction) -> Result<()> {
        // VADDPS - Vector Add Packed Single-Precision Floating-Point Values
        // VEX.256: VADDPS ymm1, ymm2, ymm3/m256
        // VEX.128: VADDPS xmm1, xmm2, xmm3/m128

        // Check if this is 256-bit (YMM) or 128-bit (XMM) operation
        let is_256bit = inst.op_register(0).is_ymm();

        if inst.op_count() != 3 {
            return Err(EmulatorError::UnsupportedInstruction(
                "VADDPS requires exactly 3 operands".to_string(),
            ));
        }

        if is_256bit {
            // 256-bit YMM operation
            let src1_reg = self.convert_register(inst.op_register(1))?;
            let src1_data = self.engine.cpu.read_ymm(src1_reg);

            let src2_data = match inst.op_kind(2) {
                OpKind::Register => {
                    let src2_reg = self.convert_register(inst.op_register(2))?;
                    self.engine.cpu.read_ymm(src2_reg)
                }
                OpKind::Memory => self.read_ymm_memory(inst, 2)?,
                _ => {
                    return Err(EmulatorError::UnsupportedInstruction(format!(
                        "Unsupported VADDPS source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            // Perform packed single-precision addition
            // Each YMM register contains 8 32-bit floats (4 per 128-bit half)
            let mut result = [0u128; 2];

            for half in 0..2 {
                let mut float_results = [0u32; 4];
                for i in 0..4 {
                    let offset = i * 32;
                    let a_bits = ((src1_data[half] >> offset) & 0xFFFFFFFF) as u32;
                    let b_bits = ((src2_data[half] >> offset) & 0xFFFFFFFF) as u32;

                    // Convert bits to f32, add, convert back to bits
                    let a = f32::from_bits(a_bits);
                    let b = f32::from_bits(b_bits);
                    let sum = a + b;
                    float_results[i] = sum.to_bits();
                }

                // Pack the results back into u128
                result[half] = (float_results[0] as u128)
                    | ((float_results[1] as u128) << 32)
                    | ((float_results[2] as u128) << 64)
                    | ((float_results[3] as u128) << 96);
            }

            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_ymm(dst_reg, result);
        } else {
            // 128-bit XMM operation
            let src1_reg = self.convert_register(inst.op_register(1))?;
            let src1_data = self.engine.cpu.read_xmm(src1_reg);

            let src2_data = match inst.op_kind(2) {
                OpKind::Register => {
                    let src2_reg = self.convert_register(inst.op_register(2))?;
                    self.engine.cpu.read_xmm(src2_reg)
                }
                OpKind::Memory => {
                    let addr = self.calculate_memory_address(inst, 2)?;
                    self.read_memory_128(addr)?
                }
                _ => {
                    return Err(EmulatorError::UnsupportedInstruction(format!(
                        "Unsupported VADDPS source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            // Perform packed single-precision addition for XMM (4 floats)
            let mut float_results = [0u32; 4];
            for i in 0..4 {
                let offset = i * 32;
                let a_bits = ((src1_data >> offset) & 0xFFFFFFFF) as u32;
                let b_bits = ((src2_data >> offset) & 0xFFFFFFFF) as u32;

                let a = f32::from_bits(a_bits);
                let b = f32::from_bits(b_bits);
                let sum = a + b;
                float_results[i] = sum.to_bits();
            }

            let result = (float_results[0] as u128)
                | ((float_results[1] as u128) << 32)
                | ((float_results[2] as u128) << 64)
                | ((float_results[3] as u128) << 96);

            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_xmm(dst_reg, result);
        }

        Ok(())
    }

    pub(crate) fn execute_vsubps(&mut self, inst: &Instruction) -> Result<()> {
        // VSUBPS - Vector Subtract Packed Single-Precision Floating-Point Values
        // VEX.256: VSUBPS ymm1, ymm2, ymm3/m256
        // VEX.128: VSUBPS xmm1, xmm2, xmm3/m128

        // Check if this is 256-bit (YMM) or 128-bit (XMM) operation
        let is_256bit = inst.op_register(0).is_ymm();

        if inst.op_count() != 3 {
            return Err(EmulatorError::UnsupportedInstruction(
                "VSUBPS requires exactly 3 operands".to_string(),
            ));
        }

        if is_256bit {
            // 256-bit YMM operation
            let src1_reg = self.convert_register(inst.op_register(1))?;
            let src1_data = self.engine.cpu.read_ymm(src1_reg);

            let src2_data = match inst.op_kind(2) {
                OpKind::Register => {
                    let src2_reg = self.convert_register(inst.op_register(2))?;
                    self.engine.cpu.read_ymm(src2_reg)
                }
                OpKind::Memory => self.read_ymm_memory(inst, 2)?,
                _ => {
                    return Err(EmulatorError::UnsupportedInstruction(format!(
                        "Unsupported VSUBPS source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            // Perform packed single-precision subtraction
            // Each YMM register contains 8 32-bit floats (4 per 128-bit half)
            let mut result = [0u128; 2];

            for half in 0..2 {
                let mut float_results = [0u32; 4];
                for i in 0..4 {
                    let offset = i * 32;
                    let a_bits = ((src1_data[half] >> offset) & 0xFFFFFFFF) as u32;
                    let b_bits = ((src2_data[half] >> offset) & 0xFFFFFFFF) as u32;

                    // Convert bits to f32, subtract, convert back to bits
                    let a = f32::from_bits(a_bits);
                    let b = f32::from_bits(b_bits);
                    let diff = a - b;
                    float_results[i] = diff.to_bits();
                }

                // Pack the results back into u128
                result[half] = (float_results[0] as u128)
                    | ((float_results[1] as u128) << 32)
                    | ((float_results[2] as u128) << 64)
                    | ((float_results[3] as u128) << 96);
            }

            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_ymm(dst_reg, result);
        } else {
            // 128-bit XMM operation
            let src1_reg = self.convert_register(inst.op_register(1))?;
            let src1_data = self.engine.cpu.read_xmm(src1_reg);

            let src2_data = match inst.op_kind(2) {
                OpKind::Register => {
                    let src2_reg = self.convert_register(inst.op_register(2))?;
                    self.engine.cpu.read_xmm(src2_reg)
                }
                OpKind::Memory => {
                    let addr = self.calculate_memory_address(inst, 2)?;
                    self.read_memory_128(addr)?
                }
                _ => {
                    return Err(EmulatorError::UnsupportedInstruction(format!(
                        "Unsupported VSUBPS source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            // Perform packed single-precision subtraction for XMM (4 floats)
            let mut float_results = [0u32; 4];
            for i in 0..4 {
                let offset = i * 32;
                let a_bits = ((src1_data >> offset) & 0xFFFFFFFF) as u32;
                let b_bits = ((src2_data >> offset) & 0xFFFFFFFF) as u32;

                let a = f32::from_bits(a_bits);
                let b = f32::from_bits(b_bits);
                let diff = a - b;
                float_results[i] = diff.to_bits();
            }

            let result = (float_results[0] as u128)
                | ((float_results[1] as u128) << 32)
                | ((float_results[2] as u128) << 64)
                | ((float_results[3] as u128) << 96);

            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_xmm(dst_reg, result);
        }

        Ok(())
    }

    pub(crate) fn execute_vmulps(&mut self, inst: &Instruction) -> Result<()> {
        // VMULPS - Vector Multiply Packed Single-Precision Floating-Point Values
        // VEX.256: VMULPS ymm1, ymm2, ymm3/m256
        // VEX.128: VMULPS xmm1, xmm2, xmm3/m128

        // Check if this is 256-bit (YMM) or 128-bit (XMM) operation
        let is_256bit = inst.op_register(0).is_ymm();

        if inst.op_count() != 3 {
            return Err(EmulatorError::UnsupportedInstruction(
                "VMULPS requires exactly 3 operands".to_string(),
            ));
        }

        if is_256bit {
            // 256-bit YMM operation
            let src1_reg = self.convert_register(inst.op_register(1))?;
            let src1_data = self.engine.cpu.read_ymm(src1_reg);

            let src2_data = match inst.op_kind(2) {
                OpKind::Register => {
                    let src2_reg = self.convert_register(inst.op_register(2))?;
                    self.engine.cpu.read_ymm(src2_reg)
                }
                OpKind::Memory => self.read_ymm_memory(inst, 2)?,
                _ => {
                    return Err(EmulatorError::UnsupportedInstruction(format!(
                        "Unsupported VMULPS source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            // Perform packed single-precision multiplication
            // Each YMM register contains 8 32-bit floats (4 per 128-bit half)
            let mut result = [0u128; 2];

            for half in 0..2 {
                let mut float_results = [0u32; 4];
                for i in 0..4 {
                    let offset = i * 32;
                    let a_bits = ((src1_data[half] >> offset) & 0xFFFFFFFF) as u32;
                    let b_bits = ((src2_data[half] >> offset) & 0xFFFFFFFF) as u32;

                    // Convert bits to f32, multiply, convert back to bits
                    let a = f32::from_bits(a_bits);
                    let b = f32::from_bits(b_bits);
                    let prod = a * b;
                    float_results[i] = prod.to_bits();
                }

                // Pack the results back into u128
                result[half] = (float_results[0] as u128)
                    | ((float_results[1] as u128) << 32)
                    | ((float_results[2] as u128) << 64)
                    | ((float_results[3] as u128) << 96);
            }

            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_ymm(dst_reg, result);
        } else {
            // 128-bit XMM operation
            let src1_reg = self.convert_register(inst.op_register(1))?;
            let src1_data = self.engine.cpu.read_xmm(src1_reg);

            let src2_data = match inst.op_kind(2) {
                OpKind::Register => {
                    let src2_reg = self.convert_register(inst.op_register(2))?;
                    self.engine.cpu.read_xmm(src2_reg)
                }
                OpKind::Memory => {
                    let addr = self.calculate_memory_address(inst, 2)?;
                    self.read_memory_128(addr)?
                }
                _ => {
                    return Err(EmulatorError::UnsupportedInstruction(format!(
                        "Unsupported VMULPS source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            // Perform packed single-precision multiplication for XMM (4 floats)
            let mut float_results = [0u32; 4];
            for i in 0..4 {
                let offset = i * 32;
                let a_bits = ((src1_data >> offset) & 0xFFFFFFFF) as u32;
                let b_bits = ((src2_data >> offset) & 0xFFFFFFFF) as u32;

                let a = f32::from_bits(a_bits);
                let b = f32::from_bits(b_bits);
                let prod = a * b;
                float_results[i] = prod.to_bits();
            }

            let result = (float_results[0] as u128)
                | ((float_results[1] as u128) << 32)
                | ((float_results[2] as u128) << 64)
                | ((float_results[3] as u128) << 96);

            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_xmm(dst_reg, result);
        }

        Ok(())
    }

    pub(crate) fn execute_vdivps(&mut self, inst: &Instruction) -> Result<()> {
        // VDIVPS - Vector Divide Packed Single-Precision Floating-Point Values
        // VEX.256: VDIVPS ymm1, ymm2, ymm3/m256
        // VEX.128: VDIVPS xmm1, xmm2, xmm3/m128

        // Check if this is 256-bit (YMM) or 128-bit (XMM) operation
        let is_256bit = inst.op_register(0).is_ymm();

        if inst.op_count() != 3 {
            return Err(EmulatorError::UnsupportedInstruction(
                "VDIVPS requires exactly 3 operands".to_string(),
            ));
        }

        if is_256bit {
            // 256-bit YMM operation
            let src1_reg = self.convert_register(inst.op_register(1))?;
            let src1_data = self.engine.cpu.read_ymm(src1_reg);

            let src2_data = match inst.op_kind(2) {
                OpKind::Register => {
                    let src2_reg = self.convert_register(inst.op_register(2))?;
                    self.engine.cpu.read_ymm(src2_reg)
                }
                OpKind::Memory => self.read_ymm_memory(inst, 2)?,
                _ => {
                    return Err(EmulatorError::UnsupportedInstruction(format!(
                        "Unsupported VDIVPS source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            // Perform packed single-precision division
            // Each YMM register contains 8 32-bit floats (4 per 128-bit half)
            let mut result = [0u128; 2];

            for half in 0..2 {
                let mut float_results = [0u32; 4];
                for i in 0..4 {
                    let offset = i * 32;
                    let a_bits = ((src1_data[half] >> offset) & 0xFFFFFFFF) as u32;
                    let b_bits = ((src2_data[half] >> offset) & 0xFFFFFFFF) as u32;

                    // Convert bits to f32, divide, convert back to bits
                    let a = f32::from_bits(a_bits);
                    let b = f32::from_bits(b_bits);
                    let quotient = a / b;
                    float_results[i] = quotient.to_bits();
                }

                // Pack the results back into u128
                result[half] = (float_results[0] as u128)
                    | ((float_results[1] as u128) << 32)
                    | ((float_results[2] as u128) << 64)
                    | ((float_results[3] as u128) << 96);
            }

            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_ymm(dst_reg, result);
        } else {
            // 128-bit XMM operation
            let src1_reg = self.convert_register(inst.op_register(1))?;
            let src1_data = self.engine.cpu.read_xmm(src1_reg);

            let src2_data = match inst.op_kind(2) {
                OpKind::Register => {
                    let src2_reg = self.convert_register(inst.op_register(2))?;
                    self.engine.cpu.read_xmm(src2_reg)
                }
                OpKind::Memory => {
                    let addr = self.calculate_memory_address(inst, 2)?;
                    self.read_memory_128(addr)?
                }
                _ => {
                    return Err(EmulatorError::UnsupportedInstruction(format!(
                        "Unsupported VDIVPS source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            // Perform packed single-precision division for XMM (4 floats)
            let mut float_results = [0u32; 4];
            for i in 0..4 {
                let offset = i * 32;
                let a_bits = ((src1_data >> offset) & 0xFFFFFFFF) as u32;
                let b_bits = ((src2_data >> offset) & 0xFFFFFFFF) as u32;

                let a = f32::from_bits(a_bits);
                let b = f32::from_bits(b_bits);
                let quotient = a / b;
                float_results[i] = quotient.to_bits();
            }

            let result = (float_results[0] as u128)
                | ((float_results[1] as u128) << 32)
                | ((float_results[2] as u128) << 64)
                | ((float_results[3] as u128) << 96);

            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_xmm(dst_reg, result);
        }

        Ok(())
    }

    pub(crate) fn execute_vaddpd(&mut self, inst: &Instruction) -> Result<()> {
        // VADDPD - Vector Add Packed Double-Precision Floating-Point Values
        // VEX.256: VADDPD ymm1, ymm2, ymm3/m256
        // VEX.128: VADDPD xmm1, xmm2, xmm3/m128

        // Check if this is 256-bit (YMM) or 128-bit (XMM) operation
        let is_256bit = inst.op_register(0).is_ymm();

        if inst.op_count() != 3 {
            return Err(EmulatorError::UnsupportedInstruction(
                "VADDPD requires exactly 3 operands".to_string(),
            ));
        }

        if is_256bit {
            // 256-bit YMM operation
            let src1_reg = self.convert_register(inst.op_register(1))?;
            let src1_data = self.engine.cpu.read_ymm(src1_reg);

            let src2_data = match inst.op_kind(2) {
                OpKind::Register => {
                    let src2_reg = self.convert_register(inst.op_register(2))?;
                    self.engine.cpu.read_ymm(src2_reg)
                }
                OpKind::Memory => self.read_ymm_memory(inst, 2)?,
                _ => {
                    return Err(EmulatorError::UnsupportedInstruction(format!(
                        "Unsupported VADDPD source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            // Perform packed double-precision addition
            // Each YMM register contains 4 64-bit doubles (2 per 128-bit half)
            let mut result = [0u128; 2];

            for half in 0..2 {
                let mut double_results = [0u64; 2];
                for i in 0..2 {
                    let offset = i * 64;
                    let a_bits = ((src1_data[half] >> offset) & 0xFFFFFFFFFFFFFFFF) as u64;
                    let b_bits = ((src2_data[half] >> offset) & 0xFFFFFFFFFFFFFFFF) as u64;

                    // Convert bits to f64, add, convert back to bits
                    let a = f64::from_bits(a_bits);
                    let b = f64::from_bits(b_bits);
                    let sum = a + b;
                    double_results[i] = sum.to_bits();
                }

                // Pack the results back into u128
                result[half] = (double_results[0] as u128) | ((double_results[1] as u128) << 64);
            }

            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_ymm(dst_reg, result);
        } else {
            // 128-bit XMM operation
            let src1_reg = self.convert_register(inst.op_register(1))?;
            let src1_data = self.engine.cpu.read_xmm(src1_reg);

            let src2_data = match inst.op_kind(2) {
                OpKind::Register => {
                    let src2_reg = self.convert_register(inst.op_register(2))?;
                    self.engine.cpu.read_xmm(src2_reg)
                }
                OpKind::Memory => {
                    let addr = self.calculate_memory_address(inst, 2)?;
                    self.read_memory_128(addr)?
                }
                _ => {
                    return Err(EmulatorError::UnsupportedInstruction(format!(
                        "Unsupported VADDPD source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            // Perform packed double-precision addition for XMM (2 doubles)
            let mut double_results = [0u64; 2];
            for i in 0..2 {
                let offset = i * 64;
                let a_bits = ((src1_data >> offset) & 0xFFFFFFFFFFFFFFFF) as u64;
                let b_bits = ((src2_data >> offset) & 0xFFFFFFFFFFFFFFFF) as u64;

                let a = f64::from_bits(a_bits);
                let b = f64::from_bits(b_bits);
                let sum = a + b;
                double_results[i] = sum.to_bits();
            }

            let result = (double_results[0] as u128) | ((double_results[1] as u128) << 64);

            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_xmm(dst_reg, result);
        }

        Ok(())
    }

    pub(crate) fn execute_vsubpd(&mut self, inst: &Instruction) -> Result<()> {
        // VSUBPD - Vector Subtract Packed Double-Precision Floating-Point Values
        // VEX.256: VSUBPD ymm1, ymm2, ymm3/m256
        // VEX.128: VSUBPD xmm1, xmm2, xmm3/m128

        // Check if this is 256-bit (YMM) or 128-bit (XMM) operation
        let is_256bit = inst.op_register(0).is_ymm();

        if inst.op_count() != 3 {
            return Err(EmulatorError::UnsupportedInstruction(
                "VSUBPD requires exactly 3 operands".to_string(),
            ));
        }

        if is_256bit {
            // 256-bit YMM operation
            let src1_reg = self.convert_register(inst.op_register(1))?;
            let src1_data = self.engine.cpu.read_ymm(src1_reg);

            let src2_data = match inst.op_kind(2) {
                OpKind::Register => {
                    let src2_reg = self.convert_register(inst.op_register(2))?;
                    self.engine.cpu.read_ymm(src2_reg)
                }
                OpKind::Memory => self.read_ymm_memory(inst, 2)?,
                _ => {
                    return Err(EmulatorError::UnsupportedInstruction(format!(
                        "Unsupported VSUBPD source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            // Perform packed double-precision subtraction
            // Each YMM register contains 4 64-bit doubles (2 per 128-bit half)
            let mut result = [0u128; 2];

            for half in 0..2 {
                let mut double_results = [0u64; 2];
                for i in 0..2 {
                    let offset = i * 64;
                    let a_bits = ((src1_data[half] >> offset) & 0xFFFFFFFFFFFFFFFF) as u64;
                    let b_bits = ((src2_data[half] >> offset) & 0xFFFFFFFFFFFFFFFF) as u64;

                    // Convert bits to f64, subtract, convert back to bits
                    let a = f64::from_bits(a_bits);
                    let b = f64::from_bits(b_bits);
                    let diff = a - b;
                    double_results[i] = diff.to_bits();
                }

                // Pack the results back into u128
                result[half] = (double_results[0] as u128) | ((double_results[1] as u128) << 64);
            }

            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_ymm(dst_reg, result);
        } else {
            // 128-bit XMM operation
            let src1_reg = self.convert_register(inst.op_register(1))?;
            let src1_data = self.engine.cpu.read_xmm(src1_reg);

            let src2_data = match inst.op_kind(2) {
                OpKind::Register => {
                    let src2_reg = self.convert_register(inst.op_register(2))?;
                    self.engine.cpu.read_xmm(src2_reg)
                }
                OpKind::Memory => {
                    let addr = self.calculate_memory_address(inst, 2)?;
                    self.read_memory_128(addr)?
                }
                _ => {
                    return Err(EmulatorError::UnsupportedInstruction(format!(
                        "Unsupported VSUBPD source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            // Perform packed double-precision subtraction for XMM (2 doubles)
            let mut double_results = [0u64; 2];
            for i in 0..2 {
                let offset = i * 64;
                let a_bits = ((src1_data >> offset) & 0xFFFFFFFFFFFFFFFF) as u64;
                let b_bits = ((src2_data >> offset) & 0xFFFFFFFFFFFFFFFF) as u64;

                let a = f64::from_bits(a_bits);
                let b = f64::from_bits(b_bits);
                let diff = a - b;
                double_results[i] = diff.to_bits();
            }

            let result = (double_results[0] as u128) | ((double_results[1] as u128) << 64);

            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_xmm(dst_reg, result);
        }

        Ok(())
    }

    pub(crate) fn execute_vmulpd(&mut self, inst: &Instruction) -> Result<()> {
        // VMULPD - Vector Multiply Packed Double-Precision Floating-Point Values
        // VEX.256: VMULPD ymm1, ymm2, ymm3/m256
        // VEX.128: VMULPD xmm1, xmm2, xmm3/m128

        // Check if this is 256-bit (YMM) or 128-bit (XMM) operation
        let is_256bit = inst.op_register(0).is_ymm();

        if inst.op_count() != 3 {
            return Err(EmulatorError::UnsupportedInstruction(
                "VMULPD requires exactly 3 operands".to_string(),
            ));
        }

        if is_256bit {
            // 256-bit YMM operation
            let src1_reg = self.convert_register(inst.op_register(1))?;
            let src1_data = self.engine.cpu.read_ymm(src1_reg);

            let src2_data = match inst.op_kind(2) {
                OpKind::Register => {
                    let src2_reg = self.convert_register(inst.op_register(2))?;
                    self.engine.cpu.read_ymm(src2_reg)
                }
                OpKind::Memory => self.read_ymm_memory(inst, 2)?,
                _ => {
                    return Err(EmulatorError::UnsupportedInstruction(format!(
                        "Unsupported VMULPD source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            // Perform packed double-precision multiplication
            // Each YMM register contains 4 64-bit doubles (2 per 128-bit half)
            let mut result = [0u128; 2];

            for half in 0..2 {
                let mut double_results = [0u64; 2];
                for i in 0..2 {
                    let offset = i * 64;
                    let a_bits = ((src1_data[half] >> offset) & 0xFFFFFFFFFFFFFFFF) as u64;
                    let b_bits = ((src2_data[half] >> offset) & 0xFFFFFFFFFFFFFFFF) as u64;

                    // Convert bits to f64, multiply, convert back to bits
                    let a = f64::from_bits(a_bits);
                    let b = f64::from_bits(b_bits);
                    let prod = a * b;
                    double_results[i] = prod.to_bits();
                }

                result[half] = (double_results[0] as u128) | ((double_results[1] as u128) << 64);
            }

            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_ymm(dst_reg, result);
        } else {
            // 128-bit XMM operation
            let src1_reg = self.convert_register(inst.op_register(1))?;
            let src1_data = self.engine.cpu.read_xmm(src1_reg);

            let src2_data = match inst.op_kind(2) {
                OpKind::Register => {
                    let src2_reg = self.convert_register(inst.op_register(2))?;
                    self.engine.cpu.read_xmm(src2_reg)
                }
                OpKind::Memory => {
                    let addr = self.calculate_memory_address(inst, 2)?;
                    self.read_memory_128(addr)?
                }
                _ => {
                    return Err(EmulatorError::UnsupportedInstruction(format!(
                        "Unsupported VMULPD source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            // Perform packed double-precision multiplication for XMM (2 doubles)
            let mut double_results = [0u64; 2];
            for i in 0..2 {
                let offset = i * 64;
                let a_bits = ((src1_data >> offset) & 0xFFFFFFFFFFFFFFFF) as u64;
                let b_bits = ((src2_data >> offset) & 0xFFFFFFFFFFFFFFFF) as u64;

                let a = f64::from_bits(a_bits);
                let b = f64::from_bits(b_bits);
                let prod = a * b;
                double_results[i] = prod.to_bits();
            }

            let result = (double_results[0] as u128) | ((double_results[1] as u128) << 64);

            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_xmm(dst_reg, result);
        }

        Ok(())
    }

    pub(crate) fn execute_vdivpd(&mut self, inst: &Instruction) -> Result<()> {
        // VDIVPD - Vector Divide Packed Double-Precision Floating-Point Values
        // VEX.256: VDIVPD ymm1, ymm2, ymm3/m256
        // VEX.128: VDIVPD xmm1, xmm2, xmm3/m128

        // Check if this is 256-bit (YMM) or 128-bit (XMM) operation
        let is_256bit = inst.op_register(0).is_ymm();

        if inst.op_count() != 3 {
            return Err(EmulatorError::UnsupportedInstruction(
                "VDIVPD requires exactly 3 operands".to_string(),
            ));
        }

        if is_256bit {
            // 256-bit YMM operation
            let src1_reg = self.convert_register(inst.op_register(1))?;
            let src1_data = self.engine.cpu.read_ymm(src1_reg);

            let src2_data = match inst.op_kind(2) {
                OpKind::Register => {
                    let src2_reg = self.convert_register(inst.op_register(2))?;
                    self.engine.cpu.read_ymm(src2_reg)
                }
                OpKind::Memory => self.read_ymm_memory(inst, 2)?,
                _ => {
                    return Err(EmulatorError::UnsupportedInstruction(format!(
                        "Unsupported VDIVPD source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            // Perform packed double-precision division
            // Each YMM register contains 4 64-bit doubles (2 per 128-bit half)
            let mut result = [0u128; 2];

            for half in 0..2 {
                let mut double_results = [0u64; 2];
                for i in 0..2 {
                    let offset = i * 64;
                    let a_bits = ((src1_data[half] >> offset) & 0xFFFFFFFFFFFFFFFF) as u64;
                    let b_bits = ((src2_data[half] >> offset) & 0xFFFFFFFFFFFFFFFF) as u64;

                    // Convert bits to f64, divide, convert back to bits
                    let a = f64::from_bits(a_bits);
                    let b = f64::from_bits(b_bits);
                    let quotient = a / b;
                    double_results[i] = quotient.to_bits();
                }

                result[half] = (double_results[0] as u128) | ((double_results[1] as u128) << 64);
            }

            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_ymm(dst_reg, result);
        } else {
            // 128-bit XMM operation
            let src1_reg = self.convert_register(inst.op_register(1))?;
            let src1_data = self.engine.cpu.read_xmm(src1_reg);

            let src2_data = match inst.op_kind(2) {
                OpKind::Register => {
                    let src2_reg = self.convert_register(inst.op_register(2))?;
                    self.engine.cpu.read_xmm(src2_reg)
                }
                OpKind::Memory => {
                    let addr = self.calculate_memory_address(inst, 2)?;
                    self.read_memory_128(addr)?
                }
                _ => {
                    return Err(EmulatorError::UnsupportedInstruction(format!(
                        "Unsupported VDIVPD source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            // Perform packed double-precision division for XMM (2 doubles)
            let mut double_results = [0u64; 2];
            for i in 0..2 {
                let offset = i * 64;
                let a_bits = ((src1_data >> offset) & 0xFFFFFFFFFFFFFFFF) as u64;
                let b_bits = ((src2_data >> offset) & 0xFFFFFFFFFFFFFFFF) as u64;

                let a = f64::from_bits(a_bits);
                let b = f64::from_bits(b_bits);
                let quotient = a / b;
                double_results[i] = quotient.to_bits();
            }

            let result = (double_results[0] as u128) | ((double_results[1] as u128) << 64);

            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_xmm(dst_reg, result);
        }

        Ok(())
    }

    pub(crate) fn execute_vsqrtps(&mut self, inst: &Instruction) -> Result<()> {
        // VSQRTPS - Vector Square Root Packed Single-Precision Floating-Point Values
        // VEX.256: VSQRTPS ymm1, ymm2/m256
        // VEX.128: VSQRTPS xmm1, xmm2/m128

        // Check if this is 256-bit (YMM) or 128-bit (XMM) operation
        let is_256bit = inst.op_register(0).is_ymm();

        if inst.op_count() != 2 {
            return Err(EmulatorError::UnsupportedInstruction(
                "VSQRTPS requires exactly 2 operands".to_string(),
            ));
        }

        if is_256bit {
            // 256-bit YMM operation
            let src_data = match inst.op_kind(1) {
                OpKind::Register => {
                    let src_reg = self.convert_register(inst.op_register(1))?;
                    self.engine.cpu.read_ymm(src_reg)
                }
                OpKind::Memory => self.read_ymm_memory(inst, 1)?,
                _ => {
                    return Err(EmulatorError::UnsupportedInstruction(format!(
                        "Unsupported VSQRTPS source operand type: {:?}",
                        inst.op_kind(1)
                    )));
                }
            };

            // Perform packed single-precision square root
            // Each YMM register contains 8 32-bit floats (4 per 128-bit half)
            let mut result = [0u128; 2];

            for half in 0..2 {
                let mut float_results = [0u32; 4];
                for i in 0..4 {
                    let offset = i * 32;
                    let val_bits = ((src_data[half] >> offset) & 0xFFFFFFFF) as u32;

                    // Convert bits to f32, take square root, convert back to bits
                    let val = f32::from_bits(val_bits);
                    let sqrt_val = val.sqrt();
                    float_results[i] = sqrt_val.to_bits();
                }

                result[half] = (float_results[0] as u128)
                    | ((float_results[1] as u128) << 32)
                    | ((float_results[2] as u128) << 64)
                    | ((float_results[3] as u128) << 96);
            }

            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_ymm(dst_reg, result);
        } else {
            // 128-bit XMM operation
            let src_data = match inst.op_kind(1) {
                OpKind::Register => {
                    let src_reg = self.convert_register(inst.op_register(1))?;
                    self.engine.cpu.read_xmm(src_reg)
                }
                OpKind::Memory => {
                    let addr = self.calculate_memory_address(inst, 1)?;
                    self.read_memory_128(addr)?
                }
                _ => {
                    return Err(EmulatorError::UnsupportedInstruction(format!(
                        "Unsupported VSQRTPS source operand type: {:?}",
                        inst.op_kind(1)
                    )));
                }
            };

            // Perform packed single-precision square root for XMM (4 floats)
            let mut float_results = [0u32; 4];
            for i in 0..4 {
                let offset = i * 32;
                let val_bits = ((src_data >> offset) & 0xFFFFFFFF) as u32;

                let val = f32::from_bits(val_bits);
                let sqrt_val = val.sqrt();
                float_results[i] = sqrt_val.to_bits();
            }

            let result = (float_results[0] as u128)
                | ((float_results[1] as u128) << 32)
                | ((float_results[2] as u128) << 64)
                | ((float_results[3] as u128) << 96);

            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_xmm(dst_reg, result);
        }

        Ok(())
    }

    pub(crate) fn execute_vsqrtpd(&mut self, inst: &Instruction) -> Result<()> {
        // VSQRTPD - Vector Square Root Packed Double-Precision Floating-Point Values
        // VEX.256: VSQRTPD ymm1, ymm2/m256
        // VEX.128: VSQRTPD xmm1, xmm2/m128

        // Check if this is 256-bit (YMM) or 128-bit (XMM) operation
        let is_256bit = inst.op_register(0).is_ymm();

        if inst.op_count() != 2 {
            return Err(EmulatorError::UnsupportedInstruction(
                "VSQRTPD requires exactly 2 operands".to_string(),
            ));
        }

        if is_256bit {
            // 256-bit YMM operation
            let src_data = match inst.op_kind(1) {
                OpKind::Register => {
                    let src_reg = self.convert_register(inst.op_register(1))?;
                    self.engine.cpu.read_ymm(src_reg)
                }
                OpKind::Memory => self.read_ymm_memory(inst, 1)?,
                _ => {
                    return Err(EmulatorError::UnsupportedInstruction(format!(
                        "Unsupported VSQRTPD source operand type: {:?}",
                        inst.op_kind(1)
                    )));
                }
            };

            // Perform packed double-precision square root
            // Each YMM register contains 4 64-bit doubles (2 per 128-bit half)
            let mut result = [0u128; 2];

            for half in 0..2 {
                let mut double_results = [0u64; 2];
                for i in 0..2 {
                    let offset = i * 64;
                    let val_bits = ((src_data[half] >> offset) & 0xFFFFFFFFFFFFFFFF) as u64;

                    // Convert bits to f64, take square root, convert back to bits
                    let val = f64::from_bits(val_bits);
                    let sqrt_val = val.sqrt();
                    double_results[i] = sqrt_val.to_bits();
                }

                result[half] = (double_results[0] as u128) | ((double_results[1] as u128) << 64);
            }

            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_ymm(dst_reg, result);
        } else {
            // 128-bit XMM operation
            let src_data = match inst.op_kind(1) {
                OpKind::Register => {
                    let src_reg = self.convert_register(inst.op_register(1))?;
                    self.engine.cpu.read_xmm(src_reg)
                }
                OpKind::Memory => {
                    let addr = self.calculate_memory_address(inst, 1)?;
                    self.read_memory_128(addr)?
                }
                _ => {
                    return Err(EmulatorError::UnsupportedInstruction(format!(
                        "Unsupported VSQRTPD source operand type: {:?}",
                        inst.op_kind(1)
                    )));
                }
            };

            // Perform packed double-precision square root for XMM (2 doubles)
            let mut double_results = [0u64; 2];
            for i in 0..2 {
                let offset = i * 64;
                let val_bits = ((src_data >> offset) & 0xFFFFFFFFFFFFFFFF) as u64;

                let val = f64::from_bits(val_bits);
                let sqrt_val = val.sqrt();
                double_results[i] = sqrt_val.to_bits();
            }

            let result = (double_results[0] as u128) | ((double_results[1] as u128) << 64);

            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_xmm(dst_reg, result);
        }

        Ok(())
    }

    pub(crate) fn execute_vmaxps(&mut self, inst: &Instruction) -> Result<()> {
        // VMAXPS - Maximum of Packed Single-Precision Floating-Point Values
        // VEX.256: VMAXPS ymm1, ymm2, ymm3/m256
        // VEX.128: VMAXPS xmm1, xmm2, xmm3/m128

        let is_256bit = inst.op_register(0).is_ymm();

        if inst.op_count() != 3 {
            return Err(EmulatorError::UnsupportedInstruction(
                "VMAXPS requires exactly 3 operands".to_string(),
            ));
        }

        if is_256bit {
            // 256-bit YMM operation
            let src1_reg = self.convert_register(inst.op_register(1))?;
            let src1_data = self.engine.cpu.read_ymm(src1_reg);

            let src2_data = match inst.op_kind(2) {
                OpKind::Register => {
                    let src2_reg = self.convert_register(inst.op_register(2))?;
                    self.engine.cpu.read_ymm(src2_reg)
                }
                OpKind::Memory => self.read_ymm_memory(inst, 2)?,
                _ => {
                    return Err(EmulatorError::UnsupportedInstruction(format!(
                        "Unsupported VMAXPS source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            // Perform element-wise maximum
            let mut result = [0u128; 2];

            for half in 0..2 {
                let mut float_results = [0u32; 4];
                for i in 0..4 {
                    let offset = i * 32;
                    let a_bits = ((src1_data[half] >> offset) & 0xFFFFFFFF) as u32;
                    let b_bits = ((src2_data[half] >> offset) & 0xFFFFFFFF) as u32;

                    let a = f32::from_bits(a_bits);
                    let b = f32::from_bits(b_bits);
                    // Handle NaN propagation: if either is NaN, result is second operand
                    let max_val = if a.is_nan() || b.is_nan() {
                        b
                    } else {
                        a.max(b)
                    };
                    float_results[i] = max_val.to_bits();
                }

                result[half] = (float_results[0] as u128)
                    | ((float_results[1] as u128) << 32)
                    | ((float_results[2] as u128) << 64)
                    | ((float_results[3] as u128) << 96);
            }

            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_ymm(dst_reg, result);
        } else {
            // 128-bit XMM operation
            let src1_reg = self.convert_register(inst.op_register(1))?;
            let src1_data = self.engine.cpu.read_xmm(src1_reg);

            let src2_data = match inst.op_kind(2) {
                OpKind::Register => {
                    let src2_reg = self.convert_register(inst.op_register(2))?;
                    self.engine.cpu.read_xmm(src2_reg)
                }
                OpKind::Memory => {
                    let addr = self.calculate_memory_address(inst, 2)?;
                    self.read_memory_128(addr)?
                }
                _ => {
                    return Err(EmulatorError::UnsupportedInstruction(format!(
                        "Unsupported VMAXPS source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            let mut float_results = [0u32; 4];
            for i in 0..4 {
                let offset = i * 32;
                let a_bits = ((src1_data >> offset) & 0xFFFFFFFF) as u32;
                let b_bits = ((src2_data >> offset) & 0xFFFFFFFF) as u32;

                let a = f32::from_bits(a_bits);
                let b = f32::from_bits(b_bits);
                let max_val = if a.is_nan() || b.is_nan() {
                    b
                } else {
                    a.max(b)
                };
                float_results[i] = max_val.to_bits();
            }

            let result = (float_results[0] as u128)
                | ((float_results[1] as u128) << 32)
                | ((float_results[2] as u128) << 64)
                | ((float_results[3] as u128) << 96);

            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_xmm(dst_reg, result);
        }

        Ok(())
    }

    pub(crate) fn execute_vmaxpd(&mut self, inst: &Instruction) -> Result<()> {
        // VMAXPD - Maximum of Packed Double-Precision Floating-Point Values
        // VEX.256: VMAXPD ymm1, ymm2, ymm3/m256
        // VEX.128: VMAXPD xmm1, xmm2, xmm3/m128

        let is_256bit = inst.op_register(0).is_ymm();

        if inst.op_count() != 3 {
            return Err(EmulatorError::UnsupportedInstruction(
                "VMAXPD requires exactly 3 operands".to_string(),
            ));
        }

        if is_256bit {
            // 256-bit YMM operation
            let src1_reg = self.convert_register(inst.op_register(1))?;
            let src1_data = self.engine.cpu.read_ymm(src1_reg);

            let src2_data = match inst.op_kind(2) {
                OpKind::Register => {
                    let src2_reg = self.convert_register(inst.op_register(2))?;
                    self.engine.cpu.read_ymm(src2_reg)
                }
                OpKind::Memory => self.read_ymm_memory(inst, 2)?,
                _ => {
                    return Err(EmulatorError::UnsupportedInstruction(format!(
                        "Unsupported VMAXPD source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            let mut result = [0u128; 2];

            for half in 0..2 {
                let mut double_results = [0u64; 2];
                for i in 0..2 {
                    let offset = i * 64;
                    let a_bits = ((src1_data[half] >> offset) & 0xFFFFFFFFFFFFFFFF) as u64;
                    let b_bits = ((src2_data[half] >> offset) & 0xFFFFFFFFFFFFFFFF) as u64;

                    let a = f64::from_bits(a_bits);
                    let b = f64::from_bits(b_bits);
                    let max_val = if a.is_nan() || b.is_nan() {
                        b
                    } else {
                        a.max(b)
                    };
                    double_results[i] = max_val.to_bits();
                }

                result[half] = (double_results[0] as u128) | ((double_results[1] as u128) << 64);
            }

            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_ymm(dst_reg, result);
        } else {
            // 128-bit XMM operation
            let src1_reg = self.convert_register(inst.op_register(1))?;
            let src1_data = self.engine.cpu.read_xmm(src1_reg);

            let src2_data = match inst.op_kind(2) {
                OpKind::Register => {
                    let src2_reg = self.convert_register(inst.op_register(2))?;
                    self.engine.cpu.read_xmm(src2_reg)
                }
                OpKind::Memory => {
                    let addr = self.calculate_memory_address(inst, 2)?;
                    self.read_memory_128(addr)?
                }
                _ => {
                    return Err(EmulatorError::UnsupportedInstruction(format!(
                        "Unsupported VMAXPD source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            let mut double_results = [0u64; 2];
            for i in 0..2 {
                let offset = i * 64;
                let a_bits = ((src1_data >> offset) & 0xFFFFFFFFFFFFFFFF) as u64;
                let b_bits = ((src2_data >> offset) & 0xFFFFFFFFFFFFFFFF) as u64;

                let a = f64::from_bits(a_bits);
                let b = f64::from_bits(b_bits);
                let max_val = if a.is_nan() || b.is_nan() {
                    b
                } else {
                    a.max(b)
                };
                double_results[i] = max_val.to_bits();
            }

            let result = (double_results[0] as u128) | ((double_results[1] as u128) << 64);

            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_xmm(dst_reg, result);
        }

        Ok(())
    }

    pub(crate) fn execute_vminps(&mut self, inst: &Instruction) -> Result<()> {
        // VMINPS - Minimum of Packed Single-Precision Floating-Point Values
        // VEX.256: VMINPS ymm1, ymm2, ymm3/m256
        // VEX.128: VMINPS xmm1, xmm2, xmm3/m128

        let is_256bit = inst.op_register(0).is_ymm();

        if inst.op_count() != 3 {
            return Err(EmulatorError::UnsupportedInstruction(
                "VMINPS requires exactly 3 operands".to_string(),
            ));
        }

        if is_256bit {
            // 256-bit YMM operation
            let src1_reg = self.convert_register(inst.op_register(1))?;
            let src1_data = self.engine.cpu.read_ymm(src1_reg);

            let src2_data = match inst.op_kind(2) {
                OpKind::Register => {
                    let src2_reg = self.convert_register(inst.op_register(2))?;
                    self.engine.cpu.read_ymm(src2_reg)
                }
                OpKind::Memory => self.read_ymm_memory(inst, 2)?,
                _ => {
                    return Err(EmulatorError::UnsupportedInstruction(format!(
                        "Unsupported VMINPS source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            // Perform element-wise minimum
            let mut result = [0u128; 2];

            for half in 0..2 {
                let mut float_results = [0u32; 4];
                for i in 0..4 {
                    let offset = i * 32;
                    let a_bits = ((src1_data[half] >> offset) & 0xFFFFFFFF) as u32;
                    let b_bits = ((src2_data[half] >> offset) & 0xFFFFFFFF) as u32;

                    let a = f32::from_bits(a_bits);
                    let b = f32::from_bits(b_bits);
                    // Handle NaN propagation: if either is NaN, result is second operand
                    let min_val = if a.is_nan() || b.is_nan() {
                        b
                    } else {
                        a.min(b)
                    };
                    float_results[i] = min_val.to_bits();
                }

                result[half] = (float_results[0] as u128)
                    | ((float_results[1] as u128) << 32)
                    | ((float_results[2] as u128) << 64)
                    | ((float_results[3] as u128) << 96);
            }

            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_ymm(dst_reg, result);
        } else {
            // 128-bit XMM operation
            let src1_reg = self.convert_register(inst.op_register(1))?;
            let src1_data = self.engine.cpu.read_xmm(src1_reg);

            let src2_data = match inst.op_kind(2) {
                OpKind::Register => {
                    let src2_reg = self.convert_register(inst.op_register(2))?;
                    self.engine.cpu.read_xmm(src2_reg)
                }
                OpKind::Memory => {
                    let addr = self.calculate_memory_address(inst, 2)?;
                    self.read_memory_128(addr)?
                }
                _ => {
                    return Err(EmulatorError::UnsupportedInstruction(format!(
                        "Unsupported VMINPS source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            let mut float_results = [0u32; 4];
            for i in 0..4 {
                let offset = i * 32;
                let a_bits = ((src1_data >> offset) & 0xFFFFFFFF) as u32;
                let b_bits = ((src2_data >> offset) & 0xFFFFFFFF) as u32;

                let a = f32::from_bits(a_bits);
                let b = f32::from_bits(b_bits);
                let min_val = if a.is_nan() || b.is_nan() {
                    b
                } else {
                    a.min(b)
                };
                float_results[i] = min_val.to_bits();
            }

            let result = (float_results[0] as u128)
                | ((float_results[1] as u128) << 32)
                | ((float_results[2] as u128) << 64)
                | ((float_results[3] as u128) << 96);

            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_xmm(dst_reg, result);
        }

        Ok(())
    }

    pub(crate) fn execute_vminpd(&mut self, inst: &Instruction) -> Result<()> {
        // VMINPD - Minimum of Packed Double-Precision Floating-Point Values
        // VEX.256: VMINPD ymm1, ymm2, ymm3/m256
        // VEX.128: VMINPD xmm1, xmm2, xmm3/m128

        let is_256bit = inst.op_register(0).is_ymm();

        if inst.op_count() != 3 {
            return Err(EmulatorError::UnsupportedInstruction(
                "VMINPD requires exactly 3 operands".to_string(),
            ));
        }

        if is_256bit {
            // 256-bit YMM operation
            let src1_reg = self.convert_register(inst.op_register(1))?;
            let src1_data = self.engine.cpu.read_ymm(src1_reg);

            let src2_data = match inst.op_kind(2) {
                OpKind::Register => {
                    let src2_reg = self.convert_register(inst.op_register(2))?;
                    self.engine.cpu.read_ymm(src2_reg)
                }
                OpKind::Memory => self.read_ymm_memory(inst, 2)?,
                _ => {
                    return Err(EmulatorError::UnsupportedInstruction(format!(
                        "Unsupported VMINPD source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            let mut result = [0u128; 2];

            for half in 0..2 {
                let mut double_results = [0u64; 2];
                for i in 0..2 {
                    let offset = i * 64;
                    let a_bits = ((src1_data[half] >> offset) & 0xFFFFFFFFFFFFFFFF) as u64;
                    let b_bits = ((src2_data[half] >> offset) & 0xFFFFFFFFFFFFFFFF) as u64;

                    let a = f64::from_bits(a_bits);
                    let b = f64::from_bits(b_bits);
                    let min_val = if a.is_nan() || b.is_nan() {
                        b
                    } else {
                        a.min(b)
                    };
                    double_results[i] = min_val.to_bits();
                }

                result[half] = (double_results[0] as u128) | ((double_results[1] as u128) << 64);
            }

            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_ymm(dst_reg, result);
        } else {
            // 128-bit XMM operation
            let src1_reg = self.convert_register(inst.op_register(1))?;
            let src1_data = self.engine.cpu.read_xmm(src1_reg);

            let src2_data = match inst.op_kind(2) {
                OpKind::Register => {
                    let src2_reg = self.convert_register(inst.op_register(2))?;
                    self.engine.cpu.read_xmm(src2_reg)
                }
                OpKind::Memory => {
                    let addr = self.calculate_memory_address(inst, 2)?;
                    self.read_memory_128(addr)?
                }
                _ => {
                    return Err(EmulatorError::UnsupportedInstruction(format!(
                        "Unsupported VMINPD source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            let mut double_results = [0u64; 2];
            for i in 0..2 {
                let offset = i * 64;
                let a_bits = ((src1_data >> offset) & 0xFFFFFFFFFFFFFFFF) as u64;
                let b_bits = ((src2_data >> offset) & 0xFFFFFFFFFFFFFFFF) as u64;

                let a = f64::from_bits(a_bits);
                let b = f64::from_bits(b_bits);
                let min_val = if a.is_nan() || b.is_nan() {
                    b
                } else {
                    a.min(b)
                };
                double_results[i] = min_val.to_bits();
            }

            let result = (double_results[0] as u128) | ((double_results[1] as u128) << 64);

            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_xmm(dst_reg, result);
        }

        Ok(())
    }
}
