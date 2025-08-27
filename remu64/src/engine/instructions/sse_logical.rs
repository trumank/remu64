use crate::HookManager;
use crate::engine::ExecutionContext;
use crate::error::{EmulatorError, Result};
use crate::memory::MemoryTrait;
use iced_x86::{Instruction, OpKind};

impl<H: HookManager<M>, M: MemoryTrait> ExecutionContext<'_, H, M> {
    pub(crate) fn execute_xorps(&mut self, inst: &Instruction) -> Result<()> {
        // XORPS: Bitwise XOR of Packed Single-Precision Floating-Point Values
        // Performs bitwise XOR between two 128-bit XMM registers

        match (inst.op_kind(0), inst.op_kind(1)) {
            (OpKind::Register, OpKind::Register) => {
                let dst_reg = self.convert_register(inst.op_register(0))?;
                let src_reg = self.convert_register(inst.op_register(1))?;

                // Check if both operands are XMM registers
                if !dst_reg.is_xmm() || !src_reg.is_xmm() {
                    return Err(EmulatorError::UnsupportedInstruction(
                        "XORPS requires XMM registers".to_string(),
                    ));
                }

                let dst_value = self.engine.cpu.read_xmm(dst_reg);
                let src_value = self.engine.cpu.read_xmm(src_reg);

                // Perform bitwise XOR
                let result = dst_value ^ src_value;

                self.engine.cpu.write_xmm(dst_reg, result);
                Ok(())
            }
            (OpKind::Register, OpKind::Memory) => {
                let dst_reg = self.convert_register(inst.op_register(0))?;

                if !dst_reg.is_xmm() {
                    return Err(EmulatorError::UnsupportedInstruction(
                        "XORPS requires XMM register as destination".to_string(),
                    ));
                }

                let dst_value = self.engine.cpu.read_xmm(dst_reg);
                let addr = self.calculate_memory_address(inst, 1)?;
                let src_value = self.read_memory_128(addr)?;

                // Perform bitwise XOR
                let result = dst_value ^ src_value;

                self.engine.cpu.write_xmm(dst_reg, result);
                Ok(())
            }
            _ => Err(EmulatorError::UnsupportedInstruction(format!(
                "Unsupported XORPS operand types: {:?}, {:?}",
                inst.op_kind(0),
                inst.op_kind(1)
            ))),
        }
    }

    pub(crate) fn execute_andps(&mut self, inst: &Instruction) -> Result<()> {
        // ANDPS: Bitwise AND Packed Single-Precision Floating-Point Values
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
                    "Invalid ANDPS source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let result = dst_value & src_value;
        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_orps(&mut self, inst: &Instruction) -> Result<()> {
        // ORPS: Bitwise OR Packed Single-Precision Floating-Point Values
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
                    "Invalid ORPS source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let result = dst_value | src_value;
        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_vandps(&mut self, inst: &Instruction) -> Result<()> {
        // VANDPS - Bitwise AND of Packed Single-Precision Floating-Point Values
        // VEX.256: VANDPS ymm1, ymm2, ymm3/m256
        // VEX.128: VANDPS xmm1, xmm2, xmm3/m128

        let is_256bit = inst.op_register(0).is_ymm();

        if inst.op_count() != 3 {
            return Err(EmulatorError::UnsupportedInstruction(
                "VANDPS requires exactly 3 operands".to_string(),
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
                        "Unsupported VANDPS source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            // Perform bitwise AND on both 128-bit halves
            let result = [src1_data[0] & src2_data[0], src1_data[1] & src2_data[1]];

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
                        "Unsupported VANDPS source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            // Perform bitwise AND
            let result = src1_data & src2_data;

            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_xmm(dst_reg, result);
        }

        Ok(())
    }

    pub(crate) fn execute_vandpd(&mut self, inst: &Instruction) -> Result<()> {
        // VANDPD - Bitwise AND of Packed Double-Precision Floating-Point Values
        // VEX.256: VANDPD ymm1, ymm2, ymm3/m256
        // VEX.128: VANDPD xmm1, xmm2, xmm3/m128

        let is_256bit = inst.op_register(0).is_ymm();

        if inst.op_count() != 3 {
            return Err(EmulatorError::UnsupportedInstruction(
                "VANDPD requires exactly 3 operands".to_string(),
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
                        "Unsupported VANDPD source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            // Perform bitwise AND on both 128-bit halves
            let result = [src1_data[0] & src2_data[0], src1_data[1] & src2_data[1]];

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
                        "Unsupported VANDPD source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            // Perform bitwise AND
            let result = src1_data & src2_data;

            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_xmm(dst_reg, result);
        }

        Ok(())
    }

    pub(crate) fn execute_vorps(&mut self, inst: &Instruction) -> Result<()> {
        // VORPS - Bitwise OR of Packed Single-Precision Floating-Point Values
        // VEX.256: VORPS ymm1, ymm2, ymm3/m256
        // VEX.128: VORPS xmm1, xmm2, xmm3/m128

        let is_256bit = inst.op_register(0).is_ymm();

        if inst.op_count() != 3 {
            return Err(EmulatorError::UnsupportedInstruction(
                "VORPS requires exactly 3 operands".to_string(),
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
                        "Unsupported VORPS source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            // Perform bitwise OR on both 128-bit halves
            let result = [src1_data[0] | src2_data[0], src1_data[1] | src2_data[1]];

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
                        "Unsupported VORPS source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            // Perform bitwise OR
            let result = src1_data | src2_data;

            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_xmm(dst_reg, result);
        }

        Ok(())
    }

    pub(crate) fn execute_vorpd(&mut self, inst: &Instruction) -> Result<()> {
        // VORPD - Bitwise OR of Packed Double-Precision Floating-Point Values
        // VEX.256: VORPD ymm1, ymm2, ymm3/m256
        // VEX.128: VORPD xmm1, xmm2, xmm3/m128

        let is_256bit = inst.op_register(0).is_ymm();

        if inst.op_count() != 3 {
            return Err(EmulatorError::UnsupportedInstruction(
                "VORPD requires exactly 3 operands".to_string(),
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
                        "Unsupported VORPD source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            // Perform bitwise OR on both 128-bit halves
            let result = [src1_data[0] | src2_data[0], src1_data[1] | src2_data[1]];

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
                        "Unsupported VORPD source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            // Perform bitwise OR
            let result = src1_data | src2_data;

            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_xmm(dst_reg, result);
        }

        Ok(())
    }

    pub(crate) fn execute_vxorps(&mut self, inst: &Instruction) -> Result<()> {
        // VXORPS - Bitwise XOR of Packed Single-Precision Floating-Point Values
        // VEX.256: VXORPS ymm1, ymm2, ymm3/m256
        // VEX.128: VXORPS xmm1, xmm2, xmm3/m128

        let is_256bit = inst.op_register(0).is_ymm();

        if inst.op_count() != 3 {
            return Err(EmulatorError::UnsupportedInstruction(
                "VXORPS requires exactly 3 operands".to_string(),
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
                        "Unsupported VXORPS source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            // Perform bitwise XOR on both 128-bit halves
            let result = [src1_data[0] ^ src2_data[0], src1_data[1] ^ src2_data[1]];

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
                        "Unsupported VXORPS source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            // Perform bitwise XOR
            let result = src1_data ^ src2_data;

            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_xmm(dst_reg, result);
        }

        Ok(())
    }

    pub(crate) fn execute_vxorpd(&mut self, inst: &Instruction) -> Result<()> {
        // VXORPD - Bitwise XOR of Packed Double-Precision Floating-Point Values
        // VEX.256: VXORPD ymm1, ymm2, ymm3/m256
        // VEX.128: VXORPD xmm1, xmm2, xmm3/m128

        let is_256bit = inst.op_register(0).is_ymm();

        if inst.op_count() != 3 {
            return Err(EmulatorError::UnsupportedInstruction(
                "VXORPD requires exactly 3 operands".to_string(),
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
                        "Unsupported VXORPD source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            // Perform bitwise XOR on both 128-bit halves
            let result = [src1_data[0] ^ src2_data[0], src1_data[1] ^ src2_data[1]];

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
                        "Unsupported VXORPD source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            // Perform bitwise XOR
            let result = src1_data ^ src2_data;

            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_xmm(dst_reg, result);
        }

        Ok(())
    }

    pub(crate) fn execute_vpxor(&mut self, inst: &Instruction) -> Result<()> {
        // VPXOR - Packed Logical XOR (Integer)
        // VEX.256: VPXOR ymm1, ymm2, ymm3/m256
        // VEX.128: VPXOR xmm1, xmm2, xmm3/m128

        let is_256bit = inst.op_register(0).is_ymm();

        if inst.op_count() != 3 {
            return Err(EmulatorError::UnsupportedInstruction(
                "VPXOR requires exactly 3 operands".to_string(),
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
                        "Unsupported VPXOR source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            // Perform bitwise XOR on both 128-bit halves
            let result = [src1_data[0] ^ src2_data[0], src1_data[1] ^ src2_data[1]];

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
                        "Unsupported VPXOR source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            // Perform bitwise XOR
            let result = src1_data ^ src2_data;

            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_xmm(dst_reg, result);
        }

        Ok(())
    }
}
