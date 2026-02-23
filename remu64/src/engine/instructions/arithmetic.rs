use crate::engine::ExecutionContext;
use crate::error::{EmulatorError, Result};
use crate::memory::MemoryTrait;
use crate::{Flags, HookManager, Register};
use iced_x86::Instruction;

impl<H: HookManager<M, PS>, M: MemoryTrait<PS>, const PS: u64> ExecutionContext<'_, H, M, PS> {
    pub(crate) fn execute_sub(&mut self, inst: &Instruction) -> Result<()> {
        let dst_value = self.read_operand(inst, 0)?;
        let src_value = self.read_operand(inst, 1)?;
        let result = dst_value.wrapping_sub(src_value);

        // Update flags
        self.update_flags_arithmetic_iced(dst_value, src_value, result, true, inst)?;

        // Write result back to destination
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    pub(crate) fn execute_add(&mut self, inst: &Instruction) -> Result<()> {
        let dst_value = self.read_operand(inst, 0)?;
        let src_value = self.read_operand(inst, 1)?;
        let result = dst_value.wrapping_add(src_value);

        // Update flags
        self.update_flags_arithmetic_iced(dst_value, src_value, result, false, inst)?;

        // Write result back to destination
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    pub(crate) fn execute_inc(&mut self, inst: &Instruction) -> Result<()> {
        let dst_value = self.read_operand(inst, 0)?;
        let result = dst_value.wrapping_add(1);

        // Update flags (INC doesn't affect CF - save and restore it)
        let cf = self.engine.cpu.rflags.contains(Flags::CF);
        self.update_flags_arithmetic_iced(dst_value, 1, result, false, inst)?;
        self.engine.cpu.rflags.set(Flags::CF, cf);

        // Write result back to destination
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    pub(crate) fn execute_dec(&mut self, inst: &Instruction) -> Result<()> {
        let dst_value = self.read_operand(inst, 0)?;
        let result = dst_value.wrapping_sub(1);

        // Update flags (DEC doesn't affect CF - save and restore it)
        let cf = self.engine.cpu.rflags.contains(Flags::CF);
        self.update_flags_arithmetic_iced(dst_value, 1, result, true, inst)?;
        self.engine.cpu.rflags.set(Flags::CF, cf);

        // Write result back to destination
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    pub(crate) fn execute_imul(&mut self, inst: &Instruction) -> Result<()> {
        // IMUL: Integer Multiply (signed)
        match inst.op_count() {
            1 => {
                // 1-operand form - size depends on operand size:
                // imul r8:  AX = AL * r8
                // imul r16: DX:AX = AX * r16
                // imul r32: EDX:EAX = EAX * r32
                // imul r64: RDX:RAX = RAX * r64
                let operand_size = self.get_operand_size_from_instruction(inst, 0)?;
                let multiplier = self.read_operand(inst, 0)?;

                let (ax_reg, dx_reg, mask, shift, sign_extend): (
                    Register,
                    Register,
                    u64,
                    u32,
                    fn(u64) -> i128,
                ) = match operand_size {
                    1 => (Register::AL, Register::AH, 0xFF, 8, |v| (v as i8) as i128),
                    2 => (Register::AX, Register::DX, 0xFFFF, 16, |v| {
                        (v as i16) as i128
                    }),
                    4 => (Register::EAX, Register::EDX, 0xFFFFFFFF, 32, |v| {
                        (v as i32) as i128
                    }),
                    8 => (Register::RAX, Register::RDX, u64::MAX, 64, |v| {
                        (v as i64) as i128
                    }),
                    _ => {
                        return Err(EmulatorError::UnsupportedInstruction(format!(
                            "Unsupported IMUL operand size: {}",
                            operand_size
                        )));
                    }
                };

                let multiplicand = sign_extend(self.engine.cpu.read_reg(ax_reg) & mask);
                let mult = sign_extend(multiplier & mask);
                let result = multiplicand * mult;

                if operand_size == 1 {
                    // 8-bit: result goes in AX
                    self.engine
                        .cpu
                        .write_reg(Register::AX, result as u64 & 0xFFFF);
                } else {
                    self.engine.cpu.write_reg(ax_reg, (result as u64) & mask);
                    self.engine
                        .cpu
                        .write_reg(dx_reg, ((result >> shift) as u64) & mask);
                }

                // Set CF and OF if result doesn't fit in lower half (signed)
                let lower_signed = sign_extend((result as u64) & mask);
                let overflow = result != lower_signed;

                self.engine.cpu.rflags.set(Flags::CF, overflow);
                self.engine.cpu.rflags.set(Flags::OF, overflow);
            }
            2 => {
                // 2-operand form: reg = reg * r/m
                let dest_size = self.get_operand_size_from_instruction(inst, 0)?;
                let sign_extend: fn(u64) -> i128 = match dest_size {
                    1 => |v| (v as i8) as i128,
                    2 => |v| (v as i16) as i128,
                    4 => |v| (v as i32) as i128,
                    8 => |v| (v as i64) as i128,
                    _ => {
                        return Err(EmulatorError::UnsupportedInstruction(format!(
                            "Unsupported IMUL operand size: {}",
                            dest_size
                        )));
                    }
                };

                let multiplicand = sign_extend(self.read_operand(inst, 0)?);
                let multiplier = sign_extend(self.read_operand(inst, 1)?);
                let result = multiplicand * multiplier;

                // Store result in destination register
                self.write_operand(inst, 0, result as u64)?;

                // Set CF and OF if result doesn't fit in destination size (signed)
                let dest_bits = dest_size * 8;
                let max_positive = (1i128 << (dest_bits - 1)) - 1;
                let min_negative = -(1i128 << (dest_bits - 1));
                let overflow = result > max_positive || result < min_negative;

                self.engine.cpu.rflags.set(Flags::CF, overflow);
                self.engine.cpu.rflags.set(Flags::OF, overflow);
            }
            3 => {
                // 3-operand form: reg = r/m * immediate
                let dest_size = self.get_operand_size_from_instruction(inst, 0)?;
                let sign_extend: fn(u64) -> i128 = match dest_size {
                    1 => |v| (v as i8) as i128,
                    2 => |v| (v as i16) as i128,
                    4 => |v| (v as i32) as i128,
                    8 => |v| (v as i64) as i128,
                    _ => {
                        return Err(EmulatorError::UnsupportedInstruction(format!(
                            "Unsupported IMUL operand size: {}",
                            dest_size
                        )));
                    }
                };

                let multiplicand = sign_extend(self.read_operand(inst, 1)?);
                let multiplier = sign_extend(self.read_operand(inst, 2)?);
                let result = multiplicand * multiplier;

                // Store result in destination register
                self.write_operand(inst, 0, result as u64)?;

                // Set CF and OF if result doesn't fit in destination size (signed)
                let dest_bits = dest_size * 8;
                let max_positive = (1i128 << (dest_bits - 1)) - 1;
                let min_negative = -(1i128 << (dest_bits - 1));
                let overflow = result > max_positive || result < min_negative;

                self.engine.cpu.rflags.set(Flags::CF, overflow);
                self.engine.cpu.rflags.set(Flags::OF, overflow);
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(format!(
                    "IMUL with {} operands not supported",
                    inst.op_count()
                )));
            }
        }

        Ok(())
    }

    pub(crate) fn execute_mul(&mut self, inst: &Instruction) -> Result<()> {
        // MUL: Unsigned multiply - result size depends on operand size
        // mul r8:  AX = AL * r8
        // mul r16: DX:AX = AX * r16
        // mul r32: EDX:EAX = EAX * r32 (clears upper 32 bits)
        // mul r64: RDX:RAX = RAX * r64
        let operand_size = self.get_operand_size_from_instruction(inst, 0)?;
        let multiplier = self.read_operand(inst, 0)?;

        let (ax_reg, dx_reg, mask, shift) = match operand_size {
            1 => (Register::AL, Register::AH, 0xFF_u64, 8),
            2 => (Register::AX, Register::DX, 0xFFFF, 16),
            4 => (Register::EAX, Register::EDX, 0xFFFFFFFF, 32),
            8 => (Register::RAX, Register::RDX, u64::MAX, 64),
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(format!(
                    "Unsupported MUL operand size: {}",
                    operand_size
                )));
            }
        };

        let multiplicand = self.engine.cpu.read_reg(ax_reg) & mask;
        let mult = multiplier & mask;
        let result = (multiplicand as u128) * (mult as u128);

        if operand_size == 1 {
            // 8-bit: result goes in AX
            self.engine.cpu.write_reg(Register::AX, result as u64);
        } else {
            self.engine.cpu.write_reg(ax_reg, (result as u64) & mask);
            self.engine
                .cpu
                .write_reg(dx_reg, ((result >> shift) as u64) & mask);
        }

        let overflow = (result >> shift) != 0;
        self.engine.cpu.rflags.set(Flags::CF, overflow);
        self.engine.cpu.rflags.set(Flags::OF, overflow);

        Ok(())
    }

    pub(crate) fn execute_div(&mut self, inst: &Instruction) -> Result<()> {
        // DIV: Unsigned divide - size depends on operand size
        // div r8:  AX / r8 -> AL (quotient), AH (remainder)
        // div r16: DX:AX / r16 -> AX (quotient), DX (remainder)
        // div r32: EDX:EAX / r32 -> EAX (quotient), EDX (remainder)
        // div r64: RDX:RAX / r64 -> RAX (quotient), RDX (remainder)
        let operand_size = self.get_operand_size_from_instruction(inst, 0)?;
        let divisor = self.read_operand(inst, 0)?;

        if divisor == 0 {
            return Err(EmulatorError::DivisionByZero);
        }

        let (dividend, quotient_max, ax_reg, dx_reg, mask) = match operand_size {
            1 => {
                let ax = self.engine.cpu.read_reg(Register::AX);
                (ax as u128, 0xFF_u128, Register::AL, Register::AH, 0xFF_u64)
            }
            2 => {
                let dx = self.engine.cpu.read_reg(Register::DX) & 0xFFFF;
                let ax = self.engine.cpu.read_reg(Register::AX) & 0xFFFF;
                (
                    ((dx as u128) << 16) | (ax as u128),
                    0xFFFF_u128,
                    Register::AX,
                    Register::DX,
                    0xFFFF_u64,
                )
            }
            4 => {
                let edx = self.engine.cpu.read_reg(Register::EDX) & 0xFFFFFFFF;
                let eax = self.engine.cpu.read_reg(Register::EAX) & 0xFFFFFFFF;
                (
                    ((edx as u128) << 32) | (eax as u128),
                    0xFFFFFFFF_u128,
                    Register::EAX,
                    Register::EDX,
                    0xFFFFFFFF_u64,
                )
            }
            8 => {
                let rdx = self.engine.cpu.read_reg(Register::RDX);
                let rax = self.engine.cpu.read_reg(Register::RAX);
                (
                    ((rdx as u128) << 64) | (rax as u128),
                    u64::MAX as u128,
                    Register::RAX,
                    Register::RDX,
                    u64::MAX,
                )
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(format!(
                    "Unsupported DIV operand size: {}",
                    operand_size
                )));
            }
        };

        let divisor_masked = divisor & mask;
        let quotient = dividend / (divisor_masked as u128);
        let remainder = dividend % (divisor_masked as u128);

        // Check for overflow (quotient too large for destination)
        if quotient > quotient_max {
            return Err(EmulatorError::DivisionByZero); // x86 throws #DE for overflow too
        }

        self.engine.cpu.write_reg(ax_reg, (quotient as u64) & mask);
        self.engine.cpu.write_reg(dx_reg, (remainder as u64) & mask);

        Ok(())
    }

    pub(crate) fn execute_idiv(&mut self, inst: &Instruction) -> Result<()> {
        // IDIV: Signed divide - size depends on operand size
        // idiv r8:  AX / r8 -> AL (quotient), AH (remainder)
        // idiv r16: DX:AX / r16 -> AX (quotient), DX (remainder)
        // idiv r32: EDX:EAX / r32 -> EAX (quotient), EDX (remainder)
        // idiv r64: RDX:RAX / r64 -> RAX (quotient), RDX (remainder)
        let operand_size = self.get_operand_size_from_instruction(inst, 0)?;
        let divisor = self.read_operand(inst, 0)?;

        if divisor == 0 {
            return Err(EmulatorError::DivisionByZero);
        }

        let (dividend, quotient_min, quotient_max, ax_reg, dx_reg, mask, sign_extend): (
            i128,
            i128,
            i128,
            Register,
            Register,
            u64,
            fn(u64) -> i128,
        ) = match operand_size {
            1 => {
                let ax = self.engine.cpu.read_reg(Register::AX) as i16;
                (
                    ax as i128,
                    i8::MIN as i128,
                    i8::MAX as i128,
                    Register::AL,
                    Register::AH,
                    0xFF_u64,
                    |v| (v as i8) as i128,
                )
            }
            2 => {
                let dx = self.engine.cpu.read_reg(Register::DX) as u16;
                let ax = self.engine.cpu.read_reg(Register::AX) as u16;
                let combined = ((dx as u32) << 16) | (ax as u32);
                (
                    combined as i32 as i128,
                    i16::MIN as i128,
                    i16::MAX as i128,
                    Register::AX,
                    Register::DX,
                    0xFFFF_u64,
                    |v| (v as i16) as i128,
                )
            }
            4 => {
                let edx = self.engine.cpu.read_reg(Register::EDX) as u32;
                let eax = self.engine.cpu.read_reg(Register::EAX) as u32;
                let combined = ((edx as u64) << 32) | (eax as u64);
                (
                    combined as i64 as i128,
                    i32::MIN as i128,
                    i32::MAX as i128,
                    Register::EAX,
                    Register::EDX,
                    0xFFFFFFFF_u64,
                    |v| (v as i32) as i128,
                )
            }
            8 => {
                let rdx = self.engine.cpu.read_reg(Register::RDX);
                let rax = self.engine.cpu.read_reg(Register::RAX);
                let combined = ((rdx as u128) << 64) | (rax as u128);
                (
                    combined as i128,
                    i64::MIN as i128,
                    i64::MAX as i128,
                    Register::RAX,
                    Register::RDX,
                    u64::MAX,
                    |v| v as i64 as i128,
                )
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(format!(
                    "Unsupported IDIV operand size: {}",
                    operand_size
                )));
            }
        };

        let divisor_signed = sign_extend(divisor);
        let quotient = dividend / divisor_signed;
        let remainder = dividend % divisor_signed;

        // Check for overflow (quotient outside destination range)
        if quotient < quotient_min || quotient > quotient_max {
            return Err(EmulatorError::DivisionByZero); // x86 throws #DE for overflow too
        }

        self.engine.cpu.write_reg(ax_reg, (quotient as u64) & mask);
        self.engine.cpu.write_reg(dx_reg, (remainder as u64) & mask);

        Ok(())
    }

    pub(crate) fn execute_neg(&mut self, inst: &Instruction) -> Result<()> {
        // NEG: Two's complement negation
        let dst_value = self.read_operand(inst, 0)?;
        let result = (!dst_value).wrapping_add(1);

        // Update flags - NEG is like SUB 0, dst
        self.update_flags_arithmetic_iced(0, dst_value, result, true, inst)?;

        // Special case: CF is always set unless operand was 0
        if dst_value == 0 {
            self.engine.cpu.rflags.remove(Flags::CF);
        } else {
            self.engine.cpu.rflags.insert(Flags::CF);
        }

        // Write result back to destination
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    pub(crate) fn execute_sbb(&mut self, inst: &Instruction) -> Result<()> {
        // SBB: Subtract with borrow (carry flag)
        let dst_value = self.read_operand(inst, 0)?;
        let src_value = self.read_operand(inst, 1)?;
        let carry = if self.engine.cpu.rflags.contains(Flags::CF) {
            1u64
        } else {
            0u64
        };

        let result = dst_value.wrapping_sub(src_value).wrapping_sub(carry);

        // Update flags for ZF, SF, OF, PF using src_value (not src+carry to avoid overflow)
        self.update_flags_arithmetic_iced(dst_value, src_value, result, true, inst)?;

        // Fix CF for SBB: borrow occurs if dst < src OR (dst == src AND carry != 0)
        // This avoids the overflow issue with src_value + carry
        let size = self.get_operand_size_from_instruction(inst, 0)?;
        let mask = match size {
            1 => 0xFF,
            2 => 0xFFFF,
            4 => 0xFFFFFFFF,
            8 => 0xFFFFFFFFFFFFFFFF,
            _ => 0xFFFFFFFFFFFFFFFF,
        };
        let masked_dst = dst_value & mask;
        let masked_src = src_value & mask;

        if masked_dst < masked_src || (masked_dst == masked_src && carry != 0) {
            self.engine.cpu.rflags.insert(Flags::CF);
        } else {
            self.engine.cpu.rflags.remove(Flags::CF);
        }

        // Write result back to destination
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    pub(crate) fn execute_adc(&mut self, inst: &Instruction) -> Result<()> {
        // ADC: Add with Carry
        // Adds the source operand and the carry flag to the destination operand
        let dst_value = self.read_operand(inst, 0)?;
        let src_value = self.read_operand(inst, 1)?;
        let carry = if self.engine.cpu.rflags.contains(Flags::CF) {
            1
        } else {
            0
        };

        let result = dst_value.wrapping_add(src_value).wrapping_add(carry);

        // Update flags - for ADC, we need to consider the total operation
        // The flags should be calculated as if we did: dst + (src + carry)
        let effective_src = src_value.wrapping_add(carry);
        self.update_flags_arithmetic_iced(dst_value, effective_src, result, false, inst)?;

        // Write result back to destination
        self.write_operand(inst, 0, result)?;
        Ok(())
    }
}
