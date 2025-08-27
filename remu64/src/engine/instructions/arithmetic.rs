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

        // Update flags (INC doesn't affect CF)
        self.update_flags_arithmetic_iced(dst_value, 1, result, false, inst)?;

        // Write result back to destination
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    pub(crate) fn execute_dec(&mut self, inst: &Instruction) -> Result<()> {
        let dst_value = self.read_operand(inst, 0)?;
        let result = dst_value.wrapping_sub(1);

        // Update flags (DEC doesn't affect CF)
        self.update_flags_arithmetic_iced(dst_value, 1, result, true, inst)?;

        // Write result back to destination
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    pub(crate) fn execute_imul(&mut self, inst: &Instruction) -> Result<()> {
        // IMUL: Integer Multiply (signed)
        match inst.op_count() {
            1 => {
                // 1-operand form: RAX = RAX * operand, result in RDX:RAX
                let multiplicand = self.engine.cpu.read_reg(Register::RAX) as i64;
                let multiplier = self.read_operand(inst, 0)? as i64;
                let result = (multiplicand as i128) * (multiplier as i128);

                // Store low part in RAX, high part in RDX
                self.engine.cpu.write_reg(Register::RAX, result as u64);
                self.engine
                    .cpu
                    .write_reg(Register::RDX, (result >> 64) as u64);

                // Set CF and OF if high part is not sign extension of low part
                let low_part = result as i64;
                let high_part = (result >> 64) as i64;
                let overflow = high_part != if low_part < 0 { -1 } else { 0 };

                self.engine.cpu.rflags.set(Flags::CF, overflow);
                self.engine.cpu.rflags.set(Flags::OF, overflow);
            }
            2 => {
                // 2-operand form: reg = reg * r/m
                let multiplicand = self.read_operand(inst, 0)? as i64;
                let multiplier = self.read_operand(inst, 1)? as i64;
                let result = (multiplicand as i128) * (multiplier as i128);

                // Store result in destination register
                self.write_operand(inst, 0, result as u64)?;

                // Set CF and OF if result doesn't fit in destination size (signed)
                let dest_size = self.get_operand_size_from_instruction(inst, 0)?;
                let dest_bits = dest_size * 8;
                let max_positive = (1i128 << (dest_bits - 1)) - 1;
                let min_negative = -(1i128 << (dest_bits - 1));
                let overflow = result > max_positive || result < min_negative;

                self.engine.cpu.rflags.set(Flags::CF, overflow);
                self.engine.cpu.rflags.set(Flags::OF, overflow);
            }
            3 => {
                // 3-operand form: reg = r/m * immediate
                let multiplicand = self.read_operand(inst, 1)? as i64;
                let multiplier = self.read_operand(inst, 2)? as i64;
                let result = (multiplicand as i128) * (multiplier as i128);

                // Store result in destination register
                self.write_operand(inst, 0, result as u64)?;

                // Set CF and OF if result doesn't fit in destination size (signed)
                let dest_size = self.get_operand_size_from_instruction(inst, 0)?;
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
        // MUL: Unsigned multiply
        // 1-operand form: RAX = RAX * operand, result in RDX:RAX
        let multiplicand = self.engine.cpu.read_reg(Register::RAX);
        let multiplier = self.read_operand(inst, 0)?;

        let result = (multiplicand as u128) * (multiplier as u128);

        // Store low 64 bits in RAX, high 64 bits in RDX
        self.engine.cpu.write_reg(Register::RAX, result as u64);
        self.engine
            .cpu
            .write_reg(Register::RDX, (result >> 64) as u64);

        // Update flags: CF and OF are set if result requires more than 64 bits
        let overflow = (result >> 64) != 0;
        self.engine.cpu.rflags.set(Flags::CF, overflow);
        self.engine.cpu.rflags.set(Flags::OF, overflow);

        Ok(())
    }

    pub(crate) fn execute_div(&mut self, inst: &Instruction) -> Result<()> {
        // DIV: Unsigned divide
        // RDX:RAX / operand -> quotient in RAX, remainder in RDX
        let dividend_high = self.engine.cpu.read_reg(Register::RDX);
        let dividend_low = self.engine.cpu.read_reg(Register::RAX);
        let divisor = self.read_operand(inst, 0)?;

        if divisor == 0 {
            return Err(EmulatorError::DivisionByZero);
        }

        let dividend = ((dividend_high as u128) << 64) | (dividend_low as u128);
        let quotient = dividend / (divisor as u128);
        let remainder = dividend % (divisor as u128);

        // Check for overflow (quotient too large for RAX)
        if quotient > u64::MAX as u128 {
            return Err(EmulatorError::DivisionByZero); // x86 throws #DE for overflow too
        }

        self.engine.cpu.write_reg(Register::RAX, quotient as u64);
        self.engine.cpu.write_reg(Register::RDX, remainder as u64);

        Ok(())
    }

    pub(crate) fn execute_idiv(&mut self, inst: &Instruction) -> Result<()> {
        // IDIV: Signed divide
        // RDX:RAX / operand -> quotient in RAX, remainder in RDX
        let dividend_high = self.engine.cpu.read_reg(Register::RDX);
        let dividend_low = self.engine.cpu.read_reg(Register::RAX);
        let divisor = self.read_operand(inst, 0)? as i64;

        if divisor == 0 {
            return Err(EmulatorError::DivisionByZero);
        }

        // Combine high and low parts into signed 128-bit dividend
        let dividend = ((dividend_high as u128) << 64) | (dividend_low as u128);
        let dividend_signed = dividend as i128;

        let quotient = dividend_signed / (divisor as i128);
        let remainder = dividend_signed % (divisor as i128);

        // Check for overflow (quotient outside i64 range)
        if quotient < i64::MIN as i128 || quotient > i64::MAX as i128 {
            return Err(EmulatorError::DivisionByZero); // x86 throws #DE for overflow too
        }

        self.engine.cpu.write_reg(Register::RAX, quotient as u64);
        self.engine.cpu.write_reg(Register::RDX, remainder as u64);

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
            1
        } else {
            0
        };

        let result = dst_value.wrapping_sub(src_value).wrapping_sub(carry);

        // Update flags - SBB is like SUB but includes carry
        self.update_flags_arithmetic_iced(dst_value, src_value + carry, result, true, inst)?;

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
