use crate::engine::ExecutionContext;
use crate::error::{EmulatorError, Result};
use crate::memory::MemoryTrait;
use crate::{Flags, HookManager, Register};
use iced_x86::Instruction;

impl<H: HookManager<M, PS>, M: MemoryTrait<PS>, const PS: u64> ExecutionContext<'_, H, M, PS> {
    pub(crate) fn execute_xor(&mut self, inst: &Instruction) -> Result<()> {
        let dst_value = self.read_operand(inst, 0)?;
        let src_value = self.read_operand(inst, 1)?;
        let result = dst_value ^ src_value;

        // Update flags (XOR is a logical operation)
        self.update_flags_logical_iced(result, inst)?;

        // Write result back to destination
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    pub(crate) fn execute_and(&mut self, inst: &Instruction) -> Result<()> {
        let dst_value = self.read_operand(inst, 0)?;
        let src_value = self.read_operand(inst, 1)?;
        let result = dst_value & src_value;

        // Update flags (AND only affects flags, clears OF and CF)
        self.update_flags_logical_iced(result, inst)?;

        // Write result back to destination
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    pub(crate) fn execute_or(&mut self, inst: &Instruction) -> Result<()> {
        let dst_value = self.read_operand(inst, 0)?;
        let src_value = self.read_operand(inst, 1)?;
        let result = dst_value | src_value;

        // Update flags (OR is a logical operation)
        self.update_flags_logical_iced(result, inst)?;

        // Write result back to destination
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    pub(crate) fn execute_sar(&mut self, inst: &Instruction) -> Result<()> {
        let dst_value = self.read_operand(inst, 0)?;
        let shift_count = self.read_operand(inst, 1)? & 0x1F; // Only use bottom 5 bits for 32-bit, 6 for 64-bit

        let size = self.get_operand_size_from_instruction(inst, 0)?;
        let result = match size {
            1 => {
                let val = dst_value as i8;
                (val >> shift_count) as u64
            }
            2 => {
                let val = dst_value as i16;
                (val >> shift_count) as u64
            }
            4 => {
                let val = dst_value as i32;
                (val >> shift_count) as u64
            }
            8 => {
                let val = dst_value as i64;
                (val >> shift_count) as u64
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(format!(
                    "Unsupported size: {}",
                    size
                )));
            }
        };

        // Update flags
        self.update_flags_logical_iced(result, inst)?;

        // Write result back to destination
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    pub(crate) fn execute_shr(&mut self, inst: &Instruction) -> Result<()> {
        let dst_value = self.read_operand(inst, 0)?;
        let shift_count = self.read_operand(inst, 1)? & 0x3F; // Only use bottom 6 bits for 64-bit

        let size = self.get_operand_size_from_instruction(inst, 0)?;
        let result = match size {
            1 => ((dst_value as u8) >> shift_count) as u64,
            2 => ((dst_value as u16) >> shift_count) as u64,
            4 => ((dst_value as u32) >> shift_count) as u64,
            8 => dst_value >> shift_count,
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(format!(
                    "Unsupported size: {}",
                    size
                )));
            }
        };

        // Update flags
        self.update_flags_logical_iced(result, inst)?;

        // Write result back to destination
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    pub(crate) fn execute_shl(&mut self, inst: &Instruction) -> Result<()> {
        let dst_value = self.read_operand(inst, 0)?;
        let shift_count = self.read_operand(inst, 1)? & 0x3F; // Only use bottom 6 bits for 64-bit

        let size = self.get_operand_size_from_instruction(inst, 0)?;
        let result = match size {
            1 => ((dst_value as u8) << shift_count) as u64,
            2 => ((dst_value as u16) << shift_count) as u64,
            4 => ((dst_value as u32) << shift_count) as u64,
            8 => dst_value << shift_count,
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(format!(
                    "Unsupported size: {}",
                    size
                )));
            }
        };

        // Update flags
        self.update_flags_logical_iced(result, inst)?;

        // Write result back to destination
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    pub(crate) fn execute_rol(&mut self, inst: &Instruction) -> Result<()> {
        // ROL: Rotate left
        let dst_value = self.read_operand(inst, 0)?;
        let count = (self.read_operand(inst, 1)? & 0x3F) as u32; // Only use bottom 6 bits for 64-bit

        if count == 0 {
            return Ok(()); // No rotation, no flag changes
        }

        let size = self.get_operand_size_from_instruction(inst, 0)?;
        let bit_count = size * 8;
        let effective_count = count % bit_count as u32;

        let result = match size {
            1 => {
                let val = dst_value as u8;
                ((val << effective_count) | (val >> (8 - effective_count))) as u64
            }
            2 => {
                let val = dst_value as u16;
                ((val << effective_count) | (val >> (16 - effective_count))) as u64
            }
            4 => {
                let val = dst_value as u32;
                ((val << effective_count) | (val >> (32 - effective_count))) as u64
            }
            8 => (dst_value << effective_count) | (dst_value >> (64 - effective_count)),
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(format!(
                    "Unsupported size for ROL: {}",
                    size
                )));
            }
        };

        // Update flags: CF = MSB of result, OF = MSB ^ (MSB-1) if count is 1
        let msb_mask = 1u64 << (bit_count - 1);
        let cf = (result & msb_mask) != 0;
        self.engine.cpu.rflags.set(Flags::CF, cf);

        if count == 1 {
            let msb_minus_1_mask = 1u64 << (bit_count - 2);
            let of = ((result & msb_mask) != 0) ^ ((result & msb_minus_1_mask) != 0);
            self.engine.cpu.rflags.set(Flags::OF, of);
        }

        // Write result back to destination
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    pub(crate) fn execute_not(&mut self, inst: &Instruction) -> Result<()> {
        // NOT: Bitwise NOT (one's complement)
        let dst_value = self.read_operand(inst, 0)?;
        let result = !dst_value;

        // NOT doesn't affect flags
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    pub(crate) fn execute_ror(&mut self, inst: &Instruction) -> Result<()> {
        // ROR: Rotate Right
        let dst_value = self.read_operand(inst, 0)?;
        let shift_count = self.read_operand(inst, 1)? & 0xFF; // Only use low 8 bits

        if shift_count == 0 {
            return Ok(()); // No operation if shift count is 0
        }

        let size = self.get_operand_size_from_instruction(inst, 0)?;
        let mask = match size {
            1 => 0xFF,
            2 => 0xFFFF,
            4 => 0xFFFFFFFF,
            8 => 0xFFFFFFFFFFFFFFFF,
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid operand size".to_string(),
                ));
            }
        };

        let masked_value = dst_value & mask;
        let effective_count = shift_count % (size * 8) as u64;

        if effective_count == 0 {
            return Ok(()); // No actual rotation needed
        }

        let bit_count = (size * 8) as u64;
        let result = ((masked_value >> effective_count)
            | (masked_value << (bit_count - effective_count)))
            & mask;

        // Update flags
        if effective_count == 1 {
            // CF = LSB of original operand
            if (dst_value & 1) != 0 {
                self.engine.cpu.rflags.insert(Flags::CF);
            } else {
                self.engine.cpu.rflags.remove(Flags::CF);
            }

            // OF = MSB of result XOR CF
            let msb = (result >> (bit_count - 1)) & 1;
            let cf = if self.engine.cpu.rflags.contains(Flags::CF) {
                1
            } else {
                0
            };
            if (msb ^ cf) != 0 {
                self.engine.cpu.rflags.insert(Flags::OF);
            } else {
                self.engine.cpu.rflags.remove(Flags::OF);
            }
        }

        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    pub(crate) fn execute_rcl(&mut self, inst: &Instruction) -> Result<()> {
        // RCL: Rotate through carry left
        let dst_value = self.read_operand(inst, 0)?;
        let count = (self.read_operand(inst, 1)? & 0x3F) as u32; // Modulo 64

        if count == 0 {
            return Ok(());
        }

        let size = self.get_operand_size_from_instruction(inst, 0)?;
        let bit_count = size * 8;

        // For RCL, we rotate through CF, making the rotation count be bit_count + 1
        let mod_count = count % (bit_count as u32 + 1);

        if mod_count == 0 {
            return Ok(());
        }

        let old_cf = if self.engine.cpu.rflags.contains(Flags::CF) {
            1u64
        } else {
            0u64
        };

        let (result, new_cf) = match size {
            1 => {
                let val = dst_value as u8;
                let extended = (val as u16) | ((old_cf as u16) << 8);
                let rotated = (extended << mod_count) | (extended >> (9 - mod_count));
                let result = (rotated & 0xFF) as u64;
                let cf = (rotated & 0x100) != 0;
                (result, cf)
            }
            2 => {
                let val = dst_value as u16;
                let extended = (val as u32) | ((old_cf as u32) << 16);
                let rotated = (extended << mod_count) | (extended >> (17 - mod_count));
                let result = (rotated & 0xFFFF) as u64;
                let cf = (rotated & 0x10000) != 0;
                (result, cf)
            }
            4 => {
                let val = dst_value as u32;
                let extended = (val as u64) | (old_cf << 32);
                let rotated = (extended << mod_count) | (extended >> (33 - mod_count));
                let result = rotated & 0xFFFFFFFF;
                let cf = (rotated & 0x100000000) != 0;
                (result, cf)
            }
            8 => {
                // For 64-bit, we need to handle this carefully
                let mut result = dst_value;
                let mut cf = old_cf != 0;

                for _ in 0..mod_count {
                    let new_cf = (result >> 63) & 1 != 0;
                    result = (result << 1) | (if cf { 1 } else { 0 });
                    cf = new_cf;
                }
                (result, cf)
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(format!(
                    "Unsupported size for RCL: {}",
                    size
                )));
            }
        };

        // Update CF
        if new_cf {
            self.engine.cpu.rflags.insert(Flags::CF);
        } else {
            self.engine.cpu.rflags.remove(Flags::CF);
        }

        // Update OF if count == 1
        if count == 1 {
            // OF = MSB XOR CF after rotation
            let msb = (result >> (bit_count - 1)) & 1 != 0;
            if msb != new_cf {
                self.engine.cpu.rflags.insert(Flags::OF);
            } else {
                self.engine.cpu.rflags.remove(Flags::OF);
            }
        }

        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    pub(crate) fn execute_rcr(&mut self, inst: &Instruction) -> Result<()> {
        // RCR: Rotate through carry right
        let dst_value = self.read_operand(inst, 0)?;
        let count = (self.read_operand(inst, 1)? & 0x3F) as u32; // Modulo 64

        if count == 0 {
            return Ok(());
        }

        let size = self.get_operand_size_from_instruction(inst, 0)?;
        let bit_count = size * 8;

        // For RCR, we rotate through CF, making the rotation count be bit_count + 1
        let mod_count = count % (bit_count as u32 + 1);

        if mod_count == 0 {
            return Ok(());
        }

        let old_cf = if self.engine.cpu.rflags.contains(Flags::CF) {
            1u64
        } else {
            0u64
        };

        let (result, new_cf) = match size {
            1 => {
                let val = dst_value as u8;
                let extended = (val as u16) | ((old_cf as u16) << 8);
                let rotated = (extended >> mod_count) | (extended << (9 - mod_count));
                let result = (rotated & 0xFF) as u64;
                let cf = ((extended >> (mod_count - 1)) & 1) != 0;
                (result, cf)
            }
            2 => {
                let val = dst_value as u16;
                let extended = (val as u32) | ((old_cf as u32) << 16);
                let rotated = (extended >> mod_count) | (extended << (17 - mod_count));
                let result = (rotated & 0xFFFF) as u64;
                let cf = ((extended >> (mod_count - 1)) & 1) != 0;
                (result, cf)
            }
            4 => {
                let val = dst_value as u32;
                let extended = (val as u64) | (old_cf << 32);
                let rotated = (extended >> mod_count) | (extended << (33 - mod_count));
                let result = rotated & 0xFFFFFFFF;
                let cf = ((extended >> (mod_count - 1)) & 1) != 0;
                (result, cf)
            }
            8 => {
                // For 64-bit, we need to handle this carefully
                let mut result = dst_value;
                let mut cf = old_cf != 0;

                for _ in 0..mod_count {
                    let new_cf = result & 1 != 0;
                    result = (result >> 1) | ((if cf { 1 } else { 0 }) << 63);
                    cf = new_cf;
                }
                (result, cf)
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(format!(
                    "Unsupported size for RCR: {}",
                    size
                )));
            }
        };

        // Update CF
        if new_cf {
            self.engine.cpu.rflags.insert(Flags::CF);
        } else {
            self.engine.cpu.rflags.remove(Flags::CF);
        }

        // Update OF if count == 1
        if count == 1 {
            // OF = two most significant bits XOR after rotation
            let msb = (result >> (bit_count - 1)) & 1 != 0;
            let msb_minus_1 = (result >> (bit_count - 2)) & 1 != 0;
            if msb != msb_minus_1 {
                self.engine.cpu.rflags.insert(Flags::OF);
            } else {
                self.engine.cpu.rflags.remove(Flags::OF);
            }
        }

        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    pub(crate) fn execute_andn(&mut self, inst: &Instruction) -> Result<()> {
        // ANDN: Logical AND NOT
        // dest = ~src1 & src2
        // This instruction performs a bitwise AND of the complement of the first source operand
        // with the second source operand and stores the result in the destination.

        // ANDN has 3 operands: dest, src1, src2
        // In VEX encoding: ANDN dest, src1, src2 means dest = ~src1 & src2
        let src1 = self.read_operand(inst, 1)?;
        let src2 = self.read_operand(inst, 2)?;

        // Perform AND NOT operation
        let result = !src1 & src2;

        // Write result to destination
        self.write_operand(inst, 0, result)?;

        // Update flags according to Intel manual
        // ANDN sets SF, ZF based on result
        // Clears OF and CF
        // AF is undefined (we'll clear it)
        // PF is undefined (we'll set it based on low byte)
        self.engine
            .cpu
            .rflags
            .remove(Flags::OF | Flags::CF | Flags::AF);

        // Set SF based on sign bit of result
        let size = self.get_operand_size_from_instruction(inst, 0)?;
        let sign_bit = match size {
            1 => (result & 0x80) != 0,
            2 => (result & 0x8000) != 0,
            4 => (result & 0x80000000) != 0,
            8 => (result & 0x8000000000000000) != 0,
            _ => false,
        };

        if sign_bit {
            self.engine.cpu.rflags.insert(Flags::SF);
        } else {
            self.engine.cpu.rflags.remove(Flags::SF);
        }

        // Set ZF if result is zero
        if result == 0 {
            self.engine.cpu.rflags.insert(Flags::ZF);
        } else {
            self.engine.cpu.rflags.remove(Flags::ZF);
        }

        // Set PF based on low byte
        let low_byte = (result & 0xFF) as u8;
        if low_byte.count_ones().is_multiple_of(2) {
            self.engine.cpu.rflags.insert(Flags::PF);
        } else {
            self.engine.cpu.rflags.remove(Flags::PF);
        }

        Ok(())
    }

    pub(crate) fn execute_bextr(&mut self, inst: &Instruction) -> Result<()> {
        // BEXTR: Bit Field Extract
        // Extracts contiguous bits from the first source operand using index and length
        // specified in the second source operand

        // BEXTR has 3 operands: dest, src1, src2
        // src2 contains: bits[7:0] = starting bit index, bits[15:8] = length
        let src1 = self.read_operand(inst, 1)?;
        let src2 = self.read_operand(inst, 2)?;

        // Extract start position and length from src2
        let start = (src2 & 0xFF) as u32;
        let length = ((src2 >> 8) & 0xFF) as u32;

        // Get operand size for masking
        let size = self.get_operand_size_from_instruction(inst, 0)?;
        let max_bits = size * 8;

        // If start position is >= operand size in bits, result is 0
        let result = if start >= max_bits as u32 {
            0u64
        } else if length == 0 {
            0u64
        } else {
            // Calculate how many bits we can actually extract
            let available_bits = (max_bits as u32).saturating_sub(start);
            let actual_length = length.min(available_bits).min(64);

            // Shift right to move the desired bits to position 0
            let shifted = src1 >> start;

            // Create a mask for the desired number of bits
            let mask = if actual_length >= 64 {
                !0u64
            } else {
                (1u64 << actual_length) - 1
            };

            // Extract the bits
            shifted & mask
        };

        // Write result to destination
        self.write_operand(inst, 0, result)?;

        // Update flags according to Intel manual
        // BEXTR clears OF and CF
        // Sets ZF based on result
        // AF, SF, PF are undefined (we'll clear AF, set SF/PF based on result)
        self.engine
            .cpu
            .rflags
            .remove(Flags::OF | Flags::CF | Flags::AF);

        // Set ZF if result is zero
        if result == 0 {
            self.engine.cpu.rflags.insert(Flags::ZF);
        } else {
            self.engine.cpu.rflags.remove(Flags::ZF);
        }

        // Set SF based on sign bit of result (even though it's undefined)
        let sign_bit = match size {
            1 => (result & 0x80) != 0,
            2 => (result & 0x8000) != 0,
            4 => (result & 0x80000000) != 0,
            8 => (result & 0x8000000000000000) != 0,
            _ => false,
        };

        if sign_bit {
            self.engine.cpu.rflags.insert(Flags::SF);
        } else {
            self.engine.cpu.rflags.remove(Flags::SF);
        }

        // Set PF based on low byte
        let low_byte = (result & 0xFF) as u8;
        if low_byte.count_ones().is_multiple_of(2) {
            self.engine.cpu.rflags.insert(Flags::PF);
        } else {
            self.engine.cpu.rflags.remove(Flags::PF);
        }

        Ok(())
    }

    pub(crate) fn execute_blsi(&mut self, inst: &Instruction) -> Result<()> {
        // BLSI: Extract Lowest Set Isolated Bit
        // Extracts the lowest set bit from the source operand and stores it in the destination
        // Operation: dest = src & -src
        // This isolates the rightmost 1 bit (if any) in the source operand

        // BLSI has 2 operands: dest, src
        // For VEX encoding, operand 0 is destination, operand 1 is source
        let src = self.read_operand(inst, 1)?;

        // Perform the operation: src & -src
        // In two's complement, -src = ~src + 1
        let neg_src = (!src).wrapping_add(1);
        let result = src & neg_src;

        // Write result to destination
        self.write_operand(inst, 0, result)?;

        // Update flags according to Intel manual
        // BLSI sets SF, CF, OF based on result
        // ZF is set if src is zero (result would be zero)
        // PF is undefined (we'll set it based on low byte)
        // AF is undefined (we'll clear it)
        self.engine.cpu.rflags.remove(Flags::AF);

        // Set ZF if source is zero (result would be zero)
        if src == 0 {
            self.engine.cpu.rflags.insert(Flags::ZF);
            // CF is cleared when src is zero
            self.engine.cpu.rflags.remove(Flags::CF);
        } else {
            self.engine.cpu.rflags.remove(Flags::ZF);
            // CF is set when src is not zero
            self.engine.cpu.rflags.insert(Flags::CF);
        }

        // SF is set to the MSB of the result
        let size = self.get_operand_size_from_instruction(inst, 0)?;
        let sign_bit = match size {
            1 => (result & 0x80) != 0,
            2 => (result & 0x8000) != 0,
            4 => (result & 0x80000000) != 0,
            8 => (result & 0x8000000000000000) != 0,
            _ => false,
        };

        if sign_bit {
            self.engine.cpu.rflags.insert(Flags::SF);
        } else {
            self.engine.cpu.rflags.remove(Flags::SF);
        }

        // OF is cleared
        self.engine.cpu.rflags.remove(Flags::OF);

        // Set PF based on low byte
        let low_byte = (result & 0xFF) as u8;
        if low_byte.count_ones().is_multiple_of(2) {
            self.engine.cpu.rflags.insert(Flags::PF);
        } else {
            self.engine.cpu.rflags.remove(Flags::PF);
        }

        Ok(())
    }

    pub(crate) fn execute_blsmsk(&mut self, inst: &Instruction) -> Result<()> {
        // BLSMSK: Get Mask Up to Lowest Set Bit
        // Creates a mask with all bits set from bit 0 up to and including
        // the lowest set bit in the source operand
        // Operation: dest = src ^ (src - 1)

        // BLSMSK has 2 operands: dest, src
        let src = self.read_operand(inst, 1)?;

        // Perform the operation: src ^ (src - 1)
        let result = src ^ src.wrapping_sub(1);

        // Write result to destination
        self.write_operand(inst, 0, result)?;

        // Update flags according to Intel manual
        // BLSMSK sets SF based on result
        // CF is set if src is NOT zero
        // ZF is cleared (result can never be zero if src != 0)
        // OF and AF are undefined (we'll clear them)
        // PF is undefined (we'll set it based on low byte)
        self.engine.cpu.rflags.remove(Flags::OF | Flags::AF);

        // Set CF if source is not zero
        if src != 0 {
            self.engine.cpu.rflags.insert(Flags::CF);
            // ZF is always clear when src != 0
            self.engine.cpu.rflags.remove(Flags::ZF);
        } else {
            self.engine.cpu.rflags.remove(Flags::CF);
            // ZF is set when src == 0 (result would be 0)
            self.engine.cpu.rflags.insert(Flags::ZF);
        }

        // SF is set to the MSB of the result
        let size = self.get_operand_size_from_instruction(inst, 0)?;
        let sign_bit = match size {
            1 => (result & 0x80) != 0,
            2 => (result & 0x8000) != 0,
            4 => (result & 0x80000000) != 0,
            8 => (result & 0x8000000000000000) != 0,
            _ => false,
        };

        if sign_bit {
            self.engine.cpu.rflags.insert(Flags::SF);
        } else {
            self.engine.cpu.rflags.remove(Flags::SF);
        }

        // Set PF based on low byte
        let low_byte = (result & 0xFF) as u8;
        if low_byte.count_ones().is_multiple_of(2) {
            self.engine.cpu.rflags.insert(Flags::PF);
        } else {
            self.engine.cpu.rflags.remove(Flags::PF);
        }

        Ok(())
    }

    pub(crate) fn execute_blsr(&mut self, inst: &Instruction) -> Result<()> {
        // BLSR: Reset Lowest Set Bit
        // Clears the lowest set bit in the source operand
        // Operation: dest = src & (src - 1)

        // BLSR has 2 operands: dest, src
        let src = self.read_operand(inst, 1)?;

        // Perform the operation: src & (src - 1)
        let result = src & src.wrapping_sub(1);

        // Write result to destination
        self.write_operand(inst, 0, result)?;

        // Update flags according to Intel manual
        // BLSR sets SF, ZF based on result
        // CF is set if src is NOT zero
        // OF is cleared
        // AF is undefined (we'll clear it)
        // PF is undefined (we'll set it based on low byte)
        self.engine.cpu.rflags.remove(Flags::OF | Flags::AF);

        // Set CF if source is not zero
        if src != 0 {
            self.engine.cpu.rflags.insert(Flags::CF);
        } else {
            self.engine.cpu.rflags.remove(Flags::CF);
        }

        // Set ZF if result is zero
        if result == 0 {
            self.engine.cpu.rflags.insert(Flags::ZF);
        } else {
            self.engine.cpu.rflags.remove(Flags::ZF);
        }

        // SF is set to the MSB of the result
        let size = self.get_operand_size_from_instruction(inst, 0)?;
        let sign_bit = match size {
            1 => (result & 0x80) != 0,
            2 => (result & 0x8000) != 0,
            4 => (result & 0x80000000) != 0,
            8 => (result & 0x8000000000000000) != 0,
            _ => false,
        };

        if sign_bit {
            self.engine.cpu.rflags.insert(Flags::SF);
        } else {
            self.engine.cpu.rflags.remove(Flags::SF);
        }

        // Set PF based on low byte
        let low_byte = (result & 0xFF) as u8;
        if low_byte.count_ones().is_multiple_of(2) {
            self.engine.cpu.rflags.insert(Flags::PF);
        } else {
            self.engine.cpu.rflags.remove(Flags::PF);
        }

        Ok(())
    }

    pub(crate) fn execute_bzhi(&mut self, inst: &Instruction) -> Result<()> {
        // BZHI: Zero High Bits Starting with Specified Bit Position
        // Takes bits from source1[0..index-1] where index is in source2[7:0]
        // Zeroes all bits from index and higher

        // BZHI has 3 operands: dest, src1, src2
        let src1 = self.read_operand(inst, 1)?;
        let src2 = self.read_operand(inst, 2)?;

        // Extract the bit index from bits 7:0 of src2
        let index = (src2 & 0xFF) as u32;

        // Get operand size in bits
        let size = inst.op0_register().size();
        let size_bits = (size * 8) as u32;

        // Compute result
        let result = if index >= size_bits {
            // If index >= operand size, result is src1 unchanged
            src1
        } else if index == 0 {
            // If index is 0, result is 0
            0
        } else {
            // Otherwise, mask off high bits starting at index
            // Create mask with 'index' low bits set
            let mask = (1u64 << index) - 1;
            src1 & mask
        };

        // Write result to destination
        self.write_operand(inst, 0, result)?;

        // Update flags according to Intel manual
        // BZHI clears CF and OF
        self.engine.cpu.rflags.remove(Flags::CF | Flags::OF);

        // Set ZF if result is zero
        if result == 0 {
            self.engine.cpu.rflags.insert(Flags::ZF);
        } else {
            self.engine.cpu.rflags.remove(Flags::ZF);
        }

        // Set SF based on sign bit of result
        let sign_bit = match size {
            1 => (result & 0x80) != 0,
            2 => (result & 0x8000) != 0,
            4 => (result & 0x80000000) != 0,
            8 => (result & 0x8000000000000000) != 0,
            _ => false,
        };

        if sign_bit {
            self.engine.cpu.rflags.insert(Flags::SF);
        } else {
            self.engine.cpu.rflags.remove(Flags::SF);
        }

        // PF is undefined - we'll set it based on low byte for consistency
        let low_byte = (result & 0xFF) as u8;
        if low_byte.count_ones().is_multiple_of(2) {
            self.engine.cpu.rflags.insert(Flags::PF);
        } else {
            self.engine.cpu.rflags.remove(Flags::PF);
        }

        // AF is undefined - we'll clear it
        self.engine.cpu.rflags.remove(Flags::AF);

        Ok(())
    }

    pub(crate) fn execute_pdep(&mut self, inst: &Instruction) -> Result<()> {
        // PDEP: Parallel Bits Deposit
        // Takes bits from source1 and deposits them at bit positions
        // marked by 1s in source2 (mask)
        // Bits from source1 are taken from LSB to MSB
        // Result bits at positions marked by 0s in mask are cleared

        // PDEP has 3 operands: dest, src1, src2 (mask)
        let src1 = self.read_operand(inst, 1)?;
        let mask = self.read_operand(inst, 2)?;

        // Get operand size to handle 32-bit vs 64-bit operations
        let size = inst.op0_register().size();

        // Mask operands to appropriate size
        let (src1_masked, mask_masked) = match size {
            4 => ((src1 & 0xFFFFFFFF), (mask & 0xFFFFFFFF)),
            8 => (src1, mask),
            _ => {
                return Err(EmulatorError::InvalidInstruction(
                    self.engine.cpu.read_reg(Register::RIP),
                ));
            }
        };

        let mut result = 0u64;
        let mut src_bits = src1_masked;
        let mut mask_copy = mask_masked;

        // For each bit position in the mask
        while mask_copy != 0 {
            // Find the lowest set bit in the mask
            let bit_pos = mask_copy.trailing_zeros();

            // Deposit the next bit from source at this position
            if src_bits & 1 != 0 {
                result |= 1u64 << bit_pos;
            }

            // Move to next source bit
            src_bits >>= 1;

            // Clear this bit from the mask
            mask_copy &= mask_copy - 1;
        }

        // Mask result to appropriate size for 32-bit operations
        if size == 4 {
            result &= 0xFFFFFFFF;
        }

        // Write result to destination
        self.write_operand(inst, 0, result)?;

        // PDEP does not modify any flags

        Ok(())
    }

    pub(crate) fn execute_pext(&mut self, inst: &Instruction) -> Result<()> {
        // PEXT: Parallel Bits Extract
        // Extracts bits from source at positions marked by 1s in mask
        // and packs them into consecutive low bits of result
        // This is the inverse of PDEP

        // PEXT has 3 operands: dest, src, mask
        let src = self.read_operand(inst, 1)?;
        let mask = self.read_operand(inst, 2)?;

        // Get operand size to handle 32-bit vs 64-bit operations
        let size = inst.op0_register().size();

        // Mask operands to appropriate size
        let (src_masked, mask_masked) = match size {
            4 => ((src & 0xFFFFFFFF), (mask & 0xFFFFFFFF)),
            8 => (src, mask),
            _ => {
                return Err(EmulatorError::InvalidInstruction(
                    self.engine.cpu.read_reg(Register::RIP),
                ));
            }
        };

        let mut result = 0u64;
        let mut result_bit = 0;
        let mut mask_copy = mask_masked;

        // For each set bit in the mask
        while mask_copy != 0 {
            // Find the lowest set bit in the mask
            let bit_pos = mask_copy.trailing_zeros();

            // Extract the bit at this position from source
            if (src_masked >> bit_pos) & 1 != 0 {
                result |= 1u64 << result_bit;
            }

            // Move to next result bit position
            result_bit += 1;

            // Clear this bit from the mask
            mask_copy &= mask_copy - 1;
        }

        // Write result to destination
        self.write_operand(inst, 0, result)?;

        // PEXT does not modify any flags

        Ok(())
    }

    pub(crate) fn execute_rorx(&mut self, inst: &Instruction) -> Result<()> {
        // RORX: Rotate Right Logical Without Affecting Flags
        // Rotates the source operand right by the specified immediate count
        // and stores the result in the destination without modifying flags
        // This is a BMI2 instruction

        // RORX has 3 operands: dest, src, imm8
        let src = self.read_operand(inst, 1)?;
        let count = self.read_operand(inst, 2)? as u32;

        // Get operand size to determine rotation width
        let size = self.get_operand_size_from_instruction(inst, 0)?;

        let result = match size {
            4 => {
                // 32-bit rotation
                let src32 = (src & 0xFFFFFFFF) as u32;
                let rotate_count = count & 0x1F; // Modulo 32
                let result32 = src32.rotate_right(rotate_count);
                result32 as u64
            }
            8 => {
                // 64-bit rotation
                let rotate_count = count & 0x3F; // Modulo 64
                src.rotate_right(rotate_count)
            }
            _ => {
                return Err(EmulatorError::InvalidInstruction(
                    self.engine.cpu.read_reg(Register::RIP),
                ));
            }
        };

        // Write result to destination
        self.write_operand(inst, 0, result)?;

        // RORX does not modify any flags - this is its key advantage

        Ok(())
    }

    pub(crate) fn execute_sarx(&mut self, inst: &Instruction) -> Result<()> {
        // SARX: Shift Arithmetic Right Without Affecting Flags
        // Performs arithmetic right shift (sign-extending) without modifying flags
        // This is a BMI2 instruction

        // SARX has 3 operands: dest, src, shift_count
        let src = self.read_operand(inst, 1)?;
        let count = self.read_operand(inst, 2)?;

        // Get operand size
        let size = self.get_operand_size_from_instruction(inst, 0)?;

        let result = match size {
            4 => {
                // 32-bit arithmetic shift
                let src32 = (src & 0xFFFFFFFF) as i32;
                let shift_count = (count & 0x1F) as u32; // Modulo 32
                let result32 = src32 >> shift_count;
                result32 as u32 as u64
            }
            8 => {
                // 64-bit arithmetic shift
                let src64 = src as i64;
                let shift_count = (count & 0x3F) as u32; // Modulo 64
                (src64 >> shift_count) as u64
            }
            _ => {
                return Err(EmulatorError::InvalidInstruction(
                    self.engine.cpu.read_reg(Register::RIP),
                ));
            }
        };

        // Write result to destination
        self.write_operand(inst, 0, result)?;

        // SARX does not modify any flags

        Ok(())
    }

    pub(crate) fn execute_shlx(&mut self, inst: &Instruction) -> Result<()> {
        // SHLX: Shift Logical Left Without Affecting Flags
        // Performs logical left shift without modifying flags
        // This is a BMI2 instruction

        // SHLX has 3 operands: dest, src, shift_count
        let src = self.read_operand(inst, 1)?;
        let count = self.read_operand(inst, 2)?;

        // Get operand size
        let size = self.get_operand_size_from_instruction(inst, 0)?;

        let result = match size {
            4 => {
                // 32-bit logical shift left
                let src32 = (src & 0xFFFFFFFF) as u32;
                let shift_count = (count & 0x1F) as u32; // Modulo 32
                let result32 = src32 << shift_count;
                result32 as u64
            }
            8 => {
                // 64-bit logical shift left
                let shift_count = (count & 0x3F) as u32; // Modulo 64
                src << shift_count
            }
            _ => {
                return Err(EmulatorError::InvalidInstruction(
                    self.engine.cpu.read_reg(Register::RIP),
                ));
            }
        };

        // Write result to destination
        self.write_operand(inst, 0, result)?;

        // SHLX does not modify any flags

        Ok(())
    }

    pub(crate) fn execute_shrx(&mut self, inst: &Instruction) -> Result<()> {
        // SHRX: Shift Logical Right Without Affecting Flags
        // Performs logical right shift without modifying flags
        // This is a BMI2 instruction

        // SHRX has 3 operands: dest, src, shift_count
        let src = self.read_operand(inst, 1)?;
        let count = self.read_operand(inst, 2)?;

        // Get operand size
        let size = self.get_operand_size_from_instruction(inst, 0)?;

        let result = match size {
            4 => {
                // 32-bit logical shift right
                let src32 = (src & 0xFFFFFFFF) as u32;
                let shift_count = (count & 0x1F) as u32; // Modulo 32
                let result32 = src32 >> shift_count;
                result32 as u64
            }
            8 => {
                // 64-bit logical shift right
                let shift_count = (count & 0x3F) as u32; // Modulo 64
                src >> shift_count
            }
            _ => {
                return Err(EmulatorError::InvalidInstruction(
                    self.engine.cpu.read_reg(Register::RIP),
                ));
            }
        };

        // Write result to destination
        self.write_operand(inst, 0, result)?;

        // SHRX does not modify any flags

        Ok(())
    }
}
