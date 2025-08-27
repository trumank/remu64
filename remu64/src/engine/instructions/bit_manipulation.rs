use crate::engine::ExecutionContext;
use crate::error::{EmulatorError, Result};
use crate::memory::MemoryTrait;
use crate::{Flags, HookManager};
use iced_x86::Instruction;

impl<H: HookManager<M>, M: MemoryTrait> ExecutionContext<'_, H, M> {
    pub(crate) fn execute_bt(&mut self, inst: &Instruction) -> Result<()> {
        // BT: Bit Test - Test bit in first operand by second operand, set CF accordingly
        let bit_base = self.read_operand(inst, 0)?;
        let bit_offset = self.read_operand(inst, 1)?;

        // Calculate effective bit position (modulo based on operand size)
        let size = self.get_operand_size_from_instruction(inst, 0)?;
        let bit_pos = (bit_offset & ((size * 8 - 1) as u64)) as u32;

        // Test the bit
        let bit_value = (bit_base >> bit_pos) & 1;

        // Set CF to the bit value
        if bit_value != 0 {
            self.engine.cpu.rflags.insert(Flags::CF);
        } else {
            self.engine.cpu.rflags.remove(Flags::CF);
        }

        Ok(())
    }

    pub(crate) fn execute_bts(&mut self, inst: &Instruction) -> Result<()> {
        // BTS: Bit Test and Set - Test bit and set it to 1
        let bit_base = self.read_operand(inst, 0)?;
        let bit_offset = self.read_operand(inst, 1)?;

        // Calculate effective bit position
        let size = self.get_operand_size_from_instruction(inst, 0)?;
        let bit_pos = (bit_offset & ((size * 8 - 1) as u64)) as u32;

        // Test the bit (set CF)
        let bit_value = (bit_base >> bit_pos) & 1;
        if bit_value != 0 {
            self.engine.cpu.rflags.insert(Flags::CF);
        } else {
            self.engine.cpu.rflags.remove(Flags::CF);
        }

        // Set the bit to 1
        let new_value = bit_base | (1u64 << bit_pos);
        self.write_operand(inst, 0, new_value)?;

        Ok(())
    }

    pub(crate) fn execute_btr(&mut self, inst: &Instruction) -> Result<()> {
        // BTR: Bit Test and Reset - Test bit and set it to 0
        let bit_base = self.read_operand(inst, 0)?;
        let bit_offset = self.read_operand(inst, 1)?;

        // Calculate effective bit position
        let size = self.get_operand_size_from_instruction(inst, 0)?;
        let bit_pos = (bit_offset & ((size * 8 - 1) as u64)) as u32;

        // Test the bit (set CF)
        let bit_value = (bit_base >> bit_pos) & 1;
        if bit_value != 0 {
            self.engine.cpu.rflags.insert(Flags::CF);
        } else {
            self.engine.cpu.rflags.remove(Flags::CF);
        }

        // Reset the bit to 0
        let new_value = bit_base & !(1u64 << bit_pos);
        self.write_operand(inst, 0, new_value)?;

        Ok(())
    }

    pub(crate) fn execute_btc(&mut self, inst: &Instruction) -> Result<()> {
        // BTC: Bit Test and Complement - Test bit and flip it
        let bit_base = self.read_operand(inst, 0)?;
        let bit_offset = self.read_operand(inst, 1)?;

        // Calculate effective bit position
        let size = self.get_operand_size_from_instruction(inst, 0)?;
        let bit_pos = (bit_offset & ((size * 8 - 1) as u64)) as u32;

        // Test the bit (set CF)
        let bit_value = (bit_base >> bit_pos) & 1;
        if bit_value != 0 {
            self.engine.cpu.rflags.insert(Flags::CF);
        } else {
            self.engine.cpu.rflags.remove(Flags::CF);
        }

        // Complement the bit
        let new_value = bit_base ^ (1u64 << bit_pos);
        self.write_operand(inst, 0, new_value)?;

        Ok(())
    }

    pub(crate) fn execute_bsf(&mut self, inst: &Instruction) -> Result<()> {
        // BSF: Bit Scan Forward - Find first set bit (from LSB)
        let source = self.read_operand(inst, 1)?;

        if source == 0 {
            // If source is 0, set ZF and destination is undefined
            self.engine.cpu.rflags.insert(Flags::ZF);
        } else {
            // Find the position of the first set bit
            let bit_pos = source.trailing_zeros() as u64;
            self.engine.cpu.rflags.remove(Flags::ZF);

            // Write result to destination
            self.write_operand(inst, 0, bit_pos)?;
        }

        Ok(())
    }

    pub(crate) fn execute_bsr(&mut self, inst: &Instruction) -> Result<()> {
        // BSR: Bit Scan Reverse - Find first set bit (from MSB)
        let source = self.read_operand(inst, 1)?;

        if source == 0 {
            // If source is 0, set ZF and destination is undefined
            self.engine.cpu.rflags.insert(Flags::ZF);
        } else {
            // Find the position of the first set bit from MSB
            let size = self.get_operand_size_from_instruction(inst, 1)?;
            let bit_pos = match size {
                1 => 7 - (source as u8).leading_zeros() as u64,
                2 => 15 - (source as u16).leading_zeros() as u64,
                4 => 31 - (source as u32).leading_zeros() as u64,
                8 => 63 - source.leading_zeros() as u64,
                _ => {
                    return Err(EmulatorError::UnsupportedInstruction(format!(
                        "Unsupported BSR operand size: {}",
                        size
                    )));
                }
            };

            self.engine.cpu.rflags.remove(Flags::ZF);

            // Write result to destination
            self.write_operand(inst, 0, bit_pos)?;
        }

        Ok(())
    }

    pub(crate) fn execute_popcnt(&mut self, inst: &Instruction) -> Result<()> {
        // POPCNT: Count the number of set bits
        let source = self.read_operand(inst, 1)?;

        // Count the number of 1 bits
        let count = source.count_ones() as u64;

        // Write result to destination
        self.write_operand(inst, 0, count)?;

        // Update flags
        // POPCNT clears all flags except CF and ZF
        self.engine
            .cpu
            .rflags
            .remove(Flags::SF | Flags::OF | Flags::AF | Flags::PF);
        self.engine.cpu.rflags.remove(Flags::CF); // CF is always cleared

        if count == 0 {
            self.engine.cpu.rflags.insert(Flags::ZF);
        } else {
            self.engine.cpu.rflags.remove(Flags::ZF);
        }

        Ok(())
    }

    pub(crate) fn execute_lzcnt(&mut self, inst: &Instruction) -> Result<()> {
        // LZCNT: Leading Zero Count - Count number of leading zero bits
        let source = self.read_operand(inst, 1)?;
        let size = self.get_operand_size_from_instruction(inst, 1)?;

        // Count leading zeros based on operand size
        let count = match size {
            1 => (source as u8).leading_zeros() as u64,
            2 => (source as u16).leading_zeros() as u64,
            4 => (source as u32).leading_zeros() as u64,
            8 => source.leading_zeros() as u64,
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(format!(
                    "Unsupported LZCNT operand size: {}",
                    size
                )));
            }
        };

        // Write result to destination
        self.write_operand(inst, 0, count)?;

        // Update flags
        // LZCNT clears all flags except CF and ZF
        self.engine
            .cpu
            .rflags
            .remove(Flags::SF | Flags::OF | Flags::AF | Flags::PF);

        // CF is set if source is zero (indicating the destination holds operand size in bits)
        if source == 0 {
            self.engine.cpu.rflags.insert(Flags::CF);
            self.engine.cpu.rflags.insert(Flags::ZF);
        } else {
            self.engine.cpu.rflags.remove(Flags::CF);
            self.engine.cpu.rflags.remove(Flags::ZF);
        }

        Ok(())
    }

    pub(crate) fn execute_tzcnt(&mut self, inst: &Instruction) -> Result<()> {
        // TZCNT: Trailing Zero Count - Count number of trailing zero bits
        let source = self.read_operand(inst, 1)?;
        let size = self.get_operand_size_from_instruction(inst, 1)?;

        // Count trailing zeros based on operand size
        let count = if source == 0 {
            // If source is 0, return the operand size in bits
            match size {
                1 => 8u64,
                2 => 16u64,
                4 => 32u64,
                8 => 64u64,
                _ => {
                    return Err(EmulatorError::UnsupportedInstruction(format!(
                        "Unsupported TZCNT operand size: {}",
                        size
                    )));
                }
            }
        } else {
            source.trailing_zeros() as u64
        };

        // Write result to destination
        self.write_operand(inst, 0, count)?;

        // Update flags
        // TZCNT clears all flags except CF and ZF
        self.engine
            .cpu
            .rflags
            .remove(Flags::SF | Flags::OF | Flags::AF | Flags::PF);

        // CF is set if source is zero
        if source == 0 {
            self.engine.cpu.rflags.insert(Flags::CF);
            self.engine.cpu.rflags.insert(Flags::ZF);
        } else {
            self.engine.cpu.rflags.remove(Flags::CF);
            self.engine.cpu.rflags.remove(Flags::ZF);
        }

        Ok(())
    }
}
