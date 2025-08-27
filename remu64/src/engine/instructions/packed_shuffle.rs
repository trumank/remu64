use crate::HookManager;
use crate::engine::ExecutionContext;
use crate::error::{EmulatorError, Result};
use crate::memory::MemoryTrait;
use iced_x86::{Instruction, OpKind};

impl<H: HookManager<M, PS>, M: MemoryTrait<PS>, const PS: u64> ExecutionContext<'_, H, M, PS> {
    pub(crate) fn execute_punpcklwd(&mut self, inst: &Instruction) -> Result<()> {
        // PUNPCKLWD: Unpack and interleave low words
        // For XMM registers: takes low 4 words (64 bits) from each operand and interleaves them
        // Result: [dst[0], src[0], dst[1], src[1], dst[2], src[2], dst[3], src[3]]

        match (inst.op_kind(0), inst.op_kind(1)) {
            (OpKind::Register, OpKind::Register) => {
                let dst_reg = self.convert_register(inst.op_register(0))?;
                let src_reg = self.convert_register(inst.op_register(1))?;

                // Check if both operands are XMM registers
                if !dst_reg.is_xmm() || !src_reg.is_xmm() {
                    return Err(EmulatorError::UnsupportedInstruction(
                        "PUNPCKLWD requires XMM registers".to_string(),
                    ));
                }

                let dst_value = self.engine.cpu.read_xmm(dst_reg);
                let src_value = self.engine.cpu.read_xmm(src_reg);

                // Extract low 4 words (16 bits each) from destination and source
                let dst_words = [
                    (dst_value & 0xFFFF) as u16,
                    ((dst_value >> 16) & 0xFFFF) as u16,
                    ((dst_value >> 32) & 0xFFFF) as u16,
                    ((dst_value >> 48) & 0xFFFF) as u16,
                ];

                let src_words = [
                    (src_value & 0xFFFF) as u16,
                    ((src_value >> 16) & 0xFFFF) as u16,
                    ((src_value >> 32) & 0xFFFF) as u16,
                    ((src_value >> 48) & 0xFFFF) as u16,
                ];

                // Interleave: dst[0], src[0], dst[1], src[1], dst[2], src[2], dst[3], src[3]
                let result = (dst_words[0] as u128)
                    | ((src_words[0] as u128) << 16)
                    | ((dst_words[1] as u128) << 32)
                    | ((src_words[1] as u128) << 48)
                    | ((dst_words[2] as u128) << 64)
                    | ((src_words[2] as u128) << 80)
                    | ((dst_words[3] as u128) << 96)
                    | ((src_words[3] as u128) << 112);

                self.engine.cpu.write_xmm(dst_reg, result);
                Ok(())
            }
            (OpKind::Register, OpKind::Memory) => {
                let dst_reg = self.convert_register(inst.op_register(0))?;

                if !dst_reg.is_xmm() {
                    return Err(EmulatorError::UnsupportedInstruction(
                        "PUNPCKLWD requires XMM register as destination".to_string(),
                    ));
                }

                let dst_value = self.engine.cpu.read_xmm(dst_reg);
                let addr = self.calculate_memory_address(inst, 1)?;
                let src_value = self.read_memory_128(addr)?;

                // Extract low 4 words (16 bits each) from destination and source
                let dst_words = [
                    (dst_value & 0xFFFF) as u16,
                    ((dst_value >> 16) & 0xFFFF) as u16,
                    ((dst_value >> 32) & 0xFFFF) as u16,
                    ((dst_value >> 48) & 0xFFFF) as u16,
                ];

                let src_words = [
                    (src_value & 0xFFFF) as u16,
                    ((src_value >> 16) & 0xFFFF) as u16,
                    ((src_value >> 32) & 0xFFFF) as u16,
                    ((src_value >> 48) & 0xFFFF) as u16,
                ];

                // Interleave: dst[0], src[0], dst[1], src[1], dst[2], src[2], dst[3], src[3]
                let result = (dst_words[0] as u128)
                    | ((src_words[0] as u128) << 16)
                    | ((dst_words[1] as u128) << 32)
                    | ((src_words[1] as u128) << 48)
                    | ((dst_words[2] as u128) << 64)
                    | ((src_words[2] as u128) << 80)
                    | ((dst_words[3] as u128) << 96)
                    | ((src_words[3] as u128) << 112);

                self.engine.cpu.write_xmm(dst_reg, result);
                Ok(())
            }
            _ => Err(EmulatorError::UnsupportedInstruction(format!(
                "Unsupported PUNPCKLWD operand types: {:?}, {:?}",
                inst.op_kind(0),
                inst.op_kind(1)
            ))),
        }
    }

    pub(crate) fn execute_pshufd(&mut self, inst: &Instruction) -> Result<()> {
        // PSHUFD: Packed Shuffle Doublewords
        // Shuffles 32-bit doublewords in a 128-bit XMM register based on an 8-bit immediate
        // Each 2-bit field in the immediate selects which source dword to copy to each position
        // Immediate bits: [7:6] -> dword[3], [5:4] -> dword[2], [3:2] -> dword[1], [1:0] -> dword[0]

        if inst.op_count() != 3 {
            return Err(EmulatorError::UnsupportedInstruction(
                "PSHUFD requires exactly 3 operands".to_string(),
            ));
        }

        match (inst.op_kind(0), inst.op_kind(1), inst.op_kind(2)) {
            (OpKind::Register, OpKind::Register, OpKind::Immediate8) => {
                let dst_reg = self.convert_register(inst.op_register(0))?;
                let src_reg = self.convert_register(inst.op_register(1))?;
                let imm8 = inst.immediate8();

                // Check if both operands are XMM registers
                if !dst_reg.is_xmm() || !src_reg.is_xmm() {
                    return Err(EmulatorError::UnsupportedInstruction(
                        "PSHUFD requires XMM registers".to_string(),
                    ));
                }

                let src_value = self.engine.cpu.read_xmm(src_reg);

                // Extract 4 doublewords (32 bits each) from source
                let src_dwords = [
                    (src_value & 0xFFFFFFFF) as u32,         // dword[0]
                    ((src_value >> 32) & 0xFFFFFFFF) as u32, // dword[1]
                    ((src_value >> 64) & 0xFFFFFFFF) as u32, // dword[2]
                    ((src_value >> 96) & 0xFFFFFFFF) as u32, // dword[3]
                ];

                // Extract 2-bit selectors from immediate
                let sel0 = (imm8 & 0x03) as usize; // bits [1:0] -> dword[0]
                let sel1 = ((imm8 >> 2) & 0x03) as usize; // bits [3:2] -> dword[1]
                let sel2 = ((imm8 >> 4) & 0x03) as usize; // bits [5:4] -> dword[2]
                let sel3 = ((imm8 >> 6) & 0x03) as usize; // bits [7:6] -> dword[3]

                // Build result by selecting dwords based on immediate
                let result = (src_dwords[sel0] as u128)
                    | ((src_dwords[sel1] as u128) << 32)
                    | ((src_dwords[sel2] as u128) << 64)
                    | ((src_dwords[sel3] as u128) << 96);

                self.engine.cpu.write_xmm(dst_reg, result);
                Ok(())
            }
            (OpKind::Register, OpKind::Memory, OpKind::Immediate8) => {
                let dst_reg = self.convert_register(inst.op_register(0))?;
                let imm8 = inst.immediate8();

                if !dst_reg.is_xmm() {
                    return Err(EmulatorError::UnsupportedInstruction(
                        "PSHUFD requires XMM register as destination".to_string(),
                    ));
                }

                let addr = self.calculate_memory_address(inst, 1)?;
                let src_value = self.read_memory_128(addr)?;

                // Extract 4 doublewords (32 bits each) from source
                let src_dwords = [
                    (src_value & 0xFFFFFFFF) as u32,         // dword[0]
                    ((src_value >> 32) & 0xFFFFFFFF) as u32, // dword[1]
                    ((src_value >> 64) & 0xFFFFFFFF) as u32, // dword[2]
                    ((src_value >> 96) & 0xFFFFFFFF) as u32, // dword[3]
                ];

                // Extract 2-bit selectors from immediate
                let sel0 = (imm8 & 0x03) as usize; // bits [1:0] -> dword[0]
                let sel1 = ((imm8 >> 2) & 0x03) as usize; // bits [3:2] -> dword[1]
                let sel2 = ((imm8 >> 4) & 0x03) as usize; // bits [5:4] -> dword[2]
                let sel3 = ((imm8 >> 6) & 0x03) as usize; // bits [7:6] -> dword[3]

                // Build result by selecting dwords based on immediate
                let result = (src_dwords[sel0] as u128)
                    | ((src_dwords[sel1] as u128) << 32)
                    | ((src_dwords[sel2] as u128) << 64)
                    | ((src_dwords[sel3] as u128) << 96);

                self.engine.cpu.write_xmm(dst_reg, result);
                Ok(())
            }
            _ => Err(EmulatorError::UnsupportedInstruction(format!(
                "Unsupported PSHUFD operand types: {:?}, {:?}, {:?}",
                inst.op_kind(0),
                inst.op_kind(1),
                inst.op_kind(2)
            ))),
        }
    }

    pub(crate) fn execute_pshuflw(&mut self, inst: &Instruction) -> Result<()> {
        // PSHUFLW: Packed Shuffle Low Words
        // Shuffles 16-bit words in the low 64 bits of a 128-bit XMM register based on an 8-bit immediate
        // The high 64 bits are preserved unchanged
        // Immediate bits: [7:6] -> word[3], [5:4] -> word[2], [3:2] -> word[1], [1:0] -> word[0]

        if inst.op_count() != 3 {
            return Err(EmulatorError::UnsupportedInstruction(
                "PSHUFLW requires exactly 3 operands".to_string(),
            ));
        }

        match (inst.op_kind(0), inst.op_kind(1), inst.op_kind(2)) {
            (OpKind::Register, OpKind::Register, OpKind::Immediate8) => {
                let dst_reg = self.convert_register(inst.op_register(0))?;
                let src_reg = self.convert_register(inst.op_register(1))?;
                let imm8 = inst.immediate8();

                // Check if both operands are XMM registers
                if !dst_reg.is_xmm() || !src_reg.is_xmm() {
                    return Err(EmulatorError::UnsupportedInstruction(
                        "PSHUFLW requires XMM registers".to_string(),
                    ));
                }

                let src_value = self.engine.cpu.read_xmm(src_reg);

                // Extract 4 words (16 bits each) from low 64 bits of source
                let src_words = [
                    (src_value & 0xFFFF) as u16,         // word[0]
                    ((src_value >> 16) & 0xFFFF) as u16, // word[1]
                    ((src_value >> 32) & 0xFFFF) as u16, // word[2]
                    ((src_value >> 48) & 0xFFFF) as u16, // word[3]
                ];

                // Extract 2-bit selectors from immediate
                let sel0 = (imm8 & 0x03) as usize; // bits [1:0] -> word[0]
                let sel1 = ((imm8 >> 2) & 0x03) as usize; // bits [3:2] -> word[1]
                let sel2 = ((imm8 >> 4) & 0x03) as usize; // bits [5:4] -> word[2]
                let sel3 = ((imm8 >> 6) & 0x03) as usize; // bits [7:6] -> word[3]

                // Build low 64 bits by selecting words based on immediate
                let low_result = (src_words[sel0] as u128)
                    | ((src_words[sel1] as u128) << 16)
                    | ((src_words[sel2] as u128) << 32)
                    | ((src_words[sel3] as u128) << 48);

                // Preserve high 64 bits
                let high_64 = src_value & 0xFFFFFFFF_FFFFFFFF_00000000_00000000u128;

                // Combine low and high parts
                let result = low_result | high_64;

                self.engine.cpu.write_xmm(dst_reg, result);
                Ok(())
            }
            (OpKind::Register, OpKind::Memory, OpKind::Immediate8) => {
                let dst_reg = self.convert_register(inst.op_register(0))?;
                let imm8 = inst.immediate8();

                if !dst_reg.is_xmm() {
                    return Err(EmulatorError::UnsupportedInstruction(
                        "PSHUFLW requires XMM register as destination".to_string(),
                    ));
                }

                let addr = self.calculate_memory_address(inst, 1)?;
                let src_value = self.read_memory_128(addr)?;

                // Extract 4 words (16 bits each) from low 64 bits of source
                let src_words = [
                    (src_value & 0xFFFF) as u16,         // word[0]
                    ((src_value >> 16) & 0xFFFF) as u16, // word[1]
                    ((src_value >> 32) & 0xFFFF) as u16, // word[2]
                    ((src_value >> 48) & 0xFFFF) as u16, // word[3]
                ];

                // Extract 2-bit selectors from immediate
                let sel0 = (imm8 & 0x03) as usize; // bits [1:0] -> word[0]
                let sel1 = ((imm8 >> 2) & 0x03) as usize; // bits [3:2] -> word[1]
                let sel2 = ((imm8 >> 4) & 0x03) as usize; // bits [5:4] -> word[2]
                let sel3 = ((imm8 >> 6) & 0x03) as usize; // bits [7:6] -> word[3]

                // Build low 64 bits by selecting words based on immediate
                let low_result = (src_words[sel0] as u128)
                    | ((src_words[sel1] as u128) << 16)
                    | ((src_words[sel2] as u128) << 32)
                    | ((src_words[sel3] as u128) << 48);

                // Preserve high 64 bits
                let high_64 = src_value & 0xFFFFFFFF_FFFFFFFF_00000000_00000000u128;

                // Combine low and high parts
                let result = low_result | high_64;

                self.engine.cpu.write_xmm(dst_reg, result);
                Ok(())
            }
            _ => Err(EmulatorError::UnsupportedInstruction(format!(
                "Unsupported PSHUFLW operand types: {:?}, {:?}, {:?}",
                inst.op_kind(0),
                inst.op_kind(1),
                inst.op_kind(2)
            ))),
        }
    }

    pub(crate) fn execute_pshufhw(&mut self, inst: &Instruction) -> Result<()> {
        // PSHUFHW: Packed Shuffle High Words
        // Shuffles 16-bit words in the high 64 bits of a 128-bit XMM register based on an 8-bit immediate
        // The low 64 bits are preserved unchanged
        // Immediate bits: [7:6] -> word[7], [5:4] -> word[6], [3:2] -> word[5], [1:0] -> word[4]

        if inst.op_count() != 3 {
            return Err(EmulatorError::UnsupportedInstruction(
                "PSHUFHW requires exactly 3 operands".to_string(),
            ));
        }

        match (inst.op_kind(0), inst.op_kind(1), inst.op_kind(2)) {
            (OpKind::Register, OpKind::Register, OpKind::Immediate8) => {
                let dst_reg = self.convert_register(inst.op_register(0))?;
                let src_reg = self.convert_register(inst.op_register(1))?;
                let imm8 = inst.immediate8();

                // Check if both operands are XMM registers
                if !dst_reg.is_xmm() || !src_reg.is_xmm() {
                    return Err(EmulatorError::UnsupportedInstruction(
                        "PSHUFHW requires XMM registers".to_string(),
                    ));
                }

                let src_value = self.engine.cpu.read_xmm(src_reg);

                // Extract 4 words (16 bits each) from high 64 bits of source
                // These are words 4-7 of the 128-bit value
                let src_words = [
                    ((src_value >> 64) & 0xFFFF) as u16,  // word[4]
                    ((src_value >> 80) & 0xFFFF) as u16,  // word[5]
                    ((src_value >> 96) & 0xFFFF) as u16,  // word[6]
                    ((src_value >> 112) & 0xFFFF) as u16, // word[7]
                ];

                // Extract 2-bit selectors from immediate
                // Note: selectors index into the 4-word array (0-3), not the absolute word positions
                let sel0 = (imm8 & 0x03) as usize; // bits [1:0] -> word[4]
                let sel1 = ((imm8 >> 2) & 0x03) as usize; // bits [3:2] -> word[5]
                let sel2 = ((imm8 >> 4) & 0x03) as usize; // bits [5:4] -> word[6]
                let sel3 = ((imm8 >> 6) & 0x03) as usize; // bits [7:6] -> word[7]

                // Build high 64 bits by selecting words based on immediate
                let high_result = ((src_words[sel0] as u128) << 64)
                    | ((src_words[sel1] as u128) << 80)
                    | ((src_words[sel2] as u128) << 96)
                    | ((src_words[sel3] as u128) << 112);

                // Preserve low 64 bits
                let low_64 = src_value & 0xFFFFFFFF_FFFFFFFFu128;

                // Combine low and high parts
                let result = low_64 | high_result;

                self.engine.cpu.write_xmm(dst_reg, result);
                Ok(())
            }
            (OpKind::Register, OpKind::Memory, OpKind::Immediate8) => {
                let dst_reg = self.convert_register(inst.op_register(0))?;
                let imm8 = inst.immediate8();

                if !dst_reg.is_xmm() {
                    return Err(EmulatorError::UnsupportedInstruction(
                        "PSHUFHW requires XMM register as destination".to_string(),
                    ));
                }

                let addr = self.calculate_memory_address(inst, 1)?;
                let src_value = self.read_memory_128(addr)?;

                // Extract 4 words (16 bits each) from high 64 bits of source
                // These are words 4-7 of the 128-bit value
                let src_words = [
                    ((src_value >> 64) & 0xFFFF) as u16,  // word[4]
                    ((src_value >> 80) & 0xFFFF) as u16,  // word[5]
                    ((src_value >> 96) & 0xFFFF) as u16,  // word[6]
                    ((src_value >> 112) & 0xFFFF) as u16, // word[7]
                ];

                // Extract 2-bit selectors from immediate
                let sel0 = (imm8 & 0x03) as usize; // bits [1:0] -> word[4]
                let sel1 = ((imm8 >> 2) & 0x03) as usize; // bits [3:2] -> word[5]
                let sel2 = ((imm8 >> 4) & 0x03) as usize; // bits [5:4] -> word[6]
                let sel3 = ((imm8 >> 6) & 0x03) as usize; // bits [7:6] -> word[7]

                // Build high 64 bits by selecting words based on immediate
                let high_result = ((src_words[sel0] as u128) << 64)
                    | ((src_words[sel1] as u128) << 80)
                    | ((src_words[sel2] as u128) << 96)
                    | ((src_words[sel3] as u128) << 112);

                // Preserve low 64 bits
                let low_64 = src_value & 0xFFFFFFFF_FFFFFFFFu128;

                // Combine low and high parts
                let result = low_64 | high_result;

                self.engine.cpu.write_xmm(dst_reg, result);
                Ok(())
            }
            _ => Err(EmulatorError::UnsupportedInstruction(format!(
                "Unsupported PSHUFHW operand types: {:?}, {:?}, {:?}",
                inst.op_kind(0),
                inst.op_kind(1),
                inst.op_kind(2)
            ))),
        }
    }

    pub(crate) fn execute_pextrw(&mut self, inst: &Instruction) -> Result<()> {
        // PEXTRW: Extract Word
        // Extracts a 16-bit word from an XMM register based on an immediate index
        // The word is zero-extended to 32 bits and stored in a general-purpose register

        if inst.op_count() != 3 {
            return Err(EmulatorError::UnsupportedInstruction(
                "PEXTRW requires exactly 3 operands".to_string(),
            ));
        }

        match (inst.op_kind(0), inst.op_kind(1), inst.op_kind(2)) {
            (OpKind::Register, OpKind::Register, OpKind::Immediate8) => {
                let dst_reg = self.convert_register(inst.op_register(0))?;
                let src_reg = self.convert_register(inst.op_register(1))?;
                let imm8 = inst.immediate8();

                // Check if source is XMM register and destination is general-purpose register
                if !src_reg.is_xmm() {
                    return Err(EmulatorError::UnsupportedInstruction(
                        "PEXTRW requires XMM register as source".to_string(),
                    ));
                }

                let src_value = self.engine.cpu.read_xmm(src_reg);

                // Extract word index (only low 3 bits are used for 8 words)
                let word_index = (imm8 & 0x07) as u32;

                // Extract the selected word (16 bits)
                let shift_amount = word_index * 16;
                let extracted_word = ((src_value >> shift_amount) & 0xFFFF) as u64;

                // Zero-extend to destination size and write to general-purpose register
                self.engine.cpu.write_reg(dst_reg, extracted_word);
                Ok(())
            }
            _ => Err(EmulatorError::UnsupportedInstruction(format!(
                "Unsupported PEXTRW operand types: {:?}, {:?}, {:?}",
                inst.op_kind(0),
                inst.op_kind(1),
                inst.op_kind(2)
            ))),
        }
    }

    pub(crate) fn execute_pinsrw(&mut self, inst: &Instruction) -> Result<()> {
        // PINSRW: Insert Word
        // Inserts a 16-bit word from a general-purpose register or memory into an XMM register
        // at a position specified by an immediate value

        if inst.op_count() != 3 {
            return Err(EmulatorError::UnsupportedInstruction(
                "PINSRW requires exactly 3 operands".to_string(),
            ));
        }

        match (inst.op_kind(0), inst.op_kind(1), inst.op_kind(2)) {
            (OpKind::Register, OpKind::Register, OpKind::Immediate8) => {
                let dst_reg = self.convert_register(inst.op_register(0))?;
                let src_reg = self.convert_register(inst.op_register(1))?;
                let imm8 = inst.immediate8();

                // Check if destination is XMM register
                if !dst_reg.is_xmm() {
                    return Err(EmulatorError::UnsupportedInstruction(
                        "PINSRW requires XMM register as destination".to_string(),
                    ));
                }

                // Read source value from general-purpose register
                let src_value = self.engine.cpu.read_reg(src_reg) & 0xFFFF; // Only low 16 bits

                // Read current XMM value
                let mut xmm_value = self.engine.cpu.read_xmm(dst_reg);

                // Extract word index (only low 3 bits are used for 8 words)
                let word_index = (imm8 & 0x07) as u32;

                // Create mask to clear the target word
                let shift_amount = word_index * 16;
                let mask = !(0xFFFFu128 << shift_amount);

                // Clear the target word and insert the new word
                xmm_value = (xmm_value & mask) | ((src_value as u128) << shift_amount);

                self.engine.cpu.write_xmm(dst_reg, xmm_value);
                Ok(())
            }
            (OpKind::Register, OpKind::Memory, OpKind::Immediate8) => {
                let dst_reg = self.convert_register(inst.op_register(0))?;
                let imm8 = inst.immediate8();

                // Check if destination is XMM register
                if !dst_reg.is_xmm() {
                    return Err(EmulatorError::UnsupportedInstruction(
                        "PINSRW requires XMM register as destination".to_string(),
                    ));
                }

                // Read 16-bit value from memory
                let addr = self.calculate_memory_address(inst, 1)?;
                let src_value = self.engine.memory.read_u16(addr)? as u128;

                // Read current XMM value
                let mut xmm_value = self.engine.cpu.read_xmm(dst_reg);

                // Extract word index (only low 3 bits are used for 8 words)
                let word_index = (imm8 & 0x07) as u32;

                // Create mask to clear the target word
                let shift_amount = word_index * 16;
                let mask = !(0xFFFFu128 << shift_amount);

                // Clear the target word and insert the new word
                xmm_value = (xmm_value & mask) | (src_value << shift_amount);

                self.engine.cpu.write_xmm(dst_reg, xmm_value);
                Ok(())
            }
            _ => Err(EmulatorError::UnsupportedInstruction(format!(
                "Unsupported PINSRW operand types: {:?}, {:?}, {:?}",
                inst.op_kind(0),
                inst.op_kind(1),
                inst.op_kind(2)
            ))),
        }
    }

    pub(crate) fn execute_punpcklbw(&mut self, inst: &Instruction) -> Result<()> {
        // PUNPCKLBW: Unpack and interleave low-order bytes
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
                    "Invalid PUNPCKLBW source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let mut result = 0u128;

        // Interleave the low 8 bytes from dst and src
        for i in 0..8 {
            let dst_byte = ((dst_value >> (i * 8)) & 0xFF) as u8;
            let src_byte = ((src_value >> (i * 8)) & 0xFF) as u8;

            // Place dst byte in even position, src byte in odd position
            result |= (dst_byte as u128) << (i * 16);
            result |= (src_byte as u128) << (i * 16 + 8);
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_punpckhbw(&mut self, inst: &Instruction) -> Result<()> {
        // PUNPCKHBW: Unpack and interleave high-order bytes
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
                    "Invalid PUNPCKHBW source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let mut result = 0u128;

        // Interleave the high 8 bytes from dst and src
        for i in 0..8 {
            let dst_byte = ((dst_value >> ((i + 8) * 8)) & 0xFF) as u8;
            let src_byte = ((src_value >> ((i + 8) * 8)) & 0xFF) as u8;

            // Place dst byte in even position, src byte in odd position
            result |= (dst_byte as u128) << (i * 16);
            result |= (src_byte as u128) << (i * 16 + 8);
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_punpckhwd(&mut self, inst: &Instruction) -> Result<()> {
        // PUNPCKHWD: Unpack and interleave high-order words
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
                    "Invalid PUNPCKHWD source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let mut result = 0u128;

        // Interleave the high 4 words from dst and src
        for i in 0..4 {
            let dst_word = ((dst_value >> ((i + 4) * 16)) & 0xFFFF) as u16;
            let src_word = ((src_value >> ((i + 4) * 16)) & 0xFFFF) as u16;

            // Place dst word in even position, src word in odd position
            result |= (dst_word as u128) << (i * 32);
            result |= (src_word as u128) << (i * 32 + 16);
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_punpckldq(&mut self, inst: &Instruction) -> Result<()> {
        // PUNPCKLDQ: Unpack and interleave low-order doublewords
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
                    "Invalid PUNPCKLDQ source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let mut result = 0u128;

        // Interleave the low 2 doublewords from dst and src
        let dst_dw0 = (dst_value & 0xFFFFFFFF) as u32;
        let dst_dw1 = ((dst_value >> 32) & 0xFFFFFFFF) as u32;
        let src_dw0 = (src_value & 0xFFFFFFFF) as u32;
        let src_dw1 = ((src_value >> 32) & 0xFFFFFFFF) as u32;

        result |= dst_dw0 as u128;
        result |= (src_dw0 as u128) << 32;
        result |= (dst_dw1 as u128) << 64;
        result |= (src_dw1 as u128) << 96;

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_punpckhdq(&mut self, inst: &Instruction) -> Result<()> {
        // PUNPCKHDQ: Unpack and interleave high-order doublewords
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
                    "Invalid PUNPCKHDQ source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let mut result = 0u128;

        // Interleave the high 2 doublewords from dst and src
        let dst_dw2 = ((dst_value >> 64) & 0xFFFFFFFF) as u32;
        let dst_dw3 = ((dst_value >> 96) & 0xFFFFFFFF) as u32;
        let src_dw2 = ((src_value >> 64) & 0xFFFFFFFF) as u32;
        let src_dw3 = ((src_value >> 96) & 0xFFFFFFFF) as u32;

        result |= dst_dw2 as u128;
        result |= (src_dw2 as u128) << 32;
        result |= (dst_dw3 as u128) << 64;
        result |= (src_dw3 as u128) << 96;

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_punpcklqdq(&mut self, inst: &Instruction) -> Result<()> {
        // PUNPCKLQDQ: Unpack and interleave low-order quadwords
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
                    "Invalid PUNPCKLQDQ source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);

        // Result contains low quadword from dst and low quadword from src
        let result = (dst_value & 0xFFFFFFFFFFFFFFFF) | ((src_value & 0xFFFFFFFFFFFFFFFF) << 64);

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_punpckhqdq(&mut self, inst: &Instruction) -> Result<()> {
        // PUNPCKHQDQ: Unpack and interleave high-order quadwords
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
                    "Invalid PUNPCKHQDQ source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);

        // Result contains high quadword from dst and high quadword from src
        let result = (dst_value >> 64) | ((src_value >> 64) << 64);

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }
}
