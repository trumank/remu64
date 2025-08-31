use crate::HookManager;
use crate::engine::ExecutionContext;
use crate::error::{EmulatorError, Result};
use crate::memory::MemoryTrait;
use iced_x86::{Instruction, OpKind};

impl<H: HookManager<M, PS>, M: MemoryTrait<PS>, const PS: u64> ExecutionContext<'_, H, M, PS> {
    pub(crate) fn execute_pmovmskb(&mut self, inst: &Instruction) -> Result<()> {
        // PMOVMSKB: Move Byte Mask
        // Creates a 16-bit mask from the most significant bits of each byte in an XMM register
        // Each bit in the result corresponds to the sign bit of each byte

        if inst.op_count() != 2 {
            return Err(EmulatorError::UnsupportedInstruction(
                "PMOVMSKB requires exactly 2 operands".to_string(),
            ));
        }

        match (inst.op_kind(0), inst.op_kind(1)) {
            (OpKind::Register, OpKind::Register) => {
                let dst_reg = self.convert_register(inst.op_register(0))?;
                let src_reg = self.convert_register(inst.op_register(1))?;

                // Check if source is XMM register
                if !src_reg.is_xmm() {
                    return Err(EmulatorError::UnsupportedInstruction(
                        "PMOVMSKB requires XMM register as source".to_string(),
                    ));
                }

                let src_value = self.engine.cpu.read_xmm(src_reg);

                // Extract sign bit from each of 16 bytes
                let mut mask = 0u64;
                for i in 0..16 {
                    let byte_shift = i * 8 + 7; // Position of sign bit for byte i
                    let sign_bit = ((src_value >> byte_shift) & 1) as u64;
                    mask |= sign_bit << i;
                }

                // Zero-extend and write to general-purpose register
                self.engine.cpu.write_reg(dst_reg, mask);
                Ok(())
            }
            _ => Err(EmulatorError::UnsupportedInstruction(format!(
                "Unsupported PMOVMSKB operand types: {:?}, {:?}",
                inst.op_kind(0),
                inst.op_kind(1)
            ))),
        }
    }

    pub(crate) fn execute_pavgb(&mut self, inst: &Instruction) -> Result<()> {
        // PAVGB: Packed Average Unsigned Bytes
        // Computes the average of unsigned bytes with rounding: (a + b + 1) >> 1

        match (inst.op_kind(0), inst.op_kind(1)) {
            (OpKind::Register, OpKind::Register) => {
                let dst_reg = self.convert_register(inst.op_register(0))?;
                let src_reg = self.convert_register(inst.op_register(1))?;

                if !dst_reg.is_xmm() || !src_reg.is_xmm() {
                    return Err(EmulatorError::UnsupportedInstruction(
                        "PAVGB requires XMM registers".to_string(),
                    ));
                }

                let dst_value = self.engine.cpu.read_xmm(dst_reg);
                let src_value = self.engine.cpu.read_xmm(src_reg);
                let mut result = 0u128;

                // Process 16 bytes
                for i in 0..16 {
                    let shift = i * 8;
                    let dst_byte = ((dst_value >> shift) & 0xFF) as u16;
                    let src_byte = ((src_value >> shift) & 0xFF) as u16;
                    // Average with rounding: (a + b + 1) >> 1
                    let avg = ((dst_byte + src_byte + 1) >> 1) as u128;
                    result |= avg << shift;
                }

                self.engine.cpu.write_xmm(dst_reg, result);
                Ok(())
            }
            (OpKind::Register, OpKind::Memory) => {
                let dst_reg = self.convert_register(inst.op_register(0))?;

                if !dst_reg.is_xmm() {
                    return Err(EmulatorError::UnsupportedInstruction(
                        "PAVGB requires XMM register as destination".to_string(),
                    ));
                }

                let addr = self.calculate_memory_address(inst, 1)?;
                let src_value = self.read_memory_128(addr)?;
                let dst_value = self.engine.cpu.read_xmm(dst_reg);
                let mut result = 0u128;

                // Process 16 bytes
                for i in 0..16 {
                    let shift = i * 8;
                    let dst_byte = ((dst_value >> shift) & 0xFF) as u16;
                    let src_byte = ((src_value >> shift) & 0xFF) as u16;
                    // Average with rounding: (a + b + 1) >> 1
                    let avg = ((dst_byte + src_byte + 1) >> 1) as u128;
                    result |= avg << shift;
                }

                self.engine.cpu.write_xmm(dst_reg, result);
                Ok(())
            }
            _ => Err(EmulatorError::UnsupportedInstruction(format!(
                "Unsupported PAVGB operand types: {:?}, {:?}",
                inst.op_kind(0),
                inst.op_kind(1)
            ))),
        }
    }

    pub(crate) fn execute_pavgw(&mut self, inst: &Instruction) -> Result<()> {
        // PAVGW: Packed Average Unsigned Words
        // Computes the average of unsigned words with rounding: (a + b + 1) >> 1

        match (inst.op_kind(0), inst.op_kind(1)) {
            (OpKind::Register, OpKind::Register) => {
                let dst_reg = self.convert_register(inst.op_register(0))?;
                let src_reg = self.convert_register(inst.op_register(1))?;

                if !dst_reg.is_xmm() || !src_reg.is_xmm() {
                    return Err(EmulatorError::UnsupportedInstruction(
                        "PAVGW requires XMM registers".to_string(),
                    ));
                }

                let dst_value = self.engine.cpu.read_xmm(dst_reg);
                let src_value = self.engine.cpu.read_xmm(src_reg);
                let mut result = 0u128;

                // Process 8 words
                for i in 0..8 {
                    let shift = i * 16;
                    let dst_word = ((dst_value >> shift) & 0xFFFF) as u32;
                    let src_word = ((src_value >> shift) & 0xFFFF) as u32;
                    // Average with rounding: (a + b + 1) >> 1
                    let avg = ((dst_word + src_word + 1) >> 1) as u128;
                    result |= avg << shift;
                }

                self.engine.cpu.write_xmm(dst_reg, result);
                Ok(())
            }
            (OpKind::Register, OpKind::Memory) => {
                let dst_reg = self.convert_register(inst.op_register(0))?;

                if !dst_reg.is_xmm() {
                    return Err(EmulatorError::UnsupportedInstruction(
                        "PAVGW requires XMM register as destination".to_string(),
                    ));
                }

                let addr = self.calculate_memory_address(inst, 1)?;
                let src_value = self.read_memory_128(addr)?;
                let dst_value = self.engine.cpu.read_xmm(dst_reg);
                let mut result = 0u128;

                // Process 8 words
                for i in 0..8 {
                    let shift = i * 16;
                    let dst_word = ((dst_value >> shift) & 0xFFFF) as u32;
                    let src_word = ((src_value >> shift) & 0xFFFF) as u32;
                    // Average with rounding: (a + b + 1) >> 1
                    let avg = ((dst_word + src_word + 1) >> 1) as u128;
                    result |= avg << shift;
                }

                self.engine.cpu.write_xmm(dst_reg, result);
                Ok(())
            }
            _ => Err(EmulatorError::UnsupportedInstruction(format!(
                "Unsupported PAVGW operand types: {:?}, {:?}",
                inst.op_kind(0),
                inst.op_kind(1)
            ))),
        }
    }

    pub(crate) fn execute_pmaxub(&mut self, inst: &Instruction) -> Result<()> {
        // PMAXUB: Packed Maximum Unsigned Bytes
        // Compares unsigned bytes and stores the maximum values

        match (inst.op_kind(0), inst.op_kind(1)) {
            (OpKind::Register, OpKind::Register) => {
                let dst_reg = self.convert_register(inst.op_register(0))?;
                let src_reg = self.convert_register(inst.op_register(1))?;

                if !dst_reg.is_xmm() || !src_reg.is_xmm() {
                    return Err(EmulatorError::UnsupportedInstruction(
                        "PMAXUB requires XMM registers".to_string(),
                    ));
                }

                let dst_value = self.engine.cpu.read_xmm(dst_reg);
                let src_value = self.engine.cpu.read_xmm(src_reg);
                let mut result = 0u128;

                // Process 16 bytes
                for i in 0..16 {
                    let shift = i * 8;
                    let dst_byte = ((dst_value >> shift) & 0xFF) as u8;
                    let src_byte = ((src_value >> shift) & 0xFF) as u8;
                    let max = std::cmp::max(dst_byte, src_byte) as u128;
                    result |= max << shift;
                }

                self.engine.cpu.write_xmm(dst_reg, result);
                Ok(())
            }
            (OpKind::Register, OpKind::Memory) => {
                let dst_reg = self.convert_register(inst.op_register(0))?;

                if !dst_reg.is_xmm() {
                    return Err(EmulatorError::UnsupportedInstruction(
                        "PMAXUB requires XMM register as destination".to_string(),
                    ));
                }

                let addr = self.calculate_memory_address(inst, 1)?;
                let src_value = self.read_memory_128(addr)?;
                let dst_value = self.engine.cpu.read_xmm(dst_reg);
                let mut result = 0u128;

                // Process 16 bytes
                for i in 0..16 {
                    let shift = i * 8;
                    let dst_byte = ((dst_value >> shift) & 0xFF) as u8;
                    let src_byte = ((src_value >> shift) & 0xFF) as u8;
                    let max = std::cmp::max(dst_byte, src_byte) as u128;
                    result |= max << shift;
                }

                self.engine.cpu.write_xmm(dst_reg, result);
                Ok(())
            }
            _ => Err(EmulatorError::UnsupportedInstruction(format!(
                "Unsupported PMAXUB operand types: {:?}, {:?}",
                inst.op_kind(0),
                inst.op_kind(1)
            ))),
        }
    }

    pub(crate) fn execute_pmaxsw(&mut self, inst: &Instruction) -> Result<()> {
        // PMAXSW: Packed Maximum Signed Words
        // Compares signed words and stores the maximum values

        match (inst.op_kind(0), inst.op_kind(1)) {
            (OpKind::Register, OpKind::Register) => {
                let dst_reg = self.convert_register(inst.op_register(0))?;
                let src_reg = self.convert_register(inst.op_register(1))?;

                if !dst_reg.is_xmm() || !src_reg.is_xmm() {
                    return Err(EmulatorError::UnsupportedInstruction(
                        "PMAXSW requires XMM registers".to_string(),
                    ));
                }

                let dst_value = self.engine.cpu.read_xmm(dst_reg);
                let src_value = self.engine.cpu.read_xmm(src_reg);
                let mut result = 0u128;

                // Process 8 words
                for i in 0..8 {
                    let shift = i * 16;
                    let dst_word = ((dst_value >> shift) & 0xFFFF) as i16;
                    let src_word = ((src_value >> shift) & 0xFFFF) as i16;
                    let max = std::cmp::max(dst_word, src_word) as u16 as u128;
                    result |= max << shift;
                }

                self.engine.cpu.write_xmm(dst_reg, result);
                Ok(())
            }
            (OpKind::Register, OpKind::Memory) => {
                let dst_reg = self.convert_register(inst.op_register(0))?;

                if !dst_reg.is_xmm() {
                    return Err(EmulatorError::UnsupportedInstruction(
                        "PMAXSW requires XMM register as destination".to_string(),
                    ));
                }

                let addr = self.calculate_memory_address(inst, 1)?;
                let src_value = self.read_memory_128(addr)?;
                let dst_value = self.engine.cpu.read_xmm(dst_reg);
                let mut result = 0u128;

                // Process 8 words
                for i in 0..8 {
                    let shift = i * 16;
                    let dst_word = ((dst_value >> shift) & 0xFFFF) as i16;
                    let src_word = ((src_value >> shift) & 0xFFFF) as i16;
                    let max = std::cmp::max(dst_word, src_word) as u16 as u128;
                    result |= max << shift;
                }

                self.engine.cpu.write_xmm(dst_reg, result);
                Ok(())
            }
            _ => Err(EmulatorError::UnsupportedInstruction(format!(
                "Unsupported PMAXSW operand types: {:?}, {:?}",
                inst.op_kind(0),
                inst.op_kind(1)
            ))),
        }
    }

    pub(crate) fn execute_pminub(&mut self, inst: &Instruction) -> Result<()> {
        // PMINUB: Packed Minimum Unsigned Bytes
        // Compares unsigned bytes and stores the minimum values

        match (inst.op_kind(0), inst.op_kind(1)) {
            (OpKind::Register, OpKind::Register) => {
                let dst_reg = self.convert_register(inst.op_register(0))?;
                let src_reg = self.convert_register(inst.op_register(1))?;

                if !dst_reg.is_xmm() || !src_reg.is_xmm() {
                    return Err(EmulatorError::UnsupportedInstruction(
                        "PMINUB requires XMM registers".to_string(),
                    ));
                }

                let dst_value = self.engine.cpu.read_xmm(dst_reg);
                let src_value = self.engine.cpu.read_xmm(src_reg);
                let mut result = 0u128;

                // Process 16 bytes
                for i in 0..16 {
                    let shift = i * 8;
                    let dst_byte = ((dst_value >> shift) & 0xFF) as u8;
                    let src_byte = ((src_value >> shift) & 0xFF) as u8;
                    let min = std::cmp::min(dst_byte, src_byte) as u128;
                    result |= min << shift;
                }

                self.engine.cpu.write_xmm(dst_reg, result);
                Ok(())
            }
            (OpKind::Register, OpKind::Memory) => {
                let dst_reg = self.convert_register(inst.op_register(0))?;

                if !dst_reg.is_xmm() {
                    return Err(EmulatorError::UnsupportedInstruction(
                        "PMINUB requires XMM register as destination".to_string(),
                    ));
                }

                let addr = self.calculate_memory_address(inst, 1)?;
                let src_value = self.read_memory_128(addr)?;
                let dst_value = self.engine.cpu.read_xmm(dst_reg);
                let mut result = 0u128;

                // Process 16 bytes
                for i in 0..16 {
                    let shift = i * 8;
                    let dst_byte = ((dst_value >> shift) & 0xFF) as u8;
                    let src_byte = ((src_value >> shift) & 0xFF) as u8;
                    let min = std::cmp::min(dst_byte, src_byte) as u128;
                    result |= min << shift;
                }

                self.engine.cpu.write_xmm(dst_reg, result);
                Ok(())
            }
            _ => Err(EmulatorError::UnsupportedInstruction(format!(
                "Unsupported PMINUB operand types: {:?}, {:?}",
                inst.op_kind(0),
                inst.op_kind(1)
            ))),
        }
    }

    pub(crate) fn execute_pminsw(&mut self, inst: &Instruction) -> Result<()> {
        // PMINSW: Packed Minimum Signed Words
        // Compares signed words and stores the minimum values

        match (inst.op_kind(0), inst.op_kind(1)) {
            (OpKind::Register, OpKind::Register) => {
                let dst_reg = self.convert_register(inst.op_register(0))?;
                let src_reg = self.convert_register(inst.op_register(1))?;

                if !dst_reg.is_xmm() || !src_reg.is_xmm() {
                    return Err(EmulatorError::UnsupportedInstruction(
                        "PMINSW requires XMM registers".to_string(),
                    ));
                }

                let dst_value = self.engine.cpu.read_xmm(dst_reg);
                let src_value = self.engine.cpu.read_xmm(src_reg);
                let mut result = 0u128;

                // Process 8 words
                for i in 0..8 {
                    let shift = i * 16;
                    let dst_word = ((dst_value >> shift) & 0xFFFF) as i16;
                    let src_word = ((src_value >> shift) & 0xFFFF) as i16;
                    let min = std::cmp::min(dst_word, src_word) as u16 as u128;
                    result |= min << shift;
                }

                self.engine.cpu.write_xmm(dst_reg, result);
                Ok(())
            }
            (OpKind::Register, OpKind::Memory) => {
                let dst_reg = self.convert_register(inst.op_register(0))?;

                if !dst_reg.is_xmm() {
                    return Err(EmulatorError::UnsupportedInstruction(
                        "PMINSW requires XMM register as destination".to_string(),
                    ));
                }

                let addr = self.calculate_memory_address(inst, 1)?;
                let src_value = self.read_memory_128(addr)?;
                let dst_value = self.engine.cpu.read_xmm(dst_reg);
                let mut result = 0u128;

                // Process 8 words
                for i in 0..8 {
                    let shift = i * 16;
                    let dst_word = ((dst_value >> shift) & 0xFFFF) as i16;
                    let src_word = ((src_value >> shift) & 0xFFFF) as i16;
                    let min = std::cmp::min(dst_word, src_word) as u16 as u128;
                    result |= min << shift;
                }

                self.engine.cpu.write_xmm(dst_reg, result);
                Ok(())
            }
            _ => Err(EmulatorError::UnsupportedInstruction(format!(
                "Unsupported PMINSW operand types: {:?}, {:?}",
                inst.op_kind(0),
                inst.op_kind(1)
            ))),
        }
    }

    pub(crate) fn execute_psadbw(&mut self, inst: &Instruction) -> Result<()> {
        // PSADBW: Packed Sum of Absolute Differences
        // Computes absolute differences between unsigned bytes, then sums them
        // Result is two 16-bit sums stored in bits [15:0] and [79:64] of destination

        match (inst.op_kind(0), inst.op_kind(1)) {
            (OpKind::Register, OpKind::Register) => {
                let dst_reg = self.convert_register(inst.op_register(0))?;
                let src_reg = self.convert_register(inst.op_register(1))?;

                if !dst_reg.is_xmm() || !src_reg.is_xmm() {
                    return Err(EmulatorError::UnsupportedInstruction(
                        "PSADBW requires XMM registers".to_string(),
                    ));
                }

                let dst_value = self.engine.cpu.read_xmm(dst_reg);
                let src_value = self.engine.cpu.read_xmm(src_reg);

                // Compute sum of absolute differences for low 8 bytes
                let mut sum_low = 0u16;
                for i in 0..8 {
                    let shift = i * 8;
                    let dst_byte = ((dst_value >> shift) & 0xFF) as u8;
                    let src_byte = ((src_value >> shift) & 0xFF) as u8;
                    sum_low += dst_byte.abs_diff(src_byte) as u16;
                }

                // Compute sum of absolute differences for high 8 bytes
                let mut sum_high = 0u16;
                for i in 8..16 {
                    let shift = i * 8;
                    let dst_byte = ((dst_value >> shift) & 0xFF) as u8;
                    let src_byte = ((src_value >> shift) & 0xFF) as u8;
                    sum_high += dst_byte.abs_diff(src_byte) as u16;
                }

                // Store results: low sum in bits [15:0], high sum in bits [79:64]
                // All other bits are zeroed
                let result = (sum_low as u128) | ((sum_high as u128) << 64);

                self.engine.cpu.write_xmm(dst_reg, result);
                Ok(())
            }
            (OpKind::Register, OpKind::Memory) => {
                let dst_reg = self.convert_register(inst.op_register(0))?;

                if !dst_reg.is_xmm() {
                    return Err(EmulatorError::UnsupportedInstruction(
                        "PSADBW requires XMM register as destination".to_string(),
                    ));
                }

                let addr = self.calculate_memory_address(inst, 1)?;
                let src_value = self.read_memory_128(addr)?;
                let dst_value = self.engine.cpu.read_xmm(dst_reg);

                // Compute sum of absolute differences for low 8 bytes
                let mut sum_low = 0u16;
                for i in 0..8 {
                    let shift = i * 8;
                    let dst_byte = ((dst_value >> shift) & 0xFF) as u8;
                    let src_byte = ((src_value >> shift) & 0xFF) as u8;
                    sum_low += dst_byte.abs_diff(src_byte) as u16;
                }

                // Compute sum of absolute differences for high 8 bytes
                let mut sum_high = 0u16;
                for i in 8..16 {
                    let shift = i * 8;
                    let dst_byte = ((dst_value >> shift) & 0xFF) as u8;
                    let src_byte = ((src_value >> shift) & 0xFF) as u8;
                    sum_high += dst_byte.abs_diff(src_byte) as u16;
                }

                // Store results: low sum in bits [15:0], high sum in bits [79:64]
                // All other bits are zeroed
                let result = (sum_low as u128) | ((sum_high as u128) << 64);

                self.engine.cpu.write_xmm(dst_reg, result);
                Ok(())
            }
            _ => Err(EmulatorError::UnsupportedInstruction(format!(
                "Unsupported PSADBW operand types: {:?}, {:?}",
                inst.op_kind(0),
                inst.op_kind(1)
            ))),
        }
    }

    pub(crate) fn execute_psllw(&mut self, inst: &Instruction) -> Result<()> {
        // PSLLW: Packed shift left logical words
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let shift_amount = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                let xmm_value = self.engine.cpu.read_xmm(src_reg);
                (xmm_value & 0xFFFF) as u8
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                let value = self.read_memory_128(addr)?;
                (value & 0xFFFF) as u8
            }
            OpKind::Immediate8 => inst.immediate8(),
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid PSLLW source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let mut result = 0u128;

        if shift_amount < 16 {
            // Shift each 16-bit word left
            for i in 0..8 {
                let word = ((dst_value >> (i * 16)) & 0xFFFF) as u16;
                let shifted = word << shift_amount;
                result |= (shifted as u128) << (i * 16);
            }
        }
        // If shift_amount >= 16, all bits are shifted out, result is 0

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_pslld(&mut self, inst: &Instruction) -> Result<()> {
        // PSLLD: Packed shift left logical doublewords
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let shift_amount = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                let xmm_value = self.engine.cpu.read_xmm(src_reg);
                (xmm_value & 0xFFFF) as u8
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                let value = self.read_memory_128(addr)?;
                (value & 0xFFFF) as u8
            }
            OpKind::Immediate8 => inst.immediate8(),
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid PSLLD source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let mut result = 0u128;

        if shift_amount < 32 {
            // Shift each 32-bit doubleword left
            for i in 0..4 {
                let dword = ((dst_value >> (i * 32)) & 0xFFFFFFFF) as u32;
                let shifted = dword << shift_amount;
                result |= (shifted as u128) << (i * 32);
            }
        }
        // If shift_amount >= 32, all bits are shifted out, result is 0

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_psllq(&mut self, inst: &Instruction) -> Result<()> {
        // PSLLQ: Packed shift left logical quadwords
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let shift_amount = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                let xmm_value = self.engine.cpu.read_xmm(src_reg);
                (xmm_value & 0xFFFF) as u8
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                let value = self.read_memory_128(addr)?;
                (value & 0xFFFF) as u8
            }
            OpKind::Immediate8 => inst.immediate8(),
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid PSLLQ source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let mut result = 0u128;

        if shift_amount < 64 {
            // Shift each 64-bit quadword left
            let low_qword = (dst_value & 0xFFFFFFFFFFFFFFFF) as u64;
            let high_qword = ((dst_value >> 64) & 0xFFFFFFFFFFFFFFFF) as u64;

            result |= ((low_qword << shift_amount) as u128) & 0xFFFFFFFFFFFFFFFF;
            result |= ((high_qword << shift_amount) as u128) << 64;
        }
        // If shift_amount >= 64, all bits are shifted out, result is 0

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_psrlw(&mut self, inst: &Instruction) -> Result<()> {
        // PSRLW: Packed shift right logical words
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let shift_amount = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                let xmm_value = self.engine.cpu.read_xmm(src_reg);
                (xmm_value & 0xFFFF) as u8
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                let value = self.read_memory_128(addr)?;
                (value & 0xFFFF) as u8
            }
            OpKind::Immediate8 => inst.immediate8(),
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid PSRLW source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let mut result = 0u128;

        if shift_amount < 16 {
            // Shift each 16-bit word right
            for i in 0..8 {
                let word = ((dst_value >> (i * 16)) & 0xFFFF) as u16;
                let shifted = word >> shift_amount;
                result |= (shifted as u128) << (i * 16);
            }
        }
        // If shift_amount >= 16, all bits are shifted out, result is 0

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_psrld(&mut self, inst: &Instruction) -> Result<()> {
        // PSRLD: Packed shift right logical doublewords
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let shift_amount = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                let xmm_value = self.engine.cpu.read_xmm(src_reg);
                (xmm_value & 0xFFFF) as u8
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                let value = self.read_memory_128(addr)?;
                (value & 0xFFFF) as u8
            }
            OpKind::Immediate8 => inst.immediate8(),
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid PSRLD source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let mut result = 0u128;

        if shift_amount < 32 {
            // Shift each 32-bit doubleword right
            for i in 0..4 {
                let dword = ((dst_value >> (i * 32)) & 0xFFFFFFFF) as u32;
                let shifted = dword >> shift_amount;
                result |= (shifted as u128) << (i * 32);
            }
        }
        // If shift_amount >= 32, all bits are shifted out, result is 0

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_psrlq(&mut self, inst: &Instruction) -> Result<()> {
        // PSRLQ: Packed shift right logical quadwords
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let shift_amount = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                let xmm_value = self.engine.cpu.read_xmm(src_reg);
                (xmm_value & 0xFFFF) as u8
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                let value = self.read_memory_128(addr)?;
                (value & 0xFFFF) as u8
            }
            OpKind::Immediate8 => inst.immediate8(),
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid PSRLQ source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let mut result = 0u128;

        if shift_amount < 64 {
            // Shift each 64-bit quadword right
            let low_qword = (dst_value & 0xFFFFFFFFFFFFFFFF) as u64;
            let high_qword = ((dst_value >> 64) & 0xFFFFFFFFFFFFFFFF) as u64;

            result |= (low_qword >> shift_amount) as u128;
            result |= ((high_qword >> shift_amount) as u128) << 64;
        }
        // If shift_amount >= 64, all bits are shifted out, result is 0

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_psraw(&mut self, inst: &Instruction) -> Result<()> {
        // PSRAW: Packed shift right arithmetic words
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let shift_amount = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                let xmm_value = self.engine.cpu.read_xmm(src_reg);
                (xmm_value & 0xFFFF) as u8
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                let value = self.read_memory_128(addr)?;
                (value & 0xFFFF) as u8
            }
            OpKind::Immediate8 => inst.immediate8(),
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid PSRAW source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let mut result = 0u128;

        // Arithmetic shift preserves sign bit
        let shift = if shift_amount > 15 { 15 } else { shift_amount };

        for i in 0..8 {
            let word = ((dst_value >> (i * 16)) & 0xFFFF) as u16 as i16;
            let shifted = (word >> shift) as u16;
            result |= (shifted as u128) << (i * 16);
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_psrad(&mut self, inst: &Instruction) -> Result<()> {
        // PSRAD: Packed shift right arithmetic doublewords
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let shift_amount = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                let xmm_value = self.engine.cpu.read_xmm(src_reg);
                (xmm_value & 0xFFFF) as u8
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                let value = self.read_memory_128(addr)?;
                (value & 0xFFFF) as u8
            }
            OpKind::Immediate8 => inst.immediate8(),
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid PSRAD source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let mut result = 0u128;

        // Arithmetic shift preserves sign bit
        let shift = if shift_amount > 31 { 31 } else { shift_amount };

        for i in 0..4 {
            let dword = ((dst_value >> (i * 32)) & 0xFFFFFFFF) as u32 as i32;
            let shifted = (dword >> shift) as u32;
            result |= (shifted as u128) << (i * 32);
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_psrldq(&mut self, inst: &Instruction) -> Result<()> {
        // PSRLDQ: Packed shift right logical double quadword
        // Shifts the entire 128-bit register right by the specified number of bytes,
        // filling the shifted-in bytes with zeros

        if inst.op_count() != 2 {
            return Err(EmulatorError::UnsupportedInstruction(
                "PSRLDQ requires exactly 2 operands".to_string(),
            ));
        }

        let dst_reg = self.convert_register(inst.op_register(0))?;

        if !dst_reg.is_xmm() {
            return Err(EmulatorError::UnsupportedInstruction(
                "PSRLDQ requires XMM register as destination".to_string(),
            ));
        }

        let shift_bytes = match inst.op_kind(1) {
            OpKind::Immediate8 => inst.immediate8(),
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "PSRLDQ requires immediate byte operand".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let result = if shift_bytes >= 16 {
            // If shifting by 16 or more bytes, result is zero
            0u128
        } else {
            // Shift right by the specified number of bytes (8 bits per byte)
            dst_value >> (shift_bytes as u32 * 8)
        };

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_vpmovmskb(&mut self, inst: &Instruction) -> Result<()> {
        // VPMOVMSKB: Move Byte Mask (AVX)
        // Creates a mask from the most significant bits of each byte in a YMM/XMM register
        // VEX.256: VPMOVMSKB reg32, ymm2 (creates 32-bit mask from 32 bytes)
        // VEX.128: VPMOVMSKB reg32, xmm2 (creates 16-bit mask from 16 bytes)

        if inst.op_count() != 2 {
            return Err(EmulatorError::UnsupportedInstruction(
                "VPMOVMSKB requires exactly 2 operands".to_string(),
            ));
        }

        match (inst.op_kind(0), inst.op_kind(1)) {
            (OpKind::Register, OpKind::Register) => {
                let dst_reg = self.convert_register(inst.op_register(0))?;
                let src_reg = self.convert_register(inst.op_register(1))?;

                let is_256bit = src_reg.is_ymm();

                if is_256bit {
                    // 256-bit YMM operation - creates 32-bit mask from 32 bytes
                    let src_value = self.engine.cpu.read_ymm(src_reg);

                    let mut mask = 0u64;

                    // Extract sign bit from each of 16 bytes in low 128-bit half
                    for i in 0..16 {
                        let byte_shift = i * 8 + 7; // Position of sign bit for byte i
                        let sign_bit = ((src_value[0] >> byte_shift) & 1) as u64;
                        mask |= sign_bit << i;
                    }

                    // Extract sign bit from each of 16 bytes in high 128-bit half
                    for i in 0..16 {
                        let byte_shift = i * 8 + 7; // Position of sign bit for byte i
                        let sign_bit = ((src_value[1] >> byte_shift) & 1) as u64;
                        mask |= sign_bit << (i + 16);
                    }

                    // Zero-extend and write to general-purpose register
                    self.engine.cpu.write_reg(dst_reg, mask);
                } else {
                    // 128-bit XMM operation - creates 16-bit mask from 16 bytes
                    if !src_reg.is_xmm() {
                        return Err(EmulatorError::UnsupportedInstruction(
                            "VPMOVMSKB requires XMM/YMM register as source".to_string(),
                        ));
                    }

                    let src_value = self.engine.cpu.read_xmm(src_reg);

                    // Extract sign bit from each of 16 bytes
                    let mut mask = 0u64;
                    for i in 0..16 {
                        let byte_shift = i * 8 + 7; // Position of sign bit for byte i
                        let sign_bit = ((src_value >> byte_shift) & 1) as u64;
                        mask |= sign_bit << i;
                    }

                    // Zero-extend and write to general-purpose register
                    self.engine.cpu.write_reg(dst_reg, mask);
                }

                Ok(())
            }
            _ => Err(EmulatorError::UnsupportedInstruction(format!(
                "Unsupported VPMOVMSKB operand types: {:?}, {:?}",
                inst.op_kind(0),
                inst.op_kind(1)
            ))),
        }
    }
}
