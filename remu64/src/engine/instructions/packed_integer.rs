use crate::HookManager;
use crate::engine::ExecutionContext;
use crate::error::{EmulatorError, Result};
use crate::memory::MemoryTrait;
use iced_x86::{Instruction, OpKind};

impl<H: HookManager<M, PS>, M: MemoryTrait<PS>, const PS: u64> ExecutionContext<'_, H, M, PS> {
    pub(crate) fn execute_paddb(&mut self, inst: &Instruction) -> Result<()> {
        // PADDB: Add packed byte integers
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
                    "Invalid PADDB source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let mut result = 0u128;

        // Add 16 bytes
        for i in 0..16 {
            let dst_byte = ((dst_value >> (i * 8)) & 0xFF) as u8;
            let src_byte = ((src_value >> (i * 8)) & 0xFF) as u8;
            let sum = dst_byte.wrapping_add(src_byte);
            result |= (sum as u128) << (i * 8);
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_paddw(&mut self, inst: &Instruction) -> Result<()> {
        // PADDW: Add packed word integers
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
                    "Invalid PADDW source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let mut result = 0u128;

        // Add 8 words (16-bit values)
        for i in 0..8 {
            let dst_word = ((dst_value >> (i * 16)) & 0xFFFF) as u16;
            let src_word = ((src_value >> (i * 16)) & 0xFFFF) as u16;
            let sum = dst_word.wrapping_add(src_word);
            result |= (sum as u128) << (i * 16);
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_paddd(&mut self, inst: &Instruction) -> Result<()> {
        // PADDD: Add packed doubleword integers
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
                    "Invalid PADDD source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let mut result = 0u128;

        // Add 4 doublewords (32-bit values)
        for i in 0..4 {
            let dst_dword = ((dst_value >> (i * 32)) & 0xFFFFFFFF) as u32;
            let src_dword = ((src_value >> (i * 32)) & 0xFFFFFFFF) as u32;
            let sum = dst_dword.wrapping_add(src_dword);
            result |= (sum as u128) << (i * 32);
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_paddq(&mut self, inst: &Instruction) -> Result<()> {
        // PADDQ: Add packed quadword integers
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
                    "Invalid PADDQ source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);

        // Add 2 quadwords (64-bit values)
        let dst_low = dst_value as u64;
        let dst_high = (dst_value >> 64) as u64;
        let src_low = src_value as u64;
        let src_high = (src_value >> 64) as u64;

        let sum_low = dst_low.wrapping_add(src_low);
        let sum_high = dst_high.wrapping_add(src_high);

        let result = (sum_low as u128) | ((sum_high as u128) << 64);

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_psubb(&mut self, inst: &Instruction) -> Result<()> {
        // PSUBB: Subtract packed byte integers
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
                    "Invalid PSUBB source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let mut result = 0u128;

        // Subtract 16 bytes
        for i in 0..16 {
            let dst_byte = ((dst_value >> (i * 8)) & 0xFF) as u8;
            let src_byte = ((src_value >> (i * 8)) & 0xFF) as u8;
            let diff = dst_byte.wrapping_sub(src_byte);
            result |= (diff as u128) << (i * 8);
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_psubw(&mut self, inst: &Instruction) -> Result<()> {
        // PSUBW: Subtract packed word integers
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
                    "Invalid PSUBW source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let mut result = 0u128;

        // Subtract 8 words (16-bit values)
        for i in 0..8 {
            let dst_word = ((dst_value >> (i * 16)) & 0xFFFF) as u16;
            let src_word = ((src_value >> (i * 16)) & 0xFFFF) as u16;
            let diff = dst_word.wrapping_sub(src_word);
            result |= (diff as u128) << (i * 16);
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_psubd(&mut self, inst: &Instruction) -> Result<()> {
        // PSUBD: Subtract packed doubleword integers
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
                    "Invalid PSUBD source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let mut result = 0u128;

        // Subtract 4 doublewords (32-bit values)
        for i in 0..4 {
            let dst_dword = ((dst_value >> (i * 32)) & 0xFFFFFFFF) as u32;
            let src_dword = ((src_value >> (i * 32)) & 0xFFFFFFFF) as u32;
            let diff = dst_dword.wrapping_sub(src_dword);
            result |= (diff as u128) << (i * 32);
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_psubq(&mut self, inst: &Instruction) -> Result<()> {
        // PSUBQ: Subtract packed quadword integers
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
                    "Invalid PSUBQ source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);

        // Subtract 2 quadwords (64-bit values)
        let dst_low = dst_value as u64;
        let dst_high = (dst_value >> 64) as u64;
        let src_low = src_value as u64;
        let src_high = (src_value >> 64) as u64;

        let diff_low = dst_low.wrapping_sub(src_low);
        let diff_high = dst_high.wrapping_sub(src_high);

        let result = (diff_low as u128) | ((diff_high as u128) << 64);

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_pmullw(&mut self, inst: &Instruction) -> Result<()> {
        // PMULLW: Multiply packed signed word integers and store low result
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
                    "Invalid PMULLW source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let mut result = 0u128;

        // Multiply each pair of 16-bit signed integers and store low 16 bits
        for i in 0..8 {
            let dst_word = ((dst_value >> (i * 16)) & 0xFFFF) as i16;
            let src_word = ((src_value >> (i * 16)) & 0xFFFF) as i16;
            let product = (dst_word as i32) * (src_word as i32);
            result |= ((product & 0xFFFF) as u128) << (i * 16);
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_pmulhw(&mut self, inst: &Instruction) -> Result<()> {
        // PMULHW: Multiply packed signed word integers and store high result
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
                    "Invalid PMULHW source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let mut result = 0u128;

        // Multiply each pair of 16-bit signed integers and store high 16 bits
        for i in 0..8 {
            let dst_word = ((dst_value >> (i * 16)) & 0xFFFF) as i16;
            let src_word = ((src_value >> (i * 16)) & 0xFFFF) as i16;
            let product = (dst_word as i32) * (src_word as i32);
            result |= (((product >> 16) & 0xFFFF) as u128) << (i * 16);
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_pmulhuw(&mut self, inst: &Instruction) -> Result<()> {
        // PMULHUW: Multiply packed unsigned word integers and store high result
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
                    "Invalid PMULHUW source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let mut result = 0u128;

        // Multiply each pair of 16-bit unsigned integers and store high 16 bits
        for i in 0..8 {
            let dst_word = ((dst_value >> (i * 16)) & 0xFFFF) as u16;
            let src_word = ((src_value >> (i * 16)) & 0xFFFF) as u16;
            let product = (dst_word as u32) * (src_word as u32);
            result |= (((product >> 16) & 0xFFFF) as u128) << (i * 16);
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_pmuludq(&mut self, inst: &Instruction) -> Result<()> {
        // PMULUDQ: Multiply packed unsigned doubleword integers
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
                    "Invalid PMULUDQ source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);

        // Multiply low dwords of each 64-bit element, store 64-bit results
        let dst_low_dword = (dst_value & 0xFFFFFFFF) as u32;
        let src_low_dword = (src_value & 0xFFFFFFFF) as u32;
        let product_low = (dst_low_dword as u64) * (src_low_dword as u64);

        let dst_high_dword = ((dst_value >> 64) & 0xFFFFFFFF) as u32;
        let src_high_dword = ((src_value >> 64) & 0xFFFFFFFF) as u32;
        let product_high = (dst_high_dword as u64) * (src_high_dword as u64);

        let result = (product_low as u128) | ((product_high as u128) << 64);

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_pand(&mut self, inst: &Instruction) -> Result<()> {
        // PAND: Logical AND of packed data
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
                    "Invalid PAND source".to_string(),
                ));
            }
        };
        let dst_value = self.engine.cpu.read_xmm(dst_reg);

        // Perform bitwise AND on the entire 128-bit value
        let result = dst_value & src_value;

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_pandn(&mut self, inst: &Instruction) -> Result<()> {
        // PANDN: Logical AND NOT of packed data (NOT dst AND src)
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
                    "Invalid PANDN source".to_string(),
                ));
            }
        };
        let dst_value = self.engine.cpu.read_xmm(dst_reg);

        // Perform bitwise AND NOT: (~dst) & src
        let result = (!dst_value) & src_value;

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_por(&mut self, inst: &Instruction) -> Result<()> {
        // POR: Logical OR of packed data
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
                    "Invalid POR source".to_string(),
                ));
            }
        };
        let dst_value = self.engine.cpu.read_xmm(dst_reg);

        // Perform bitwise OR on the entire 128-bit value
        let result = dst_value | src_value;

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_pxor(&mut self, inst: &Instruction) -> Result<()> {
        // PXOR: Logical XOR of packed data
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
                    "Invalid PXOR source".to_string(),
                ));
            }
        };
        let dst_value = self.engine.cpu.read_xmm(dst_reg);

        // Perform bitwise XOR on the entire 128-bit value
        let result = dst_value ^ src_value;

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_pcmpeqb(&mut self, inst: &Instruction) -> Result<()> {
        // PCMPEQB: Compare packed bytes for equality
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
                    "Invalid PCMPEQB source".to_string(),
                ));
            }
        };
        let dst_value = self.engine.cpu.read_xmm(dst_reg);

        // Compare each byte
        let mut result = 0u128;
        for i in 0..16 {
            let dst_byte = ((dst_value >> (i * 8)) & 0xFF) as u8;
            let src_byte = ((src_value >> (i * 8)) & 0xFF) as u8;
            if dst_byte == src_byte {
                result |= 0xFFu128 << (i * 8);
            }
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_pcmpeqw(&mut self, inst: &Instruction) -> Result<()> {
        // PCMPEQW: Compare packed words for equality
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
                    "Invalid PCMPEQW source".to_string(),
                ));
            }
        };
        let dst_value = self.engine.cpu.read_xmm(dst_reg);

        // Compare each 16-bit word
        let mut result = 0u128;
        for i in 0..8 {
            let dst_word = ((dst_value >> (i * 16)) & 0xFFFF) as u16;
            let src_word = ((src_value >> (i * 16)) & 0xFFFF) as u16;
            if dst_word == src_word {
                result |= 0xFFFFu128 << (i * 16);
            }
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_pcmpeqd(&mut self, inst: &Instruction) -> Result<()> {
        // PCMPEQD: Compare packed doublewords for equality
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
                    "Invalid PCMPEQD source".to_string(),
                ));
            }
        };
        let dst_value = self.engine.cpu.read_xmm(dst_reg);

        // Compare each 32-bit doubleword
        let mut result = 0u128;
        for i in 0..4 {
            let dst_dword = ((dst_value >> (i * 32)) & 0xFFFFFFFF) as u32;
            let src_dword = ((src_value >> (i * 32)) & 0xFFFFFFFF) as u32;
            if dst_dword == src_dword {
                result |= 0xFFFFFFFFu128 << (i * 32);
            }
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_pcmpgtb(&mut self, inst: &Instruction) -> Result<()> {
        // PCMPGTB: Compare packed signed bytes for greater than
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
                    "Invalid PCMPGTB source".to_string(),
                ));
            }
        };
        let dst_value = self.engine.cpu.read_xmm(dst_reg);

        // Compare each signed byte
        let mut result = 0u128;
        for i in 0..16 {
            let dst_byte = ((dst_value >> (i * 8)) & 0xFF) as u8 as i8;
            let src_byte = ((src_value >> (i * 8)) & 0xFF) as u8 as i8;
            if dst_byte > src_byte {
                result |= 0xFFu128 << (i * 8);
            }
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_pcmpgtw(&mut self, inst: &Instruction) -> Result<()> {
        // PCMPGTW: Compare packed signed words for greater than
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
                    "Invalid PCMPGTW source".to_string(),
                ));
            }
        };
        let dst_value = self.engine.cpu.read_xmm(dst_reg);

        // Compare each signed 16-bit word
        let mut result = 0u128;
        for i in 0..8 {
            let dst_word = ((dst_value >> (i * 16)) & 0xFFFF) as u16 as i16;
            let src_word = ((src_value >> (i * 16)) & 0xFFFF) as u16 as i16;
            if dst_word > src_word {
                result |= 0xFFFFu128 << (i * 16);
            }
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_pcmpgtd(&mut self, inst: &Instruction) -> Result<()> {
        // PCMPGTD: Compare packed signed doublewords for greater than
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
                    "Invalid PCMPGTD source".to_string(),
                ));
            }
        };
        let dst_value = self.engine.cpu.read_xmm(dst_reg);

        // Compare each signed 32-bit doubleword
        let mut result = 0u128;
        for i in 0..4 {
            let dst_dword = ((dst_value >> (i * 32)) & 0xFFFFFFFF) as u32 as i32;
            let src_dword = ((src_value >> (i * 32)) & 0xFFFFFFFF) as u32 as i32;
            if dst_dword > src_dword {
                result |= 0xFFFFFFFFu128 << (i * 32);
            }
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_vpcmpeqw(&mut self, inst: &Instruction) -> Result<()> {
        // VPCMPEQW - Compare packed words for equality (AVX)
        // VEX.256: VPCMPEQW ymm1, ymm2, ymm3/m256
        // VEX.128: VPCMPEQW xmm1, xmm2, xmm3/m128

        let is_256bit = inst.op_register(0).is_ymm();

        if inst.op_count() != 3 {
            return Err(EmulatorError::UnsupportedInstruction(
                "VPCMPEQW requires exactly 3 operands".to_string(),
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
                        "Unsupported VPCMPEQW source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            // Compare both 128-bit halves
            let mut result = [0u128; 2];
            for half in 0..2 {
                let src1_half = src1_data[half];
                let src2_half = src2_data[half];

                // Compare each 16-bit word in this half
                for i in 0..8 {
                    let src1_word = ((src1_half >> (i * 16)) & 0xFFFF) as u16;
                    let src2_word = ((src2_half >> (i * 16)) & 0xFFFF) as u16;
                    if src1_word == src2_word {
                        result[half] |= 0xFFFFu128 << (i * 16);
                    }
                }
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
                        "Unsupported VPCMPEQW source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            // Compare each 16-bit word
            let mut result = 0u128;
            for i in 0..8 {
                let src1_word = ((src1_data >> (i * 16)) & 0xFFFF) as u16;
                let src2_word = ((src2_data >> (i * 16)) & 0xFFFF) as u16;
                if src1_word == src2_word {
                    result |= 0xFFFFu128 << (i * 16);
                }
            }

            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_xmm(dst_reg, result);
        }

        Ok(())
    }
}
