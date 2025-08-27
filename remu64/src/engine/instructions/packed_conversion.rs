use crate::HookManager;
use crate::engine::ExecutionContext;
use crate::error::{EmulatorError, Result};
use crate::memory::MemoryTrait;
use iced_x86::{Instruction, OpKind};

impl<H: HookManager<M, PS>, M: MemoryTrait<PS>, const PS: u64> ExecutionContext<'_, H, M, PS> {
    pub(crate) fn execute_packsswb(&mut self, inst: &Instruction) -> Result<()> {
        // PACKSSWB: Pack signed words to signed bytes with saturation
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
                    "Invalid PACKSSWB source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let mut result = 0u128;

        // Process destination words (low 8 bytes of result)
        for i in 0..8 {
            let word = ((dst_value >> (i * 16)) & 0xFFFF) as i16;
            let byte = if word > 127 {
                127i8
            } else if word < -128 {
                -128i8
            } else {
                word as i8
            };
            result |= ((byte as u8) as u128) << (i * 8);
        }

        // Process source words (high 8 bytes of result)
        for i in 0..8 {
            let word = ((src_value >> (i * 16)) & 0xFFFF) as i16;
            let byte = if word > 127 {
                127i8
            } else if word < -128 {
                -128i8
            } else {
                word as i8
            };
            result |= ((byte as u8) as u128) << ((i + 8) * 8);
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_packuswb(&mut self, inst: &Instruction) -> Result<()> {
        // PACKUSWB: Pack signed words to unsigned bytes with saturation
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
                    "Invalid PACKUSWB source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let mut result = 0u128;

        // Process destination words (low 8 bytes of result)
        for i in 0..8 {
            let word = ((dst_value >> (i * 16)) & 0xFFFF) as i16;
            let byte = if word > 255 {
                255u8
            } else if word < 0 {
                0u8
            } else {
                word as u8
            };
            result |= (byte as u128) << (i * 8);
        }

        // Process source words (high 8 bytes of result)
        for i in 0..8 {
            let word = ((src_value >> (i * 16)) & 0xFFFF) as i16;
            let byte = if word > 255 {
                255u8
            } else if word < 0 {
                0u8
            } else {
                word as u8
            };
            result |= (byte as u128) << ((i + 8) * 8);
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_pmaddwd(&mut self, inst: &Instruction) -> Result<()> {
        // PMADDWD: Multiply packed signed words and add pairs of results
        // Multiplies 8 pairs of signed words, then adds adjacent products to form 4 signed dwords
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
                    "Invalid PMADDWD source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let mut result = 0u128;

        // Process 4 pairs of words to produce 4 dwords
        for i in 0..4 {
            // Get two consecutive words from each operand
            let dst_word1 = ((dst_value >> (i * 32)) & 0xFFFF) as i16;
            let dst_word2 = ((dst_value >> (i * 32 + 16)) & 0xFFFF) as i16;
            let src_word1 = ((src_value >> (i * 32)) & 0xFFFF) as i16;
            let src_word2 = ((src_value >> (i * 32 + 16)) & 0xFFFF) as i16;

            // Multiply and add the products
            let product1 = (dst_word1 as i32) * (src_word1 as i32);
            let product2 = (dst_word2 as i32) * (src_word2 as i32);
            let sum = product1.wrapping_add(product2);

            // Store the 32-bit result
            result |= ((sum as u32) as u128) << (i * 32);
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_packssdw(&mut self, inst: &Instruction) -> Result<()> {
        // PACKSSDW: Pack signed doublewords to signed words with saturation
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
                    "Invalid PACKSSDW source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let mut result = 0u128;

        // Process destination dwords (low 4 words of result)
        for i in 0..4 {
            let dword = ((dst_value >> (i * 32)) & 0xFFFFFFFF) as i32;
            let word = if dword > 32767 {
                32767i16
            } else if dword < -32768 {
                -32768i16
            } else {
                dword as i16
            };
            result |= ((word as u16) as u128) << (i * 16);
        }

        // Process source dwords (high 4 words of result)
        for i in 0..4 {
            let dword = ((src_value >> (i * 32)) & 0xFFFFFFFF) as i32;
            let word = if dword > 32767 {
                32767i16
            } else if dword < -32768 {
                -32768i16
            } else {
                dword as i16
            };
            result |= ((word as u16) as u128) << ((i + 4) * 16);
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_pmovsxbw(&mut self, inst: &Instruction) -> Result<()> {
        // PMOVSXBW: Sign extend 8 bytes to 8 words
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let src_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_xmm(src_reg) & 0xFFFFFFFFFFFFFFFF // Take lower 64 bits (8 bytes)
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                self.read_memory_64(addr)? as u128
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid PMOVSXBW source".to_string(),
                ));
            }
        };

        let mut result = 0u128;
        for i in 0..8 {
            let byte = ((src_value >> (i * 8)) & 0xFF) as i8;
            let word = byte as i16 as u16;
            result |= (word as u128) << (i * 16);
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_pmovsxbd(&mut self, inst: &Instruction) -> Result<()> {
        // PMOVSXBD: Sign extend 4 bytes to 4 doublewords
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let src_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_xmm(src_reg) & 0xFFFFFFFF // Take lower 32 bits (4 bytes)
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                self.read_memory_32(addr)? as u128
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid PMOVSXBD source".to_string(),
                ));
            }
        };

        let mut result = 0u128;
        for i in 0..4 {
            let byte = ((src_value >> (i * 8)) & 0xFF) as i8;
            let dword = byte as i32 as u32;
            result |= (dword as u128) << (i * 32);
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_pmovsxbq(&mut self, inst: &Instruction) -> Result<()> {
        // PMOVSXBQ: Sign extend 2 bytes to 2 quadwords
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let src_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_xmm(src_reg) & 0xFFFF // Take lower 16 bits (2 bytes)
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                // Read 32 bits and take lower 16 bits
                (self.read_memory_32(addr)? & 0xFFFF) as u128
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid PMOVSXBQ source".to_string(),
                ));
            }
        };

        let mut result = 0u128;
        for i in 0..2 {
            let byte = ((src_value >> (i * 8)) & 0xFF) as i8;
            let qword = byte as i64 as u64;
            result |= (qword as u128) << (i * 64);
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_pmovsxwd(&mut self, inst: &Instruction) -> Result<()> {
        // PMOVSXWD: Sign extend 4 words to 4 doublewords
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let src_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_xmm(src_reg) & 0xFFFFFFFFFFFFFFFF // Take lower 64 bits (4 words)
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                self.read_memory_64(addr)? as u128
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid PMOVSXWD source".to_string(),
                ));
            }
        };

        let mut result = 0u128;
        for i in 0..4 {
            let word = ((src_value >> (i * 16)) & 0xFFFF) as i16;
            let dword = word as i32 as u32;
            result |= (dword as u128) << (i * 32);
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_pmovsxwq(&mut self, inst: &Instruction) -> Result<()> {
        // PMOVSXWQ: Sign extend 2 words to 2 quadwords
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let src_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_xmm(src_reg) & 0xFFFFFFFF // Take lower 32 bits (2 words)
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                self.read_memory_32(addr)? as u128
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid PMOVSXWQ source".to_string(),
                ));
            }
        };

        let mut result = 0u128;
        for i in 0..2 {
            let word = ((src_value >> (i * 16)) & 0xFFFF) as i16;
            let qword = word as i64 as u64;
            result |= (qword as u128) << (i * 64);
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_pmovsxdq(&mut self, inst: &Instruction) -> Result<()> {
        // PMOVSXDQ: Sign extend 2 doublewords to 2 quadwords
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let src_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_xmm(src_reg) & 0xFFFFFFFFFFFFFFFF // Take lower 64 bits (2 dwords)
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                self.read_memory_64(addr)? as u128
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid PMOVSXDQ source".to_string(),
                ));
            }
        };

        let mut result = 0u128;
        for i in 0..2 {
            let dword = ((src_value >> (i * 32)) & 0xFFFFFFFF) as i32;
            let qword = dword as i64 as u64;
            result |= (qword as u128) << (i * 64);
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_pmovzxbw(&mut self, inst: &Instruction) -> Result<()> {
        // PMOVZXBW: Zero extend 8 bytes to 8 words
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let src_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_xmm(src_reg) & 0xFFFFFFFFFFFFFFFF // Take lower 64 bits (8 bytes)
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                self.read_memory_64(addr)? as u128
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid PMOVZXBW source".to_string(),
                ));
            }
        };

        let mut result = 0u128;
        for i in 0..8 {
            let byte = ((src_value >> (i * 8)) & 0xFF) as u16;
            result |= (byte as u128) << (i * 16);
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_pmovzxbd(&mut self, inst: &Instruction) -> Result<()> {
        // PMOVZXBD: Zero extend 4 bytes to 4 doublewords
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let src_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_xmm(src_reg) & 0xFFFFFFFF // Take lower 32 bits (4 bytes)
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                self.read_memory_32(addr)? as u128
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid PMOVZXBD source".to_string(),
                ));
            }
        };

        let mut result = 0u128;
        for i in 0..4 {
            let byte = ((src_value >> (i * 8)) & 0xFF) as u32;
            result |= (byte as u128) << (i * 32);
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_pmovzxbq(&mut self, inst: &Instruction) -> Result<()> {
        // PMOVZXBQ: Zero extend 2 bytes to 2 quadwords
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let src_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_xmm(src_reg) & 0xFFFF // Take lower 16 bits (2 bytes)
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                // Read 32 bits and take lower 16 bits
                (self.read_memory_32(addr)? & 0xFFFF) as u128
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid PMOVZXBQ source".to_string(),
                ));
            }
        };

        let mut result = 0u128;
        for i in 0..2 {
            let byte = ((src_value >> (i * 8)) & 0xFF) as u64;
            result |= (byte as u128) << (i * 64);
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_pmovzxwd(&mut self, inst: &Instruction) -> Result<()> {
        // PMOVZXWD: Zero extend 4 words to 4 doublewords
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let src_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_xmm(src_reg) & 0xFFFFFFFFFFFFFFFF // Take lower 64 bits (4 words)
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                self.read_memory_64(addr)? as u128
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid PMOVZXWD source".to_string(),
                ));
            }
        };

        let mut result = 0u128;
        for i in 0..4 {
            let word = ((src_value >> (i * 16)) & 0xFFFF) as u32;
            result |= (word as u128) << (i * 32);
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_pmovzxwq(&mut self, inst: &Instruction) -> Result<()> {
        // PMOVZXWQ: Zero extend 2 words to 2 quadwords
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let src_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_xmm(src_reg) & 0xFFFFFFFF // Take lower 32 bits (2 words)
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                self.read_memory_32(addr)? as u128
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid PMOVZXWQ source".to_string(),
                ));
            }
        };

        let mut result = 0u128;
        for i in 0..2 {
            let word = ((src_value >> (i * 16)) & 0xFFFF) as u64;
            result |= (word as u128) << (i * 64);
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    pub(crate) fn execute_pmovzxdq(&mut self, inst: &Instruction) -> Result<()> {
        // PMOVZXDQ: Zero extend 2 doublewords to 2 quadwords
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let src_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_xmm(src_reg) & 0xFFFFFFFFFFFFFFFF // Take lower 64 bits (2 dwords)
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                self.read_memory_64(addr)? as u128
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid PMOVZXDQ source".to_string(),
                ));
            }
        };

        let mut result = 0u128;
        for i in 0..2 {
            let dword = ((src_value >> (i * 32)) & 0xFFFFFFFF) as u64;
            result |= (dword as u128) << (i * 64);
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }
}
