use crate::engine::ExecutionContext;
use crate::error::{EmulatorError, Result};
use crate::memory::MemoryTrait;
use crate::{Flags, HookManager, Register};
use iced_x86::{Instruction, OpKind};

impl<H: HookManager<M, PS>, M: MemoryTrait<PS>, const PS: u64> ExecutionContext<'_, H, M, PS> {
    pub(crate) fn execute_cdq(&mut self, _inst: &Instruction) -> Result<()> {
        // CDQ: Sign-extend EAX into EDX:EAX (32-bit version)
        // If EAX high bit is set, EDX = 0xFFFFFFFF, else EDX = 0
        let eax = self.engine.cpu.read_reg(Register::RAX) as u32;
        let edx = if (eax & 0x80000000) != 0 {
            0xFFFFFFFFu32
        } else {
            0
        };
        self.engine.cpu.write_reg(Register::RDX, edx as u64);
        Ok(())
    }

    pub(crate) fn execute_cdqe(&mut self, _inst: &Instruction) -> Result<()> {
        // CDQE: Sign-extend EAX to RAX (convert dword to qword)
        let eax = self.engine.cpu.read_reg(Register::RAX) as u32;
        let rax = eax as i32 as i64 as u64; // Sign extend 32-bit to 64-bit
        self.engine.cpu.write_reg(Register::RAX, rax);
        Ok(())
    }

    pub(crate) fn execute_shld(&mut self, inst: &Instruction) -> Result<()> {
        // SHLD shifts dst left by count, filling from src
        let dst_value = self.read_operand(inst, 0)?;
        let src_value = self.read_operand(inst, 1)?;
        let shift_count = (self.read_operand(inst, 2)? & 0x3F) as u32; // Count is modulo 64

        if shift_count == 0 {
            return Ok(());
        }

        let size = self.get_operand_size_from_instruction(inst, 0)?;
        let (result, cf, of) = match size {
            2 => {
                let count = shift_count & 0x1F; // For 16-bit, modulo 32
                if count >= 16 {
                    let result = (src_value as u16).wrapping_shl(count - 16) as u64;
                    let cf = ((dst_value >> (16 - count)) & 1) != 0;
                    (result, cf, false)
                } else {
                    let result =
                        ((dst_value as u16) << count) | ((src_value as u16) >> (16 - count));
                    let cf = ((dst_value >> (16 - count)) & 1) != 0;
                    let of = count == 1 && (((result >> 15) & 1) as u64 != ((dst_value >> 15) & 1));
                    (result as u64, cf, of)
                }
            }
            4 => {
                let count = shift_count & 0x1F; // For 32-bit, modulo 32
                if count == 0 {
                    return Ok(());
                }
                let dst32 = dst_value as u32;
                let src32 = src_value as u32;
                let result = (dst32 << count) | (src32 >> (32 - count));
                let cf = ((dst32 >> (32 - count)) & 1) != 0;
                let of = count == 1 && (((result >> 31) & 1) != ((dst32 >> 31) & 1));
                (result as u64, cf, of)
            }
            8 => {
                if shift_count >= 64 {
                    // Undefined behavior, but typically zeroes result
                    (0, false, false)
                } else {
                    let result = (dst_value << shift_count) | (src_value >> (64 - shift_count));
                    let cf = ((dst_value >> (64 - shift_count)) & 1) != 0;
                    let of = shift_count == 1 && (((result >> 63) & 1) != ((dst_value >> 63) & 1));
                    (result, cf, of)
                }
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(format!(
                    "SHLD: Unsupported size: {}",
                    size
                )));
            }
        };

        // Update flags
        if cf {
            self.engine.cpu.rflags.insert(Flags::CF);
        } else {
            self.engine.cpu.rflags.remove(Flags::CF);
        }
        if shift_count == 1 {
            if of {
                self.engine.cpu.rflags.insert(Flags::OF);
            } else {
                self.engine.cpu.rflags.remove(Flags::OF);
            }
        }
        // Update SF, ZF, PF based on result (but not CF/OF, which we already set)
        // Zero flag
        if result == 0 {
            self.engine.cpu.rflags.insert(Flags::ZF);
        } else {
            self.engine.cpu.rflags.remove(Flags::ZF);
        }

        // Sign flag
        let sign_bit = match size {
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

        // Parity flag - count 1-bits in low byte
        let low_byte = (result & 0xFF) as u8;
        if low_byte.count_ones().is_multiple_of(2) {
            self.engine.cpu.rflags.insert(Flags::PF);
        } else {
            self.engine.cpu.rflags.remove(Flags::PF);
        }

        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    pub(crate) fn execute_shrd(&mut self, inst: &Instruction) -> Result<()> {
        // SHRD shifts dst right by count, filling from src
        let dst_value = self.read_operand(inst, 0)?;
        let src_value = self.read_operand(inst, 1)?;
        let shift_count = (self.read_operand(inst, 2)? & 0x3F) as u32; // Count is modulo 64

        if shift_count == 0 {
            return Ok(());
        }

        let size = self.get_operand_size_from_instruction(inst, 0)?;
        let (result, cf, of) = match size {
            2 => {
                let count = shift_count & 0x1F; // For 16-bit, modulo 32
                if count >= 16 {
                    let result = (src_value as u16).wrapping_shr(count - 16) as u64;
                    let cf = ((dst_value >> (count - 1)) & 1) != 0;
                    (result, cf, false)
                } else {
                    let result =
                        ((dst_value as u16) >> count) | ((src_value as u16) << (16 - count));
                    let cf = ((dst_value >> (count - 1)) & 1) != 0;
                    let msb = (dst_value >> 15) & 1;
                    let of = count == 1 && (msb != ((src_value >> 15) & 1));
                    (result as u64, cf, of)
                }
            }
            4 => {
                let count = shift_count & 0x1F; // For 32-bit, modulo 32
                if count == 0 {
                    return Ok(());
                }
                let dst32 = dst_value as u32;
                let src32 = src_value as u32;
                let result = (dst32 >> count) | (src32 << (32 - count));
                let cf = ((dst32 >> (count - 1)) & 1) != 0;
                let msb = (dst32 >> 31) & 1;
                let of = count == 1 && (msb != ((src32 >> 31) & 1));
                (result as u64, cf, of)
            }
            8 => {
                if shift_count >= 64 {
                    // Undefined behavior, but typically zeroes result
                    (0, false, false)
                } else {
                    let result = (dst_value >> shift_count) | (src_value << (64 - shift_count));
                    let cf = ((dst_value >> (shift_count - 1)) & 1) != 0;
                    let msb = (dst_value >> 63) & 1;
                    let of = shift_count == 1 && (msb != ((src_value >> 63) & 1));
                    (result, cf, of)
                }
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(format!(
                    "SHRD: Unsupported size: {}",
                    size
                )));
            }
        };

        // Update flags
        if cf {
            self.engine.cpu.rflags.insert(Flags::CF);
        } else {
            self.engine.cpu.rflags.remove(Flags::CF);
        }
        if shift_count == 1 {
            if of {
                self.engine.cpu.rflags.insert(Flags::OF);
            } else {
                self.engine.cpu.rflags.remove(Flags::OF);
            }
        }
        // Update SF, ZF, PF based on result (but not CF/OF, which we already set)
        // Zero flag
        if result == 0 {
            self.engine.cpu.rflags.insert(Flags::ZF);
        } else {
            self.engine.cpu.rflags.remove(Flags::ZF);
        }

        // Sign flag
        let sign_bit = match size {
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

        // Parity flag - count 1-bits in low byte
        let low_byte = (result & 0xFF) as u8;
        if low_byte.count_ones().is_multiple_of(2) {
            self.engine.cpu.rflags.insert(Flags::PF);
        } else {
            self.engine.cpu.rflags.remove(Flags::PF);
        }

        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    pub(crate) fn execute_vzeroupper(&mut self, _inst: &Instruction) -> Result<()> {
        // VZEROUPPER - Zero upper bits of all YMM registers
        // This sets the upper 128 bits (bits 255:128) of all YMM registers to zero
        // The lower 128 bits (XMM portions) are preserved

        // Zero the upper 128 bits of all YMM registers (YMM0-YMM15)
        for reg in &mut self.engine.cpu.ymm_regs[0..16] {
            // Keep the lower 128 bits (XMM part) and zero the upper 128 bits
            reg[1] = 0;
        }

        Ok(())
    }

    pub(crate) fn execute_nop(&mut self, _inst: &Instruction) -> Result<()> {
        // NOP: No Operation - do nothing
        Ok(())
    }

    pub(crate) fn execute_cmpxchg(&mut self, inst: &Instruction) -> Result<()> {
        // CMPXCHG: Compare and exchange
        // Compare AL/AX/EAX/RAX with destination operand
        // If equal: ZF=1, destination = source
        // If not equal: ZF=0, AL/AX/EAX/RAX = destination

        let dest_value = self.read_operand(inst, 0)?;
        let src_value = self.read_operand(inst, 1)?;
        let size = self.get_operand_size_from_instruction(inst, 0)?;

        // Get the appropriate accumulator register based on operand size
        let acc_reg = match size {
            1 => Register::AL,
            2 => Register::AX,
            4 => Register::EAX,
            8 => Register::RAX,
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(format!(
                    "Unsupported size for CMPXCHG: {}",
                    size
                )));
            }
        };

        let acc_value = self.engine.cpu.read_reg(acc_reg);

        // Mask values based on operand size
        let mask = match size {
            1 => 0xFF,
            2 => 0xFFFF,
            4 => 0xFFFFFFFF,
            8 => 0xFFFFFFFFFFFFFFFF,
            _ => unreachable!(),
        };

        let masked_acc = acc_value & mask;
        let masked_dest = dest_value & mask;

        if masked_acc == masked_dest {
            // Values are equal: set ZF=1, store source in destination
            self.engine.cpu.rflags.insert(Flags::ZF);
            self.write_operand(inst, 0, src_value & mask)?;
        } else {
            // Values are not equal: set ZF=0, load destination into accumulator
            self.engine.cpu.rflags.remove(Flags::ZF);
            self.engine.cpu.write_reg(acc_reg, dest_value & mask);
        }

        // Update other flags based on comparison (like CMP instruction)
        let result = masked_acc.wrapping_sub(masked_dest);
        self.update_flags_arithmetic_iced(masked_acc, masked_dest, result, true, inst)?;

        Ok(())
    }

    pub(crate) fn execute_stc(&mut self, _inst: &Instruction) -> Result<()> {
        // STC: Set carry flag
        self.engine.cpu.rflags.insert(Flags::CF);
        Ok(())
    }

    pub(crate) fn execute_clc(&mut self, _inst: &Instruction) -> Result<()> {
        // CLC: Clear carry flag
        self.engine.cpu.rflags.remove(Flags::CF);
        Ok(())
    }

    pub(crate) fn execute_cmc(&mut self, _inst: &Instruction) -> Result<()> {
        // CMC: Complement carry flag
        if self.engine.cpu.rflags.contains(Flags::CF) {
            self.engine.cpu.rflags.remove(Flags::CF);
        } else {
            self.engine.cpu.rflags.insert(Flags::CF);
        }
        Ok(())
    }

    pub(crate) fn execute_xlat(&mut self, _inst: &Instruction) -> Result<()> {
        // XLAT: Table lookup translation
        // AL = [DS:RBX + AL] (64-bit mode)
        // AL = [DS:EBX + AL] (32-bit mode)
        // AL = [DS:BX + AL] (16-bit mode)

        // Get AL value as index
        let al = self.engine.cpu.read_reg(Register::AL) as u8;

        // In 64-bit mode, use RBX as base
        // TODO: Handle 32-bit and 16-bit modes when needed
        let base_addr = self.engine.cpu.read_reg(Register::RBX);

        // Calculate effective address: base + zero-extended AL
        let effective_addr = base_addr.wrapping_add(al as u64);

        // Read byte from memory at effective address
        let value = self.read_memory_sized(effective_addr, 1)? as u8;

        // Get current RAX value and preserve upper bits
        let rax = self.engine.cpu.read_reg(Register::RAX);
        let new_rax = (rax & 0xFFFFFFFFFFFFFF00) | (value as u64);

        // Store result, preserving upper bits of RAX
        self.engine.cpu.write_reg(Register::RAX, new_rax);

        // XLAT doesn't affect flags
        Ok(())
    }

    pub(crate) fn execute_pause(&mut self, _inst: &Instruction) -> Result<()> {
        // PAUSE: Spin-wait loop hint
        // This is a hint to the processor that the code is in a spin-wait loop
        // In emulation, we don't need to do anything special
        // Real processors use this to improve power consumption and performance
        // when one logical processor is waiting for another

        // PAUSE doesn't affect registers or flags
        // It's essentially a NOP with a hint for the processor
        Ok(())
    }

    pub(crate) fn execute_ud2(&mut self, _inst: &Instruction) -> Result<()> {
        // UD2: Undefined instruction
        // Guaranteed to raise an invalid opcode exception
        // Often used for marking unreachable code or debugging

        // Raise an invalid opcode error
        Err(EmulatorError::InvalidOpcode)
    }

    pub(crate) fn execute_mulx(&mut self, inst: &Instruction) -> Result<()> {
        // MULX: Unsigned Multiply Without Affecting Flags
        // Performs unsigned multiplication of RDX/EDX with source operand
        // Results go to two destination registers - high bits in dest1, low bits in dest2
        // Does NOT affect any flags

        // MULX encoding is special in VEX instructions
        // In Intel syntax: MULX r32a, r32b, r/m32
        // But iced-x86 seems to decode it as having EDX as both source and sometimes dest
        // We need to handle the VEX.vvvv encoded destination specially

        // Get the source operand (should be op2 in iced-x86)
        let src = self.read_operand(inst, 2)?;

        // Get operand size to determine which register and operation size
        let size = inst.op0_register().size();

        let (high, low) = match size {
            4 => {
                // 32-bit mode: EDX * src -> 64-bit result
                let edx_value = (self.engine.cpu.read_reg(Register::RDX) & 0xFFFFFFFF) as u32;
                let src32 = (src & 0xFFFFFFFF) as u32;
                let result = edx_value as u64 * src32 as u64;
                let high = result >> 32;
                let low = result & 0xFFFFFFFF;
                (high, low)
            }
            8 => {
                // 64-bit mode: RDX * src -> 128-bit result
                let rdx_value = self.engine.cpu.read_reg(Register::RDX);
                // Perform 128-bit multiplication
                let result = (rdx_value as u128) * (src as u128);
                let high = (result >> 64) as u64;
                let low = (result & 0xFFFFFFFFFFFFFFFF) as u64;
                (high, low)
            }
            _ => {
                return Err(EmulatorError::InvalidInstruction(
                    self.engine.cpu.read_reg(Register::RIP),
                ));
            }
        };

        // Write results to destinations
        // MULX has a quirk in iced-x86 where the VEX.vvvv destination register
        // isn't properly exposed in the operand list.
        // For now, we'll write to the registers that iced-x86 provides:
        // Op0 gets high bits (this should be correct)
        // Op1 seems to be EDX in iced-x86, but this is actually where low bits go

        self.write_operand(inst, 0, high)?;

        // For the low bits destination, we need special handling
        // In the original Intel encoding, this would come from VEX.vvvv
        // But iced-x86 seems to treat EDX as both source and a destination
        // So we write low bits to op1 (which iced-x86 says is EDX)
        self.write_operand(inst, 1, low)?;

        // MULX does not modify any flags - this is its key difference from MUL

        Ok(())
    }

    pub(crate) fn execute_cqo(&mut self, _inst: &Instruction) -> Result<()> {
        // CQO: Convert Quadword to Octoword
        // Sign-extend RAX to RDX:RAX
        let rax_value = self.engine.cpu.read_reg(Register::RAX);

        // Sign extend RAX to RDX
        let sign_extended = if rax_value & 0x8000000000000000 != 0 {
            0xFFFFFFFFFFFFFFFF // Negative, fill RDX with 1s
        } else {
            0x0000000000000000 // Positive, fill RDX with 0s
        };

        self.engine.cpu.write_reg(Register::RDX, sign_extended);

        Ok(())
    }

    pub(crate) fn execute_xadd(&mut self, inst: &Instruction) -> Result<()> {
        // XADD: Exchange and Add
        // Exchanges the first operand (destination) with the second operand (source),
        // then adds the original destination value to the source and stores in destination

        let dest_value = self.read_operand(inst, 0)?;
        let src_value = self.read_operand(inst, 1)?;

        // Add dest + src and store in destination
        let sum = dest_value.wrapping_add(src_value);
        self.write_operand(inst, 0, sum)?;

        // Store original destination value in source
        self.write_operand(inst, 1, dest_value)?;

        // Update flags based on the addition
        // Update flags for addition
        self.update_flags_arithmetic_iced(dest_value, src_value, sum, true, inst)?;

        Ok(())
    }

    pub(crate) fn execute_bswap(&mut self, inst: &Instruction) -> Result<()> {
        // BSWAP: Byte swap - reverses the byte order of a 32-bit or 64-bit register
        if inst.op_kind(0) != OpKind::Register {
            return Err(EmulatorError::InvalidOperand);
        }

        let reg = inst.op0_register();
        let reg_enum = self.convert_register(reg)?;
        let value = self.engine.cpu.read_reg(reg_enum);

        let swapped = match reg.size() {
            4 => {
                // 32-bit swap
                let val32 = value as u32;
                let swapped32 = val32.swap_bytes();
                // Zero-extend for 64-bit mode
                swapped32 as u64
            }
            8 => {
                // 64-bit swap
                value.swap_bytes()
            }
            _ => return Err(EmulatorError::InvalidOperand),
        };

        self.engine.cpu.write_reg(reg_enum, swapped);
        Ok(())
    }

    pub(crate) fn execute_cld(&mut self, _inst: &Instruction) -> Result<()> {
        // CLD: Clear Direction Flag
        self.engine.cpu.rflags.remove(Flags::DF);
        Ok(())
    }

    pub(crate) fn execute_std(&mut self, _inst: &Instruction) -> Result<()> {
        // STD: Set Direction Flag
        self.engine.cpu.rflags.insert(Flags::DF);
        Ok(())
    }

    pub(crate) fn execute_vcmpps(&mut self, inst: &Instruction) -> Result<()> {
        // VCMPPS - Compare Packed Single-Precision Floating-Point Values
        // VEX.256: VCMPPS ymm1, ymm2, ymm3/m256, imm8
        // VEX.128: VCMPPS xmm1, xmm2, xmm3/m128, imm8

        let is_256bit = inst.op_register(0).is_ymm();

        if inst.op_count() != 4 {
            return Err(EmulatorError::UnsupportedInstruction(
                "VCMPPS requires exactly 4 operands".to_string(),
            ));
        }

        let imm = inst.immediate(3) as u8;

        if is_256bit {
            // 256-bit YMM operation - compare 8 floats
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
                        "Unsupported VCMPPS source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            let mut result = [0u128; 2];

            // Process lower 128 bits (4 floats)
            for i in 0..4 {
                let offset = i * 32;
                let a = f32::from_bits(((src1_data[0] >> offset) & 0xFFFFFFFF) as u32);
                let b = f32::from_bits(((src2_data[0] >> offset) & 0xFFFFFFFF) as u32);

                if self.compare_floats_avx(a, b, imm) {
                    result[0] |= 0xFFFFFFFFu128 << offset;
                }
            }

            // Process upper 128 bits (4 floats)
            for i in 0..4 {
                let offset = i * 32;
                let a = f32::from_bits(((src1_data[1] >> offset) & 0xFFFFFFFF) as u32);
                let b = f32::from_bits(((src2_data[1] >> offset) & 0xFFFFFFFF) as u32);

                if self.compare_floats_avx(a, b, imm) {
                    result[1] |= 0xFFFFFFFFu128 << offset;
                }
            }

            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_ymm(dst_reg, result);
        } else {
            // 128-bit XMM operation - compare 4 floats
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
                        "Unsupported VCMPPS source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            let mut result = 0u128;

            for i in 0..4 {
                let offset = i * 32;
                let a = f32::from_bits(((src1_data >> offset) & 0xFFFFFFFF) as u32);
                let b = f32::from_bits(((src2_data >> offset) & 0xFFFFFFFF) as u32);

                if self.compare_floats_avx(a, b, imm) {
                    result |= 0xFFFFFFFFu128 << offset;
                }
            }

            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_xmm(dst_reg, result);
        }

        Ok(())
    }

    pub(crate) fn execute_vcmppd(&mut self, inst: &Instruction) -> Result<()> {
        // VCMPPD - Compare Packed Double-Precision Floating-Point Values
        // VEX.256: VCMPPD ymm1, ymm2, ymm3/m256, imm8
        // VEX.128: VCMPPD xmm1, xmm2, xmm3/m128, imm8

        let is_256bit = inst.op_register(0).is_ymm();

        if inst.op_count() != 4 {
            return Err(EmulatorError::UnsupportedInstruction(
                "VCMPPD requires exactly 4 operands".to_string(),
            ));
        }

        let imm = inst.immediate(3) as u8;

        if is_256bit {
            // 256-bit YMM operation - compare 4 doubles
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
                        "Unsupported VCMPPD source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            let mut result = [0u128; 2];

            // Process lower 128 bits (2 doubles)
            for i in 0..2 {
                let offset = i * 64;
                let a = f64::from_bits((src1_data[0] >> offset) as u64);
                let b = f64::from_bits((src2_data[0] >> offset) as u64);

                if self.compare_doubles_avx(a, b, imm) {
                    result[0] |= 0xFFFFFFFFFFFFFFFFu128 << offset;
                }
            }

            // Process upper 128 bits (2 doubles)
            for i in 0..2 {
                let offset = i * 64;
                let a = f64::from_bits((src1_data[1] >> offset) as u64);
                let b = f64::from_bits((src2_data[1] >> offset) as u64);

                if self.compare_doubles_avx(a, b, imm) {
                    result[1] |= 0xFFFFFFFFFFFFFFFFu128 << offset;
                }
            }

            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_ymm(dst_reg, result);
        } else {
            // 128-bit XMM operation - compare 2 doubles
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
                        "Unsupported VCMPPD source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            let mut result = 0u128;

            for i in 0..2 {
                let offset = i * 64;
                let a = f64::from_bits((src1_data >> offset) as u64);
                let b = f64::from_bits((src2_data >> offset) as u64);

                if self.compare_doubles_avx(a, b, imm) {
                    result |= 0xFFFFFFFFFFFFFFFFu128 << offset;
                }
            }

            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_xmm(dst_reg, result);
        }

        Ok(())
    }

    pub(crate) fn execute_vshufps(&mut self, inst: &Instruction) -> Result<()> {
        // VSHUFPS - Shuffle Packed Single-Precision Floating-Point Values
        // VEX.256: VSHUFPS ymm1, ymm2, ymm3/m256, imm8
        // VEX.128: VSHUFPS xmm1, xmm2, xmm3/m128, imm8

        if inst.op_count() != 4 {
            return Err(EmulatorError::UnsupportedInstruction(
                "VSHUFPS requires exactly 4 operands".to_string(),
            ));
        }

        let imm8 = inst.immediate8() as usize;

        // Check if we're dealing with YMM (256-bit) or XMM (128-bit) registers
        if inst.op_register(0).is_ymm() {
            // YMM version (256-bit)
            let src1_reg = self.convert_register(inst.op_register(1))?;
            let src1 = self.engine.cpu.read_ymm(src1_reg);

            let src2 = match inst.op_kind(2) {
                OpKind::Register => {
                    let src2_reg = self.convert_register(inst.op_register(2))?;
                    self.engine.cpu.read_ymm(src2_reg)
                }
                OpKind::Memory => self.read_ymm_memory(inst, 2)?,
                _ => {
                    return Err(EmulatorError::UnsupportedInstruction(format!(
                        "Unsupported VSHUFPS source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            // Process each 128-bit lane separately
            let mut result = [0u128; 2];

            for lane in 0..2 {
                let src1_lane = src1[lane];
                let src2_lane = src2[lane];

                // Extract the 4 floats from each source
                let src1_bytes = src1_lane.to_le_bytes();
                let src2_bytes = src2_lane.to_le_bytes();

                let mut src1_floats = [0f32; 4];
                let mut src2_floats = [0f32; 4];
                for i in 0..4 {
                    src1_floats[i] = f32::from_le_bytes([
                        src1_bytes[i * 4],
                        src1_bytes[i * 4 + 1],
                        src1_bytes[i * 4 + 2],
                        src1_bytes[i * 4 + 3],
                    ]);
                    src2_floats[i] = f32::from_le_bytes([
                        src2_bytes[i * 4],
                        src2_bytes[i * 4 + 1],
                        src2_bytes[i * 4 + 2],
                        src2_bytes[i * 4 + 3],
                    ]);
                }

                // Shuffle according to imm8
                let mut result_floats = [0f32; 4];
                result_floats[0] = src1_floats[imm8 & 0x3];
                result_floats[1] = src1_floats[(imm8 >> 2) & 0x3];
                result_floats[2] = src2_floats[(imm8 >> 4) & 0x3];
                result_floats[3] = src2_floats[(imm8 >> 6) & 0x3];

                // Build result for this lane
                let mut lane_bytes = [0u8; 16];
                for i in 0..4 {
                    let bytes = result_floats[i].to_le_bytes();
                    lane_bytes[i * 4..i * 4 + 4].copy_from_slice(&bytes);
                }
                result[lane] = u128::from_le_bytes(lane_bytes);
            }

            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_ymm(dst_reg, result);
        } else {
            // XMM version (128-bit)
            let src1_reg = self.convert_register(inst.op_register(1))?;
            let src1 = self.engine.cpu.read_xmm(src1_reg);

            let src2 = match inst.op_kind(2) {
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
                        "Unsupported VSHUFPS source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            // Extract the 4 floats from each source
            let src1_bytes = src1.to_le_bytes();
            let src2_bytes = src2.to_le_bytes();

            let mut src1_floats = [0f32; 4];
            let mut src2_floats = [0f32; 4];
            for i in 0..4 {
                src1_floats[i] = f32::from_le_bytes([
                    src1_bytes[i * 4],
                    src1_bytes[i * 4 + 1],
                    src1_bytes[i * 4 + 2],
                    src1_bytes[i * 4 + 3],
                ]);
                src2_floats[i] = f32::from_le_bytes([
                    src2_bytes[i * 4],
                    src2_bytes[i * 4 + 1],
                    src2_bytes[i * 4 + 2],
                    src2_bytes[i * 4 + 3],
                ]);
            }

            // Shuffle according to imm8
            let mut result_floats = [0f32; 4];
            result_floats[0] = src1_floats[imm8 & 0x3];
            result_floats[1] = src1_floats[(imm8 >> 2) & 0x3];
            result_floats[2] = src2_floats[(imm8 >> 4) & 0x3];
            result_floats[3] = src2_floats[(imm8 >> 6) & 0x3];

            // Build result
            let mut result_bytes = [0u8; 16];
            for i in 0..4 {
                let bytes = result_floats[i].to_le_bytes();
                result_bytes[i * 4..i * 4 + 4].copy_from_slice(&bytes);
            }

            let result = u128::from_le_bytes(result_bytes);
            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_xmm(dst_reg, result);
        }

        Ok(())
    }

    pub(crate) fn execute_vshufpd(&mut self, inst: &Instruction) -> Result<()> {
        // VSHUFPD - Shuffle Packed Double-Precision Floating-Point Values
        // VEX.256: VSHUFPD ymm1, ymm2, ymm3/m256, imm8
        // VEX.128: VSHUFPD xmm1, xmm2, xmm3/m128, imm8

        if inst.op_count() != 4 {
            return Err(EmulatorError::UnsupportedInstruction(
                "VSHUFPD requires exactly 4 operands".to_string(),
            ));
        }

        let imm8 = inst.immediate8() as usize;

        // Check if we're dealing with YMM (256-bit) or XMM (128-bit) registers
        if inst.op_register(0).is_ymm() {
            // YMM version (256-bit) - contains 4 doubles
            let src1_reg = self.convert_register(inst.op_register(1))?;
            let src1 = self.engine.cpu.read_ymm(src1_reg);

            let src2 = match inst.op_kind(2) {
                OpKind::Register => {
                    let src2_reg = self.convert_register(inst.op_register(2))?;
                    self.engine.cpu.read_ymm(src2_reg)
                }
                OpKind::Memory => self.read_ymm_memory(inst, 2)?,
                _ => {
                    return Err(EmulatorError::UnsupportedInstruction(format!(
                        "Unsupported VSHUFPD source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            // Process each 128-bit lane separately
            let mut result = [0u128; 2];

            for lane in 0..2 {
                let src1_lane = src1[lane];
                let src2_lane = src2[lane];

                // Extract the 2 doubles from each source
                let src1_bytes = src1_lane.to_le_bytes();
                let src2_bytes = src2_lane.to_le_bytes();

                let src1_doubles = [
                    f64::from_le_bytes([
                        src1_bytes[0],
                        src1_bytes[1],
                        src1_bytes[2],
                        src1_bytes[3],
                        src1_bytes[4],
                        src1_bytes[5],
                        src1_bytes[6],
                        src1_bytes[7],
                    ]),
                    f64::from_le_bytes([
                        src1_bytes[8],
                        src1_bytes[9],
                        src1_bytes[10],
                        src1_bytes[11],
                        src1_bytes[12],
                        src1_bytes[13],
                        src1_bytes[14],
                        src1_bytes[15],
                    ]),
                ];
                let src2_doubles = [
                    f64::from_le_bytes([
                        src2_bytes[0],
                        src2_bytes[1],
                        src2_bytes[2],
                        src2_bytes[3],
                        src2_bytes[4],
                        src2_bytes[5],
                        src2_bytes[6],
                        src2_bytes[7],
                    ]),
                    f64::from_le_bytes([
                        src2_bytes[8],
                        src2_bytes[9],
                        src2_bytes[10],
                        src2_bytes[11],
                        src2_bytes[12],
                        src2_bytes[13],
                        src2_bytes[14],
                        src2_bytes[15],
                    ]),
                ];

                // Shuffle according to imm8 bits for this lane
                let bit_offset = lane * 2;
                let result_doubles = [
                    src1_doubles[(imm8 >> bit_offset) & 0x1],
                    src2_doubles[(imm8 >> (bit_offset + 1)) & 0x1],
                ];

                // Build result for this lane
                let mut lane_bytes = [0u8; 16];
                lane_bytes[0..8].copy_from_slice(&result_doubles[0].to_le_bytes());
                lane_bytes[8..16].copy_from_slice(&result_doubles[1].to_le_bytes());
                result[lane] = u128::from_le_bytes(lane_bytes);
            }

            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_ymm(dst_reg, result);
        } else {
            // XMM version (128-bit) - contains 2 doubles
            let src1_reg = self.convert_register(inst.op_register(1))?;
            let src1 = self.engine.cpu.read_xmm(src1_reg);

            let src2 = match inst.op_kind(2) {
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
                        "Unsupported VSHUFPD source operand type: {:?}",
                        inst.op_kind(2)
                    )));
                }
            };

            // Extract the 2 doubles from each source
            let src1_bytes = src1.to_le_bytes();
            let src2_bytes = src2.to_le_bytes();

            let src1_doubles = [
                f64::from_le_bytes([
                    src1_bytes[0],
                    src1_bytes[1],
                    src1_bytes[2],
                    src1_bytes[3],
                    src1_bytes[4],
                    src1_bytes[5],
                    src1_bytes[6],
                    src1_bytes[7],
                ]),
                f64::from_le_bytes([
                    src1_bytes[8],
                    src1_bytes[9],
                    src1_bytes[10],
                    src1_bytes[11],
                    src1_bytes[12],
                    src1_bytes[13],
                    src1_bytes[14],
                    src1_bytes[15],
                ]),
            ];
            let src2_doubles = [
                f64::from_le_bytes([
                    src2_bytes[0],
                    src2_bytes[1],
                    src2_bytes[2],
                    src2_bytes[3],
                    src2_bytes[4],
                    src2_bytes[5],
                    src2_bytes[6],
                    src2_bytes[7],
                ]),
                f64::from_le_bytes([
                    src2_bytes[8],
                    src2_bytes[9],
                    src2_bytes[10],
                    src2_bytes[11],
                    src2_bytes[12],
                    src2_bytes[13],
                    src2_bytes[14],
                    src2_bytes[15],
                ]),
            ];

            // Shuffle according to imm8
            let result_doubles = [
                src1_doubles[imm8 & 0x1],        // Bit 0 selects from src1
                src2_doubles[(imm8 >> 1) & 0x1], // Bit 1 selects from src2
            ];

            // Build result
            let mut result_bytes = [0u8; 16];
            result_bytes[0..8].copy_from_slice(&result_doubles[0].to_le_bytes());
            result_bytes[8..16].copy_from_slice(&result_doubles[1].to_le_bytes());

            let result = u128::from_le_bytes(result_bytes);
            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_xmm(dst_reg, result);
        }

        Ok(())
    }
}
