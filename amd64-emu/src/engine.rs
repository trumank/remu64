use crate::cpu::{CpuState, Register, Flags};
use crate::memory::{Memory, Permission};
use crate::decoder::{Decoder, DecoderMode, Instruction, Opcode, Operand, OperandSize};
use crate::hooks::{HookManager, HookType, HookId};
use crate::error::{EmulatorError, Result};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug, Clone, Copy)]
pub enum EngineMode {
    Mode16,
    Mode32,
    Mode64,
}

pub struct Engine {
    cpu: CpuState,
    memory: Memory,
    decoder: Decoder,
    hooks: HookManager,
    _mode: EngineMode,
    stop_requested: Arc<AtomicBool>,
    instruction_count: u64,
    trace_enabled: bool,
}

impl Engine {
    pub fn new(mode: EngineMode) -> Self {
        let decoder_mode = match mode {
            EngineMode::Mode16 => DecoderMode::Mode16,
            EngineMode::Mode32 => DecoderMode::Mode32,
            EngineMode::Mode64 => DecoderMode::Mode64,
        };
        
        Self {
            cpu: CpuState::new(),
            memory: Memory::new(),
            decoder: Decoder::new(decoder_mode),
            hooks: HookManager::new(),
            _mode: mode,
            stop_requested: Arc::new(AtomicBool::new(false)),
            instruction_count: 0,
            trace_enabled: false,
        }
    }
    
    pub fn mem_map(&mut self, address: u64, size: usize, perms: Permission) -> Result<()> {
        self.memory.map(address, size, perms)
    }
    
    pub fn mem_unmap(&mut self, address: u64, size: usize) -> Result<()> {
        self.memory.unmap(address, size)
    }
    
    pub fn mem_protect(&mut self, address: u64, size: usize, perms: Permission) -> Result<()> {
        self.memory.protect(address, size, perms)
    }
    
    pub fn mem_write(&mut self, address: u64, data: &[u8]) -> Result<()> {
        self.hooks.run_mem_write_hooks(&mut self.cpu, address, data.len())?;
        // For code loading, bypass permission checks and write directly
        self.memory.write_bytes(address, data)
    }
    
    pub fn mem_read(&mut self, address: u64, buf: &mut [u8]) -> Result<()> {
        self.hooks.run_mem_read_hooks(&mut self.cpu, address, buf.len())?;
        
        // Try to read memory, handle faults with hooks
        match self.memory.read(address, buf) {
            Ok(()) => Ok(()),
            Err(EmulatorError::UnmappedMemory(_)) => {
                // Try to handle the fault with memory fault hooks
                if self.hooks.run_mem_fault_hooks(&mut self.cpu, address, buf.len())? {
                    // Hook handled the fault, try reading again
                    self.memory.read(address, buf)
                } else {
                    // No hook handled the fault, return original error
                    Err(EmulatorError::UnmappedMemory(address))
                }
            }
            Err(e) => Err(e),
        }
    }
    
    pub fn reg_read(&self, reg: Register) -> Result<u64> {
        Ok(self.cpu.read_reg(reg))
    }
    
    pub fn reg_write(&mut self, reg: Register, value: u64) -> Result<()> {
        self.cpu.write_reg(reg, value);
        Ok(())
    }
    
    pub fn flags_read(&self) -> Flags {
        self.cpu.rflags
    }
    
    pub fn hook_add(
        &mut self,
        hook_type: HookType,
        begin: u64,
        end: u64,
        callback: impl Fn(&mut CpuState, u64, usize) -> Result<()> + Send + Sync + 'static,
    ) -> Result<HookId> {
        Ok(self.hooks.add_hook(
            hook_type,
            begin,
            end,
            Arc::new(callback),
        ))
    }
    
    pub fn hook_del(&mut self, id: HookId) -> Result<()> {
        if self.hooks.remove_hook(id) {
            Ok(())
        } else {
            Err(EmulatorError::InvalidArgument("Invalid hook ID".into()))
        }
    }
    
    pub fn emu_start(&mut self, begin: u64, until: u64, timeout: u64, count: usize) -> Result<()> {
        self.cpu.rip = begin;
        self.stop_requested.store(false, Ordering::SeqCst);
        self.instruction_count = 0;
        
        let start_time = std::time::Instant::now();
        let timeout_duration = if timeout > 0 {
            Some(std::time::Duration::from_micros(timeout))
        } else {
            None
        };
        
        loop {
            if self.stop_requested.load(Ordering::SeqCst) {
                break;
            }
            
            if self.cpu.rip >= until && until != 0 {
                break;
            }
            
            if count > 0 && self.instruction_count >= count as u64 {
                break;
            }
            
            if let Some(timeout) = timeout_duration {
                if start_time.elapsed() > timeout {
                    break;
                }
            }
            
            self.step()?;
        }
        
        Ok(())
    }
    
    pub fn emu_stop(&mut self) -> Result<()> {
        self.stop_requested.store(true, Ordering::SeqCst);
        Ok(())
    }
    
    pub fn set_trace(&mut self, enabled: bool) {
        self.trace_enabled = enabled;
    }
    
    fn step(&mut self) -> Result<()> {
        let rip = self.cpu.rip;
        
        self.memory.check_exec(rip)?;
        
        let mut inst_bytes = vec![0u8; 15];
        self.memory.read(rip, &mut inst_bytes)?;
        
        let inst = self.decoder.decode(&inst_bytes, rip)?;
        
        if self.trace_enabled {
            log::debug!("Executing at {:#x}: {:?}", rip, inst.opcode);
        }
        
        self.hooks.run_code_hooks(&mut self.cpu, rip, inst.size)?;
        
        self.cpu.rip = rip + inst.size as u64;
        
        self.execute_instruction(&inst)?;
        
        self.instruction_count += 1;
        
        Ok(())
    }
    
    fn execute_instruction(&mut self, inst: &Instruction) -> Result<()> {
        match inst.opcode {
            Opcode::MOV => self.execute_mov(inst),
            Opcode::ADD => self.execute_add(inst),
            Opcode::ADC => self.execute_adc(inst),
            Opcode::SUB => self.execute_sub(inst),
            Opcode::SBB => self.execute_sbb(inst),
            Opcode::XOR => self.execute_xor(inst),
            Opcode::AND => self.execute_and(inst),
            Opcode::OR => self.execute_or(inst),
            Opcode::CMP => self.execute_cmp(inst),
            Opcode::TEST => self.execute_test(inst),
            Opcode::PUSH => self.execute_push(inst),
            Opcode::POP => self.execute_pop(inst),
            Opcode::CALL => self.execute_call(inst),
            Opcode::RET => self.execute_ret(inst),
            Opcode::JMP => self.execute_jmp(inst),
            Opcode::JZ => self.execute_jcc(inst, self.cpu.rflags.contains(Flags::ZF)),
            Opcode::JNZ => self.execute_jcc(inst, !self.cpu.rflags.contains(Flags::ZF)),
            Opcode::JS => self.execute_jcc(inst, self.cpu.rflags.contains(Flags::SF)),
            Opcode::JNS => self.execute_jcc(inst, !self.cpu.rflags.contains(Flags::SF)),
            Opcode::JO => self.execute_jcc(inst, self.cpu.rflags.contains(Flags::OF)),
            Opcode::JNO => self.execute_jcc(inst, !self.cpu.rflags.contains(Flags::OF)),
            Opcode::JB => self.execute_jcc(inst, self.cpu.rflags.contains(Flags::CF)),
            Opcode::JAE => self.execute_jcc(inst, !self.cpu.rflags.contains(Flags::CF)),
            Opcode::INC => self.execute_inc(inst),
            Opcode::DEC => self.execute_dec(inst),
            Opcode::NEG => self.execute_neg(inst),
            Opcode::NOT => self.execute_not(inst),
            Opcode::SHL => self.execute_shl(inst),
            Opcode::SHR => self.execute_shr(inst),
            Opcode::SAR => self.execute_sar(inst),
            Opcode::LEA => self.execute_lea(inst),
            Opcode::ROL => self.execute_rol(inst),
            Opcode::ROR => self.execute_ror(inst),
            Opcode::XCHG => self.execute_xchg(inst),
            Opcode::XADD => self.execute_xadd(inst),
            Opcode::MUL => self.execute_mul(inst),
            Opcode::DIV => self.execute_div(inst),
            Opcode::IMUL => self.execute_imul(inst),
            Opcode::IDIV => self.execute_idiv(inst),
            Opcode::LOOP => self.execute_loop(inst),
            Opcode::LOOPE => self.execute_loope(inst),
            Opcode::LOOPNE => self.execute_loopne(inst),
            Opcode::MOVS => self.execute_movs(inst),
            Opcode::CMPS => self.execute_cmps(inst),
            Opcode::SCAS => self.execute_scas(inst),
            Opcode::STOS => self.execute_stos(inst),
            Opcode::LODS => self.execute_lods(inst),
            Opcode::REP | Opcode::REPZ | Opcode::REPNZ => {
                // REP prefixes are handled within the string instructions
                Err(EmulatorError::InvalidInstruction(inst.address))
            }
            Opcode::NOP => Ok(()),
            Opcode::HLT => {
                self.stop_requested.store(true, Ordering::SeqCst);
                Ok(())
            }
            Opcode::SYSCALL => self.execute_syscall(inst),
            Opcode::MOVAPS => self.execute_movaps(inst),
            Opcode::MOVUPS => self.execute_movups(inst),
            Opcode::ADDPS => self.execute_addps(inst),
            Opcode::SUBPS => self.execute_subps(inst),
            Opcode::MULPS => self.execute_mulps(inst),
            Opcode::DIVPS => self.execute_divps(inst),
            Opcode::XORPS => self.execute_xorps(inst),
            Opcode::ANDPS => self.execute_andps(inst),
            Opcode::ORPS => self.execute_orps(inst),
            Opcode::CMPPS => self.execute_cmpps(inst),
            Opcode::CMPSS => self.execute_cmpss(inst),
            Opcode::COMISS => self.execute_comiss(inst),
            Opcode::UCOMISS => self.execute_ucomiss(inst),
            _ => {
                self.hooks.run_invalid_hooks(&mut self.cpu, inst.address)?;
                Err(EmulatorError::UnsupportedInstruction(format!("{:?}", inst.opcode)))
            }
        }
    }
    
    fn execute_mov(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        
        let value = self.read_operand(&inst.operands[1])?;
        self.write_operand(&inst.operands[0], value)?;
        Ok(())
    }
    
    fn execute_add(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        
        let dst = self.read_operand(&inst.operands[0])?;
        let src = self.read_operand(&inst.operands[1])?;
        
        // Determine the operation size based on the destination operand
        let size = self.get_operand_size(&inst.operands[0]);
        
        // Mask values to the appropriate size
        let (dst_masked, src_masked, result) = match size {
            OperandSize::Byte => {
                let d = dst as u8;
                let s = src as u8;
                let r = d.wrapping_add(s);
                (d as u64, s as u64, r as u64)
            }
            OperandSize::Word => {
                let d = dst as u16;
                let s = src as u16;
                let r = d.wrapping_add(s);
                (d as u64, s as u64, r as u64)
            }
            OperandSize::DWord => {
                let d = dst as u32;
                let s = src as u32;
                let r = d.wrapping_add(s);
                (d as u64, s as u64, r as u64)
            }
            _ => {
                let result = dst.wrapping_add(src);
                (dst, src, result)
            }
        };
        
        self.update_flags_arithmetic_sized(dst_masked, src_masked, result, false, size);
        self.write_operand(&inst.operands[0], result)?;
        Ok(())
    }
    
    fn execute_sub(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        
        let dst = self.read_operand(&inst.operands[0])?;
        let src = self.read_operand(&inst.operands[1])?;
        
        // Determine the operation size based on the destination operand
        let size = self.get_operand_size(&inst.operands[0]);
        
        // Mask values to the appropriate size
        let (dst_masked, src_masked, result) = match size {
            OperandSize::Byte => {
                let d = dst as u8;
                let s = src as u8;
                let r = d.wrapping_sub(s);
                (d as u64, s as u64, r as u64)
            }
            OperandSize::Word => {
                let d = dst as u16;
                let s = src as u16;
                let r = d.wrapping_sub(s);
                (d as u64, s as u64, r as u64)
            }
            OperandSize::DWord => {
                let d = dst as u32;
                let s = src as u32;
                let r = d.wrapping_sub(s);
                (d as u64, s as u64, r as u64)
            }
            _ => {
                let result = dst.wrapping_sub(src);
                (dst, src, result)
            }
        };
        
        self.update_flags_arithmetic_sized(dst_masked, src_masked, result, true, size);
        self.write_operand(&inst.operands[0], result)?;
        Ok(())
    }
    
    fn execute_adc(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        
        let dst = self.read_operand(&inst.operands[0])?;
        let src = self.read_operand(&inst.operands[1])?;
        let carry = if self.cpu.rflags.contains(Flags::CF) { 1 } else { 0 };
        
        // Determine the operation size based on the destination operand
        let size = self.get_operand_size(&inst.operands[0]);
        
        // Perform the add with carry at the appropriate size
        let (dst_masked, src_masked, result) = match size {
            OperandSize::Byte => {
                let d = dst as u8;
                let s = src as u8;
                let c = carry as u8;
                let r = d.wrapping_add(s).wrapping_add(c);
                (d as u64, s as u64, r as u64)
            }
            OperandSize::Word => {
                let d = dst as u16;
                let s = src as u16;
                let c = carry as u16;
                let r = d.wrapping_add(s).wrapping_add(c);
                (d as u64, s as u64, r as u64)
            }
            OperandSize::DWord => {
                let d = dst as u32;
                let s = src as u32;
                let c = carry as u32;
                let r = d.wrapping_add(s).wrapping_add(c);
                (d as u64, s as u64, r as u64)
            }
            _ => {
                let result = dst.wrapping_add(src).wrapping_add(carry);
                (dst, src, result)
            }
        };
        
        // Update flags with consideration for the carry
        let intermediate = dst_masked.wrapping_add(src_masked);
        let (max_val, sign_bit) = match size {
            OperandSize::Byte => (0xFF_u64, 0x80_u64),
            OperandSize::Word => (0xFFFF_u64, 0x8000_u64),
            OperandSize::DWord => (0xFFFFFFFF_u64, 0x80000000_u64),
            _ => (u64::MAX, 0x8000000000000000_u64),
        };
        
        let result_masked = result & max_val;
        let carry_out = (intermediate > max_val) || ((intermediate & max_val) + carry > max_val);
        
        self.cpu.rflags.set(Flags::CF, carry_out);
        self.cpu.rflags.set(Flags::ZF, result_masked == 0);
        self.cpu.rflags.set(Flags::SF, (result_masked & sign_bit) != 0);
        
        // Overflow flag
        let dst_sign = (dst_masked & sign_bit) != 0;
        let src_sign = (src_masked & sign_bit) != 0;
        let res_sign = (result_masked & sign_bit) != 0;
        self.cpu.rflags.set(Flags::OF, dst_sign == src_sign && dst_sign != res_sign);
        
        // Parity flag
        let parity = (result_masked as u8).count_ones() % 2 == 0;
        self.cpu.rflags.set(Flags::PF, parity);
        
        self.write_operand(&inst.operands[0], result)?;
        Ok(())
    }
    
    fn execute_sbb(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        
        let dst = self.read_operand(&inst.operands[0])?;
        let src = self.read_operand(&inst.operands[1])?;
        let borrow = if self.cpu.rflags.contains(Flags::CF) { 1 } else { 0 };
        
        // Subtract with borrow: dst - src - CF
        let result = dst.wrapping_sub(src).wrapping_sub(borrow);
        
        // Update flags - need to check both subtractions for borrow
        let intermediate = dst.wrapping_sub(src);
        let borrow_out = (dst < src) || (intermediate < borrow);
        
        self.cpu.rflags.set(Flags::CF, borrow_out);
        self.cpu.rflags.set(Flags::ZF, result == 0);
        self.cpu.rflags.set(Flags::SF, (result as i64) < 0);
        
        // Overflow flag: sign change when subtracting values of different sign
        let dst_sign = (dst as i64) < 0;
        let src_sign = (src as i64) < 0;
        let result_sign = (result as i64) < 0;
        let overflow = (dst_sign != src_sign) && (dst_sign != result_sign);
        self.cpu.rflags.set(Flags::OF, overflow);
        
        // Parity flag
        let parity = (result as u8).count_ones() % 2 == 0;
        self.cpu.rflags.set(Flags::PF, parity);
        
        self.write_operand(&inst.operands[0], result)?;
        Ok(())
    }
    
    fn execute_xor(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        
        let dst = self.read_operand(&inst.operands[0])?;
        let src = self.read_operand(&inst.operands[1])?;
        let result = dst ^ src;
        
        self.update_flags_logical(result);
        self.write_operand(&inst.operands[0], result)?;
        Ok(())
    }
    
    fn execute_and(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        
        let dst = self.read_operand(&inst.operands[0])?;
        let src = self.read_operand(&inst.operands[1])?;
        let result = dst & src;
        
        self.update_flags_logical(result);
        self.write_operand(&inst.operands[0], result)?;
        Ok(())
    }
    
    fn execute_or(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        
        let dst = self.read_operand(&inst.operands[0])?;
        let src = self.read_operand(&inst.operands[1])?;
        let result = dst | src;
        
        self.update_flags_logical(result);
        self.write_operand(&inst.operands[0], result)?;
        Ok(())
    }
    
    fn execute_cmp(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        
        let dst = self.read_operand(&inst.operands[0])?;
        let src = self.read_operand(&inst.operands[1])?;
        let result = dst.wrapping_sub(src);
        
        self.update_flags_arithmetic(dst, src, result, true);
        Ok(())
    }
    
    fn execute_test(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        
        let dst = self.read_operand(&inst.operands[0])?;
        let src = self.read_operand(&inst.operands[1])?;
        let result = dst & src;
        
        self.update_flags_logical(result);
        Ok(())
    }
    
    fn execute_inc(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.is_empty() {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        
        let value = self.read_operand(&inst.operands[0])?;
        let result = value.wrapping_add(1);
        
        // INC doesn't affect CF flag, only other arithmetic flags
        let cf = self.cpu.rflags.contains(Flags::CF);
        self.update_flags_arithmetic(value, 1, result, false);
        self.cpu.rflags.set(Flags::CF, cf);
        
        self.write_operand(&inst.operands[0], result)?;
        Ok(())
    }
    
    fn execute_dec(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.is_empty() {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        
        let value = self.read_operand(&inst.operands[0])?;
        let result = value.wrapping_sub(1);
        
        // DEC doesn't affect CF flag, only other arithmetic flags
        let cf = self.cpu.rflags.contains(Flags::CF);
        self.update_flags_arithmetic(value, 1, result, true);
        self.cpu.rflags.set(Flags::CF, cf);
        
        self.write_operand(&inst.operands[0], result)?;
        Ok(())
    }
    
    fn execute_neg(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.is_empty() {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        
        let value = self.read_operand(&inst.operands[0])?;
        let result = 0u64.wrapping_sub(value);
        
        // NEG sets CF to 0 if operand is 0, otherwise 1
        self.cpu.rflags.set(Flags::CF, value != 0);
        
        // Update other arithmetic flags
        self.update_flags_arithmetic(0, value, result, true);
        
        self.write_operand(&inst.operands[0], result)?;
        Ok(())
    }
    
    fn execute_not(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.is_empty() {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        
        let value = self.read_operand(&inst.operands[0])?;
        let result = !value;
        
        // NOT doesn't affect any flags
        
        self.write_operand(&inst.operands[0], result)?;
        Ok(())
    }
    
    fn execute_shl(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() < 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        
        let value = self.read_operand(&inst.operands[0])?;
        let count = (self.read_operand(&inst.operands[1])? & 0x3F) as u32; // Mask to 6 bits for 64-bit mode
        
        if count == 0 {
            return Ok(());
        }
        
        let result = value.wrapping_shl(count);
        
        // Set CF to the last bit shifted out
        let last_bit_out = if count <= 64 {
            (value >> (64 - count)) & 1 != 0
        } else {
            false
        };
        self.cpu.rflags.set(Flags::CF, last_bit_out);
        
        // OF is set if the sign bit changed (only for count == 1)
        if count == 1 {
            let sign_changed = ((value >> 63) & 1) != ((result >> 63) & 1);
            self.cpu.rflags.set(Flags::OF, sign_changed);
        }
        
        // Update SF, ZF, PF based on result
        self.update_flags_logical(result);
        
        self.write_operand(&inst.operands[0], result)?;
        Ok(())
    }
    
    fn execute_shr(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() < 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        
        let value = self.read_operand(&inst.operands[0])?;
        let count = (self.read_operand(&inst.operands[1])? & 0x3F) as u32;
        
        if count == 0 {
            return Ok(());
        }
        
        let result = value.wrapping_shr(count);
        
        // Set CF to the last bit shifted out
        let last_bit_out = if count <= 64 {
            (value >> (count - 1)) & 1 != 0
        } else {
            false
        };
        self.cpu.rflags.set(Flags::CF, last_bit_out);
        
        // OF is set to the sign bit of the original value (only for count == 1)
        if count == 1 {
            self.cpu.rflags.set(Flags::OF, (value >> 63) & 1 != 0);
        }
        
        // Update SF, ZF, PF based on result
        self.update_flags_logical(result);
        
        self.write_operand(&inst.operands[0], result)?;
        Ok(())
    }
    
    fn execute_sar(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() < 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        
        let value = self.read_operand(&inst.operands[0])? as i64;
        let count = (self.read_operand(&inst.operands[1])? & 0x3F) as u32;
        
        if count == 0 {
            return Ok(());
        }
        
        let result = value.wrapping_shr(count) as u64;
        
        // Set CF to the last bit shifted out
        let last_bit_out = if count <= 64 {
            (value >> (count - 1)) & 1 != 0
        } else {
            // For SAR, if shifting more than 63, CF = sign bit
            value < 0
        };
        self.cpu.rflags.set(Flags::CF, last_bit_out);
        
        // OF is cleared for SAR with count == 1
        if count == 1 {
            self.cpu.rflags.set(Flags::OF, false);
        }
        
        // Update SF, ZF, PF based on result
        self.update_flags_logical(result);
        
        self.write_operand(&inst.operands[0], result)?;
        Ok(())
    }
    
    fn execute_lea(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() < 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        
        // LEA loads the effective address, not the value at that address
        // First operand must be a register, second must be memory
        let dest = match &inst.operands[0] {
            Operand::Register(reg) => *reg,
            _ => return Err(EmulatorError::InvalidInstruction(inst.address)),
        };
        
        let address = match &inst.operands[1] {
            Operand::Memory { base, index, scale, displacement, .. } => {
                let mut addr = *displacement as u64;
                
                if let Some(base_reg) = base {
                    addr = addr.wrapping_add(self.cpu.read_reg(*base_reg));
                }
                
                if let Some(index_reg) = index {
                    let index_val = self.cpu.read_reg(*index_reg);
                    addr = addr.wrapping_add(index_val.wrapping_mul(*scale as u64));
                }
                
                addr
            }
            _ => return Err(EmulatorError::InvalidInstruction(inst.address)),
        };
        
        // LEA doesn't affect any flags
        self.cpu.write_reg(dest, address);
        Ok(())
    }
    
    fn execute_rol(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() < 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        
        let value = self.read_operand(&inst.operands[0])?;
        let count = (self.read_operand(&inst.operands[1])? & 0x3F) as u32;
        
        if count == 0 {
            return Ok(());
        }
        
        // Rotate left: bits shifted out on the left are rotated back in on the right
        let actual_count = count % 64;
        let result = value.rotate_left(actual_count);
        
        // CF gets the last bit rotated out (which is now the LSB)
        self.cpu.rflags.set(Flags::CF, result & 1 != 0);
        
        // OF is set if sign bit changed (only for count == 1)
        if count == 1 {
            let sign_changed = ((value >> 63) & 1) != ((result >> 63) & 1);
            self.cpu.rflags.set(Flags::OF, sign_changed);
        }
        
        self.write_operand(&inst.operands[0], result)?;
        Ok(())
    }
    
    fn execute_ror(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() < 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        
        let value = self.read_operand(&inst.operands[0])?;
        let count = (self.read_operand(&inst.operands[1])? & 0x3F) as u32;
        
        if count == 0 {
            return Ok(());
        }
        
        // Rotate right: bits shifted out on the right are rotated back in on the left
        let actual_count = count % 64;
        let result = value.rotate_right(actual_count);
        
        // CF gets the last bit rotated out (which is now the MSB)
        self.cpu.rflags.set(Flags::CF, (result >> 63) & 1 != 0);
        
        // OF is set based on the two most significant bits (only for count == 1)
        if count == 1 {
            let msb = (result >> 63) & 1;
            let next_msb = (result >> 62) & 1;
            self.cpu.rflags.set(Flags::OF, msb != next_msb);
        }
        
        self.write_operand(&inst.operands[0], result)?;
        Ok(())
    }
    
    fn execute_xchg(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() < 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        
        // Read both values
        let value1 = self.read_operand(&inst.operands[0])?;
        let value2 = self.read_operand(&inst.operands[1])?;
        
        // Exchange them
        self.write_operand(&inst.operands[0], value2)?;
        self.write_operand(&inst.operands[1], value1)?;
        
        // XCHG doesn't affect any flags
        Ok(())
    }
    
    fn execute_xadd(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        
        // XADD: Exchange and Add
        // Exchanges the destination and source operands, then adds the original source value to the destination
        let dst = self.read_operand(&inst.operands[0])?;
        let src = self.read_operand(&inst.operands[1])?;
        
        // Store original destination in source
        self.write_operand(&inst.operands[1], dst)?;
        
        // Add original source to original destination and store in destination
        let result = dst.wrapping_add(src);
        self.write_operand(&inst.operands[0], result)?;
        
        // Update flags based on the addition result
        self.update_flags_arithmetic(dst, src, result, false);
        
        Ok(())
    }
    
    fn execute_mul(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.is_empty() {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        
        // MUL performs unsigned multiplication
        // For 64-bit operand: RDX:RAX = RAX * operand
        let multiplicand = self.cpu.read_reg(Register::RAX);
        let multiplier = self.read_operand(&inst.operands[0])?;
        
        let result = (multiplicand as u128) * (multiplier as u128);
        
        // Store low 64 bits in RAX, high 64 bits in RDX
        self.cpu.write_reg(Register::RAX, result as u64);
        self.cpu.write_reg(Register::RDX, (result >> 64) as u64);
        
        // Set CF and OF if upper half is non-zero
        let overflow = (result >> 64) != 0;
        self.cpu.rflags.set(Flags::CF, overflow);
        self.cpu.rflags.set(Flags::OF, overflow);
        
        // SF, ZF, AF, and PF are undefined after MUL
        
        Ok(())
    }
    
    fn execute_div(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.is_empty() {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        
        // DIV performs unsigned division
        // For 64-bit operand: Quotient = RDX:RAX / operand -> RAX
        //                     Remainder = RDX:RAX % operand -> RDX
        let dividend_low = self.cpu.read_reg(Register::RAX);
        let dividend_high = self.cpu.read_reg(Register::RDX);
        let dividend = ((dividend_high as u128) << 64) | (dividend_low as u128);
        let divisor = self.read_operand(&inst.operands[0])? as u128;
        
        if divisor == 0 {
            // Division by zero - should trigger exception
            return Err(EmulatorError::DivisionByZero);
        }
        
        let quotient = dividend / divisor;
        let remainder = dividend % divisor;
        
        // Check for quotient overflow
        if quotient > u64::MAX as u128 {
            return Err(EmulatorError::DivisionOverflow);
        }
        
        self.cpu.write_reg(Register::RAX, quotient as u64);
        self.cpu.write_reg(Register::RDX, remainder as u64);
        
        // All flags are undefined after DIV
        
        Ok(())
    }
    
    fn execute_imul(&mut self, inst: &Instruction) -> Result<()> {
        // IMUL has multiple forms, for now implement single operand form
        if inst.operands.is_empty() {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        
        // Single operand form: RDX:RAX = RAX * operand (signed)
        let multiplicand = self.cpu.read_reg(Register::RAX) as i64;
        let multiplier = self.read_operand(&inst.operands[0])? as i64;
        
        let result = (multiplicand as i128) * (multiplier as i128);
        
        // Store low 64 bits in RAX, high 64 bits in RDX
        self.cpu.write_reg(Register::RAX, result as u64);
        self.cpu.write_reg(Register::RDX, (result >> 64) as u64);
        
        // Set CF and OF if result doesn't fit in 64 bits (signed)
        let sign_extended = (result as i64) as i128;
        let overflow = result != sign_extended;
        self.cpu.rflags.set(Flags::CF, overflow);
        self.cpu.rflags.set(Flags::OF, overflow);
        
        Ok(())
    }
    
    fn execute_idiv(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.is_empty() {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        
        // IDIV performs signed division
        let dividend_low = self.cpu.read_reg(Register::RAX) as i64;
        let dividend_high = self.cpu.read_reg(Register::RDX) as i64;
        let dividend = ((dividend_high as i128) << 64) | (dividend_low as u64 as i128);
        let divisor = self.read_operand(&inst.operands[0])? as i64 as i128;
        
        if divisor == 0 {
            return Err(EmulatorError::DivisionByZero);
        }
        
        let quotient = dividend / divisor;
        let remainder = dividend % divisor;
        
        // Check for quotient overflow
        if quotient > i64::MAX as i128 || quotient < i64::MIN as i128 {
            return Err(EmulatorError::DivisionOverflow);
        }
        
        self.cpu.write_reg(Register::RAX, quotient as u64);
        self.cpu.write_reg(Register::RDX, remainder as u64);
        
        Ok(())
    }
    
    fn execute_push(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.is_empty() {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        
        let value = self.read_operand(&inst.operands[0])?;
        let rsp = self.cpu.read_reg(Register::RSP);
        let new_rsp = rsp.wrapping_sub(8);
        self.cpu.write_reg(Register::RSP, new_rsp);
        self.memory.write_u64(new_rsp, value)?;
        Ok(())
    }
    
    fn execute_pop(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.is_empty() {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        
        let rsp = self.cpu.read_reg(Register::RSP);
        let value = self.memory.read_u64(rsp)?;
        self.write_operand(&inst.operands[0], value)?;
        self.cpu.write_reg(Register::RSP, rsp.wrapping_add(8));
        Ok(())
    }
    
    fn execute_call(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.is_empty() {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        
        let rsp = self.cpu.read_reg(Register::RSP);
        let new_rsp = rsp.wrapping_sub(8);
        self.cpu.write_reg(Register::RSP, new_rsp);
        self.memory.write_u64(new_rsp, self.cpu.rip)?;
        
        match &inst.operands[0] {
            Operand::Relative(offset) => {
                self.cpu.rip = (self.cpu.rip as i64 + offset) as u64;
            }
            _ => {
                let target = self.read_operand(&inst.operands[0])?;
                self.cpu.rip = target;
            }
        }
        Ok(())
    }
    
    fn execute_ret(&mut self, _inst: &Instruction) -> Result<()> {
        let rsp = self.cpu.read_reg(Register::RSP);
        let return_addr = self.memory.read_u64(rsp)?;
        self.cpu.write_reg(Register::RSP, rsp.wrapping_add(8));
        self.cpu.rip = return_addr;
        Ok(())
    }
    
    fn execute_jmp(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.is_empty() {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        
        match &inst.operands[0] {
            Operand::Relative(offset) => {
                self.cpu.rip = (self.cpu.rip as i64 + offset) as u64;
            }
            _ => {
                let target = self.read_operand(&inst.operands[0])?;
                self.cpu.rip = target;
            }
        }
        Ok(())
    }
    
    fn execute_jcc(&mut self, inst: &Instruction, condition: bool) -> Result<()> {
        if condition {
            self.execute_jmp(inst)?;
        }
        Ok(())
    }
    
    fn execute_syscall(&mut self, _inst: &Instruction) -> Result<()> {
        self.hooks.run_interrupt_hooks(&mut self.cpu, 0x80)?;
        Ok(())
    }
    
    fn execute_loop(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.is_empty() {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        
        // Decrement RCX (treating it as unsigned)
        let count = self.cpu.read_reg(Register::RCX);
        let new_count = count.wrapping_sub(1);
        self.cpu.write_reg(Register::RCX, new_count);
        
        // Jump if new_count != 0 (after decrement)
        if new_count != 0 {
            match &inst.operands[0] {
                Operand::Relative(offset) => {
                    self.cpu.rip = (self.cpu.rip as i64 + offset) as u64;
                }
                _ => return Err(EmulatorError::InvalidInstruction(inst.address)),
            }
        }
        
        Ok(())
    }
    
    fn execute_loope(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.is_empty() {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        
        // Decrement RCX (treating it as unsigned)
        let count = self.cpu.read_reg(Register::RCX);
        let new_count = count.wrapping_sub(1);
        self.cpu.write_reg(Register::RCX, new_count);
        
        // Jump if new_count != 0 AND ZF = 1
        if new_count != 0 && self.cpu.rflags.contains(Flags::ZF) {
            match &inst.operands[0] {
                Operand::Relative(offset) => {
                    self.cpu.rip = (self.cpu.rip as i64 + offset) as u64;
                }
                _ => return Err(EmulatorError::InvalidInstruction(inst.address)),
            }
        }
        
        Ok(())
    }
    
    fn execute_loopne(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.is_empty() {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        
        // Decrement RCX (treating it as unsigned)
        let count = self.cpu.read_reg(Register::RCX);
        let new_count = count.wrapping_sub(1);
        self.cpu.write_reg(Register::RCX, new_count);
        
        // Jump if new_count != 0 AND ZF = 0
        if new_count != 0 && !self.cpu.rflags.contains(Flags::ZF) {
            match &inst.operands[0] {
                Operand::Relative(offset) => {
                    self.cpu.rip = (self.cpu.rip as i64 + offset) as u64;
                }
                _ => return Err(EmulatorError::InvalidInstruction(inst.address)),
            }
        }
        
        Ok(())
    }
    
    fn execute_movs(&mut self, inst: &Instruction) -> Result<()> {
        // Determine operand size from the size indicator operand
        let size = if let Some(Operand::Immediate(1)) = inst.operands.get(0) {
            OperandSize::Byte
        } else {
            inst.operand_size
        };
        
        // Check if there's a REP prefix
        let has_rep = inst.prefix.rep.is_some();
        
        if has_rep {
            let count = self.cpu.read_reg(Register::RCX);
            if count == 0 {
                return Ok(());
            }
            
            for _ in 0..count {
                self.movs_single(size)?;
            }
            self.cpu.write_reg(Register::RCX, 0);
        } else {
            self.movs_single(size)?;
        }
        
        Ok(())
    }
    
    fn movs_single(&mut self, size: OperandSize) -> Result<()> {
        let rsi = self.cpu.read_reg(Register::RSI);
        let rdi = self.cpu.read_reg(Register::RDI);
        
        // Read from [RSI]
        let value = match size {
            OperandSize::Byte => self.memory.read_u8(rsi)? as u64,
            OperandSize::Word => self.memory.read_u16(rsi)? as u64,
            OperandSize::DWord => self.memory.read_u32(rsi)? as u64,
            OperandSize::QWord => self.memory.read_u64(rsi)?,
            OperandSize::XmmWord => return Err(EmulatorError::InvalidOperand),
        };
        
        // Write to [RDI]
        match size {
            OperandSize::Byte => self.memory.write_u8(rdi, value as u8)?,
            OperandSize::Word => self.memory.write_u16(rdi, value as u16)?,
            OperandSize::DWord => self.memory.write_u32(rdi, value as u32)?,
            OperandSize::QWord => self.memory.write_u64(rdi, value)?,
            OperandSize::XmmWord => return Err(EmulatorError::InvalidOperand),
        };
        
        // Update RSI and RDI based on direction flag
        let increment = size.bytes() as u64;
        if self.cpu.rflags.contains(Flags::DF) {
            self.cpu.write_reg(Register::RSI, rsi.wrapping_sub(increment));
            self.cpu.write_reg(Register::RDI, rdi.wrapping_sub(increment));
        } else {
            self.cpu.write_reg(Register::RSI, rsi.wrapping_add(increment));
            self.cpu.write_reg(Register::RDI, rdi.wrapping_add(increment));
        }
        
        Ok(())
    }
    
    fn execute_cmps(&mut self, inst: &Instruction) -> Result<()> {
        // Determine operand size from the size indicator operand
        let size = if let Some(Operand::Immediate(1)) = inst.operands.get(0) {
            OperandSize::Byte
        } else {
            inst.operand_size
        };
        
        // Check if there's a REP prefix
        match inst.prefix.rep {
            Some(crate::decoder::RepPrefix::RepZ) => {
                let count = self.cpu.read_reg(Register::RCX);
                if count == 0 {
                    return Ok(());
                }
                
                for i in 0..count {
                    self.cmps_single(size)?;
                    let new_count = count - i - 1;
                    self.cpu.write_reg(Register::RCX, new_count);
                    
                    // Continue while ZF=1 (equal)
                    if !self.cpu.rflags.contains(Flags::ZF) {
                        break;
                    }
                }
            }
            Some(crate::decoder::RepPrefix::RepNZ) => {
                let count = self.cpu.read_reg(Register::RCX);
                if count == 0 {
                    return Ok(());
                }
                
                for i in 0..count {
                    self.cmps_single(size)?;
                    let new_count = count - i - 1;
                    self.cpu.write_reg(Register::RCX, new_count);
                    
                    // Continue while ZF=0 (not equal)
                    if self.cpu.rflags.contains(Flags::ZF) {
                        break;
                    }
                }
            }
            _ => self.cmps_single(size)?,
        }
        
        Ok(())
    }
    
    fn cmps_single(&mut self, size: OperandSize) -> Result<()> {
        let rsi = self.cpu.read_reg(Register::RSI);
        let rdi = self.cpu.read_reg(Register::RDI);
        
        // Read from [RSI] and [RDI]
        let src1 = match size {
            OperandSize::Byte => self.memory.read_u8(rsi)? as u64,
            OperandSize::Word => self.memory.read_u16(rsi)? as u64,
            OperandSize::DWord => self.memory.read_u32(rsi)? as u64,
            OperandSize::QWord => self.memory.read_u64(rsi)?,
            OperandSize::XmmWord => return Err(EmulatorError::InvalidOperand),
        };
        
        let src2 = match size {
            OperandSize::Byte => self.memory.read_u8(rdi)? as u64,
            OperandSize::Word => self.memory.read_u16(rdi)? as u64,
            OperandSize::DWord => self.memory.read_u32(rdi)? as u64,
            OperandSize::QWord => self.memory.read_u64(rdi)?,
            OperandSize::XmmWord => return Err(EmulatorError::InvalidOperand),
        };
        
        // Compare src1 - src2
        let result = src1.wrapping_sub(src2);
        self.update_flags_arithmetic(src1, src2, result, true);
        
        // Update RSI and RDI based on direction flag
        let increment = size.bytes() as u64;
        if self.cpu.rflags.contains(Flags::DF) {
            self.cpu.write_reg(Register::RSI, rsi.wrapping_sub(increment));
            self.cpu.write_reg(Register::RDI, rdi.wrapping_sub(increment));
        } else {
            self.cpu.write_reg(Register::RSI, rsi.wrapping_add(increment));
            self.cpu.write_reg(Register::RDI, rdi.wrapping_add(increment));
        }
        
        Ok(())
    }
    
    fn execute_scas(&mut self, inst: &Instruction) -> Result<()> {
        // Determine operand size from the size indicator operand
        let size = if let Some(Operand::Immediate(1)) = inst.operands.get(0) {
            OperandSize::Byte
        } else {
            inst.operand_size
        };
        
        // Check if there's a REP prefix
        match inst.prefix.rep {
            Some(crate::decoder::RepPrefix::RepZ) => {
                let count = self.cpu.read_reg(Register::RCX);
                if count == 0 {
                    return Ok(());
                }
                
                for i in 0..count {
                    self.scas_single(size)?;
                    let new_count = count - i - 1;
                    self.cpu.write_reg(Register::RCX, new_count);
                    
                    // Continue while ZF=1 (equal)
                    if !self.cpu.rflags.contains(Flags::ZF) {
                        break;
                    }
                }
            }
            Some(crate::decoder::RepPrefix::RepNZ) => {
                let count = self.cpu.read_reg(Register::RCX);
                if count == 0 {
                    return Ok(());
                }
                
                for i in 0..count {
                    self.scas_single(size)?;
                    let new_count = count - i - 1;
                    self.cpu.write_reg(Register::RCX, new_count);
                    
                    // Continue while ZF=0 (not equal)
                    if self.cpu.rflags.contains(Flags::ZF) {
                        break;
                    }
                }
            }
            _ => self.scas_single(size)?,
        }
        
        Ok(())
    }
    
    fn scas_single(&mut self, size: OperandSize) -> Result<()> {
        let rdi = self.cpu.read_reg(Register::RDI);
        
        // Get accumulator value
        let acc = match size {
            OperandSize::Byte => self.cpu.read_reg(Register::AL),
            OperandSize::Word => self.cpu.read_reg(Register::AX),
            OperandSize::DWord => self.cpu.read_reg(Register::EAX),
            OperandSize::QWord => self.cpu.read_reg(Register::RAX),
            OperandSize::XmmWord => return Err(EmulatorError::InvalidOperand),
        };
        
        // Read from [RDI]
        let mem_value = match size {
            OperandSize::Byte => self.memory.read_u8(rdi)? as u64,
            OperandSize::Word => self.memory.read_u16(rdi)? as u64,
            OperandSize::DWord => self.memory.read_u32(rdi)? as u64,
            OperandSize::QWord => self.memory.read_u64(rdi)?,
            OperandSize::XmmWord => return Err(EmulatorError::InvalidOperand),
        };
        
        // Compare accumulator - memory
        let result = acc.wrapping_sub(mem_value);
        self.update_flags_arithmetic(acc, mem_value, result, true);
        
        // Update RDI based on direction flag
        let increment = size.bytes() as u64;
        if self.cpu.rflags.contains(Flags::DF) {
            self.cpu.write_reg(Register::RDI, rdi.wrapping_sub(increment));
        } else {
            self.cpu.write_reg(Register::RDI, rdi.wrapping_add(increment));
        }
        
        Ok(())
    }
    
    fn execute_stos(&mut self, inst: &Instruction) -> Result<()> {
        // Determine operand size from the size indicator operand
        let size = if let Some(Operand::Immediate(1)) = inst.operands.get(0) {
            OperandSize::Byte
        } else {
            inst.operand_size
        };
        
        // Check if there's a REP prefix
        let has_rep = inst.prefix.rep.is_some();
        
        if has_rep {
            let count = self.cpu.read_reg(Register::RCX);
            if count == 0 {
                return Ok(());
            }
            
            for _ in 0..count {
                self.stos_single(size)?;
            }
            self.cpu.write_reg(Register::RCX, 0);
        } else {
            self.stos_single(size)?;
        }
        
        Ok(())
    }
    
    fn stos_single(&mut self, size: OperandSize) -> Result<()> {
        let rdi = self.cpu.read_reg(Register::RDI);
        
        // Get accumulator value
        let acc = match size {
            OperandSize::Byte => self.cpu.read_reg(Register::AL),
            OperandSize::Word => self.cpu.read_reg(Register::AX),
            OperandSize::DWord => self.cpu.read_reg(Register::EAX),
            OperandSize::QWord => self.cpu.read_reg(Register::RAX),
            OperandSize::XmmWord => return Err(EmulatorError::InvalidOperand),
        };
        
        // Write to [RDI]
        match size {
            OperandSize::Byte => self.memory.write_u8(rdi, acc as u8)?,
            OperandSize::Word => self.memory.write_u16(rdi, acc as u16)?,
            OperandSize::DWord => self.memory.write_u32(rdi, acc as u32)?,
            OperandSize::QWord => self.memory.write_u64(rdi, acc)?,
            OperandSize::XmmWord => return Err(EmulatorError::InvalidOperand),
        };
        
        // Update RDI based on direction flag
        let increment = size.bytes() as u64;
        if self.cpu.rflags.contains(Flags::DF) {
            self.cpu.write_reg(Register::RDI, rdi.wrapping_sub(increment));
        } else {
            self.cpu.write_reg(Register::RDI, rdi.wrapping_add(increment));
        }
        
        Ok(())
    }
    
    fn execute_lods(&mut self, inst: &Instruction) -> Result<()> {
        // Determine operand size from the size indicator operand
        let size = if let Some(Operand::Immediate(1)) = inst.operands.get(0) {
            OperandSize::Byte
        } else {
            inst.operand_size
        };
        
        // Check if there's a REP prefix (rarely used with LODS)
        let has_rep = inst.prefix.rep.is_some();
        
        if has_rep {
            let count = self.cpu.read_reg(Register::RCX);
            if count == 0 {
                return Ok(());
            }
            
            for _ in 0..count {
                self.lods_single(size)?;
            }
            self.cpu.write_reg(Register::RCX, 0);
        } else {
            self.lods_single(size)?;
        }
        
        Ok(())
    }
    
    fn lods_single(&mut self, size: OperandSize) -> Result<()> {
        let rsi = self.cpu.read_reg(Register::RSI);
        
        // Read from [RSI]
        let value = match size {
            OperandSize::Byte => self.memory.read_u8(rsi)? as u64,
            OperandSize::Word => self.memory.read_u16(rsi)? as u64,
            OperandSize::DWord => self.memory.read_u32(rsi)? as u64,
            OperandSize::QWord => self.memory.read_u64(rsi)?,
            OperandSize::XmmWord => return Err(EmulatorError::InvalidOperand),
        };
        
        // Store in accumulator
        match size {
            OperandSize::Byte => self.cpu.write_reg(Register::AL, value),
            OperandSize::Word => self.cpu.write_reg(Register::AX, value),
            OperandSize::DWord => self.cpu.write_reg(Register::EAX, value),
            OperandSize::QWord => self.cpu.write_reg(Register::RAX, value),
            OperandSize::XmmWord => return Err(EmulatorError::InvalidOperand),
        };
        
        // Update RSI based on direction flag
        let increment = size.bytes() as u64;
        if self.cpu.rflags.contains(Flags::DF) {
            self.cpu.write_reg(Register::RSI, rsi.wrapping_sub(increment));
        } else {
            self.cpu.write_reg(Register::RSI, rsi.wrapping_add(increment));
        }
        
        Ok(())
    }
    
    fn read_operand(&mut self, operand: &Operand) -> Result<u64> {
        match operand {
            Operand::Register(reg) => Ok(self.cpu.read_reg(*reg)),
            Operand::Immediate(val) => Ok(*val as u64),
            Operand::Memory { base, index, scale, displacement, size } => {
                let mut addr = *displacement as u64;
                if let Some(base_reg) = base {
                    addr = addr.wrapping_add(self.cpu.read_reg(*base_reg));
                }
                if let Some(index_reg) = index {
                    addr = addr.wrapping_add(self.cpu.read_reg(*index_reg) * (*scale as u64));
                }
                
                match size {
                    OperandSize::Byte => self.memory.read_u8(addr).map(|v| v as u64),
                    OperandSize::Word => self.memory.read_u16(addr).map(|v| v as u64),
                    OperandSize::DWord => self.memory.read_u32(addr).map(|v| v as u64),
                    OperandSize::QWord => self.memory.read_u64(addr),
                    OperandSize::XmmWord => Err(EmulatorError::InvalidOperand),
                }
            }
            Operand::Relative(offset) => Ok((self.cpu.rip as i64 + offset) as u64),
        }
    }
    
    fn write_operand(&mut self, operand: &Operand, value: u64) -> Result<()> {
        match operand {
            Operand::Register(reg) => {
                self.cpu.write_reg(*reg, value);
                Ok(())
            }
            Operand::Memory { base, index, scale, displacement, size } => {
                let mut addr = *displacement as u64;
                if let Some(base_reg) = base {
                    addr = addr.wrapping_add(self.cpu.read_reg(*base_reg));
                }
                if let Some(index_reg) = index {
                    addr = addr.wrapping_add(self.cpu.read_reg(*index_reg) * (*scale as u64));
                }
                
                match size {
                    OperandSize::Byte => self.memory.write_u8(addr, value as u8),
                    OperandSize::Word => self.memory.write_u16(addr, value as u16),
                    OperandSize::DWord => self.memory.write_u32(addr, value as u32),
                    OperandSize::QWord => self.memory.write_u64(addr, value),
                    OperandSize::XmmWord => Err(EmulatorError::InvalidOperand),
                }
            }
            _ => Err(EmulatorError::InvalidInstruction(0)),
        }
    }
    
    fn update_flags_arithmetic(&mut self, dst: u64, src: u64, result: u64, is_sub: bool) {
        self.cpu.rflags.set(Flags::ZF, result == 0);
        self.cpu.rflags.set(Flags::SF, (result as i64) < 0);
        
        if is_sub {
            self.cpu.rflags.set(Flags::CF, dst < src);
            let dst_sign = (dst as i64) < 0;
            let src_sign = (src as i64) < 0;
            let res_sign = (result as i64) < 0;
            self.cpu.rflags.set(Flags::OF, dst_sign != src_sign && dst_sign != res_sign);
        } else {
            self.cpu.rflags.set(Flags::CF, result < dst);
            let dst_sign = (dst as i64) < 0;
            let src_sign = (src as i64) < 0;
            let res_sign = (result as i64) < 0;
            self.cpu.rflags.set(Flags::OF, dst_sign == src_sign && dst_sign != res_sign);
        }
        
        let parity = (result as u8).count_ones() % 2 == 0;
        self.cpu.rflags.set(Flags::PF, parity);
    }
    
    fn update_flags_logical(&mut self, result: u64) {
        self.cpu.rflags.set(Flags::ZF, result == 0);
        self.cpu.rflags.set(Flags::SF, (result as i64) < 0);
        self.cpu.rflags.set(Flags::CF, false);
        self.cpu.rflags.set(Flags::OF, false);
        
        let parity = (result as u8).count_ones() % 2 == 0;
        self.cpu.rflags.set(Flags::PF, parity);
    }
    
    pub fn context_save(&self) -> CpuState {
        self.cpu.clone()
    }
    
    pub fn context_restore(&mut self, state: &CpuState) {
        self.cpu = state.clone();
    }
    
    pub fn xmm_read(&self, reg: Register) -> Result<u128> {
        Ok(self.cpu.read_xmm(reg))
    }
    
    pub fn xmm_write(&mut self, reg: Register, value: u128) -> Result<()> {
        self.cpu.write_xmm(reg, value);
        Ok(())
    }
    
    fn calculate_address(
        &self,
        base: Option<Register>,
        index: Option<Register>,
        scale: u8,
        displacement: i64,
    ) -> Result<u64> {
        let mut addr = displacement as u64;
        if let Some(base_reg) = base {
            addr = addr.wrapping_add(self.cpu.read_reg(base_reg));
        }
        if let Some(index_reg) = index {
            addr = addr.wrapping_add(self.cpu.read_reg(index_reg) * (scale as u64));
        }
        Ok(addr)
    }
    
    fn read_xmm_operand(&self, operand: &Operand) -> Result<u128> {
        match operand {
            Operand::Register(reg) => Ok(self.cpu.read_xmm(*reg)),
            Operand::Memory { base, index, scale, displacement, size } => {
                if *size != OperandSize::XmmWord {
                    return Err(EmulatorError::InvalidOperand);
                }
                let address = self.calculate_address(*base, *index, *scale, *displacement)?;
                let mut bytes = [0u8; 16];
                self.memory.read(address, &mut bytes)?;
                Ok(u128::from_le_bytes(bytes))
            }
            _ => Err(EmulatorError::InvalidOperand),
        }
    }
    
    fn write_xmm_operand(&mut self, operand: &Operand, value: u128) -> Result<()> {
        match operand {
            Operand::Register(reg) => {
                self.cpu.write_xmm(*reg, value);
                Ok(())
            }
            Operand::Memory { base, index, scale, displacement, size } => {
                if *size != OperandSize::XmmWord {
                    return Err(EmulatorError::InvalidOperand);
                }
                let address = self.calculate_address(*base, *index, *scale, *displacement)?;
                let bytes = value.to_le_bytes();
                self.memory.write(address, &bytes)?;
                Ok(())
            }
            _ => Err(EmulatorError::InvalidOperand),
        }
    }
    
    fn execute_movaps(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        let value = self.read_xmm_operand(&inst.operands[1])?;
        self.write_xmm_operand(&inst.operands[0], value)?;
        Ok(())
    }
    
    fn execute_movups(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        let value = self.read_xmm_operand(&inst.operands[1])?;
        self.write_xmm_operand(&inst.operands[0], value)?;
        Ok(())
    }
    
    fn execute_addps(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        let src = self.read_xmm_operand(&inst.operands[1])?;
        let dst = self.read_xmm_operand(&inst.operands[0])?;
        
        let result = self.simd_add_ps(dst, src);
        self.write_xmm_operand(&inst.operands[0], result)?;
        Ok(())
    }
    
    fn execute_subps(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        let src = self.read_xmm_operand(&inst.operands[1])?;
        let dst = self.read_xmm_operand(&inst.operands[0])?;
        
        let result = self.simd_sub_ps(dst, src);
        self.write_xmm_operand(&inst.operands[0], result)?;
        Ok(())
    }
    
    fn execute_mulps(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        let src = self.read_xmm_operand(&inst.operands[1])?;
        let dst = self.read_xmm_operand(&inst.operands[0])?;
        
        let result = self.simd_mul_ps(dst, src);
        self.write_xmm_operand(&inst.operands[0], result)?;
        Ok(())
    }
    
    fn execute_divps(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        let src = self.read_xmm_operand(&inst.operands[1])?;
        let dst = self.read_xmm_operand(&inst.operands[0])?;
        
        let result = self.simd_div_ps(dst, src);
        self.write_xmm_operand(&inst.operands[0], result)?;
        Ok(())
    }
    
    fn execute_xorps(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        let src = self.read_xmm_operand(&inst.operands[1])?;
        let dst = self.read_xmm_operand(&inst.operands[0])?;
        
        let result = dst ^ src;
        self.write_xmm_operand(&inst.operands[0], result)?;
        Ok(())
    }
    
    fn execute_andps(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        let src = self.read_xmm_operand(&inst.operands[1])?;
        let dst = self.read_xmm_operand(&inst.operands[0])?;
        
        let result = dst & src;
        self.write_xmm_operand(&inst.operands[0], result)?;
        Ok(())
    }
    
    fn execute_orps(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        let src = self.read_xmm_operand(&inst.operands[1])?;
        let dst = self.read_xmm_operand(&inst.operands[0])?;
        
        let result = dst | src;
        self.write_xmm_operand(&inst.operands[0], result)?;
        Ok(())
    }
    
    fn execute_cmpps(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() != 3 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        
        let dst = self.read_xmm_operand(&inst.operands[0])?;
        let src = self.read_xmm_operand(&inst.operands[1])?;
        let imm = match &inst.operands[2] {
            Operand::Immediate(imm) => *imm as u8,
            _ => return Err(EmulatorError::InvalidOperand),
        };
        
        let result = self.simd_cmp_ps(dst, src, imm);
        self.write_xmm_operand(&inst.operands[0], result)?;
        Ok(())
    }
    
    fn execute_cmpss(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() != 3 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        
        let mut dst = self.read_xmm_operand(&inst.operands[0])?;
        let src = self.read_xmm_operand(&inst.operands[1])?;
        let imm = match &inst.operands[2] {
            Operand::Immediate(imm) => *imm as u8,
            _ => return Err(EmulatorError::InvalidOperand),
        };
        
        // Only compare and update the lowest 32 bits
        let dst_float = f32::from_bits((dst & 0xFFFFFFFF) as u32);
        let src_float = f32::from_bits((src & 0xFFFFFFFF) as u32);
        let result = self.compare_scalar_ps(dst_float, src_float, imm);
        
        // Clear lower 32 bits and set result
        dst = (dst & !0xFFFFFFFF) | (result as u128);
        self.write_xmm_operand(&inst.operands[0], dst)?;
        Ok(())
    }
    
    fn execute_comiss(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        
        let dst = self.read_xmm_operand(&inst.operands[0])?;
        let src = self.read_xmm_operand(&inst.operands[1])?;
        
        // Extract lowest 32-bit floats
        let dst_float = f32::from_bits((dst & 0xFFFFFFFF) as u32);
        let src_float = f32::from_bits((src & 0xFFFFFFFF) as u32);
        
        // Update EFLAGS based on comparison
        self.update_flags_comiss(dst_float, src_float);
        Ok(())
    }
    
    fn execute_ucomiss(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        
        let dst = self.read_xmm_operand(&inst.operands[0])?;
        let src = self.read_xmm_operand(&inst.operands[1])?;
        
        // Extract lowest 32-bit floats
        let dst_float = f32::from_bits((dst & 0xFFFFFFFF) as u32);
        let src_float = f32::from_bits((src & 0xFFFFFFFF) as u32);
        
        // Update EFLAGS based on unordered comparison
        self.update_flags_ucomiss(dst_float, src_float);
        Ok(())
    }
    
    fn simd_cmp_ps(&self, a: u128, b: u128, imm: u8) -> u128 {
        let mut result = 0u128;
        for i in 0..4 {
            let offset = i * 32;
            let a_float = f32::from_bits(((a >> offset) & 0xFFFFFFFF) as u32);
            let b_float = f32::from_bits(((b >> offset) & 0xFFFFFFFF) as u32);
            
            let cmp_result = self.compare_scalar_ps(a_float, b_float, imm);
            result |= (cmp_result as u128) << offset;
        }
        result
    }
    
    fn compare_scalar_ps(&self, a: f32, b: f32, imm: u8) -> u32 {
        let result = match imm & 0x7 {
            0 => a == b,           // EQ
            1 => a < b,            // LT
            2 => a <= b,           // LE
            3 => a.is_nan() || b.is_nan(), // UNORD
            4 => a != b,           // NEQ
            5 => !(a < b),         // NLT (a >= b or unordered)
            6 => !(a <= b),        // NLE (a > b or unordered)
            7 => !a.is_nan() && !b.is_nan(), // ORD
            _ => false,
        };
        
        if result {
            0xFFFFFFFF
        } else {
            0
        }
    }
    
    fn update_flags_comiss(&mut self, a: f32, b: f32) {
        // COMISS sets ZF, PF, CF according to comparison
        // Signals invalid if either operand is SNaN
        if a.is_nan() || b.is_nan() {
            // Unordered result
            self.cpu.rflags.set(Flags::ZF, true);
            self.cpu.rflags.set(Flags::PF, true);
            self.cpu.rflags.set(Flags::CF, true);
        } else if a > b {
            self.cpu.rflags.set(Flags::ZF, false);
            self.cpu.rflags.set(Flags::PF, false);
            self.cpu.rflags.set(Flags::CF, false);
        } else if a < b {
            self.cpu.rflags.set(Flags::ZF, false);
            self.cpu.rflags.set(Flags::PF, false);
            self.cpu.rflags.set(Flags::CF, true);
        } else { // a == b
            self.cpu.rflags.set(Flags::ZF, true);
            self.cpu.rflags.set(Flags::PF, false);
            self.cpu.rflags.set(Flags::CF, false);
        }
        
        // Clear OF and SF
        self.cpu.rflags.set(Flags::OF, false);
        self.cpu.rflags.set(Flags::SF, false);
    }
    
    fn update_flags_ucomiss(&mut self, a: f32, b: f32) {
        // UCOMISS is similar to COMISS but doesn't signal on QNaN
        if a.is_nan() || b.is_nan() {
            // Unordered result
            self.cpu.rflags.set(Flags::ZF, true);
            self.cpu.rflags.set(Flags::PF, true);
            self.cpu.rflags.set(Flags::CF, true);
        } else if a > b {
            self.cpu.rflags.set(Flags::ZF, false);
            self.cpu.rflags.set(Flags::PF, false);
            self.cpu.rflags.set(Flags::CF, false);
        } else if a < b {
            self.cpu.rflags.set(Flags::ZF, false);
            self.cpu.rflags.set(Flags::PF, false);
            self.cpu.rflags.set(Flags::CF, true);
        } else { // a == b
            self.cpu.rflags.set(Flags::ZF, true);
            self.cpu.rflags.set(Flags::PF, false);
            self.cpu.rflags.set(Flags::CF, false);
        }
        
        // Clear OF and SF
        self.cpu.rflags.set(Flags::OF, false);
        self.cpu.rflags.set(Flags::SF, false);
    }
    
    fn simd_add_ps(&self, a: u128, b: u128) -> u128 {
        let mut result = 0u128;
        for i in 0..4 {
            let offset = i * 32;
            let a_float = f32::from_bits(((a >> offset) & 0xFFFFFFFF) as u32);
            let b_float = f32::from_bits(((b >> offset) & 0xFFFFFFFF) as u32);
            let sum = a_float + b_float;
            result |= (sum.to_bits() as u128) << offset;
        }
        result
    }
    
    fn simd_sub_ps(&self, a: u128, b: u128) -> u128 {
        let mut result = 0u128;
        for i in 0..4 {
            let offset = i * 32;
            let a_float = f32::from_bits(((a >> offset) & 0xFFFFFFFF) as u32);
            let b_float = f32::from_bits(((b >> offset) & 0xFFFFFFFF) as u32);
            let diff = a_float - b_float;
            result |= (diff.to_bits() as u128) << offset;
        }
        result
    }
    
    fn simd_mul_ps(&self, a: u128, b: u128) -> u128 {
        let mut result = 0u128;
        for i in 0..4 {
            let offset = i * 32;
            let a_float = f32::from_bits(((a >> offset) & 0xFFFFFFFF) as u32);
            let b_float = f32::from_bits(((b >> offset) & 0xFFFFFFFF) as u32);
            let product = a_float * b_float;
            result |= (product.to_bits() as u128) << offset;
        }
        result
    }
    
    fn simd_div_ps(&self, a: u128, b: u128) -> u128 {
        let mut result = 0u128;
        for i in 0..4 {
            let offset = i * 32;
            let a_float = f32::from_bits(((a >> offset) & 0xFFFFFFFF) as u32);
            let b_float = f32::from_bits(((b >> offset) & 0xFFFFFFFF) as u32);
            let quotient = a_float / b_float;
            result |= (quotient.to_bits() as u128) << offset;
        }
        result
    }
    
    fn get_operand_size(&self, operand: &Operand) -> OperandSize {
        match operand {
            Operand::Register(reg) => {
                match reg {
                    Register::AL | Register::AH | Register::BL | Register::BH |
                    Register::CL | Register::CH | Register::DL | Register::DH |
                    Register::SIL | Register::DIL | Register::SPL | Register::BPL => OperandSize::Byte,
                    
                    Register::AX | Register::BX | Register::CX | Register::DX |
                    Register::SI | Register::DI | Register::SP | Register::BP => OperandSize::Word,
                    
                    Register::EAX | Register::EBX | Register::ECX | Register::EDX |
                    Register::ESI | Register::EDI | Register::ESP | Register::EBP => OperandSize::DWord,
                    
                    _ => OperandSize::QWord,
                }
            }
            Operand::Memory { size, .. } => *size,
            _ => OperandSize::QWord,
        }
    }
    
    fn update_flags_arithmetic_sized(&mut self, dst: u64, src: u64, result: u64, is_sub: bool, size: OperandSize) {
        // Determine the bit width for overflow/carry calculations
        let (max_val, sign_bit) = match size {
            OperandSize::Byte => (0xFF_u64, 0x80_u64),
            OperandSize::Word => (0xFFFF_u64, 0x8000_u64),
            OperandSize::DWord => (0xFFFFFFFF_u64, 0x80000000_u64),
            _ => (u64::MAX, 0x8000000000000000_u64),
        };
        
        // Mask results to the appropriate size
        let result_masked = result & max_val;
        
        self.cpu.rflags.set(Flags::ZF, result_masked == 0);
        self.cpu.rflags.set(Flags::SF, (result_masked & sign_bit) != 0);
        
        if is_sub {
            self.cpu.rflags.set(Flags::CF, dst < src);
            let dst_sign = (dst & sign_bit) != 0;
            let src_sign = (src & sign_bit) != 0;
            let res_sign = (result_masked & sign_bit) != 0;
            self.cpu.rflags.set(Flags::OF, dst_sign != src_sign && dst_sign != res_sign);
        } else {
            // For addition, carry occurs when the result is less than either operand (wrapped around)
            self.cpu.rflags.set(Flags::CF, result_masked < (dst & max_val) || result_masked < (src & max_val));
            let dst_sign = (dst & sign_bit) != 0;
            let src_sign = (src & sign_bit) != 0;
            let res_sign = (result_masked & sign_bit) != 0;
            self.cpu.rflags.set(Flags::OF, dst_sign == src_sign && dst_sign != res_sign);
        }
        
        let parity = (result_masked as u8).count_ones() % 2 == 0;
        self.cpu.rflags.set(Flags::PF, parity);
    }
}