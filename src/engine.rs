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
        self.memory.read(address, buf)
    }
    
    pub fn reg_read(&self, reg: Register) -> Result<u64> {
        Ok(self.cpu.read_reg(reg))
    }
    
    pub fn reg_write(&mut self, reg: Register, value: u64) -> Result<()> {
        self.cpu.write_reg(reg, value);
        Ok(())
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
            Opcode::SUB => self.execute_sub(inst),
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
            Opcode::NOP => Ok(()),
            Opcode::HLT => {
                self.stop_requested.store(true, Ordering::SeqCst);
                Ok(())
            }
            Opcode::SYSCALL => self.execute_syscall(inst),
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
        let result = dst.wrapping_add(src);
        
        self.update_flags_arithmetic(dst, src, result, false);
        self.write_operand(&inst.operands[0], result)?;
        Ok(())
    }
    
    fn execute_sub(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }
        
        let dst = self.read_operand(&inst.operands[0])?;
        let src = self.read_operand(&inst.operands[1])?;
        let result = dst.wrapping_sub(src);
        
        self.update_flags_arithmetic(dst, src, result, true);
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
}