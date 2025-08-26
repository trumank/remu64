use crate::cpu::{CpuState, Flags, Register};
use crate::error::{EmulatorError, Result};
use crate::hooks::HookManager;
use crate::memory::{Memory, Permission};
use iced_x86::{
    Code, Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register as IcedRegister,
};

#[derive(Debug, Clone, Copy)]
pub enum EngineMode {
    Mode16,
    Mode32,
    Mode64,
}

pub struct Engine {
    pub cpu: CpuState,
    pub memory: Memory,
    _mode: EngineMode,
    instruction_count: u64,
}

impl Engine {
    pub fn new(mode: EngineMode) -> Self {
        Self {
            cpu: CpuState::new(),
            memory: Memory::new(),
            _mode: mode,
            instruction_count: 0,
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
        // For code loading, bypass permission checks and write directly
        self.memory.write_bytes(address, data)
    }

    pub fn mem_read(&mut self, address: u64, buf: &mut [u8]) -> Result<()> {
        self.memory.read(address, buf)
    }

    fn mem_read_with_hooks<H: HookManager>(
        &mut self,
        address: u64,
        buf: &mut [u8],
        mut hooks: Option<&mut H>,
    ) -> Result<()> {
        if let Some(hooks) = hooks.as_deref_mut() {
            hooks.on_mem_read(self, address, buf.len())?;
        }

        // Try to read memory, handle faults with hooks
        match self.memory.read(address, buf) {
            Ok(()) => Ok(()),
            Err(EmulatorError::UnmappedMemory(_)) => {
                // Try to handle the fault with memory fault hooks
                if let Some(hooks) = hooks {
                    if hooks.on_mem_fault(self, address, buf.len())? {
                        // Hook handled the fault, try reading again
                        self.memory.read(address, buf)
                    } else {
                        // No hook handled the fault, return original error
                        Err(EmulatorError::UnmappedMemory(address))
                    }
                } else {
                    Err(EmulatorError::UnmappedMemory(address))
                }
            }
            Err(e) => Err(e),
        }
    }

    pub fn reg_read(&self, reg: Register) -> u64 {
        self.cpu.read_reg(reg)
    }

    pub fn reg_write(&mut self, reg: Register, value: u64) {
        self.cpu.write_reg(reg, value)
    }

    pub fn flags_read(&self) -> Flags {
        self.cpu.rflags
    }

    pub fn set_gs_base(&mut self, base: u64) {
        self.cpu.segments.gs.base = base;
    }

    pub fn emu_start<H: HookManager>(
        &mut self,
        begin: u64,
        until: u64,
        timeout: u64,
        count: usize,
        mut hooks: Option<&mut H>,
    ) -> Result<()> {
        self.cpu.rip = begin;
        self.instruction_count = 0;

        let start_time = std::time::Instant::now();
        let timeout_duration = if timeout > 0 {
            Some(std::time::Duration::from_micros(timeout))
        } else {
            None
        };

        loop {
            if self.cpu.rip == until && until != 0 {
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

            self.step(hooks.as_deref_mut())?;
        }

        Ok(())
    }

    fn step<H: HookManager>(&mut self, mut hooks: Option<&mut H>) -> Result<()> {
        let rip = self.cpu.rip;

        // Check if we can execute at this address, but allow memory fault hooks to handle unmapped memory
        match self.memory.check_exec(rip) {
            Ok(()) => {} // Memory is mapped and executable, continue
            Err(EmulatorError::UnmappedMemory(_)) => {
                // Memory is unmapped, try to handle with memory fault hooks
                if let Some(hooks) = hooks.as_deref_mut() {
                    // Try to let the memory fault hook handle this
                    // TODO refactor the decoder to do memory reads instead of operate on a slice of data
                    if !hooks.on_mem_fault(self, rip, 1)? {
                        // Hook couldn't handle it, return the original error
                        return Err(EmulatorError::UnmappedMemory(rip));
                    }
                    // Hook handled it, try check_exec again
                    self.memory.check_exec(rip)?;
                } else {
                    // No hooks available, return the error
                    return Err(EmulatorError::UnmappedMemory(rip));
                }
            }
            Err(e) => return Err(e), // Other errors (like permission denied) are fatal
        }

        let mut inst_bytes = vec![0u8; 15];
        self.mem_read_with_hooks(rip, &mut inst_bytes, hooks.as_deref_mut())?;

        // Create iced_x86 decoder for this instruction
        let bitness = match self._mode {
            EngineMode::Mode16 => 16,
            EngineMode::Mode32 => 32,
            EngineMode::Mode64 => 64,
        };
        let mut decoder = Decoder::with_ip(bitness, &inst_bytes, rip, DecoderOptions::NONE);

        let inst = decoder.decode();

        if let Some(hooks) = hooks.as_deref_mut() {
            hooks.on_code(self, rip, inst.len())?;
        }

        self.cpu.rip = rip + inst.len() as u64;

        ExecutionContext {
            engine: self,
            hooks,
        }
        .execute_instruction(&inst)?;

        self.instruction_count += 1;

        Ok(())
    }
}

struct ExecutionContext<'a, H: HookManager> {
    engine: &'a mut Engine,
    hooks: Option<&'a mut H>,
}

impl<H: HookManager> ExecutionContext<'_, H> {
    fn mem_read_with_hooks(&mut self, address: u64, buf: &mut [u8]) -> Result<()> {
        if let Some(hooks) = self.hooks.as_deref_mut() {
            hooks.on_mem_read(self.engine, address, buf.len())?;
        }

        // Try to read memory, handle faults with hooks
        match self.engine.memory.read(address, buf) {
            Ok(()) => Ok(()),
            Err(EmulatorError::UnmappedMemory(_)) => {
                // Try to handle the fault with memory fault hooks
                if let Some(hooks) = self.hooks.as_deref_mut() {
                    if hooks.on_mem_fault(self.engine, address, buf.len())? {
                        // Hook handled the fault, try reading again
                        self.engine.memory.read(address, buf)
                    } else {
                        // No hook handled the fault, return original error
                        Err(EmulatorError::UnmappedMemory(address))
                    }
                } else {
                    Err(EmulatorError::UnmappedMemory(address))
                }
            }
            Err(e) => Err(e),
        }
    }

    fn mem_write_with_hooks(&mut self, address: u64, buf: &[u8]) -> Result<()> {
        if let Some(hooks) = self.hooks.as_deref_mut() {
            hooks.on_mem_write(self.engine, address, buf.len())?;
        }

        // Try to write memory, handle faults with hooks
        match self.engine.memory.write(address, buf) {
            Ok(()) => Ok(()),
            Err(EmulatorError::UnmappedMemory(_)) => {
                // Try to handle the fault with memory fault hooks
                if let Some(hooks) = self.hooks.as_deref_mut() {
                    if hooks.on_mem_fault(self.engine, address, buf.len())? {
                        // Hook handled the fault, try writing again
                        self.engine.memory.write(address, buf)
                    } else {
                        // No hook handled the fault, return original error
                        Err(EmulatorError::UnmappedMemory(address))
                    }
                } else {
                    Err(EmulatorError::UnmappedMemory(address))
                }
            }
            Err(e) => Err(e),
        }
    }

    fn execute_instruction(&mut self, inst: &Instruction) -> Result<()> {
        match inst.mnemonic() {
            Mnemonic::Mov => self.execute_mov(inst),
            Mnemonic::Push => self.execute_push(inst),
            Mnemonic::Sub => self.execute_sub(inst),
            Mnemonic::Call => self.execute_call(inst),
            Mnemonic::Test => self.execute_test(inst),
            Mnemonic::Jne => self.execute_jcc(inst, !self.engine.cpu.rflags.contains(Flags::ZF)),
            Mnemonic::Je => self.execute_jcc(inst, self.engine.cpu.rflags.contains(Flags::ZF)),
            Mnemonic::Jg => {
                let sf = self.engine.cpu.rflags.contains(Flags::SF);
                let of = self.engine.cpu.rflags.contains(Flags::OF);
                let zf = self.engine.cpu.rflags.contains(Flags::ZF);
                self.execute_jcc(inst, !zf && (sf == of))
            }
            Mnemonic::Jge => {
                let sf = self.engine.cpu.rflags.contains(Flags::SF);
                let of = self.engine.cpu.rflags.contains(Flags::OF);
                self.execute_jcc(inst, sf == of)
            }
            Mnemonic::Jns => self.execute_jcc(inst, !self.engine.cpu.rflags.contains(Flags::SF)),
            Mnemonic::Js => self.execute_jcc(inst, self.engine.cpu.rflags.contains(Flags::SF)),
            Mnemonic::Jl => {
                let sf = self.engine.cpu.rflags.contains(Flags::SF);
                let of = self.engine.cpu.rflags.contains(Flags::OF);
                self.execute_jcc(inst, sf != of)
            }
            Mnemonic::Jle => {
                let sf = self.engine.cpu.rflags.contains(Flags::SF);
                let of = self.engine.cpu.rflags.contains(Flags::OF);
                let zf = self.engine.cpu.rflags.contains(Flags::ZF);
                self.execute_jcc(inst, zf || (sf != of))
            }
            Mnemonic::Jae => self.execute_jcc(inst, !self.engine.cpu.rflags.contains(Flags::CF)),
            Mnemonic::Ja => {
                let cf = self.engine.cpu.rflags.contains(Flags::CF);
                let zf = self.engine.cpu.rflags.contains(Flags::ZF);
                self.execute_jcc(inst, !cf && !zf)
            }
            Mnemonic::Jb => self.execute_jcc(inst, self.engine.cpu.rflags.contains(Flags::CF)),
            Mnemonic::Jbe => {
                let cf = self.engine.cpu.rflags.contains(Flags::CF);
                let zf = self.engine.cpu.rflags.contains(Flags::ZF);
                self.execute_jcc(inst, cf || zf)
            }
            Mnemonic::Cmp => self.execute_cmp(inst),
            Mnemonic::Xor => self.execute_xor(inst),
            Mnemonic::Jmp => self.execute_jmp(inst),
            Mnemonic::Lea => self.execute_lea(inst),
            Mnemonic::Add => self.execute_add(inst),
            Mnemonic::Pop => self.execute_pop(inst),
            Mnemonic::Ret => self.execute_ret(inst),
            Mnemonic::Cdq => self.execute_cdq(inst),
            Mnemonic::Cdqe => self.execute_cdqe(inst),
            Mnemonic::And => self.execute_and(inst),
            Mnemonic::Sar => self.execute_sar(inst),
            Mnemonic::Movsxd => self.execute_movsxd(inst),
            Mnemonic::Movzx => self.execute_movzx(inst),
            Mnemonic::Movsx => self.execute_movsx(inst),
            Mnemonic::Inc => self.execute_inc(inst),
            Mnemonic::Dec => self.execute_dec(inst),
            Mnemonic::Setbe => self.execute_setbe(inst),
            Mnemonic::Sete => self.execute_sete(inst),
            Mnemonic::Setne => self.execute_setne(inst),
            Mnemonic::Setle => self.execute_setle(inst),
            Mnemonic::Shr => self.execute_shr(inst),
            Mnemonic::Shl => self.execute_shl(inst),
            Mnemonic::Cmovb => self.execute_cmovb(inst),
            Mnemonic::Cmovg => self.execute_cmovg(inst),
            Mnemonic::Cmovbe => self.execute_cmovbe(inst),
            Mnemonic::Cmovns => self.execute_cmovns(inst),
            Mnemonic::Cmova => self.execute_cmova(inst),
            Mnemonic::Cmovle => self.execute_cmovle(inst),
            Mnemonic::Vmovdqu => self.execute_vmovdqu(inst),
            Mnemonic::Vmovdqa => self.execute_vmovdqa(inst),
            Mnemonic::Movdqu => self.execute_movdqu(inst),
            Mnemonic::Vzeroupper => self.execute_vzeroupper(inst),
            Mnemonic::Imul => self.execute_imul(inst),
            Mnemonic::Nop => self.execute_nop(inst),
            Mnemonic::Neg => self.execute_neg(inst),
            Mnemonic::Sbb => self.execute_sbb(inst),
            Mnemonic::Rol => self.execute_rol(inst),
            _ => {
                println!(
                    "Unsupported instruction: {} ({:?}) at {:#x}",
                    inst,
                    inst.mnemonic(),
                    inst.ip()
                );
                Err(EmulatorError::UnsupportedInstruction(format!(
                    "{:?}",
                    inst.mnemonic()
                )))
            }
        }
    }

    fn execute_mov(&mut self, inst: &Instruction) -> Result<()> {
        let src_value = self.read_operand(inst, 1)?;
        self.write_operand(inst, 0, src_value)?;
        Ok(())
    }

    fn execute_push(&mut self, inst: &Instruction) -> Result<()> {
        let value = self.read_operand(inst, 0)?;
        let stack_size = match inst.code() {
            Code::Push_r64 | Code::Push_rm64 | Code::Pushd_imm32 => 8,
            Code::Push_r32 | Code::Push_rm32 => 4,
            Code::Push_r16 | Code::Push_rm16 | Code::Pushw_imm8 => 2,
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(format!(
                    "Unsupported push variant: {:?}",
                    inst.code()
                )))
            }
        };

        // Update RSP first
        let new_rsp = self
            .engine
            .cpu
            .read_reg(Register::RSP)
            .wrapping_sub(stack_size as u64);
        self.engine.cpu.write_reg(Register::RSP, new_rsp);

        // Write value to stack
        self.write_memory_sized(new_rsp, value, stack_size)?;
        Ok(())
    }

    fn execute_sub(&mut self, inst: &Instruction) -> Result<()> {
        let dst_value = self.read_operand(inst, 0)?;
        let src_value = self.read_operand(inst, 1)?;
        let result = dst_value.wrapping_sub(src_value);

        // Update flags
        self.update_flags_arithmetic_iced(dst_value, src_value, result, true, inst)?;

        // Write result back to destination
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    fn execute_call(&mut self, inst: &Instruction) -> Result<()> {
        // Push return address onto stack
        let return_addr = inst.next_ip();
        let new_rsp = self.engine.cpu.read_reg(Register::RSP).wrapping_sub(8);
        self.engine.cpu.write_reg(Register::RSP, new_rsp);
        self.write_memory_sized(new_rsp, return_addr, 8)?;

        // Get target address
        let target = match inst.op_kind(0) {
            OpKind::NearBranch64 => inst.near_branch64(),
            OpKind::Memory => self.read_operand(inst, 0)?,
            OpKind::Register => self.read_operand(inst, 0)?,
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(format!(
                    "Unsupported call target: {:?}",
                    inst.op_kind(0)
                )))
            }
        };

        // Update RIP to target
        self.engine.cpu.write_reg(Register::RIP, target);
        Ok(())
    }

    fn execute_test(&mut self, inst: &Instruction) -> Result<()> {
        let src1 = self.read_operand(inst, 0)?;
        let src2 = self.read_operand(inst, 1)?;
        let result = src1 & src2;

        // Update flags (TEST only affects flags, doesn't write result)
        self.update_flags_logical_iced(result, inst)?;
        Ok(())
    }

    fn execute_jcc(&mut self, inst: &Instruction, condition: bool) -> Result<()> {
        if condition {
            let target = self.read_operand(inst, 0)?;
            self.engine.cpu.write_reg(Register::RIP, target);
        }
        Ok(())
    }

    fn execute_cmp(&mut self, inst: &Instruction) -> Result<()> {
        let dst_value = self.read_operand(inst, 0)?;
        let src_value = self.read_operand(inst, 1)?;
        let result = dst_value.wrapping_sub(src_value);

        // Update flags (CMP is like SUB but doesn't write result)
        self.update_flags_arithmetic_iced(dst_value, src_value, result, true, inst)?;
        Ok(())
    }

    fn execute_xor(&mut self, inst: &Instruction) -> Result<()> {
        let dst_value = self.read_operand(inst, 0)?;
        let src_value = self.read_operand(inst, 1)?;
        let result = dst_value ^ src_value;

        // Update flags (XOR is a logical operation)
        self.update_flags_logical_iced(result, inst)?;

        // Write result back to destination
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    fn execute_jmp(&mut self, inst: &Instruction) -> Result<()> {
        let target = self.read_operand(inst, 0)?;
        self.engine.cpu.write_reg(Register::RIP, target);
        Ok(())
    }

    fn execute_lea(&mut self, inst: &Instruction) -> Result<()> {
        // LEA (Load Effective Address) calculates the memory address but doesn't actually access memory
        let address = self.calculate_memory_address(inst, 1)?;
        self.write_operand(inst, 0, address)?;
        Ok(())
    }

    fn execute_add(&mut self, inst: &Instruction) -> Result<()> {
        let dst_value = self.read_operand(inst, 0)?;
        let src_value = self.read_operand(inst, 1)?;
        let result = dst_value.wrapping_add(src_value);

        // Update flags
        self.update_flags_arithmetic_iced(dst_value, src_value, result, false, inst)?;

        // Write result back to destination
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    fn execute_pop(&mut self, inst: &Instruction) -> Result<()> {
        // Read value from top of stack
        let rsp = self.engine.cpu.read_reg(Register::RSP);
        let stack_size = match inst.code() {
            Code::Pop_r64 | Code::Pop_rm64 => 8,
            Code::Pop_r32 | Code::Pop_rm32 => 4,
            Code::Pop_r16 | Code::Pop_rm16 => 2,
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(format!(
                    "Unsupported pop variant: {:?}",
                    inst.code()
                )))
            }
        };

        let value = self.read_memory_sized(rsp, stack_size)?;

        // Update RSP first
        let new_rsp = rsp + stack_size as u64;
        self.engine.cpu.write_reg(Register::RSP, new_rsp);

        // Write value to destination
        self.write_operand(inst, 0, value)?;
        Ok(())
    }

    fn execute_ret(&mut self, inst: &Instruction) -> Result<()> {
        // Pop return address from stack
        let rsp = self.engine.cpu.read_reg(Register::RSP);
        let return_addr = self.read_memory_sized(rsp, 8)?;
        let new_rsp = rsp + 8;

        // Handle ret with immediate (ret imm16) - adjust stack pointer by additional amount
        if inst.op_count() > 0 {
            let imm = self.read_operand(inst, 0)?;
            self.engine.cpu.write_reg(Register::RSP, new_rsp + imm);
        } else {
            self.engine.cpu.write_reg(Register::RSP, new_rsp);
        }

        // Jump to return address
        self.engine.cpu.write_reg(Register::RIP, return_addr);
        Ok(())
    }

    fn execute_cdq(&mut self, _inst: &Instruction) -> Result<()> {
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

    fn execute_cdqe(&mut self, _inst: &Instruction) -> Result<()> {
        // CDQE: Sign-extend EAX to RAX (convert dword to qword)
        let eax = self.engine.cpu.read_reg(Register::RAX) as u32;
        let rax = eax as i32 as i64 as u64; // Sign extend 32-bit to 64-bit
        self.engine.cpu.write_reg(Register::RAX, rax);
        Ok(())
    }

    fn execute_and(&mut self, inst: &Instruction) -> Result<()> {
        let dst_value = self.read_operand(inst, 0)?;
        let src_value = self.read_operand(inst, 1)?;
        let result = dst_value & src_value;

        // Update flags (AND only affects flags, clears OF and CF)
        self.update_flags_logical_iced(result, inst)?;

        // Write result back to destination
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    fn execute_sar(&mut self, inst: &Instruction) -> Result<()> {
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
                )))
            }
        };

        // Update flags
        self.update_flags_logical_iced(result, inst)?;

        // Write result back to destination
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    fn execute_movsxd(&mut self, inst: &Instruction) -> Result<()> {
        // MOVSXD: Move with sign extension from 32-bit to 64-bit
        let src_value = self.read_operand(inst, 1)? as u32; // Read as 32-bit
        let result = src_value as i32 as i64 as u64; // Sign extend to 64-bit

        // Write 64-bit result to destination
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    fn execute_movzx(&mut self, inst: &Instruction) -> Result<()> {
        // MOVZX: Move with zero extension
        let src_value = self.read_operand(inst, 1)?;
        let src_size = self.get_operand_size_from_instruction(inst, 1)?;

        // Zero extend based on source size
        let result = match src_size {
            1 => src_value & 0xFF,   // byte to word/dword/qword
            2 => src_value & 0xFFFF, // word to dword/qword
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(format!(
                    "Invalid MOVZX source size: {}",
                    src_size
                )))
            }
        };

        // Write result to destination (automatically zero-extends to full register size)
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    fn execute_movsx(&mut self, inst: &Instruction) -> Result<()> {
        // MOVSX: Move with sign extension
        let src_value = self.read_operand(inst, 1)?;
        let src_size = self.get_operand_size_from_instruction(inst, 1)?;

        // Sign extend based on source size
        let result = match src_size {
            1 => ((src_value as i8) as i64) as u64, // byte to word/dword/qword (sign extend)
            2 => ((src_value as i16) as i64) as u64, // word to dword/qword (sign extend)
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(format!(
                    "Invalid MOVSX source size: {}",
                    src_size
                )))
            }
        };

        // Write result to destination
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    fn execute_inc(&mut self, inst: &Instruction) -> Result<()> {
        let dst_value = self.read_operand(inst, 0)?;
        let result = dst_value.wrapping_add(1);

        // Update flags (INC doesn't affect CF)
        self.update_flags_arithmetic_iced(dst_value, 1, result, false, inst)?;

        // Write result back to destination
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    fn execute_dec(&mut self, inst: &Instruction) -> Result<()> {
        let dst_value = self.read_operand(inst, 0)?;
        let result = dst_value.wrapping_sub(1);

        // Update flags (DEC doesn't affect CF)
        self.update_flags_arithmetic_iced(dst_value, 1, result, true, inst)?;

        // Write result back to destination
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    fn execute_setbe(&mut self, inst: &Instruction) -> Result<()> {
        // SETBE: Set if below or equal (CF=1 or ZF=1)
        let cf = self.engine.cpu.rflags.contains(Flags::CF);
        let zf = self.engine.cpu.rflags.contains(Flags::ZF);
        let result = if cf || zf { 1u64 } else { 0u64 };

        // Write 1 byte result to destination
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    fn execute_sete(&mut self, inst: &Instruction) -> Result<()> {
        // SETE: Set if equal (ZF=1)
        let zf = self.engine.cpu.rflags.contains(Flags::ZF);
        let result = if zf { 1u64 } else { 0u64 };

        // Write 1 byte result to destination
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    fn execute_setne(&mut self, inst: &Instruction) -> Result<()> {
        // SETNE: Set if not equal (ZF=0)
        let zf = self.engine.cpu.rflags.contains(Flags::ZF);
        let result = if !zf { 1u64 } else { 0u64 };

        // Write 1 byte result to destination
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    fn execute_setle(&mut self, inst: &Instruction) -> Result<()> {
        // SETLE: Set if less than or equal (ZF=1 or SF!=OF)
        let zf = self.engine.cpu.rflags.contains(Flags::ZF);
        let sf = self.engine.cpu.rflags.contains(Flags::SF);
        let of = self.engine.cpu.rflags.contains(Flags::OF);
        let result = if zf || (sf != of) { 1u64 } else { 0u64 };

        // Write 1 byte result to destination
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    fn execute_shr(&mut self, inst: &Instruction) -> Result<()> {
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
                )))
            }
        };

        // Update flags
        self.update_flags_logical_iced(result, inst)?;

        // Write result back to destination
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    fn execute_shl(&mut self, inst: &Instruction) -> Result<()> {
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
                )))
            }
        };

        // Update flags
        self.update_flags_logical_iced(result, inst)?;

        // Write result back to destination
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    fn execute_cmovb(&mut self, inst: &Instruction) -> Result<()> {
        // CMOVB: Conditional move if below (CF=1)
        let cf = self.engine.cpu.rflags.contains(Flags::CF);

        if cf {
            let src_value = self.read_operand(inst, 1)?;
            self.write_operand(inst, 0, src_value)?;
        }
        // If condition is false, no move occurs

        Ok(())
    }

    fn execute_cmovg(&mut self, inst: &Instruction) -> Result<()> {
        // CMOVG: Conditional move if greater (ZF=0 and SF=OF)
        let zf = self.engine.cpu.rflags.contains(Flags::ZF);
        let sf = self.engine.cpu.rflags.contains(Flags::SF);
        let of = self.engine.cpu.rflags.contains(Flags::OF);

        if !zf && (sf == of) {
            let src_value = self.read_operand(inst, 1)?;
            self.write_operand(inst, 0, src_value)?;
        }
        // If condition is false, no move occurs

        Ok(())
    }

    fn execute_cmovbe(&mut self, inst: &Instruction) -> Result<()> {
        // CMOVBE: Conditional move if below or equal (CF=1 or ZF=1)
        let cf = self.engine.cpu.rflags.contains(Flags::CF);
        let zf = self.engine.cpu.rflags.contains(Flags::ZF);

        if cf || zf {
            let src_value = self.read_operand(inst, 1)?;
            self.write_operand(inst, 0, src_value)?;
        }
        // If condition is false, no move occurs

        Ok(())
    }

    fn execute_cmovns(&mut self, inst: &Instruction) -> Result<()> {
        // CMOVNS: Conditional move if not sign (SF=0)
        let sf = self.engine.cpu.rflags.contains(Flags::SF);

        if !sf {
            let src_value = self.read_operand(inst, 1)?;
            self.write_operand(inst, 0, src_value)?;
        }
        // If condition is false, no move occurs

        Ok(())
    }

    fn execute_cmova(&mut self, inst: &Instruction) -> Result<()> {
        // CMOVA: Conditional move if above (CF=0 and ZF=0)
        let cf = self.engine.cpu.rflags.contains(Flags::CF);
        let zf = self.engine.cpu.rflags.contains(Flags::ZF);

        if !cf && !zf {
            let src_value = self.read_operand(inst, 1)?;
            self.write_operand(inst, 0, src_value)?;
        }
        // If condition is false, no move occurs

        Ok(())
    }

    fn execute_cmovle(&mut self, inst: &Instruction) -> Result<()> {
        // CMOVLE: Conditional move if less than or equal (ZF=1 or SF!=OF)
        let zf = self.engine.cpu.rflags.contains(Flags::ZF);
        let sf = self.engine.cpu.rflags.contains(Flags::SF);
        let of = self.engine.cpu.rflags.contains(Flags::OF);

        if zf || (sf != of) {
            let src_value = self.read_operand(inst, 1)?;
            self.write_operand(inst, 0, src_value)?;
        }
        // If condition is false, no move occurs

        Ok(())
    }

    fn execute_vmovdqu(&mut self, inst: &Instruction) -> Result<()> {
        // VMOVDQU: Vector Move Unaligned Packed Integer Values (256-bit)
        // Can move from YMM to memory, memory to YMM, or YMM to YMM

        match (inst.op_kind(0), inst.op_kind(1)) {
            (OpKind::Register, OpKind::Memory) => {
                // ymm, [mem] - load from memory to YMM register
                let src_data = self.read_ymm_memory(inst, 1)?;
                let dst_reg = self.convert_register(inst.op_register(0))?;
                self.engine.cpu.write_ymm(dst_reg, src_data);
                Ok(())
            }
            (OpKind::Memory, OpKind::Register) => {
                // [mem], ymm - store from YMM register to memory
                let src_reg = self.convert_register(inst.op_register(1))?;
                let src_data = self.engine.cpu.read_ymm(src_reg);
                self.write_ymm_memory(inst, 0, src_data)?;
                Ok(())
            }
            (OpKind::Register, OpKind::Register) => {
                // ymm, ymm - move YMM register to YMM register
                let src_reg = self.convert_register(inst.op_register(1))?;
                let dst_reg = self.convert_register(inst.op_register(0))?;
                let src_data = self.engine.cpu.read_ymm(src_reg);
                self.engine.cpu.write_ymm(dst_reg, src_data);
                Ok(())
            }
            _ => Err(EmulatorError::UnsupportedInstruction(format!(
                "Unsupported VMOVDQU operand types: {:?}, {:?}",
                inst.op_kind(0),
                inst.op_kind(1)
            ))),
        }
    }

    fn execute_vmovdqa(&mut self, inst: &Instruction) -> Result<()> {
        // VMOVDQA: Vector Move Aligned Packed Integer Values (256-bit)
        // Same as VMOVDQU but requires 32-byte alignment (we'll ignore alignment for now)
        match (inst.op_kind(0), inst.op_kind(1)) {
            (OpKind::Register, OpKind::Memory) => {
                // ymm, [mem] - load from memory to YMM register
                let src_data = self.read_ymm_memory(inst, 1)?;
                let dst_reg = self.convert_register(inst.op_register(0))?;
                self.engine.cpu.write_ymm(dst_reg, src_data);
                Ok(())
            }
            (OpKind::Memory, OpKind::Register) => {
                // [mem], ymm - store from YMM register to memory
                let src_reg = self.convert_register(inst.op_register(1))?;
                let src_data = self.engine.cpu.read_ymm(src_reg);
                self.write_ymm_memory(inst, 0, src_data)?;
                Ok(())
            }
            (OpKind::Register, OpKind::Register) => {
                // ymm, ymm - move YMM register to YMM register
                let src_reg = self.convert_register(inst.op_register(1))?;
                let dst_reg = self.convert_register(inst.op_register(0))?;
                let src_data = self.engine.cpu.read_ymm(src_reg);
                self.engine.cpu.write_ymm(dst_reg, src_data);
                Ok(())
            }
            _ => Err(EmulatorError::UnsupportedInstruction(format!(
                "Unsupported VMOVDQA operand types: {:?}, {:?}",
                inst.op_kind(0),
                inst.op_kind(1)
            ))),
        }
    }

    fn execute_movdqu(&mut self, inst: &Instruction) -> Result<()> {
        // MOVDQU: Move Unaligned Packed Integer Values (128-bit SSE)
        match (inst.op_kind(0), inst.op_kind(1)) {
            (OpKind::Register, OpKind::Memory) => {
                // xmm, [mem] - load from memory to XMM register
                let addr = self.calculate_memory_address(inst, 1)?;
                let src_data = self.read_memory_128(addr)?;
                let dst_reg = self.convert_register(inst.op_register(0))?;
                self.engine.cpu.write_xmm(dst_reg, src_data);
                Ok(())
            }
            (OpKind::Memory, OpKind::Register) => {
                // [mem], xmm - store from XMM register to memory
                let addr = self.calculate_memory_address(inst, 0)?;
                let src_reg = self.convert_register(inst.op_register(1))?;
                let src_data = self.engine.cpu.read_xmm(src_reg);
                self.write_memory_128(addr, src_data)?;
                Ok(())
            }
            (OpKind::Register, OpKind::Register) => {
                // xmm, xmm - move XMM register to XMM register
                let src_reg = self.convert_register(inst.op_register(1))?;
                let dst_reg = self.convert_register(inst.op_register(0))?;
                let src_data = self.engine.cpu.read_xmm(src_reg);
                self.engine.cpu.write_xmm(dst_reg, src_data);
                Ok(())
            }
            _ => Err(EmulatorError::UnsupportedInstruction(format!(
                "Unsupported MOVDQU operand types: {:?}, {:?}",
                inst.op_kind(0),
                inst.op_kind(1)
            ))),
        }
    }

    fn execute_vzeroupper(&mut self, _inst: &Instruction) -> Result<()> {
        // VZEROUPPER - Zero upper bits of all YMM registers
        // This sets the upper 128 bits (bits 255:128) of all YMM registers to zero
        // The lower 128 bits (XMM portions) are preserved

        // Zero the upper 128 bits of all YMM registers (YMM0-YMM15)
        for i in 0..16 {
            // Keep the lower 128 bits (XMM part) and zero the upper 128 bits
            self.engine.cpu.ymm_regs[i][1] = 0;
        }

        Ok(())
    }

    fn execute_imul(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_nop(&mut self, _inst: &Instruction) -> Result<()> {
        // NOP: No Operation - do nothing
        Ok(())
    }

    fn execute_neg(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_sbb(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_rol(&mut self, inst: &Instruction) -> Result<()> {
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

    fn read_ymm_memory(&mut self, inst: &Instruction, operand_idx: u32) -> Result<[u128; 2]> {
        let addr = self.calculate_memory_address(inst, operand_idx)?;

        // Read 256 bits (32 bytes) from memory as two 128-bit values
        let low_128 = self.read_memory_128(addr)?;
        let high_128 = self.read_memory_128(addr + 16)?;

        Ok([low_128, high_128])
    }

    fn write_ymm_memory(
        &mut self,
        inst: &Instruction,
        operand_idx: u32,
        data: [u128; 2],
    ) -> Result<()> {
        let addr = self.calculate_memory_address(inst, operand_idx)?;

        // Write 256 bits (32 bytes) to memory as two 128-bit values
        self.write_memory_128(addr, data[0])?;
        self.write_memory_128(addr + 16, data[1])?;

        Ok(())
    }

    fn read_memory_128(&mut self, addr: u64) -> Result<u128> {
        let mut buf = [0u8; 16];
        self.mem_read_with_hooks(addr, &mut buf)?;
        Ok(u128::from_le_bytes(buf))
    }

    fn write_memory_128(&mut self, addr: u64, value: u128) -> Result<()> {
        let bytes = value.to_le_bytes();
        self.mem_write_with_hooks(addr, &bytes)
    }

    fn calculate_memory_address(&mut self, inst: &Instruction, operand_idx: u32) -> Result<u64> {
        if inst.op_kind(operand_idx) != OpKind::Memory {
            return Err(EmulatorError::UnsupportedInstruction(
                "Expected memory operand for LEA".to_string(),
            ));
        }

        // For LEA, we need to use the same address calculation logic as read_operand
        let mut addr;

        // Handle RIP-relative addressing differently
        if inst.memory_base() == IcedRegister::RIP {
            // iced_x86 already calculates the effective address for RIP-relative
            addr = inst.memory_displacement64();
        } else {
            // Standard addressing: disp + base + index*scale
            addr = inst.memory_displacement64();

            if inst.memory_base() != IcedRegister::None {
                let base_reg = self.convert_register(inst.memory_base())?;
                addr = addr.wrapping_add(self.engine.cpu.read_reg(base_reg));
            }

            if inst.memory_index() != IcedRegister::None {
                let index_reg = self.convert_register(inst.memory_index())?;
                let scale = inst.memory_index_scale();
                addr = addr.wrapping_add(self.engine.cpu.read_reg(index_reg) * (scale as u64));
            }
        }

        // Apply segment base if segment prefix is present
        if inst.has_segment_prefix() {
            let segment = inst.segment_prefix();
            addr = addr.wrapping_add(self.get_segment_base(segment)?);
        }

        Ok(addr)
    }

    fn update_flags_arithmetic_iced(
        &mut self,
        dst: u64,
        src: u64,
        result: u64,
        is_sub: bool,
        inst: &Instruction,
    ) -> Result<()> {
        let size = self.get_operand_size_from_instruction(inst, 0)?;

        // Mask result based on operand size
        let mask = match size {
            1 => 0xFF,
            2 => 0xFFFF,
            4 => 0xFFFFFFFF,
            8 => 0xFFFFFFFFFFFFFFFF,
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(format!(
                    "Unsupported size: {}",
                    size
                )))
            }
        };

        let masked_result = result & mask;
        let masked_dst = dst & mask;
        let masked_src = src & mask;

        // Zero flag
        if masked_result == 0 {
            self.engine.cpu.rflags.insert(Flags::ZF);
        } else {
            self.engine.cpu.rflags.remove(Flags::ZF);
        }

        // Sign flag (check MSB of result)
        let sign_bit = match size {
            1 => 0x80,
            2 => 0x8000,
            4 => 0x80000000,
            8 => 0x8000000000000000,
            _ => unreachable!(),
        };

        if masked_result & sign_bit != 0 {
            self.engine.cpu.rflags.insert(Flags::SF);
        } else {
            self.engine.cpu.rflags.remove(Flags::SF);
        }

        // Carry flag
        if is_sub {
            // For subtraction, carry is set if dst < src
            if masked_dst < masked_src {
                self.engine.cpu.rflags.insert(Flags::CF);
            } else {
                self.engine.cpu.rflags.remove(Flags::CF);
            }
        } else {
            // For addition, check if result overflowed
            if result > mask {
                self.engine.cpu.rflags.insert(Flags::CF);
            } else {
                self.engine.cpu.rflags.remove(Flags::CF);
            }
        }

        // Overflow flag - check if sign changed inappropriately
        let dst_sign = (masked_dst & sign_bit) != 0;
        let src_sign = (masked_src & sign_bit) != 0;
        let result_sign = (masked_result & sign_bit) != 0;

        let overflow = if is_sub {
            // Overflow in subtraction: dst and src have different signs, and result has same sign as src
            dst_sign != src_sign && result_sign == src_sign
        } else {
            // Overflow in addition: dst and src have same sign, but result has different sign
            dst_sign == src_sign && result_sign != dst_sign
        };

        if overflow {
            self.engine.cpu.rflags.insert(Flags::OF);
        } else {
            self.engine.cpu.rflags.remove(Flags::OF);
        }

        // Parity flag - count 1-bits in low byte of result
        let low_byte = (masked_result & 0xFF) as u8;
        if low_byte.count_ones().is_multiple_of(2) {
            self.engine.cpu.rflags.insert(Flags::PF);
        } else {
            self.engine.cpu.rflags.remove(Flags::PF);
        }

        Ok(())
    }

    fn update_flags_logical_iced(&mut self, result: u64, inst: &Instruction) -> Result<()> {
        let size = self.get_operand_size_from_instruction(inst, 0)?;

        // Mask result based on operand size
        let mask = match size {
            1 => 0xFF,
            2 => 0xFFFF,
            4 => 0xFFFFFFFF,
            8 => 0xFFFFFFFFFFFFFFFF,
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(format!(
                    "Unsupported size: {}",
                    size
                )))
            }
        };

        let masked_result = result & mask;

        // Zero flag
        if masked_result == 0 {
            self.engine.cpu.rflags.insert(Flags::ZF);
        } else {
            self.engine.cpu.rflags.remove(Flags::ZF);
        }

        // Sign flag (check MSB of result)
        let sign_bit = match size {
            1 => 0x80,
            2 => 0x8000,
            4 => 0x80000000,
            8 => 0x8000000000000000,
            _ => unreachable!(),
        };

        if masked_result & sign_bit != 0 {
            self.engine.cpu.rflags.insert(Flags::SF);
        } else {
            self.engine.cpu.rflags.remove(Flags::SF);
        }

        // Carry and Overflow are cleared for logical operations
        self.engine.cpu.rflags.remove(Flags::CF);
        self.engine.cpu.rflags.remove(Flags::OF);

        // Parity flag - count 1-bits in low byte of result
        let low_byte = (masked_result & 0xFF) as u8;
        if low_byte.count_ones().is_multiple_of(2) {
            self.engine.cpu.rflags.insert(Flags::PF);
        } else {
            self.engine.cpu.rflags.remove(Flags::PF);
        }

        Ok(())
    }

    fn read_operand(&mut self, inst: &Instruction, operand_idx: u32) -> Result<u64> {
        match inst.op_kind(operand_idx) {
            OpKind::Register => {
                let iced_reg = inst.op_register(operand_idx);
                let our_reg = self.convert_register(iced_reg)?;
                Ok(self.engine.cpu.read_reg(our_reg))
            }
            OpKind::Immediate8 => Ok(inst.immediate8() as u64),
            OpKind::Immediate8to16 => Ok(inst.immediate8to16() as u64),
            OpKind::Immediate8to32 => Ok(inst.immediate8to32() as u64),
            OpKind::Immediate8to64 => Ok(inst.immediate8to64() as u64),
            OpKind::Immediate16 => Ok(inst.immediate16() as u64),
            OpKind::Immediate32 => Ok(inst.immediate32() as u64),
            OpKind::Immediate32to64 => Ok(inst.immediate32to64() as u64),
            OpKind::Immediate64 => Ok(inst.immediate64()),
            OpKind::NearBranch16 => Ok(inst.near_branch16() as u64),
            OpKind::NearBranch32 => Ok(inst.near_branch32() as u64),
            OpKind::NearBranch64 => Ok(inst.near_branch64()),
            OpKind::Memory => {
                // Calculate effective address based on addressing mode
                let mut addr;

                // Handle RIP-relative addressing differently
                if inst.memory_base() == IcedRegister::RIP {
                    // iced_x86 already calculates the effective address for RIP-relative
                    addr = inst.memory_displacement64();
                } else {
                    // Standard addressing: disp + base + index*scale
                    addr = inst.memory_displacement64();

                    if inst.memory_base() != IcedRegister::None {
                        let base_reg = self.convert_register(inst.memory_base())?;
                        addr = addr.wrapping_add(self.engine.cpu.read_reg(base_reg));
                    }

                    if inst.memory_index() != IcedRegister::None {
                        let index_reg = self.convert_register(inst.memory_index())?;
                        let scale = inst.memory_index_scale();
                        let index_value = self.engine.cpu.read_reg(index_reg);
                        addr = addr.wrapping_add(index_value * (scale as u64));
                    }
                }

                // Apply segment base if segment prefix is present
                if inst.has_segment_prefix() {
                    let segment = inst.segment_prefix();
                    addr = addr.wrapping_add(self.get_segment_base(segment)?);
                }

                let size = self.get_operand_size_from_instruction(inst, operand_idx)?;
                self.read_memory_sized(addr, size)
            }
            _ => Err(EmulatorError::UnsupportedInstruction(format!(
                "Unsupported operand kind: {:?}",
                inst.op_kind(operand_idx)
            ))),
        }
    }

    fn write_operand(&mut self, inst: &Instruction, operand_idx: u32, value: u64) -> Result<()> {
        match inst.op_kind(operand_idx) {
            OpKind::Register => {
                let iced_reg = inst.op_register(operand_idx);
                let our_reg = self.convert_register(iced_reg)?;
                self.engine.cpu.write_reg(our_reg, value);
                Ok(())
            }
            OpKind::Memory => {
                let mut addr = inst.memory_displacement64();

                if inst.memory_base() != IcedRegister::None {
                    let base_reg = self.convert_register(inst.memory_base())?;
                    addr = addr.wrapping_add(self.engine.cpu.read_reg(base_reg));
                }

                if inst.memory_index() != IcedRegister::None {
                    let index_reg = self.convert_register(inst.memory_index())?;
                    let scale = inst.memory_index_scale();
                    addr = addr.wrapping_add(self.engine.cpu.read_reg(index_reg) * (scale as u64));
                }

                // Apply segment base if segment prefix is present
                if inst.has_segment_prefix() {
                    let segment = inst.segment_prefix();
                    addr = addr.wrapping_add(self.get_segment_base(segment)?);
                }

                let size = self.get_operand_size_from_instruction(inst, operand_idx)?;
                self.write_memory_sized(addr, value, size)
            }
            _ => Err(EmulatorError::UnsupportedInstruction(format!(
                "Cannot write to operand kind: {:?}",
                inst.op_kind(operand_idx)
            ))),
        }
    }

    fn convert_register(&self, iced_reg: IcedRegister) -> Result<Register> {
        use IcedRegister as IR;
        match iced_reg {
            IR::RAX => Ok(Register::RAX),
            IR::RBX => Ok(Register::RBX),
            IR::RCX => Ok(Register::RCX),
            IR::RDX => Ok(Register::RDX),
            IR::RSI => Ok(Register::RSI),
            IR::RDI => Ok(Register::RDI),
            IR::RBP => Ok(Register::RBP),
            IR::RSP => Ok(Register::RSP),
            IR::R8 => Ok(Register::R8),
            IR::R9 => Ok(Register::R9),
            IR::R10 => Ok(Register::R10),
            IR::R11 => Ok(Register::R11),
            IR::R12 => Ok(Register::R12),
            IR::R13 => Ok(Register::R13),
            IR::R14 => Ok(Register::R14),
            IR::R15 => Ok(Register::R15),
            IR::EAX => Ok(Register::EAX),
            IR::EBX => Ok(Register::EBX),
            IR::ECX => Ok(Register::ECX),
            IR::EDX => Ok(Register::EDX),
            IR::ESI => Ok(Register::ESI),
            IR::EDI => Ok(Register::EDI),
            IR::EBP => Ok(Register::EBP),
            IR::ESP => Ok(Register::ESP),
            IR::R8D => Ok(Register::R8D),
            IR::R9D => Ok(Register::R9D),
            IR::R10D => Ok(Register::R10D),
            IR::R11D => Ok(Register::R11D),
            IR::R12D => Ok(Register::R12D),
            IR::R13D => Ok(Register::R13D),
            IR::R14D => Ok(Register::R14D),
            IR::R15D => Ok(Register::R15D),
            IR::RIP => Ok(Register::RIP),
            // 16-bit registers
            IR::AX => Ok(Register::AX),
            IR::BX => Ok(Register::BX),
            IR::CX => Ok(Register::CX),
            IR::DX => Ok(Register::DX),
            IR::SI => Ok(Register::SI),
            IR::DI => Ok(Register::DI),
            IR::BP => Ok(Register::BP),
            IR::SP => Ok(Register::SP),
            IR::R8W => Ok(Register::R8W),
            IR::R9W => Ok(Register::R9W),
            IR::R10W => Ok(Register::R10W),
            IR::R11W => Ok(Register::R11W),
            IR::R12W => Ok(Register::R12W),
            IR::R13W => Ok(Register::R13W),
            IR::R14W => Ok(Register::R14W),
            IR::R15W => Ok(Register::R15W),
            // 8-bit registers
            IR::AL => Ok(Register::AL),
            IR::BL => Ok(Register::BL),
            IR::CL => Ok(Register::CL),
            IR::DL => Ok(Register::DL),
            IR::AH => Ok(Register::AH),
            IR::BH => Ok(Register::BH),
            IR::CH => Ok(Register::CH),
            IR::DH => Ok(Register::DH),
            IR::SIL => Ok(Register::SIL),
            IR::DIL => Ok(Register::DIL),
            IR::BPL => Ok(Register::BPL),
            IR::SPL => Ok(Register::SPL),
            IR::R8L => Ok(Register::R8B),
            IR::R9L => Ok(Register::R9B),
            IR::R10L => Ok(Register::R10B),
            IR::R11L => Ok(Register::R11B),
            IR::R12L => Ok(Register::R12B),
            IR::R13L => Ok(Register::R13B),
            IR::R14L => Ok(Register::R14B),
            IR::R15L => Ok(Register::R15B),
            // YMM registers
            IR::YMM0 => Ok(Register::YMM0),
            IR::YMM1 => Ok(Register::YMM1),
            IR::YMM2 => Ok(Register::YMM2),
            IR::YMM3 => Ok(Register::YMM3),
            IR::YMM4 => Ok(Register::YMM4),
            IR::YMM5 => Ok(Register::YMM5),
            IR::YMM6 => Ok(Register::YMM6),
            IR::YMM7 => Ok(Register::YMM7),
            IR::YMM8 => Ok(Register::YMM8),
            IR::YMM9 => Ok(Register::YMM9),
            IR::YMM10 => Ok(Register::YMM10),
            IR::YMM11 => Ok(Register::YMM11),
            IR::YMM12 => Ok(Register::YMM12),
            IR::YMM13 => Ok(Register::YMM13),
            IR::YMM14 => Ok(Register::YMM14),
            IR::YMM15 => Ok(Register::YMM15),
            // XMM registers
            IR::XMM0 => Ok(Register::XMM0),
            IR::XMM1 => Ok(Register::XMM1),
            IR::XMM2 => Ok(Register::XMM2),
            IR::XMM3 => Ok(Register::XMM3),
            IR::XMM4 => Ok(Register::XMM4),
            IR::XMM5 => Ok(Register::XMM5),
            IR::XMM6 => Ok(Register::XMM6),
            IR::XMM7 => Ok(Register::XMM7),
            IR::XMM8 => Ok(Register::XMM8),
            IR::XMM9 => Ok(Register::XMM9),
            IR::XMM10 => Ok(Register::XMM10),
            IR::XMM11 => Ok(Register::XMM11),
            IR::XMM12 => Ok(Register::XMM12),
            IR::XMM13 => Ok(Register::XMM13),
            IR::XMM14 => Ok(Register::XMM14),
            IR::XMM15 => Ok(Register::XMM15),
            _ => Err(EmulatorError::UnsupportedInstruction(format!(
                "Unsupported register: {:?}",
                iced_reg
            ))),
        }
    }

    fn get_segment_base(&self, segment: IcedRegister) -> Result<u64> {
        use IcedRegister as IR;
        match segment {
            IR::CS => Ok(self.engine.cpu.segments.cs.base),
            IR::DS => Ok(self.engine.cpu.segments.ds.base),
            IR::ES => Ok(self.engine.cpu.segments.es.base),
            IR::FS => Ok(self.engine.cpu.segments.fs.base),
            IR::GS => Ok(self.engine.cpu.segments.gs.base),
            IR::SS => Ok(self.engine.cpu.segments.ss.base),
            _ => Err(EmulatorError::UnsupportedInstruction(format!(
                "Unsupported segment register: {:?}",
                segment
            ))),
        }
    }

    fn get_operand_size_from_instruction(
        &self,
        inst: &Instruction,
        operand_idx: u32,
    ) -> Result<usize> {
        match inst.op_kind(operand_idx) {
            OpKind::Memory => {
                let memory_size = inst.memory_size();
                let size = memory_size.size();
                if size == 0 {
                    return Err(EmulatorError::UnsupportedInstruction(format!(
                        "Cannot determine memory size for operand {}",
                        operand_idx
                    )));
                }
                Ok(size)
            }
            OpKind::Register => {
                let reg = inst.op_register(operand_idx);
                Ok(reg.size())
            }
            _ => {
                // For immediate operands, use the instruction's memory size as a fallback
                let memory_size = inst.memory_size();
                let size = memory_size.size();
                if size > 0 {
                    Ok(size)
                } else {
                    Ok(8) // Default to 64-bit for 64-bit mode
                }
            }
        }
    }

    fn read_memory_sized(&mut self, addr: u64, size: usize) -> Result<u64> {
        match size {
            1 => {
                let mut buf = [0u8; 1];
                self.mem_read_with_hooks(addr, &mut buf)?;
                Ok(buf[0] as u64)
            }
            2 => {
                let mut buf = [0u8; 2];
                self.mem_read_with_hooks(addr, &mut buf)?;
                Ok(u16::from_le_bytes(buf) as u64)
            }
            4 => {
                let mut buf = [0u8; 4];
                self.mem_read_with_hooks(addr, &mut buf)?;
                Ok(u32::from_le_bytes(buf) as u64)
            }
            8 => {
                let mut buf = [0u8; 8];
                self.mem_read_with_hooks(addr, &mut buf)?;
                Ok(u64::from_le_bytes(buf))
            }
            _ => Err(EmulatorError::UnsupportedInstruction(format!(
                "Unsupported memory size: {}",
                size
            ))),
        }
    }

    fn write_memory_sized(&mut self, addr: u64, value: u64, size: usize) -> Result<()> {
        match size {
            1 => self.mem_write_with_hooks(addr, &[value as u8]),
            2 => self.mem_write_with_hooks(addr, &(value as u16).to_le_bytes()),
            4 => self.mem_write_with_hooks(addr, &(value as u32).to_le_bytes()),
            8 => self.mem_write_with_hooks(addr, &value.to_le_bytes()),
            _ => Err(EmulatorError::UnsupportedInstruction(format!(
                "Unsupported memory size: {}",
                size
            ))),
        }
    }
}
