use crate::cpu::{CpuState, Flags, Register};
use crate::error::{EmulatorError, Result};
use crate::hooks::{HookManager, NoHooks};
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
    mode: EngineMode,
    instruction_count: u64,
}

impl Engine {
    pub fn new(mode: EngineMode) -> Self {
        Self {
            cpu: CpuState::new(),
            memory: Memory::new(),
            mode,
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
        hooks: &mut H,
    ) -> Result<()> {
        hooks.on_mem_read(self, address, buf.len())?;

        // Try to read memory, handle faults with hooks
        match self.memory.read(address, buf) {
            Ok(()) => Ok(()),
            Err(EmulatorError::UnmappedMemory(_)) => {
                // Try to handle the fault with memory fault hooks
                if hooks.on_mem_fault(self, address, buf.len())? {
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

    pub fn reg_read(&self, reg: Register) -> u64 {
        self.cpu.read_reg(reg)
    }

    pub fn reg_write(&mut self, reg: Register, value: u64) {
        self.cpu.write_reg(reg, value)
    }

    pub fn xmm_read(&self, reg: Register) -> u128 {
        self.cpu.read_xmm(reg)
    }

    pub fn xmm_write(&mut self, reg: Register, value: u128) {
        self.cpu.write_xmm(reg, value);
    }

    pub fn context_save(&self) -> CpuState {
        self.cpu.clone()
    }

    pub fn context_restore(&mut self, state: &CpuState) {
        self.cpu = state.clone();
    }

    pub fn flags_read(&self) -> Flags {
        self.cpu.rflags
    }

    pub fn set_gs_base(&mut self, base: u64) {
        self.cpu.segments.gs.base = base;
    }

    /// Start emulation with default no-op hooks
    pub fn emu_start(&mut self, begin: u64, until: u64, timeout: u64, count: usize) -> Result<()> {
        let mut no_hooks = NoHooks;
        self.emu_start_with_hooks(begin, until, timeout, count, &mut no_hooks)
    }

    /// Start emulation with custom hooks
    pub fn emu_start_with_hooks<H: HookManager>(
        &mut self,
        begin: u64,
        until: u64,
        timeout: u64,
        count: usize,
        hooks: &mut H,
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

            self.step(hooks)?;
        }

        Ok(())
    }

    fn step<H: HookManager>(&mut self, hooks: &mut H) -> Result<()> {
        let rip = self.cpu.rip;

        // Check if we can execute at this address, but allow memory fault hooks to handle unmapped memory
        match self.memory.check_exec(rip) {
            Ok(()) => {} // Memory is mapped and executable, continue
            Err(EmulatorError::UnmappedMemory(_)) => {
                // Memory is unmapped, try to handle with memory fault hooks
                // Try to let the memory fault hook handle this
                // TODO refactor the decoder to do memory reads instead of operate on a slice of data
                if !hooks.on_mem_fault(self, rip, 1)? {
                    // Hook couldn't handle it, return the original error
                    return Err(EmulatorError::UnmappedMemory(rip));
                }
                // Hook handled it, try check_exec again
                self.memory.check_exec(rip)?;
            }
            Err(e) => return Err(e), // Other errors (like permission denied) are fatal
        }

        let mut inst_bytes = vec![0u8; 15];
        self.mem_read_with_hooks(rip, &mut inst_bytes, hooks)?;

        // Create iced_x86 decoder for this instruction
        let bitness = match self.mode {
            EngineMode::Mode16 => 16,
            EngineMode::Mode32 => 32,
            EngineMode::Mode64 => 64,
        };
        let mut decoder = Decoder::with_ip(bitness, &inst_bytes, rip, DecoderOptions::NONE);

        let inst = decoder.decode();

        hooks.on_code(self, rip, inst.len())?;

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
    hooks: &'a mut H,
}

impl<H: HookManager> ExecutionContext<'_, H> {
    fn mem_read_with_hooks(&mut self, address: u64, buf: &mut [u8]) -> Result<()> {
        self.hooks.on_mem_read(self.engine, address, buf.len())?;

        // Try to read memory, handle faults with hooks
        match self.engine.memory.read(address, buf) {
            Ok(()) => Ok(()),
            Err(EmulatorError::UnmappedMemory(_)) => {
                // Try to handle the fault with memory fault hooks
                if self.hooks.on_mem_fault(self.engine, address, buf.len())? {
                    // Hook handled the fault, try reading again
                    self.engine.memory.read(address, buf)
                } else {
                    // No hook handled the fault, return original error
                    Err(EmulatorError::UnmappedMemory(address))
                }
            }
            Err(e) => Err(e),
        }
    }

    fn mem_write_with_hooks(&mut self, address: u64, buf: &[u8]) -> Result<()> {
        self.hooks.on_mem_write(self.engine, address, buf.len())?;

        // Try to write memory, handle faults with hooks
        match self.engine.memory.write(address, buf) {
            Ok(()) => Ok(()),
            Err(EmulatorError::UnmappedMemory(_)) => {
                // Try to handle the fault with memory fault hooks
                if self.hooks.on_mem_fault(self.engine, address, buf.len())? {
                    // Hook handled the fault, try writing again
                    self.engine.memory.write(address, buf)
                } else {
                    // No hook handled the fault, return original error
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
            Mnemonic::Or => self.execute_or(inst),
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
            Mnemonic::Cmove => self.execute_cmove(inst),
            Mnemonic::Vmovdqu => self.execute_vmovdqu(inst),
            Mnemonic::Vmovdqa => self.execute_vmovdqa(inst),
            Mnemonic::Movdqu => self.execute_movdqu(inst),
            Mnemonic::Movdqa => self.execute_movdqa(inst),
            Mnemonic::Movd => self.execute_movd(inst),
            Mnemonic::Vzeroupper => self.execute_vzeroupper(inst),
            Mnemonic::Imul => self.execute_imul(inst),
            Mnemonic::Mul => self.execute_mul(inst),
            Mnemonic::Div => self.execute_div(inst),
            Mnemonic::Idiv => self.execute_idiv(inst),
            Mnemonic::Nop => self.execute_nop(inst),
            Mnemonic::Neg => self.execute_neg(inst),
            Mnemonic::Sbb => self.execute_sbb(inst),
            Mnemonic::Rol => self.execute_rol(inst),
            Mnemonic::Cmpxchg => self.execute_cmpxchg(inst),
            Mnemonic::Bt => self.execute_bt(inst),
            Mnemonic::Bts => self.execute_bts(inst),
            Mnemonic::Btr => self.execute_btr(inst),
            Mnemonic::Btc => self.execute_btc(inst),
            Mnemonic::Bsf => self.execute_bsf(inst),
            Mnemonic::Bsr => self.execute_bsr(inst),
            Mnemonic::Punpcklwd => self.execute_punpcklwd(inst),
            Mnemonic::Pshufd => self.execute_pshufd(inst),
            Mnemonic::Xorps => self.execute_xorps(inst),
            Mnemonic::Cmpps => self.execute_cmpps(inst),
            Mnemonic::Cmpss => self.execute_cmpss(inst),
            Mnemonic::Comiss => self.execute_comiss(inst),
            Mnemonic::Ucomiss => self.execute_ucomiss(inst),
            Mnemonic::Movaps => self.execute_movaps(inst),
            Mnemonic::Addps => self.execute_addps(inst),
            Mnemonic::Subps => self.execute_subps(inst),
            Mnemonic::Mulps => self.execute_mulps(inst),
            Mnemonic::Divps => self.execute_divps(inst),
            Mnemonic::Andps => self.execute_andps(inst),
            Mnemonic::Orps => self.execute_orps(inst),
            Mnemonic::Movsb => self.execute_movsb(inst),
            Mnemonic::Stosb => self.execute_stosb(inst),
            Mnemonic::Lodsb => self.execute_lodsb(inst),
            Mnemonic::Scasb => self.execute_scasb(inst),
            Mnemonic::Cmpsb => self.execute_cmpsb(inst),
            Mnemonic::Adc => self.execute_adc(inst),
            Mnemonic::Not => self.execute_not(inst),
            Mnemonic::Ror => self.execute_ror(inst),
            Mnemonic::Xchg => self.execute_xchg(inst),
            Mnemonic::Loop => self.execute_loop(inst),
            Mnemonic::Loope => self.execute_loope(inst),
            Mnemonic::Loopne => self.execute_loopne(inst),
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

    fn execute_or(&mut self, inst: &Instruction) -> Result<()> {
        let dst_value = self.read_operand(inst, 0)?;
        let src_value = self.read_operand(inst, 1)?;
        let result = dst_value | src_value;

        // Update flags (OR is a logical operation)
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

    fn execute_cmove(&mut self, inst: &Instruction) -> Result<()> {
        // CMOVE: Conditional move if equal (ZF=1), same as CMOVZ
        let zf = self.engine.cpu.rflags.contains(Flags::ZF);

        if zf {
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

    fn execute_movdqa(&mut self, inst: &Instruction) -> Result<()> {
        // MOVDQA: Move Aligned Packed Integer Values (128-bit SSE)
        // Same as MOVDQU but requires 16-byte alignment (we'll ignore alignment for now)
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
                "Unsupported MOVDQA operand types: {:?}, {:?}",
                inst.op_kind(0),
                inst.op_kind(1)
            ))),
        }
    }

    fn execute_movd(&mut self, inst: &Instruction) -> Result<()> {
        // MOVD: Move 32-bit value between general-purpose register and XMM register
        match (inst.op_kind(0), inst.op_kind(1)) {
            (OpKind::Register, OpKind::Register) => {
                let dst_reg = self.convert_register(inst.op_register(0))?;
                let src_reg = self.convert_register(inst.op_register(1))?;

                // Check if destination is XMM and source is general-purpose
                if matches!(
                    dst_reg,
                    Register::XMM0
                        | Register::XMM1
                        | Register::XMM2
                        | Register::XMM3
                        | Register::XMM4
                        | Register::XMM5
                        | Register::XMM6
                        | Register::XMM7
                        | Register::XMM8
                        | Register::XMM9
                        | Register::XMM10
                        | Register::XMM11
                        | Register::XMM12
                        | Register::XMM13
                        | Register::XMM14
                        | Register::XMM15
                ) {
                    // Moving from general-purpose register to XMM
                    let src_value = self.engine.cpu.read_reg(src_reg) as u32; // Take lower 32 bits
                                                                              // Zero out the XMM register and set the lower 32 bits
                    self.engine.cpu.write_xmm(dst_reg, src_value as u128);
                } else if matches!(
                    src_reg,
                    Register::XMM0
                        | Register::XMM1
                        | Register::XMM2
                        | Register::XMM3
                        | Register::XMM4
                        | Register::XMM5
                        | Register::XMM6
                        | Register::XMM7
                        | Register::XMM8
                        | Register::XMM9
                        | Register::XMM10
                        | Register::XMM11
                        | Register::XMM12
                        | Register::XMM13
                        | Register::XMM14
                        | Register::XMM15
                ) {
                    // Moving from XMM register to general-purpose register
                    let src_value = self.engine.cpu.read_xmm(src_reg) as u32; // Take lower 32 bits
                    self.engine.cpu.write_reg(dst_reg, src_value as u64);
                } else {
                    return Err(EmulatorError::UnsupportedInstruction(
                        "MOVD requires one XMM and one general-purpose register".to_string(),
                    ));
                }
                Ok(())
            }
            (OpKind::Register, OpKind::Memory) => {
                // xmm, [mem] - load 32 bits from memory to XMM register
                let dst_reg = self.convert_register(inst.op_register(0))?;
                let addr = self.calculate_memory_address(inst, 1)?;
                let src_value = self.read_memory_sized(addr, 4)? as u32;
                self.engine.cpu.write_xmm(dst_reg, src_value as u128);
                Ok(())
            }
            (OpKind::Memory, OpKind::Register) => {
                // [mem], xmm - store lower 32 bits of XMM register to memory
                let src_reg = self.convert_register(inst.op_register(1))?;
                let addr = self.calculate_memory_address(inst, 0)?;
                let src_value = self.engine.cpu.read_xmm(src_reg) as u32;
                self.write_memory_sized(addr, src_value as u64, 4)?;
                Ok(())
            }
            _ => Err(EmulatorError::UnsupportedInstruction(format!(
                "Unsupported MOVD operand types: {:?}, {:?}",
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

    fn execute_mul(&mut self, inst: &Instruction) -> Result<()> {
        // MUL: Unsigned multiply
        // 1-operand form: RAX = RAX * operand, result in RDX:RAX
        let multiplicand = self.engine.cpu.read_reg(Register::RAX);
        let multiplier = self.read_operand(inst, 0)?;

        let result = (multiplicand as u128) * (multiplier as u128);

        // Store low 64 bits in RAX, high 64 bits in RDX
        self.engine.cpu.write_reg(Register::RAX, result as u64);
        self.engine
            .cpu
            .write_reg(Register::RDX, (result >> 64) as u64);

        // Update flags: CF and OF are set if result requires more than 64 bits
        let overflow = (result >> 64) != 0;
        self.engine.cpu.rflags.set(Flags::CF, overflow);
        self.engine.cpu.rflags.set(Flags::OF, overflow);

        Ok(())
    }

    fn execute_div(&mut self, inst: &Instruction) -> Result<()> {
        // DIV: Unsigned divide
        // RDX:RAX / operand -> quotient in RAX, remainder in RDX
        let dividend_high = self.engine.cpu.read_reg(Register::RDX);
        let dividend_low = self.engine.cpu.read_reg(Register::RAX);
        let divisor = self.read_operand(inst, 0)?;

        if divisor == 0 {
            return Err(EmulatorError::DivisionByZero);
        }

        let dividend = ((dividend_high as u128) << 64) | (dividend_low as u128);
        let quotient = dividend / (divisor as u128);
        let remainder = dividend % (divisor as u128);

        // Check for overflow (quotient too large for RAX)
        if quotient > u64::MAX as u128 {
            return Err(EmulatorError::DivisionByZero); // x86 throws #DE for overflow too
        }

        self.engine.cpu.write_reg(Register::RAX, quotient as u64);
        self.engine.cpu.write_reg(Register::RDX, remainder as u64);

        Ok(())
    }

    fn execute_idiv(&mut self, inst: &Instruction) -> Result<()> {
        // IDIV: Signed divide
        // RDX:RAX / operand -> quotient in RAX, remainder in RDX
        let dividend_high = self.engine.cpu.read_reg(Register::RDX);
        let dividend_low = self.engine.cpu.read_reg(Register::RAX);
        let divisor = self.read_operand(inst, 0)? as i64;

        if divisor == 0 {
            return Err(EmulatorError::DivisionByZero);
        }

        // Combine high and low parts into signed 128-bit dividend
        let dividend = ((dividend_high as u128) << 64) | (dividend_low as u128);
        let dividend_signed = dividend as i128;

        let quotient = dividend_signed / (divisor as i128);
        let remainder = dividend_signed % (divisor as i128);

        // Check for overflow (quotient outside i64 range)
        if quotient < i64::MIN as i128 || quotient > i64::MAX as i128 {
            return Err(EmulatorError::DivisionByZero); // x86 throws #DE for overflow too
        }

        self.engine.cpu.write_reg(Register::RAX, quotient as u64);
        self.engine.cpu.write_reg(Register::RDX, remainder as u64);

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

    fn execute_cmpxchg(&mut self, inst: &Instruction) -> Result<()> {
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
                )))
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

    fn execute_punpcklwd(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_pshufd(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_xorps(&mut self, inst: &Instruction) -> Result<()> {
        // XORPS: Bitwise XOR of Packed Single-Precision Floating-Point Values
        // Performs bitwise XOR between two 128-bit XMM registers

        match (inst.op_kind(0), inst.op_kind(1)) {
            (OpKind::Register, OpKind::Register) => {
                let dst_reg = self.convert_register(inst.op_register(0))?;
                let src_reg = self.convert_register(inst.op_register(1))?;

                // Check if both operands are XMM registers
                if !dst_reg.is_xmm() || !src_reg.is_xmm() {
                    return Err(EmulatorError::UnsupportedInstruction(
                        "XORPS requires XMM registers".to_string(),
                    ));
                }

                let dst_value = self.engine.cpu.read_xmm(dst_reg);
                let src_value = self.engine.cpu.read_xmm(src_reg);

                // Perform bitwise XOR
                let result = dst_value ^ src_value;

                self.engine.cpu.write_xmm(dst_reg, result);
                Ok(())
            }
            (OpKind::Register, OpKind::Memory) => {
                let dst_reg = self.convert_register(inst.op_register(0))?;

                if !dst_reg.is_xmm() {
                    return Err(EmulatorError::UnsupportedInstruction(
                        "XORPS requires XMM register as destination".to_string(),
                    ));
                }

                let dst_value = self.engine.cpu.read_xmm(dst_reg);
                let addr = self.calculate_memory_address(inst, 1)?;
                let src_value = self.read_memory_128(addr)?;

                // Perform bitwise XOR
                let result = dst_value ^ src_value;

                self.engine.cpu.write_xmm(dst_reg, result);
                Ok(())
            }
            _ => Err(EmulatorError::UnsupportedInstruction(format!(
                "Unsupported XORPS operand types: {:?}, {:?}",
                inst.op_kind(0),
                inst.op_kind(1)
            ))),
        }
    }

    fn execute_cmpps(&mut self, inst: &Instruction) -> Result<()> {
        // CMPPS: Compare Packed Single-Precision Floating-Point Values
        // Compares four 32-bit floats simultaneously
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
                    "Invalid CMPPS source".to_string(),
                ))
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let imm = inst.immediate(2) as u8;

        // Extract four 32-bit floats from each operand
        let dst_floats = [
            f32::from_bits(dst_value as u32),
            f32::from_bits((dst_value >> 32) as u32),
            f32::from_bits((dst_value >> 64) as u32),
            f32::from_bits((dst_value >> 96) as u32),
        ];
        let src_floats = [
            f32::from_bits(src_value as u32),
            f32::from_bits((src_value >> 32) as u32),
            f32::from_bits((src_value >> 64) as u32),
            f32::from_bits((src_value >> 96) as u32),
        ];

        let mut result = 0u128;
        for i in 0..4 {
            let cmp_result = self.compare_floats(dst_floats[i], src_floats[i], imm);
            if cmp_result {
                result |= 0xFFFFFFFFu128 << (i * 32);
            }
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    fn execute_cmpss(&mut self, inst: &Instruction) -> Result<()> {
        // CMPSS: Compare Scalar Single-Precision Floating-Point Values
        // Compares only the lowest 32-bit float, preserves upper bits
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let src_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_xmm(src_reg) as u32
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                self.read_memory_sized(addr, 4)? as u32
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid CMPSS source".to_string(),
                ))
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let imm = inst.immediate(2) as u8;

        let dst_float = f32::from_bits(dst_value as u32);
        let src_float = f32::from_bits(src_value);

        let cmp_result = self.compare_floats(dst_float, src_float, imm);
        let result_low = if cmp_result { 0xFFFFFFFFu32 } else { 0 };

        // Preserve upper 96 bits, replace lower 32 bits
        let result = (dst_value & !0xFFFFFFFF) | result_low as u128;

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    fn execute_comiss(&mut self, inst: &Instruction) -> Result<()> {
        // COMISS: Compare Ordered Scalar Single-Precision Floating-Point Values and Set EFLAGS
        let src1_reg = self.convert_register(inst.op_register(0))?;
        let src1_float = f32::from_bits(self.engine.cpu.read_xmm(src1_reg) as u32);

        let src2_float = match inst.op_kind(1) {
            OpKind::Register => {
                let src2_reg = self.convert_register(inst.op_register(1))?;
                f32::from_bits(self.engine.cpu.read_xmm(src2_reg) as u32)
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                f32::from_bits(self.read_memory_sized(addr, 4)? as u32)
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid COMISS source".to_string(),
                ))
            }
        };

        self.set_comparison_flags(src1_float, src2_float, false);
        Ok(())
    }

    fn execute_ucomiss(&mut self, inst: &Instruction) -> Result<()> {
        // UCOMISS: Compare Unordered Scalar Single-Precision Floating-Point Values and Set EFLAGS
        let src1_reg = self.convert_register(inst.op_register(0))?;
        let src1_float = f32::from_bits(self.engine.cpu.read_xmm(src1_reg) as u32);

        let src2_float = match inst.op_kind(1) {
            OpKind::Register => {
                let src2_reg = self.convert_register(inst.op_register(1))?;
                f32::from_bits(self.engine.cpu.read_xmm(src2_reg) as u32)
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                f32::from_bits(self.read_memory_sized(addr, 4)? as u32)
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid UCOMISS source".to_string(),
                ))
            }
        };

        self.set_comparison_flags(src1_float, src2_float, true);
        Ok(())
    }

    fn compare_floats(&self, a: f32, b: f32, imm: u8) -> bool {
        match imm {
            0 => a == b,                      // Equal
            1 => a < b,                       // Less than
            2 => a <= b,                      // Less than or equal
            3 => a.is_nan() || b.is_nan(),    // Unordered (NaN)
            4 => a != b,                      // Not equal
            5 => !(a < b),                    // Not less than
            6 => !(a <= b),                   // Not less than or equal
            7 => !(a.is_nan() || b.is_nan()), // Ordered (not NaN)
            _ => false,
        }
    }

    fn set_comparison_flags(&mut self, a: f32, b: f32, unordered_on_nan: bool) {
        self.engine.cpu.rflags.remove(Flags::ZF);
        self.engine.cpu.rflags.remove(Flags::CF);
        self.engine.cpu.rflags.remove(Flags::PF);

        if a.is_nan() || b.is_nan() {
            if unordered_on_nan {
                // Unordered result for UCOMISS
                self.engine.cpu.rflags.insert(Flags::ZF);
                self.engine.cpu.rflags.insert(Flags::CF);
                self.engine.cpu.rflags.insert(Flags::PF);
            } else {
                // Ordered comparison with NaN - set all flags for invalid operation
                self.engine.cpu.rflags.insert(Flags::ZF);
                self.engine.cpu.rflags.insert(Flags::CF);
                self.engine.cpu.rflags.insert(Flags::PF);
            }
        } else if a == b {
            self.engine.cpu.rflags.insert(Flags::ZF);
        } else if a < b {
            self.engine.cpu.rflags.insert(Flags::CF);
        }
        // Greater than: no flags set (all clear)
    }

    fn execute_movaps(&mut self, inst: &Instruction) -> Result<()> {
        // MOVAPS: Move Aligned Packed Single-Precision Floating-Point Values
        // Same as MOVDQA/MOVDQU but with float semantics (we ignore alignment requirements)
        match (inst.op_kind(0), inst.op_kind(1)) {
            (OpKind::Register, OpKind::Register) => {
                let dst_reg = self.convert_register(inst.op_register(0))?;
                let src_reg = self.convert_register(inst.op_register(1))?;
                let src_value = self.engine.cpu.read_xmm(src_reg);
                self.engine.cpu.write_xmm(dst_reg, src_value);
                Ok(())
            }
            (OpKind::Register, OpKind::Memory) => {
                let dst_reg = self.convert_register(inst.op_register(0))?;
                let addr = self.calculate_memory_address(inst, 1)?;
                let src_value = self.read_memory_128(addr)?;
                self.engine.cpu.write_xmm(dst_reg, src_value);
                Ok(())
            }
            (OpKind::Memory, OpKind::Register) => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                let addr = self.calculate_memory_address(inst, 0)?;
                let src_value = self.engine.cpu.read_xmm(src_reg);
                self.write_memory_128(addr, src_value)?;
                Ok(())
            }
            _ => Err(EmulatorError::UnsupportedInstruction(format!(
                "Unsupported MOVAPS operand types: {:?}, {:?}",
                inst.op_kind(0),
                inst.op_kind(1)
            ))),
        }
    }

    fn execute_addps(&mut self, inst: &Instruction) -> Result<()> {
        // ADDPS: Add Packed Single-Precision Floating-Point Values
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
                    "Invalid ADDPS source".to_string(),
                ))
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let result = self.packed_float_operation(dst_value, src_value, |a, b| a + b);
        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    fn execute_subps(&mut self, inst: &Instruction) -> Result<()> {
        // SUBPS: Subtract Packed Single-Precision Floating-Point Values
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
                    "Invalid SUBPS source".to_string(),
                ))
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let result = self.packed_float_operation(dst_value, src_value, |a, b| a - b);
        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    fn execute_mulps(&mut self, inst: &Instruction) -> Result<()> {
        // MULPS: Multiply Packed Single-Precision Floating-Point Values
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
                    "Invalid MULPS source".to_string(),
                ))
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let result = self.packed_float_operation(dst_value, src_value, |a, b| a * b);
        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    fn execute_divps(&mut self, inst: &Instruction) -> Result<()> {
        // DIVPS: Divide Packed Single-Precision Floating-Point Values
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
                    "Invalid DIVPS source".to_string(),
                ))
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let result = self.packed_float_operation(dst_value, src_value, |a, b| a / b);
        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    fn execute_andps(&mut self, inst: &Instruction) -> Result<()> {
        // ANDPS: Bitwise AND Packed Single-Precision Floating-Point Values
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
                    "Invalid ANDPS source".to_string(),
                ))
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let result = dst_value & src_value;
        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    fn execute_orps(&mut self, inst: &Instruction) -> Result<()> {
        // ORPS: Bitwise OR Packed Single-Precision Floating-Point Values
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
                    "Invalid ORPS source".to_string(),
                ))
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let result = dst_value | src_value;
        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    fn packed_float_operation<F>(&self, dst: u128, src: u128, op: F) -> u128
    where
        F: Fn(f32, f32) -> f32,
    {
        // Extract four 32-bit floats from each operand
        let dst_floats = [
            f32::from_bits(dst as u32),
            f32::from_bits((dst >> 32) as u32),
            f32::from_bits((dst >> 64) as u32),
            f32::from_bits((dst >> 96) as u32),
        ];
        let src_floats = [
            f32::from_bits(src as u32),
            f32::from_bits((src >> 32) as u32),
            f32::from_bits((src >> 64) as u32),
            f32::from_bits((src >> 96) as u32),
        ];

        // Apply operation to each pair
        let results = [
            op(dst_floats[0], src_floats[0]),
            op(dst_floats[1], src_floats[1]),
            op(dst_floats[2], src_floats[2]),
            op(dst_floats[3], src_floats[3]),
        ];

        // Pack results back into u128
        (results[0].to_bits() as u128)
            | ((results[1].to_bits() as u128) << 32)
            | ((results[2].to_bits() as u128) << 64)
            | ((results[3].to_bits() as u128) << 96)
    }

    fn execute_movsb(&mut self, inst: &Instruction) -> Result<()> {
        // MOVSB: Move Byte from [RSI] to [RDI]
        let count = if inst.has_rep_prefix() || inst.has_repne_prefix() {
            self.engine.cpu.read_reg(Register::RCX)
        } else {
            1
        };

        let mut remaining = count;
        while remaining > 0 {
            let rsi = self.engine.cpu.read_reg(Register::RSI);
            let rdi = self.engine.cpu.read_reg(Register::RDI);

            // Move byte from [RSI] to [RDI]
            let byte = self.read_memory_sized(rsi, 1)? as u8;
            self.write_memory_sized(rdi, byte as u64, 1)?;

            // Update RSI and RDI based on direction flag
            let df = self.engine.cpu.rflags.contains(Flags::DF);
            let increment = if df { -1i64 as u64 } else { 1 };

            self.engine
                .cpu
                .write_reg(Register::RSI, rsi.wrapping_add(increment));
            self.engine
                .cpu
                .write_reg(Register::RDI, rdi.wrapping_add(increment));

            remaining -= 1;
        }

        if inst.has_rep_prefix() || inst.has_repne_prefix() {
            self.engine.cpu.write_reg(Register::RCX, 0);
        }

        Ok(())
    }

    fn execute_stosb(&mut self, inst: &Instruction) -> Result<()> {
        // STOSB: Store AL to [RDI]
        let count = if inst.has_rep_prefix() || inst.has_repne_prefix() {
            self.engine.cpu.read_reg(Register::RCX)
        } else {
            1
        };

        let al_value = (self.engine.cpu.read_reg(Register::RAX) & 0xFF) as u8;
        let mut remaining = count;

        while remaining > 0 {
            let rdi = self.engine.cpu.read_reg(Register::RDI);

            // Store AL to [RDI]
            self.write_memory_sized(rdi, al_value as u64, 1)?;

            // Update RDI based on direction flag
            let df = self.engine.cpu.rflags.contains(Flags::DF);
            let increment = if df { -1i64 as u64 } else { 1 };

            self.engine
                .cpu
                .write_reg(Register::RDI, rdi.wrapping_add(increment));

            remaining -= 1;
        }

        if inst.has_rep_prefix() || inst.has_repne_prefix() {
            self.engine.cpu.write_reg(Register::RCX, 0);
        }

        Ok(())
    }

    fn execute_lodsb(&mut self, inst: &Instruction) -> Result<()> {
        // LODSB: Load byte from [RSI] into AL
        let count = if inst.has_rep_prefix() || inst.has_repne_prefix() {
            self.engine.cpu.read_reg(Register::RCX)
        } else {
            1
        };

        let mut remaining = count;

        while remaining > 0 {
            let rsi = self.engine.cpu.read_reg(Register::RSI);

            // Load byte from [RSI] into AL
            let byte = self.read_memory_sized(rsi, 1)? as u8;
            let rax = self.engine.cpu.read_reg(Register::RAX);
            self.engine
                .cpu
                .write_reg(Register::RAX, (rax & !0xFF) | (byte as u64));

            // Update RSI based on direction flag
            let df = self.engine.cpu.rflags.contains(Flags::DF);
            let increment = if df { -1i64 as u64 } else { 1 };

            self.engine
                .cpu
                .write_reg(Register::RSI, rsi.wrapping_add(increment));

            remaining -= 1;
        }

        if inst.has_rep_prefix() || inst.has_repne_prefix() {
            self.engine.cpu.write_reg(Register::RCX, 0);
        }

        Ok(())
    }

    fn execute_scasb(&mut self, inst: &Instruction) -> Result<()> {
        // SCASB: Compare AL with [RDI]
        let al_value = (self.engine.cpu.read_reg(Register::RAX) & 0xFF) as u8;

        if inst.has_repne_prefix() {
            // REPNE SCASB: Repeat while not equal and RCX > 0
            while self.engine.cpu.read_reg(Register::RCX) > 0 {
                let rdi = self.engine.cpu.read_reg(Register::RDI);
                let byte = self.read_memory_sized(rdi, 1)? as u8;

                // Compare AL with [RDI]
                self.update_flags_arithmetic_iced(
                    al_value as u64,
                    byte as u64,
                    (al_value as i16 - byte as i16) as u64,
                    true,
                    inst,
                )?;

                // Update RDI and RCX
                let df = self.engine.cpu.rflags.contains(Flags::DF);
                let increment = if df { -1i64 as u64 } else { 1 };
                self.engine
                    .cpu
                    .write_reg(Register::RDI, rdi.wrapping_add(increment));
                self.engine
                    .cpu
                    .write_reg(Register::RCX, self.engine.cpu.read_reg(Register::RCX) - 1);

                // Stop if equal (ZF set)
                if self.engine.cpu.rflags.contains(Flags::ZF) {
                    break;
                }
            }
        } else if inst.has_rep_prefix() {
            // REPE SCASB: Repeat while equal and RCX > 0
            while self.engine.cpu.read_reg(Register::RCX) > 0 {
                let rdi = self.engine.cpu.read_reg(Register::RDI);
                let byte = self.read_memory_sized(rdi, 1)? as u8;

                // Compare AL with [RDI]
                self.update_flags_arithmetic_iced(
                    al_value as u64,
                    byte as u64,
                    (al_value as i16 - byte as i16) as u64,
                    true,
                    inst,
                )?;

                // Update RDI and RCX
                let df = self.engine.cpu.rflags.contains(Flags::DF);
                let increment = if df { -1i64 as u64 } else { 1 };
                self.engine
                    .cpu
                    .write_reg(Register::RDI, rdi.wrapping_add(increment));
                self.engine
                    .cpu
                    .write_reg(Register::RCX, self.engine.cpu.read_reg(Register::RCX) - 1);

                // Stop if not equal (ZF clear)
                if !self.engine.cpu.rflags.contains(Flags::ZF) {
                    break;
                }
            }
        } else {
            // Single SCASB
            let rdi = self.engine.cpu.read_reg(Register::RDI);
            let byte = self.read_memory_sized(rdi, 1)? as u8;

            // Compare AL with [RDI]
            self.update_flags_arithmetic_iced(
                al_value as u64,
                byte as u64,
                (al_value as i16 - byte as i16) as u64,
                true,
                inst,
            )?;

            // Update RDI
            let df = self.engine.cpu.rflags.contains(Flags::DF);
            let increment = if df { -1i64 as u64 } else { 1 };
            self.engine
                .cpu
                .write_reg(Register::RDI, rdi.wrapping_add(increment));
        }

        Ok(())
    }

    fn execute_cmpsb(&mut self, inst: &Instruction) -> Result<()> {
        // CMPSB: Compare bytes at [RSI] and [RDI]
        if inst.has_repne_prefix() {
            // REPNE CMPSB: Repeat while not equal and RCX > 0
            while self.engine.cpu.read_reg(Register::RCX) > 0 {
                let rsi = self.engine.cpu.read_reg(Register::RSI);
                let rdi = self.engine.cpu.read_reg(Register::RDI);
                let byte1 = self.read_memory_sized(rsi, 1)? as u8;
                let byte2 = self.read_memory_sized(rdi, 1)? as u8;

                // Compare bytes
                self.update_flags_arithmetic_iced(
                    byte1 as u64,
                    byte2 as u64,
                    (byte1 as i16 - byte2 as i16) as u64,
                    true,
                    inst,
                )?;

                // Update RSI, RDI and RCX
                let df = self.engine.cpu.rflags.contains(Flags::DF);
                let increment = if df { -1i64 as u64 } else { 1 };
                self.engine
                    .cpu
                    .write_reg(Register::RSI, rsi.wrapping_add(increment));
                self.engine
                    .cpu
                    .write_reg(Register::RDI, rdi.wrapping_add(increment));
                self.engine
                    .cpu
                    .write_reg(Register::RCX, self.engine.cpu.read_reg(Register::RCX) - 1);

                // Stop if equal (ZF set)
                if self.engine.cpu.rflags.contains(Flags::ZF) {
                    break;
                }
            }
        } else if inst.has_rep_prefix() {
            // REPE CMPSB: Repeat while equal and RCX > 0
            while self.engine.cpu.read_reg(Register::RCX) > 0 {
                let rsi = self.engine.cpu.read_reg(Register::RSI);
                let rdi = self.engine.cpu.read_reg(Register::RDI);
                let byte1 = self.read_memory_sized(rsi, 1)? as u8;
                let byte2 = self.read_memory_sized(rdi, 1)? as u8;

                // Compare bytes
                self.update_flags_arithmetic_iced(
                    byte1 as u64,
                    byte2 as u64,
                    (byte1 as i16 - byte2 as i16) as u64,
                    true,
                    inst,
                )?;

                // Update RSI, RDI and RCX
                let df = self.engine.cpu.rflags.contains(Flags::DF);
                let increment = if df { -1i64 as u64 } else { 1 };
                self.engine
                    .cpu
                    .write_reg(Register::RSI, rsi.wrapping_add(increment));
                self.engine
                    .cpu
                    .write_reg(Register::RDI, rdi.wrapping_add(increment));
                self.engine
                    .cpu
                    .write_reg(Register::RCX, self.engine.cpu.read_reg(Register::RCX) - 1);

                // Stop if not equal (ZF clear)
                if !self.engine.cpu.rflags.contains(Flags::ZF) {
                    break;
                }
            }
        } else {
            // Single CMPSB
            let rsi = self.engine.cpu.read_reg(Register::RSI);
            let rdi = self.engine.cpu.read_reg(Register::RDI);
            let byte1 = self.read_memory_sized(rsi, 1)? as u8;
            let byte2 = self.read_memory_sized(rdi, 1)? as u8;

            // Compare bytes
            self.update_flags_arithmetic_iced(
                byte1 as u64,
                byte2 as u64,
                (byte1 as i16 - byte2 as i16) as u64,
                true,
                inst,
            )?;

            // Update RSI and RDI
            let df = self.engine.cpu.rflags.contains(Flags::DF);
            let increment = if df { -1i64 as u64 } else { 1 };
            self.engine
                .cpu
                .write_reg(Register::RSI, rsi.wrapping_add(increment));
            self.engine
                .cpu
                .write_reg(Register::RDI, rdi.wrapping_add(increment));
        }

        Ok(())
    }

    fn execute_adc(&mut self, inst: &Instruction) -> Result<()> {
        // ADC: Add with Carry
        // Adds the source operand and the carry flag to the destination operand
        let dst_value = self.read_operand(inst, 0)?;
        let src_value = self.read_operand(inst, 1)?;
        let carry = if self.engine.cpu.rflags.contains(Flags::CF) {
            1
        } else {
            0
        };

        let result = dst_value.wrapping_add(src_value).wrapping_add(carry);

        // Update flags - for ADC, we need to consider the total operation
        // The flags should be calculated as if we did: dst + (src + carry)
        let effective_src = src_value.wrapping_add(carry);
        self.update_flags_arithmetic_iced(dst_value, effective_src, result, false, inst)?;

        // Write result back to destination
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    fn execute_not(&mut self, inst: &Instruction) -> Result<()> {
        // NOT: Bitwise NOT (one's complement)
        let dst_value = self.read_operand(inst, 0)?;
        let result = !dst_value;

        // NOT doesn't affect flags
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    fn execute_ror(&mut self, inst: &Instruction) -> Result<()> {
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
                ))
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

    fn execute_xchg(&mut self, inst: &Instruction) -> Result<()> {
        // XCHG: Exchange values between two operands
        let operand1_value = self.read_operand(inst, 0)?;
        let operand2_value = self.read_operand(inst, 1)?;

        // Write values in swapped positions
        self.write_operand(inst, 0, operand2_value)?;
        self.write_operand(inst, 1, operand1_value)?;

        // XCHG doesn't affect flags
        Ok(())
    }

    fn execute_loop(&mut self, inst: &Instruction) -> Result<()> {
        // LOOP: Decrement RCX/ECX and jump if not zero
        // Get address mode to determine if using RCX or ECX
        let address_size = match self.engine.mode {
            EngineMode::Mode64 => 8, // Use RCX in 64-bit mode
            EngineMode::Mode32 => 4, // Use ECX in 32-bit mode
            EngineMode::Mode16 => 2, // Use CX in 16-bit mode
        };

        let counter_reg = Register::RCX;
        let counter_value = self.engine.cpu.read_reg(counter_reg);

        // Decrement counter based on address size
        let new_counter = match address_size {
            8 => counter_value.wrapping_sub(1),
            4 => {
                (counter_value & 0xFFFFFFFF00000000)
                    | ((counter_value as u32).wrapping_sub(1) as u64)
            }
            2 => {
                (counter_value & 0xFFFFFFFFFFFF0000)
                    | ((counter_value as u16).wrapping_sub(1) as u64)
            }
            _ => unreachable!(),
        };

        self.engine.cpu.write_reg(counter_reg, new_counter);

        // Check if counter is zero (based on address size)
        let counter_zero = match address_size {
            8 => new_counter == 0,
            4 => (new_counter as u32) == 0,
            2 => (new_counter as u16) == 0,
            _ => unreachable!(),
        };

        // Jump if counter is not zero
        if !counter_zero {
            let target_address = inst.near_branch_target();
            self.engine.cpu.rip = target_address;
        }

        Ok(())
    }

    fn execute_loope(&mut self, inst: &Instruction) -> Result<()> {
        // LOOPE: Decrement RCX/ECX and jump if not zero AND ZF=1
        let address_size = match self.engine.mode {
            EngineMode::Mode64 => 8,
            EngineMode::Mode32 => 4,
            EngineMode::Mode16 => 2,
        };

        let counter_reg = Register::RCX;
        let counter_value = self.engine.cpu.read_reg(counter_reg);

        // Decrement counter
        let new_counter = match address_size {
            8 => counter_value.wrapping_sub(1),
            4 => {
                (counter_value & 0xFFFFFFFF00000000)
                    | ((counter_value as u32).wrapping_sub(1) as u64)
            }
            2 => {
                (counter_value & 0xFFFFFFFFFFFF0000)
                    | ((counter_value as u16).wrapping_sub(1) as u64)
            }
            _ => unreachable!(),
        };

        self.engine.cpu.write_reg(counter_reg, new_counter);

        // Check conditions
        let counter_zero = match address_size {
            8 => new_counter == 0,
            4 => (new_counter as u32) == 0,
            2 => (new_counter as u16) == 0,
            _ => unreachable!(),
        };

        let zero_flag_set = self.engine.cpu.rflags.contains(Flags::ZF);

        // Jump if counter is not zero AND zero flag is set
        if !counter_zero && zero_flag_set {
            let target_address = inst.near_branch_target();
            self.engine.cpu.rip = target_address;
        }

        Ok(())
    }

    fn execute_loopne(&mut self, inst: &Instruction) -> Result<()> {
        // LOOPNE: Decrement RCX/ECX and jump if not zero AND ZF=0
        let address_size = match self.engine.mode {
            EngineMode::Mode64 => 8,
            EngineMode::Mode32 => 4,
            EngineMode::Mode16 => 2,
        };

        let counter_reg = Register::RCX;
        let counter_value = self.engine.cpu.read_reg(counter_reg);

        // Decrement counter
        let new_counter = match address_size {
            8 => counter_value.wrapping_sub(1),
            4 => {
                (counter_value & 0xFFFFFFFF00000000)
                    | ((counter_value as u32).wrapping_sub(1) as u64)
            }
            2 => {
                (counter_value & 0xFFFFFFFFFFFF0000)
                    | ((counter_value as u16).wrapping_sub(1) as u64)
            }
            _ => unreachable!(),
        };

        self.engine.cpu.write_reg(counter_reg, new_counter);

        // Check conditions
        let counter_zero = match address_size {
            8 => new_counter == 0,
            4 => (new_counter as u32) == 0,
            2 => (new_counter as u16) == 0,
            _ => unreachable!(),
        };

        let zero_flag_clear = !self.engine.cpu.rflags.contains(Flags::ZF);

        // Jump if counter is not zero AND zero flag is clear
        if !counter_zero && zero_flag_clear {
            let target_address = inst.near_branch_target();
            self.engine.cpu.rip = target_address;
        }

        Ok(())
    }

    fn execute_bt(&mut self, inst: &Instruction) -> Result<()> {
        // BT: Bit Test - Test bit in first operand by second operand, set CF accordingly
        let bit_base = self.read_operand_value(inst, 0)?;
        let bit_offset = self.read_operand_value(inst, 1)?;
        
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

    fn execute_bts(&mut self, inst: &Instruction) -> Result<()> {
        // BTS: Bit Test and Set - Test bit and set it to 1
        let bit_base = self.read_operand_value(inst, 0)?;
        let bit_offset = self.read_operand_value(inst, 1)?;
        
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
        self.write_operand_value(inst, 0, new_value)?;
        
        Ok(())
    }

    fn execute_btr(&mut self, inst: &Instruction) -> Result<()> {
        // BTR: Bit Test and Reset - Test bit and set it to 0
        let bit_base = self.read_operand_value(inst, 0)?;
        let bit_offset = self.read_operand_value(inst, 1)?;
        
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
        self.write_operand_value(inst, 0, new_value)?;
        
        Ok(())
    }

    fn execute_btc(&mut self, inst: &Instruction) -> Result<()> {
        // BTC: Bit Test and Complement - Test bit and flip it
        let bit_base = self.read_operand_value(inst, 0)?;
        let bit_offset = self.read_operand_value(inst, 1)?;
        
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
        self.write_operand_value(inst, 0, new_value)?;
        
        Ok(())
    }

    fn execute_bsf(&mut self, inst: &Instruction) -> Result<()> {
        // BSF: Bit Scan Forward - Find first set bit (from LSB)
        let source = self.read_operand_value(inst, 1)?;
        
        if source == 0 {
            // If source is 0, set ZF and destination is undefined
            self.engine.cpu.rflags.insert(Flags::ZF);
        } else {
            // Find the position of the first set bit
            let bit_pos = source.trailing_zeros() as u64;
            self.engine.cpu.rflags.remove(Flags::ZF);
            
            // Write result to destination
            self.write_operand_value(inst, 0, bit_pos)?;
        }
        
        Ok(())
    }

    fn execute_bsr(&mut self, inst: &Instruction) -> Result<()> {
        // BSR: Bit Scan Reverse - Find first set bit (from MSB)
        let source = self.read_operand_value(inst, 1)?;
        
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
                _ => return Err(EmulatorError::UnsupportedInstruction(format!(
                    "Unsupported BSR operand size: {}",
                    size
                ))),
            };
            
            self.engine.cpu.rflags.remove(Flags::ZF);
            
            // Write result to destination
            self.write_operand_value(inst, 0, bit_pos)?;
        }
        
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
            // For addition, check if result overflowed by detecting wraparound
            // Carry occurs when the result is smaller than either operand due to overflow
            if masked_result < masked_dst || masked_result < masked_src {
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
