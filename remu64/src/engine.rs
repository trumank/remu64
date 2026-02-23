#![allow(clippy::neg_cmp_op_on_partial_ord)]

mod instructions;

use crate::DEFAULT_PAGE_SIZE;
use crate::OwnedMemory;
use crate::cpu::{CpuState, Flags, Register};
use crate::error::{EmulatorError, Result};
use crate::hooks::{HookAction, HookManager, NoHooks};
use crate::memory::{MemoryTrait, Permission};
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register as IcedRegister};

#[derive(Debug, Clone, Copy)]
pub enum EngineMode {
    Mode16,
    Mode32,
    Mode64,
}

#[derive(Clone)]
pub struct Engine<M: MemoryTrait<PS>, const PS: u64 = DEFAULT_PAGE_SIZE> {
    pub cpu: CpuState,
    pub memory: M,
    mode: EngineMode,
}

impl Engine<OwnedMemory, DEFAULT_PAGE_SIZE> {
    pub fn new(mode: EngineMode) -> Self {
        Self {
            cpu: CpuState::new(),
            memory: OwnedMemory::new(),
            mode,
        }
    }
}
impl<M: MemoryTrait<PS>, const PS: u64> Engine<M, PS> {
    pub fn new_memory(mode: EngineMode, memory: M) -> Self {
        Self {
            cpu: CpuState::new(),
            memory,
            mode,
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

    pub fn ymm_read(&self, reg: Register) -> [u128; 2] {
        self.cpu.read_ymm(reg)
    }

    pub fn ymm_write(&mut self, reg: Register, value: [u128; 2]) {
        self.cpu.write_ymm(reg, value);
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

    /// Low-level execution function that simply resumes from current state
    /// - Does NOT modify RIP/instruction pointer
    /// - Does NOT handle timeouts or instruction limits
    /// - Does NOT reset any state
    /// - Simply executes instructions until hook returns Stop
    /// - Returns Ok(()) on normal completion, Err on execution error
    pub fn emu_resume_with_hooks<H: HookManager<M, PS>>(&mut self, hooks: &mut H) -> Result<()> {
        ExecutionContext {
            engine: self,
            hooks,
        }
        .emu_resume()
    }

    pub fn emu_start_with_hooks<H: HookManager<M, PS>>(
        &mut self,
        begin: u64,
        until: u64,
        timeout: u64,
        count: usize,
        hooks: &mut H,
    ) -> Result<()> {
        ExecutionContext {
            engine: self,
            hooks,
        }
        .emu_start(begin, until, timeout, count)
    }
}

struct ExecutionContext<'a, H: HookManager<M, PS>, M: MemoryTrait<PS>, const PS: u64> {
    engine: &'a mut Engine<M, PS>,
    hooks: &'a mut H,
}

/// Orchestrating hook wrapper that adds timeout, instruction counting, and until address logic
/// on top of user-provided hooks for the high-level emu_start functions
struct OrchestratingHooks<'a, H, M, const PS: u64>
where
    H: HookManager<M, PS>,
    M: MemoryTrait<PS>,
{
    user_hooks: &'a mut H,
    until_address: u64,
    instruction_count: u64,
    max_instructions: usize,
    start_time: std::time::Instant,
    timeout_duration: Option<std::time::Duration>,
    _phantom: std::marker::PhantomData<M>,
}

impl<'a, H, M, const PS: u64> HookManager<M, PS> for OrchestratingHooks<'a, H, M, PS>
where
    H: HookManager<M, PS>,
    M: MemoryTrait<PS>,
{
    fn on_pre_code(&mut self, engine: &mut Engine<M, PS>, address: u64) -> Result<HookAction> {
        // Check until address condition before any decoding/memory access
        if self.until_address != 0 && address == self.until_address {
            return Ok(HookAction::Stop);
        }

        // Check timeout condition
        if let Some(timeout) = self.timeout_duration
            && self.start_time.elapsed() > timeout
        {
            return Ok(HookAction::Stop);
        }

        // Call user pre_code hook
        self.user_hooks.on_pre_code(engine, address)
    }

    fn on_code(
        &mut self,
        engine: &mut Engine<M, PS>,
        address: u64,
        size: usize,
    ) -> Result<HookAction> {
        // Check instruction count limit
        if self.max_instructions > 0 && self.instruction_count >= self.max_instructions as u64 {
            return Ok(HookAction::Stop);
        }

        // Call user hooks
        let user_action = self.user_hooks.on_code(engine, address, size)?;

        // Increment instruction count only if we're not skipping/stopping
        match user_action {
            HookAction::Continue => self.instruction_count += 1,
            HookAction::Skip => self.instruction_count += 1,
            HookAction::Stop => {}
        }

        Ok(user_action)
    }

    fn on_mem_read(&mut self, engine: &mut Engine<M, PS>, address: u64, size: usize) -> Result<()> {
        self.user_hooks.on_mem_read(engine, address, size)
    }

    fn on_mem_post_read(
        &mut self,
        engine: &mut Engine<M, PS>,
        address: u64,
        data: &[u8],
    ) -> Result<()> {
        self.user_hooks.on_mem_post_read(engine, address, data)
    }

    fn on_mem_write(
        &mut self,
        engine: &mut Engine<M, PS>,
        address: u64,
        data: &[u8],
    ) -> Result<()> {
        self.user_hooks.on_mem_write(engine, address, data)
    }

    fn on_mem_fault(
        &mut self,
        engine: &mut Engine<M, PS>,
        address: u64,
        size: usize,
    ) -> Result<bool> {
        self.user_hooks.on_mem_fault(engine, address, size)
    }

    fn on_interrupt(&mut self, engine: &mut Engine<M, PS>, intno: u64, size: usize) -> Result<()> {
        self.user_hooks.on_interrupt(engine, intno, size)
    }

    fn on_invalid(&mut self, engine: &mut Engine<M, PS>, address: u64, size: usize) -> Result<()> {
        self.user_hooks.on_invalid(engine, address, size)
    }
}

impl<H: HookManager<M, PS>, M: MemoryTrait<PS>, const PS: u64> ExecutionContext<'_, H, M, PS> {
    /// Low-level execution that resumes from current state
    /// Executes instructions until hook returns Stop
    fn emu_resume(&mut self) -> Result<()> {
        while self.step()? {}
        Ok(())
    }

    /// Start emulation with custom hooks
    fn emu_start(&mut self, begin: u64, until: u64, timeout: u64, count: usize) -> Result<()> {
        // Set initial RIP
        self.engine.cpu.rip = begin;

        // Create orchestrating hooks wrapper
        let timeout_duration = if timeout > 0 {
            Some(std::time::Duration::from_micros(timeout))
        } else {
            None
        };

        let mut orchestrating_hooks = OrchestratingHooks {
            user_hooks: self.hooks,
            until_address: until,
            instruction_count: 0,
            max_instructions: count,
            start_time: std::time::Instant::now(),
            timeout_duration,
            _phantom: std::marker::PhantomData,
        };

        // Use the low-level resume function
        ExecutionContext {
            engine: self.engine,
            hooks: &mut orchestrating_hooks,
        }
        .emu_resume()
    }

    fn step(&mut self) -> Result<bool> {
        let rip = self.engine.cpu.rip;

        // Call pre-code hook before any memory access or decoding
        let pre_action = self.hooks.on_pre_code(self.engine, rip)?;
        match pre_action {
            HookAction::Stop => return Ok(false),
            HookAction::Skip => {
                // Skip is invalid for pre_code hook since we don't know instruction size yet
                return Err(EmulatorError::InvalidInstruction(rip));
            }
            HookAction::Continue => {}
        }

        // Check if we can execute at this address, but allow memory fault hooks to handle unmapped memory
        match self.engine.memory.permissions(rip) {
            Ok(perms) => {
                // Memory is mapped, check if it's executable
                if !perms.contains(Permission::EXEC) {
                    return Err(EmulatorError::PermissionDenied(rip));
                }
            }
            Err(EmulatorError::UnmappedMemory(_)) => {
                // Memory is unmapped, try to handle with memory fault hooks
                // Try to let the memory fault hook handle this
                // TODO refactor the decoder to do memory reads instead of operate on a slice of data
                if !self.hooks.on_mem_fault(self.engine, rip, 1)? {
                    // Hook couldn't handle it, return the original error
                    return Err(EmulatorError::UnmappedMemory(rip));
                }
                // Hook handled it, check permissions again
                let perms = self.engine.memory.permissions(rip)?;
                if !perms.contains(Permission::EXEC) {
                    return Err(EmulatorError::PermissionDenied(rip));
                }
            }
            Err(e) => return Err(e), // Other errors are fatal
        }

        // Decode instruction with page boundary awareness
        let bitness = match self.engine.mode {
            EngineMode::Mode16 => 16,
            EngineMode::Mode32 => 32,
            EngineMode::Mode64 => 64,
        };

        let inst = self.decode_instruction_with_page_boundaries(rip, bitness)?;

        let hook_action = self.hooks.on_code(self.engine, rip, inst.len())?;

        match hook_action {
            HookAction::Continue => {
                self.engine.cpu.rip = rip + inst.len() as u64;
                self.execute_instruction(&inst)?;
                Ok(true) // Continue emulation
            }
            HookAction::Skip => {
                // Just advance RIP, don't execute the instruction
                self.engine.cpu.rip = rip + inst.len() as u64;
                Ok(true) // Continue emulation
            }
            HookAction::Stop => {
                Ok(false) // Stop emulation
            }
        }
    }

    fn mem_read_with_hooks(&mut self, address: u64, buf: &mut [u8]) -> Result<()> {
        self.hooks.on_mem_read(self.engine, address, buf.len())?;

        // Try to read memory, handle faults with hooks
        let result = match self.engine.memory.read(address, buf) {
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
        };

        // Call post-read hook if read was successful
        if result.is_ok() {
            self.hooks.on_mem_post_read(self.engine, address, buf)?;
        }

        result
    }

    fn mem_write_with_hooks(&mut self, address: u64, buf: &[u8]) -> Result<()> {
        self.hooks.on_mem_write(self.engine, address, buf)?;

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

    fn decode_instruction_with_page_boundaries(
        &mut self,
        rip: u64,
        bitness: u32,
    ) -> Result<Instruction> {
        const CHUNK_SIZE: usize = 16;

        let mut inst_bytes = vec![];
        let mut chunk = [0u8; CHUNK_SIZE];

        loop {
            // Calculate the next address to read from
            let next_addr = rip + inst_bytes.len() as u64;

            // Calculate how many bytes we can read until the next page boundary
            let page_start = next_addr & !(PS - 1);
            let page_end = page_start + PS;
            let bytes_until_page_boundary = (page_end - next_addr) as usize;

            // Read either 16 bytes or until page boundary, whichever is smaller
            let chunk = &mut chunk[0..bytes_until_page_boundary.min(CHUNK_SIZE)];

            // Read more bytes
            self.mem_read_with_hooks(next_addr, chunk)?;

            // Check execute permissions (memory read already handled page faults)
            let perms = self.engine.memory.permissions(next_addr)?;
            if !perms.contains(Permission::EXEC) {
                return Err(EmulatorError::PermissionDenied(next_addr));
            }

            inst_bytes.extend_from_slice(chunk);

            // Try to decode with current bytes
            let mut decoder = Decoder::with_ip(bitness, &inst_bytes, rip, DecoderOptions::NONE);
            let inst = decoder.decode();

            match decoder.last_error() {
                iced_x86::DecoderError::None => return Ok(inst),
                iced_x86::DecoderError::InvalidInstruction => {
                    return Err(EmulatorError::InvalidInstruction(rip));
                }
                iced_x86::DecoderError::NoMoreBytes => {}
                err => unreachable!("Unhandled iced_x86 error {err:?}"),
            }
        }
    }

    fn execute_instruction(&mut self, inst: &Instruction) -> Result<()> {
        match inst.mnemonic() {
            Mnemonic::Mov => self.execute_mov(inst),
            Mnemonic::Push => self.execute_push(inst),
            Mnemonic::Pushfq => self.execute_pushfq(inst),
            Mnemonic::Popfq => self.execute_popfq(inst),
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
            Mnemonic::Seta => self.execute_seta(inst),
            Mnemonic::Setae => self.execute_setae(inst),
            Mnemonic::Setb => self.execute_setb(inst),
            Mnemonic::Setg => self.execute_setg(inst),
            Mnemonic::Setge => self.execute_setge(inst),
            Mnemonic::Setl => self.execute_setl(inst),
            Mnemonic::Sets => self.execute_sets(inst),
            Mnemonic::Setns => self.execute_setns(inst),
            Mnemonic::Seto => self.execute_seto(inst),
            Mnemonic::Setno => self.execute_setno(inst),
            Mnemonic::Setp => self.execute_setp(inst),
            Mnemonic::Setnp => self.execute_setnp(inst),
            Mnemonic::Shr => self.execute_shr(inst),
            Mnemonic::Shl => self.execute_shl(inst),
            Mnemonic::Cmovb => self.execute_cmovb(inst),
            Mnemonic::Cmovg => self.execute_cmovg(inst),
            Mnemonic::Cmovbe => self.execute_cmovbe(inst),
            Mnemonic::Cmovns => self.execute_cmovns(inst),
            Mnemonic::Cmova => self.execute_cmova(inst),
            Mnemonic::Cmovl => self.execute_cmovl(inst),
            Mnemonic::Cmovle => self.execute_cmovle(inst),
            Mnemonic::Cmove => self.execute_cmove(inst),
            Mnemonic::Cmovne => self.execute_cmovne(inst),
            Mnemonic::Cmovae => self.execute_cmovae(inst),
            Mnemonic::Cmovge => self.execute_cmovge(inst),
            Mnemonic::Cmovs => self.execute_cmovs(inst),
            Mnemonic::Cmovo => self.execute_cmovo(inst),
            Mnemonic::Cmovno => self.execute_cmovno(inst),
            Mnemonic::Cmovp => self.execute_cmovp(inst),
            Mnemonic::Cmovnp => self.execute_cmovnp(inst),
            Mnemonic::Vmovdqu => self.execute_vmovdqu(inst),
            Mnemonic::Vmovdqa => self.execute_vmovdqa(inst),
            Mnemonic::Movups => self.execute_movups(inst),
            Mnemonic::Vmovups => self.execute_vmovups(inst),
            Mnemonic::Vmovaps => self.execute_vmovaps(inst),
            Mnemonic::Movdqu => self.execute_movdqu(inst),
            Mnemonic::Movdqa => self.execute_movdqa(inst),
            Mnemonic::Movd => self.execute_movd(inst),
            Mnemonic::Movq => self.execute_movq(inst),
            Mnemonic::Movss => self.execute_movss(inst),
            Mnemonic::Movlhps => self.execute_movlhps(inst),
            Mnemonic::Vzeroupper => self.execute_vzeroupper(inst),
            Mnemonic::Vaddps => self.execute_vaddps(inst),
            Mnemonic::Vsubps => self.execute_vsubps(inst),
            Mnemonic::Vmulps => self.execute_vmulps(inst),
            Mnemonic::Vdivps => self.execute_vdivps(inst),
            Mnemonic::Vaddpd => self.execute_vaddpd(inst),
            Mnemonic::Vsubpd => self.execute_vsubpd(inst),
            Mnemonic::Vmulpd => self.execute_vmulpd(inst),
            Mnemonic::Vdivpd => self.execute_vdivpd(inst),
            Mnemonic::Vsqrtps => self.execute_vsqrtps(inst),
            Mnemonic::Vsqrtpd => self.execute_vsqrtpd(inst),
            Mnemonic::Vmaxps => self.execute_vmaxps(inst),
            Mnemonic::Vmaxpd => self.execute_vmaxpd(inst),
            Mnemonic::Vminps => self.execute_vminps(inst),
            Mnemonic::Vminpd => self.execute_vminpd(inst),
            Mnemonic::Vandps => self.execute_vandps(inst),
            Mnemonic::Vandpd => self.execute_vandpd(inst),
            Mnemonic::Vorps => self.execute_vorps(inst),
            Mnemonic::Vorpd => self.execute_vorpd(inst),
            Mnemonic::Vxorps => self.execute_vxorps(inst),
            Mnemonic::Vxorpd => self.execute_vxorpd(inst),
            Mnemonic::Vpxor => self.execute_vpxor(inst),
            Mnemonic::Vpxorq => self.execute_vpxorq(inst),
            Mnemonic::Vcmpps => self.execute_vcmpps(inst),
            Mnemonic::Vcmppd => self.execute_vcmppd(inst),
            Mnemonic::Vshufps => self.execute_vshufps(inst),
            Mnemonic::Vshufpd => self.execute_vshufpd(inst),
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
            Mnemonic::Enter => self.execute_enter(inst),
            Mnemonic::Leave => self.execute_leave(inst),
            Mnemonic::Popcnt => self.execute_popcnt(inst),
            Mnemonic::Lzcnt => self.execute_lzcnt(inst),
            Mnemonic::Tzcnt => self.execute_tzcnt(inst),
            Mnemonic::Andn => self.execute_andn(inst),
            Mnemonic::Bextr => self.execute_bextr(inst),
            Mnemonic::Blsi => self.execute_blsi(inst),
            Mnemonic::Blsmsk => self.execute_blsmsk(inst),
            Mnemonic::Blsr => self.execute_blsr(inst),
            Mnemonic::Bzhi => self.execute_bzhi(inst),
            Mnemonic::Mulx => self.execute_mulx(inst),
            Mnemonic::Pdep => self.execute_pdep(inst),
            Mnemonic::Pext => self.execute_pext(inst),
            Mnemonic::Rorx => self.execute_rorx(inst),
            Mnemonic::Sarx => self.execute_sarx(inst),
            Mnemonic::Shlx => self.execute_shlx(inst),
            Mnemonic::Shrx => self.execute_shrx(inst),
            Mnemonic::Cqo => self.execute_cqo(inst),
            Mnemonic::Xadd => self.execute_xadd(inst),
            Mnemonic::Cpuid => self.execute_cpuid(inst),
            Mnemonic::Rdtsc => self.execute_rdtsc(inst),
            Mnemonic::Rdtscp => self.execute_rdtscp(inst),
            Mnemonic::Punpcklwd => self.execute_punpcklwd(inst),
            Mnemonic::Pshufd => self.execute_pshufd(inst),
            Mnemonic::Pshuflw => self.execute_pshuflw(inst),
            Mnemonic::Pshufhw => self.execute_pshufhw(inst),
            Mnemonic::Pextrw => self.execute_pextrw(inst),
            Mnemonic::Pinsrw => self.execute_pinsrw(inst),
            Mnemonic::Pmovmskb => self.execute_pmovmskb(inst),
            Mnemonic::Vpmovmskb => self.execute_vpmovmskb(inst),
            Mnemonic::Pavgb => self.execute_pavgb(inst),
            Mnemonic::Pavgw => self.execute_pavgw(inst),
            Mnemonic::Pmaxub => self.execute_pmaxub(inst),
            Mnemonic::Pmaxsw => self.execute_pmaxsw(inst),
            Mnemonic::Pminub => self.execute_pminub(inst),
            Mnemonic::Pminsw => self.execute_pminsw(inst),
            Mnemonic::Pminud => self.execute_pminud(inst),
            Mnemonic::Psadbw => self.execute_psadbw(inst),
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
            Mnemonic::Cvtps2pd => self.execute_cvtps2pd(inst),
            Mnemonic::Cvtpd2ps => self.execute_cvtpd2ps(inst),
            Mnemonic::Cvtss2sd => self.execute_cvtss2sd(inst),
            Mnemonic::Cvtsd2ss => self.execute_cvtsd2ss(inst),
            Mnemonic::Cvtps2dq => self.execute_cvtps2dq(inst),
            // Scalar double-precision floating-point operations
            Mnemonic::Addsd => self.execute_addsd(inst),
            Mnemonic::Subsd => self.execute_subsd(inst),
            Mnemonic::Mulsd => self.execute_mulsd(inst),
            Mnemonic::Divsd => self.execute_divsd(inst),
            // Scalar single-precision floating-point operations
            Mnemonic::Addss => self.execute_addss(inst),
            Mnemonic::Subss => self.execute_subss(inst),
            Mnemonic::Mulss => self.execute_mulss(inst),
            Mnemonic::Divss => self.execute_divss(inst),
            Mnemonic::Cvttps2dq => self.execute_cvttps2dq(inst),
            Mnemonic::Cvtdq2ps => self.execute_cvtdq2ps(inst),
            Mnemonic::Cvtsi2ss => self.execute_cvtsi2ss(inst),
            Mnemonic::Cvtsi2sd => self.execute_cvtsi2sd(inst),
            Mnemonic::Cvtss2si => self.execute_cvtss2si(inst),
            Mnemonic::Cvtsd2si => self.execute_cvtsd2si(inst),
            Mnemonic::Cvttss2si => self.execute_cvttss2si(inst),
            Mnemonic::Cvttsd2si => self.execute_cvttsd2si(inst),
            Mnemonic::Movsb => self.execute_movsb(inst),
            Mnemonic::Stosb => self.execute_stosb(inst),
            Mnemonic::Lodsb => self.execute_lodsb(inst),
            Mnemonic::Scasb => self.execute_scasb(inst),
            Mnemonic::Cmpsb => self.execute_cmpsb(inst),
            Mnemonic::Movsw => self.execute_movsw(inst),
            Mnemonic::Movsd => {
                // Differentiate between SSE movsd and string movsd
                // SSE movsd involves XMM registers, string movsd does not
                if inst.op_count() >= 1
                    && (inst.op_kind(0) == OpKind::Register && inst.op_register(0).is_xmm())
                    || (inst.op_kind(1) == OpKind::Register && inst.op_register(1).is_xmm())
                {
                    self.execute_movsd_sse(inst)
                } else {
                    self.execute_movsd_string(inst)
                }
            }
            Mnemonic::Movsq => self.execute_movsq(inst),
            Mnemonic::Stosw => self.execute_stosw(inst),
            Mnemonic::Stosd => self.execute_stosd(inst),
            Mnemonic::Stosq => self.execute_stosq(inst),
            Mnemonic::Lodsw => self.execute_lodsw(inst),
            Mnemonic::Lodsd => self.execute_lodsd(inst),
            Mnemonic::Lodsq => self.execute_lodsq(inst),
            Mnemonic::Scasw => self.execute_scasw(inst),
            Mnemonic::Scasd => self.execute_scasd(inst),
            Mnemonic::Scasq => self.execute_scasq(inst),
            Mnemonic::Cmpsw => self.execute_cmpsw(inst),
            Mnemonic::Cmpsd => self.execute_cmpsd_string(inst),
            Mnemonic::Cmpsq => self.execute_cmpsq(inst),
            Mnemonic::Pcmpistri => self.execute_pcmpistri(inst),
            Mnemonic::Bswap => self.execute_bswap(inst),
            Mnemonic::Jo => self.execute_jcc(inst, self.engine.cpu.rflags.contains(Flags::OF)),
            Mnemonic::Jno => self.execute_jcc(inst, !self.engine.cpu.rflags.contains(Flags::OF)),
            Mnemonic::Jp => self.execute_jcc(inst, self.engine.cpu.rflags.contains(Flags::PF)),
            Mnemonic::Jnp => self.execute_jcc(inst, !self.engine.cpu.rflags.contains(Flags::PF)),
            Mnemonic::Cld => self.execute_cld(inst),
            Mnemonic::Std => self.execute_std(inst),
            Mnemonic::Int => self.execute_int(inst),
            Mnemonic::Int3 => self.execute_int3(inst),
            // Note: INTO is not valid in 64-bit mode, only supported in 32-bit mode
            Mnemonic::Syscall => self.execute_syscall(inst),
            Mnemonic::Mfence => self.execute_mfence(inst),
            Mnemonic::Sfence => self.execute_sfence(inst),
            Mnemonic::Lfence => self.execute_lfence(inst),
            Mnemonic::Clflush => self.execute_clflush(inst),
            Mnemonic::Fnstcw => self.execute_fnstcw(inst),
            Mnemonic::Fidivr => self.execute_fidivr(inst),
            Mnemonic::Stmxcsr => self.execute_stmxcsr(inst),
            Mnemonic::Fxrstor => self.execute_fxrstor(inst),
            Mnemonic::Rdsspq => self.execute_rdsspq(inst),
            Mnemonic::Clflushopt => self.execute_clflush(inst), // Same as CLFLUSH for emulation
            Mnemonic::Adc => self.execute_adc(inst),
            Mnemonic::Not => self.execute_not(inst),
            Mnemonic::Ror => self.execute_ror(inst),
            Mnemonic::Xchg => self.execute_xchg(inst),
            Mnemonic::Vinsertf128 => self.execute_vinsertf128(inst),
            Mnemonic::Loop => self.execute_loop(inst),
            Mnemonic::Loope => self.execute_loope(inst),
            Mnemonic::Loopne => self.execute_loopne(inst),
            Mnemonic::Shld => self.execute_shld(inst),
            Mnemonic::Shrd => self.execute_shrd(inst),
            Mnemonic::Rcl => self.execute_rcl(inst),
            Mnemonic::Rcr => self.execute_rcr(inst),
            Mnemonic::Stc => self.execute_stc(inst),
            Mnemonic::Clc => self.execute_clc(inst),
            Mnemonic::Cmc => self.execute_cmc(inst),
            Mnemonic::Xlatb => self.execute_xlat(inst),
            Mnemonic::Pause => self.execute_pause(inst),
            Mnemonic::Ud2 => self.execute_ud2(inst),
            Mnemonic::Shufps => self.execute_shufps(inst),
            Mnemonic::Unpcklps => self.execute_unpcklps(inst),
            Mnemonic::Unpckhps => self.execute_unpckhps(inst),
            Mnemonic::Shufpd => self.execute_shufpd(inst),
            Mnemonic::Unpcklpd => self.execute_unpcklpd(inst),
            Mnemonic::Unpckhpd => self.execute_unpckhpd(inst),
            Mnemonic::Paddb => self.execute_paddb(inst),
            Mnemonic::Paddw => self.execute_paddw(inst),
            Mnemonic::Paddd => self.execute_paddd(inst),
            Mnemonic::Paddq => self.execute_paddq(inst),
            Mnemonic::Psubb => self.execute_psubb(inst),
            Mnemonic::Psubw => self.execute_psubw(inst),
            Mnemonic::Psubd => self.execute_psubd(inst),
            Mnemonic::Psubq => self.execute_psubq(inst),
            Mnemonic::Pmullw => self.execute_pmullw(inst),
            Mnemonic::Pmulhw => self.execute_pmulhw(inst),
            Mnemonic::Pmulhuw => self.execute_pmulhuw(inst),
            Mnemonic::Pmuludq => self.execute_pmuludq(inst),
            Mnemonic::Pmaddwd => self.execute_pmaddwd(inst),
            Mnemonic::Pand => self.execute_pand(inst),
            Mnemonic::Pandn => self.execute_pandn(inst),
            Mnemonic::Por => self.execute_por(inst),
            Mnemonic::Pxor => self.execute_pxor(inst),
            Mnemonic::Pcmpeqb => self.execute_pcmpeqb(inst),
            Mnemonic::Pcmpeqw => self.execute_pcmpeqw(inst),
            Mnemonic::Pcmpeqd => self.execute_pcmpeqd(inst),
            Mnemonic::Vpcmpeqb => self.execute_vpcmpeqb(inst),
            Mnemonic::Vpcmpeqw => self.execute_vpcmpeqw(inst),
            Mnemonic::Pcmpgtb => self.execute_pcmpgtb(inst),
            Mnemonic::Pcmpgtw => self.execute_pcmpgtw(inst),
            Mnemonic::Pcmpgtd => self.execute_pcmpgtd(inst),
            Mnemonic::Psllw => self.execute_psllw(inst),
            Mnemonic::Pslld => self.execute_pslld(inst),
            Mnemonic::Psllq => self.execute_psllq(inst),
            Mnemonic::Psrlw => self.execute_psrlw(inst),
            Mnemonic::Psrld => self.execute_psrld(inst),
            Mnemonic::Psrlq => self.execute_psrlq(inst),
            Mnemonic::Psraw => self.execute_psraw(inst),
            Mnemonic::Psrad => self.execute_psrad(inst),
            Mnemonic::Psrldq => self.execute_psrldq(inst),
            Mnemonic::Packsswb => self.execute_packsswb(inst),
            Mnemonic::Packuswb => self.execute_packuswb(inst),
            Mnemonic::Packssdw => self.execute_packssdw(inst),
            Mnemonic::Punpcklbw => self.execute_punpcklbw(inst),
            Mnemonic::Punpckhbw => self.execute_punpckhbw(inst),
            Mnemonic::Punpckhwd => self.execute_punpckhwd(inst),
            Mnemonic::Punpckldq => self.execute_punpckldq(inst),
            Mnemonic::Punpckhdq => self.execute_punpckhdq(inst),
            Mnemonic::Punpcklqdq => self.execute_punpcklqdq(inst),
            Mnemonic::Punpckhqdq => self.execute_punpckhqdq(inst),
            // SSE4.1 move with sign/zero extension
            Mnemonic::Pmovsxbw => self.execute_pmovsxbw(inst),
            Mnemonic::Pmovsxbd => self.execute_pmovsxbd(inst),
            Mnemonic::Pmovsxbq => self.execute_pmovsxbq(inst),
            Mnemonic::Pmovsxwd => self.execute_pmovsxwd(inst),
            Mnemonic::Pmovsxwq => self.execute_pmovsxwq(inst),
            Mnemonic::Pmovsxdq => self.execute_pmovsxdq(inst),
            Mnemonic::Pmovzxbw => self.execute_pmovzxbw(inst),
            Mnemonic::Pmovzxbd => self.execute_pmovzxbd(inst),
            Mnemonic::Pmovzxbq => self.execute_pmovzxbq(inst),
            Mnemonic::Pmovzxwd => self.execute_pmovzxwd(inst),
            Mnemonic::Pmovzxwq => self.execute_pmovzxwq(inst),
            Mnemonic::Pmovzxdq => self.execute_pmovzxdq(inst),
            Mnemonic::Prefetchw => self.execute_prefetchw(inst),
            Mnemonic::Prefetcht0 => self.execute_prefetcht0(inst),
            Mnemonic::Cmpxchg16b => self.execute_cmpxchg16b(inst),
            Mnemonic::Endbr64 => self.execute_endbr64(inst),
            Mnemonic::Kmovd => self.execute_kmovd(inst),
            Mnemonic::Xsavec64 => self.execute_xsavec64(inst),
            Mnemonic::Xrstor64 => self.execute_xrstor64(inst),
            _ => Err(EmulatorError::UnsupportedInstruction(format!(
                "{:?}",
                inst.mnemonic()
            ))),
        }
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

    fn read_memory_32(&mut self, addr: u64) -> Result<u32> {
        let mut buf = [0u8; 4];
        self.mem_read_with_hooks(addr, &mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn read_memory_64(&mut self, addr: u64) -> Result<u64> {
        let mut buf = [0u8; 8];
        self.mem_read_with_hooks(addr, &mut buf)?;
        Ok(u64::from_le_bytes(buf))
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
                )));
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
                )));
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
                // Handle XMM/YMM registers specially - return low 64 bits
                if our_reg.is_xmm() {
                    Ok(self.engine.cpu.read_xmm(our_reg) as u64)
                } else if our_reg.is_ymm() {
                    Ok(self.engine.cpu.read_ymm(our_reg)[0] as u64)
                } else {
                    Ok(self.engine.cpu.read_reg(our_reg))
                }
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
                // Handle XMM/YMM registers specially - write to low 64 bits
                if our_reg.is_xmm() {
                    self.engine.cpu.write_xmm(our_reg, value as u128);
                } else if our_reg.is_ymm() {
                    self.engine.cpu.write_ymm(our_reg, [value as u128, 0]);
                } else {
                    self.engine.cpu.write_reg(our_reg, value);
                }
                Ok(())
            }
            OpKind::Memory => {
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
                        addr =
                            addr.wrapping_add(self.engine.cpu.read_reg(index_reg) * (scale as u64));
                    }
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

    fn is_64bit_register(&self, reg: Register) -> bool {
        use Register::*;
        matches!(
            reg,
            RAX | RBX
                | RCX
                | RDX
                | RSI
                | RDI
                | RBP
                | RSP
                | R8
                | R9
                | R10
                | R11
                | R12
                | R13
                | R14
                | R15
        )
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
            IR::YMM16 => Ok(Register::YMM16),
            IR::YMM17 => Ok(Register::YMM17),
            IR::YMM18 => Ok(Register::YMM18),
            IR::YMM19 => Ok(Register::YMM19),
            IR::YMM20 => Ok(Register::YMM20),
            IR::YMM21 => Ok(Register::YMM21),
            IR::YMM22 => Ok(Register::YMM22),
            IR::YMM23 => Ok(Register::YMM23),
            IR::YMM24 => Ok(Register::YMM24),
            IR::YMM25 => Ok(Register::YMM25),
            IR::YMM26 => Ok(Register::YMM26),
            IR::YMM27 => Ok(Register::YMM27),
            IR::YMM28 => Ok(Register::YMM28),
            IR::YMM29 => Ok(Register::YMM29),
            IR::YMM30 => Ok(Register::YMM30),
            IR::YMM31 => Ok(Register::YMM31),
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
            IR::XMM16 => Ok(Register::XMM16),
            IR::XMM17 => Ok(Register::XMM17),
            IR::XMM18 => Ok(Register::XMM18),
            IR::XMM19 => Ok(Register::XMM19),
            IR::XMM20 => Ok(Register::XMM20),
            IR::XMM21 => Ok(Register::XMM21),
            IR::XMM22 => Ok(Register::XMM22),
            IR::XMM23 => Ok(Register::XMM23),
            IR::XMM24 => Ok(Register::XMM24),
            IR::XMM25 => Ok(Register::XMM25),
            IR::XMM26 => Ok(Register::XMM26),
            IR::XMM27 => Ok(Register::XMM27),
            IR::XMM28 => Ok(Register::XMM28),
            IR::XMM29 => Ok(Register::XMM29),
            IR::XMM30 => Ok(Register::XMM30),
            IR::XMM31 => Ok(Register::XMM31),
            // Mask registers
            IR::K0 => Ok(Register::K0),
            IR::K1 => Ok(Register::K1),
            IR::K2 => Ok(Register::K2),
            IR::K3 => Ok(Register::K3),
            IR::K4 => Ok(Register::K4),
            IR::K5 => Ok(Register::K5),
            IR::K6 => Ok(Register::K6),
            IR::K7 => Ok(Register::K7),
            // Segment registers
            IR::CS => Ok(Register::CS),
            IR::DS => Ok(Register::DS),
            IR::ES => Ok(Register::ES),
            IR::FS => Ok(Register::FS),
            IR::GS => Ok(Register::GS),
            IR::SS => Ok(Register::SS),
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

    fn compare_floats_avx(&self, a: f32, b: f32, imm: u8) -> bool {
        // AVX comparison predicates (0-31)
        match imm & 0x1F {
            0 => a == b,                                   // EQ_OQ (Equal, Ordered, Quiet)
            1 => a < b,                                    // LT_OS (Less Than, Ordered, Signaling)
            2 => a <= b, // LE_OS (Less Than or Equal, Ordered, Signaling)
            3 => a.is_nan() || b.is_nan(), // UNORD_Q (Unordered, Quiet)
            4 => !(a == b), // NEQ_UQ (Not Equal, Unordered, Quiet)
            5 => !(a < b), // NLT_US (Not Less Than, Unordered, Signaling)
            6 => !(a <= b), // NLE_US (Not Less Than or Equal, Unordered, Signaling)
            7 => !(a.is_nan() || b.is_nan()), // ORD_Q (Ordered, Quiet)
            8 => a == b || (a.is_nan() || b.is_nan()), // EQ_UQ (Equal, Unordered, Quiet)
            9 => !(a >= b), // NGE_US (Not Greater Than or Equal, Unordered, Signaling)
            10 => !(a > b), // NGT_US (Not Greater Than, Unordered, Signaling)
            11 => false, // FALSE_OQ (Always False, Ordered, Quiet)
            12 => !((a == b) || a.is_nan() || b.is_nan()), // NEQ_OQ (Not Equal, Ordered, Quiet)
            13 => a >= b, // GE_OS (Greater Than or Equal, Ordered, Signaling)
            14 => a > b, // GT_OS (Greater Than, Ordered, Signaling)
            15 => true,  // TRUE_UQ (Always True, Unordered, Quiet)
            16 => a == b && !(a.is_nan() || b.is_nan()), // EQ_OS (Equal, Ordered, Signaling)
            17 => a < b && !(a.is_nan() || b.is_nan()), // LT_OQ (Less Than, Ordered, Quiet)
            18 => a <= b && !(a.is_nan() || b.is_nan()), // LE_OQ (Less Than or Equal, Ordered, Quiet)
            19 => a.is_nan() || b.is_nan(),              // UNORD_S (Unordered, Signaling)
            20 => a != b || (a.is_nan() || b.is_nan()),  // NEQ_US (Not Equal, Unordered, Signaling)
            21 => !(a < b) || (a.is_nan() || b.is_nan()), // NLT_UQ (Not Less Than, Unordered, Quiet)
            22 => !(a <= b) || (a.is_nan() || b.is_nan()), // NLE_UQ (Not Less Than or Equal, Unordered, Quiet)
            23 => !(a.is_nan() || b.is_nan()),             // ORD_S (Ordered, Signaling)
            24 => a == b,                                  // EQ_US (Equal, Unordered, Signaling)
            25 => !(a >= b) || (a.is_nan() || b.is_nan()), // NGE_UQ (Not Greater Than or Equal, Unordered, Quiet)
            26 => !(a > b) || (a.is_nan() || b.is_nan()), // NGT_UQ (Not Greater Than, Unordered, Quiet)
            27 => false, // FALSE_OS (Always False, Ordered, Signaling)
            28 => a != b && !(a.is_nan() || b.is_nan()), // NEQ_OS (Not Equal, Ordered, Signaling)
            29 => a >= b && !(a.is_nan() || b.is_nan()), // GE_OQ (Greater Than or Equal, Ordered, Quiet)
            30 => a > b && !(a.is_nan() || b.is_nan()),  // GT_OQ (Greater Than, Ordered, Quiet)
            31 => true, // TRUE_US (Always True, Unordered, Signaling)
            _ => false,
        }
    }

    fn compare_doubles_avx(&self, a: f64, b: f64, imm: u8) -> bool {
        // AVX comparison predicates (0-31) - same logic as floats but with f64
        match imm & 0x1F {
            0 => a == b,                                   // EQ_OQ
            1 => a < b,                                    // LT_OS
            2 => a <= b,                                   // LE_OS
            3 => a.is_nan() || b.is_nan(),                 // UNORD_Q
            4 => !(a == b),                                // NEQ_UQ
            5 => !(a < b),                                 // NLT_US
            6 => !(a <= b),                                // NLE_US
            7 => !(a.is_nan() || b.is_nan()),              // ORD_Q
            8 => a == b || (a.is_nan() || b.is_nan()),     // EQ_UQ
            9 => !(a >= b),                                // NGE_US
            10 => !(a > b),                                // NGT_US
            11 => false,                                   // FALSE_OQ
            12 => !((a == b) || a.is_nan() || b.is_nan()), // NEQ_OQ
            13 => a >= b,                                  // GE_OS
            14 => a > b,                                   // GT_OS
            15 => true,                                    // TRUE_UQ
            16 => a == b && !(a.is_nan() || b.is_nan()),   // EQ_OS
            17 => a < b && !(a.is_nan() || b.is_nan()),    // LT_OQ
            18 => a <= b && !(a.is_nan() || b.is_nan()),   // LE_OQ
            19 => a.is_nan() || b.is_nan(),                // UNORD_S
            20 => a != b || (a.is_nan() || b.is_nan()),    // NEQ_US
            21 => !(a < b) || (a.is_nan() || b.is_nan()),  // NLT_UQ
            22 => !(a <= b) || (a.is_nan() || b.is_nan()), // NLE_UQ
            23 => !(a.is_nan() || b.is_nan()),             // ORD_S
            24 => a == b,                                  // EQ_US
            25 => !(a >= b) || (a.is_nan() || b.is_nan()), // NGE_UQ
            26 => !(a > b) || (a.is_nan() || b.is_nan()),  // NGT_UQ
            27 => false,                                   // FALSE_OS
            28 => a != b && !(a.is_nan() || b.is_nan()),   // NEQ_OS
            29 => a >= b && !(a.is_nan() || b.is_nan()),   // GE_OQ
            30 => a > b && !(a.is_nan() || b.is_nan()),    // GT_OQ
            31 => true,                                    // TRUE_US
            _ => false,
        }
    }
}
