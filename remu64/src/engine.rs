use crate::OwnedMemory;
use crate::cpu::{CpuState, Flags, Register};
use crate::error::{EmulatorError, Result};
use crate::hooks::{HookManager, NoHooks};
use crate::memory::{MemoryTrait, Permission};
use iced_x86::{
    Code, Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register as IcedRegister,
};

#[derive(Debug, Clone, Copy)]
pub enum EngineMode {
    Mode16,
    Mode32,
    Mode64,
}

pub struct Engine<M: MemoryTrait> {
    pub cpu: CpuState,
    pub memory: M,
    mode: EngineMode,
}

impl Engine<OwnedMemory> {
    pub fn new(mode: EngineMode) -> Self {
        Self {
            cpu: CpuState::new(),
            memory: OwnedMemory::new(),
            mode,
        }
    }
}
impl<M: MemoryTrait> Engine<M> {
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

    pub fn emu_start_with_hooks<H: HookManager<M>>(
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

struct ExecutionContext<'a, H: HookManager<M>, M: MemoryTrait> {
    engine: &'a mut Engine<M>,
    hooks: &'a mut H,
}

impl<H: HookManager<M>, M: MemoryTrait> ExecutionContext<'_, H, M> {
    /// Start emulation with custom hooks
    fn emu_start(&mut self, begin: u64, until: u64, timeout: u64, count: usize) -> Result<()> {
        self.engine.cpu.rip = begin;
        let mut instruction_count = 0;

        let start_time = std::time::Instant::now();
        let timeout_duration = if timeout > 0 {
            Some(std::time::Duration::from_micros(timeout))
        } else {
            None
        };

        loop {
            if self.engine.cpu.rip == until && until != 0 {
                break;
            }

            if count > 0 && instruction_count >= count as u64 {
                break;
            }

            if let Some(timeout) = timeout_duration
                && start_time.elapsed() > timeout
            {
                break;
            }

            self.step()?;

            instruction_count += 1;
        }

        Ok(())
    }

    fn step(&mut self) -> Result<()> {
        let rip = self.engine.cpu.rip;

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

        let mut inst_bytes = vec![0u8; 15];
        self.mem_read_with_hooks(rip, &mut inst_bytes)?;

        // Create iced_x86 decoder for this instruction
        let bitness = match self.engine.mode {
            EngineMode::Mode16 => 16,
            EngineMode::Mode32 => 32,
            EngineMode::Mode64 => 64,
        };
        let mut decoder = Decoder::with_ip(bitness, &inst_bytes, rip, DecoderOptions::NONE);

        let inst = decoder.decode();

        self.hooks.on_code(self.engine, rip, inst.len())?;

        self.engine.cpu.rip = rip + inst.len() as u64;

        self.execute_instruction(&inst)?;

        Ok(())
    }

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
            Mnemonic::Movdqu => self.execute_movdqu(inst),
            Mnemonic::Movdqa => self.execute_movdqa(inst),
            Mnemonic::Movd => self.execute_movd(inst),
            Mnemonic::Vzeroupper => self.execute_vzeroupper(inst),
            Mnemonic::Vaddps => self.execute_vaddps(inst),
            Mnemonic::Vsubps => self.execute_vsubps(inst),
            Mnemonic::Vmulps => self.execute_vmulps(inst),
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
            Mnemonic::Pavgb => self.execute_pavgb(inst),
            Mnemonic::Pavgw => self.execute_pavgw(inst),
            Mnemonic::Pmaxub => self.execute_pmaxub(inst),
            Mnemonic::Pmaxsw => self.execute_pmaxsw(inst),
            Mnemonic::Pminub => self.execute_pminub(inst),
            Mnemonic::Pminsw => self.execute_pminsw(inst),
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
            Mnemonic::Movsd => self.execute_movsd_string(inst),
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
            Mnemonic::Clflushopt => self.execute_clflush(inst), // Same as CLFLUSH for emulation
            Mnemonic::Adc => self.execute_adc(inst),
            Mnemonic::Not => self.execute_not(inst),
            Mnemonic::Ror => self.execute_ror(inst),
            Mnemonic::Xchg => self.execute_xchg(inst),
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
                )));
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
                )));
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
                )));
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
                )));
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
                )));
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
                )));
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
    
    fn execute_seta(&mut self, inst: &Instruction) -> Result<()> {
        // SETA: Set if above (CF=0 and ZF=0)
        let cf = self.engine.cpu.rflags.contains(Flags::CF);
        let zf = self.engine.cpu.rflags.contains(Flags::ZF);
        let result = if !cf && !zf { 1u64 } else { 0u64 };
        self.write_operand(inst, 0, result)?;
        Ok(())
    }
    
    fn execute_setae(&mut self, inst: &Instruction) -> Result<()> {
        // SETAE: Set if above or equal (CF=0)
        let cf = self.engine.cpu.rflags.contains(Flags::CF);
        let result = if !cf { 1u64 } else { 0u64 };
        self.write_operand(inst, 0, result)?;
        Ok(())
    }
    
    fn execute_setb(&mut self, inst: &Instruction) -> Result<()> {
        // SETB: Set if below (CF=1)
        let cf = self.engine.cpu.rflags.contains(Flags::CF);
        let result = if cf { 1u64 } else { 0u64 };
        self.write_operand(inst, 0, result)?;
        Ok(())
    }
    
    fn execute_setg(&mut self, inst: &Instruction) -> Result<()> {
        // SETG: Set if greater (ZF=0 and SF=OF)
        let zf = self.engine.cpu.rflags.contains(Flags::ZF);
        let sf = self.engine.cpu.rflags.contains(Flags::SF);
        let of = self.engine.cpu.rflags.contains(Flags::OF);
        let result = if !zf && (sf == of) { 1u64 } else { 0u64 };
        self.write_operand(inst, 0, result)?;
        Ok(())
    }
    
    fn execute_setge(&mut self, inst: &Instruction) -> Result<()> {
        // SETGE: Set if greater or equal (SF=OF)
        let sf = self.engine.cpu.rflags.contains(Flags::SF);
        let of = self.engine.cpu.rflags.contains(Flags::OF);
        let result = if sf == of { 1u64 } else { 0u64 };
        self.write_operand(inst, 0, result)?;
        Ok(())
    }
    
    fn execute_setl(&mut self, inst: &Instruction) -> Result<()> {
        // SETL: Set if less (SF!=OF)
        let sf = self.engine.cpu.rflags.contains(Flags::SF);
        let of = self.engine.cpu.rflags.contains(Flags::OF);
        let result = if sf != of { 1u64 } else { 0u64 };
        self.write_operand(inst, 0, result)?;
        Ok(())
    }
    
    fn execute_sets(&mut self, inst: &Instruction) -> Result<()> {
        // SETS: Set if sign (SF=1)
        let sf = self.engine.cpu.rflags.contains(Flags::SF);
        let result = if sf { 1u64 } else { 0u64 };
        self.write_operand(inst, 0, result)?;
        Ok(())
    }
    
    fn execute_setns(&mut self, inst: &Instruction) -> Result<()> {
        // SETNS: Set if not sign (SF=0)
        let sf = self.engine.cpu.rflags.contains(Flags::SF);
        let result = if !sf { 1u64 } else { 0u64 };
        self.write_operand(inst, 0, result)?;
        Ok(())
    }
    
    fn execute_seto(&mut self, inst: &Instruction) -> Result<()> {
        // SETO: Set if overflow (OF=1)
        let of = self.engine.cpu.rflags.contains(Flags::OF);
        let result = if of { 1u64 } else { 0u64 };
        self.write_operand(inst, 0, result)?;
        Ok(())
    }
    
    fn execute_setno(&mut self, inst: &Instruction) -> Result<()> {
        // SETNO: Set if not overflow (OF=0)
        let of = self.engine.cpu.rflags.contains(Flags::OF);
        let result = if !of { 1u64 } else { 0u64 };
        self.write_operand(inst, 0, result)?;
        Ok(())
    }
    
    fn execute_setp(&mut self, inst: &Instruction) -> Result<()> {
        // SETP: Set if parity (PF=1)
        let pf = self.engine.cpu.rflags.contains(Flags::PF);
        let result = if pf { 1u64 } else { 0u64 };
        self.write_operand(inst, 0, result)?;
        Ok(())
    }
    
    fn execute_setnp(&mut self, inst: &Instruction) -> Result<()> {
        // SETNP: Set if not parity (PF=0)
        let pf = self.engine.cpu.rflags.contains(Flags::PF);
        let result = if !pf { 1u64 } else { 0u64 };
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
                )));
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
                )));
            }
        };

        // Update flags
        self.update_flags_logical_iced(result, inst)?;

        // Write result back to destination
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    fn execute_shld(&mut self, inst: &Instruction) -> Result<()> {
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
                let count = (shift_count & 0x1F) as u32; // For 16-bit, modulo 32
                if count >= 16 {
                    let result = (src_value as u16).wrapping_shl(count - 16) as u64;
                    let cf = ((dst_value >> (16 - count)) & 1) != 0;
                    (result, cf, false)
                } else {
                    let result = ((dst_value as u16) << count) | ((src_value as u16) >> (16 - count));
                    let cf = ((dst_value >> (16 - count)) & 1) != 0;
                    let of = count == 1 && (((result >> 15) & 1) as u64 != ((dst_value >> 15) & 1));
                    (result as u64, cf, of)
                }
            }
            4 => {
                let count = (shift_count & 0x1F) as u32; // For 32-bit, modulo 32
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
        if low_byte.count_ones() % 2 == 0 {
            self.engine.cpu.rflags.insert(Flags::PF);
        } else {
            self.engine.cpu.rflags.remove(Flags::PF);
        }

        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    fn execute_shrd(&mut self, inst: &Instruction) -> Result<()> {
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
                let count = (shift_count & 0x1F) as u32; // For 16-bit, modulo 32
                if count >= 16 {
                    let result = (src_value as u16).wrapping_shr(count - 16) as u64;
                    let cf = ((dst_value >> (count - 1)) & 1) != 0;
                    (result, cf, false)
                } else {
                    let result = ((dst_value as u16) >> count) | ((src_value as u16) << (16 - count));
                    let cf = ((dst_value >> (count - 1)) & 1) != 0;
                    let msb = (dst_value >> 15) & 1;
                    let of = count == 1 && (msb != ((src_value >> 15) & 1));
                    (result as u64, cf, of)
                }
            }
            4 => {
                let count = (shift_count & 0x1F) as u32; // For 32-bit, modulo 32
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
        if low_byte.count_ones() % 2 == 0 {
            self.engine.cpu.rflags.insert(Flags::PF);
        } else {
            self.engine.cpu.rflags.remove(Flags::PF);
        }

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

    fn execute_cmovl(&mut self, inst: &Instruction) -> Result<()> {
        // CMOVL: Conditional move if less than (SF!=OF)
        let sf = self.engine.cpu.rflags.contains(Flags::SF);
        let of = self.engine.cpu.rflags.contains(Flags::OF);

        if sf != of {
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

    fn execute_cmovne(&mut self, inst: &Instruction) -> Result<()> {
        // CMOVNE: Conditional move if not equal (ZF=0)
        let zf = self.engine.cpu.rflags.contains(Flags::ZF);

        if !zf {
            let src_value = self.read_operand(inst, 1)?;
            self.write_operand(inst, 0, src_value)?;
        }
        // If condition is false, no move occurs

        Ok(())
    }
    
    fn execute_cmovae(&mut self, inst: &Instruction) -> Result<()> {
        // CMOVAE: Conditional move if above or equal (CF=0)
        let cf = self.engine.cpu.rflags.contains(Flags::CF);
        
        if !cf {
            let src_value = self.read_operand(inst, 1)?;
            self.write_operand(inst, 0, src_value)?;
        }
        
        Ok(())
    }
    
    fn execute_cmovge(&mut self, inst: &Instruction) -> Result<()> {
        // CMOVGE: Conditional move if greater or equal (SF=OF)
        let sf = self.engine.cpu.rflags.contains(Flags::SF);
        let of = self.engine.cpu.rflags.contains(Flags::OF);
        
        if sf == of {
            let src_value = self.read_operand(inst, 1)?;
            self.write_operand(inst, 0, src_value)?;
        }
        
        Ok(())
    }
    
    fn execute_cmovs(&mut self, inst: &Instruction) -> Result<()> {
        // CMOVS: Conditional move if sign (SF=1)
        let sf = self.engine.cpu.rflags.contains(Flags::SF);
        
        if sf {
            let src_value = self.read_operand(inst, 1)?;
            self.write_operand(inst, 0, src_value)?;
        }
        
        Ok(())
    }
    
    fn execute_cmovo(&mut self, inst: &Instruction) -> Result<()> {
        // CMOVO: Conditional move if overflow (OF=1)
        let of = self.engine.cpu.rflags.contains(Flags::OF);
        
        if of {
            let src_value = self.read_operand(inst, 1)?;
            self.write_operand(inst, 0, src_value)?;
        }
        
        Ok(())
    }
    
    fn execute_cmovno(&mut self, inst: &Instruction) -> Result<()> {
        // CMOVNO: Conditional move if not overflow (OF=0)
        let of = self.engine.cpu.rflags.contains(Flags::OF);
        
        if !of {
            let src_value = self.read_operand(inst, 1)?;
            self.write_operand(inst, 0, src_value)?;
        }
        
        Ok(())
    }
    
    fn execute_cmovp(&mut self, inst: &Instruction) -> Result<()> {
        // CMOVP: Conditional move if parity (PF=1)
        let pf = self.engine.cpu.rflags.contains(Flags::PF);
        
        if pf {
            let src_value = self.read_operand(inst, 1)?;
            self.write_operand(inst, 0, src_value)?;
        }
        
        Ok(())
    }
    
    fn execute_cmovnp(&mut self, inst: &Instruction) -> Result<()> {
        // CMOVNP: Conditional move if not parity (PF=0)
        let pf = self.engine.cpu.rflags.contains(Flags::PF);
        
        if !pf {
            let src_value = self.read_operand(inst, 1)?;
            self.write_operand(inst, 0, src_value)?;
        }
        
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

    fn execute_movups(&mut self, inst: &Instruction) -> Result<()> {
        // MOVUPS: Move Unaligned Packed Single Precision Floating-Point Values (128-bit SSE)
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
                "Unsupported MOVUPS operand types: {:?}, {:?}",
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

    fn execute_vaddps(&mut self, inst: &Instruction) -> Result<()> {
        // VADDPS - Vector Add Packed Single-Precision Floating-Point Values
        // VEX.256: VADDPS ymm1, ymm2, ymm3/m256
        // VEX.128: VADDPS xmm1, xmm2, xmm3/m128
        
        // Check if this is 256-bit (YMM) or 128-bit (XMM) operation
        let is_256bit = inst.op_register(0).is_ymm();
        
        if inst.op_count() != 3 {
            return Err(EmulatorError::UnsupportedInstruction(
                "VADDPS requires exactly 3 operands".to_string(),
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
                OpKind::Memory => {
                    self.read_ymm_memory(inst, 2)?
                }
                _ => {
                    return Err(EmulatorError::UnsupportedInstruction(
                        format!("Unsupported VADDPS source operand type: {:?}", inst.op_kind(2))
                    ));
                }
            };
            
            // Perform packed single-precision addition
            // Each YMM register contains 8 32-bit floats (4 per 128-bit half)
            let mut result = [0u128; 2];
            
            for half in 0..2 {
                let mut float_results = [0u32; 4];
                for i in 0..4 {
                    let offset = i * 32;
                    let a_bits = ((src1_data[half] >> offset) & 0xFFFFFFFF) as u32;
                    let b_bits = ((src2_data[half] >> offset) & 0xFFFFFFFF) as u32;
                    
                    // Convert bits to f32, add, convert back to bits
                    let a = f32::from_bits(a_bits);
                    let b = f32::from_bits(b_bits);
                    let sum = a + b;
                    float_results[i] = sum.to_bits();
                }
                
                // Pack the results back into u128
                result[half] = (float_results[0] as u128) |
                              ((float_results[1] as u128) << 32) |
                              ((float_results[2] as u128) << 64) |
                              ((float_results[3] as u128) << 96);
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
                    return Err(EmulatorError::UnsupportedInstruction(
                        format!("Unsupported VADDPS source operand type: {:?}", inst.op_kind(2))
                    ));
                }
            };
            
            // Perform packed single-precision addition for XMM (4 floats)
            let mut float_results = [0u32; 4];
            for i in 0..4 {
                let offset = i * 32;
                let a_bits = ((src1_data >> offset) & 0xFFFFFFFF) as u32;
                let b_bits = ((src2_data >> offset) & 0xFFFFFFFF) as u32;
                
                let a = f32::from_bits(a_bits);
                let b = f32::from_bits(b_bits);
                let sum = a + b;
                float_results[i] = sum.to_bits();
            }
            
            let result = (float_results[0] as u128) |
                        ((float_results[1] as u128) << 32) |
                        ((float_results[2] as u128) << 64) |
                        ((float_results[3] as u128) << 96);
            
            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_xmm(dst_reg, result);
        }
        
        Ok(())
    }

    fn execute_vsubps(&mut self, inst: &Instruction) -> Result<()> {
        // VSUBPS - Vector Subtract Packed Single-Precision Floating-Point Values
        // VEX.256: VSUBPS ymm1, ymm2, ymm3/m256
        // VEX.128: VSUBPS xmm1, xmm2, xmm3/m128
        
        // Check if this is 256-bit (YMM) or 128-bit (XMM) operation
        let is_256bit = inst.op_register(0).is_ymm();
        
        if inst.op_count() != 3 {
            return Err(EmulatorError::UnsupportedInstruction(
                "VSUBPS requires exactly 3 operands".to_string(),
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
                OpKind::Memory => {
                    self.read_ymm_memory(inst, 2)?
                }
                _ => {
                    return Err(EmulatorError::UnsupportedInstruction(
                        format!("Unsupported VSUBPS source operand type: {:?}", inst.op_kind(2))
                    ));
                }
            };
            
            // Perform packed single-precision subtraction
            // Each YMM register contains 8 32-bit floats (4 per 128-bit half)
            let mut result = [0u128; 2];
            
            for half in 0..2 {
                let mut float_results = [0u32; 4];
                for i in 0..4 {
                    let offset = i * 32;
                    let a_bits = ((src1_data[half] >> offset) & 0xFFFFFFFF) as u32;
                    let b_bits = ((src2_data[half] >> offset) & 0xFFFFFFFF) as u32;
                    
                    // Convert bits to f32, subtract, convert back to bits
                    let a = f32::from_bits(a_bits);
                    let b = f32::from_bits(b_bits);
                    let diff = a - b;
                    float_results[i] = diff.to_bits();
                }
                
                // Pack the results back into u128
                result[half] = (float_results[0] as u128) |
                              ((float_results[1] as u128) << 32) |
                              ((float_results[2] as u128) << 64) |
                              ((float_results[3] as u128) << 96);
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
                    return Err(EmulatorError::UnsupportedInstruction(
                        format!("Unsupported VSUBPS source operand type: {:?}", inst.op_kind(2))
                    ));
                }
            };
            
            // Perform packed single-precision subtraction for XMM (4 floats)
            let mut float_results = [0u32; 4];
            for i in 0..4 {
                let offset = i * 32;
                let a_bits = ((src1_data >> offset) & 0xFFFFFFFF) as u32;
                let b_bits = ((src2_data >> offset) & 0xFFFFFFFF) as u32;
                
                let a = f32::from_bits(a_bits);
                let b = f32::from_bits(b_bits);
                let diff = a - b;
                float_results[i] = diff.to_bits();
            }
            
            let result = (float_results[0] as u128) |
                        ((float_results[1] as u128) << 32) |
                        ((float_results[2] as u128) << 64) |
                        ((float_results[3] as u128) << 96);
            
            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_xmm(dst_reg, result);
        }
        
        Ok(())
    }

    fn execute_vmulps(&mut self, inst: &Instruction) -> Result<()> {
        // VMULPS - Vector Multiply Packed Single-Precision Floating-Point Values
        // VEX.256: VMULPS ymm1, ymm2, ymm3/m256
        // VEX.128: VMULPS xmm1, xmm2, xmm3/m128
        
        // Check if this is 256-bit (YMM) or 128-bit (XMM) operation
        let is_256bit = inst.op_register(0).is_ymm();
        
        if inst.op_count() != 3 {
            return Err(EmulatorError::UnsupportedInstruction(
                "VMULPS requires exactly 3 operands".to_string(),
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
                OpKind::Memory => {
                    self.read_ymm_memory(inst, 2)?
                }
                _ => {
                    return Err(EmulatorError::UnsupportedInstruction(
                        format!("Unsupported VMULPS source operand type: {:?}", inst.op_kind(2))
                    ));
                }
            };
            
            // Perform packed single-precision multiplication
            // Each YMM register contains 8 32-bit floats (4 per 128-bit half)
            let mut result = [0u128; 2];
            
            for half in 0..2 {
                let mut float_results = [0u32; 4];
                for i in 0..4 {
                    let offset = i * 32;
                    let a_bits = ((src1_data[half] >> offset) & 0xFFFFFFFF) as u32;
                    let b_bits = ((src2_data[half] >> offset) & 0xFFFFFFFF) as u32;
                    
                    // Convert bits to f32, multiply, convert back to bits
                    let a = f32::from_bits(a_bits);
                    let b = f32::from_bits(b_bits);
                    let prod = a * b;
                    float_results[i] = prod.to_bits();
                }
                
                // Pack the results back into u128
                result[half] = (float_results[0] as u128) |
                              ((float_results[1] as u128) << 32) |
                              ((float_results[2] as u128) << 64) |
                              ((float_results[3] as u128) << 96);
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
                    return Err(EmulatorError::UnsupportedInstruction(
                        format!("Unsupported VMULPS source operand type: {:?}", inst.op_kind(2))
                    ));
                }
            };
            
            // Perform packed single-precision multiplication for XMM (4 floats)
            let mut float_results = [0u32; 4];
            for i in 0..4 {
                let offset = i * 32;
                let a_bits = ((src1_data >> offset) & 0xFFFFFFFF) as u32;
                let b_bits = ((src2_data >> offset) & 0xFFFFFFFF) as u32;
                
                let a = f32::from_bits(a_bits);
                let b = f32::from_bits(b_bits);
                let prod = a * b;
                float_results[i] = prod.to_bits();
            }
            
            let result = (float_results[0] as u128) |
                        ((float_results[1] as u128) << 32) |
                        ((float_results[2] as u128) << 64) |
                        ((float_results[3] as u128) << 96);
            
            let dst_reg = self.convert_register(inst.op_register(0))?;
            self.engine.cpu.write_xmm(dst_reg, result);
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

    fn execute_pshuflw(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_pshufhw(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_pextrw(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_pinsrw(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_pmovmskb(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_pavgb(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_pavgw(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_pmaxub(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_pmaxsw(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_pminub(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_pminsw(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_psadbw(&mut self, inst: &Instruction) -> Result<()> {
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
                ));
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
                ));
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
                ));
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
                ));
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
                ));
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
                ));
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
                ));
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
                ));
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
                ));
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
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let result = dst_value | src_value;
        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    fn execute_cvtps2pd(&mut self, inst: &Instruction) -> Result<()> {
        // Convert Packed Single-Precision FP to Packed Double-Precision FP
        // Converts 2 single-precision floats from source to 2 double-precision floats in destination
        let (dst_reg, src_value) = match (inst.op_kind(0), inst.op_kind(1)) {
            (OpKind::Register, OpKind::Register) => {
                let dst = self.convert_register(inst.op_register(0))?;
                let src = self.convert_register(inst.op_register(1))?;
                (dst, self.engine.cpu.read_xmm(src))
            }
            (OpKind::Register, OpKind::Memory) => {
                let dst = self.convert_register(inst.op_register(0))?;
                let addr = self.calculate_memory_address(inst, 1)?;
                // Only read 64 bits (2 floats) from memory
                let value = self.read_memory_64(addr)?;
                (dst, value as u128)
            }
            _ => return Err(EmulatorError::UnsupportedOperandType),
        };

        // Extract two single-precision floats
        let float1 = f32::from_bits(src_value as u32);
        let float2 = f32::from_bits((src_value >> 32) as u32);

        // Convert to double-precision
        let double1 = float1 as f64;
        let double2 = float2 as f64;

        // Pack the two doubles into the XMM register
        let result = double1.to_bits() as u128 | ((double2.to_bits() as u128) << 64);
        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    fn execute_cvtpd2ps(&mut self, inst: &Instruction) -> Result<()> {
        // Convert Packed Double-Precision FP to Packed Single-Precision FP
        // Converts 2 double-precision floats from source to 2 single-precision floats in destination (lower 64 bits)
        let (dst_reg, src_value) = match (inst.op_kind(0), inst.op_kind(1)) {
            (OpKind::Register, OpKind::Register) => {
                let dst = self.convert_register(inst.op_register(0))?;
                let src = self.convert_register(inst.op_register(1))?;
                (dst, self.engine.cpu.read_xmm(src))
            }
            (OpKind::Register, OpKind::Memory) => {
                let dst = self.convert_register(inst.op_register(0))?;
                let addr = self.calculate_memory_address(inst, 1)?;
                let value = self.read_memory_128(addr)?;
                (dst, value)
            }
            _ => return Err(EmulatorError::UnsupportedOperandType),
        };

        // Extract two double-precision floats
        let double1 = f64::from_bits(src_value as u64);
        let double2 = f64::from_bits((src_value >> 64) as u64);

        // Convert to single-precision
        let float1 = double1 as f32;
        let float2 = double2 as f32;

        // Pack the two floats into the lower 64 bits, upper 64 bits are zeroed
        let result = float1.to_bits() as u128 | ((float2.to_bits() as u128) << 32);
        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    fn execute_cvtss2sd(&mut self, inst: &Instruction) -> Result<()> {
        // Convert Scalar Single-Precision FP to Scalar Double-Precision FP
        // Converts the lower single-precision float to double-precision, preserves upper bits
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let src_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_xmm(src)
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                self.read_memory_32(addr)? as u128
            }
            _ => return Err(EmulatorError::UnsupportedOperandType),
        };

        // Extract the single-precision float
        let float = f32::from_bits(src_value as u32);

        // Convert to double-precision
        let double = float as f64;

        // Get current destination value to preserve upper bits
        let dst_value = self.engine.cpu.read_xmm(dst_reg);

        // Replace lower 64 bits with the converted double, preserve upper 64 bits
        let result = double.to_bits() as u128 | (dst_value & 0xFFFFFFFFFFFFFFFF0000000000000000);
        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    fn execute_cvtsd2ss(&mut self, inst: &Instruction) -> Result<()> {
        // Convert Scalar Double-Precision FP to Scalar Single-Precision FP
        // Converts the lower double-precision float to single-precision, preserves upper bits
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let src_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_xmm(src)
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                self.read_memory_64(addr)? as u128
            }
            _ => return Err(EmulatorError::UnsupportedOperandType),
        };

        // Extract the double-precision float
        let double = f64::from_bits(src_value as u64);

        // Convert to single-precision
        let float = double as f32;

        // Get current destination value to preserve upper bits
        let dst_value = self.engine.cpu.read_xmm(dst_reg);

        // Replace lower 32 bits with the converted float, preserve upper 96 bits
        let result = float.to_bits() as u128 | (dst_value & 0xFFFFFFFFFFFFFFFFFFFFFFFF00000000);
        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    fn execute_cvtps2dq(&mut self, inst: &Instruction) -> Result<()> {
        // Convert Packed Single-Precision FP to Packed Signed Doubleword Integers
        // Converts 4 single-precision floats to 4 signed 32-bit integers with rounding
        let (dst_reg, src_value) = match (inst.op_kind(0), inst.op_kind(1)) {
            (OpKind::Register, OpKind::Register) => {
                let dst = self.convert_register(inst.op_register(0))?;
                let src = self.convert_register(inst.op_register(1))?;
                (dst, self.engine.cpu.read_xmm(src))
            }
            (OpKind::Register, OpKind::Memory) => {
                let dst = self.convert_register(inst.op_register(0))?;
                let addr = self.calculate_memory_address(inst, 1)?;
                let value = self.read_memory_128(addr)?;
                (dst, value)
            }
            _ => return Err(EmulatorError::UnsupportedOperandType),
        };

        // Extract four single-precision floats
        let floats = [
            f32::from_bits(src_value as u32),
            f32::from_bits((src_value >> 32) as u32),
            f32::from_bits((src_value >> 64) as u32),
            f32::from_bits((src_value >> 96) as u32),
        ];

        // Convert to signed integers with rounding
        let mut result = 0u128;
        for i in 0..4 {
            let int_val = if floats[i].is_nan() {
                i32::MIN // Indefinite integer value
            } else if floats[i] > i32::MAX as f32 {
                i32::MAX
            } else if floats[i] < i32::MIN as f32 {
                i32::MIN
            } else {
                floats[i].round() as i32
            };
            result |= (int_val as u32 as u128) << (i * 32);
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    fn execute_cvttps2dq(&mut self, inst: &Instruction) -> Result<()> {
        // Convert Packed Single-Precision FP to Packed Signed Doubleword Integers with Truncation
        // Converts 4 single-precision floats to 4 signed 32-bit integers with truncation
        let (dst_reg, src_value) = match (inst.op_kind(0), inst.op_kind(1)) {
            (OpKind::Register, OpKind::Register) => {
                let dst = self.convert_register(inst.op_register(0))?;
                let src = self.convert_register(inst.op_register(1))?;
                (dst, self.engine.cpu.read_xmm(src))
            }
            (OpKind::Register, OpKind::Memory) => {
                let dst = self.convert_register(inst.op_register(0))?;
                let addr = self.calculate_memory_address(inst, 1)?;
                let value = self.read_memory_128(addr)?;
                (dst, value)
            }
            _ => return Err(EmulatorError::UnsupportedOperandType),
        };

        // Extract four single-precision floats
        let floats = [
            f32::from_bits(src_value as u32),
            f32::from_bits((src_value >> 32) as u32),
            f32::from_bits((src_value >> 64) as u32),
            f32::from_bits((src_value >> 96) as u32),
        ];

        // Convert to signed integers with truncation
        let mut result = 0u128;
        for i in 0..4 {
            let int_val = if floats[i].is_nan() {
                i32::MIN // Indefinite integer value
            } else if floats[i] > i32::MAX as f32 {
                i32::MAX
            } else if floats[i] < i32::MIN as f32 {
                i32::MIN
            } else {
                floats[i].trunc() as i32
            };
            result |= (int_val as u32 as u128) << (i * 32);
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    fn execute_cvtdq2ps(&mut self, inst: &Instruction) -> Result<()> {
        // Convert Packed Signed Doubleword Integers to Packed Single-Precision FP
        // Converts 4 signed 32-bit integers to 4 single-precision floats
        let (dst_reg, src_value) = match (inst.op_kind(0), inst.op_kind(1)) {
            (OpKind::Register, OpKind::Register) => {
                let dst = self.convert_register(inst.op_register(0))?;
                let src = self.convert_register(inst.op_register(1))?;
                (dst, self.engine.cpu.read_xmm(src))
            }
            (OpKind::Register, OpKind::Memory) => {
                let dst = self.convert_register(inst.op_register(0))?;
                let addr = self.calculate_memory_address(inst, 1)?;
                let value = self.read_memory_128(addr)?;
                (dst, value)
            }
            _ => return Err(EmulatorError::UnsupportedOperandType),
        };

        // Extract four signed 32-bit integers
        let ints = [
            src_value as u32 as i32,
            (src_value >> 32) as u32 as i32,
            (src_value >> 64) as u32 as i32,
            (src_value >> 96) as u32 as i32,
        ];

        // Convert to single-precision floats
        let mut result = 0u128;
        for i in 0..4 {
            let float_val = ints[i] as f32;
            result |= (float_val.to_bits() as u128) << (i * 32);
        }

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    fn execute_cvtsi2ss(&mut self, inst: &Instruction) -> Result<()> {
        // Convert Signed Integer to Scalar Single-Precision FP
        // Converts a 32/64-bit signed integer to single-precision float in lower 32 bits
        let dst_reg = self.convert_register(inst.op_register(0))?;

        let int_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_reg(src) as i64
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                // Check operand size to determine if we read 32 or 64 bits
                if inst.memory_size().size() == 4 {
                    self.read_memory_32(addr)? as i32 as i64
                } else {
                    self.read_memory_64(addr)? as i64
                }
            }
            _ => return Err(EmulatorError::UnsupportedOperandType),
        };

        // Convert to single-precision float
        let float_val = int_value as f32;

        // Get current destination value to preserve upper bits
        let dst_value = self.engine.cpu.read_xmm(dst_reg);

        // Replace lower 32 bits with the converted float, preserve upper 96 bits
        let result = float_val.to_bits() as u128 | (dst_value & 0xFFFFFFFFFFFFFFFFFFFFFFFF00000000);
        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    fn execute_cvtsi2sd(&mut self, inst: &Instruction) -> Result<()> {
        // Convert Signed Integer to Scalar Double-Precision FP
        // Converts a 32/64-bit signed integer to double-precision float in lower 64 bits
        let dst_reg = self.convert_register(inst.op_register(0))?;

        let int_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_reg(src) as i64
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                // Check operand size to determine if we read 32 or 64 bits
                if inst.memory_size().size() == 4 {
                    self.read_memory_32(addr)? as i32 as i64
                } else {
                    self.read_memory_64(addr)? as i64
                }
            }
            _ => return Err(EmulatorError::UnsupportedOperandType),
        };

        // Convert to double-precision float
        let double_val = int_value as f64;

        // Get current destination value to preserve upper bits
        let dst_value = self.engine.cpu.read_xmm(dst_reg);

        // Replace lower 64 bits with the converted double, preserve upper 64 bits
        let result =
            double_val.to_bits() as u128 | (dst_value & 0xFFFFFFFFFFFFFFFF0000000000000000);
        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    fn execute_cvtss2si(&mut self, inst: &Instruction) -> Result<()> {
        // Convert Scalar Single-Precision FP to Signed Integer
        // Converts the lower single-precision float to a 32/64-bit signed integer with rounding
        let dst_reg = self.convert_register(inst.op_register(0))?;

        let float_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src = self.convert_register(inst.op_register(1))?;
                let value = self.engine.cpu.read_xmm(src);
                f32::from_bits(value as u32)
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                let value = self.read_memory_32(addr)?;
                f32::from_bits(value)
            }
            _ => return Err(EmulatorError::UnsupportedOperandType),
        };

        // Convert to signed integer with rounding
        let int_val = if float_value.is_nan() {
            i64::MIN // Indefinite integer value
        } else if self.is_64bit_register(dst_reg) {
            // 64-bit destination
            if float_value > i64::MAX as f32 {
                i64::MAX
            } else if float_value < i64::MIN as f32 {
                i64::MIN
            } else {
                float_value.round() as i64
            }
        } else {
            // 32-bit destination
            if float_value > i32::MAX as f32 {
                i32::MAX as i64
            } else if float_value < i32::MIN as f32 {
                i32::MIN as i64
            } else {
                float_value.round() as i32 as i64
            }
        };

        self.engine.cpu.write_reg(dst_reg, int_val as u64);
        Ok(())
    }

    fn execute_cvtsd2si(&mut self, inst: &Instruction) -> Result<()> {
        // Convert Scalar Double-Precision FP to Signed Integer
        // Converts the lower double-precision float to a 32/64-bit signed integer with rounding
        let dst_reg = self.convert_register(inst.op_register(0))?;

        let double_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src = self.convert_register(inst.op_register(1))?;
                let value = self.engine.cpu.read_xmm(src);
                f64::from_bits(value as u64)
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                let value = self.read_memory_64(addr)?;
                f64::from_bits(value)
            }
            _ => return Err(EmulatorError::UnsupportedOperandType),
        };

        // Convert to signed integer with rounding
        let int_val = if double_value.is_nan() {
            i64::MIN // Indefinite integer value
        } else if self.is_64bit_register(dst_reg) {
            // 64-bit destination
            if double_value > i64::MAX as f64 {
                i64::MAX
            } else if double_value < i64::MIN as f64 {
                i64::MIN
            } else {
                double_value.round() as i64
            }
        } else {
            // 32-bit destination
            if double_value > i32::MAX as f64 {
                i32::MAX as i64
            } else if double_value < i32::MIN as f64 {
                i32::MIN as i64
            } else {
                double_value.round() as i32 as i64
            }
        };

        self.engine.cpu.write_reg(dst_reg, int_val as u64);
        Ok(())
    }

    fn execute_cvttss2si(&mut self, inst: &Instruction) -> Result<()> {
        // Convert Scalar Single-Precision FP to Signed Integer with Truncation
        // Converts the lower single-precision float to a 32/64-bit signed integer with truncation
        let dst_reg = self.convert_register(inst.op_register(0))?;

        let float_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src = self.convert_register(inst.op_register(1))?;
                let value = self.engine.cpu.read_xmm(src);
                f32::from_bits(value as u32)
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                let value = self.read_memory_32(addr)?;
                f32::from_bits(value)
            }
            _ => return Err(EmulatorError::UnsupportedOperandType),
        };

        // Convert to signed integer with truncation
        let int_val = if float_value.is_nan() {
            i64::MIN // Indefinite integer value
        } else if self.is_64bit_register(dst_reg) {
            // 64-bit destination
            if float_value > i64::MAX as f32 {
                i64::MAX
            } else if float_value < i64::MIN as f32 {
                i64::MIN
            } else {
                float_value.trunc() as i64
            }
        } else {
            // 32-bit destination
            if float_value > i32::MAX as f32 {
                i32::MAX as i64
            } else if float_value < i32::MIN as f32 {
                i32::MIN as i64
            } else {
                float_value.trunc() as i32 as i64
            }
        };

        self.engine.cpu.write_reg(dst_reg, int_val as u64);
        Ok(())
    }

    fn execute_cvttsd2si(&mut self, inst: &Instruction) -> Result<()> {
        // Convert Scalar Double-Precision FP to Signed Integer with Truncation
        // Converts the lower double-precision float to a 32/64-bit signed integer with truncation
        let dst_reg = self.convert_register(inst.op_register(0))?;

        let double_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src = self.convert_register(inst.op_register(1))?;
                let value = self.engine.cpu.read_xmm(src);
                f64::from_bits(value as u64)
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                let value = self.read_memory_64(addr)?;
                f64::from_bits(value)
            }
            _ => return Err(EmulatorError::UnsupportedOperandType),
        };

        // Convert to signed integer with truncation
        let int_val = if double_value.is_nan() {
            i64::MIN // Indefinite integer value
        } else if self.is_64bit_register(dst_reg) {
            // 64-bit destination
            if double_value > i64::MAX as f64 {
                i64::MAX
            } else if double_value < i64::MIN as f64 {
                i64::MIN
            } else {
                double_value.trunc() as i64
            }
        } else {
            // 32-bit destination
            if double_value > i32::MAX as f64 {
                i32::MAX as i64
            } else if double_value < i32::MIN as f64 {
                i32::MIN as i64
            } else {
                double_value.trunc() as i32 as i64
            }
        };

        self.engine.cpu.write_reg(dst_reg, int_val as u64);
        Ok(())
    }

    // Scalar Double-Precision Floating-Point Arithmetic Operations

    fn execute_addsd(&mut self, inst: &Instruction) -> Result<()> {
        // ADDSD: Add Scalar Double-Precision Floating-Point Value
        // Adds the low double-precision float values, preserves upper bits
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let src_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_xmm(src_reg) as u64
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                self.read_memory_64(addr)?
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid ADDSD source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let dst_double = f64::from_bits(dst_value as u64);
        let src_double = f64::from_bits(src_value);
        let result_double = dst_double + src_double;

        // Replace lower 64 bits with result, preserve upper 64 bits
        let result =
            (result_double.to_bits() as u128) | (dst_value & 0xFFFFFFFFFFFFFFFF0000000000000000);
        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    fn execute_subsd(&mut self, inst: &Instruction) -> Result<()> {
        // SUBSD: Subtract Scalar Double-Precision Floating-Point Value
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let src_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_xmm(src_reg) as u64
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                self.read_memory_64(addr)?
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid SUBSD source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let dst_double = f64::from_bits(dst_value as u64);
        let src_double = f64::from_bits(src_value);
        let result_double = dst_double - src_double;

        let result =
            (result_double.to_bits() as u128) | (dst_value & 0xFFFFFFFFFFFFFFFF0000000000000000);
        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    fn execute_mulsd(&mut self, inst: &Instruction) -> Result<()> {
        // MULSD: Multiply Scalar Double-Precision Floating-Point Value
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let src_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_xmm(src_reg) as u64
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                self.read_memory_64(addr)?
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid MULSD source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let dst_double = f64::from_bits(dst_value as u64);
        let src_double = f64::from_bits(src_value);
        let result_double = dst_double * src_double;

        let result =
            (result_double.to_bits() as u128) | (dst_value & 0xFFFFFFFFFFFFFFFF0000000000000000);
        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    fn execute_divsd(&mut self, inst: &Instruction) -> Result<()> {
        // DIVSD: Divide Scalar Double-Precision Floating-Point Value
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let src_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_xmm(src_reg) as u64
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                self.read_memory_64(addr)?
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid DIVSD source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let dst_double = f64::from_bits(dst_value as u64);
        let src_double = f64::from_bits(src_value);
        let result_double = dst_double / src_double;

        let result =
            (result_double.to_bits() as u128) | (dst_value & 0xFFFFFFFFFFFFFFFF0000000000000000);
        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    // Scalar Single-Precision Floating-Point Arithmetic Operations

    fn execute_addss(&mut self, inst: &Instruction) -> Result<()> {
        // ADDSS: Add Scalar Single-Precision Floating-Point Value
        // Adds the low single-precision float values, preserves upper bits
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let src_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_xmm(src_reg) as u32
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                self.read_memory_32(addr)?
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid ADDSS source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let dst_float = f32::from_bits(dst_value as u32);
        let src_float = f32::from_bits(src_value);
        let result_float = dst_float + src_float;

        // Replace lower 32 bits with result, preserve upper 96 bits
        let result =
            (result_float.to_bits() as u128) | (dst_value & 0xFFFFFFFFFFFFFFFFFFFFFFFF00000000);
        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    fn execute_subss(&mut self, inst: &Instruction) -> Result<()> {
        // SUBSS: Subtract Scalar Single-Precision Floating-Point Value
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let src_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_xmm(src_reg) as u32
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                self.read_memory_32(addr)?
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid SUBSS source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let dst_float = f32::from_bits(dst_value as u32);
        let src_float = f32::from_bits(src_value);
        let result_float = dst_float - src_float;

        let result =
            (result_float.to_bits() as u128) | (dst_value & 0xFFFFFFFFFFFFFFFFFFFFFFFF00000000);
        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    fn execute_mulss(&mut self, inst: &Instruction) -> Result<()> {
        // MULSS: Multiply Scalar Single-Precision Floating-Point Value
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let src_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_xmm(src_reg) as u32
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                self.read_memory_32(addr)?
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid MULSS source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let dst_float = f32::from_bits(dst_value as u32);
        let src_float = f32::from_bits(src_value);
        let result_float = dst_float * src_float;

        let result =
            (result_float.to_bits() as u128) | (dst_value & 0xFFFFFFFFFFFFFFFFFFFFFFFF00000000);
        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    fn execute_divss(&mut self, inst: &Instruction) -> Result<()> {
        // DIVSS: Divide Scalar Single-Precision Floating-Point Value
        let dst_reg = self.convert_register(inst.op_register(0))?;
        let src_value = match inst.op_kind(1) {
            OpKind::Register => {
                let src_reg = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_xmm(src_reg) as u32
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                self.read_memory_32(addr)?
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid DIVSS source".to_string(),
                ));
            }
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);
        let dst_float = f32::from_bits(dst_value as u32);
        let src_float = f32::from_bits(src_value);
        let result_float = dst_float / src_float;

        let result =
            (result_float.to_bits() as u128) | (dst_value & 0xFFFFFFFFFFFFFFFFFFFFFFFF00000000);
        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    fn execute_shufps(&mut self, inst: &Instruction) -> Result<()> {
        // SHUFPS: Shuffle Packed Single-Precision Floating-Point Values
        // Shuffles floats from dst and src according to imm8 control byte
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
            _ => return Err(EmulatorError::UnsupportedOperandType),
        };

        // Get the immediate control byte
        let imm8 = inst.immediate8();
        let dst_value = self.engine.cpu.read_xmm(dst_reg);

        // Extract four 32-bit floats from each operand
        let dst_floats = [
            (dst_value as u32),
            ((dst_value >> 32) as u32),
            ((dst_value >> 64) as u32),
            ((dst_value >> 96) as u32),
        ];
        let src_floats = [
            (src_value as u32),
            ((src_value >> 32) as u32),
            ((src_value >> 64) as u32),
            ((src_value >> 96) as u32),
        ];

        // Shuffle according to immediate bits
        // Bits 0-1 select from dst for result[0]
        // Bits 2-3 select from dst for result[1]
        // Bits 4-5 select from src for result[2]
        // Bits 6-7 select from src for result[3]
        let result0 = dst_floats[(imm8 & 0x03) as usize];
        let result1 = dst_floats[((imm8 >> 2) & 0x03) as usize];
        let result2 = src_floats[((imm8 >> 4) & 0x03) as usize];
        let result3 = src_floats[((imm8 >> 6) & 0x03) as usize];

        // Pack results into u128
        let result = (result0 as u128)
            | ((result1 as u128) << 32)
            | ((result2 as u128) << 64)
            | ((result3 as u128) << 96);

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    fn execute_unpcklps(&mut self, inst: &Instruction) -> Result<()> {
        // UNPCKLPS: Unpack and Interleave Low Packed Single-Precision Floating-Point Values
        // Interleaves the low quadword (2 floats) of destination and source
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
            _ => return Err(EmulatorError::UnsupportedOperandType),
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);

        // Extract the low quadword (first 2 floats) from each operand
        let dst_float0 = dst_value as u32;
        let dst_float1 = (dst_value >> 32) as u32;
        let src_float0 = src_value as u32;
        let src_float1 = (src_value >> 32) as u32;

        // Interleave: dst[0], src[0], dst[1], src[1]
        let result = (dst_float0 as u128)
            | ((src_float0 as u128) << 32)
            | ((dst_float1 as u128) << 64)
            | ((src_float1 as u128) << 96);

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    fn execute_unpckhps(&mut self, inst: &Instruction) -> Result<()> {
        // UNPCKHPS: Unpack and Interleave High Packed Single-Precision Floating-Point Values
        // Interleaves the high quadword (2 floats) of destination and source
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
            _ => return Err(EmulatorError::UnsupportedOperandType),
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);

        // Extract the high quadword (last 2 floats) from each operand
        let dst_float2 = (dst_value >> 64) as u32;
        let dst_float3 = (dst_value >> 96) as u32;
        let src_float2 = (src_value >> 64) as u32;
        let src_float3 = (src_value >> 96) as u32;

        // Interleave: dst[2], src[2], dst[3], src[3]
        let result = (dst_float2 as u128)
            | ((src_float2 as u128) << 32)
            | ((dst_float3 as u128) << 64)
            | ((src_float3 as u128) << 96);

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    fn execute_shufpd(&mut self, inst: &Instruction) -> Result<()> {
        // SHUFPD: Shuffle Packed Double-Precision Floating-Point Values
        // Shuffles doubles from dst and src according to imm8 control byte
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
            _ => return Err(EmulatorError::UnsupportedOperandType),
        };

        // Get the immediate control byte
        let imm8 = inst.immediate8();
        let dst_value = self.engine.cpu.read_xmm(dst_reg);

        // Extract two 64-bit doubles from each operand
        let dst_doubles = [(dst_value as u64), ((dst_value >> 64) as u64)];
        let src_doubles = [(src_value as u64), ((src_value >> 64) as u64)];

        // Shuffle according to immediate bits
        // Bit 0 selects from dst for result[0]
        // Bit 1 selects from src for result[1]
        let result0 = dst_doubles[(imm8 & 0x01) as usize];
        let result1 = src_doubles[((imm8 >> 1) & 0x01) as usize];

        // Pack results into u128
        let result = (result0 as u128) | ((result1 as u128) << 64);

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    fn execute_unpcklpd(&mut self, inst: &Instruction) -> Result<()> {
        // UNPCKLPD: Unpack and Interleave Low Packed Double-Precision Floating-Point Values
        // Takes the low double from each operand
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
            _ => return Err(EmulatorError::UnsupportedOperandType),
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);

        // Extract the low double from each operand
        let dst_low = dst_value as u64;
        let src_low = src_value as u64;

        // Result is: dst[0], src[0]
        let result = (dst_low as u128) | ((src_low as u128) << 64);

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    fn execute_unpckhpd(&mut self, inst: &Instruction) -> Result<()> {
        // UNPCKHPD: Unpack and Interleave High Packed Double-Precision Floating-Point Values
        // Takes the high double from each operand
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
            _ => return Err(EmulatorError::UnsupportedOperandType),
        };

        let dst_value = self.engine.cpu.read_xmm(dst_reg);

        // Extract the high double from each operand
        let dst_high = (dst_value >> 64) as u64;
        let src_high = (src_value >> 64) as u64;

        // Result is: dst[1], src[1]
        let result = (dst_high as u128) | ((src_high as u128) << 64);

        self.engine.cpu.write_xmm(dst_reg, result);
        Ok(())
    }

    fn execute_paddb(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_paddw(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_paddd(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_paddq(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_psubb(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_psubw(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_psubd(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_psubq(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_pmullw(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_pmulhw(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_pmulhuw(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_pmuludq(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_pand(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_pandn(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_por(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_pxor(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_pcmpeqb(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_pcmpeqw(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_pcmpeqd(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_pcmpgtb(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_pcmpgtw(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_pcmpgtd(&mut self, inst: &Instruction) -> Result<()> {
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
                ));
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

    fn execute_rcl(&mut self, inst: &Instruction) -> Result<()> {
        // RCL: Rotate through carry left
        let dst_value = self.read_operand(inst, 0)?;
        let count = (self.read_operand(inst, 1)? & 0x3F) as u32; // Modulo 64
        
        if count == 0 {
            return Ok(());
        }
        
        let size = self.get_operand_size_from_instruction(inst, 0)?;
        let bit_count = size * 8;
        
        // For RCL, we rotate through CF, making the rotation count be bit_count + 1
        let mod_count = count % (bit_count as u32 + 1);
        
        if mod_count == 0 {
            return Ok(());
        }
        
        let old_cf = if self.engine.cpu.rflags.contains(Flags::CF) { 1u64 } else { 0u64 };
        
        let (result, new_cf) = match size {
            1 => {
                let val = dst_value as u8;
                let extended = (val as u16) | ((old_cf as u16) << 8);
                let rotated = (extended << mod_count) | (extended >> (9 - mod_count));
                let result = (rotated & 0xFF) as u64;
                let cf = (rotated & 0x100) != 0;
                (result, cf)
            }
            2 => {
                let val = dst_value as u16;
                let extended = (val as u32) | ((old_cf as u32) << 16);
                let rotated = (extended << mod_count) | (extended >> (17 - mod_count));
                let result = (rotated & 0xFFFF) as u64;
                let cf = (rotated & 0x10000) != 0;
                (result, cf)
            }
            4 => {
                let val = dst_value as u32;
                let extended = (val as u64) | (old_cf << 32);
                let rotated = (extended << mod_count) | (extended >> (33 - mod_count));
                let result = rotated & 0xFFFFFFFF;
                let cf = (rotated & 0x100000000) != 0;
                (result, cf)
            }
            8 => {
                // For 64-bit, we need to handle this carefully
                let mut result = dst_value;
                let mut cf = old_cf != 0;
                
                for _ in 0..mod_count {
                    let new_cf = (result >> 63) & 1 != 0;
                    result = (result << 1) | (if cf { 1 } else { 0 });
                    cf = new_cf;
                }
                (result, cf)
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(format!(
                    "Unsupported size for RCL: {}",
                    size
                )));
            }
        };
        
        // Update CF
        if new_cf {
            self.engine.cpu.rflags.insert(Flags::CF);
        } else {
            self.engine.cpu.rflags.remove(Flags::CF);
        }
        
        // Update OF if count == 1
        if count == 1 {
            // OF = MSB XOR CF after rotation
            let msb = (result >> (bit_count - 1)) & 1 != 0;
            if msb != new_cf {
                self.engine.cpu.rflags.insert(Flags::OF);
            } else {
                self.engine.cpu.rflags.remove(Flags::OF);
            }
        }
        
        self.write_operand(inst, 0, result)?;
        Ok(())
    }
    
    fn execute_rcr(&mut self, inst: &Instruction) -> Result<()> {
        // RCR: Rotate through carry right
        let dst_value = self.read_operand(inst, 0)?;
        let count = (self.read_operand(inst, 1)? & 0x3F) as u32; // Modulo 64
        
        if count == 0 {
            return Ok(());
        }
        
        let size = self.get_operand_size_from_instruction(inst, 0)?;
        let bit_count = size * 8;
        
        // For RCR, we rotate through CF, making the rotation count be bit_count + 1
        let mod_count = count % (bit_count as u32 + 1);
        
        if mod_count == 0 {
            return Ok(());
        }
        
        let old_cf = if self.engine.cpu.rflags.contains(Flags::CF) { 1u64 } else { 0u64 };
        
        let (result, new_cf) = match size {
            1 => {
                let val = dst_value as u8;
                let extended = (val as u16) | ((old_cf as u16) << 8);
                let rotated = (extended >> mod_count) | (extended << (9 - mod_count));
                let result = (rotated & 0xFF) as u64;
                let cf = ((extended >> (mod_count - 1)) & 1) != 0;
                (result, cf)
            }
            2 => {
                let val = dst_value as u16;
                let extended = (val as u32) | ((old_cf as u32) << 16);
                let rotated = (extended >> mod_count) | (extended << (17 - mod_count));
                let result = (rotated & 0xFFFF) as u64;
                let cf = ((extended >> (mod_count - 1)) & 1) != 0;
                (result, cf)
            }
            4 => {
                let val = dst_value as u32;
                let extended = (val as u64) | (old_cf << 32);
                let rotated = (extended >> mod_count) | (extended << (33 - mod_count));
                let result = rotated & 0xFFFFFFFF;
                let cf = ((extended >> (mod_count - 1)) & 1) != 0;
                (result, cf)
            }
            8 => {
                // For 64-bit, we need to handle this carefully
                let mut result = dst_value;
                let mut cf = old_cf != 0;
                
                for _ in 0..mod_count {
                    let new_cf = result & 1 != 0;
                    result = (result >> 1) | ((if cf { 1 } else { 0 }) << 63);
                    cf = new_cf;
                }
                (result, cf)
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(format!(
                    "Unsupported size for RCR: {}",
                    size
                )));
            }
        };
        
        // Update CF
        if new_cf {
            self.engine.cpu.rflags.insert(Flags::CF);
        } else {
            self.engine.cpu.rflags.remove(Flags::CF);
        }
        
        // Update OF if count == 1
        if count == 1 {
            // OF = two most significant bits XOR after rotation
            let msb = (result >> (bit_count - 1)) & 1 != 0;
            let msb_minus_1 = (result >> (bit_count - 2)) & 1 != 0;
            if msb != msb_minus_1 {
                self.engine.cpu.rflags.insert(Flags::OF);
            } else {
                self.engine.cpu.rflags.remove(Flags::OF);
            }
        }
        
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    fn execute_stc(&mut self, _inst: &Instruction) -> Result<()> {
        // STC: Set carry flag
        self.engine.cpu.rflags.insert(Flags::CF);
        Ok(())
    }
    
    fn execute_clc(&mut self, _inst: &Instruction) -> Result<()> {
        // CLC: Clear carry flag
        self.engine.cpu.rflags.remove(Flags::CF);
        Ok(())
    }
    
    fn execute_cmc(&mut self, _inst: &Instruction) -> Result<()> {
        // CMC: Complement carry flag
        if self.engine.cpu.rflags.contains(Flags::CF) {
            self.engine.cpu.rflags.remove(Flags::CF);
        } else {
            self.engine.cpu.rflags.insert(Flags::CF);
        }
        Ok(())
    }
    
    fn execute_xlat(&mut self, _inst: &Instruction) -> Result<()> {
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
    
    fn execute_pause(&mut self, _inst: &Instruction) -> Result<()> {
        // PAUSE: Spin-wait loop hint
        // This is a hint to the processor that the code is in a spin-wait loop
        // In emulation, we don't need to do anything special
        // Real processors use this to improve power consumption and performance
        // when one logical processor is waiting for another
        
        // PAUSE doesn't affect registers or flags
        // It's essentially a NOP with a hint for the processor
        Ok(())
    }
    
    fn execute_ud2(&mut self, _inst: &Instruction) -> Result<()> {
        // UD2: Undefined instruction
        // Guaranteed to raise an invalid opcode exception
        // Often used for marking unreachable code or debugging
        
        // Raise an invalid opcode error
        Err(EmulatorError::InvalidOpcode)
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
        let bit_base = self.read_operand(inst, 0)?;
        let bit_offset = self.read_operand(inst, 1)?;

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
        let bit_base = self.read_operand(inst, 0)?;
        let bit_offset = self.read_operand(inst, 1)?;

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
        self.write_operand(inst, 0, new_value)?;

        Ok(())
    }

    fn execute_btr(&mut self, inst: &Instruction) -> Result<()> {
        // BTR: Bit Test and Reset - Test bit and set it to 0
        let bit_base = self.read_operand(inst, 0)?;
        let bit_offset = self.read_operand(inst, 1)?;

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
        self.write_operand(inst, 0, new_value)?;

        Ok(())
    }

    fn execute_btc(&mut self, inst: &Instruction) -> Result<()> {
        // BTC: Bit Test and Complement - Test bit and flip it
        let bit_base = self.read_operand(inst, 0)?;
        let bit_offset = self.read_operand(inst, 1)?;

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
        self.write_operand(inst, 0, new_value)?;

        Ok(())
    }

    fn execute_bsf(&mut self, inst: &Instruction) -> Result<()> {
        // BSF: Bit Scan Forward - Find first set bit (from LSB)
        let source = self.read_operand(inst, 1)?;

        if source == 0 {
            // If source is 0, set ZF and destination is undefined
            self.engine.cpu.rflags.insert(Flags::ZF);
        } else {
            // Find the position of the first set bit
            let bit_pos = source.trailing_zeros() as u64;
            self.engine.cpu.rflags.remove(Flags::ZF);

            // Write result to destination
            self.write_operand(inst, 0, bit_pos)?;
        }

        Ok(())
    }

    fn execute_bsr(&mut self, inst: &Instruction) -> Result<()> {
        // BSR: Bit Scan Reverse - Find first set bit (from MSB)
        let source = self.read_operand(inst, 1)?;

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
                _ => {
                    return Err(EmulatorError::UnsupportedInstruction(format!(
                        "Unsupported BSR operand size: {}",
                        size
                    )));
                }
            };

            self.engine.cpu.rflags.remove(Flags::ZF);

            // Write result to destination
            self.write_operand(inst, 0, bit_pos)?;
        }

        Ok(())
    }

    fn execute_enter(&mut self, inst: &Instruction) -> Result<()> {
        // ENTER: Create stack frame for procedure
        // Enter imm16, imm8
        // imm16 = size of stack frame, imm8 = nesting level (we'll only implement level 0)

        // Get operands - for ENTER, operands are immediates
        let frame_size = inst.immediate(0);
        let nesting_level = inst.immediate(1) as u8;

        if nesting_level != 0 {
            return Err(EmulatorError::UnsupportedInstruction(format!(
                "ENTER with nesting level {} not supported",
                nesting_level
            )));
        }

        // Push RBP
        let rbp_value = self.engine.cpu.read_reg(Register::RBP);
        let rsp_value = self.engine.cpu.read_reg(Register::RSP);

        // Decrement RSP and store RBP
        let new_rsp = rsp_value.wrapping_sub(8);
        // Write 64-bit value to memory
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&rbp_value.to_le_bytes());
        self.engine.memory.write(new_rsp, &bytes)?;
        self.engine.cpu.write_reg(Register::RSP, new_rsp);

        // Set RBP to current RSP
        self.engine.cpu.write_reg(Register::RBP, new_rsp);

        // Allocate space for local variables (subtract frame_size from RSP)
        let final_rsp = new_rsp.wrapping_sub(frame_size);
        self.engine.cpu.write_reg(Register::RSP, final_rsp);

        Ok(())
    }

    fn execute_leave(&mut self, _inst: &Instruction) -> Result<()> {
        // LEAVE: Destroy stack frame before returning
        // Equivalent to: MOV RSP, RBP; POP RBP

        // Set RSP to RBP
        let rbp_value = self.engine.cpu.read_reg(Register::RBP);
        self.engine.cpu.write_reg(Register::RSP, rbp_value);

        // Pop RBP
        // Read 64-bit value from memory
        let mut bytes = [0u8; 8];
        self.engine.memory.read(rbp_value, &mut bytes)?;
        let old_rbp = u64::from_le_bytes(bytes);
        self.engine.cpu.write_reg(Register::RBP, old_rbp);

        // Increment RSP
        let new_rsp = rbp_value.wrapping_add(8);
        self.engine.cpu.write_reg(Register::RSP, new_rsp);

        Ok(())
    }

    fn execute_popcnt(&mut self, inst: &Instruction) -> Result<()> {
        // POPCNT: Count the number of set bits
        let source = self.read_operand(inst, 1)?;

        // Count the number of 1 bits
        let count = source.count_ones() as u64;

        // Write result to destination
        self.write_operand(inst, 0, count)?;

        // Update flags
        // POPCNT clears all flags except CF and ZF
        self.engine
            .cpu
            .rflags
            .remove(Flags::SF | Flags::OF | Flags::AF | Flags::PF);
        self.engine.cpu.rflags.remove(Flags::CF); // CF is always cleared

        if count == 0 {
            self.engine.cpu.rflags.insert(Flags::ZF);
        } else {
            self.engine.cpu.rflags.remove(Flags::ZF);
        }

        Ok(())
    }

    fn execute_lzcnt(&mut self, inst: &Instruction) -> Result<()> {
        // LZCNT: Leading Zero Count - Count number of leading zero bits
        let source = self.read_operand(inst, 1)?;
        let size = self.get_operand_size_from_instruction(inst, 1)?;
        
        // Count leading zeros based on operand size
        let count = match size {
            1 => (source as u8).leading_zeros() as u64,
            2 => (source as u16).leading_zeros() as u64,
            4 => (source as u32).leading_zeros() as u64,
            8 => source.leading_zeros() as u64,
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(format!(
                    "Unsupported LZCNT operand size: {}",
                    size
                )));
            }
        };

        // Write result to destination
        self.write_operand(inst, 0, count)?;

        // Update flags
        // LZCNT clears all flags except CF and ZF
        self.engine.cpu.rflags.remove(Flags::SF | Flags::OF | Flags::AF | Flags::PF);
        
        // CF is set if source is zero (indicating the destination holds operand size in bits)
        if source == 0 {
            self.engine.cpu.rflags.insert(Flags::CF);
            self.engine.cpu.rflags.insert(Flags::ZF);
        } else {
            self.engine.cpu.rflags.remove(Flags::CF);
            self.engine.cpu.rflags.remove(Flags::ZF);
        }

        Ok(())
    }

    fn execute_tzcnt(&mut self, inst: &Instruction) -> Result<()> {
        // TZCNT: Trailing Zero Count - Count number of trailing zero bits
        let source = self.read_operand(inst, 1)?;
        let size = self.get_operand_size_from_instruction(inst, 1)?;
        
        // Count trailing zeros based on operand size
        let count = if source == 0 {
            // If source is 0, return the operand size in bits
            match size {
                1 => 8u64,
                2 => 16u64,
                4 => 32u64,
                8 => 64u64,
                _ => {
                    return Err(EmulatorError::UnsupportedInstruction(format!(
                        "Unsupported TZCNT operand size: {}",
                        size
                    )));
                }
            }
        } else {
            source.trailing_zeros() as u64
        };

        // Write result to destination
        self.write_operand(inst, 0, count)?;

        // Update flags
        // TZCNT clears all flags except CF and ZF
        self.engine.cpu.rflags.remove(Flags::SF | Flags::OF | Flags::AF | Flags::PF);
        
        // CF is set if source is zero
        if source == 0 {
            self.engine.cpu.rflags.insert(Flags::CF);
            self.engine.cpu.rflags.insert(Flags::ZF);
        } else {
            self.engine.cpu.rflags.remove(Flags::CF);
            self.engine.cpu.rflags.remove(Flags::ZF);
        }

        Ok(())
    }

    fn execute_andn(&mut self, inst: &Instruction) -> Result<()> {
        // ANDN: Logical AND NOT
        // dest = ~src1 & src2
        // This instruction performs a bitwise AND of the complement of the first source operand
        // with the second source operand and stores the result in the destination.
        
        // ANDN has 3 operands: dest, src1, src2
        // In VEX encoding: ANDN dest, src1, src2 means dest = ~src1 & src2
        let src1 = self.read_operand(inst, 1)?;
        let src2 = self.read_operand(inst, 2)?;
        
        // Perform AND NOT operation
        let result = !src1 & src2;
        
        // Write result to destination
        self.write_operand(inst, 0, result)?;
        
        // Update flags according to Intel manual
        // ANDN sets SF, ZF based on result
        // Clears OF and CF
        // AF is undefined (we'll clear it)
        // PF is undefined (we'll set it based on low byte)
        self.engine.cpu.rflags.remove(Flags::OF | Flags::CF | Flags::AF);
        
        // Set SF based on sign bit of result
        let size = self.get_operand_size_from_instruction(inst, 0)?;
        let sign_bit = match size {
            1 => (result & 0x80) != 0,
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
        
        // Set ZF if result is zero
        if result == 0 {
            self.engine.cpu.rflags.insert(Flags::ZF);
        } else {
            self.engine.cpu.rflags.remove(Flags::ZF);
        }
        
        // Set PF based on low byte
        let low_byte = (result & 0xFF) as u8;
        if low_byte.count_ones() % 2 == 0 {
            self.engine.cpu.rflags.insert(Flags::PF);
        } else {
            self.engine.cpu.rflags.remove(Flags::PF);
        }
        
        Ok(())
    }

    fn execute_bextr(&mut self, inst: &Instruction) -> Result<()> {
        // BEXTR: Bit Field Extract
        // Extracts contiguous bits from the first source operand using index and length
        // specified in the second source operand
        
        // BEXTR has 3 operands: dest, src1, src2
        // src2 contains: bits[7:0] = starting bit index, bits[15:8] = length
        let src1 = self.read_operand(inst, 1)?;
        let src2 = self.read_operand(inst, 2)?;
        
        // Extract start position and length from src2
        let start = (src2 & 0xFF) as u32;
        let length = ((src2 >> 8) & 0xFF) as u32;
        
        // Get operand size for masking
        let size = self.get_operand_size_from_instruction(inst, 0)?;
        let max_bits = size * 8;
        
        // If start position is >= operand size in bits, result is 0
        let result = if start >= max_bits as u32 {
            0u64
        } else if length == 0 {
            0u64
        } else {
            // Calculate how many bits we can actually extract
            let available_bits = (max_bits as u32).saturating_sub(start);
            let actual_length = length.min(available_bits).min(64);
            
            // Shift right to move the desired bits to position 0
            let shifted = src1 >> start;
            
            // Create a mask for the desired number of bits
            let mask = if actual_length >= 64 {
                !0u64
            } else {
                (1u64 << actual_length) - 1
            };
            
            // Extract the bits
            shifted & mask
        };
        
        // Write result to destination
        self.write_operand(inst, 0, result)?;
        
        // Update flags according to Intel manual
        // BEXTR clears OF and CF
        // Sets ZF based on result
        // AF, SF, PF are undefined (we'll clear AF, set SF/PF based on result)
        self.engine.cpu.rflags.remove(Flags::OF | Flags::CF | Flags::AF);
        
        // Set ZF if result is zero
        if result == 0 {
            self.engine.cpu.rflags.insert(Flags::ZF);
        } else {
            self.engine.cpu.rflags.remove(Flags::ZF);
        }
        
        // Set SF based on sign bit of result (even though it's undefined)
        let sign_bit = match size {
            1 => (result & 0x80) != 0,
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
        
        // Set PF based on low byte
        let low_byte = (result & 0xFF) as u8;
        if low_byte.count_ones() % 2 == 0 {
            self.engine.cpu.rflags.insert(Flags::PF);
        } else {
            self.engine.cpu.rflags.remove(Flags::PF);
        }
        
        Ok(())
    }

    fn execute_blsi(&mut self, inst: &Instruction) -> Result<()> {
        // BLSI: Extract Lowest Set Isolated Bit
        // Extracts the lowest set bit from the source operand and stores it in the destination
        // Operation: dest = src & -src
        // This isolates the rightmost 1 bit (if any) in the source operand
        
        // BLSI has 2 operands: dest, src
        // For VEX encoding, operand 0 is destination, operand 1 is source
        let src = self.read_operand(inst, 1)?;
        
        // Perform the operation: src & -src
        // In two's complement, -src = ~src + 1
        let neg_src = (!src).wrapping_add(1);
        let result = src & neg_src;
        
        // Write result to destination
        self.write_operand(inst, 0, result)?;
        
        // Update flags according to Intel manual
        // BLSI sets SF, CF, OF based on result
        // ZF is set if src is zero (result would be zero)
        // PF is undefined (we'll set it based on low byte)
        // AF is undefined (we'll clear it)
        self.engine.cpu.rflags.remove(Flags::AF);
        
        // Set ZF if source is zero (result would be zero)
        if src == 0 {
            self.engine.cpu.rflags.insert(Flags::ZF);
            // CF is cleared when src is zero
            self.engine.cpu.rflags.remove(Flags::CF);
        } else {
            self.engine.cpu.rflags.remove(Flags::ZF);
            // CF is set when src is not zero
            self.engine.cpu.rflags.insert(Flags::CF);
        }
        
        // SF is set to the MSB of the result
        let size = self.get_operand_size_from_instruction(inst, 0)?;
        let sign_bit = match size {
            1 => (result & 0x80) != 0,
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
        
        // OF is cleared
        self.engine.cpu.rflags.remove(Flags::OF);
        
        // Set PF based on low byte
        let low_byte = (result & 0xFF) as u8;
        if low_byte.count_ones() % 2 == 0 {
            self.engine.cpu.rflags.insert(Flags::PF);
        } else {
            self.engine.cpu.rflags.remove(Flags::PF);
        }
        
        Ok(())
    }

    fn execute_blsmsk(&mut self, inst: &Instruction) -> Result<()> {
        // BLSMSK: Get Mask Up to Lowest Set Bit
        // Creates a mask with all bits set from bit 0 up to and including 
        // the lowest set bit in the source operand
        // Operation: dest = src ^ (src - 1)
        
        // BLSMSK has 2 operands: dest, src
        let src = self.read_operand(inst, 1)?;
        
        // Perform the operation: src ^ (src - 1)
        let result = src ^ src.wrapping_sub(1);
        
        // Write result to destination
        self.write_operand(inst, 0, result)?;
        
        // Update flags according to Intel manual
        // BLSMSK sets SF based on result
        // CF is set if src is NOT zero
        // ZF is cleared (result can never be zero if src != 0)
        // OF and AF are undefined (we'll clear them)
        // PF is undefined (we'll set it based on low byte)
        self.engine.cpu.rflags.remove(Flags::OF | Flags::AF);
        
        // Set CF if source is not zero
        if src != 0 {
            self.engine.cpu.rflags.insert(Flags::CF);
            // ZF is always clear when src != 0
            self.engine.cpu.rflags.remove(Flags::ZF);
        } else {
            self.engine.cpu.rflags.remove(Flags::CF);
            // ZF is set when src == 0 (result would be 0)
            self.engine.cpu.rflags.insert(Flags::ZF);
        }
        
        // SF is set to the MSB of the result
        let size = self.get_operand_size_from_instruction(inst, 0)?;
        let sign_bit = match size {
            1 => (result & 0x80) != 0,
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
        
        // Set PF based on low byte
        let low_byte = (result & 0xFF) as u8;
        if low_byte.count_ones() % 2 == 0 {
            self.engine.cpu.rflags.insert(Flags::PF);
        } else {
            self.engine.cpu.rflags.remove(Flags::PF);
        }
        
        Ok(())
    }

    fn execute_blsr(&mut self, inst: &Instruction) -> Result<()> {
        // BLSR: Reset Lowest Set Bit
        // Clears the lowest set bit in the source operand
        // Operation: dest = src & (src - 1)
        
        // BLSR has 2 operands: dest, src
        let src = self.read_operand(inst, 1)?;
        
        // Perform the operation: src & (src - 1)
        let result = src & src.wrapping_sub(1);
        
        // Write result to destination
        self.write_operand(inst, 0, result)?;
        
        // Update flags according to Intel manual
        // BLSR sets SF, ZF based on result
        // CF is set if src is NOT zero
        // OF is cleared
        // AF is undefined (we'll clear it)
        // PF is undefined (we'll set it based on low byte)
        self.engine.cpu.rflags.remove(Flags::OF | Flags::AF);
        
        // Set CF if source is not zero
        if src != 0 {
            self.engine.cpu.rflags.insert(Flags::CF);
        } else {
            self.engine.cpu.rflags.remove(Flags::CF);
        }
        
        // Set ZF if result is zero
        if result == 0 {
            self.engine.cpu.rflags.insert(Flags::ZF);
        } else {
            self.engine.cpu.rflags.remove(Flags::ZF);
        }
        
        // SF is set to the MSB of the result
        let size = self.get_operand_size_from_instruction(inst, 0)?;
        let sign_bit = match size {
            1 => (result & 0x80) != 0,
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
        
        // Set PF based on low byte
        let low_byte = (result & 0xFF) as u8;
        if low_byte.count_ones() % 2 == 0 {
            self.engine.cpu.rflags.insert(Flags::PF);
        } else {
            self.engine.cpu.rflags.remove(Flags::PF);
        }
        
        Ok(())
    }

    fn execute_bzhi(&mut self, inst: &Instruction) -> Result<()> {
        // BZHI: Zero High Bits Starting with Specified Bit Position
        // Takes bits from source1[0..index-1] where index is in source2[7:0]
        // Zeroes all bits from index and higher
        
        // BZHI has 3 operands: dest, src1, src2
        let src1 = self.read_operand(inst, 1)?;
        let src2 = self.read_operand(inst, 2)?;
        
        // Extract the bit index from bits 7:0 of src2
        let index = (src2 & 0xFF) as u32;
        
        // Get operand size in bits
        let size = inst.op0_register().size();
        let size_bits = (size * 8) as u32;
        
        // Compute result
        let result = if index >= size_bits {
            // If index >= operand size, result is src1 unchanged
            src1
        } else if index == 0 {
            // If index is 0, result is 0
            0
        } else {
            // Otherwise, mask off high bits starting at index
            // Create mask with 'index' low bits set
            let mask = (1u64 << index) - 1;
            src1 & mask
        };
        
        // Write result to destination
        self.write_operand(inst, 0, result)?;
        
        // Update flags according to Intel manual
        // BZHI clears CF and OF
        self.engine.cpu.rflags.remove(Flags::CF | Flags::OF);
        
        // Set ZF if result is zero
        if result == 0 {
            self.engine.cpu.rflags.insert(Flags::ZF);
        } else {
            self.engine.cpu.rflags.remove(Flags::ZF);
        }
        
        // Set SF based on sign bit of result
        let sign_bit = match size {
            1 => (result & 0x80) != 0,
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
        
        // PF is undefined - we'll set it based on low byte for consistency
        let low_byte = (result & 0xFF) as u8;
        if low_byte.count_ones() % 2 == 0 {
            self.engine.cpu.rflags.insert(Flags::PF);
        } else {
            self.engine.cpu.rflags.remove(Flags::PF);
        }
        
        // AF is undefined - we'll clear it
        self.engine.cpu.rflags.remove(Flags::AF);
        
        Ok(())
    }

    fn execute_mulx(&mut self, inst: &Instruction) -> Result<()> {
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
                let high = (result >> 32) as u64;
                let low = (result & 0xFFFFFFFF) as u64;
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
            _ => return Err(EmulatorError::InvalidInstruction(self.engine.cpu.read_reg(Register::RIP))),
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

    fn execute_pdep(&mut self, inst: &Instruction) -> Result<()> {
        // PDEP: Parallel Bits Deposit
        // Takes bits from source1 and deposits them at bit positions 
        // marked by 1s in source2 (mask)
        // Bits from source1 are taken from LSB to MSB
        // Result bits at positions marked by 0s in mask are cleared
        
        // PDEP has 3 operands: dest, src1, src2 (mask)
        let src1 = self.read_operand(inst, 1)?;
        let mask = self.read_operand(inst, 2)?;
        
        // Get operand size to handle 32-bit vs 64-bit operations
        let size = inst.op0_register().size();
        
        // Mask operands to appropriate size
        let (src1_masked, mask_masked) = match size {
            4 => ((src1 & 0xFFFFFFFF), (mask & 0xFFFFFFFF)),
            8 => (src1, mask),
            _ => return Err(EmulatorError::InvalidInstruction(self.engine.cpu.read_reg(Register::RIP))),
        };
        
        let mut result = 0u64;
        let mut src_bits = src1_masked;
        let mut mask_copy = mask_masked;
        
        // For each bit position in the mask
        while mask_copy != 0 {
            // Find the lowest set bit in the mask
            let bit_pos = mask_copy.trailing_zeros();
            
            // Deposit the next bit from source at this position
            if src_bits & 1 != 0 {
                result |= 1u64 << bit_pos;
            }
            
            // Move to next source bit
            src_bits >>= 1;
            
            // Clear this bit from the mask
            mask_copy &= mask_copy - 1;
        }
        
        // Mask result to appropriate size for 32-bit operations
        if size == 4 {
            result &= 0xFFFFFFFF;
        }
        
        // Write result to destination
        self.write_operand(inst, 0, result)?;
        
        // PDEP does not modify any flags
        
        Ok(())
    }

    fn execute_pext(&mut self, inst: &Instruction) -> Result<()> {
        // PEXT: Parallel Bits Extract
        // Extracts bits from source at positions marked by 1s in mask
        // and packs them into consecutive low bits of result
        // This is the inverse of PDEP
        
        // PEXT has 3 operands: dest, src, mask
        let src = self.read_operand(inst, 1)?;
        let mask = self.read_operand(inst, 2)?;
        
        // Get operand size to handle 32-bit vs 64-bit operations
        let size = inst.op0_register().size();
        
        // Mask operands to appropriate size
        let (src_masked, mask_masked) = match size {
            4 => ((src & 0xFFFFFFFF), (mask & 0xFFFFFFFF)),
            8 => (src, mask),
            _ => return Err(EmulatorError::InvalidInstruction(self.engine.cpu.read_reg(Register::RIP))),
        };
        
        let mut result = 0u64;
        let mut result_bit = 0;
        let mut mask_copy = mask_masked;
        
        // For each set bit in the mask
        while mask_copy != 0 {
            // Find the lowest set bit in the mask
            let bit_pos = mask_copy.trailing_zeros();
            
            // Extract the bit at this position from source
            if (src_masked >> bit_pos) & 1 != 0 {
                result |= 1u64 << result_bit;
            }
            
            // Move to next result bit position
            result_bit += 1;
            
            // Clear this bit from the mask
            mask_copy &= mask_copy - 1;
        }
        
        // Write result to destination
        self.write_operand(inst, 0, result)?;
        
        // PEXT does not modify any flags
        
        Ok(())
    }

    fn execute_rorx(&mut self, inst: &Instruction) -> Result<()> {
        // RORX: Rotate Right Logical Without Affecting Flags
        // Rotates the source operand right by the specified immediate count
        // and stores the result in the destination without modifying flags
        // This is a BMI2 instruction
        
        // RORX has 3 operands: dest, src, imm8
        let src = self.read_operand(inst, 1)?;
        let count = self.read_operand(inst, 2)? as u32;
        
        // Get operand size to determine rotation width
        let size = self.get_operand_size_from_instruction(inst, 0)?;
        
        let result = match size {
            4 => {
                // 32-bit rotation
                let src32 = (src & 0xFFFFFFFF) as u32;
                let rotate_count = count & 0x1F; // Modulo 32
                let result32 = src32.rotate_right(rotate_count);
                result32 as u64
            }
            8 => {
                // 64-bit rotation
                let rotate_count = count & 0x3F; // Modulo 64
                src.rotate_right(rotate_count)
            }
            _ => return Err(EmulatorError::InvalidInstruction(self.engine.cpu.read_reg(Register::RIP))),
        };
        
        // Write result to destination
        self.write_operand(inst, 0, result)?;
        
        // RORX does not modify any flags - this is its key advantage
        
        Ok(())
    }

    fn execute_sarx(&mut self, inst: &Instruction) -> Result<()> {
        // SARX: Shift Arithmetic Right Without Affecting Flags
        // Performs arithmetic right shift (sign-extending) without modifying flags
        // This is a BMI2 instruction
        
        // SARX has 3 operands: dest, src, shift_count
        let src = self.read_operand(inst, 1)?;
        let count = self.read_operand(inst, 2)?;
        
        // Get operand size
        let size = self.get_operand_size_from_instruction(inst, 0)?;
        
        let result = match size {
            4 => {
                // 32-bit arithmetic shift
                let src32 = (src & 0xFFFFFFFF) as i32;
                let shift_count = (count & 0x1F) as u32; // Modulo 32
                let result32 = src32 >> shift_count;
                result32 as u32 as u64
            }
            8 => {
                // 64-bit arithmetic shift
                let src64 = src as i64;
                let shift_count = (count & 0x3F) as u32; // Modulo 64
                (src64 >> shift_count) as u64
            }
            _ => return Err(EmulatorError::InvalidInstruction(self.engine.cpu.read_reg(Register::RIP))),
        };
        
        // Write result to destination
        self.write_operand(inst, 0, result)?;
        
        // SARX does not modify any flags
        
        Ok(())
    }

    fn execute_shlx(&mut self, inst: &Instruction) -> Result<()> {
        // SHLX: Shift Logical Left Without Affecting Flags
        // Performs logical left shift without modifying flags
        // This is a BMI2 instruction
        
        // SHLX has 3 operands: dest, src, shift_count
        let src = self.read_operand(inst, 1)?;
        let count = self.read_operand(inst, 2)?;
        
        // Get operand size
        let size = self.get_operand_size_from_instruction(inst, 0)?;
        
        let result = match size {
            4 => {
                // 32-bit logical shift left
                let src32 = (src & 0xFFFFFFFF) as u32;
                let shift_count = (count & 0x1F) as u32; // Modulo 32
                let result32 = src32 << shift_count;
                result32 as u64
            }
            8 => {
                // 64-bit logical shift left
                let shift_count = (count & 0x3F) as u32; // Modulo 64
                src << shift_count
            }
            _ => return Err(EmulatorError::InvalidInstruction(self.engine.cpu.read_reg(Register::RIP))),
        };
        
        // Write result to destination
        self.write_operand(inst, 0, result)?;
        
        // SHLX does not modify any flags
        
        Ok(())
    }

    fn execute_shrx(&mut self, inst: &Instruction) -> Result<()> {
        // SHRX: Shift Logical Right Without Affecting Flags
        // Performs logical right shift without modifying flags
        // This is a BMI2 instruction
        
        // SHRX has 3 operands: dest, src, shift_count
        let src = self.read_operand(inst, 1)?;
        let count = self.read_operand(inst, 2)?;
        
        // Get operand size
        let size = self.get_operand_size_from_instruction(inst, 0)?;
        
        let result = match size {
            4 => {
                // 32-bit logical shift right
                let src32 = (src & 0xFFFFFFFF) as u32;
                let shift_count = (count & 0x1F) as u32; // Modulo 32
                let result32 = src32 >> shift_count;
                result32 as u64
            }
            8 => {
                // 64-bit logical shift right
                let shift_count = (count & 0x3F) as u32; // Modulo 64
                src >> shift_count
            }
            _ => return Err(EmulatorError::InvalidInstruction(self.engine.cpu.read_reg(Register::RIP))),
        };
        
        // Write result to destination
        self.write_operand(inst, 0, result)?;
        
        // SHRX does not modify any flags
        
        Ok(())
    }

    fn execute_cqo(&mut self, _inst: &Instruction) -> Result<()> {
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

    fn execute_xadd(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_cpuid(&mut self, _inst: &Instruction) -> Result<()> {
        // CPUID: CPU Identification
        // Input: EAX = function number, ECX = sub-function (for some functions)
        // Output: EAX, EBX, ECX, EDX with CPU information

        let function = self.engine.cpu.read_reg(Register::RAX) as u32;
        let sub_function = self.engine.cpu.read_reg(Register::RCX) as u32;

        let (eax, ebx, ecx, edx) = match function {
            // Basic CPUID Information
            0x00 => {
                // Maximum input value for basic CPUID information
                // Vendor ID string: "GenuineIntel" or "AuthenticAMD"
                // For emulation, we'll use a custom vendor "AMDEmu64Rust"
                (
                    0x16,       // Maximum supported standard level
                    0x444d4165, // "eAMD"
                    0x52343665, // "e64R"
                    0x74737565, // "eust"
                )
            }
            // Processor Info and Feature Bits
            0x01 => {
                // EAX: Version Information (Family, Model, Stepping)
                // EBX: Brand Index, CLFLUSH line size, Max IDs, Initial APIC ID
                // ECX: Feature flags
                // EDX: Feature flags
                (
                    0x000906EA,    // Version info
                    0x00040800,    // Brand/Cache info
                    0x7FFAFBBF,    // Feature flags ECX
                    0xBFEBFBFFu32, // Feature flags EDX
                )
            }
            // Cache and TLB Information
            0x02 => {
                // Return zeros for simplicity
                (0, 0, 0, 0)
            }
            // Extended Features
            0x07 if sub_function == 0 => {
                // EAX: Maximum sub-leaves
                // EBX, ECX, EDX: Extended feature flags
                (
                    0,          // Max sub-leaves
                    0x029C6FBB, // Extended features EBX
                    0x00000000, // Extended features ECX
                    0x00000000, // Extended features EDX
                )
            }
            // Extended CPUID Information
            0x80000000 => {
                // Maximum extended function supported
                (0x80000008u32, 0, 0, 0)
            }
            // Extended Processor Info and Feature Bits
            0x80000001 => {
                // Extended feature flags
                (
                    0,          // Reserved
                    0,          // Reserved
                    0x00000121, // Extended feature flags ECX
                    0x2C100800, // Extended feature flags EDX
                )
            }
            // Processor Brand String (Part 1)
            0x80000002 => {
                // "AMD64 Emulator  "
                (0x34444d41, 0x6d452036, 0x74616c75, 0x2020726f)
            }
            // Processor Brand String (Part 2)
            0x80000003 => {
                // "in Pure Rust    "
                (0x50206e69, 0x20657275, 0x74737552, 0x20202020)
            }
            // Processor Brand String (Part 3)
            0x80000004 => {
                // "                "
                (0x20202020, 0x20202020, 0x20202020, 0x20202020)
            }
            _ => {
                // Unknown function, return zeros
                (0, 0, 0, 0)
            }
        };

        // Write results to registers (preserving upper 32 bits)
        let rax = (self.engine.cpu.read_reg(Register::RAX) & 0xFFFFFFFF00000000) | eax as u64;
        let rbx = (self.engine.cpu.read_reg(Register::RBX) & 0xFFFFFFFF00000000) | ebx as u64;
        let rcx = (self.engine.cpu.read_reg(Register::RCX) & 0xFFFFFFFF00000000) | ecx as u64;
        let rdx = (self.engine.cpu.read_reg(Register::RDX) & 0xFFFFFFFF00000000) | edx as u64;

        self.engine.cpu.write_reg(Register::RAX, rax);
        self.engine.cpu.write_reg(Register::RBX, rbx);
        self.engine.cpu.write_reg(Register::RCX, rcx);
        self.engine.cpu.write_reg(Register::RDX, rdx);

        Ok(())
    }

    fn execute_rdtsc(&mut self, _inst: &Instruction) -> Result<()> {
        // RDTSC: Read Time-Stamp Counter
        // Returns the current value of the processor's time-stamp counter in EDX:EAX

        // For emulation purposes, we'll use a simple counter or system time
        // In a real implementation, this would read the actual TSC
        use std::time::{SystemTime, UNIX_EPOCH};

        let tsc = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        // Split into EDX:EAX (high:low 32-bit parts)
        let eax = tsc as u32 as u64;
        let edx = (tsc >> 32) as u32 as u64;

        // Write to registers (preserving upper 32 bits)
        let rax = (self.engine.cpu.read_reg(Register::RAX) & 0xFFFFFFFF00000000) | eax;
        let rdx = (self.engine.cpu.read_reg(Register::RDX) & 0xFFFFFFFF00000000) | edx;

        self.engine.cpu.write_reg(Register::RAX, rax);
        self.engine.cpu.write_reg(Register::RDX, rdx);

        Ok(())
    }

    fn execute_rdtscp(&mut self, _inst: &Instruction) -> Result<()> {
        // RDTSCP: Read Time-Stamp Counter and Processor ID
        // Like RDTSC but also returns processor ID in ECX

        // First do the same as RDTSC
        self.execute_rdtsc(_inst)?;

        // Additionally, set ECX to processor ID (we'll use 0 for simplicity)
        let rcx = self.engine.cpu.read_reg(Register::RCX) & 0xFFFFFFFF00000000;
        self.engine.cpu.write_reg(Register::RCX, rcx);

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

    fn execute_psllw(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_pslld(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_psllq(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_psrlw(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_psrld(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_psrlq(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_psraw(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_psrad(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_packsswb(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_packuswb(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_pmaddwd(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_packssdw(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_punpcklbw(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_punpckhbw(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_punpckhwd(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_punpckldq(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_punpckhdq(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_punpcklqdq(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_punpckhqdq(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_pmovsxbw(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_pmovsxbd(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_pmovsxbq(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_pmovsxwd(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_pmovsxwq(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_pmovsxdq(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_pmovzxbw(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_pmovzxbd(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_pmovzxbq(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_pmovzxwd(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_pmovzxwq(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_pmovzxdq(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_movsw(&mut self, inst: &Instruction) -> Result<()> {
        // MOVSW: Move Word from [RSI] to [RDI]
        let count = if inst.has_rep_prefix() || inst.has_repne_prefix() {
            self.engine.cpu.read_reg(Register::RCX)
        } else {
            1
        };

        let mut remaining = count;
        while remaining > 0 {
            let rsi = self.engine.cpu.read_reg(Register::RSI);
            let rdi = self.engine.cpu.read_reg(Register::RDI);

            // Move word from [RSI] to [RDI]
            let word = self.read_memory_sized(rsi, 2)? as u16;
            self.write_memory_sized(rdi, word as u64, 2)?;

            // Update RSI and RDI
            let df = self.engine.cpu.rflags.contains(Flags::DF);
            let increment = if df { -2i64 as u64 } else { 2 };
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

    fn execute_movsd_string(&mut self, inst: &Instruction) -> Result<()> {
        // MOVSD: Move Doubleword from [RSI] to [RDI] (string operation, not SSE)
        let count = if inst.has_rep_prefix() || inst.has_repne_prefix() {
            self.engine.cpu.read_reg(Register::RCX)
        } else {
            1
        };

        let mut remaining = count;
        while remaining > 0 {
            let rsi = self.engine.cpu.read_reg(Register::RSI);
            let rdi = self.engine.cpu.read_reg(Register::RDI);

            // Move dword from [RSI] to [RDI]
            let dword = self.read_memory_sized(rsi, 4)? as u32;
            self.write_memory_sized(rdi, dword as u64, 4)?;

            // Update RSI and RDI
            let df = self.engine.cpu.rflags.contains(Flags::DF);
            let increment = if df { -4i64 as u64 } else { 4 };
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

    fn execute_movsq(&mut self, inst: &Instruction) -> Result<()> {
        // MOVSQ: Move Quadword from [RSI] to [RDI]
        let count = if inst.has_rep_prefix() || inst.has_repne_prefix() {
            self.engine.cpu.read_reg(Register::RCX)
        } else {
            1
        };

        let mut remaining = count;
        while remaining > 0 {
            let rsi = self.engine.cpu.read_reg(Register::RSI);
            let rdi = self.engine.cpu.read_reg(Register::RDI);

            // Move qword from [RSI] to [RDI]
            let qword = self.read_memory_sized(rsi, 8)?;
            self.write_memory_sized(rdi, qword, 8)?;

            // Update RSI and RDI
            let df = self.engine.cpu.rflags.contains(Flags::DF);
            let increment = if df { -8i64 as u64 } else { 8 };
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

    fn execute_stosw(&mut self, inst: &Instruction) -> Result<()> {
        // STOSW: Store AX to [RDI]
        let count = if inst.has_rep_prefix() || inst.has_repne_prefix() {
            self.engine.cpu.read_reg(Register::RCX)
        } else {
            1
        };

        let ax_value = (self.engine.cpu.read_reg(Register::RAX) & 0xFFFF) as u16;
        let mut remaining = count;

        while remaining > 0 {
            let rdi = self.engine.cpu.read_reg(Register::RDI);

            // Store AX to [RDI]
            self.write_memory_sized(rdi, ax_value as u64, 2)?;

            // Update RDI
            let df = self.engine.cpu.rflags.contains(Flags::DF);
            let increment = if df { -2i64 as u64 } else { 2 };
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

    fn execute_stosd(&mut self, inst: &Instruction) -> Result<()> {
        // STOSD: Store EAX to [RDI]
        let count = if inst.has_rep_prefix() || inst.has_repne_prefix() {
            self.engine.cpu.read_reg(Register::RCX)
        } else {
            1
        };

        let eax_value = (self.engine.cpu.read_reg(Register::RAX) & 0xFFFFFFFF) as u32;
        let mut remaining = count;

        while remaining > 0 {
            let rdi = self.engine.cpu.read_reg(Register::RDI);

            // Store EAX to [RDI]
            self.write_memory_sized(rdi, eax_value as u64, 4)?;

            // Update RDI
            let df = self.engine.cpu.rflags.contains(Flags::DF);
            let increment = if df { -4i64 as u64 } else { 4 };
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

    fn execute_stosq(&mut self, inst: &Instruction) -> Result<()> {
        // STOSQ: Store RAX to [RDI]
        let count = if inst.has_rep_prefix() || inst.has_repne_prefix() {
            self.engine.cpu.read_reg(Register::RCX)
        } else {
            1
        };

        let rax_value = self.engine.cpu.read_reg(Register::RAX);
        let mut remaining = count;

        while remaining > 0 {
            let rdi = self.engine.cpu.read_reg(Register::RDI);

            // Store RAX to [RDI]
            self.write_memory_sized(rdi, rax_value, 8)?;

            // Update RDI
            let df = self.engine.cpu.rflags.contains(Flags::DF);
            let increment = if df { -8i64 as u64 } else { 8 };
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

    fn execute_lodsw(&mut self, inst: &Instruction) -> Result<()> {
        // LODSW: Load word from [RSI] into AX
        let count = if inst.has_rep_prefix() || inst.has_repne_prefix() {
            self.engine.cpu.read_reg(Register::RCX)
        } else {
            1
        };

        let mut remaining = count;

        while remaining > 0 {
            let rsi = self.engine.cpu.read_reg(Register::RSI);

            // Load word from [RSI] into AX
            let word = self.read_memory_sized(rsi, 2)? as u16;
            let rax = self.engine.cpu.read_reg(Register::RAX);
            self.engine
                .cpu
                .write_reg(Register::RAX, (rax & !0xFFFF) | (word as u64));

            // Update RSI
            let df = self.engine.cpu.rflags.contains(Flags::DF);
            let increment = if df { -2i64 as u64 } else { 2 };
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

    fn execute_lodsd(&mut self, inst: &Instruction) -> Result<()> {
        // LODSD: Load doubleword from [RSI] into EAX
        let count = if inst.has_rep_prefix() || inst.has_repne_prefix() {
            self.engine.cpu.read_reg(Register::RCX)
        } else {
            1
        };

        let mut remaining = count;

        while remaining > 0 {
            let rsi = self.engine.cpu.read_reg(Register::RSI);

            // Load dword from [RSI] into EAX
            let dword = self.read_memory_sized(rsi, 4)? as u32;
            let rax = self.engine.cpu.read_reg(Register::RAX);
            self.engine
                .cpu
                .write_reg(Register::RAX, (rax & !0xFFFFFFFF) | (dword as u64));

            // Update RSI
            let df = self.engine.cpu.rflags.contains(Flags::DF);
            let increment = if df { -4i64 as u64 } else { 4 };
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

    fn execute_lodsq(&mut self, inst: &Instruction) -> Result<()> {
        // LODSQ: Load quadword from [RSI] into RAX
        let count = if inst.has_rep_prefix() || inst.has_repne_prefix() {
            self.engine.cpu.read_reg(Register::RCX)
        } else {
            1
        };

        let mut remaining = count;

        while remaining > 0 {
            let rsi = self.engine.cpu.read_reg(Register::RSI);

            // Load qword from [RSI] into RAX
            let qword = self.read_memory_sized(rsi, 8)?;
            self.engine.cpu.write_reg(Register::RAX, qword);

            // Update RSI
            let df = self.engine.cpu.rflags.contains(Flags::DF);
            let increment = if df { -8i64 as u64 } else { 8 };
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

    fn execute_scasw(&mut self, inst: &Instruction) -> Result<()> {
        // SCASW: Scan Word - Compare AX with word at [RDI]
        let ax_value = (self.engine.cpu.read_reg(Register::RAX) & 0xFFFF) as u16;

        if inst.has_repne_prefix() {
            // REPNE SCASW: Repeat while not equal and RCX > 0
            while self.engine.cpu.read_reg(Register::RCX) > 0 {
                let rdi = self.engine.cpu.read_reg(Register::RDI);

                // Compare AX with word at [RDI]
                let word = self.read_memory_sized(rdi, 2)? as u16;

                // Update flags
                self.update_flags_arithmetic_iced(
                    ax_value as u64,
                    word as u64,
                    (ax_value as i32 - word as i32) as u64,
                    true,
                    inst,
                )?;

                // Update RDI
                let df = self.engine.cpu.rflags.contains(Flags::DF);
                let increment = if df { -2i64 as u64 } else { 2 };
                self.engine
                    .cpu
                    .write_reg(Register::RDI, rdi.wrapping_add(increment));

                // Decrement RCX
                let rcx = self.engine.cpu.read_reg(Register::RCX);
                self.engine.cpu.write_reg(Register::RCX, rcx - 1);

                // Check ZF for termination
                if self.engine.cpu.rflags.contains(Flags::ZF) {
                    break;
                }
            }
        } else if inst.has_rep_prefix() {
            // REPE SCASW: Repeat while equal and RCX > 0
            while self.engine.cpu.read_reg(Register::RCX) > 0 {
                let rdi = self.engine.cpu.read_reg(Register::RDI);

                // Compare AX with word at [RDI]
                let word = self.read_memory_sized(rdi, 2)? as u16;

                // Update flags
                self.update_flags_arithmetic_iced(
                    ax_value as u64,
                    word as u64,
                    (ax_value as i32 - word as i32) as u64,
                    true,
                    inst,
                )?;

                // Update RDI
                let df = self.engine.cpu.rflags.contains(Flags::DF);
                let increment = if df { -2i64 as u64 } else { 2 };
                self.engine
                    .cpu
                    .write_reg(Register::RDI, rdi.wrapping_add(increment));

                // Decrement RCX
                let rcx = self.engine.cpu.read_reg(Register::RCX);
                self.engine.cpu.write_reg(Register::RCX, rcx - 1);

                // Check ZF for termination
                if !self.engine.cpu.rflags.contains(Flags::ZF) {
                    break;
                }
            }
        } else {
            // Single SCASW
            let rdi = self.engine.cpu.read_reg(Register::RDI);

            // Compare AX with word at [RDI]
            let word = self.read_memory_sized(rdi, 2)? as u16;

            // Update flags
            self.update_flags_arithmetic_iced(
                ax_value as u64,
                word as u64,
                (ax_value as i32 - word as i32) as u64,
                true,
                inst,
            )?;

            // Update RDI
            let df = self.engine.cpu.rflags.contains(Flags::DF);
            let increment = if df { -2i64 as u64 } else { 2 };
            self.engine
                .cpu
                .write_reg(Register::RDI, rdi.wrapping_add(increment));
        }

        Ok(())
    }

    fn execute_scasd(&mut self, inst: &Instruction) -> Result<()> {
        // SCASD: Scan Doubleword - Compare EAX with dword at [RDI]
        let eax_value = (self.engine.cpu.read_reg(Register::RAX) & 0xFFFFFFFF) as u32;

        if inst.has_repne_prefix() {
            // REPNE SCASD: Repeat while not equal and RCX > 0
            while self.engine.cpu.read_reg(Register::RCX) > 0 {
                let rdi = self.engine.cpu.read_reg(Register::RDI);

                // Compare EAX with dword at [RDI]
                let dword = self.read_memory_sized(rdi, 4)? as u32;

                // Update flags
                self.update_flags_arithmetic_iced(
                    eax_value as u64,
                    dword as u64,
                    (eax_value as i64 - dword as i64) as u64,
                    true,
                    inst,
                )?;

                // Update RDI
                let df = self.engine.cpu.rflags.contains(Flags::DF);
                let increment = if df { -4i64 as u64 } else { 4 };
                self.engine
                    .cpu
                    .write_reg(Register::RDI, rdi.wrapping_add(increment));

                // Decrement RCX
                let rcx = self.engine.cpu.read_reg(Register::RCX);
                self.engine.cpu.write_reg(Register::RCX, rcx - 1);

                // Check ZF for termination
                if self.engine.cpu.rflags.contains(Flags::ZF) {
                    break;
                }
            }
        } else if inst.has_rep_prefix() {
            // REPE SCASD: Repeat while equal and RCX > 0
            while self.engine.cpu.read_reg(Register::RCX) > 0 {
                let rdi = self.engine.cpu.read_reg(Register::RDI);

                // Compare EAX with dword at [RDI]
                let dword = self.read_memory_sized(rdi, 4)? as u32;

                // Update flags
                self.update_flags_arithmetic_iced(
                    eax_value as u64,
                    dword as u64,
                    (eax_value as i64 - dword as i64) as u64,
                    true,
                    inst,
                )?;

                // Update RDI
                let df = self.engine.cpu.rflags.contains(Flags::DF);
                let increment = if df { -4i64 as u64 } else { 4 };
                self.engine
                    .cpu
                    .write_reg(Register::RDI, rdi.wrapping_add(increment));

                // Decrement RCX
                let rcx = self.engine.cpu.read_reg(Register::RCX);
                self.engine.cpu.write_reg(Register::RCX, rcx - 1);

                // Check ZF for termination
                if !self.engine.cpu.rflags.contains(Flags::ZF) {
                    break;
                }
            }
        } else {
            // Single SCASD
            let rdi = self.engine.cpu.read_reg(Register::RDI);

            // Compare EAX with dword at [RDI]
            let dword = self.read_memory_sized(rdi, 4)? as u32;

            // Update flags
            self.update_flags_arithmetic_iced(
                eax_value as u64,
                dword as u64,
                (eax_value as i64 - dword as i64) as u64,
                true,
                inst,
            )?;

            // Update RDI
            let df = self.engine.cpu.rflags.contains(Flags::DF);
            let increment = if df { -4i64 as u64 } else { 4 };
            self.engine
                .cpu
                .write_reg(Register::RDI, rdi.wrapping_add(increment));
        }

        Ok(())
    }

    fn execute_scasq(&mut self, inst: &Instruction) -> Result<()> {
        // SCASQ: Scan Quadword - Compare RAX with qword at [RDI]
        let rax_value = self.engine.cpu.read_reg(Register::RAX);

        if inst.has_repne_prefix() {
            // REPNE SCASQ: Repeat while not equal and RCX > 0
            while self.engine.cpu.read_reg(Register::RCX) > 0 {
                let rdi = self.engine.cpu.read_reg(Register::RDI);

                // Compare RAX with qword at [RDI]
                let qword = self.read_memory_sized(rdi, 8)?;

                // Update flags
                self.update_flags_arithmetic_iced(
                    rax_value,
                    qword,
                    rax_value.wrapping_sub(qword),
                    true,
                    inst,
                )?;

                // Update RDI
                let df = self.engine.cpu.rflags.contains(Flags::DF);
                let increment = if df { -8i64 as u64 } else { 8 };
                self.engine
                    .cpu
                    .write_reg(Register::RDI, rdi.wrapping_add(increment));

                // Decrement RCX
                let rcx = self.engine.cpu.read_reg(Register::RCX);
                self.engine.cpu.write_reg(Register::RCX, rcx - 1);

                // Check ZF for termination
                if self.engine.cpu.rflags.contains(Flags::ZF) {
                    break;
                }
            }
        } else if inst.has_rep_prefix() {
            // REPE SCASQ: Repeat while equal and RCX > 0
            while self.engine.cpu.read_reg(Register::RCX) > 0 {
                let rdi = self.engine.cpu.read_reg(Register::RDI);

                // Compare RAX with qword at [RDI]
                let qword = self.read_memory_sized(rdi, 8)?;

                // Update flags
                self.update_flags_arithmetic_iced(
                    rax_value,
                    qword,
                    rax_value.wrapping_sub(qword),
                    true,
                    inst,
                )?;

                // Update RDI
                let df = self.engine.cpu.rflags.contains(Flags::DF);
                let increment = if df { -8i64 as u64 } else { 8 };
                self.engine
                    .cpu
                    .write_reg(Register::RDI, rdi.wrapping_add(increment));

                // Decrement RCX
                let rcx = self.engine.cpu.read_reg(Register::RCX);
                self.engine.cpu.write_reg(Register::RCX, rcx - 1);

                // Check ZF for termination
                if !self.engine.cpu.rflags.contains(Flags::ZF) {
                    break;
                }
            }
        } else {
            // Single SCASQ
            let rdi = self.engine.cpu.read_reg(Register::RDI);

            // Compare RAX with qword at [RDI]
            let qword = self.read_memory_sized(rdi, 8)?;

            // Update flags
            self.update_flags_arithmetic_iced(
                rax_value,
                qword,
                rax_value.wrapping_sub(qword),
                true,
                inst,
            )?;

            // Update RDI
            let df = self.engine.cpu.rflags.contains(Flags::DF);
            let increment = if df { -8i64 as u64 } else { 8 };
            self.engine
                .cpu
                .write_reg(Register::RDI, rdi.wrapping_add(increment));
        }

        Ok(())
    }

    fn execute_cmpsw(&mut self, inst: &Instruction) -> Result<()> {
        // CMPSW: Compare words at [RSI] and [RDI]
        if inst.has_repne_prefix() {
            // REPNE CMPSW: Repeat while not equal and RCX > 0
            while self.engine.cpu.read_reg(Register::RCX) > 0 {
                let rsi = self.engine.cpu.read_reg(Register::RSI);
                let rdi = self.engine.cpu.read_reg(Register::RDI);

                // Compare words
                let word1 = self.read_memory_sized(rsi, 2)? as u16;
                let word2 = self.read_memory_sized(rdi, 2)? as u16;

                // Update flags
                self.update_flags_arithmetic_iced(
                    word1 as u64,
                    word2 as u64,
                    (word1 as i32 - word2 as i32) as u64,
                    true,
                    inst,
                )?;

                // Update RSI and RDI
                let df = self.engine.cpu.rflags.contains(Flags::DF);
                let increment = if df { -2i64 as u64 } else { 2 };
                self.engine
                    .cpu
                    .write_reg(Register::RSI, rsi.wrapping_add(increment));
                self.engine
                    .cpu
                    .write_reg(Register::RDI, rdi.wrapping_add(increment));

                // Decrement RCX
                let rcx = self.engine.cpu.read_reg(Register::RCX);
                self.engine.cpu.write_reg(Register::RCX, rcx - 1);

                // Check ZF for termination
                if self.engine.cpu.rflags.contains(Flags::ZF) {
                    break;
                }
            }
        } else if inst.has_rep_prefix() {
            // REPE CMPSW: Repeat while equal and RCX > 0
            while self.engine.cpu.read_reg(Register::RCX) > 0 {
                let rsi = self.engine.cpu.read_reg(Register::RSI);
                let rdi = self.engine.cpu.read_reg(Register::RDI);

                // Compare words
                let word1 = self.read_memory_sized(rsi, 2)? as u16;
                let word2 = self.read_memory_sized(rdi, 2)? as u16;

                // Update flags
                self.update_flags_arithmetic_iced(
                    word1 as u64,
                    word2 as u64,
                    (word1 as i32 - word2 as i32) as u64,
                    true,
                    inst,
                )?;

                // Update RSI and RDI
                let df = self.engine.cpu.rflags.contains(Flags::DF);
                let increment = if df { -2i64 as u64 } else { 2 };
                self.engine
                    .cpu
                    .write_reg(Register::RSI, rsi.wrapping_add(increment));
                self.engine
                    .cpu
                    .write_reg(Register::RDI, rdi.wrapping_add(increment));

                // Decrement RCX
                let rcx = self.engine.cpu.read_reg(Register::RCX);
                self.engine.cpu.write_reg(Register::RCX, rcx - 1);

                // Check ZF for termination
                if !self.engine.cpu.rflags.contains(Flags::ZF) {
                    break;
                }
            }
        } else {
            // Single CMPSW
            let rsi = self.engine.cpu.read_reg(Register::RSI);
            let rdi = self.engine.cpu.read_reg(Register::RDI);

            // Compare words
            let word1 = self.read_memory_sized(rsi, 2)? as u16;
            let word2 = self.read_memory_sized(rdi, 2)? as u16;

            // Update flags
            self.update_flags_arithmetic_iced(
                word1 as u64,
                word2 as u64,
                (word1 as i32 - word2 as i32) as u64,
                true,
                inst,
            )?;

            // Update RSI and RDI
            let df = self.engine.cpu.rflags.contains(Flags::DF);
            let increment = if df { -2i64 as u64 } else { 2 };
            self.engine
                .cpu
                .write_reg(Register::RSI, rsi.wrapping_add(increment));
            self.engine
                .cpu
                .write_reg(Register::RDI, rdi.wrapping_add(increment));
        }

        Ok(())
    }

    fn execute_cmpsd_string(&mut self, inst: &Instruction) -> Result<()> {
        // CMPSD: Compare doublewords at [RSI] and [RDI] (string operation, not SSE)
        if inst.has_repne_prefix() {
            // REPNE CMPSD: Repeat while not equal and RCX > 0
            while self.engine.cpu.read_reg(Register::RCX) > 0 {
                let rsi = self.engine.cpu.read_reg(Register::RSI);
                let rdi = self.engine.cpu.read_reg(Register::RDI);

                // Compare dwords
                let dword1 = self.read_memory_sized(rsi, 4)? as u32;
                let dword2 = self.read_memory_sized(rdi, 4)? as u32;

                // Update flags
                self.update_flags_arithmetic_iced(
                    dword1 as u64,
                    dword2 as u64,
                    (dword1 as i64 - dword2 as i64) as u64,
                    true,
                    inst,
                )?;

                // Update RSI and RDI
                let df = self.engine.cpu.rflags.contains(Flags::DF);
                let increment = if df { -4i64 as u64 } else { 4 };
                self.engine
                    .cpu
                    .write_reg(Register::RSI, rsi.wrapping_add(increment));
                self.engine
                    .cpu
                    .write_reg(Register::RDI, rdi.wrapping_add(increment));

                // Decrement RCX
                let rcx = self.engine.cpu.read_reg(Register::RCX);
                self.engine.cpu.write_reg(Register::RCX, rcx - 1);

                // Check ZF for termination
                if self.engine.cpu.rflags.contains(Flags::ZF) {
                    break;
                }
            }
        } else if inst.has_rep_prefix() {
            // REPE CMPSD: Repeat while equal and RCX > 0
            while self.engine.cpu.read_reg(Register::RCX) > 0 {
                let rsi = self.engine.cpu.read_reg(Register::RSI);
                let rdi = self.engine.cpu.read_reg(Register::RDI);

                // Compare dwords
                let dword1 = self.read_memory_sized(rsi, 4)? as u32;
                let dword2 = self.read_memory_sized(rdi, 4)? as u32;

                // Update flags
                self.update_flags_arithmetic_iced(
                    dword1 as u64,
                    dword2 as u64,
                    (dword1 as i64 - dword2 as i64) as u64,
                    true,
                    inst,
                )?;

                // Update RSI and RDI
                let df = self.engine.cpu.rflags.contains(Flags::DF);
                let increment = if df { -4i64 as u64 } else { 4 };
                self.engine
                    .cpu
                    .write_reg(Register::RSI, rsi.wrapping_add(increment));
                self.engine
                    .cpu
                    .write_reg(Register::RDI, rdi.wrapping_add(increment));

                // Decrement RCX
                let rcx = self.engine.cpu.read_reg(Register::RCX);
                self.engine.cpu.write_reg(Register::RCX, rcx - 1);

                // Check ZF for termination
                if !self.engine.cpu.rflags.contains(Flags::ZF) {
                    break;
                }
            }
        } else {
            // Single CMPSD
            let rsi = self.engine.cpu.read_reg(Register::RSI);
            let rdi = self.engine.cpu.read_reg(Register::RDI);

            // Compare dwords
            let dword1 = self.read_memory_sized(rsi, 4)? as u32;
            let dword2 = self.read_memory_sized(rdi, 4)? as u32;

            // Update flags
            self.update_flags_arithmetic_iced(
                dword1 as u64,
                dword2 as u64,
                (dword1 as i64 - dword2 as i64) as u64,
                true,
                inst,
            )?;

            // Update RSI and RDI
            let df = self.engine.cpu.rflags.contains(Flags::DF);
            let increment = if df { -4i64 as u64 } else { 4 };
            self.engine
                .cpu
                .write_reg(Register::RSI, rsi.wrapping_add(increment));
            self.engine
                .cpu
                .write_reg(Register::RDI, rdi.wrapping_add(increment));
        }

        Ok(())
    }

    fn execute_cmpsq(&mut self, inst: &Instruction) -> Result<()> {
        // CMPSQ: Compare quadwords at [RSI] and [RDI]
        if inst.has_repne_prefix() {
            // REPNE CMPSQ: Repeat while not equal and RCX > 0
            while self.engine.cpu.read_reg(Register::RCX) > 0 {
                let rsi = self.engine.cpu.read_reg(Register::RSI);
                let rdi = self.engine.cpu.read_reg(Register::RDI);

                // Compare qwords
                let qword1 = self.read_memory_sized(rsi, 8)?;
                let qword2 = self.read_memory_sized(rdi, 8)?;

                // Update flags
                self.update_flags_arithmetic_iced(
                    qword1,
                    qword2,
                    qword1.wrapping_sub(qword2),
                    true,
                    inst,
                )?;

                // Update RSI and RDI
                let df = self.engine.cpu.rflags.contains(Flags::DF);
                let increment = if df { -8i64 as u64 } else { 8 };
                self.engine
                    .cpu
                    .write_reg(Register::RSI, rsi.wrapping_add(increment));
                self.engine
                    .cpu
                    .write_reg(Register::RDI, rdi.wrapping_add(increment));

                // Decrement RCX
                let rcx = self.engine.cpu.read_reg(Register::RCX);
                self.engine.cpu.write_reg(Register::RCX, rcx - 1);

                // Check ZF for termination
                if self.engine.cpu.rflags.contains(Flags::ZF) {
                    break;
                }
            }
        } else if inst.has_rep_prefix() {
            // REPE CMPSQ: Repeat while equal and RCX > 0
            while self.engine.cpu.read_reg(Register::RCX) > 0 {
                let rsi = self.engine.cpu.read_reg(Register::RSI);
                let rdi = self.engine.cpu.read_reg(Register::RDI);

                // Compare qwords
                let qword1 = self.read_memory_sized(rsi, 8)?;
                let qword2 = self.read_memory_sized(rdi, 8)?;

                // Update flags
                self.update_flags_arithmetic_iced(
                    qword1,
                    qword2,
                    qword1.wrapping_sub(qword2),
                    true,
                    inst,
                )?;

                // Update RSI and RDI
                let df = self.engine.cpu.rflags.contains(Flags::DF);
                let increment = if df { -8i64 as u64 } else { 8 };
                self.engine
                    .cpu
                    .write_reg(Register::RSI, rsi.wrapping_add(increment));
                self.engine
                    .cpu
                    .write_reg(Register::RDI, rdi.wrapping_add(increment));

                // Decrement RCX
                let rcx = self.engine.cpu.read_reg(Register::RCX);
                self.engine.cpu.write_reg(Register::RCX, rcx - 1);

                // Check ZF for termination
                if !self.engine.cpu.rflags.contains(Flags::ZF) {
                    break;
                }
            }
        } else {
            // Single CMPSQ
            let rsi = self.engine.cpu.read_reg(Register::RSI);
            let rdi = self.engine.cpu.read_reg(Register::RDI);

            // Compare qwords
            let qword1 = self.read_memory_sized(rsi, 8)?;
            let qword2 = self.read_memory_sized(rdi, 8)?;

            // Update flags
            self.update_flags_arithmetic_iced(
                qword1,
                qword2,
                qword1.wrapping_sub(qword2),
                true,
                inst,
            )?;

            // Update RSI and RDI
            let df = self.engine.cpu.rflags.contains(Flags::DF);
            let increment = if df { -8i64 as u64 } else { 8 };
            self.engine
                .cpu
                .write_reg(Register::RSI, rsi.wrapping_add(increment));
            self.engine
                .cpu
                .write_reg(Register::RDI, rdi.wrapping_add(increment));
        }

        Ok(())
    }

    fn execute_bswap(&mut self, inst: &Instruction) -> Result<()> {
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

    fn execute_cld(&mut self, _inst: &Instruction) -> Result<()> {
        // CLD: Clear Direction Flag
        self.engine.cpu.rflags.remove(Flags::DF);
        Ok(())
    }

    fn execute_std(&mut self, _inst: &Instruction) -> Result<()> {
        // STD: Set Direction Flag
        self.engine.cpu.rflags.insert(Flags::DF);
        Ok(())
    }

    fn execute_int(&mut self, inst: &Instruction) -> Result<()> {
        // INT: Software Interrupt
        let intno = self.read_operand(inst, 0)?;
        
        // Call interrupt hook
        self.hooks.on_interrupt(self.engine, intno, inst.len() as usize)?;
        
        // In a real system, this would trigger an interrupt handler
        // For emulation, we just call the hook and continue
        // The hook implementation can decide what to do (e.g., emulate syscalls)
        
        Ok(())
    }

    fn execute_int3(&mut self, inst: &Instruction) -> Result<()> {
        // INT3: Breakpoint (single-byte INT 3)
        // Call interrupt hook with interrupt number 3
        self.hooks.on_interrupt(self.engine, 3, inst.len() as usize)?;
        
        // INT3 is typically used for debugging breakpoints
        // The debugger/hook can decide how to handle it
        
        Ok(())
    }

    fn execute_syscall(&mut self, inst: &Instruction) -> Result<()> {
        // SYSCALL: Fast System Call
        // In x86-64, SYSCALL is used for system calls instead of INT 0x80
        
        // Save return address (next instruction) in RCX
        let return_addr = inst.next_ip();
        self.engine.cpu.write_reg(Register::RCX, return_addr);
        
        // Save RFLAGS in R11 (masked according to IA32_FMASK MSR, but we'll save all for simplicity)
        let rflags = self.engine.cpu.rflags.bits();
        self.engine.cpu.write_reg(Register::R11, rflags);
        
        // The syscall number is typically in RAX, parameters in RDI, RSI, RDX, R10, R8, R9
        // Call the interrupt hook with a special interrupt number for SYSCALL (e.g., 0x80 for Linux compatibility)
        // The actual syscall number is in RAX, so the hook can read it from there
        self.hooks.on_interrupt(self.engine, 0x80, inst.len() as usize)?;
        
        // Note: The actual kernel entry point would be loaded from MSR registers
        // For emulation purposes, the hook handles the syscall and we continue
        
        Ok(())
    }

    fn execute_mfence(&mut self, _inst: &Instruction) -> Result<()> {
        // MFENCE: Memory Fence
        // Serializes all load and store operations that occurred prior to the MFENCE instruction
        // In emulation, this is essentially a no-op since we're single-threaded
        // But for completeness, we could flush any pending memory operations here
        
        // In a real CPU, this ensures:
        // - All loads and stores before the fence are globally visible before any after
        // - Used for strong memory ordering guarantees
        
        Ok(())
    }

    fn execute_sfence(&mut self, _inst: &Instruction) -> Result<()> {
        // SFENCE: Store Fence
        // Serializes all store operations that occurred prior to the SFENCE instruction
        // Stores before SFENCE are guaranteed to be globally visible before stores after
        
        // In emulation, this is a no-op since we execute instructions sequentially
        // In real hardware, ensures store ordering for weakly-ordered memory types
        
        Ok(())
    }

    fn execute_lfence(&mut self, _inst: &Instruction) -> Result<()> {
        // LFENCE: Load Fence  
        // Serializes all load operations that occurred prior to the LFENCE instruction
        // Loads before LFENCE are guaranteed to be globally visible before loads after
        
        // In emulation, this is a no-op since we execute instructions sequentially
        // In real hardware, ensures load ordering and can prevent speculative execution
        
        Ok(())
    }
    
    fn execute_clflush(&mut self, inst: &Instruction) -> Result<()> {
        // CLFLUSH: Cache Line Flush
        // Flushes the cache line containing the linear address from all levels of the processor cache hierarchy
        // CLFLUSHOPT is an optimized version but functionally the same for emulation
        
        // In real hardware, this instruction:
        // 1. Invalidates the cache line from all processor caches
        // 2. Writes back modified data to memory if the cache line is dirty
        // 3. Does not affect the TLBs
        
        // Get the memory address to flush
        // CLFLUSH takes a memory operand (m8)
        if inst.op_count() != 1 {
            return Err(EmulatorError::InvalidArgument("CLFLUSH requires exactly one operand".to_string()));
        }
        
        // Calculate the effective address
        let _address = match inst.op_kind(0) {
            OpKind::Memory => {
                // Calculate effective address from memory operand
                let mut addr;
                if inst.memory_base() == IcedRegister::RIP {
                    // RIP-relative addressing
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
                        let index_value = self.engine.cpu.read_reg(index_reg);
                        let scale = inst.memory_index_scale() as u64;
                        addr = addr.wrapping_add(index_value.wrapping_mul(scale));
                    }
                }
                addr
            }
            _ => return Err(EmulatorError::InvalidOperand),
        };
        
        // In emulation, we don't have actual CPU caches to flush
        // This is effectively a no-op for correctness of execution
        // Real implementations would interact with the cache subsystem here
        
        // CLFLUSH does not affect RFLAGS
        Ok(())
    }
}
