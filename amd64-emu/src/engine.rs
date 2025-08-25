use crate::cpu::{CpuState, Flags, Register};
use crate::decoder::{Decoder, DecoderMode, Instruction, Opcode, Operand, OperandSize};
use crate::error::{EmulatorError, Result};
use crate::hooks::HookManager;
use crate::memory::{Memory, Permission};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

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
    _mode: EngineMode,
    stop_requested: Arc<AtomicBool>,
    instruction_count: u64,
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
            _mode: mode,
            stop_requested: Arc::new(AtomicBool::new(false)),
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

    pub fn emu_stop(&mut self) -> Result<()> {
        self.stop_requested.store(true, Ordering::SeqCst);
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

        let inst = self.decoder.decode(&inst_bytes, rip)?;

        if let Some(hooks) = hooks.as_deref_mut() {
            hooks.on_code(self, rip, inst.size)?;
        }

        self.cpu.rip = rip + inst.size as u64;

        ExecutionContext {
            engine: self,
            hooks: hooks,
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

    fn mem_read_u8(&mut self, address: u64) -> Result<u8> {
        let mut buf = [0u8; 1];
        self.mem_read_with_hooks(address, &mut buf)?;
        Ok(buf[0])
    }

    fn mem_read_u16(&mut self, address: u64) -> Result<u16> {
        let mut buf = [0u8; 2];
        self.mem_read_with_hooks(address, &mut buf)?;
        Ok(u16::from_le_bytes(buf))
    }

    fn mem_read_u32(&mut self, address: u64) -> Result<u32> {
        let mut buf = [0u8; 4];
        self.mem_read_with_hooks(address, &mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn mem_read_u64(&mut self, address: u64) -> Result<u64> {
        let mut buf = [0u8; 8];
        self.mem_read_with_hooks(address, &mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    fn mem_write_u8(&mut self, address: u64, value: u8) -> Result<()> {
        let buf = [value];
        self.mem_write_with_hooks(address, &buf)
    }

    fn mem_write_u16(&mut self, address: u64, value: u16) -> Result<()> {
        let buf = value.to_le_bytes();
        self.mem_write_with_hooks(address, &buf)
    }

    fn mem_write_u32(&mut self, address: u64, value: u32) -> Result<()> {
        let buf = value.to_le_bytes();
        self.mem_write_with_hooks(address, &buf)
    }

    fn mem_write_u64(&mut self, address: u64, value: u64) -> Result<()> {
        let buf = value.to_le_bytes();
        self.mem_write_with_hooks(address, &buf)
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
            Opcode::JZ => self.execute_jcc(inst, self.engine.cpu.rflags.contains(Flags::ZF)),
            Opcode::JNZ => self.execute_jcc(inst, !self.engine.cpu.rflags.contains(Flags::ZF)),
            Opcode::JS => self.execute_jcc(inst, self.engine.cpu.rflags.contains(Flags::SF)),
            Opcode::JNS => self.execute_jcc(inst, !self.engine.cpu.rflags.contains(Flags::SF)),
            Opcode::JO => self.execute_jcc(inst, self.engine.cpu.rflags.contains(Flags::OF)),
            Opcode::JNO => self.execute_jcc(inst, !self.engine.cpu.rflags.contains(Flags::OF)),
            Opcode::JB => self.execute_jcc(inst, self.engine.cpu.rflags.contains(Flags::CF)),
            Opcode::JAE => self.execute_jcc(inst, !self.engine.cpu.rflags.contains(Flags::CF)),
            Opcode::JBE => self.execute_jcc(
                inst,
                self.engine.cpu.rflags.contains(Flags::CF)
                    || self.engine.cpu.rflags.contains(Flags::ZF),
            ),
            Opcode::JA => self.execute_jcc(
                inst,
                !self.engine.cpu.rflags.contains(Flags::CF)
                    && !self.engine.cpu.rflags.contains(Flags::ZF),
            ),
            Opcode::JL => self.execute_jcc(inst, {
                let sf = self.engine.cpu.rflags.contains(Flags::SF);
                let of = self.engine.cpu.rflags.contains(Flags::OF);
                sf != of
            }),
            Opcode::JGE => self.execute_jcc(inst, {
                let sf = self.engine.cpu.rflags.contains(Flags::SF);
                let of = self.engine.cpu.rflags.contains(Flags::OF);
                sf == of
            }),
            Opcode::JLE => self.execute_jcc(inst, {
                let sf = self.engine.cpu.rflags.contains(Flags::SF);
                let of = self.engine.cpu.rflags.contains(Flags::OF);
                let zf = self.engine.cpu.rflags.contains(Flags::ZF);
                zf || (sf != of)
            }),
            Opcode::JG => self.execute_jcc(inst, {
                let sf = self.engine.cpu.rflags.contains(Flags::SF);
                let of = self.engine.cpu.rflags.contains(Flags::OF);
                let zf = self.engine.cpu.rflags.contains(Flags::ZF);
                !zf && (sf == of)
            }),
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
                self.engine.stop_requested.store(true, Ordering::SeqCst);
                Ok(())
            }
            Opcode::SYSCALL => self.execute_syscall(inst),
            Opcode::MOVAPS => self.execute_movaps(inst),
            Opcode::MOVUPS => self.execute_movups(inst),
            Opcode::MOVQ => self.execute_movq(inst),
            Opcode::MOVLHPS => self.execute_movlhps(inst),
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
            Opcode::CDQ => self.execute_cdq(inst),
            Opcode::MOVSXD => self.execute_movsxd(inst),
            Opcode::MOVZX => self.execute_movzx(inst),
            Opcode::SETBE => self.execute_setbe(inst),
            Opcode::SETNE => self.execute_setne(inst),
            Opcode::CMOVAE => self.execute_cmovae(inst),
            Opcode::CMOVB => self.execute_cmovb(inst),
            Opcode::CMOVBE => self.execute_cmovbe(inst),
            Opcode::CMOVE => self.execute_cmove(inst),
            Opcode::CMOVG => self.execute_cmovg(inst),
            Opcode::CMOVNE => self.execute_cmovne(inst),
            Opcode::RDTSC => self.execute_rdtsc(inst),
            Opcode::MONITORX => self.execute_monitorx(inst),
            Opcode::PREFETCHW => self.execute_prefetchw(inst),
            Opcode::CMPXCHG => self.execute_cmpxchg(inst),
            Opcode::BT => self.execute_bt(inst),
            Opcode::BTS => self.execute_bts(inst),
            Opcode::BTR => self.execute_btr(inst),
            Opcode::BTC => self.execute_btc(inst),
            Opcode::VINSERTF128 => self.execute_vinsertf128(inst),
            Opcode::VZEROUPPER => self.execute_vzeroupper(inst),
            Opcode::MOVDQA => self.execute_movdqa(inst),
            Opcode::BSR => self.execute_bsr(inst),
            _ => {
                if let Some(hooks) = &mut self.hooks {
                    hooks.on_invalid(self.engine, inst.address, 0)?;
                }
                Err(EmulatorError::UnsupportedInstruction(format!(
                    "{:?}",
                    inst.opcode
                )))
            }
        }
    }

    fn execute_mov(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        let value = self.read_operand(&inst.operands[1], inst)?;
        self.write_operand(&inst.operands[0], value, inst)?;
        Ok(())
    }

    fn execute_add(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        let dst = self.read_operand(&inst.operands[0], inst)?;
        let src = self.read_operand(&inst.operands[1], inst)?;

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
        self.write_operand(&inst.operands[0], result, inst)?;
        Ok(())
    }

    fn execute_sub(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        let dst = self.read_operand(&inst.operands[0], inst)?;
        let src = self.read_operand(&inst.operands[1], inst)?;

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
        self.write_operand(&inst.operands[0], result, inst)?;
        Ok(())
    }

    fn execute_adc(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        let dst = self.read_operand(&inst.operands[0], inst)?;
        let src = self.read_operand(&inst.operands[1], inst)?;
        let carry = if self.engine.cpu.rflags.contains(Flags::CF) {
            1
        } else {
            0
        };

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

        self.engine.cpu.rflags.set(Flags::CF, carry_out);
        self.engine.cpu.rflags.set(Flags::ZF, result_masked == 0);
        self.engine
            .cpu
            .rflags
            .set(Flags::SF, (result_masked & sign_bit) != 0);

        // Overflow flag
        let dst_sign = (dst_masked & sign_bit) != 0;
        let src_sign = (src_masked & sign_bit) != 0;
        let res_sign = (result_masked & sign_bit) != 0;
        self.engine
            .cpu
            .rflags
            .set(Flags::OF, dst_sign == src_sign && dst_sign != res_sign);

        // Parity flag
        let parity = (result_masked as u8).count_ones().is_multiple_of(2);
        self.engine.cpu.rflags.set(Flags::PF, parity);

        self.write_operand(&inst.operands[0], result, inst)?;
        Ok(())
    }

    fn execute_sbb(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        let dst = self.read_operand(&inst.operands[0], inst)?;
        let src = self.read_operand(&inst.operands[1], inst)?;
        let borrow = if self.engine.cpu.rflags.contains(Flags::CF) {
            1
        } else {
            0
        };

        // Subtract with borrow: dst - src - CF
        let result = dst.wrapping_sub(src).wrapping_sub(borrow);

        // Update flags - need to check both subtractions for borrow
        let intermediate = dst.wrapping_sub(src);
        let borrow_out = (dst < src) || (intermediate < borrow);

        self.engine.cpu.rflags.set(Flags::CF, borrow_out);
        self.engine.cpu.rflags.set(Flags::ZF, result == 0);
        self.engine.cpu.rflags.set(Flags::SF, (result as i64) < 0);

        // Overflow flag: sign change when subtracting values of different sign
        let dst_sign = (dst as i64) < 0;
        let src_sign = (src as i64) < 0;
        let result_sign = (result as i64) < 0;
        let overflow = (dst_sign != src_sign) && (dst_sign != result_sign);
        self.engine.cpu.rflags.set(Flags::OF, overflow);

        // Parity flag
        let parity = (result as u8).count_ones().is_multiple_of(2);
        self.engine.cpu.rflags.set(Flags::PF, parity);

        self.write_operand(&inst.operands[0], result, inst)?;
        Ok(())
    }

    fn execute_xor(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        let dst = self.read_operand(&inst.operands[0], inst)?;
        let src = self.read_operand(&inst.operands[1], inst)?;
        let result = dst ^ src;

        self.update_flags_logical(result);
        self.write_operand(&inst.operands[0], result, inst)?;
        Ok(())
    }

    fn execute_and(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        let dst = self.read_operand(&inst.operands[0], inst)?;
        let src = self.read_operand(&inst.operands[1], inst)?;
        let result = dst & src;

        self.update_flags_logical(result);
        self.write_operand(&inst.operands[0], result, inst)?;
        Ok(())
    }

    fn execute_or(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        let dst = self.read_operand(&inst.operands[0], inst)?;
        let src = self.read_operand(&inst.operands[1], inst)?;
        let result = dst | src;

        self.update_flags_logical(result);
        self.write_operand(&inst.operands[0], result, inst)?;
        Ok(())
    }

    fn execute_cmp(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        let dst = self.read_operand(&inst.operands[0], inst)?;
        let src = self.read_operand(&inst.operands[1], inst)?;
        let result = dst.wrapping_sub(src);

        self.update_flags_arithmetic(dst, src, result, true);
        Ok(())
    }

    fn execute_test(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        let dst = self.read_operand(&inst.operands[0], inst)?;
        let src = self.read_operand(&inst.operands[1], inst)?;
        let result = dst & src;

        self.update_flags_logical(result);
        Ok(())
    }

    fn execute_inc(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.is_empty() {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        let value = self.read_operand(&inst.operands[0], inst)?;
        let result = value.wrapping_add(1);

        // INC doesn't affect CF flag, only other arithmetic flags
        let cf = self.engine.cpu.rflags.contains(Flags::CF);
        self.update_flags_arithmetic(value, 1, result, false);
        self.engine.cpu.rflags.set(Flags::CF, cf);

        self.write_operand(&inst.operands[0], result, inst)?;
        Ok(())
    }

    fn execute_dec(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.is_empty() {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        let value = self.read_operand(&inst.operands[0], inst)?;
        let result = value.wrapping_sub(1);

        // DEC doesn't affect CF flag, only other arithmetic flags
        let cf = self.engine.cpu.rflags.contains(Flags::CF);
        self.update_flags_arithmetic(value, 1, result, true);
        self.engine.cpu.rflags.set(Flags::CF, cf);

        self.write_operand(&inst.operands[0], result, inst)?;
        Ok(())
    }

    fn execute_neg(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.is_empty() {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        let value = self.read_operand(&inst.operands[0], inst)?;
        let result = 0u64.wrapping_sub(value);

        // NEG sets CF to 0 if operand is 0, otherwise 1
        self.engine.cpu.rflags.set(Flags::CF, value != 0);

        // Update other arithmetic flags
        self.update_flags_arithmetic(0, value, result, true);

        self.write_operand(&inst.operands[0], result, inst)?;
        Ok(())
    }

    fn execute_not(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.is_empty() {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        let value = self.read_operand(&inst.operands[0], inst)?;
        let result = !value;

        // NOT doesn't affect any flags

        self.write_operand(&inst.operands[0], result, inst)?;
        Ok(())
    }

    fn execute_shl(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() < 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        let value = self.read_operand(&inst.operands[0], inst)?;
        let count = (self.read_operand(&inst.operands[1], inst)? & 0x3F) as u32; // Mask to 6 bits for 64-bit mode

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
        self.engine.cpu.rflags.set(Flags::CF, last_bit_out);

        // OF is set if the sign bit changed (only for count == 1)
        if count == 1 {
            let sign_changed = ((value >> 63) & 1) != ((result >> 63) & 1);
            self.engine.cpu.rflags.set(Flags::OF, sign_changed);
        }

        // Update SF, ZF, PF based on result
        self.update_flags_logical(result);

        self.write_operand(&inst.operands[0], result, inst)?;
        Ok(())
    }

    fn execute_shr(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() < 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        let value = self.read_operand(&inst.operands[0], inst)?;
        let count = (self.read_operand(&inst.operands[1], inst)? & 0x3F) as u32;

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
        self.engine.cpu.rflags.set(Flags::CF, last_bit_out);

        // OF is set to the sign bit of the original value (only for count == 1)
        if count == 1 {
            self.engine
                .cpu
                .rflags
                .set(Flags::OF, (value >> 63) & 1 != 0);
        }

        // Update SF, ZF, PF based on result
        self.update_flags_logical(result);

        self.write_operand(&inst.operands[0], result, inst)?;
        Ok(())
    }

    fn execute_sar(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() < 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        let value = self.read_operand(&inst.operands[0], inst)? as i64;
        let count = (self.read_operand(&inst.operands[1], inst)? & 0x3F) as u32;

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
        self.engine.cpu.rflags.set(Flags::CF, last_bit_out);

        // OF is cleared for SAR with count == 1
        if count == 1 {
            self.engine.cpu.rflags.set(Flags::OF, false);
        }

        // Update SF, ZF, PF based on result
        self.update_flags_logical(result);

        self.write_operand(&inst.operands[0], result, inst)?;
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
            Operand::Memory {
                base,
                index,
                scale,
                displacement,
                ..
            } => {
                let mut addr = *displacement as u64;

                if let Some(base_reg) = base {
                    addr = addr.wrapping_add(self.engine.cpu.read_reg(*base_reg));
                }

                if let Some(index_reg) = index {
                    let index_val = self.engine.cpu.read_reg(*index_reg);
                    addr = addr.wrapping_add(index_val.wrapping_mul(*scale as u64));
                }

                addr
            }
            _ => return Err(EmulatorError::InvalidInstruction(inst.address)),
        };

        // LEA doesn't affect any flags
        self.engine.cpu.write_reg(dest, address);
        Ok(())
    }

    fn execute_rol(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() < 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        let value = self.read_operand(&inst.operands[0], inst)?;
        let count = (self.read_operand(&inst.operands[1], inst)? & 0x3F) as u32;

        if count == 0 {
            return Ok(());
        }

        // Rotate left: bits shifted out on the left are rotated back in on the right
        let actual_count = count % 64;
        let result = value.rotate_left(actual_count);

        // CF gets the last bit rotated out (which is now the LSB)
        self.engine.cpu.rflags.set(Flags::CF, result & 1 != 0);

        // OF is set if sign bit changed (only for count == 1)
        if count == 1 {
            let sign_changed = ((value >> 63) & 1) != ((result >> 63) & 1);
            self.engine.cpu.rflags.set(Flags::OF, sign_changed);
        }

        self.write_operand(&inst.operands[0], result, inst)?;
        Ok(())
    }

    fn execute_ror(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() < 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        let value = self.read_operand(&inst.operands[0], inst)?;
        let count = (self.read_operand(&inst.operands[1], inst)? & 0x3F) as u32;

        if count == 0 {
            return Ok(());
        }

        // Rotate right: bits shifted out on the right are rotated back in on the left
        let actual_count = count % 64;
        let result = value.rotate_right(actual_count);

        // CF gets the last bit rotated out (which is now the MSB)
        self.engine
            .cpu
            .rflags
            .set(Flags::CF, (result >> 63) & 1 != 0);

        // OF is set based on the two most significant bits (only for count == 1)
        if count == 1 {
            let msb = (result >> 63) & 1;
            let next_msb = (result >> 62) & 1;
            self.engine.cpu.rflags.set(Flags::OF, msb != next_msb);
        }

        self.write_operand(&inst.operands[0], result, inst)?;
        Ok(())
    }

    fn execute_xchg(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() < 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        // Read both values
        let value1 = self.read_operand(&inst.operands[0], inst)?;
        let value2 = self.read_operand(&inst.operands[1], inst)?;

        // Exchange them
        self.write_operand(&inst.operands[0], value2, inst)?;
        self.write_operand(&inst.operands[1], value1, inst)?;

        // XCHG doesn't affect any flags
        Ok(())
    }

    fn execute_xadd(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        // XADD: Exchange and Add
        // Exchanges the destination and source operands, then adds the original source value to the destination
        let dst = self.read_operand(&inst.operands[0], inst)?;
        let src = self.read_operand(&inst.operands[1], inst)?;

        // Store original destination in source
        self.write_operand(&inst.operands[1], dst, inst)?;

        // Add original source to original destination and store in destination
        let result = dst.wrapping_add(src);
        self.write_operand(&inst.operands[0], result, inst)?;

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
        let multiplicand = self.engine.cpu.read_reg(Register::RAX);
        let multiplier = self.read_operand(&inst.operands[0], inst)?;

        let result = (multiplicand as u128) * (multiplier as u128);

        // Store low 64 bits in RAX, high 64 bits in RDX
        self.engine.cpu.write_reg(Register::RAX, result as u64);
        self.engine
            .cpu
            .write_reg(Register::RDX, (result >> 64) as u64);

        // Set CF and OF if upper half is non-zero
        let overflow = (result >> 64) != 0;
        self.engine.cpu.rflags.set(Flags::CF, overflow);
        self.engine.cpu.rflags.set(Flags::OF, overflow);

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
        let dividend_low = self.engine.cpu.read_reg(Register::RAX);
        let dividend_high = self.engine.cpu.read_reg(Register::RDX);
        let dividend = ((dividend_high as u128) << 64) | (dividend_low as u128);
        let divisor = self.read_operand(&inst.operands[0], inst)? as u128;

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

        self.engine.cpu.write_reg(Register::RAX, quotient as u64);
        self.engine.cpu.write_reg(Register::RDX, remainder as u64);

        // All flags are undefined after DIV

        Ok(())
    }

    fn execute_imul(&mut self, inst: &Instruction) -> Result<()> {
        // IMUL has multiple forms
        if inst.operands.is_empty() {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        match inst.operands.len() {
            1 => {
                // Single operand form: RDX:RAX = RAX * operand (signed)
                let multiplicand = self.engine.cpu.read_reg(Register::RAX) as i64;
                let multiplier = self.read_operand(&inst.operands[0], inst)? as i64;

                let result = (multiplicand as i128) * (multiplier as i128);

                // Store low 64 bits in RAX, high 64 bits in RDX
                self.engine.cpu.write_reg(Register::RAX, result as u64);
                self.engine
                    .cpu
                    .write_reg(Register::RDX, (result >> 64) as u64);

                // Set CF and OF if result doesn't fit in 64 bits (signed)
                let sign_extended = (result as i64) as i128;
                let overflow = result != sign_extended;
                self.engine.cpu.rflags.set(Flags::CF, overflow);
                self.engine.cpu.rflags.set(Flags::OF, overflow);
            }
            2 => {
                // Two operand form: reg = reg * r/m (signed)
                let multiplicand = self.read_operand(&inst.operands[0], inst)? as i64;
                let multiplier = self.read_operand(&inst.operands[1], inst)? as i64;

                let result = (multiplicand as i128) * (multiplier as i128);

                // Store result in destination register
                self.write_operand(&inst.operands[0], result as u64, inst)?;

                // Set CF and OF if result doesn't fit in destination size (signed)
                let dest_size = match inst.operand_size {
                    OperandSize::Word => 16,
                    OperandSize::DWord => 32,
                    OperandSize::QWord => 64,
                    _ => 64,
                };

                let max_positive = (1i128 << (dest_size - 1)) - 1;
                let min_negative = -(1i128 << (dest_size - 1));
                let overflow = result > max_positive || result < min_negative;

                self.engine.cpu.rflags.set(Flags::CF, overflow);
                self.engine.cpu.rflags.set(Flags::OF, overflow);
            }
            3 => {
                // Three operand form: reg1 = reg2/mem * imm (signed)
                let multiplicand = self.read_operand(&inst.operands[1], inst)? as i64;
                let multiplier = self.read_operand(&inst.operands[2], inst)? as i64;

                let result = (multiplicand as i128) * (multiplier as i128);

                // Store result in destination register
                self.write_operand(&inst.operands[0], result as u64, inst)?;

                // Set CF and OF if result doesn't fit in destination size (signed)
                let dest_size = match inst.operand_size {
                    OperandSize::Word => 16,
                    OperandSize::DWord => 32,
                    OperandSize::QWord => 64,
                    _ => 64,
                };

                let max_positive = (1i128 << (dest_size - 1)) - 1;
                let min_negative = -(1i128 << (dest_size - 1));
                let overflow = result > max_positive || result < min_negative;

                self.engine.cpu.rflags.set(Flags::CF, overflow);
                self.engine.cpu.rflags.set(Flags::OF, overflow);
            }
            _ => {
                return Err(EmulatorError::InvalidInstruction(inst.address));
            }
        }

        Ok(())
    }

    fn execute_idiv(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.is_empty() {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        // IDIV performs signed division
        let dividend_low = self.engine.cpu.read_reg(Register::RAX) as i64;
        let dividend_high = self.engine.cpu.read_reg(Register::RDX) as i64;
        let dividend = ((dividend_high as i128) << 64) | (dividend_low as u64 as i128);
        let divisor = self.read_operand(&inst.operands[0], inst)? as i64 as i128;

        if divisor == 0 {
            return Err(EmulatorError::DivisionByZero);
        }

        let quotient = dividend / divisor;
        let remainder = dividend % divisor;

        // Check for quotient overflow
        if quotient > i64::MAX as i128 || quotient < i64::MIN as i128 {
            return Err(EmulatorError::DivisionOverflow);
        }

        self.engine.cpu.write_reg(Register::RAX, quotient as u64);
        self.engine.cpu.write_reg(Register::RDX, remainder as u64);

        Ok(())
    }

    fn execute_push(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.is_empty() {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        let value = self.read_operand(&inst.operands[0], inst)?;
        let rsp = self.engine.cpu.read_reg(Register::RSP);
        let new_rsp = rsp.wrapping_sub(8);
        self.engine.cpu.write_reg(Register::RSP, new_rsp);
        self.mem_write_u64(new_rsp, value)?;
        Ok(())
    }

    fn execute_pop(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.is_empty() {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        let rsp = self.engine.cpu.read_reg(Register::RSP);
        let value = self.mem_read_u64(rsp)?;
        self.write_operand(&inst.operands[0], value, inst)?;
        self.engine
            .cpu
            .write_reg(Register::RSP, rsp.wrapping_add(8));
        Ok(())
    }

    fn execute_call(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.is_empty() {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        let rsp = self.engine.cpu.read_reg(Register::RSP);
        let new_rsp = rsp.wrapping_sub(8);
        self.engine.cpu.write_reg(Register::RSP, new_rsp);
        self.mem_write_u64(new_rsp, self.engine.cpu.rip)?;

        match &inst.operands[0] {
            Operand::Relative(offset) => {
                self.engine.cpu.rip = (self.engine.cpu.rip as i64 + offset) as u64;
            }
            _ => {
                let target = self.read_operand(&inst.operands[0], inst)?;
                self.engine.cpu.rip = target;
            }
        }
        Ok(())
    }

    fn execute_ret(&mut self, _inst: &Instruction) -> Result<()> {
        let rsp = self.engine.cpu.read_reg(Register::RSP);
        let return_addr = self.mem_read_u64(rsp)?;
        self.engine
            .cpu
            .write_reg(Register::RSP, rsp.wrapping_add(8));
        self.engine.cpu.rip = return_addr;
        Ok(())
    }

    fn execute_jmp(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.is_empty() {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        match &inst.operands[0] {
            Operand::Relative(offset) => {
                self.engine.cpu.rip = (self.engine.cpu.rip as i64 + offset) as u64;
            }
            _ => {
                let target = self.read_operand(&inst.operands[0], inst)?;
                self.engine.cpu.rip = target;
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
        if let Some(hooks) = &mut self.hooks {
            hooks.on_interrupt(self.engine, 0x80, 0)?;
        }
        Ok(())
    }

    fn execute_loop(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.is_empty() {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        // Decrement RCX (treating it as unsigned)
        let count = self.engine.cpu.read_reg(Register::RCX);
        let new_count = count.wrapping_sub(1);
        self.engine.cpu.write_reg(Register::RCX, new_count);

        // Jump if new_count != 0 (after decrement)
        if new_count != 0 {
            match &inst.operands[0] {
                Operand::Relative(offset) => {
                    self.engine.cpu.rip = (self.engine.cpu.rip as i64 + offset) as u64;
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
        let count = self.engine.cpu.read_reg(Register::RCX);
        let new_count = count.wrapping_sub(1);
        self.engine.cpu.write_reg(Register::RCX, new_count);

        // Jump if new_count != 0 AND ZF = 1
        if new_count != 0 && self.engine.cpu.rflags.contains(Flags::ZF) {
            match &inst.operands[0] {
                Operand::Relative(offset) => {
                    self.engine.cpu.rip = (self.engine.cpu.rip as i64 + offset) as u64;
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
        let count = self.engine.cpu.read_reg(Register::RCX);
        let new_count = count.wrapping_sub(1);
        self.engine.cpu.write_reg(Register::RCX, new_count);

        // Jump if new_count != 0 AND ZF = 0
        if new_count != 0 && !self.engine.cpu.rflags.contains(Flags::ZF) {
            match &inst.operands[0] {
                Operand::Relative(offset) => {
                    self.engine.cpu.rip = (self.engine.cpu.rip as i64 + offset) as u64;
                }
                _ => return Err(EmulatorError::InvalidInstruction(inst.address)),
            }
        }

        Ok(())
    }

    fn execute_movs(&mut self, inst: &Instruction) -> Result<()> {
        // Determine operand size from the size indicator operand
        let size = if let Some(Operand::Immediate(1)) = inst.operands.first() {
            OperandSize::Byte
        } else {
            inst.operand_size
        };

        // Check if there's a REP prefix
        let has_rep = inst.prefix.rep.is_some();

        if has_rep {
            let count = self.engine.cpu.read_reg(Register::RCX);
            if count == 0 {
                return Ok(());
            }

            for _ in 0..count {
                self.movs_single(size)?;
            }
            self.engine.cpu.write_reg(Register::RCX, 0);
        } else {
            self.movs_single(size)?;
        }

        Ok(())
    }

    fn movs_single(&mut self, size: OperandSize) -> Result<()> {
        let rsi = self.engine.cpu.read_reg(Register::RSI);
        let rdi = self.engine.cpu.read_reg(Register::RDI);

        // Read from [RSI]
        let value = match size {
            OperandSize::Byte => self.mem_read_u8(rsi)? as u64,
            OperandSize::Word => self.mem_read_u16(rsi)? as u64,
            OperandSize::DWord => self.mem_read_u32(rsi)? as u64,
            OperandSize::QWord => self.mem_read_u64(rsi)?,
            OperandSize::XmmWord => return Err(EmulatorError::InvalidOperand),
            OperandSize::YmmWord => return Err(EmulatorError::InvalidOperand),
        };

        // Write to [RDI]
        match size {
            OperandSize::Byte => self.mem_write_u8(rdi, value as u8)?,
            OperandSize::Word => self.mem_write_u16(rdi, value as u16)?,
            OperandSize::DWord => self.mem_write_u32(rdi, value as u32)?,
            OperandSize::QWord => self.mem_write_u64(rdi, value)?,
            OperandSize::XmmWord => return Err(EmulatorError::InvalidOperand),
            OperandSize::YmmWord => return Err(EmulatorError::InvalidOperand),
        };

        // Update RSI and RDI based on direction flag
        let increment = size.bytes() as u64;
        if self.engine.cpu.rflags.contains(Flags::DF) {
            self.engine
                .cpu
                .write_reg(Register::RSI, rsi.wrapping_sub(increment));
            self.engine
                .cpu
                .write_reg(Register::RDI, rdi.wrapping_sub(increment));
        } else {
            self.engine
                .cpu
                .write_reg(Register::RSI, rsi.wrapping_add(increment));
            self.engine
                .cpu
                .write_reg(Register::RDI, rdi.wrapping_add(increment));
        }

        Ok(())
    }

    fn execute_cmps(&mut self, inst: &Instruction) -> Result<()> {
        // Determine operand size from the size indicator operand
        let size = if let Some(Operand::Immediate(1)) = inst.operands.first() {
            OperandSize::Byte
        } else {
            inst.operand_size
        };

        // Check if there's a REP prefix
        match inst.prefix.rep {
            Some(crate::decoder::RepPrefix::RepZ) => {
                let count = self.engine.cpu.read_reg(Register::RCX);
                if count == 0 {
                    return Ok(());
                }

                for i in 0..count {
                    self.cmps_single(size)?;
                    let new_count = count - i - 1;
                    self.engine.cpu.write_reg(Register::RCX, new_count);

                    // Continue while ZF=1 (equal)
                    if !self.engine.cpu.rflags.contains(Flags::ZF) {
                        break;
                    }
                }
            }
            Some(crate::decoder::RepPrefix::RepNZ) => {
                let count = self.engine.cpu.read_reg(Register::RCX);
                if count == 0 {
                    return Ok(());
                }

                for i in 0..count {
                    self.cmps_single(size)?;
                    let new_count = count - i - 1;
                    self.engine.cpu.write_reg(Register::RCX, new_count);

                    // Continue while ZF=0 (not equal)
                    if self.engine.cpu.rflags.contains(Flags::ZF) {
                        break;
                    }
                }
            }
            _ => self.cmps_single(size)?,
        }

        Ok(())
    }

    fn cmps_single(&mut self, size: OperandSize) -> Result<()> {
        let rsi = self.engine.cpu.read_reg(Register::RSI);
        let rdi = self.engine.cpu.read_reg(Register::RDI);

        // Read from [RSI] and [RDI]
        let src1 = match size {
            OperandSize::Byte => self.mem_read_u8(rsi)? as u64,
            OperandSize::Word => self.mem_read_u16(rsi)? as u64,
            OperandSize::DWord => self.mem_read_u32(rsi)? as u64,
            OperandSize::QWord => self.mem_read_u64(rsi)?,
            OperandSize::XmmWord => return Err(EmulatorError::InvalidOperand),
            OperandSize::YmmWord => return Err(EmulatorError::InvalidOperand),
        };

        let src2 = match size {
            OperandSize::Byte => self.mem_read_u8(rdi)? as u64,
            OperandSize::Word => self.mem_read_u16(rdi)? as u64,
            OperandSize::DWord => self.mem_read_u32(rdi)? as u64,
            OperandSize::QWord => self.mem_read_u64(rdi)?,
            OperandSize::XmmWord => return Err(EmulatorError::InvalidOperand),
            OperandSize::YmmWord => return Err(EmulatorError::InvalidOperand),
        };

        // Compare src1 - src2
        let result = src1.wrapping_sub(src2);
        self.update_flags_arithmetic(src1, src2, result, true);

        // Update RSI and RDI based on direction flag
        let increment = size.bytes() as u64;
        if self.engine.cpu.rflags.contains(Flags::DF) {
            self.engine
                .cpu
                .write_reg(Register::RSI, rsi.wrapping_sub(increment));
            self.engine
                .cpu
                .write_reg(Register::RDI, rdi.wrapping_sub(increment));
        } else {
            self.engine
                .cpu
                .write_reg(Register::RSI, rsi.wrapping_add(increment));
            self.engine
                .cpu
                .write_reg(Register::RDI, rdi.wrapping_add(increment));
        }

        Ok(())
    }

    fn execute_scas(&mut self, inst: &Instruction) -> Result<()> {
        // Determine operand size from the size indicator operand
        let size = if let Some(Operand::Immediate(1)) = inst.operands.first() {
            OperandSize::Byte
        } else {
            inst.operand_size
        };

        // Check if there's a REP prefix
        match inst.prefix.rep {
            Some(crate::decoder::RepPrefix::RepZ) => {
                let count = self.engine.cpu.read_reg(Register::RCX);
                if count == 0 {
                    return Ok(());
                }

                for i in 0..count {
                    self.scas_single(size)?;
                    let new_count = count - i - 1;
                    self.engine.cpu.write_reg(Register::RCX, new_count);

                    // Continue while ZF=1 (equal)
                    if !self.engine.cpu.rflags.contains(Flags::ZF) {
                        break;
                    }
                }
            }
            Some(crate::decoder::RepPrefix::RepNZ) => {
                let count = self.engine.cpu.read_reg(Register::RCX);
                if count == 0 {
                    return Ok(());
                }

                for i in 0..count {
                    self.scas_single(size)?;
                    let new_count = count - i - 1;
                    self.engine.cpu.write_reg(Register::RCX, new_count);

                    // Continue while ZF=0 (not equal)
                    if self.engine.cpu.rflags.contains(Flags::ZF) {
                        break;
                    }
                }
            }
            _ => self.scas_single(size)?,
        }

        Ok(())
    }

    fn scas_single(&mut self, size: OperandSize) -> Result<()> {
        let rdi = self.engine.cpu.read_reg(Register::RDI);

        // Get accumulator value
        let acc = match size {
            OperandSize::Byte => self.engine.cpu.read_reg(Register::AL),
            OperandSize::Word => self.engine.cpu.read_reg(Register::AX),
            OperandSize::DWord => self.engine.cpu.read_reg(Register::EAX),
            OperandSize::QWord => self.engine.cpu.read_reg(Register::RAX),
            OperandSize::XmmWord => return Err(EmulatorError::InvalidOperand),
            OperandSize::YmmWord => return Err(EmulatorError::InvalidOperand),
        };

        // Read from [RDI]
        let mem_value = match size {
            OperandSize::Byte => self.mem_read_u8(rdi)? as u64,
            OperandSize::Word => self.mem_read_u16(rdi)? as u64,
            OperandSize::DWord => self.mem_read_u32(rdi)? as u64,
            OperandSize::QWord => self.mem_read_u64(rdi)?,
            OperandSize::XmmWord => return Err(EmulatorError::InvalidOperand),
            OperandSize::YmmWord => return Err(EmulatorError::InvalidOperand),
        };

        // Compare accumulator - memory
        let result = acc.wrapping_sub(mem_value);
        self.update_flags_arithmetic(acc, mem_value, result, true);

        // Update RDI based on direction flag
        let increment = size.bytes() as u64;
        if self.engine.cpu.rflags.contains(Flags::DF) {
            self.engine
                .cpu
                .write_reg(Register::RDI, rdi.wrapping_sub(increment));
        } else {
            self.engine
                .cpu
                .write_reg(Register::RDI, rdi.wrapping_add(increment));
        }

        Ok(())
    }

    fn execute_stos(&mut self, inst: &Instruction) -> Result<()> {
        // Determine operand size from the size indicator operand
        let size = if let Some(Operand::Immediate(1)) = inst.operands.first() {
            OperandSize::Byte
        } else {
            inst.operand_size
        };

        // Check if there's a REP prefix
        let has_rep = inst.prefix.rep.is_some();

        if has_rep {
            let count = self.engine.cpu.read_reg(Register::RCX);
            if count == 0 {
                return Ok(());
            }

            for _ in 0..count {
                self.stos_single(size)?;
            }
            self.engine.cpu.write_reg(Register::RCX, 0);
        } else {
            self.stos_single(size)?;
        }

        Ok(())
    }

    fn stos_single(&mut self, size: OperandSize) -> Result<()> {
        let rdi = self.engine.cpu.read_reg(Register::RDI);

        // Get accumulator value
        let acc = match size {
            OperandSize::Byte => self.engine.cpu.read_reg(Register::AL),
            OperandSize::Word => self.engine.cpu.read_reg(Register::AX),
            OperandSize::DWord => self.engine.cpu.read_reg(Register::EAX),
            OperandSize::QWord => self.engine.cpu.read_reg(Register::RAX),
            OperandSize::XmmWord => return Err(EmulatorError::InvalidOperand),
            OperandSize::YmmWord => return Err(EmulatorError::InvalidOperand),
        };

        // Write to [RDI]
        match size {
            OperandSize::Byte => self.mem_write_u8(rdi, acc as u8)?,
            OperandSize::Word => self.mem_write_u16(rdi, acc as u16)?,
            OperandSize::DWord => self.mem_write_u32(rdi, acc as u32)?,
            OperandSize::QWord => self.mem_write_u64(rdi, acc)?,
            OperandSize::XmmWord => return Err(EmulatorError::InvalidOperand),
            OperandSize::YmmWord => return Err(EmulatorError::InvalidOperand),
        };

        // Update RDI based on direction flag
        let increment = size.bytes() as u64;
        if self.engine.cpu.rflags.contains(Flags::DF) {
            self.engine
                .cpu
                .write_reg(Register::RDI, rdi.wrapping_sub(increment));
        } else {
            self.engine
                .cpu
                .write_reg(Register::RDI, rdi.wrapping_add(increment));
        }

        Ok(())
    }

    fn execute_lods(&mut self, inst: &Instruction) -> Result<()> {
        // Determine operand size from the size indicator operand
        let size = if let Some(Operand::Immediate(1)) = inst.operands.first() {
            OperandSize::Byte
        } else {
            inst.operand_size
        };

        // Check if there's a REP prefix (rarely used with LODS)
        let has_rep = inst.prefix.rep.is_some();

        if has_rep {
            let count = self.engine.cpu.read_reg(Register::RCX);
            if count == 0 {
                return Ok(());
            }

            for _ in 0..count {
                self.lods_single(size)?;
            }
            self.engine.cpu.write_reg(Register::RCX, 0);
        } else {
            self.lods_single(size)?;
        }

        Ok(())
    }

    fn lods_single(&mut self, size: OperandSize) -> Result<()> {
        let rsi = self.engine.cpu.read_reg(Register::RSI);

        // Read from [RSI]
        let value = match size {
            OperandSize::Byte => self.mem_read_u8(rsi)? as u64,
            OperandSize::Word => self.mem_read_u16(rsi)? as u64,
            OperandSize::DWord => self.mem_read_u32(rsi)? as u64,
            OperandSize::QWord => self.mem_read_u64(rsi)?,
            OperandSize::XmmWord => return Err(EmulatorError::InvalidOperand),
            OperandSize::YmmWord => return Err(EmulatorError::InvalidOperand),
        };

        // Store in accumulator
        match size {
            OperandSize::Byte => self.engine.cpu.write_reg(Register::AL, value),
            OperandSize::Word => self.engine.cpu.write_reg(Register::AX, value),
            OperandSize::DWord => self.engine.cpu.write_reg(Register::EAX, value),
            OperandSize::QWord => self.engine.cpu.write_reg(Register::RAX, value),
            OperandSize::XmmWord => return Err(EmulatorError::InvalidOperand),
            OperandSize::YmmWord => return Err(EmulatorError::InvalidOperand),
        };

        // Update RSI based on direction flag
        let increment = size.bytes() as u64;
        if self.engine.cpu.rflags.contains(Flags::DF) {
            self.engine
                .cpu
                .write_reg(Register::RSI, rsi.wrapping_sub(increment));
        } else {
            self.engine
                .cpu
                .write_reg(Register::RSI, rsi.wrapping_add(increment));
        }

        Ok(())
    }

    fn read_operand(&mut self, operand: &Operand, inst: &Instruction) -> Result<u64> {
        match operand {
            Operand::Register(reg) => Ok(self.engine.cpu.read_reg(*reg)),
            Operand::Immediate(val) => Ok(*val as u64),
            Operand::Memory {
                base,
                index,
                scale,
                displacement,
                size,
            } => {
                let mut addr = *displacement as u64;
                if let Some(base_reg) = base {
                    addr = addr.wrapping_add(self.engine.cpu.read_reg(*base_reg));
                }
                if let Some(index_reg) = index {
                    addr =
                        addr.wrapping_add(self.engine.cpu.read_reg(*index_reg) * (*scale as u64));
                }

                // Apply segment base if segment prefix is present
                if let Some(segment_reg) = inst.prefix.segment {
                    let segment_base = match segment_reg {
                        Register::CS => self.engine.cpu.segments.cs.base,
                        Register::DS => self.engine.cpu.segments.ds.base,
                        Register::ES => self.engine.cpu.segments.es.base,
                        Register::FS => self.engine.cpu.segments.fs.base,
                        Register::GS => self.engine.cpu.segments.gs.base,
                        Register::SS => self.engine.cpu.segments.ss.base,
                        _ => 0, // Should not happen for segment registers
                    };
                    addr = addr.wrapping_add(segment_base);
                }

                match size {
                    OperandSize::Byte => self.mem_read_u8(addr).map(|v| v as u64),
                    OperandSize::Word => self.mem_read_u16(addr).map(|v| v as u64),
                    OperandSize::DWord => self.mem_read_u32(addr).map(|v| v as u64),
                    OperandSize::QWord => self.mem_read_u64(addr),
                    OperandSize::XmmWord => Err(EmulatorError::InvalidOperand),
                    OperandSize::YmmWord => Err(EmulatorError::InvalidOperand),
                }
            }
            Operand::Relative(offset) => Ok((self.engine.cpu.rip as i64 + offset) as u64),
        }
    }

    fn write_operand(&mut self, operand: &Operand, value: u64, inst: &Instruction) -> Result<()> {
        match operand {
            Operand::Register(reg) => {
                // Handle 32-bit writes to 64-bit registers - in x86-64, writing to 32-bit
                // reg should zero the upper 32 bits of the corresponding 64-bit reg
                if inst.operand_size == OperandSize::DWord {
                    match reg {
                        Register::R8
                        | Register::R9
                        | Register::R10
                        | Register::R11
                        | Register::R12
                        | Register::R13
                        | Register::R14
                        | Register::R15 => {
                            // For R8-R15, zero upper 32 bits when writing 32-bit value
                            self.engine.cpu.write_reg(*reg, value & 0xFFFFFFFF);
                        }
                        _ => {
                            // For other registers, normal write_reg handles 32-bit semantics
                            self.engine.cpu.write_reg(*reg, value);
                        }
                    }
                } else {
                    self.engine.cpu.write_reg(*reg, value);
                }
                Ok(())
            }
            Operand::Memory {
                base,
                index,
                scale,
                displacement,
                size,
            } => {
                let mut addr = *displacement as u64;
                if let Some(base_reg) = base {
                    addr = addr.wrapping_add(self.engine.cpu.read_reg(*base_reg));
                }
                if let Some(index_reg) = index {
                    addr =
                        addr.wrapping_add(self.engine.cpu.read_reg(*index_reg) * (*scale as u64));
                }

                // Apply segment base if segment prefix is present
                if let Some(segment_reg) = inst.prefix.segment {
                    let segment_base = match segment_reg {
                        Register::CS => self.engine.cpu.segments.cs.base,
                        Register::DS => self.engine.cpu.segments.ds.base,
                        Register::ES => self.engine.cpu.segments.es.base,
                        Register::FS => self.engine.cpu.segments.fs.base,
                        Register::GS => self.engine.cpu.segments.gs.base,
                        Register::SS => self.engine.cpu.segments.ss.base,
                        _ => 0, // Should not happen for segment registers
                    };
                    addr = addr.wrapping_add(segment_base);
                }

                match size {
                    OperandSize::Byte => self.mem_write_u8(addr, value as u8),
                    OperandSize::Word => self.mem_write_u16(addr, value as u16),
                    OperandSize::DWord => self.mem_write_u32(addr, value as u32),
                    OperandSize::QWord => self.mem_write_u64(addr, value),
                    OperandSize::XmmWord => Err(EmulatorError::InvalidOperand),
                    OperandSize::YmmWord => Err(EmulatorError::InvalidOperand),
                }
            }
            _ => Err(EmulatorError::InvalidInstruction(0)),
        }
    }

    fn execute_rdtsc(&mut self, inst: &Instruction) -> Result<()> {
        // RDTSC: Read Time-Stamp Counter
        // Returns a 64-bit timestamp counter in EDX:EAX
        if !inst.operands.is_empty() {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        // Use a simple fake timestamp that increments with each instruction
        // In a real CPU, this would be a high-resolution timestamp
        let timestamp = self.engine.instruction_count * 1000; // Simple fake timestamp

        // Split the 64-bit timestamp into high and low 32-bit parts
        let low_part = timestamp as u32;
        let high_part = (timestamp >> 32) as u32;

        // Store in EAX (low part) and EDX (high part)
        self.engine.cpu.write_reg(Register::EAX, low_part as u64);
        self.engine.cpu.write_reg(Register::EDX, high_part as u64);

        Ok(())
    }

    fn execute_monitorx(&mut self, inst: &Instruction) -> Result<()> {
        // MONITORX: Monitor a memory address range (AMD instruction)
        // This is typically used for optimized waiting/synchronization
        // For emulation purposes, we implement this as a no-op
        if !inst.operands.is_empty() {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        // MONITORX uses EAX for the address to monitor, but we don't need to
        // actually implement the monitoring functionality for emulation
        Ok(())
    }

    fn execute_prefetchw(&mut self, inst: &Instruction) -> Result<()> {
        // PREFETCHW: Prefetch data into cache with intent to write
        // This is a performance hint instruction - implement as no-op for emulation
        if inst.operands.len() != 1 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        // We don't need to actually do anything - it's just a cache hint
        // The operand specifies which memory address to prefetch, but we ignore it
        Ok(())
    }

    fn execute_cmpxchg(&mut self, inst: &Instruction) -> Result<()> {
        // CMPXCHG: Compare and Exchange
        // Compares the accumulator (EAX/RAX) with the destination operand
        // If equal: ZF=1 and destination = source operand
        // If not equal: ZF=0 and accumulator = destination operand
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        let dest_value = self.read_operand(&inst.operands[0], inst)?;
        let src_value = self.read_operand(&inst.operands[1], inst)?;

        // Determine operand size from the first operand
        let operand_size = self.get_operand_size(&inst.operands[0]);
        let mask = match operand_size {
            OperandSize::Byte => 0xFF,
            OperandSize::Word => 0xFFFF,
            OperandSize::DWord => 0xFFFFFFFF,
            OperandSize::QWord => 0xFFFFFFFFFFFFFFFF,
            OperandSize::XmmWord => return Err(EmulatorError::InvalidInstruction(inst.address)),
            OperandSize::YmmWord => return Err(EmulatorError::InvalidInstruction(inst.address)),
        };

        // Get the appropriate accumulator register
        let acc_reg = match operand_size {
            OperandSize::Byte => Register::AL,
            OperandSize::Word => Register::AX,
            OperandSize::DWord => Register::EAX,
            OperandSize::QWord => Register::RAX,
            OperandSize::XmmWord => return Err(EmulatorError::InvalidInstruction(inst.address)),
            OperandSize::YmmWord => return Err(EmulatorError::InvalidInstruction(inst.address)),
        };

        let acc_value = self.engine.cpu.read_reg(acc_reg) & mask;
        let dest_masked = dest_value & mask;

        if acc_value == dest_masked {
            // Equal: Set ZF=1 and destination = source
            self.engine.cpu.rflags.set(Flags::ZF, true);
            self.write_operand(&inst.operands[0], src_value & mask, inst)?;
        } else {
            // Not equal: Set ZF=0 and accumulator = destination
            self.engine.cpu.rflags.set(Flags::ZF, false);
            self.engine.cpu.write_reg(acc_reg, dest_masked);
        }

        Ok(())
    }

    fn execute_bt(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        let bit_base = self.read_operand(&inst.operands[0], inst)?;
        let bit_offset = self.read_operand(&inst.operands[1], inst)? & 0x3F; // Mask to 6 bits for 64-bit

        let bit_value = (bit_base >> bit_offset) & 1;
        self.engine.cpu.rflags.set(Flags::CF, bit_value != 0);

        Ok(())
    }

    fn execute_bts(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        let bit_base = self.read_operand(&inst.operands[0], inst)?;
        let bit_offset = self.read_operand(&inst.operands[1], inst)? & 0x3F; // Mask to 6 bits for 64-bit

        let bit_value = (bit_base >> bit_offset) & 1;
        self.engine.cpu.rflags.set(Flags::CF, bit_value != 0);

        let new_value = bit_base | (1 << bit_offset);
        self.write_operand(&inst.operands[0], new_value, inst)?;

        Ok(())
    }

    fn execute_btr(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        let bit_base = self.read_operand(&inst.operands[0], inst)?;
        let bit_offset = self.read_operand(&inst.operands[1], inst)? & 0x3F; // Mask to 6 bits for 64-bit

        let bit_value = (bit_base >> bit_offset) & 1;
        self.engine.cpu.rflags.set(Flags::CF, bit_value != 0);

        let new_value = bit_base & !(1 << bit_offset);
        self.write_operand(&inst.operands[0], new_value, inst)?;

        Ok(())
    }

    fn execute_btc(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        let bit_base = self.read_operand(&inst.operands[0], inst)?;
        let bit_offset = self.read_operand(&inst.operands[1], inst)? & 0x3F; // Mask to 6 bits for 64-bit

        let bit_value = (bit_base >> bit_offset) & 1;
        self.engine.cpu.rflags.set(Flags::CF, bit_value != 0);

        let new_value = bit_base ^ (1 << bit_offset);
        self.write_operand(&inst.operands[0], new_value, inst)?;

        Ok(())
    }

    fn update_flags_arithmetic(&mut self, dst: u64, src: u64, result: u64, is_sub: bool) {
        self.engine.cpu.rflags.set(Flags::ZF, result == 0);
        self.engine.cpu.rflags.set(Flags::SF, (result as i64) < 0);

        if is_sub {
            self.engine.cpu.rflags.set(Flags::CF, dst < src);
            let dst_sign = (dst as i64) < 0;
            let src_sign = (src as i64) < 0;
            let res_sign = (result as i64) < 0;
            self.engine
                .cpu
                .rflags
                .set(Flags::OF, dst_sign != src_sign && dst_sign != res_sign);
        } else {
            self.engine.cpu.rflags.set(Flags::CF, result < dst);
            let dst_sign = (dst as i64) < 0;
            let src_sign = (src as i64) < 0;
            let res_sign = (result as i64) < 0;
            self.engine
                .cpu
                .rflags
                .set(Flags::OF, dst_sign == src_sign && dst_sign != res_sign);
        }

        let parity = (result as u8).count_ones().is_multiple_of(2);
        self.engine.cpu.rflags.set(Flags::PF, parity);
    }

    fn update_flags_logical(&mut self, result: u64) {
        self.engine.cpu.rflags.set(Flags::ZF, result == 0);
        self.engine.cpu.rflags.set(Flags::SF, (result as i64) < 0);
        self.engine.cpu.rflags.set(Flags::CF, false);
        self.engine.cpu.rflags.set(Flags::OF, false);

        let parity = (result as u8).count_ones().is_multiple_of(2);
        self.engine.cpu.rflags.set(Flags::PF, parity);
    }

    pub fn context_save(&self) -> CpuState {
        self.engine.cpu.clone()
    }

    pub fn context_restore(&mut self, state: &CpuState) {
        self.engine.cpu = state.clone();
    }

    pub fn xmm_read(&self, reg: Register) -> Result<u128> {
        Ok(self.engine.cpu.read_xmm(reg))
    }

    pub fn xmm_write(&mut self, reg: Register, value: u128) -> Result<()> {
        self.engine.cpu.write_xmm(reg, value);
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
            addr = addr.wrapping_add(self.engine.cpu.read_reg(base_reg));
        }
        if let Some(index_reg) = index {
            addr = addr.wrapping_add(self.engine.cpu.read_reg(index_reg) * (scale as u64));
        }
        Ok(addr)
    }

    fn read_xmm_operand(&mut self, operand: &Operand) -> Result<u128> {
        match operand {
            Operand::Register(reg) => Ok(self.engine.cpu.read_xmm(*reg)),
            Operand::Memory {
                base,
                index,
                scale,
                displacement,
                size,
            } => {
                if *size != OperandSize::XmmWord {
                    return Err(EmulatorError::InvalidOperand);
                }
                let address = self.calculate_address(*base, *index, *scale, *displacement)?;
                let mut bytes = [0u8; 16];
                self.mem_read_with_hooks(address, &mut bytes)?;
                Ok(u128::from_le_bytes(bytes))
            }
            _ => Err(EmulatorError::InvalidOperand),
        }
    }

    fn read_ymm_operand(&mut self, operand: &Operand) -> Result<[u128; 2]> {
        match operand {
            Operand::Register(reg) => Ok(self.engine.cpu.read_ymm(*reg)),
            Operand::Memory {
                base,
                index,
                scale,
                displacement,
                size,
            } => {
                if *size != OperandSize::YmmWord {
                    return Err(EmulatorError::InvalidOperand);
                }
                let address = self.calculate_address(*base, *index, *scale, *displacement)?;
                let mut bytes = [0u8; 32];
                self.mem_read_with_hooks(address, &mut bytes)?;
                // Split into two u128 values (low, high)
                let low = u128::from_le_bytes(bytes[0..16].try_into().unwrap());
                let high = u128::from_le_bytes(bytes[16..32].try_into().unwrap());
                Ok([low, high])
            }
            _ => Err(EmulatorError::InvalidOperand),
        }
    }

    fn write_xmm_operand(&mut self, operand: &Operand, value: u128) -> Result<()> {
        match operand {
            Operand::Register(reg) => {
                self.engine.cpu.write_xmm(*reg, value);
                Ok(())
            }
            Operand::Memory {
                base,
                index,
                scale,
                displacement,
                size,
            } => {
                if *size != OperandSize::XmmWord {
                    return Err(EmulatorError::InvalidOperand);
                }
                let address = self.calculate_address(*base, *index, *scale, *displacement)?;
                let bytes = value.to_le_bytes();
                self.mem_write_with_hooks(address, &bytes)?;
                Ok(())
            }
            _ => Err(EmulatorError::InvalidOperand),
        }
    }

    fn write_ymm_operand(&mut self, operand: &Operand, value: [u128; 2]) -> Result<()> {
        match operand {
            Operand::Register(reg) => {
                self.engine.cpu.write_ymm(*reg, value);
                Ok(())
            }
            Operand::Memory {
                base,
                index,
                scale,
                displacement,
                size,
            } => {
                if *size != OperandSize::YmmWord {
                    return Err(EmulatorError::InvalidOperand);
                }
                let address = self.calculate_address(*base, *index, *scale, *displacement)?;
                let mut bytes = [0u8; 32];
                bytes[0..16].copy_from_slice(&value[0].to_le_bytes());
                bytes[16..32].copy_from_slice(&value[1].to_le_bytes());
                self.mem_write_with_hooks(address, &bytes)?;
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

        // Check if we're dealing with YMM or XMM registers
        let is_ymm = match &inst.operands[1] {
            Operand::Register(reg) => reg.is_ymm(),
            Operand::Memory { size, .. } => *size == OperandSize::YmmWord,
            _ => false,
        };

        if is_ymm {
            // YMM operation (256-bit)
            let value = self.read_ymm_operand(&inst.operands[1])?;
            self.write_ymm_operand(&inst.operands[0], value)?;
        } else {
            // XMM operation (128-bit)
            let value = self.read_xmm_operand(&inst.operands[1])?;
            self.write_xmm_operand(&inst.operands[0], value)?;
        }
        Ok(())
    }

    fn execute_movq(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        // MOVQ can move between XMM and general-purpose registers
        // Check if destination is XMM and source is general-purpose register
        match (&inst.operands[0], &inst.operands[1]) {
            (Operand::Register(dst_reg), Operand::Register(src_reg)) => {
                if dst_reg.is_xmm() && !src_reg.is_xmm() {
                    // XMM <- GPR (zero upper 64 bits)
                    let value = self.engine.cpu.read_reg(*src_reg);
                    self.engine.cpu.write_xmm(*dst_reg, value as u128);
                } else if !dst_reg.is_xmm() && src_reg.is_xmm() {
                    // GPR <- XMM (take lower 64 bits)
                    let value = self.engine.cpu.read_xmm(*src_reg);
                    self.engine.cpu.write_reg(*dst_reg, value as u64);
                } else {
                    return Err(EmulatorError::InvalidInstruction(inst.address));
                }
            }
            _ => {
                // For memory operands, use standard XMM operations
                let value = self.read_xmm_operand(&inst.operands[1])?;
                self.write_xmm_operand(&inst.operands[0], value)?;
            }
        }
        Ok(())
    }

    fn execute_movlhps(&mut self, inst: &Instruction) -> Result<()> {
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        // MOVLHPS: Move low 64 bits of source to high 64 bits of destination
        // High 64 bits of destination remain unchanged
        let src_value = self.read_xmm_operand(&inst.operands[1])?;
        let dst_value = self.read_xmm_operand(&inst.operands[0])?;

        // Take low 64 bits of source and put them in high 64 bits of destination
        let low_src = src_value & 0xFFFFFFFFFFFFFFFF;
        let result = (dst_value & 0xFFFFFFFFFFFFFFFF) | (low_src << 64);

        self.write_xmm_operand(&inst.operands[0], result)?;
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
            0 => a == b,                     // EQ
            1 => a < b,                      // LT
            2 => a <= b,                     // LE
            3 => a.is_nan() || b.is_nan(),   // UNORD
            4 => a != b,                     // NEQ
            5 => !(a < b),                   // NLT (a >= b or unordered)
            6 => !(a <= b),                  // NLE (a > b or unordered)
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
            self.engine.cpu.rflags.set(Flags::ZF, true);
            self.engine.cpu.rflags.set(Flags::PF, true);
            self.engine.cpu.rflags.set(Flags::CF, true);
        } else if a > b {
            self.engine.cpu.rflags.set(Flags::ZF, false);
            self.engine.cpu.rflags.set(Flags::PF, false);
            self.engine.cpu.rflags.set(Flags::CF, false);
        } else if a < b {
            self.engine.cpu.rflags.set(Flags::ZF, false);
            self.engine.cpu.rflags.set(Flags::PF, false);
            self.engine.cpu.rflags.set(Flags::CF, true);
        } else {
            // a == b
            self.engine.cpu.rflags.set(Flags::ZF, true);
            self.engine.cpu.rflags.set(Flags::PF, false);
            self.engine.cpu.rflags.set(Flags::CF, false);
        }

        // Clear OF and SF
        self.engine.cpu.rflags.set(Flags::OF, false);
        self.engine.cpu.rflags.set(Flags::SF, false);
    }

    fn update_flags_ucomiss(&mut self, a: f32, b: f32) {
        // UCOMISS is similar to COMISS but doesn't signal on QNaN
        if a.is_nan() || b.is_nan() {
            // Unordered result
            self.engine.cpu.rflags.set(Flags::ZF, true);
            self.engine.cpu.rflags.set(Flags::PF, true);
            self.engine.cpu.rflags.set(Flags::CF, true);
        } else if a > b {
            self.engine.cpu.rflags.set(Flags::ZF, false);
            self.engine.cpu.rflags.set(Flags::PF, false);
            self.engine.cpu.rflags.set(Flags::CF, false);
        } else if a < b {
            self.engine.cpu.rflags.set(Flags::ZF, false);
            self.engine.cpu.rflags.set(Flags::PF, false);
            self.engine.cpu.rflags.set(Flags::CF, true);
        } else {
            // a == b
            self.engine.cpu.rflags.set(Flags::ZF, true);
            self.engine.cpu.rflags.set(Flags::PF, false);
            self.engine.cpu.rflags.set(Flags::CF, false);
        }

        // Clear OF and SF
        self.engine.cpu.rflags.set(Flags::OF, false);
        self.engine.cpu.rflags.set(Flags::SF, false);
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
            Operand::Register(reg) => match reg {
                Register::AL
                | Register::AH
                | Register::BL
                | Register::BH
                | Register::CL
                | Register::CH
                | Register::DL
                | Register::DH
                | Register::SIL
                | Register::DIL
                | Register::SPL
                | Register::BPL => OperandSize::Byte,

                Register::AX
                | Register::BX
                | Register::CX
                | Register::DX
                | Register::SI
                | Register::DI
                | Register::SP
                | Register::BP => OperandSize::Word,

                Register::EAX
                | Register::EBX
                | Register::ECX
                | Register::EDX
                | Register::ESI
                | Register::EDI
                | Register::ESP
                | Register::EBP => OperandSize::DWord,

                _ => OperandSize::QWord,
            },
            Operand::Memory { size, .. } => *size,
            _ => OperandSize::QWord,
        }
    }

    fn update_flags_arithmetic_sized(
        &mut self,
        dst: u64,
        src: u64,
        result: u64,
        is_sub: bool,
        size: OperandSize,
    ) {
        // Determine the bit width for overflow/carry calculations
        let (max_val, sign_bit) = match size {
            OperandSize::Byte => (0xFF_u64, 0x80_u64),
            OperandSize::Word => (0xFFFF_u64, 0x8000_u64),
            OperandSize::DWord => (0xFFFFFFFF_u64, 0x80000000_u64),
            _ => (u64::MAX, 0x8000000000000000_u64),
        };

        // Mask results to the appropriate size
        let result_masked = result & max_val;

        self.engine.cpu.rflags.set(Flags::ZF, result_masked == 0);
        self.engine
            .cpu
            .rflags
            .set(Flags::SF, (result_masked & sign_bit) != 0);

        if is_sub {
            self.engine.cpu.rflags.set(Flags::CF, dst < src);
            let dst_sign = (dst & sign_bit) != 0;
            let src_sign = (src & sign_bit) != 0;
            let res_sign = (result_masked & sign_bit) != 0;
            self.engine
                .cpu
                .rflags
                .set(Flags::OF, dst_sign != src_sign && dst_sign != res_sign);
        } else {
            // For addition, carry occurs when the result is less than either operand (wrapped around)
            self.engine.cpu.rflags.set(
                Flags::CF,
                result_masked < (dst & max_val) || result_masked < (src & max_val),
            );
            let dst_sign = (dst & sign_bit) != 0;
            let src_sign = (src & sign_bit) != 0;
            let res_sign = (result_masked & sign_bit) != 0;
            self.engine
                .cpu
                .rflags
                .set(Flags::OF, dst_sign == src_sign && dst_sign != res_sign);
        }

        let parity = (result_masked as u8).count_ones().is_multiple_of(2);
        self.engine.cpu.rflags.set(Flags::PF, parity);
    }

    fn execute_cdq(&mut self, _inst: &Instruction) -> Result<()> {
        // CDQ: Convert Doubleword to Quadword
        // Sign-extend EAX into EDX:EAX
        let eax = self.engine.cpu.read_reg(Register::EAX) as u32 as i32;

        // If EAX is negative (bit 31 is set), EDX should be 0xFFFFFFFF
        // If EAX is positive or zero, EDX should be 0x00000000
        let edx = if eax < 0 { 0xFFFFFFFF } else { 0x00000000 };

        self.engine.cpu.write_reg(Register::EDX, edx);

        // CDQ doesn't affect any flags
        Ok(())
    }

    fn execute_movsxd(&mut self, inst: &Instruction) -> Result<()> {
        // MOVSXD: Move with Sign-Extend Doubleword
        // Takes a 32-bit source operand, sign-extends it to 64 bits, and stores in 64-bit destination
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        // Read the source as a 32-bit value
        let src_value = self.read_operand(&inst.operands[1], inst)? as u32 as i32;

        // Sign-extend to 64 bits
        let dest_value = src_value as i64 as u64;

        // Write to the destination register (always 64-bit)
        self.write_operand(&inst.operands[0], dest_value, inst)?;

        // MOVSXD doesn't affect any flags
        Ok(())
    }

    fn execute_movzx(&mut self, inst: &Instruction) -> Result<()> {
        // MOVZX: Move with Zero-Extend
        // Takes a smaller source operand, zero-extends it, and stores in destination
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        // Determine source size based on the source operand or instruction context
        let src_value = self.read_operand(&inst.operands[1], inst)?;

        // For MOVZX, we need to determine if it's byte-to-larger or word-to-larger
        // This can be inferred from the operand or we may need additional context
        // For now, let's assume byte extension (0x0F 0xB6) and handle word extension (0x0F 0xB7) later
        let src_size = self.get_operand_size(&inst.operands[1]);

        let dest_value = match src_size {
            OperandSize::Byte => {
                // Zero-extend 8-bit to destination size
                (src_value as u8) as u64
            }
            OperandSize::Word => {
                // Zero-extend 16-bit to destination size
                (src_value as u16) as u64
            }
            _ => {
                // For larger source sizes, just use the value as-is
                src_value
            }
        };

        // Write to the destination register
        self.write_operand(&inst.operands[0], dest_value, inst)?;

        // MOVZX doesn't affect any flags
        Ok(())
    }

    fn execute_setbe(&mut self, inst: &Instruction) -> Result<()> {
        // SETBE: Set byte if below or equal (CF=1 or ZF=1)
        if inst.operands.len() != 1 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        // Check condition: CF=1 or ZF=1 (below or equal for unsigned comparison)
        let condition = self.engine.cpu.rflags.contains(Flags::CF)
            || self.engine.cpu.rflags.contains(Flags::ZF);

        // Set the byte operand to 1 if condition is true, 0 if false
        let value = if condition { 1u64 } else { 0u64 };

        // Write only to the low byte of the operand
        match &inst.operands[0] {
            Operand::Register(reg) => {
                // For register operands, we need to preserve the upper bits and only set the low byte
                let current_value = self.engine.cpu.read_reg(*reg);
                let new_value = (current_value & !0xFF) | (value & 0xFF);
                self.engine.cpu.write_reg(*reg, new_value);
                Ok(())
            }
            Operand::Memory { .. } => {
                // For memory operands, write just the byte
                // But we need to use a different approach since write_operand expects full size
                // Let's force the operand to be treated as a byte
                if let Operand::Memory {
                    base,
                    index,
                    scale,
                    displacement,
                    ..
                } = &inst.operands[0]
                {
                    let mut addr = *displacement as u64;
                    if let Some(base_reg) = base {
                        addr = addr.wrapping_add(self.engine.cpu.read_reg(*base_reg));
                    }
                    if let Some(index_reg) = index {
                        addr = addr
                            .wrapping_add(self.engine.cpu.read_reg(*index_reg) * (*scale as u64));
                    }
                    self.mem_write_u8(addr, value as u8)
                } else {
                    Err(EmulatorError::InvalidOperand)
                }
            }
            _ => Err(EmulatorError::InvalidOperand),
        }
    }

    fn execute_setne(&mut self, inst: &Instruction) -> Result<()> {
        // SETNE: Set byte if not equal (ZF=0)
        if inst.operands.len() != 1 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        // Check condition: ZF=0 (not equal)
        let condition = !self.engine.cpu.rflags.contains(Flags::ZF);

        // Set the byte operand to 1 if condition is true, 0 if false
        let value = if condition { 1u64 } else { 0u64 };

        // Write only to the low byte of the operand
        match &inst.operands[0] {
            Operand::Register(reg) => {
                // For register operands, we need to preserve the upper bits and only set the low byte
                let current_value = self.engine.cpu.read_reg(*reg);
                let new_value = (current_value & !0xFF) | (value & 0xFF);
                self.engine.cpu.write_reg(*reg, new_value);
                Ok(())
            }
            Operand::Memory { .. } => {
                // For memory operands, write just the byte using mem_write_u8
                if let Operand::Memory {
                    base,
                    index,
                    scale,
                    displacement,
                    ..
                } = &inst.operands[0]
                {
                    let mut addr = *displacement as u64;
                    if let Some(base_reg) = base {
                        addr = addr.wrapping_add(self.engine.cpu.read_reg(*base_reg));
                    }
                    if let Some(index_reg) = index {
                        addr = addr
                            .wrapping_add(self.engine.cpu.read_reg(*index_reg) * (*scale as u64));
                    }

                    // Apply segment base if segment prefix is present
                    if let Some(segment_reg) = inst.prefix.segment {
                        let segment_base = match segment_reg {
                            Register::CS => self.engine.cpu.segments.cs.base,
                            Register::DS => self.engine.cpu.segments.ds.base,
                            Register::ES => self.engine.cpu.segments.es.base,
                            Register::FS => self.engine.cpu.segments.fs.base,
                            Register::GS => self.engine.cpu.segments.gs.base,
                            Register::SS => self.engine.cpu.segments.ss.base,
                            _ => 0,
                        };
                        addr = addr.wrapping_add(segment_base);
                    }

                    self.mem_write_u8(addr, value as u8)
                } else {
                    Err(EmulatorError::InvalidOperand)
                }
            }
            _ => Err(EmulatorError::InvalidOperand),
        }
    }

    fn execute_cmovae(&mut self, inst: &Instruction) -> Result<()> {
        // CMOVAE: Conditional move if above or equal (CF=0)
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        // Check condition: CF=0 (above or equal for unsigned comparison)
        let condition = !self.engine.cpu.rflags.contains(Flags::CF);

        if condition {
            // Only move if condition is true
            let value = self.read_operand(&inst.operands[1], inst)?;
            self.write_operand(&inst.operands[0], value, inst)?;
        }
        // If condition is false, do nothing (don't modify destination)

        // CMOVAE doesn't affect any flags
        Ok(())
    }

    fn execute_cmovb(&mut self, inst: &Instruction) -> Result<()> {
        // CMOVB: Conditional move if below (CF=1)
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        // Check condition: CF=1 (below for unsigned comparison)
        let condition = self.engine.cpu.rflags.contains(Flags::CF);

        if condition {
            // Only move if condition is true
            let value = self.read_operand(&inst.operands[1], inst)?;
            self.write_operand(&inst.operands[0], value, inst)?;
        }
        // If condition is false, do nothing (don't modify destination)

        // CMOVB doesn't affect any flags
        Ok(())
    }

    fn execute_cmove(&mut self, inst: &Instruction) -> Result<()> {
        // CMOVE: Conditional move if equal (ZF=1)
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        // Check condition: ZF=1 (equal)
        let condition = self.engine.cpu.rflags.contains(Flags::ZF);

        if condition {
            // Only move if condition is true
            let value = self.read_operand(&inst.operands[1], inst)?;
            self.write_operand(&inst.operands[0], value, inst)?;
        }
        // If condition is false, do nothing (don't modify destination)

        // CMOVE doesn't affect any flags
        Ok(())
    }

    fn execute_cmovbe(&mut self, inst: &Instruction) -> Result<()> {
        // CMOVBE: Conditional move if below or equal (CF=1 OR ZF=1)
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        // Check condition: CF=1 OR ZF=1 (below or equal)
        let condition = self.engine.cpu.rflags.contains(Flags::CF)
            || self.engine.cpu.rflags.contains(Flags::ZF);

        if condition {
            // Only move if condition is true
            let value = self.read_operand(&inst.operands[1], inst)?;
            self.write_operand(&inst.operands[0], value, inst)?;
        }
        // If condition is false, do nothing (don't modify destination)

        // CMOVBE doesn't affect any flags
        Ok(())
    }

    fn execute_cmovne(&mut self, inst: &Instruction) -> Result<()> {
        // CMOVNE: Conditional move if not equal (ZF=0)
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        // Check condition: ZF=0 (not equal)
        let condition = !self.engine.cpu.rflags.contains(Flags::ZF);

        if condition {
            // Only move if condition is true
            let value = self.read_operand(&inst.operands[1], inst)?;
            self.write_operand(&inst.operands[0], value, inst)?;
        }
        // If condition is false, do nothing (don't modify destination)

        // CMOVNE doesn't affect any flags
        Ok(())
    }

    fn execute_cmovg(&mut self, inst: &Instruction) -> Result<()> {
        // CMOVG: Conditional move if greater (ZF=0 AND SF=OF)
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        // Check condition: ZF=0 AND SF=OF (greater for signed comparison)
        let zf = self.engine.cpu.rflags.contains(Flags::ZF);
        let sf = self.engine.cpu.rflags.contains(Flags::SF);
        let of = self.engine.cpu.rflags.contains(Flags::OF);
        let condition = !zf && (sf == of);

        if condition {
            // Only move if condition is true
            let value = self.read_operand(&inst.operands[1], inst)?;
            self.write_operand(&inst.operands[0], value, inst)?;
        }
        // If condition is false, do nothing (don't modify destination)

        // CMOVG doesn't affect any flags
        Ok(())
    }

    fn execute_vinsertf128(&mut self, inst: &Instruction) -> Result<()> {
        // VINSERTF128 ymm1, ymm2, xmm3/m128, imm8
        // Insert 128-bit float values from xmm3/m128 into ymm2 at position specified by imm8
        // Store result in ymm1
        if inst.operands.len() != 4 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        // Get the destination YMM register
        let dst_ymm = if let Operand::Register(reg) = &inst.operands[0] {
            if !reg.is_ymm() {
                return Err(EmulatorError::InvalidInstruction(inst.address));
            }
            *reg
        } else {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        };

        // Get the source YMM register (first source)
        let src1_value = if let Operand::Register(reg) = &inst.operands[1] {
            if reg.is_ymm() {
                self.engine.cpu.read_ymm(*reg)
            } else if reg.is_xmm() {
                // If source is XMM, treat as lower half of YMM
                [self.engine.cpu.read_xmm(*reg), 0]
            } else {
                return Err(EmulatorError::InvalidInstruction(inst.address));
            }
        } else {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        };

        // Get the second source (128-bit XMM or memory)
        let src2_value = if let Operand::Register(reg) = &inst.operands[2] {
            if reg.is_xmm() {
                self.engine.cpu.read_xmm(*reg)
            } else {
                return Err(EmulatorError::InvalidInstruction(inst.address));
            }
        } else {
            // Memory operand - read 128 bits
            self.read_xmm_operand(&inst.operands[2])?
        };

        // Get the immediate value (position selector)
        let imm = if let Operand::Immediate(val) = &inst.operands[3] {
            *val as u8
        } else {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        };

        // Perform the insertion based on the immediate value
        let mut result = src1_value;
        match imm & 1 {
            // Only bit 0 is significant for VINSERTF128
            0 => {
                // Insert into lower 128 bits (bits 127:0)
                result[0] = src2_value;
            }
            1 => {
                // Insert into upper 128 bits (bits 255:128)
                result[1] = src2_value;
            }
            _ => unreachable!(),
        }

        // Store result in destination YMM register
        self.engine.cpu.write_ymm(dst_ymm, result);
        Ok(())
    }

    fn execute_vzeroupper(&mut self, inst: &Instruction) -> Result<()> {
        // VZEROUPPER - Zero upper bits of all YMM registers
        // This sets the upper 128 bits (bits 255:128) of all YMM registers to zero
        // The lower 128 bits (which correspond to XMM registers) are left unchanged
        if !inst.operands.is_empty() {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        // Zero the upper 128 bits of all YMM registers (YMM0-YMM15)
        for i in 0..16 {
            let mut ymm_value = self.engine.cpu.ymm_regs[i];
            ymm_value[1] = 0; // Clear upper 128 bits, keep lower 128 bits
            self.engine.cpu.ymm_regs[i] = ymm_value;
        }

        Ok(())
    }

    fn execute_movdqa(&mut self, inst: &Instruction) -> Result<()> {
        // MOVDQA - Move Aligned Double Quadword
        // This is identical to MOVUPS but requires alignment (we'll treat it the same for simplicity)
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        let value = self.read_xmm_operand(&inst.operands[1])?;
        self.write_xmm_operand(&inst.operands[0], value)?;
        Ok(())
    }

    fn execute_bsr(&mut self, inst: &Instruction) -> Result<()> {
        // BSR - Bit Scan Reverse (find most significant bit set)
        if inst.operands.len() != 2 {
            return Err(EmulatorError::InvalidInstruction(inst.address));
        }

        let src_value = self.read_operand(&inst.operands[1], inst)?;

        if src_value == 0 {
            // If source is zero, set ZF and destination is undefined
            self.engine.cpu.rflags.set(Flags::ZF, true);
            // Leave destination register unchanged (undefined behavior)
        } else {
            // Find the most significant bit set (0-based from right)
            let bit_pos = 63 - src_value.leading_zeros() as u64;

            // Clear ZF to indicate bit was found
            self.engine.cpu.rflags.set(Flags::ZF, false);

            // Store bit position in destination
            self.write_operand(&inst.operands[0], bit_pos, inst)?;
        }

        // BSR only affects ZF flag, other flags are undefined
        Ok(())
    }
}
