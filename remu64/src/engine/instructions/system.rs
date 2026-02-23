use crate::engine::ExecutionContext;
use crate::error::{EmulatorError, Result};
use crate::memory::MemoryTrait;
use crate::{HookManager, Register};
use iced_x86::{Instruction, OpKind, Register as IcedRegister};

impl<H: HookManager<M, PS>, M: MemoryTrait<PS>, const PS: u64> ExecutionContext<'_, H, M, PS> {
    pub(crate) fn execute_cpuid(&mut self, _inst: &Instruction) -> Result<()> {
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

    pub(crate) fn execute_rdtsc(&mut self, _inst: &Instruction) -> Result<()> {
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

    pub(crate) fn execute_rdtscp(&mut self, _inst: &Instruction) -> Result<()> {
        // RDTSCP: Read Time-Stamp Counter and Processor ID
        // Like RDTSC but also returns processor ID in ECX

        // First do the same as RDTSC
        self.execute_rdtsc(_inst)?;

        // Additionally, set ECX to processor ID (we'll use 0 for simplicity)
        let rcx = self.engine.cpu.read_reg(Register::RCX) & 0xFFFFFFFF00000000;
        self.engine.cpu.write_reg(Register::RCX, rcx);

        Ok(())
    }

    pub(crate) fn execute_int(&mut self, inst: &Instruction) -> Result<()> {
        // INT: Software Interrupt
        let intno = self.read_operand(inst, 0)?;

        // Call interrupt hook
        self.hooks.on_interrupt(self.engine, intno, inst.len())?;

        // In a real system, this would trigger an interrupt handler
        // For emulation, we just call the hook and continue
        // The hook implementation can decide what to do (e.g., emulate syscalls)

        Ok(())
    }

    pub(crate) fn execute_int3(&mut self, inst: &Instruction) -> Result<()> {
        // INT3: Breakpoint (single-byte INT 3)
        // Call interrupt hook with interrupt number 3
        self.hooks.on_interrupt(self.engine, 3, inst.len())?;

        // INT3 is typically used for debugging breakpoints
        // The debugger/hook can decide how to handle it

        Ok(())
    }

    pub(crate) fn execute_syscall(&mut self, inst: &Instruction) -> Result<()> {
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
        self.hooks.on_interrupt(self.engine, 0x80, inst.len())?;

        // Note: The actual kernel entry point would be loaded from MSR registers
        // For emulation purposes, the hook handles the syscall and we continue

        Ok(())
    }

    pub(crate) fn execute_mfence(&mut self, _inst: &Instruction) -> Result<()> {
        // MFENCE: Memory Fence
        // Serializes all load and store operations that occurred prior to the MFENCE instruction
        // In emulation, this is essentially a no-op since we're single-threaded
        // But for completeness, we could flush any pending memory operations here

        // In a real CPU, this ensures:
        // - All loads and stores before the fence are globally visible before any after
        // - Used for strong memory ordering guarantees

        Ok(())
    }

    pub(crate) fn execute_sfence(&mut self, _inst: &Instruction) -> Result<()> {
        // SFENCE: Store Fence
        // Serializes all store operations that occurred prior to the SFENCE instruction
        // Stores before SFENCE are guaranteed to be globally visible before stores after

        // In emulation, this is a no-op since we execute instructions sequentially
        // In real hardware, ensures store ordering for weakly-ordered memory types

        Ok(())
    }

    pub(crate) fn execute_lfence(&mut self, _inst: &Instruction) -> Result<()> {
        // LFENCE: Load Fence
        // Serializes all load operations that occurred prior to the LFENCE instruction
        // Loads before LFENCE are guaranteed to be globally visible before loads after

        // In emulation, this is a no-op since we execute instructions sequentially
        // In real hardware, ensures load ordering and can prevent speculative execution

        Ok(())
    }

    pub(crate) fn execute_clflush(&mut self, inst: &Instruction) -> Result<()> {
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
            return Err(EmulatorError::InvalidArgument(
                "CLFLUSH requires exactly one operand".to_string(),
            ));
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

    pub(crate) fn execute_fnstcw(&mut self, inst: &Instruction) -> Result<()> {
        // FNSTCW: Store x87 FPU Control Word
        // Stores the current value of the FPU control word to the specified memory location
        // Format: FNSTCW m16

        if inst.op_count() != 1 {
            return Err(EmulatorError::UnsupportedInstruction(
                "FNSTCW requires exactly 1 operand".to_string(),
            ));
        }

        match inst.op_kind(0) {
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 0)?;

                // Default x87 FPU control word value
                // Bit 0-1: Exception masks (precision control)
                // Bit 2-3: Rounding control (00 = round to nearest)
                // Bit 4-5: Precision control (11 = 64-bit precision)
                // Bit 6-11: Exception mask bits (all masked = 1)
                // Standard default value is 0x037F
                let fpu_control_word: u16 = 0x037F;

                // Store as 16-bit value
                self.write_memory_sized(addr, fpu_control_word as u64, 2)?;
                Ok(())
            }
            _ => Err(EmulatorError::UnsupportedInstruction(
                "FNSTCW requires memory operand".to_string(),
            )),
        }
    }

    pub(crate) fn execute_fidivr(&mut self, inst: &Instruction) -> Result<()> {
        // FIDIVR: Reverse Divide Integer
        // Divides the source integer operand by ST(0) and stores the result in ST(0)
        // ST(0) = m16int / ST(0)  or  ST(0) = m32int / ST(0)
        // Format: FIDIVR m16int or FIDIVR m32int

        if inst.op_count() < 1 {
            return Err(EmulatorError::UnsupportedInstruction(
                "FIDIVR requires at least 1 operand".to_string(),
            ));
        }

        match inst.op_kind(0) {
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 0)?;
                let mem_size = inst.memory_size().size();

                // Read integer from memory and convert to f64
                let int_value: f64 = match mem_size {
                    2 => {
                        // 16-bit signed integer (word)
                        let mut buf = [0u8; 2];
                        self.mem_read_with_hooks(addr, &mut buf)?;
                        i16::from_le_bytes(buf) as f64
                    }
                    4 => {
                        // 32-bit signed integer (dword)
                        let mut buf = [0u8; 4];
                        self.mem_read_with_hooks(addr, &mut buf)?;
                        i32::from_le_bytes(buf) as f64
                    }
                    _ => {
                        return Err(EmulatorError::UnsupportedInstruction(format!(
                            "FIDIVR unsupported memory size: {}",
                            mem_size
                        )));
                    }
                };

                // Read ST(0)
                let st0 = self.engine.cpu.fpu.read_st(0);

                // Compute: int_value / ST(0)
                let result = int_value / st0;

                // Store result back to ST(0)
                self.engine.cpu.fpu.write_st(0, result);

                Ok(())
            }
            _ => Err(EmulatorError::UnsupportedInstruction(
                "FIDIVR requires memory operand".to_string(),
            )),
        }
    }

    pub(crate) fn execute_stmxcsr(&mut self, inst: &Instruction) -> Result<()> {
        // STMXCSR: Store SSE Control and Status Register (MXCSR)
        // Stores the current value of the MXCSR register to the specified memory location
        // Format: STMXCSR m32

        if inst.op_count() != 1 {
            return Err(EmulatorError::UnsupportedInstruction(
                "STMXCSR requires exactly 1 operand".to_string(),
            ));
        }

        match inst.op_kind(0) {
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 0)?;

                // Default MXCSR value
                // Bit 0-5: Exception flags (sticky)
                // Bit 6: Denormals are zeros
                // Bit 7-12: Exception mask bits (all masked = 1)
                // Bit 13-14: Rounding control (00 = round to nearest)
                // Bit 15: Flush to zero
                // Standard default value is 0x1F80 (all exceptions masked, round to nearest)
                let mxcsr_value: u32 = 0x1F80;

                // Store as 32-bit value
                self.write_memory_sized(addr, mxcsr_value as u64, 4)?;
                Ok(())
            }
            _ => Err(EmulatorError::UnsupportedInstruction(
                "STMXCSR requires memory operand".to_string(),
            )),
        }
    }

    pub(crate) fn execute_rdsspq(&mut self, inst: &Instruction) -> Result<()> {
        // RDSSPQ: Read Shadow Stack Pointer (64-bit)
        // CET (Control-flow Enforcement Technology) instruction
        // Reads the current shadow stack pointer and stores it in the destination register
        // Format: RDSSPQ reg64

        if inst.op_count() != 1 {
            return Err(EmulatorError::UnsupportedInstruction(
                "RDSSPQ requires exactly 1 operand".to_string(),
            ));
        }

        match inst.op_kind(0) {
            OpKind::Register => {
                let dst_reg = self.convert_register(inst.op_register(0))?;

                // In emulation, we don't have a real shadow stack
                // For compatibility, we'll return a reasonable dummy value
                // Typically this would be close to but separate from the main stack
                let rsp = self.engine.cpu.read_reg(Register::RSP);
                let shadow_stack_ptr = rsp.wrapping_add(0x10000); // Offset from main stack

                self.engine.cpu.write_reg(dst_reg, shadow_stack_ptr);
                Ok(())
            }
            _ => Err(EmulatorError::UnsupportedInstruction(
                "RDSSPQ requires register operand".to_string(),
            )),
        }
    }

    pub(crate) fn execute_endbr64(&mut self, _inst: &Instruction) -> Result<()> {
        // ENDBR64: End Branch 64-bit
        // CET (Control-flow Enforcement Technology) instruction
        // This is a landing pad instruction for indirect branches and calls
        // In emulation, this is effectively a no-op since we don't enforce CET
        // The instruction serves as a valid target for indirect control flow transfers

        // No registers or flags are affected by this instruction
        // It simply marks a valid landing point for indirect jumps/calls

        Ok(())
    }

    pub(crate) fn execute_fxrstor(&mut self, inst: &Instruction) -> Result<()> {
        // FXRSTOR: Restore x87 FPU, MMX, XMM, and MXCSR register state from memory
        // Restores the x87 FPU, MMX, XMM, and MXCSR registers from a 512-byte memory area
        // Format: FXRSTOR m512byte

        if inst.op_count() != 1 {
            return Err(EmulatorError::UnsupportedInstruction(
                "FXRSTOR requires exactly 1 operand".to_string(),
            ));
        }

        match inst.op_kind(0) {
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 0)?;

                // FXRSTOR memory layout (512 bytes total):
                // Bytes 0-1: FCW (FPU Control Word)
                // Bytes 2-3: FSW (FPU Status Word)
                // Byte 4: FTW (FPU Tag Word)
                // Byte 5: Reserved
                // Bytes 6-7: FOP (FPU Opcode)
                // Bytes 8-15: FPU IP (Instruction Pointer)
                // Bytes 16-23: FPU DP (Data Pointer)
                // Bytes 24-27: MXCSR
                // Bytes 28-31: MXCSR_MASK
                // Bytes 32-159: ST0-ST7 (x87 registers, 16 bytes each)
                // Bytes 160-287: XMM0-XMM7 (16 bytes each)
                // Bytes 288-511: XMM8-XMM15 (16 bytes each, x86-64 only)

                // For emulation purposes, we focus on the key registers that affect execution:
                // - MXCSR (SSE control/status register)
                // - XMM registers (XMM0-XMM15)

                // Read MXCSR from offset 24
                let _mxcsr = self.read_memory_32(addr + 24)?;
                // For emulation, we don't need to actually restore MXCSR as we use default behavior

                // Restore XMM0-XMM7 (160 bytes offset, 16 bytes each)
                for i in 0..8 {
                    let xmm_addr = addr + 160 + (i * 16);
                    let xmm_value = self.read_memory_128(xmm_addr)?;
                    let xmm_reg = match i {
                        0 => Register::XMM0,
                        1 => Register::XMM1,
                        2 => Register::XMM2,
                        3 => Register::XMM3,
                        4 => Register::XMM4,
                        5 => Register::XMM5,
                        6 => Register::XMM6,
                        7 => Register::XMM7,
                        _ => unreachable!(),
                    };
                    self.engine.cpu.write_xmm(xmm_reg, xmm_value);
                }

                // Restore XMM8-XMM15 (288 bytes offset, 16 bytes each) - x86-64 only
                for i in 0..8 {
                    let xmm_addr = addr + 288 + (i * 16);
                    let xmm_value = self.read_memory_128(xmm_addr)?;
                    let xmm_reg = match i {
                        0 => Register::XMM8,
                        1 => Register::XMM9,
                        2 => Register::XMM10,
                        3 => Register::XMM11,
                        4 => Register::XMM12,
                        5 => Register::XMM13,
                        6 => Register::XMM14,
                        7 => Register::XMM15,
                        _ => unreachable!(),
                    };
                    self.engine.cpu.write_xmm(xmm_reg, xmm_value);
                }

                // Note: We skip restoring x87 FPU state (ST0-ST7) and MMX registers
                // as they're less commonly used and more complex to emulate properly.
                // The XMM register restoration is the most important for modern code.

                Ok(())
            }
            _ => Err(EmulatorError::UnsupportedInstruction(
                "FXRSTOR requires memory operand".to_string(),
            )),
        }
    }

    pub(crate) fn execute_kmovd(&mut self, inst: &Instruction) -> Result<()> {
        // KMOVD: Move 32-bit mask register value
        // Format: KMOVD r32, k
        //         KMOVD k, r32
        //         KMOVD k, m32
        //         KMOVD m32, k

        if inst.op_count() != 2 {
            return Err(EmulatorError::UnsupportedInstruction(
                "KMOVD requires exactly 2 operands".to_string(),
            ));
        }

        // Determine direction based on operand types
        match (inst.op_kind(0), inst.op_kind(1)) {
            // KMOVD r32, k - Move from mask register to general register
            (OpKind::Register, OpKind::Register) => {
                let dst_iced_reg = inst.op_register(0);
                let src_iced_reg = inst.op_register(1);

                // Check if source is mask register and destination is general register
                if src_iced_reg.is_k() {
                    let src_reg = self.convert_register(src_iced_reg)?;
                    let dst_reg = self.convert_register(dst_iced_reg)?;

                    // Read from mask register (K0-K7)
                    let mask_value = self.engine.cpu.read_reg(src_reg);

                    // Write to general register (only lower 32 bits for KMOVD)
                    // Zero-extend to 64 bits for 64-bit registers
                    let value_32 = (mask_value & 0xFFFFFFFF) as u32;
                    self.engine.cpu.write_reg(dst_reg, value_32 as u64);
                } else if dst_iced_reg.is_k() {
                    // KMOVD k, r32 - Move from general register to mask register
                    let dst_reg = self.convert_register(dst_iced_reg)?;
                    let src_reg = self.convert_register(src_iced_reg)?;

                    // Read from general register (only lower 32 bits)
                    let src_value = self.engine.cpu.read_reg(src_reg);
                    let value_32 = (src_value & 0xFFFFFFFF) as u32;

                    // Write to mask register
                    self.engine.cpu.write_reg(dst_reg, value_32 as u64);
                } else {
                    return Err(EmulatorError::UnsupportedInstruction(
                        "KMOVD requires one operand to be a mask register".to_string(),
                    ));
                }
            }
            // KMOVD k, m32 - Move from memory to mask register
            (OpKind::Register, OpKind::Memory) => {
                let dst_iced_reg = inst.op_register(0);
                if !dst_iced_reg.is_k() {
                    return Err(EmulatorError::UnsupportedInstruction(
                        "KMOVD destination must be a mask register for memory source".to_string(),
                    ));
                }

                let dst_reg = self.convert_register(dst_iced_reg)?;
                let addr = self.calculate_memory_address(inst, 1)?;

                // Read 32-bit value from memory
                let value = self.read_memory_32(addr)? as u64;

                // Write to mask register
                self.engine.cpu.write_reg(dst_reg, value);
            }
            // KMOVD m32, k - Move from mask register to memory
            (OpKind::Memory, OpKind::Register) => {
                let src_iced_reg = inst.op_register(1);
                if !src_iced_reg.is_k() {
                    return Err(EmulatorError::UnsupportedInstruction(
                        "KMOVD source must be a mask register for memory destination".to_string(),
                    ));
                }

                let src_reg = self.convert_register(src_iced_reg)?;
                let addr = self.calculate_memory_address(inst, 0)?;

                // Read from mask register (only lower 32 bits)
                let mask_value = self.engine.cpu.read_reg(src_reg);
                let value_32 = (mask_value & 0xFFFFFFFF) as u32;

                // Write to memory
                self.write_memory_sized(addr, value_32 as u64, 4)?;
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Unsupported KMOVD operand combination".to_string(),
                ));
            }
        }

        Ok(())
    }

    pub(crate) fn execute_xsavec64(&mut self, inst: &Instruction) -> Result<()> {
        // XSAVEC64: Save Processor Extended States with Compaction (64-bit)
        // Saves the state components specified by EDX:EAX to memory in compacted format
        // Format: XSAVEC64 mem

        match inst.op_kind(0) {
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 0)?;

                // Read the request mask from EDX:EAX
                let eax = self.engine.cpu.read_reg(Register::RAX) as u32;
                let edx = self.engine.cpu.read_reg(Register::RDX) as u32;
                let requested_features = ((edx as u64) << 32) | (eax as u64);

                // XSAVE area layout:
                // Bytes 0-1: FCW (FPU Control Word)
                // Bytes 2-3: FSW (FPU Status Word)
                // Byte 4: FTW (FPU Tag Word - abridged)
                // Byte 5: Reserved
                // Bytes 6-7: FOP (FPU Opcode)
                // Bytes 8-15: FPU IP (Instruction Pointer)
                // Bytes 16-23: FPU DP (Data Pointer)
                // Bytes 24-27: MXCSR
                // Bytes 28-31: MXCSR_MASK
                // Bytes 32-159: ST0-ST7 / MM0-MM7 (x87/MMX registers, 16 bytes each)
                // Bytes 160-415: XMM0-XMM15 (16 bytes each)
                // Bytes 416-511: Reserved
                // Bytes 512-519: XSTATE_BV (which state components are present)
                // Bytes 520-527: XCOMP_BV (compaction vector, bit 63 = compaction mode)
                // Bytes 528-575: Reserved header space

                // For XSAVEC, the compaction bit (bit 63 of XCOMP_BV) is always set
                // State components requested via EDX:EAX are saved

                // Track which components we actually save
                let mut xstate_bv: u64 = 0;

                // Component 0: x87 FPU state (bits 0-159)
                if requested_features & 1 != 0 {
                    // Save x87 FPU control word at offset 0
                    let fpu_control_word: u16 = 0x037F; // Default value
                    self.write_memory_sized(addr, fpu_control_word as u64, 2)?;

                    // Save FPU status word at offset 2
                    self.write_memory_sized(addr + 2, 0, 2)?;

                    // Save FPU tag word (abridged) at offset 4
                    self.write_memory_sized(addr + 4, 0xFF, 1)?; // All registers empty

                    // FOP at offset 6
                    self.write_memory_sized(addr + 6, 0, 2)?;

                    // FPU IP at offset 8 (8 bytes)
                    self.write_memory_sized(addr + 8, 0, 8)?;

                    // FPU DP at offset 16 (8 bytes)
                    self.write_memory_sized(addr + 16, 0, 8)?;

                    // Note: ST0-ST7 at offset 32-159 are left at their current memory values
                    // In a full implementation, we would save the x87 register stack here

                    xstate_bv |= 1;
                }

                // Component 1: SSE state (MXCSR and XMM registers)
                if requested_features & 2 != 0 {
                    // Save MXCSR at offset 24
                    let mxcsr: u32 = 0x1F80; // Default value (all exceptions masked)
                    self.write_memory_sized(addr + 24, mxcsr as u64, 4)?;

                    // Save MXCSR_MASK at offset 28
                    self.write_memory_sized(addr + 28, 0xFFFF, 4)?;

                    // Save XMM0-XMM15 at offsets 160-415 (16 bytes each)
                    let xmm_registers = [
                        Register::XMM0,
                        Register::XMM1,
                        Register::XMM2,
                        Register::XMM3,
                        Register::XMM4,
                        Register::XMM5,
                        Register::XMM6,
                        Register::XMM7,
                        Register::XMM8,
                        Register::XMM9,
                        Register::XMM10,
                        Register::XMM11,
                        Register::XMM12,
                        Register::XMM13,
                        Register::XMM14,
                        Register::XMM15,
                    ];

                    for (i, &xmm_reg) in xmm_registers.iter().enumerate() {
                        let xmm_value = self.engine.cpu.read_xmm(xmm_reg);
                        let xmm_addr = addr + 160 + (i as u64 * 16);
                        self.write_memory_128(xmm_addr, xmm_value)?;
                    }

                    xstate_bv |= 2;
                }

                // Write XSAVE header (bytes 512-575)
                // XSTATE_BV at offset 512 (8 bytes) - indicates which components are present
                self.write_memory_sized(addr + 512, xstate_bv, 8)?;

                // XCOMP_BV at offset 520 (8 bytes) - compaction vector
                // Bit 63 = 1 indicates compacted format (XSAVEC)
                // Lower bits indicate which components are in the compacted area
                let xcomp_bv: u64 = (1u64 << 63) | xstate_bv;
                self.write_memory_sized(addr + 520, xcomp_bv, 8)?;

                // Reserved bytes 528-575 should be cleared
                for i in 0..6 {
                    self.write_memory_sized(addr + 528 + (i * 8), 0, 8)?;
                }

                Ok(())
            }
            _ => Err(EmulatorError::UnsupportedInstruction(
                "XSAVEC64 requires memory operand".to_string(),
            )),
        }
    }

    pub(crate) fn execute_xrstor64(&mut self, inst: &Instruction) -> Result<()> {
        // XRSTOR64: Restore Processor Extended States (64-bit)
        // Restores state components specified by EDX:EAX from memory
        // Format: XRSTOR64 mem

        match inst.op_kind(0) {
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 0)?;

                // Read the request mask from EDX:EAX
                let eax = self.engine.cpu.read_reg(Register::RAX) as u32;
                let edx = self.engine.cpu.read_reg(Register::RDX) as u32;
                let requested_features = ((edx as u64) << 32) | (eax as u64);

                // Read XSTATE_BV from header to see which components are actually present
                let xstate_bv = self.read_memory_64(addr + 512)?;

                // Component 0: x87 FPU state
                if requested_features & 1 != 0 && xstate_bv & 1 != 0 {
                    // x87 state is present and requested - restore it
                    // For emulation, we don't track full x87 state, so this is mostly a no-op
                    // A full implementation would restore FCW, FSW, FTW, FOP, FIP, FDP, ST0-ST7
                }

                // Component 1: SSE state (MXCSR and XMM registers)
                if requested_features & 2 != 0 && xstate_bv & 2 != 0 {
                    // Restore XMM0-XMM15 from offsets 160-415 (16 bytes each)
                    let xmm_registers = [
                        Register::XMM0,
                        Register::XMM1,
                        Register::XMM2,
                        Register::XMM3,
                        Register::XMM4,
                        Register::XMM5,
                        Register::XMM6,
                        Register::XMM7,
                        Register::XMM8,
                        Register::XMM9,
                        Register::XMM10,
                        Register::XMM11,
                        Register::XMM12,
                        Register::XMM13,
                        Register::XMM14,
                        Register::XMM15,
                    ];

                    for (i, &xmm_reg) in xmm_registers.iter().enumerate() {
                        let xmm_addr = addr + 160 + (i as u64 * 16);
                        let xmm_value = self.read_memory_128(xmm_addr)?;
                        self.engine.cpu.write_xmm(xmm_reg, xmm_value);
                    }
                }

                Ok(())
            }
            _ => Err(EmulatorError::UnsupportedInstruction(
                "XRSTOR64 requires memory operand".to_string(),
            )),
        }
    }
}
