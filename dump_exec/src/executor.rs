use crate::fastcall::{ArgumentType, CallingConvention};
use crate::memory_manager::MemoryManager;
use crate::minidump_loader::MinidumpLoader;
use crate::tracer::InstructionTracer;
use amd64_emu::{EmulatorError, Engine, EngineMode, Permission, Register};
use anyhow::{Context, Result};
use iced_x86::Formatter;

pub struct FunctionExecutor<'a> {
    engine: Engine<'a>,
    memory_manager: MemoryManager,
    stack_base: u64,
    tracer: InstructionTracer,
}

impl<'a> FunctionExecutor<'a> {
    pub fn new(minidump_loader: MinidumpLoader) -> Result<Self> {
        let mut engine = Engine::new(EngineMode::Mode64);
        let mut memory_manager = MemoryManager::with_minidump(minidump_loader);

        let stack_base = memory_manager
            .allocate_stack(0x10000)
            .context("Failed to allocate stack")?;

        // Map stack memory in engine
        engine
            .mem_map(stack_base - 0x10000, 0x10000, Permission::ALL)
            .context("Failed to map stack memory")?;

        let tracer = InstructionTracer::new(false);

        let mut executor = FunctionExecutor {
            engine,
            memory_manager,
            stack_base,
            tracer,
        };

        // Set up memory fault hook for automatic minidump loading
        executor.setup_memory_fault_hook()?;

        Ok(executor)
    }

    pub fn execute_function(
        &mut self,
        function_address: u64,
        args: Vec<ArgumentType>,
    ) -> Result<()> {
        let return_address = 0xdeadbeef;

        // Setup calling convention
        CallingConvention::setup_fastcall(&mut self.engine, args, self.stack_base, return_address)?;

        CallingConvention::setup_shadow_space(&mut self.engine)?;

        // Set RIP to function start
        self.engine.reg_write(Register::RIP, function_address)?;

        // Execute instruction by instruction
        let mut instruction_count = 0;
        let max_instructions = 1000000;

        loop {
            if instruction_count >= max_instructions {
                anyhow::bail!("Execution exceeded maximum instruction count");
            }

            let rip = self.engine.reg_read(Register::RIP)?;

            // Check for return
            if rip == return_address {
                if self.tracer.is_enabled() {
                    let rax = self.engine.reg_read(Register::RAX)?;
                    self.tracer.trace_return(return_address, rax)?;
                }
                break;
            }

            // Read instruction bytes
            let instruction_bytes = self.read_instruction_at(rip)?;

            // Trace before execution
            if self.tracer.is_enabled() {
                self.tracer.trace_instruction(
                    rip,
                    &instruction_bytes,
                    &self.engine,
                    Some(self.memory_manager.get_loader()),
                )?;
            }

            // Execute single instruction
            match self.engine.emu_start(rip, rip + 15, 0, 1) {
                Ok(()) => {}
                Err(EmulatorError::UnmappedMemory(addr)) => {
                    // Try to handle memory fault by loading from minidump
                    if self.handle_memory_fault(addr, 8).unwrap_or(false) {
                        // Retry the instruction after loading memory
                        if let Err(e) = self.engine.emu_start(rip, rip + 15, 0, 1) {
                            self.report_instruction_error(rip, &instruction_bytes, e)?;
                        }
                    } else {
                        self.report_instruction_error(
                            rip,
                            &instruction_bytes,
                            EmulatorError::UnmappedMemory(addr),
                        )?;
                    }
                }
                Err(e) => {
                    self.report_instruction_error(rip, &instruction_bytes, e)?;
                }
            }

            instruction_count += 1;
        }

        if self.tracer.is_enabled() {
            println!("\n[TRACE] Executed {} instructions", instruction_count);
        }

        Ok(())
    }

    fn read_instruction_at(&mut self, address: u64) -> Result<Vec<u8>> {
        // Ensure memory is mapped
        self.ensure_memory_mapped(address)?;

        // Read up to 15 bytes for the instruction (max x86-64 instruction length)
        let mut instruction_bytes = vec![0u8; 15];
        self.engine.mem_read(address, &mut instruction_bytes)?;
        Ok(instruction_bytes)
    }

    fn ensure_memory_mapped(&mut self, address: u64) -> Result<()> {
        let page_base = address & !0xfff;

        // NEVER map the null page (address 0) - this should always be unmapped
        if page_base == 0 {
            anyhow::bail!(
                "Attempt to access null page at address 0x{:x} - this should never be mapped",
                address
            );
        }

        // Try to read from minidump and map it
        if let Ok(page_data) = self.memory_manager.read_memory(page_base, 4096) {
            // Map the page if not already mapped
            if self
                .engine
                .mem_map(page_base, 4096, Permission::ALL)
                .is_ok()
            {
                self.engine.mem_write(page_base, &page_data)?;
            }
        }
        Ok(())
    }

    pub fn get_return_value(&self) -> Result<u64> {
        Ok(self.engine.reg_read(Register::RAX)?)
    }

    pub fn get_engine(&self) -> &Engine {
        &self.engine
    }

    pub fn get_engine_mut(&mut self) -> &mut Engine<'a> {
        &mut self.engine
    }

    pub fn read_memory(&mut self, address: u64, size: usize) -> Result<Vec<u8>> {
        self.memory_manager.read_memory(address, size)
    }

    pub fn write_memory(&mut self, address: u64, data: &[u8]) -> Result<()> {
        self.memory_manager.write_memory(address, data)
    }

    pub fn set_register(&mut self, register: Register, value: u64) -> Result<()> {
        Ok(self.engine.reg_write(register, value)?)
    }

    pub fn get_register(&self, register: Register) -> Result<u64> {
        Ok(self.engine.reg_read(register)?)
    }

    pub fn enable_tracing(&mut self, enabled: bool) {
        self.tracer.set_enabled(enabled);
    }

    pub fn enable_full_trace(&mut self, enabled: bool) {
        self.tracer.set_full_trace(enabled);
    }

    pub fn is_tracing_enabled(&self) -> bool {
        self.tracer.is_enabled()
    }

    pub fn get_instruction_count(&self) -> usize {
        self.tracer.get_instruction_count()
    }

    fn setup_memory_fault_hook(&mut self) -> Result<()> {
        // For now, we'll handle memory faults in the mem_read override
        // The engine's hook system will call back to handle_memory_fault
        // when an unmapped memory access occurs
        Ok(())
    }

    pub fn handle_memory_fault(&mut self, address: u64, _size: usize) -> Result<bool> {
        // Try to load the missing memory page from the minidump
        self.ensure_memory_mapped(address)?;
        Ok(true) // Indicate we handled the fault
    }

    fn report_instruction_error(
        &self,
        rip: u64,
        instruction_bytes: &[u8],
        e: EmulatorError,
    ) -> Result<()> {
        // Enhanced error reporting with instruction details
        let instruction_len = if !instruction_bytes.is_empty() {
            // Try to decode to get actual length
            let mut decoder = iced_x86::Decoder::with_ip(
                64,
                instruction_bytes,
                rip,
                iced_x86::DecoderOptions::NONE,
            );
            let mut instruction = iced_x86::Instruction::default();
            decoder.decode_out(&mut instruction);
            instruction.len()
        } else {
            1
        };

        let actual_bytes = &instruction_bytes[..instruction_len.min(instruction_bytes.len())];
        let hex_bytes = actual_bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");

        // Try to disassemble for better error reporting
        let disasm = if !actual_bytes.is_empty() {
            let mut decoder =
                iced_x86::Decoder::with_ip(64, actual_bytes, rip, iced_x86::DecoderOptions::NONE);
            let mut instruction = iced_x86::Instruction::default();
            decoder.decode_out(&mut instruction);
            let mut formatter = iced_x86::IntelFormatter::new();
            let mut output = String::new();
            formatter.format(&instruction, &mut output);
            output
        } else {
            "<unable to decode>".to_string()
        };

        // Check if RIP is in a known module
        let module_info = self
            .memory_manager
            .get_loader()
            .find_module_for_address(rip);
        let address_str = match module_info {
            Some((module_name, _base, offset)) => {
                format!("0x{:016x} ({}+0x{:x})", rip, module_name, offset)
            }
            None => format!("0x{:016x}", rip),
        };

        anyhow::bail!(
            "Emulation failed at {}: {} [{}] ({} bytes)\nOriginal error: {}",
            address_str,
            disasm,
            hex_bytes,
            instruction_len,
            e
        )
    }
}

#[derive(Debug)]
pub struct ExecutionContext {
    pub function_address: u64,
    pub return_value: u64,
    pub instruction_count: usize,
    pub execution_time_ms: u64,
}

impl ExecutionContext {
    pub fn new(function_address: u64) -> Self {
        ExecutionContext {
            function_address,
            return_value: 0,
            instruction_count: 0,
            execution_time_ms: 0,
        }
    }
}
