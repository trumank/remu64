use crate::fastcall::{ArgumentType, CallingConvention};
use crate::memory_manager::MemoryManager;
use crate::minidump_loader::MinidumpLoader;
use crate::tracer::InstructionTracer;
use amd64_emu::{EmulatorError, Engine, EngineMode, HookManager, HookType, Permission, Register};
use anyhow::{Context, Result};
use iced_x86::Formatter;
use std::sync::{Arc, Mutex};

pub struct FunctionExecutor {
    engine: Engine,
    memory_manager: MemoryManager,
    stack_base: u64,
    tracer: InstructionTracer,
}

impl FunctionExecutor {
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

        // Create hooks for memory fault handling and instruction tracing
        let mut hooks = HookManager::new();

        // Shared state for instruction counting and tracing
        let instruction_count = Arc::new(Mutex::new(0u64));
        let max_instructions = 1000000u64;

        // Setup memory fault hook - we'll handle the actual memory mapping
        // outside the hook to avoid unsafe pointer usage
        let fault_addresses = Arc::new(Mutex::new(Vec::<u64>::new()));
        let fault_addresses_clone = fault_addresses.clone();

        hooks.add_hook(
            HookType::MemFault,
            0,
            u64::MAX,
            move |_cpu, address, _size| {
                let page_base = address & !0xfff;

                // NEVER map the null page (address 0)
                if page_base == 0 {
                    return Ok(()); // Don't handle null page faults
                }

                // Record the fault address for handling outside the hook
                fault_addresses_clone.lock().unwrap().push(page_base);
                Ok(()) // Indicate we will handle this fault
            },
        );

        // Setup code hook for instruction counting and return detection
        let count_clone = instruction_count.clone();
        let tracer_enabled = self.tracer.is_enabled();
        let instruction_addresses = Arc::new(Mutex::new(Vec::<u64>::new()));
        let instruction_addresses_clone = instruction_addresses.clone();

        hooks.add_hook(HookType::Code, 0, u64::MAX, move |_cpu, address, _size| {
            // Record instruction for tracing outside the hook
            if tracer_enabled {
                instruction_addresses_clone.lock().unwrap().push(address);
            }

            // Check instruction count limit
            {
                let mut count = count_clone.lock().unwrap();
                *count += 1;
                if *count > max_instructions {
                    return Err(EmulatorError::UnsupportedInstruction(
                        "Execution exceeded maximum instruction count".to_string(),
                    ));
                }
            }

            // Check for return to exit execution
            if address == return_address {
                return Err(EmulatorError::UnsupportedInstruction(
                    "FUNCTION_RETURN".to_string(),
                ));
            }

            Ok(())
        });

        // Execute with retry logic for memory faults
        let mut retry_count = 0;
        const MAX_RETRIES: u32 = 100;

        loop {
            // Clear fault and instruction tracking for this execution attempt
            fault_addresses.lock().unwrap().clear();
            instruction_addresses.lock().unwrap().clear();

            // Execute the function
            match self
                .engine
                .emu_start(function_address, return_address, 0, 0, Some(&mut hooks))
            {
                Ok(()) => {
                    // Normal completion - function reached end address
                    break;
                }
                Err(EmulatorError::UnsupportedInstruction(msg)) if msg == "FUNCTION_RETURN" => {
                    // Function returned normally - handle tracing and cleanup
                    if self.tracer.is_enabled() {
                        let rax = self.engine.reg_read(Register::RAX)?;
                        self.tracer.trace_return(return_address, rax)?;
                    }
                    break;
                }
                Err(EmulatorError::UnmappedMemory(addr)) => {
                    // Handle memory fault by mapping the required pages
                    if retry_count >= MAX_RETRIES {
                        return Err(anyhow::anyhow!(
                            "Too many memory fault retries at 0x{:x}",
                            addr
                        ));
                    }

                    // Collect all fault addresses that need mapping
                    let mut addresses_to_map = fault_addresses.lock().unwrap().clone();
                    addresses_to_map.push(addr & !0xfff);
                    addresses_to_map.sort_unstable();
                    addresses_to_map.dedup();

                    let mut mapped_any = false;
                    for page_base in addresses_to_map {
                        if page_base == 0 {
                            continue; // Never map null page
                        }

                        if let Ok(page_data) = self.memory_manager.read_memory(page_base, 4096) {
                            if self
                                .engine
                                .mem_map(page_base, 4096, Permission::ALL)
                                .is_ok()
                            {
                                self.engine.mem_write(page_base, &page_data)?;
                                mapped_any = true;
                            }
                        }
                    }

                    if !mapped_any {
                        return Err(anyhow::anyhow!(
                            "Failed to map memory at address 0x{:x}",
                            addr
                        ));
                    }

                    retry_count += 1;
                    // Continue loop to retry execution
                }
                Err(e) => {
                    // Other errors are fatal
                    return Err(anyhow::anyhow!("Execution failed: {:?}", e));
                }
            }

            // Handle instruction tracing for the addresses we collected
            if self.tracer.is_enabled() {
                let traced_addresses = instruction_addresses.lock().unwrap().clone();
                for address in traced_addresses {
                    if address == return_address {
                        continue; // Skip tracing the return address itself
                    }

                    // Try to read instruction bytes for tracing
                    if let Ok(inst_bytes) = self.read_instruction_bytes_for_tracing(address) {
                        if let Err(e) = self.tracer.trace_instruction(
                            address,
                            &inst_bytes,
                            &self.engine,
                            Some(self.memory_manager.get_loader()),
                        ) {
                            eprintln!(
                                "Warning: Failed to trace instruction at 0x{:x}: {}",
                                address, e
                            );
                        }
                    }
                }
            }
        }

        if self.tracer.is_enabled() {
            let final_count = *instruction_count.lock().unwrap();
            println!("\n[TRACE] Executed {} instructions", final_count);
        }

        Ok(())
    }

    fn read_instruction_bytes_for_tracing(&mut self, address: u64) -> Result<Vec<u8>> {
        // Ensure instruction memory is mapped for tracing
        let page_base = address & !0xfff;
        if let Ok(page_data) = self.memory_manager.read_memory(page_base, 4096) {
            if self
                .engine
                .mem_map(page_base, 4096, Permission::ALL)
                .is_ok()
            {
                let _ = self.engine.mem_write(page_base, &page_data);
            }
        }

        // Read instruction bytes (up to 15 bytes max for x86-64)
        let mut inst_bytes = vec![0u8; 15];
        match self.engine.mem_read(address, &mut inst_bytes) {
            Ok(()) => Ok(inst_bytes),
            Err(_) => {
                // If we can't read, return a minimal instruction (single byte)
                Ok(vec![0x90]) // NOP instruction as placeholder
            }
        }
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

    pub fn get_engine_mut(&mut self) -> &mut Engine {
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
