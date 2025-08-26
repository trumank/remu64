use crate::fastcall::{ArgumentType, CallingConvention};
use crate::memory_manager::MemoryManager;
use crate::minidump_loader::MinidumpLoader;
use crate::tracer::InstructionTracer;
use amd64_emu::{EmulatorError, Engine, EngineMode, HookManager, Permission, Register};
use anyhow::{Context, Result};
use iced_x86::Formatter;

// Hook implementation that contains the context
struct ExecutionHooks<'a> {
    memory_manager: &'a mut MemoryManager,
    tracer: &'a mut InstructionTracer,
    instruction_count: u64,
}

impl<'a> HookManager for ExecutionHooks<'a> {
    fn on_mem_fault(
        &mut self,
        engine: &mut Engine,
        address: u64,
        _size: usize,
    ) -> amd64_emu::Result<bool> {
        println!("!!mem fault hook at 0x{:x}", address);
        let page_base = address & !0xfff;

        // NEVER map the null page (address 0)
        if page_base == 0 {
            return Ok(false); // Don't handle null page faults
        }

        // Try to read from minidump and map it in the engine
        if let Ok(page_data) = self.memory_manager.read_memory(page_base, 4096) {
            // Map the page in the engine
            match engine.mem_map(page_base, 4096, Permission::ALL) {
                Ok(()) => {
                    // Write the data to the mapped page
                    match engine.mem_write(page_base, &page_data) {
                        Ok(()) => {
                            println!("Successfully mapped and wrote page at 0x{:x}", page_base);
                            Ok(true) // Successfully handled the fault
                        }
                        Err(_) => {
                            println!("Failed to write data to mapped page at 0x{:x}", page_base);
                            Ok(false) // Failed to write data
                        }
                    }
                }
                Err(_) => {
                    // Page might already be mapped, try to write anyway
                    match engine.mem_write(page_base, &page_data) {
                        Ok(()) => {
                            println!("Page already mapped, wrote data at 0x{:x}", page_base);
                            Ok(true) // Successfully handled the fault
                        }
                        Err(_) => {
                            println!("Failed to map or write page at 0x{:x}", page_base);
                            Ok(false) // Failed to handle
                        }
                    }
                }
            }
        } else {
            println!("No data in minidump for page at 0x{:x}", page_base);
            Ok(false) // Can't handle this fault - no data in minidump
        }
    }

    fn on_code(&mut self, engine: &mut Engine, address: u64, size: usize) -> amd64_emu::Result<()> {
        // Handle instruction tracing
        if self.tracer.is_enabled() {
            let mut instruction_bytes = vec![0; size];
            engine.mem_read(address, &mut instruction_bytes).unwrap();
            self.tracer
                .trace_instruction(
                    address,
                    &instruction_bytes,
                    engine,
                    Some(self.memory_manager.get_loader()),
                )
                .unwrap();
        }

        Ok(())
    }

    // fn on_mem_read(&mut self, engine: &mut Engine, address: u64, size: usize) -> amd64_emu::Result<()> {
    //     // Read the actual memory value to display it
    //     let mut buffer = vec![0u8; size];
    //     if let Ok(()) = engine.mem_read(address, &mut buffer) {
    //         let value_str = if size <= 8 {
    //             let mut value = 0u64;
    //             for (i, &byte) in buffer.iter().enumerate() {
    //                 value |= (byte as u64) << (i * 8);
    //             }
    //             format!("0x{:016x}", value)
    //         } else {
    //             format!("{} bytes", size)
    //         };
    //         println!("MEM READ  0x{:016x} ({} bytes) -> {}", address, size, value_str);
    //     } else {
    //         println!("MEM READ  0x{:016x} ({} bytes) -> <failed>", address, size);
    //     }
    //     Ok(())
    // }

    // fn on_mem_write(&mut self, engine: &mut Engine, address: u64, size: usize) -> amd64_emu::Result<()> {
    //     // Read the memory value that was just written to display it
    //     let mut buffer = vec![0u8; size];
    //     if let Ok(()) = engine.mem_read(address, &mut buffer) {
    //         let value_str = if size <= 8 {
    //             let mut value = 0u64;
    //             for (i, &byte) in buffer.iter().enumerate() {
    //                 value |= (byte as u64) << (i * 8);
    //             }
    //             format!("0x{:016x}", value)
    //         } else {
    //             format!("{} bytes", size)
    //         };
    //         println!("MEM WRITE 0x{:016x} ({} bytes) <- {}", address, size, value_str);
    //     } else {
    //         println!("MEM WRITE 0x{:016x} ({} bytes) <- <failed>", address, size);
    //     }
    //     Ok(())
    // }
}

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

        let stack_size = 0x10000;
        let stack_base = memory_manager
            .allocate_stack(stack_size)
            .context("Failed to allocate stack")?;

        // Map stack memory in engine
        engine
            .mem_map(
                stack_base - stack_size,
                stack_size as usize,
                Permission::ALL,
            )
            .context("Failed to map stack memory")?;

        let tracer = InstructionTracer::new(false);

        let executor = FunctionExecutor {
            engine,
            memory_manager,
            stack_base,
            tracer,
        };

        Ok(executor)
    }

    pub fn execute_function(
        &mut self,
        function_address: u64,
        args: Vec<ArgumentType>,
    ) -> Result<()> {
        // Use a canary return address that we can detect
        let return_address = 0xDEADBEEFCAFEBABE_u64;

        // Setup calling convention with shadow space
        CallingConvention::setup_fastcall(
            &mut self.engine,
            args.clone(),
            self.stack_base,
            return_address,
        )?;

        // Set RIP to function start
        self.engine.reg_write(Register::RIP, function_address);

        // Get TEB address from minidump thread stream
        let teb_address = self.memory_manager.get_loader().get_teb_address()?;
        self.engine.set_gs_base(teb_address);

        let mut hooks = ExecutionHooks {
            memory_manager: &mut self.memory_manager,
            tracer: &mut self.tracer,
            instruction_count: 0,
        };

        // Execute the function
        match self
            .engine
            .emu_start(function_address, return_address, 0, 0, Some(&mut hooks))
        {
            Ok(()) => {
                // Normal completion - function reached end address
            }
            Err(EmulatorError::UnsupportedInstruction(msg)) if msg == "FUNCTION_RETURN" => {
                // Function returned normally - handle tracing and cleanup
                if hooks.tracer.is_enabled() {
                    let rax = self.engine.reg_read(Register::RAX);
                    hooks.tracer.trace_return(return_address, rax)?;
                }
            }
            Err(EmulatorError::UnmappedMemory(addr)) => {
                // Handle memory fault by mapping the required page
                return Err(anyhow::anyhow!(
                    "Attempted to access unmapped page at 0x{:x}",
                    addr
                ));
            }
            Err(e) => {
                let rip = self.engine.reg_read(Register::RIP);
                let instruction_bytes = self.read_instruction_at(rip).unwrap_or_default();
                return self.report_instruction_error(rip, &instruction_bytes, e);
            }
        }

        if hooks.tracer.is_enabled() {
            println!(
                "\n[TRACE] Executed {} instructions",
                hooks.instruction_count
            );
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

    pub fn get_return_value(&self) -> u64 {
        self.engine.reg_read(Register::RAX)
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

    pub fn set_register(&mut self, register: Register, value: u64) {
        self.engine.reg_write(register, value)
    }

    pub fn get_register(&self, register: Register) -> u64 {
        self.engine.reg_read(register)
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
