use crate::fastcall::{ArgumentType, CallingConvention, FString};
use crate::minidump_loader::MinidumpLoader;
use crate::minidump_memory::MinidumpMemory;
use crate::tracer::InstructionTracer;
use amd64_emu::memory::{CowMemory, MemoryTrait};
use amd64_emu::{EmulatorError, Engine, EngineMode, HookManager, Permission, Register};
use anyhow::Result;
use iced_x86::Formatter;

// Hook implementation that contains the context
struct ExecutionHooks<'a> {
    minidump_loader: &'a MinidumpLoader,
    tracer: &'a mut InstructionTracer,
    instruction_count: u64,
}

impl<'a, M: MemoryTrait> HookManager<M> for ExecutionHooks<'a> {
    fn on_mem_fault(
        &mut self,
        _engine: &mut Engine<M>,
        address: u64,
        size: usize,
    ) -> amd64_emu::Result<bool> {
        // With CowMemory on top of MinidumpMemory, we should not get memory faults
        // for valid minidump addresses as they are accessible through the read implementation.
        // If we get here, it's likely an invalid memory access.
        println!(
            "Memory fault at address 0x{:x}, size {} - invalid access",
            address, size
        );
        Ok(false)
    }

    fn on_code(
        &mut self,
        engine: &mut Engine<M>,
        address: u64,
        size: usize,
    ) -> amd64_emu::Result<()> {
        // Increment instruction counter
        self.instruction_count += 1;

        // Handle instruction tracing
        if self.tracer.is_enabled() {
            let mut instruction_bytes = vec![0; size];
            engine.memory.read(address, &mut instruction_bytes).unwrap();
            self.tracer
                .trace_instruction(
                    address,
                    &instruction_bytes,
                    engine,
                    Some(self.minidump_loader),
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

pub struct FunctionExecutor<'a> {
    engine: Engine<CowMemory<MinidumpMemory<'a>>>,
    minidump_loader: &'a MinidumpLoader,
    stack_base: u64,
    tracer: InstructionTracer,
    fstring_addresses: Vec<u64>,
}

impl<'a> FunctionExecutor<'a> {
    pub fn new(minidump_loader: &'a MinidumpLoader) -> Result<FunctionExecutor<'a>> {
        // Create MinidumpMemory from the loader
        let minidump_memory = MinidumpMemory::new(minidump_loader.get_dump())?;

        // Wrap with CowMemory for writability
        let cow_memory = CowMemory::new(minidump_memory);

        // Create engine with the CoW memory
        let mut engine = Engine::new_memory(EngineMode::Mode64, cow_memory);

        // Set up stack - use a standard location
        let stack_base = 0x7fff_f000_0000u64;
        let stack_size = 0x10000;

        engine.memory.map(
            stack_base - stack_size,
            stack_size as usize,
            Permission::READ | Permission::WRITE,
        )?;

        // Initialize stack pointer
        engine.reg_write(Register::RSP, stack_base - 8);

        let tracer = InstructionTracer::new(false);

        let executor = FunctionExecutor {
            engine,
            minidump_loader,
            stack_base,
            tracer,
            fstring_addresses: Vec::new(),
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
        let (_struct_addresses, fstring_addresses) = CallingConvention::setup_fastcall(
            &mut self.engine,
            args.clone(),
            self.stack_base,
            return_address,
        )?;

        // Store FString addresses for later output reading
        self.fstring_addresses = fstring_addresses;

        // Set RIP to function start
        self.engine.reg_write(Register::RIP, function_address);

        // Get TEB address from minidump thread stream
        let teb_address = self.minidump_loader.get_teb_address()?;
        self.engine.set_gs_base(teb_address);

        let mut hooks = ExecutionHooks {
            minidump_loader: self.minidump_loader,
            tracer: &mut self.tracer,
            instruction_count: 0,
        };

        // Execute the function
        match self
            .engine
            .emu_start_with_hooks(function_address, return_address, 0, 0, &mut hooks)
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

    fn read_instruction_at(&mut self, address: u64) -> Result<Vec<u8>> {
        // Ensure memory is mapped
        self.ensure_memory_mapped(address)?;

        // Read up to 15 bytes for the instruction (max x86-64 instruction length)
        let mut instruction_bytes = vec![0u8; 15];
        self.engine.memory.read(address, &mut instruction_bytes)?;
        Ok(instruction_bytes)
    }

    fn ensure_memory_mapped(&mut self, address: u64) -> Result<()> {
        let page_base = address & !0xfff;

        // NEVER access the null page (address 0) - this should always be unmapped
        if page_base == 0 {
            anyhow::bail!(
                "Attempt to access null page at address 0x{:x} - this should never be mapped",
                address
            );
        }

        // With CowMemory on top of MinidumpMemory, all minidump memory is already accessible
        // No manual mapping required
        Ok(())
    }

    pub fn get_return_value(&self) -> u64 {
        self.engine.reg_read(Register::RAX)
    }

    pub fn get_engine(&self) -> &Engine<CowMemory<MinidumpMemory<'a>>> {
        &self.engine
    }

    pub fn get_engine_mut(&mut self) -> &mut Engine<CowMemory<MinidumpMemory<'a>>> {
        &mut self.engine
    }

    pub fn read_memory(&mut self, address: u64, size: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; size];
        self.engine.memory.read(address, &mut buf)?;
        Ok(buf)
    }

    pub fn write_memory(&mut self, address: u64, data: &[u8]) -> Result<()> {
        self.engine.memory.write(address, data)?;
        Ok(())
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
        let module_info = self.minidump_loader.find_module_for_address(rip);
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

    pub fn read_fstring_outputs(&mut self) -> Result<Vec<FString>> {
        let mut outputs = Vec::new();
        for &addr in &self.fstring_addresses {
            outputs.push(CallingConvention::read_fstring_output(
                &mut self.engine,
                addr,
            )?);
        }
        Ok(outputs)
    }
}
