use anyhow::{Context, Result};
use amd64_emu::{Engine, EngineMode, Register, Permission};
use crate::minidump_loader::MinidumpLoader;
use crate::memory_manager::MemoryManager;
use crate::fastcall::{ArgumentType, CallingConvention};
use crate::tracer::InstructionTracer;

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
        
        let stack_base = memory_manager.allocate_stack(0x10000)
            .context("Failed to allocate stack")?;

        // Map stack memory in engine
        engine.mem_map(stack_base - 0x10000, 0x10000, Permission::ALL)
            .context("Failed to map stack memory")?;

        let tracer = InstructionTracer::new(false);

        Ok(FunctionExecutor {
            engine,
            memory_manager,
            stack_base,
            tracer,
        })
    }

    pub fn execute_function(
        &mut self,
        function_address: u64,
        args: Vec<ArgumentType>,
    ) -> Result<()> {
        let return_address = 0xdeadbeef;
        
        // Setup calling convention
        CallingConvention::setup_fastcall(
            &mut self.engine,
            args,
            self.stack_base,
            return_address,
        )?;

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
                self.tracer.trace_instruction(rip, &instruction_bytes, &self.engine, Some(self.memory_manager.get_loader()))?;
            }
            
            // Execute single instruction
            self.engine.emu_start(rip, rip + 15, 0, 1)?;
            
            instruction_count += 1;
        }
        
        if self.tracer.is_enabled() {
            println!("\n[TRACE] Executed {} instructions", instruction_count);
        }

        Ok(())
    }
    
    fn read_instruction_at(&mut self, address: u64) -> Result<Vec<u8>> {
        // Ensure memory is mapped
        let page_base = address & !0xfff;
        
        // Try to read from minidump first
        if let Ok(page_data) = self.memory_manager.read_memory(page_base, 4096) {
            // Map the page if not already mapped
            if self.engine.mem_map(page_base, 4096, Permission::ALL).is_ok() {
                self.engine.mem_write(page_base, &page_data)?;
            }
        }
        
        // Read up to 15 bytes for the instruction (max x86-64 instruction length)
        let mut instruction_bytes = vec![0u8; 15];
        self.engine.mem_read(address, &mut instruction_bytes)?;
        Ok(instruction_bytes)
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
    
    pub fn is_tracing_enabled(&self) -> bool {
        self.tracer.is_enabled()
    }
    
    pub fn get_instruction_count(&self) -> usize {
        self.tracer.get_instruction_count()
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