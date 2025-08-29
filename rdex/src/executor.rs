use crate::execution_controller::{ExecutionController, ExecutionHooks};
use crate::fastcall::{ArgumentType, CallingConvention, FString};
use crate::process_trait::ProcessTrait;
use crate::symbolizer::Symbolizer;
use crate::tracer::InstructionTracer;
use crate::vm_context::VMContext;
use anyhow::Result;
use remu64::Register;

pub struct FunctionExecutor<P>
where
    P: ProcessTrait,
{
    pub vm_context: VMContext<P::Memory>,
    pub process: P,
    pub stack_base: u64,
    pub tracer: InstructionTracer,
    pub fstring_addresses: Vec<u64>,
    pub symbolizer: Option<Box<dyn Symbolizer>>,
}

impl<P> FunctionExecutor<P>
where
    P: ProcessTrait,
{
    pub fn new(process: P) -> Result<Self> {
        let vm_context = VMContext::new(&process)?;
        let stack_base = 0x7fff_f000_0000u64;
        let tracer = InstructionTracer::new(false);

        let mut executor = FunctionExecutor {
            vm_context,
            process,
            stack_base,
            tracer,
            fstring_addresses: Vec::new(),
            symbolizer: None,
        };

        executor.setup_stack()?;
        Ok(executor)
    }

    pub fn new_with_symbolizer(process: P, symbolizer: Box<dyn Symbolizer>) -> Result<Self> {
        let mut executor = Self::new(process)?;
        executor.symbolizer = Some(symbolizer);
        Ok(executor)
    }

    fn setup_stack(&mut self) -> Result<()> {
        let stack_size = 0x10000000;
        self.vm_context.setup_stack(self.stack_base, stack_size)?;

        // Set initial stack pointer
        self.vm_context
            .engine
            .reg_write(Register::RSP, self.stack_base - 8);
        Ok(())
    }

    pub fn execute_function(
        &mut self,
        function_address: u64,
        args: Vec<ArgumentType>,
    ) -> Result<()> {
        let return_address = 0xFFFF800000000000u64;

        let (_struct_addresses, fstring_addresses) =
            CallingConvention::setup_fastcall(&mut self.vm_context, args, return_address)?;

        self.fstring_addresses = fstring_addresses;
        self.vm_context
            .engine
            .reg_write(Register::RIP, function_address);

        let mut hooks = ExecutionHooks {
            process: &self.process,
            tracer: &mut self.tracer,
            instruction_count: 0,
            symbolizer: match &mut self.symbolizer {
                Some(symbolizer) => Some(symbolizer.as_mut()),
                None => None,
            },
        };

        ExecutionController::execute_with_hooks(
            &mut self.vm_context.engine,
            function_address,
            return_address,
            &mut hooks,
        )?;

        if hooks.tracer.is_enabled() {
            println!(
                "\n[TRACE] Executed {} instructions",
                hooks.instruction_count
            );
        }

        Ok(())
    }

    pub fn get_return_value(&self) -> u64 {
        self.vm_context.engine.reg_read(Register::RAX)
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

    pub fn read_fstring_outputs(&mut self) -> Result<Vec<FString>> {
        let mut outputs = Vec::new();
        for &addr in &self.fstring_addresses {
            outputs.push(CallingConvention::read_fstring_output(
                &mut self.vm_context.engine,
                addr,
            )?);
        }
        Ok(outputs)
    }

    /// Reset the VM state for reuse while keeping the base minidump memory
    /// This clears the CowMemory overlay and rebuilds the stack
    pub fn reset_for_reuse(&mut self) -> Result<()> {
        self.vm_context.engine.memory.reset_to_base();
        self.setup_stack()?;
        self.fstring_addresses.clear();
        Ok(())
    }

    /// Push raw bytes to the stack and return a pointer to them
    /// Convenience method that delegates to VMContext
    pub fn push_bytes_to_stack(&mut self, data: &[u8]) -> Result<u64> {
        self.vm_context.push_bytes_to_stack(data)
    }

    /// Get module by name from the process
    pub fn get_module_by_name(&self, name: &str) -> Option<crate::process_trait::ModuleInfo> {
        self.process.get_module_by_name(name)
    }

    /// Get module base address by name
    pub fn get_module_base_address(&self, name: &str) -> Option<u64> {
        self.process.get_module_base_address(name)
    }

    /// List all modules in the process
    pub fn list_modules(&self) -> Vec<crate::process_trait::ModuleInfo> {
        self.process.list_modules()
    }

    /// Find module for a given address
    pub fn find_module_for_address(&self, address: u64) -> Option<(String, u64, u64)> {
        self.process.find_module_for_address(address)
    }
}
