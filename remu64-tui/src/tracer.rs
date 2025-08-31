use anyhow::Result;
use rdex::{ExecutionController, MinidumpLoader, MinidumpMemory, VMContext};
use remu64::{
    CowMemory, CpuState, Engine, EngineMode, HookAction, HookManager, Register, memory::MemoryTrait,
};
use std::collections::HashMap;
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct TraceEntry {
    pub address: u64,
    pub size: usize,
    pub cpu_state: CpuState,
    pub was_skipped: bool,
}

#[derive(Debug, Clone)]
pub enum InstructionAction {
    Skip,
}

pub type InstructionActions = HashMap<usize, Vec<InstructionAction>>;

pub struct CapturingTracer<M> {
    pub trace_entries: Vec<TraceEntry>,
    pub max_instructions: usize,
    pub selected_instruction: usize,
    pub actions: InstructionActions,
    pub current_instruction_index: usize,
    /// Snapshot of memory at selected instruction
    pub memory_snapshot: Option<M>,
}

impl<M> CapturingTracer<M> {
    pub fn new(
        max_instructions: usize,
        selected_instruction: usize,
        actions: &InstructionActions,
    ) -> Self {
        Self {
            trace_entries: Vec::new(),
            max_instructions,
            selected_instruction,
            actions: actions.clone(),
            current_instruction_index: 0,
            memory_snapshot: None,
        }
    }
}

impl<M: MemoryTrait + Clone> HookManager<M> for CapturingTracer<M> {
    fn on_code(
        &mut self,
        engine: &mut Engine<M>,
        address: u64,
        size: usize,
    ) -> remu64::Result<HookAction> {
        // Check if we've reached the maximum number of instructions
        if self.trace_entries.len() >= self.max_instructions {
            return Ok(HookAction::Stop);
        }

        // Capture CPU state at this instruction (before any modifications)
        let cpu_state = engine.cpu.clone();
        if self.current_instruction_index == self.selected_instruction {
            self.memory_snapshot = Some(engine.memory.clone());
        }

        // Check for actions on this instruction index
        let mut was_skipped = false;
        if let Some(actions) = self.actions.get(&self.current_instruction_index) {
            for action in actions {
                match action {
                    InstructionAction::Skip => {
                        debug!(
                            "Skipping instruction {} at 0x{:x}",
                            self.current_instruction_index, address
                        );
                        was_skipped = true;
                    }
                }
            }
        }

        // Store the trace entry (whether skipped or not)
        self.trace_entries.push(TraceEntry {
            address,
            size,
            cpu_state,
            was_skipped,
        });

        self.current_instruction_index += 1;

        if was_skipped {
            Ok(HookAction::Skip)
        } else {
            Ok(HookAction::Continue)
        }
    }
}

pub struct Tracer<'a> {
    pub minidump_loader: &'a MinidumpLoader<'static>,
    pub memory: &'a MinidumpMemory<'static>,
}

impl<'a> Tracer<'a> {
    /// Run trace up to specified instruction index, returning trace entries
    pub fn run_trace(
        &self,
        config: &crate::config::Config,
        max_instructions: usize,
        current_idx: usize,
    ) -> Result<(
        Vec<TraceEntry>,
        CowMemory<&'a MinidumpMemory<'static>>,
        Option<String>,
    )> {
        debug!(
            "run_trace called: addr=0x{:x}, max={}",
            config.function_address, max_instructions,
        );
        debug!("Creating VM context from minidump loader");

        let loader = self.minidump_loader;

        // Create VM context directly from the process
        let cow_memory = CowMemory::new(self.memory);
        let mut engine = Engine::new_memory(EngineMode::Mode64, cow_memory);
        let teb_address = loader.get_teb_address()?;
        engine.set_gs_base(teb_address);
        let mut vm_context = VMContext { engine };

        // Set up stack using config values
        let stack_base = config.stack.base_address;
        let stack_size = config.stack.size;
        vm_context.setup_stack(stack_base, stack_size)?;

        let initial_rsp = stack_base - config.stack.initial_offset;
        vm_context.engine.reg_write(Register::RSP, initial_rsp);

        // Set initial register values from config
        for (&register, &value) in &config.registers {
            vm_context.engine.reg_write(register, value);
        }

        let mut capturing_tracer =
            CapturingTracer::new(max_instructions, current_idx, &config.instruction_actions);

        debug!(
            "Executing function at 0x{:x} with CapturingTracer",
            config.function_address
        );

        // Use ExecutionController with our custom tracer
        let return_address = 0xFFFF800000000000u64;
        let error_message = match ExecutionController::execute_with_hooks(
            &mut vm_context.engine,
            config.function_address,
            return_address,
            &mut capturing_tracer,
        ) {
            Ok(_) => {
                info!(
                    "Function execution completed successfully with {} instructions traced",
                    capturing_tracer.trace_entries.len()
                );
                None
            }
            Err(e) => {
                // Check if this was due to reaching max instructions
                if capturing_tracer.trace_entries.len() >= max_instructions {
                    debug!(
                        "Function execution stopped after reaching max instructions: {} traced",
                        capturing_tracer.trace_entries.len()
                    );
                    None
                } else {
                    let error_msg = format!("Execution failed: {}", e);
                    warn!(
                        "Function execution failed: {}, captured {} instructions",
                        e,
                        capturing_tracer.trace_entries.len()
                    );
                    Some(error_msg)
                }
            }
        };

        // Return the captured trace, limited by up_to_index
        let total_entries = capturing_tracer.trace_entries.len();
        let trace = capturing_tracer.trace_entries;

        debug!(
            "Returning {} trace entries (limited from {} total)",
            trace.len(),
            total_entries
        );

        Ok((
            trace,
            capturing_tracer
                .memory_snapshot
                .unwrap_or(vm_context.engine.memory),
            error_message,
        ))
    }
}
