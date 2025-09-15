use anyhow::Result;
use remu64::{CpuState, Engine, HookAction, HookManager, memory::MemoryTrait};
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
pub struct TraceResult<M> {
    /// Sparse trace storage - only contains entries for instructions that have been viewed/requested
    pub entries: HashMap<usize, TraceEntry>,
    /// Total number of instructions executed
    pub total_instructions: usize,
    /// Memory snapshot at the selected instruction
    pub memory_snapshot: Option<M>,
    /// Error message if execution failed
    pub error_message: Option<String>,
    /// Time taken to execute and capture the trace
    pub trace_duration: std::time::Duration,
}

impl<M> TraceResult<M> {
    /// Get a trace entry by index, returning None if not captured
    pub fn get_entry(&self, index: usize) -> Option<&TraceEntry> {
        self.entries.get(&index)
    }
}

#[derive(Debug, Clone)]
pub enum InstructionAction {
    Skip,
}

pub type InstructionActions = HashMap<usize, Vec<InstructionAction>>;

pub struct CapturingTracer<M> {
    /// Sparse trace storage
    pub trace_entries: HashMap<usize, TraceEntry>,
    pub total_instructions: usize,
    pub max_instructions: usize,
    pub selected_instruction: usize,
    pub actions: InstructionActions,
    pub current_instruction_index: usize,
    /// Range of instructions to capture (start, end)
    pub capture_range: (usize, usize),
    /// Snapshot of memory at selected instruction
    pub memory_snapshot: Option<M>,
}

impl<M> CapturingTracer<M> {
    pub fn new(
        max_instructions: usize,
        selected_instruction: usize,
        actions: &InstructionActions,
        capture_range: (usize, usize),
    ) -> Self {
        Self {
            trace_entries: HashMap::new(),
            total_instructions: 0,
            max_instructions,
            selected_instruction,
            actions: actions.clone(),
            current_instruction_index: 0,
            capture_range,
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
        if self.current_instruction_index >= self.max_instructions {
            return Ok(HookAction::Stop);
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

        // Only capture trace entry if it's within our requested range
        let should_capture = self.current_instruction_index >= self.capture_range.0
            && self.current_instruction_index <= self.capture_range.1;

        if should_capture {
            // Capture CPU state at this instruction (before any modifications)
            let cpu_state = engine.cpu.clone();

            // Store the trace entry (whether skipped or not)
            self.trace_entries.insert(
                self.current_instruction_index,
                TraceEntry {
                    address,
                    size,
                    cpu_state,
                    was_skipped,
                },
            );
        }

        // Always capture memory snapshot at selected instruction regardless of range
        if self.current_instruction_index == self.selected_instruction {
            self.memory_snapshot = Some(engine.memory.clone());
        }

        self.current_instruction_index += 1;

        if was_skipped {
            Ok(HookAction::Skip)
        } else {
            Ok(HookAction::Continue)
        }
    }
}

/// Composite hook manager that combines CapturingTracer with user-provided hooks
pub struct CompositeHookManager<M, H> {
    pub capturing_tracer: CapturingTracer<M>,
    pub user_hooks: H,
}

impl<M, H> CompositeHookManager<M, H> {
    pub fn new(capturing_tracer: CapturingTracer<M>, user_hooks: H) -> Self {
        Self {
            capturing_tracer,
            user_hooks,
        }
    }
}

impl<M: MemoryTrait + Clone, H: HookManager<M>> HookManager<M> for CompositeHookManager<M, H> {
    fn on_code(
        &mut self,
        engine: &mut Engine<M>,
        address: u64,
        size: usize,
    ) -> remu64::Result<HookAction> {
        // Call user hooks first
        let user_action = self.user_hooks.on_code(engine, address, size)?;

        // If user hooks want to stop or skip, respect that
        match user_action {
            HookAction::Stop => return Ok(HookAction::Stop),
            HookAction::Skip => return Ok(HookAction::Skip),
            HookAction::Continue => {}
        }

        // Otherwise, call capturing tracer
        self.capturing_tracer.on_code(engine, address, size)
    }

    fn on_mem_read(
        &mut self,
        engine: &mut Engine<M>,
        address: u64,
        size: usize,
    ) -> remu64::Result<()> {
        self.user_hooks.on_mem_read(engine, address, size)?;
        self.capturing_tracer.on_mem_read(engine, address, size)
    }

    fn on_mem_write(
        &mut self,
        engine: &mut Engine<M>,
        address: u64,
        size: usize,
    ) -> remu64::Result<()> {
        self.user_hooks.on_mem_write(engine, address, size)?;
        self.capturing_tracer.on_mem_write(engine, address, size)
    }

    fn on_mem_access(
        &mut self,
        engine: &mut Engine<M>,
        address: u64,
        size: usize,
    ) -> remu64::Result<()> {
        self.user_hooks.on_mem_access(engine, address, size)?;
        self.capturing_tracer.on_mem_access(engine, address, size)
    }

    fn on_mem_fault(
        &mut self,
        engine: &mut Engine<M>,
        address: u64,
        size: usize,
    ) -> remu64::Result<bool> {
        // For mem_fault, try user hooks first, then capturing tracer if user doesn't handle it
        let user_handled = self.user_hooks.on_mem_fault(engine, address, size)?;
        if user_handled {
            Ok(true)
        } else {
            self.capturing_tracer.on_mem_fault(engine, address, size)
        }
    }

    fn on_interrupt(
        &mut self,
        engine: &mut Engine<M>,
        intno: u64,
        size: usize,
    ) -> remu64::Result<()> {
        self.user_hooks.on_interrupt(engine, intno, size)?;
        self.capturing_tracer.on_interrupt(engine, intno, size)
    }

    fn on_invalid(
        &mut self,
        engine: &mut Engine<M>,
        address: u64,
        size: usize,
    ) -> remu64::Result<()> {
        self.user_hooks.on_invalid(engine, address, size)?;
        self.capturing_tracer.on_invalid(engine, address, size)
    }
}

/// Run trace capturing only instructions in the specified range
/// Uses an already-configured engine from the VmSetupProvider
pub fn run_trace<M: MemoryTrait + Clone, H: HookManager<M>>(
    mut engine: remu64::Engine<M>,
    config: crate::VmConfig<H>,
    current_idx: usize,
    capture_range: (usize, usize),
    instruction_actions: &InstructionActions,
) -> Result<TraceResult<M>> {
    let trace_start_time = std::time::Instant::now();

    debug!(
        "run_trace called: addr=0x{:x}, max={}, range=({}, {})",
        config.function_address, config.max_instructions, capture_range.0, capture_range.1
    );

    let capturing_tracer = CapturingTracer::new(
        config.max_instructions,
        current_idx,
        instruction_actions,
        capture_range,
    );

    let mut composite_hooks = CompositeHookManager::new(capturing_tracer, config.hooks);

    debug!(
        "Executing function at 0x{:x} with CompositeHookManager",
        config.function_address
    );

    // Execute with hooks - engine should already be properly set up by VmSetupProvider
    let error_message = match engine.emu_start_with_hooks(
        config.function_address,
        config.until_address,
        0, // No timeout
        config.max_instructions,
        &mut composite_hooks,
    ) {
        Ok(_) => {
            info!(
                "Function execution completed successfully with {} total instructions, captured {} entries in range ({}, {})",
                composite_hooks.capturing_tracer.current_instruction_index,
                composite_hooks.capturing_tracer.trace_entries.len(),
                capture_range.0,
                capture_range.1
            );
            None
        }
        Err(e) => {
            // Check if this was due to reaching max instructions
            if composite_hooks.capturing_tracer.current_instruction_index >= config.max_instructions
            {
                debug!(
                    "Function execution stopped after reaching max instructions: {} total, {} captured",
                    composite_hooks.capturing_tracer.current_instruction_index,
                    composite_hooks.capturing_tracer.trace_entries.len()
                );
                None
            } else {
                let error_msg = format!("Execution failed: {}", e);
                warn!(
                    "Function execution failed: {}, total {} instructions, captured {} entries",
                    e,
                    composite_hooks.capturing_tracer.current_instruction_index,
                    composite_hooks.capturing_tracer.trace_entries.len()
                );
                Some(error_msg)
            }
        }
    };

    // Store total instructions executed
    composite_hooks.capturing_tracer.total_instructions =
        composite_hooks.capturing_tracer.current_instruction_index;

    let trace_duration = trace_start_time.elapsed();

    debug!(
        "Returning {} sparse trace entries from {} total instructions in {:?}",
        composite_hooks.capturing_tracer.trace_entries.len(),
        composite_hooks.capturing_tracer.total_instructions,
        trace_duration
    );

    Ok(TraceResult {
        entries: composite_hooks.capturing_tracer.trace_entries,
        total_instructions: composite_hooks.capturing_tracer.total_instructions,
        memory_snapshot: composite_hooks
            .capturing_tracer
            .memory_snapshot
            .or(Some(engine.memory)),
        error_message,
        trace_duration,
    })
}
