use anyhow::Result;
use remu64::{CpuState, Engine, HookAction, HookManager, Register, memory::MemoryTrait};
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

pub struct GenericTracer<'a, M: MemoryTrait, S> {
    pub memory: M,
    pub symbolizer: &'a S,
}

impl<'a, M: MemoryTrait + Clone, S> GenericTracer<'a, M, S> {
    pub fn new(memory: M, symbolizer: &'a S) -> Self {
        Self { memory, symbolizer }
    }
    /// Run trace capturing only instructions in the specified range
    pub fn run_trace(
        &self,
        initial_cpu_state: CpuState,
        function_address: u64,
        max_instructions: usize,
        current_idx: usize,
        capture_range: (usize, usize),
        instruction_actions: &InstructionActions,
    ) -> Result<TraceResult<M>> {
        let trace_start_time = std::time::Instant::now();

        debug!(
            "run_trace called: addr=0x{:x}, max={}, range=({}, {})",
            function_address, max_instructions, capture_range.0, capture_range.1
        );
        debug!("Creating engine with provided memory");

        // Create engine with the provided memory
        let mut engine = Engine::new_memory(remu64::EngineMode::Mode64, self.memory.clone());

        // Set initial CPU state
        engine.cpu = initial_cpu_state;

        let return_address = 0xFFFF800000000000u64;

        let mut capturing_tracer = CapturingTracer::new(
            max_instructions,
            current_idx,
            instruction_actions,
            capture_range,
        );

        debug!(
            "Executing function at 0x{:x} with CapturingTracer",
            function_address
        );

        // Set up return address on stack
        let rsp = engine.reg_read(Register::RSP);
        engine
            .memory
            .write(rsp - 8, &return_address.to_le_bytes())?;
        engine.reg_write(Register::RSP, rsp - 8);

        // Set initial RIP to function address
        engine.reg_write(Register::RIP, function_address);

        // Execute with hooks
        let error_message = match engine.emu_start_with_hooks(
            function_address,
            return_address,
            0, // No timeout
            max_instructions,
            &mut capturing_tracer,
        ) {
            Ok(_) => {
                info!(
                    "Function execution completed successfully with {} total instructions, captured {} entries in range ({}, {})",
                    capturing_tracer.current_instruction_index,
                    capturing_tracer.trace_entries.len(),
                    capture_range.0,
                    capture_range.1
                );
                None
            }
            Err(e) => {
                // Check if this was due to reaching max instructions
                if capturing_tracer.current_instruction_index >= max_instructions {
                    debug!(
                        "Function execution stopped after reaching max instructions: {} total, {} captured",
                        capturing_tracer.current_instruction_index,
                        capturing_tracer.trace_entries.len()
                    );
                    None
                } else {
                    let error_msg = format!("Execution failed: {}", e);
                    warn!(
                        "Function execution failed: {}, total {} instructions, captured {} entries",
                        e,
                        capturing_tracer.current_instruction_index,
                        capturing_tracer.trace_entries.len()
                    );
                    Some(error_msg)
                }
            }
        };

        // Store total instructions executed
        capturing_tracer.total_instructions = capturing_tracer.current_instruction_index;

        let trace_duration = trace_start_time.elapsed();

        debug!(
            "Returning {} sparse trace entries from {} total instructions in {:?}",
            capturing_tracer.trace_entries.len(),
            capturing_tracer.total_instructions,
            trace_duration
        );

        Ok(TraceResult {
            entries: capturing_tracer.trace_entries,
            total_instructions: capturing_tracer.total_instructions,
            memory_snapshot: capturing_tracer.memory_snapshot.or(Some(engine.memory)),
            error_message,
            trace_duration,
        })
    }
}
