use anyhow::Result;
use remu64::{
    CowMemory, CpuState, Engine, HookAction, HookManager, hooks::NoHooks, memory::MemoryTrait,
};
use std::collections::{BTreeMap, HashMap};
use tracing::{debug, info, warn};

pub trait TracerHook<M: MemoryTrait>: HookManager<CowMemory<M>> + Clone {
    fn get_log_messages(&self) -> &[(usize, String)];
}

impl<M: MemoryTrait> TracerHook<M> for NoHooks {
    fn get_log_messages(&self) -> &[(usize, String)] {
        &[]
    }
}

#[derive(Debug, Clone)]
pub struct TraceEntry {
    pub address: u64,
    pub size: usize,
    pub cpu_state: CpuState,
    pub was_skipped: bool,
}

#[derive(Debug, Clone)]
pub struct TraceResult<M, H> {
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
    /// User hooks for accessing log messages
    pub hooks: H,
}

impl<M, H> TraceResult<M, H> {
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

pub struct CapturingTracer<'a, M: MemoryTrait + Clone, H: TracerHook<M>> {
    /// Sparse trace storage
    pub trace_entries: HashMap<usize, TraceEntry>,
    pub total_instructions: usize,
    pub max_instructions: usize,
    pub capture_idx_memory: Option<usize>,
    pub current_instruction_index: usize,
    /// Range of instructions to capture (start, end)
    pub capture_inst_range: Option<(usize, usize)>,
    /// Snapshot of memory at selected instruction
    pub memory_snapshot: Option<CowMemory<M>>,
    /// Snapshot interval for creating periodic snapshots
    pub snapshot_interval: usize,
    /// Snapshots map for creating periodic snapshots
    pub snapshots_map: &'a mut BTreeMap<usize, crate::Snapshot<M, H>>,
    /// Config containing hooks and other settings
    pub config: crate::VmConfig<H>,
}

impl<'a, M: MemoryTrait + Clone, H: TracerHook<M>> CapturingTracer<'a, M, H> {
    pub fn new(
        max_instructions: usize,
        capture_idx_memory: Option<usize>,
        capture_inst_range: Option<(usize, usize)>,
        snapshot_interval: usize,
        snapshot_start: usize,
        snapshots_map: &'a mut BTreeMap<usize, crate::Snapshot<M, H>>,
        config: crate::VmConfig<H>,
    ) -> Self {
        Self {
            trace_entries: HashMap::new(),
            total_instructions: snapshot_start,
            max_instructions,
            capture_idx_memory,
            current_instruction_index: snapshot_start,
            capture_inst_range,
            memory_snapshot: None,
            snapshot_interval,
            snapshots_map,
            config,
        }
    }
}

impl<'a, M: MemoryTrait + Clone, H: TracerHook<M>> HookManager<CowMemory<M>>
    for CapturingTracer<'a, M, H>
{
    fn on_code(
        &mut self,
        engine: &mut Engine<CowMemory<M>>,
        address: u64,
        size: usize,
    ) -> remu64::Result<HookAction> {
        // Call user hooks first
        let user_action = self.config.hooks.on_code(engine, address, size)?;

        // If user hooks want to stop or skip, respect that
        match user_action {
            HookAction::Stop => return Ok(HookAction::Stop),
            HookAction::Skip => return Ok(HookAction::Skip),
            HookAction::Continue => {}
        }

        // Check if we've reached the maximum number of instructions
        if self.current_instruction_index >= self.max_instructions {
            return Ok(HookAction::Stop);
        }

        // Create snapshot at interval boundaries
        if self.current_instruction_index > 0
            && self
                .current_instruction_index
                .is_multiple_of(self.snapshot_interval)
            && !self
                .snapshots_map
                .contains_key(&self.current_instruction_index)
        {
            debug!(
                "Creating snapshot at instruction {} at address 0x{:x}",
                self.current_instruction_index, address
            );

            self.snapshots_map.insert(
                self.current_instruction_index,
                crate::Snapshot {
                    engine: engine.clone(),
                    config: self.config.clone(),
                    instruction_index: self.current_instruction_index,
                },
            );
        }

        // Check for actions on this instruction index
        let mut was_skipped = false;
        if let Some(actions) = self
            .config
            .instruction_actions
            .get(&self.current_instruction_index)
        {
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
        let should_capture = if let Some((start, end)) = self.capture_inst_range {
            self.current_instruction_index >= start && self.current_instruction_index <= end
        } else {
            false // No capture range specified, don't capture entries
        };

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
        if let Some(capture_idx) = self.capture_idx_memory
            && self.current_instruction_index == capture_idx
        {
            self.memory_snapshot = Some(engine.memory.clone());
        }

        self.current_instruction_index += 1;

        if was_skipped {
            Ok(HookAction::Skip)
        } else {
            Ok(HookAction::Continue)
        }
    }

    fn on_mem_read(
        &mut self,
        engine: &mut Engine<CowMemory<M>>,
        address: u64,
        size: usize,
    ) -> remu64::Result<()> {
        self.config.hooks.on_mem_read(engine, address, size)
    }

    fn on_mem_write(
        &mut self,
        engine: &mut Engine<CowMemory<M>>,
        address: u64,
        size: usize,
    ) -> remu64::Result<()> {
        self.config.hooks.on_mem_write(engine, address, size)
    }

    fn on_mem_fault(
        &mut self,
        engine: &mut Engine<CowMemory<M>>,
        address: u64,
        size: usize,
    ) -> remu64::Result<bool> {
        self.config.hooks.on_mem_fault(engine, address, size)
    }

    fn on_interrupt(
        &mut self,
        engine: &mut Engine<CowMemory<M>>,
        intno: u64,
        size: usize,
    ) -> remu64::Result<()> {
        self.config.hooks.on_interrupt(engine, intno, size)
    }

    fn on_invalid(
        &mut self,
        engine: &mut Engine<CowMemory<M>>,
        address: u64,
        size: usize,
    ) -> remu64::Result<()> {
        self.config.hooks.on_invalid(engine, address, size)
    }
}

/// Runner for trace capturing with configurable parameters
pub struct TraceRunner<'a, M: MemoryTrait + Clone, H: TracerHook<M>> {
    pub base_engine: remu64::Engine<CowMemory<M>>,
    pub base_config: crate::VmConfig<H>,
    pub capture_idx_memory: Option<usize>,
    pub capture_inst_range: Option<(usize, usize)>,
    pub snapshots: &'a mut BTreeMap<usize, crate::Snapshot<M, H>>,
    pub snapshot_interval: usize,
    pub max_instructions: usize,
}

impl<M: MemoryTrait + Clone, H: TracerHook<M>> TraceRunner<'_, M, H> {
    /// Find the optimal starting point (engine, config, start_idx) based on available snapshots
    fn find_optimal_start(&mut self) -> (remu64::Engine<CowMemory<M>>, crate::VmConfig<H>, usize) {
        // Determine the range start for snapshot selection
        let range_start = if let Some((start, _)) = self.capture_inst_range {
            start
        } else {
            // No capture range specified, try to use the latest snapshot for efficiency
            if let Some((&snap_idx, _)) = self.snapshots.iter().next_back() {
                snap_idx
            } else {
                0
            }
        };

        if let Some((&snap_idx, snapshot)) = self.snapshots.range(..=range_start).next_back() {
            debug!(
                "Found snapshot at instruction {} for range start {}, using snapshot",
                snap_idx, range_start
            );
            (snapshot.engine.clone(), snapshot.config.clone(), snap_idx)
        } else {
            debug!(
                "No snapshot found for range start {}, using base engine",
                range_start
            );
            (self.base_engine.clone(), self.base_config.clone(), 0)
        }
    }

    pub fn run(mut self) -> Result<TraceResult<CowMemory<M>, H>> {
        // Find the optimal starting point using snapshot selection logic
        let (mut engine, config, snapshot_start) = self.find_optimal_start();

        let TraceRunner {
            capture_idx_memory,
            capture_inst_range,
            snapshots,
            snapshot_interval,
            max_instructions,
            ..
        } = self;

        let trace_start_time = std::time::Instant::now();

        debug!(
            "run_trace called: max={}, range={:?}",
            config.max_instructions, capture_inst_range
        );

        let mut capturing_tracer = CapturingTracer::new(
            max_instructions,
            capture_idx_memory,
            capture_inst_range,
            snapshot_interval,
            snapshot_start,
            snapshots,
            config,
        );

        debug!("Executing function with CapturingTracer");

        // Execute with hooks - engine should already be properly set up by VmSetupProvider
        let error_message = match engine.emu_resume_with_hooks(&mut capturing_tracer) {
            Ok(_) => {
                info!(
                    "Function execution completed successfully with {} total instructions, captured {} entries in range {:?}",
                    capturing_tracer.current_instruction_index,
                    capturing_tracer.trace_entries.len(),
                    capture_inst_range
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
            hooks: capturing_tracer.config.hooks,
        })
    }
}
