use anyhow::Result;
use remu64::{
    CowMemory, CpuState, Engine, HookAction, HookManager, hooks::NoHooks, memory::MemoryTrait,
};
use std::collections::{BTreeMap, HashMap};
use tracing::{debug, info, warn};

use crate::Snapshot;

#[derive(Debug)]
pub struct TuiContext<'a> {
    pub instruction_index: usize,
    pub logs: &'a mut Vec<(usize, String)>,
}

impl<'a> TuiContext<'a> {
    pub fn log(&mut self, message: String) {
        self.logs.push((self.instruction_index, message));
    }
}

pub struct Snapshots<M: MemoryTrait + Clone, H: Clone> {
    pub snapshots_map: BTreeMap<usize, crate::Snapshot<M, H>>,
    pub most_recent: Option<crate::Snapshot<M, H>>,
}

impl<M: MemoryTrait + Clone, H: Clone> Snapshots<M, H> {
    pub fn new() -> Self {
        Self {
            snapshots_map: BTreeMap::new(),
            most_recent: None,
        }
    }

    pub fn find_optimal_start(&self, range_start: usize) -> Option<Snapshot<M, H>> {
        // Check most_recent first if it's available and suitable
        if let Some(ref recent_snapshot) = self.most_recent
            && recent_snapshot.instruction_index <= range_start
        {
            return Some(recent_snapshot.clone());
        }

        // Fall back to searching the snapshots_map
        self.snapshots_map
            .range(..=range_start)
            .next_back()
            .map(|(_, snapshot)| snapshot)
            .cloned()
    }

    pub fn clear(&mut self) {
        self.snapshots_map.clear();
        self.most_recent = None;
    }
}

pub trait TracerHook<M: MemoryTrait>: Clone {
    fn on_code(
        &mut self,
        _tui_context: TuiContext,
        _engine: &mut Engine<CowMemory<M>>,
        _address: u64,
        _size: usize,
    ) -> remu64::Result<HookAction> {
        Ok(HookAction::Continue)
    }

    fn on_mem_read(
        &mut self,
        _tui_context: TuiContext,
        _engine: &mut Engine<CowMemory<M>>,
        _address: u64,
        _size: usize,
    ) -> remu64::Result<()> {
        Ok(())
    }

    fn on_mem_write(
        &mut self,
        _tui_context: TuiContext,
        _engine: &mut Engine<CowMemory<M>>,
        _address: u64,
        _size: usize,
    ) -> remu64::Result<()> {
        Ok(())
    }

    fn on_mem_fault(
        &mut self,
        _tui_context: TuiContext,
        _engine: &mut Engine<CowMemory<M>>,
        _address: u64,
        _size: usize,
    ) -> remu64::Result<bool> {
        Ok(false)
    }

    fn on_interrupt(
        &mut self,
        _tui_context: TuiContext,
        _engine: &mut Engine<CowMemory<M>>,
        _intno: u64,
        _size: usize,
    ) -> remu64::Result<()> {
        Ok(())
    }

    fn on_invalid(
        &mut self,
        _tui_context: TuiContext,
        _engine: &mut Engine<CowMemory<M>>,
        _address: u64,
        _size: usize,
    ) -> remu64::Result<()> {
        Ok(())
    }
}

impl<M: MemoryTrait> TracerHook<M> for NoHooks {}

#[derive(Debug, Clone)]
pub struct TraceEntry {
    pub address: u64,
    pub size: usize,
    pub cpu_state: CpuState,
    pub was_skipped: bool,
}

#[derive(Clone)]
pub struct TraceResult<M: MemoryTrait + Clone, H: Clone> {
    /// Sparse trace storage - only contains entries for instructions that have been viewed/requested
    pub entries: HashMap<usize, TraceEntry>,
    /// Memory snapshot at the selected instruction
    pub memory_snapshot: Option<CowMemory<M>>,
    /// Error message if execution failed
    pub error_message: Option<String>,
    /// Time taken to execute and capture the trace
    pub trace_duration: std::time::Duration,
    /// Final execution snapshot
    pub snapshot: crate::Snapshot<M, H>,
}

impl<M: MemoryTrait + Clone, H: Clone> TraceResult<M, H> {
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
    /// Snapshot of memory at selected instruction
    pub memory_snapshot: Option<CowMemory<M>>,

    pub max_instructions: usize,
    pub capture_idx_memory: Option<usize>,
    pub instruction_index: usize,
    /// Range of instructions to capture (start, end)
    pub capture_inst_range: Option<(usize, usize)>,
    /// Snapshot interval for creating periodic snapshots
    pub snapshot_interval: usize,
    /// Snapshots container
    pub snapshots: &'a mut Snapshots<M, H>,
    /// Config containing hooks and other settings
    pub config: crate::VmConfig<H>,
    /// Logs collected during execution
    pub logs: &'a mut Vec<(usize, String)>,
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
        let tui_context = TuiContext {
            instruction_index: self.instruction_index,
            logs: self.logs,
        };
        let user_action = self
            .config
            .hooks
            .on_code(tui_context, engine, address, size)?;

        // If user hooks want to stop or skip, respect that
        match user_action {
            HookAction::Stop => return Ok(HookAction::Stop),
            HookAction::Skip => return Ok(HookAction::Skip),
            HookAction::Continue => {}
        }

        // Check if we've reached the maximum number of instructions
        if self.instruction_index >= self.max_instructions {
            return Ok(HookAction::Stop);
        }

        // Create snapshot at interval boundaries
        if self.instruction_index > 0
            && self
                .instruction_index
                .is_multiple_of(self.snapshot_interval)
            && !self
                .snapshots
                .snapshots_map
                .contains_key(&self.instruction_index)
        {
            debug!(
                "Creating snapshot at instruction {} at address 0x{:x}",
                self.instruction_index, address
            );

            self.snapshots.snapshots_map.insert(
                self.instruction_index,
                crate::Snapshot {
                    engine: engine.clone(),
                    config: self.config.clone(),
                    instruction_index: self.instruction_index,
                    logs: self.logs.clone(),
                },
            );
        }

        // Check for actions on this instruction index
        let mut was_skipped = false;
        if let Some(actions) = self.config.instruction_actions.get(&self.instruction_index) {
            for action in actions {
                match action {
                    InstructionAction::Skip => {
                        debug!(
                            "Skipping instruction {} at 0x{:x}",
                            self.instruction_index, address
                        );
                        was_skipped = true;
                    }
                }
            }
        }

        // Only capture trace entry if it's within our requested range
        let should_capture = if let Some((start, end)) = self.capture_inst_range {
            self.instruction_index >= start && self.instruction_index <= end
        } else {
            false // No capture range specified, don't capture entries
        };

        if should_capture {
            // Capture CPU state at this instruction (before any modifications)
            let cpu_state = engine.cpu.clone();

            // Store the trace entry (whether skipped or not)
            self.trace_entries.insert(
                self.instruction_index,
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
            && self.instruction_index == capture_idx
        {
            self.memory_snapshot = Some(engine.memory.clone());
        }

        self.instruction_index += 1;

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
        let tui_context = TuiContext {
            instruction_index: self.instruction_index,
            logs: self.logs,
        };
        self.config
            .hooks
            .on_mem_read(tui_context, engine, address, size)
    }

    fn on_mem_write(
        &mut self,
        engine: &mut Engine<CowMemory<M>>,
        address: u64,
        size: usize,
    ) -> remu64::Result<()> {
        let tui_context = TuiContext {
            instruction_index: self.instruction_index,
            logs: self.logs,
        };
        self.config
            .hooks
            .on_mem_write(tui_context, engine, address, size)
    }

    fn on_mem_fault(
        &mut self,
        engine: &mut Engine<CowMemory<M>>,
        address: u64,
        size: usize,
    ) -> remu64::Result<bool> {
        let tui_context = TuiContext {
            instruction_index: self.instruction_index,
            logs: self.logs,
        };
        self.config
            .hooks
            .on_mem_fault(tui_context, engine, address, size)
    }

    fn on_interrupt(
        &mut self,
        engine: &mut Engine<CowMemory<M>>,
        intno: u64,
        size: usize,
    ) -> remu64::Result<()> {
        let tui_context = TuiContext {
            instruction_index: self.instruction_index,
            logs: self.logs,
        };
        self.config
            .hooks
            .on_interrupt(tui_context, engine, intno, size)
    }

    fn on_invalid(
        &mut self,
        engine: &mut Engine<CowMemory<M>>,
        address: u64,
        size: usize,
    ) -> remu64::Result<()> {
        let tui_context = TuiContext {
            instruction_index: self.instruction_index,
            logs: self.logs,
        };
        self.config
            .hooks
            .on_invalid(tui_context, engine, address, size)
    }
}

/// Runner for trace capturing with configurable parameters
pub struct TraceRunner<'a, M: MemoryTrait + Clone, H: TracerHook<M>> {
    pub start_point: Snapshot<M, H>,
    pub capture_idx_memory: Option<usize>,
    pub capture_inst_range: Option<(usize, usize)>,
    pub snapshots: &'a mut Snapshots<M, H>,
    pub snapshot_interval: usize,
    pub max_instructions: usize,
}

impl<M: MemoryTrait + Clone, H: TracerHook<M>> TraceRunner<'_, M, H> {
    /// Find the optimal starting point (engine, config, start_idx) based on available snapshots
    fn find_optimal_start(&mut self) -> Snapshot<M, H> {
        // Determine the range start for snapshot selection
        let range_start = if let Some((start, _)) = self.capture_inst_range {
            start
        } else {
            usize::MAX
        };

        if let Some(snapshot) = self.snapshots.find_optimal_start(range_start) {
            debug!(
                "Found snapshot at instruction {} for range start {}, using snapshot",
                snapshot.instruction_index, range_start
            );
            snapshot
        } else {
            debug!(
                "No snapshot found for range start {}, using base engine",
                range_start
            );
            self.start_point.clone()
        }
    }

    pub fn run(mut self) -> Result<TraceResult<M, H>> {
        // Find the optimal starting point using snapshot selection logic
        let Snapshot {
            mut engine,
            config,
            instruction_index,
            mut logs,
        } = self.find_optimal_start();

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

        let mut capturing_tracer = CapturingTracer {
            trace_entries: HashMap::new(),
            memory_snapshot: None,
            max_instructions,
            capture_idx_memory,
            instruction_index,
            capture_inst_range,
            snapshot_interval,
            snapshots,
            config,
            logs: &mut logs,
        };

        debug!("Executing function with CapturingTracer");

        // Execute with hooks - engine should already be properly set up by VmSetupProvider
        let error_message = match engine.emu_resume_with_hooks(&mut capturing_tracer) {
            Ok(_) => {
                info!(
                    "Function execution completed successfully with {} total instructions, captured {} entries in range {:?}",
                    capturing_tracer.instruction_index,
                    capturing_tracer.trace_entries.len(),
                    capture_inst_range
                );
                None
            }
            Err(e) => {
                // Check if this was due to reaching max instructions
                if capturing_tracer.instruction_index >= max_instructions {
                    debug!(
                        "Function execution stopped after reaching max instructions: {} total, {} captured",
                        capturing_tracer.instruction_index,
                        capturing_tracer.trace_entries.len()
                    );
                    None
                } else {
                    let error_msg = format!("Execution failed: {}", e);
                    warn!(
                        "Function execution failed: {}, total {} instructions, captured {} entries",
                        e,
                        capturing_tracer.instruction_index,
                        capturing_tracer.trace_entries.len()
                    );
                    Some(error_msg)
                }
            }
        };

        let trace_duration = trace_start_time.elapsed();

        debug!(
            "Returning {} sparse trace entries from {} total instructions in {:?}",
            capturing_tracer.trace_entries.len(),
            capturing_tracer.instruction_index,
            trace_duration
        );

        Ok(TraceResult {
            entries: capturing_tracer.trace_entries,
            memory_snapshot: capturing_tracer
                .memory_snapshot
                .or(Some(engine.memory.clone())),
            error_message,
            trace_duration,
            snapshot: crate::Snapshot {
                engine,
                config: capturing_tracer.config,
                instruction_index: capturing_tracer.instruction_index,
                logs,
            },
        })
    }
}
