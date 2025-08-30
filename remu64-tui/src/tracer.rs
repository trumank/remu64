use anyhow::Result;
use iced_x86::{
    Decoder, DecoderOptions, Formatter, FormatterOutput, FormatterTextKind, IntelFormatter,
};
use ratatui::{
    style::{Color, Style},
    text::Span,
};
use rdex::{
    DumpExec, ExecutionController, MinidumpLoader, ProcessTrait, VMContext,
    pe_symbolizer::PeSymbolizer,
    symbolizer::{ResolvedSymbol, Symbolizer},
};
use remu64::{CowMemory, CpuState, Engine, HookAction, HookManager, Register, memory::MemoryTrait};
use std::{collections::HashMap, marker::PhantomData, path::PathBuf};
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

struct ColoredFormatterOutput {
    spans: Vec<Span<'static>>,
}

impl ColoredFormatterOutput {
    fn new() -> Self {
        Self { spans: Vec::new() }
    }

    fn into_spans(self) -> Vec<Span<'static>> {
        self.spans
    }
}

impl FormatterOutput for ColoredFormatterOutput {
    fn write(&mut self, text: &str, kind: FormatterTextKind) {
        let style = match kind {
            FormatterTextKind::Directive => Style::default().fg(Color::Cyan), // Prefixes like "rep"
            FormatterTextKind::Prefix => Style::default().fg(Color::Cyan), // Instruction prefixes
            FormatterTextKind::Mnemonic => Style::default().fg(Color::Yellow), // Instruction mnemonic
            FormatterTextKind::Keyword => Style::default().fg(Color::Magenta), // Keywords like "ptr", "byte"
            FormatterTextKind::Operator => Style::default().fg(Color::White), // Operators like +, -, *
            FormatterTextKind::Punctuation => Style::default().fg(Color::White), // Punctuation like [, ], ,
            FormatterTextKind::Number => Style::default().fg(Color::Green), // Numbers and addresses
            FormatterTextKind::Register => Style::default().fg(Color::Blue), // Register names
            FormatterTextKind::SelectorValue => Style::default().fg(Color::Green), // Selector values
            FormatterTextKind::LabelAddress => Style::default().fg(Color::Green), // Label addresses
            FormatterTextKind::FunctionAddress => Style::default().fg(Color::Green), // Function addresses
            FormatterTextKind::Data => Style::default().fg(Color::Green), // Data references
            FormatterTextKind::Label => Style::default().fg(Color::Green), // Labels
            FormatterTextKind::Function => Style::default().fg(Color::Green), // Function names
            _ => Style::default(),                                        // Default for other types
        };

        self.spans.push(Span::styled(text.to_owned(), style));
    }
}

pub struct CapturingTracer<P: ProcessTrait> {
    pub trace_entries: Vec<TraceEntry>,
    pub max_instructions: usize,
    pub actions: InstructionActions,
    pub current_instruction_index: usize,
    _phantom: PhantomData<P>,
}

impl<P: ProcessTrait> CapturingTracer<P> {
    pub fn new(max_instructions: usize, actions: &InstructionActions) -> Self {
        Self {
            trace_entries: Vec::new(),
            max_instructions,
            actions: actions.clone(),
            current_instruction_index: 0,
            _phantom: PhantomData,
        }
    }
}

impl<P: ProcessTrait> HookManager<CowMemory<P::Memory>> for CapturingTracer<P> {
    fn on_code(
        &mut self,
        engine: &mut Engine<CowMemory<P::Memory>>,
        address: u64,
        size: usize,
    ) -> remu64::Result<HookAction> {
        // Check if we've reached the maximum number of instructions
        if self.trace_entries.len() >= self.max_instructions {
            return Ok(HookAction::Stop);
        }

        // Capture CPU state at this instruction (before any modifications)
        let cpu_state = engine.cpu.clone();

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

pub struct Tracer {
    minidump_loader: MinidumpLoader<'static>,
    memory: rdex::MinidumpMemory<'static>,
    symbolizer: PeSymbolizer,
}

impl Tracer {
    pub fn new(minidump_path: PathBuf) -> Result<Self> {
        debug!("Attempting to load minidump: {:?}", minidump_path);
        let minidump_loader = DumpExec::load_minidump(&minidump_path)?;
        info!("Successfully loaded minidump: {:?}", minidump_path);

        // Create the memory object from the loader
        let memory = minidump_loader.create_memory()?;
        debug!("Created MinidumpMemory from loader");

        // Initialize the PeSymbolizer with the minidump loader
        let symbolizer = PeSymbolizer::new(&minidump_loader);
        info!("Initialized PeSymbolizer");

        Ok(Tracer {
            minidump_loader,
            memory,
            symbolizer,
        })
    }

    /// Run trace up to specified instruction index, returning trace entries
    pub fn run_trace(
        &self,
        function_address: u64,
        max_instructions: usize,
        actions: &InstructionActions,
    ) -> Result<(Vec<TraceEntry>, Option<String>)> {
        debug!(
            "run_trace called: addr=0x{:x}, max={}",
            function_address, max_instructions,
        );
        debug!("Creating VM context from minidump loader");

        let loader = &self.minidump_loader;

        // Create VM context directly from the process
        let mut vm_context = VMContext::new(loader)?;

        // Set up stack
        let stack_base = 0x7fff_f000_0000u64;
        let stack_size = 0x100000;
        vm_context.setup_stack(stack_base, stack_size)?;

        let initial_rsp = stack_base - 0x1000;
        vm_context.engine.reg_write(Register::RSP, initial_rsp);

        // let out = vm_context.push_bytes_to_stack(&u64::to_le_bytes(0x289f6333a00))?;
        vm_context.engine.reg_write(Register::RCX, 0x289836c6200);

        let mut capturing_tracer =
            CapturingTracer::<MinidumpLoader>::new(max_instructions, actions);

        debug!(
            "Executing function at 0x{:x} with CapturingTracer",
            function_address
        );

        // Use ExecutionController with our custom tracer
        let return_address = 0xFFFF800000000000u64;
        let error_message = match ExecutionController::execute_with_hooks(
            &mut vm_context.engine,
            function_address,
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

        Ok((trace, error_message))
    }

    /// Get symbol information for an address
    pub fn get_symbol_info(&mut self, address: u64) -> Option<ResolvedSymbol<'_>> {
        self.symbolizer.resolve_address(&self.memory, address)
    }

    /// Disassemble instruction and return colored spans for UI
    pub fn disassemble_instruction(&self, address: u64, size: usize) -> Vec<Span<'static>> {
        let mut instruction_bytes = vec![0; size];
        match self.memory.read(address, &mut instruction_bytes) {
            Ok(_) => {
                // Disassemble the instruction
                let mut decoder =
                    Decoder::with_ip(64, &instruction_bytes, address, DecoderOptions::NONE);

                if let Some(instruction) = decoder.iter().next() {
                    let mut formatter = IntelFormatter::new();
                    let mut output = ColoredFormatterOutput::new();
                    formatter.format(&instruction, &mut output);
                    output.into_spans()
                } else {
                    vec![Span::styled(
                        format!("invalid @ 0x{:x}", address),
                        Style::default().fg(Color::Red),
                    )]
                }
            }
            Err(_) => vec![Span::styled(
                format!("unmapped @ 0x{:x}", address),
                Style::default().fg(Color::Red),
            )],
        }
    }
}
