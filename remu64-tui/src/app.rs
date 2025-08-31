use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, prelude::*, widgets::ListState};
use std::io;
use std::{collections::HashMap, path::PathBuf};
use tracing::{debug, info};

use crate::tracer::{InstructionAction, InstructionActions, Tracer};
use crate::ui;
use rdex::{
    DumpExec, MinidumpLoader, MinidumpMemory, ProcessTrait as _, pe_symbolizer::PeSymbolizer,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Panel {
    Instructions,
    CpuState,
    Stack,
    Controls,
}

pub struct AppState {
    pub minidump_path: PathBuf,
    pub function_address: u64,

    pub selected_panel: Panel,
    pub instruction_scroll: usize,
    pub stack_scroll: usize,
    pub instruction_list_state: ListState,
    pub trace_to_end: bool,
    pub instruction_actions: InstructionActions,

    pub symbolizer: PeSymbolizer,
}

impl AppState {
    pub fn current_trace_index(&self) -> usize {
        self.instruction_list_state.selected().unwrap_or(0)
    }

    pub fn toggle_skip_instruction(&mut self, index: usize) {
        let actions = self.instruction_actions.entry(index).or_default();

        // Check if skip action already exists
        if let Some(pos) = actions
            .iter()
            .position(|action| matches!(action, InstructionAction::Skip))
        {
            // Remove skip action
            actions.remove(pos);
            debug!("Removed skip action for instruction {}", index);

            // Remove empty action list
            if actions.is_empty() {
                self.instruction_actions.remove(&index);
            }
        } else {
            // Add skip action
            actions.push(InstructionAction::Skip);
            debug!("Added skip action for instruction {}", index);
        }
    }
}

pub struct App {
    state: AppState,
    minidump_loader: MinidumpLoader<'static>,
    memory: MinidumpMemory<'static>,
}

impl App {
    pub fn new(minidump_path: PathBuf, function_address: u64) -> Result<Self> {
        debug!("Loading minidump: {:?}", minidump_path);
        let minidump_loader = DumpExec::load_minidump(&minidump_path)?;
        info!("Successfully loaded minidump: {:?}", minidump_path);

        // Create the memory object from the loader
        let memory = minidump_loader.create_memory()?;
        debug!("Created MinidumpMemory from loader");

        // Initialize the PeSymbolizer with the minidump loader
        let symbolizer = PeSymbolizer::new(&minidump_loader);
        info!("Initialized PeSymbolizer");

        let mut instruction_list_state = ListState::default();
        instruction_list_state.select(Some(0));

        let state = AppState {
            minidump_path,
            function_address,
            selected_panel: Panel::Instructions,
            instruction_scroll: 0,
            stack_scroll: 0,
            instruction_list_state,
            trace_to_end: false,
            instruction_actions: HashMap::new(),
            symbolizer,
        };

        Ok(App {
            state,
            minidump_loader,
            memory,
        })
    }

    pub fn run(&mut self) -> Result<()> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        let result = self.run_app(&mut terminal);

        disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        terminal.show_cursor()?;

        result
    }

    fn run_app(&mut self, terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
        info!("Starting TUI main loop");
        let mut frame_count = 0;

        loop {
            frame_count += 1;
            if frame_count % 100 == 0 {
                debug!(
                    "Frame {}, current trace index: {}",
                    frame_count,
                    self.state.current_trace_index()
                );
            }

            let current_idx = self.state.current_trace_index();

            // Calculate required instructions based on mode and current position
            let required_instructions = if self.state.trace_to_end {
                // Run trace to completion (use a very large number)
                usize::MAX
            } else {
                // Calculate dynamic max_instructions based on terminal size and current position
                let terminal_size = terminal.size()?;
                let instruction_area_height = terminal_size.height
                    .saturating_sub(3) // Header
                    .saturating_sub(2) // Borders
                    * 70
                    / 100; // Instructions panel is 70% of the main area
                let base_instructions = (instruction_area_height as usize).max(10);

                // Get the current trace index to see how far we've scrolled

                // Calculate required instructions: current position + visible area + buffer
                current_idx + base_instructions + 50 // 50 instruction buffer
            };

            // Create tracer for this frame
            let tracer = Tracer {
                minidump_loader: &self.minidump_loader,
                memory: &self.memory,
            };

            // Generate trace with appropriate limit
            let (trace, memory_snapshot, trace_error) = tracer.run_trace(
                self.state.function_address,
                required_instructions,
                current_idx,
                &self.state.instruction_actions,
            )?;

            // Handle trace_to_end completion
            if self.state.trace_to_end {
                // Move to the last instruction and reset the flag
                if !trace.is_empty() {
                    self.state
                        .instruction_list_state
                        .select(Some(trace.len() - 1));
                    debug!("Moved to end of trace: {} instructions", trace.len());
                }
                self.state.trace_to_end = false;
            } else {
                // Ensure current trace index is within bounds
                if current_idx >= trace.len() && !trace.is_empty() {
                    self.state
                        .instruction_list_state
                        .select(Some(trace.len() - 1));
                }
            }

            debug!("Generated trace with {} entries", trace.len());
            terminal.draw(|f| {
                ui::draw(
                    f,
                    &mut self.state,
                    &trace,
                    &self.memory,
                    &memory_snapshot,
                    trace_error.as_deref(),
                )
            })?;

            if let Event::Key(key) = event::read()?
                && key.kind == KeyEventKind::Press
            {
                debug!("Key pressed: {:?}", key.code);
                match key.code {
                    KeyCode::Char('q') => {
                        info!("User requested quit");
                        break;
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        debug!("Up key - calling handle_up");
                        self.handle_up();
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        debug!("Down key - calling handle_down");
                        self.handle_down();
                    }
                    KeyCode::PageUp | KeyCode::Char('u') => {
                        debug!("PageUp key - calling handle_page_up");
                        self.handle_page_up();
                    }
                    KeyCode::PageDown | KeyCode::Char('d') => {
                        debug!("PageDown key - calling handle_page_down");
                        self.handle_page_down();
                    }
                    KeyCode::Tab => {
                        debug!("Tab key - switching panel");
                        self.next_panel();
                    }
                    KeyCode::BackTab => {
                        debug!("BackTab key - switching panel backward");
                        self.prev_panel();
                    }
                    KeyCode::Char('r') => {
                        info!("Reset requested");
                        self.reset();
                    }
                    KeyCode::Char('g') => {
                        debug!("'g' key - go to beginning");
                        self.handle_go_to_beginning();
                    }
                    KeyCode::Char('G') => {
                        debug!("'G' key - go to end");
                        self.handle_go_to_end();
                    }
                    KeyCode::Char('s') => {
                        debug!("'s' key - toggle skip instruction");
                        self.handle_toggle_skip();
                    }
                    _ => {
                        debug!("Unhandled key: {:?}", key.code);
                    }
                }
            }
        }

        Ok(())
    }

    fn handle_up(&mut self) {
        match self.state.selected_panel {
            Panel::Instructions => {
                let current_idx = self.state.current_trace_index();
                if current_idx > 0 {
                    let new_idx = current_idx - 1;
                    self.state.instruction_list_state.select(Some(new_idx));
                    debug!("Moved to instruction index: {}", new_idx);
                }
            }
            Panel::Stack => {
                if self.state.stack_scroll > 0 {
                    self.state.stack_scroll -= 1;
                    debug!("Stack scroll up to: {}", self.state.stack_scroll);
                }
            }
            _ => {
                debug!(
                    "Up key pressed but not handled for panel: {:?}",
                    self.state.selected_panel
                );
            }
        }
    }

    fn handle_down(&mut self) {
        match self.state.selected_panel {
            Panel::Instructions => {
                let new_idx = self.state.current_trace_index() + 1;
                self.state.instruction_list_state.select(Some(new_idx));
            }
            Panel::Stack => {
                self.state.stack_scroll += 1;
            }
            _ => {}
        }
    }

    fn handle_page_up(&mut self) {
        match self.state.selected_panel {
            Panel::Instructions => {
                let new_idx = self.state.current_trace_index().saturating_sub(10);
                self.state.instruction_list_state.select(Some(new_idx));
            }
            Panel::Stack => {
                self.state.stack_scroll = self.state.stack_scroll.saturating_sub(10);
            }
            _ => {}
        }
    }

    fn handle_page_down(&mut self) {
        match self.state.selected_panel {
            Panel::Instructions => {
                let new_idx = self.state.current_trace_index() + 10;
                self.state.instruction_list_state.select(Some(new_idx));
            }
            Panel::Stack => {
                self.state.stack_scroll += 10;
            }
            _ => {}
        }
    }

    fn next_panel(&mut self) {
        self.state.selected_panel = match self.state.selected_panel {
            Panel::Instructions => Panel::CpuState,
            Panel::CpuState => Panel::Stack,
            Panel::Stack => Panel::Controls,
            Panel::Controls => Panel::Instructions,
        };
    }

    fn prev_panel(&mut self) {
        self.state.selected_panel = match self.state.selected_panel {
            Panel::Instructions => Panel::Controls,
            Panel::CpuState => Panel::Instructions,
            Panel::Stack => Panel::CpuState,
            Panel::Controls => Panel::Stack,
        };
    }

    fn reset(&mut self) {
        self.state.instruction_list_state.select(Some(0));
        self.state.instruction_scroll = 0;
        self.state.stack_scroll = 0;
        self.state.trace_to_end = false;
    }

    fn handle_go_to_beginning(&mut self) {
        match self.state.selected_panel {
            Panel::Instructions => {
                self.state.instruction_list_state.select(Some(0));
                debug!("Moved to first instruction");
            }
            Panel::Stack => {
                self.state.stack_scroll = 0;
                debug!("Moved to top of stack");
            }
            _ => {
                debug!(
                    "'g' key pressed but not handled for panel: {:?}",
                    self.state.selected_panel
                );
            }
        }
    }

    fn handle_go_to_end(&mut self) {
        match self.state.selected_panel {
            Panel::Instructions => {
                // Set flag to run trace to completion
                self.state.trace_to_end = true;
                debug!("Set trace_to_end flag - will trace to function completion");
            }
            Panel::Stack => {
                // Move to a reasonable "end" position for stack view
                self.state.stack_scroll = 100; // Will get clamped by UI bounds
                debug!("Moved to bottom of stack view");
            }
            _ => {
                debug!(
                    "'G' key pressed but not handled for panel: {:?}",
                    self.state.selected_panel
                );
            }
        }
    }

    fn handle_toggle_skip(&mut self) {
        match self.state.selected_panel {
            Panel::Instructions => {
                let current_idx = self.state.current_trace_index();
                self.state.toggle_skip_instruction(current_idx);
            }
            _ => {
                debug!(
                    "'s' key pressed but not handled for panel: {:?}",
                    self.state.selected_panel
                );
            }
        }
    }
}
