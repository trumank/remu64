use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, prelude::*, widgets::ListState};
use std::io;
use std::time::{Duration, Instant};
use tracing::{debug, info};

use crate::config::ConfigLoader;
use crate::tracer::Tracer;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusMessage {
    ConfigReloaded,
    ConfigError(String),
}

pub struct AppState {
    pub selected_panel: Panel,
    pub instruction_scroll: usize,
    pub stack_scroll: usize,
    pub instruction_list_state: ListState,
    pub go_to_end: bool,

    pub symbolizer: PeSymbolizer,

    pub config_loader: ConfigLoader,

    // Status message system
    pub status_message: Option<StatusMessage>,
    pub status_message_expires: Option<Instant>,
}

impl AppState {
    pub fn current_trace_index(&self) -> usize {
        self.instruction_list_state.selected().unwrap_or(0)
    }

    pub fn set_status_message(&mut self, message: StatusMessage, duration: Option<Duration>) {
        self.status_message = Some(message);
        self.status_message_expires = duration.map(|d| Instant::now() + d);
    }

    pub fn update_status_message(&mut self) -> bool {
        if let Some(expires) = self.status_message_expires
            && Instant::now() >= expires
        {
            self.status_message = None;
            self.status_message_expires = None;
            return true; // Message was cleared
        }
        false
    }

    pub fn get_current_status_message(&self) -> Option<&StatusMessage> {
        self.status_message.as_ref()
    }

    pub fn toggle_skip_instruction(&mut self, index: usize) {
        use crate::tracer::InstructionAction;

        let actions = self
            .config_loader
            .config
            .instruction_actions
            .entry(index)
            .or_default();

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
                self.config_loader.config.instruction_actions.remove(&index);
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
    pub fn new(config_loader: ConfigLoader) -> Result<Self> {
        let config = &config_loader.config;

        debug!("Loading minidump: {}", config.minidump_path);
        let minidump_loader = DumpExec::load_minidump(&config.minidump_path)?;
        info!("Successfully loaded minidump: {}", config.minidump_path);

        // Create the memory object from the loader
        let memory = minidump_loader.create_memory()?;
        debug!("Created MinidumpMemory from loader");

        // Initialize the PeSymbolizer with the minidump loader
        let symbolizer = PeSymbolizer::new(&minidump_loader);
        info!("Initialized PeSymbolizer");

        let mut instruction_list_state = ListState::default();
        instruction_list_state.select(Some(0));

        let state = AppState {
            selected_panel: Panel::Instructions,
            instruction_scroll: 0,
            stack_scroll: 0,
            instruction_list_state,
            go_to_end: false,
            symbolizer,
            config_loader,
            status_message: None,
            status_message_expires: None,
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

        loop {
            let mut current_idx = self.state.current_trace_index();
            let max_limit = self.state.config_loader.config.tracing.max_instructions;

            // Create tracer for this frame
            let tracer = Tracer {
                minidump_loader: &self.minidump_loader,
                memory: &self.memory,
            };

            // Optional pre-pass: when tracing to end, determine the final instruction index
            if self.state.go_to_end {
                debug!("Trace-to-end pre-pass: determining total instruction count");

                let pre_pass_result = tracer.run_trace(
                    &self.state.config_loader.config,
                    max_limit,
                    0,      // Not capturing any entries in pre-pass
                    (0, 0), // Empty range - capture nothing
                )?;

                let total_instructions = pre_pass_result.total_instructions;
                debug!(
                    "Pre-pass completed: {} total instructions",
                    total_instructions
                );

                if total_instructions > 0 {
                    // Update current_idx to point to the final instruction
                    current_idx = total_instructions - 1;
                    debug!("Updated current_idx to final instruction: {}", current_idx);
                }

                // Update UI state and reset the flag
                self.state.instruction_list_state.select(Some(current_idx));
                debug!("Moved to end of trace: instruction {}", current_idx);
                self.state.go_to_end = false;
            }

            // Calculate dynamic capture range based on terminal size and current position
            let terminal_size = terminal.size()?;
            let instruction_area_height = terminal_size.height
                .saturating_sub(3) // Header
                .saturating_sub(2) // Borders
                * 70
                / 100; // Instructions panel is 70% of the main area
            let visible_instructions = (instruction_area_height as usize).max(10);
            let buffer = 50; // Buffer around visible area

            // Calculate range around current position (which may have been updated by pre-pass)
            let start = current_idx.saturating_sub(buffer);
            let end = current_idx + visible_instructions + buffer;

            let trace_result = tracer.run_trace(
                &self.state.config_loader.config,
                max_limit.min(end),
                current_idx,
                (start, end),
            )?;

            // Ensure current trace index is within bounds for normal tracing
            if current_idx >= trace_result.total_instructions && trace_result.total_instructions > 0
            {
                self.state
                    .instruction_list_state
                    .select(Some(trace_result.total_instructions - 1));
            }

            debug!(
                "Generated trace with {} sparse entries from {} total instructions",
                trace_result.entries.len(),
                trace_result.total_instructions
            );
            terminal.draw(|f| ui::draw(f, &mut self.state, &trace_result, &self.memory))?;

            let mut event = None;
            loop {
                if event::poll(std::time::Duration::from_millis(10))? {
                    while event::poll(std::time::Duration::from_millis(0))? {
                        match event::read()? {
                            Event::Mouse(_mouse_event) => {
                                // ignore mouse events for now because they can stack up and take a while to process
                                // if needed in the future, can merge and handle them together in one frame
                            }
                            other => {
                                event = Some(other);
                                break;
                            }
                        }
                    }
                    break;
                } else {
                    // Check if status message expired and needs redraw
                    if self.state.update_status_message() {
                        break;
                    }

                    // Check hot reload channel during polling timeout
                    match self.state.config_loader.check_watcher_changes() {
                        Ok(true) => {
                            info!(
                                "Config file was reloaded - breaking poll loop for immediate redraw"
                            );
                            self.state.set_status_message(
                                StatusMessage::ConfigReloaded,
                                Some(Duration::from_secs(1)),
                            );
                            break;
                        }
                        Ok(false) => {
                            // No config change, continue polling
                        }
                        Err(e) => {
                            debug!("Config watcher error: {}", e);
                            self.state.set_status_message(
                                StatusMessage::ConfigError(e.to_string()),
                                None,
                            );
                            break;
                        }
                    }
                }
            }

            if let Some(Event::Key(key)) = event
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
        self.state.go_to_end = false;
        // Reset instruction actions in config
        self.state.config_loader.config.instruction_actions.clear();
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
                self.state.go_to_end = true;
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
