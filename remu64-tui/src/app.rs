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

use crate::protocol_server::ProtocolServer;
use crate::tracer;
use crate::ui;
use crate::{VmSetupProvider, tracer::Snapshots};
use remu64::memory::MemoryTrait;
use remu64::{CowMemory, Engine};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Panel {
    Instructions,
    CpuState,
    Stack,
    Controls,
    Log,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusMessage {
    ConfigReloaded,
    ConfigError(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Goto {
    Line(usize),
    End,
}

#[derive(Clone)]
pub struct Snapshot<M: MemoryTrait + Clone, H: Clone> {
    pub engine: Engine<CowMemory<M>>,
    pub config: crate::VmConfig<H>,
    pub instruction_index: usize,
    pub logs: Vec<(usize, String)>,
}

pub struct AppState {
    pub selected_panel: Panel,
    pub instruction_scroll: usize,
    pub stack_scroll: usize,
    pub instruction_list_state: ListState,
    pub goto_target: Option<Goto>,

    // Status message system
    pub status_message: Option<StatusMessage>,
    pub status_message_expires: Option<Instant>,

    // Command mode
    pub command_input: Option<String>,
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
}

pub struct App {
    state: AppState,
    config: crate::TuiConfig,
    protocol_server: Option<ProtocolServer>,
}

impl App {
    pub fn new(config: crate::TuiConfig) -> Result<Self> {
        let mut instruction_list_state = ListState::default();
        instruction_list_state.select(Some(0));

        let state = AppState {
            selected_panel: Panel::Instructions,
            instruction_scroll: 0,
            stack_scroll: 0,
            instruction_list_state,
            goto_target: None,
            status_message: None,
            status_message_expires: None,
            command_input: None,
        };

        let protocol_server = if let Some(port) = config.tcp_port {
            Some(ProtocolServer::new(port)?)
        } else {
            None
        };

        Ok(App {
            state,
            config,
            protocol_server,
        })
    }

    pub fn run_with_provider<P: VmSetupProvider>(&mut self, setup_provider: P) -> Result<()> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        let result = self.run_app_with_provider(&mut terminal, setup_provider);

        disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        terminal.show_cursor()?;

        result
    }

    fn run_app_with_provider<P: VmSetupProvider>(
        &mut self,
        terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
        mut setup_provider: P,
    ) -> Result<()> {
        info!("Starting TUI main loop");

        // Create backend and hooks once
        let (vm_memory, mut symbolizer) = setup_provider.create_backend()?;
        let memory = CowMemory::new(vm_memory);

        // Snapshots at regular intervals for fast seeking
        let mut snapshots = Snapshots::new();

        loop {
            let mut current_idx = self.state.current_trace_index();

            // Create fresh engine and setup for each frame - only time we call setup_engine
            let mut engine = Engine::new_memory(remu64::EngineMode::Mode64, memory.clone());
            let config = setup_provider.setup_engine(&mut engine)?;

            let start_point = Snapshot {
                engine,
                config,
                instruction_index: 0,
                logs: Vec::new(),
            };

            // Handle goto operations: advance by snapshot_interval each frame for responsive UI
            if let Some(ref goto_target) = self.state.goto_target {
                let target_max = match goto_target {
                    Goto::End => self.config.max_instructions,
                    Goto::Line(target_line) => (*target_line + 1).min(self.config.max_instructions),
                };

                // Clamp max_instructions to last snapshot + snapshot_interval for incremental progress
                let incremental_max = snapshots
                    .snapshots_map
                    .last_key_value()
                    .map(|(i, _)| *i)
                    .unwrap_or(0)
                    + self.config.snapshot_interval;
                let max_instructions = target_max.min(incremental_max);

                let pre_pass_result = tracer::TraceRunner {
                    start_point: start_point.clone(),
                    capture_idx_memory: None,
                    capture_inst_range: None,
                    snapshots: &mut snapshots,
                    snapshot_interval: self.config.snapshot_interval,
                    max_instructions,
                }
                .run()?;

                let total_instructions = pre_pass_result.snapshot.instruction_index;
                debug!(
                    "Goto pre-pass completed: {} total instructions (target was {})",
                    total_instructions, max_instructions
                );

                // Check completion conditions
                let mut is_complete = total_instructions < max_instructions
                    || total_instructions >= self.config.max_instructions;

                if let Goto::Line(_) = goto_target {
                    is_complete |= total_instructions >= target_max;
                }

                if is_complete {
                    // We've reached the target or end - stop the goto operation
                    let last_instruction = total_instructions.saturating_sub(1);
                    current_idx = match goto_target {
                        Goto::End => last_instruction,
                        Goto::Line(target_line) => (*target_line).min(last_instruction),
                    };
                    debug!("Reached target at instruction: {}", current_idx);
                    self.state.goto_target = None;
                } else {
                    // Continue incrementally
                    current_idx = total_instructions;
                    debug!(
                        "Continuing incremental goto, now at instruction: {}",
                        current_idx
                    );
                }

                self.state.instruction_list_state.select(Some(current_idx));
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

            // Calculate range around current position
            let start = current_idx.saturating_sub(buffer);
            let end = current_idx + visible_instructions + buffer;

            let max_instructions = self.config.max_instructions.min(end);
            let trace_result = tracer::TraceRunner {
                start_point,
                capture_idx_memory: Some(current_idx),
                capture_inst_range: Some((start, end)),
                snapshots: &mut snapshots,
                snapshot_interval: self.config.snapshot_interval,
                max_instructions,
            }
            .run()?;

            // Ensure current trace index is within bounds
            if current_idx >= trace_result.snapshot.instruction_index {
                self.state
                    .instruction_list_state
                    .select(Some(trace_result.snapshot.instruction_index - 1));
            }

            debug!(
                "Generated trace with {} sparse entries from {} total instructions",
                trace_result.entries.len(),
                trace_result.snapshot.instruction_index + 1
            );

            terminal.draw(|f| {
                ui::draw(
                    f,
                    &mut self.state,
                    &trace_result,
                    &memory,
                    &mut symbolizer,
                    setup_provider.display_name(),
                )
            })?;

            // Set the most recent snapshot from the trace result
            // snapshots.most_recent = Some(trace_result.snapshot);

            let mut event = None;
            loop {
                let timeout = if self.state.goto_target.is_some() {
                    std::time::Duration::ZERO
                } else {
                    // TODO handle refresh if new TCP packets OR delay 10 millis
                    std::time::Duration::ZERO
                    // std::time::Duration::from_millis(10)
                };
                if event::poll(timeout)? {
                    while event::poll(std::time::Duration::ZERO)? {
                        match event::read()? {
                            Event::Mouse(_mouse_event) => {
                                // ignore mouse events for now
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
                    // Process protocol server requests
                    if let Some(ref mut server) = self.protocol_server {
                        server.process_requests(trace_result.memory_snapshot.as_ref().unwrap());
                    }
                    // debug!("frame");

                    // Continue to next frame if goto operation is still active
                    if self.state.goto_target.is_some() {
                        break;
                    }

                    // Check for reload signal from provider during polling timeout
                    match setup_provider.check_reload_signal() {
                        Ok(true) => {
                            snapshots.clear();
                            info!(
                                "Config reload signal received - breaking poll loop for immediate redraw"
                            );
                            self.state.set_status_message(
                                StatusMessage::ConfigReloaded,
                                Some(Duration::from_secs(1)),
                            );
                            break;
                        }
                        Ok(false) => {
                            // No reload signal, continue polling
                        }
                        Err(e) => {
                            debug!("Reload signal check error: {}", e);
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

                // Try handling command input
                if self.handle_command_mode_input(key.code) {
                    continue;
                }

                // Interrupt goto operation on any key press
                if self.state.goto_target.is_some() {
                    debug!("Interrupting goto operation");
                    self.state.goto_target = None;
                }

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
                        // TODO fix
                        // toggle_skip_index = Some(self.state.current_trace_index());
                    }
                    KeyCode::Char(':') => {
                        debug!("':' key - enter command mode");
                        self.state.command_input = Some(String::new());
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
            Panel::Stack => Panel::Log,
            Panel::Log => Panel::Controls,
            Panel::Controls => Panel::Instructions,
        };
    }

    fn prev_panel(&mut self) {
        self.state.selected_panel = match self.state.selected_panel {
            Panel::Instructions => Panel::Controls,
            Panel::CpuState => Panel::Instructions,
            Panel::Stack => Panel::CpuState,
            Panel::Log => Panel::Stack,
            Panel::Controls => Panel::Log,
        };
    }

    fn reset(&mut self) {
        self.state.instruction_list_state.select(Some(0));
        self.state.instruction_scroll = 0;
        self.state.stack_scroll = 0;
        self.state.goto_target = None;
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
                // Set goto target to end of trace
                self.state.goto_target = Some(Goto::End);
                debug!("Set goto target to end - will trace to function completion");
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

    fn handle_command_mode_input(&mut self, key_code: KeyCode) -> bool {
        if key_code == KeyCode::Enter
            && let Some(command) = self.state.command_input.take()
        {
            debug!("Executing command: {}", command);
            self.execute_command(&command);
            return true;
        }
        let Some(command) = &mut self.state.command_input else {
            return false;
        };
        match key_code {
            KeyCode::Esc => {
                debug!("Exiting command mode");
                self.state.command_input = None;
            }
            KeyCode::Backspace => {
                command.pop();
            }
            KeyCode::Char(c) => {
                command.push(c);
            }
            _ => {
                // Ignore other keys in command mode
            }
        }
        true
    }

    fn execute_command(&mut self, command: &str) {
        debug!("Command received: '{}'", command);

        let trimmed = command.trim();

        if trimmed.is_empty() {
            return;
        }

        if let Some(stripped) = trimmed.strip_prefix('+') {
            if let Ok(offset) = stripped.parse::<usize>() {
                let current_idx = self.state.current_trace_index();
                let target_line = current_idx + offset;
                self.state.goto_target = Some(Goto::Line(target_line));
            }
        } else if let Some(stripped) = trimmed.strip_prefix('-') {
            if let Ok(offset) = stripped.parse::<usize>() {
                let current_idx = self.state.current_trace_index();
                let target_line = current_idx.saturating_sub(offset);
                self.state.goto_target = Some(Goto::Line(target_line));
            }
        } else if let Ok(line_num) = trimmed.parse::<usize>() {
            self.state.goto_target = Some(Goto::Line(line_num));
        }
    }
}
