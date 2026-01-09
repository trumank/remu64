use iced_x86::{
    Decoder, DecoderOptions, Formatter as _, FormatterOutput, FormatterTextKind, IntelFormatter,
};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
};
use rdex::symbolizer::Symbolizer;
use remu64::{CowMemory, Register, memory::MemoryTrait};

use crate::app::{AppState, Panel, StatusMessage};
use crate::tracer::{TraceResult, TracerHook};

pub fn draw<M: MemoryTrait + Clone, S: Symbolizer, H: TracerHook<M> + Clone>(
    f: &mut Frame,
    state: &mut AppState,
    trace_result: &TraceResult<M, H>,
    memory: &CowMemory<M>,
    symbolizer: &mut S,
    display_name: &str,
) {
    let chunks = if state.command_input.is_some() {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Min(0),
                Constraint::Length(1),
            ])
            .split(f.area())
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Min(0)])
            .split(f.area())
    };

    // Header
    draw_header(f, chunks[0], display_name, trace_result, state);

    // Main content area
    let main_content_area = chunks[1];
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(main_content_area);

    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(12), Constraint::Min(0)])
        .split(main_chunks[1]);

    // Split the lower right area between stack and log panes
    let stack_log_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(right_chunks[1]);

    let right_top_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(51), Constraint::Min(0)])
        .split(right_chunks[0]);

    // Draw panels
    draw_instructions(f, main_chunks[0], state, memory, symbolizer, trace_result);
    draw_cpu_state(f, right_top_chunks[0], state, trace_result);
    draw_controls(f, right_top_chunks[1], state);
    draw_stack(
        f,
        stack_log_chunks[0],
        state,
        trace_result,
        memory,
        symbolizer,
    );
    draw_log(f, stack_log_chunks[1], state, trace_result);

    // Draw command bar if in command mode
    if state.command_input.is_some() {
        draw_command_bar(f, chunks[2], state);
    }
}

fn draw_header<M: MemoryTrait + Clone, H: Clone>(
    f: &mut Frame,
    area: Rect,
    display_name: &str,
    trace_result: &TraceResult<M, H>,
    state: &AppState,
) {
    let mut status_parts = Vec::new();

    // Add timing and performance information
    let duration_ms = trace_result.trace_duration.as_millis();
    let time_str = if duration_ms < 1000 {
        format!("{}ms", duration_ms)
    } else {
        format!("{:.2}s", trace_result.trace_duration.as_secs_f64())
    };

    // Include sparse capture info
    let sparse_info = format!(
        "{}/{} entries",
        trace_result.entries.len(),
        trace_result.snapshot.instruction_index
    );
    status_parts.push(format!("Trace: {} ({})", time_str, sparse_info));

    // Add other status messages
    if let Some(status_msg) = state.get_current_status_message() {
        let msg_text = match status_msg {
            StatusMessage::ConfigReloaded => "Config reloaded",
            StatusMessage::ConfigError(err) => err,
        };
        status_parts.push(msg_text.to_string());
    } else if let Some(error) = &trace_result.error_message {
        status_parts.push(format!("Error: {}", error));
    }

    let status = if status_parts.is_empty() {
        "".to_string()
    } else {
        format!(" | {}", status_parts.join(" | "))
    };

    let title = format!("remu64-tui | {}{status}", display_name,);

    let header_style = if trace_result.error_message.is_some() {
        Style::default().fg(Color::White).bg(Color::Red)
    } else if let Some(status_msg) = state.get_current_status_message() {
        match status_msg {
            StatusMessage::ConfigReloaded => Style::default().fg(Color::White).bg(Color::DarkGray),
            StatusMessage::ConfigError(_) => Style::default().fg(Color::White).bg(Color::Red),
        }
    } else {
        Style::default().fg(Color::White).bg(Color::DarkGray)
    };

    let header = Paragraph::new(title).style(header_style);

    f.render_widget(header, area);
}

fn draw_instructions<M: MemoryTrait + Clone, S: Symbolizer, H: Clone>(
    f: &mut Frame,
    area: Rect,
    state: &mut AppState,
    memory: &CowMemory<M>,
    symbolizer: &mut S,
    trace_result: &TraceResult<M, H>,
) {
    let selected = state.selected_panel == Panel::Instructions;
    let border_style = if selected {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    };

    // Calculate the range of instructions to display
    let current_index = state.current_trace_index();
    let visible_height = area.height.saturating_sub(2) as usize; // Account for borders
    let start_index = current_index.saturating_sub(visible_height / 2);
    let end_index = (start_index + visible_height).min(trace_result.snapshot.instruction_index);

    let instructions: Vec<ListItem> = (start_index..end_index)
        .map(|index| {
            if let Some(entry) = trace_result.get_entry(index) {
                // We have trace data for this instruction
                let mut instruction_spans = vec![];

                // Add instruction index column
                let index_color = if entry.was_skipped {
                    Color::DarkGray
                } else {
                    Color::Gray
                };
                instruction_spans.push(Span::styled(
                    format!("{:4}: ", index),
                    Style::default().fg(index_color),
                ));

                // Add address column
                let addr_color = if entry.was_skipped {
                    Color::DarkGray
                } else {
                    Color::Cyan
                };
                instruction_spans.push(Span::styled(
                    format!("0x{:08x}: ", entry.address),
                    Style::default().fg(addr_color),
                ));

                // Add disassembled instruction (fixed width for alignment)
                let colored_instruction =
                    disassemble_instruction(memory, entry.address, entry.size);

                // Calculate the total length of the disassembly text
                let disasm_text: String = colored_instruction
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect();

                // Add the colored instruction spans, applying grey-out if skipped
                if entry.was_skipped {
                    // Override colors for skipped instructions
                    for span in colored_instruction {
                        instruction_spans.push(Span::styled(
                            span.content.to_string(),
                            Style::default().fg(Color::DarkGray),
                        ));
                    }
                } else {
                    instruction_spans.extend(colored_instruction);
                }

                // Pad to fixed width (40 chars) for alignment
                let padding_needed =
                    40_i32.saturating_sub(disasm_text.len() as i32).max(0) as usize;
                if padding_needed > 0 {
                    instruction_spans.push(Span::raw(" ".repeat(padding_needed)));
                }

                // Add symbol/module+offset column at the end with different colors
                instruction_spans.push(Span::raw(" "));

                match symbolizer.resolve_address(memory, entry.address) {
                    Some(resolved_symbol) => {
                        if let Some(symbol_name) = &resolved_symbol.symbol.name {
                            // We have a specific symbol
                            if entry.was_skipped {
                                // Grey out everything for skipped instructions
                                instruction_spans.push(Span::styled(
                                    format!("{}!{}", resolved_symbol.symbol.module, symbol_name),
                                    Style::default().fg(Color::DarkGray),
                                ));
                                if resolved_symbol.offset > 0 {
                                    instruction_spans.push(Span::styled(
                                        format!("+0x{:x}", resolved_symbol.offset),
                                        Style::default().fg(Color::DarkGray),
                                    ));
                                }
                            } else {
                                // Normal coloring for active instructions - module in cyan, symbol in yellow
                                instruction_spans.push(Span::styled(
                                    resolved_symbol.symbol.module.clone(),
                                    Style::default().fg(Color::Magenta),
                                ));
                                instruction_spans
                                    .push(Span::styled("!".to_string(), Style::default()));
                                instruction_spans.push(Span::styled(
                                    symbol_name.clone(),
                                    Style::default().fg(Color::Yellow),
                                ));

                                if resolved_symbol.offset > 0 {
                                    instruction_spans.push(Span::raw(format!(
                                        "+0x{:x}",
                                        resolved_symbol.offset
                                    )));
                                }
                            }
                        } else {
                            // We have a module but no specific symbol
                            if entry.was_skipped {
                                instruction_spans.push(Span::styled(
                                    format!(
                                        "{}+0x{:x}",
                                        resolved_symbol.symbol.module, resolved_symbol.offset
                                    ),
                                    Style::default().fg(Color::DarkGray),
                                ));
                            } else {
                                instruction_spans.push(Span::styled(
                                    resolved_symbol.symbol.module.clone(),
                                    Style::default().fg(Color::Magenta),
                                ));
                                instruction_spans
                                    .push(Span::raw(format!("+0x{:x}", resolved_symbol.offset)));
                            }
                        }
                    }
                    None => {
                        // No symbol information available
                        let addr_str = format!("+0x{:x}", entry.address);
                        if entry.was_skipped {
                            instruction_spans
                                .push(Span::styled(addr_str, Style::default().fg(Color::DarkGray)));
                        } else {
                            instruction_spans
                                .push(Span::styled(addr_str, Style::default().fg(Color::Cyan)));
                        }
                    }
                }

                ListItem::new(Line::from(instruction_spans))
            } else {
                // No trace data available for this instruction - show placeholder
                let instruction_spans = vec![
                    Span::styled(
                        format!("{:4}: ", index),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled("????????: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        "[trace data not available]",
                        Style::default()
                            .fg(Color::DarkGray)
                            .add_modifier(Modifier::ITALIC),
                    ),
                ];
                ListItem::new(Line::from(instruction_spans))
            }
        })
        .collect();

    let list = List::new(instructions)
        .block(
            Block::default()
                .title("Instructions")
                .borders(Borders::ALL)
                .border_style(border_style),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("");

    // Adjust list state to reflect the local index within the visible range
    let mut local_list_state = state.instruction_list_state.clone();
    if current_index >= start_index && current_index < end_index {
        local_list_state.select(Some(current_index - start_index));
    } else {
        local_list_state.select(None);
    }

    f.render_stateful_widget(list, area, &mut local_list_state);
}

fn draw_stack<M: MemoryTrait + Clone, S: Symbolizer, H: Clone>(
    f: &mut Frame,
    area: Rect,
    state: &mut AppState,
    trace_result: &TraceResult<M, H>,
    memory: &CowMemory<M>,
    symbolizer: &mut S,
) {
    let selected = state.selected_panel == Panel::Stack;
    let border_style = if selected {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    };

    // Get current CPU state to find stack pointer
    let stack_content = if let Some(current_entry) =
        trace_result.get_entry(state.current_trace_index())
    {
        let width = 8;
        let rsp = current_entry.cpu_state.read_reg(Register::RSP);
        let start = rsp.saturating_sub(5 * width);

        // Calculate how many stack entries we can display based on available height
        let available_height = area.height.saturating_sub(2) as usize; // Subtract borders
        let num_entries = available_height.max(1);

        // Read real stack data from memory snapshot
        let mut lines = Vec::new();
        let memory_snapshot = trace_result.memory_snapshot.as_ref().unwrap();

        for i in 0..num_entries {
            let addr = start + i as u64 * width;
            let is_current_rsp = addr == rsp;
            let mut buffer = [0u8; 8];
            match memory_snapshot.read(addr, &mut buffer) {
                Ok(_) => {
                    let mut hex_spans = Vec::new();
                    for (i, b) in buffer.iter().enumerate() {
                        if i > 0 {
                            hex_spans.push(Span::raw(" "));
                        }
                        let hex_color = if *b == 0 {
                            Color::DarkGray
                        } else {
                            Color::Reset
                        };
                        hex_spans.push(Span::styled(
                            format!("{:02x}", b),
                            Style::default().fg(hex_color),
                        ));
                    }

                    let mut current_addr = u64::from_le_bytes(buffer);
                    let mut value_chain = vec![current_addr];

                    while value_chain.len() < 3 && current_addr != 0 {
                        // Check if this address resolves to a symbol with a name
                        if let Some(resolved_symbol) =
                            symbolizer.resolve_address(memory_snapshot, current_addr)
                            && resolved_symbol.symbol.name.is_some()
                        {
                            // Stop chain following when we find a named symbol
                            break;
                        }

                        if let Ok(dereferenced) = memory_snapshot.read_u64(current_addr) {
                            value_chain.push(dereferenced);
                            current_addr = dereferenced;
                        } else {
                            break;
                        }
                    }

                    let address_style = if is_current_rsp {
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::Cyan)
                    };

                    let mut line_spans = vec![
                        if is_current_rsp {
                            Span::styled(
                                ">",
                                Style::default()
                                    .fg(Color::Yellow)
                                    .add_modifier(Modifier::BOLD),
                            )
                        } else {
                            Span::raw(" ")
                        },
                        Span::styled(format!("0x{:016x}: ", addr), address_style),
                    ];
                    line_spans.extend(hex_spans);
                    line_spans.push(Span::raw(" "));

                    for (i, &chain_value) in value_chain.iter().enumerate() {
                        // Try to resolve the address to a symbol if it's not zero
                        let mut sym_spans = vec![];
                        if chain_value != 0
                            && let Some(resolved_symbol) =
                                symbolizer.resolve_address(memory, chain_value)
                            && let Some(symbol_name) = &resolved_symbol.symbol.name
                        {
                            sym_spans.push(Span::raw(" ("));
                            sym_spans.push(Span::styled(
                                resolved_symbol.symbol.module.clone(),
                                Style::default().fg(Color::Magenta),
                            ));
                            sym_spans.push(Span::styled("!".to_string(), Style::default()));
                            sym_spans.push(Span::styled(
                                symbol_name.clone(),
                                Style::default().fg(Color::Yellow),
                            ));
                            if resolved_symbol.offset > 0 {
                                sym_spans
                                    .push(Span::raw(format!("+0x{:x}", resolved_symbol.offset)));
                            }
                            sym_spans.push(Span::raw(")"));
                        }
                        if i > 0 {
                            line_spans.push(Span::raw(" -> "));
                        }

                        let color = if chain_value == 0 {
                            // null
                            Color::DarkGray
                        } else if i < value_chain.len() - 1 || !sym_spans.is_empty() {
                            // points to valid data or symbol
                            Color::Green
                        } else {
                            Color::Blue
                        };

                        line_spans.push(Span::styled(
                            format!("0x{:016x}", chain_value),
                            Style::default().fg(color),
                        ));

                        line_spans.extend(sym_spans);
                    }

                    lines.push(Line::from(line_spans));
                }
                Err(_) => {
                    let address_style = if is_current_rsp {
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::Cyan)
                    };

                    lines.push(Line::from(vec![
                        if is_current_rsp {
                            Span::styled(
                                ">",
                                Style::default()
                                    .fg(Color::Yellow)
                                    .add_modifier(Modifier::BOLD),
                            )
                        } else {
                            Span::raw(" ")
                        },
                        Span::styled(format!("0x{:016x}: ", addr), address_style),
                        Span::styled(
                            "-- -- -- -- -- -- -- --",
                            Style::default().fg(Color::DarkGray),
                        ),
                        Span::styled(" (unmapped)", Style::default().fg(Color::Red)),
                    ]));
                }
            }
        }
        lines
    } else {
        vec![Line::from("No stack data available")]
    };

    let paragraph = Paragraph::new(stack_content).block(
        Block::default()
            .title("Stack")
            .borders(Borders::ALL)
            .border_style(border_style),
    );

    f.render_widget(paragraph, area);
}

fn draw_cpu_state<M: MemoryTrait + Clone, H: Clone>(
    f: &mut Frame,
    area: Rect,
    state: &AppState,
    trace_result: &TraceResult<M, H>,
) {
    let selected = state.selected_panel == Panel::CpuState;
    let border_style = if selected {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    };

    let cpu_content = if let Some(current_entry) =
        trace_result.get_entry(state.current_trace_index())
    {
        let cpu = &current_entry.cpu_state;
        // Get next CPU state for comparison (from next instruction)
        let next_cpu = trace_result
            .get_entry(state.current_trace_index() + 1)
            .map(|entry| &entry.cpu_state);

        let create_reg_span = |reg: Register, name: &str, spacing: &str| -> Vec<Span<'static>> {
            let value = cpu.read_reg(reg);
            let next_value = next_cpu.map(|next| next.read_reg(reg));
            let name_style = Style::default().fg(Color::Green);

            let mut spans = vec![
                Span::styled(format!("{}: ", name), name_style),
                Span::styled("0x", Style::default()),
            ];

            if let Some(next_val) = next_value {
                let current_hex = format!("{:016x}", value);
                let next_hex = format!("{:016x}", next_val);

                // Compare each hex digit and highlight ones that will change
                for (cur_char, next_char) in current_hex.chars().zip(next_hex.chars()) {
                    let digit_style = if cur_char != next_char {
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                    };
                    spans.push(Span::styled(cur_char.to_string(), digit_style));
                }
            } else {
                // No next value, show all digits in default style
                spans.push(Span::styled(format!("{:016x}", value), Style::default()));
            }

            spans.push(Span::raw(spacing.to_owned()));
            spans
        };

        let reg_pairs = [
            (Register::RAX, "RAX", Register::RCX, "RCX"),
            (Register::RDX, "RDX", Register::RBX, "RBX"),
            (Register::RSP, "RSP", Register::RBP, "RBP"),
            (Register::RSI, "RSI", Register::RDI, "RDI"),
            (Register::R8, "R8 ", Register::R9, "R9 "),
            (Register::R10, "R10", Register::R11, "R11"),
            (Register::R12, "R12", Register::R13, "R13"),
            (Register::R14, "R14", Register::R15, "R15"),
        ];

        let mut lines: Vec<Line> = reg_pairs
            .iter()
            .map(|(reg1, name1, reg2, name2)| {
                let mut spans = create_reg_span(*reg1, name1, "  ");
                spans.extend(create_reg_span(*reg2, name2, ""));
                Line::from(spans)
            })
            .collect();

        lines.push(Line::from(""));

        // RIP and RFLAGS with digit-level diffing
        let create_special_reg_line = |name: &str, value: u64, next_value: Option<u64>| {
            let name_style = Style::default().fg(Color::Yellow);
            let mut spans = vec![
                Span::styled(format!("{}: ", name), name_style),
                Span::styled("0x", Style::default()),
            ];

            if let Some(next_val) = next_value {
                let current_hex = format!("{:016x}", value);
                let next_hex = format!("{:016x}", next_val);

                // Compare each hex digit and highlight ones that will change
                for (cur_char, next_char) in current_hex.chars().zip(next_hex.chars()) {
                    let digit_style = if cur_char != next_char {
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                    };
                    spans.push(Span::styled(cur_char.to_string(), digit_style));
                }
            } else {
                // No next value, show all digits in default style
                spans.push(Span::styled(format!("{:016x}", value), Style::default()));
            }

            Line::from(spans)
        };

        lines.extend([
            create_special_reg_line("RIP", cpu.rip, next_cpu.map(|next| next.rip)),
            create_special_reg_line(
                "RFLAGS",
                cpu.rflags.bits(),
                next_cpu.map(|next| next.rflags.bits()),
            ),
        ]);

        lines
    } else {
        vec![Line::from("No CPU state available")]
    };

    let paragraph = Paragraph::new(cpu_content)
        .block(
            Block::default()
                .title("CPU State")
                .borders(Borders::ALL)
                .border_style(border_style),
        )
        .wrap(Wrap { trim: true });

    f.render_widget(paragraph, area);
}

fn draw_controls(f: &mut Frame, area: Rect, state: &AppState) {
    let selected = state.selected_panel == Panel::Controls;
    let border_style = if selected {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    };

    let controls = vec![
        Line::from(vec![
            Span::styled("↑/↓, j/k: ", Style::default().fg(Color::Cyan)),
            Span::raw("Navigate Trace"),
        ]),
        Line::from(vec![
            Span::styled("PgUp/PgDn, u/d: ", Style::default().fg(Color::Cyan)),
            Span::raw("Page Up/Down"),
        ]),
        Line::from(vec![
            Span::styled("g/G: ", Style::default().fg(Color::Cyan)),
            Span::raw("Go to Start/End"),
        ]),
        Line::from(vec![
            Span::styled("Tab: ", Style::default().fg(Color::Cyan)),
            Span::raw("Switch Panel"),
        ]),
        Line::from(vec![
            Span::styled("r: ", Style::default().fg(Color::Cyan)),
            Span::raw("Reset"),
        ]),
        Line::from(vec![
            Span::styled("q: ", Style::default().fg(Color::Cyan)),
            Span::raw("Quit"),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Config: ", Style::default().fg(Color::Green)),
            Span::raw("Hot-reloadable"),
        ]),
    ];

    let paragraph = Paragraph::new(controls).block(
        Block::default()
            .title("Controls")
            .borders(Borders::ALL)
            .border_style(border_style),
    );

    f.render_widget(paragraph, area);
}

fn draw_command_bar(f: &mut Frame, area: Rect, state: &AppState) {
    let command_text = format!(":{}", state.command_input.as_ref().unwrap());
    let command_paragraph =
        Paragraph::new(command_text).style(Style::default().fg(Color::White).bg(Color::Black));

    f.render_widget(command_paragraph, area);
}

/// Disassemble instruction and return colored spans for UI
fn disassemble_instruction(
    memory: &dyn MemoryTrait,
    address: u64,
    size: usize,
) -> Vec<Span<'static>> {
    let mut instruction_bytes = vec![0; size];
    match memory.read(address, &mut instruction_bytes) {
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

fn draw_log<M: MemoryTrait + Clone, H: TracerHook<M> + Clone>(
    f: &mut Frame,
    area: Rect,
    state: &AppState,
    trace_result: &TraceResult<M, H>,
) {
    let selected = state.selected_panel == Panel::Log;
    let border_style = if selected {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    };

    let current_index = state.current_trace_index();
    let log_messages = &trace_result.snapshot.logs;

    // Filter log messages to show only those up to the current instruction
    let relevant_logs: Vec<&(usize, String)> = log_messages
        .iter()
        .filter(|(instruction_idx, _)| *instruction_idx <= current_index)
        .collect();

    let available_height = area.height.saturating_sub(2) as usize; // Account for borders
    let start_idx = relevant_logs.len().saturating_sub(available_height);
    let visible_logs = &relevant_logs[start_idx..];

    let log_lines: Vec<Line> = visible_logs
        .iter()
        .map(|(instruction_idx, message)| {
            let line_spans = vec![
                Span::styled(
                    format!("{:4}: ", instruction_idx),
                    Style::default().fg(Color::Gray),
                ),
                Span::styled(message.clone(), Style::default().fg(Color::White)),
            ];
            Line::from(line_spans)
        })
        .collect();

    let paragraph = Paragraph::new(log_lines)
        .block(
            Block::default()
                .title("Log")
                .borders(Borders::ALL)
                .border_style(border_style),
        )
        .wrap(Wrap { trim: false });

    f.render_widget(paragraph, area);
}
