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
use rdex::symbolizer::Symbolizer as _;
use remu64::{Register, memory::MemoryTrait};

use crate::app::{AppState, Panel};
use crate::tracer::TraceEntry;

pub fn draw(
    f: &mut Frame,
    state: &mut AppState,
    trace: &[TraceEntry],
    memory: &dyn MemoryTrait,
    memory_snapshot: &dyn MemoryTrait,
    trace_error: Option<&str>,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)])
        .split(f.area());

    // Header
    draw_header(f, chunks[0], state, trace_error);

    // Main content area
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);

    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(12), Constraint::Min(0)])
        .split(main_chunks[1]);

    let right_top_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(51), Constraint::Min(0)])
        .split(right_chunks[0]);

    // Draw panels
    draw_instructions(f, main_chunks[0], state, memory, trace);
    draw_cpu_state(f, right_top_chunks[0], state, trace);
    draw_controls(f, right_top_chunks[1], state);
    draw_stack(f, right_chunks[1], state, trace, memory_snapshot);
}

fn draw_header(f: &mut Frame, area: Rect, state: &AppState, trace_error: Option<&str>) {
    let status = if let Some(error) = trace_error {
        format!("Error: {}", error)
    } else {
        "Ready".to_string()
    };

    let title = format!(
        "remu64-tui | File: {} | Function: 0x{:x} | Status: {}",
        state
            .minidump_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown"),
        state.function_address,
        status
    );

    let header_style = if trace_error.is_some() {
        Style::default().fg(Color::White).bg(Color::Red)
    } else {
        Style::default().fg(Color::White).bg(Color::DarkGray)
    };

    let header = Paragraph::new(title).style(header_style);

    f.render_widget(header, area);
}

fn draw_instructions(
    f: &mut Frame,
    area: Rect,
    state: &mut AppState,
    memory: &dyn MemoryTrait,
    trace: &[TraceEntry],
) {
    let selected = state.selected_panel == Panel::Instructions;
    let border_style = if selected {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    };

    let instructions: Vec<ListItem> = trace
        .iter()
        .enumerate()
        .map(|(index, entry)| {
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
            let colored_instruction = disassemble_instruction(memory, entry.address, entry.size);

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
            let padding_needed = 40_i32.saturating_sub(disasm_text.len() as i32).max(0) as usize;
            if padding_needed > 0 {
                instruction_spans.push(Span::raw(" ".repeat(padding_needed)));
            }

            // Add symbol/module+offset column at the end with different colors
            instruction_spans.push(Span::raw(" "));
            match state.symbolizer.resolve_address(memory, entry.address) {
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
                            instruction_spans.push(Span::styled("!".to_string(), Style::default()));
                            instruction_spans.push(Span::styled(
                                symbol_name.clone(),
                                Style::default().fg(Color::Yellow),
                            ));

                            if resolved_symbol.offset > 0 {
                                instruction_spans
                                    .push(Span::raw(format!("+0x{:x}", resolved_symbol.offset)));
                            }
                        }
                    } else {
                        // Just module information
                        let color = if entry.was_skipped {
                            Color::DarkGray
                        } else {
                            Color::Magenta
                        };
                        instruction_spans.push(Span::styled(
                            resolved_symbol.symbol.module.clone(),
                            Style::default().fg(color),
                        ));
                        let offset_style = if entry.was_skipped {
                            Style::default().fg(Color::DarkGray)
                        } else {
                            Style::default()
                        };
                        instruction_spans.push(Span::styled(
                            format!("+0x{:x}", resolved_symbol.offset),
                            offset_style,
                        ));
                    }
                }
                None => {
                    let color = if entry.was_skipped {
                        Color::DarkGray
                    } else {
                        Color::Red
                    };
                    instruction_spans.push(Span::styled("unknown", Style::default().fg(color)));
                }
            }

            ListItem::new(Line::from(instruction_spans))
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

    f.render_stateful_widget(list, area, &mut state.instruction_list_state);
}

fn draw_stack(
    f: &mut Frame,
    area: Rect,
    state: &mut AppState,
    trace: &[TraceEntry],
    memory_snapshot: &dyn MemoryTrait,
) {
    let selected = state.selected_panel == Panel::Stack;
    let border_style = if selected {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    };

    // Get current CPU state to find stack pointer
    let stack_content = if let Some(current_entry) = trace.get(state.current_trace_index()) {
        let rsp = current_entry.cpu_state.read_reg(Register::RSP);

        // Calculate how many stack entries we can display based on available height
        let available_height = area.height.saturating_sub(2) as usize; // Subtract borders
        let num_entries = available_height.max(1);

        // Read real stack data from memory snapshot
        let mut lines = Vec::new();
        for i in 0..num_entries {
            let addr = rsp + (i * 8) as u64;
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
                        if let Some(resolved_symbol) = state
                            .symbolizer
                            .resolve_address(memory_snapshot, current_addr)
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

                    let mut line_spans = vec![Span::styled(
                        format!("0x{:016x}: ", addr),
                        Style::default().fg(Color::Cyan),
                    )];
                    line_spans.extend(hex_spans);
                    line_spans.push(Span::raw(" "));

                    for (i, &chain_value) in value_chain.iter().enumerate() {
                        // Try to resolve the address to a symbol if it's not zero
                        let mut sym_spans = vec![];
                        if chain_value != 0
                            && let Some(resolved_symbol) = state
                                .symbolizer
                                .resolve_address(memory_snapshot, chain_value)
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
                    lines.push(Line::from(vec![
                        Span::styled(
                            format!("0x{:016x}: ", addr),
                            Style::default().fg(Color::Cyan),
                        ),
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

fn draw_cpu_state(f: &mut Frame, area: Rect, state: &AppState, trace: &[TraceEntry]) {
    let selected = state.selected_panel == Panel::CpuState;
    let border_style = if selected {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    };

    let cpu_content = if let Some(current_entry) = trace.get(state.current_trace_index()) {
        let cpu = &current_entry.cpu_state;
        // Get next CPU state for comparison (from next instruction)
        let next_cpu = trace
            .get(state.current_trace_index() + 1)
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
    ];

    let paragraph = Paragraph::new(controls).block(
        Block::default()
            .title("Controls")
            .borders(Borders::ALL)
            .border_style(border_style),
    );

    f.render_widget(paragraph, area);
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
