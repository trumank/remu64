use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
};
use remu64::Register;

use crate::app::{AppState, Panel};
use crate::tracer::{TraceEntry, Tracer};

pub fn draw(
    f: &mut Frame,
    state: &mut AppState,
    trace: &[TraceEntry],
    tracer: &mut Tracer,
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

    let left_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(main_chunks[0]);

    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(main_chunks[1]);

    // Draw panels
    draw_instructions(f, left_chunks[0], state, trace, tracer);
    draw_stack(f, left_chunks[1], state, trace);
    draw_cpu_state(f, right_chunks[0], state, trace);
    draw_controls(f, right_chunks[1], state);
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
    trace: &[TraceEntry],
    tracer: &mut Tracer,
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
            let colored_instruction = tracer.disassemble_instruction(entry.address, entry.size);

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
            match tracer.get_symbol_info(entry.address) {
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
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    f.render_stateful_widget(list, area, &mut state.instruction_list_state);
}

fn draw_stack(f: &mut Frame, area: Rect, state: &AppState, trace: &[TraceEntry]) {
    let selected = state.selected_panel == Panel::Stack;
    let border_style = if selected {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    };

    // Get current CPU state to find stack pointer
    let stack_content = if let Some(current_entry) = trace.get(state.current_trace_index()) {
        let rsp = current_entry.cpu_state.read_reg(Register::RSP);

        // Create mock stack data for now
        let mut lines = Vec::new();
        for i in 0..16 {
            let addr = rsp + (i * 8);
            lines.push(Line::from(vec![
                Span::styled(
                    format!("0x{:016x}: ", addr),
                    Style::default().fg(Color::Cyan),
                ),
                Span::raw("00 01 02 03 04 05 06 07"),
            ]));
        }
        lines
    } else {
        vec![Line::from("No stack data available")]
    };

    let paragraph = Paragraph::new(stack_content)
        .block(
            Block::default()
                .title("Stack")
                .borders(Borders::ALL)
                .border_style(border_style),
        )
        .wrap(Wrap { trim: true });

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
