use crate::process_trait::ProcessTrait;
use crate::symbolizer::Symbolizer;
use anyhow::Result;
use colored::*;
use iced_x86::{
    Decoder, DecoderOptions, Formatter, FormatterOutput, FormatterTextKind, Instruction,
    IntelFormatter,
};
use remu64::{Engine, Register, memory::MemoryTrait};
use std::io::Write;

struct ColorFormatterOutput {
    result: String,
}

impl ColorFormatterOutput {
    fn new() -> Self {
        Self {
            result: String::new(),
        }
    }

    fn clear(&mut self) {
        self.result.clear();
    }

    fn get_result(&self) -> &str {
        &self.result
    }
}

impl FormatterOutput for ColorFormatterOutput {
    fn write(&mut self, text: &str, kind: FormatterTextKind) {
        let colored_text = match kind {
            FormatterTextKind::Directive | FormatterTextKind::Keyword => text.bright_yellow(),
            FormatterTextKind::Prefix | FormatterTextKind::Mnemonic => text.red().bold(),
            FormatterTextKind::Register => text.bright_green(),
            FormatterTextKind::Number => text.bright_cyan(),
            FormatterTextKind::Punctuation => text.white(),
            FormatterTextKind::Text => text.white(),
            _ => text.normal(),
        };
        self.result.push_str(&colored_text.to_string());
    }
}

pub struct InstructionTracer {
    formatter: IntelFormatter,
    enabled: bool,
    full_trace: bool,
    instruction_count: usize,
    output: Box<dyn Write>,
    formatter_output: ColorFormatterOutput,
}

impl InstructionTracer {
    pub fn new(enabled: bool) -> Self {
        InstructionTracer {
            formatter: IntelFormatter::new(),
            enabled,
            full_trace: false,
            instruction_count: 0,
            output: Box::new(std::io::stdout()),
            formatter_output: ColorFormatterOutput::new(),
        }
    }

    pub fn new_with_output(enabled: bool, output: Box<dyn Write>) -> Self {
        InstructionTracer {
            formatter: IntelFormatter::new(),
            enabled,
            full_trace: false,
            instruction_count: 0,
            output,
            formatter_output: ColorFormatterOutput::new(),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    pub fn set_full_trace(&mut self, full_trace: bool) {
        self.full_trace = full_trace;
    }

    pub fn is_full_trace_enabled(&self) -> bool {
        self.full_trace
    }

    pub fn trace_instruction<M: MemoryTrait, P: ProcessTrait, S: Symbolizer<M>>(
        &mut self,
        rip: u64,
        instruction_bytes: &[u8],
        engine: &Engine<M>,
        process: &P,
        symbolizer: &mut S,
    ) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        self.instruction_count += 1;

        // Decode the instruction
        let mut decoder = Decoder::with_ip(64, instruction_bytes, rip, DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        decoder.decode_out(&mut instruction);

        // Get instruction length and actual bytes
        let hex_bytes = instruction_bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");

        // Format the disassembly with colors
        self.formatter_output.clear();
        self.formatter
            .format(&instruction, &mut self.formatter_output);

        // Create a plain text version for proper width formatting
        let mut plain = String::new();
        self.formatter.format(&instruction, &mut plain);
        let pad = 32usize.saturating_sub(plain.len() + (hex_bytes.len().saturating_sub(26)));

        let colored_disasm = format!(
            "{}{}",
            self.formatter_output.get_result().trim(),
            " ".repeat(pad)
        );

        // Get register values
        let rax = engine.reg_read(Register::RAX);
        let rcx = engine.reg_read(Register::RCX);
        let rdx = engine.reg_read(Register::RDX);
        let rbx = engine.reg_read(Register::RBX);
        let rsp = engine.reg_read(Register::RSP);
        let rbp = engine.reg_read(Register::RBP);
        let rsi = engine.reg_read(Register::RSI);
        let rdi = engine.reg_read(Register::RDI);
        let r8 = engine.reg_read(Register::R8);
        let r9 = engine.reg_read(Register::R9);
        let r10 = engine.reg_read(Register::R10);
        let r11 = engine.reg_read(Register::R11);
        let r12 = engine.reg_read(Register::R12);
        let r13 = engine.reg_read(Register::R13);
        let r14 = engine.reg_read(Register::R14);
        let r15 = engine.reg_read(Register::R15);

        // Check if RIP is in a known module
        let module_info = process.find_module_for_address(rip);

        // Try to get symbol information for the current instruction address
        let resolved_symbol = symbolizer.resolve_address(&engine.memory, rip);

        // Format the symbol information (no address since it's shown separately)
        let symbol_str = match (module_info, resolved_symbol) {
            (_, Some(resolved)) => {
                if resolved.offset == 0 {
                    format!("{}", resolved.symbol.name.bright_cyan())
                } else {
                    format!(
                        "{}+0x{:x}",
                        resolved.symbol.name.bright_cyan(),
                        resolved.offset
                    )
                }
            }
            (Some((module_name, _base, offset)), None) => {
                format!("{}+0x{:x}", module_name.green().bold(), offset)
            }
            (None, None) => String::new(),
        };

        if self.full_trace {
            // Full trace mode - show all registers
            writeln!(
                self.output,
                "{} 0x{:016x} {:26} {} {}",
                format!("[{:06}]", self.instruction_count).bright_black(),
                rip,
                hex_bytes.bright_magenta(),
                colored_disasm,
                symbol_str
            )?;

            // Show all general-purpose registers in a compact format
            writeln!(
                self.output,
                "         RAX={:016x} RCX={:016x} RDX={:016x} RBX={:016x}",
                rax, rcx, rdx, rbx
            )?;
            writeln!(
                self.output,
                "         RSP={:016x} RBP={:016x} RSI={:016x} RDI={:016x}",
                rsp, rbp, rsi, rdi
            )?;
            writeln!(
                self.output,
                "         R8 ={:016x} R9 ={:016x} R10={:016x} R11={:016x}",
                r8, r9, r10, r11
            )?;
            writeln!(
                self.output,
                "         R12={:016x} R13={:016x} R14={:016x} R15={:016x}",
                r12, r13, r14, r15
            )?;

            // Show XMM and YMM registers
            // for i in 0..16 {
            //     let xmm_reg = match i {
            //         0 => Register::XMM0, 1 => Register::XMM1, 2 => Register::XMM2, 3 => Register::XMM3,
            //         4 => Register::XMM4, 5 => Register::XMM5, 6 => Register::XMM6, 7 => Register::XMM7,
            //         8 => Register::XMM8, 9 => Register::XMM9, 10 => Register::XMM10, 11 => Register::XMM11,
            //         12 => Register::XMM12, 13 => Register::XMM13, 14 => Register::XMM14, 15 => Register::XMM15,
            //         _ => unreachable!(),
            //     };
            //     let ymm_reg = match i {
            //         0 => Register::YMM0, 1 => Register::YMM1, 2 => Register::YMM2, 3 => Register::YMM3,
            //         4 => Register::YMM4, 5 => Register::YMM5, 6 => Register::YMM6, 7 => Register::YMM7,
            //         8 => Register::YMM8, 9 => Register::YMM9, 10 => Register::YMM10, 11 => Register::YMM11,
            //         12 => Register::YMM12, 13 => Register::YMM13, 14 => Register::YMM14, 15 => Register::YMM15,
            //         _ => unreachable!(),
            //     };
            //     let xmm_val = engine.cpu.read_xmm(xmm_reg);
            //     let ymm_val = engine.cpu.read_ymm(ymm_reg);
            //     writeln!(self.output, "         XMM{:<2}={:032x} YMM{:<2}={:032x}{:032x}", i, xmm_val, i, ymm_val[1], ymm_val[0])?;
            // }
        } else {
            // Collect only the registers that are actually used by this instruction
            let mut seen_registers = std::collections::HashSet::new();
            let mut used_registers = Vec::new();

            // Check each operand to see which registers are involved
            for i in 0..instruction.op_count() {
                let reg = instruction.op_register(i);

                let reg_info = match reg {
                    iced_x86::Register::RAX => Some(("RAX", rax)),
                    iced_x86::Register::RCX => Some(("RCX", rcx)),
                    iced_x86::Register::RDX => Some(("RDX", rdx)),
                    iced_x86::Register::RBX => Some(("RBX", rbx)),
                    iced_x86::Register::RSP => Some(("RSP", rsp)),
                    iced_x86::Register::RBP => Some(("RBP", rbp)),
                    iced_x86::Register::RSI => Some(("RSI", rsi)),
                    iced_x86::Register::RDI => Some(("RDI", rdi)),
                    iced_x86::Register::R8 => Some(("R8", r8)),
                    iced_x86::Register::R9 => Some(("R9", r9)),
                    iced_x86::Register::R10 => Some(("R10", r10)),
                    iced_x86::Register::R11 => Some(("R11", r11)),
                    iced_x86::Register::R12 => Some(("R12", r12)),
                    iced_x86::Register::R13 => Some(("R13", r13)),
                    iced_x86::Register::R14 => Some(("R14", r14)),
                    iced_x86::Register::R15 => Some(("R15", r15)),
                    _ => None,
                };

                if let Some((name, value)) = reg_info
                    && seen_registers.insert(reg)
                {
                    used_registers
                        .push(format!("{}={:016x}", name, value).bright_blue().to_string());
                }
            }

            // Standard trace mode - show instruction with only the registers it uses
            let register_display = if used_registers.is_empty() {
                String::new()
            } else {
                format!(" \t {}", used_registers.join(" "))
            };

            writeln!(
                self.output,
                "{} 0x{:016x} {:26} {} {}{}",
                format!("[{:06}]", self.instruction_count).bright_black(),
                rip,
                hex_bytes.bright_magenta(),
                colored_disasm,
                symbol_str,
                register_display
            )?;
        }

        Ok(())
    }

    pub fn trace_memory_access(
        &mut self,
        address: u64,
        is_write: bool,
        value: Option<u64>,
    ) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        let access_type = if is_write {
            "WRITE".red()
        } else {
            "READ".blue()
        };

        match value {
            Some(val) => {
                writeln!(
                    self.output,
                    "{} {} @ 0x{:016x}: {}",
                    "[MEMORY]".bright_black(),
                    access_type,
                    address,
                    format!("0x{:x}", val).bright_white()
                )?;
            }
            None => {
                writeln!(
                    self.output,
                    "{} {} @ 0x{:016x}",
                    "[MEMORY]".bright_black(),
                    access_type,
                    address
                )?;
            }
        }

        Ok(())
    }

    pub fn trace_call(&mut self, from: u64, to: u64) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        writeln!(
            self.output,
            "{} from {} to {}",
            "[CALL]".bright_black(),
            format!("0x{:016x}", from).yellow(),
            format!("0x{:016x}", to).green().bold()
        )?;

        Ok(())
    }

    pub fn trace_return(&mut self, address: u64, return_value: u64) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        writeln!(
            self.output,
            "{} to {}, {}",
            "[RETURN]".bright_black(),
            format!("0x{:016x}", address).yellow(),
            format!("RAX=0x{:016x}", return_value).bright_blue()
        )?;

        Ok(())
    }

    pub fn get_instruction_count(&self) -> usize {
        self.instruction_count
    }

    pub fn reset(&mut self) {
        self.instruction_count = 0;
    }
}
