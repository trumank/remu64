use anyhow::Result;
use iced_x86::{Decoder, DecoderOptions, Formatter, FormatterOutput, FormatterTextKind, IntelFormatter, Instruction};
use amd64_emu::{Engine, Register};
use std::io::Write;
use colored::*;
use crate::MinidumpLoader;

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
    instruction_count: usize,
    output: Box<dyn Write>,
    formatter_output: ColorFormatterOutput,
}

impl InstructionTracer {
    pub fn new(enabled: bool) -> Self {
        InstructionTracer {
            formatter: IntelFormatter::new(),
            enabled,
            instruction_count: 0,
            output: Box::new(std::io::stdout()),
            formatter_output: ColorFormatterOutput::new(),
        }
    }

    pub fn new_with_output(enabled: bool, output: Box<dyn Write>) -> Self {
        InstructionTracer {
            formatter: IntelFormatter::new(),
            enabled,
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

    pub fn trace_instruction(
        &mut self,
        rip: u64,
        instruction_bytes: &[u8],
        engine: &Engine,
        loader: Option<&MinidumpLoader>,
    ) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        self.instruction_count += 1;

        // Decode the instruction
        let mut decoder = Decoder::with_ip(64, instruction_bytes, rip, DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        decoder.decode_out(&mut instruction);

        // Format the disassembly with colors
        self.formatter_output.clear();
        self.formatter.format(&instruction, &mut self.formatter_output);
        let colored_disasm = self.formatter_output.get_result();

        // Get key register values
        let rax = engine.reg_read(Register::RAX).unwrap_or(0);
        let rcx = engine.reg_read(Register::RCX).unwrap_or(0);
        let rdx = engine.reg_read(Register::RDX).unwrap_or(0);
        let rsp = engine.reg_read(Register::RSP).unwrap_or(0);
        let rbp = engine.reg_read(Register::RBP).unwrap_or(0);
        let rsi = engine.reg_read(Register::RSI).unwrap_or(0);
        let rdi = engine.reg_read(Register::RDI).unwrap_or(0);
        let r8 = engine.reg_read(Register::R8).unwrap_or(0);
        let r9 = engine.reg_read(Register::R9).unwrap_or(0);

        // Check if RIP is in a known module
        let module_info = loader
            .and_then(|l| l.find_module_for_address(rip));

        // Format the address with module information
        let address_str = match module_info {
            Some((module_name, _base, offset)) => {
                format!("{}+0x{:x}", module_name.green().bold(), offset)
            }
            None => format!("0x{:016x}", rip).yellow().to_string()
        };

        // Format the trace output
        writeln!(
            self.output,
            "{} {}: {} | {} {} {}",
            format!("[{:06}]", self.instruction_count).bright_black(),
            address_str,
            colored_disasm,
            format!("RAX={:016x}", rax).bright_blue(),
            format!("RCX={:016x}", rcx).bright_blue(),
            format!("RDX={:016x}", rdx).bright_blue()
        )?;

        // Print additional registers if they're being used by the instruction
        let uses_rsp_rbp = (0..instruction.op_count()).any(|i| {
            let reg = instruction.op_register(i);
            reg == iced_x86::Register::RSP || reg == iced_x86::Register::RBP
        });
        
        if uses_rsp_rbp {
            writeln!(
                self.output,
                "         {:30} | {} {}",
                "",
                format!("RSP={:016x}", rsp).bright_blue(),
                format!("RBP={:016x}", rbp).bright_blue()
            )?;
        }

        let uses_rsi_rdi = (0..instruction.op_count()).any(|i| {
            let reg = instruction.op_register(i);
            reg == iced_x86::Register::RSI || reg == iced_x86::Register::RDI
        });
        
        if uses_rsi_rdi {
            writeln!(
                self.output,
                "         {:30} | {} {}",
                "",
                format!("RSI={:016x}", rsi).bright_blue(),
                format!("RDI={:016x}", rdi).bright_blue()
            )?;
        }

        let uses_r8_r9 = (0..instruction.op_count()).any(|i| {
            let reg = instruction.op_register(i);
            reg == iced_x86::Register::R8 || reg == iced_x86::Register::R9
        });
        
        if uses_r8_r9 {
            writeln!(
                self.output,
                "         {:30} | {} {}",
                "",
                format!("R8={:016x}", r8).bright_blue(),
                format!("R9={:016x}", r9).bright_blue()
            )?;
        }

        Ok(())
    }


    pub fn trace_memory_access(
        &mut self,
        address: u64,
        size: usize,
        is_write: bool,
        value: Option<u64>,
    ) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        let access_type = if is_write { "WRITE".red() } else { "READ".blue() };
        
        match value {
            Some(val) => {
                writeln!(
                    self.output,
                    "{} {} @ {} ({} bytes): {}",
                    "[MEMORY]".bright_black(),
                    access_type,
                    format!("0x{:016x}", address).yellow(),
                    size,
                    format!("0x{:x}", val).bright_white()
                )?;
            }
            None => {
                writeln!(
                    self.output,
                    "{} {} @ {} ({} bytes)",
                    "[MEMORY]".bright_black(),
                    access_type,
                    format!("0x{:016x}", address).yellow(),
                    size
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