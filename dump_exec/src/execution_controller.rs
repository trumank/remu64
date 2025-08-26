use crate::process_trait::ProcessTrait;
use crate::tracer::InstructionTracer;
use amd64_emu::memory::MemoryTrait;
use amd64_emu::{EmulatorError, Engine, HookManager};
use anyhow::Result;
use iced_x86::Formatter;

pub struct ExecutionHooks<'a, 'b, P: ProcessTrait> {
    pub process: &'a P,
    pub tracer: &'b mut InstructionTracer,
    pub instruction_count: u64,
}

impl<'a, 'b, P: ProcessTrait, M: MemoryTrait> HookManager<M> for ExecutionHooks<'a, 'b, P> {
    fn on_code(
        &mut self,
        engine: &mut Engine<M>,
        address: u64,
        size: usize,
    ) -> amd64_emu::Result<()> {
        self.instruction_count += 1;

        if self.tracer.is_enabled() {
            let mut instruction_bytes = vec![0; size];
            engine.memory.read(address, &mut instruction_bytes).unwrap();
            self.tracer
                .trace_instruction(address, &instruction_bytes, engine, Some(self.process))
                .unwrap();
        }

        Ok(())
    }
}

pub struct ExecutionController;

impl ExecutionController {
    pub fn execute_with_hooks<M: MemoryTrait>(
        engine: &mut Engine<M>,
        start_address: u64,
        end_address: u64,
        hooks: &mut impl HookManager<M>,
    ) -> Result<()> {
        match engine.emu_start_with_hooks(start_address, end_address, 0, 0, hooks) {
            Ok(()) => Ok(()),
            Err(EmulatorError::UnmappedMemory(addr)) => Err(anyhow::anyhow!(
                "Attempted to access unmapped page at 0x{:x}",
                addr
            )),
            Err(e) => Err(anyhow::anyhow!("Emulation error: {}", e)),
        }
    }

    pub fn format_instruction_error<P: ProcessTrait>(
        process: &P,
        rip: u64,
        instruction_bytes: &[u8],
        error: EmulatorError,
    ) -> Result<()> {
        let instruction_len = if !instruction_bytes.is_empty() {
            let mut decoder = iced_x86::Decoder::with_ip(
                64,
                instruction_bytes,
                rip,
                iced_x86::DecoderOptions::NONE,
            );
            let mut instruction = iced_x86::Instruction::default();
            decoder.decode_out(&mut instruction);
            instruction.len()
        } else {
            1
        };

        let actual_bytes = &instruction_bytes[..instruction_len.min(instruction_bytes.len())];
        let hex_bytes = actual_bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");

        let disasm = if !actual_bytes.is_empty() {
            let mut decoder =
                iced_x86::Decoder::with_ip(64, actual_bytes, rip, iced_x86::DecoderOptions::NONE);
            let mut instruction = iced_x86::Instruction::default();
            decoder.decode_out(&mut instruction);
            let mut formatter = iced_x86::IntelFormatter::new();
            let mut output = String::new();
            formatter.format(&instruction, &mut output);
            output
        } else {
            "<unable to decode>".to_string()
        };

        let address_str = match process.find_module_for_address(rip) {
            Some((module_name, _base, offset)) => {
                format!("0x{:016x} ({}+0x{:x})", rip, module_name, offset)
            }
            None => format!("0x{:016x}", rip),
        };

        anyhow::bail!(
            "Emulation failed at {}: {} [{}] ({} bytes)\nOriginal error: {}",
            address_str,
            disasm,
            hex_bytes,
            instruction_len,
            error
        )
    }
}
