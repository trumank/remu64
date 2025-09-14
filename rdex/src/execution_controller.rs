use crate::process_trait::{ProcessTrait, VmMemory};
use crate::symbolizer::Symbolizer;
use crate::tracer::InstructionTracer;
use anyhow::Result;
use iced_x86::Formatter;
use remu64::memory::MemoryTrait;
use remu64::{CowMemory, EmulatorError, Engine, HookAction, HookManager};

pub struct ExecutionHooks<'a, 'b, P>
where
    P: ProcessTrait + ?Sized,
{
    pub process: &'a P,
    pub tracer: &'b mut InstructionTracer,
    pub symbolizer: Option<&'b mut dyn Symbolizer>,
    pub instruction_count: u64,
}

impl<'a, 'b, P> HookManager<CowMemory<VmMemory>> for ExecutionHooks<'a, 'b, P>
where
    P: ProcessTrait + ?Sized,
{
    fn on_code(
        &mut self,
        engine: &mut Engine<CowMemory<VmMemory>>,
        address: u64,
        size: usize,
    ) -> remu64::Result<HookAction> {
        self.instruction_count += 1;

        if self.tracer.is_enabled() {
            let mut instruction_bytes = vec![0; size];
            engine.memory.read(address, &mut instruction_bytes).unwrap();
            self.tracer
                .trace_instruction(
                    address,
                    &instruction_bytes,
                    engine,
                    self.symbolizer.as_deref_mut(),
                )
                .unwrap();
        }

        Ok(HookAction::Continue)
    }
}

pub struct ExecutionController;

impl ExecutionController {
    pub fn execute_with_hooks<M: MemoryTrait, H: HookManager<M>>(
        engine: &mut Engine<M>,
        start_address: u64,
        end_address: u64,
        hooks: &mut H,
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

    pub fn format_instruction_error<P: ProcessTrait + ?Sized>(
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
