use std::path::Path;

use crate::{VmConfig, VmSetupProvider};
use anyhow::Result;
use rdex::{
    DumpExec, MinidumpLoader, ProcessTrait, pe_symbolizer::PeSymbolizer, process_trait::VmMemory,
};
use remu64::{CowMemory, Engine, Register, hooks::NoHooks, memory::MemoryTrait as _};

use crate::config::ConfigLoader;

pub struct MinidumpSetupProvider {
    pub config_loader: ConfigLoader,
    pub minidump_loader: MinidumpLoader<'static>,
}

impl MinidumpSetupProvider {
    pub fn new(config_path: impl AsRef<Path>) -> Result<Self> {
        let config_loader = ConfigLoader::new(config_path)?;
        let minidump_loader = DumpExec::load_minidump(&config_loader.config.minidump_path)?;

        Ok(Self {
            config_loader,
            minidump_loader,
        })
    }
}

impl VmSetupProvider for MinidumpSetupProvider {
    type Memory = VmMemory;
    type Symbolizer = PeSymbolizer;
    type Hooks = NoHooks;

    fn create_backend(&self) -> Result<(Self::Memory, Self::Symbolizer)> {
        // Create memory from minidump
        let memory = self.minidump_loader.create_memory()?;

        // Create symbolizer
        let symbolizer = PeSymbolizer::new(&self.minidump_loader);

        Ok((memory, symbolizer))
    }

    fn setup_engine(
        &mut self,
        engine: &mut Engine<CowMemory<Self::Memory>>,
    ) -> Result<VmConfig<Self::Hooks>> {
        let config = &self.config_loader.config;

        // Set up stack memory region
        let stack_base = config.stack.base_address;
        let stack_size = config.stack.size;
        engine.memory.map(
            stack_base - stack_size,
            stack_size as usize,
            remu64::memory::Permission::READ | remu64::memory::Permission::WRITE,
        )?;

        // Set initial stack pointer
        let initial_rsp = stack_base - config.stack.initial_offset;
        engine.reg_write(Register::RSP, initial_rsp);

        // Set initial register values from config
        for (&reg, &value) in &config.registers {
            engine.reg_write(reg, value);
        }

        // Set GS base to TEB (Thread Environment Block) from minidump
        engine.set_gs_base(self.minidump_loader.get_teb_address()?);

        // Set initial RIP to function address
        engine.reg_write(Register::RIP, config.function_address);

        // Set up return address on stack
        let return_address = 0xFFFF800000000000u64;
        engine
            .memory
            .write(initial_rsp - 8, &return_address.to_le_bytes())?;
        engine.reg_write(Register::RSP, initial_rsp - 8);

        Ok(VmConfig {
            until_address: return_address,
            max_instructions: config.tracing.max_instructions,
            instruction_actions: config.instruction_actions.clone(),
            hooks: NoHooks,
        })
    }

    fn check_reload_signal(&mut self) -> Result<bool> {
        self.config_loader.check_watcher_changes()
    }

    fn display_name(&self) -> &str {
        // Create a static string from the minidump path
        // Note: This is a bit of a hack, but works for this use case
        &self.config_loader.config.minidump_path
    }
}
