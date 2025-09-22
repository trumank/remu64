use anyhow::Result;
use rdex::{
    MinidumpLoader, ProcessTrait as _, pe_symbolizer::PeSymbolizer, process_trait::VmMemory,
};
use remu64::{CowMemory, Engine, HookAction, Register, memory::MemoryTrait};
use remu64_tui::{TracerHook, TuiConfig, TuiContext, VmConfig, VmSetupProvider, run_tui};
use std::collections::HashMap;

fn main() -> Result<()> {
    let path = "../meatloaf/dumps/FSD-Win64-Shipping.DMP";
    let setup = FsdSetupProvider {
        minidump: MinidumpLoader::load(path)?,
    };

    run_tui(setup, TuiConfig::default())?;

    Ok(())
}

struct FsdSetupProvider {
    pub minidump: rdex::MinidumpLoader<'static>,
}

impl VmSetupProvider for FsdSetupProvider {
    type Memory = VmMemory;
    type Symbolizer = PeSymbolizer;
    type Hooks = FsdHooks;

    fn create_backend(&self) -> Result<(Self::Memory, Self::Symbolizer)> {
        let memory = self.minidump.create_memory()?;
        let symbolizer = PeSymbolizer::new(&self.minidump);
        Ok((memory, symbolizer))
    }

    fn setup_engine(
        &mut self,
        engine: &mut Engine<CowMemory<Self::Memory>>,
    ) -> Result<VmConfig<Self::Hooks>> {
        // Set up stack memory region from fsd.toml configuration
        let stack_base = 0x7fff_f000_0000;
        let stack_size = 0x100000;
        engine.memory.map(
            stack_base - stack_size,
            stack_size as usize,
            remu64::memory::Permission::READ | remu64::memory::Permission::WRITE,
        )?;

        // Set initial stack pointer with offset from config
        let initial_rsp = stack_base - 0x1000;
        engine.reg_write(Register::RSP, initial_rsp);

        engine.set_gs_base(self.minidump.get_teb_address()?);

        // Set function address from fsd.toml
        engine.reg_write(Register::RIP, 0x7ff728460d50);

        // Set RCX register from config
        engine.reg_write(Register::RCX, 0x289836c6200);

        // Set up return address
        let return_address = 0xFFFF800000000000u64;
        engine
            .memory
            .write(initial_rsp - 8, &return_address.to_le_bytes())?;
        engine.reg_write(Register::RSP, initial_rsp - 8);

        // Configure instruction actions from fsd.toml
        let mut instruction_actions = HashMap::new();
        instruction_actions.insert(206, vec![remu64_tui::InstructionAction::Skip]);

        Ok(VmConfig {
            until_address: return_address,
            instruction_actions,
            hooks: FsdHooks::new(),
        })
    }

    fn display_name(&self) -> &str {
        "FSD Analysis"
    }

    fn check_reload_signal(&mut self) -> Result<bool> {
        Ok(false)
    }
}

#[derive(Clone)]
struct FsdHooks {
    // Hook at address 0x7ff728460db1 from fsd.toml
    hook_address: u64,
}

impl FsdHooks {
    fn new() -> Self {
        Self {
            hook_address: 0x7ff728460db1,
        }
    }
}

impl<M: MemoryTrait> TracerHook<M> for FsdHooks {
    fn on_code(
        &mut self,
        mut ctx: TuiContext,
        engine: &mut Engine<CowMemory<M>>,
        address: u64,
        _size: usize,
    ) -> remu64::Result<HookAction> {
        // Python hook equivalent - log when we hit the configured address
        if address == self.hook_address {
            ctx.log(format!(
                "Hit Python hook address: 0x{:x} (RIP: 0x{:x})",
                self.hook_address,
                engine.reg_read(Register::RIP)
            ));

            // Log some register state like the Python hook might do
            let rcx = engine.reg_read(Register::RCX);
            let rdx = engine.reg_read(Register::RDX);
            let r8 = engine.reg_read(Register::R8);

            ctx.log(format!(
                "Registers: RCX=0x{:x}, RDX=0x{:x}, R8=0x{:x}",
                rcx, rdx, r8
            ));
        }

        Ok(HookAction::Continue)
    }

    fn on_mem_write(
        &mut self,
        mut ctx: TuiContext,
        _engine: &mut Engine<CowMemory<M>>,
        address: u64,
        size: usize,
    ) -> remu64::Result<()> {
        // Log memory writes for debugging
        ctx.log(format!("Memory write: 0x{:x} ({} bytes)", address, size));
        Ok(())
    }
}
