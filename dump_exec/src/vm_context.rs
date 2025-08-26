use crate::minidump_loader::MinidumpLoader;
use crate::minidump_memory::MinidumpMemory;
use amd64_emu::memory::{CowMemory, MemoryTrait as _};
use amd64_emu::{Engine, EngineMode, Permission};
use anyhow::Result;

pub struct VMContext<'a> {
    pub engine: Engine<CowMemory<MinidumpMemory<'a>>>,
    pub minidump_loader: &'a MinidumpLoader<'a>,
}

impl<'a> VMContext<'a> {
    pub fn new(minidump_loader: &'a MinidumpLoader<'a>) -> Result<Self> {
        let minidump_memory = MinidumpMemory::new(minidump_loader.get_dump())?;
        let cow_memory = CowMemory::new(minidump_memory);
        let engine = Engine::new_memory(EngineMode::Mode64, cow_memory);

        Ok(VMContext {
            engine,
            minidump_loader,
        })
    }

    pub fn setup_stack(&mut self, base: u64, size: u64) -> Result<()> {
        self.engine.memory.map(
            base - size,
            size as usize,
            Permission::READ | Permission::WRITE,
        )?;
        Ok(())
    }

    pub fn setup_gs_segment(&mut self) -> Result<()> {
        let teb_address = self.minidump_loader.get_teb_address()?;
        self.engine.set_gs_base(teb_address);
        Ok(())
    }
}
