use crate::error::Result;
use crate::memory::MemoryTrait;
use crate::{DEFAULT_PAGE_SIZE, Engine};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HookType {
    Code,
    MemRead,
    MemWrite,
    MemAccess,
    MemFault, // Called when memory access fails
    Interrupt,
    Invalid,
}

pub trait HookManager<M: MemoryTrait<PS>, const PS: u64 = DEFAULT_PAGE_SIZE> {
    fn on_code(&mut self, engine: &mut Engine<M, PS>, address: u64, size: usize) -> Result<()> {
        let _ = (engine, address, size);
        Ok(())
    }

    fn on_mem_read(&mut self, engine: &mut Engine<M, PS>, address: u64, size: usize) -> Result<()> {
        let _ = (engine, address, size);
        Ok(())
    }

    fn on_mem_write(
        &mut self,
        engine: &mut Engine<M, PS>,
        address: u64,
        size: usize,
    ) -> Result<()> {
        let _ = (engine, address, size);
        Ok(())
    }

    fn on_mem_access(
        &mut self,
        engine: &mut Engine<M, PS>,
        address: u64,
        size: usize,
    ) -> Result<()> {
        let _ = (engine, address, size);
        Ok(())
    }

    fn on_mem_fault(
        &mut self,
        engine: &mut Engine<M, PS>,
        address: u64,
        size: usize,
    ) -> Result<bool> {
        let _ = (engine, address, size);
        Ok(false)
    }

    fn on_interrupt(&mut self, engine: &mut Engine<M, PS>, intno: u64, size: usize) -> Result<()> {
        let _ = (engine, intno, size);
        Ok(())
    }

    fn on_invalid(&mut self, engine: &mut Engine<M, PS>, address: u64, size: usize) -> Result<()> {
        let _ = (engine, address, size);
        Ok(())
    }
}

/// Default no-op hook manager that does nothing for all hook events
#[derive(Debug, Default, Clone, Copy)]
pub struct NoHooks;

impl<M: MemoryTrait<PS>, const PS: u64> HookManager<M, PS> for NoHooks {
    // All methods use the default implementations which do nothing
}
