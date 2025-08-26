use crate::error::Result;
use crate::memory::MemoryTrait;
use crate::Engine;

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

pub trait HookManager<M: MemoryTrait> {
    fn on_code(&mut self, engine: &mut Engine<M>, address: u64, size: usize) -> Result<()> {
        let _ = (engine, address, size);
        Ok(())
    }

    fn on_mem_read(&mut self, engine: &mut Engine<M>, address: u64, size: usize) -> Result<()> {
        let _ = (engine, address, size);
        Ok(())
    }

    fn on_mem_write(&mut self, engine: &mut Engine<M>, address: u64, size: usize) -> Result<()> {
        let _ = (engine, address, size);
        Ok(())
    }

    fn on_mem_access(&mut self, engine: &mut Engine<M>, address: u64, size: usize) -> Result<()> {
        let _ = (engine, address, size);
        Ok(())
    }

    fn on_mem_fault(&mut self, engine: &mut Engine<M>, address: u64, size: usize) -> Result<bool> {
        let _ = (engine, address, size);
        Ok(false)
    }

    fn on_interrupt(&mut self, engine: &mut Engine<M>, intno: u64, size: usize) -> Result<()> {
        let _ = (engine, intno, size);
        Ok(())
    }

    fn on_invalid(&mut self, engine: &mut Engine<M>, address: u64, size: usize) -> Result<()> {
        let _ = (engine, address, size);
        Ok(())
    }
}

/// Default no-op hook manager that does nothing for all hook events
#[derive(Debug, Default, Clone, Copy)]
pub struct NoHooks;

impl<M: MemoryTrait> HookManager<M> for NoHooks {
    // All methods use the default implementations which do nothing
}
