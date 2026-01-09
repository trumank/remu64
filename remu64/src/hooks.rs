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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookAction {
    /// Continue normal execution
    Continue,
    /// Skip the current instruction (advance RIP but don't execute)
    Skip,
    /// Stop emulation immediately
    Stop,
}

pub trait HookManager<M: MemoryTrait<PS>, const PS: u64 = DEFAULT_PAGE_SIZE> {
    /// Called before instruction decode/execution at the given address
    /// This allows checking conditions like until address before memory access
    fn on_pre_code(&mut self, engine: &mut Engine<M, PS>, address: u64) -> Result<HookAction> {
        let _ = (engine, address);
        Ok(HookAction::Continue)
    }

    fn on_code(
        &mut self,
        engine: &mut Engine<M, PS>,
        address: u64,
        size: usize,
    ) -> Result<HookAction> {
        let _ = (engine, address, size);
        Ok(HookAction::Continue)
    }

    fn on_mem_read(&mut self, engine: &mut Engine<M, PS>, address: u64, size: usize) -> Result<()> {
        let _ = (engine, address, size);
        Ok(())
    }

    fn on_mem_post_read(&mut self, engine: &mut Engine<M, PS>, address: u64, data: &[u8]) -> Result<()> {
        let _ = (engine, address, data);
        Ok(())
    }

    fn on_mem_write(
        &mut self,
        engine: &mut Engine<M, PS>,
        address: u64,
        data: &[u8],
    ) -> Result<()> {
        let _ = (engine, address, data);
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
