use crate::process_trait::ProcessTrait;
use amd64_emu::memory::{CowMemory, MemoryTrait};
use amd64_emu::{Engine, EngineMode, Permission, Register};
use anyhow::Result;

pub struct VMContext<M: MemoryTrait> {
    pub engine: Engine<CowMemory<M>>,
}

impl<M: MemoryTrait> VMContext<M> {
    pub fn new<P: ProcessTrait<Memory = M>>(process: &P) -> Result<Self> {
        let base_memory = process.create_memory()?;
        let cow_memory = CowMemory::new(base_memory);
        let mut engine = Engine::new_memory(EngineMode::Mode64, cow_memory);

        let teb_address = process.get_teb_address()?;
        engine.set_gs_base(teb_address);

        Ok(VMContext { engine })
    }

    pub fn setup_stack(&mut self, base: u64, size: u64) -> Result<()> {
        self.engine.memory.map(
            base - size,
            size as usize,
            Permission::READ | Permission::WRITE,
        )?;
        Ok(())
    }

    /// Push raw bytes to the stack and return a pointer to them
    /// This operates directly on RSP
    pub fn push_bytes_to_stack(&mut self, data: &[u8]) -> Result<u64> {
        let current_rsp = self.engine.reg_read(Register::RSP);
        let new_rsp = current_rsp - data.len() as u64;

        // Write data to the new stack location
        self.engine.memory.write(new_rsp, data)?;

        // Update RSP
        self.engine.reg_write(Register::RSP, new_rsp);

        Ok(new_rsp)
    }

    /// Push a 64-bit value to the stack
    pub fn push_u64(&mut self, value: u64) -> Result<()> {
        let current_rsp = self.engine.reg_read(Register::RSP);
        let new_rsp = current_rsp - 8;

        let bytes = value.to_le_bytes();
        self.engine.memory.write(new_rsp, &bytes)?;
        self.engine.reg_write(Register::RSP, new_rsp);

        Ok(())
    }

    /// Reserve space on the stack (like shadow space)
    pub fn reserve_stack_space(&mut self, size: u64) {
        let current_rsp = self.engine.reg_read(Register::RSP);
        self.engine.reg_write(Register::RSP, current_rsp - size);
    }
}
