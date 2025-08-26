use amd64_emu::memory::MemoryTrait;
use amd64_emu::{Engine, Register};
use anyhow::Result;

pub struct StackManager {
    pub base: u64,
    pub current: u64,
}

impl StackManager {
    pub fn new(base: u64) -> Self {
        Self {
            base,
            current: base - 8,
        }
    }

    pub fn push_u64<M: MemoryTrait>(&mut self, engine: &mut Engine<M>, value: u64) -> Result<()> {
        self.current -= 8;
        let bytes = value.to_le_bytes();
        engine.memory.write(self.current, &bytes)?;
        Ok(())
    }

    pub fn push_bytes<M: MemoryTrait>(
        &mut self,
        engine: &mut Engine<M>,
        data: &[u8],
    ) -> Result<u64> {
        self.current -= data.len() as u64;
        let addr = self.current;
        engine.memory.write(addr, data)?;
        Ok(addr)
    }

    pub fn allocate(&mut self, size: u64) -> u64 {
        self.current -= size;
        self.current
    }

    pub fn align_to(&mut self, alignment: u64) {
        self.current = (self.current - alignment + 1) & !(alignment - 1);
    }

    pub fn set_stack_pointer<M: MemoryTrait>(&self, engine: &mut Engine<M>) {
        engine.reg_write(Register::RSP, self.current);
    }

    pub fn reserve_shadow_space(&mut self) {
        self.current -= 32;
    }
}
