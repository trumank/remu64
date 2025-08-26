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
    /// This operates directly on RSP and maintains 16-byte alignment
    pub fn push_bytes_to_stack(&mut self, data: &[u8]) -> Result<u64> {
        let current_rsp = self.engine.reg_read(Register::RSP);

        // Calculate aligned size (round up to next 16-byte boundary)
        let aligned_size = (data.len() + 15) & !15;
        let new_rsp = current_rsp - aligned_size as u64;

        // Write data to the new stack location
        self.engine.memory.write(new_rsp, data)?;

        // Zero out any padding for security
        if aligned_size > data.len() {
            let padding_start = new_rsp + data.len() as u64;
            let padding_size = aligned_size - data.len();
            let zero_padding = vec![0u8; padding_size];
            self.engine.memory.write(padding_start, &zero_padding)?;
        }

        // Update RSP (maintains 16-byte alignment)
        self.engine.reg_write(Register::RSP, new_rsp);

        Ok(new_rsp)
    }

    /// Push a 64-bit value to the stack (maintains 16-byte alignment)
    pub fn push_u64(&mut self, value: u64) -> Result<()> {
        let current_rsp = self.engine.reg_read(Register::RSP);
        // Allocate 16 bytes to maintain alignment (even though we only need 8)
        let new_rsp = current_rsp - 16;

        let bytes = value.to_le_bytes();
        self.engine.memory.write(new_rsp, &bytes)?;

        // Zero out the padding for security
        let padding = [0u8; 8];
        self.engine.memory.write(new_rsp + 8, &padding)?;

        self.engine.reg_write(Register::RSP, new_rsp);

        Ok(())
    }

    /// Reserve space on the stack (like shadow space) maintaining 16-byte alignment
    pub fn reserve_stack_space(&mut self, size: u64) {
        let current_rsp = self.engine.reg_read(Register::RSP);
        // Round up to next 16-byte boundary
        let aligned_size = (size + 15) & !15;
        self.engine
            .reg_write(Register::RSP, current_rsp - aligned_size);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use amd64_emu::memory::OwnedMemory;

    // Mock process for testing
    struct MockProcess;

    impl MockProcess {
        fn new() -> Self {
            Self
        }
    }

    impl ProcessTrait for MockProcess {
        type Memory = OwnedMemory;

        fn get_module_by_name(&self, _name: &str) -> Option<crate::process_trait::ModuleInfo> {
            None
        }

        fn get_module_base_address(&self, _name: &str) -> Option<u64> {
            None
        }

        fn list_modules(&self) -> Vec<crate::process_trait::ModuleInfo> {
            Vec::new()
        }

        fn find_module_for_address(&self, _address: u64) -> Option<(String, u64, u64)> {
            None
        }

        fn create_memory(&self) -> Result<Self::Memory> {
            Ok(OwnedMemory::new())
        }

        fn get_teb_address(&self) -> Result<u64> {
            Ok(0x7fff_0000_0000)
        }

        fn get_architecture(&self) -> crate::process_trait::ProcessArchitecture {
            crate::process_trait::ProcessArchitecture::X64
        }
    }

    #[test]
    fn test_stack_alignment_failure() {
        let process = MockProcess::new();
        let mut ctx = VMContext::new(&process).unwrap();

        // Setup stack
        let stack_base = 0x0001_0000_0000u64;
        let stack_size = 0x100000u64; // 1MB
        ctx.setup_stack(stack_base, stack_size).unwrap();

        // Set initial RSP to be 16-byte aligned
        let initial_rsp = stack_base - 0x1000;
        ctx.engine.reg_write(Register::RSP, initial_rsp);

        // Verify initial alignment
        assert_eq!(initial_rsp % 16, 0, "Initial RSP should be 16-byte aligned");

        // Push some odd-sized data that will break alignment
        let test_data = b"hello"; // 5 bytes
        ctx.push_bytes_to_stack(test_data).unwrap();

        let rsp_after_push = ctx.engine.reg_read(Register::RSP);

        // This should fail - RSP is no longer 16-byte aligned
        assert_eq!(
            rsp_after_push % 16,
            0,
            "RSP should remain 16-byte aligned after push, but it's at {:#x}",
            rsp_after_push
        );
    }

    #[test]
    fn test_push_u64_alignment() {
        let process = MockProcess::new();
        let mut ctx = VMContext::new(&process).unwrap();

        // Setup stack
        let stack_base = 0x0001_0000_0000u64;
        let stack_size = 0x100000u64;
        ctx.setup_stack(stack_base, stack_size).unwrap();

        // Set initial RSP to be 16-byte aligned
        let initial_rsp = stack_base - 0x1000;
        ctx.engine.reg_write(Register::RSP, initial_rsp);

        // Push one u64 (8 bytes) - this breaks 16-byte alignment
        ctx.push_u64(0x1234567890abcdef).unwrap();

        let rsp_after_push = ctx.engine.reg_read(Register::RSP);

        // This should fail - after pushing 8 bytes, we're no longer 16-byte aligned
        assert_eq!(
            rsp_after_push % 16,
            0,
            "RSP should remain 16-byte aligned after push_u64, but it's at {:#x}",
            rsp_after_push
        );
    }

    #[test]
    fn test_reserve_stack_space_alignment() {
        let process = MockProcess::new();
        let mut ctx = VMContext::new(&process).unwrap();

        // Setup stack
        let stack_base = 0x0001_0000_0000u64;
        let stack_size = 0x100000u64;
        ctx.setup_stack(stack_base, stack_size).unwrap();

        // Set initial RSP to be 16-byte aligned
        let initial_rsp = stack_base - 0x1000;
        ctx.engine.reg_write(Register::RSP, initial_rsp);

        // Reserve odd amount of space (e.g., 12 bytes) - breaks alignment
        ctx.reserve_stack_space(12);

        let rsp_after_reserve = ctx.engine.reg_read(Register::RSP);

        // This should fail - RSP is no longer 16-byte aligned
        assert_eq!(
            rsp_after_reserve % 16,
            0,
            "RSP should remain 16-byte aligned after reserving space, but it's at {:#x}",
            rsp_after_reserve
        );
    }

    #[test]
    fn test_multiple_stack_operations_maintain_alignment() {
        let process = MockProcess::new();
        let mut ctx = VMContext::new(&process).unwrap();

        // Setup stack
        let stack_base = 0x0001_0000_0000u64;
        let stack_size = 0x100000u64;
        ctx.setup_stack(stack_base, stack_size).unwrap();

        // Set initial RSP to be 16-byte aligned
        let initial_rsp = stack_base - 0x1000;
        ctx.engine.reg_write(Register::RSP, initial_rsp);

        // Perform multiple operations and verify alignment is maintained throughout

        // Push a u64
        ctx.push_u64(0x1111111111111111).unwrap();
        let rsp1 = ctx.engine.reg_read(Register::RSP);
        assert_eq!(
            rsp1 % 16,
            0,
            "RSP should be 16-byte aligned after push_u64: {:#x}",
            rsp1
        );

        // Push some bytes
        ctx.push_bytes_to_stack(b"test data").unwrap();
        let rsp2 = ctx.engine.reg_read(Register::RSP);
        assert_eq!(
            rsp2 % 16,
            0,
            "RSP should be 16-byte aligned after push_bytes_to_stack: {:#x}",
            rsp2
        );

        // Reserve some space
        ctx.reserve_stack_space(40);
        let rsp3 = ctx.engine.reg_read(Register::RSP);
        assert_eq!(
            rsp3 % 16,
            0,
            "RSP should be 16-byte aligned after reserve_stack_space: {:#x}",
            rsp3
        );

        // Push another u64
        ctx.push_u64(0x2222222222222222).unwrap();
        let rsp4 = ctx.engine.reg_read(Register::RSP);
        assert_eq!(
            rsp4 % 16,
            0,
            "RSP should be 16-byte aligned after second push_u64: {:#x}",
            rsp4
        );

        // Verify we moved down from the original RSP
        assert!(rsp4 < initial_rsp, "RSP should have moved down the stack");

        // Verify the data we pushed is still there
        let mut buffer = [0u8; 8];
        ctx.engine.memory.read(rsp4, &mut buffer).unwrap();
        assert_eq!(u64::from_le_bytes(buffer), 0x2222222222222222);
    }

    #[test]
    fn test_alignment_with_various_data_sizes() {
        let process = MockProcess::new();
        let mut ctx = VMContext::new(&process).unwrap();

        // Setup stack
        let stack_base = 0x0001_0000_0000u64;
        let stack_size = 0x100000u64;
        ctx.setup_stack(stack_base, stack_size).unwrap();

        // Set initial RSP to be 16-byte aligned
        let initial_rsp = stack_base - 0x1000;
        ctx.engine.reg_write(Register::RSP, initial_rsp);

        // Test various data sizes
        let test_sizes = [1, 5, 8, 12, 16, 17, 24, 32, 33];

        for &size in &test_sizes {
            let test_data = vec![0x42u8; size];
            ctx.push_bytes_to_stack(&test_data).unwrap();

            let rsp = ctx.engine.reg_read(Register::RSP);
            assert_eq!(
                rsp % 16,
                0,
                "RSP should be 16-byte aligned after pushing {} bytes: {:#x}",
                size,
                rsp
            );
        }
    }
}
