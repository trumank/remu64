use amd64_emu::hooks::HookManager;
use amd64_emu::memory::MemoryTrait;
use amd64_emu::{Engine, EngineMode, Permission, Register};

// Custom hook manager implementation
struct CustomHooks {
    code_hook_count: usize,
    mem_write_count: Vec<(u64, usize)>,
    mem_read_count: Vec<(u64, usize)>,
}

impl CustomHooks {
    fn new() -> Self {
        Self {
            code_hook_count: 0,
            mem_write_count: Vec::new(),
            mem_read_count: Vec::new(),
        }
    }
}

impl<M: MemoryTrait> HookManager<M> for CustomHooks {
    fn on_code(
        &mut self,
        engine: &mut Engine<M>,
        address: u64,
        size: usize,
    ) -> amd64_emu::Result<()> {
        self.code_hook_count += 1;
        println!(
            "[CODE] Executing instruction at {:#x} (size: {} bytes)",
            address, size
        );
        println!("  RAX = {:#x}", engine.reg_read(Register::RAX));
        Ok(())
    }

    fn on_mem_read(
        &mut self,
        _engine: &mut Engine<M>,
        address: u64,
        size: usize,
    ) -> amd64_emu::Result<()> {
        // Only log reads in the 0x2000 range
        if (0x2000..0x3000).contains(&address) {
            self.mem_read_count.push((address, size));
            println!("[MEM READ] Reading {} bytes from {:#x}", size, address);
        }
        Ok(())
    }

    fn on_mem_write(
        &mut self,
        _engine: &mut Engine<M>,
        address: u64,
        size: usize,
    ) -> amd64_emu::Result<()> {
        // Only log writes in the 0x2000 range
        if (0x2000..0x3000).contains(&address) {
            self.mem_write_count.push((address, size));
            println!("[MEM WRITE] Writing {} bytes to {:#x}", size, address);
        }
        Ok(())
    }
}

fn main() {
    env_logger::init();

    let mut engine = Engine::new(EngineMode::Mode64);
    let mut hooks = CustomHooks::new();

    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    engine
        .memory
        .map(0x2000, 0x1000, Permission::READ | Permission::WRITE)
        .unwrap();

    let code = vec![
        0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, 0x48, 0x89, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00,
        0x48, 0xC7, 0xC0, 0x02, 0x00, 0x00, 0x00, 0x48, 0x89, 0x04, 0x25, 0x08, 0x20, 0x00, 0x00,
        0x48, 0x8B, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, 0x48, 0x03, 0x04, 0x25, 0x08, 0x20, 0x00,
        0x00,
    ];

    engine.memory.write(0x1000, &code).unwrap();

    println!("\nStarting emulation with hooks...\n");
    engine
        .emu_start_with_hooks(0x1000, 0x1000 + code.len() as u64, 0, 0, &mut hooks)
        .unwrap();

    let rax = engine.reg_read(Register::RAX);
    println!("\n=== Emulation Results ===");
    println!("Final RAX value: {:#x}", rax);
    println!("Code hook executed {} times", hooks.code_hook_count);
    println!("Memory writes: {:?}", hooks.mem_write_count);
    println!("Memory reads: {:?}", hooks.mem_read_count);

    assert_eq!(rax, 3);
    println!("\nResult verified: 1 + 2 = {}", rax);
}
