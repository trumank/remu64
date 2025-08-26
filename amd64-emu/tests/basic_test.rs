use amd64_emu::{Engine, EngineMode, Permission, Register};

#[test]
fn test_mov_instruction() {
    let mut engine = Engine::new(EngineMode::Mode64);

    engine.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();

    let code = vec![
        0x48, 0xB8, 0x37, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0xC3,
    ];

    engine.mem_write(0x1000, &code).unwrap();

    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(engine.reg_read(Register::RAX), 0x1337);
    assert_eq!(engine.reg_read(Register::RBX), 0x1337);
}

#[test]
fn test_arithmetic_operations() {
    let mut engine = Engine::new(EngineMode::Mode64);

    engine.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();

    let code = vec![
        0x48, 0xC7, 0xC0, 0x0A, 0x00, 0x00, 0x00, 0x48, 0xC7, 0xC3, 0x05, 0x00, 0x00, 0x00, 0x48,
        0x01, 0xD8, 0x48, 0x29, 0xD8, 0x48, 0x31, 0xDB,
    ];

    engine.mem_write(0x1000, &code).unwrap();

    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(engine.reg_read(Register::RAX), 10);
    assert_eq!(engine.reg_read(Register::RBX), 0);
}

#[test]
fn test_memory_operations() {
    let mut engine = Engine::new(EngineMode::Mode64);

    engine
        .mem_map(0x1000, 0x1000, Permission::EXEC | Permission::READ)
        .unwrap();
    engine
        .mem_map(0x2000, 0x1000, Permission::READ | Permission::WRITE)
        .unwrap();

    let code = vec![
        0x48, 0xC7, 0xC0, 0x42, 0x00, 0x00, 0x00, 0x48, 0x89, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00,
        0x48, 0x8B, 0x1C, 0x25, 0x00, 0x20, 0x00, 0x00,
    ];

    engine.mem_write(0x1000, &code).unwrap();

    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(engine.reg_read(Register::RBX), 0x42);

    let mut buf = [0u8; 8];
    engine.mem_read(0x2000, &mut buf).unwrap();
    assert_eq!(u64::from_le_bytes(buf), 0x42);
}

#[test]
fn test_stack_operations() {
    let mut engine = Engine::new(EngineMode::Mode64);

    engine.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();
    engine
        .mem_map(0x7000, 0x1000, Permission::READ | Permission::WRITE)
        .unwrap();

    engine.reg_write(Register::RSP, 0x7800);

    let code = vec![0x48, 0xC7, 0xC0, 0xEF, 0xBE, 0xAD, 0xDE, 0x50, 0x5B];

    engine.mem_write(0x1000, &code).unwrap();

    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // The correct behavior is for 0xC7 with REX.W to sign-extend imm32
    // So 0xDEADBEEF becomes 0xFFFFFFFFDEADBEEF
    assert_eq!(engine.reg_read(Register::RBX), 0xFFFFFFFFDEADBEEF);
    assert_eq!(engine.reg_read(Register::RSP), 0x7800);
}

#[test]
fn test_conditional_jumps() {
    let mut engine = Engine::new(EngineMode::Mode64);

    engine.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();

    let code = vec![
        0x48, 0x31, 0xC0, 0x48, 0x85, 0xC0, 0x74, 0x05, 0x48, 0xFF, 0xC0, 0xEB, 0x03, 0x48, 0xFF,
        0xC3, 0x90,
    ];

    engine.mem_write(0x1000, &code).unwrap();

    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(engine.reg_read(Register::RAX), 0);
    assert_eq!(engine.reg_read(Register::RBX), 1);
}

#[test]
fn test_hook_code() {
    use amd64_emu::hooks::HookManager;

    // Custom hook manager for counting code executions
    struct CodeCounter {
        count: usize,
    }

    impl CodeCounter {
        fn new() -> Self {
            Self { count: 0 }
        }
    }

    impl HookManager for CodeCounter {
        fn on_code(
            &mut self,
            _engine: &mut amd64_emu::Engine,
            _address: u64,
            _size: usize,
        ) -> amd64_emu::Result<()> {
            self.count += 1;
            Ok(())
        }
    }

    let mut engine = Engine::new(EngineMode::Mode64);
    let mut hooks = CodeCounter::new();

    engine.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();

    let code = vec![0x48, 0xFF, 0xC0, 0x48, 0xFF, 0xC0, 0x48, 0xFF, 0xC0];

    engine.mem_write(0x1000, &code).unwrap();

    engine
        .emu_start_with_hooks(0x1000, 0x1000 + code.len() as u64, 0, 0, &mut hooks)
        .unwrap();

    assert_eq!(engine.reg_read(Register::RAX), 3);
    assert_eq!(hooks.count, 3);
}
