use remu64::{memory::MemoryTrait as _, Engine, EngineMode, Permission, Register};

#[test]
fn test_neg_instruction() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test NEG with positive value
    engine.reg_write(Register::RAX, 0x42);

    // NEG RAX (48 F7 D8)
    let code = vec![0x48, 0xF7, 0xD8];
    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(engine.reg_read(Register::RAX), (-0x42i64) as u64);

    // Test NEG with zero (CF should be 0)
    engine.reg_write(Register::RAX, 0);
    engine.reg_write(Register::RIP, 0x1000);
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(engine.reg_read(Register::RAX), 0);
}

#[test]
fn test_not_instruction() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    engine.reg_write(Register::RAX, 0x00FF00FF00FF00FF);

    // NOT RAX (48 F7 D0)
    let code = vec![0x48, 0xF7, 0xD0];
    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(engine.reg_read(Register::RAX), 0xFF00FF00FF00FF00);
}

#[test]
fn test_shift_left() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    engine.reg_write(Register::RAX, 0x1);
    engine.reg_write(Register::RCX, 4);

    // SHL RAX, CL (48 D3 E0)
    let code = vec![0x48, 0xD3, 0xE0];
    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(engine.reg_read(Register::RAX), 0x10);
}

#[test]
fn test_shift_right_logical() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    engine.reg_write(Register::RAX, 0x80);
    engine.reg_write(Register::RCX, 4);

    // SHR RAX, CL (48 D3 E8)
    let code = vec![0x48, 0xD3, 0xE8];
    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(engine.reg_read(Register::RAX), 0x8);
}

#[test]
fn test_shift_right_arithmetic() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test with negative number to verify sign extension
    engine.reg_write(Register::RAX, 0xF000000000000000u64);
    engine.reg_write(Register::RCX, 4);

    // SAR RAX, CL (48 D3 F8)
    let code = vec![0x48, 0xD3, 0xF8];
    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Should preserve sign bit (arithmetic shift)
    assert_eq!(engine.reg_read(Register::RAX), 0xFF00000000000000u64);
}

#[test]
fn test_lea_instruction() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    engine.reg_write(Register::RBX, 0x2000);
    engine.reg_write(Register::RSI, 0x8);

    // LEA RAX, [RBX + RSI*4 + 0x100] (48 8D 84 B3 00 01 00 00)
    let code = vec![0x48, 0x8D, 0x84, 0xB3, 0x00, 0x01, 0x00, 0x00];
    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // RAX should contain the calculated address: 0x2000 + 0x8*4 + 0x100 = 0x2120
    assert_eq!(engine.reg_read(Register::RAX), 0x2120);
}

#[test]
fn test_rotate_left() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    engine.reg_write(Register::RAX, 0x8000000000000001);
    engine.reg_write(Register::RCX, 1);

    // ROL RAX, CL (48 D3 C0)
    let code = vec![0x48, 0xD3, 0xC0];
    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Bit 63 rotates to bit 0, bit 0 rotates to bit 1
    assert_eq!(engine.reg_read(Register::RAX), 0x0000000000000003);
}

#[test]
fn test_rotate_right() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    engine.reg_write(Register::RAX, 0x8000000000000001);
    engine.reg_write(Register::RCX, 1);

    // ROR RAX, CL (48 D3 C8)
    let code = vec![0x48, 0xD3, 0xC8];
    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Bit 0 rotates to bit 63, bit 63 rotates to bit 62
    assert_eq!(engine.reg_read(Register::RAX), 0xC000000000000000);
}

#[test]
fn test_xchg_instruction() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code and data
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    engine.memory.map(0x2000, 0x1000, Permission::ALL).unwrap();

    engine.reg_write(Register::RAX, 0x1234);
    engine.reg_write(Register::RBX, 0x5678);

    // XCHG RAX, RBX (48 87 D8)
    let code = vec![0x48, 0x87, 0xD8];
    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(engine.reg_read(Register::RAX), 0x5678);
    assert_eq!(engine.reg_read(Register::RBX), 0x1234);
}
