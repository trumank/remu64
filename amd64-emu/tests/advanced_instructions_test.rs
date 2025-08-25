use amd64_emu::{Engine, EngineMode, Permission, Register};

#[test]
fn test_neg_instruction() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test NEG with positive value
    engine.reg_write(Register::RAX, 0x42).unwrap();

    // NEG RAX (48 F7 D8)
    let code = vec![0x48, 0xF7, 0xD8];
    engine.mem_write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0, None)
        .unwrap();

    assert_eq!(engine.reg_read(Register::RAX).unwrap(), (-0x42i64) as u64);

    // Test NEG with zero (CF should be 0)
    engine.reg_write(Register::RAX, 0).unwrap();
    engine.reg_write(Register::RIP, 0x1000).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0, None)
        .unwrap();

    assert_eq!(engine.reg_read(Register::RAX).unwrap(), 0);
}

#[test]
fn test_not_instruction() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();

    engine.reg_write(Register::RAX, 0x00FF00FF00FF00FF).unwrap();

    // NOT RAX (48 F7 D0)
    let code = vec![0x48, 0xF7, 0xD0];
    engine.mem_write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0, None)
        .unwrap();

    assert_eq!(engine.reg_read(Register::RAX).unwrap(), 0xFF00FF00FF00FF00);
}

#[test]
fn test_shift_left() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();

    engine.reg_write(Register::RAX, 0x1).unwrap();
    engine.reg_write(Register::RCX, 4).unwrap();

    // SHL RAX, CL (48 D3 E0)
    let code = vec![0x48, 0xD3, 0xE0];
    engine.mem_write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0, None)
        .unwrap();

    assert_eq!(engine.reg_read(Register::RAX).unwrap(), 0x10);
}

#[test]
fn test_shift_right_logical() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();

    engine.reg_write(Register::RAX, 0x80).unwrap();
    engine.reg_write(Register::RCX, 4).unwrap();

    // SHR RAX, CL (48 D3 E8)
    let code = vec![0x48, 0xD3, 0xE8];
    engine.mem_write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0, None)
        .unwrap();

    assert_eq!(engine.reg_read(Register::RAX).unwrap(), 0x8);
}

#[test]
fn test_shift_right_arithmetic() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test with negative number to verify sign extension
    engine
        .reg_write(Register::RAX, 0xF000000000000000u64)
        .unwrap();
    engine.reg_write(Register::RCX, 4).unwrap();

    // SAR RAX, CL (48 D3 F8)
    let code = vec![0x48, 0xD3, 0xF8];
    engine.mem_write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0, None)
        .unwrap();

    // Should preserve sign bit (arithmetic shift)
    assert_eq!(
        engine.reg_read(Register::RAX).unwrap(),
        0xFF00000000000000u64
    );
}

#[test]
fn test_lea_instruction() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();

    engine.reg_write(Register::RBX, 0x2000).unwrap();
    engine.reg_write(Register::RSI, 0x8).unwrap();

    // LEA RAX, [RBX + RSI*4 + 0x100] (48 8D 84 B3 00 01 00 00)
    let code = vec![0x48, 0x8D, 0x84, 0xB3, 0x00, 0x01, 0x00, 0x00];
    engine.mem_write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0, None)
        .unwrap();

    // RAX should contain the calculated address: 0x2000 + 0x8*4 + 0x100 = 0x2120
    assert_eq!(engine.reg_read(Register::RAX).unwrap(), 0x2120);
}

#[test]
fn test_rotate_left() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();

    engine.reg_write(Register::RAX, 0x8000000000000001).unwrap();
    engine.reg_write(Register::RCX, 1).unwrap();

    // ROL RAX, CL (48 D3 C0)
    let code = vec![0x48, 0xD3, 0xC0];
    engine.mem_write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0, None)
        .unwrap();

    // Bit 63 rotates to bit 0, bit 0 rotates to bit 1
    assert_eq!(engine.reg_read(Register::RAX).unwrap(), 0x0000000000000003);
}

#[test]
fn test_rotate_right() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();

    engine.reg_write(Register::RAX, 0x8000000000000001).unwrap();
    engine.reg_write(Register::RCX, 1).unwrap();

    // ROR RAX, CL (48 D3 C8)
    let code = vec![0x48, 0xD3, 0xC8];
    engine.mem_write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0, None)
        .unwrap();

    // Bit 0 rotates to bit 63, bit 63 rotates to bit 62
    assert_eq!(engine.reg_read(Register::RAX).unwrap(), 0xC000000000000000);
}

#[test]
fn test_xchg_instruction() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code and data
    engine.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();
    engine.mem_map(0x2000, 0x1000, Permission::ALL).unwrap();

    engine.reg_write(Register::RAX, 0x1234).unwrap();
    engine.reg_write(Register::RBX, 0x5678).unwrap();

    // XCHG RAX, RBX (48 87 D8)
    let code = vec![0x48, 0x87, 0xD8];
    engine.mem_write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0, None)
        .unwrap();

    assert_eq!(engine.reg_read(Register::RAX).unwrap(), 0x5678);
    assert_eq!(engine.reg_read(Register::RBX).unwrap(), 0x1234);
}
