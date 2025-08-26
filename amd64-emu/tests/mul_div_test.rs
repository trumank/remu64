use amd64_emu::{Engine, EngineMode, Permission, Register};

#[test]
fn test_mul_instruction() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test basic multiplication
    engine.reg_write(Register::RAX, 0x10);
    engine.reg_write(Register::RBX, 0x20);
    engine.reg_write(Register::RDX, 0);

    // MUL RBX (48 F7 E3)
    let code = vec![0x48, 0xF7, 0xE3];
    engine.mem_write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Result should be 0x10 * 0x20 = 0x200
    assert_eq!(engine.reg_read(Register::RAX), 0x200);
    assert_eq!(engine.reg_read(Register::RDX), 0); // No overflow

    // Test multiplication with overflow
    engine.reg_write(Register::RAX, 0xFFFFFFFFFFFFFFFF);
    engine.reg_write(Register::RBX, 0x02);
    engine.reg_write(Register::RIP, 0x1000);
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Result should overflow into RDX
    assert_eq!(engine.reg_read(Register::RAX), 0xFFFFFFFFFFFFFFFE);
    assert_eq!(engine.reg_read(Register::RDX), 0x01);
}

#[test]
fn test_div_instruction() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test basic division
    engine.reg_write(Register::RAX, 0x200);
    engine.reg_write(Register::RDX, 0);
    engine.reg_write(Register::RBX, 0x10);

    // DIV RBX (48 F7 F3)
    let code = vec![0x48, 0xF7, 0xF3];
    engine.mem_write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Quotient should be 0x200 / 0x10 = 0x20
    assert_eq!(engine.reg_read(Register::RAX), 0x20);
    // Remainder should be 0
    assert_eq!(engine.reg_read(Register::RDX), 0);

    // Test division with remainder
    engine.reg_write(Register::RAX, 0x203);
    engine.reg_write(Register::RDX, 0);
    engine.reg_write(Register::RBX, 0x10);
    engine.reg_write(Register::RIP, 0x1000);
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(engine.reg_read(Register::RAX), 0x20); // Quotient
    assert_eq!(engine.reg_read(Register::RDX), 0x03); // Remainder
}

#[test]
fn test_imul_instruction() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test signed multiplication with negative numbers
    engine.reg_write(Register::RAX, (-10i64) as u64);
    engine.reg_write(Register::RBX, 5);
    engine.reg_write(Register::RDX, 0);

    // IMUL RBX (48 F7 EB)
    let code = vec![0x48, 0xF7, 0xEB];
    engine.mem_write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Result should be -10 * 5 = -50
    assert_eq!(engine.reg_read(Register::RAX) as i64, -50);
    // RDX should contain sign extension (all 1s for negative)
    assert_eq!(engine.reg_read(Register::RDX), 0xFFFFFFFFFFFFFFFF);
}

#[test]
fn test_idiv_instruction() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test signed division with negative dividend
    engine.reg_write(Register::RAX, (-50i64) as u64);
    engine.reg_write(Register::RDX, 0xFFFFFFFFFFFFFFFF); // Sign extension
    engine.reg_write(Register::RBX, 5);

    // IDIV RBX (48 F7 FB)
    let code = vec![0x48, 0xF7, 0xFB];
    engine.mem_write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Quotient should be -50 / 5 = -10
    assert_eq!(engine.reg_read(Register::RAX) as i64, -10);
    // Remainder should be 0
    assert_eq!(engine.reg_read(Register::RDX), 0);
}

#[test]
#[should_panic(expected = "DivisionByZero")]
fn test_div_by_zero() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();

    engine.reg_write(Register::RAX, 0x100);
    engine.reg_write(Register::RDX, 0);
    engine.reg_write(Register::RBX, 0); // Divisor is zero

    // DIV RBX - should cause division by zero
    let code = vec![0x48, 0xF7, 0xF3];
    engine.mem_write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();
}
