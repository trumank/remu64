use remu64::{Engine, EngineMode, Permission, Register, memory::MemoryTrait as _};

#[test]
fn test_adc_basic() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test ADC without carry flag
    let code = vec![
        0x48, 0xC7, 0xC0, 0x05, 0x00, 0x00, 0x00, // mov rax, 5
        0x48, 0xC7, 0xC3, 0x03, 0x00, 0x00, 0x00, // mov rbx, 3
        0x48, 0x11, 0xD8, // adc rax, rbx
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Without carry: 5 + 3 = 8
    assert_eq!(engine.reg_read(Register::RAX), 8);
}

#[test]
fn test_adc_with_carry() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test ADC with carry flag set
    let code = vec![
        0x48, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF, // mov rax, 0xFFFFFFFF
        0x48, 0xC7, 0xC3, 0x01, 0x00, 0x00, 0x00, // mov rbx, 1
        0x48, 0x01, 0xD8, // add rax, rbx (sets carry)
        0x48, 0xC7, 0xC0, 0x05, 0x00, 0x00, 0x00, // mov rax, 5
        0x48, 0xC7, 0xC3, 0x03, 0x00, 0x00, 0x00, // mov rbx, 3
        0x48, 0x11, 0xD8, // adc rax, rbx
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // With carry: 5 + 3 + 1 = 9
    assert_eq!(engine.reg_read(Register::RAX), 9);
}

#[test]
fn test_sbb_basic() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test SBB without borrow flag
    let code = vec![
        0x48, 0xC7, 0xC0, 0x0A, 0x00, 0x00, 0x00, // mov rax, 10
        0x48, 0xC7, 0xC3, 0x03, 0x00, 0x00, 0x00, // mov rbx, 3
        0x48, 0x19, 0xD8, // sbb rax, rbx
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Without borrow: 10 - 3 = 7
    assert_eq!(engine.reg_read(Register::RAX), 7);
}

#[test]
fn test_sbb_with_borrow() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test SBB with borrow flag set
    let code = vec![
        0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00, // mov rax, 0
        0x48, 0xC7, 0xC3, 0x01, 0x00, 0x00, 0x00, // mov rbx, 1
        0x48, 0x29, 0xD8, // sub rax, rbx (sets carry/borrow)
        0x48, 0xC7, 0xC0, 0x0A, 0x00, 0x00, 0x00, // mov rax, 10
        0x48, 0xC7, 0xC3, 0x03, 0x00, 0x00, 0x00, // mov rbx, 3
        0x48, 0x19, 0xD8, // sbb rax, rbx
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // With borrow: 10 - 3 - 1 = 6
    assert_eq!(engine.reg_read(Register::RAX), 6);
}

#[test]
fn test_adc_chain() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test multi-precision addition using ADC
    // Add two 128-bit numbers: (0xFFFFFFFFFFFFFFFF, 0x1) + (0x1, 0x0)
    let code = vec![
        // Low 64 bits
        0x48, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, // mov rax, 0xFFFFFFFFFFFFFFFF
        0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00, // mov rdx, 1 (low part of second number)
        0x48, 0x01, 0xD0, // add rax, rdx (produces carry)
        // High 64 bits
        0x48, 0xC7, 0xC1, 0x01, 0x00, 0x00, 0x00, // mov rcx, 1 (high part of first number)
        0x48, 0xC7, 0xC2, 0x00, 0x00, 0x00, 0x00, // mov rdx, 0 (high part of second number)
        0x48, 0x11, 0xD1, // adc rcx, rdx (add with carry)
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Low part: 0xFFFFFFFFFFFFFFFF + 1 = 0 (wraps to 0, sets carry)
    assert_eq!(engine.reg_read(Register::RAX), 0);
    // High part: 1 + 0 + carry = 2
    assert_eq!(engine.reg_read(Register::RCX), 2);
}

#[test]
fn test_sbb_chain() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test multi-precision subtraction using SBB
    // Subtract (0x1, 0x0) from (0x0, 0x2)
    let code = vec![
        // Low 64 bits
        0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00, // mov rax, 0 (low part of minuend)
        0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00, // mov rdx, 1 (low part of subtrahend)
        0x48, 0x29, 0xD0, // sub rax, rdx (produces borrow)
        // High 64 bits
        0x48, 0xC7, 0xC1, 0x02, 0x00, 0x00, 0x00, // mov rcx, 2 (high part of minuend)
        0x48, 0xC7, 0xC2, 0x00, 0x00, 0x00, 0x00, // mov rdx, 0 (high part of subtrahend)
        0x48, 0x19, 0xD1, // sbb rcx, rdx (subtract with borrow)
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Low part: 0 - 1 = -1 (wraps to 0xFFFFFFFFFFFFFFFF, sets borrow)
    assert_eq!(engine.reg_read(Register::RAX), 0xFFFFFFFFFFFFFFFF);
    // High part: 2 - 0 - borrow = 1
    assert_eq!(engine.reg_read(Register::RCX), 1);
}

#[test]
fn test_adc_immediate() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test ADC with immediate values
    let code = vec![
        0xB0, 0xFF, // mov al, 0xFF
        0x04, 0x01, // add al, 1 (sets carry when AL wraps)
        0xB0, 0x05, // mov al, 5
        0x14, 0x03, // adc al, 3
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // AL = 5 + 3 + 1 (carry) = 9
    assert_eq!(engine.reg_read(Register::RAX) & 0xFF, 9);
}

#[test]
fn test_sbb_immediate() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test SBB with immediate values
    let code = vec![
        0xB0, 0x00, // mov al, 0
        0x2C, 0x01, // sub al, 1 (sets borrow when AL underflows)
        0xB0, 0x0A, // mov al, 10
        0x1C, 0x03, // sbb al, 3
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // AL = 10 - 3 - 1 (borrow) = 6
    assert_eq!(engine.reg_read(Register::RAX) & 0xFF, 6);
}

#[test]
fn test_add_carry_flag() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test if ADD sets carry flag correctly
    let code = vec![
        0x48, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF,
        0xFF, // mov rax, 0xFFFFFFFF (should sign extend to 0xFFFFFFFFFFFFFFFF)
        0x48, 0xC7, 0xC3, 0x01, 0x00, 0x00, 0x00, // mov rbx, 1
        0x48, 0x01, 0xD8, // add rax, rbx (should set carry: 0xFFFFFFFFFFFFFFFF + 1 overflows)
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    let rax = engine.reg_read(Register::RAX);
    let flags = engine.flags_read();

    println!(
        "ADD result: RAX={:#x}, carry={}",
        rax,
        flags.contains(remu64::Flags::CF)
    );

    // RAX should be 0, carry should be set
    assert_eq!(rax, 0);
    assert!(flags.contains(remu64::Flags::CF));
}
