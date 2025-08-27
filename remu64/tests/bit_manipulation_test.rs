use remu64::{memory::MemoryTrait as _, Engine, EngineMode, Permission, Register};

#[test]
fn test_bt_instruction() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory and load code
    engine
        .memory
        .map(
            0x1000,
            0x1000,
            Permission::READ | Permission::WRITE | Permission::EXEC,
        )
        .unwrap();

    // Test BT with register operands
    // BT rax, rcx - test bit in rax at position specified by rcx
    let code = vec![
        0x48, 0xc7, 0xc0, 0x0a, 0x00, 0x00, 0x00, // mov rax, 10 (0b1010)
        0x48, 0xc7, 0xc1, 0x01, 0x00, 0x00, 0x00, // mov rcx, 1
        0x48, 0x0f, 0xa3, 0xc8, // bt rax, rcx
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine.reg_write(Register::RIP, 0x1000);

    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Bit 1 of 0b1010 is 1, so CF should be set
    assert!(engine.cpu.rflags.contains(remu64::Flags::CF));

    // Test with bit that's not set
    let code2 = vec![
        0x48, 0xc7, 0xc0, 0x0a, 0x00, 0x00, 0x00, // mov rax, 10 (0b1010)
        0x48, 0xc7, 0xc1, 0x00, 0x00, 0x00, 0x00, // mov rcx, 0
        0x48, 0x0f, 0xa3, 0xc8, // bt rax, rcx
    ];

    engine.memory.write(0x1000, &code2).unwrap();
    engine.reg_write(Register::RIP, 0x1000);

    engine
        .emu_start(0x1000, 0x1000 + code2.len() as u64, 0, 0)
        .unwrap();

    // Bit 0 of 0b1010 is 0, so CF should be clear
    assert!(!engine.cpu.rflags.contains(remu64::Flags::CF));
}

#[test]
fn test_bts_instruction() {
    let mut engine = Engine::new(EngineMode::Mode64);

    engine
        .memory
        .map(
            0x1000,
            0x1000,
            Permission::READ | Permission::WRITE | Permission::EXEC,
        )
        .unwrap();

    // Test BTS - should test bit and set it
    let code = vec![
        0x48, 0xc7, 0xc0, 0x08, 0x00, 0x00, 0x00, // mov rax, 8 (0b1000)
        0x48, 0xc7, 0xc1, 0x01, 0x00, 0x00, 0x00, // mov rcx, 1
        0x48, 0x0f, 0xab, 0xc8, // bts rax, rcx
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine.reg_write(Register::RIP, 0x1000);

    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Bit 1 of 0b1000 was 0, so CF should be clear
    assert!(!engine.cpu.rflags.contains(remu64::Flags::CF));
    // After BTS, rax should be 0b1010 = 10
    assert_eq!(engine.reg_read(Register::RAX), 10);
}

#[test]
fn test_btr_instruction() {
    let mut engine = Engine::new(EngineMode::Mode64);

    engine
        .memory
        .map(
            0x1000,
            0x1000,
            Permission::READ | Permission::WRITE | Permission::EXEC,
        )
        .unwrap();

    // Test BTR - should test bit and reset it
    let code = vec![
        0x48, 0xc7, 0xc0, 0x0f, 0x00, 0x00, 0x00, // mov rax, 15 (0b1111)
        0x48, 0xc7, 0xc1, 0x02, 0x00, 0x00, 0x00, // mov rcx, 2
        0x48, 0x0f, 0xb3, 0xc8, // btr rax, rcx
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine.reg_write(Register::RIP, 0x1000);

    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Bit 2 of 0b1111 was 1, so CF should be set
    assert!(engine.cpu.rflags.contains(remu64::Flags::CF));
    // After BTR, rax should be 0b1011 = 11
    assert_eq!(engine.reg_read(Register::RAX), 11);
}

#[test]
fn test_btc_instruction() {
    let mut engine = Engine::new(EngineMode::Mode64);

    engine
        .memory
        .map(
            0x1000,
            0x1000,
            Permission::READ | Permission::WRITE | Permission::EXEC,
        )
        .unwrap();

    // Test BTC - should test bit and complement it
    let code = vec![
        0x48, 0xc7, 0xc0, 0x05, 0x00, 0x00, 0x00, // mov rax, 5 (0b0101)
        0x48, 0xc7, 0xc1, 0x01, 0x00, 0x00, 0x00, // mov rcx, 1
        0x48, 0x0f, 0xbb, 0xc8, // btc rax, rcx
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine.reg_write(Register::RIP, 0x1000);

    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Bit 1 of 0b0101 was 0, so CF should be clear
    assert!(!engine.cpu.rflags.contains(remu64::Flags::CF));
    // After BTC, bit 1 is flipped: 0b0111 = 7
    assert_eq!(engine.reg_read(Register::RAX), 7);
}

#[test]
fn test_bsf_instruction() {
    let mut engine = Engine::new(EngineMode::Mode64);

    engine
        .memory
        .map(
            0x1000,
            0x1000,
            Permission::READ | Permission::WRITE | Permission::EXEC,
        )
        .unwrap();

    // Test BSF - find first set bit from LSB
    let code = vec![
        0x48, 0xc7, 0xc1, 0x18, 0x00, 0x00, 0x00, // mov rcx, 0x18 (0b11000)
        0x48, 0x0f, 0xbc, 0xc1, // bsf rax, rcx
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine.reg_write(Register::RIP, 0x1000);

    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // First set bit in 0b11000 is at position 3
    assert_eq!(engine.reg_read(Register::RAX), 3);
    assert!(!engine.cpu.rflags.contains(remu64::Flags::ZF));
}

#[test]
fn test_bsf_zero() {
    let mut engine = Engine::new(EngineMode::Mode64);

    engine
        .memory
        .map(
            0x1000,
            0x1000,
            Permission::READ | Permission::WRITE | Permission::EXEC,
        )
        .unwrap();

    // Test BSF with zero input
    let code = vec![
        0x48, 0x31, 0xc9, // xor rcx, rcx (rcx = 0)
        0x48, 0x0f, 0xbc, 0xc1, // bsf rax, rcx
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine.reg_write(Register::RIP, 0x1000);
    engine.reg_write(Register::RAX, 0xdeadbeef); // Set initial value

    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // With zero input, ZF should be set and destination unchanged
    assert!(engine.cpu.rflags.contains(remu64::Flags::ZF));
    // RAX should still contain the initial value (undefined behavior)
    assert_eq!(engine.reg_read(Register::RAX), 0xdeadbeef);
}

#[test]
fn test_bsr_instruction() {
    let mut engine = Engine::new(EngineMode::Mode64);

    engine
        .memory
        .map(
            0x1000,
            0x1000,
            Permission::READ | Permission::WRITE | Permission::EXEC,
        )
        .unwrap();

    // Test BSR - find first set bit from MSB
    let code = vec![
        0x48, 0xc7, 0xc1, 0x18, 0x00, 0x00, 0x00, // mov rcx, 0x18 (0b11000)
        0x48, 0x0f, 0xbd, 0xc1, // bsr rax, rcx
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine.reg_write(Register::RIP, 0x1000);

    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Last set bit in 0b11000 is at position 4
    assert_eq!(engine.reg_read(Register::RAX), 4);
    assert!(!engine.cpu.rflags.contains(remu64::Flags::ZF));
}

#[test]
fn test_bsr_zero() {
    let mut engine = Engine::new(EngineMode::Mode64);

    engine
        .memory
        .map(
            0x1000,
            0x1000,
            Permission::READ | Permission::WRITE | Permission::EXEC,
        )
        .unwrap();

    // Test BSR with zero input
    let code = vec![
        0x48, 0x31, 0xc9, // xor rcx, rcx (rcx = 0)
        0x48, 0x0f, 0xbd, 0xc1, // bsr rax, rcx
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine.reg_write(Register::RIP, 0x1000);
    engine.reg_write(Register::RAX, 0xdeadbeef); // Set initial value

    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // With zero input, ZF should be set and destination unchanged
    assert!(engine.cpu.rflags.contains(remu64::Flags::ZF));
    // RAX should still contain the initial value (undefined behavior)
    assert_eq!(engine.reg_read(Register::RAX), 0xdeadbeef);
}

#[test]
fn test_bit_ops_32bit() {
    let mut engine = Engine::new(EngineMode::Mode64);

    engine
        .memory
        .map(
            0x1000,
            0x1000,
            Permission::READ | Permission::WRITE | Permission::EXEC,
        )
        .unwrap();

    // Test 32-bit variants
    let code = vec![
        0xb8, 0xff, 0x00, 0x00, 0x00, // mov eax, 0xff
        0xb9, 0x07, 0x00, 0x00, 0x00, // mov ecx, 7
        0x0f, 0xa3, 0xc8, // bt eax, ecx (32-bit)
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine.reg_write(Register::RIP, 0x1000);

    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Bit 7 of 0xff is 1
    assert!(engine.cpu.rflags.contains(remu64::Flags::CF));
}
