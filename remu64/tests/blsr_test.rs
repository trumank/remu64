use remu64::{Engine, EngineMode, Permission, Register, memory::MemoryTrait};

#[test]
fn test_blsr_basic() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x2000, Permission::ALL).unwrap();

    // Test: BLSR with value 0x12 (0001 0010)
    // Operation: src & (src - 1) = 0x12 & 0x11 = 0x10
    // This clears the lowest set bit (bit 1), leaving bit 4
    let code = vec![
        0x48, 0xC7, 0xC0, 0x12, 0x00, 0x00, 0x00, // mov rax, 0x12
        0xC4, 0xE2, 0xF8, 0xF3, 0xC8, // blsr rax, rax (VEX encoding)
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(
        engine.reg_read(Register::RAX),
        0x10,
        "BLSR should reset lowest set bit"
    );
    assert!(
        !engine.cpu.rflags.contains(remu64::cpu::Flags::ZF),
        "ZF should be clear for non-zero result"
    );
    assert!(
        engine.cpu.rflags.contains(remu64::cpu::Flags::CF),
        "CF should be set for non-zero input"
    );
}

#[test]
fn test_blsr_zero() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x2000, Permission::ALL).unwrap();

    // Test: BLSR with value 0
    // Operation: 0 & (0 - 1) = 0 & 0xFFFFFFFFFFFFFFFF = 0
    let code = vec![
        0x48, 0x31, 0xC0, // xor rax, rax (rax = 0)
        0xC4, 0xE2, 0xF8, 0xF3, 0xC8, // blsr rax, rax
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(
        engine.reg_read(Register::RAX),
        0,
        "BLSR of zero should be zero"
    );
    assert!(
        engine.cpu.rflags.contains(remu64::cpu::Flags::ZF),
        "ZF should be set for zero result"
    );
    assert!(
        !engine.cpu.rflags.contains(remu64::cpu::Flags::CF),
        "CF should be clear for zero input"
    );
}

#[test]
fn test_blsr_powers_of_two() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x2000, Permission::ALL).unwrap();

    // Test: BLSR with powers of two (only one bit set)
    // Result should be 0 since we're clearing the only set bit
    let code = vec![
        // Test with 1: 1 & 0 = 0
        0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, // mov rax, 0x01
        0xC4, 0xE2, 0xF8, 0xF3, 0xC8, // blsr rax, rax
        0x48, 0x89, 0xC3, // mov rbx, rax (save result)
        // Test with 8: 8 & 7 = 0
        0x48, 0xC7, 0xC0, 0x08, 0x00, 0x00, 0x00, // mov rax, 0x08
        0xC4, 0xE2, 0xF8, 0xF3, 0xC8, // blsr rax, rax
        0x48, 0x89, 0xC2, // mov rdx, rax (save result)
        // Test with 0x80: 0x80 & 0x7F = 0
        0x48, 0xC7, 0xC0, 0x80, 0x00, 0x00, 0x00, // mov rax, 0x80
        0xC4, 0xE2, 0xF8, 0xF3, 0xC8, // blsr rax, rax
        0x48, 0x89, 0xC1, // mov rcx, rax (save result)
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(
        engine.reg_read(Register::RBX),
        0x00,
        "BLSR of 0x01 should be 0x00"
    );
    assert_eq!(
        engine.reg_read(Register::RDX),
        0x00,
        "BLSR of 0x08 should be 0x00"
    );
    assert_eq!(
        engine.reg_read(Register::RCX),
        0x00,
        "BLSR of 0x80 should be 0x00"
    );
}

#[test]
fn test_blsr_multiple_bits() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x2000, Permission::ALL).unwrap();

    // Test various values with multiple bits set
    let code = vec![
        // Test with 0xFF: 0xFF & 0xFE = 0xFE (clears bit 0)
        0x48, 0xC7, 0xC0, 0xFF, 0x00, 0x00, 0x00, // mov rax, 0xFF
        0xC4, 0xE2, 0xF8, 0xF3, 0xC8, // blsr rax, rax
        0x48, 0x89, 0xC3, // mov rbx, rax (save result)
        // Test with 0x1C (0001 1100): 0x1C & 0x1B = 0x18 (clears bit 2)
        0x48, 0xC7, 0xC0, 0x1C, 0x00, 0x00, 0x00, // mov rax, 0x1C
        0xC4, 0xE2, 0xF8, 0xF3, 0xC8, // blsr rax, rax
        0x48, 0x89, 0xC2, // mov rdx, rax (save result)
        // Test with 0xF0 (1111 0000): 0xF0 & 0xEF = 0xE0 (clears bit 4)
        0x48, 0xC7, 0xC0, 0xF0, 0x00, 0x00, 0x00, // mov rax, 0xF0
        0xC4, 0xE2, 0xF8, 0xF3, 0xC8, // blsr rax, rax
        0x48, 0x89, 0xC1, // mov rcx, rax (save result)
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(
        engine.reg_read(Register::RBX),
        0xFE,
        "BLSR of 0xFF should be 0xFE"
    );
    assert_eq!(
        engine.reg_read(Register::RDX),
        0x18,
        "BLSR of 0x1C should be 0x18"
    );
    assert_eq!(
        engine.reg_read(Register::RCX),
        0xE0,
        "BLSR of 0xF0 should be 0xE0"
    );
}

#[test]
fn test_blsr_consecutive_application() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x2000, Permission::ALL).unwrap();

    // Test: Apply BLSR multiple times to clear all bits one by one
    // Start with 0x07 (0000 0111), clear one bit at a time
    let code = vec![
        0x48, 0xC7, 0xC0, 0x07, 0x00, 0x00, 0x00, // mov rax, 0x07 (111 in binary)
        0xC4, 0xE2, 0xF8, 0xF3, 0xC8, // blsr rax, rax -> 0x06 (110)
        0xC4, 0xE2, 0xF8, 0xF3, 0xC8, // blsr rax, rax -> 0x04 (100)
        0xC4, 0xE2, 0xF8, 0xF3, 0xC8, // blsr rax, rax -> 0x00 (000)
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(
        engine.reg_read(Register::RAX),
        0x00,
        "Three applications of BLSR on 0x07 should result in 0x00"
    );
    assert!(
        engine.cpu.rflags.contains(remu64::cpu::Flags::ZF),
        "ZF should be set when result is zero"
    );
}

#[test]
fn test_blsr_32bit() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x2000, Permission::ALL).unwrap();

    // Test 32-bit BLSR
    // 0x30 & 0x2F = 0x20 (clears bit 4)
    let code = vec![
        0xB8, 0x30, 0x00, 0x00, 0x00, // mov eax, 0x30
        0xC4, 0xE2, 0x78, 0xF3, 0xC8, // blsr eax, eax (32-bit version)
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine.reg_write(Register::RAX, 0xFFFFFFFFFFFFFFFF); // Pre-fill with all 1s
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(
        engine.reg_read(Register::EAX),
        0x20,
        "32-bit BLSR of 0x30 should be 0x20"
    );
    assert_eq!(
        engine.reg_read(Register::RAX),
        0x20,
        "Upper 32 bits should be cleared"
    );
}

#[test]
fn test_blsr_large_values() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x2000, Permission::ALL).unwrap();

    // Test with large 64-bit values
    let code = vec![
        // Test with 0x8000000000000000: huge & (huge-1) = 0
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x80, // movabs rax, 0x8000000000000000
        0xC4, 0xE2, 0xF8, 0xF3, 0xC8, // blsr rax, rax
        0x48, 0x89, 0xC3, // mov rbx, rax (save result)
        // Test with 0xFFFFFFFFFFFFFFF0: clear bit 4, result is 0xFFFFFFFFFFFFFFE0
        0x48, 0xB8, 0xF0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, // movabs rax, 0xFFFFFFFFFFFFFFF0
        0xC4, 0xE2, 0xF8, 0xF3, 0xC8, // blsr rax, rax
        0x48, 0x89, 0xC2, // mov rdx, rax (save result)
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(
        engine.reg_read(Register::RBX),
        0,
        "BLSR of MSB only should be 0"
    );
    assert_eq!(
        engine.reg_read(Register::RDX),
        0xFFFFFFFFFFFFFFE0,
        "BLSR of 0xFFFFFFFFFFFFFFF0 should be 0xFFFFFFFFFFFFFFE0"
    );
}
