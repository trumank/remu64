use remu64::{Engine, EngineMode, Permission, Register, memory::MemoryTrait};

fn setup_engine() -> Engine<impl MemoryTrait> {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x2000, Permission::ALL).unwrap();
    engine
}

#[test]
fn test_rorx_basic() {
    let mut engine = setup_engine();

    // Test basic rotation: rotate 0x12345678 right by 4 bits
    // For 64-bit: Expected: 0x8000000001234567
    let code = vec![
        0x48, 0xC7, 0xC0, 0x78, 0x56, 0x34, 0x12, // mov rax, 0x12345678
        0xC4, 0xE3, 0xFB, 0xF0, 0xD8, 0x04, // rorx rbx, rax, 4 (VEX.L0.F2.0F3A.W1)
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(
        engine.reg_read(Register::RBX),
        0x8000000001234567,
        "RORX should rotate right by 4"
    );
    assert_eq!(
        engine.reg_read(Register::RAX),
        0x12345678,
        "Source should remain unchanged"
    );
}

#[test]
fn test_rorx_no_flags() {
    let mut engine = setup_engine();

    // Test that RORX doesn't modify flags
    let code = vec![
        0x48, 0x31, 0xC0, // xor rax, rax (sets ZF)
        0x48, 0xC7, 0xC1, 0xFF, 0x00, 0x00, 0x00, // mov rcx, 0xFF
        0xC4, 0xE3, 0xFB, 0xF0, 0xD9, 0x08, // rorx rbx, rcx, 8
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert!(
        engine.cpu.rflags.contains(remu64::cpu::Flags::ZF),
        "ZF should remain set"
    );
    assert_eq!(
        engine.reg_read(Register::RBX),
        0xFF00000000000000,
        "RORX result should be correct"
    );
}

#[test]
fn test_rorx_32bit() {
    let mut engine = setup_engine();

    // Test 32-bit rotation
    let code = vec![
        0x48, 0xC7, 0xC0, 0x78, 0x56, 0x34, 0x12, // mov rax, 0x12345678
        0xC4, 0xE3, 0x7B, 0xF0, 0xD8, 0x10, // rorx ebx, eax, 16 (VEX.L0.F2.0F3A.W0)
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(
        engine.reg_read(Register::RBX) & 0xFFFFFFFF,
        0x56781234,
        "32-bit RORX should rotate by 16"
    );
}

#[test]
fn test_rorx_wrap_around() {
    let mut engine = setup_engine();

    // Test rotation that wraps around (rotate by 63)
    let code = vec![
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x80, // mov rax, 0x8000000000000000
        0xC4, 0xE3, 0xFB, 0xF0, 0xD8, 0x3F, // rorx rbx, rax, 63
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(
        engine.reg_read(Register::RBX),
        0x0000000000000001,
        "RORX by 63 should wrap MSB to LSB"
    );
}

#[test]
fn test_rorx_zero_count() {
    let mut engine = setup_engine();

    // Test rotation by 0 (no rotation)
    let code = vec![
        0x48, 0xC7, 0xC0, 0x42, 0x00, 0x00, 0x00, // mov rax, 0x42
        0xC4, 0xE3, 0xFB, 0xF0, 0xD8, 0x00, // rorx rbx, rax, 0
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(
        engine.reg_read(Register::RBX),
        0x42,
        "RORX by 0 should not change value"
    );
}

#[test]
fn test_rorx_modulo_count() {
    let mut engine = setup_engine();

    // Test that rotation count is taken modulo operand size
    // For 64-bit: count & 0x3F, so 65 becomes 1
    let code = vec![
        0x48, 0xC7, 0xC0, 0x02, 0x00, 0x00, 0x00, // mov rax, 0x02
        0xC4, 0xE3, 0xFB, 0xF0, 0xD8, 0x41, // rorx rbx, rax, 65 (65 & 0x3F = 1)
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(
        engine.reg_read(Register::RBX),
        0x01,
        "RORX by 65 should be same as by 1"
    );
}

#[test]
fn test_rorx_memory_source() {
    let mut engine = setup_engine();

    // Store value in memory
    engine
        .memory
        .write(0x2000, &0x123456789ABCDEF0u64.to_le_bytes())
        .unwrap();

    // Test RORX with memory source
    let code = vec![
        0xC4, 0xE3, 0xFB, 0xF0, 0x1C, 0x25, 0x00, 0x20, 0x00, 0x00,
        0x08, // rorx rbx, qword ptr [0x2000], 8
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(
        engine.reg_read(Register::RBX),
        0xF0123456789ABCDE,
        "RORX from memory should work"
    );
}

#[test]
fn test_rorx_different_registers() {
    let mut engine = setup_engine();

    // Test with different destination registers
    let code = vec![
        0x48, 0xC7, 0xC0, 0xAA, 0x00, 0x00, 0x00, // mov rax, 0xAA
        0xC4, 0xE3, 0xFB, 0xF0, 0xD0, 0x04, // rorx rdx, rax, 4
        0xC4, 0xE3, 0xFB, 0xF0, 0xC8, 0x08, // rorx rcx, rax, 8
        0xC4, 0xE3, 0xFB, 0xF0, 0xF8, 0x0C, // rorx rdi, rax, 12
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // 0xAA rotated right by 4: bottom 4 bits (0xA) go to top
    assert_eq!(
        engine.reg_read(Register::RDX),
        0xa00000000000000a,
        "RORX to RDX"
    );
    // 0xAA rotated right by 8: all 8 bits go to top
    assert_eq!(
        engine.reg_read(Register::RCX),
        0xaa00000000000000,
        "RORX to RCX"
    );
    // 0xAA rotated right by 12: bottom 12 bits go to top
    assert_eq!(
        engine.reg_read(Register::RDI),
        0x0aa0000000000000,
        "RORX to RDI"
    );
}
