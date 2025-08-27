use remu64::{Engine, EngineMode, Permission, Register, memory::MemoryTrait};

fn setup_engine() -> Engine<impl MemoryTrait> {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x3000, Permission::ALL).unwrap();
    engine
}

#[test]
fn test_pdep_simple() {
    let mut engine = setup_engine();

    // Test basic PDEP operation
    // Source bits: 0b1101 (0xD)
    // Mask: 0b11110000 (0xF0)
    // Expected: bits from source placed at mask positions
    // Result: 0b11010000 (0xD0)

    let code = vec![
        0x48, 0xB8, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0xD
        0x48, 0xBB, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rbx, 0xF0
        0xC4, 0xE2, 0xFB, 0xF5, 0xCB, // pdep rcx, rax, rbx
    ];
    engine.memory.write(0x1000, &code).unwrap();
    engine.cpu.write_reg(Register::RIP, 0x1000);

    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(engine.cpu.read_reg(Register::RCX), 0xD0);
}

#[test]
fn test_pdep_scattered_bits() {
    let mut engine = setup_engine();

    // Test with scattered mask bits
    // Source: 0b111 (0x7)
    // Mask: 0b10101000 (0xA8)
    // Expected: source bits placed at positions 3, 5, 7
    // Result: 0b10101000 (0xA8)

    let code = vec![
        0x48, 0xB8, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0x7
        0x48, 0xBB, 0xA8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rbx, 0xA8
        0xC4, 0xE2, 0xFB, 0xF5, 0xCB, // pdep rcx, rax, rbx
    ];
    engine.memory.write(0x1000, &code).unwrap();
    engine.cpu.write_reg(Register::RIP, 0x1000);

    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(engine.cpu.read_reg(Register::RCX), 0xA8);
}

#[test]
fn test_pdep_partial_bits() {
    let mut engine = setup_engine();

    // Test with partial bits from source
    // Source: 0b1010 (0xA)
    // Mask: 0b11110000 (0xF0)
    // Expected: only alternating bits deposited
    // Result: 0b10100000 (0xA0)

    let code = vec![
        0x48, 0xB8, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0xA
        0x48, 0xBB, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rbx, 0xF0
        0xC4, 0xE2, 0xFB, 0xF5, 0xCB, // pdep rcx, rax, rbx
    ];
    engine.memory.write(0x1000, &code).unwrap();
    engine.cpu.write_reg(Register::RIP, 0x1000);

    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(engine.cpu.read_reg(Register::RCX), 0xA0);
}

#[test]
fn test_pdep_zero_mask() {
    let mut engine = setup_engine();

    // Test with zero mask - should always produce zero
    let code = vec![
        0x48, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, // mov rax, 0xFFFFFFFF
        0x48, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rbx, 0x0
        0xC4, 0xE2, 0xFB, 0xF5, 0xCB, // pdep rcx, rax, rbx
    ];
    engine.memory.write(0x1000, &code).unwrap();
    engine.cpu.write_reg(Register::RIP, 0x1000);

    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(engine.cpu.read_reg(Register::RCX), 0x0);
}

#[test]
fn test_pdep_full_mask() {
    let mut engine = setup_engine();

    // Test with full mask - should copy source bits as-is
    let code = vec![
        0x48, 0xB8, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, // mov rax, 0x12345678
        0x48, 0xBB, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, // mov rbx, 0xFFFFFFFF
        0xC4, 0xE2, 0xFB, 0xF5, 0xCB, // pdep rcx, rax, rbx
    ];
    engine.memory.write(0x1000, &code).unwrap();
    engine.cpu.write_reg(Register::RIP, 0x1000);

    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(engine.cpu.read_reg(Register::RCX), 0x12345678);
}

#[test]
fn test_pdep_32bit() {
    let mut engine = setup_engine();

    // Test 32-bit PDEP operation
    let code = vec![
        0x48, 0xB8, 0x78, 0x56, 0x34, 0x12, 0xFF, 0xFF, 0xFF,
        0xFF, // mov rax, 0xFFFFFFFF12345678
        0x48, 0xBB, 0xF0, 0xF0, 0xF0, 0xF0, 0xFF, 0xFF, 0xFF,
        0xFF, // mov rbx, 0xFFFFFFFFF0F0F0F0
        0xC4, 0xE2, 0x7B, 0xF5, 0xCB, // pdep ecx, eax, ebx (32-bit)
    ];
    engine.memory.write(0x1000, &code).unwrap();
    engine.cpu.write_reg(Register::RIP, 0x1000);

    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Result should only use lower 32 bits
    assert_eq!(engine.cpu.read_reg(Register::RCX) & 0xFFFFFFFF, 0x50607080);
}

#[test]
fn test_pdep_memory_source() {
    let mut engine = setup_engine();

    // Test PDEP with memory source (mask)
    // Write mask to memory
    engine
        .memory
        .write(0x2000, &0xF0F0u64.to_le_bytes())
        .unwrap();

    let code = vec![
        0x48, 0xB8, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0xFF
        0xC4, 0xE2, 0xFB, 0xF5, 0x0C, 0x25, // pdep rcx, rax, [0x2000]
        0x00, 0x20, 0x00, 0x00, // [0x2000] address
    ];
    engine.memory.write(0x1000, &code).unwrap();
    engine.cpu.write_reg(Register::RIP, 0x1000);

    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(engine.cpu.read_reg(Register::RCX), 0xF0F0);
}
