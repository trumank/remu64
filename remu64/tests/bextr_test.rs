use remu64::{Engine, EngineMode, Permission, Register, memory::MemoryTrait};

#[test]
fn test_bextr_basic() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test BEXTR: Extract 4 bits starting at position 4
    // src = 0x12345678 = 0001 0010 0011 0100 0101 0110 0111 1000
    // Extract 4 bits starting at bit 4: bits[7:4] = 0x7
    engine.reg_write(Register::RAX, 0x12345678); // Source value
    engine.reg_write(Register::RBX, 0x0404); // Start=4, Length=4

    let code = vec![
        0xC4, 0xE2, 0x60, 0xF7,
        0xC8, // bextr ecx, eax, ebx (vvvv=0011 inverted = 1100 = 0x60 bits[6:3])
        0x90, // nop
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(engine.reg_read(Register::RCX) & 0xFFFFFFFF, 0x7);
    assert!(!engine.cpu.rflags.contains(remu64::Flags::ZF));
    assert!(!engine.cpu.rflags.contains(remu64::Flags::CF));
    assert!(!engine.cpu.rflags.contains(remu64::Flags::OF));
}

#[test]
fn test_bextr_extract_byte() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Extract a full byte (8 bits) from the middle
    // src = 0xAABBCCDD
    // Extract 8 bits starting at bit 8: should get 0xCC
    engine.reg_write(Register::RAX, 0xAABBCCDD);
    engine.reg_write(Register::RBX, 0x0808); // Start=8, Length=8

    let code = vec![
        0xC4, 0xE2, 0x60, 0xF7,
        0xC8, // bextr ecx, eax, ebx (vvvv=0011 inverted = 1100 = 0x60 bits[6:3])
        0x90, // nop
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(engine.reg_read(Register::RCX) & 0xFFFFFFFF, 0xCC);
    assert!(!engine.cpu.rflags.contains(remu64::Flags::ZF));
}

#[test]
fn test_bextr_zero_length() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test with zero length - should return 0
    engine.reg_write(Register::RAX, 0x12345678);
    engine.reg_write(Register::RBX, 0x0004); // Start=4, Length=0

    let code = vec![
        0xC4, 0xE2, 0x60, 0xF7,
        0xC8, // bextr ecx, eax, ebx (vvvv=0011 inverted = 1100 = 0x60 bits[6:3])
        0x90, // nop
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(engine.reg_read(Register::RCX) & 0xFFFFFFFF, 0);
    assert!(engine.cpu.rflags.contains(remu64::Flags::ZF));
}

#[test]
fn test_bextr_out_of_bounds() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test with start position beyond operand size (32-bit)
    // Start=40 is beyond 32 bits, should return 0
    engine.reg_write(Register::RAX, 0x12345678);
    engine.reg_write(Register::RBX, 0x0828); // Start=40, Length=8

    let code = vec![
        0xC4, 0xE2, 0x60, 0xF7,
        0xC8, // bextr ecx, eax, ebx (vvvv=0011 inverted = 1100 = 0x60 bits[6:3])
        0x90, // nop
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(engine.reg_read(Register::RCX) & 0xFFFFFFFF, 0);
    assert!(engine.cpu.rflags.contains(remu64::Flags::ZF));
}

#[test]
fn test_bextr_64bit() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test 64-bit BEXTR
    // Extract 16 bits starting at bit 32
    engine.reg_write(Register::RAX, 0xFEDCBA9876543210);
    engine.reg_write(Register::RBX, 0x1020); // Start=32, Length=16

    let code = vec![
        0xC4, 0xE2, 0xE0, 0xF7, 0xC8, // bextr rcx, rax, rbx (64-bit, W=1, vvvv=rbx)
        0x90, // nop
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Should extract bits[47:32] = 0xBA98
    // (0xFEDCBA9876543210 >> 32) & 0xFFFF = 0xBA98
    assert_eq!(engine.reg_read(Register::RCX), 0xBA98);
    assert!(!engine.cpu.rflags.contains(remu64::Flags::ZF));
}

#[test]
fn test_bextr_partial_extraction() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test extraction that goes beyond operand boundary
    // For 32-bit operand, start at bit 28, length 8
    // Should only extract 4 bits (28,29,30,31)
    engine.reg_write(Register::RAX, 0xF0000000); // Top 4 bits set
    engine.reg_write(Register::RBX, 0x081C); // Start=28, Length=8

    let code = vec![
        0xC4, 0xE2, 0x60, 0xF7,
        0xC8, // bextr ecx, eax, ebx (vvvv=0011 inverted = 1100 = 0x60 bits[6:3])
        0x90, // nop
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Should extract only the top 4 bits = 0xF
    assert_eq!(engine.reg_read(Register::RCX) & 0xFFFFFFFF, 0xF);
    assert!(!engine.cpu.rflags.contains(remu64::Flags::ZF));
}

#[test]
fn test_bextr_extract_single_bit() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test extracting a single bit
    engine.reg_write(Register::RAX, 0x00000080); // Bit 7 set
    engine.reg_write(Register::RBX, 0x0107); // Start=7, Length=1

    let code = vec![
        0xC4, 0xE2, 0x60, 0xF7,
        0xC8, // bextr ecx, eax, ebx (vvvv=0011 inverted = 1100 = 0x60 bits[6:3])
        0x90, // nop
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(engine.reg_read(Register::RCX) & 0xFFFFFFFF, 1);
    assert!(!engine.cpu.rflags.contains(remu64::Flags::ZF));
}

#[test]
fn test_bextr_max_length() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test with maximum length (255)
    // Should extract all 32 bits for 32-bit operand
    engine.reg_write(Register::RAX, 0x12345678);
    engine.reg_write(Register::RBX, 0xFF00); // Start=0, Length=255

    let code = vec![
        0xC4, 0xE2, 0x60, 0xF7,
        0xC8, // bextr ecx, eax, ebx (vvvv=0011 inverted = 1100 = 0x60 bits[6:3])
        0x90, // nop
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Should extract entire 32-bit value
    assert_eq!(engine.reg_read(Register::RCX) & 0xFFFFFFFF, 0x12345678);
    assert!(!engine.cpu.rflags.contains(remu64::Flags::ZF));
}

#[test]
fn test_bextr_memory_operand() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code and data
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    engine
        .memory
        .map(0x2000, 0x1000, Permission::READ | Permission::WRITE)
        .unwrap();

    // Write test value to memory
    let value: u32 = 0xABCDEF00;
    engine.memory.write(0x2000, &value.to_le_bytes()).unwrap();

    // Extract bits[11:8] = 0xF
    engine.reg_write(Register::RBX, 0x0408); // Start=8, Length=4

    let code = vec![
        0xC4, 0xE2, 0x60, 0xF7, 0x0C, 0x25, 0x00, 0x20, 0x00,
        0x00, // bextr ecx, [0x2000], ebx (vvvv=ebx)
        0x90, // nop
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(engine.reg_read(Register::RCX) & 0xFFFFFFFF, 0xF);
    assert!(!engine.cpu.rflags.contains(remu64::Flags::ZF));
}
