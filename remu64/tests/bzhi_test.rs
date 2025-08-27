use remu64::{Engine, EngineMode, Permission, Register, memory::MemoryTrait};

fn setup_engine() -> Engine<impl MemoryTrait> {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x2000, Permission::ALL).unwrap();
    engine
}

#[test]
fn test_bzhi_32bit_basic() {
    let mut engine = setup_engine();
    
    // Test: BZHI with value 0xFFFFFFFF, index 8
    // Expected: 0xFF (keeps only lower 8 bits)
    let code = vec![
        0xB8, 0xFF, 0xFF, 0xFF, 0xFF,        // mov eax, 0xFFFFFFFF
        0xB9, 0x08, 0x00, 0x00, 0x00,        // mov ecx, 8
        0xC4, 0xE2, 0x70, 0xF5, 0xD8,        // bzhi ebx, eax, ecx
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.cpu.write_reg(Register::RIP, 0x1000);
    
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.cpu.read_reg(Register::RBX) as u32, 0xFF);
    assert!(!engine.cpu.rflags.contains(remu64::Flags::CF), "CF should be cleared");
    assert!(!engine.cpu.rflags.contains(remu64::Flags::OF), "OF should be cleared");
    assert!(!engine.cpu.rflags.contains(remu64::Flags::SF), "SF should be clear");
    assert!(!engine.cpu.rflags.contains(remu64::Flags::ZF), "ZF should be clear");
}

#[test]
fn test_bzhi_32bit_zero_index() {
    let mut engine = setup_engine();
    
    // Test: BZHI with index = 0 (should return 0)
    let code = vec![
        0xB8, 0xFF, 0xFF, 0xFF, 0xFF,        // mov eax, 0xFFFFFFFF
        0xB9, 0x00, 0x00, 0x00, 0x00,        // mov ecx, 0
        0xC4, 0xE2, 0x70, 0xF5, 0xD8,        // bzhi ebx, eax, ecx
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.cpu.write_reg(Register::RIP, 0x1000);
    
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.cpu.read_reg(Register::RBX) as u32, 0);
    assert!(!engine.cpu.rflags.contains(remu64::Flags::CF), "CF should be cleared");
    assert!(!engine.cpu.rflags.contains(remu64::Flags::OF), "OF should be cleared");
    assert!(!engine.cpu.rflags.contains(remu64::Flags::SF), "SF should be clear");
    assert!(engine.cpu.rflags.contains(remu64::Flags::ZF), "ZF should be set for zero result");
}

#[test]
fn test_bzhi_32bit_full_width() {
    let mut engine = setup_engine();
    
    // Test: BZHI with index >= 32 (should return unchanged value)
    let code = vec![
        0xB8, 0x78, 0x56, 0x34, 0x12,        // mov eax, 0x12345678
        0xB9, 0x20, 0x00, 0x00, 0x00,        // mov ecx, 32
        0xC4, 0xE2, 0x70, 0xF5, 0xD8,        // bzhi ebx, eax, ecx
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.cpu.write_reg(Register::RIP, 0x1000);
    
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.cpu.read_reg(Register::RBX) as u32, 0x12345678);
    assert!(!engine.cpu.rflags.contains(remu64::Flags::CF), "CF should be cleared");
    assert!(!engine.cpu.rflags.contains(remu64::Flags::OF), "OF should be cleared");
    assert!(!engine.cpu.rflags.contains(remu64::Flags::SF), "SF should be clear");
    assert!(!engine.cpu.rflags.contains(remu64::Flags::ZF), "ZF should be clear");
}

#[test]
fn test_bzhi_32bit_16_bits() {
    let mut engine = setup_engine();
    
    // Test: BZHI extracting 16 bits
    let code = vec![
        0xB8, 0x78, 0x56, 0x34, 0x12,        // mov eax, 0x12345678
        0xB9, 0x10, 0x00, 0x00, 0x00,        // mov ecx, 16
        0xC4, 0xE2, 0x70, 0xF5, 0xD8,        // bzhi ebx, eax, ecx
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.cpu.write_reg(Register::RIP, 0x1000);
    
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.cpu.read_reg(Register::RBX) as u32, 0x5678);
    assert!(!engine.cpu.rflags.contains(remu64::Flags::CF), "CF should be cleared");
    assert!(!engine.cpu.rflags.contains(remu64::Flags::OF), "OF should be cleared");
    assert!(!engine.cpu.rflags.contains(remu64::Flags::SF), "SF should be clear");
    assert!(!engine.cpu.rflags.contains(remu64::Flags::ZF), "ZF should be clear");
}

#[test]
fn test_bzhi_32bit_negative_result() {
    let mut engine = setup_engine();
    
    // Test: BZHI with result having sign bit set
    let code = vec![
        0xB8, 0x21, 0x43, 0x65, 0x87,        // mov eax, 0x87654321
        0xB9, 0x64, 0x00, 0x00, 0x00,        // mov ecx, 100 (>32, returns unchanged)
        0xC4, 0xE2, 0x70, 0xF5, 0xD8,        // bzhi ebx, eax, ecx
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.cpu.write_reg(Register::RIP, 0x1000);
    
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.cpu.read_reg(Register::RBX) as u32, 0x87654321);
    assert!(!engine.cpu.rflags.contains(remu64::Flags::CF), "CF should be cleared");
    assert!(!engine.cpu.rflags.contains(remu64::Flags::OF), "OF should be cleared");
    assert!(engine.cpu.rflags.contains(remu64::Flags::SF), "SF should be set for negative result");
    assert!(!engine.cpu.rflags.contains(remu64::Flags::ZF), "ZF should be clear");
}

#[test]
fn test_bzhi_64bit_basic() {
    let mut engine = setup_engine();
    
    // Test: BZHI with 64-bit operands, extracting 32 bits
    let code = vec![
        0x48, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // mov rax, 0xFFFFFFFFFFFFFFFF
        0x48, 0xC7, 0xC1, 0x20, 0x00, 0x00, 0x00,                    // mov rcx, 32
        0xC4, 0xE2, 0xF0, 0xF5, 0xD8,                                // bzhi rbx, rax, rcx
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.cpu.write_reg(Register::RIP, 0x1000);
    
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.cpu.read_reg(Register::RBX), 0xFFFFFFFF);
    assert!(!engine.cpu.rflags.contains(remu64::Flags::CF), "CF should be cleared");
    assert!(!engine.cpu.rflags.contains(remu64::Flags::OF), "OF should be cleared");
    assert!(!engine.cpu.rflags.contains(remu64::Flags::SF), "SF should be clear");
    assert!(!engine.cpu.rflags.contains(remu64::Flags::ZF), "ZF should be clear");
}

#[test]
fn test_bzhi_64bit_48_bits() {
    let mut engine = setup_engine();
    
    // Test: BZHI extracting 48 bits
    let code = vec![
        0x48, 0xB8, 0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12,  // mov rax, 0x123456789ABCDEF0
        0x48, 0xC7, 0xC1, 0x30, 0x00, 0x00, 0x00,                    // mov rcx, 48
        0xC4, 0xE2, 0xF0, 0xF5, 0xD8,                                // bzhi rbx, rax, rcx
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.cpu.write_reg(Register::RIP, 0x1000);
    
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.cpu.read_reg(Register::RBX), 0x56789ABCDEF0);
    assert!(!engine.cpu.rflags.contains(remu64::Flags::CF), "CF should be cleared");
    assert!(!engine.cpu.rflags.contains(remu64::Flags::OF), "OF should be cleared");
    assert!(!engine.cpu.rflags.contains(remu64::Flags::SF), "SF should be clear");
    assert!(!engine.cpu.rflags.contains(remu64::Flags::ZF), "ZF should be clear");
}

#[test]
fn test_bzhi_64bit_full_width() {
    let mut engine = setup_engine();
    
    // Test: BZHI with index >= 64 (should return unchanged value)
    let code = vec![
        0x48, 0xB8, 0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,  // mov rax, 0xFEDCBA9876543210
        0x48, 0xC7, 0xC1, 0x40, 0x00, 0x00, 0x00,                    // mov rcx, 64
        0xC4, 0xE2, 0xF0, 0xF5, 0xD8,                                // bzhi rbx, rax, rcx
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.cpu.write_reg(Register::RIP, 0x1000);
    
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.cpu.read_reg(Register::RBX), 0xFEDCBA9876543210);
    assert!(!engine.cpu.rflags.contains(remu64::Flags::CF), "CF should be cleared");
    assert!(!engine.cpu.rflags.contains(remu64::Flags::OF), "OF should be cleared");
    assert!(engine.cpu.rflags.contains(remu64::Flags::SF), "SF should be set for negative result");
    assert!(!engine.cpu.rflags.contains(remu64::Flags::ZF), "ZF should be clear");
}

#[test]
fn test_bzhi_64bit_zero_result() {
    let mut engine = setup_engine();
    
    // Test: BZHI producing zero result (all set bits above index)
    let code = vec![
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF,  // mov rax, 0xFF00000000000000
        0x48, 0xC7, 0xC1, 0x20, 0x00, 0x00, 0x00,                    // mov rcx, 32
        0xC4, 0xE2, 0xF0, 0xF5, 0xD8,                                // bzhi rbx, rax, rcx
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.cpu.write_reg(Register::RIP, 0x1000);
    
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.cpu.read_reg(Register::RBX), 0);
    assert!(!engine.cpu.rflags.contains(remu64::Flags::CF), "CF should be cleared");
    assert!(!engine.cpu.rflags.contains(remu64::Flags::OF), "OF should be cleared");
    assert!(!engine.cpu.rflags.contains(remu64::Flags::SF), "SF should be clear");
    assert!(engine.cpu.rflags.contains(remu64::Flags::ZF), "ZF should be set for zero result");
}

#[test]
fn test_bzhi_index_only_low_byte() {
    let mut engine = setup_engine();
    
    // Test: Only bits 7:0 of index are used (0x108 & 0xFF = 8)
    let code = vec![
        0xB8, 0xFF, 0xFF, 0xFF, 0xFF,              // mov eax, 0xFFFFFFFF
        0xB9, 0x08, 0x01, 0x00, 0x00,              // mov ecx, 0x108
        0xC4, 0xE2, 0x70, 0xF5, 0xD8,              // bzhi ebx, eax, ecx
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.cpu.write_reg(Register::RIP, 0x1000);
    
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.cpu.read_reg(Register::RBX) as u32, 0xFF);
    assert!(!engine.cpu.rflags.contains(remu64::Flags::CF), "CF should be cleared");
    assert!(!engine.cpu.rflags.contains(remu64::Flags::OF), "OF should be cleared");
    assert!(!engine.cpu.rflags.contains(remu64::Flags::SF), "SF should be clear");
    assert!(!engine.cpu.rflags.contains(remu64::Flags::ZF), "ZF should be clear");
}