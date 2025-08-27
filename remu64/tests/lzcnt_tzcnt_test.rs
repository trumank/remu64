use remu64::{Engine, EngineMode, Permission, Register, memory::MemoryTrait};

#[test]
fn test_lzcnt_basic() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Test LZCNT with various values
    // LZCNT counts leading zeros
    
    // Test 1: LZCNT with non-zero 32-bit value (0x00008000 = 16384)
    // Binary: 0000 0000 0000 0000 1000 0000 0000 0000
    // Should have 16 leading zeros
    engine.reg_write(Register::RAX, 0x00008000);
    
    let code = vec![
        0xF3, 0x0F, 0xBD, 0xC8,  // lzcnt ecx, eax
        0x90,                     // nop
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.reg_read(Register::RCX) & 0xFFFFFFFF, 16);
    assert!(!engine.cpu.rflags.contains(remu64::Flags::CF));
    assert!(!engine.cpu.rflags.contains(remu64::Flags::ZF));
}

#[test]
fn test_lzcnt_zero() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Test LZCNT with zero (32-bit)
    // Should return 32 (operand size in bits) and set CF
    engine.reg_write(Register::RAX, 0);
    
    let code = vec![
        0xF3, 0x0F, 0xBD, 0xC8,  // lzcnt ecx, eax
        0x90,                     // nop
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.reg_read(Register::RCX) & 0xFFFFFFFF, 32);
    assert!(engine.cpu.rflags.contains(remu64::Flags::CF));
    assert!(engine.cpu.rflags.contains(remu64::Flags::ZF));
}

#[test]
fn test_lzcnt_64bit() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Test LZCNT with 64-bit value
    // 0x0000000100000000 has 31 leading zeros
    engine.reg_write(Register::RAX, 0x0000000100000000);
    
    let code = vec![
        0xF3, 0x48, 0x0F, 0xBD, 0xC8,  // lzcnt rcx, rax
        0x90,                           // nop
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.reg_read(Register::RCX), 31);
    assert!(!engine.cpu.rflags.contains(remu64::Flags::CF));
    assert!(!engine.cpu.rflags.contains(remu64::Flags::ZF));
}

#[test]
fn test_lzcnt_16bit() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Test LZCNT with 16-bit value
    // 0x0100 = 256 has 7 leading zeros in 16-bit
    engine.reg_write(Register::RAX, 0x0100);
    
    let code = vec![
        0x66, 0xF3, 0x0F, 0xBD, 0xC8,  // lzcnt cx, ax (16-bit)
        0x90,                           // nop
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.reg_read(Register::RCX) & 0xFFFF, 7);
    assert!(!engine.cpu.rflags.contains(remu64::Flags::CF));
    assert!(!engine.cpu.rflags.contains(remu64::Flags::ZF));
}

#[test]
fn test_tzcnt_basic() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Test TZCNT with various values
    // TZCNT counts trailing zeros
    
    // Test 1: TZCNT with value 0x00008000 (bit 15 set)
    // Binary: 0000 0000 0000 0000 1000 0000 0000 0000
    // Should have 15 trailing zeros
    engine.reg_write(Register::RAX, 0x00008000);
    
    let code = vec![
        0xF3, 0x0F, 0xBC, 0xC8,  // tzcnt ecx, eax
        0x90,                     // nop
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.reg_read(Register::RCX) & 0xFFFFFFFF, 15);
    assert!(!engine.cpu.rflags.contains(remu64::Flags::CF));
    assert!(!engine.cpu.rflags.contains(remu64::Flags::ZF));
}

#[test]
fn test_tzcnt_zero() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Test TZCNT with zero (32-bit)
    // Should return 32 (operand size in bits) and set CF
    engine.reg_write(Register::RAX, 0);
    
    let code = vec![
        0xF3, 0x0F, 0xBC, 0xC8,  // tzcnt ecx, eax
        0x90,                     // nop
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.reg_read(Register::RCX) & 0xFFFFFFFF, 32);
    assert!(engine.cpu.rflags.contains(remu64::Flags::CF));
    assert!(engine.cpu.rflags.contains(remu64::Flags::ZF));
}

#[test]
fn test_tzcnt_64bit() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Test TZCNT with 64-bit value
    // 0x0000100000000000 has 44 trailing zeros
    engine.reg_write(Register::RAX, 0x0000100000000000);
    
    let code = vec![
        0xF3, 0x48, 0x0F, 0xBC, 0xC8,  // tzcnt rcx, rax
        0x90,                           // nop
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.reg_read(Register::RCX), 44);
    assert!(!engine.cpu.rflags.contains(remu64::Flags::CF));
    assert!(!engine.cpu.rflags.contains(remu64::Flags::ZF));
}

#[test]
fn test_tzcnt_no_trailing_zeros() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Test TZCNT with odd number (no trailing zeros)
    engine.reg_write(Register::RAX, 0x12345679);  // Odd number
    
    let code = vec![
        0xF3, 0x0F, 0xBC, 0xC8,  // tzcnt ecx, eax
        0x90,                     // nop
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.reg_read(Register::RCX) & 0xFFFFFFFF, 0);
    assert!(!engine.cpu.rflags.contains(remu64::Flags::CF));
    assert!(!engine.cpu.rflags.contains(remu64::Flags::ZF));
}

#[test]
fn test_lzcnt_all_ones() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Test LZCNT with all ones (32-bit)
    engine.reg_write(Register::RAX, 0xFFFFFFFF);
    
    let code = vec![
        0xF3, 0x0F, 0xBD, 0xC8,  // lzcnt ecx, eax
        0x90,                     // nop
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.reg_read(Register::RCX) & 0xFFFFFFFF, 0);
    assert!(!engine.cpu.rflags.contains(remu64::Flags::CF));
    assert!(!engine.cpu.rflags.contains(remu64::Flags::ZF));
}

#[test]
fn test_tzcnt_memory_operand() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory for code and data
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    engine.memory.map(0x2000, 0x1000, Permission::READ | Permission::WRITE).unwrap();
    
    // Write test value to memory
    let value: u32 = 0x00001000;  // 12 trailing zeros
    engine.memory.write(0x2000, &value.to_le_bytes()).unwrap();
    
    // Test TZCNT with memory operand
    let code = vec![
        0xF3, 0x0F, 0xBC, 0x0C, 0x25, 0x00, 0x20, 0x00, 0x00,  // tzcnt ecx, [0x2000]
        0x90,                                                     // nop
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.reg_read(Register::RCX) & 0xFFFFFFFF, 12);
    assert!(!engine.cpu.rflags.contains(remu64::Flags::CF));
    assert!(!engine.cpu.rflags.contains(remu64::Flags::ZF));
}

#[test]
fn test_lzcnt_memory_operand() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory for code and data
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    engine.memory.map(0x2000, 0x1000, Permission::READ | Permission::WRITE).unwrap();
    
    // Write test value to memory
    let value: u32 = 0x00100000;  // 11 leading zeros
    engine.memory.write(0x2000, &value.to_le_bytes()).unwrap();
    
    // Test LZCNT with memory operand
    let code = vec![
        0xF3, 0x0F, 0xBD, 0x0C, 0x25, 0x00, 0x20, 0x00, 0x00,  // lzcnt ecx, [0x2000]
        0x90,                                                     // nop
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.reg_read(Register::RCX) & 0xFFFFFFFF, 11);
    assert!(!engine.cpu.rflags.contains(remu64::Flags::CF));
    assert!(!engine.cpu.rflags.contains(remu64::Flags::ZF));
}