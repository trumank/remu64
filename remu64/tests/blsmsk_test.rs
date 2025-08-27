use remu64::{Engine, EngineMode, Permission, Register, memory::MemoryTrait};

#[test]
fn test_blsmsk_basic() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x2000, Permission::ALL).unwrap();
    
    // Test: BLSMSK with value 0x12 (0001 0010)
    // Operation: src ^ (src - 1) = 0x12 ^ 0x11 = 0x03
    // Expected result: 0x03 (mask up to lowest set bit)
    // Note: The encoding actually produces blsmsk rax, rax
    let code = vec![
        0x48, 0xC7, 0xC0, 0x12, 0x00, 0x00, 0x00,  // mov rax, 0x12
        0xC4, 0xE2, 0xF8, 0xF3, 0xD0,              // blsmsk rax, rax (actual decoding)
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.reg_read(Register::RAX), 0x03, "BLSMSK should create mask up to lowest set bit");
    assert!(!engine.cpu.rflags.contains(remu64::cpu::Flags::ZF), "ZF should be clear for non-zero input");
    assert!(engine.cpu.rflags.contains(remu64::cpu::Flags::CF), "CF should be set for non-zero input");
}

#[test]
fn test_blsmsk_zero() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x2000, Permission::ALL).unwrap();
    
    // Test: BLSMSK with value 0
    // Operation: 0 ^ (0 - 1) = 0 ^ 0xFFFFFFFFFFFFFFFF = 0xFFFFFFFFFFFFFFFF
    // But since src=0, result should be 0 and ZF=1, CF=0
    let code = vec![
        0x48, 0x31, 0xC0,                          // xor rax, rax (rax = 0)
        0xC4, 0xE2, 0xF8, 0xF3, 0xD0,              // blsmsk rax, rax (actual)
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    // When src=0: 0 ^ (0-1) = 0 ^ 0xFFFFFFFFFFFFFFFF = 0xFFFFFFFFFFFFFFFF
    assert_eq!(engine.reg_read(Register::RAX), 0xFFFFFFFFFFFFFFFF, "BLSMSK of zero should be all 1s");
    assert!(engine.cpu.rflags.contains(remu64::cpu::Flags::ZF), "ZF should be set for zero input");
    assert!(!engine.cpu.rflags.contains(remu64::cpu::Flags::CF), "CF should be clear for zero input");
}

#[test]
fn test_blsmsk_powers_of_two() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x2000, Permission::ALL).unwrap();
    
    // Test: BLSMSK with powers of two
    let code = vec![
        // Test with 1: 1 ^ 0 = 1
        0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,  // mov rax, 0x01
        0xC4, 0xE2, 0xF8, 0xF3, 0xD8,              // blsmsk rax, rax (writes back to rax)
        0x48, 0x89, 0xC3,                          // mov rbx, rax (save result)
        
        // Test with 8: 8 ^ 7 = 0xF
        0x48, 0xC7, 0xC0, 0x08, 0x00, 0x00, 0x00,  // mov rax, 0x08
        0xC4, 0xE2, 0xF8, 0xF3, 0xD0,              // blsmsk rax, rax
        0x48, 0x89, 0xC2,                          // mov rdx, rax (save result)
        
        // Test with 0x80: 0x80 ^ 0x7F = 0xFF
        0x48, 0xC7, 0xC0, 0x80, 0x00, 0x00, 0x00,  // mov rax, 0x80
        0xC4, 0xE2, 0xF8, 0xF3, 0xC8,              // blsmsk rax, rax
        0x48, 0x89, 0xC1,                          // mov rcx, rax (save result)
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.reg_read(Register::RBX), 0x01, "BLSMSK of 0x01 should be 0x01");
    assert_eq!(engine.reg_read(Register::RDX), 0x0F, "BLSMSK of 0x08 should be 0x0F");
    assert_eq!(engine.reg_read(Register::RCX), 0xFF, "BLSMSK of 0x80 should be 0xFF");
}

#[test]
fn test_blsmsk_multiple_bits() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x2000, Permission::ALL).unwrap();
    
    // Test various values with multiple bits set
    let code = vec![
        // Test with 0xFF: 0xFF ^ 0xFE = 0x01
        0x48, 0xC7, 0xC0, 0xFF, 0x00, 0x00, 0x00,  // mov rax, 0xFF
        0xC4, 0xE2, 0xF8, 0xF3, 0xD8,              // blsmsk rbx, rax
        
        // Test with 0x1C (0001 1100): 0x1C ^ 0x1B = 0x07
        0x48, 0xC7, 0xC0, 0x1C, 0x00, 0x00, 0x00,  // mov rax, 0x1C
        0xC4, 0xE2, 0xF8, 0xF3, 0xD0,              // blsmsk rdx, rax
        
        // Test with 0xF0 (1111 0000): 0xF0 ^ 0xEF = 0x1F
        0x48, 0xC7, 0xC0, 0xF0, 0x00, 0x00, 0x00,  // mov rax, 0xF0
        0xC4, 0xE2, 0xF8, 0xF3, 0xC8,              // blsmsk rcx, rax
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.reg_read(Register::RBX), 0x01, "BLSMSK of 0xFF should be 0x01");
    assert_eq!(engine.reg_read(Register::RDX), 0x07, "BLSMSK of 0x1C should be 0x07");
    assert_eq!(engine.reg_read(Register::RCX), 0x1F, "BLSMSK of 0xF0 should be 0x1F");
}

#[test]
fn test_blsmsk_32bit() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x2000, Permission::ALL).unwrap();
    
    // Test 32-bit BLSMSK
    // 0x30 ^ 0x2F = 0x1F
    let code = vec![
        0xB8, 0x30, 0x00, 0x00, 0x00,              // mov eax, 0x30
        0xC4, 0xE2, 0x78, 0xF3, 0xD0,              // blsmsk edx, eax (32-bit version)
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.reg_write(Register::RDX, 0xFFFFFFFFFFFFFFFF); // Pre-fill with all 1s
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.reg_read(Register::EDX), 0x1F, "32-bit BLSMSK of 0x30 should be 0x1F");
    assert_eq!(engine.reg_read(Register::RDX), 0x1F, "Upper 32 bits should be cleared");
}

#[test]
fn test_blsmsk_large_values() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x2000, Permission::ALL).unwrap();
    
    // Test with large 64-bit values
    let code = vec![
        // Test with 0x8000000000000000: huge ^ (huge-1) = 0xFFFFFFFFFFFFFFFF
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,  // movabs rax, 0x8000000000000000
        0xC4, 0xE2, 0xF8, 0xF3, 0xD8,              // blsmsk rbx, rax
        
        // Test with 0xFFFFFFFFFFFFFFF0: 0xF...F0 ^ 0xF...EF = 0x1F
        0x48, 0xB8, 0xF0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // movabs rax, 0xFFFFFFFFFFFFFFF0
        0xC4, 0xE2, 0xF8, 0xF3, 0xD0,              // blsmsk rdx, rax
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.reg_read(Register::RBX), 0xFFFFFFFFFFFFFFFF, 
               "BLSMSK of MSB only should create full mask");
    assert_eq!(engine.reg_read(Register::RDX), 0x1F, 
               "BLSMSK of 0xFFFFFFFFFFFFFFF0 should be 0x1F");
}