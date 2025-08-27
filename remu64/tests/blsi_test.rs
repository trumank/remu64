use remu64::{Engine, EngineMode, Permission, Register, memory::MemoryTrait};

fn setup_engine() -> Engine<impl MemoryTrait> {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x2000, Permission::ALL).unwrap();
    engine
}

#[test]
fn test_blsi_basic() {
    let mut engine = setup_engine();
    
    // Test: BLSI with value 0x12 (0001 0010)
    // Expected result: 0x02 (0000 0010) - isolates the lowest set bit
    let code = vec![
        0x48, 0xC7, 0xC0, 0x12, 0x00, 0x00, 0x00,  // mov rax, 0x12
        0xC4, 0xE2, 0xE0, 0xF3, 0xD8,              // blsi rbx, rax (VEX.LZ.0F38.F3 /3)
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.reg_read(Register::RBX), 0x02, "BLSI should isolate lowest set bit");
    assert!(!engine.cpu.rflags.contains(remu64::cpu::Flags::ZF), "ZF should be clear for non-zero input");
    assert!(engine.cpu.rflags.contains(remu64::cpu::Flags::CF), "CF should be set for non-zero input");
}

#[test]
fn test_blsi_zero() {
    let mut engine = setup_engine();
    
    // Test: BLSI with value 0
    // Expected result: 0, ZF=1, CF=0
    let code = vec![
        0x48, 0x31, 0xC0,                          // xor rax, rax (rax = 0)
        0xC4, 0xE2, 0xE0, 0xF3, 0xD8,              // blsi rbx, rax (VEX.LZ.0F38.F3 /3)
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.reg_read(Register::RBX), 0, "BLSI of zero should be zero");
    assert!(engine.cpu.rflags.contains(remu64::cpu::Flags::ZF), "ZF should be set for zero input");
    assert!(!engine.cpu.rflags.contains(remu64::cpu::Flags::CF), "CF should be clear for zero input");
}

#[test]
fn test_blsi_powers_of_two() {
    let mut engine = setup_engine();
    
    // Test: BLSI with powers of two (only one bit set)
    // Expected: Same value (since there's only one bit set)
    let code = vec![
        // Test with 1
        0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,  // mov rax, 0x01
        0xC4, 0xE2, 0xE0, 0xF3, 0xD8,              // blsi rbx, rax
        
        // Test with 8
        0x48, 0xC7, 0xC0, 0x08, 0x00, 0x00, 0x00,  // mov rax, 0x08
        0xC4, 0xE2, 0xE8, 0xF3, 0xD8,              // blsi rdx, rax
        
        // Test with 0x80
        0x48, 0xC7, 0xC0, 0x80, 0x00, 0x00, 0x00,  // mov rax, 0x80
        0xC4, 0xE2, 0xF0, 0xF3, 0xD8,              // blsi rcx, rax
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.reg_read(Register::RBX), 0x01, "BLSI of 0x01 should be 0x01");
    assert_eq!(engine.reg_read(Register::RDX), 0x08, "BLSI of 0x08 should be 0x08");
    assert_eq!(engine.reg_read(Register::RCX), 0x80, "BLSI of 0x80 should be 0x80");
}

#[test]
fn test_blsi_multiple_bits() {
    let mut engine = setup_engine();
    
    // Test various values with multiple bits set
    let code = vec![
        // Test with 0xFF (all bits set in low byte)
        // Expected: 0x01 (lowest bit)
        0x48, 0xC7, 0xC0, 0xFF, 0x00, 0x00, 0x00,  // mov rax, 0xFF
        0xC4, 0xE2, 0xE0, 0xF3, 0xD8,              // blsi rbx, rax
        
        // Test with 0x1C (0001 1100)
        // Expected: 0x04 (0000 0100)
        0x48, 0xC7, 0xC0, 0x1C, 0x00, 0x00, 0x00,  // mov rax, 0x1C
        0xC4, 0xE2, 0xE8, 0xF3, 0xD8,              // blsi rdx, rax
        
        // Test with 0xF0 (1111 0000)
        // Expected: 0x10 (0001 0000)
        0x48, 0xC7, 0xC0, 0xF0, 0x00, 0x00, 0x00,  // mov rax, 0xF0
        0xC4, 0xE2, 0xF0, 0xF3, 0xD8,              // blsi rcx, rax
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.reg_read(Register::RBX), 0x01, "BLSI of 0xFF should be 0x01");
    assert_eq!(engine.reg_read(Register::RDX), 0x04, "BLSI of 0x1C should be 0x04");
    assert_eq!(engine.reg_read(Register::RCX), 0x10, "BLSI of 0xF0 should be 0x10");
}

#[test]
fn test_blsi_32bit() {
    let mut engine = setup_engine();
    
    // Test 32-bit BLSI
    let code = vec![
        0xB8, 0x30, 0x00, 0x00, 0x00,              // mov eax, 0x30
        0xC4, 0xE2, 0x60, 0xF3, 0xD8,              // blsi ebx, eax (32-bit VEX.LZ.0F38.F3 /3)
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.reg_write(Register::RBX, 0xFFFFFFFFFFFFFFFF); // Pre-fill with all 1s
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    // Check that only lower 32 bits are affected
    assert_eq!(engine.reg_read(Register::EBX), 0x10, "32-bit BLSI of 0x30 should be 0x10");
    assert_eq!(engine.reg_read(Register::RBX), 0x10, "Upper 32 bits should be cleared");
}

#[test]
fn test_blsi_large_values() {
    let mut engine = setup_engine();
    
    // Test with large 64-bit values
    let code = vec![
        // Test with 0x8000000000000000 (only MSB set)
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,  // movabs rax, 0x8000000000000000
        0xC4, 0xE2, 0xE0, 0xF3, 0xD8,              // blsi rbx, rax
        
        // Test with 0xFFFFFFFFFFFFFFF0
        0x48, 0xB8, 0xF0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // movabs rax, 0xFFFFFFFFFFFFFFF0
        0xC4, 0xE2, 0xE8, 0xF3, 0xD8,              // blsi rdx, rax
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.reg_read(Register::RBX), 0x8000000000000000u64, 
               "BLSI of MSB only should return MSB");
    assert_eq!(engine.reg_read(Register::RDX), 0x10, 
               "BLSI of 0xFFFFFFFFFFFFFFF0 should be 0x10");
}

#[test]
fn test_blsi_alternating_pattern() {
    let mut engine = setup_engine();
    
    // Test with alternating bit patterns
    let code = vec![
        // 0xAAAA (1010 1010 1010 1010) -> should get 0x0002
        0x48, 0xC7, 0xC0, 0xAA, 0xAA, 0x00, 0x00,  // mov rax, 0xAAAA
        0xC4, 0xE2, 0xE0, 0xF3, 0xD8,              // blsi rbx, rax
        
        // 0x5555 (0101 0101 0101 0101) -> should get 0x0001
        0x48, 0xC7, 0xC0, 0x55, 0x55, 0x00, 0x00,  // mov rax, 0x5555
        0xC4, 0xE2, 0xE8, 0xF3, 0xD8,              // blsi rdx, rax
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.reg_read(Register::RBX), 0x0002, "BLSI of 0xAAAA should be 0x0002");
    assert_eq!(engine.reg_read(Register::RDX), 0x0001, "BLSI of 0x5555 should be 0x0001");
}

#[test]
fn test_blsi_memory_operand() {
    let mut engine = setup_engine();
    
    // Test BLSI with memory operand
    engine.memory.write(0x2000, &0x48u64.to_le_bytes()).unwrap(); // Write 0x48 to memory
    
    let code = vec![
        0xC4, 0xE2, 0xE0, 0xF3, 0x1C, 0x25, 0x00, 0x20, 0x00, 0x00,  // blsi rbx, qword ptr [0x2000] (VEX.LZ.0F38.F3 /3)
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.reg_read(Register::RBX), 0x08, "BLSI of 0x48 from memory should be 0x08");
}

#[test]
fn test_blsi_sign_flag() {
    let mut engine = setup_engine();
    
    // Test SF flag with negative result (when MSB is set in result)
    let code = vec![
        // For 32-bit: 0x80000000 -> BLSI result is 0x80000000 (SF=1)
        0xB8, 0x00, 0x00, 0x00, 0x80,              // mov eax, 0x80000000
        0xC4, 0xE2, 0x60, 0xF3, 0xD8,              // blsi ebx, eax
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.reg_read(Register::EBX), 0x80000000, "BLSI of 0x80000000 should be 0x80000000");
    assert!(engine.cpu.rflags.contains(remu64::cpu::Flags::SF), "SF should be set when result has MSB set");
}