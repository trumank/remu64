use remu64::{Engine, EngineMode, Permission, Register, memory::MemoryTrait};

#[test]
fn test_andn_basic() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Test ANDN: result = ~src1 & src2
    // src1 = 0x0F0F0F0F, src2 = 0xAAAAAAAA
    // ~src1 = 0xF0F0F0F0
    // result = 0xF0F0F0F0 & 0xAAAAAAAA = 0xA0A0A0A0
    engine.reg_write(Register::RAX, 0x0F0F0F0F);  // src1
    engine.reg_write(Register::RBX, 0xAAAAAAAA);  // src2
    
    let code = vec![
        0xC4, 0xE2, 0x78, 0xF2, 0xCB,  // andn ecx, eax, ebx
        0x90,                           // nop
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.reg_read(Register::RCX) & 0xFFFFFFFF, 0xA0A0A0A0);
    assert!(!engine.cpu.rflags.contains(remu64::Flags::ZF));
    assert!(engine.cpu.rflags.contains(remu64::Flags::SF));  // Negative result
    assert!(!engine.cpu.rflags.contains(remu64::Flags::CF));
    assert!(!engine.cpu.rflags.contains(remu64::Flags::OF));
}

#[test]
fn test_andn_zero_result() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Test ANDN with result = 0
    // src1 = 0xFFFFFFFF, src2 = 0x00000000
    // ~src1 = 0x00000000
    // result = 0x00000000 & 0x00000000 = 0x00000000
    engine.reg_write(Register::RAX, 0xFFFFFFFF);  // src1
    engine.reg_write(Register::RBX, 0x00000000);  // src2
    
    let code = vec![
        0xC4, 0xE2, 0x78, 0xF2, 0xCB,  // andn ecx, eax, ebx
        0x90,                           // nop
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.reg_read(Register::RCX) & 0xFFFFFFFF, 0);
    assert!(engine.cpu.rflags.contains(remu64::Flags::ZF));  // Zero flag set
    assert!(!engine.cpu.rflags.contains(remu64::Flags::SF));
    assert!(!engine.cpu.rflags.contains(remu64::Flags::CF));
    assert!(!engine.cpu.rflags.contains(remu64::Flags::OF));
}

#[test]
fn test_andn_64bit() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Test 64-bit ANDN
    // src1 = 0x0F0F0F0F0F0F0F0F, src2 = 0xAAAAAAAAAAAAAAAA
    // ~src1 = 0xF0F0F0F0F0F0F0F0
    // result = 0xA0A0A0A0A0A0A0A0
    engine.reg_write(Register::RAX, 0x0F0F0F0F0F0F0F0F);
    engine.reg_write(Register::RBX, 0xAAAAAAAAAAAAAAAA);
    
    let code = vec![
        0xC4, 0xE2, 0xF8, 0xF2, 0xCB,  // andn rcx, rax, rbx (64-bit)
        0x90,                           // nop
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.reg_read(Register::RCX), 0xA0A0A0A0A0A0A0A0);
    assert!(!engine.cpu.rflags.contains(remu64::Flags::ZF));
    assert!(engine.cpu.rflags.contains(remu64::Flags::SF));  // Negative in 64-bit
}

#[test]
fn test_andn_all_ones() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Test ANDN where src1 = 0, src2 = all ones
    // ~0 = 0xFFFFFFFF, result = 0xFFFFFFFF
    engine.reg_write(Register::RAX, 0x00000000);  // src1
    engine.reg_write(Register::RBX, 0xFFFFFFFF);  // src2
    
    let code = vec![
        0xC4, 0xE2, 0x78, 0xF2, 0xCB,  // andn ecx, eax, ebx
        0x90,                           // nop
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.reg_read(Register::RCX) & 0xFFFFFFFF, 0xFFFFFFFF);
    assert!(!engine.cpu.rflags.contains(remu64::Flags::ZF));
    assert!(engine.cpu.rflags.contains(remu64::Flags::SF));  // Sign bit set
}

#[test]
fn test_andn_memory_operand() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory for code and data
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    engine.memory.map(0x2000, 0x1000, Permission::READ | Permission::WRITE).unwrap();
    
    // Write test value to memory
    let value: u32 = 0x55555555;
    engine.memory.write(0x2000, &value.to_le_bytes()).unwrap();
    
    // Test ANDN with memory operand as src2
    // src1 = 0xAAAAAAAA, src2 = 0x55555555
    // ~src1 = 0x55555555
    // result = 0x55555555 & 0x55555555 = 0x55555555
    engine.reg_write(Register::RAX, 0xAAAAAAAA);
    
    let code = vec![
        0xC4, 0xE2, 0x78, 0xF2, 0x0C, 0x25, 0x00, 0x20, 0x00, 0x00,  // andn ecx, eax, [0x2000]
        0x90,                                                           // nop
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.reg_read(Register::RCX) & 0xFFFFFFFF, 0x55555555);
    assert!(!engine.cpu.rflags.contains(remu64::Flags::ZF));
    assert!(!engine.cpu.rflags.contains(remu64::Flags::SF));
}

#[test]
fn test_andn_alternating_bits() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Test with alternating bit patterns
    // src1 = 0x55555555 (0101...)
    // src2 = 0xAAAAAAAA (1010...)
    // ~src1 = 0xAAAAAAAA
    // result = 0xAAAAAAAA & 0xAAAAAAAA = 0xAAAAAAAA
    engine.reg_write(Register::RAX, 0x55555555);
    engine.reg_write(Register::RBX, 0xAAAAAAAA);
    
    let code = vec![
        0xC4, 0xE2, 0x78, 0xF2, 0xCB,  // andn ecx, eax, ebx
        0x90,                           // nop
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.reg_read(Register::RCX) & 0xFFFFFFFF, 0xAAAAAAAA);
    assert!(!engine.cpu.rflags.contains(remu64::Flags::ZF));
    assert!(engine.cpu.rflags.contains(remu64::Flags::SF));  // Negative
    
    // Verify parity flag (even number of bits in low byte)
    // 0xAA = 10101010 = 4 ones = even parity
    assert!(engine.cpu.rflags.contains(remu64::Flags::PF));
}

#[test]
fn test_andn_same_register() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Test ANDN with same register as both sources
    // src1 = src2 = 0x12345678
    // ~src1 = 0xEDCBA987
    // result = 0xEDCBA987 & 0x12345678 = 0x00000000
    engine.reg_write(Register::RAX, 0x12345678);
    
    let code = vec![
        0xC4, 0xE2, 0x78, 0xF2, 0xC8,  // andn ecx, eax, eax
        0x90,                           // nop
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    // ANDN with same register should always result in 0
    assert_eq!(engine.reg_read(Register::RCX) & 0xFFFFFFFF, 0);
    assert!(engine.cpu.rflags.contains(remu64::Flags::ZF));
    assert!(!engine.cpu.rflags.contains(remu64::Flags::SF));
}