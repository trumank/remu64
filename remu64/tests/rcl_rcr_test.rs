use remu64::{Engine, EngineMode, Permission, Register, memory::MemoryTrait, cpu::Flags};

#[test]
fn test_rcl_basic() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Set CF=1 and test RCL
    let code = vec![
        0xf9,                           // STC (set carry flag)
        0xb8, 0x01, 0x00, 0x00, 0x80,  // mov eax, 0x80000001
        0xd1, 0xd0,                     // rcl eax, 1
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();

    // 0x80000001 with CF=1:
    // Rotate left through carry: CF becomes LSB, MSB goes to CF
    // Result: 0x00000003, CF=1
    assert_eq!(engine.reg_read(Register::EAX), 0x00000003);
    assert!(engine.flags_read().contains(Flags::CF));
}

#[test]
fn test_rcl_no_carry() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // CF=0 and test RCL
    let code = vec![
        0xf8,                           // CLC (clear carry flag)
        0xb8, 0x01, 0x00, 0x00, 0x80,  // mov eax, 0x80000001
        0xd1, 0xd0,                     // rcl eax, 1
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();

    // 0x80000001 with CF=0:
    // Rotate left through carry: CF (0) becomes LSB, MSB goes to CF
    // Result: 0x00000002, CF=1
    assert_eq!(engine.reg_read(Register::EAX), 0x00000002);
    assert!(engine.flags_read().contains(Flags::CF));
}

#[test]
fn test_rcr_basic() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Set CF=1 and test RCR
    let code = vec![
        0xf9,                           // STC (set carry flag)
        0xb8, 0x01, 0x00, 0x00, 0x00,  // mov eax, 0x00000001
        0xd1, 0xd8,                     // rcr eax, 1
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();

    // 0x00000001 with CF=1:
    // Rotate right through carry: CF becomes MSB, LSB goes to CF
    // Result: 0x80000000, CF=1
    assert_eq!(engine.reg_read(Register::EAX), 0x80000000);
    assert!(engine.flags_read().contains(Flags::CF));
}

#[test]
fn test_rcr_no_carry() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // CF=0 and test RCR
    let code = vec![
        0xf8,                           // CLC (clear carry flag)
        0xb8, 0x01, 0x00, 0x00, 0x00,  // mov eax, 0x00000001
        0xd1, 0xd8,                     // rcr eax, 1
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();

    // 0x00000001 with CF=0:
    // Rotate right through carry: CF (0) becomes MSB, LSB goes to CF
    // Result: 0x00000000, CF=1
    assert_eq!(engine.reg_read(Register::EAX), 0x00000000);
    assert!(engine.flags_read().contains(Flags::CF));
}

#[test]
fn test_rcl_multi_bit() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Test RCL with count > 1
    let code = vec![
        0xf8,                           // CLC (clear carry flag)
        0xb8, 0x55, 0x00, 0x00, 0x00,  // mov eax, 0x00000055
        0xc1, 0xd0, 0x04,               // rcl eax, 4
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();

    // 0x00000055 rotated left by 4 through carry (CF=0)
    // Binary: 0101 0101 -> 0101 0101 0000 (but through 33-bit rotation)
    // The rotation is modulo 33 for 32-bit operand
    assert_eq!(engine.reg_read(Register::EAX), 0x00000550);
}

#[test]
fn test_rcr_multi_bit() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Test RCR with count > 1
    let code = vec![
        0xf8,                           // CLC (clear carry flag)
        0xb8, 0x00, 0x00, 0x00, 0xaa,  // mov eax, 0xaa000000
        0xc1, 0xd8, 0x04,               // rcr eax, 4
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();

    // 0xaa000000 rotated right by 4 through carry (CF=0)
    assert_eq!(engine.reg_read(Register::EAX), 0x0aa00000);
}

#[test]
fn test_rcl_16bit() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Test 16-bit RCL
    let code = vec![
        0xf9,                    // STC (set carry flag)
        0x66, 0xb8, 0x00, 0x80,  // mov ax, 0x8000
        0x66, 0xd1, 0xd0,        // rcl ax, 1
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();

    // 0x8000 with CF=1:
    // Rotate left through carry: CF becomes LSB, MSB goes to CF
    // Result: 0x0001, CF=1
    assert_eq!(engine.reg_read(Register::AX), 0x0001);
    assert!(engine.flags_read().contains(Flags::CF));
}

#[test]
fn test_rcr_8bit() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Test 8-bit RCR
    let code = vec![
        0xf9,           // STC (set carry flag)
        0xb0, 0x01,     // mov al, 0x01
        0xd0, 0xd8,     // rcr al, 1
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();

    // 0x01 with CF=1:
    // Rotate right through carry: CF becomes MSB, LSB goes to CF
    // Result: 0x80, CF=1
    assert_eq!(engine.reg_read(Register::AL), 0x80);
    assert!(engine.flags_read().contains(Flags::CF));
}

#[test]
fn test_rcl_with_register_count() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Test RCL with count in CL
    let code = vec![
        0xf8,                           // CLC
        0xb8, 0x01, 0x00, 0x00, 0x00,  // mov eax, 0x00000001
        0xb1, 0x02,                     // mov cl, 2
        0xd3, 0xd0,                     // rcl eax, cl
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();

    // 0x00000001 rotated left by 2 through carry
    assert_eq!(engine.reg_read(Register::EAX), 0x00000004);
}

#[test]
fn test_rcr_with_register_count() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Test RCR with count in CL
    let code = vec![
        0xf8,                           // CLC
        0xb8, 0x00, 0x00, 0x00, 0x80,  // mov eax, 0x80000000
        0xb1, 0x02,                     // mov cl, 2
        0xd3, 0xd8,                     // rcr eax, cl
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();

    // 0x80000000 rotated right by 2 through carry
    assert_eq!(engine.reg_read(Register::EAX), 0x20000000);
}