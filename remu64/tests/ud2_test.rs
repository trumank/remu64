use remu64::{EmulatorError, Engine, EngineMode, Permission, Register, memory::MemoryTrait};

#[test]
fn test_ud2_raises_exception() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    let code = vec![
        // Set up some state to verify it doesn't change
        0x48, 0xb8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, // mov rax, 0x8877665544332211
        // Execute UD2 instruction
        0x0F, 0x0B, // ud2
        // This should never execute
        0x48, 0xb9, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
        0x11, // mov rcx, 0x1100FFEEDDCCBBAA
    ];

    engine.memory.write(0x1000, &code).unwrap();

    // Execute instructions - should fail at UD2
    let result = engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0);

    // Verify that execution failed with InvalidOpcode error
    assert!(result.is_err());
    match result.unwrap_err() {
        EmulatorError::InvalidOpcode => {}
        other => panic!("Expected InvalidOpcode error, got: {:?}", other),
    }

    // Verify that RAX was set before UD2
    assert_eq!(engine.reg_read(Register::RAX), 0x8877665544332211);

    // Verify that RCX was not set (instruction after UD2 didn't execute)
    assert_eq!(engine.reg_read(Register::RCX), 0);
}

#[test]
fn test_ud2_stops_execution() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    engine.memory.map(0x2000, 0x1000, Permission::ALL).unwrap();

    // Write a counter value to memory
    engine.memory.write(0x2000, &[0x00]).unwrap();

    let code = vec![
        // Increment counter
        0x48, 0xb8, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0x2000
        0xfe, 0x00, // inc byte [rax]
        // UD2 - should stop execution here
        0x0F, 0x0B, // ud2
        // This should never execute
        0xfe, 0x00, // inc byte [rax]
        0xfe, 0x00, // inc byte [rax]
    ];

    engine.memory.write(0x1000, &code).unwrap();

    // Execute instructions
    let result = engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0);

    // Verify execution failed
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), EmulatorError::InvalidOpcode));

    // Check that counter was only incremented once (before UD2)
    let mut counter = vec![0u8; 1];
    engine.memory.read(0x2000, &mut counter).unwrap();
    assert_eq!(
        counter[0], 1,
        "Counter should be 1 (only incremented before UD2)"
    );
}

#[test]
fn test_ud2_preserves_state() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    let code = vec![
        // Set up various registers
        0x48, 0xb8, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, // mov rax, 0x1111111111111111
        0x48, 0xbb, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x22, // mov rbx, 0x2222222222222222
        0x48, 0xb9, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
        0x33, // mov rcx, 0x3333333333333333
        0x48, 0xba, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
        0x44, // mov rdx, 0x4444444444444444
        // UD2
        0x0F, 0x0B, // ud2
    ];

    engine.memory.write(0x1000, &code).unwrap();

    // Execute instructions
    let result = engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0);

    // Verify execution failed
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), EmulatorError::InvalidOpcode));

    // Verify all registers were set correctly before UD2
    assert_eq!(engine.reg_read(Register::RAX), 0x1111111111111111);
    assert_eq!(engine.reg_read(Register::RBX), 0x2222222222222222);
    assert_eq!(engine.reg_read(Register::RCX), 0x3333333333333333);
    assert_eq!(engine.reg_read(Register::RDX), 0x4444444444444444);
}
