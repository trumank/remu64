use remu64::{Engine, EngineMode, Permission, Register, memory::MemoryTrait};

#[test]
fn test_pause_basic() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    let code = vec![
        // Set up some registers to ensure they aren't changed
        0x48, 0xb8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, // mov rax, 0x8877665544332211
        0x48, 0xb9, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
        0x11, // mov rcx, 0x1100FFEEDDCCBBAA
        // Execute PAUSE instruction
        0xF3, 0x90, // pause (rep nop)
        // Continue with more instructions to ensure execution continues
        0x48, 0xba, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE,
        0xF0, // mov rdx, 0xF0DEBC9A78563412
    ];

    engine.memory.write(0x1000, &code).unwrap();

    // Execute instructions
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Verify that all registers have expected values and PAUSE didn't affect them
    assert_eq!(engine.reg_read(Register::RAX), 0x8877665544332211);
    assert_eq!(engine.reg_read(Register::RCX), 0x1100FFEEDDCCBBAA);
    assert_eq!(engine.reg_read(Register::RDX), 0xF0DEBC9A78563412);
}

#[test]
fn test_pause_doesnt_affect_arithmetic() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    let code = vec![
        // Set up initial values
        0x48, 0xc7, 0xc0, 0x05, 0x00, 0x00, 0x00, // mov rax, 5
        0x48, 0xc7, 0xc3, 0x03, 0x00, 0x00, 0x00, // mov rbx, 3
        // Perform arithmetic
        0x48, 0x01, 0xd8, // add rax, rbx (rax = 8)
        // Execute PAUSE instruction
        0xF3, 0x90, // pause
        // Continue with more arithmetic
        0x48, 0x01, 0xd8, // add rax, rbx (rax = 11)
    ];

    engine.memory.write(0x1000, &code).unwrap();

    // Execute instructions
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Verify that arithmetic worked correctly with PAUSE in the middle
    assert_eq!(engine.reg_read(Register::RAX), 11);
    assert_eq!(engine.reg_read(Register::RBX), 3);
}

#[test]
fn test_pause_in_spinloop() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code and data
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    engine.memory.map(0x2000, 0x1000, Permission::ALL).unwrap();

    // Write initial value to memory location (non-zero to enter loop)
    engine.memory.write(0x2000, &[0x01]).unwrap();

    let code = vec![
        // Simulated spin-wait loop with PAUSE
        // spin_loop:
        0x48, 0xb8, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0x2000
        0x8a, 0x18, // mov bl, [rax]
        0x84, 0xdb, // test bl, bl
        0x74, 0x08, // jz exit_loop
        // In the loop: execute PAUSE and decrement counter
        0xF3, 0x90, // pause
        0xfe, 0xcb, // dec bl
        0x88, 0x18, // mov [rax], bl
        0xeb, 0xf0, // jmp spin_loop (-16 bytes)
        // exit_loop:
        0x48, 0xc7, 0xc0, 0xAB, 0xCD, 0xEF, 0x00, // mov rax, 0xEFCDAB
    ];

    engine.memory.write(0x1000, &code).unwrap();

    // Execute instructions
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Verify that we exited the loop correctly
    assert_eq!(engine.reg_read(Register::RAX), 0xEFCDAB);

    // Verify counter reached 0
    let mut counter = vec![0u8; 1];
    engine.memory.read(0x2000, &mut counter).unwrap();
    assert_eq!(counter[0], 0);
}
