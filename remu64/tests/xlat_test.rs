use remu64::{Engine, EngineMode, Permission, Register, memory::MemoryTrait};

#[test]
fn test_xlat_basic() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code and data
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    engine.memory.map(0x2000, 0x1000, Permission::ALL).unwrap();

    let code = vec![
        // Create a lookup table in memory starting at address 0x2000
        // Set up RBX to point to the table
        0x48, 0xbb, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rbx, 0x2000
        // Set AL to 3 (index into the table)
        0xb0, 0x03, // mov al, 3
        // Perform XLAT
        0xd7, // xlatb
    ];

    engine.memory.write(0x1000, &code).unwrap();

    // Create a lookup table with some test values
    let table = vec![0x10, 0x20, 0x30, 0x40, 0x50]; // Table at 0x2000
    engine.memory.write(0x2000, &table).unwrap();

    // Execute instructions
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // AL should now contain the value at table[3] which is 0x40
    assert_eq!(engine.reg_read(Register::AL), 0x40);
}

#[test]
fn test_xlat_zero_index() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code and data
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    engine.memory.map(0x2000, 0x1000, Permission::ALL).unwrap();

    let code = vec![
        // Set up RBX to point to the table at 0x2000
        0x48, 0xbb, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rbx, 0x2000
        // Set AL to 0 (first index)
        0xb0, 0x00, // mov al, 0
        // Perform XLAT
        0xd7, // xlatb
    ];

    engine.memory.write(0x1000, &code).unwrap();

    // Create a lookup table
    let table = vec![0xAA, 0xBB, 0xCC, 0xDD];
    engine.memory.write(0x2000, &table).unwrap();

    // Execute instructions
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // AL should contain the value at table[0] which is 0xAA
    assert_eq!(engine.reg_read(Register::AL), 0xAA);
}

#[test]
fn test_xlat_max_index() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code and data
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    engine.memory.map(0x2000, 0x1000, Permission::ALL).unwrap();

    let code = vec![
        // Set up RBX to point to the table at 0x2000
        0x48, 0xbb, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rbx, 0x2000
        // Set AL to 255 (max index)
        0xb0, 0xFF, // mov al, 0xFF
        // Perform XLAT
        0xd7, // xlatb
    ];

    engine.memory.write(0x1000, &code).unwrap();

    // Create a full 256-byte lookup table
    let mut table = vec![0u8; 256];
    for i in 0..256 {
        table[i] = (i as u8).wrapping_mul(2); // Each entry is index * 2
    }

    engine.memory.write(0x2000, &table).unwrap();

    // Execute instructions
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // AL should contain the value at table[255] which is 255 * 2 = 254 (with wrapping)
    assert_eq!(engine.reg_read(Register::AL), 254);
}

#[test]
fn test_xlat_preserves_other_registers() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code and data
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    engine.memory.map(0x2000, 0x1000, Permission::ALL).unwrap();

    let code = vec![
        // Set up various registers
        0x48, 0xb8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, // mov rax, 0x8877665544332211
        0x48, 0xbb, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rbx, 0x2000
        0x48, 0xb9, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
        0x11, // mov rcx, 0x1100FFEEDDCCBBAA
        // Set AL to 5
        0xb0, 0x05, // mov al, 5
        // Perform XLAT
        0xd7, // xlatb
    ];

    engine.memory.write(0x1000, &code).unwrap();

    // Create a lookup table
    let table = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x99, 0x66, 0x77];
    engine.memory.write(0x2000, &table).unwrap();

    // Execute instructions
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Check that AL was updated but other parts of RAX preserved
    assert_eq!(engine.reg_read(Register::AL), 0x99); // table[5]
    assert_eq!(engine.reg_read(Register::AH), 0x22); // Should be preserved from original RAX (0x22 is at AH position)

    // Check that other registers are unchanged
    assert_eq!(engine.reg_read(Register::RBX), 0x2000);
    assert_eq!(engine.reg_read(Register::RCX), 0x1100FFEEDDCCBBAA);
}
