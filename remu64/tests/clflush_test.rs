use remu64::{Engine, EngineMode, Permission, Register, memory::MemoryTrait};

#[test]
fn test_clflush_basic() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code and data
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    engine
        .memory
        .map(0x2000, 0x1000, Permission::READ | Permission::WRITE)
        .unwrap();

    // Write some data to memory
    let data1: u64 = 0xDEADBEEF12345678;
    let data2: u64 = 0xCAFEBABE87654321;
    engine.memory.write(0x2000, &data1.to_le_bytes()).unwrap();
    engine.memory.write(0x2080, &data2.to_le_bytes()).unwrap(); // Different cache line (128-byte boundary)

    // Test CLFLUSH with direct addressing: clflush [0x2000]
    let code = vec![
        0x0F, 0xAE, 0x3C, 0x25, 0x00, 0x20, 0x00, 0x00, // clflush [0x2000]
        0x90, // nop
    ];

    engine.memory.write(0x1000, &code).unwrap();

    // Execute the instruction
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Verify memory is still intact (CLFLUSH doesn't modify memory)
    let mut buf1 = [0u8; 8];
    let mut buf2 = [0u8; 8];
    engine.memory.read(0x2000, &mut buf1).unwrap();
    engine.memory.read(0x2080, &mut buf2).unwrap();
    assert_eq!(u64::from_le_bytes(buf1), 0xDEADBEEF12345678);
    assert_eq!(u64::from_le_bytes(buf2), 0xCAFEBABE87654321);
}

#[test]
fn test_clflush_register_indirect() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    engine
        .memory
        .map(0x2000, 0x1000, Permission::READ | Permission::WRITE)
        .unwrap();

    // Write test data
    let data: u64 = 0x1234567890ABCDEF;
    engine.memory.write(0x2800, &data.to_le_bytes()).unwrap();

    // Set up registers
    engine.reg_write(Register::RAX, 0x2800); // Point to data

    // Test CLFLUSH with register indirect: clflush [rax]
    let code = vec![
        0x0F, 0xAE, 0x38, // clflush [rax]
        0x90, // nop
    ];

    engine.memory.write(0x1000, &code).unwrap();

    // Execute
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Verify data is still intact
    let mut buf = [0u8; 8];
    engine.memory.read(0x2800, &mut buf).unwrap();
    assert_eq!(u64::from_le_bytes(buf), 0x1234567890ABCDEF);
}

#[test]
fn test_clflush_base_plus_displacement() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    engine
        .memory
        .map(0x2000, 0x1000, Permission::READ | Permission::WRITE)
        .unwrap();

    // Write test data
    let data: u64 = 0xFEDCBA0987654321;
    engine.memory.write(0x2010, &data.to_le_bytes()).unwrap();

    // Set up registers
    engine.reg_write(Register::RBX, 0x2000); // Base address

    // Test CLFLUSH with base+displacement: clflush [rbx+0x10]
    let code = vec![
        0x0F, 0xAE, 0x7B, 0x10, // clflush [rbx+0x10]
        0x90, // nop
    ];

    engine.memory.write(0x1000, &code).unwrap();

    // Execute
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Verify data is intact
    let mut buf = [0u8; 8];
    engine.memory.read(0x2010, &mut buf).unwrap();
    assert_eq!(u64::from_le_bytes(buf), 0xFEDCBA0987654321);
}

#[test]
fn test_clflush_with_scale() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    engine
        .memory
        .map(0x2000, 0x1000, Permission::READ | Permission::WRITE)
        .unwrap();

    // Write test data
    let data: u64 = 0xAAAABBBBCCCCDDDD;
    engine.memory.write(0x2020, &data.to_le_bytes()).unwrap();

    // Set up registers
    engine.reg_write(Register::RBX, 0x2000); // Base
    engine.reg_write(Register::RSI, 4); // Index (4 * 8 = 0x20)

    // Test CLFLUSH with SIB byte: clflush [rbx+rsi*8]
    let code = vec![
        0x0F, 0xAE, 0x3C, 0xF3, // clflush [rbx+rsi*8]
        0x90, // nop
    ];

    engine.memory.write(0x1000, &code).unwrap();

    // Execute
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Verify the data is intact
    let mut buf = [0u8; 8];
    engine.memory.read(0x2020, &mut buf).unwrap();
    assert_eq!(u64::from_le_bytes(buf), 0xAAAABBBBCCCCDDDD);
}

#[test]
fn test_clflushopt() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    engine
        .memory
        .map(0x2000, 0x1000, Permission::READ | Permission::WRITE)
        .unwrap();

    // Write test data
    let data: u64 = 0x1111222233334444;
    engine.memory.write(0x2500, &data.to_le_bytes()).unwrap();

    engine.reg_write(Register::RAX, 0x2500);

    // Test CLFLUSHOPT (prefix 66 0F AE /7)
    let code = vec![
        0x66, 0x0F, 0xAE, 0x38, // clflushopt [rax]
        0x90, // nop
    ];

    engine.memory.write(0x1000, &code).unwrap();

    // Execute
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Verify data is intact (CLFLUSHOPT is also a no-op for emulation)
    let mut buf = [0u8; 8];
    engine.memory.read(0x2500, &mut buf).unwrap();
    assert_eq!(u64::from_le_bytes(buf), 0x1111222233334444);
}
