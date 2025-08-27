use remu64::{Engine, EngineMode, Register, Permission};
use remu64::memory::MemoryTrait;

#[test]
fn test_movsw() {
    let mut emu = Engine::new(EngineMode::Mode64);

    // Map memory
    emu.memory.map(0x1000, 0x2000, Permission::READ | Permission::WRITE | Permission::EXEC).unwrap();

    // Set up source string "Hello" (as words)
    emu.memory.write(0x1000, b"Hello World").unwrap();

    // Set RSI to source and RDI to destination
    emu.reg_write(Register::RSI, 0x1000);
    emu.reg_write(Register::RDI, 0x1500);
    emu.reg_write(Register::RCX, 5); // Copy 5 words (10 bytes)

    // REP MOVSW
    let code = b"\xF3\x66\xA5"; // REP MOVSW
    emu.memory.write(0x2000, code).unwrap();

    emu.emu_start(0x2000, 0x2000 + code.len() as u64, 0, 0).unwrap();

    // Check that the string was copied
    let mut buf = [0u8; 10];
    emu.memory.read(0x1500, &mut buf).unwrap();
    assert_eq!(&buf, b"Hello Worl");

    // Check that RSI and RDI were updated
    assert_eq!(emu.reg_read(Register::RSI), 0x100A); // +10 bytes
    assert_eq!(emu.reg_read(Register::RDI), 0x150A);
    assert_eq!(emu.reg_read(Register::RCX), 0);
}

#[test]
fn test_stosd() {
    let mut emu = Engine::new(EngineMode::Mode64);

    // Map memory
    emu.memory.map(0x1000, 0x2000, Permission::READ | Permission::WRITE | Permission::EXEC).unwrap();

    // Set EAX to value to store
    emu.reg_write(Register::RAX, 0x12345678);
    emu.reg_write(Register::RDI, 0x1000);
    emu.reg_write(Register::RCX, 4); // Store 4 dwords

    // REP STOSD
    let code = b"\xF3\xAB"; // REP STOSD
    emu.memory.write(0x2000, code).unwrap();

    emu.emu_start(0x2000, 0x2000 + code.len() as u64, 0, 0).unwrap();

    // Check that the dwords were stored
    for i in 0..4 {
        let value = emu.memory.read_u32(0x1000 + (i * 4) as u64).unwrap();
        assert_eq!(value, 0x12345678);
    }

    // Check that RDI was updated
    assert_eq!(emu.reg_read(Register::RDI), 0x1010); // +16 bytes
    assert_eq!(emu.reg_read(Register::RCX), 0);
}

#[test]
fn test_scasw() {
    let mut emu = Engine::new(EngineMode::Mode64);

    // Map memory
    emu.memory.map(0x1000, 0x2000, Permission::READ | Permission::WRITE | Permission::EXEC).unwrap();

    // Set up array of words
    let data = [0x1111u16, 0x2222, 0x3333, 0x4444, 0x5555];
    for (i, &word) in data.iter().enumerate() {
        emu.memory.write_u16(0x1000 + (i * 2) as u64, word).unwrap();
    }

    // Set AX to value to scan for
    emu.reg_write(Register::RAX, 0x3333);
    emu.reg_write(Register::RDI, 0x1000);
    emu.reg_write(Register::RCX, 5); // Scan max 5 words

    // REPNE SCASW - scan until equal
    let code = b"\xF2\x66\xAF"; // REPNE SCASW
    emu.memory.write(0x2000, code).unwrap();

    emu.emu_start(0x2000, 0x2000 + code.len() as u64, 0, 0).unwrap();

    // Should stop at third word
    assert_eq!(emu.reg_read(Register::RDI), 0x1006); // After 3rd word
    assert_eq!(emu.reg_read(Register::RCX), 2); // 5 - 3 = 2 remaining
}

#[test]
fn test_cmpsq() {
    let mut emu = Engine::new(EngineMode::Mode64);

    // Map memory
    emu.memory.map(0x1000, 0x2000, Permission::READ | Permission::WRITE | Permission::EXEC).unwrap();

    // Set up two arrays
    let src = [0x1111111111111111u64, 0x2222222222222222, 0x3333333333333333];
    let dst = [0x1111111111111111u64, 0x2222222222222222, 0x4444444444444444];

    for (i, &qword) in src.iter().enumerate() {
        emu.memory.write_u64(0x1000 + (i * 8) as u64, qword).unwrap();
    }
    for (i, &qword) in dst.iter().enumerate() {
        emu.memory.write_u64(0x1500 + (i * 8) as u64, qword).unwrap();
    }

    emu.reg_write(Register::RSI, 0x1000);
    emu.reg_write(Register::RDI, 0x1500);
    emu.reg_write(Register::RCX, 3);

    // REPE CMPSQ - compare while equal
    let code = b"\xF3\x48\xA7"; // REPE CMPSQ
    emu.memory.write(0x2000, code).unwrap();

    emu.emu_start(0x2000, 0x2000 + code.len() as u64, 0, 0).unwrap();

    // Should stop at third qword (different)
    assert_eq!(emu.reg_read(Register::RSI), 0x1018); // After 3rd qword
    assert_eq!(emu.reg_read(Register::RDI), 0x1518);
    assert_eq!(emu.reg_read(Register::RCX), 0);
}

#[test]
fn test_bswap() {
    let mut emu = Engine::new(EngineMode::Mode64);

    // Map memory
    emu.memory.map(0x1000, 0x2000, Permission::READ | Permission::WRITE | Permission::EXEC).unwrap();

    // Test 32-bit BSWAP
    emu.reg_write(Register::RAX, 0x12345678);
    
    let code = b"\x0F\xC8"; // BSWAP EAX
    emu.memory.write(0x2000, code).unwrap();
    
    emu.emu_start(0x2000, 0x2000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(emu.reg_read(Register::RAX) as u32, 0x78563412);

    // Test 64-bit BSWAP
    emu.reg_write(Register::RBX, 0x123456789ABCDEF0);
    
    let code = b"\x48\x0F\xCB"; // BSWAP RBX
    emu.memory.write(0x2000, code).unwrap();
    
    emu.emu_start(0x2000, 0x2000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(emu.reg_read(Register::RBX), 0xF0DEBC9A78563412);
}

#[test]
fn test_direction_flag() {
    let mut emu = Engine::new(EngineMode::Mode64);

    // Map memory
    emu.memory.map(0x1000, 0x2000, Permission::READ | Permission::WRITE | Permission::EXEC).unwrap();

    // Test STD (Set Direction Flag)
    let code = b"\xFD"; // STD
    emu.memory.write(0x2000, code).unwrap();
    emu.emu_start(0x2000, 0x2000 + code.len() as u64, 0, 0).unwrap();
    
    assert!(emu.flags_read().contains(remu64::Flags::DF));

    // Test CLD (Clear Direction Flag)  
    let code = b"\xFC"; // CLD
    emu.memory.write(0x2000, code).unwrap();
    emu.emu_start(0x2000, 0x2000 + code.len() as u64, 0, 0).unwrap();
    
    assert!(!emu.flags_read().contains(remu64::Flags::DF));

    // Test MOVSB with direction flag set (backwards)
    emu.memory.write(0x1000, b"ABCD").unwrap();
    emu.reg_write(Register::RSI, 0x1003); // Point to 'D'
    emu.reg_write(Register::RDI, 0x1503); // Destination
    emu.reg_write(Register::RCX, 4);

    // Set direction flag and do REP MOVSB
    let code = b"\xFD\xF3\xA4"; // STD; REP MOVSB
    emu.memory.write(0x2000, code).unwrap();
    emu.emu_start(0x2000, 0x2000 + code.len() as u64, 0, 0).unwrap();

    // Check that string was copied backwards
    let mut buf = [0u8; 4];
    emu.memory.read(0x1500, &mut buf).unwrap();
    assert_eq!(&buf, b"DCBA");
}