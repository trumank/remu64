use amd64_emu::{cpu::Register, memory::Permission, Engine, EngineMode};

#[test]
fn test_movs_byte() {
    let mut emu = Engine::new(EngineMode::Mode64);

    // Map memory
    emu.mem_map(0x1000, 0x2000, Permission::all()).unwrap();

    // Write source data
    emu.mem_write(0x1500, b"Hello").unwrap();

    // Set up registers
    emu.reg_write(Register::RSI, 0x1500).unwrap();
    emu.reg_write(Register::RDI, 0x1600).unwrap();

    // MOVS BYTE instruction
    let code = vec![0xA4]; // MOVSB
    emu.mem_write(0x1000, &code).unwrap();

    emu.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0, None)
        .unwrap();

    // Check that byte was copied
    let mut buf = vec![0u8; 1];
    emu.mem_read(0x1600, &mut buf).unwrap();
    assert_eq!(buf[0], b'H');

    // Check RSI and RDI were incremented
    assert_eq!(emu.reg_read(Register::RSI).unwrap(), 0x1501);
    assert_eq!(emu.reg_read(Register::RDI).unwrap(), 0x1601);
}

#[test]
fn test_rep_movs() {
    let mut emu = Engine::new(EngineMode::Mode64);

    // Map memory
    emu.mem_map(0x1000, 0x2000, Permission::all()).unwrap();

    // Write source data
    emu.mem_write(0x1500, b"Hello, World!").unwrap();

    // Set up registers
    emu.reg_write(Register::RSI, 0x1500).unwrap();
    emu.reg_write(Register::RDI, 0x1600).unwrap();
    emu.reg_write(Register::RCX, 13).unwrap(); // Length of "Hello, World!"

    // REP MOVS BYTE instruction
    let code = vec![0xF3, 0xA4]; // REP MOVSB
    emu.mem_write(0x1000, &code).unwrap();

    emu.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0, None)
        .unwrap();

    // Check that string was copied
    let mut buf = vec![0u8; 13];
    emu.mem_read(0x1600, &mut buf).unwrap();
    assert_eq!(&buf, b"Hello, World!");

    // Check RCX is 0
    assert_eq!(emu.reg_read(Register::RCX).unwrap(), 0);

    // Check RSI and RDI were updated
    assert_eq!(emu.reg_read(Register::RSI).unwrap(), 0x150D);
    assert_eq!(emu.reg_read(Register::RDI).unwrap(), 0x160D);
}

#[test]
fn test_stos_byte() {
    let mut emu = Engine::new(EngineMode::Mode64);

    // Map memory
    emu.mem_map(0x1000, 0x2000, Permission::all()).unwrap();

    // Set up registers
    emu.reg_write(Register::AL, 0x41).unwrap(); // 'A'
    emu.reg_write(Register::RDI, 0x1500).unwrap();

    // STOS BYTE instruction
    let code = vec![0xAA]; // STOSB
    emu.mem_write(0x1000, &code).unwrap();

    emu.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0, None)
        .unwrap();

    // Check that byte was stored
    let mut buf = vec![0u8; 1];
    emu.mem_read(0x1500, &mut buf).unwrap();
    assert_eq!(buf[0], 0x41);

    // Check RDI was incremented
    assert_eq!(emu.reg_read(Register::RDI).unwrap(), 0x1501);
}

#[test]
fn test_rep_stos() {
    let mut emu = Engine::new(EngineMode::Mode64);

    // Map memory
    emu.mem_map(0x1000, 0x2000, Permission::all()).unwrap();

    // Set up registers
    emu.reg_write(Register::AL, 0x00).unwrap(); // Fill with zeros
    emu.reg_write(Register::RDI, 0x1500).unwrap();
    emu.reg_write(Register::RCX, 16).unwrap(); // Fill 16 bytes

    // Write non-zero data first
    emu.mem_write(0x1500, b"XXXXXXXXXXXXXXXX").unwrap();

    // REP STOS BYTE instruction
    let code = vec![0xF3, 0xAA]; // REP STOSB
    emu.mem_write(0x1000, &code).unwrap();

    emu.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0, None)
        .unwrap();

    // Check that memory was zeroed
    let mut buf = vec![0u8; 16];
    emu.mem_read(0x1500, &mut buf).unwrap();
    assert_eq!(buf, vec![0u8; 16]);

    // Check RCX is 0
    assert_eq!(emu.reg_read(Register::RCX).unwrap(), 0);

    // Check RDI was updated
    assert_eq!(emu.reg_read(Register::RDI).unwrap(), 0x1510);
}

#[test]
fn test_lods_byte() {
    let mut emu = Engine::new(EngineMode::Mode64);

    // Map memory
    emu.mem_map(0x1000, 0x2000, Permission::all()).unwrap();

    // Write source data
    emu.mem_write(0x1500, b"Z").unwrap();

    // Set up registers
    emu.reg_write(Register::RSI, 0x1500).unwrap();
    emu.reg_write(Register::AL, 0).unwrap(); // Clear AL

    // LODS BYTE instruction
    let code = vec![0xAC]; // LODSB
    emu.mem_write(0x1000, &code).unwrap();

    emu.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0, None)
        .unwrap();

    // Check that byte was loaded into AL
    assert_eq!(emu.reg_read(Register::AL).unwrap(), b'Z' as u64);

    // Check RSI was incremented
    assert_eq!(emu.reg_read(Register::RSI).unwrap(), 0x1501);
}

#[test]
fn test_scas_byte() {
    let mut emu = Engine::new(EngineMode::Mode64);

    // Map memory
    emu.mem_map(0x1000, 0x2000, Permission::all()).unwrap();

    // Write data to scan
    emu.mem_write(0x1500, b"Hello").unwrap();

    // Set up registers
    emu.reg_write(Register::AL, b'e' as u64).unwrap();
    emu.reg_write(Register::RDI, 0x1501).unwrap(); // Point to 'e'

    // SCAS BYTE instruction
    let code = vec![0xAE]; // SCASB
    emu.mem_write(0x1000, &code).unwrap();

    emu.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0, None)
        .unwrap();

    // Check that ZF is set (match found)
    let flags = emu.reg_read(Register::RFLAGS).unwrap();
    assert!((flags & (1 << 6)) != 0); // ZF is bit 6

    // Check RDI was incremented
    assert_eq!(emu.reg_read(Register::RDI).unwrap(), 0x1502);
}

#[test]
fn test_repz_scas() {
    let mut emu = Engine::new(EngineMode::Mode64);

    // Map memory
    emu.mem_map(0x1000, 0x2000, Permission::all()).unwrap();

    // Write data to scan (all 'A's then a 'B')
    emu.mem_write(0x1500, b"AAAAAB").unwrap();

    // Set up registers
    emu.reg_write(Register::AL, b'A' as u64).unwrap();
    emu.reg_write(Register::RDI, 0x1500).unwrap();
    emu.reg_write(Register::RCX, 6).unwrap(); // Scan 6 bytes

    // REPZ SCAS BYTE instruction - scan while equal
    let code = vec![0xF3, 0xAE]; // REPZ SCASB
    emu.mem_write(0x1000, &code).unwrap();

    emu.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0, None)
        .unwrap();

    // Check that scan stopped at 'B'
    assert_eq!(emu.reg_read(Register::RDI).unwrap(), 0x1506);
    assert_eq!(emu.reg_read(Register::RCX).unwrap(), 0);

    // ZF should be clear (not equal)
    let flags = emu.reg_read(Register::RFLAGS).unwrap();
    assert!((flags & (1 << 6)) == 0); // ZF is bit 6
}

#[test]
fn test_cmps_byte() {
    let mut emu = Engine::new(EngineMode::Mode64);

    // Map memory
    emu.mem_map(0x1000, 0x2000, Permission::all()).unwrap();

    // Write data to compare
    emu.mem_write(0x1500, b"AB").unwrap();
    emu.mem_write(0x1600, b"AC").unwrap();

    // Set up registers
    emu.reg_write(Register::RSI, 0x1501).unwrap(); // Point to 'B'
    emu.reg_write(Register::RDI, 0x1601).unwrap(); // Point to 'C'

    // CMPS BYTE instruction
    let code = vec![0xA6]; // CMPSB
    emu.mem_write(0x1000, &code).unwrap();

    emu.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0, None)
        .unwrap();

    // Check that ZF is clear (not equal) and CF is set (B < C)
    let flags = emu.reg_read(Register::RFLAGS).unwrap();
    assert!((flags & (1 << 6)) == 0); // ZF is bit 6
    assert!((flags & (1 << 0)) != 0); // CF is bit 0

    // Check RSI and RDI were incremented
    assert_eq!(emu.reg_read(Register::RSI).unwrap(), 0x1502);
    assert_eq!(emu.reg_read(Register::RDI).unwrap(), 0x1602);
}

#[test]
fn test_repz_cmps() {
    let mut emu = Engine::new(EngineMode::Mode64);

    // Map memory
    emu.mem_map(0x1000, 0x2000, Permission::all()).unwrap();

    // Write strings to compare
    emu.mem_write(0x1500, b"Hello").unwrap();
    emu.mem_write(0x1600, b"HeLLo").unwrap(); // Different at position 2

    // Set up registers
    emu.reg_write(Register::RSI, 0x1500).unwrap();
    emu.reg_write(Register::RDI, 0x1600).unwrap();
    emu.reg_write(Register::RCX, 5).unwrap();

    // REPZ CMPS BYTE instruction - compare while equal
    let code = vec![0xF3, 0xA6]; // REPZ CMPSB
    emu.mem_write(0x1000, &code).unwrap();

    emu.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0, None)
        .unwrap();

    // Check that comparison stopped at the difference
    assert_eq!(emu.reg_read(Register::RSI).unwrap(), 0x1503); // Position 3
    assert_eq!(emu.reg_read(Register::RDI).unwrap(), 0x1603);
    assert_eq!(emu.reg_read(Register::RCX).unwrap(), 2); // 2 bytes remaining

    // ZF should be clear (not equal)
    let flags = emu.reg_read(Register::RFLAGS).unwrap();
    assert!((flags & (1 << 6)) == 0); // ZF is bit 6
}
