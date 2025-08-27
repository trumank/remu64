use remu64::{memory::MemoryTrait as _, Engine, EngineMode, Permission, Register};

#[test]
fn test_pmovsxbw() {
    let mut emu = Engine::new(EngineMode::Mode64);

    // Test PMOVSXBW - sign extend bytes to words
    let code = vec![
        // movdqa xmm0, [rsp]
        0x66, 0x0F, 0x6F, 0x04, 0x24, // pmovsxbw xmm1, xmm0
        0x66, 0x0F, 0x38, 0x20, 0xC8,
    ];

    emu.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    emu.memory.map(0x100000, 0x1000, Permission::ALL).unwrap();
    emu.memory.write(0x1000, &code).unwrap();
    emu.reg_write(Register::RIP, 0x1000);
    emu.reg_write(Register::RSP, 0x100400);

    // Test data: mix of positive and negative bytes
    let test_data = vec![
        0x7F, // 127
        0x80, // -128
        0x01, // 1
        0xFF, // -1
        0x40, // 64
        0xC0, // -64
        0x00, // 0
        0xF0, // -16
    ];

    emu.memory.write(0x100400, &test_data).unwrap();

    emu.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 10)
        .unwrap();

    let result = emu.xmm_read(Register::XMM1);

    // Check each word - sign extended
    assert_eq!((result & 0xFFFF) as i16, 127i16);
    assert_eq!(((result >> 16) & 0xFFFF) as i16, -128i16);
    assert_eq!(((result >> 32) & 0xFFFF) as i16, 1i16);
    assert_eq!(((result >> 48) & 0xFFFF) as i16, -1i16);
    assert_eq!(((result >> 64) & 0xFFFF) as i16, 64i16);
    assert_eq!(((result >> 80) & 0xFFFF) as i16, -64i16);
    assert_eq!(((result >> 96) & 0xFFFF) as i16, 0i16);
    assert_eq!(((result >> 112) & 0xFFFF) as i16, -16i16);
}

#[test]
fn test_pmovsxbd() {
    let mut emu = Engine::new(EngineMode::Mode64);

    // Test PMOVSXBD - sign extend bytes to doublewords
    let code = vec![
        // movdqa xmm0, [rsp]
        0x66, 0x0F, 0x6F, 0x04, 0x24, // pmovsxbd xmm1, xmm0
        0x66, 0x0F, 0x38, 0x21, 0xC8,
    ];

    emu.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    emu.memory.map(0x100000, 0x1000, Permission::ALL).unwrap();
    emu.memory.write(0x1000, &code).unwrap();
    emu.reg_write(Register::RIP, 0x1000);
    emu.reg_write(Register::RSP, 0x100400);

    // Test data: 4 bytes to extend
    let test_data = vec![
        0x7F, // 127
        0x80, // -128
        0x01, // 1
        0xFF, // -1
    ];

    emu.memory.write(0x100400, &test_data).unwrap();

    emu.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 10)
        .unwrap();

    let result = emu.xmm_read(Register::XMM1);

    // Check each doubleword - sign extended
    assert_eq!((result & 0xFFFFFFFF) as i32, 127i32);
    assert_eq!(((result >> 32) & 0xFFFFFFFF) as i32, -128i32);
    assert_eq!(((result >> 64) & 0xFFFFFFFF) as i32, 1i32);
    assert_eq!(((result >> 96) & 0xFFFFFFFF) as i32, -1i32);
}

#[test]
fn test_pmovsxbq() {
    let mut emu = Engine::new(EngineMode::Mode64);

    // Test PMOVSXBQ - sign extend bytes to quadwords
    let code = vec![
        // movdqa xmm0, [rsp]
        0x66, 0x0F, 0x6F, 0x04, 0x24, // pmovsxbq xmm1, xmm0
        0x66, 0x0F, 0x38, 0x22, 0xC8,
    ];

    emu.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    emu.memory.map(0x100000, 0x1000, Permission::ALL).unwrap();
    emu.memory.write(0x1000, &code).unwrap();
    emu.reg_write(Register::RIP, 0x1000);
    emu.reg_write(Register::RSP, 0x100400);

    // Test data: 2 bytes to extend
    let test_data = vec![
        0x7F, // 127
        0x80, // -128
    ];

    emu.memory.write(0x100400, &test_data).unwrap();

    emu.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 10)
        .unwrap();

    let result = emu.xmm_read(Register::XMM1);

    // Check each quadword - sign extended
    assert_eq!((result & 0xFFFFFFFFFFFFFFFF) as i64, 127i64);
    assert_eq!(((result >> 64) & 0xFFFFFFFFFFFFFFFF) as i64, -128i64);
}

#[test]
fn test_pmovsxwd() {
    let mut emu = Engine::new(EngineMode::Mode64);

    // Test PMOVSXWD - sign extend words to doublewords
    let code = vec![
        // movdqa xmm0, [rsp]
        0x66, 0x0F, 0x6F, 0x04, 0x24, // pmovsxwd xmm1, xmm0
        0x66, 0x0F, 0x38, 0x23, 0xC8,
    ];

    emu.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    emu.memory.map(0x100000, 0x1000, Permission::ALL).unwrap();
    emu.memory.write(0x1000, &code).unwrap();
    emu.reg_write(Register::RIP, 0x1000);
    emu.reg_write(Register::RSP, 0x100400);

    // Test data: 4 words to extend
    let test_data = vec![
        0xFF, 0x7F, // 32767
        0x00, 0x80, // -32768
        0x01, 0x00, // 1
        0xFF, 0xFF, // -1
    ];

    emu.memory.write(0x100400, &test_data).unwrap();

    emu.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 10)
        .unwrap();

    let result = emu.xmm_read(Register::XMM1);

    // Check each doubleword - sign extended
    assert_eq!((result & 0xFFFFFFFF) as i32, 32767i32);
    assert_eq!(((result >> 32) & 0xFFFFFFFF) as i32, -32768i32);
    assert_eq!(((result >> 64) & 0xFFFFFFFF) as i32, 1i32);
    assert_eq!(((result >> 96) & 0xFFFFFFFF) as i32, -1i32);
}

#[test]
fn test_pmovsxwq() {
    let mut emu = Engine::new(EngineMode::Mode64);

    // Test PMOVSXWQ - sign extend words to quadwords
    let code = vec![
        // movdqa xmm0, [rsp]
        0x66, 0x0F, 0x6F, 0x04, 0x24, // pmovsxwq xmm1, xmm0
        0x66, 0x0F, 0x38, 0x24, 0xC8,
    ];

    emu.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    emu.memory.map(0x100000, 0x1000, Permission::ALL).unwrap();
    emu.memory.write(0x1000, &code).unwrap();
    emu.reg_write(Register::RIP, 0x1000);
    emu.reg_write(Register::RSP, 0x100400);

    // Test data: 2 words to extend
    let test_data = vec![
        0xFF, 0x7F, // 32767
        0x00, 0x80, // -32768
    ];

    emu.memory.write(0x100400, &test_data).unwrap();

    emu.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 10)
        .unwrap();

    let result = emu.xmm_read(Register::XMM1);

    // Check each quadword - sign extended
    assert_eq!((result & 0xFFFFFFFFFFFFFFFF) as i64, 32767i64);
    assert_eq!(((result >> 64) & 0xFFFFFFFFFFFFFFFF) as i64, -32768i64);
}

#[test]
fn test_pmovsxdq() {
    let mut emu = Engine::new(EngineMode::Mode64);

    // Test PMOVSXDQ - sign extend doublewords to quadwords
    let code = vec![
        // movdqa xmm0, [rsp]
        0x66, 0x0F, 0x6F, 0x04, 0x24, // pmovsxdq xmm1, xmm0
        0x66, 0x0F, 0x38, 0x25, 0xC8,
    ];

    emu.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    emu.memory.map(0x100000, 0x1000, Permission::ALL).unwrap();
    emu.memory.write(0x1000, &code).unwrap();
    emu.reg_write(Register::RIP, 0x1000);
    emu.reg_write(Register::RSP, 0x100400);

    // Test data: 2 doublewords to extend
    let test_data = vec![
        0xFF, 0xFF, 0xFF, 0x7F, // 2147483647
        0x00, 0x00, 0x00, 0x80, // -2147483648
    ];

    emu.memory.write(0x100400, &test_data).unwrap();

    emu.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 10)
        .unwrap();

    let result = emu.xmm_read(Register::XMM1);

    // Check each quadword - sign extended
    assert_eq!((result & 0xFFFFFFFFFFFFFFFF) as i64, 2147483647i64);
    assert_eq!(((result >> 64) & 0xFFFFFFFFFFFFFFFF) as i64, -2147483648i64);
}

#[test]
fn test_pmovzxbw() {
    let mut emu = Engine::new(EngineMode::Mode64);

    // Test PMOVZXBW - zero extend bytes to words
    let code = vec![
        // movdqa xmm0, [rsp]
        0x66, 0x0F, 0x6F, 0x04, 0x24, // pmovzxbw xmm1, xmm0
        0x66, 0x0F, 0x38, 0x30, 0xC8,
    ];

    emu.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    emu.memory.map(0x100000, 0x1000, Permission::ALL).unwrap();
    emu.memory.write(0x1000, &code).unwrap();
    emu.reg_write(Register::RIP, 0x1000);
    emu.reg_write(Register::RSP, 0x100400);

    // Test data: all bytes zero extended
    let test_data = vec![
        0xFF, // 255
        0x80, // 128
        0x01, // 1
        0x00, // 0
        0x40, // 64
        0xC0, // 192
        0x7F, // 127
        0xF0, // 240
    ];

    emu.memory.write(0x100400, &test_data).unwrap();

    emu.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 10)
        .unwrap();

    let result = emu.xmm_read(Register::XMM1);

    // Check each word - zero extended
    assert_eq!((result & 0xFFFF) as u16, 255u16);
    assert_eq!(((result >> 16) & 0xFFFF) as u16, 128u16);
    assert_eq!(((result >> 32) & 0xFFFF) as u16, 1u16);
    assert_eq!(((result >> 48) & 0xFFFF) as u16, 0u16);
    assert_eq!(((result >> 64) & 0xFFFF) as u16, 64u16);
    assert_eq!(((result >> 80) & 0xFFFF) as u16, 192u16);
    assert_eq!(((result >> 96) & 0xFFFF) as u16, 127u16);
    assert_eq!(((result >> 112) & 0xFFFF) as u16, 240u16);
}

#[test]
fn test_pmovzxbd() {
    let mut emu = Engine::new(EngineMode::Mode64);

    // Test PMOVZXBD - zero extend bytes to doublewords
    let code = vec![
        // movdqa xmm0, [rsp]
        0x66, 0x0F, 0x6F, 0x04, 0x24, // pmovzxbd xmm1, xmm0
        0x66, 0x0F, 0x38, 0x31, 0xC8,
    ];

    emu.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    emu.memory.map(0x100000, 0x1000, Permission::ALL).unwrap();
    emu.memory.write(0x1000, &code).unwrap();
    emu.reg_write(Register::RIP, 0x1000);
    emu.reg_write(Register::RSP, 0x100400);

    // Test data: 4 bytes to extend
    let test_data = vec![
        0xFF, // 255
        0x80, // 128
        0x01, // 1
        0x00, // 0
    ];

    emu.memory.write(0x100400, &test_data).unwrap();

    emu.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 10)
        .unwrap();

    let result = emu.xmm_read(Register::XMM1);

    // Check each doubleword - zero extended
    assert_eq!((result & 0xFFFFFFFF) as u32, 255u32);
    assert_eq!(((result >> 32) & 0xFFFFFFFF) as u32, 128u32);
    assert_eq!(((result >> 64) & 0xFFFFFFFF) as u32, 1u32);
    assert_eq!(((result >> 96) & 0xFFFFFFFF) as u32, 0u32);
}

#[test]
fn test_pmovzxbq() {
    let mut emu = Engine::new(EngineMode::Mode64);

    // Test PMOVZXBQ - zero extend bytes to quadwords
    let code = vec![
        // movdqa xmm0, [rsp]
        0x66, 0x0F, 0x6F, 0x04, 0x24, // pmovzxbq xmm1, xmm0
        0x66, 0x0F, 0x38, 0x32, 0xC8,
    ];

    emu.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    emu.memory.map(0x100000, 0x1000, Permission::ALL).unwrap();
    emu.memory.write(0x1000, &code).unwrap();
    emu.reg_write(Register::RIP, 0x1000);
    emu.reg_write(Register::RSP, 0x100400);

    // Test data: 2 bytes to extend
    let test_data = vec![
        0xFF, // 255
        0x80, // 128
    ];

    emu.memory.write(0x100400, &test_data).unwrap();

    emu.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 10)
        .unwrap();

    let result = emu.xmm_read(Register::XMM1);

    // Check each quadword - zero extended
    assert_eq!((result & 0xFFFFFFFFFFFFFFFF) as u64, 255u64);
    assert_eq!(((result >> 64) & 0xFFFFFFFFFFFFFFFF) as u64, 128u64);
}

#[test]
fn test_pmovzxwd() {
    let mut emu = Engine::new(EngineMode::Mode64);

    // Test PMOVZXWD - zero extend words to doublewords
    let code = vec![
        // movdqa xmm0, [rsp]
        0x66, 0x0F, 0x6F, 0x04, 0x24, // pmovzxwd xmm1, xmm0
        0x66, 0x0F, 0x38, 0x33, 0xC8,
    ];

    emu.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    emu.memory.map(0x100000, 0x1000, Permission::ALL).unwrap();
    emu.memory.write(0x1000, &code).unwrap();
    emu.reg_write(Register::RIP, 0x1000);
    emu.reg_write(Register::RSP, 0x100400);

    // Test data: 4 words to extend
    let test_data = vec![
        0xFF, 0xFF, // 65535
        0x00, 0x80, // 32768
        0x01, 0x00, // 1
        0x00, 0x00, // 0
    ];

    emu.memory.write(0x100400, &test_data).unwrap();

    emu.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 10)
        .unwrap();

    let result = emu.xmm_read(Register::XMM1);

    // Check each doubleword - zero extended
    assert_eq!((result & 0xFFFFFFFF) as u32, 65535u32);
    assert_eq!(((result >> 32) & 0xFFFFFFFF) as u32, 32768u32);
    assert_eq!(((result >> 64) & 0xFFFFFFFF) as u32, 1u32);
    assert_eq!(((result >> 96) & 0xFFFFFFFF) as u32, 0u32);
}

#[test]
fn test_pmovzxwq() {
    let mut emu = Engine::new(EngineMode::Mode64);

    // Test PMOVZXWQ - zero extend words to quadwords
    let code = vec![
        // movdqa xmm0, [rsp]
        0x66, 0x0F, 0x6F, 0x04, 0x24, // pmovzxwq xmm1, xmm0
        0x66, 0x0F, 0x38, 0x34, 0xC8,
    ];

    emu.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    emu.memory.map(0x100000, 0x1000, Permission::ALL).unwrap();
    emu.memory.write(0x1000, &code).unwrap();
    emu.reg_write(Register::RIP, 0x1000);
    emu.reg_write(Register::RSP, 0x100400);

    // Test data: 2 words to extend
    let test_data = vec![
        0xFF, 0xFF, // 65535
        0x00, 0x80, // 32768
    ];

    emu.memory.write(0x100400, &test_data).unwrap();

    emu.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 10)
        .unwrap();

    let result = emu.xmm_read(Register::XMM1);

    // Check each quadword - zero extended
    assert_eq!((result & 0xFFFFFFFFFFFFFFFF) as u64, 65535u64);
    assert_eq!(((result >> 64) & 0xFFFFFFFFFFFFFFFF) as u64, 32768u64);
}

#[test]
fn test_pmovzxdq() {
    let mut emu = Engine::new(EngineMode::Mode64);

    // Test PMOVZXDQ - zero extend doublewords to quadwords
    let code = vec![
        // movdqa xmm0, [rsp]
        0x66, 0x0F, 0x6F, 0x04, 0x24, // pmovzxdq xmm1, xmm0
        0x66, 0x0F, 0x38, 0x35, 0xC8,
    ];

    emu.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    emu.memory.map(0x100000, 0x1000, Permission::ALL).unwrap();
    emu.memory.write(0x1000, &code).unwrap();
    emu.reg_write(Register::RIP, 0x1000);
    emu.reg_write(Register::RSP, 0x100400);

    // Test data: 2 doublewords to extend
    let test_data = vec![
        0xFF, 0xFF, 0xFF, 0xFF, // 4294967295
        0x00, 0x00, 0x00, 0x80, // 2147483648
    ];

    emu.memory.write(0x100400, &test_data).unwrap();

    emu.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 10)
        .unwrap();

    let result = emu.xmm_read(Register::XMM1);

    // Check each quadword - zero extended
    assert_eq!((result & 0xFFFFFFFFFFFFFFFF) as u64, 4294967295u64);
    assert_eq!(((result >> 64) & 0xFFFFFFFFFFFFFFFF) as u64, 2147483648u64);
}

#[test]
fn test_pmovsxbw_memory() {
    let mut emu = Engine::new(EngineMode::Mode64);

    // Test PMOVSXBW with memory operand
    let code = vec![
        // pmovsxbw xmm1, qword ptr [rsp]
        0x66, 0x0F, 0x38, 0x20, 0x0C, 0x24,
    ];

    emu.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    emu.memory.map(0x100000, 0x1000, Permission::ALL).unwrap();
    emu.memory.write(0x1000, &code).unwrap();
    emu.reg_write(Register::RIP, 0x1000);
    emu.reg_write(Register::RSP, 0x100400);

    // Test data: 8 bytes to sign extend
    let test_data = vec![
        0x7F, // 127
        0x80, // -128
        0x01, // 1
        0xFF, // -1
        0x40, // 64
        0xC0, // -64
        0x00, // 0
        0xF0, // -16
    ];

    emu.memory.write(0x100400, &test_data).unwrap();

    emu.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 10)
        .unwrap();

    let result = emu.xmm_read(Register::XMM1);

    // Check each word - sign extended
    assert_eq!((result & 0xFFFF) as i16, 127i16);
    assert_eq!(((result >> 16) & 0xFFFF) as i16, -128i16);
    assert_eq!(((result >> 32) & 0xFFFF) as i16, 1i16);
    assert_eq!(((result >> 48) & 0xFFFF) as i16, -1i16);
    assert_eq!(((result >> 64) & 0xFFFF) as i16, 64i16);
    assert_eq!(((result >> 80) & 0xFFFF) as i16, -64i16);
    assert_eq!(((result >> 96) & 0xFFFF) as i16, 0i16);
    assert_eq!(((result >> 112) & 0xFFFF) as i16, -16i16);
}
