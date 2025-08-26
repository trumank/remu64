use amd64_emu::{Engine, EngineMode, Permission, Register};

#[test]
fn test_pshuflw() {
    let mut emu = Engine::new(EngineMode::Mode64);

    // Allocate memory for code
    let code_addr = 0x1000;
    emu.mem_map(
        code_addr,
        0x1000,
        Permission::READ | Permission::WRITE | Permission::EXEC,
    )
    .unwrap();

    // PSHUFLW XMM1, XMM0, 0x1B (00 01 10 11) - reverse order of low words
    let code = vec![
        0xF2, 0x0F, 0x70, 0xC8, 0x1B, // pshuflw xmm1, xmm0, 0x1B
    ];

    emu.mem_write(code_addr, &code).unwrap();

    // Set up test data in XMM0
    // Low 64 bits: 0x0004_0003_0002_0001 (4 words)
    // High 64 bits: 0x0008_0007_0006_0005 (4 words)
    emu.xmm_write(Register::XMM0, 0x0008_0007_0006_0005_0004_0003_0002_0001);
    emu.reg_write(Register::RIP, code_addr);

    // Execute the instruction
    emu.emu_start(code_addr, code_addr + code.len() as u64, 0, 0)
        .unwrap();

    // Check result in XMM1
    // Expected: low words reversed (0x0001_0002_0003_0004), high unchanged
    let result = emu.xmm_read(Register::XMM1);
    assert_eq!(
        result, 0x0008_0007_0006_0005_0001_0002_0003_0004,
        "PSHUFLW should reverse low words while preserving high words"
    );
}

#[test]
fn test_pshufhw() {
    let mut emu = Engine::new(EngineMode::Mode64);

    // Allocate memory for code
    let code_addr = 0x1000;
    emu.mem_map(
        code_addr,
        0x1000,
        Permission::READ | Permission::WRITE | Permission::EXEC,
    )
    .unwrap();

    // PSHUFHW XMM1, XMM0, 0x1B (00 01 10 11) - reverse order of high words
    let code = vec![
        0xF3, 0x0F, 0x70, 0xC8, 0x1B, // pshufhw xmm1, xmm0, 0x1B
    ];

    emu.mem_write(code_addr, &code).unwrap();

    // Set up test data in XMM0
    emu.xmm_write(Register::XMM0, 0x0008_0007_0006_0005_0004_0003_0002_0001);
    emu.reg_write(Register::RIP, code_addr);

    // Execute the instruction
    emu.emu_start(code_addr, code_addr + code.len() as u64, 0, 0)
        .unwrap();

    // Check result in XMM1
    // Expected: high words reversed (0x0005_0006_0007_0008), low unchanged
    let result = emu.xmm_read(Register::XMM1);
    assert_eq!(
        result, 0x0005_0006_0007_0008_0004_0003_0002_0001,
        "PSHUFHW should reverse high words while preserving low words"
    );
}

#[test]
fn test_pextrw() {
    let mut emu = Engine::new(EngineMode::Mode64);

    // Allocate memory for code
    let code_addr = 0x1000;
    emu.mem_map(
        code_addr,
        0x1000,
        Permission::READ | Permission::WRITE | Permission::EXEC,
    )
    .unwrap();

    // PEXTRW EAX, XMM0, 3 - extract word at index 3
    let code = vec![
        0x66, 0x0F, 0xC5, 0xC0, 0x03, // pextrw eax, xmm0, 3
    ];

    emu.mem_write(code_addr, &code).unwrap();

    // Set up test data in XMM0: words are [0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0x8888]
    emu.xmm_write(Register::XMM0, 0x8888_7777_6666_5555_4444_3333_2222_1111);
    emu.reg_write(Register::RIP, code_addr);
    emu.reg_write(Register::RAX, 0xDEADBEEF); // Set initial value

    // Execute the instruction
    emu.emu_start(code_addr, code_addr + code.len() as u64, 0, 0)
        .unwrap();

    // Check result in RAX - should extract word at index 3 (0x4444)
    let result = emu.reg_read(Register::RAX);
    assert_eq!(
        result & 0xFFFF,
        0x4444,
        "PEXTRW should extract word at index 3"
    );
}

#[test]
fn test_pinsrw() {
    let mut emu = Engine::new(EngineMode::Mode64);

    // Allocate memory for code
    let code_addr = 0x1000;
    emu.mem_map(
        code_addr,
        0x1000,
        Permission::READ | Permission::WRITE | Permission::EXEC,
    )
    .unwrap();

    // PINSRW XMM0, EAX, 2 - insert word at index 2
    let code = vec![
        0x66, 0x0F, 0xC4, 0xC0, 0x02, // pinsrw xmm0, eax, 2
    ];

    emu.mem_write(code_addr, &code).unwrap();

    // Set up test data
    emu.xmm_write(Register::XMM0, 0x8888_7777_6666_5555_4444_3333_2222_1111);
    emu.reg_write(Register::RAX, 0xAAAA); // Word to insert
    emu.reg_write(Register::RIP, code_addr);

    // Execute the instruction
    emu.emu_start(code_addr, code_addr + code.len() as u64, 0, 0)
        .unwrap();

    // Check result in XMM0 - word at index 2 should be 0xAAAA
    let result = emu.xmm_read(Register::XMM0);
    assert_eq!(
        result, 0x8888_7777_6666_5555_4444_AAAA_2222_1111,
        "PINSRW should insert word at index 2"
    );
}

#[test]
fn test_pmovmskb() {
    let mut emu = Engine::new(EngineMode::Mode64);

    // Allocate memory for code
    let code_addr = 0x1000;
    emu.mem_map(
        code_addr,
        0x1000,
        Permission::READ | Permission::WRITE | Permission::EXEC,
    )
    .unwrap();

    // PMOVMSKB EAX, XMM0
    let code = vec![
        0x66, 0x0F, 0xD7, 0xC0, // pmovmskb eax, xmm0
    ];

    emu.mem_write(code_addr, &code).unwrap();

    // Set up test data in XMM0
    // Bytes with MSB set: 0x80, 0x00, 0xFF, 0x7F, 0x81, 0x01, 0x80, 0x00, ...
    emu.xmm_write(Register::XMM0, 0x0080_0181_7FFF_0080_0080_0181_7FFF_0080);
    emu.reg_write(Register::RIP, code_addr);

    // Execute the instruction
    emu.emu_start(code_addr, code_addr + code.len() as u64, 0, 0)
        .unwrap();

    // Check result in EAX - should have bits set for bytes with MSB=1
    let result = emu.reg_read(Register::RAX);
    // Expected mask: bytes at positions 0, 2, 4, 6, 8, 10, 12, 14 have MSB set
    assert_eq!(
        result & 0xFFFF,
        0x5555,
        "PMOVMSKB should extract sign bits correctly"
    );
}

#[test]
fn test_pavgb() {
    let mut emu = Engine::new(EngineMode::Mode64);

    // Allocate memory for code
    let code_addr = 0x1000;
    emu.mem_map(
        code_addr,
        0x1000,
        Permission::READ | Permission::WRITE | Permission::EXEC,
    )
    .unwrap();

    // PAVGB XMM0, XMM1
    let code = vec![
        0x66, 0x0F, 0xE0, 0xC1, // pavgb xmm0, xmm1
    ];

    emu.mem_write(code_addr, &code).unwrap();

    // Set up test data
    // XMM0: bytes = [0x10, 0x20, 0x30, 0x40, ...]
    // XMM1: bytes = [0x20, 0x30, 0x40, 0x50, ...]
    emu.xmm_write(Register::XMM0, 0x4030_2010_4030_2010_4030_2010_4030_2010);
    emu.xmm_write(Register::XMM1, 0x5040_3020_5040_3020_5040_3020_5040_3020);
    emu.reg_write(Register::RIP, code_addr);

    // Execute the instruction
    emu.emu_start(code_addr, code_addr + code.len() as u64, 0, 0)
        .unwrap();

    // Check result - average with rounding: (a + b + 1) >> 1
    let result = emu.xmm_read(Register::XMM0);
    // Expected: (0x10+0x20+1)>>1=0x18, (0x20+0x30+1)>>1=0x28, etc.
    assert_eq!(
        result, 0x4838_2818_4838_2818_4838_2818_4838_2818,
        "PAVGB should compute rounded average of bytes"
    );
}

#[test]
fn test_pmaxub() {
    let mut emu = Engine::new(EngineMode::Mode64);

    // Allocate memory for code
    let code_addr = 0x1000;
    emu.mem_map(
        code_addr,
        0x1000,
        Permission::READ | Permission::WRITE | Permission::EXEC,
    )
    .unwrap();

    // PMAXUB XMM0, XMM1
    let code = vec![
        0x66, 0x0F, 0xDE, 0xC1, // pmaxub xmm0, xmm1
    ];

    emu.mem_write(code_addr, &code).unwrap();

    // Set up test data
    emu.xmm_write(Register::XMM0, 0x10203040_50607080_90A0B0C0_D0E0F000);
    emu.xmm_write(Register::XMM1, 0x08182838_48586878_8898A8B8_C8D8E8F8);
    emu.reg_write(Register::RIP, code_addr);

    // Execute the instruction
    emu.emu_start(code_addr, code_addr + code.len() as u64, 0, 0)
        .unwrap();

    // Check result - should have maximum of each byte pair
    let result = emu.xmm_read(Register::XMM0);
    assert_eq!(
        result, 0x10203040_50607080_90A0B0C0_D0E0F0F8,
        "PMAXUB should store maximum unsigned bytes"
    );
}

#[test]
fn test_psadbw() {
    let mut emu = Engine::new(EngineMode::Mode64);

    // Allocate memory for code
    let code_addr = 0x1000;
    emu.mem_map(
        code_addr,
        0x1000,
        Permission::READ | Permission::WRITE | Permission::EXEC,
    )
    .unwrap();

    // PSADBW XMM0, XMM1
    let code = vec![
        0x66, 0x0F, 0xF6, 0xC1, // psadbw xmm0, xmm1
    ];

    emu.mem_write(code_addr, &code).unwrap();

    // Set up test data
    // XMM0: bytes = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, ...]
    // XMM1: bytes = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, ...]
    emu.xmm_write(Register::XMM0, 0x8070_6050_4030_2010_8070_6050_4030_2010);
    emu.xmm_write(Register::XMM1, 0x8877_6655_4433_2211_8877_6655_4433_2211);
    emu.reg_write(Register::RIP, code_addr);

    // Execute the instruction
    emu.emu_start(code_addr, code_addr + code.len() as u64, 0, 0)
        .unwrap();

    // Check result - sum of absolute differences
    // Low 8 bytes: |0x10-0x11| + |0x20-0x22| + ... = 1+2+3+4+5+6+7+8 = 36 = 0x24
    // High 8 bytes: same = 36 = 0x24
    let result = emu.xmm_read(Register::XMM0);
    assert_eq!(result & 0xFFFF, 0x24, "PSADBW low sum incorrect");
    assert_eq!((result >> 64) & 0xFFFF, 0x24, "PSADBW high sum incorrect");
    // Check that other bits are cleared
    assert_eq!(
        result & 0xFFFF_FFFF_FFFF_0000,
        0,
        "PSADBW should clear bits [63:16]"
    );
    assert_eq!(
        result & 0xFFFF_0000_0000_0000_0000_0000_0000_0000,
        0,
        "PSADBW should clear bits [127:80]"
    );
}
