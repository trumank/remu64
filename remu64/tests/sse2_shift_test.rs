use remu64::{Engine, EngineMode, Permission, Register, memory::MemoryTrait as _};

#[test]
fn test_psllw() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test PSLLW - Packed shift left logical words
    let code = vec![
        // Initialize XMM0 with test values (at 0x1000, next RIP is 0x1008, +0x10 = 0x1018)
        0x66, 0x0F, 0x6F, 0x05, 0x10, 0x00, 0x00, 0x00, // movdqa xmm0, [rip + 0x10]
        // PSLLW xmm0, 4
        0x66, 0x0F, 0x71, 0xF0, 0x04, // psllw xmm0, 4
        // Move result to memory for checking (at 0x100D, next RIP is 0x1015, +0x13 = 0x1028)
        0x66, 0x0F, 0x7F, 0x05, 0x13, 0x00, 0x00, 0x00, // movdqa [rip + 0x13], xmm0
        // Padding to reach 0x1018
        0x90, 0x90, 0x90, // Data at offset 0x1018: XMM0 initial value (8 words)
        0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x66, 0x66, 0x77, 0x77, 0x88,
        0x88, // Space for result at offset 0x1028
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine.reg_write(Register::RIP, 0x1000);

    // Execute instructions
    assert!(engine.emu_start(0x1000, 0x1000 + 0x15, 0, 0).is_ok());

    // Check result
    let mut result = vec![0u8; 16];
    engine.memory.read(0x1028, &mut result).unwrap();

    // Expected: each word shifted left by 4
    assert_eq!(u16::from_le_bytes([result[0], result[1]]), 0x1110); // 0x1111 << 4
    assert_eq!(u16::from_le_bytes([result[2], result[3]]), 0x2220); // 0x2222 << 4
    assert_eq!(u16::from_le_bytes([result[4], result[5]]), 0x3330); // 0x3333 << 4
    assert_eq!(u16::from_le_bytes([result[6], result[7]]), 0x4440); // 0x4444 << 4
    assert_eq!(u16::from_le_bytes([result[8], result[9]]), 0x5550); // 0x5555 << 4
    assert_eq!(u16::from_le_bytes([result[10], result[11]]), 0x6660); // 0x6666 << 4
    assert_eq!(u16::from_le_bytes([result[12], result[13]]), 0x7770); // 0x7777 << 4
    assert_eq!(u16::from_le_bytes([result[14], result[15]]), 0x8880); // 0x8888 << 4
}

#[test]
fn test_pslld() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test PSLLD - Packed shift left logical doublewords
    let code = vec![
        // Initialize XMM0 with test values
        0x66, 0x0F, 0x6F, 0x05, 0x10, 0x00, 0x00, 0x00, // movdqa xmm0, [rip + 0x10]
        // PSLLD xmm0, 8
        0x66, 0x0F, 0x72, 0xF0, 0x08, // pslld xmm0, 8
        // Move result to memory for checking
        0x66, 0x0F, 0x7F, 0x05, 0x13, 0x00, 0x00, 0x00, // movdqa [rip + 0x13], xmm0
        // Padding to reach 0x1018
        0x90, 0x90, 0x90, // Data at offset 0x1018: XMM0 initial value (4 dwords)
        0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22, 0x33, 0x33, 0x33, 0x33, 0x44, 0x44, 0x44,
        0x44, // Space for result at offset 0x1028
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine.reg_write(Register::RIP, 0x1000);

    // Execute instructions
    assert!(engine.emu_start(0x1000, 0x1000 + 0x15, 0, 0).is_ok());

    // Check result
    let mut result = vec![0u8; 16];
    engine.memory.read(0x1028, &mut result).unwrap();

    // Expected: each dword shifted left by 8
    assert_eq!(
        u32::from_le_bytes([result[0], result[1], result[2], result[3]]),
        0x11111100
    );
    assert_eq!(
        u32::from_le_bytes([result[4], result[5], result[6], result[7]]),
        0x22222200
    );
    assert_eq!(
        u32::from_le_bytes([result[8], result[9], result[10], result[11]]),
        0x33333300
    );
    assert_eq!(
        u32::from_le_bytes([result[12], result[13], result[14], result[15]]),
        0x44444400
    );
}

#[test]
fn test_psllq() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test PSLLQ - Packed shift left logical quadwords
    let code = vec![
        // Initialize XMM0 with test values
        0x66, 0x0F, 0x6F, 0x05, 0x10, 0x00, 0x00, 0x00, // movdqa xmm0, [rip + 0x10]
        // PSLLQ xmm0, 16
        0x66, 0x0F, 0x73, 0xF0, 0x10, // psllq xmm0, 16
        // Move result to memory for checking
        0x66, 0x0F, 0x7F, 0x05, 0x13, 0x00, 0x00, 0x00, // movdqa [rip + 0x13], xmm0
        // Padding to reach 0x1018
        0x90, 0x90, 0x90, // Data at offset 0x1018: XMM0 initial value (2 qwords)
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x22, // Space for result at offset 0x1028
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine.reg_write(Register::RIP, 0x1000);

    // Execute instructions
    assert!(engine.emu_start(0x1000, 0x1000 + 0x15, 0, 0).is_ok());

    // Check result
    let mut result = vec![0u8; 16];
    engine.memory.read(0x1028, &mut result).unwrap();

    // Expected: each qword shifted left by 16
    assert_eq!(
        u64::from_le_bytes([
            result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7]
        ]),
        0x1111111111110000
    );
    assert_eq!(
        u64::from_le_bytes([
            result[8], result[9], result[10], result[11], result[12], result[13], result[14],
            result[15]
        ]),
        0x2222222222220000
    );
}

#[test]
fn test_psrlw() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test PSRLW - Packed shift right logical words
    let code = vec![
        // Initialize XMM0 with test values
        0x66, 0x0F, 0x6F, 0x05, 0x10, 0x00, 0x00, 0x00, // movdqa xmm0, [rip + 0x10]
        // PSRLW xmm0, 4
        0x66, 0x0F, 0x71, 0xD0, 0x04, // psrlw xmm0, 4
        // Move result to memory for checking
        0x66, 0x0F, 0x7F, 0x05, 0x13, 0x00, 0x00, 0x00, // movdqa [rip + 0x13], xmm0
        // Padding to reach 0x1018
        0x90, 0x90, 0x90, // Data at offset 0x1018: XMM0 initial value (8 words)
        0x10, 0x11, 0x20, 0x22, 0x40, 0x44, 0x80, 0x88, 0x10, 0xF0, 0x20, 0xE0, 0x40, 0xC0, 0x80,
        0x80, // Space for result at offset 0x1028
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine.reg_write(Register::RIP, 0x1000);

    // Execute instructions
    assert!(engine.emu_start(0x1000, 0x1000 + 0x15, 0, 0).is_ok());

    // Check result
    let mut result = vec![0u8; 16];
    engine.memory.read(0x1028, &mut result).unwrap();

    // Expected: each word shifted right by 4
    assert_eq!(u16::from_le_bytes([result[0], result[1]]), 0x0111); // 0x1110 >> 4
    assert_eq!(u16::from_le_bytes([result[2], result[3]]), 0x0222); // 0x2220 >> 4
    assert_eq!(u16::from_le_bytes([result[4], result[5]]), 0x0444); // 0x4440 >> 4
    assert_eq!(u16::from_le_bytes([result[6], result[7]]), 0x0888); // 0x8880 >> 4
    assert_eq!(u16::from_le_bytes([result[8], result[9]]), 0x0F01); // 0xF010 >> 4
    assert_eq!(u16::from_le_bytes([result[10], result[11]]), 0x0E02); // 0xE020 >> 4
    assert_eq!(u16::from_le_bytes([result[12], result[13]]), 0x0C04); // 0xC040 >> 4
    assert_eq!(u16::from_le_bytes([result[14], result[15]]), 0x0808); // 0x8080 >> 4
}

#[test]
fn test_psrld() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test PSRLD - Packed shift right logical doublewords
    let code = vec![
        // Initialize XMM0 with test values
        0x66, 0x0F, 0x6F, 0x05, 0x10, 0x00, 0x00, 0x00, // movdqa xmm0, [rip + 0x10]
        // PSRLD xmm0, 8
        0x66, 0x0F, 0x72, 0xD0, 0x08, // psrld xmm0, 8
        // Move result to memory for checking
        0x66, 0x0F, 0x7F, 0x05, 0x13, 0x00, 0x00, 0x00, // movdqa [rip + 0x13], xmm0
        // Padding to reach 0x1018
        0x90, 0x90, 0x90, // Data at offset 0x1018: XMM0 initial value (4 dwords)
        0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22, 0x44, 0x44, 0x44, 0x44, 0x88, 0x88, 0x88,
        0x88, // Space for result at offset 0x1028
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine.reg_write(Register::RIP, 0x1000);

    // Execute instructions
    assert!(engine.emu_start(0x1000, 0x1000 + 0x15, 0, 0).is_ok());

    // Check result
    let mut result = vec![0u8; 16];
    engine.memory.read(0x1028, &mut result).unwrap();

    // Expected: each dword shifted right by 8
    assert_eq!(
        u32::from_le_bytes([result[0], result[1], result[2], result[3]]),
        0x00111111
    );
    assert_eq!(
        u32::from_le_bytes([result[4], result[5], result[6], result[7]]),
        0x00222222
    );
    assert_eq!(
        u32::from_le_bytes([result[8], result[9], result[10], result[11]]),
        0x00444444
    );
    assert_eq!(
        u32::from_le_bytes([result[12], result[13], result[14], result[15]]),
        0x00888888
    );
}

#[test]
fn test_psrlq() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test PSRLQ - Packed shift right logical quadwords
    let code = vec![
        // Initialize XMM0 with test values
        0x66, 0x0F, 0x6F, 0x05, 0x10, 0x00, 0x00, 0x00, // movdqa xmm0, [rip + 0x10]
        // PSRLQ xmm0, 16
        0x66, 0x0F, 0x73, 0xD0, 0x10, // psrlq xmm0, 16
        // Move result to memory for checking
        0x66, 0x0F, 0x7F, 0x05, 0x13, 0x00, 0x00, 0x00, // movdqa [rip + 0x13], xmm0
        // Padding to reach 0x1018
        0x90, 0x90, 0x90, // Data at offset 0x1018: XMM0 initial value (2 qwords)
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,
        0x88, // Space for result at offset 0x1028
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine.reg_write(Register::RIP, 0x1000);

    // Execute instructions
    assert!(engine.emu_start(0x1000, 0x1000 + 0x15, 0, 0).is_ok());

    // Check result
    let mut result = vec![0u8; 16];
    engine.memory.read(0x1028, &mut result).unwrap();

    // Expected: each qword shifted right by 16
    assert_eq!(
        u64::from_le_bytes([
            result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7]
        ]),
        0x0000111111111111
    );
    assert_eq!(
        u64::from_le_bytes([
            result[8], result[9], result[10], result[11], result[12], result[13], result[14],
            result[15]
        ]),
        0x0000888888888888
    );
}

#[test]
fn test_psraw() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test PSRAW - Packed shift right arithmetic words
    let code = vec![
        // Initialize XMM0 with test values
        0x66, 0x0F, 0x6F, 0x05, 0x10, 0x00, 0x00, 0x00, // movdqa xmm0, [rip + 0x10]
        // PSRAW xmm0, 4
        0x66, 0x0F, 0x71, 0xE0, 0x04, // psraw xmm0, 4
        // Move result to memory for checking
        0x66, 0x0F, 0x7F, 0x05, 0x13, 0x00, 0x00, 0x00, // movdqa [rip + 0x13], xmm0
        // Padding to reach 0x1018
        0x90, 0x90, 0x90,
        // Data at offset 0x1018: XMM0 initial value (8 words, some negative)
        0x10, 0x11, 0x20, 0x22, 0x40, 0x44, 0x00, 0x80, // Last is -32768
        0x10, 0xF0, 0x20, 0xE0, 0x40, 0xC0, 0xFF, 0xFF, // Last two are negative
        // Space for result at offset 0x1028
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine.reg_write(Register::RIP, 0x1000);

    // Execute instructions
    assert!(engine.emu_start(0x1000, 0x1000 + 0x15, 0, 0).is_ok());

    // Check result
    let mut result = vec![0u8; 16];
    engine.memory.read(0x1028, &mut result).unwrap();

    // Expected: each word arithmetic shifted right by 4
    assert_eq!(u16::from_le_bytes([result[0], result[1]]), 0x0111); // 0x1110 >> 4
    assert_eq!(u16::from_le_bytes([result[2], result[3]]), 0x0222); // 0x2220 >> 4
    assert_eq!(u16::from_le_bytes([result[4], result[5]]), 0x0444); // 0x4440 >> 4
    assert_eq!(u16::from_le_bytes([result[6], result[7]]), 0xF800); // 0x8000 >> 4 (sign extended)
    assert_eq!(u16::from_le_bytes([result[8], result[9]]), 0xFF01); // 0xF010 >> 4 (sign extended)
    assert_eq!(u16::from_le_bytes([result[10], result[11]]), 0xFE02); // 0xE020 >> 4 (sign extended)
    assert_eq!(u16::from_le_bytes([result[12], result[13]]), 0xFC04); // 0xC040 >> 4 (sign extended)
    assert_eq!(u16::from_le_bytes([result[14], result[15]]), 0xFFFF); // 0xFFFF >> 4 (all 1s)
}

#[test]
fn test_psrad() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test PSRAD - Packed shift right arithmetic doublewords
    let code = vec![
        // Initialize XMM0 with test values
        0x66, 0x0F, 0x6F, 0x05, 0x10, 0x00, 0x00, 0x00, // movdqa xmm0, [rip + 0x10]
        // PSRAD xmm0, 8
        0x66, 0x0F, 0x72, 0xE0, 0x08, // psrad xmm0, 8
        // Move result to memory for checking
        0x66, 0x0F, 0x7F, 0x05, 0x13, 0x00, 0x00, 0x00, // movdqa [rip + 0x13], xmm0
        // Padding to reach 0x1018
        0x90, 0x90, 0x90,
        // Data at offset 0x1018: XMM0 initial value (4 dwords, some negative)
        0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22, 0x00, 0x00, 0x00, 0x80, // -2147483648
        0xFF, 0xFF, 0xFF, 0xFF, // -1
        // Space for result at offset 0x1028
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine.reg_write(Register::RIP, 0x1000);

    // Execute instructions
    assert!(engine.emu_start(0x1000, 0x1000 + 0x15, 0, 0).is_ok());

    // Check result
    let mut result = vec![0u8; 16];
    engine.memory.read(0x1028, &mut result).unwrap();

    // Expected: each dword arithmetic shifted right by 8
    assert_eq!(
        u32::from_le_bytes([result[0], result[1], result[2], result[3]]),
        0x00111111
    );
    assert_eq!(
        u32::from_le_bytes([result[4], result[5], result[6], result[7]]),
        0x00222222
    );
    assert_eq!(
        u32::from_le_bytes([result[8], result[9], result[10], result[11]]),
        0xFF800000
    ); // Sign extended
    assert_eq!(
        u32::from_le_bytes([result[12], result[13], result[14], result[15]]),
        0xFFFFFFFF
    ); // All 1s
}

#[test]
fn test_shift_overflow() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test shift overflow - shift by amount >= element size
    let code = vec![
        // Initialize XMM0 with all 1s
        0x66, 0x0F, 0x6F, 0x05, 0x10, 0x00, 0x00, 0x00, // movdqa xmm0, [rip + 0x10]
        // PSLLW xmm0, 16 (shift by 16, all bits should be shifted out)
        0x66, 0x0F, 0x71, 0xF0, 0x10, // psllw xmm0, 16
        // Move result to memory for checking
        0x66, 0x0F, 0x7F, 0x05, 0x13, 0x00, 0x00, 0x00, // movdqa [rip + 0x13], xmm0
        // Padding to reach 0x1018
        0x90, 0x90, 0x90, // Data at offset 0x1018: XMM0 initial value (all 1s)
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, // Space for result at offset 0x1028
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine.reg_write(Register::RIP, 0x1000);

    // Execute instructions
    assert!(engine.emu_start(0x1000, 0x1000 + 0x15, 0, 0).is_ok());

    // Check result
    let mut result = vec![0u8; 16];
    engine.memory.read(0x1028, &mut result).unwrap();

    // Expected: all zeros (all bits shifted out)
    for item in result.iter().take(16) {
        assert_eq!(*item, 0);
    }
}
