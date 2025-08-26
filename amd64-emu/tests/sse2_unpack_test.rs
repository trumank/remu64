use amd64_emu::{Engine, EngineMode, Permission, Register};

#[test]
fn test_punpcklbw() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory for code
    engine.mem_map(0x1000, 0x1000, Permission::READ | Permission::EXEC).unwrap();
    
    // PUNPCKLBW XMM0, XMM1
    // Interleaves low 8 bytes from XMM0 and XMM1
    let code = vec![0x66, 0x0F, 0x60, 0xC1];
    engine.mem_write(0x1000, &code).unwrap();
    
    // Set up test values
    // XMM0: 0x0F0E0D0C0B0A09080706050403020100
    // XMM1: 0x1F1E1D1C1B1A19181716151413121110
    engine.xmm_write(Register::XMM0, 0x0F0E0D0C0B0A09080706050403020100);
    engine.xmm_write(Register::XMM1, 0x1F1E1D1C1B1A19181716151413121110);
    
    // Set RIP to point to our code
    engine.reg_write(Register::RIP, 0x1000);
    
    // Execute the instruction
    engine.emu_start(0x1000, 0x1004, 0, 0).unwrap();
    
    // Check result
    // Result should interleave low 8 bytes: 
    // 0x10, 0x00, 0x11, 0x01, 0x12, 0x02, 0x13, 0x03, 0x14, 0x04, 0x15, 0x05, 0x16, 0x06, 0x17, 0x07
    let result = engine.xmm_read(Register::XMM0);
    assert_eq!(result, 0x1707160615051404130312021101_1000);
}

#[test]
fn test_punpckhbw() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory for code
    engine.mem_map(0x1000, 0x1000, Permission::READ | Permission::EXEC).unwrap();
    
    // PUNPCKHBW XMM0, XMM1
    // Interleaves high 8 bytes from XMM0 and XMM1
    let code = vec![0x66, 0x0F, 0x68, 0xC1];
    engine.mem_write(0x1000, &code).unwrap();
    
    // Set up test values
    engine.xmm_write(Register::XMM0, 0x0F0E0D0C0B0A09080706050403020100);
    engine.xmm_write(Register::XMM1, 0x1F1E1D1C1B1A19181716151413121110);
    
    // Set RIP to point to our code
    engine.reg_write(Register::RIP, 0x1000);
    
    // Execute the instruction
    engine.emu_start(0x1000, 0x1004, 0, 0).unwrap();
    
    // Check result
    // Result should interleave high 8 bytes:
    // 0x18, 0x08, 0x19, 0x09, 0x1A, 0x0A, 0x1B, 0x0B, 0x1C, 0x0C, 0x1D, 0x0D, 0x1E, 0x0E, 0x1F, 0x0F
    let result = engine.xmm_read(Register::XMM0);
    assert_eq!(result, 0x1F0F1E0E1D0D1C0C1B0B1A0A19091808);
}

#[test]
fn test_punpckldq() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory for code
    engine.mem_map(0x1000, 0x1000, Permission::READ | Permission::EXEC).unwrap();
    
    // PUNPCKLDQ XMM0, XMM1
    // Interleaves low 2 doublewords from XMM0 and XMM1
    let code = vec![0x66, 0x0F, 0x62, 0xC1];
    engine.mem_write(0x1000, &code).unwrap();
    
    // Set up test values
    engine.xmm_write(Register::XMM0, 0xDDDDDDDDCCCCCCCCBBBBBBBBAAAAAAAA);
    engine.xmm_write(Register::XMM1, 0x44444444333333332222222211111111);
    
    // Set RIP to point to our code
    engine.reg_write(Register::RIP, 0x1000);
    
    // Execute the instruction
    engine.emu_start(0x1000, 0x1004, 0, 0).unwrap();
    
    // Check result
    // Result should be: BBBBBBBB 11111111 AAAAAAAA 11111111
    let result = engine.xmm_read(Register::XMM0);
    assert_eq!(result, 0x22222222BBBBBBBB11111111AAAAAAAA);
}

#[test]
fn test_punpckhdq() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory for code
    engine.mem_map(0x1000, 0x1000, Permission::READ | Permission::EXEC).unwrap();
    
    // PUNPCKHDQ XMM0, XMM1
    // Interleaves high 2 doublewords from XMM0 and XMM1
    let code = vec![0x66, 0x0F, 0x6A, 0xC1];
    engine.mem_write(0x1000, &code).unwrap();
    
    // Set up test values
    engine.xmm_write(Register::XMM0, 0xDDDDDDDDCCCCCCCCBBBBBBBBAAAAAAAA);
    engine.xmm_write(Register::XMM1, 0x44444444333333332222222211111111);
    
    // Set RIP to point to our code
    engine.reg_write(Register::RIP, 0x1000);
    
    // Execute the instruction
    engine.emu_start(0x1000, 0x1004, 0, 0).unwrap();
    
    // Check result
    // Result should be: DDDDDDDD 44444444 CCCCCCCC 33333333
    let result = engine.xmm_read(Register::XMM0);
    assert_eq!(result, 0x44444444DDDDDDDD33333333CCCCCCCC);
}

#[test]
fn test_punpcklqdq() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory for code
    engine.mem_map(0x1000, 0x1000, Permission::READ | Permission::EXEC).unwrap();
    
    // PUNPCKLQDQ XMM0, XMM1
    // Places low quadword from XMM0 and low quadword from XMM1
    let code = vec![0x66, 0x0F, 0x6C, 0xC1];
    engine.mem_write(0x1000, &code).unwrap();
    
    // Set up test values
    engine.xmm_write(Register::XMM0, 0xFEDCBA9876543210_0123456789ABCDEF);
    engine.xmm_write(Register::XMM1, 0x1111111111111111_2222222222222222);
    
    // Set RIP to point to our code
    engine.reg_write(Register::RIP, 0x1000);
    
    // Execute the instruction
    engine.emu_start(0x1000, 0x1004, 0, 0).unwrap();
    
    // Check result
    // Result should have low quadword from XMM0 and low quadword from XMM1
    let result = engine.xmm_read(Register::XMM0);
    assert_eq!(result, 0x2222222222222222_0123456789ABCDEF);
}

#[test]
fn test_punpckhqdq() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory for code
    engine.mem_map(0x1000, 0x1000, Permission::READ | Permission::EXEC).unwrap();
    
    // PUNPCKHQDQ XMM0, XMM1
    // Places high quadword from XMM0 and high quadword from XMM1
    let code = vec![0x66, 0x0F, 0x6D, 0xC1];
    engine.mem_write(0x1000, &code).unwrap();
    
    // Set up test values
    engine.xmm_write(Register::XMM0, 0xFEDCBA9876543210_0123456789ABCDEF);
    engine.xmm_write(Register::XMM1, 0x1111111111111111_2222222222222222);
    
    // Set RIP to point to our code
    engine.reg_write(Register::RIP, 0x1000);
    
    // Execute the instruction
    engine.emu_start(0x1000, 0x1004, 0, 0).unwrap();
    
    // Check result
    // Result should have high quadword from XMM0 and high quadword from XMM1
    let result = engine.xmm_read(Register::XMM0);
    assert_eq!(result, 0x1111111111111111_FEDCBA9876543210);
}

#[test]
fn test_punpcklbw_memory() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory for code and data
    engine.mem_map(0x1000, 0x2000, Permission::READ | Permission::WRITE | Permission::EXEC).unwrap();
    
    // PUNPCKLBW XMM0, [0x2000]
    let code = vec![
        0x66, 0x0F, 0x60, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00 // punpcklbw xmm0, [0x2000]
    ];
    engine.mem_write(0x1000, &code).unwrap();
    
    // Write test data to memory
    let data: u128 = 0x1F1E1D1C1B1A19181716151413121110;
    engine.mem_write(0x2000, &data.to_le_bytes()).unwrap();
    
    // Set up XMM0
    engine.xmm_write(Register::XMM0, 0x0F0E0D0C0B0A09080706050403020100);
    
    // Set RIP to point to our code
    engine.reg_write(Register::RIP, 0x1000);
    
    // Execute the instruction
    engine.emu_start(0x1000, 0x1009, 0, 0).unwrap();
    
    // Check result
    let result = engine.xmm_read(Register::XMM0);
    assert_eq!(result, 0x1707160615051404130312021101_1000);
}

#[test]
fn test_punpckldq_memory() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory for code and data
    engine.mem_map(0x1000, 0x2000, Permission::READ | Permission::WRITE | Permission::EXEC).unwrap();
    
    // PUNPCKLDQ XMM0, [0x2000]
    let code = vec![
        0x66, 0x0F, 0x62, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00 // punpckldq xmm0, [0x2000]
    ];
    engine.mem_write(0x1000, &code).unwrap();
    
    // Write test data to memory
    let data: u128 = 0x44444444333333332222222211111111;
    engine.mem_write(0x2000, &data.to_le_bytes()).unwrap();
    
    // Set up XMM0
    engine.xmm_write(Register::XMM0, 0xDDDDDDDDCCCCCCCCBBBBBBBBAAAAAAAA);
    
    // Set RIP to point to our code
    engine.reg_write(Register::RIP, 0x1000);
    
    // Execute the instruction
    engine.emu_start(0x1000, 0x1009, 0, 0).unwrap();
    
    // Check result
    let result = engine.xmm_read(Register::XMM0);
    assert_eq!(result, 0x22222222BBBBBBBB11111111AAAAAAAA);
}