use amd64_emu::{Engine, EngineMode, Permission, Register};

#[test]
fn test_pmullw() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory
    engine.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Test PMULLW - Multiply packed signed words and store low result
    let code = vec![
        // Initialize XMM0 with test values
        0x66, 0x0F, 0x6F, 0x05, 0x14, 0x00, 0x00, 0x00,  // movdqa xmm0, [rip + 0x14]
        // Initialize XMM1 with multipliers
        0x66, 0x0F, 0x6F, 0x0D, 0x1C, 0x00, 0x00, 0x00,  // movdqa xmm1, [rip + 0x1C]
        // PMULLW xmm0, xmm1
        0x66, 0x0F, 0xD5, 0xC1,  // pmullw xmm0, xmm1
        // Move result to memory for checking
        0x66, 0x0F, 0x7F, 0x05, 0x20, 0x00, 0x00, 0x00,  // movdqa [rip + 0x20], xmm0
        
        // Data at offset 0x101C (0x1C from start): XMM0 initial value (8 signed words)
        0x02, 0x00, 0x04, 0x00, 0x08, 0x00, 0x10, 0x00,  // 2, 4, 8, 16
        0xFF, 0xFF, 0xFE, 0xFF, 0x00, 0x80, 0x00, 0x40,  // -1, -2, -32768, 16384
        
        // Data at offset 0x102C (0x2C from start): XMM1 multipliers
        0x03, 0x00, 0x05, 0x00, 0x07, 0x00, 0x09, 0x00,  // 3, 5, 7, 9
        0x02, 0x00, 0x04, 0x00, 0x02, 0x00, 0x02, 0x00,  // 2, 4, 2, 2
        
        // Space for result at offset 0x103C (0x3C from start)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    
    engine.mem_write(0x1000, &code).unwrap();
    engine.reg_write(Register::RIP, 0x1000);
    
    // Execute instructions  
    match engine.emu_start(0x1000, 0x1000 + 0x1C, 0, 0) {
        Ok(_) => {},
        Err(e) => panic!("Execution failed: {:?}", e),
    }
    
    // Check result
    let mut result = vec![0u8; 16];
    engine.mem_read(0x103C, &mut result).unwrap();
    
    // Expected: low 16 bits of each multiplication
    assert_eq!(u16::from_le_bytes([result[0], result[1]]), 6);      // 2 * 3 = 6
    assert_eq!(u16::from_le_bytes([result[2], result[3]]), 20);     // 4 * 5 = 20
    assert_eq!(u16::from_le_bytes([result[4], result[5]]), 56);     // 8 * 7 = 56
    assert_eq!(u16::from_le_bytes([result[6], result[7]]), 144);    // 16 * 9 = 144
    assert_eq!(u16::from_le_bytes([result[8], result[9]]), 0xFFFE); // -1 * 2 = -2
    assert_eq!(u16::from_le_bytes([result[10], result[11]]), 0xFFF8); // -2 * 4 = -8
    assert_eq!(u16::from_le_bytes([result[12], result[13]]), 0);    // -32768 * 2 = -65536 (overflow, low 16 bits = 0)
    assert_eq!(u16::from_le_bytes([result[14], result[15]]), 0x8000); // 16384 * 2 = 32768
}

#[test]
fn test_pmulhw() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory
    engine.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Test PMULHW - Multiply packed signed words and store high result
    let code = vec![
        // Initialize XMM0 with test values
        0x66, 0x0F, 0x6F, 0x05, 0x14, 0x00, 0x00, 0x00,  // movdqa xmm0, [rip + 0x14]
        // Initialize XMM1 with multipliers
        0x66, 0x0F, 0x6F, 0x0D, 0x1C, 0x00, 0x00, 0x00,  // movdqa xmm1, [rip + 0x1C]
        // PMULHW xmm0, xmm1
        0x66, 0x0F, 0xE5, 0xC1,  // pmulhw xmm0, xmm1
        // Move result to memory for checking
        0x66, 0x0F, 0x7F, 0x05, 0x20, 0x00, 0x00, 0x00,  // movdqa [rip + 0x20], xmm0
        
        // Data at offset 0x101C: XMM0 initial value (8 signed words)
        0x00, 0x10, 0x00, 0x20, 0x00, 0x40, 0xFF, 0x7F,  // 0x1000, 0x2000, 0x4000, 0x7FFF
        0x00, 0x80, 0xFF, 0xFF, 0x00, 0xC0, 0x00, 0x60,  // -32768, -1, -16384, 0x6000
        
        // Data at offset 0x102C: XMM1 multipliers
        0x00, 0x10, 0x00, 0x08, 0x00, 0x04, 0x02, 0x00,  // 0x1000, 0x800, 0x400, 2
        0x02, 0x00, 0x00, 0x10, 0x04, 0x00, 0x00, 0x02,  // 2, 0x1000, 4, 0x200
        
        // Space for result at offset 0x103C
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    
    engine.mem_write(0x1000, &code).unwrap();
    engine.reg_write(Register::RIP, 0x1000);
    
    // Execute instructions  
    match engine.emu_start(0x1000, 0x1000 + 0x1C, 0, 0) {
        Ok(_) => {},
        Err(e) => panic!("Execution failed: {:?}", e),
    }
    
    // Check result
    let mut result = vec![0u8; 16];
    engine.mem_read(0x103C, &mut result).unwrap();
    
    // Expected: high 16 bits of each multiplication
    assert_eq!(u16::from_le_bytes([result[0], result[1]]), 0x0100);  // (0x1000 * 0x1000) >> 16
    assert_eq!(u16::from_le_bytes([result[2], result[3]]), 0x0100);  // (0x2000 * 0x0800) >> 16
    assert_eq!(u16::from_le_bytes([result[4], result[5]]), 0x0100);  // (0x4000 * 0x0400) >> 16
    assert_eq!(u16::from_le_bytes([result[6], result[7]]), 0);       // (0x7FFF * 2) >> 16 = 0
    assert_eq!(u16::from_le_bytes([result[8], result[9]]), 0xFFFF);  // (-32768 * 2) >> 16 = -1
    assert_eq!(u16::from_le_bytes([result[10], result[11]]), 0xFFFF); // (-1 * 0x1000) >> 16
    assert_eq!(u16::from_le_bytes([result[12], result[13]]), 0xFFFF); // (-16384 * 4) >> 16 = -1
    assert_eq!(u16::from_le_bytes([result[14], result[15]]), 0x00C);  // (0x6000 * 0x200) >> 16
}

#[test]
fn test_pmulhuw() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory
    engine.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Test PMULHUW - Multiply packed unsigned words and store high result
    let code = vec![
        // Initialize XMM0 with test values
        0x66, 0x0F, 0x6F, 0x05, 0x14, 0x00, 0x00, 0x00,  // movdqa xmm0, [rip + 0x14]
        // Initialize XMM1 with multipliers
        0x66, 0x0F, 0x6F, 0x0D, 0x1C, 0x00, 0x00, 0x00,  // movdqa xmm1, [rip + 0x1C]
        // PMULHUW xmm0, xmm1
        0x66, 0x0F, 0xE4, 0xC1,  // pmulhuw xmm0, xmm1
        // Move result to memory for checking
        0x66, 0x0F, 0x7F, 0x05, 0x20, 0x00, 0x00, 0x00,  // movdqa [rip + 0x20], xmm0
        
        // Data at offset 0x101C: XMM0 initial value (8 unsigned words)
        0x00, 0x10, 0x00, 0x20, 0x00, 0x40, 0xFF, 0xFF,  // 0x1000, 0x2000, 0x4000, 0xFFFF
        0x00, 0x80, 0xFF, 0xFF, 0x00, 0xC0, 0x00, 0x60,  // 0x8000, 0xFFFF, 0xC000, 0x6000
        
        // Data at offset 0x102C: XMM1 multipliers
        0x00, 0x10, 0x00, 0x08, 0x00, 0x04, 0x02, 0x00,  // 0x1000, 0x800, 0x400, 2
        0x02, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x02,  // 2, 1, 4, 0x200
        
        // Space for result at offset 0x103C
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    
    engine.mem_write(0x1000, &code).unwrap();
    engine.reg_write(Register::RIP, 0x1000);
    
    // Execute instructions  
    match engine.emu_start(0x1000, 0x1000 + 0x1C, 0, 0) {
        Ok(_) => {},
        Err(e) => panic!("Execution failed: {:?}", e),
    }
    
    // Check result
    let mut result = vec![0u8; 16];
    engine.mem_read(0x103C, &mut result).unwrap();
    
    // Expected: high 16 bits of unsigned multiplication
    assert_eq!(u16::from_le_bytes([result[0], result[1]]), 0x0100);  // (0x1000 * 0x1000) >> 16
    assert_eq!(u16::from_le_bytes([result[2], result[3]]), 0x0100);  // (0x2000 * 0x0800) >> 16
    assert_eq!(u16::from_le_bytes([result[4], result[5]]), 0x0100);  // (0x4000 * 0x0400) >> 16
    assert_eq!(u16::from_le_bytes([result[6], result[7]]), 1);       // (0xFFFF * 2) >> 16 = 1
    assert_eq!(u16::from_le_bytes([result[8], result[9]]), 1);       // (0x8000 * 2) >> 16 = 1
    assert_eq!(u16::from_le_bytes([result[10], result[11]]), 0);     // (0xFFFF * 1) >> 16 = 0
    assert_eq!(u16::from_le_bytes([result[12], result[13]]), 2);     // (0xC000 * 4) >> 16 = 2
    assert_eq!(u16::from_le_bytes([result[14], result[15]]), 0x0C);  // (0x6000 * 0x200) >> 16
}

#[test]
fn test_pmuludq() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory
    engine.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Test PMULUDQ - Multiply packed unsigned doubleword integers
    let code = vec![
        // Initialize XMM0 with test values
        0x66, 0x0F, 0x6F, 0x05, 0x14, 0x00, 0x00, 0x00,  // movdqa xmm0, [rip + 0x14]
        // Initialize XMM1 with multipliers
        0x66, 0x0F, 0x6F, 0x0D, 0x1C, 0x00, 0x00, 0x00,  // movdqa xmm1, [rip + 0x1C]
        // PMULUDQ xmm0, xmm1
        0x66, 0x0F, 0xF4, 0xC1,  // pmuludq xmm0, xmm1
        // Move result to memory for checking
        0x66, 0x0F, 0x7F, 0x05, 0x20, 0x00, 0x00, 0x00,  // movdqa [rip + 0x20], xmm0
        
        // Data at offset 0x101C: XMM0 initial value (low dwords of each qword)
        0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,  // 0x10000000 (low dword), ignored (high dword)
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,  // 0xFFFFFFFF (low dword), ignored (high dword)
        
        // Data at offset 0x102C: XMM1 multipliers (low dwords of each qword)
        0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,  // 0x02000000 (low dword), ignored (high dword)
        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,  // 0x00010000 (low dword), ignored (high dword)
        
        // Space for result at offset 0x103C
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    
    engine.mem_write(0x1000, &code).unwrap();
    engine.reg_write(Register::RIP, 0x1000);
    
    // Execute instructions  
    match engine.emu_start(0x1000, 0x1000 + 0x1C, 0, 0) {
        Ok(_) => {},
        Err(e) => panic!("Execution failed: {:?}", e),
    }
    
    // Check result
    let mut result = vec![0u8; 16];
    engine.mem_read(0x103C, &mut result).unwrap();
    
    // Expected: 64-bit products of low dwords
    assert_eq!(u64::from_le_bytes([result[0], result[1], result[2], result[3],
                                   result[4], result[5], result[6], result[7]]), 
               0x20000000000000);  // 0x10000000 * 0x02000000
    assert_eq!(u64::from_le_bytes([result[8], result[9], result[10], result[11],
                                   result[12], result[13], result[14], result[15]]), 
               0xFFFF0000);  // 0xFFFFFFFF * 0x00010000
}

#[test]
fn test_pmullw_memory_operand() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory
    engine.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Test PMULLW with memory operand
    let code = vec![
        // Initialize XMM0 with test values
        0x66, 0x0F, 0x6F, 0x05, 0x14, 0x00, 0x00, 0x00,  // movdqa xmm0, [rip + 0x14]
        // PMULLW xmm0, [rip + 0x1C] - multiply with memory operand
        0x66, 0x0F, 0xD5, 0x05, 0x1C, 0x00, 0x00, 0x00,  // pmullw xmm0, [rip + 0x1C]
        // Move result to memory for checking - adjust displacement for correct address
        0x66, 0x0F, 0x7F, 0x05, 0x24, 0x00, 0x00, 0x00,  // movdqa [rip + 0x24], xmm0
        
        // Data at offset 0x101C: XMM0 initial value
        0x0A, 0x00, 0x14, 0x00, 0x1E, 0x00, 0x28, 0x00,  // 10, 20, 30, 40
        0x32, 0x00, 0x3C, 0x00, 0x46, 0x00, 0x50, 0x00,  // 50, 60, 70, 80
        
        // Data at offset 0x102C: Memory operand (multipliers)
        0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00,  // 2, 3, 4, 5
        0x06, 0x00, 0x07, 0x00, 0x08, 0x00, 0x09, 0x00,  // 6, 7, 8, 9
        
        // Space for result at offset 0x103C
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    
    engine.mem_write(0x1000, &code).unwrap();
    engine.reg_write(Register::RIP, 0x1000);
    
    // Execute instructions (3 instructions * 8 bytes = 0x18)
    match engine.emu_start(0x1000, 0x1000 + 0x18, 0, 0) {
        Ok(_) => {},
        Err(e) => panic!("Execution failed: {:?}", e),
    }
    
    // Check result
    // The final movdqa stores to [rip + 0x24]
    // When executed at 0x1010, the next RIP is 0x1018
    // So it stores to 0x1018 + 0x24 = 0x103C
    let mut result = vec![0u8; 16];
    engine.mem_read(0x103C, &mut result).unwrap();
    
    // Expected results
    assert_eq!(u16::from_le_bytes([result[0], result[1]]), 20);   // 10 * 2 = 20
    assert_eq!(u16::from_le_bytes([result[2], result[3]]), 60);   // 20 * 3 = 60
    assert_eq!(u16::from_le_bytes([result[4], result[5]]), 120);  // 30 * 4 = 120
    assert_eq!(u16::from_le_bytes([result[6], result[7]]), 200);  // 40 * 5 = 200
    assert_eq!(u16::from_le_bytes([result[8], result[9]]), 300);  // 50 * 6 = 300
    assert_eq!(u16::from_le_bytes([result[10], result[11]]), 420); // 60 * 7 = 420
    assert_eq!(u16::from_le_bytes([result[12], result[13]]), 560); // 70 * 8 = 560
    assert_eq!(u16::from_le_bytes([result[14], result[15]]), 720); // 80 * 9 = 720
}