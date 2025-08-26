use amd64_emu::{Engine, EngineMode, Permission, Register};

#[test]
fn test_debug_pmullw_memory() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory
    engine.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Simplified test code
    let code = vec![
        // Initialize XMM0 with test values
        0x66, 0x0F, 0x6F, 0x05, 0x14, 0x00, 0x00, 0x00,  // movdqa xmm0, [rip + 0x14]
        // PMULLW xmm0, [rip + 0x1C] - multiply with memory operand
        0x66, 0x0F, 0xD5, 0x05, 0x1C, 0x00, 0x00, 0x00,  // pmullw xmm0, [rip + 0x1C]
        // Move result to memory for checking
        0x66, 0x0F, 0x7F, 0x05, 0x20, 0x00, 0x00, 0x00,  // movdqa [rip + 0x20], xmm0
        
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

    // Execute first instruction - load XMM0
    match engine.emu_start(0x1000, 0x1008, 0, 0) {
        Ok(_) => {},
        Err(e) => panic!("Failed to execute movdqa: {:?}", e),
    }
    
    // Check XMM0 after first load
    println!("XMM0 after first movdqa:");
    println!("  (Debug: Cannot directly read XMM register as int in current implementation)");

    // Execute PMULLW with memory operand
    match engine.emu_start(0x1008, 0x1010, 0, 0) {
        Ok(_) => {},
        Err(e) => panic!("Failed to execute pmullw: {:?}", e),
    }
    
    // Check XMM0 after multiplication (skip for now)
    println!("\nXMM0 after PMULLW: (skipped direct register read)");

    // Execute final movdqa to store result
    match engine.emu_start(0x1010, 0x1018, 0, 0) {
        Ok(_) => {},
        Err(e) => panic!("Failed to execute final movdqa: {:?}", e),
    }
    
    // Check result in memory
    let mut result = vec![0u8; 16];
    engine.mem_read(0x103C, &mut result).unwrap();
    
    println!("\nResult stored at 0x103C:");
    for i in 0..8 {
        let word = u16::from_le_bytes([result[i*2], result[i*2+1]]);
        let expected = match i {
            0 => 20,   // 10 * 2
            1 => 60,   // 20 * 3
            2 => 120,  // 30 * 4
            3 => 200,  // 40 * 5
            4 => 300,  // 50 * 6
            5 => 420,  // 60 * 7
            6 => 560,  // 70 * 8
            7 => 720,  // 80 * 9
            _ => 0,
        };
        println!("  Word {}: {} (expected: {}) {}", 
                 i, word, expected,
                 if word == expected { "✓" } else { "✗" });
    }
}