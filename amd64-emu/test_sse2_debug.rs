use amd64_emu::{Engine, EngineMode, Permission, Register};

fn main() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory
    engine.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Test PMULLW - simple test case first
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
    
    // Debug: Write the code and data to memory
    engine.mem_write(0x1000, &code).unwrap();
    engine.reg_write(Register::RIP, 0x1000);
    
    // Debug: Check what we wrote at 0x101C (XMM0 data)
    let mut xmm0_data = vec![0u8; 16];
    engine.mem_read(0x101C, &mut xmm0_data).unwrap();
    println!("XMM0 data at 0x101C:");
    for i in 0..8 {
        let word = u16::from_le_bytes([xmm0_data[i*2], xmm0_data[i*2+1]]);
        print!("0x{:04x} ", word);
    }
    println!();
    
    // Debug: Check XMM1 data at 0x102C
    let mut xmm1_data = vec![0u8; 16];
    engine.mem_read(0x102C, &mut xmm1_data).unwrap();
    println!("XMM1 data at 0x102C:");
    for i in 0..8 {
        let word = u16::from_le_bytes([xmm1_data[i*2], xmm1_data[i*2+1]]);
        print!("0x{:04x} ", word);
    }
    println!();
    
    // Execute the first movdqa instruction
    match engine.emu_start(0x1000, 0x1008, 0, 0) {
        Ok(_) => println!("First movdqa executed successfully"),
        Err(e) => println!("Error executing first movdqa: {:?}", e),
    }
    
    // Check XMM0 value
    let xmm0 = engine.reg_read(Register::XMM0);
    println!("XMM0 after first movdqa: 0x{:032x}", xmm0);
    
    // Execute the second movdqa instruction
    match engine.emu_start(0x1008, 0x1010, 0, 0) {
        Ok(_) => println!("Second movdqa executed successfully"),
        Err(e) => println!("Error executing second movdqa: {:?}", e),
    }
    
    // Check XMM1 value
    let xmm1 = engine.reg_read(Register::XMM1);
    println!("XMM1 after second movdqa: 0x{:032x}", xmm1);
    
    // Execute PMULLW instruction
    match engine.emu_start(0x1010, 0x1014, 0, 0) {
        Ok(_) => println!("PMULLW executed successfully"),
        Err(e) => println!("Error executing PMULLW: {:?}", e),
    }
    
    // Check XMM0 result
    let xmm0_result = engine.reg_read(Register::XMM0);
    println!("XMM0 after PMULLW: 0x{:032x}", xmm0_result);
    
    // Execute final movdqa to store result
    match engine.emu_start(0x1014, 0x101C, 0, 0) {
        Ok(_) => println!("Final movdqa executed successfully"),
        Err(e) => println!("Error executing final movdqa: {:?}", e),
    }
    
    // Check result in memory
    let mut result = vec![0u8; 16];
    engine.mem_read(0x103C, &mut result).unwrap();
    
    println!("\nResults at 0x103C:");
    for i in 0..8 {
        let word = u16::from_le_bytes([result[i*2], result[i*2+1]]);
        let expected = match i {
            0 => 6u16,      // 2 * 3 = 6
            1 => 20u16,     // 4 * 5 = 20
            2 => 56u16,     // 8 * 7 = 56
            3 => 144u16,    // 16 * 9 = 144
            4 => 0xFFFEu16, // -1 * 2 = -2
            5 => 0xFFF8u16, // -2 * 4 = -8
            6 => 0u16,      // -32768 * 2 = -65536 (overflow, low 16 bits = 0)
            7 => 0x8000u16, // 16384 * 2 = 32768
            _ => 0,
        };
        println!("  Word {}: 0x{:04x} (expected: 0x{:04x}) {}", 
                 i, word, expected, 
                 if word == expected { "✓" } else { "✗" });
    }
}