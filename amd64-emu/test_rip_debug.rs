use amd64_emu::{Engine, EngineMode, Permission, Register};

fn main() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory
    engine.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Test RIP-relative addressing
    // PMULLW xmm0, [rip + 0x1C] at address 0x1008
    let code = vec![
        // Initialize XMM0 with test values (0x1000-0x1007)
        0x66, 0x0F, 0x6F, 0x05, 0x14, 0x00, 0x00, 0x00,  // movdqa xmm0, [rip + 0x14]
        // PMULLW xmm0, [rip + 0x1C] (0x1008-0x100F)
        0x66, 0x0F, 0xD5, 0x05, 0x1C, 0x00, 0x00, 0x00,  // pmullw xmm0, [rip + 0x1C]
        // Move result to memory for checking (0x1010-0x1017)
        0x66, 0x0F, 0x7F, 0x05, 0x20, 0x00, 0x00, 0x00,  // movdqa [rip + 0x20], xmm0
        // We are now at 0x1018
        
        // XMM0 data should be at 0x101C (rip=0x1008, + 0x14 = 0x101C)
        0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00,  // 1, 2, 3, 4
        0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08, 0x00,  // 5, 6, 7, 8
        
        // Multiplier data should be at 0x102C (when rip=0x1010, + 0x1C = 0x102C)
        // But the instruction at 0x1008 says [rip + 0x1C], so when rip=0x1010 (after instruction), it's 0x102C
        // Wait... when executing at 0x1008, RIP is 0x1008 or 0x1010?
        // x86 uses RIP of NEXT instruction for RIP-relative, so at 0x1008, RIP for calculation is 0x1010
        // So [rip + 0x1C] = 0x1010 + 0x1C = 0x102C
        0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00,  // 2, 2, 2, 2
        0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00,  // 2, 2, 2, 2
        
        // Result location at 0x103C (when rip=0x1018, + 0x20 = 0x1038) 
        // Wait, it should be 0x103C...
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    
    engine.mem_write(0x1000, &code).unwrap();
    engine.reg_write(Register::RIP, 0x1000);
    
    println!("Initial RIP: 0x1000");
    
    // Execute first movdqa: loads from [rip + 0x14] where RIP after instruction = 0x1008
    // So it loads from 0x1008 + 0x14 = 0x101C
    match engine.emu_start(0x1000, 0x1008, 0, 0) {
        Ok(_) => println!("First movdqa executed (should load from 0x101C)"),
        Err(e) => panic!("Error: {:?}", e),
    }
    
    // Check what was loaded
    let mut check = vec![0u8; 16];
    engine.mem_read(0x101C, &mut check).unwrap();
    print!("Data at 0x101C: ");
    for i in 0..8 {
        let word = u16::from_le_bytes([check[i*2], check[i*2+1]]);
        print!("{} ", word);
    }
    println!();
    
    // Execute PMULLW: loads from [rip + 0x1C] where RIP after instruction = 0x1010
    // So it loads from 0x1010 + 0x1C = 0x102C
    println!("\nExecuting PMULLW at 0x1008, should load from 0x102C");
    match engine.emu_start(0x1008, 0x1010, 0, 0) {
        Ok(_) => println!("PMULLW executed"),
        Err(e) => panic!("Error: {:?}", e),
    }
    
    // Check data at expected source
    engine.mem_read(0x102C, &mut check).unwrap();
    print!("Data at 0x102C: ");
    for i in 0..8 {
        let word = u16::from_le_bytes([check[i*2], check[i*2+1]]);
        print!("{} ", word);
    }
    println!();
    
    // Execute final movdqa to store result
    // Stores to [rip + 0x20] where RIP after instruction = 0x1018
    // So it stores to 0x1018 + 0x20 = 0x1038
    println!("\nExecuting final movdqa at 0x1010, should store to 0x1038");
    match engine.emu_start(0x1010, 0x1018, 0, 0) {
        Ok(_) => println!("Final movdqa executed"),
        Err(e) => panic!("Error: {:?}", e),
    }
    
    // Check result at 0x1038
    let mut result = vec![0u8; 16];
    engine.mem_read(0x1038, &mut result).unwrap();
    print!("\nResult at 0x1038: ");
    for i in 0..8 {
        let word = u16::from_le_bytes([result[i*2], result[i*2+1]]);
        let expected = (i + 1) * 2; // Since we multiply (i+1) * 2
        print!("{} (exp: {}) ", word, expected);
    }
    println!();
}