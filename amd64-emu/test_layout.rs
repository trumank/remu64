fn main() {
    // Test PMULLW with memory operand - analyze memory layout
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
    
    println!("Memory layout when code is written to 0x1000:");
    println!("0x1000-0x1007: movdqa xmm0, [rip + 0x14]");
    println!("0x1008-0x100F: pmullw xmm0, [rip + 0x1C]");
    println!("0x1010-0x1017: movdqa [rip + 0x24], xmm0");
    println!("0x1018-0x101B: (next 4 bytes after instructions)");
    
    let offset = 0x18;
    println!("\nData starts at offset 0x{:02X} from code start:", offset);
    println!("0x10{:02X}-0x10{:02X}: XMM0 initial data (10,20,30,40,50,60,70,80)", 
             0x00 + offset, 0x00 + offset + 0x0F);
    println!("0x10{:02X}-0x10{:02X}: Multiplier data (2,3,4,5,6,7,8,9)", 
             0x00 + offset + 0x10, 0x00 + offset + 0x1F);
    println!("0x10{:02X}-0x10{:02X}: Result space", 
             0x00 + offset + 0x20, 0x00 + offset + 0x2F);
    
    println!("\nBut wait, the code comments say:");
    println!("  '// Data at offset 0x101C: XMM0 initial value'");
    println!("  '// Data at offset 0x102C: Memory operand (multipliers)'");
    println!("  '// Space for result at offset 0x103C'");
    
    println!("\nThese comments are WRONG! The actual offsets are:");
    println!("  XMM0 data is at 0x1018 (offset 0x18), not 0x101C");
    println!("  Multipliers are at 0x1028 (offset 0x28), not 0x102C");
    println!("  Result space is at 0x1038 (offset 0x38), not 0x103C");
    
    println!("\nSo when instruction 1 loads from [rip + 0x14] at RIP=0x1008:");
    println!("  It loads from 0x1008 + 0x14 = 0x101C");
    println!("  But the data is actually at 0x1018!");
    println!("  This is a 4-byte offset error!");
    
    println!("\nTo fix, we need to adjust the displacements:");
    println!("  Instruction 1: [rip + 0x10] to load from 0x1018");
    println!("  Instruction 2: [rip + 0x18] to load from 0x1028");  
    println!("  Instruction 3: [rip + 0x20] to store to 0x1038");
}