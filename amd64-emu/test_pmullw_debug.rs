use amd64_emu::{Engine, EngineMode, Permission, Register};
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic};

fn main() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory
    engine.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Simple test: Load values and multiply
    let code = vec![
        // Initialize XMM0 with [2,2,2,2,2,2,2,2]
        0x66, 0x0F, 0x6F, 0x05, 0x10, 0x00, 0x00, 0x00,  // movdqa xmm0, [rip + 0x10]
        // Initialize XMM1 with [3,3,3,3,3,3,3,3] 
        0x66, 0x0F, 0x6F, 0x0D, 0x18, 0x00, 0x00, 0x00,  // movdqa xmm1, [rip + 0x18]
        // PMULLW xmm0, xmm1
        0x66, 0x0F, 0xD5, 0xC1,  // pmullw xmm0, xmm1
        // Halt
        0xF4,  // hlt
        
        // Padding
        0x90, 0x90, 0x90,
        
        // Data at offset 0x1018: XMM0 initial value (8 words of 2)
        0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00,
        0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00,
        
        // Data at offset 0x1028: XMM1 initial value (8 words of 3)
        0x03, 0x00, 0x03, 0x00, 0x03, 0x00, 0x03, 0x00,
        0x03, 0x00, 0x03, 0x00, 0x03, 0x00, 0x03, 0x00,
    ];
    
    // Check the PMULLW instruction encoding
    let pmullw_bytes = &code[0x10..0x14];
    println!("PMULLW bytes: {:02X} {:02X} {:02X} {:02X}", 
             pmullw_bytes[0], pmullw_bytes[1], pmullw_bytes[2], pmullw_bytes[3]);
    
    // Decode it
    let mut decoder = Decoder::new(64, pmullw_bytes, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    decoder.decode_out(&mut instruction);
    
    println!("Decoded mnemonic: {:?}", instruction.mnemonic());
    println!("Op0: {:?}", instruction.op0_kind());
    println!("Op1: {:?}", instruction.op1_kind());
    
    engine.mem_write(0x1000, &code).unwrap();
    engine.reg_write(Register::RIP, 0x1000);
    
    // Execute up to PMULLW
    match engine.emu_start(0x1000, 0x1000 + 0x14, 0, 0) {
        Ok(_) => println!("Execution succeeded"),
        Err(e) => println!("Execution failed: {:?}", e),
    }
    
    // Check XMM0
    println!("\nReading XMM0 value...");
    let xmm0_val = engine.reg_read(Register::XMM0);
    
    println!("XMM0 raw: 0x{:032X}", xmm0_val);
    
    // Extract first word
    let word0 = (xmm0_val & 0xFFFF) as u16;
    println!("First word of XMM0: {} (expected: 6)", word0);
}