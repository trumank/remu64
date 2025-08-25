use amd64_emu::{Engine, EngineMode, Register, Permission};

fn main() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory for code
    engine.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Test ADC AL, imm8
    let code = vec![
        0xB0, 0x05,                                // mov al, 5
        0xF9,                                      // stc (set carry flag)
        0x14, 0x03,                                // adc al, 3
    ];
    
    engine.mem_write(0x1000, &code).unwrap();
    engine.set_trace(true);
    
    match engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0, None) {
        Ok(()) => {
            let result = engine.reg_read(Register::RAX).unwrap() & 0xFF;
            println!("Result: AL = {}", result);
            println!("Expected: AL = 9 (5 + 3 + 1)");
        }
        Err(e) => {
            println!("Error: {:?}", e);
        }
    }
}