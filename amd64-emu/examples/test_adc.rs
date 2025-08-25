use amd64_emu::{Engine, EngineMode, Permission, Register};

fn main() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test ADC AL, imm8 - check if 0x14 opcode is decoded
    let code = vec![
        0xB0, 0x05, // mov al, 5
        0x14, 0x03, // adc al, 3
    ];

    engine.mem_write(0x1000, &code).unwrap();

    match engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0) {
        Ok(()) => {
            let result = engine.reg_read(Register::RAX).unwrap() & 0xFF;
            println!("ADC AL, imm8 test:");
            println!("Result: AL = {:#x}", result);
            println!("Expected: AL = 0x8 (5 + 3, no carry)");
        }
        Err(e) => {
            println!("Error executing ADC AL, imm8: {:?}", e);
        }
    }
}
