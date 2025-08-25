use amd64_emu::{Engine, EngineMode, Register, Permission};

fn main() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    let code = [
        0x0F, 0x28, 0xC1,  // movaps xmm0, xmm1
    ];
    
    let base = 0x1000;
    engine.mem_map(base, 0x1000, Permission::READ | Permission::EXEC).unwrap();
    engine.mem_write(base, &code).unwrap();
    
    // Set XMM1 to a test value
    let test_value = 0x0123456789ABCDEF0123456789ABCDEFu128;
    
    // For now just test that the instruction doesn't crash
    println!("Before execution:");
    println!("RIP: {:#x}", engine.reg_read(Register::RIP).unwrap());
    
    engine.reg_write(Register::RIP, base).unwrap();
    let result = engine.emu_start(base, base + code.len() as u64, 0, 0);
    
    println!("Execute result: {:?}", result);
    println!("After execution:");
    println!("RIP: {:#x}", engine.reg_read(Register::RIP).unwrap());
}