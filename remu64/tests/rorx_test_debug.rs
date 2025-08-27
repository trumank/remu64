use remu64::{Engine, EngineMode, Permission, Register, memory::MemoryTrait};

fn main() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x2000, Permission::ALL).unwrap();
    
    // Test basic rotation: rotate 0x12345678 right by 4 bits
    // Expected: 0x81234567
    let code = vec![
        0x48, 0xC7, 0xC0, 0x78, 0x56, 0x34, 0x12,  // mov rax, 0x12345678
        0xC4, 0xE3, 0xFB, 0xF0, 0xD8, 0x04,        // rorx rbx, rax, 4 
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    
    println!("Before execution:");
    println!("RAX: 0x{:016x}", engine.reg_read(Register::RAX));
    println!("RBX: 0x{:016x}", engine.reg_read(Register::RBX));
    
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    println!("\nAfter execution:");
    println!("RAX: 0x{:016x}", engine.reg_read(Register::RAX));
    println!("RBX: 0x{:016x}", engine.reg_read(Register::RBX));
    
    // Manual calculation
    let src = 0x12345678u64;
    let result = src.rotate_right(4);
    println!("\nExpected RBX: 0x{:016x}", result);
    println!("Expected (32-bit): 0x{:016x}", (0x12345678u32).rotate_right(4) as u64);
}