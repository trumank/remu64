use remu64::{Engine, EngineMode, Permission, Register, memory::MemoryTrait};

fn main() {
    let mut engine = Engine::new(EngineMode::Mode64);

    engine.memory.map(0x1000, 0x2000, Permission::ALL).unwrap();

    let code = vec![
        0xb8, 0x00, 0x00, 0x00, 0x80, // mov eax, 0x80000000 (little-endian)
        0xbb, 0x00, 0x00, 0x00, 0x00, // mov ebx, 0x00000000
        0x0f, 0xa4, 0xd8, 0x01, // shld eax, ebx, 1
    ];

    engine.memory.write(0x1000, &code).unwrap();

    // Check flags before execution
    println!(
        "Before: CF = {}",
        engine.flags_read().contains(remu64::cpu::Flags::CF)
    );
    println!("Initial EAX = {:#x}", engine.reg_read(Register::EAX));

    // Execute just the first two MOV instructions
    engine.emu_start(0x1000, 0x100a, 0, 0).unwrap();

    // Check that MOV worked
    println!(
        "After MOVs (before SHLD): EAX = {:#x}, EBX = {:#x}",
        engine.reg_read(Register::EAX),
        engine.reg_read(Register::EBX)
    );

    // Now execute SHLD
    engine
        .emu_start(0x100a, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    println!(
        "After SHLD: EAX = {:#x}, EBX = {:#x}",
        engine.reg_read(Register::EAX),
        engine.reg_read(Register::EBX)
    );

    // The MSB (bit 31) of 0x80000000 should be shifted into CF
    println!(
        "After: CF = {}",
        engine.flags_read().contains(remu64::cpu::Flags::CF)
    );
    println!("Final EAX = {:#x}", engine.reg_read(Register::EAX));

    // Test SHRD as well
    engine.reg_write(Register::RIP, 0x2000);

    let code2 = vec![
        0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 0x00000001
        0xbb, 0x00, 0x00, 0x00, 0x00, // mov ebx, 0x00000000
        0x0f, 0xac, 0xd8, 0x01, // shrd eax, ebx, 1
    ];

    engine.memory.write(0x2000, &code2).unwrap();

    println!("\n--- SHRD Test ---");
    println!(
        "Before: CF = {}",
        engine.flags_read().contains(remu64::cpu::Flags::CF)
    );
    println!("Initial EAX = {:#x}", engine.reg_read(Register::EAX));

    engine
        .emu_start(0x2000, 0x2000 + code2.len() as u64, 0, 0)
        .unwrap();

    println!(
        "After: CF = {}",
        engine.flags_read().contains(remu64::cpu::Flags::CF)
    );
    println!("Final EAX = {:#x}", engine.reg_read(Register::EAX));
}
