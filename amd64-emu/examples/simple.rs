use amd64_emu::{memory::MemoryTrait as _, Engine, EngineMode, Permission, Register};

fn main() {
    let mut engine = Engine::new(EngineMode::Mode64);

    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    let code = vec![
        0x48, 0xC7, 0xC0, 0x37, 0x13, 0x00, 0x00, 0x48, 0xC7, 0xC3, 0x42, 0x00, 0x00, 0x00, 0x48,
        0x01, 0xD8,
    ];

    println!("Writing {} bytes of code to 0x1000", code.len());
    engine.memory.write(0x1000, &code).unwrap();

    println!("Starting emulation...");
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    let rax = engine.reg_read(Register::RAX);
    let rbx = engine.reg_read(Register::RBX);

    println!("Emulation complete!");
    println!("RAX = {:#x}", rax);
    println!("RBX = {:#x}", rbx);

    assert_eq!(rax, 0x1337 + 0x42);
    println!("Result verified: {:#x} + {:#x} = {:#x}", 0x1337, 0x42, rax);
}
