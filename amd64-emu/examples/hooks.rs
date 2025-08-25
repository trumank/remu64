use amd64_emu::{Engine, EngineMode, HookManager, HookType, Permission, Register};
use std::sync::{Arc, Mutex};

fn main() {
    env_logger::init();

    let mut engine = Engine::new(EngineMode::Mode64);
    let mut hooks = HookManager::new();

    engine.set_trace(true);

    engine.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();
    engine
        .mem_map(0x2000, 0x1000, Permission::READ | Permission::WRITE)
        .unwrap();

    let code = vec![
        0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, 0x48, 0x89, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00,
        0x48, 0xC7, 0xC0, 0x02, 0x00, 0x00, 0x00, 0x48, 0x89, 0x04, 0x25, 0x08, 0x20, 0x00, 0x00,
        0x48, 0x8B, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, 0x48, 0x03, 0x04, 0x25, 0x08, 0x20, 0x00,
        0x00,
    ];

    engine.mem_write(0x1000, &code).unwrap();

    let code_hook_count = Arc::new(Mutex::new(0));
    let code_hook_clone = code_hook_count.clone();

    hooks.add_hook(HookType::Code, 0x1000, 0x2000, move |cpu, addr, size| {
        let mut count = code_hook_clone.lock().unwrap();
        *count += 1;
        println!(
            "[CODE] Executing instruction at {:#x} (size: {} bytes)",
            addr, size
        );
        println!("  RAX = {:#x}", cpu.read_reg(Register::RAX));
        Ok(())
    });

    let mem_write_count = Arc::new(Mutex::new(Vec::new()));
    let mem_write_clone = mem_write_count.clone();

    hooks.add_hook(
        HookType::MemWrite,
        0x2000,
        0x3000,
        move |_cpu, addr, size| {
            mem_write_clone.lock().unwrap().push((addr, size));
            println!("[MEM WRITE] Writing {} bytes to {:#x}", size, addr);
            Ok(())
        },
    );

    let mem_read_count = Arc::new(Mutex::new(Vec::new()));
    let mem_read_clone = mem_read_count.clone();

    hooks.add_hook(
        HookType::MemRead,
        0x2000,
        0x3000,
        move |_cpu, addr, size| {
            mem_read_clone.lock().unwrap().push((addr, size));
            println!("[MEM READ] Reading {} bytes from {:#x}", size, addr);
            Ok(())
        },
    );

    println!("\nStarting emulation with hooks...\n");
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0, Some(&mut hooks))
        .unwrap();

    let rax = engine.reg_read(Register::RAX).unwrap();
    println!("\n=== Emulation Results ===");
    println!("Final RAX value: {:#x}", rax);
    println!(
        "Code hook executed {} times",
        *code_hook_count.lock().unwrap()
    );
    println!("Memory writes: {:?}", *mem_write_count.lock().unwrap());
    println!("Memory reads: {:?}", *mem_read_count.lock().unwrap());

    assert_eq!(rax, 3);
    println!("\nResult verified: 1 + 2 = {}", rax);
}
