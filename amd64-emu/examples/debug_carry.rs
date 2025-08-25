use amd64_emu::{Engine, EngineMode, Permission, Register};

fn main() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code
    engine.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test if carry flag is set correctly for 8-bit ADD
    let code = vec![
        0xB0, 0xFF, // mov al, 0xFF
        0x04, 0x01, // add al, 1 (should set carry)
    ];

    engine.mem_write(0x1000, &code).unwrap();

    match engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0) {
        Ok(()) => {
            let al = engine.reg_read(Register::RAX).unwrap() & 0xFF;
            let flags = engine.reg_read(Register::RFLAGS).unwrap();
            let carry = (flags & 1) != 0; // CF is bit 0

            println!("After ADD AL(0xFF), 1:");
            println!("AL = {:#x} (expected 0x00)", al);
            println!("Carry Flag = {} (expected true)", carry);
        }
        Err(e) => {
            println!("Error: {:?}", e);
        }
    }
}
