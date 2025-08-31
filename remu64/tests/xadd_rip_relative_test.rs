use remu64::{Engine, EngineMode, Permission, Register, memory::MemoryTrait as _};

#[test]
fn test_xadd_rip_relative_addressing_bug() {
    // This test catches the specific bug where read_operand and write_operand
    // had different address calculation logic for RIP-relative addressing
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory for code and data
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    engine
        .memory
        .map(0x4295000, 0x1000, Permission::ALL)
        .unwrap();

    // Set up initial values
    engine.reg_write(Register::RAX, 0x11111111);

    // Write initial value to target memory location
    // RIP-relative displacement 0x04294771 + RIP (0x1008) = 0x4295779
    let target_addr = 0x4295779u64;
    let target_value: u32 = 0x22222222;
    engine
        .memory
        .write(target_addr, &target_value.to_le_bytes())
        .unwrap();

    // LOCK XADD [RIP + displacement], EAX - the exact failing instruction pattern
    // f0 0f c1 05 71 47 29 04
    let code = vec![
        0xF0, 0x0F, 0xC1, 0x05, // LOCK XADD [RIP + disp32], EAX
        0x71, 0x47, 0x29, 0x04, // displacement
    ];

    engine.memory.write(0x1000, &code).unwrap();

    // Execute the instruction - this would fail with "unmapped page" before the fix
    // because read_operand and write_operand calculated different addresses
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Verify the exchange and add happened correctly:
    // - EAX should now contain the original memory value (0x22222222)
    // - Memory should contain the sum (0x11111111 + 0x22222222 = 0x33333333)
    assert_eq!(engine.reg_read(Register::RAX), 0x22222222);

    let mut buf = [0u8; 4];
    engine.memory.read(target_addr, &mut buf).unwrap();
    let memory_value = u32::from_le_bytes(buf);
    assert_eq!(memory_value, 0x33333333);
}
