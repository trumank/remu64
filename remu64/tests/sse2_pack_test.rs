use remu64::{memory::MemoryTrait as _, Engine, EngineMode, Permission, Register};

#[test]
fn test_packsswb() {
    let mut emu = Engine::new(EngineMode::Mode64);

    // Test basic PACKSSWB operation
    let code = vec![
        // movdqa xmm0, [rsp]
        0x66, 0x0F, 0x6F, 0x04, 0x24, // movdqa xmm1, [rsp+16]
        0x66, 0x0F, 0x6F, 0x4C, 0x24, 0x10, // packsswb xmm0, xmm1
        0x66, 0x0F, 0x63, 0xC1,
    ];

    emu.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    emu.memory.map(0x100000, 0x1000, Permission::ALL).unwrap();
    emu.memory.write(0x1000, &code).unwrap();
    emu.reg_write(Register::RIP, 0x1000);
    emu.reg_write(Register::RSP, 0x100400);

    // Set up test data - words to pack
    // xmm0: 0x007F, 0x0100, 0xFF80, 0xFE00, 0x0020, 0xFFE0, 0x0040, 0x7FFF
    let xmm0_data = vec![
        0x7F, 0x00, // 0x007F (127)
        0x00, 0x01, // 0x0100 (256) -> saturate to 127
        0x80, 0xFF, // 0xFF80 (-128)
        0x00, 0xFE, // 0xFE00 (-512) -> saturate to -128
        0x20, 0x00, // 0x0020 (32)
        0xE0, 0xFF, // 0xFFE0 (-32)
        0x40, 0x00, // 0x0040 (64)
        0xFF, 0x7F, // 0x7FFF (32767) -> saturate to 127
    ];

    // xmm1: 0x0010, 0xFFF0, 0x0000, 0xFFFF, 0x0050, 0xFF50, 0x0001, 0x8000
    let xmm1_data = vec![
        0x10, 0x00, // 0x0010 (16)
        0xF0, 0xFF, // 0xFFF0 (-16)
        0x00, 0x00, // 0x0000 (0)
        0xFF, 0xFF, // 0xFFFF (-1)
        0x50, 0x00, // 0x0050 (80)
        0x50, 0xFF, // 0xFF50 (-176) -> saturate to -128
        0x01, 0x00, // 0x0001 (1)
        0x00, 0x80, // 0x8000 (-32768) -> saturate to -128
    ];

    emu.memory.write(0x100400, &xmm0_data).unwrap();
    emu.memory.write(0x100410, &xmm1_data).unwrap();

    // Execute instructions
    emu.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 3)
        .unwrap(); // packsswb

    let result = emu.xmm_read(Register::XMM0);

    // Expected: packed bytes from xmm0 (low) and xmm1 (high)
    // xmm0 -> 0x7F, 0x7F, 0x80, 0x80, 0x20, 0xE0, 0x40, 0x7F
    // xmm1 -> 0x10, 0xF0, 0x00, 0xFF, 0x50, 0x80, 0x01, 0x80
    let expected = (0x7Fu128
        | (0x7Fu128 << 8)
        | (0x80u128 << 16)
        | (0x80u128 << 24)
        | (0x20u128 << 32)
        | (0xE0u128 << 40)
        | (0x40u128 << 48)
        | (0x7Fu128 << 56)
        | (0x10u128 << 64)
        | (0xF0u128 << 72))
        | (0xFFu128 << 88)
        | (0x50u128 << 96)
        | (0x80u128 << 104)
        | (0x01u128 << 112)
        | (0x80u128 << 120);

    assert_eq!(
        result, expected,
        "PACKSSWB failed: got {:#034x}, expected {:#034x}",
        result, expected
    );
}

#[test]
fn test_packuswb() {
    let mut emu = Engine::new(EngineMode::Mode64);

    // Test basic PACKUSWB operation
    let code = vec![
        // movdqa xmm0, [rsp]
        0x66, 0x0F, 0x6F, 0x04, 0x24, // movdqa xmm1, [rsp+16]
        0x66, 0x0F, 0x6F, 0x4C, 0x24, 0x10, // packuswb xmm0, xmm1
        0x66, 0x0F, 0x67, 0xC1,
    ];

    emu.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    emu.memory.map(0x100000, 0x1000, Permission::ALL).unwrap();
    emu.memory.write(0x1000, &code).unwrap();
    emu.reg_write(Register::RIP, 0x1000);
    emu.reg_write(Register::RSP, 0x100400);

    // Set up test data - signed words to pack as unsigned bytes
    // xmm0: 0x00FF, 0x0100, 0xFF80, 0x0000, 0x0080, 0xFFFE, 0x00FE, 0x7FFF
    let xmm0_data = vec![
        0xFF, 0x00, // 0x00FF (255)
        0x00, 0x01, // 0x0100 (256) -> saturate to 255
        0x80, 0xFF, // 0xFF80 (-128) -> saturate to 0
        0x00, 0x00, // 0x0000 (0)
        0x80, 0x00, // 0x0080 (128)
        0xFE, 0xFF, // 0xFFFE (-2) -> saturate to 0
        0xFE, 0x00, // 0x00FE (254)
        0xFF, 0x7F, // 0x7FFF (32767) -> saturate to 255
    ];

    // xmm1: 0x0001, 0xFFFF, 0x0100, 0x0000, 0x0050, 0x8000, 0x00C8, 0x0200
    let xmm1_data = vec![
        0x01, 0x00, // 0x0001 (1)
        0xFF, 0xFF, // 0xFFFF (-1) -> saturate to 0
        0x00, 0x01, // 0x0100 (256) -> saturate to 255
        0x00, 0x00, // 0x0000 (0)
        0x50, 0x00, // 0x0050 (80)
        0x00, 0x80, // 0x8000 (-32768) -> saturate to 0
        0xC8, 0x00, // 0x00C8 (200)
        0x00, 0x02, // 0x0200 (512) -> saturate to 255
    ];

    emu.memory.write(0x100400, &xmm0_data).unwrap();
    emu.memory.write(0x100410, &xmm1_data).unwrap();

    // Execute instructions
    emu.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 3)
        .unwrap(); // packuswb

    let result = emu.xmm_read(Register::XMM0);

    // Expected: unsigned bytes from xmm0 (low) and xmm1 (high)
    // xmm0 -> 0xFF, 0xFF, 0x00, 0x00, 0x80, 0x00, 0xFE, 0xFF
    // xmm1 -> 0x01, 0x00, 0xFF, 0x00, 0x50, 0x00, 0xC8, 0xFF
    let expected = (((0xFFu128 | (0xFFu128 << 8)) | (0x80u128 << 32))
        | (0xFEu128 << 48)
        | (0xFFu128 << 56)
        | (0x01u128 << 64))
        | (0xFFu128 << 80)
        | (0x00u128 << 88)
        | (0x50u128 << 96)
        | (0x00u128 << 104)
        | (0xC8u128 << 112)
        | (0xFFu128 << 120);

    assert_eq!(
        result, expected,
        "PACKUSWB failed: got {:#034x}, expected {:#034x}",
        result, expected
    );
}

#[test]
fn test_packssdw() {
    let mut emu = Engine::new(EngineMode::Mode64);

    // Test basic PACKSSDW operation
    let code = vec![
        // movdqa xmm0, [rsp]
        0x66, 0x0F, 0x6F, 0x04, 0x24, // movdqa xmm1, [rsp+16]
        0x66, 0x0F, 0x6F, 0x4C, 0x24, 0x10, // packssdw xmm0, xmm1
        0x66, 0x0F, 0x6B, 0xC1,
    ];

    emu.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    emu.memory.map(0x100000, 0x1000, Permission::ALL).unwrap();
    emu.memory.write(0x1000, &code).unwrap();
    emu.reg_write(Register::RIP, 0x1000);
    emu.reg_write(Register::RSP, 0x100400);

    // Set up test data - doublewords to pack as signed words
    // xmm0: 0x00007FFF, 0x00010000, 0xFFFF8000, 0xFFFE0000
    let xmm0_data = vec![
        0xFF, 0x7F, 0x00, 0x00, // 0x00007FFF (32767)
        0x00, 0x00, 0x01, 0x00, // 0x00010000 (65536) -> saturate to 32767
        0x00, 0x80, 0xFF, 0xFF, // 0xFFFF8000 (-32768)
        0x00, 0x00, 0xFE, 0xFF, // 0xFFFE0000 (-131072) -> saturate to -32768
    ];

    // xmm1: 0x00001000, 0xFFFFF000, 0x00000000, 0x80000000
    let xmm1_data = vec![
        0x00, 0x10, 0x00, 0x00, // 0x00001000 (4096)
        0x00, 0xF0, 0xFF, 0xFF, // 0xFFFFF000 (-4096)
        0x00, 0x00, 0x00, 0x00, // 0x00000000 (0)
        0x00, 0x00, 0x00, 0x80, // 0x80000000 (-2147483648) -> saturate to -32768
    ];

    emu.memory.write(0x100400, &xmm0_data).unwrap();
    emu.memory.write(0x100410, &xmm1_data).unwrap();

    // Execute instructions
    emu.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 3)
        .unwrap(); // packssdw

    let result = emu.xmm_read(Register::XMM0);

    // Expected: signed words from xmm0 (low) and xmm1 (high)
    // xmm0 -> 0x7FFF, 0x7FFF, 0x8000, 0x8000
    // xmm1 -> 0x1000, 0xF000, 0x0000, 0x8000
    let expected = (0x7FFFu128
        | (0x7FFFu128 << 16)
        | (0x8000u128 << 32)
        | (0x8000u128 << 48)
        | (0x1000u128 << 64)
        | (0xF000u128 << 80))
        | (0x8000u128 << 112);

    assert_eq!(
        result, expected,
        "PACKSSDW failed: got {:#034x}, expected {:#034x}",
        result, expected
    );
}

#[test]
fn test_pack_memory_operand() {
    let mut emu = Engine::new(EngineMode::Mode64);

    // Test pack instruction with memory operand
    let code = vec![
        // movdqa xmm0, [rsp]
        0x66, 0x0F, 0x6F, 0x04, 0x24, // packsswb xmm0, [rsp+16]
        0x66, 0x0F, 0x63, 0x44, 0x24, 0x10,
    ];

    emu.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    emu.memory.map(0x100000, 0x1000, Permission::ALL).unwrap();
    emu.memory.write(0x1000, &code).unwrap();
    emu.reg_write(Register::RIP, 0x1000);
    emu.reg_write(Register::RSP, 0x100400);

    // Set up test data
    let xmm0_data = vec![
        0x10, 0x00, 0x20, 0x00, 0x30, 0x00, 0x40, 0x00, 0x50, 0x00, 0x60, 0x00, 0x70, 0x00, 0x7F,
        0x00,
    ];
    let mem_data = vec![
        0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08,
        0x00,
    ];

    emu.memory.write(0x100400, &xmm0_data).unwrap();
    emu.memory.write(0x100410, &mem_data).unwrap();

    // Execute instructions
    emu.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 2)
        .unwrap();

    let result = emu.xmm_read(Register::XMM0);

    // Verify result contains packed bytes from both operands
    let expected = 0x10u128
        | (0x20u128 << 8)
        | (0x30u128 << 16)
        | (0x40u128 << 24)
        | (0x50u128 << 32)
        | (0x60u128 << 40)
        | (0x70u128 << 48)
        | (0x7Fu128 << 56)
        | (0x01u128 << 64)
        | (0x02u128 << 72)
        | (0x03u128 << 80)
        | (0x04u128 << 88)
        | (0x05u128 << 96)
        | (0x06u128 << 104)
        | (0x07u128 << 112)
        | (0x08u128 << 120);

    assert_eq!(
        result, expected,
        "PACKSSWB with memory failed: got {:#034x}, expected {:#034x}",
        result, expected
    );
}
