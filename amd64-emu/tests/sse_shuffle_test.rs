use amd64_emu::{Engine, EngineMode, Permission, Register};

#[test]
fn test_shufps() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // SHUFPS xmm0, xmm1, 0b11100100 (0xE4)
    // Selects: xmm0[0], xmm0[1], xmm1[2], xmm1[3]
    let code = [
        0x0F, 0xC6, 0xC1, 0xE4, // shufps xmm0, xmm1, 0xE4
    ];

    let base = 0x1000;
    engine
        .mem_map(base, 0x1000, Permission::READ | Permission::EXEC)
        .unwrap();
    engine.mem_write(base, &code).unwrap();

    // Set up test values (4 floats in each XMM register)
    // XMM0 = [1.0, 2.0, 3.0, 4.0]
    // XMM1 = [5.0, 6.0, 7.0, 8.0]
    let mut xmm0_val = 0u128;
    xmm0_val |= (1.0f32.to_bits() as u128) << 0;
    xmm0_val |= (2.0f32.to_bits() as u128) << 32;
    xmm0_val |= (3.0f32.to_bits() as u128) << 64;
    xmm0_val |= (4.0f32.to_bits() as u128) << 96;
    engine.xmm_write(Register::XMM0, xmm0_val);

    let mut xmm1_val = 0u128;
    xmm1_val |= (5.0f32.to_bits() as u128) << 0;
    xmm1_val |= (6.0f32.to_bits() as u128) << 32;
    xmm1_val |= (7.0f32.to_bits() as u128) << 64;
    xmm1_val |= (8.0f32.to_bits() as u128) << 96;
    engine.xmm_write(Register::XMM1, xmm1_val);

    engine.reg_write(Register::RIP, base);
    engine
        .emu_start(base, base + code.len() as u64, 0, 0)
        .unwrap();

    // Check results: 0xE4 = 0b11100100
    // Bits 0-1 (00) = xmm0[0] = 1.0
    // Bits 2-3 (01) = xmm0[1] = 2.0
    // Bits 4-5 (10) = xmm1[2] = 7.0
    // Bits 6-7 (11) = xmm1[3] = 8.0
    // Result should be [1.0, 2.0, 7.0, 8.0]
    let result = engine.xmm_read(Register::XMM0);
    assert_eq!(f32::from_bits((result & 0xFFFFFFFF) as u32), 1.0);
    assert_eq!(f32::from_bits(((result >> 32) & 0xFFFFFFFF) as u32), 2.0);
    assert_eq!(f32::from_bits(((result >> 64) & 0xFFFFFFFF) as u32), 7.0);
    assert_eq!(f32::from_bits(((result >> 96) & 0xFFFFFFFF) as u32), 8.0);
}

#[test]
fn test_unpcklps() {
    let mut engine = Engine::new(EngineMode::Mode64);

    let code = [
        0x0F, 0x14, 0xC1, // unpcklps xmm0, xmm1
    ];

    let base = 0x1000;
    engine
        .mem_map(base, 0x1000, Permission::READ | Permission::EXEC)
        .unwrap();
    engine.mem_write(base, &code).unwrap();

    // Set up test values
    // XMM0 = [1.0, 2.0, 3.0, 4.0]
    // XMM1 = [5.0, 6.0, 7.0, 8.0]
    let mut xmm0_val = 0u128;
    xmm0_val |= (1.0f32.to_bits() as u128) << 0;
    xmm0_val |= (2.0f32.to_bits() as u128) << 32;
    xmm0_val |= (3.0f32.to_bits() as u128) << 64;
    xmm0_val |= (4.0f32.to_bits() as u128) << 96;
    engine.xmm_write(Register::XMM0, xmm0_val);

    let mut xmm1_val = 0u128;
    xmm1_val |= (5.0f32.to_bits() as u128) << 0;
    xmm1_val |= (6.0f32.to_bits() as u128) << 32;
    xmm1_val |= (7.0f32.to_bits() as u128) << 64;
    xmm1_val |= (8.0f32.to_bits() as u128) << 96;
    engine.xmm_write(Register::XMM1, xmm1_val);

    engine.reg_write(Register::RIP, base);
    engine
        .emu_start(base, base + code.len() as u64, 0, 0)
        .unwrap();

    // Check results: UNPCKLPS interleaves low 2 floats
    // Result should be [1.0, 5.0, 2.0, 6.0]
    let result = engine.xmm_read(Register::XMM0);
    assert_eq!(f32::from_bits((result & 0xFFFFFFFF) as u32), 1.0);
    assert_eq!(f32::from_bits(((result >> 32) & 0xFFFFFFFF) as u32), 5.0);
    assert_eq!(f32::from_bits(((result >> 64) & 0xFFFFFFFF) as u32), 2.0);
    assert_eq!(f32::from_bits(((result >> 96) & 0xFFFFFFFF) as u32), 6.0);
}

#[test]
fn test_unpckhps() {
    let mut engine = Engine::new(EngineMode::Mode64);

    let code = [
        0x0F, 0x15, 0xC1, // unpckhps xmm0, xmm1
    ];

    let base = 0x1000;
    engine
        .mem_map(base, 0x1000, Permission::READ | Permission::EXEC)
        .unwrap();
    engine.mem_write(base, &code).unwrap();

    // Set up test values
    // XMM0 = [1.0, 2.0, 3.0, 4.0]
    // XMM1 = [5.0, 6.0, 7.0, 8.0]
    let mut xmm0_val = 0u128;
    xmm0_val |= (1.0f32.to_bits() as u128) << 0;
    xmm0_val |= (2.0f32.to_bits() as u128) << 32;
    xmm0_val |= (3.0f32.to_bits() as u128) << 64;
    xmm0_val |= (4.0f32.to_bits() as u128) << 96;
    engine.xmm_write(Register::XMM0, xmm0_val);

    let mut xmm1_val = 0u128;
    xmm1_val |= (5.0f32.to_bits() as u128) << 0;
    xmm1_val |= (6.0f32.to_bits() as u128) << 32;
    xmm1_val |= (7.0f32.to_bits() as u128) << 64;
    xmm1_val |= (8.0f32.to_bits() as u128) << 96;
    engine.xmm_write(Register::XMM1, xmm1_val);

    engine.reg_write(Register::RIP, base);
    engine
        .emu_start(base, base + code.len() as u64, 0, 0)
        .unwrap();

    // Check results: UNPCKHPS interleaves high 2 floats
    // Result should be [3.0, 7.0, 4.0, 8.0]
    let result = engine.xmm_read(Register::XMM0);
    assert_eq!(f32::from_bits((result & 0xFFFFFFFF) as u32), 3.0);
    assert_eq!(f32::from_bits(((result >> 32) & 0xFFFFFFFF) as u32), 7.0);
    assert_eq!(f32::from_bits(((result >> 64) & 0xFFFFFFFF) as u32), 4.0);
    assert_eq!(f32::from_bits(((result >> 96) & 0xFFFFFFFF) as u32), 8.0);
}

#[test]
fn test_shufpd() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // SHUFPD xmm0, xmm1, 0b01 (0x01)
    // Bit 0 = 1: Select xmm0[1] for result[0]
    // Bit 1 = 0: Select xmm1[0] for result[1]
    let code = [
        0x66, 0x0F, 0xC6, 0xC1, 0x01, // shufpd xmm0, xmm1, 0x01
    ];

    let base = 0x1000;
    engine
        .mem_map(base, 0x1000, Permission::READ | Permission::EXEC)
        .unwrap();
    engine.mem_write(base, &code).unwrap();

    // Set up test values (2 doubles in each XMM register)
    // XMM0 = [1.0, 2.0]
    // XMM1 = [3.0, 4.0]
    let mut xmm0_val = 0u128;
    xmm0_val |= (1.0f64.to_bits() as u128) << 0;
    xmm0_val |= (2.0f64.to_bits() as u128) << 64;
    engine.xmm_write(Register::XMM0, xmm0_val);

    let mut xmm1_val = 0u128;
    xmm1_val |= (3.0f64.to_bits() as u128) << 0;
    xmm1_val |= (4.0f64.to_bits() as u128) << 64;
    engine.xmm_write(Register::XMM1, xmm1_val);

    engine.reg_write(Register::RIP, base);
    engine
        .emu_start(base, base + code.len() as u64, 0, 0)
        .unwrap();

    // Check results: 0x01 = 0b01
    // Bit 0 (1) = xmm0[1] = 2.0
    // Bit 1 (0) = xmm1[0] = 3.0
    // Result should be [2.0, 3.0]
    let result = engine.xmm_read(Register::XMM0);
    assert_eq!(f64::from_bits((result & 0xFFFFFFFFFFFFFFFF) as u64), 2.0);
    assert_eq!(f64::from_bits((result >> 64) as u64), 3.0);
}

#[test]
fn test_unpcklpd() {
    let mut engine = Engine::new(EngineMode::Mode64);

    let code = [
        0x66, 0x0F, 0x14, 0xC1, // unpcklpd xmm0, xmm1
    ];

    let base = 0x1000;
    engine
        .mem_map(base, 0x1000, Permission::READ | Permission::EXEC)
        .unwrap();
    engine.mem_write(base, &code).unwrap();

    // Set up test values (2 doubles in each XMM register)
    // XMM0 = [1.0, 2.0]
    // XMM1 = [3.0, 4.0]
    let mut xmm0_val = 0u128;
    xmm0_val |= (1.0f64.to_bits() as u128) << 0;
    xmm0_val |= (2.0f64.to_bits() as u128) << 64;
    engine.xmm_write(Register::XMM0, xmm0_val);

    let mut xmm1_val = 0u128;
    xmm1_val |= (3.0f64.to_bits() as u128) << 0;
    xmm1_val |= (4.0f64.to_bits() as u128) << 64;
    engine.xmm_write(Register::XMM1, xmm1_val);

    engine.reg_write(Register::RIP, base);
    engine
        .emu_start(base, base + code.len() as u64, 0, 0)
        .unwrap();

    // Check results: UNPCKLPD takes low doubles
    // Result should be [1.0, 3.0]
    let result = engine.xmm_read(Register::XMM0);
    assert_eq!(f64::from_bits((result & 0xFFFFFFFFFFFFFFFF) as u64), 1.0);
    assert_eq!(f64::from_bits((result >> 64) as u64), 3.0);
}

#[test]
fn test_unpckhpd() {
    let mut engine = Engine::new(EngineMode::Mode64);

    let code = [
        0x66, 0x0F, 0x15, 0xC1, // unpckhpd xmm0, xmm1
    ];

    let base = 0x1000;
    engine
        .mem_map(base, 0x1000, Permission::READ | Permission::EXEC)
        .unwrap();
    engine.mem_write(base, &code).unwrap();

    // Set up test values (2 doubles in each XMM register)
    // XMM0 = [1.0, 2.0]
    // XMM1 = [3.0, 4.0]
    let mut xmm0_val = 0u128;
    xmm0_val |= (1.0f64.to_bits() as u128) << 0;
    xmm0_val |= (2.0f64.to_bits() as u128) << 64;
    engine.xmm_write(Register::XMM0, xmm0_val);

    let mut xmm1_val = 0u128;
    xmm1_val |= (3.0f64.to_bits() as u128) << 0;
    xmm1_val |= (4.0f64.to_bits() as u128) << 64;
    engine.xmm_write(Register::XMM1, xmm1_val);

    engine.reg_write(Register::RIP, base);
    engine
        .emu_start(base, base + code.len() as u64, 0, 0)
        .unwrap();

    // Check results: UNPCKHPD takes high doubles
    // Result should be [2.0, 4.0]
    let result = engine.xmm_read(Register::XMM0);
    assert_eq!(f64::from_bits((result & 0xFFFFFFFFFFFFFFFF) as u64), 2.0);
    assert_eq!(f64::from_bits((result >> 64) as u64), 4.0);
}