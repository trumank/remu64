use remu64::{Engine, EngineMode, Permission, Register, memory::MemoryTrait};

#[test]
fn test_vsqrtps_xmm_register() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Initialize XMM1 with test values
    // 4.0, 9.0, 16.0, 25.0
    let test_data: u128 = (4.0f32.to_bits() as u128)
        | ((9.0f32.to_bits() as u128) << 32)
        | ((16.0f32.to_bits() as u128) << 64)
        | ((25.0f32.to_bits() as u128) << 96);

    engine.xmm_write(Register::XMM1, test_data);

    // VSQRTPS XMM0, XMM1
    let code = vec![
        0xC5, 0xF8, 0x51, 0xC1, // vsqrtps xmm0, xmm1
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Check the result in XMM0
    let result = engine.xmm_read(Register::XMM0);

    // Extract and verify the results - should be 2.0, 3.0, 4.0, 5.0
    let result0 = f32::from_bits((result & 0xFFFFFFFF) as u32);
    let result1 = f32::from_bits(((result >> 32) & 0xFFFFFFFF) as u32);
    let result2 = f32::from_bits(((result >> 64) & 0xFFFFFFFF) as u32);
    let result3 = f32::from_bits(((result >> 96) & 0xFFFFFFFF) as u32);

    assert_eq!(result0, 2.0);
    assert_eq!(result1, 3.0);
    assert_eq!(result2, 4.0);
    assert_eq!(result3, 5.0);
}

#[test]
fn test_vsqrtps_ymm_register() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Initialize YMM1 with test values
    // Lower 128 bits: 4.0, 9.0, 16.0, 25.0
    // Upper 128 bits: 36.0, 49.0, 64.0, 81.0
    let lower_data: u128 = (4.0f32.to_bits() as u128)
        | ((9.0f32.to_bits() as u128) << 32)
        | ((16.0f32.to_bits() as u128) << 64)
        | ((25.0f32.to_bits() as u128) << 96);

    let upper_data: u128 = (36.0f32.to_bits() as u128)
        | ((49.0f32.to_bits() as u128) << 32)
        | ((64.0f32.to_bits() as u128) << 64)
        | ((81.0f32.to_bits() as u128) << 96);

    engine.ymm_write(Register::YMM1, [lower_data, upper_data]);

    // VSQRTPS YMM0, YMM1
    let code = vec![
        0xC5, 0xFC, 0x51, 0xC1, // vsqrtps ymm0, ymm1
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Check the result in YMM0
    let result = engine.ymm_read(Register::YMM0);

    // Lower 128 bits should be 2.0, 3.0, 4.0, 5.0
    let lower_result0 = f32::from_bits((result[0] & 0xFFFFFFFF) as u32);
    let lower_result1 = f32::from_bits(((result[0] >> 32) & 0xFFFFFFFF) as u32);
    let lower_result2 = f32::from_bits(((result[0] >> 64) & 0xFFFFFFFF) as u32);
    let lower_result3 = f32::from_bits(((result[0] >> 96) & 0xFFFFFFFF) as u32);

    assert_eq!(lower_result0, 2.0);
    assert_eq!(lower_result1, 3.0);
    assert_eq!(lower_result2, 4.0);
    assert_eq!(lower_result3, 5.0);

    // Upper 128 bits should be 6.0, 7.0, 8.0, 9.0
    let upper_result0 = f32::from_bits((result[1] & 0xFFFFFFFF) as u32);
    let upper_result1 = f32::from_bits(((result[1] >> 32) & 0xFFFFFFFF) as u32);
    let upper_result2 = f32::from_bits(((result[1] >> 64) & 0xFFFFFFFF) as u32);
    let upper_result3 = f32::from_bits(((result[1] >> 96) & 0xFFFFFFFF) as u32);

    assert_eq!(upper_result0, 6.0);
    assert_eq!(upper_result1, 7.0);
    assert_eq!(upper_result2, 8.0);
    assert_eq!(upper_result3, 9.0);
}

#[test]
fn test_vsqrtpd_xmm_register() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Initialize XMM1 with test values
    // 4.0, 9.0
    let test_data: u128 = (4.0f64.to_bits() as u128) | ((9.0f64.to_bits() as u128) << 64);

    engine.xmm_write(Register::XMM1, test_data);

    // VSQRTPD XMM0, XMM1
    let code = vec![
        0xC5, 0xF9, 0x51, 0xC1, // vsqrtpd xmm0, xmm1
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Check the result in XMM0
    let result = engine.xmm_read(Register::XMM0);

    // Extract and verify the results - should be 2.0, 3.0
    let result0 = f64::from_bits((result & 0xFFFFFFFFFFFFFFFF) as u64);
    let result1 = f64::from_bits((result >> 64) as u64);

    assert_eq!(result0, 2.0);
    assert_eq!(result1, 3.0);
}

#[test]
fn test_vsqrtpd_ymm_register() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Initialize YMM1 with test values
    // Lower 128 bits: 4.0, 9.0
    // Upper 128 bits: 16.0, 25.0
    let lower_data: u128 = (4.0f64.to_bits() as u128) | ((9.0f64.to_bits() as u128) << 64);

    let upper_data: u128 = (16.0f64.to_bits() as u128) | ((25.0f64.to_bits() as u128) << 64);

    engine.ymm_write(Register::YMM1, [lower_data, upper_data]);

    // VSQRTPD YMM0, YMM1
    let code = vec![
        0xC5, 0xFD, 0x51, 0xC1, // vsqrtpd ymm0, ymm1
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Check the result in YMM0
    let result = engine.ymm_read(Register::YMM0);

    // Lower 128 bits should be 2.0, 3.0
    let lower_result0 = f64::from_bits((result[0] & 0xFFFFFFFFFFFFFFFF) as u64);
    let lower_result1 = f64::from_bits((result[0] >> 64) as u64);

    assert_eq!(lower_result0, 2.0);
    assert_eq!(lower_result1, 3.0);

    // Upper 128 bits should be 4.0, 5.0
    let upper_result0 = f64::from_bits((result[1] & 0xFFFFFFFFFFFFFFFF) as u64);
    let upper_result1 = f64::from_bits((result[1] >> 64) as u64);

    assert_eq!(upper_result0, 4.0);
    assert_eq!(upper_result1, 5.0);
}

#[test]
fn test_vsqrtps_memory() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    engine.memory.map(0x2000, 0x1000, Permission::ALL).unwrap();

    // Store test data in memory
    let test_values = [4.0f32, 9.0f32, 16.0f32, 25.0f32];
    let memory_addr = 0x2000;

    for (i, &value) in test_values.iter().enumerate() {
        let bytes = value.to_bits().to_le_bytes();
        for (j, &byte) in bytes.iter().enumerate() {
            engine
                .memory
                .write(memory_addr + (i * 4) as u64 + j as u64, &[byte])
                .unwrap();
        }
    }

    // VSQRTPS XMM0, [memory]
    let code = vec![
        0xC5, 0xF8, 0x51, 0x04, 0x25, // vsqrtps xmm0, [memory]
        0x00, 0x20, 0x00, 0x00, // address 0x2000
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Check the result in XMM0
    let result = engine.xmm_read(Register::XMM0);

    let result0 = f32::from_bits((result & 0xFFFFFFFF) as u32);
    let result1 = f32::from_bits(((result >> 32) & 0xFFFFFFFF) as u32);
    let result2 = f32::from_bits(((result >> 64) & 0xFFFFFFFF) as u32);
    let result3 = f32::from_bits(((result >> 96) & 0xFFFFFFFF) as u32);

    assert_eq!(result0, 2.0);
    assert_eq!(result1, 3.0);
    assert_eq!(result2, 4.0);
    assert_eq!(result3, 5.0);
}

#[test]
fn test_vsqrtpd_memory() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    engine.memory.map(0x2000, 0x1000, Permission::ALL).unwrap();

    // Store test data in memory
    let test_values = [4.0f64, 9.0f64];
    let memory_addr = 0x2000;

    for (i, &value) in test_values.iter().enumerate() {
        let bytes = value.to_bits().to_le_bytes();
        for (j, &byte) in bytes.iter().enumerate() {
            engine
                .memory
                .write(memory_addr + (i * 8) as u64 + j as u64, &[byte])
                .unwrap();
        }
    }

    // VSQRTPD XMM0, [memory]
    let code = vec![
        0xC5, 0xF9, 0x51, 0x04, 0x25, // vsqrtpd xmm0, [memory]
        0x00, 0x20, 0x00, 0x00, // address 0x2000
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Check the result in XMM0
    let result = engine.xmm_read(Register::XMM0);

    let result0 = f64::from_bits((result & 0xFFFFFFFFFFFFFFFF) as u64);
    let result1 = f64::from_bits((result >> 64) as u64);

    assert_eq!(result0, 2.0);
    assert_eq!(result1, 3.0);
}

#[test]
fn test_vsqrtps_negative() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Initialize XMM1 with negative values - should produce NaN
    let test_data: u128 = ((-1.0f32).to_bits() as u128)
        | (((-4.0f32).to_bits() as u128) << 32)
        | (((-9.0f32).to_bits() as u128) << 64)
        | (((-16.0f32).to_bits() as u128) << 96);

    engine.xmm_write(Register::XMM1, test_data);

    // VSQRTPS XMM0, XMM1
    let code = vec![
        0xC5, 0xF8, 0x51, 0xC1, // vsqrtps xmm0, xmm1
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Check the result in XMM0 - all should be NaN
    let result = engine.xmm_read(Register::XMM0);

    let result0 = f32::from_bits((result & 0xFFFFFFFF) as u32);
    let result1 = f32::from_bits(((result >> 32) & 0xFFFFFFFF) as u32);
    let result2 = f32::from_bits(((result >> 64) & 0xFFFFFFFF) as u32);
    let result3 = f32::from_bits(((result >> 96) & 0xFFFFFFFF) as u32);

    assert!(result0.is_nan());
    assert!(result1.is_nan());
    assert!(result2.is_nan());
    assert!(result3.is_nan());
}

#[test]
fn test_vsqrtpd_special_values() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Initialize XMM1 with special values: 0.0 and infinity
    let test_data: u128 = (0.0f64.to_bits() as u128) | ((f64::INFINITY.to_bits() as u128) << 64);

    engine.xmm_write(Register::XMM1, test_data);

    // VSQRTPD XMM0, XMM1
    let code = vec![
        0xC5, 0xF9, 0x51, 0xC1, // vsqrtpd xmm0, xmm1
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Check the result in XMM0
    let result = engine.xmm_read(Register::XMM0);

    let result0 = f64::from_bits((result & 0xFFFFFFFFFFFFFFFF) as u64);
    let result1 = f64::from_bits((result >> 64) as u64);

    // sqrt(0.0) = 0.0, sqrt(inf) = inf
    assert_eq!(result0, 0.0);
    assert!(result1.is_infinite() && result1.is_sign_positive());
}
