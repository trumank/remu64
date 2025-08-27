use remu64::{Engine, EngineMode, Permission, Register, memory::MemoryTrait};

#[test]
fn test_vaddps_xmm() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Initialize XMM registers with test values
    // XMM1 = [1.0, 2.0, 3.0, 4.0] (packed single-precision)
    let xmm1_data: u128 = 
        (1.0_f32.to_bits() as u128) |
        ((2.0_f32.to_bits() as u128) << 32) |
        ((3.0_f32.to_bits() as u128) << 64) |
        ((4.0_f32.to_bits() as u128) << 96);
    
    // XMM2 = [5.0, 6.0, 7.0, 8.0]
    let xmm2_data: u128 = 
        (5.0_f32.to_bits() as u128) |
        ((6.0_f32.to_bits() as u128) << 32) |
        ((7.0_f32.to_bits() as u128) << 64) |
        ((8.0_f32.to_bits() as u128) << 96);
    
    engine.reg_write_xmm(Register::XMM1, xmm1_data);
    engine.reg_write_xmm(Register::XMM2, xmm2_data);

    // vaddps xmm0, xmm1, xmm2
    // C5 F0 58 C2
    let code = vec![0xC5, 0xF0, 0x58, 0xC2];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();

    // Expected: XMM0 = [6.0, 8.0, 10.0, 12.0]
    let result = engine.reg_read_xmm(Register::XMM0);
    assert_eq!(result & 0xFFFFFFFF, 6.0_f32.to_bits() as u128);
    assert_eq!((result >> 32) & 0xFFFFFFFF, 8.0_f32.to_bits() as u128);
    assert_eq!((result >> 64) & 0xFFFFFFFF, 10.0_f32.to_bits() as u128);
    assert_eq!((result >> 96) & 0xFFFFFFFF, 12.0_f32.to_bits() as u128);
}

#[test]
fn test_vsubps_xmm() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // XMM1 = [10.0, 20.0, 30.0, 40.0]
    let xmm1_data: u128 = 
        (10.0_f32.to_bits() as u128) |
        ((20.0_f32.to_bits() as u128) << 32) |
        ((30.0_f32.to_bits() as u128) << 64) |
        ((40.0_f32.to_bits() as u128) << 96);
    
    // XMM2 = [1.0, 2.0, 3.0, 4.0]
    let xmm2_data: u128 = 
        (1.0_f32.to_bits() as u128) |
        ((2.0_f32.to_bits() as u128) << 32) |
        ((3.0_f32.to_bits() as u128) << 64) |
        ((4.0_f32.to_bits() as u128) << 96);
    
    engine.reg_write_xmm(Register::XMM1, xmm1_data);
    engine.reg_write_xmm(Register::XMM2, xmm2_data);

    // vsubps xmm0, xmm1, xmm2
    // C5 F0 5C C2
    let code = vec![0xC5, 0xF0, 0x5C, 0xC2];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();

    // Expected: XMM0 = [9.0, 18.0, 27.0, 36.0]
    let result = engine.reg_read_xmm(Register::XMM0);
    assert_eq!(result & 0xFFFFFFFF, 9.0_f32.to_bits() as u128);
    assert_eq!((result >> 32) & 0xFFFFFFFF, 18.0_f32.to_bits() as u128);
    assert_eq!((result >> 64) & 0xFFFFFFFF, 27.0_f32.to_bits() as u128);
    assert_eq!((result >> 96) & 0xFFFFFFFF, 36.0_f32.to_bits() as u128);
}

#[test]
fn test_vmulps_xmm() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // XMM1 = [2.0, 3.0, 4.0, 5.0]
    let xmm1_data: u128 = 
        (2.0_f32.to_bits() as u128) |
        ((3.0_f32.to_bits() as u128) << 32) |
        ((4.0_f32.to_bits() as u128) << 64) |
        ((5.0_f32.to_bits() as u128) << 96);
    
    // XMM2 = [3.0, 2.0, 1.5, 2.0]
    let xmm2_data: u128 = 
        (3.0_f32.to_bits() as u128) |
        ((2.0_f32.to_bits() as u128) << 32) |
        ((1.5_f32.to_bits() as u128) << 64) |
        ((2.0_f32.to_bits() as u128) << 96);
    
    engine.reg_write_xmm(Register::XMM1, xmm1_data);
    engine.reg_write_xmm(Register::XMM2, xmm2_data);

    // vmulps xmm0, xmm1, xmm2
    // C5 F0 59 C2
    let code = vec![0xC5, 0xF0, 0x59, 0xC2];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();

    // Expected: XMM0 = [6.0, 6.0, 6.0, 10.0]
    let result = engine.reg_read_xmm(Register::XMM0);
    assert_eq!(result & 0xFFFFFFFF, 6.0_f32.to_bits() as u128);
    assert_eq!((result >> 32) & 0xFFFFFFFF, 6.0_f32.to_bits() as u128);
    assert_eq!((result >> 64) & 0xFFFFFFFF, 6.0_f32.to_bits() as u128);
    assert_eq!((result >> 96) & 0xFFFFFFFF, 10.0_f32.to_bits() as u128);
}

#[test]
fn test_vdivps_xmm() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // XMM1 = [12.0, 8.0, 6.0, 15.0]
    let xmm1_data: u128 = 
        (12.0_f32.to_bits() as u128) |
        ((8.0_f32.to_bits() as u128) << 32) |
        ((6.0_f32.to_bits() as u128) << 64) |
        ((15.0_f32.to_bits() as u128) << 96);
    
    // XMM2 = [3.0, 2.0, 3.0, 5.0]
    let xmm2_data: u128 = 
        (3.0_f32.to_bits() as u128) |
        ((2.0_f32.to_bits() as u128) << 32) |
        ((3.0_f32.to_bits() as u128) << 64) |
        ((5.0_f32.to_bits() as u128) << 96);
    
    engine.reg_write_xmm(Register::XMM1, xmm1_data);
    engine.reg_write_xmm(Register::XMM2, xmm2_data);

    // vdivps xmm0, xmm1, xmm2
    // C5 F0 5E C2
    let code = vec![0xC5, 0xF0, 0x5E, 0xC2];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();

    // Expected: XMM0 = [4.0, 4.0, 2.0, 3.0]
    let result = engine.reg_read_xmm(Register::XMM0);
    assert_eq!(result & 0xFFFFFFFF, 4.0_f32.to_bits() as u128);
    assert_eq!((result >> 32) & 0xFFFFFFFF, 4.0_f32.to_bits() as u128);
    assert_eq!((result >> 64) & 0xFFFFFFFF, 2.0_f32.to_bits() as u128);
    assert_eq!((result >> 96) & 0xFFFFFFFF, 3.0_f32.to_bits() as u128);
}

#[test]
fn test_vaddpd_xmm() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // XMM1 = [1.5, 2.5] (packed double-precision)
    let xmm1_data: u128 = 
        (1.5_f64.to_bits() as u128) |
        ((2.5_f64.to_bits() as u128) << 64);
    
    // XMM2 = [3.5, 4.5]
    let xmm2_data: u128 = 
        (3.5_f64.to_bits() as u128) |
        ((4.5_f64.to_bits() as u128) << 64);
    
    engine.reg_write_xmm(Register::XMM1, xmm1_data);
    engine.reg_write_xmm(Register::XMM2, xmm2_data);

    // vaddpd xmm0, xmm1, xmm2
    // C5 F1 58 C2
    let code = vec![0xC5, 0xF1, 0x58, 0xC2];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();

    // Expected: XMM0 = [5.0, 7.0]
    let result = engine.reg_read_xmm(Register::XMM0);
    assert_eq!(result & 0xFFFFFFFFFFFFFFFF, 5.0_f64.to_bits() as u128);
    assert_eq!((result >> 64) & 0xFFFFFFFFFFFFFFFF, 7.0_f64.to_bits() as u128);
}

#[test]
fn test_vsubpd_xmm() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // XMM1 = [10.5, 20.5]
    let xmm1_data: u128 = 
        (10.5_f64.to_bits() as u128) |
        ((20.5_f64.to_bits() as u128) << 64);
    
    // XMM2 = [0.5, 5.5]
    let xmm2_data: u128 = 
        (0.5_f64.to_bits() as u128) |
        ((5.5_f64.to_bits() as u128) << 64);
    
    engine.reg_write_xmm(Register::XMM1, xmm1_data);
    engine.reg_write_xmm(Register::XMM2, xmm2_data);

    // vsubpd xmm0, xmm1, xmm2
    // C5 F1 5C C2
    let code = vec![0xC5, 0xF1, 0x5C, 0xC2];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();

    // Expected: XMM0 = [10.0, 15.0]
    let result = engine.reg_read_xmm(Register::XMM0);
    assert_eq!(result & 0xFFFFFFFFFFFFFFFF, 10.0_f64.to_bits() as u128);
    assert_eq!((result >> 64) & 0xFFFFFFFFFFFFFFFF, 15.0_f64.to_bits() as u128);
}

#[test]
fn test_vaddps_ymm() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // YMM1 = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]
    let ymm1_low: u128 = 
        (1.0_f32.to_bits() as u128) |
        ((2.0_f32.to_bits() as u128) << 32) |
        ((3.0_f32.to_bits() as u128) << 64) |
        ((4.0_f32.to_bits() as u128) << 96);
    
    let ymm1_high: u128 = 
        (5.0_f32.to_bits() as u128) |
        ((6.0_f32.to_bits() as u128) << 32) |
        ((7.0_f32.to_bits() as u128) << 64) |
        ((8.0_f32.to_bits() as u128) << 96);
    
    // YMM2 = [2.0, 2.0, 2.0, 2.0, 2.0, 2.0, 2.0, 2.0]
    let ymm2_low: u128 = 
        (2.0_f32.to_bits() as u128) |
        ((2.0_f32.to_bits() as u128) << 32) |
        ((2.0_f32.to_bits() as u128) << 64) |
        ((2.0_f32.to_bits() as u128) << 96);
    
    let ymm2_high = ymm2_low;
    
    engine.reg_write_ymm(Register::YMM1, [ymm1_low, ymm1_high]);
    engine.reg_write_ymm(Register::YMM2, [ymm2_low, ymm2_high]);

    // vaddps ymm0, ymm1, ymm2
    // C5 F4 58 C2  
    let code = vec![0xC5, 0xF4, 0x58, 0xC2];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();

    // Expected: YMM0 = [3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]
    let result = engine.reg_read_ymm(Register::YMM0);
    assert_eq!(result[0] & 0xFFFFFFFF, 3.0_f32.to_bits() as u128);
    assert_eq!((result[0] >> 32) & 0xFFFFFFFF, 4.0_f32.to_bits() as u128);
    assert_eq!((result[0] >> 64) & 0xFFFFFFFF, 5.0_f32.to_bits() as u128);
    assert_eq!((result[0] >> 96) & 0xFFFFFFFF, 6.0_f32.to_bits() as u128);
    assert_eq!(result[1] & 0xFFFFFFFF, 7.0_f32.to_bits() as u128);
    assert_eq!((result[1] >> 32) & 0xFFFFFFFF, 8.0_f32.to_bits() as u128);
    assert_eq!((result[1] >> 64) & 0xFFFFFFFF, 9.0_f32.to_bits() as u128);
    assert_eq!((result[1] >> 96) & 0xFFFFFFFF, 10.0_f32.to_bits() as u128);
}