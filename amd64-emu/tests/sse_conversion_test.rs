use amd64_emu::{Engine, EngineMode, Permission, Register};

#[test]
fn test_cvtps2pd() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory for code and stack
    engine.mem_map(0x1000, 0x2000, Permission::ALL).unwrap();
    engine.mem_map(0x10000, 0x2000, Permission::READ | Permission::WRITE).unwrap();
    
    // Test CVTPS2PD - Convert packed single to packed double
    // Input: Two single-precision floats: 1.5f32 and 2.25f32
    let float1: f32 = 1.5;
    let float2: f32 = 2.25;
    
    // Store floats in XMM0
    let xmm0_value = (float1.to_bits() as u128) | ((float2.to_bits() as u128) << 32);
    engine.xmm_write(Register::XMM0, xmm0_value);
    
    // CVTPS2PD xmm1, xmm0
    let code = vec![0x0F, 0x5A, 0xC8]; // cvtps2pd xmm1, xmm0
    engine.mem_write(0x1000, &code).unwrap();
    
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    // Check result
    let result = engine.xmm_read(Register::XMM1);
    let double1 = f64::from_bits(result as u64);
    let double2 = f64::from_bits((result >> 64) as u64);
    
    assert_eq!(double1, 1.5);
    assert_eq!(double2, 2.25);
}

#[test]
fn test_cvtpd2ps() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory for code
    engine.mem_map(0x1000, 0x2000, Permission::ALL).unwrap();
    
    // Test CVTPD2PS - Convert packed double to packed single
    // Input: Two double-precision floats: 3.75 and 4.5
    let double1: f64 = 3.75;
    let double2: f64 = 4.5;
    
    // Store doubles in XMM0
    let xmm0_value = (double1.to_bits() as u128) | ((double2.to_bits() as u128) << 64);
    engine.xmm_write(Register::XMM0, xmm0_value);
    
    // CVTPD2PS xmm1, xmm0
    let code = vec![0x66, 0x0F, 0x5A, 0xC8]; // cvtpd2ps xmm1, xmm0
    engine.mem_write(0x1000, &code).unwrap();
    
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    // Check result - two floats in lower 64 bits
    let result = engine.xmm_read(Register::XMM1);
    let float1 = f32::from_bits(result as u32);
    let float2 = f32::from_bits((result >> 32) as u32);
    
    assert_eq!(float1, 3.75);
    assert_eq!(float2, 4.5);
    // Upper 64 bits should be zero
    assert_eq!((result >> 64), 0);
}

#[test]
fn test_cvtss2sd() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory for code
    engine.mem_map(0x1000, 0x2000, Permission::ALL).unwrap();
    
    // Test CVTSS2SD - Convert scalar single to scalar double
    let float_val: f32 = 6.25;
    
    // Store float in XMM0
    let xmm0_value = float_val.to_bits() as u128;
    engine.xmm_write(Register::XMM0, xmm0_value);
    
    // CVTSS2SD xmm1, xmm0
    let code = vec![0xF3, 0x0F, 0x5A, 0xC8]; // cvtss2sd xmm1, xmm0
    engine.mem_write(0x1000, &code).unwrap();
    
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    // Check result
    let result = engine.xmm_read(Register::XMM1);
    let double_val = f64::from_bits(result as u64);
    
    assert_eq!(double_val, 6.25);
}

#[test]
fn test_cvtsd2ss() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory for code
    engine.mem_map(0x1000, 0x2000, Permission::ALL).unwrap();
    
    // Test CVTSD2SS - Convert scalar double to scalar single
    let double_val: f64 = 7.125;
    
    // Store double in XMM0
    let xmm0_value = double_val.to_bits() as u128;
    engine.xmm_write(Register::XMM0, xmm0_value);
    
    // CVTSD2SS xmm1, xmm0
    let code = vec![0xF2, 0x0F, 0x5A, 0xC8]; // cvtsd2ss xmm1, xmm0
    engine.mem_write(0x1000, &code).unwrap();
    
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    // Check result
    let result = engine.xmm_read(Register::XMM1);
    let float_val = f32::from_bits(result as u32);
    
    assert_eq!(float_val, 7.125);
}

#[test]
fn test_cvtps2dq() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory for code
    engine.mem_map(0x1000, 0x2000, Permission::ALL).unwrap();
    
    // Test CVTPS2DQ - Convert packed single to packed signed doubleword integers (with rounding)
    let floats = [1.7f32, -2.3f32, 3.5f32, -4.8f32];
    
    // Store floats in XMM0
    let xmm0_value = (floats[0].to_bits() as u128) |
                     ((floats[1].to_bits() as u128) << 32) |
                     ((floats[2].to_bits() as u128) << 64) |
                     ((floats[3].to_bits() as u128) << 96);
    engine.xmm_write(Register::XMM0, xmm0_value);
    
    // CVTPS2DQ xmm1, xmm0
    let code = vec![0x66, 0x0F, 0x5B, 0xC8]; // cvtps2dq xmm1, xmm0
    engine.mem_write(0x1000, &code).unwrap();
    
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    // Check result - should be rounded to nearest
    let result = engine.xmm_read(Register::XMM1);
    assert_eq!(result as u32 as i32, 2);  // 1.7 rounds to 2
    assert_eq!((result >> 32) as u32 as i32, -2);  // -2.3 rounds to -2
    assert_eq!((result >> 64) as u32 as i32, 4);  // 3.5 rounds to 4
    assert_eq!((result >> 96) as u32 as i32, -5);  // -4.8 rounds to -5
}

#[test]
fn test_cvttps2dq() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory for code
    engine.mem_map(0x1000, 0x2000, Permission::ALL).unwrap();
    
    // Test CVTTPS2DQ - Convert packed single to packed signed doubleword integers (with truncation)
    let floats = [1.7f32, -2.3f32, 3.5f32, -4.8f32];
    
    // Store floats in XMM0
    let xmm0_value = (floats[0].to_bits() as u128) |
                     ((floats[1].to_bits() as u128) << 32) |
                     ((floats[2].to_bits() as u128) << 64) |
                     ((floats[3].to_bits() as u128) << 96);
    engine.xmm_write(Register::XMM0, xmm0_value);
    
    // CVTTPS2DQ xmm1, xmm0
    let code = vec![0xF3, 0x0F, 0x5B, 0xC8]; // cvttps2dq xmm1, xmm0
    engine.mem_write(0x1000, &code).unwrap();
    
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    // Check result - should be truncated
    let result = engine.xmm_read(Register::XMM1);
    assert_eq!(result as u32 as i32, 1);  // 1.7 truncates to 1
    assert_eq!((result >> 32) as u32 as i32, -2);  // -2.3 truncates to -2
    assert_eq!((result >> 64) as u32 as i32, 3);  // 3.5 truncates to 3
    assert_eq!((result >> 96) as u32 as i32, -4);  // -4.8 truncates to -4
}

#[test]
fn test_cvtdq2ps() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory for code
    engine.mem_map(0x1000, 0x2000, Permission::ALL).unwrap();
    
    // Test CVTDQ2PS - Convert packed signed doubleword integers to packed single
    let ints = [5i32, -10i32, 15i32, -20i32];
    
    // Store ints in XMM0
    let xmm0_value = (ints[0] as u32 as u128) |
                     ((ints[1] as u32 as u128) << 32) |
                     ((ints[2] as u32 as u128) << 64) |
                     ((ints[3] as u32 as u128) << 96);
    engine.xmm_write(Register::XMM0, xmm0_value);
    
    // CVTDQ2PS xmm1, xmm0
    let code = vec![0x0F, 0x5B, 0xC8]; // cvtdq2ps xmm1, xmm0
    engine.mem_write(0x1000, &code).unwrap();
    
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    // Check result
    let result = engine.xmm_read(Register::XMM1);
    assert_eq!(f32::from_bits(result as u32), 5.0);
    assert_eq!(f32::from_bits((result >> 32) as u32), -10.0);
    assert_eq!(f32::from_bits((result >> 64) as u32), 15.0);
    assert_eq!(f32::from_bits((result >> 96) as u32), -20.0);
}

#[test]
fn test_cvtsi2ss() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory for code
    engine.mem_map(0x1000, 0x2000, Permission::ALL).unwrap();
    
    // Test CVTSI2SS - Convert signed integer to scalar single
    engine.reg_write(Register::RAX, 42);
    
    // CVTSI2SS xmm0, rax
    let code = vec![0xF3, 0x48, 0x0F, 0x2A, 0xC0]; // cvtsi2ss xmm0, rax
    engine.mem_write(0x1000, &code).unwrap();
    
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    // Check result
    let result = engine.xmm_read(Register::XMM0);
    let float_val = f32::from_bits(result as u32);
    assert_eq!(float_val, 42.0);
}

#[test]
fn test_cvtss2si() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory for code
    engine.mem_map(0x1000, 0x2000, Permission::ALL).unwrap();
    
    // Test CVTSS2SI - Convert scalar single to signed integer (with rounding)
    let float_val: f32 = 42.7;
    engine.xmm_write(Register::XMM0, float_val.to_bits() as u128);
    
    // CVTSS2SI rax, xmm0
    let code = vec![0xF3, 0x48, 0x0F, 0x2D, 0xC0]; // cvtss2si rax, xmm0
    engine.mem_write(0x1000, &code).unwrap();
    
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    // Check result - should be rounded
    assert_eq!(engine.reg_read(Register::RAX) as i64, 43);
}

#[test]
fn test_cvttss2si() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Map memory for code
    engine.mem_map(0x1000, 0x2000, Permission::ALL).unwrap();
    
    // Test CVTTSS2SI - Convert scalar single to signed integer (with truncation)
    let float_val: f32 = 42.7;
    engine.xmm_write(Register::XMM0, float_val.to_bits() as u128);
    
    // CVTTSS2SI rax, xmm0
    let code = vec![0xF3, 0x48, 0x0F, 0x2C, 0xC0]; // cvttss2si rax, xmm0
    engine.mem_write(0x1000, &code).unwrap();
    
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    // Check result - should be truncated
    assert_eq!(engine.reg_read(Register::RAX) as i64, 42);
}