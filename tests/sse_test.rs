use amd64_emu::{Engine, EngineMode, Register, Permission};

#[test]
fn test_movaps() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    let code = [
        0x0F, 0x28, 0xC1,  // movaps xmm0, xmm1
    ];
    
    let base = 0x1000;
    engine.mem_map(base, 0x1000, Permission::READ | Permission::EXEC).unwrap();
    engine.mem_write(base, &code).unwrap();
    
    // Set XMM1 to a test value
    let test_value = 0x0123456789ABCDEF0123456789ABCDEFu128;
    engine.context_save().xmm_regs[1] = test_value;
    let mut state = engine.context_save();
    state.xmm_regs[1] = test_value;
    engine.context_restore(&state);
    
    engine.reg_write(Register::RIP, base).unwrap();
    engine.emu_start(base, base + code.len() as u64, 0, 0).unwrap();
    
    // Check that XMM0 now contains the value from XMM1
    assert_eq!(engine.context_save().xmm_regs[0], test_value);
}

#[test]
fn test_xorps() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    let code = [
        0x0F, 0x57, 0xC0,  // xorps xmm0, xmm0 (zero XMM0)
    ];
    
    let base = 0x1000;
    engine.mem_map(base, 0x1000, Permission::READ | Permission::EXEC).unwrap();
    engine.mem_write(base, &code).unwrap();
    
    // Set XMM0 to a non-zero value
    let mut state = engine.context_save();
    state.xmm_regs[0] = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFu128;
    engine.context_restore(&state);
    
    engine.reg_write(Register::RIP, base).unwrap();
    engine.emu_start(base, base + code.len() as u64, 0, 0).unwrap();
    
    // Check that XMM0 is now zero
    assert_eq!(engine.context_save().xmm_regs[0], 0);
}

#[test]
fn test_addps() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    let code = [
        0x0F, 0x58, 0xC1,  // addps xmm0, xmm1
    ];
    
    let base = 0x1000;
    engine.mem_map(base, 0x1000, Permission::READ | Permission::EXEC).unwrap();
    engine.mem_write(base, &code).unwrap();
    
    // Set up test values (4 floats in each XMM register)
    // XMM0 = [1.0, 2.0, 3.0, 4.0]
    // XMM1 = [5.0, 6.0, 7.0, 8.0]
    let mut state = engine.context_save();
    
    let mut xmm0_val = 0u128;
    xmm0_val |= (1.0f32.to_bits() as u128) << 0;
    xmm0_val |= (2.0f32.to_bits() as u128) << 32;
    xmm0_val |= (3.0f32.to_bits() as u128) << 64;
    xmm0_val |= (4.0f32.to_bits() as u128) << 96;
    state.xmm_regs[0] = xmm0_val;
    
    let mut xmm1_val = 0u128;
    xmm1_val |= (5.0f32.to_bits() as u128) << 0;
    xmm1_val |= (6.0f32.to_bits() as u128) << 32;
    xmm1_val |= (7.0f32.to_bits() as u128) << 64;
    xmm1_val |= (8.0f32.to_bits() as u128) << 96;
    state.xmm_regs[1] = xmm1_val;
    
    engine.context_restore(&state);
    
    engine.reg_write(Register::RIP, base).unwrap();
    engine.emu_start(base, base + code.len() as u64, 0, 0).unwrap();
    
    // Check results: XMM0 should now contain [6.0, 8.0, 10.0, 12.0]
    let result = engine.context_save().xmm_regs[0];
    assert_eq!(f32::from_bits((result & 0xFFFFFFFF) as u32), 6.0);
    assert_eq!(f32::from_bits(((result >> 32) & 0xFFFFFFFF) as u32), 8.0);
    assert_eq!(f32::from_bits(((result >> 64) & 0xFFFFFFFF) as u32), 10.0);
    assert_eq!(f32::from_bits(((result >> 96) & 0xFFFFFFFF) as u32), 12.0);
}

#[test]
fn test_subps() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    let code = [
        0x0F, 0x5C, 0xC1,  // subps xmm0, xmm1
    ];
    
    let base = 0x1000;
    engine.mem_map(base, 0x1000, Permission::READ | Permission::EXEC).unwrap();
    engine.mem_write(base, &code).unwrap();
    
    // Set up test values
    // XMM0 = [10.0, 20.0, 30.0, 40.0]
    // XMM1 = [5.0, 10.0, 15.0, 20.0]
    let mut state = engine.context_save();
    
    let mut xmm0_val = 0u128;
    xmm0_val |= (10.0f32.to_bits() as u128) << 0;
    xmm0_val |= (20.0f32.to_bits() as u128) << 32;
    xmm0_val |= (30.0f32.to_bits() as u128) << 64;
    xmm0_val |= (40.0f32.to_bits() as u128) << 96;
    state.xmm_regs[0] = xmm0_val;
    
    let mut xmm1_val = 0u128;
    xmm1_val |= (5.0f32.to_bits() as u128) << 0;
    xmm1_val |= (10.0f32.to_bits() as u128) << 32;
    xmm1_val |= (15.0f32.to_bits() as u128) << 64;
    xmm1_val |= (20.0f32.to_bits() as u128) << 96;
    state.xmm_regs[1] = xmm1_val;
    
    engine.context_restore(&state);
    
    engine.reg_write(Register::RIP, base).unwrap();
    engine.emu_start(base, base + code.len() as u64, 0, 0).unwrap();
    
    // Check results: XMM0 should now contain [5.0, 10.0, 15.0, 20.0]
    let result = engine.context_save().xmm_regs[0];
    assert_eq!(f32::from_bits((result & 0xFFFFFFFF) as u32), 5.0);
    assert_eq!(f32::from_bits(((result >> 32) & 0xFFFFFFFF) as u32), 10.0);
    assert_eq!(f32::from_bits(((result >> 64) & 0xFFFFFFFF) as u32), 15.0);
    assert_eq!(f32::from_bits(((result >> 96) & 0xFFFFFFFF) as u32), 20.0);
}

#[test]
fn test_mulps() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    let code = [
        0x0F, 0x59, 0xC1,  // mulps xmm0, xmm1
    ];
    
    let base = 0x1000;
    engine.mem_map(base, 0x1000, Permission::READ | Permission::EXEC).unwrap();
    engine.mem_write(base, &code).unwrap();
    
    // Set up test values
    // XMM0 = [2.0, 3.0, 4.0, 5.0]
    // XMM1 = [3.0, 4.0, 5.0, 6.0]
    let mut state = engine.context_save();
    
    let mut xmm0_val = 0u128;
    xmm0_val |= (2.0f32.to_bits() as u128) << 0;
    xmm0_val |= (3.0f32.to_bits() as u128) << 32;
    xmm0_val |= (4.0f32.to_bits() as u128) << 64;
    xmm0_val |= (5.0f32.to_bits() as u128) << 96;
    state.xmm_regs[0] = xmm0_val;
    
    let mut xmm1_val = 0u128;
    xmm1_val |= (3.0f32.to_bits() as u128) << 0;
    xmm1_val |= (4.0f32.to_bits() as u128) << 32;
    xmm1_val |= (5.0f32.to_bits() as u128) << 64;
    xmm1_val |= (6.0f32.to_bits() as u128) << 96;
    state.xmm_regs[1] = xmm1_val;
    
    engine.context_restore(&state);
    
    engine.reg_write(Register::RIP, base).unwrap();
    engine.emu_start(base, base + code.len() as u64, 0, 0).unwrap();
    
    // Check results: XMM0 should now contain [6.0, 12.0, 20.0, 30.0]
    let result = engine.context_save().xmm_regs[0];
    assert_eq!(f32::from_bits((result & 0xFFFFFFFF) as u32), 6.0);
    assert_eq!(f32::from_bits(((result >> 32) & 0xFFFFFFFF) as u32), 12.0);
    assert_eq!(f32::from_bits(((result >> 64) & 0xFFFFFFFF) as u32), 20.0);
    assert_eq!(f32::from_bits(((result >> 96) & 0xFFFFFFFF) as u32), 30.0);
}

#[test]
fn test_divps() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    let code = [
        0x0F, 0x5E, 0xC1,  // divps xmm0, xmm1
    ];
    
    let base = 0x1000;
    engine.mem_map(base, 0x1000, Permission::READ | Permission::EXEC).unwrap();
    engine.mem_write(base, &code).unwrap();
    
    // Set up test values
    // XMM0 = [10.0, 20.0, 30.0, 40.0]
    // XMM1 = [2.0, 4.0, 5.0, 8.0]
    let mut state = engine.context_save();
    
    let mut xmm0_val = 0u128;
    xmm0_val |= (10.0f32.to_bits() as u128) << 0;
    xmm0_val |= (20.0f32.to_bits() as u128) << 32;
    xmm0_val |= (30.0f32.to_bits() as u128) << 64;
    xmm0_val |= (40.0f32.to_bits() as u128) << 96;
    state.xmm_regs[0] = xmm0_val;
    
    let mut xmm1_val = 0u128;
    xmm1_val |= (2.0f32.to_bits() as u128) << 0;
    xmm1_val |= (4.0f32.to_bits() as u128) << 32;
    xmm1_val |= (5.0f32.to_bits() as u128) << 64;
    xmm1_val |= (8.0f32.to_bits() as u128) << 96;
    state.xmm_regs[1] = xmm1_val;
    
    engine.context_restore(&state);
    
    engine.reg_write(Register::RIP, base).unwrap();
    engine.emu_start(base, base + code.len() as u64, 0, 0).unwrap();
    
    // Check results: XMM0 should now contain [5.0, 5.0, 6.0, 5.0]
    let result = engine.context_save().xmm_regs[0];
    assert_eq!(f32::from_bits((result & 0xFFFFFFFF) as u32), 5.0);
    assert_eq!(f32::from_bits(((result >> 32) & 0xFFFFFFFF) as u32), 5.0);
    assert_eq!(f32::from_bits(((result >> 64) & 0xFFFFFFFF) as u32), 6.0);
    assert_eq!(f32::from_bits(((result >> 96) & 0xFFFFFFFF) as u32), 5.0);
}

#[test]
fn test_andps() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    let code = [
        0x0F, 0x54, 0xC1,  // andps xmm0, xmm1
    ];
    
    let base = 0x1000;
    engine.mem_map(base, 0x1000, Permission::READ | Permission::EXEC).unwrap();
    engine.mem_write(base, &code).unwrap();
    
    // Set up test values for bitwise operations
    let mut state = engine.context_save();
    
    state.xmm_regs[0] = 0xFFFFFFFF00000000FFFFFFFF00000000u128;
    state.xmm_regs[1] = 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAu128;
    
    engine.context_restore(&state);
    
    engine.reg_write(Register::RIP, base).unwrap();
    engine.emu_start(base, base + code.len() as u64, 0, 0).unwrap();
    
    // Check result
    let result = engine.context_save().xmm_regs[0];
    assert_eq!(result, 0xAAAAAAAA00000000AAAAAAAA00000000u128);
}

#[test]
fn test_orps() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    let code = [
        0x0F, 0x56, 0xC1,  // orps xmm0, xmm1
    ];
    
    let base = 0x1000;
    engine.mem_map(base, 0x1000, Permission::READ | Permission::EXEC).unwrap();
    engine.mem_write(base, &code).unwrap();
    
    // Set up test values for bitwise operations
    let mut state = engine.context_save();
    
    state.xmm_regs[0] = 0xFF00FF00FF00FF00FF00FF00FF00FF00u128;
    state.xmm_regs[1] = 0x00FF00FF00FF00FF00FF00FF00FF00FFu128;
    
    engine.context_restore(&state);
    
    engine.reg_write(Register::RIP, base).unwrap();
    engine.emu_start(base, base + code.len() as u64, 0, 0).unwrap();
    
    // Check result
    let result = engine.context_save().xmm_regs[0];
    assert_eq!(result, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFu128);
}