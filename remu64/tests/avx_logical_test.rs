use remu64::{Engine, Register};

#[test]
fn test_vandps_xmm() {
    let mut engine = Engine::new();
    
    // Test VANDPS xmm0, xmm1, xmm2
    // Set up test values in XMM registers
    // Using bit patterns that will show clear AND behavior
    engine.xmm_write(Register::XMM1, 0xFFFFFFFF_00000000_FFFFFFFF_00000000);
    engine.xmm_write(Register::XMM2, 0xFFFFFFFF_FFFFFFFF_00000000_00000000);
    
    // VANDPS xmm0, xmm1, xmm2
    let code = vec![
        0xC5, 0xF0, 0x54, 0xC2,  // vandps xmm0, xmm1, xmm2
    ];
    
    engine.execute(&code, 0x1000).unwrap();
    
    // Result should be bitwise AND of xmm1 and xmm2
    assert_eq!(
        engine.xmm_read(Register::XMM0),
        0xFFFFFFFF_00000000_00000000_00000000
    );
}

#[test]
fn test_vandps_ymm() {
    let mut engine = Engine::new();
    
    // Test VANDPS ymm0, ymm1, ymm2
    // Set up test values in YMM registers
    engine.ymm_write(Register::YMM1, [
        0xFFFFFFFF_00000000_FFFFFFFF_00000000,
        0x00000000_FFFFFFFF_00000000_FFFFFFFF,
    ]);
    engine.ymm_write(Register::YMM2, [
        0xFFFFFFFF_FFFFFFFF_00000000_00000000,
        0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF,
    ]);
    
    // VANDPS ymm0, ymm1, ymm2
    let code = vec![
        0xC5, 0xF4, 0x54, 0xC2,  // vandps ymm0, ymm1, ymm2
    ];
    
    engine.execute(&code, 0x1000).unwrap();
    
    // Result should be bitwise AND of ymm1 and ymm2
    let result = engine.ymm_read(Register::YMM0);
    assert_eq!(result[0], 0xFFFFFFFF_00000000_00000000_00000000);
    assert_eq!(result[1], 0x00000000_FFFFFFFF_00000000_FFFFFFFF);
}

#[test]
fn test_vandpd_xmm() {
    let mut engine = Engine::new();
    
    // Test VANDPD xmm0, xmm1, xmm2
    // Set up test values in XMM registers
    engine.xmm_write(Register::XMM1, 0xFFFFFFFFFFFFFFFF_0000000000000000);
    engine.xmm_write(Register::XMM2, 0xFFFFFFFFFFFFFFFF_FFFFFFFFFFFFFFFF);
    
    // VANDPD xmm0, xmm1, xmm2
    let code = vec![
        0xC5, 0xF1, 0x54, 0xC2,  // vandpd xmm0, xmm1, xmm2
    ];
    
    engine.execute(&code, 0x1000).unwrap();
    
    // Result should be bitwise AND of xmm1 and xmm2
    assert_eq!(
        engine.xmm_read(Register::XMM0),
        0xFFFFFFFFFFFFFFFF_0000000000000000
    );
}

#[test]
fn test_vandpd_ymm() {
    let mut engine = Engine::new();
    
    // Test VANDPD ymm0, ymm1, ymm2
    // Set up test values in YMM registers
    engine.ymm_write(Register::YMM1, [
        0xFFFFFFFFFFFFFFFF_0000000000000000,
        0x0000000000000000_FFFFFFFFFFFFFFFF,
    ]);
    engine.ymm_write(Register::YMM2, [
        0xFFFFFFFFFFFFFFFF_FFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF_FFFFFFFFFFFFFFFF,
    ]);
    
    // VANDPD ymm0, ymm1, ymm2
    let code = vec![
        0xC5, 0xF5, 0x54, 0xC2,  // vandpd ymm0, ymm1, ymm2
    ];
    
    engine.execute(&code, 0x1000).unwrap();
    
    // Result should be bitwise AND of ymm1 and ymm2
    let result = engine.ymm_read(Register::YMM0);
    assert_eq!(result[0], 0xFFFFFFFFFFFFFFFF_0000000000000000);
    assert_eq!(result[1], 0x0000000000000000_FFFFFFFFFFFFFFFF);
}

#[test]
fn test_vandps_memory() {
    let mut engine = Engine::new();
    
    // Test VANDPS with memory operand
    // Store test value in memory
    let mem_value: u128 = 0xFFFFFFFF_FFFFFFFF_00000000_00000000;
    engine.mem_write_128(0x2000, mem_value).unwrap();
    
    // Set up XMM1 with test value
    engine.xmm_write(Register::XMM1, 0xFFFFFFFF_00000000_FFFFFFFF_00000000);
    
    // Set RAX to point to memory
    engine.reg_write(Register::RAX, 0x2000);
    
    // VANDPS xmm0, xmm1, [rax]
    let code = vec![
        0xC5, 0xF0, 0x54, 0x00,  // vandps xmm0, xmm1, [rax]
    ];
    
    engine.execute(&code, 0x1000).unwrap();
    
    // Result should be bitwise AND of xmm1 and memory value
    assert_eq!(
        engine.xmm_read(Register::XMM0),
        0xFFFFFFFF_00000000_00000000_00000000
    );
}

#[test]
fn test_vandpd_memory() {
    let mut engine = Engine::new();
    
    // Test VANDPD with memory operand
    // Store test value in memory
    let mem_value: u128 = 0xFFFFFFFFFFFFFFFF_FFFFFFFFFFFFFFFF;
    engine.mem_write_128(0x2000, mem_value).unwrap();
    
    // Set up XMM1 with test value
    engine.xmm_write(Register::XMM1, 0xFFFFFFFFFFFFFFFF_0000000000000000);
    
    // Set RAX to point to memory
    engine.reg_write(Register::RAX, 0x2000);
    
    // VANDPD xmm0, xmm1, [rax]
    let code = vec![
        0xC5, 0xF1, 0x54, 0x00,  // vandpd xmm0, xmm1, [rax]
    ];
    
    engine.execute(&code, 0x1000).unwrap();
    
    // Result should be bitwise AND of xmm1 and memory value
    assert_eq!(
        engine.xmm_read(Register::XMM0),
        0xFFFFFFFFFFFFFFFF_0000000000000000
    );
}

#[test]
fn test_vandps_all_ones() {
    let mut engine = Engine::new();
    
    // Test VANDPS with all ones - result should be all ones
    engine.xmm_write(Register::XMM1, 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF);
    engine.xmm_write(Register::XMM2, 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF);
    
    // VANDPS xmm0, xmm1, xmm2
    let code = vec![
        0xC5, 0xF0, 0x54, 0xC2,  // vandps xmm0, xmm1, xmm2
    ];
    
    engine.execute(&code, 0x1000).unwrap();
    
    assert_eq!(
        engine.xmm_read(Register::XMM0),
        0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF
    );
}

#[test]
fn test_vandps_all_zeros() {
    let mut engine = Engine::new();
    
    // Test VANDPS with all zeros - result should be all zeros
    engine.xmm_write(Register::XMM1, 0x00000000_00000000_00000000_00000000);
    engine.xmm_write(Register::XMM2, 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF);
    
    // VANDPS xmm0, xmm1, xmm2
    let code = vec![
        0xC5, 0xF0, 0x54, 0xC2,  // vandps xmm0, xmm1, xmm2
    ];
    
    engine.execute(&code, 0x1000).unwrap();
    
    assert_eq!(
        engine.xmm_read(Register::XMM0),
        0x00000000_00000000_00000000_00000000
    );
}

#[test]
fn test_vandpd_pattern() {
    let mut engine = Engine::new();
    
    // Test VANDPD with alternating pattern
    engine.xmm_write(Register::XMM1, 0xAAAAAAAAAAAAAAAA_5555555555555555);
    engine.xmm_write(Register::XMM2, 0xCCCCCCCCCCCCCCCC_3333333333333333);
    
    // VANDPD xmm0, xmm1, xmm2
    let code = vec![
        0xC5, 0xF1, 0x54, 0xC2,  // vandpd xmm0, xmm1, xmm2
    ];
    
    engine.execute(&code, 0x1000).unwrap();
    
    // Result: 0xAAAA... & 0xCCCC... = 0x8888..., 0x5555... & 0x3333... = 0x1111...
    assert_eq!(
        engine.xmm_read(Register::XMM0),
        0x8888888888888888_1111111111111111
    );
}