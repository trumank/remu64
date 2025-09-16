use remu64::{Engine, EngineMode, Permission, Register, memory::MemoryTrait as _};

#[test]
fn test_addsd() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test ADDSD - Add Scalar Double-Precision Floating-Point Value
    let code = vec![
        // Initialize XMM0 with test value
        0x66, 0x0F, 0x6F, 0x05, 0x14, 0x00, 0x00, 0x00, // movdqa xmm0, [rip + 0x14]
        // Initialize XMM1 with value to add
        0x66, 0x0F, 0x6F, 0x0D, 0x1C, 0x00, 0x00, 0x00, // movdqa xmm1, [rip + 0x1C]
        // ADDSD xmm0, xmm1
        0xF2, 0x0F, 0x58, 0xC1, // addsd xmm0, xmm1
        // Move result to memory for checking
        0x66, 0x0F, 0x7F, 0x05, 0x20, 0x00, 0x00, 0x00, // movdqa [rip + 0x20], xmm0
        // Data at offset 0x1C: XMM0 initial value
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x40, // 4.0 (double)
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x12, 0x34, // Upper 64 bits (preserved)
        // Data at offset 0x2C: XMM1 value to add
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x40, // 3.0 (double)
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // Upper 64 bits (ignored)
        // Space for result at offset 0x3C
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine.reg_write(Register::RIP, 0x1000);

    // Execute instructions
    match engine.emu_start(0x1000, 0x1000 + 0x1C, 0, 0) {
        Ok(_) => {}
        Err(e) => panic!("Execution failed: {:?}", e),
    }

    // Check result
    let mut result = vec![0u8; 16];
    engine.memory.read(0x103C, &mut result).unwrap();

    // Expected: 4.0 + 3.0 = 7.0
    let result_double = f64::from_bits(u64::from_le_bytes([
        result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7],
    ]));
    assert_eq!(result_double, 7.0);

    // Check that upper 64 bits are preserved
    assert_eq!(result[8], 0xAA);
    assert_eq!(result[9], 0xBB);
    assert_eq!(result[10], 0xCC);
    assert_eq!(result[11], 0xDD);
    assert_eq!(result[12], 0xEE);
    assert_eq!(result[13], 0xFF);
    assert_eq!(result[14], 0x12);
    assert_eq!(result[15], 0x34);
}

#[test]
fn test_subsd() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test SUBSD - Subtract Scalar Double-Precision Floating-Point Value
    let code = vec![
        // Initialize XMM0 with test value
        0x66, 0x0F, 0x6F, 0x05, 0x14, 0x00, 0x00, 0x00, // movdqa xmm0, [rip + 0x14]
        // Initialize XMM1 with value to subtract
        0x66, 0x0F, 0x6F, 0x0D, 0x1C, 0x00, 0x00, 0x00, // movdqa xmm1, [rip + 0x1C]
        // SUBSD xmm0, xmm1
        0xF2, 0x0F, 0x5C, 0xC1, // subsd xmm0, xmm1
        // Move result to memory for checking
        0x66, 0x0F, 0x7F, 0x05, 0x20, 0x00, 0x00, 0x00, // movdqa [rip + 0x20], xmm0
        // Data at offset 0x1C: XMM0 initial value
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x40, // 8.0 (double)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Upper 64 bits
        // Data at offset 0x2C: XMM1 value to subtract
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x40, // 3.0 (double)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Upper 64 bits
        // Space for result at offset 0x3C
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine.reg_write(Register::RIP, 0x1000);

    // Execute instructions
    match engine.emu_start(0x1000, 0x1000 + 0x1C, 0, 0) {
        Ok(_) => {}
        Err(e) => panic!("Execution failed: {:?}", e),
    }

    // Check result
    let mut result = vec![0u8; 16];
    engine.memory.read(0x103C, &mut result).unwrap();

    // Expected: 8.0 - 3.0 = 5.0
    let result_double = f64::from_bits(u64::from_le_bytes([
        result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7],
    ]));
    assert_eq!(result_double, 5.0);
}

#[test]
fn test_mulsd() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test MULSD - Multiply Scalar Double-Precision Floating-Point Value
    let code = vec![
        // Initialize XMM0 with test value
        0x66, 0x0F, 0x6F, 0x05, 0x14, 0x00, 0x00, 0x00, // movdqa xmm0, [rip + 0x14]
        // Initialize XMM1 with multiplier
        0x66, 0x0F, 0x6F, 0x0D, 0x1C, 0x00, 0x00, 0x00, // movdqa xmm1, [rip + 0x1C]
        // MULSD xmm0, xmm1
        0xF2, 0x0F, 0x59, 0xC1, // mulsd xmm0, xmm1
        // Move result to memory for checking
        0x66, 0x0F, 0x7F, 0x05, 0x20, 0x00, 0x00, 0x00, // movdqa [rip + 0x20], xmm0
        // Data at offset 0x1C: XMM0 initial value
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x40, // 5.0 (double)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Upper 64 bits
        // Data at offset 0x2C: XMM1 multiplier
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, // 2.0 (double)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Upper 64 bits
        // Space for result at offset 0x3C
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine.reg_write(Register::RIP, 0x1000);

    // Execute instructions
    match engine.emu_start(0x1000, 0x1000 + 0x1C, 0, 0) {
        Ok(_) => {}
        Err(e) => panic!("Execution failed: {:?}", e),
    }

    // Check result
    let mut result = vec![0u8; 16];
    engine.memory.read(0x103C, &mut result).unwrap();

    // Expected: 5.0 * 2.0 = 10.0
    let result_double = f64::from_bits(u64::from_le_bytes([
        result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7],
    ]));
    assert_eq!(result_double, 10.0);
}

#[test]
fn test_divsd() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test DIVSD - Divide Scalar Double-Precision Floating-Point Value
    let code = vec![
        // Initialize XMM0 with test value
        0x66, 0x0F, 0x6F, 0x05, 0x14, 0x00, 0x00, 0x00, // movdqa xmm0, [rip + 0x14]
        // Initialize XMM1 with divisor
        0x66, 0x0F, 0x6F, 0x0D, 0x1C, 0x00, 0x00, 0x00, // movdqa xmm1, [rip + 0x1C]
        // DIVSD xmm0, xmm1
        0xF2, 0x0F, 0x5E, 0xC1, // divsd xmm0, xmm1
        // Move result to memory for checking
        0x66, 0x0F, 0x7F, 0x05, 0x20, 0x00, 0x00, 0x00, // movdqa [rip + 0x20], xmm0
        // Data at offset 0x1C: XMM0 initial value
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x40, // 12.0 (double)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Upper 64 bits
        // Data at offset 0x2C: XMM1 divisor
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x40, // 3.0 (double)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Upper 64 bits
        // Space for result at offset 0x3C
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine.reg_write(Register::RIP, 0x1000);

    // Execute instructions
    match engine.emu_start(0x1000, 0x1000 + 0x1C, 0, 0) {
        Ok(_) => {}
        Err(e) => panic!("Execution failed: {:?}", e),
    }

    // Check result
    let mut result = vec![0u8; 16];
    engine.memory.read(0x103C, &mut result).unwrap();

    // Expected: 12.0 / 3.0 = 4.0
    let result_double = f64::from_bits(u64::from_le_bytes([
        result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7],
    ]));
    assert_eq!(result_double, 4.0);
}

#[test]
fn test_addss() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test ADDSS - Add Scalar Single-Precision Floating-Point Value
    let code = vec![
        // Initialize XMM0 with test value
        0x66, 0x0F, 0x6F, 0x05, 0x14, 0x00, 0x00, 0x00, // movdqa xmm0, [rip + 0x14]
        // Initialize XMM1 with value to add
        0x66, 0x0F, 0x6F, 0x0D, 0x1C, 0x00, 0x00, 0x00, // movdqa xmm1, [rip + 0x1C]
        // ADDSS xmm0, xmm1
        0xF3, 0x0F, 0x58, 0xC1, // addss xmm0, xmm1
        // Move result to memory for checking
        0x66, 0x0F, 0x7F, 0x05, 0x20, 0x00, 0x00, 0x00, // movdqa [rip + 0x20], xmm0
        // Data at offset 0x1C: XMM0 initial value
        0x00, 0x00, 0x80, 0x40, // 4.0 (float)
        0xAA, 0xBB, 0xCC, 0xDD, // Preserved 32-95 bits
        0xEE, 0xFF, 0x12, 0x34, // Preserved
        0x56, 0x78, 0x9A, 0xBC, // Preserved
        // Data at offset 0x2C: XMM1 value to add
        0x00, 0x00, 0x40, 0x40, // 3.0 (float)
        0x11, 0x22, 0x33, 0x44, // Ignored
        0x55, 0x66, 0x77, 0x88, // Ignored
        0x99, 0xAA, 0xBB, 0xCC, // Ignored
        // Space for result at offset 0x3C
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine.reg_write(Register::RIP, 0x1000);

    // Execute instructions
    match engine.emu_start(0x1000, 0x1000 + 0x1C, 0, 0) {
        Ok(_) => {}
        Err(e) => panic!("Execution failed: {:?}", e),
    }

    // Check result
    let mut result = vec![0u8; 16];
    engine.memory.read(0x103C, &mut result).unwrap();

    // Expected: 4.0 + 3.0 = 7.0
    let result_float = f32::from_bits(u32::from_le_bytes([
        result[0], result[1], result[2], result[3],
    ]));
    assert_eq!(result_float, 7.0);

    // Check that upper bits are preserved
    assert_eq!(result[4], 0xAA);
    assert_eq!(result[5], 0xBB);
    assert_eq!(result[6], 0xCC);
    assert_eq!(result[7], 0xDD);
}

#[test]
fn test_movss_memory_to_xmm() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test MOVSS - Move Scalar Single-Precision Floating-Point Value from memory to XMM
    let code = vec![
        // MOVSS XMM0, [rip + 0x00] - move from memory address using RIP-relative addressing
        0xF3, 0x0F, 0x10, 0x05, 0x00, 0x00, 0x00, 0x00, // movss xmm0, [rip + 0x00]
        // Float value to load (3.14159 as f32)
        0xD0, 0x0F, 0x49, 0x40, // 3.14159 (float32 little-endian)
    ];

    // Set XMM0 with some initial value to test zeroing behavior
    engine.xmm_write(Register::XMM0, 0xFFFFFFFFFFFFFFFF_AAAAAAAAAAAAAAAA);

    engine.memory.write(0x1000, &code).unwrap();
    engine.reg_write(Register::RIP, 0x1000);

    // Execute instruction
    match engine.emu_start(0x1000, 0x1008, 0, 0) {
        Ok(_) => {}
        Err(e) => panic!("Execution failed: {:?}", e),
    }

    // Check result directly from XMM register
    let result = engine.xmm_read(Register::XMM0);

    // Expected: lower 32 bits should contain 3.14159, upper 96 bits should be zero
    let result_float = f32::from_bits((result & 0xFFFFFFFF) as u32);
    assert!(
        (result_float - std::f32::consts::PI).abs() < 0.0001,
        "Expected 3.14159, got {}",
        result_float
    );

    // Check that upper 96 bits are zeroed (this is the key behavior of MOVSS from memory)
    let upper_96 = result >> 32;
    assert_eq!(
        upper_96, 0,
        "Upper 96 bits should be zeroed, but got {:024X}",
        upper_96
    );
}

#[test]
fn test_movss_xmm_to_xmm() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test MOVSS - Move Scalar Single-Precision between XMM registers
    let code = vec![
        // MOVSS xmm1, xmm0 - move lower 32 bits from xmm0 to xmm1, preserve upper bits of xmm1
        0xF3, 0x0F, 0x10, 0xC8, // movss xmm1, xmm0
    ];

    // Set up XMM0 with 10.0f32 in lower 32 bits + some upper bits
    let float_bits = 10.0f32.to_bits() as u128;
    let xmm0_value =
        float_bits | (0x1122334455667788u64 as u128) << 32 | (0x99AABBCCDDEEFFu64 as u128) << 96;
    engine.xmm_write(Register::XMM0, xmm0_value);

    // Set up XMM1 with different values to test upper bit preservation
    let xmm1_value = 0xAAAABBBBCCCCDDDD_EEEEFFFF12345678_u128;
    engine.xmm_write(Register::XMM1, xmm1_value);

    engine.memory.write(0x1000, &code).unwrap();
    engine.reg_write(Register::RIP, 0x1000);

    // Execute instruction
    match engine.emu_start(0x1000, 0x1004, 0, 0) {
        Ok(_) => {}
        Err(e) => panic!("Execution failed: {:?}", e),
    }

    // Check result
    let result = engine.xmm_read(Register::XMM1);

    // Expected: lower 32 bits should be 10.0 from XMM0
    let result_float = f32::from_bits((result & 0xFFFFFFFF) as u32);
    assert_eq!(result_float, 10.0);

    // Check that upper 96 bits of XMM1 are preserved (not zeroed like memory-to-register)
    let upper_96 = result >> 32;
    let expected_upper_96 = xmm1_value >> 32; // Should preserve original upper bits
    assert_eq!(
        upper_96, expected_upper_96,
        "Upper 96 bits should be preserved"
    );
}

#[test]
fn test_movss_simple() {
    use remu64::{Engine, EngineMode, Permission, Register, memory::MemoryTrait as _};

    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Simple MOVSS xmm0, xmm1 test
    let code = vec![
        0xF3, 0x0F, 0x10, 0xC1, // movss xmm0, xmm1
    ];

    // Set XMM1 with a known value (10.0f32 in lower 32 bits)
    let float_bits = 10.0f32.to_bits() as u128;
    engine.xmm_write(
        Register::XMM1,
        (0xDEADBEEF_CAFEBABE_12345678u128 << 32) | float_bits,
    );

    // Set XMM0 with different value to check preservation
    engine.xmm_write(Register::XMM0, 0xAAAAAAAA_BBBBBBBB_CCCCCCCC_DDDDDDDD);

    engine.memory.write(0x1000, &code).unwrap();
    engine.reg_write(Register::RIP, 0x1000);

    match engine.emu_start(0x1000, 0x1004, 0, 0) {
        Ok(_) => {
            let result = engine.xmm_read(Register::XMM0);
            let lower_32 = (result & 0xFFFFFFFF) as u32;
            let float_result = f32::from_bits(lower_32);

            assert_eq!(float_result, 10.0);

            // Check upper bits preserved
            let upper_96 = result >> 32;
            let expected_upper = 0xAAAAAAAA_BBBBBBBB_CCCCCCCC;
            assert_eq!(
                upper_96, expected_upper,
                "Upper 96 bits should be preserved"
            );
        }
        Err(e) => panic!("Execution failed: {:?}", e),
    }
}
