use amd64_emu::{Engine, EngineMode, Permission, Register};

#[test]
fn test_pmaddwd() {
    let mut emu = Engine::new(EngineMode::Mode64);
    
    // Test basic PMADDWD operation
    let code = vec![
        // movdqa xmm0, [rsp]
        0x66, 0x0F, 0x6F, 0x04, 0x24,
        // movdqa xmm1, [rsp+16]
        0x66, 0x0F, 0x6F, 0x4C, 0x24, 0x10,
        // pmaddwd xmm0, xmm1
        0x66, 0x0F, 0xF5, 0xC1,
    ];
    
    emu.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();
    emu.mem_map(0x100000, 0x1000, Permission::ALL).unwrap();
    emu.mem_write(0x1000, &code).unwrap();
    emu.reg_write(Register::RIP, 0x1000);
    emu.reg_write(Register::RSP, 0x100400);
    
    // Set up test data - words to multiply and add
    // xmm0: [2, 3], [4, 5], [-2, 3], [100, -50]
    let xmm0_data = vec![
        0x02, 0x00,  // 2
        0x03, 0x00,  // 3
        0x04, 0x00,  // 4  
        0x05, 0x00,  // 5
        0xFE, 0xFF,  // -2
        0x03, 0x00,  // 3
        0x64, 0x00,  // 100
        0xCE, 0xFF,  // -50
    ];
    
    // xmm1: [3, 4], [2, -1], [5, 6], [2, 3]
    let xmm1_data = vec![
        0x03, 0x00,  // 3
        0x04, 0x00,  // 4
        0x02, 0x00,  // 2
        0xFF, 0xFF,  // -1
        0x05, 0x00,  // 5
        0x06, 0x00,  // 6
        0x02, 0x00,  // 2
        0x03, 0x00,  // 3
    ];
    
    emu.mem_write(0x100400, &xmm0_data).unwrap();
    emu.mem_write(0x100410, &xmm1_data).unwrap();
    
    // Execute instructions
    emu.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 3).unwrap();
    
    let result = emu.xmm_read(Register::XMM0);
    
    // Expected results:
    // Pair 0: 2*3 + 3*4 = 6 + 12 = 18
    // Pair 1: 4*2 + 5*(-1) = 8 - 5 = 3
    // Pair 2: (-2)*5 + 3*6 = -10 + 18 = 8
    // Pair 3: 100*2 + (-50)*3 = 200 - 150 = 50
    let expected = 
        18u128 |
        (3u128 << 32) |
        (8u128 << 64) |
        (50u128 << 96);
        
    assert_eq!(result, expected, "PMADDWD failed: got {:#034x}, expected {:#034x}", result, expected);
}

#[test]
fn test_pmaddwd_overflow() {
    let mut emu = Engine::new(EngineMode::Mode64);
    
    // Test PMADDWD with values that cause overflow in intermediate calculations
    let code = vec![
        // movdqa xmm0, [rsp]
        0x66, 0x0F, 0x6F, 0x04, 0x24,
        // movdqa xmm1, [rsp+16]
        0x66, 0x0F, 0x6F, 0x4C, 0x24, 0x10,
        // pmaddwd xmm0, xmm1
        0x66, 0x0F, 0xF5, 0xC1,
    ];
    
    emu.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();
    emu.mem_map(0x100000, 0x1000, Permission::ALL).unwrap();
    emu.mem_write(0x1000, &code).unwrap();
    emu.reg_write(Register::RIP, 0x1000);
    emu.reg_write(Register::RSP, 0x100400);
    
    // Set up test data with large values
    // xmm0: [0x7FFF, 0x7FFF], [0x8000, 0x8000], [0x4000, 0x4000], [1, 1]
    let xmm0_data = vec![
        0xFF, 0x7F,  // 0x7FFF (32767)
        0xFF, 0x7F,  // 0x7FFF (32767)
        0x00, 0x80,  // 0x8000 (-32768)
        0x00, 0x80,  // 0x8000 (-32768)
        0x00, 0x40,  // 0x4000 (16384)
        0x00, 0x40,  // 0x4000 (16384)
        0x01, 0x00,  // 1
        0x01, 0x00,  // 1
    ];
    
    // xmm1: [2, 2], [2, 2], [3, 3], [0x7FFF, 0x8000]
    let xmm1_data = vec![
        0x02, 0x00,  // 2
        0x02, 0x00,  // 2
        0x02, 0x00,  // 2
        0x02, 0x00,  // 2
        0x03, 0x00,  // 3
        0x03, 0x00,  // 3
        0xFF, 0x7F,  // 0x7FFF (32767)
        0x00, 0x80,  // 0x8000 (-32768)
    ];
    
    emu.mem_write(0x100400, &xmm0_data).unwrap();
    emu.mem_write(0x100410, &xmm1_data).unwrap();
    
    // Execute instructions
    emu.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 3).unwrap();
    
    let result = emu.xmm_read(Register::XMM0);
    
    // Expected results (with wrapping arithmetic):
    // Pair 0: 32767*2 + 32767*2 = 65534 + 65534 = 131068 (0x1FFFC)
    // Pair 1: (-32768)*2 + (-32768)*2 = -65536 + -65536 = -131072 (0xFFFE0000)
    // Pair 2: 16384*3 + 16384*3 = 49152 + 49152 = 98304 (0x18000)
    // Pair 3: 1*32767 + 1*(-32768) = 32767 - 32768 = -1 (0xFFFFFFFF)
    let expected = 
        0x1FFFCu128 |
        (0xFFFE0000u128 << 32) |
        (0x18000u128 << 64) |
        (0xFFFFFFFFu128 << 96);
        
    assert_eq!(result, expected, "PMADDWD overflow test failed: got {:#034x}, expected {:#034x}", result, expected);
}

#[test]
fn test_pmaddwd_memory() {
    let mut emu = Engine::new(EngineMode::Mode64);
    
    // Test PMADDWD with memory operand
    let code = vec![
        // movdqa xmm0, [rsp]
        0x66, 0x0F, 0x6F, 0x04, 0x24,
        // pmaddwd xmm0, [rsp+16]
        0x66, 0x0F, 0xF5, 0x44, 0x24, 0x10,
    ];
    
    emu.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();
    emu.mem_map(0x100000, 0x1000, Permission::ALL).unwrap();
    emu.mem_write(0x1000, &code).unwrap();
    emu.reg_write(Register::RIP, 0x1000);
    emu.reg_write(Register::RSP, 0x100400);
    
    // Set up simple test data
    // xmm0: [1, 2], [3, 4], [5, 6], [7, 8]
    let xmm0_data = vec![
        0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00,
        0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08, 0x00,
    ];
    
    // memory: [1, 1], [1, 1], [1, 1], [1, 1]
    let mem_data = vec![
        0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00,
        0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00,
    ];
    
    emu.mem_write(0x100400, &xmm0_data).unwrap();
    emu.mem_write(0x100410, &mem_data).unwrap();
    
    // Execute instructions
    emu.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 2).unwrap();
    
    let result = emu.xmm_read(Register::XMM0);
    
    // Expected results:
    // Pair 0: 1*1 + 2*1 = 1 + 2 = 3
    // Pair 1: 3*1 + 4*1 = 3 + 4 = 7
    // Pair 2: 5*1 + 6*1 = 5 + 6 = 11
    // Pair 3: 7*1 + 8*1 = 7 + 8 = 15
    let expected = 
        3u128 |
        (7u128 << 32) |
        (11u128 << 64) |
        (15u128 << 96);
    
    assert_eq!(result, expected, "PMADDWD memory test failed: got {:#034x}, expected {:#034x}", result, expected);
}

#[test]
fn test_pmaddwd_negative() {
    let mut emu = Engine::new(EngineMode::Mode64);
    
    // Test PMADDWD with negative values
    let code = vec![
        // movdqa xmm0, [rsp]
        0x66, 0x0F, 0x6F, 0x04, 0x24,
        // movdqa xmm1, [rsp+16]
        0x66, 0x0F, 0x6F, 0x4C, 0x24, 0x10,
        // pmaddwd xmm0, xmm1
        0x66, 0x0F, 0xF5, 0xC1,
    ];
    
    emu.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();
    emu.mem_map(0x100000, 0x1000, Permission::ALL).unwrap();
    emu.mem_write(0x1000, &code).unwrap();
    emu.reg_write(Register::RIP, 0x1000);
    emu.reg_write(Register::RSP, 0x100400);
    
    // Set up test data with negative values
    // xmm0: [-1, -1], [10, -10], [-5, 5], [0, 0]
    let xmm0_data = vec![
        0xFF, 0xFF,  // -1
        0xFF, 0xFF,  // -1
        0x0A, 0x00,  // 10
        0xF6, 0xFF,  // -10
        0xFB, 0xFF,  // -5
        0x05, 0x00,  // 5
        0x00, 0x00,  // 0
        0x00, 0x00,  // 0
    ];
    
    // xmm1: [-2, 2], [5, 5], [-3, -3], [100, -100]
    let xmm1_data = vec![
        0xFE, 0xFF,  // -2
        0x02, 0x00,  // 2
        0x05, 0x00,  // 5
        0x05, 0x00,  // 5
        0xFD, 0xFF,  // -3
        0xFD, 0xFF,  // -3
        0x64, 0x00,  // 100
        0x9C, 0xFF,  // -100
    ];
    
    emu.mem_write(0x100400, &xmm0_data).unwrap();
    emu.mem_write(0x100410, &xmm1_data).unwrap();
    
    // Execute instructions
    emu.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 3).unwrap();
    
    let result = emu.xmm_read(Register::XMM0);
    
    // Expected results:
    // Pair 0: (-1)*(-2) + (-1)*2 = 2 - 2 = 0
    // Pair 1: 10*5 + (-10)*5 = 50 - 50 = 0
    // Pair 2: (-5)*(-3) + 5*(-3) = 15 - 15 = 0
    // Pair 3: 0*100 + 0*(-100) = 0 + 0 = 0
    let expected = 0u128;
        
    assert_eq!(result, expected, "PMADDWD negative test failed: got {:#034x}, expected {:#034x}", result, expected);
}