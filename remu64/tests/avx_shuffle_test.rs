use remu64::{Engine, Result};
use std::mem;

#[test]
fn test_vshufps_xmm() -> Result<()> {
    let mut engine = Engine::new();
    
    // Test VSHUFPS xmm1, xmm2, xmm3, imm8
    // imm8 = 0xE4 (11100100b)
    // bits [1:0] = 00 -> select src1[0]
    // bits [3:2] = 01 -> select src1[1]
    // bits [5:4] = 10 -> select src2[2]
    // bits [7:6] = 11 -> select src2[3]
    let code = vec![
        // Load test values into xmm1 and xmm2
        0xC5, 0xF8, 0x10, 0x0D, 0x10, 0x00, 0x00, 0x00,  // vmovups xmm1, [rip+0x10]
        0xC5, 0xF8, 0x10, 0x15, 0x18, 0x00, 0x00, 0x00,  // vmovups xmm2, [rip+0x18]
        
        // vshufps xmm3, xmm1, xmm2, 0xE4
        0xC5, 0xF0, 0xC6, 0xDA, 0xE4,                     
        
        0xF4,  // hlt
        
        // Padding
        0x00, 0x00, 0x00,
        
        // Data for xmm1: [1.0, 2.0, 3.0, 4.0]
        0x00, 0x00, 0x80, 0x3F,  // 1.0f
        0x00, 0x00, 0x00, 0x40,  // 2.0f
        0x00, 0x00, 0x40, 0x40,  // 3.0f
        0x00, 0x00, 0x80, 0x40,  // 4.0f
        
        // Data for xmm2: [5.0, 6.0, 7.0, 8.0]
        0x00, 0x00, 0xA0, 0x40,  // 5.0f
        0x00, 0x00, 0xC0, 0x40,  // 6.0f
        0x00, 0x00, 0xE0, 0x40,  // 7.0f
        0x00, 0x00, 0x00, 0x41,  // 8.0f
    ];
    
    engine.load_code(&code, 0x1000)?;
    engine.cpu.set_rip(0x1000);
    engine.run()?;
    
    // Check XMM3 result
    let xmm3 = engine.cpu.read_xmm(3)?;
    
    // Expected: [1.0, 2.0, 7.0, 8.0] based on imm8=0xE4
    let expected_floats = [1.0f32, 2.0f32, 7.0f32, 8.0f32];
    
    for i in 0..4 {
        let result_bytes = &xmm3[i*4..(i+1)*4];
        let result_float = f32::from_le_bytes([
            result_bytes[0], result_bytes[1], result_bytes[2], result_bytes[3]
        ]);
        
        assert!(
            (result_float - expected_floats[i]).abs() < 0.0001,
            "XMM3[{}]: expected {}, got {}",
            i, expected_floats[i], result_float
        );
    }
    
    Ok(())
}

#[test]
fn test_vshufps_ymm() -> Result<()> {
    let mut engine = Engine::new();
    
    // Test VSHUFPS ymm1, ymm2, ymm3, imm8
    // imm8 = 0x1B (00011011b)
    // Lower 128 bits and upper 128 bits use same shuffle pattern
    let code = vec![
        // Load test values into ymm1 and ymm2
        0xC5, 0xFC, 0x10, 0x0D, 0x18, 0x00, 0x00, 0x00,  // vmovups ymm1, [rip+0x18]
        0xC5, 0xFC, 0x10, 0x15, 0x30, 0x00, 0x00, 0x00,  // vmovups ymm2, [rip+0x30]
        
        // vshufps ymm3, ymm1, ymm2, 0x1B
        0xC5, 0xF4, 0xC6, 0xDA, 0x1B,                     
        
        0xF4,  // hlt
        
        // Padding
        0x00, 0x00, 0x00, 0x00, 0x00,
        
        // Data for ymm1: [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]
        0x00, 0x00, 0x80, 0x3F,  // 1.0f
        0x00, 0x00, 0x00, 0x40,  // 2.0f
        0x00, 0x00, 0x40, 0x40,  // 3.0f
        0x00, 0x00, 0x80, 0x40,  // 4.0f
        0x00, 0x00, 0xA0, 0x40,  // 5.0f
        0x00, 0x00, 0xC0, 0x40,  // 6.0f
        0x00, 0x00, 0xE0, 0x40,  // 7.0f
        0x00, 0x00, 0x00, 0x41,  // 8.0f
        
        // Data for ymm2: [9.0, 10.0, 11.0, 12.0, 13.0, 14.0, 15.0, 16.0]
        0x00, 0x00, 0x10, 0x41,  // 9.0f
        0x00, 0x00, 0x20, 0x41,  // 10.0f
        0x00, 0x00, 0x30, 0x41,  // 11.0f
        0x00, 0x00, 0x40, 0x41,  // 12.0f
        0x00, 0x00, 0x50, 0x41,  // 13.0f
        0x00, 0x00, 0x60, 0x41,  // 14.0f
        0x00, 0x00, 0x70, 0x41,  // 15.0f
        0x00, 0x00, 0x80, 0x41,  // 16.0f
    ];
    
    engine.load_code(&code, 0x1000)?;
    engine.cpu.set_rip(0x1000);
    engine.run()?;
    
    // Check YMM3 result
    let ymm3 = engine.cpu.read_ymm(3)?;
    
    // imm8 = 0x1B (00011011b)
    // bits [1:0] = 11 -> select src1[3]
    // bits [3:2] = 10 -> select src1[2]
    // bits [5:4] = 01 -> select src2[1]
    // bits [7:6] = 00 -> select src2[0]
    // Expected lower 128: [4.0, 3.0, 10.0, 9.0]
    // Expected upper 128: [8.0, 7.0, 14.0, 13.0]
    let expected_floats = [
        4.0f32, 3.0f32, 10.0f32, 9.0f32,    // Lower 128 bits
        8.0f32, 7.0f32, 14.0f32, 13.0f32,   // Upper 128 bits
    ];
    
    for i in 0..8 {
        let result_bytes = &ymm3[i*4..(i+1)*4];
        let result_float = f32::from_le_bytes([
            result_bytes[0], result_bytes[1], result_bytes[2], result_bytes[3]
        ]);
        
        assert!(
            (result_float - expected_floats[i]).abs() < 0.0001,
            "YMM3[{}]: expected {}, got {}",
            i, expected_floats[i], result_float
        );
    }
    
    Ok(())
}

#[test]
fn test_vshufpd_xmm() -> Result<()> {
    let mut engine = Engine::new();
    
    // Test VSHUFPD xmm1, xmm2, xmm3, imm8
    // imm8 = 0x01 (01b)
    // bit 0 = 1 -> select src1[1]
    // bit 1 = 0 -> select src2[0]
    let code = vec![
        // Load test values into xmm1 and xmm2
        0xC5, 0xF9, 0x10, 0x0D, 0x10, 0x00, 0x00, 0x00,  // vmovupd xmm1, [rip+0x10]
        0xC5, 0xF9, 0x10, 0x15, 0x18, 0x00, 0x00, 0x00,  // vmovupd xmm2, [rip+0x18]
        
        // vshufpd xmm3, xmm1, xmm2, 0x01
        0xC5, 0xF1, 0xC6, 0xDA, 0x01,                     
        
        0xF4,  // hlt
        
        // Padding
        0x00, 0x00, 0x00,
        
        // Data for xmm1: [1.0, 2.0]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x3F,  // 1.0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,  // 2.0
        
        // Data for xmm2: [3.0, 4.0]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x40,  // 3.0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x40,  // 4.0
    ];
    
    engine.load_code(&code, 0x1000)?;
    engine.cpu.set_rip(0x1000);
    engine.run()?;
    
    // Check XMM3 result
    let xmm3 = engine.cpu.read_xmm(3)?;
    
    // Expected: [2.0, 3.0]
    let expected_doubles = [2.0f64, 3.0f64];
    
    for i in 0..2 {
        let result_bytes = &xmm3[i*8..(i+1)*8];
        let result_double = f64::from_le_bytes([
            result_bytes[0], result_bytes[1], result_bytes[2], result_bytes[3],
            result_bytes[4], result_bytes[5], result_bytes[6], result_bytes[7]
        ]);
        
        assert!(
            (result_double - expected_doubles[i]).abs() < 0.0001,
            "XMM3[{}]: expected {}, got {}",
            i, expected_doubles[i], result_double
        );
    }
    
    Ok(())
}

#[test]
fn test_vshufpd_ymm() -> Result<()> {
    let mut engine = Engine::new();
    
    // Test VSHUFPD ymm1, ymm2, ymm3, imm8
    // imm8 = 0x0A (1010b)
    // bits [0] = 0 -> lower 128: select src1[0]
    // bits [1] = 1 -> lower 128: select src2[1]
    // bits [2] = 0 -> upper 128: select src1[0]
    // bits [3] = 1 -> upper 128: select src2[1]
    let code = vec![
        // Load test values into ymm1 and ymm2
        0xC5, 0xFD, 0x10, 0x0D, 0x18, 0x00, 0x00, 0x00,  // vmovupd ymm1, [rip+0x18]
        0xC5, 0xFD, 0x10, 0x15, 0x30, 0x00, 0x00, 0x00,  // vmovupd ymm2, [rip+0x30]
        
        // vshufpd ymm3, ymm1, ymm2, 0x0A
        0xC5, 0xF5, 0xC6, 0xDA, 0x0A,                     
        
        0xF4,  // hlt
        
        // Padding
        0x00, 0x00, 0x00, 0x00, 0x00,
        
        // Data for ymm1: [1.0, 2.0, 3.0, 4.0]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x3F,  // 1.0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,  // 2.0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x40,  // 3.0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x40,  // 4.0
        
        // Data for ymm2: [5.0, 6.0, 7.0, 8.0]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x40,  // 5.0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x40,  // 6.0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1C, 0x40,  // 7.0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x40,  // 8.0
    ];
    
    engine.load_code(&code, 0x1000)?;
    engine.cpu.set_rip(0x1000);
    engine.run()?;
    
    // Check YMM3 result
    let ymm3 = engine.cpu.read_ymm(3)?;
    
    // Expected: [1.0, 6.0, 3.0, 8.0]
    let expected_doubles = [1.0f64, 6.0f64, 3.0f64, 8.0f64];
    
    for i in 0..4 {
        let result_bytes = &ymm3[i*8..(i+1)*8];
        let result_double = f64::from_le_bytes([
            result_bytes[0], result_bytes[1], result_bytes[2], result_bytes[3],
            result_bytes[4], result_bytes[5], result_bytes[6], result_bytes[7]
        ]);
        
        assert!(
            (result_double - expected_doubles[i]).abs() < 0.0001,
            "YMM3[{}]: expected {}, got {}",
            i, expected_doubles[i], result_double
        );
    }
    
    Ok(())
}

#[test]
fn test_vshufps_memory() -> Result<()> {
    let mut engine = Engine::new();
    
    // Test VSHUFPS with memory operand
    let code = vec![
        // Load value into xmm1
        0xC5, 0xF8, 0x10, 0x0D, 0x14, 0x00, 0x00, 0x00,  // vmovups xmm1, [rip+0x14]
        
        // vshufps xmm2, xmm1, [rip+0x1C], 0x44
        0xC5, 0xF0, 0xC6, 0x15, 0x1C, 0x00, 0x00, 0x00, 0x44,
        
        0xF4,  // hlt
        
        // Padding
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        
        // Data for xmm1: [1.0, 2.0, 3.0, 4.0]
        0x00, 0x00, 0x80, 0x3F,  // 1.0f
        0x00, 0x00, 0x00, 0x40,  // 2.0f
        0x00, 0x00, 0x40, 0x40,  // 3.0f
        0x00, 0x00, 0x80, 0x40,  // 4.0f
        
        // Memory data: [5.0, 6.0, 7.0, 8.0]
        0x00, 0x00, 0xA0, 0x40,  // 5.0f
        0x00, 0x00, 0xC0, 0x40,  // 6.0f
        0x00, 0x00, 0xE0, 0x40,  // 7.0f
        0x00, 0x00, 0x00, 0x41,  // 8.0f
    ];
    
    engine.load_code(&code, 0x1000)?;
    engine.cpu.set_rip(0x1000);
    engine.run()?;
    
    // Check XMM2 result
    let xmm2 = engine.cpu.read_xmm(2)?;
    
    // imm8 = 0x44 (01000100b)
    // bits [1:0] = 00 -> select src1[0] = 1.0
    // bits [3:2] = 01 -> select src1[1] = 2.0
    // bits [5:4] = 00 -> select mem[0] = 5.0
    // bits [7:6] = 01 -> select mem[1] = 6.0
    let expected_floats = [1.0f32, 2.0f32, 5.0f32, 6.0f32];
    
    for i in 0..4 {
        let result_bytes = &xmm2[i*4..(i+1)*4];
        let result_float = f32::from_le_bytes([
            result_bytes[0], result_bytes[1], result_bytes[2], result_bytes[3]
        ]);
        
        assert!(
            (result_float - expected_floats[i]).abs() < 0.0001,
            "XMM2[{}]: expected {}, got {}",
            i, expected_floats[i], result_float
        );
    }
    
    Ok(())
}