use remu64::{Engine, EngineMode, Permission, Register, memory::MemoryTrait};

#[test]
fn test_vcmpps_xmm_equal() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Set up test values
    engine.xmm_write(Register::XMM1, 0x3F800000_3F800000_3F800000_3F800000); // 1.0, 1.0, 1.0, 1.0
    engine.xmm_write(Register::XMM2, 0x3F800000_3F800000_3F800000_3F800000); // 1.0, 1.0, 1.0, 1.0
    
    // VCMPPS XMM0, XMM1, XMM2, 0 (Equal)
    let code = vec![0xC5, 0xF0, 0xC2, 0xC2, 0x00];
    engine.memory.write(0x1000, &code).unwrap();
    
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    // All comparisons should be true (all bits set)
    assert_eq!(engine.xmm_read(Register::XMM0), 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF);
}

#[test]
fn test_vcmpps_xmm_less_than() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Set up test values
    engine.xmm_write(Register::XMM1, 0x40800000_40400000_40000000_3F800000); // 4.0, 3.0, 2.0, 1.0
    engine.xmm_write(Register::XMM2, 0x40A00000_40800000_40400000_40000000); // 5.0, 4.0, 3.0, 2.0
    
    // VCMPPS XMM0, XMM1, XMM2, 1 (Less than)
    let code = vec![0xC5, 0xF0, 0xC2, 0xC2, 0x01];
    engine.memory.write(0x1000, &code).unwrap();
    
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    // All comparisons should be true (all bits set)
    assert_eq!(engine.xmm_read(Register::XMM0), 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF);
}

#[test]
fn test_vcmpps_ymm_mixed_comparison() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Set up test values - 8 floats
    engine.ymm_write(Register::YMM1, [
        0x40800000_40400000_40000000_3F800000, // 4.0, 3.0, 2.0, 1.0
        0x41000000_40E00000_40C00000_40A00000, // 8.0, 7.0, 6.0, 5.0
    ]);
    engine.ymm_write(Register::YMM2, [
        0x40A00000_40400000_40000000_40000000, // 5.0, 3.0, 2.0, 2.0
        0x41000000_40E00000_40E00000_40A00000, // 8.0, 7.0, 7.0, 5.0
    ]);
    
    // VCMPPS YMM0, YMM1, YMM2, 1 (Less than)
    let code = vec![0xC5, 0xF4, 0xC2, 0xC2, 0x01];
    engine.memory.write(0x1000, &code).unwrap();
    
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    let result = engine.ymm_read(Register::YMM0);
    // Check each comparison:
    // 1.0 < 2.0: true
    assert_eq!((result[0] & 0xFFFFFFFF) as u32, 0xFFFFFFFF);
    // 2.0 < 2.0: false
    assert_eq!(((result[0] >> 32) & 0xFFFFFFFF) as u32, 0x00000000);
    // 3.0 < 3.0: false
    assert_eq!(((result[0] >> 64) & 0xFFFFFFFF) as u32, 0x00000000);
    // 4.0 < 5.0: true
    assert_eq!(((result[0] >> 96) & 0xFFFFFFFF) as u32, 0xFFFFFFFF);
    // 5.0 < 5.0: false
    assert_eq!((result[1] & 0xFFFFFFFF) as u32, 0x00000000);
    // 6.0 < 7.0: true
    assert_eq!(((result[1] >> 32) & 0xFFFFFFFF) as u32, 0xFFFFFFFF);
    // 7.0 < 7.0: false
    assert_eq!(((result[1] >> 64) & 0xFFFFFFFF) as u32, 0x00000000);
    // 8.0 < 8.0: false
    assert_eq!(((result[1] >> 96) & 0xFFFFFFFF) as u32, 0x00000000);
}

#[test]
fn test_vcmpps_memory_operand() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    engine.memory.map(0x2000, 0x1000, Permission::ALL).unwrap();
    
    // Set up test values
    engine.xmm_write(Register::XMM1, 0x40800000_40400000_40000000_3F800000); // 4.0, 3.0, 2.0, 1.0
    
    // Write comparison values to memory
    let mem_addr = 0x2000;
    let data = 0x40A00000_40800000_40400000_40000000u128; // 5.0, 4.0, 3.0, 2.0
    engine.memory.write(mem_addr, &data.to_le_bytes()).unwrap();
    engine.cpu.write_reg(Register::RDI, mem_addr as u64);
    
    // VCMPPS XMM0, XMM1, [RDI], 2 (Less than or equal)
    let code = vec![0xC5, 0xF0, 0xC2, 0x07, 0x02];
    engine.memory.write(0x1000, &code).unwrap();
    
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    // All comparisons should be true (1.0 <= 2.0, 2.0 <= 3.0, 3.0 <= 4.0, 4.0 <= 5.0)
    assert_eq!(engine.xmm_read(Register::XMM0), 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF);
}

#[test]
fn test_vcmppd_xmm_equal() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Set up test values - 2 doubles
    engine.xmm_write(Register::XMM1, 0x3FF0000000000000_3FF0000000000000); // 1.0, 1.0
    engine.xmm_write(Register::XMM2, 0x3FF0000000000000_3FF0000000000000); // 1.0, 1.0
    
    // VCMPPD XMM0, XMM1, XMM2, 0 (Equal)
    let code = vec![0xC5, 0xF1, 0xC2, 0xC2, 0x00];
    engine.memory.write(0x1000, &code).unwrap();
    
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    // Both comparisons should be true (all bits set)
    assert_eq!(engine.xmm_read(Register::XMM0), 0xFFFFFFFFFFFFFFFF_FFFFFFFFFFFFFFFF);
}

#[test]
fn test_vcmppd_xmm_greater_than() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Set up test values - 2 doubles
    engine.xmm_write(Register::XMM1, 0x4008000000000000_4000000000000000); // 3.0, 2.0
    engine.xmm_write(Register::XMM2, 0x4000000000000000_3FF0000000000000); // 2.0, 1.0
    
    // VCMPPD XMM0, XMM1, XMM2, 14 (Greater than)
    let code = vec![0xC5, 0xF1, 0xC2, 0xC2, 0x0E];
    engine.memory.write(0x1000, &code).unwrap();
    
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    // Both comparisons should be true (2.0 > 1.0, 3.0 > 2.0)
    assert_eq!(engine.xmm_read(Register::XMM0), 0xFFFFFFFFFFFFFFFF_FFFFFFFFFFFFFFFF);
}

#[test]
fn test_vcmppd_ymm_mixed() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Set up test values - 4 doubles
    engine.ymm_write(Register::YMM1, [
        0x4000000000000000_3FF0000000000000, // 2.0, 1.0
        0x4010000000000000_4008000000000000, // 4.0, 3.0
    ]);
    engine.ymm_write(Register::YMM2, [
        0x4000000000000000_4000000000000000, // 2.0, 2.0
        0x4014000000000000_4008000000000000, // 5.0, 3.0
    ]);
    
    // VCMPPD YMM0, YMM1, YMM2, 1 (Less than)
    let code = vec![0xC5, 0xF5, 0xC2, 0xC2, 0x01];
    engine.memory.write(0x1000, &code).unwrap();
    
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    let result = engine.ymm_read(Register::YMM0);
    // Check each comparison:
    // 1.0 < 2.0: true
    assert_eq!((result[0] & 0xFFFFFFFFFFFFFFFF), 0xFFFFFFFFFFFFFFFF);
    // 2.0 < 2.0: false
    assert_eq!((result[0] >> 64), 0x0000000000000000);
    // 3.0 < 3.0: false
    assert_eq!((result[1] & 0xFFFFFFFFFFFFFFFF), 0x0000000000000000);
    // 4.0 < 5.0: true
    assert_eq!((result[1] >> 64), 0xFFFFFFFFFFFFFFFF);
}

#[test]
fn test_vcmpps_nan_handling() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Set up test values with NaN
    let nan_bits = 0x7FC00000u32; // NaN
    engine.xmm_write(Register::XMM1, 
        ((nan_bits as u128) << 96) | 
        (0x3F800000u128 << 64) | // 1.0
        (0x40000000u128 << 32) | // 2.0
        0x3F800000u128); // 1.0
    engine.xmm_write(Register::XMM2, 0x3F800000_3F800000_3F800000_3F800000); // 1.0, 1.0, 1.0, 1.0
    
    // VCMPPS XMM0, XMM1, XMM2, 3 (Unordered - true if either operand is NaN)
    let code = vec![0xC5, 0xF0, 0xC2, 0xC2, 0x03];
    engine.memory.write(0x1000, &code).unwrap();
    
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    let result = engine.xmm_read(Register::XMM0);
    // First comparison (1.0 vs 1.0): false (not NaN)
    assert_eq!((result & 0xFFFFFFFF) as u32, 0x00000000);
    // Second comparison (2.0 vs 1.0): false (not NaN)
    assert_eq!(((result >> 32) & 0xFFFFFFFF) as u32, 0x00000000);
    // Third comparison (1.0 vs 1.0): false (not NaN)
    assert_eq!(((result >> 64) & 0xFFFFFFFF) as u32, 0x00000000);
    // Fourth comparison (NaN vs 1.0): true (one operand is NaN)
    assert_eq!(((result >> 96) & 0xFFFFFFFF) as u32, 0xFFFFFFFF);
}

#[test]
fn test_vcmpps_ordered_check() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Set up test values with NaN
    let nan_bits = 0x7FC00000u32; // NaN
    engine.xmm_write(Register::XMM1, 
        ((nan_bits as u128) << 96) | 
        (0x3F800000u128 << 64) | // 1.0
        (0x40000000u128 << 32) | // 2.0
        0x3F800000u128); // 1.0
    engine.xmm_write(Register::XMM2, 0x3F800000_3F800000_3F800000_3F800000); // 1.0, 1.0, 1.0, 1.0
    
    // VCMPPS XMM0, XMM1, XMM2, 7 (Ordered - true if neither operand is NaN)
    let code = vec![0xC5, 0xF0, 0xC2, 0xC2, 0x07];
    engine.memory.write(0x1000, &code).unwrap();
    
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    let result = engine.xmm_read(Register::XMM0);
    // First three comparisons: true (neither operand is NaN)
    assert_eq!((result & 0xFFFFFFFF) as u32, 0xFFFFFFFF);
    assert_eq!(((result >> 32) & 0xFFFFFFFF) as u32, 0xFFFFFFFF);
    assert_eq!(((result >> 64) & 0xFFFFFFFF) as u32, 0xFFFFFFFF);
    // Fourth comparison: false (one operand is NaN)
    assert_eq!(((result >> 96) & 0xFFFFFFFF) as u32, 0x00000000);
}

#[test]
fn test_vcmppd_false_true_predicates() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Set up any test values
    engine.xmm_write(Register::XMM1, 0x4000000000000000_3FF0000000000000); // 2.0, 1.0
    engine.xmm_write(Register::XMM2, 0x3FF0000000000000_4008000000000000); // 1.0, 3.0
    
    // Test FALSE predicate (11)
    let code = vec![0xC5, 0xF1, 0xC2, 0xC2, 0x0B];
    engine.memory.write(0x1000, &code).unwrap();
    
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    // Both comparisons should be false (all bits clear)
    assert_eq!(engine.xmm_read(Register::XMM0), 0x0000000000000000_0000000000000000);
    
    // Test TRUE predicate (15)
    let code = vec![0xC5, 0xF1, 0xC2, 0xC2, 0x0F];
    engine.memory.write(0x1100, &code).unwrap();
    
    engine.emu_start(0x1100, 0x1100 + code.len() as u64, 0, 0).unwrap();
    
    // Both comparisons should be true (all bits set)
    assert_eq!(engine.xmm_read(Register::XMM0), 0xFFFFFFFFFFFFFFFF_FFFFFFFFFFFFFFFF);
}

#[test]
fn test_vcmpps_not_equal() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    // Set up test values
    engine.xmm_write(Register::XMM1, 0x40800000_40400000_40000000_3F800000); // 4.0, 3.0, 2.0, 1.0
    engine.xmm_write(Register::XMM2, 0x40A00000_40400000_40000000_40000000); // 5.0, 3.0, 2.0, 2.0
    
    // VCMPPS XMM0, XMM1, XMM2, 4 (Not equal)
    let code = vec![0xC5, 0xF0, 0xC2, 0xC2, 0x04];
    engine.memory.write(0x1000, &code).unwrap();
    
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    let result = engine.xmm_read(Register::XMM0);
    // 1.0 != 2.0: true
    assert_eq!((result & 0xFFFFFFFF) as u32, 0xFFFFFFFF);
    // 2.0 != 2.0: false
    assert_eq!(((result >> 32) & 0xFFFFFFFF) as u32, 0x00000000);
    // 3.0 != 3.0: false
    assert_eq!(((result >> 64) & 0xFFFFFFFF) as u32, 0x00000000);
    // 4.0 != 5.0: true
    assert_eq!(((result >> 96) & 0xFFFFFFFF) as u32, 0xFFFFFFFF);
}

#[test]
fn test_vcmppd_memory_256bit() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    engine.memory.map(0x2000, 0x1000, Permission::ALL).unwrap();
    
    // Set up test values
    engine.ymm_write(Register::YMM1, [
        0x4000000000000000_3FF0000000000000, // 2.0, 1.0
        0x4010000000000000_4008000000000000, // 4.0, 3.0
    ]);
    
    // Write comparison values to memory
    let mem_addr = 0x2000;
    let data1 = 0x4008000000000000_3FF0000000000000u128; // 3.0, 1.0
    let data2 = 0x4010000000000000_4008000000000000u128; // 4.0, 3.0
    engine.memory.write(mem_addr, &data1.to_le_bytes()).unwrap();
    engine.memory.write(mem_addr + 16, &data2.to_le_bytes()).unwrap();
    engine.cpu.write_reg(Register::RDI, mem_addr as u64);
    
    // VCMPPD YMM0, YMM1, [RDI], 13 (Greater than or equal)
    let code = vec![0xC5, 0xF5, 0xC2, 0x07, 0x0D];
    engine.memory.write(0x1000, &code).unwrap();
    
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    let result = engine.ymm_read(Register::YMM0);
    // 1.0 >= 1.0: true
    assert_eq!((result[0] & 0xFFFFFFFFFFFFFFFF), 0xFFFFFFFFFFFFFFFF);
    // 2.0 >= 3.0: false
    assert_eq!((result[0] >> 64), 0x0000000000000000);
    // 3.0 >= 3.0: true
    assert_eq!((result[1] & 0xFFFFFFFFFFFFFFFF), 0xFFFFFFFFFFFFFFFF);
    // 4.0 >= 4.0: true
    assert_eq!((result[1] >> 64), 0xFFFFFFFFFFFFFFFF);
}