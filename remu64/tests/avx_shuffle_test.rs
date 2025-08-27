use remu64::{Engine, EngineMode, Permission, Register, memory::MemoryTrait};

#[test]
fn test_vshufps_xmm() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Initialize XMM1 = [1.0, 2.0, 3.0, 4.0]
    let xmm1_data: u128 = (1.0_f32.to_bits() as u128)
        | ((2.0_f32.to_bits() as u128) << 32)
        | ((3.0_f32.to_bits() as u128) << 64)
        | ((4.0_f32.to_bits() as u128) << 96);

    // Initialize XMM2 = [5.0, 6.0, 7.0, 8.0]
    let xmm2_data: u128 = (5.0_f32.to_bits() as u128)
        | ((6.0_f32.to_bits() as u128) << 32)
        | ((7.0_f32.to_bits() as u128) << 64)
        | ((8.0_f32.to_bits() as u128) << 96);

    engine.xmm_write(Register::XMM1, xmm1_data);
    engine.xmm_write(Register::XMM2, xmm2_data);

    // vshufps xmm3, xmm1, xmm2, 0xE4
    // imm8 = 0xE4 (11100100b)
    // bits [1:0] = 00 -> select src1[0] = 1.0
    // bits [3:2] = 01 -> select src1[1] = 2.0
    // bits [5:4] = 10 -> select src2[2] = 7.0
    // bits [7:6] = 11 -> select src2[3] = 8.0
    // Expected: XMM3 = [1.0, 2.0, 7.0, 8.0]
    let code = vec![0xC5, 0xF0, 0xC6, 0xDA, 0xE4];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Check XMM3 result
    let result = engine.xmm_read(Register::XMM3);
    assert_eq!(result & 0xFFFFFFFF, 1.0_f32.to_bits() as u128);
    assert_eq!((result >> 32) & 0xFFFFFFFF, 2.0_f32.to_bits() as u128);
    assert_eq!((result >> 64) & 0xFFFFFFFF, 7.0_f32.to_bits() as u128);
    assert_eq!((result >> 96) & 0xFFFFFFFF, 8.0_f32.to_bits() as u128);
}

#[test]
fn test_vshufps_ymm() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Initialize YMM1 = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]
    let ymm1_low: u128 = (1.0_f32.to_bits() as u128)
        | ((2.0_f32.to_bits() as u128) << 32)
        | ((3.0_f32.to_bits() as u128) << 64)
        | ((4.0_f32.to_bits() as u128) << 96);
    let ymm1_high: u128 = (5.0_f32.to_bits() as u128)
        | ((6.0_f32.to_bits() as u128) << 32)
        | ((7.0_f32.to_bits() as u128) << 64)
        | ((8.0_f32.to_bits() as u128) << 96);

    // Initialize YMM2 = [9.0, 10.0, 11.0, 12.0, 13.0, 14.0, 15.0, 16.0]
    let ymm2_low: u128 = (9.0_f32.to_bits() as u128)
        | ((10.0_f32.to_bits() as u128) << 32)
        | ((11.0_f32.to_bits() as u128) << 64)
        | ((12.0_f32.to_bits() as u128) << 96);
    let ymm2_high: u128 = (13.0_f32.to_bits() as u128)
        | ((14.0_f32.to_bits() as u128) << 32)
        | ((15.0_f32.to_bits() as u128) << 64)
        | ((16.0_f32.to_bits() as u128) << 96);

    engine.ymm_write(Register::YMM1, [ymm1_low, ymm1_high]);
    engine.ymm_write(Register::YMM2, [ymm2_low, ymm2_high]);

    // vshufps ymm3, ymm1, ymm2, 0x1B
    // imm8 = 0x1B (00011011b)
    // bits [1:0] = 11 -> select src1[3]
    // bits [3:2] = 10 -> select src1[2]
    // bits [5:4] = 01 -> select src2[1]
    // bits [7:6] = 00 -> select src2[0]
    // Expected lower 128: [4.0, 3.0, 10.0, 9.0]
    // Expected upper 128: [8.0, 7.0, 14.0, 13.0]
    let code = vec![0xC5, 0xF4, 0xC6, 0xDA, 0x1B];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Check YMM3 result
    let [result_low, result_high] = engine.ymm_read(Register::YMM3);

    // Check lower 128 bits
    assert_eq!(result_low & 0xFFFFFFFF, 4.0_f32.to_bits() as u128);
    assert_eq!((result_low >> 32) & 0xFFFFFFFF, 3.0_f32.to_bits() as u128);
    assert_eq!((result_low >> 64) & 0xFFFFFFFF, 10.0_f32.to_bits() as u128);
    assert_eq!((result_low >> 96) & 0xFFFFFFFF, 9.0_f32.to_bits() as u128);

    // Check upper 128 bits
    assert_eq!(result_high & 0xFFFFFFFF, 8.0_f32.to_bits() as u128);
    assert_eq!((result_high >> 32) & 0xFFFFFFFF, 7.0_f32.to_bits() as u128);
    assert_eq!((result_high >> 64) & 0xFFFFFFFF, 14.0_f32.to_bits() as u128);
    assert_eq!((result_high >> 96) & 0xFFFFFFFF, 13.0_f32.to_bits() as u128);
}

#[test]
fn test_vshufpd_xmm() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Initialize XMM1 = [1.0, 2.0] (doubles)
    let xmm1_data: u128 = (1.0_f64.to_bits() as u128) | ((2.0_f64.to_bits() as u128) << 64);

    // Initialize XMM2 = [3.0, 4.0] (doubles)
    let xmm2_data: u128 = (3.0_f64.to_bits() as u128) | ((4.0_f64.to_bits() as u128) << 64);

    engine.xmm_write(Register::XMM1, xmm1_data);
    engine.xmm_write(Register::XMM2, xmm2_data);

    // vshufpd xmm3, xmm1, xmm2, 0x01
    // imm8 = 0x01 (01b)
    // bit 0 = 1 -> select src1[1] = 2.0
    // bit 1 = 0 -> select src2[0] = 3.0
    // Expected: XMM3 = [2.0, 3.0]
    let code = vec![0xC5, 0xF1, 0xC6, 0xDA, 0x01];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Check XMM3 result
    let result = engine.xmm_read(Register::XMM3);
    assert_eq!(result & 0xFFFFFFFFFFFFFFFF, 2.0_f64.to_bits() as u128);
    assert_eq!(result >> 64, 3.0_f64.to_bits() as u128);
}

#[test]
fn test_vshufpd_ymm() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Initialize YMM1 = [1.0, 2.0, 3.0, 4.0] (doubles)
    let ymm1_low: u128 = (1.0_f64.to_bits() as u128) | ((2.0_f64.to_bits() as u128) << 64);
    let ymm1_high: u128 = (3.0_f64.to_bits() as u128) | ((4.0_f64.to_bits() as u128) << 64);

    // Initialize YMM2 = [5.0, 6.0, 7.0, 8.0] (doubles)
    let ymm2_low: u128 = (5.0_f64.to_bits() as u128) | ((6.0_f64.to_bits() as u128) << 64);
    let ymm2_high: u128 = (7.0_f64.to_bits() as u128) | ((8.0_f64.to_bits() as u128) << 64);

    engine.ymm_write(Register::YMM1, [ymm1_low, ymm1_high]);
    engine.ymm_write(Register::YMM2, [ymm2_low, ymm2_high]);

    // vshufpd ymm3, ymm1, ymm2, 0x0A
    // imm8 = 0x0A (1010b)
    // bit 0 = 0 -> lower 128: select src1[0] = 1.0
    // bit 1 = 1 -> lower 128: select src2[1] = 6.0
    // bit 2 = 0 -> upper 128: select src1[0] = 3.0
    // bit 3 = 1 -> upper 128: select src2[1] = 8.0
    // Expected: YMM3 = [1.0, 6.0, 3.0, 8.0]
    let code = vec![0xC5, 0xF5, 0xC6, 0xDA, 0x0A];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Check YMM3 result
    let [result_low, result_high] = engine.ymm_read(Register::YMM3);

    // Check lower 128 bits
    assert_eq!(result_low & 0xFFFFFFFFFFFFFFFF, 1.0_f64.to_bits() as u128);
    assert_eq!(result_low >> 64, 6.0_f64.to_bits() as u128);

    // Check upper 128 bits
    assert_eq!(result_high & 0xFFFFFFFFFFFFFFFF, 3.0_f64.to_bits() as u128);
    assert_eq!(result_high >> 64, 8.0_f64.to_bits() as u128);
}

#[test]
fn test_vshufps_memory() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x2000, Permission::ALL).unwrap();

    // Store data for memory operand at 0x1100: [5.0, 6.0, 7.0, 8.0]
    let mem_data = [
        5.0_f32.to_le_bytes(),
        6.0_f32.to_le_bytes(),
        7.0_f32.to_le_bytes(),
        8.0_f32.to_le_bytes(),
    ];
    let mut mem_bytes = Vec::new();
    for bytes in &mem_data {
        mem_bytes.extend_from_slice(bytes);
    }
    engine.memory.write(0x1100, &mem_bytes).unwrap();

    // Initialize XMM1 = [1.0, 2.0, 3.0, 4.0]
    let xmm1_data: u128 = (1.0_f32.to_bits() as u128)
        | ((2.0_f32.to_bits() as u128) << 32)
        | ((3.0_f32.to_bits() as u128) << 64)
        | ((4.0_f32.to_bits() as u128) << 96);

    engine.xmm_write(Register::XMM1, xmm1_data);
    engine.reg_write(Register::RAX, 0x1100);

    // vshufps xmm2, xmm1, [rax], 0x44
    // imm8 = 0x44 (01000100b)
    // bits [1:0] = 00 -> select src1[0] = 1.0
    // bits [3:2] = 01 -> select src1[1] = 2.0
    // bits [5:4] = 00 -> select mem[0] = 5.0
    // bits [7:6] = 01 -> select mem[1] = 6.0
    // Expected: XMM2 = [1.0, 2.0, 5.0, 6.0]
    let code = vec![0xC5, 0xF0, 0xC6, 0x10, 0x44];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // Check XMM2 result
    let result = engine.xmm_read(Register::XMM2);
    assert_eq!(result & 0xFFFFFFFF, 1.0_f32.to_bits() as u128);
    assert_eq!((result >> 32) & 0xFFFFFFFF, 2.0_f32.to_bits() as u128);
    assert_eq!((result >> 64) & 0xFFFFFFFF, 5.0_f32.to_bits() as u128);
    assert_eq!((result >> 96) & 0xFFFFFFFF, 6.0_f32.to_bits() as u128);
}
