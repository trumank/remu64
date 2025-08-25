use amd64_emu::{Engine, EngineMode, Flags, Permission, Register};

#[test]
fn test_cmpps_equal() {
    let mut emu = Engine::new(EngineMode::Mode64);

    // Map memory for code
    emu.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Initialize XMM registers with test values
    // XMM0 = [1.0, 2.0, 3.0, 4.0]
    // XMM1 = [1.0, 5.0, 3.0, 6.0]
    let xmm0_val: u128 = (1.0_f32.to_bits() as u128)
        | ((2.0_f32.to_bits() as u128) << 32)
        | ((3.0_f32.to_bits() as u128) << 64)
        | ((4.0_f32.to_bits() as u128) << 96);

    let xmm1_val: u128 = (1.0_f32.to_bits() as u128)
        | ((5.0_f32.to_bits() as u128) << 32)
        | ((3.0_f32.to_bits() as u128) << 64)
        | ((6.0_f32.to_bits() as u128) << 96);

    emu.xmm_write(Register::XMM0, xmm0_val).unwrap();
    emu.xmm_write(Register::XMM1, xmm1_val).unwrap();

    // CMPPS XMM0, XMM1, 0 (equal comparison)
    // 0F C2 C1 00
    let code = vec![0x0F, 0xC2, 0xC1, 0x00];

    emu.mem_write(0x1000, &code).unwrap();
    emu.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0, None)
        .unwrap();

    // Check result - should be [0xFFFFFFFF, 0, 0xFFFFFFFF, 0]
    let result = emu.xmm_read(Register::XMM0).unwrap();
    assert_eq!(result & 0xFFFFFFFF, 0xFFFFFFFF); // First element equal
    assert_eq!((result >> 32) & 0xFFFFFFFF, 0); // Second element not equal
    assert_eq!((result >> 64) & 0xFFFFFFFF, 0xFFFFFFFF); // Third element equal
    assert_eq!((result >> 96) & 0xFFFFFFFF, 0); // Fourth element not equal
}

#[test]
fn test_cmpps_less_than() {
    let mut emu = Engine::new(EngineMode::Mode64);

    emu.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();

    // XMM0 = [1.0, 6.0, 2.0, 4.0]
    // XMM1 = [2.0, 5.0, 3.0, 3.0]
    let xmm0_val: u128 = (1.0_f32.to_bits() as u128)
        | ((6.0_f32.to_bits() as u128) << 32)
        | ((2.0_f32.to_bits() as u128) << 64)
        | ((4.0_f32.to_bits() as u128) << 96);

    let xmm1_val: u128 = (2.0_f32.to_bits() as u128)
        | ((5.0_f32.to_bits() as u128) << 32)
        | ((3.0_f32.to_bits() as u128) << 64)
        | ((3.0_f32.to_bits() as u128) << 96);

    emu.xmm_write(Register::XMM0, xmm0_val).unwrap();
    emu.xmm_write(Register::XMM1, xmm1_val).unwrap();

    // CMPPS XMM0, XMM1, 1 (less than comparison)
    let code = vec![0x0F, 0xC2, 0xC1, 0x01];

    emu.mem_write(0x1000, &code).unwrap();
    emu.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0, None)
        .unwrap();

    // Check result - should be [0xFFFFFFFF, 0, 0xFFFFFFFF, 0]
    let result = emu.xmm_read(Register::XMM0).unwrap();
    assert_eq!(result & 0xFFFFFFFF, 0xFFFFFFFF); // 1.0 < 2.0
    assert_eq!((result >> 32) & 0xFFFFFFFF, 0); // 6.0 not < 5.0
    assert_eq!((result >> 64) & 0xFFFFFFFF, 0xFFFFFFFF); // 2.0 < 3.0
    assert_eq!((result >> 96) & 0xFFFFFFFF, 0); // 4.0 not < 3.0
}

#[test]
fn test_cmpss_equal() {
    let mut emu = Engine::new(EngineMode::Mode64);

    emu.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();

    // XMM0 = [3.0, keep, keep, keep]
    // XMM1 = [3.0, x, x, x]
    let xmm0_val: u128 = (3.0_f32.to_bits() as u128)
        | ((99.0_f32.to_bits() as u128) << 32)
        | ((88.0_f32.to_bits() as u128) << 64)
        | ((77.0_f32.to_bits() as u128) << 96);

    let xmm1_val: u128 = 3.0_f32.to_bits() as u128;

    emu.xmm_write(Register::XMM0, xmm0_val).unwrap();
    emu.xmm_write(Register::XMM1, xmm1_val).unwrap();

    // CMPSS XMM0, XMM1, 0 (equal comparison)
    // F3 0F C2 C1 00
    let code = vec![0xF3, 0x0F, 0xC2, 0xC1, 0x00];

    emu.mem_write(0x1000, &code).unwrap();
    emu.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0, None)
        .unwrap();

    // Check result - only lowest 32 bits should be affected
    let result = emu.xmm_read(Register::XMM0).unwrap();
    assert_eq!(result & 0xFFFFFFFF, 0xFFFFFFFF); // Equal, so all 1s
                                                 // Upper bits should remain unchanged
    assert_eq!((result >> 32) & 0xFFFFFFFF, 99.0_f32.to_bits() as u128);
    assert_eq!((result >> 64) & 0xFFFFFFFF, 88.0_f32.to_bits() as u128);
    assert_eq!((result >> 96) & 0xFFFFFFFF, 77.0_f32.to_bits() as u128);
}

#[test]
fn test_comiss_equal() {
    let mut emu = Engine::new(EngineMode::Mode64);

    emu.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();

    // XMM0 = [5.0, ...]
    // XMM1 = [5.0, ...]
    let xmm0_val: u128 = 5.0_f32.to_bits() as u128;
    let xmm1_val: u128 = 5.0_f32.to_bits() as u128;

    emu.xmm_write(Register::XMM0, xmm0_val).unwrap();
    emu.xmm_write(Register::XMM1, xmm1_val).unwrap();

    // COMISS XMM0, XMM1
    // 0F 2F C1
    let code = vec![0x0F, 0x2F, 0xC1];

    emu.mem_write(0x1000, &code).unwrap();
    emu.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0, None)
        .unwrap();

    // Check EFLAGS for equal result
    let flags = emu.flags_read();
    assert!(flags.contains(amd64_emu::Flags::ZF)); // Zero flag set for equal
    assert!(!flags.contains(amd64_emu::Flags::CF)); // Carry flag clear
    assert!(!flags.contains(amd64_emu::Flags::PF)); // Parity flag clear
}

#[test]
fn test_comiss_less_than() {
    let mut emu = Engine::new(EngineMode::Mode64);

    emu.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();

    // XMM0 = [3.0, ...]
    // XMM1 = [7.0, ...]
    let xmm0_val: u128 = 3.0_f32.to_bits() as u128;
    let xmm1_val: u128 = 7.0_f32.to_bits() as u128;

    emu.xmm_write(Register::XMM0, xmm0_val).unwrap();
    emu.xmm_write(Register::XMM1, xmm1_val).unwrap();

    // COMISS XMM0, XMM1
    let code = vec![0x0F, 0x2F, 0xC1];

    emu.mem_write(0x1000, &code).unwrap();
    emu.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0, None)
        .unwrap();

    // Check EFLAGS for less than result
    let flags = emu.flags_read();
    assert!(!flags.contains(amd64_emu::Flags::ZF)); // Zero flag clear
    assert!(flags.contains(amd64_emu::Flags::CF)); // Carry flag set for less than
    assert!(!flags.contains(amd64_emu::Flags::PF)); // Parity flag clear
}

#[test]
fn test_comiss_greater_than() {
    let mut emu = Engine::new(EngineMode::Mode64);

    emu.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();

    // XMM0 = [9.0, ...]
    // XMM1 = [2.0, ...]
    let xmm0_val: u128 = 9.0_f32.to_bits() as u128;
    let xmm1_val: u128 = 2.0_f32.to_bits() as u128;

    emu.xmm_write(Register::XMM0, xmm0_val).unwrap();
    emu.xmm_write(Register::XMM1, xmm1_val).unwrap();

    // COMISS XMM0, XMM1
    let code = vec![0x0F, 0x2F, 0xC1];

    emu.mem_write(0x1000, &code).unwrap();
    emu.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0, None)
        .unwrap();

    // Check EFLAGS for greater than result
    let flags = emu.flags_read();
    assert!(!flags.contains(amd64_emu::Flags::ZF)); // Zero flag clear
    assert!(!flags.contains(amd64_emu::Flags::CF)); // Carry flag clear for greater than
    assert!(!flags.contains(amd64_emu::Flags::PF)); // Parity flag clear
}

#[test]
fn test_ucomiss_nan() {
    let mut emu = Engine::new(EngineMode::Mode64);

    emu.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();

    // XMM0 = [NaN, ...]
    // XMM1 = [5.0, ...]
    let xmm0_val: u128 = f32::NAN.to_bits() as u128;
    let xmm1_val: u128 = 5.0_f32.to_bits() as u128;

    emu.xmm_write(Register::XMM0, xmm0_val).unwrap();
    emu.xmm_write(Register::XMM1, xmm1_val).unwrap();

    // UCOMISS XMM0, XMM1
    // 0F 2E C1
    let code = vec![0x0F, 0x2E, 0xC1];

    emu.mem_write(0x1000, &code).unwrap();
    emu.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0, None)
        .unwrap();

    // Check EFLAGS for unordered result (NaN)
    let flags = emu.flags_read();
    assert!(flags.contains(amd64_emu::Flags::ZF)); // Zero flag set for unordered
    assert!(flags.contains(amd64_emu::Flags::CF)); // Carry flag set for unordered
    assert!(flags.contains(amd64_emu::Flags::PF)); // Parity flag set for unordered
}

#[test]
fn test_cmpps_unordered() {
    let mut emu = Engine::new(EngineMode::Mode64);

    emu.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();

    // XMM0 = [NaN, 2.0, NaN, 4.0]
    // XMM1 = [1.0, NaN, 3.0, 4.0]
    let xmm0_val: u128 = (f32::NAN.to_bits() as u128)
        | ((2.0_f32.to_bits() as u128) << 32)
        | ((f32::NAN.to_bits() as u128) << 64)
        | ((4.0_f32.to_bits() as u128) << 96);

    let xmm1_val: u128 = (1.0_f32.to_bits() as u128)
        | ((f32::NAN.to_bits() as u128) << 32)
        | ((3.0_f32.to_bits() as u128) << 64)
        | ((4.0_f32.to_bits() as u128) << 96);

    emu.xmm_write(Register::XMM0, xmm0_val).unwrap();
    emu.xmm_write(Register::XMM1, xmm1_val).unwrap();

    // CMPPS XMM0, XMM1, 3 (unordered comparison)
    let code = vec![0x0F, 0xC2, 0xC1, 0x03];

    emu.mem_write(0x1000, &code).unwrap();
    emu.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0, None)
        .unwrap();

    // Check result - NaN comparisons should return true for unordered
    let result = emu.xmm_read(Register::XMM0).unwrap();
    assert_eq!(result & 0xFFFFFFFF, 0xFFFFFFFF); // NaN vs anything is unordered
    assert_eq!((result >> 32) & 0xFFFFFFFF, 0xFFFFFFFF); // anything vs NaN is unordered
    assert_eq!((result >> 64) & 0xFFFFFFFF, 0xFFFFFFFF); // NaN vs anything is unordered
    assert_eq!((result >> 96) & 0xFFFFFFFF, 0); // 4.0 vs 4.0 is ordered
}
