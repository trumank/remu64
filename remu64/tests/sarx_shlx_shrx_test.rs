use remu64::{Engine, EngineMode, Permission, Register, memory::MemoryTrait};

fn setup_engine() -> Engine<impl MemoryTrait> {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x2000, Permission::ALL).unwrap();
    engine
}

#[test]
fn test_sarx_basic() {
    let mut engine = setup_engine();

    // Test arithmetic right shift with negative number
    // -8 (0xFFFFFFFFFFFFFFF8) >> 2 = -2 (0xFFFFFFFFFFFFFFFE)
    let code = vec![
        0x48, 0xC7, 0xC0, 0xF8, 0xFF, 0xFF, 0xFF, // mov rax, -8
        0x48, 0xC7, 0xC1, 0x02, 0x00, 0x00, 0x00, // mov rcx, 2
        0xC4, 0xE2, 0xF2, 0xF7, 0xD8, // sarx rbx, rax, rcx (VEX.LZ.F2.0F38.W1)
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(
        engine.reg_read(Register::RBX),
        0xFFFFFFFFFFFFFFFE,
        "SARX should sign-extend"
    );
}

#[test]
fn test_sarx_positive() {
    let mut engine = setup_engine();

    // Test with positive number: 0x80 >> 4 = 0x08
    let code = vec![
        0x48, 0xC7, 0xC0, 0x80, 0x00, 0x00, 0x00, // mov rax, 0x80
        0x48, 0xC7, 0xC2, 0x04, 0x00, 0x00, 0x00, // mov rdx, 4
        0xC4, 0xE2, 0xEA, 0xF7, 0xD8, // sarx rbx, rax, rdx
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(
        engine.reg_read(Register::RBX),
        0x08,
        "SARX on positive should work like SHR"
    );
}

#[test]
fn test_sarx_no_flags() {
    let mut engine = setup_engine();

    // Test that SARX doesn't modify flags
    let code = vec![
        0x48, 0x31, 0xC0, // xor rax, rax (sets ZF)
        0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF, // mov rcx, -1
        0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00, // mov rdx, 1
        0xC4, 0xE2, 0xEA, 0xF7, 0xD9, // sarx rbx, rcx, rdx
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert!(
        engine.cpu.rflags.contains(remu64::cpu::Flags::ZF),
        "ZF should remain set"
    );
    assert_eq!(
        engine.reg_read(Register::RBX),
        0xFFFFFFFFFFFFFFFF,
        "SARX should sign-extend -1"
    );
}

#[test]
fn test_sarx_32bit() {
    let mut engine = setup_engine();

    // Test 32-bit SARX with negative number
    let code = vec![
        0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x80, // mov rax, 0x80000000 (INT32_MIN)
        0x48, 0xC7, 0xC1, 0x1F, 0x00, 0x00, 0x00, // mov rcx, 31
        0xC4, 0xE2, 0x72, 0xF7, 0xD8, // sarx ebx, eax, ecx (32-bit)
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(
        engine.reg_read(Register::RBX) & 0xFFFFFFFF,
        0xFFFFFFFF,
        "32-bit SARX should sign-extend MSB"
    );
}

#[test]
fn test_shlx_basic() {
    let mut engine = setup_engine();

    // Test shift left: 0x01 << 4 = 0x10
    let code = vec![
        0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, // mov rax, 1
        0x48, 0xC7, 0xC1, 0x04, 0x00, 0x00, 0x00, // mov rcx, 4
        0xC4, 0xE2, 0xF1, 0xF7, 0xD8, // shlx rbx, rax, rcx
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(
        engine.reg_read(Register::RBX),
        0x10,
        "SHLX should shift left"
    );
}

#[test]
fn test_shlx_overflow() {
    let mut engine = setup_engine();

    // Test that bits shift out without setting overflow
    let code = vec![
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x80, // mov rax, 0x8000000000000000
        0x48, 0xC7, 0xC1, 0x01, 0x00, 0x00, 0x00, // mov rcx, 1
        0xC4, 0xE2, 0xF1, 0xF7, 0xD8, // shlx rbx, rax, rcx
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(
        engine.reg_read(Register::RBX),
        0,
        "SHLX should shift out MSB"
    );
}

#[test]
fn test_shrx_basic() {
    let mut engine = setup_engine();

    // Test logical right shift: 0x80 >> 4 = 0x08
    let code = vec![
        0x48, 0xC7, 0xC0, 0x80, 0x00, 0x00, 0x00, // mov rax, 0x80
        0x48, 0xC7, 0xC1, 0x04, 0x00, 0x00, 0x00, // mov rcx, 4
        0xC4, 0xE2, 0xF3, 0xF7, 0xD8, // shrx rbx, rax, rcx
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(
        engine.reg_read(Register::RBX),
        0x08,
        "SHRX should shift right"
    );
}

#[test]
fn test_shrx_no_sign_extend() {
    let mut engine = setup_engine();

    // Test that SHRX does NOT sign extend (unlike SARX)
    let code = vec![
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x80, // mov rax, 0x8000000000000000
        0x48, 0xC7, 0xC1, 0x01, 0x00, 0x00, 0x00, // mov rcx, 1
        0xC4, 0xE2, 0xF3, 0xF7, 0xD8, // shrx rbx, rax, rcx
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(
        engine.reg_read(Register::RBX),
        0x4000000000000000,
        "SHRX should not sign-extend"
    );
}

#[test]
fn test_shift_modulo() {
    let mut engine = setup_engine();

    // Test that shift counts are taken modulo operand size
    let code = vec![
        0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, // mov rax, 1
        0x48, 0xC7, 0xC1, 0x41, 0x00, 0x00, 0x00, // mov rcx, 65 (65 & 0x3F = 1)
        0xC4, 0xE2, 0xF1, 0xF7, 0xD8, // shlx rbx, rax, rcx
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(
        engine.reg_read(Register::RBX),
        0x02,
        "Shift by 65 should be same as shift by 1"
    );
}

#[test]
fn test_32bit_shifts() {
    let mut engine = setup_engine();

    // Test 32-bit versions
    let code = vec![
        // SHLX 32-bit
        0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, // mov rax, 1
        0x48, 0xC7, 0xC1, 0x08, 0x00, 0x00, 0x00, // mov rcx, 8
        0xC4, 0xE2, 0x71, 0xF7, 0xD8, // shlx ebx, eax, ecx
        // SHRX 32-bit
        0x48, 0xC7, 0xC0, 0x00, 0x01, 0x00, 0x00, // mov rax, 0x100
        0x48, 0xC7, 0xC1, 0x04, 0x00, 0x00, 0x00, // mov rcx, 4
        0xC4, 0xE2, 0x73, 0xF7, 0xE8, // shrx ebp, eax, ecx
        // SARX 32-bit with sign bit
        0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x80, // mov rax, 0x80000000
        0x48, 0xC7, 0xC1, 0x04, 0x00, 0x00, 0x00, // mov rcx, 4
        0xC4, 0xE2, 0x72, 0xF7, 0xF0, // sarx esi, eax, ecx
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(
        engine.reg_read(Register::RBX) & 0xFFFFFFFF,
        0x100,
        "32-bit SHLX"
    );
    assert_eq!(
        engine.reg_read(Register::RBP) & 0xFFFFFFFF,
        0x10,
        "32-bit SHRX"
    );
    assert_eq!(
        engine.reg_read(Register::RSI) & 0xFFFFFFFF,
        0xF8000000,
        "32-bit SARX"
    );
}

#[test]
fn test_zero_shift_count() {
    let mut engine = setup_engine();

    // Test shift by 0 (no change)
    let code = vec![
        0x48, 0xC7, 0xC0, 0x42, 0x00, 0x00, 0x00, // mov rax, 0x42
        0x48, 0x31, 0xC9, // xor rcx, rcx (rcx = 0)
        0xC4, 0xE2, 0xF1, 0xF7, 0xD8, // shlx rbx, rax, rcx
        0xC4, 0xE2, 0xF3, 0xF7, 0xE8, // shrx rbp, rax, rcx
        0xC4, 0xE2, 0xF2, 0xF7, 0xF0, // sarx rsi, rax, rcx
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(engine.reg_read(Register::RBX), 0x42, "SHLX by 0");
    assert_eq!(engine.reg_read(Register::RBP), 0x42, "SHRX by 0");
    assert_eq!(engine.reg_read(Register::RSI), 0x42, "SARX by 0");
}
