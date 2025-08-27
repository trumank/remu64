use remu64::{Engine, EngineMode, Permission, Register, memory::MemoryTrait};

#[test]
fn test_shld_basic() {
    let mut engine = Engine::new(EngineMode::Mode64);

    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    // Test SHLD with immediate count
    let code = vec![
        0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x80, // mov rax, 0x8000000000000000
        0x48, 0xbb, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55,
        0xaa, // mov rbx, 0xAA55AA55AA55AA55
        0x48, 0x0f, 0xa4, 0xd8, 0x04, // shld rax, rbx, 4
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // After shifting left by 4 and filling from rbx
    // 0x8000000000000000 << 4 = 0x0000000000000000 (upper bits)
    // 0xAA55AA55AA55AA55 >> (64-4) = 0x0000000000000000A (lower bits to fill)
    // Result: 0x000000000000000A
    assert_eq!(engine.reg_read(Register::RAX), 0x000000000000000A);
}

#[test]
fn test_shld_32bit() {
    let mut engine = Engine::new(EngineMode::Mode64);

    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    let code = vec![
        0xb8, 0x00, 0x00, 0x00, 0x80, // mov eax, 0x80000000
        0xbb, 0x55, 0xaa, 0x55, 0xaa, // mov ebx, 0xAA55AA55
        0x0f, 0xa4, 0xd8, 0x04, // shld eax, ebx, 4
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // 0x80000000 << 4 = 0x00000000 (upper 28 bits)
    // 0xAA55AA55 >> (32-4) = 0x0000000A (lower 4 bits to fill)
    // Result: 0x0000000A
    assert_eq!(engine.reg_read(Register::EAX), 0x0000000A);
}

#[test]
fn test_shld_with_register_count() {
    let mut engine = Engine::new(EngineMode::Mode64);

    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    let code = vec![
        0x48, 0xc7, 0xc0, 0x34, 0x12, 0x00, 0x00, // mov rax, 0x1234
        0x48, 0xc7, 0xc3, 0xcd, 0xab, 0x00, 0x00, // mov rbx, 0xabcd
        0x48, 0xc7, 0xc1, 0x08, 0x00, 0x00, 0x00, // mov rcx, 8
        0x48, 0x0f, 0xa5, 0xd8, // shld rax, rbx, cl
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // 0x1234 << 8 = 0x123400
    // 0xabcd >> (64-8) = 0x00 (upper 8 bits of 0xabcd)
    // Result: 0x123400
    assert_eq!(engine.reg_read(Register::RAX), 0x123400);
}

#[test]
fn test_shrd_basic() {
    let mut engine = Engine::new(EngineMode::Mode64);

    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    let code = vec![
        0x48, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, // mov rax, 0x0000000000000001
        0x48, 0xbb, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55,
        0xaa, // mov rbx, 0xAA55AA55AA55AA55
        0x48, 0x0f, 0xac, 0xd8, 0x04, // shrd rax, rbx, 4
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // 0x0000000000000001 >> 4 = 0x0000000000000000
    // 0xAA55AA55AA55AA55 << (64-4) = 0x5000000000000000 (upper bits to fill)
    // Result: 0x5000000000000000
    assert_eq!(engine.reg_read(Register::RAX), 0x5000000000000000);
}

#[test]
fn test_shrd_32bit() {
    let mut engine = Engine::new(EngineMode::Mode64);

    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    let code = vec![
        0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 0x00000001
        0xbb, 0x55, 0xaa, 0x55, 0xaa, // mov ebx, 0xAA55AA55
        0x0f, 0xac, 0xd8, 0x04, // shrd eax, ebx, 4
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // 0x00000001 >> 4 = 0x00000000
    // 0xAA55AA55 << (32-4) = 0x50000000 (upper 4 bits to fill)
    // Result: 0x50000000
    assert_eq!(engine.reg_read(Register::EAX), 0x50000000);
}

#[test]
fn test_shrd_with_register_count() {
    let mut engine = Engine::new(EngineMode::Mode64);

    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    let code = vec![
        0x48, 0xc7, 0xc0, 0x34, 0x12, 0x00, 0x00, // mov rax, 0x1234
        0x48, 0xc7, 0xc3, 0xcd, 0xab, 0x00, 0x00, // mov rbx, 0xabcd
        0x48, 0xc7, 0xc1, 0x08, 0x00, 0x00, 0x00, // mov rcx, 8
        0x48, 0x0f, 0xad, 0xd8, // shrd rax, rbx, cl
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // 0x1234 >> 8 = 0x12
    // 0xabcd << (64-8) = 0xcd00000000000000
    // Result: 0xcd00000000000012
    assert_eq!(engine.reg_read(Register::RAX), 0xcd00000000000012);
}

#[test]
fn test_shld_carry_flag() {
    let mut engine = Engine::new(EngineMode::Mode64);

    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    let code = vec![
        0xb8, 0x00, 0x00, 0x00, 0x80, // mov eax, 0x80000000
        0xbb, 0x00, 0x00, 0x00, 0x00, // mov ebx, 0x00000000
        0x0f, 0xa4, 0xd8, 0x01, // shld eax, ebx, 1
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // The MSB (bit 31) of 0x80000000 should be shifted into CF
    assert!(engine.flags_read().contains(remu64::cpu::Flags::CF));
    assert_eq!(engine.reg_read(Register::EAX), 0x00000000);
}

#[test]
fn test_shrd_carry_flag() {
    let mut engine = Engine::new(EngineMode::Mode64);

    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    let code = vec![
        0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 0x00000001
        0xbb, 0x00, 0x00, 0x00, 0x00, // mov ebx, 0x00000000
        0x0f, 0xac, 0xd8, 0x01, // shrd eax, ebx, 1
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // The LSB (bit 0) of 0x00000001 should be shifted into CF
    assert!(engine.flags_read().contains(remu64::cpu::Flags::CF));
    assert_eq!(engine.reg_read(Register::EAX), 0x00000000);
}

#[test]
fn test_shld_zero_count() {
    let mut engine = Engine::new(EngineMode::Mode64);

    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    let code = vec![
        0x48, 0xc7, 0xc0, 0x34, 0x12, 0x00, 0x00, // mov rax, 0x1234
        0x48, 0xc7, 0xc3, 0xcd, 0xab, 0x00, 0x00, // mov rbx, 0xabcd
        0x48, 0x0f, 0xa4, 0xd8, 0x00, // shld rax, rbx, 0
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // With count=0, the destination should not change
    assert_eq!(engine.reg_read(Register::RAX), 0x1234);
}

#[test]
fn test_shrd_zero_count() {
    let mut engine = Engine::new(EngineMode::Mode64);

    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

    let code = vec![
        0x48, 0xc7, 0xc0, 0x34, 0x12, 0x00, 0x00, // mov rax, 0x1234
        0x48, 0xc7, 0xc3, 0xcd, 0xab, 0x00, 0x00, // mov rbx, 0xabcd
        0x48, 0x0f, 0xac, 0xd8, 0x00, // shrd rax, rbx, 0
    ];

    engine.memory.write(0x1000, &code).unwrap();
    engine
        .emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    // With count=0, the destination should not change
    assert_eq!(engine.reg_read(Register::RAX), 0x1234);
}
