use amd64_emu::{Engine, EngineMode, Permission, Register};

#[test]
fn test_loop_basic() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory
    engine.mem_map(0x1000, 0x1000, Permission::READ | Permission::WRITE | Permission::EXEC).unwrap();

    // LOOP instruction test
    // mov rcx, 5
    // xor rax, rax    ; Clear RAX
    // loop_start:
    // inc rax         ; Increment RAX
    // loop loop_start ; Decrement RCX and jump if not zero
    // nop             ; Landing point
    let code = vec![
        0x48, 0xC7, 0xC1, 0x05, 0x00, 0x00, 0x00, // mov rcx, 5
        0x48, 0x31, 0xC0,                         // xor rax, rax
        0x48, 0xFF, 0xC0,                         // inc rax
        0xE2, 0xFB,                               // loop -5 (back to inc rax)
        0x90,                                     // nop
    ];

    engine.mem_write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();

    // After 5 iterations, RAX should be 5 and RCX should be 0
    assert_eq!(engine.reg_read(Register::RAX).unwrap(), 5);
    assert_eq!(engine.reg_read(Register::RCX).unwrap(), 0);
}

#[test]
fn test_loope_condition_met() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory
    engine.mem_map(0x1000, 0x1000, Permission::READ | Permission::WRITE | Permission::EXEC).unwrap();

    // LOOPE test - loop while ZF is set
    // mov rcx, 3
    // xor rax, rax    ; Clear RAX and set ZF
    // mov rbx, 2      ; Value to compare against
    // loop_start:
    // inc rax         ; Increment RAX
    // cmp rax, rbx    ; Compare RAX with RBX
    // loope loop_start; Loop while equal (ZF=1)
    // nop
    let code = vec![
        0x48, 0xC7, 0xC1, 0x03, 0x00, 0x00, 0x00, // mov rcx, 3
        0x48, 0x31, 0xC0,                         // xor rax, rax (sets ZF)
        0x48, 0xC7, 0xC3, 0x02, 0x00, 0x00, 0x00, // mov rbx, 2
        0x48, 0xFF, 0xC0,                         // inc rax
        0x48, 0x39, 0xD8,                         // cmp rax, rbx
        0xE1, 0xF8,                               // loope -8 (back to inc rax)
        0x90,                                     // nop
    ];

    engine.mem_write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();

    // After the loop, check the results
    let rax = engine.reg_read(Register::RAX).unwrap();
    let rcx = engine.reg_read(Register::RCX).unwrap();
    
    // Loop execution:
    // 1. RAX=0, RCX=3, ZF=1 (from XOR)
    // 2. INC RAX (RAX=1), CMP 1,2 (ZF=0), LOOPE: RCX=2, ZF=0 so exit loop
    // Final: RAX=1, RCX=2
    assert_eq!(rax, 1);
    assert_eq!(rcx, 2);
}

#[test]
fn test_loopne_condition_met() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory
    engine.mem_map(0x1000, 0x1000, Permission::READ | Permission::WRITE | Permission::EXEC).unwrap();

    // LOOPNE test - loop while ZF is not set
    // mov rcx, 5
    // xor rax, rax    ; Clear RAX
    // mov rbx, 3      ; Value to compare against
    // loop_start:
    // inc rax         ; Increment RAX
    // cmp rax, rbx    ; Compare RAX with RBX
    // loopne loop_start; Loop while not equal (ZF=0)
    // nop
    let code = vec![
        0x48, 0xC7, 0xC1, 0x05, 0x00, 0x00, 0x00, // mov rcx, 5
        0x48, 0x31, 0xC0,                         // xor rax, rax
        0x48, 0xC7, 0xC3, 0x03, 0x00, 0x00, 0x00, // mov rbx, 3
        0x48, 0xFF, 0xC0,                         // inc rax
        0x48, 0x39, 0xD8,                         // cmp rax, rbx
        0xE0, 0xF8,                               // loopne -8 (back to inc rax)
        0x90,                                     // nop
    ];

    engine.mem_write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();

    // Should stop when RAX == 3 (ZF=1), so RAX should be 3
    assert_eq!(engine.reg_read(Register::RAX).unwrap(), 3);
    assert_eq!(engine.reg_read(Register::RCX).unwrap(), 2); // 5 - 3 = 2 iterations left
}

#[test]
fn test_loop_zero_count() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory
    engine.mem_map(0x1000, 0x1000, Permission::READ | Permission::WRITE | Permission::EXEC).unwrap();

    // Test with RCX = 0 (should not loop)
    // mov rcx, 0
    // mov rax, 10     ; Set RAX to 10
    // loop_start:
    // inc rax         ; This should not execute
    // loop loop_start
    // nop
    let code = vec![
        0x48, 0xC7, 0xC1, 0x00, 0x00, 0x00, 0x00, // mov rcx, 0
        0x48, 0xC7, 0xC0, 0x0A, 0x00, 0x00, 0x00, // mov rax, 10
        0x48, 0xFF, 0xC0,                         // inc rax
        0xE2, 0xFB,                               // loop -5
        0x90,                                     // nop
    ];

    engine.mem_write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();

    // RAX should be 10 (not incremented) and RCX should wrap to 0xFFFFFFFFFFFFFFFF then not loop
    assert_eq!(engine.reg_read(Register::RAX).unwrap(), 10);
    assert_eq!(engine.reg_read(Register::RCX).unwrap(), 0xFFFFFFFFFFFFFFFF);
}

#[test]
fn test_loope_early_exit() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory
    engine.mem_map(0x1000, 0x1000, Permission::READ | Permission::WRITE | Permission::EXEC).unwrap();

    // Test LOOPE early exit when counter reaches zero
    // mov rcx, 2      ; Only 2 iterations
    // mov rax, 0
    // loop_start:
    // inc rax
    // xor rbx, rbx    ; Clear RBX and set ZF=1
    // loope loop_start
    // nop
    let code = vec![
        0x48, 0xC7, 0xC1, 0x02, 0x00, 0x00, 0x00, // mov rcx, 2
        0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00, // mov rax, 0
        0x48, 0xFF, 0xC0,                         // inc rax
        0x48, 0x31, 0xDB,                         // xor rbx, rbx (sets ZF)
        0xE1, 0xF9,                               // loope -7 (back to inc rax)
        0x90,                                     // nop
    ];

    engine.mem_write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();

    // Should have done 2 iterations
    assert_eq!(engine.reg_read(Register::RAX).unwrap(), 2);
    assert_eq!(engine.reg_read(Register::RCX).unwrap(), 0);
}