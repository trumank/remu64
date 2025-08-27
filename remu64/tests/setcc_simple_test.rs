use remu64::{Engine, EngineMode, Permission, Register, memory::MemoryTrait};

#[test] 
fn test_seta_setae_setb() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    let code = vec![
        // Test CF=0, ZF=0 (5 > 3)
        0x48, 0xc7, 0xc0, 0x05, 0x00, 0x00, 0x00, // mov rax, 5
        0x48, 0xc7, 0xc3, 0x03, 0x00, 0x00, 0x00, // mov rbx, 3
        0x48, 0x39, 0xd8,                          // cmp rax, rbx
        0x0f, 0x97, 0xc1,                          // seta cl
        0x0f, 0x93, 0xc2,                          // setae dl
        0x0f, 0x92, 0xc6,                          // setb sil
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.reg_read(Register::CL), 1, "SETA should set for 5 > 3");
    assert_eq!(engine.reg_read(Register::DL), 1, "SETAE should set for 5 >= 3");
    assert_eq!(engine.reg_read(Register::SIL), 0, "SETB should not set for 5 > 3");
}

#[test]
fn test_setg_setge_setl_setle() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    let code = vec![
        // Test positive comparison 5 > 3 (SF=0, OF=0, ZF=0)
        0x48, 0xc7, 0xc0, 0x05, 0x00, 0x00, 0x00, // mov rax, 5
        0x48, 0xc7, 0xc3, 0x03, 0x00, 0x00, 0x00, // mov rbx, 3
        0x48, 0x39, 0xd8,                          // cmp rax, rbx
        0x0f, 0x9f, 0xc1,                          // setg cl
        0x0f, 0x9d, 0xc2,                          // setge dl
        0x0f, 0x9c, 0xc6,                          // setl sil
        0x0f, 0x9e, 0xc7,                          // setle dil
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.reg_read(Register::CL), 1, "SETG should set for 5 > 3");
    assert_eq!(engine.reg_read(Register::DL), 1, "SETGE should set for 5 > 3");
    assert_eq!(engine.reg_read(Register::SIL), 0, "SETL should not set for 5 > 3");
    assert_eq!(engine.reg_read(Register::DIL), 0, "SETLE should not set for 5 > 3");
}

#[test]
fn test_sets_setns() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    let code = vec![
        // Create negative result (SF=1)
        0x48, 0xc7, 0xc0, 0x00, 0x00, 0x00, 0x00, // mov rax, 0
        0x48, 0xff, 0xc8,                          // dec rax (result = -1, SF=1)
        0x0f, 0x98, 0xc1,                          // sets cl
        0x0f, 0x99, 0xc2,                          // setns dl
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.reg_read(Register::CL), 1, "SETS should set when SF=1");
    assert_eq!(engine.reg_read(Register::DL), 0, "SETNS should not set when SF=1");
}

#[test]
fn test_seto_setno() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    let code = vec![
        // Test with overflow
        0xb0, 0x7f,       // mov al, 127
        0xb3, 0x01,       // mov bl, 1
        0x00, 0xd8,       // add al, bl (127 + 1 = -128 signed overflow)
        0x0f, 0x90, 0xc1, // seto cl
        0x0f, 0x91, 0xc2, // setno dl
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.reg_read(Register::CL), 1, "SETO should set when OF=1");
    assert_eq!(engine.reg_read(Register::DL), 0, "SETNO should not set when OF=1");
}

#[test]
fn test_setp_setnp() {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
    
    let code = vec![
        // Test with even parity (2 bits set)
        0xb0, 0x03,       // mov al, 0x03 (00000011 - 2 bits)
        0x84, 0xc0,       // test al, al
        0x0f, 0x9a, 0xc1, // setp cl
        0x0f, 0x9b, 0xc2, // setnp dl
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.reg_read(Register::CL), 1, "SETP should set when PF=1 (even parity)");
    assert_eq!(engine.reg_read(Register::DL), 0, "SETNP should not set when PF=1");
}