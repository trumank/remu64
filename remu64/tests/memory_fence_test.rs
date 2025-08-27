use remu64::{Engine, EngineMode, Register};
use remu64::memory::{MemoryTrait, Permission};

#[test]
fn test_mfence() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // MFENCE instruction - full memory fence
    let code = vec![
        // Some memory operations before fence
        0x48, 0xc7, 0x00, 0x01, 0x00, 0x00, 0x00, // mov qword [rax], 1
        0x0f, 0xae, 0xf0, // mfence
        // Memory operations after fence
        0x48, 0xc7, 0x00, 0x02, 0x00, 0x00, 0x00, // mov qword [rax], 2
        0x90, // nop
    ];
    
    let base = 0x1000;
    let data_addr = 0x2000;
    
    // Map code and data regions
    engine.memory.map(base, 0x1000, Permission::READ | Permission::WRITE | Permission::EXEC).unwrap();
    engine.memory.map(data_addr, 0x1000, Permission::READ | Permission::WRITE).unwrap();
    engine.memory.write(base, &code).unwrap();
    
    // Set RAX to point to data region
    engine.reg_write(Register::RAX, data_addr);
    
    // Execute the code
    engine.emu_start(base, base + code.len() as u64, 0, 0).unwrap();
    
    // Check that memory was written (fence doesn't prevent writes, just orders them)
    let mut result = [0u8; 8];
    engine.memory.read(data_addr, &mut result).unwrap();
    assert_eq!(u64::from_le_bytes(result), 2); // Final value should be 2
    
    // RIP should be at the end
    assert_eq!(engine.reg_read(Register::RIP), base + code.len() as u64);
}

#[test]
fn test_sfence() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // SFENCE instruction - store fence
    let code = vec![
        // Store operations before fence
        0x48, 0xc7, 0x00, 0xaa, 0x00, 0x00, 0x00, // mov qword [rax], 0xaa
        0x0f, 0xae, 0xf8, // sfence
        // Store operations after fence
        0x48, 0xc7, 0x00, 0xbb, 0x00, 0x00, 0x00, // mov qword [rax], 0xbb
        0x90, // nop
    ];
    
    let base = 0x1000;
    let data_addr = 0x2000;
    
    // Map code and data regions
    engine.memory.map(base, 0x1000, Permission::READ | Permission::WRITE | Permission::EXEC).unwrap();
    engine.memory.map(data_addr, 0x1000, Permission::READ | Permission::WRITE).unwrap();
    engine.memory.write(base, &code).unwrap();
    
    // Set RAX to point to data region
    engine.reg_write(Register::RAX, data_addr);
    
    // Execute the code
    engine.emu_start(base, base + code.len() as u64, 0, 0).unwrap();
    
    // Check that stores completed in order
    let mut result = [0u8; 8];
    engine.memory.read(data_addr, &mut result).unwrap();
    assert_eq!(u64::from_le_bytes(result), 0xbb); // Final value should be 0xbb
    
    // RIP should be at the end
    assert_eq!(engine.reg_read(Register::RIP), base + code.len() as u64);
}

#[test]
fn test_lfence() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // LFENCE instruction - load fence
    let code = vec![
        // Load operations before fence
        0x48, 0x8b, 0x18, // mov rbx, [rax]
        0x0f, 0xae, 0xe8, // lfence
        // Load operations after fence
        0x48, 0x8b, 0x08, // mov rcx, [rax]
        0x90, // nop
    ];
    
    let base = 0x1000;
    let data_addr = 0x2000;
    
    // Map code and data regions
    engine.memory.map(base, 0x1000, Permission::READ | Permission::WRITE | Permission::EXEC).unwrap();
    engine.memory.map(data_addr, 0x1000, Permission::READ | Permission::WRITE).unwrap();
    engine.memory.write(base, &code).unwrap();
    
    // Write test data
    let test_value = 0x123456789abcdef0u64;
    engine.memory.write(data_addr, &test_value.to_le_bytes()).unwrap();
    
    // Set RAX to point to data region
    engine.reg_write(Register::RAX, data_addr);
    
    // Execute the code
    engine.emu_start(base, base + code.len() as u64, 0, 0).unwrap();
    
    // Check that loads completed correctly
    assert_eq!(engine.reg_read(Register::RBX), test_value);
    assert_eq!(engine.reg_read(Register::RCX), test_value);
    
    // RIP should be at the end
    assert_eq!(engine.reg_read(Register::RIP), base + code.len() as u64);
}

#[test]
fn test_multiple_fences() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Test multiple fence instructions in sequence
    let code = vec![
        0x48, 0xc7, 0x00, 0x01, 0x00, 0x00, 0x00, // mov qword [rax], 1
        0x0f, 0xae, 0xf0, // mfence
        0x48, 0xc7, 0x00, 0x02, 0x00, 0x00, 0x00, // mov qword [rax], 2
        0x0f, 0xae, 0xf8, // sfence
        0x48, 0x8b, 0x18, // mov rbx, [rax]
        0x0f, 0xae, 0xe8, // lfence
        0x48, 0x8b, 0x08, // mov rcx, [rax]
        0x0f, 0xae, 0xf0, // mfence (again)
        0x90, // nop
    ];
    
    let base = 0x1000;
    let data_addr = 0x2000;
    
    // Map code and data regions
    engine.memory.map(base, 0x1000, Permission::READ | Permission::WRITE | Permission::EXEC).unwrap();
    engine.memory.map(data_addr, 0x1000, Permission::READ | Permission::WRITE).unwrap();
    engine.memory.write(base, &code).unwrap();
    
    // Set RAX to point to data region
    engine.reg_write(Register::RAX, data_addr);
    
    // Execute the code - should not crash or error
    engine.emu_start(base, base + code.len() as u64, 0, 0).unwrap();
    
    // Check final state
    let mut result = [0u8; 8];
    engine.memory.read(data_addr, &mut result).unwrap();
    assert_eq!(u64::from_le_bytes(result), 2); // Final store value
    assert_eq!(engine.reg_read(Register::RBX), 2); // Loaded after second store
    assert_eq!(engine.reg_read(Register::RCX), 2); // Also loaded after second store
    
    // RIP should be at the end
    assert_eq!(engine.reg_read(Register::RIP), base + code.len() as u64);
}

#[test]
fn test_fence_with_sse() {
    let mut engine = Engine::new(EngineMode::Mode64);
    
    // Test fence instructions with SSE memory operations
    let code = vec![
        // SSE store before fence
        0x0f, 0x11, 0x00, // movups [rax], xmm0
        0x0f, 0xae, 0xf0, // mfence
        // SSE load after fence
        0x0f, 0x10, 0x08, // movups xmm1, [rax]
        0x90, // nop
    ];
    
    let base = 0x1000;
    let data_addr = 0x2000;
    
    // Map code and data regions
    engine.memory.map(base, 0x1000, Permission::READ | Permission::WRITE | Permission::EXEC).unwrap();
    engine.memory.map(data_addr, 0x1000, Permission::READ | Permission::WRITE).unwrap();
    engine.memory.write(base, &code).unwrap();
    
    // Set test value in XMM0
    let test_xmm_value = 0x123456789abcdef0fedcba9876543210u128;
    engine.xmm_write(Register::XMM0, test_xmm_value);
    
    // Set RAX to point to data region
    engine.reg_write(Register::RAX, data_addr);
    
    // Execute the code
    engine.emu_start(base, base + code.len() as u64, 0, 0).unwrap();
    
    // Check that SSE operations completed correctly
    assert_eq!(engine.xmm_read(Register::XMM1), test_xmm_value);
    
    // Verify memory contains the SSE data
    let mut result = [0u8; 16];
    engine.memory.read(data_addr, &mut result).unwrap();
    assert_eq!(u128::from_le_bytes(result), test_xmm_value);
    
    // RIP should be at the end
    assert_eq!(engine.reg_read(Register::RIP), base + code.len() as u64);
}