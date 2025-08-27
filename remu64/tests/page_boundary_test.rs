use remu64::{DEFAULT_PAGE_SIZE, Engine, EngineMode, Permission, Register, memory::MemoryTrait};

#[test]
fn test_instruction_near_page_end() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map a single page for code
    let code_base = 0x1000;
    engine
        .memory
        .map(code_base, DEFAULT_PAGE_SIZE as usize, Permission::ALL)
        .unwrap();

    // Place a multi-byte instruction very close to the end of the page
    // Using a 7-byte instruction: mov rax, 0x1234567890abcdef
    let instruction = vec![0x48, 0xB8, 0xEF, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12];

    // Place instruction so it ends exactly at page boundary
    let instruction_addr = code_base + DEFAULT_PAGE_SIZE - instruction.len() as u64;

    engine
        .memory
        .write_code(instruction_addr, &instruction)
        .unwrap();

    // Execute the instruction near the page boundary
    engine
        .emu_start(
            instruction_addr,
            instruction_addr + instruction.len() as u64,
            0,
            0,
        )
        .unwrap();

    // Verify the instruction executed correctly
    assert_eq!(engine.reg_read(Register::RAX), 0x1234567890abcdef);
    assert_eq!(
        engine.reg_read(Register::RIP),
        instruction_addr + instruction.len() as u64
    );
}

#[test]
fn test_instruction_crossing_page_boundary() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map two consecutive pages
    let page1_base = 0x1000;
    let page2_base = 0x2000;

    engine
        .memory
        .map(page1_base, DEFAULT_PAGE_SIZE as usize, Permission::ALL)
        .unwrap();
    engine
        .memory
        .map(page2_base, DEFAULT_PAGE_SIZE as usize, Permission::ALL)
        .unwrap();

    // Place a multi-byte instruction that spans across the page boundary
    // Using a 10-byte instruction: mov rax, 0x1234567890abcdef
    let instruction = vec![0x48, 0xB8, 0xEF, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12];

    // Place instruction so it spans the page boundary (starts before, ends after)
    let instruction_addr = page2_base - 5; // 5 bytes in first page, 5 bytes in second page

    engine
        .memory
        .write_code(instruction_addr, &instruction)
        .unwrap();

    // Execute the instruction that crosses page boundary
    engine
        .emu_start(
            instruction_addr,
            instruction_addr + instruction.len() as u64,
            0,
            0,
        )
        .unwrap();

    // Verify the instruction executed correctly
    assert_eq!(engine.reg_read(Register::RAX), 0x1234567890abcdef);
    assert_eq!(
        engine.reg_read(Register::RIP),
        instruction_addr + instruction.len() as u64
    );
}

#[test]
fn test_instruction_at_end_of_mapped_memory() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map memory region
    let mem_base = 0x10000;
    engine
        .memory
        .map(mem_base, DEFAULT_PAGE_SIZE as usize, Permission::ALL)
        .unwrap();

    // Place instruction at the very end of mapped memory
    // Using a 3-byte instruction: inc rax (0x48, 0xFF, 0xC0)
    let instruction = vec![0x48, 0xFF, 0xC0];
    let instruction_addr = mem_base + DEFAULT_PAGE_SIZE - instruction.len() as u64;

    engine
        .memory
        .write_code(instruction_addr, &instruction)
        .unwrap();

    // Set initial RAX value
    engine.reg_write(Register::RAX, 0x100);

    // Execute the instruction at the end of mapped memory
    engine
        .emu_start(
            instruction_addr,
            instruction_addr + instruction.len() as u64,
            0,
            0,
        )
        .unwrap();

    // Verify the instruction executed correctly
    assert_eq!(engine.reg_read(Register::RAX), 0x101);
    assert_eq!(
        engine.reg_read(Register::RIP),
        instruction_addr + instruction.len() as u64
    );
}

#[test]
fn test_jump_near_page_boundary() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map two pages
    let page1_base = 0x1000;
    let page2_base = 0x2000;

    engine
        .memory
        .map(page1_base, DEFAULT_PAGE_SIZE as usize, Permission::ALL)
        .unwrap();
    engine
        .memory
        .map(page2_base, DEFAULT_PAGE_SIZE as usize, Permission::ALL)
        .unwrap();

    // Code that jumps from near end of first page to second page
    let jump_code = vec![
        0x48, 0xFF, 0xC0, // inc rax (3 bytes)
        0xEB, 0x00, // jmp +0 (2 bytes) - jumps to second page
    ];

    let target_code = vec![
        0x48, 0xFF, 0xC3, // inc rbx (3 bytes)
        0x90, // nop (1 byte)
    ];

    // Place jump code near end of first page
    let jump_addr = page2_base - jump_code.len() as u64;
    let target_addr = page2_base;

    engine.memory.write_code(jump_addr, &jump_code).unwrap();
    engine.memory.write_code(target_addr, &target_code).unwrap();

    // Set initial register values
    engine.reg_write(Register::RAX, 0);
    engine.reg_write(Register::RBX, 0);

    // Execute starting from the jump instruction
    engine
        .emu_start(jump_addr, target_addr + target_code.len() as u64, 0, 0)
        .unwrap();

    // Verify both instructions executed
    assert_eq!(engine.reg_read(Register::RAX), 1); // inc rax executed
    assert_eq!(engine.reg_read(Register::RBX), 1); // inc rbx executed after jump
}

#[test]
fn test_memory_access_near_page_boundary() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map code page and data page
    let code_base = 0x1000;
    let data_base = 0x2000;

    engine
        .memory
        .map(code_base, DEFAULT_PAGE_SIZE as usize, Permission::ALL)
        .unwrap();
    engine
        .memory
        .map(data_base, DEFAULT_PAGE_SIZE as usize, Permission::ALL)
        .unwrap();

    // Code that accesses memory near page boundary
    let code = vec![
        0x48, 0xC7, 0x00, 0x42, 0x00, 0x00, 0x00, // mov qword [rax], 0x42 (7 bytes)
        0x48, 0x8B, 0x18, // mov rbx, [rax] (3 bytes)
    ];

    engine.memory.write_code(code_base, &code).unwrap();

    // Set RAX to point near end of data page (but still within bounds)
    let data_addr = data_base + DEFAULT_PAGE_SIZE - 8; // 8 bytes from end for qword access
    engine.reg_write(Register::RAX, data_addr);

    // Execute the memory access instructions
    engine
        .emu_start(code_base, code_base + code.len() as u64, 0, 0)
        .unwrap();

    // Verify memory was written and read correctly
    assert_eq!(engine.reg_read(Register::RBX), 0x42);

    // Verify memory contains the expected value
    let mut buf = [0u8; 8];
    engine.memory.read(data_addr, &mut buf).unwrap();
    assert_eq!(u64::from_le_bytes(buf), 0x42);
}

#[test]
fn test_instruction_sequence_across_pages() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Map multiple pages to test instruction sequences
    for i in 0..3 {
        let page_base = 0x1000 + (i * DEFAULT_PAGE_SIZE);
        engine
            .memory
            .map(page_base, DEFAULT_PAGE_SIZE as usize, Permission::ALL)
            .unwrap();
    }

    // Create a sequence of instructions that spans multiple pages
    let mut all_code = Vec::new();

    // Fill most of first page with NOPs, leaving space for a few instructions
    let nop_count = DEFAULT_PAGE_SIZE as usize - 20; // Leave 20 bytes at end of page
    all_code.extend(vec![0x90; nop_count]); // NOPs

    // Add instructions that will span page boundaries
    all_code.extend(vec![
        0x48, 0xFF, 0xC0, // inc rax
        0x48, 0xFF, 0xC3, // inc rbx
        0x48, 0xFF, 0xC1, // inc rcx
        0x48, 0xFF, 0xC2, // inc rdx
        0x48, 0xFF, 0xC6, // inc rsi
        0x48, 0xFF, 0xC7, // inc rdi
        0x90, // nop
    ]);

    let start_addr = 0x1000;
    engine.memory.write_code(start_addr, &all_code).unwrap();

    // Execute the entire sequence
    engine
        .emu_start(start_addr, start_addr + all_code.len() as u64, 0, 0)
        .unwrap();

    // Verify all increment instructions executed
    assert_eq!(engine.reg_read(Register::RAX), 1);
    assert_eq!(engine.reg_read(Register::RBX), 1);
    assert_eq!(engine.reg_read(Register::RCX), 1);
    assert_eq!(engine.reg_read(Register::RDX), 1);
    assert_eq!(engine.reg_read(Register::RSI), 1);
    assert_eq!(engine.reg_read(Register::RDI), 1);
}
