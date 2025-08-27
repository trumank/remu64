use remu64::{Engine, EngineMode, Permission, Register, memory::MemoryTrait};

fn setup_engine() -> Engine<impl MemoryTrait> {
    let mut engine = Engine::new(EngineMode::Mode64);
    engine.memory.map(0x1000, 0x2000, Permission::ALL).unwrap();
    engine
}

#[test]
fn test_mulx_32bit_basic() {
    let mut engine = setup_engine();
    
    // Test: MULX with EDX=0x00000003, src=0x00000005
    // Expected: 0x03 * 0x05 = 0x0F (high=0, low=0xF)
    let code = vec![
        0xBA, 0x03, 0x00, 0x00, 0x00,        // mov edx, 3
        0xB8, 0x05, 0x00, 0x00, 0x00,        // mov eax, 5
        0xC4, 0xE2, 0x6B, 0xF6, 0xD8,        // mulx ebx, edx, eax (with iced-x86: ebx=high, edx=low)
    ];
    // Note: Due to iced-x86's quirk with MULX, EDX acts as both source and destination for low bits
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.cpu.write_reg(Register::RIP, 0x1000);
    
    // Save initial flags to verify they aren't modified
    let initial_flags = engine.cpu.rflags;
    
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.cpu.read_reg(Register::RBX) as u32, 0, "High bits should be 0");
    assert_eq!(engine.cpu.read_reg(Register::RDX) as u32, 0xF, "Low bits should be 0xF in EDX (iced-x86 quirk)");
    assert_eq!(engine.cpu.rflags.bits(), initial_flags.bits(), "MULX should not modify flags");
}

#[test]
fn test_mulx_32bit_large() {
    let mut engine = setup_engine();
    
    // Test: MULX with large values that produce a 64-bit result
    // EDX=0x10000000, src=0x20000000
    // Expected: 0x10000000 * 0x20000000 = 0x200000000000000 (high=0x2000000, low=0)
    let code = vec![
        0xBA, 0x00, 0x00, 0x00, 0x10,        // mov edx, 0x10000000
        0xB8, 0x00, 0x00, 0x00, 0x20,        // mov eax, 0x20000000
        0xC4, 0xE2, 0x6B, 0xF6, 0xD8,        // mulx ebx, edx, eax (with iced-x86: ebx=high, edx=low)
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.cpu.write_reg(Register::RIP, 0x1000);
    
    let initial_flags = engine.cpu.rflags;
    
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.cpu.read_reg(Register::RBX) as u32, 0x02000000, "High bits incorrect");
    assert_eq!(engine.cpu.read_reg(Register::RDX) as u32, 0, "Low bits should be 0 in EDX");
    assert_eq!(engine.cpu.rflags.bits(), initial_flags.bits(), "MULX should not modify flags");
}

#[test]
fn test_mulx_32bit_max() {
    let mut engine = setup_engine();
    
    // Test: MULX with maximum 32-bit values
    // EDX=0xFFFFFFFF, src=0xFFFFFFFF
    // Expected: 0xFFFFFFFF * 0xFFFFFFFF = 0xFFFFFFFE00000001
    let code = vec![
        0xBA, 0xFF, 0xFF, 0xFF, 0xFF,        // mov edx, 0xFFFFFFFF
        0xB8, 0xFF, 0xFF, 0xFF, 0xFF,        // mov eax, 0xFFFFFFFF
        0xC4, 0xE2, 0x6B, 0xF6, 0xD8,        // mulx ebx, edx, eax (with iced-x86: ebx=high, edx=low)
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.cpu.write_reg(Register::RIP, 0x1000);
    
    let initial_flags = engine.cpu.rflags;
    
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.cpu.read_reg(Register::RBX) as u32, 0xFFFFFFFE, "High bits incorrect");
    assert_eq!(engine.cpu.read_reg(Register::RDX) as u32, 0x00000001, "Low bits incorrect in EDX");
    assert_eq!(engine.cpu.rflags.bits(), initial_flags.bits(), "MULX should not modify flags");
}

#[test]
fn test_mulx_64bit_basic() {
    let mut engine = setup_engine();
    
    // Test: MULX with RDX=0x0000000000000003, src=0x0000000000000005
    // Expected: 0x03 * 0x05 = 0x0F (high=0, low=0xF)
    let code = vec![
        0x48, 0xBA, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rdx, 3
        0x48, 0xB8, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, 5
        0xC4, 0xE2, 0xEB, 0xF6, 0xD8,                                // mulx rbx, rdx, rax (with iced-x86: rbx=high, rdx=low)
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.cpu.write_reg(Register::RIP, 0x1000);
    
    let initial_flags = engine.cpu.rflags;
    
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.cpu.read_reg(Register::RBX), 0, "High bits should be 0");
    assert_eq!(engine.cpu.read_reg(Register::RDX), 0xF, "Low bits should be 0xF in RDX");
    assert_eq!(engine.cpu.rflags.bits(), initial_flags.bits(), "MULX should not modify flags");
}

#[test]
fn test_mulx_64bit_large() {
    let mut engine = setup_engine();
    
    // Test: MULX with large 64-bit values
    // RDX=0x1000000000000000, src=0x2000000000000000
    // Expected: produces 128-bit result with high bits set
    let code = vec![
        0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,  // mov rdx, 0x1000000000000000
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20,  // mov rax, 0x2000000000000000
        0xC4, 0xE2, 0xEB, 0xF6, 0xD8,                                // mulx rbx, rdx, rax (with iced-x86: rbx=high, rdx=low)
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.cpu.write_reg(Register::RIP, 0x1000);
    
    let initial_flags = engine.cpu.rflags;
    
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.cpu.read_reg(Register::RBX), 0x0200000000000000, "High bits incorrect");
    assert_eq!(engine.cpu.read_reg(Register::RDX), 0, "Low bits should be 0 in RDX");
    assert_eq!(engine.cpu.rflags.bits(), initial_flags.bits(), "MULX should not modify flags");
}

#[test]
fn test_mulx_64bit_max() {
    let mut engine = setup_engine();
    
    // Test: MULX with maximum 64-bit values
    // RDX=0xFFFFFFFFFFFFFFFF, src=0xFFFFFFFFFFFFFFFF
    // Expected: 0xFFFFFFFFFFFFFFFF * 0xFFFFFFFFFFFFFFFF = 0xFFFFFFFFFFFFFFFE0000000000000001
    let code = vec![
        0x48, 0xBA, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // mov rdx, 0xFFFFFFFFFFFFFFFF
        0x48, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // mov rax, 0xFFFFFFFFFFFFFFFF
        0xC4, 0xE2, 0xEB, 0xF6, 0xD8,                                // mulx rbx, rdx, rax (with iced-x86: rbx=high, rdx=low)
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.cpu.write_reg(Register::RIP, 0x1000);
    
    let initial_flags = engine.cpu.rflags;
    
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.cpu.read_reg(Register::RBX), 0xFFFFFFFFFFFFFFFE, "High bits incorrect");
    assert_eq!(engine.cpu.read_reg(Register::RDX), 0x0000000000000001, "Low bits incorrect in RDX");
    assert_eq!(engine.cpu.rflags.bits(), initial_flags.bits(), "MULX should not modify flags");
}

#[test]
fn test_mulx_64bit_mixed() {
    let mut engine = setup_engine();
    
    // Test: MULX with mixed values
    // RDX=0x123456789ABCDEF0, src=0x10
    let code = vec![
        0x48, 0xBA, 0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12,  // mov rdx, 0x123456789ABCDEF0
        0x48, 0xB8, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, 0x10
        0xC4, 0xE2, 0xEB, 0xF6, 0xD8,                                // mulx rbx, rdx, rax (with iced-x86: rbx=high, rdx=low)
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.cpu.write_reg(Register::RIP, 0x1000);
    
    let initial_flags = engine.cpu.rflags;
    
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    // 0x123456789ABCDEF0 * 0x10 = 0x123456789ABCDEF00
    assert_eq!(engine.cpu.read_reg(Register::RBX), 0x1, "High bits incorrect");
    assert_eq!(engine.cpu.read_reg(Register::RDX), 0x23456789ABCDEF00, "Low bits incorrect in RDX");
    assert_eq!(engine.cpu.rflags.bits(), initial_flags.bits(), "MULX should not modify flags");
}

#[test]
fn test_mulx_preserves_flags_cf_set() {
    let mut engine = setup_engine();
    
    // Test that MULX preserves all flags including CF
    let code = vec![
        0xF9,                                 // stc (set carry flag)
        0xBA, 0x02, 0x00, 0x00, 0x00,        // mov edx, 2
        0xB8, 0x03, 0x00, 0x00, 0x00,        // mov eax, 3
        0xC4, 0xE2, 0x6B, 0xF6, 0xD8,        // mulx ebx, edx, eax (with iced-x86: ebx=high, edx=low)
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.cpu.write_reg(Register::RIP, 0x1000);
    
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.cpu.read_reg(Register::RBX) as u32, 0, "High bits should be 0");
    assert_eq!(engine.cpu.read_reg(Register::RDX) as u32, 6, "Low bits should be 6 in EDX");
    assert!(engine.cpu.rflags.contains(remu64::Flags::CF), "CF should remain set");
}

#[test]
fn test_mulx_preserves_flags_zf_sf_set() {
    let mut engine = setup_engine();
    
    // Test that MULX preserves ZF and SF flags
    let code = vec![
        0x31, 0xC0,                           // xor eax, eax (sets ZF, clears SF)
        0xBA, 0x04, 0x00, 0x00, 0x00,        // mov edx, 4
        0xB8, 0x05, 0x00, 0x00, 0x00,        // mov eax, 5
        0xC4, 0xE2, 0x6B, 0xF6, 0xD8,        // mulx ebx, edx, eax (with iced-x86: ebx=high, edx=low)
    ];
    
    engine.memory.write(0x1000, &code).unwrap();
    engine.cpu.write_reg(Register::RIP, 0x1000);
    
    engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();
    
    assert_eq!(engine.cpu.read_reg(Register::RBX) as u32, 0, "High bits should be 0");
    assert_eq!(engine.cpu.read_reg(Register::RDX) as u32, 20, "Low bits should be 20 in EDX");
    assert!(engine.cpu.rflags.contains(remu64::Flags::ZF), "ZF should remain set");
}