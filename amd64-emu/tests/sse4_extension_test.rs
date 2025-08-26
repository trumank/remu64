use amd64_emu::{Engine, MemoryValue, OperandAccess, RegisterType};
use iced_x86::{code_asm::*, Mnemonic};

#[test]
fn test_pmovsxbw() {
    let mut engine = Engine::new();
    engine.init_memory_region(0x1000, 0x1000);
    
    // Test sign extension of 8 bytes to 8 words
    // Load test data: mix of positive and negative bytes
    let test_bytes: [i8; 8] = [0x7F, -128i8, 0x01, -1i8, 0x40, -64i8, 0x00, -16i8];
    let mut test_data = 0u64;
    for (i, &byte) in test_bytes.iter().enumerate() {
        test_data |= (byte as u8 as u64) << (i * 8);
    }
    
    engine.cpu.write_xmm(0, test_data as u128);
    
    let mut asm = CodeAssembler::new(64).unwrap();
    asm.pmovsxbw(xmm1, xmm0).unwrap();
    
    let bytes = asm.assemble(0x1000).unwrap();
    engine.write_memory(0x1000, &bytes);
    engine.cpu.set_rip(0x1000);
    
    engine.step().unwrap();
    
    let result = engine.cpu.read_xmm(1);
    
    // Check each word
    for i in 0..8 {
        let expected = test_bytes[i] as i16;
        let actual = ((result >> (i * 16)) & 0xFFFF) as i16;
        assert_eq!(actual, expected, "Word {} mismatch", i);
    }
}

#[test]
fn test_pmovsxbd() {
    let mut engine = Engine::new();
    engine.init_memory_region(0x1000, 0x1000);
    
    // Test sign extension of 4 bytes to 4 doublewords
    let test_bytes: [i8; 4] = [0x7F, -128i8, 0x01, -1i8];
    let mut test_data = 0u32;
    for (i, &byte) in test_bytes.iter().enumerate() {
        test_data |= (byte as u8 as u32) << (i * 8);
    }
    
    engine.cpu.write_xmm(0, test_data as u128);
    
    let mut asm = CodeAssembler::new(64).unwrap();
    asm.pmovsxbd(xmm1, xmm0).unwrap();
    
    let bytes = asm.assemble(0x1000).unwrap();
    engine.write_memory(0x1000, &bytes);
    engine.cpu.set_rip(0x1000);
    
    engine.step().unwrap();
    
    let result = engine.cpu.read_xmm(1);
    
    // Check each doubleword
    for i in 0..4 {
        let expected = test_bytes[i] as i32;
        let actual = ((result >> (i * 32)) & 0xFFFFFFFF) as i32;
        assert_eq!(actual, expected, "Doubleword {} mismatch", i);
    }
}

#[test]
fn test_pmovsxbq() {
    let mut engine = Engine::new();
    engine.init_memory_region(0x1000, 0x1000);
    
    // Test sign extension of 2 bytes to 2 quadwords
    let test_bytes: [i8; 2] = [0x7F, -128i8];
    let test_data = (test_bytes[0] as u8 as u16) | ((test_bytes[1] as u8 as u16) << 8);
    
    engine.cpu.write_xmm(0, test_data as u128);
    
    let mut asm = CodeAssembler::new(64).unwrap();
    asm.pmovsxbq(xmm1, xmm0).unwrap();
    
    let bytes = asm.assemble(0x1000).unwrap();
    engine.write_memory(0x1000, &bytes);
    engine.cpu.set_rip(0x1000);
    
    engine.step().unwrap();
    
    let result = engine.cpu.read_xmm(1);
    
    // Check each quadword
    for i in 0..2 {
        let expected = test_bytes[i] as i64;
        let actual = ((result >> (i * 64)) & 0xFFFFFFFFFFFFFFFF) as i64;
        assert_eq!(actual, expected, "Quadword {} mismatch", i);
    }
}

#[test]
fn test_pmovsxwd() {
    let mut engine = Engine::new();
    engine.init_memory_region(0x1000, 0x1000);
    
    // Test sign extension of 4 words to 4 doublewords
    let test_words: [i16; 4] = [0x7FFF, -32768i16, 0x0001, -1i16];
    let mut test_data = 0u64;
    for (i, &word) in test_words.iter().enumerate() {
        test_data |= (word as u16 as u64) << (i * 16);
    }
    
    engine.cpu.write_xmm(0, test_data as u128);
    
    let mut asm = CodeAssembler::new(64).unwrap();
    asm.pmovsxwd(xmm1, xmm0).unwrap();
    
    let bytes = asm.assemble(0x1000).unwrap();
    engine.write_memory(0x1000, &bytes);
    engine.cpu.set_rip(0x1000);
    
    engine.step().unwrap();
    
    let result = engine.cpu.read_xmm(1);
    
    // Check each doubleword
    for i in 0..4 {
        let expected = test_words[i] as i32;
        let actual = ((result >> (i * 32)) & 0xFFFFFFFF) as i32;
        assert_eq!(actual, expected, "Doubleword {} mismatch", i);
    }
}

#[test]
fn test_pmovsxwq() {
    let mut engine = Engine::new();
    engine.init_memory_region(0x1000, 0x1000);
    
    // Test sign extension of 2 words to 2 quadwords
    let test_words: [i16; 2] = [0x7FFF, -32768i16];
    let test_data = (test_words[0] as u16 as u32) | ((test_words[1] as u16 as u32) << 16);
    
    engine.cpu.write_xmm(0, test_data as u128);
    
    let mut asm = CodeAssembler::new(64).unwrap();
    asm.pmovsxwq(xmm1, xmm0).unwrap();
    
    let bytes = asm.assemble(0x1000).unwrap();
    engine.write_memory(0x1000, &bytes);
    engine.cpu.set_rip(0x1000);
    
    engine.step().unwrap();
    
    let result = engine.cpu.read_xmm(1);
    
    // Check each quadword
    for i in 0..2 {
        let expected = test_words[i] as i64;
        let actual = ((result >> (i * 64)) & 0xFFFFFFFFFFFFFFFF) as i64;
        assert_eq!(actual, expected, "Quadword {} mismatch", i);
    }
}

#[test]
fn test_pmovsxdq() {
    let mut engine = Engine::new();
    engine.init_memory_region(0x1000, 0x1000);
    
    // Test sign extension of 2 doublewords to 2 quadwords
    let test_dwords: [i32; 2] = [0x7FFFFFFF, -2147483648i32];
    let test_data = (test_dwords[0] as u32 as u64) | ((test_dwords[1] as u32 as u64) << 32);
    
    engine.cpu.write_xmm(0, test_data as u128);
    
    let mut asm = CodeAssembler::new(64).unwrap();
    asm.pmovsxdq(xmm1, xmm0).unwrap();
    
    let bytes = asm.assemble(0x1000).unwrap();
    engine.write_memory(0x1000, &bytes);
    engine.cpu.set_rip(0x1000);
    
    engine.step().unwrap();
    
    let result = engine.cpu.read_xmm(1);
    
    // Check each quadword
    for i in 0..2 {
        let expected = test_dwords[i] as i64;
        let actual = ((result >> (i * 64)) & 0xFFFFFFFFFFFFFFFF) as i64;
        assert_eq!(actual, expected, "Quadword {} mismatch", i);
    }
}

#[test]
fn test_pmovzxbw() {
    let mut engine = Engine::new();
    engine.init_memory_region(0x1000, 0x1000);
    
    // Test zero extension of 8 bytes to 8 words
    let test_bytes: [u8; 8] = [0xFF, 0x80, 0x01, 0x00, 0x40, 0xC0, 0x7F, 0xF0];
    let mut test_data = 0u64;
    for (i, &byte) in test_bytes.iter().enumerate() {
        test_data |= (byte as u64) << (i * 8);
    }
    
    engine.cpu.write_xmm(0, test_data as u128);
    
    let mut asm = CodeAssembler::new(64).unwrap();
    asm.pmovzxbw(xmm1, xmm0).unwrap();
    
    let bytes = asm.assemble(0x1000).unwrap();
    engine.write_memory(0x1000, &bytes);
    engine.cpu.set_rip(0x1000);
    
    engine.step().unwrap();
    
    let result = engine.cpu.read_xmm(1);
    
    // Check each word
    for i in 0..8 {
        let expected = test_bytes[i] as u16;
        let actual = (result >> (i * 16)) & 0xFFFF;
        assert_eq!(actual, expected as u128, "Word {} mismatch", i);
    }
}

#[test]
fn test_pmovzxbd() {
    let mut engine = Engine::new();
    engine.init_memory_region(0x1000, 0x1000);
    
    // Test zero extension of 4 bytes to 4 doublewords
    let test_bytes: [u8; 4] = [0xFF, 0x80, 0x01, 0x00];
    let mut test_data = 0u32;
    for (i, &byte) in test_bytes.iter().enumerate() {
        test_data |= (byte as u32) << (i * 8);
    }
    
    engine.cpu.write_xmm(0, test_data as u128);
    
    let mut asm = CodeAssembler::new(64).unwrap();
    asm.pmovzxbd(xmm1, xmm0).unwrap();
    
    let bytes = asm.assemble(0x1000).unwrap();
    engine.write_memory(0x1000, &bytes);
    engine.cpu.set_rip(0x1000);
    
    engine.step().unwrap();
    
    let result = engine.cpu.read_xmm(1);
    
    // Check each doubleword
    for i in 0..4 {
        let expected = test_bytes[i] as u32;
        let actual = (result >> (i * 32)) & 0xFFFFFFFF;
        assert_eq!(actual, expected as u128, "Doubleword {} mismatch", i);
    }
}

#[test]
fn test_pmovzxbq() {
    let mut engine = Engine::new();
    engine.init_memory_region(0x1000, 0x1000);
    
    // Test zero extension of 2 bytes to 2 quadwords
    let test_bytes: [u8; 2] = [0xFF, 0x80];
    let test_data = (test_bytes[0] as u16) | ((test_bytes[1] as u16) << 8);
    
    engine.cpu.write_xmm(0, test_data as u128);
    
    let mut asm = CodeAssembler::new(64).unwrap();
    asm.pmovzxbq(xmm1, xmm0).unwrap();
    
    let bytes = asm.assemble(0x1000).unwrap();
    engine.write_memory(0x1000, &bytes);
    engine.cpu.set_rip(0x1000);
    
    engine.step().unwrap();
    
    let result = engine.cpu.read_xmm(1);
    
    // Check each quadword
    for i in 0..2 {
        let expected = test_bytes[i] as u64;
        let actual = (result >> (i * 64)) & 0xFFFFFFFFFFFFFFFF;
        assert_eq!(actual, expected as u128, "Quadword {} mismatch", i);
    }
}

#[test]
fn test_pmovzxwd() {
    let mut engine = Engine::new();
    engine.init_memory_region(0x1000, 0x1000);
    
    // Test zero extension of 4 words to 4 doublewords
    let test_words: [u16; 4] = [0xFFFF, 0x8000, 0x0001, 0x0000];
    let mut test_data = 0u64;
    for (i, &word) in test_words.iter().enumerate() {
        test_data |= (word as u64) << (i * 16);
    }
    
    engine.cpu.write_xmm(0, test_data as u128);
    
    let mut asm = CodeAssembler::new(64).unwrap();
    asm.pmovzxwd(xmm1, xmm0).unwrap();
    
    let bytes = asm.assemble(0x1000).unwrap();
    engine.write_memory(0x1000, &bytes);
    engine.cpu.set_rip(0x1000);
    
    engine.step().unwrap();
    
    let result = engine.cpu.read_xmm(1);
    
    // Check each doubleword
    for i in 0..4 {
        let expected = test_words[i] as u32;
        let actual = (result >> (i * 32)) & 0xFFFFFFFF;
        assert_eq!(actual, expected as u128, "Doubleword {} mismatch", i);
    }
}

#[test]
fn test_pmovzxwq() {
    let mut engine = Engine::new();
    engine.init_memory_region(0x1000, 0x1000);
    
    // Test zero extension of 2 words to 2 quadwords
    let test_words: [u16; 2] = [0xFFFF, 0x8000];
    let test_data = (test_words[0] as u32) | ((test_words[1] as u32) << 16);
    
    engine.cpu.write_xmm(0, test_data as u128);
    
    let mut asm = CodeAssembler::new(64).unwrap();
    asm.pmovzxwq(xmm1, xmm0).unwrap();
    
    let bytes = asm.assemble(0x1000).unwrap();
    engine.write_memory(0x1000, &bytes);
    engine.cpu.set_rip(0x1000);
    
    engine.step().unwrap();
    
    let result = engine.cpu.read_xmm(1);
    
    // Check each quadword
    for i in 0..2 {
        let expected = test_words[i] as u64;
        let actual = (result >> (i * 64)) & 0xFFFFFFFFFFFFFFFF;
        assert_eq!(actual, expected as u128, "Quadword {} mismatch", i);
    }
}

#[test]
fn test_pmovzxdq() {
    let mut engine = Engine::new();
    engine.init_memory_region(0x1000, 0x1000);
    
    // Test zero extension of 2 doublewords to 2 quadwords
    let test_dwords: [u32; 2] = [0xFFFFFFFF, 0x80000000];
    let test_data = (test_dwords[0] as u64) | ((test_dwords[1] as u64) << 32);
    
    engine.cpu.write_xmm(0, test_data as u128);
    
    let mut asm = CodeAssembler::new(64).unwrap();
    asm.pmovzxdq(xmm1, xmm0).unwrap();
    
    let bytes = asm.assemble(0x1000).unwrap();
    engine.write_memory(0x1000, &bytes);
    engine.cpu.set_rip(0x1000);
    
    engine.step().unwrap();
    
    let result = engine.cpu.read_xmm(1);
    
    // Check each quadword
    for i in 0..2 {
        let expected = test_dwords[i] as u64;
        let actual = (result >> (i * 64)) & 0xFFFFFFFFFFFFFFFF;
        assert_eq!(actual, expected as u128, "Quadword {} mismatch", i);
    }
}

#[test]
fn test_pmovsxbw_memory() {
    let mut engine = Engine::new();
    engine.init_memory_region(0x1000, 0x1000);
    engine.init_memory_region(0x2000, 0x1000);
    
    // Store test data in memory
    let test_bytes: [i8; 8] = [0x7F, -128i8, 0x01, -1i8, 0x40, -64i8, 0x00, -16i8];
    let mut test_data = 0u64;
    for (i, &byte) in test_bytes.iter().enumerate() {
        test_data |= (byte as u8 as u64) << (i * 8);
    }
    
    // Write to memory
    engine.write_memory(0x2000, &test_data.to_le_bytes());
    
    let mut asm = CodeAssembler::new(64).unwrap();
    asm.pmovsxbw(xmm1, qword_ptr(0x2000)).unwrap();
    
    let bytes = asm.assemble(0x1000).unwrap();
    engine.write_memory(0x1000, &bytes);
    engine.cpu.set_rip(0x1000);
    
    engine.step().unwrap();
    
    let result = engine.cpu.read_xmm(1);
    
    // Check each word
    for i in 0..8 {
        let expected = test_bytes[i] as i16;
        let actual = ((result >> (i * 16)) & 0xFFFF) as i16;
        assert_eq!(actual, expected, "Word {} mismatch", i);
    }
}

#[test]
fn test_pmovzxbw_memory() {
    let mut engine = Engine::new();
    engine.init_memory_region(0x1000, 0x1000);
    engine.init_memory_region(0x2000, 0x1000);
    
    // Store test data in memory
    let test_bytes: [u8; 8] = [0xFF, 0x80, 0x01, 0x00, 0x40, 0xC0, 0x7F, 0xF0];
    let mut test_data = 0u64;
    for (i, &byte) in test_bytes.iter().enumerate() {
        test_data |= (byte as u64) << (i * 8);
    }
    
    // Write to memory
    engine.write_memory(0x2000, &test_data.to_le_bytes());
    
    let mut asm = CodeAssembler::new(64).unwrap();
    asm.pmovzxbw(xmm1, qword_ptr(0x2000)).unwrap();
    
    let bytes = asm.assemble(0x1000).unwrap();
    engine.write_memory(0x1000, &bytes);
    engine.cpu.set_rip(0x1000);
    
    engine.step().unwrap();
    
    let result = engine.cpu.read_xmm(1);
    
    // Check each word
    for i in 0..8 {
        let expected = test_bytes[i] as u16;
        let actual = (result >> (i * 16)) & 0xFFFF;
        assert_eq!(actual, expected as u128, "Word {} mismatch", i);
    }
}