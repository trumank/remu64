use anyhow::Result;
use rdex::{ArgumentType, DumpExec};
use remu64::memory::MemoryTrait as _;

fn main() -> Result<()> {
    let minidump_loader = DumpExec::load_minidump("StringEncryptionFun_x64.dmp")?;
    let mut executor = DumpExec::create_executor(&minidump_loader)?;

    // Allocate 256 bytes for output buffer
    let temp_addr = allocate_memory(&mut executor, 256)?;

    // Call decrypt function: decrypt(output_buffer, encrypted_string_addr)
    let args = vec![
        ArgumentType::Pointer(temp_addr),   // Output buffer
        ArgumentType::Pointer(0x140017000), // Encrypted string address
    ];

    executor.execute_function(0x140001000, args)?;

    // Read decrypted string
    let decrypted = read_string(&mut executor, temp_addr)?;
    println!("decrypted: '{}'", decrypted);

    Ok(())
}

// Helper function to allocate memory (simplified version)
fn allocate_memory<P: rdex::ProcessTrait>(
    executor: &mut rdex::FunctionExecutor<P>,
    size: usize,
) -> Result<u64> {
    use remu64::{DEFAULT_PAGE_SIZE, Permission};

    // Use a fixed allocation area for simplicity
    let alloc_base = 0x7fff_e000_0000u64;

    // Round up size to next page boundary
    let aligned_size = ((size + DEFAULT_PAGE_SIZE as usize - 1) / DEFAULT_PAGE_SIZE as usize)
        * DEFAULT_PAGE_SIZE as usize;

    executor.vm_context.engine.memory.map(
        alloc_base,
        aligned_size,
        Permission::READ | Permission::WRITE,
    )?;

    // Zero out the allocated memory
    let zero_buffer = vec![0u8; aligned_size];
    executor
        .vm_context
        .engine
        .memory
        .write(alloc_base, &zero_buffer)?;

    Ok(alloc_base)
}

// Helper function to read null-terminated string
fn read_string<P: rdex::ProcessTrait>(
    executor: &mut rdex::FunctionExecutor<P>,
    addr: u64,
) -> Result<String> {
    let mut string_bytes = Vec::new();
    let mut offset = 0u64;

    loop {
        let mut byte = [0u8; 1];
        executor
            .vm_context
            .engine
            .memory
            .read(addr + offset, &mut byte)?;
        if byte[0] == 0 {
            break;
        }
        string_bytes.push(byte[0]);
        offset += 1;
        if offset > 1024 {
            break;
        }
    }

    Ok(String::from_utf8_lossy(&string_bytes).to_string())
}
