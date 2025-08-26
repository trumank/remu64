use amd64_emu::memory::MemoryTrait as _;
use anyhow::Result;
use dump_exec::{ArgumentType, DumpExec};
use std::env;

/// Example showing efficient batch processing of thousands of strings
/// using CowMemory resets to prevent OOM issues
fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <minidump_path>", args[0]);
        eprintln!("Example: {} StringProcessor.dmp", args[0]);
        std::process::exit(1);
    }

    let minidump_path = &args[1];
    let minidump_loader = DumpExec::load_minidump(minidump_path)?;

    // Process many strings efficiently
    process_strings_batch(&minidump_loader)?;

    Ok(())
}

fn process_strings_batch(minidump_loader: &dump_exec::MinidumpLoader<'_>) -> Result<()> {
    // Create executor once and reuse it
    let mut executor = DumpExec::create_executor(minidump_loader)?;

    for i in 0..10000 {
        executor.reset_for_reuse()?;

        let result = process_single_string(&mut executor, (i, i))?;
        println!("  {}: {}", i, result);
    }
    Ok(())
}

fn process_single_string(
    executor: &mut dump_exec::FunctionExecutor<'_>,
    input: (i32, i32),
) -> Result<String> {
    let fname_bytes = [
        input.0.to_le_bytes(), // comparison_index
        input.1.to_le_bytes(), // value
    ]
    .concat();

    let fname_addr = executor.push_bytes_to_stack(&fname_bytes)?;
    let fstring_addr = executor.push_bytes_to_stack(&[0; 16])?;

    let args = vec![
        ArgumentType::Pointer(fname_addr),
        ArgumentType::Pointer(fstring_addr),
    ];

    let function_address = 0x7ff70fb37f20;
    executor.execute_function(function_address, args)?;

    let mut fstring_data = [0u8; 16];
    executor
        .vm_context
        .engine
        .memory
        .read(fstring_addr, &mut fstring_data)?;

    let data_ptr = u64::from_le_bytes(fstring_data[0..8].try_into().unwrap());
    let length = i32::from_le_bytes(fstring_data[8..12].try_into().unwrap());

    if data_ptr != 0 && length > 0 {
        let mut wide_char_data = vec![0u8; length as usize * 2];
        executor
            .vm_context
            .engine
            .memory
            .read(data_ptr, &mut wide_char_data)?;

        let wide_chars: Vec<u16> = wide_char_data
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes(chunk.try_into().unwrap()))
            .collect();

        return Ok(String::from_utf16(&wide_chars)?);
    }

    Ok(String::new())
}
