use anyhow::Result;
use clap::Parser;
use dump_exec::{ArgumentType, DumpExec};

#[derive(Parser)]
#[command(name = "dump_exec")]
#[command(about = "A minidump loader and function emulator")]
#[command(long_about = None)]
struct Cli {
    /// Enable instruction tracing with disassembly
    #[arg(long)]
    trace: bool,

    /// Enable full CPU state tracing with all registers
    #[arg(long)]
    full_trace: bool,

    /// List all modules found in the minidump
    #[arg(long)]
    list_modules: bool,

    /// Path to the minidump file
    minidump_path: String,

    /// Function address to execute (optional)
    function_address: Option<String>,

    /// Function arguments in format: 42, ptr:0x7ff000000, 3.14, etc.
    #[arg(trailing_var_arg = true)]
    args: Vec<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let minidump_path = &cli.minidump_path;

    println!("Loading minidump from: {}", minidump_path);
    let loader = DumpExec::load_minidump(minidump_path)?;

    if cli.list_modules {
        println!("Modules found:");
        for (name, base, size) in loader.list_modules() {
            println!("  {} - Base: 0x{:x}, Size: 0x{:x}", name, base, size);
        }
        println!();
    }

    let Some(function_address_str) = &cli.function_address else {
        println!("No function address specified. Use the function_address argument to specify a function address to execute.");
        return Ok(());
    };

    let function_address = if function_address_str.starts_with("0x") {
        u64::from_str_radix(&function_address_str[2..], 16)
    } else {
        function_address_str.parse::<u64>()
    }
    .map_err(|_| anyhow::anyhow!("Invalid function address: {}", function_address_str))?;

    let mut function_args = Vec::new();
    for arg in &cli.args {
        if arg.starts_with("ptr:0x") {
            let ptr_value = u64::from_str_radix(&arg[6..], 16)
                .map_err(|_| anyhow::anyhow!("Invalid pointer argument: {}", arg))?;
            function_args.push(ArgumentType::Pointer(ptr_value));
        } else if arg.starts_with("ptr:") {
            let ptr_value = arg[4..]
                .parse::<u64>()
                .map_err(|_| anyhow::anyhow!("Invalid pointer argument: {}", arg))?;
            function_args.push(ArgumentType::Pointer(ptr_value));
        } else if arg.contains('.') {
            let float_value = arg
                .parse::<f64>()
                .map_err(|_| anyhow::anyhow!("Invalid float argument: {}", arg))?;
            function_args.push(ArgumentType::Float(float_value));
        } else {
            let int_value = arg
                .parse::<u64>()
                .map_err(|_| anyhow::anyhow!("Invalid integer argument: {}", arg))?;
            function_args.push(ArgumentType::Integer(int_value));
        }
    }

    println!("Creating function executor...");
    let mut executor = DumpExec::create_executor(loader)?;

    if cli.trace {
        println!("Enabling instruction tracing...");
        executor.enable_tracing(true);
    }

    if cli.full_trace {
        println!("Enabling full CPU state tracing...");
        executor.enable_tracing(true);
        executor.enable_full_trace(true);
    }

    println!(
        "Executing function at 0x{:x} with {} arguments",
        function_address,
        function_args.len()
    );

    match executor.execute_function(function_address, function_args) {
        Ok(_) => match executor.get_return_value() {
            Ok(return_value) => {
                println!("Function executed successfully!");
                println!("Return value: 0x{:x} ({})", return_value, return_value);
            }
            Err(e) => {
                println!("Function executed, but failed to read return value: {}", e);
            }
        },
        Err(e) => {
            eprintln!("Function execution failed: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}
