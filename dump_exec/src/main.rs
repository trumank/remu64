use anyhow::Result;
use clap::Parser;
use dump_exec::{ArgumentType, DumpExec, FName, FString};

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

    /// Function arguments in format: 42, ptr:0x7ff000000, 3.14, fname:123,456, fstring:max_size[:initial_text], etc.
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

    let function_address = if let Some(hex) = function_address_str.strip_prefix("0x") {
        u64::from_str_radix(hex, 16)
    } else {
        function_address_str.parse::<u64>()
    }
    .map_err(|_| anyhow::anyhow!("Invalid function address: {}", function_address_str))?;

    let mut function_args = Vec::new();
    for arg in &cli.args {
        if let Some(rest) = arg.strip_prefix("ptr:0x") {
            let ptr_value = u64::from_str_radix(rest, 16)
                .map_err(|_| anyhow::anyhow!("Invalid pointer argument: {}", arg))?;
            function_args.push(ArgumentType::Pointer(ptr_value));
        } else if let Some(rest) = arg.strip_prefix("ptr:") {
            let ptr_value = rest
                .parse::<u64>()
                .map_err(|_| anyhow::anyhow!("Invalid pointer argument: {}", arg))?;
            function_args.push(ArgumentType::Pointer(ptr_value));
        } else if let Some(rest) = arg.strip_prefix("fname:") {
            let parts: Vec<&str> = rest.split(',').collect();
            if parts.len() != 2 {
                return Err(anyhow::anyhow!(
                    "FName format should be 'fname:comparison_index,value': {}",
                    arg
                ));
            }
            let comparison_index = parts[0]
                .parse::<i32>()
                .map_err(|_| anyhow::anyhow!("Invalid comparison_index in FName: {}", parts[0]))?;
            let value = parts[1]
                .parse::<i32>()
                .map_err(|_| anyhow::anyhow!("Invalid value in FName: {}", parts[1]))?;
            function_args.push(ArgumentType::FName(FName {
                comparison_index,
                value,
            }));
        } else if let Some(rest) = arg.strip_prefix("fstring:") {
            let parts: Vec<&str> = rest.splitn(2, ':').collect();
            let max_size = parts[0]
                .parse::<i32>()
                .map_err(|_| anyhow::anyhow!("Invalid max_size in FString: {}", parts[0]))?;

            let (data, num) = if parts.len() > 1 && !parts[1].is_empty() {
                // Convert UTF-8 string to UTF-16
                let utf16_data: Vec<u16> = parts[1].encode_utf16().collect();
                let num = utf16_data.len() as i32;
                (Some(utf16_data), num)
            } else {
                (None, 0)
            };

            function_args.push(ArgumentType::FString(FString {
                data,
                num,
                max: max_size,
            }));
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
    let mut executor = DumpExec::create_executor(&loader)?;

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
        Ok(_) => {
            let return_value = executor.get_return_value();
            println!("Function executed successfully!");
            println!("Return value: 0x{:x} ({})", return_value, return_value);

            // Display FString outputs
            match executor.read_fstring_outputs() {
                Ok(fstrings) => {
                    if !fstrings.is_empty() {
                        println!("\nFString outputs:");
                        for (i, fstring) in fstrings.iter().enumerate() {
                            println!("  FString[{}]:", i);
                            println!("    num: {}", fstring.num);
                            println!("    max: {}", fstring.max);
                            if let Some(ref data) = fstring.data {
                                // Convert UTF-16 to UTF-8 for display
                                match String::from_utf16(data) {
                                    Ok(text) => println!("    data: \"{}\"", text),
                                    Err(_) => {
                                        let hex_data: Vec<String> =
                                            data.iter().map(|&x| format!("{:04x}", x)).collect();
                                        println!("    data (raw): [{}]", hex_data.join(", "));
                                    }
                                }
                            } else {
                                println!("    data: null");
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to read FString outputs: {}", e);
                }
            }
        }
        Err(e) => {
            eprintln!("Function execution failed: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}
