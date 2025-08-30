use anyhow::Result;
use clap::Parser;
use std::panic;
use std::path::PathBuf;
use tracing::{error, info};

mod app;
mod tracer;
mod ui;

use app::App;

#[derive(Parser)]
#[command(name = "remu64-tui")]
#[command(about = "Terminal user interface for remu64 minidump debugging")]
struct Args {
    /// Path to the minidump file
    minidump_file: PathBuf,

    /// Function address to execute (in hex, e.g., 0x140001000)
    #[arg(value_parser = parse_hex)]
    function_address: u64,
}

fn parse_hex(s: &str) -> Result<u64, std::num::ParseIntError> {
    if let Some(hex_str) = s.strip_prefix("0x") {
        u64::from_str_radix(hex_str, 16)
    } else {
        u64::from_str_radix(s, 16)
    }
}

fn setup_logging() -> Result<()> {
    use std::fs::File;
    use tracing_subscriber::{EnvFilter, fmt, prelude::*};

    // Create a simple file that gets overwritten each run
    let log_file = File::create("remu64-tui.log")?;

    // Set up the tracing subscriber to write to the file
    tracing_subscriber::registry()
        .with(fmt::layer().with_writer(log_file).with_ansi(false))
        .with(EnvFilter::from_default_env().add_directive("remu64_tui=debug".parse()?))
        .init();

    Ok(())
}

fn main() -> Result<()> {
    // Setup logging first
    setup_logging()?;

    // Set up panic handler to ensure terminal cleanup
    panic::set_hook(Box::new(|panic_info| {
        // Try to restore terminal state before displaying panic
        let _ = cleanup_terminal();

        // Log the panic
        error!("Panic occurred: {:?}", panic_info);

        // Print panic info to stderr
        eprintln!("remu64-tui panicked: {:?}", panic_info);
    }));

    let args = Args::parse();

    info!("Starting remu64-tui");
    info!("Minidump file: {:?}", args.minidump_file);
    info!("Function address: 0x{:x}", args.function_address);

    run_app_with_error_handling(args)
}

fn run_app_with_error_handling(args: Args) -> Result<()> {
    let mut app = App::new(args.minidump_file, args.function_address)?;

    info!("App created successfully, starting TUI");

    // Catch panics during TUI operation
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| app.run()));

    match result {
        Ok(Ok(())) => {
            info!("TUI exited successfully");
            Ok(())
        }
        Ok(Err(e)) => {
            error!("TUI exited with error: {}", e);
            Err(e)
        }
        Err(panic_payload) => {
            error!("TUI panicked during execution");

            // Try to extract panic message
            let panic_message = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                s.clone()
            } else {
                "Unknown panic".to_string()
            };

            Err(anyhow::anyhow!("Application panicked: {}", panic_message))
        }
    }
}

fn cleanup_terminal() -> Result<()> {
    use crossterm::{
        event::DisableMouseCapture,
        execute,
        terminal::{LeaveAlternateScreen, disable_raw_mode},
    };
    use std::io;

    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture);
    Ok(())
}
