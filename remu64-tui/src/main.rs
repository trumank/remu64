use anyhow::Result;
use clap::Parser;
use std::panic;
use std::path::PathBuf;
use tracing::{error, info};

mod app;
mod config;
mod tracer;
mod ui;

use app::App;
use config::{Config, ConfigLoader};

#[derive(Parser)]
#[command(name = "remu64-tui")]
#[command(about = "Terminal user interface for remu64 minidump debugging")]
struct Args {
    /// Path to the configuration file
    config_file: PathBuf,

    /// Generate a sample configuration file at the specified path and exit
    #[arg(long, value_name = "PATH")]
    generate_sample: Option<PathBuf>,
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

    // Handle sample generation
    if let Some(sample_path) = &args.generate_sample {
        info!("Generating sample configuration at: {:?}", sample_path);
        let sample_config = Config::create_sample();
        sample_config.save_to_file(sample_path)?;
        println!("Sample configuration saved to: {:?}", sample_path);
        return Ok(());
    }

    info!("Starting remu64-tui");
    info!("Config file: {:?}", args.config_file);

    // Load configuration with file watcher
    let config_loader = ConfigLoader::new(&args.config_file)?;
    info!("Loaded configuration from: {:?}", config_loader.config_path);
    info!("Minidump file: {}", config_loader.config.minidump_path);
    info!(
        "Function address: {}",
        config_loader.config.function_address
    );

    run_app_with_error_handling(config_loader)
}

fn run_app_with_error_handling(config_loader: ConfigLoader) -> Result<()> {
    let mut app = App::new(config_loader)?;

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
