use anyhow::Result;
use rdex::symbolizer::Symbolizer;
use remu64::{CowMemory, memory::MemoryTrait};

mod app;
mod config;
mod minidump_provider;
mod protocol_server;
mod tracer;
mod ui;

pub use app::Snapshot;
pub use config::{Config, ConfigLoader, StackConfig};
pub use minidump_provider::MinidumpSetupProvider;
pub use tracer::{InstructionAction, InstructionActions, TracerHook, TuiContext};

/// User-provided trait for VM initialization and per-frame setup
pub trait VmSetupProvider {
    type Memory: MemoryTrait + Clone;
    type Symbolizer: Symbolizer;
    type Hooks: TracerHook<Self::Memory>;

    /// Create the memory and symbolizer instances (called once)
    fn create_backend(&self) -> Result<(Self::Memory, Self::Symbolizer)>;

    /// Configure the engine for this frame (called each frame)
    fn setup_engine(
        &mut self,
        engine: &mut remu64::Engine<CowMemory<Self::Memory>>,
    ) -> Result<VmConfig<Self::Hooks>>;

    /// Check for reload signals (called during event polling)
    /// Returns Ok(true) if reload happened, Ok(false) if no reload, Err on error
    fn check_reload_signal(&mut self) -> Result<bool>;

    /// Get display name for UI
    fn display_name(&self) -> &str;
}

/// Configuration for the TUI itself
#[derive(Debug, Clone)]
pub struct TuiConfig {
    pub tcp_port: Option<u16>,
    pub max_instructions: usize,
    pub snapshot_interval: usize,
}

impl Default for TuiConfig {
    fn default() -> Self {
        Self {
            tcp_port: None,
            max_instructions: 1000000,
            snapshot_interval: 100000,
        }
    }
}

impl TuiConfig {
    pub fn with_tcp_port(mut self, port: u16) -> Self {
        self.tcp_port = Some(port);
        self
    }

    pub fn with_max_instructions(mut self, max: usize) -> Self {
        self.max_instructions = max;
        self
    }

    pub fn with_snapshot_interval(mut self, interval: usize) -> Self {
        self.snapshot_interval = interval;
        self
    }
}

/// Configuration for a single trace run
#[derive(Clone)]
pub struct VmConfig<H> {
    pub until_address: u64,
    pub instruction_actions: InstructionActions,
    pub hooks: H,
}

/// Main library entry point - runs the TUI with user-provided VM setup
pub fn run_tui<P: VmSetupProvider>(setup_provider: P, config: TuiConfig) -> Result<()> {
    app::App::new(config)?.run_with_provider(setup_provider)
}
