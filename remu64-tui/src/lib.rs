use anyhow::Result;
use rdex::symbolizer::Symbolizer;
use remu64::{CowMemory, hooks::HookManager, memory::MemoryTrait};

mod app;
mod tracer;
mod ui;

pub use tracer::{InstructionAction, InstructionActions};

/// User-provided trait for VM initialization and per-frame setup
pub trait VmSetupProvider {
    type Memory: MemoryTrait + Clone;
    type Symbolizer: Symbolizer;
    type Hooks: HookManager<CowMemory<Self::Memory>>;

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

/// Configuration for a single trace run
pub struct VmConfig<H> {
    pub function_address: u64,
    pub until_address: u64,
    pub max_instructions: usize,
    pub instruction_actions: InstructionActions,
    pub hooks: H,
}

/// Main library entry point - runs the TUI with user-provided VM setup
pub fn run_tui<P: VmSetupProvider>(setup_provider: P) -> Result<()> {
    let mut app = app::App::new()?;
    app.run_with_provider(setup_provider)
}
