use anyhow::Result;
use remu64::memory::MemoryTrait;
use std::rc::Rc;

/// Type alias for VM memory - using Rc to allow cloning for snapshots
pub type VmMemory = Rc<dyn MemoryTrait + 'static>;

/// Process trait that provides process metadata and creates memory objects
pub trait ProcessTrait {
    /// Module information
    fn get_module_by_name(&self, name: &str) -> Option<ModuleInfo>;
    fn get_module_base_address(&self, name: &str) -> Option<u64>;
    fn list_modules(&self) -> Vec<ModuleInfo>;
    fn find_module_for_address(&self, address: u64) -> Option<(String, u64, u64)>;

    /// Create memory object for this process (returns Rc trait object)
    fn create_memory(&self) -> Result<VmMemory>;

    /// Thread context (for TEB and other thread-specific data)
    fn get_teb_address(&self) -> Result<u64>;

    /// Architecture information
    fn get_architecture(&self) -> ProcessArchitecture;
}

/// Information about a loaded module
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub name: String,
    pub base_address: u64,
    pub size: u64,
    pub path: Option<String>,
}

/// Memory region information
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub base_address: u64,
    pub size: usize,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

/// Supported process architectures
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessArchitecture {
    X86,
    X64,
    Arm64,
}
