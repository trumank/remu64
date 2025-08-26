pub mod execution_controller;
pub mod executor;
pub mod fastcall;
pub mod memory_manager;
pub mod minidump_loader;
pub mod minidump_memory;
pub mod stack_manager;
pub mod tracer;
pub mod vm_context;

pub use execution_controller::{ExecutionController, ExecutionHooks};
pub use executor::FunctionExecutor;
pub use fastcall::{ArgumentType, CallingConvention, FName, FString};
pub use memory_manager::MemoryManager;
pub use minidump_loader::MinidumpLoader;
pub use minidump_memory::MinidumpMemory;
pub use stack_manager::StackManager;
pub use vm_context::VMContext;

use anyhow::Result;
use minidump::MmapMinidump;

pub struct DumpExec;

impl DumpExec {
    pub fn load_minidump<P: AsRef<std::path::Path>>(path: P) -> Result<MinidumpLoader<'static>> {
        MinidumpLoader::load(path)
    }

    pub fn from_minidump<'a>(dump: &'a MmapMinidump) -> Result<MinidumpLoader<'a>> {
        MinidumpLoader::from_minidump(dump)
    }

    pub fn create_executor<'a>(loader: &'a MinidumpLoader<'a>) -> Result<FunctionExecutor<'a>> {
        FunctionExecutor::new(loader)
    }
}
