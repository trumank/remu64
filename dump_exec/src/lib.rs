pub mod executor;
pub mod fastcall;
pub mod memory_manager;
pub mod minidump_loader;
pub mod minidump_memory;
pub mod tracer;

pub use executor::FunctionExecutor;
pub use fastcall::{ArgumentType, CallingConvention, FName, FString};
pub use memory_manager::MemoryManager;
pub use minidump_loader::MinidumpLoader;
pub use minidump_memory::MinidumpMemory;

use anyhow::Result;

pub struct DumpExec;

impl DumpExec {
    pub fn load_minidump<P: AsRef<std::path::Path>>(path: P) -> Result<MinidumpLoader> {
        MinidumpLoader::load(path)
    }

    pub fn create_executor<'a>(loader: &'a MinidumpLoader) -> Result<FunctionExecutor<'a>> {
        FunctionExecutor::new(loader)
    }
}
