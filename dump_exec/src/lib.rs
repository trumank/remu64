pub mod executor;
pub mod fastcall;
pub mod memory_manager;
pub mod minidump_loader;
pub mod tracer;

pub use executor::{ExecutionContext, FunctionExecutor};
pub use fastcall::{ArgumentType, CallingConvention};
pub use memory_manager::MemoryManager;
pub use minidump_loader::MinidumpLoader;

use anyhow::Result;

pub struct DumpExec;

impl DumpExec {
    pub fn load_minidump<P: AsRef<std::path::Path>>(path: P) -> Result<MinidumpLoader> {
        MinidumpLoader::load(path)
    }

    pub fn create_executor(loader: MinidumpLoader) -> Result<FunctionExecutor> {
        FunctionExecutor::new(loader)
    }
}
