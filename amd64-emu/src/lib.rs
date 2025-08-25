pub mod cpu;
pub mod decoder;
pub mod engine;
pub mod error;
pub mod hooks;
pub mod memory;

pub use cpu::{CpuState, Flags, Register};
pub use engine::{Engine, EngineMode};
pub use error::{EmulatorError, Result};
pub use hooks::{HookManager, HookType};
pub use memory::{Memory, MemoryRegion, Permission};

pub const VERSION_MAJOR: u32 = 0;
pub const VERSION_MINOR: u32 = 1;
pub const VERSION_PATCH: u32 = 0;
