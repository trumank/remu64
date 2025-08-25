pub mod cpu;
pub mod memory;
pub mod decoder;
pub mod engine;
pub mod error;
pub mod hooks;

pub use engine::{Engine, EngineMode};
pub use error::{EmulatorError, Result};
pub use cpu::{Register, CpuState, Flags};
pub use memory::{Memory, MemoryRegion, Permission};
pub use hooks::{Hook, HookType};

pub const VERSION_MAJOR: u32 = 0;
pub const VERSION_MINOR: u32 = 1;
pub const VERSION_PATCH: u32 = 0;