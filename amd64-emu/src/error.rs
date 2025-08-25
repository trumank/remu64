use thiserror::Error;

#[derive(Error, Debug)]
pub enum EmulatorError {
    #[error("Invalid memory address: {0:#x}")]
    InvalidAddress(u64),
    
    #[error("Memory not mapped at address: {0:#x}")]
    UnmappedMemory(u64),
    
    #[error("Permission denied for operation at address: {0:#x}")]
    PermissionDenied(u64),
    
    #[error("Invalid instruction at address: {0:#x}")]
    InvalidInstruction(u64),
    
    #[error("Unsupported instruction: {0}")]
    UnsupportedInstruction(String),
    
    #[error("Invalid register: {0}")]
    InvalidRegister(String),
    
    #[error("Emulation stopped")]
    EmulationStopped,
    
    #[error("Hook error: {0}")]
    HookError(String),
    
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),
    
    #[error("Out of memory")]
    OutOfMemory,
    
    #[error("Division by zero")]
    DivisionByZero,
    
    #[error("Division overflow")]
    DivisionOverflow,
    
    #[error("Invalid operand")]
    InvalidOperand,
    
    #[error("Internal error: {0}")]
    InternalError(String),
}

pub type Result<T> = std::result::Result<T, EmulatorError>;