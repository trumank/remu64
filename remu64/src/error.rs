use std::fmt;

#[derive(Debug)]
pub enum EmulatorError {
    InvalidAddress(u64),
    UnmappedMemory(u64),
    PermissionDenied(u64),
    InvalidInstruction(u64),
    UnsupportedInstruction(String),
    InvalidRegister(String),
    EmulationStopped,
    HookError(String),
    InvalidArgument(String),
    OutOfMemory,
    DivisionByZero,
    DivisionOverflow,
    InvalidOperand,
    UnsupportedOperandType,
    InternalError(String),
}

impl fmt::Display for EmulatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EmulatorError::InvalidAddress(addr) => write!(f, "Invalid memory address: {:#x}", addr),
            EmulatorError::UnmappedMemory(addr) => {
                write!(f, "Memory not mapped at address: {:#x}", addr)
            }
            EmulatorError::PermissionDenied(addr) => {
                write!(f, "Permission denied for operation at address: {:#x}", addr)
            }
            EmulatorError::InvalidInstruction(addr) => {
                write!(f, "Invalid instruction at address: {:#x}", addr)
            }
            EmulatorError::UnsupportedInstruction(instr) => {
                write!(f, "Unsupported instruction: {}", instr)
            }
            EmulatorError::InvalidRegister(reg) => write!(f, "Invalid register: {}", reg),
            EmulatorError::EmulationStopped => write!(f, "Emulation stopped"),
            EmulatorError::HookError(msg) => write!(f, "Hook error: {}", msg),
            EmulatorError::InvalidArgument(msg) => write!(f, "Invalid argument: {}", msg),
            EmulatorError::OutOfMemory => write!(f, "Out of memory"),
            EmulatorError::DivisionByZero => write!(f, "Division by zero"),
            EmulatorError::DivisionOverflow => write!(f, "Division overflow"),
            EmulatorError::InvalidOperand => write!(f, "Invalid operand"),
            EmulatorError::UnsupportedOperandType => write!(f, "Unsupported operand type"),
            EmulatorError::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for EmulatorError {}

pub type Result<T> = std::result::Result<T, EmulatorError>;
