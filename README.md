# AMD64 Emulator

A pure Rust implementation of an AMD64 (x86-64) emulator with a Unicorn Engine-like API.

## Features

- **Pure Rust Implementation**: No external dependencies on QEMU or Unicorn
- **x86-64 Instruction Set**: Support for basic arithmetic, logic, control flow, and memory operations
- **Memory Management**: Virtual memory with page-based allocation and permission control
- **Hook System**: Instrumentation hooks for code execution, memory access, and invalid instructions
- **Unicorn-like API**: Familiar API for users of Unicorn Engine
- **Tracing Support**: Built-in instruction tracing for debugging

## Architecture

### Core Components

1. **CPU State**: Full x86-64 register set including general purpose, flags, and segment registers
2. **Memory Management**: Page-based virtual memory with read/write/execute permissions
3. **Instruction Decoder**: Handles x86-64 instruction formats including REX prefixes
4. **Execution Engine**: Interprets decoded instructions and updates CPU/memory state
5. **Hook System**: Flexible instrumentation for analysis and debugging

## Usage

### Basic Example

```rust
use amd64_emu::{Engine, EngineMode, Register, Permission};

let mut engine = Engine::new(EngineMode::Mode64);

// Map memory for code
engine.mem_map(0x1000, 0x1000, Permission::ALL).unwrap();

// Write machine code (mov rax, 0x1337; mov rbx, 0x42; add rax, rbx)
let code = vec![
    0x48, 0xC7, 0xC0, 0x37, 0x13, 0x00, 0x00,  // mov rax, 0x1337
    0x48, 0xC7, 0xC3, 0x42, 0x00, 0x00, 0x00,  // mov rbx, 0x42
    0x48, 0x01, 0xD8,                          // add rax, rbx
];

engine.mem_write(0x1000, &code).unwrap();

// Start emulation
engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();

// Read result
let result = engine.reg_read(Register::RAX).unwrap();
assert_eq!(result, 0x1337 + 0x42);
```

### Using Hooks

```rust
use amd64_emu::{Engine, EngineMode, HookType};

let mut engine = Engine::new(EngineMode::Mode64);

// Add a code hook
engine.hook_add(
    HookType::Code,
    0x1000,
    0x2000,
    |cpu, addr, size| {
        println!("Executing at {:#x}", addr);
        Ok(())
    },
).unwrap();

// Add a memory write hook
engine.hook_add(
    HookType::MemWrite,
    0x2000,
    0x3000,
    |_cpu, addr, size| {
        println!("Writing {} bytes to {:#x}", size, addr);
        Ok(())
    },
).unwrap();
```

## Supported Instructions

### Data Movement
- MOV (register/memory/immediate)
- PUSH/POP
- LEA

### Arithmetic
- ADD, SUB
- INC, DEC
- NEG

### Logic
- AND, OR, XOR
- NOT
- TEST, CMP

### Control Flow
- JMP (direct/indirect)
- Conditional jumps (JZ, JNZ, JS, JNS, JO, JNO, JB, JAE, etc.)
- CALL/RET

### System
- NOP
- HLT
- SYSCALL

## Building

```bash
cargo build --release
```

## Testing

```bash
cargo test
```

## Examples

Run the examples with:

```bash
cargo run --example simple
cargo run --example hooks
```

## License

This project is dual-licensed under MIT OR Apache-2.0.